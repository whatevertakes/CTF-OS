"""Release-blocker regressions for the hostile-boundary audit.

These tests intentionally exercise the public boundary rather than merely
asserting implementation details.  They cover the conditions that made the
previous release a NO-GO.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ctf_os.artifact_writer import ArtifactWriter
from ctf_os.local_state import LocalState, StateTransitionError
from ctf_os.models import Attempt, Challenge, ChallengeStatus, Event, FlagCandidate
from ctf_os.sandbox.network_policy import RemotePolicyError, parse_remote_endpoints, resolve_remote_endpoints
from ctf_os.solver_engine.codex_cli_backend import CodexCliBackend, CodexExecRequest
from ctf_os.solver_engine.verifier import Verifier
from ctf_os.model_routing import ModelRouter


def _router() -> ModelRouter:
    return ModelRouter.from_mapping({
        "model_profiles": {"safe": {"model": "gpt-5.6-terra", "reasoning_effort": "high"}},
        "default_roles": {"default": "safe", "recon": "safe", "exploit": "safe", "source": "safe", "fallback": "safe"},
    })


def _attempt(challenge_id: str, ident: str) -> Attempt:
    return Attempt(id=ident, challenge_id=challenge_id, profile="recon", role="recon", backend="codex", workdir="/work")


def test_codex_request_requires_a_sterile_boundary_and_never_exposes_unsafe_escape_hatch(tmp_path: Path) -> None:
    """A parent ``.codex/config.toml`` must be irrelevant to an attempt."""
    parent = tmp_path / "parent"
    (parent / ".codex").mkdir(parents=True)
    (parent / ".codex" / "config.toml").write_text('sandbox_mode = "danger-full-access"\n', encoding="utf-8")
    work = parent / "output" / "attempt" / "work"
    work.mkdir(parents=True)
    backend = CodexCliBackend(model_router=_router())
    with pytest.raises(ValueError, match="sterile"):
        backend.build_exec_argv(CodexExecRequest(workdir=work, prompt="x", broker_socket=tmp_path / "broker.sock"))


def test_artifact_writer_rejects_notes_symlink_and_destination_swap(tmp_path: Path) -> None:
    writer = ArtifactWriter(tmp_path / "output", "Demo")
    challenge = Challenge(contest="Demo", category="web", name="login")
    root = writer.prepare_challenge(challenge)
    victim = tmp_path / "victim"
    victim.write_text("do-not-touch", encoding="utf-8")
    (root / "notes.md").unlink()
    (root / "notes.md").symlink_to(victim)
    with pytest.raises(ValueError, match="symlink"):
        writer.append_note(challenge, "finding", "attacker text")
    assert victim.read_text(encoding="utf-8") == "do-not-touch"

    staged = tmp_path / "staged.py"
    staged.write_text("print('ok')\n", encoding="utf-8")
    final = root / "final" / "exploit.py"
    final.symlink_to(victim)
    with pytest.raises(ValueError, match="symlink"):
        writer.write_final_exploit(challenge, "print('replacement')\n")
    assert victim.read_text(encoding="utf-8") == "do-not-touch"


def test_verifier_rejects_worker_owned_replay_before_any_self_attestation(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    replay = work / "replay.py"
    replay.write_text("# real artifact\n", encoding="utf-8")
    verifier = Verifier()
    records = verifier.parse_artifact_records("[ARTIFACT] /work/replay.py")
    command = verifier.derive_command(
        records, attempt_workdir=work, challenge_artifacts=tmp_path / "private-artifacts",
        candidate="FLAG{REAL}", challenge_id="chal", attempt_id="attempt", nonce="fresh-nonce",
    )
    assert command is None
    assert verifier.verify_sandbox("FLAG{REAL}", command, execute=lambda _argv: None).state == "rejected"


def test_expired_owner_cannot_mutate_or_solve_after_new_fenced_claim(tmp_path: Path) -> None:
    now = datetime(2026, 7, 10, tzinfo=timezone.utc)
    state = LocalState(tmp_path / "state.db", clock=lambda: now)
    challenge = state.upsert_challenge(Challenge(contest="Demo", category="web", name="login"))
    state.transition_challenge_status(challenge.id, ChallengeStatus.QUEUED)
    first = state.claim_attempt(_attempt(challenge.id, "a"), owner="A", lease_seconds=1, max_workers_total=1, max_workers_per_challenge=1)
    assert first.granted and first.fencing_token
    state.transition_challenge_status(challenge.id, ChallengeStatus.RUNNING, attempt_id="a", owner="A", fencing_token=first.fencing_token)
    later = now + timedelta(seconds=2)
    second = state.claim_attempt(_attempt(challenge.id, "b"), owner="B", lease_seconds=30, max_workers_total=1, max_workers_per_challenge=1, now=later)
    assert second.granted and second.fencing_token > first.fencing_token
    with pytest.raises(StateTransitionError, match="lease"):
        state.finish_attempt("a", "SUCCEEDED", owner="A", fencing_token=first.fencing_token, now=later)
    candidate = FlagCandidate(challenge_id=challenge.id, attempt_id="a", value="FLAG{OLD}")
    with pytest.raises(StateTransitionError, match="lease"):
        state.record_candidate(candidate, Event(team_id="t", member="m", contest="Demo", type="FLAG_CANDIDATE"), owner="A", fencing_token=first.fencing_token, now=later)


@pytest.mark.parametrize("remote", [
    "http://localhost/", "http://127.0.0.1/", "http://169.254.169.254/", "http://10.0.0.1/",
    "http://[::1]/", "http://[::]/", "http://[ff02::1]/", "http://example.test:0/",
])
def test_egress_rejects_private_special_and_port_zero_by_default(remote: str) -> None:
    with pytest.raises(RemotePolicyError):
        parse_remote_endpoints(remote)


def test_http_hostname_fails_closed_and_nc_requires_a_frozen_safe_address() -> None:
    with pytest.raises(RemotePolicyError, match="HTTP\\(S\\)"):
        parse_remote_endpoints("https://alternate-vhost.example/")
    endpoint = parse_remote_endpoints("nc pwn.example 31337")
    with pytest.raises(RemotePolicyError):
        resolve_remote_endpoints(endpoint, resolver=lambda *_: [(2, 1, 6, "", ("127.0.0.1", 31337))])
    allowed = resolve_remote_endpoints(endpoint, resolver=lambda *_: [(2, 1, 6, "", ("8.8.8.8", 31337))])
    assert allowed[0].address == "8.8.8.8"
