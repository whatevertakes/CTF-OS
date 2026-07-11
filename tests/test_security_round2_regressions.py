"""Regression PoCs for the second production-security remediation round.

Each test describes a hostile-boundary behavior that must fail closed.  They
are intentionally written against public runtime boundaries so a future
refactor cannot reintroduce a policy-only mitigation.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path

import pytest
import yaml

from ctf_os.artifact_writer import ArtifactWriter
from ctf_os.application import LocalApplication, PlannedAttempt
from ctf_os.config import AppConfig, default_config_mapping
from ctf_os.contest_parser import ContestManifest
from ctf_os.intake import IntakeChallenge
from ctf_os.local_state import LocalState
from ctf_os.local_worker_pool import LocalWorkerPool
from ctf_os.model_routing import ModelRouter
from ctf_os.models import Attempt, AttemptStatus, Challenge, ChallengeStatus, Event, FlagCandidate
from ctf_os.sandbox.container import SandboxScope, build_container_name
from ctf_os.sandbox.docker_cli import CommandResult, DockerCli, RecordingCommandRunner
from ctf_os.sandbox.exec import execute_attempt_command
from ctf_os.sandbox.network_policy import AllowedEndpoint, RemoteEndpoint, RemotePolicyError, parse_remote_endpoints, resolve_remote_endpoints
from ctf_os.solver_engine.codex_cli_backend import CodexCliBackend, CodexExecRequest
from ctf_os.solver_engine.parser import ActionObservationParser
from ctf_os.solver_engine.race_plan import RacePlan
from ctf_os.solver_engine.verifier import Verifier


def _router() -> ModelRouter:
    return ModelRouter.from_mapping({
        "model_profiles": {"safe": {"model": "gpt-5.6-terra", "reasoning_effort": "high"}},
        "default_roles": {"default": "safe", "recon": "safe", "exploit": "safe", "source": "safe", "fallback": "safe"},
    })


def test_c1_production_argv_selects_only_the_named_profile(sterile_staging_factory) -> None:
    staging = sterile_staging_factory()
    endpoint = staging.workdir / ".ctf-os-broker"
    endpoint.mkdir(mode=0o700)
    argv = CodexCliBackend(model_router=_router()).build_exec_argv(CodexExecRequest(
        workdir=staging.workdir, prompt="solve", broker_socket=endpoint,
    ))

    assert "--sandbox" not in argv
    assert not any("dangerously-bypass" in item or "danger-full-access" in item for item in argv)
    assert 'default_permissions="ctf_os_attempt"' in argv
    profiles = [item for item in argv if item.startswith("permissions.ctf_os_attempt=")]
    assert len(profiles) == 1
    assert "network={enabled=false" in profiles[0]
    assert "enabled=true" not in profiles[0]
    assert "unix_sockets" not in profiles[0]


def test_c1_strict_probe_rejects_a_cli_that_advertises_flags_but_cannot_parse_profile(monkeypatch) -> None:
    import subprocess

    calls: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        calls.append(list(argv))
        if len(calls) == 1:
            return type("Result", (), {"returncode": 0, "stdout": "--strict-config --ignore-user-config --ignore-rules --ephemeral --disable --config", "stderr": ""})()
        return type("Result", (), {"returncode": 2, "stdout": "", "stderr": "unknown configuration default_permissions"})()

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert not CodexCliBackend.strict_isolation_supported("codex")
    assert len(calls) == 2
    assert "--sandbox" not in calls[1]
    assert 'default_permissions="ctf_os_attempt"' in calls[1]


def test_c2_promotion_rejects_an_intermediate_workdir_symlink(tmp_path: Path) -> None:
    writer = ArtifactWriter(tmp_path / "output", "Demo")
    challenge = Challenge(contest="Demo", category="web", name="login")
    staging = writer.create_attempt_staging()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "exploit.py").write_text("print('stolen')\n", encoding="utf-8")
    (staging.workdir / "nested").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink|unsafe|private"):
        writer.promote_verified_artifacts(
            challenge,
            attempt_workdir=staging.workdir,
            artifact_paths=(staging.workdir / "nested" / "exploit.py",),
        )
    assert not (writer.challenge_dir(challenge) / "final" / "exploit.py").exists()


def test_c2_promotion_copies_the_opened_inode_when_worker_swaps_the_leaf(tmp_path: Path, monkeypatch) -> None:
    writer = ArtifactWriter(tmp_path / "output", "Demo")
    challenge = Challenge(contest="Demo", category="web", name="login")
    staging = writer.create_attempt_staging()
    source = staging.workdir / "exploit.py"
    source.write_text("print('approved')\n", encoding="utf-8")
    replacement = tmp_path / "replacement.py"
    replacement.write_text("print('swapped')\n", encoding="utf-8")

    import ctf_os.artifact_writer as artifacts

    original = artifacts._copy_fd_atomic_to_fd

    def swap_after_open(source_fd, destination_fd, name):
        source.unlink()
        replacement.replace(source)
        return original(source_fd, destination_fd, name)

    monkeypatch.setattr(artifacts, "_copy_fd_atomic_to_fd", swap_after_open)
    writer.promote_verified_artifacts(challenge, attempt_workdir=staging.workdir, artifact_paths=(source,))
    assert (writer.challenge_dir(challenge) / "final" / "exploit.py").read_text(encoding="utf-8") == "print('approved')\n"


def test_h1_worker_replay_that_echoes_every_binding_is_not_a_trust_anchor(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    (work / "replay.py").write_text("# worker controls this file\n", encoding="utf-8")
    verifier = Verifier()
    command = verifier.derive_command(
        ActionObservationParser().parse("[ARTIFACT] /work/replay.py"),
        attempt_workdir=work,
        challenge_artifacts=tmp_path / "artifacts",
        candidate="FLAG{SELF_ECHO}", challenge_id="chal", attempt_id="attempt", nonce="fresh",
    )
    if command is not None:
        proof = '{"candidate":"FLAG{SELF_ECHO}","challenge_id":"chal","attempt_id":"attempt","nonce":"fresh"}'
        result = type("Result", (), {"returncode": 0, "stdout": f"[VERIFICATION_PROOF] {proof}\n", "stderr": "", "timed_out": False, "truncated": False})()
        assert verifier.verify_sandbox("FLAG{SELF_ECHO}", command, execute=lambda _argv: result).state != "solved"


@pytest.mark.parametrize("remote", ["http://8.8.8.8/", "https://1.1.1.1/"])
def test_h4_http_ip_declarations_fail_closed_without_host_sni_mediation(remote: str) -> None:
    with pytest.raises(RemotePolicyError, match=r"HTTP\(S\)"):
        parse_remote_endpoints(remote)


def test_h4_private_opt_in_cannot_allow_the_docker_gateway() -> None:
    endpoint = parse_remote_endpoints("nc pwn.example 2375")
    with pytest.raises(RemotePolicyError, match="private|disallowed"):
        resolve_remote_endpoints(endpoint, resolver=lambda *_: [(2, 1, 6, "", ("172.17.0.1", 2375))], allow_private=True)


def test_h4_direct_policy_objects_cannot_reintroduce_http_egress() -> None:
    with pytest.raises(RemotePolicyError, match=r"HTTP\(S\)"):
        RemoteEndpoint("8.8.8.8", 80, "http")
    with pytest.raises(RemotePolicyError, match=r"HTTP\(S\)"):
        AllowedEndpoint("8.8.8.8", "8.8.8.8", 80, "tcp", "https")


def _config(tmp_path: Path) -> AppConfig:
    raw = default_config_mapping("Demo")
    raw["model_routing"]["enabled"] = False
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return AppConfig.from_file(path)


def test_h5_direct_exec_timeout_removes_exact_sterile_attempt_container(tmp_path: Path) -> None:
    config = _config(tmp_path)
    state = LocalState(config.state_path())
    challenge = state.upsert_challenge(Challenge(contest="Demo", category="web", name="login"))
    state.transition_challenge_status(challenge.id, ChallengeStatus.QUEUED)
    staging = ArtifactWriter(tmp_path / "output", "Demo").create_attempt_staging()
    name = build_container_name(config.team_id, challenge.contest, challenge.name, "attempt-direct")
    attempt = Attempt(id="attempt-direct", challenge_id=challenge.id, profile="recon_fast", role="recon", backend="codex_cli",
                      workdir=str(staging.workdir), container_name=name)
    claim = state.claim_attempt(attempt, owner="owner", lease_seconds=30, max_workers_total=1, max_workers_per_challenge=1)
    assert claim.granted and claim.fencing_token
    attempt = replace(attempt, lease_owner="owner", fencing_token=claim.fencing_token, status=AttemptStatus.RUNNING)
    state.upsert_attempt(attempt, owner="owner", fencing_token=claim.fencing_token)
    state.transition_challenge_status(challenge.id, ChallengeStatus.RUNNING, attempt_id=attempt.id, owner="owner", fencing_token=claim.fencing_token)

    class TimeoutDocker(DockerCli):
        def __init__(self) -> None:
            super().__init__(runner=RecordingCommandRunner())
            self.removed: list[str] = []

        def exec(self, argv, *, timeout_sec=None, cancel_event=None):
            return CommandResult(tuple(argv), returncode=124, timed_out=True)

        def remove(self, container_name: str) -> CommandResult:
            self.removed.append(container_name)
            return CommandResult(("docker", "rm", "-f", container_name))

    docker = TimeoutDocker()
    result = execute_attempt_command(config, attempt.id, ["sleep", "999"], docker=docker)
    assert result.timed_out
    assert docker.removed == [name]
    assert not staging.root.exists()
    assert len(docker.calls) == 1
    scrub = docker.calls[0]
    assert scrub[:3] == ["docker", "run", "--rm"]
    assert f"{staging.workdir}:/work:rw" in scrub
    assert f"{staging.artifacts}:/artifacts:rw" in scrub
    assert "/workspace" not in " ".join(scrub)


def test_h5_codex_output_callbacks_and_result_are_hard_bounded(sterile_staging_factory) -> None:
    class LoudProcess:
        pid = 99

        def __init__(self) -> None:
            self.stdout = StringIO("A" * 32_000 + "\n")
            self.stderr = StringIO("B" * 32_000 + "\n")

        def poll(self):
            return 0

        def wait(self, timeout=None):
            return 0

    staging = sterile_staging_factory()
    endpoint = staging.workdir / ".ctf-os-broker"
    endpoint.mkdir(mode=0o700)
    observed: list[object] = []
    backend = CodexCliBackend(model_router=_router(), process_factory=lambda *_a, **_k: LoudProcess(), max_retained_output_bytes=4096)
    result = backend.run(CodexExecRequest(workdir=staging.workdir, prompt="x", broker_socket=endpoint), on_output=observed.append)
    assert result.truncated
    assert len((result.stdout + result.stderr).encode("utf-8")) <= 4096
    assert sum(len(record.line.encode("utf-8")) for record in observed) <= 4096


def _planned_task(tmp_path: Path):
    config = _config(tmp_path)
    app = LocalApplication(config)
    state = LocalState(config.state_path())
    challenge = state.upsert_challenge(Challenge(contest="Demo", category="web", name="login"))
    state.transition_challenge_status(challenge.id, ChallengeStatus.QUEUED)
    manifest_path = tmp_path / "incoming" / "Demo" / "contest.md"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text("# placeholder\n", encoding="utf-8")
    manifest = ContestManifest(name="Demo", path=manifest_path, challenges=(challenge,))
    intake = IntakeChallenge(manifest, challenge, tmp_path / "workspace", ())
    writer = ArtifactWriter(config.output_root, "Demo")
    return config, app, state, challenge, PlannedAttempt(intake, state, writer, RacePlan.for_score(1).attempts[0])


def test_h2_reassigned_old_callback_cannot_mutate_aggregate_or_events(tmp_path: Path) -> None:
    _config_value, app, state, challenge, task = _planned_task(tmp_path)
    staging = task.writer.create_attempt_staging()
    old = Attempt(id="attempt-old", challenge_id=challenge.id, profile="recon_fast", role="recon", backend="codex_cli", workdir=str(staging.workdir))
    first = state.claim_attempt(old, owner=app._owner, lease_seconds=0.01, max_workers_total=1, max_workers_per_challenge=1)
    assert first.granted and first.fencing_token
    old = replace(old, lease_owner=app._owner, fencing_token=first.fencing_token, status=AttemptStatus.RUNNING)
    state.upsert_attempt(old, owner=app._owner, fencing_token=first.fencing_token)
    state.transition_challenge_status(challenge.id, ChallengeStatus.RUNNING, attempt_id=old.id, owner=app._owner, fencing_token=first.fencing_token)
    import time
    time.sleep(0.03)
    replacement = Attempt(id="attempt-new", challenge_id=challenge.id, profile="recon_fast", role="recon", backend="codex_cli", workdir="/work")
    second = state.claim_attempt(replacement, owner="new-owner", lease_seconds=30, max_workers_total=1, max_workers_per_challenge=1)
    assert second.granted
    baseline_events = tuple(state.list_events(challenge_id=challenge.id))
    root = task.writer.prepare_challenge(challenge)
    baseline_notes = (root / "notes.md").read_text(encoding="utf-8")
    baseline_evidence = (root / "evidence.log").read_text(encoding="utf-8")

    app._stream_line(task, challenge, old, "[FINDING] stale callback payload", synthetic=False)

    assert tuple(state.list_events(challenge_id=challenge.id)) == baseline_events
    assert (root / "notes.md").read_text(encoding="utf-8") == baseline_notes
    assert (root / "evidence.log").read_text(encoding="utf-8") == baseline_evidence


def test_candidate_then_artifact_is_requeued_instead_of_process_deduped(tmp_path: Path) -> None:
    _config_value, app, state, challenge, task = _planned_task(tmp_path)
    staging = task.writer.create_attempt_staging()
    attempt = Attempt(id="attempt-order", challenge_id=challenge.id, profile="recon_fast", role="recon", backend="codex_cli", workdir=str(staging.workdir))
    claim = state.claim_attempt(attempt, owner=app._owner, lease_seconds=30, max_workers_total=1, max_workers_per_challenge=1)
    assert claim.granted and claim.fencing_token
    attempt = replace(attempt, lease_owner=app._owner, fencing_token=claim.fencing_token, status=AttemptStatus.RUNNING)
    state.upsert_attempt(attempt, owner=app._owner, fencing_token=claim.fencing_token)
    state.transition_challenge_status(challenge.id, ChallengeStatus.RUNNING, attempt_id=attempt.id, owner=app._owner, fencing_token=claim.fencing_token)
    pool = LocalWorkerPool(max_workers_total=1, max_workers_per_challenge=1)
    from collections import deque

    app._stream_line(task, challenge, attempt, "[FLAG_CANDIDATE] FLAG{ORDERED}", synthetic=False)
    app._drain_candidate_signals(pool, deque(), set(), auto_confirm_flags=False)
    app._stream_line(task, challenge, attempt, "[ARTIFACT] /work/replay.py", synthetic=False)
    retried = app._candidate_signals.get_nowait()
    assert retried.candidate.value == "FLAG{ORDERED}" and retried.attempt.id == attempt.id


def test_recovery_requeues_stale_candidate_and_verifying_work_with_fenced_events(tmp_path: Path) -> None:
    now = datetime(2026, 7, 10, tzinfo=timezone.utc)
    state = LocalState(tmp_path / "state.db", clock=lambda: now)
    challenge = state.upsert_challenge(Challenge(contest="Demo", category="web", name="login"))
    state.transition_challenge_status(challenge.id, ChallengeStatus.QUEUED)
    attempt = Attempt(id="attempt-stale", challenge_id=challenge.id, profile="recon_fast", role="recon", backend="codex_cli", workdir="/work")
    claim = state.claim_attempt(attempt, owner="old", lease_seconds=1, max_workers_total=1, max_workers_per_challenge=1)
    assert claim.granted and claim.fencing_token
    attempt = replace(attempt, lease_owner="old", fencing_token=claim.fencing_token)
    state.transition_challenge_status(challenge.id, ChallengeStatus.RUNNING, attempt_id=attempt.id, owner="old", fencing_token=claim.fencing_token)
    candidate = FlagCandidate(challenge_id=challenge.id, attempt_id=attempt.id, value="FLAG{RECOVER}")
    state.record_candidate(candidate, Event(team_id="t", member="m", contest="Demo", type="FLAG_CANDIDATE", challenge_id=challenge.id, attempt_id=attempt.id), owner="old", fencing_token=claim.fencing_token)
    state.transition_challenge_status(challenge.id, ChallengeStatus.VERIFYING, attempt_id=attempt.id, owner="old", fencing_token=claim.fencing_token)

    recovered = state.reconcile_stale_attempts(
        now=now + timedelta(seconds=2),
        recovery_event_factory=lambda kind, attempt_id, challenge_id, token: Event(
            team_id="t", member="m", contest="Demo", type=kind, challenge_id=challenge_id, attempt_id=attempt_id,
            payload={"recovery": True, "fencing_token": token},
        ),
    )
    assert recovered.requeued_challenge_ids == (challenge.id,)
    assert state.get_challenge(challenge.id).status is ChallengeStatus.QUEUED
    assert state.list_flag_candidates(challenge.id)[0].verification_status == "UNAVAILABLE"
    events = state.list_events(challenge_id=challenge.id)
    assert any(event.type == "WORKER_STOPPED" and event.payload.get("recovery") for event in events)
    assert any(event.type == "QUEUED" and event.payload.get("fencing_token") == claim.fencing_token for event in events)
