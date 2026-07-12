from __future__ import annotations

from collections import deque
from dataclasses import replace
from pathlib import Path

import yaml

from ctf_os.application import CandidateSignal, LocalApplication, PlannedAttempt
from ctf_os.artifact_writer import ArtifactWriter
from ctf_os.config import AppConfig, default_config_mapping
from ctf_os.contest_parser import ContestManifest
from ctf_os.intake import IntakeChallenge
from ctf_os.local_state import LocalState
from ctf_os.local_worker_pool import LocalWorkerPool
from ctf_os.models import Attempt, Challenge, ChallengeStatus, Event, FlagCandidate
from ctf_os.solver_engine.immutable_verifier import ParentOwnedVerifier
from ctf_os.solver_engine.race_plan import RacePlan


def _fixture(tmp_path: Path, reference: str):
    raw = default_config_mapping("Verifier Demo", team_id="team", member_name="parent")
    raw["paths"] = {
        "incoming": str(tmp_path / "incoming"),
        "output": str(tmp_path / "output" / "team" / "parent"),
    }
    raw["sandbox"]["enabled"] = False
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    config = AppConfig.from_file(config_path)
    state = LocalState(config.state_path())
    challenge = state.upsert_challenge(Challenge("Verifier Demo", "pwn", "immutable", score=100))
    state.transition_challenge_status(challenge.id, ChallengeStatus.QUEUED)
    app = LocalApplication(
        config,
        parent_verifier=ParentOwnedVerifier.from_flag(challenge_id=challenge.id, flag=reference),
    )
    attempt = Attempt(
        id="attempt-parent-verifier", challenge_id=challenge.id, profile="exploit_main",
        role="exploit", backend="codex", workdir=str(tmp_path / "private-work"),
    )
    claim = state.claim_attempt(
        attempt, owner=app._owner, lease_seconds=60,
        max_workers_total=1, max_workers_per_challenge=1,
    )
    assert claim.granted and claim.fencing_token
    attempt = replace(attempt, lease_owner=app._owner, fencing_token=claim.fencing_token)
    state.upsert_attempt(attempt, owner=app._owner, fencing_token=claim.fencing_token)
    state.transition_challenge_status(
        challenge.id, ChallengeStatus.RUNNING, attempt_id=attempt.id,
        owner=app._owner, fencing_token=attempt.fencing_token,
    )
    manifest_path = tmp_path / "incoming" / "Verifier Demo" / "contest.md"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text("# verifier test\n", encoding="utf-8")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    task = PlannedAttempt(
        IntakeChallenge(
            ContestManifest("Verifier Demo", manifest_path, (challenge,), flag_patterns=(r"FLAG\{[^}]+\}",)),
            challenge, workspace, (),
        ),
        state, ArtifactWriter(config.output_root, "Verifier Demo"),
        RacePlan.for_score(100, category="pwn").attempts[0],
    )
    return app, state, challenge, attempt, task, workspace


def _submit_candidate(app, state, challenge, attempt, task, value: str):
    candidate = FlagCandidate(
        challenge_id=challenge.id, attempt_id=attempt.id, value=value,
        verification_status="RAW_CANDIDATE",
    )
    candidate = state.record_candidate(
        candidate,
        Event("team", "parent", "Verifier Demo", "FLAG_OBSERVED",
              challenge_id=challenge.id, attempt_id=attempt.id,
              payload={"candidate_sha256": "redacted"}),
        owner=app._owner, fencing_token=attempt.fencing_token,
    )
    pool = LocalWorkerPool(max_workers_total=1, max_workers_per_challenge=1)
    solved: set[str] = set()
    app._handle_candidate(
        CandidateSignal(task, attempt, candidate, False, ()), pool, deque(), solved,
        auto_confirm_flags=False,
    )
    return solved


def test_parent_verifier_is_challenge_bound_and_does_not_retain_reference_in_repr() -> None:
    reference = "FLAG{parent_only_secret_value}"
    verifier = ParentOwnedVerifier.from_flag(challenge_id="challenge-a", flag=reference, key=b"K" * 32)

    assert verifier.verify(challenge_id="challenge-a", candidate=reference).valid
    assert not verifier.verify(challenge_id="challenge-a", candidate="FLAG{wrong}").valid
    assert not verifier.verify(challenge_id="challenge-b", candidate=reference).valid
    assert reference not in repr(verifier)


def test_parent_verifier_rejects_wrong_flag_and_worker_verifier_tampering(tmp_path: Path) -> None:
    reference = "FLAG{correct_parent_answer}"
    app, state, challenge, attempt, task, workspace = _fixture(tmp_path, reference)
    # A worker-controlled verifier is deliberately convincing but is outside
    # the parent trust boundary and must never be consulted.
    (workspace / "verifier.py").write_text(
        "import sys; raise SystemExit(0)  # malicious always-accept verifier\n",
        encoding="utf-8",
    )

    solved = _submit_candidate(app, state, challenge, attempt, task, "FLAG{wrong}")

    assert not solved
    assert state.get_challenge(challenge.id).status is ChallengeStatus.FLAG_CANDIDATE
    assert state.list_flag_candidates(challenge.id)[0].verification_status == "REJECTED"
    assert not any(event.type == "VERIFIER_UNAVAILABLE" for event in state.list_events(challenge_id=challenge.id))


def test_parent_verifier_commits_flag_verified_and_solved_without_logging_raw_flag(tmp_path: Path) -> None:
    reference = "FLAG{accepted_only_by_parent}"
    app, state, challenge, attempt, task, workspace = _fixture(tmp_path, reference)
    assert reference not in "\n".join(
        path.read_text(errors="ignore") for path in workspace.rglob("*") if path.is_file()
    )

    solved = _submit_candidate(app, state, challenge, attempt, task, reference)

    assert challenge.id in solved
    assert state.get_challenge(challenge.id).status is ChallengeStatus.SOLVED
    events = state.list_events(challenge_id=challenge.id)
    verified = [event for event in events if event.type == "flag.verified"]
    assert len(verified) == 1 and verified[0].payload["redacted"] is True
    assert verified[0].payload["candidate_sha256"]
    assert all(reference not in (event.message or "") and reference not in str(event.payload) for event in events)
    assert not any(event.type == "VERIFIER_UNAVAILABLE" for event in events)


def test_solve_cancels_other_branches_without_removing_winner_staging() -> None:
    challenge_id = "challenge-winner"
    pool = LocalWorkerPool(max_workers_total=2, max_workers_per_challenge=2)
    winner = Attempt(id="winner", challenge_id=challenge_id, profile="exploit", role="exploit", backend="codex", workdir="/work/winner")
    loser = Attempt(id="loser", challenge_id=challenge_id, profile="recon", role="recon", backend="codex", workdir="/work/loser")
    winner_handle = pool.submit(winner, lambda cancel: cancel.wait(1))
    loser_handle = pool.submit(loser, lambda cancel: cancel.wait(1))

    solved: set[str] = set()
    LocalApplication._complete_solve(
        challenge_id, pool, deque(), solved, except_attempt_id=winner.id,
    )

    assert challenge_id in solved
    assert not winner_handle.cancel_event.is_set()
    assert loser_handle.cancel_event.is_set()
    winner_handle.cancel()
    pool.wait_all(2)
