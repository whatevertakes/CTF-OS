from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import sqlite3

import pytest

from ctf_os.local_state import CURRENT_SCHEMA_VERSION, LocalState, StateTransitionError
from ctf_os.models import (
    Challenge,
    ChallengeSession,
    ContractTask,
    ContractTaskStatus,
    SessionStatus,
    Attempt,
    ChallengeStatus,
)


def test_persistent_session_checkpoints_sol_continuation_and_summary(tmp_path):
    path = tmp_path / "state.db"
    state = LocalState(path)
    challenge = state.upsert_challenge(Challenge(contest="CTF", category="pwn", name="heap"))

    session = state.get_or_create_challenge_session(
        challenge.id,
        leader_model="gpt-5.6-sol",
        reasoning_effort="xhigh",
        execution_contract={"primary": "heap primitive"},
    )
    checkpoint = state.checkpoint_challenge_session(
        challenge.id,
        leader_session_id="codex-session-1",
        leader_resume_id="resume-1",
        summary_state={"verified": ["UAF"], "next": "leak libc"},
        advance_generation=True,
    )

    assert checkpoint.id == session.id
    assert checkpoint.generation == 1
    assert checkpoint.leader_session_id == "codex-session-1"
    assert checkpoint.summary_state["verified"] == ["UAF"]
    reopened = LocalState(path).get_challenge_session(challenge.id)
    assert reopened == checkpoint
    assert LocalState(path).get_or_create_challenge_session(
        challenge.id, leader_model="ignored-on-resume"
    ) == checkpoint


def test_contract_tasks_persist_proof_artifact_handoff_and_outcome(tmp_path):
    state = LocalState(tmp_path / "state.db")
    challenge = state.upsert_challenge(Challenge(contest="CTF", category="crypto", name="oracle"))
    session = state.upsert_challenge_session(ChallengeSession(
        challenge_id=challenge.id, leader_model="gpt-5.6-sol"
    ))
    task = state.upsert_contract_task(ContractTask(
        id="task-luna-recon", session_id=session.id, challenge_id=challenge.id,
        branch="recon-1", role="luna", objective="classify the oracle",
        success_criteria=("provide a reproducible distinguishing query",),
        deliverables=("replay.py", "transcript.txt"),
        failure_handoff="report eliminated oracle classes to Sol",
        backend="codex", model_profile="luna_high", reasoning_effort="high",
        prompt_family="recon", timeout_sec=480, tool_strategy="fast_recon", priority=90,
    ))

    finished = state.mark_contract_task_outcome(
        task.id, status=ContractTaskStatus.SUCCEEDED,
        result_summary="CBC padding oracle reproduced",
        evidence_ids=("artifact:replay.py", "event:finding-1"),
        assigned_attempt_id="attempt-luna-1",
    )
    assert finished.status is ContractTaskStatus.SUCCEEDED
    assert finished.evidence_ids == ("artifact:replay.py", "event:finding-1")
    assert (finished.backend, finished.model_profile, finished.prompt_family) == (
        "codex", "luna_high", "recon"
    )
    assert (finished.timeout_sec, finished.tool_strategy, finished.priority) == (480, "fast_recon", 90)
    assert state.list_contract_tasks(session.id, status="succeeded") == [finished]
    assert LocalState(state.path).get_contract_task(task.id) == finished


def test_structured_artifact_handoff_records_producer_consumer_and_provenance(tmp_path):
    state = LocalState(tmp_path / "state.db")
    challenge = state.upsert_challenge(Challenge("CTF", "pwn", "heap-handoff"))
    session = state.upsert_challenge_session(ChallengeSession(challenge.id, "gpt-5.6-sol"))
    producer = state.upsert_contract_task(ContractTask(
        session.id, challenge.id, "leak", "reverse", "obtain one-shot leak",
        tool_strategy="dynamic_analysis",
    ))
    consumer = state.upsert_contract_task(ContractTask(
        session.id, challenge.id, "exploit", "exploit", "consume promoted leak",
        tool_strategy="exploit_build", depends_on=(producer.id,),
    ))
    artifact = state.record_tactical_artifact({
        "id": "artifact-leak", "challenge_id": challenge.id,
        "artifact_type": "structured_result", "path": "/artifacts/leak.json",
        "sha256": "a" * 64, "contract_id": producer.id, "strategy_id": "dynamic_analysis",
        "strategy_version": 1, "creation_event_id": "event-leak",
        "content_metadata": {"finding_kind": "libc_leak"},
    })

    handed = state.handoff_tactical_artifacts(
        challenge_id=challenge.id, producer_contract_id=producer.id,
        filenames=("/artifacts/leak.json",), consumer_contract_ids=(consumer.id,),
    )

    assert handed == (artifact["id"],)
    stored = state.list_tactical_artifacts(challenge.id)[0]
    assert stored["sha256"] == "a" * 64
    assert stored["contract_id"] == producer.id
    assert stored["consumers"] == [consumer.id]
    assert stored["trust_state"] == "promoted"


def test_contract_task_cannot_cross_challenge_session_boundary(tmp_path):
    state = LocalState(tmp_path / "state.db")
    one = state.upsert_challenge(Challenge(contest="CTF", category="rev", name="one"))
    two = state.upsert_challenge(Challenge(contest="CTF", category="rev", name="two"))
    session = state.upsert_challenge_session(ChallengeSession(
        challenge_id=one.id, leader_model="gpt-5.6-sol"
    ))
    with pytest.raises(StateTransitionError, match="does not match"):
        state.upsert_contract_task(ContractTask(
            session_id=session.id, challenge_id=two.id, branch="bad", role="terra",
            objective="cross challenge state",
        ))


def test_schema_v9_contains_session_tables(tmp_path):
    path = tmp_path / "state.db"
    LocalState(path)
    with sqlite3.connect(path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_SCHEMA_VERSION == 10
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
    assert {"challenge_sessions", "contract_tasks"} <= tables


def test_contract_task_materialization_is_idempotent_and_preserves_outcome(tmp_path):
    state = LocalState(tmp_path / "state.db")
    challenge = state.upsert_challenge(Challenge(contest="CTF", category="pwn", name="idem"))
    session = state.upsert_challenge_session(ChallengeSession(
        challenge_id=challenge.id, leader_model="gpt-5.6-sol"
    ))
    first = state.upsert_contract_task(ContractTask(
        session_id=session.id, challenge_id=challenge.id, branch="g1:A",
        role="exploit", objective="build exploit", model_profile="terra_high",
        tool_strategy="exploit_build",
    ))
    state.mark_contract_task_outcome(first.id, status="RUNNING", assigned_attempt_id="attempt-1")
    finished = state.mark_contract_task_outcome(first.id, status="SUCCEEDED", result_summary="worked")

    replayed = state.upsert_contract_task(ContractTask(
        session_id=session.id, challenge_id=challenge.id, branch="g1:A",
        role="exploit", objective="build improved exploit", model_profile="terra_xhigh",
        reasoning_effort="max", priority=99,
    ))
    assert replayed.id == first.id
    assert replayed.status is ContractTaskStatus.SUCCEEDED
    assert replayed.result_summary == finished.result_summary == "worked"
    assert (replayed.model_profile, replayed.reasoning_effort, replayed.priority) == (
        "terra_xhigh", "max", 99
    )


def test_session_status_can_be_checkpointed_without_losing_contract(tmp_path):
    state = LocalState(tmp_path / "state.db")
    challenge = state.upsert_challenge(Challenge(contest="CTF", category="misc", name="maze"))
    session = state.upsert_challenge_session(ChallengeSession(
        challenge_id=challenge.id, leader_model="gpt-5.6-sol",
        execution_contract={"goal": "solve"},
    ))
    paused = state.checkpoint_challenge_session(challenge.id, status=SessionStatus.PAUSED)
    assert paused.status is SessionStatus.PAUSED
    assert paused.execution_contract == session.execution_contract


def test_stale_attempt_recovery_retires_running_and_orphaned_pending_contracts(tmp_path):
    now = datetime(2026, 7, 12, tzinfo=timezone.utc)
    state = LocalState(tmp_path / "state.db", clock=lambda: now)
    challenge = state.upsert_challenge(Challenge(contest="CTF", category="rev", name="recover"))
    state.transition_challenge_status(challenge.id, ChallengeStatus.QUEUED)
    session = state.upsert_challenge_session(ChallengeSession(
        challenge_id=challenge.id, leader_model="gpt-5.6-sol"
    ))
    running = state.upsert_contract_task(ContractTask(
        session_id=session.id, challenge_id=challenge.id, branch="g1:A",
        role="reverse", objective="trace verifier",
    ))
    pending = state.upsert_contract_task(ContractTask(
        session_id=session.id, challenge_id=challenge.id, branch="g1:B",
        role="fuzz_symbolic", objective="solve constraints",
    ))
    attempt = Attempt(
        id="attempt-stale-contract", challenge_id=challenge.id, profile="contract_sol_xhigh",
        role="reverse", backend="codex", workdir="/work",
    )
    claim = state.claim_attempt(
        attempt, owner="old", lease_seconds=1, max_workers_total=2,
        max_workers_per_challenge=2,
    )
    assert claim.granted and claim.fencing_token
    state.transition_challenge_status(
        challenge.id, ChallengeStatus.RUNNING, attempt_id=attempt.id,
        owner="old", fencing_token=claim.fencing_token,
    )
    state.mark_contract_task_outcome(running.id, status="RUNNING", assigned_attempt_id=attempt.id)

    recovery = state.reconcile_stale_attempts(now=now + timedelta(seconds=2))
    assert recovery.requeued_challenge_ids == (challenge.id,)
    assert state.get_contract_task(running.id).status is ContractTaskStatus.FAILED
    assert state.get_contract_task(pending.id).status is ContractTaskStatus.CANCELLED
