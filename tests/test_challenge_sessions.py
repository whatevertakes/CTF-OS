from __future__ import annotations

from dataclasses import replace
import sqlite3

import pytest

from ctf_os.local_state import CURRENT_SCHEMA_VERSION, LocalState, StateTransitionError
from ctf_os.models import (
    Challenge,
    ChallengeSession,
    ContractTask,
    ContractTaskStatus,
    SessionStatus,
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
    ))

    finished = state.mark_contract_task_outcome(
        task.id, status=ContractTaskStatus.SUCCEEDED,
        result_summary="CBC padding oracle reproduced",
        evidence_ids=("artifact:replay.py", "event:finding-1"),
        assigned_attempt_id="attempt-luna-1",
    )
    assert finished.status is ContractTaskStatus.SUCCEEDED
    assert finished.evidence_ids == ("artifact:replay.py", "event:finding-1")
    assert state.list_contract_tasks(session.id, status="succeeded") == [finished]
    assert LocalState(state.path).get_contract_task(task.id) == finished


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


def test_schema_v8_contains_session_tables(tmp_path):
    path = tmp_path / "state.db"
    LocalState(path)
    with sqlite3.connect(path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_SCHEMA_VERSION == 8
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
    assert {"challenge_sessions", "contract_tasks"} <= tables


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
