from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from ctf_os.candidates import CandidateError, build_candidate, load_candidates, record_candidate
from ctf_os.challenge import SelectionError, resolve_selector
from ctf_os.control import (
    acknowledge_control_action, create_control_action, load_control_actions,
)
from ctf_os.delegation import (
    confirm_branch_start, load_plan, record_branch_sandbox_ready,
    record_capacity_admission, update_branch,
)
from ctf_os.events import insight_packet, publish_event
from ctf_os.milestones import load_milestones, save_milestone
from ctf_os.progress import (
    evaluate_progress_gate, evaluate_remote_transition, heartbeat_long_compute,
    record_command, register_milestone,
)
from ctf_os.race import RaceBranchSpec, race_board, start_race_plan
from ctf_os.resources.scheduler import ResourceLedger, default_request
from ctf_os.sandbox.network import NetworkPolicyError, parse_remotes
from ctf_os.terminal import (
    converge_terminal, record_native_stop, record_submission_result,
    terminal_status,
)
from ctf_os.transitions import evaluate_race_transition
from ctf_os.verification import FastFlagError, record_remote_flag
from ctf_os.workspace import (
    bind_input_fingerprint, record_target_revision, resolve_active_run, target_revisions,
)
from conftest import write_contest


def _challenge(challenge_id: str, *, remotes: tuple[str, ...] = ()) -> SimpleNamespace:
    return SimpleNamespace(
        id=challenge_id, key=f"misc/{challenge_id}", category="misc", name=challenge_id,
        remotes=remotes, description=challenge_id, hint=None, flag_format="CTF{...}",
        flag_pattern=r"\ACTF\{[^}]+\}\Z", input_profile="standard",
    )


def _run(tmp_path: Path, challenge_id: str = "challenge", *, fingerprint: str = "fp", remotes: tuple[str, ...] = ()) -> tuple[Path, Path, SimpleNamespace]:
    workspace = tmp_path / challenge_id
    (workspace / "input").mkdir(parents=True)
    challenge = _challenge(challenge_id, remotes=remotes)
    run = bind_input_fingerprint(workspace, challenge, fingerprint)
    return workspace, run, challenge


def _spec(session_id: str = "race-1") -> RaceBranchSpec:
    return RaceBranchSpec.from_mapping({
        "session_id": session_id, "role": "independent-full-solve",
        "hypothesis_family": "independent", "hypothesis": "race for flag",
        "scope": ["challenge-input"], "tool_strategy": ["direct-test"],
        "expected_artifacts": [f"artifacts/{session_id}.py"],
    }, index=0)


def _plan_one(run: Path, challenge_id: str, fingerprint: str = "fp", session_id: str = "race-1") -> None:
    start_race_plan(
        run, challenge_id=challenge_id, input_fingerprint=fingerprint,
        parent_session_id="sol-main", category="misc", tier=0, tier_reason="optional",
        branch_specs=[_spec(session_id)],
    )


def _start_one(run: Path, challenge_id: str, fingerprint: str = "fp", session_id: str = "race-1") -> None:
    _plan_one(run, challenge_id, fingerprint, session_id)
    record_capacity_admission(run, input_fingerprint=fingerprint, admitted_session_ids=[session_id])
    metadata = run / "workers" / session_id / "sandbox.json"
    metadata.parent.mkdir(parents=True)
    metadata.write_text("{}", encoding="utf-8")
    record_branch_sandbox_ready(
        run, input_fingerprint=fingerprint, session_id=session_id,
        sandbox_metadata_path=str(metadata), input_available=True,
    )
    confirm_branch_start(
        run, input_fingerprint=fingerprint, replacement_request_id="initial-race",
        session_id=session_id, native_session_observed=f"native-{session_id}",
        runtime_observation_evidence="native session receipt",
        sandbox_metadata_path=str(metadata),
    )


def _remote_flag(run: Path, challenge_id: str, *, fingerprint: str = "fp", branch_id: str = "sol-main", candidate: str = "CTF{winner}", target_revision: int | None = None) -> dict[str, object]:
    exploit = run / "exploit" / "solve.py"
    exploit.parent.mkdir(exist_ok=True)
    exploit.write_text("print('flag')\n", encoding="utf-8")
    return record_remote_flag(
        run, challenge_id=challenge_id, input_fingerprint=fingerprint, branch_id=branch_id,
        declared_targets=parse_remotes(("tcp://8.8.8.8:31337",)),
        observed_host="8.8.8.8", observed_port=31337, observed_protocol="tcp",
        network_observed=True, output=f"service: {candidate}", candidate=candidate,
        flag_pattern=r"\ACTF\{[^}]+\}\Z", command_argv=["python3", "exploit/solve.py"],
        exploit_artifact="exploit/solve.py", target_revision=target_revision,
    )


def _iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def test_fingerprint_generation_preserves_verified_run_and_active_pointer(tmp_path: Path) -> None:
    workspace, first, challenge = _run(tmp_path, remotes=("tcp://8.8.8.8:31337",))
    receipt = _remote_flag(first, challenge.id)
    old_state = json.loads((first / "STATE.json").read_text())
    second = bind_input_fingerprint(workspace, challenge, "fp-2")

    assert second != first
    assert resolve_active_run(workspace) == second
    assert json.loads((first / "STATE.json").read_text()) == old_state
    assert Path(str(receipt["receipt"])).is_file()
    assert json.loads((second / "STATE.json").read_text())["flag_candidate"] is None


def test_legacy_migration_is_idempotent_and_preserves_receipts(tmp_path: Path) -> None:
    workspace = tmp_path / "legacy"
    workspace.mkdir()
    (workspace / "STATE.json").write_text(json.dumps({
        "challenge_id": "legacy", "input_fingerprint": "old-fp", "target_revision": 1,
        "status": "SUBMISSION_RECOMMENDED", "flag_candidate": "CTF{old}",
        "remote_flag_receipt": "flag-receipts/remote-old.json", "flag_history": [{"candidate": "CTF{old}"}],
    }))
    receipts = workspace / "flag-receipts"
    receipts.mkdir()
    (receipts / "remote-old.json").write_text('{"candidate":"CTF{old}"}\n')

    first = resolve_active_run(workspace)
    pointer = (workspace / "ACTIVE_RUN.json").read_bytes()
    second = resolve_active_run(workspace)

    assert first == second
    assert (workspace / "ACTIVE_RUN.json").read_bytes() == pointer
    assert (first / "flag-receipts" / "remote-old.json").is_file()
    assert json.loads((first / "STATE.json").read_text())["flag_history"] == [{"candidate": "CTF{old}"}]
    (workspace / "flag-receipts" / "late-recovery.json").write_text('{"recovered":true}\n')
    (workspace / "ACTIVE_RUN.json").unlink()
    recovered = resolve_active_run(workspace)
    assert recovered == first
    assert (first / "flag-receipts" / "late-recovery.json").is_file()


@pytest.mark.parametrize("event_type", ["REMOTE_FLAG_OBTAINED", "SUBMISSION_RECOMMENDED", "ACCEPTED"])
def test_protected_events_reject_general_publish(tmp_path: Path, event_type: str) -> None:
    _workspace, run, challenge = _run(tmp_path)
    with pytest.raises(Exception, match="verified receipt"):
        publish_event(
            run, challenge_id=challenge.id, input_fingerprint="fp", session_id="sol-main",
            event_type=event_type, summary="bypass",
        )
    state = json.loads((run / "STATE.json").read_text())
    assert state["flag_candidate"] is None and state["remote_flag_receipt"] is None
    if event_type == "REMOTE_FLAG_OBTAINED":
        with pytest.raises(Exception, match="verified lifecycle receipt"):
            evaluate_race_transition(run, event_type, "sol-main", "fp")
        state = json.loads((run / "STATE.json").read_text())
        assert state["status"] == "PREPARED"


def test_malformed_event_ledger_is_explicit_and_writes_recovery_note(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    (run / "race-events.jsonl").write_text("{malformed\n", encoding="utf-8")
    with pytest.raises(Exception, match="malformed"):
        publish_event(
            run, challenge_id=challenge.id, input_fingerprint="fp", session_id="sol-main",
            event_type="SUPPORTED_FACT", summary="must not ignore corruption",
        )
    assert list(run.glob("race-events.jsonl.recovery-*.txt"))


def test_event_projection_retries_and_malformed_plan_is_not_treated_as_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    import ctf_os.resources.scheduler as scheduler_module
    monkeypatch.setattr(
        scheduler_module, "note_race_event",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("scheduler offline")),
    )
    first = publish_event(
        run, challenge_id=challenge.id, input_fingerprint="fp", session_id="sol-main",
        event_type="SUPPORTED_FACT", summary="one persisted fact", event_id="fact-one",
    )
    second = publish_event(
        run, challenge_id=challenge.id, input_fingerprint="fp", session_id="sol-main",
        event_type="SUPPORTED_FACT", summary="one persisted fact", event_id="fact-one",
    )
    assert first["post_commit_warnings"] and second["idempotent"] is True
    assert len((run / "race-events.jsonl").read_text().splitlines()) == 1
    assert len((run / "scheduler-errors.jsonl").read_text().splitlines()) == 2

    (run / "DELEGATION_PLAN.json").write_text("{malformed\n", encoding="utf-8")
    with pytest.raises(Exception, match="valid JSON"):
        evaluate_race_transition(run, "DECISIVE_EXPERIMENT", "sol-main", "fp")


def test_remote_receipt_atomic_projection_idempotence_and_identity_gates(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path, remotes=("tcp://8.8.8.8:31337",))
    first = _remote_flag(run, challenge.id, target_revision=1)
    second = _remote_flag(run, challenge.id, target_revision=1)
    state = json.loads((run / "STATE.json").read_text())
    candidates = load_candidates(run)["candidates"]

    assert second["idempotent"] is True
    assert state["status"] == "SUBMISSION_RECOMMENDED"
    assert state["flag_candidate"] == "CTF{winner}" and state["remote_flag_receipt"]
    assert len(state["flag_history"]) == 1 and len(candidates) == 1
    assert first["candidate_id"] == candidates[0]["candidate_id"]
    assert "CTF{winner}" in (run / "RESULT.md").read_text()
    with pytest.raises(Exception, match="immutable"):
        publish_event(
            run, challenge_id=challenge.id, input_fingerprint="fp", session_id="sol-main",
            event_type="SUPPORTED_FACT", summary="late mutation",
        )
    with pytest.raises(Exception, match="convergence stop"):
        create_control_action(
            run, session_id="sol-main", action_type="REPLACE_ATTACK_FAMILY",
            reason="must not mutate a verified run", triggering_evidence_id="late",
            evidence_generation=2,
        )
    with pytest.raises(FastFlagError, match="immutable"):
        _remote_flag(run, challenge.id, candidate="CTF{other}")
    with pytest.raises(Exception, match="fingerprint"):
        _remote_flag(run, challenge.id, fingerprint="wrong")
    with pytest.raises(Exception, match="revision"):
        _remote_flag(run, challenge.id, target_revision=2)


def test_remote_receipt_survives_optional_event_projection_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _workspace, run, challenge = _run(tmp_path, remotes=("tcp://8.8.8.8:31337",))
    import ctf_os.events as event_module
    monkeypatch.setattr(event_module, "publish_verified_event", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("event bus offline")))

    result = _remote_flag(run, challenge.id)
    state = json.loads((run / "STATE.json").read_text())

    assert result["state"] == "SUBMISSION_RECOMMENDED"
    assert result["post_commit_warnings"]
    assert state["flag_candidate"] == "CTF{winner}" and state["remote_flag_receipt"]
    assert (run / "post-commit-errors.jsonl").is_file()


def test_remote_receipt_rejects_symlinked_exploit_artifact(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path, remotes=("tcp://8.8.8.8:31337",))
    outside = tmp_path / "outside.py"
    outside.write_text("print('CTF{winner}')\n", encoding="utf-8")
    exploit = run / "exploit"
    exploit.mkdir()
    (exploit / "solve.py").symlink_to(outside)
    with pytest.raises(FastFlagError, match="unsafe"):
        record_remote_flag(
            run, challenge_id=challenge.id, input_fingerprint="fp", branch_id="sol-main",
            declared_targets=parse_remotes(("tcp://8.8.8.8:31337",)),
            observed_host="8.8.8.8", observed_port=31337, observed_protocol="tcp",
            network_observed=True, output="CTF{winner}", candidate="CTF{winner}",
            flag_pattern=r"\ACTF\{[^}]+\}\Z", command_argv=["python3", "exploit/solve.py"],
            exploit_artifact="exploit/solve.py",
        )


def test_low_remote_candidate_does_not_freeze_the_run(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path, remotes=("tcp://8.8.8.8:31337",))
    candidate = _remote_flag(run, challenge.id, candidate="CTF{example}")
    state = json.loads((run / "STATE.json").read_text())
    assert candidate["state"] == "FLAG_CANDIDATE"
    assert state["remote_flag_receipt"] is None and state["remote_candidate_receipt"]
    event = publish_event(
        run, challenge_id=challenge.id, input_fingerprint="fp", session_id="sol-main",
        event_type="SUPPORTED_FACT", summary="continue after low-confidence candidate",
    )
    assert event["type"] == "SUPPORTED_FACT"


def test_truthful_branch_width_requires_sandbox_input_and_native_receipt(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    _plan_one(run, challenge.id)
    planned = race_board(load_plan(run, input_fingerprint="fp"))
    assert (planned["planned_width"], planned["admitted_width"], planned["native_started_width"], planned["running_width"]) == (1, 0, 0, 0)
    assert planned["active_branches"] == [] and planned["native_children_created"] is False

    record_capacity_admission(run, input_fingerprint="fp", admitted_session_ids=["race-1"])
    metadata = run / "workers" / "race-1" / "sandbox.json"
    metadata.parent.mkdir(parents=True)
    metadata.write_text("{}")
    record_branch_sandbox_ready(
        run, input_fingerprint="fp", session_id="race-1",
        sandbox_metadata_path=str(metadata), input_available=True,
    )
    before_start = race_board(load_plan(run, input_fingerprint="fp"))
    assert before_start["admitted_width"] == 1 and before_start["running_width"] == 0
    confirm_branch_start(
        run, input_fingerprint="fp", replacement_request_id="initial-race", session_id="race-1",
        native_session_observed="native-race-1", runtime_observation_evidence="tree receipt",
        sandbox_metadata_path=str(metadata),
    )
    running = race_board(load_plan(run, input_fingerprint="fp"))
    assert running["native_started_width"] == running["running_width"] == 1
    assert [row["session_id"] for row in running["active_branches"]] == ["race-1"]


def test_invalid_native_branch_transition_cannot_claim_running(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    _plan_one(run, challenge.id)
    with pytest.raises(Exception, match="invalid native branch transition"):
        update_branch(run, input_fingerprint="fp", session_id="race-1", status="RUNNING")
    board = race_board(load_plan(run, input_fingerprint="fp"))
    assert board["running_width"] == 0 and board["active_branches"] == []


def test_verified_remote_flag_requests_race_convergence_with_one_verifier(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path, remotes=("tcp://8.8.8.8:31337",))
    specs = [_spec("flagger"), _spec("low-value"), RaceBranchSpec.from_mapping({
        "session_id": "verifier", "role": "clean-room-verifier",
        "hypothesis_family": "verification", "hypothesis": "independently verify exact bytes",
        "scope": ["challenge-input"], "tool_strategy": ["validator"],
        "expected_artifacts": ["artifacts/verifier.txt"], "purpose": "clean-room-verification",
    }, index=2)]
    start_race_plan(
        run, challenge_id=challenge.id, input_fingerprint="fp", parent_session_id="sol-main",
        category="misc", tier=0, tier_reason="optional convergence", branch_specs=specs,
    )
    result = _remote_flag(run, challenge.id, branch_id="flagger")
    plan = load_plan(run, input_fingerprint="fp")
    statuses = {row["session_id"]: row["status"] for row in plan["branches"]}
    actions = result["race_transition"]["control_actions"]
    assert statuses["low-value"] == "STOP_REQUESTED"
    assert statuses["verifier"] == "PLANNED"
    assert any(row["session_id"] == "low-value" and row["action_type"] == "STOP_LOW_VALUE_BRANCH" for row in actions)


def test_child_input_failure_does_not_block_sol_milestone(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    _plan_one(run, challenge.id)
    record_capacity_admission(run, input_fingerprint="fp", admitted_session_ids=["race-1"])
    record_branch_sandbox_ready(
        run, input_fingerprint="fp", session_id="race-1",
        sandbox_metadata_path="workers/race-1/sandbox.json", input_available=False,
    )
    milestone = save_milestone(
        run, challenge_id=challenge.id, session_id="sol-main", input_fingerprint="fp",
        event_type="DECISIVE_EXPERIMENT", summary="Sol killed the leading parser theory",
        command_argv=["python3", "probe.py"], output="control matched",
        details={"decision": "KILL"}, exploit_proximity=.2,
    )
    board = race_board(load_plan(run, input_fingerprint="fp"))
    assert milestone["session_id"] == "sol-main" and milestone["progress"]["counts_as_progress"]
    assert board["running_width"] == 0 and board["sol_lane"]["status"] == "RUNNING"


def test_sol_and_child_share_typed_milestone_schema(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    sol = save_milestone(
        run, challenge_id=challenge.id, session_id="sol-main", input_fingerprint="fp",
        event_type="PRIMITIVE_CANDIDATE", summary="candidate oracle", evidence=["evidence/sol.txt"],
        command_argv=["python3", "probe.py"], output="delta", exploit_proximity=.4,
    )
    child = save_milestone(
        run, challenge_id=challenge.id, session_id="race-1", input_fingerprint="fp",
        event_type="CHILD_TERMINAL_RESULT", summary="independent family refuted",
        evidence=["evidence/child.txt"], output="no alias", exploit_proximity=.1,
    )
    required = {
        "run_id", "challenge_id", "session_id", "input_fingerprint", "target_revision",
        "sequence", "event_type", "summary", "evidence", "artifacts", "command_digest",
        "output_digest", "output_excerpt", "exploit_proximity", "created_at",
    }
    assert required <= sol.keys() and required <= child.keys()
    assert [row["session_id"] for row in load_milestones(run)] == ["sol-main", "race-1"]


def test_command_drift_supported_fact_and_decisive_reset(tmp_path: Path) -> None:
    _workspace, run, _challenge_spec = _run(tmp_path)
    last = None
    for number in range(6):
        last = record_command(
            run, session_id="sol-main", command_argv=["file", f"input-{number}"], category="misc",
        )
    assert last and last["gate"]["triggered"]
    unsupported = register_milestone(run, {
        "receipt_id": "fact-only", "session_id": "sol-main", "event_type": "SUPPORTED_FACT",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }, declared_remote=False)
    assert unsupported["counts_as_progress"] is False
    assert evaluate_progress_gate(run, session_id="sol-main", category="misc")["triggered"]
    reset = register_milestone(run, {
        "receipt_id": "refuted-family", "session_id": "sol-main", "event_type": "PRIMITIVE_REFUTED",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }, declared_remote=False)
    assert reset["counts_as_progress"] is True
    assert not evaluate_progress_gate(run, session_id="sol-main", category="misc")["triggered"]


def test_long_compute_is_bounded_by_heartbeat_and_maximum_duration(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    receipt = save_milestone(
        run, challenge_id=challenge.id, session_id="sol-main", input_fingerprint="fp",
        event_type="LONG_COMPUTE", summary="bounded symbolic execution",
        command_argv=["angr", "solve.py"], exploit_proximity=.3,
        details={
            "process_identity": "pid-receipt-1", "expected_output_artifact": "artifacts/model.json",
            "expected_completion_signal": "model.json exists", "maximum_duration_seconds": 300,
            "checkpoint_interval_seconds": 60, "resource_requirement": {"cpus": 2},
            "cancel_condition": "no constraint reduction", "fallback_plan": "manual backward slice",
        },
    )
    created = _iso(str(receipt["created_at"]))
    valid_at = (created + timedelta(seconds=30)).isoformat()
    assert not evaluate_progress_gate(run, session_id="sol-main", category="misc", now=valid_at)["triggered"]
    heartbeat_long_compute(
        run, session_id="sol-main", receipt_id=str(receipt["receipt_id"]), artifact_changed=True,
        observed_at=(created + timedelta(seconds=50)).isoformat(),
    )
    assert not evaluate_progress_gate(
        run, session_id="sol-main", category="misc", now=(created + timedelta(seconds=100)).isoformat(),
    )["triggered"]
    stale = evaluate_progress_gate(
        run, session_id="sol-main", category="misc", now=(created + timedelta(seconds=111)).isoformat(),
    )
    assert stale["triggered"] and stale["action"]["action_type"] == "LONG_COMPUTE_REVIEW"


def test_control_action_deduplicates_until_new_evidence_generation(tmp_path: Path) -> None:
    _workspace, run, _challenge_spec = _run(tmp_path)
    first = create_control_action(
        run, session_id="sol-main", action_type="REPLACE_ATTACK_FAMILY", reason="plateau",
        triggering_evidence_id="command-6", evidence_generation=0,
    )
    duplicate = create_control_action(
        run, session_id="sol-main", action_type="REPLACE_ATTACK_FAMILY", reason="same plateau",
        triggering_evidence_id="command-7", evidence_generation=0,
    )
    acknowledge_control_action(run, action_id=str(first["action_id"]), status="ACKED_DECLINED")
    still_same = create_control_action(
        run, session_id="sol-main", action_type="REPLACE_ATTACK_FAMILY", reason="same plateau",
        triggering_evidence_id="command-8", evidence_generation=0,
    )
    next_generation = create_control_action(
        run, session_id="sol-main", action_type="REPLACE_ATTACK_FAMILY", reason="new decisive evidence",
        triggering_evidence_id="primitive-refuted", evidence_generation=1,
    )
    assert duplicate["idempotent"] and still_same["idempotent"]
    assert next_generation["action_id"] != first["action_id"]
    assert len(load_control_actions(run)) == 2


def test_working_poc_remote_deadlines_attempt_and_typed_blocker(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path, remotes=("tcp://8.8.8.8:31337",))
    poc = save_milestone(
        run, challenge_id=challenge.id, session_id="sol-main", input_fingerprint="fp",
        event_type="WORKING_POC", summary="local exploit works", artifacts=["artifacts/poc.py"],
        exploit_proximity=.8, declared_remote=True,
    )
    deadline = poc["progress"]["remote_transition"]
    soft = _iso(deadline["soft_deadline_at"])
    action = evaluate_remote_transition(
        run, session_id="sol-main", now=(soft + timedelta(seconds=1)).isoformat(),
    )
    assert action["triggered"] and action["action"]["action_type"] == "REMOTE_ATTEMPT_REQUIRED"
    blocker = save_milestone(
        run, challenge_id=challenge.id, session_id="sol-main", input_fingerprint="fp",
        event_type="TYPED_BLOCKER", summary="service rate limited",
        details={"blocker_type": "RATE_LIMITED", "evidence": "HTTP 429 receipt"},
        exploit_proximity=.8, declared_remote=True,
    )
    assert blocker["progress"]["remote_transition"]["status"] == "SATISFIED"
    assert blocker["progress"]["remote_transition"]["satisfaction_type"] == "RATE_LIMITED"


def test_remote_attempt_satisfies_deadline_and_local_only_has_none(tmp_path: Path) -> None:
    _workspace, remote_run, remote_challenge = _run(tmp_path / "remote", remotes=("tcp://8.8.8.8:31337",))
    save_milestone(
        remote_run, challenge_id=remote_challenge.id, session_id="sol-main", input_fingerprint="fp",
        event_type="WORKING_POC", summary="PoC", declared_remote=True,
    )
    attempt = save_milestone(
        remote_run, challenge_id=remote_challenge.id, session_id="sol-main", input_fingerprint="fp",
        event_type="REMOTE_ATTEMPT", summary="declared target attempted",
        command_argv=["python3", "exploit.py", "8.8.8.8", "31337"], output="connected",
        declared_remote=True,
    )
    assert attempt["progress"]["remote_transition"]["status"] == "SATISFIED"
    _workspace2, local_run, local_challenge = _run(tmp_path / "local", challenge_id="local")
    local = save_milestone(
        local_run, challenge_id=local_challenge.id, session_id="sol-main", input_fingerprint="fp",
        event_type="WORKING_POC", summary="offline PoC", declared_remote=False,
    )
    assert local["progress"]["remote_transition"] is None


def test_static_candidate_exactness_gate(tmp_path: Path) -> None:
    low = build_candidate(
        run_id="run-1", session_id="sol-main", candidate="CTF{static}",
        source_type="STATIC_ANALYSIS", receipt_id="extract-1", confidence="HIGH",
        validation_method="FORMAT_ONLY", status="PROPOSED",
    )
    assert low["confidence"] == "MEDIUM"
    with pytest.raises(CandidateError, match="exact-byte"):
        build_candidate(
            run_id="run-1", session_id="sol-main", candidate="CTF{static}",
            source_type="STATIC_ANALYSIS", receipt_id="extract-1", confidence="HIGH",
            validation_method="FORMAT_ONLY", status="ACCEPTED",
        )
    _workspace, run, _challenge_spec = _run(tmp_path / "state")
    with pytest.raises(CandidateError, match="flag-receipt-save"):
        record_candidate(
            run, session_id="sol-main", candidate="CTF{forged}", source_type="REMOTE_OUTPUT",
            receipt_id="forged", confidence="HIGH", validation_method="REMOTE_SERVICE_ACCEPTANCE",
            status="SUBMISSION_RECOMMENDED",
        )
    with pytest.raises(CandidateError, match="human feedback"):
        record_candidate(
            run, session_id="sol-main", candidate="CTF{forged}", source_type="STATIC_ANALYSIS",
            receipt_id="validator", confidence="HIGH", validation_method="ORIGINAL_VALIDATOR",
            status="ACCEPTED",
        )


def test_wrong_refutes_exact_candidate_and_challenges_are_isolated(tmp_path: Path) -> None:
    _wa, run_a, challenge_a = _run(tmp_path / "a", challenge_id="a", remotes=("tcp://8.8.8.8:31337",))
    _wb, run_b, challenge_b = _run(tmp_path / "b", challenge_id="b", remotes=("tcp://8.8.8.8:31337",))
    candidate_a = _remote_flag(run_a, challenge_a.id, candidate="CTF{a}")
    candidate_b = _remote_flag(run_b, challenge_b.id, candidate="CTF{b}")
    before_b = (run_b / "candidates.json").read_bytes()
    wrong = record_submission_result(
        run_a, run_id=run_a.name, candidate_id=str(candidate_a["candidate_id"]), result="wrong",
    )
    state_a = json.loads((run_a / "STATE.json").read_text())

    assert wrong["result"] == "WRONG" and state_a["status"] == "SOLVING"
    assert state_a["active_candidate_id"] is None and state_a["flag_candidate"] is None
    assert state_a["remote_flag_receipt"] is None
    assert load_candidates(run_a)["candidates"][0]["status"] == "REFUTED"
    with pytest.raises(FastFlagError, match="refuted"):
        _remote_flag(run_a, challenge_a.id, candidate="CTF{a}")
    assert (run_b / "candidates.json").read_bytes() == before_b
    assert load_candidates(run_b)["candidates"][0]["candidate_id"] == candidate_b["candidate_id"]


def test_wrong_non_active_candidate_preserves_active_remote_candidate(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path, remotes=("tcp://8.8.8.8:31337",))
    local = record_candidate(
        run, session_id="sol-main", candidate="CTF{static}", source_type="STATIC_ANALYSIS",
        receipt_id="validator-receipt", confidence="MEDIUM", validation_method="ORIGINAL_VALIDATOR",
        status="VALIDATED_LOCAL",
    )
    remote = _remote_flag(run, challenge.id)
    before = json.loads((run / "STATE.json").read_text())
    record_submission_result(
        run, run_id=run.name, candidate_id=str(local["candidate_id"]), result="wrong",
    )
    after = json.loads((run / "STATE.json").read_text())
    assert after["active_candidate_id"] == remote["candidate_id"] == before["active_candidate_id"]
    assert after["status"] == "SUBMISSION_RECOMMENDED" and after["remote_flag_receipt"]


def test_accepted_starts_terminal_convergence_and_cleanup_is_idempotent(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path, remotes=("tcp://8.8.8.8:31337",))
    _start_one(run, challenge.id)
    ledger = ResourceLedger(run)
    ledger.request(
        default_request(
            contest="contest", challenge_id=challenge.id, session_id="race-1",
            workload_class="quick-recon",
        ),
        actor_session_id="sol-main", actor_role="sol",
    )
    candidate = _remote_flag(run, challenge.id, branch_id="race-1")
    accepted = record_submission_result(
        run, run_id=run.name, candidate_id=str(candidate["candidate_id"]), result="accepted",
    )
    plan = load_plan(run, input_fingerprint="fp")
    assert accepted["result"] == "ACCEPTED"
    assert next(row for row in plan["branches"] if row["session_id"] == "race-1")["status"] == "STOP_REQUESTED"
    assert accepted["stop_actions"][0]["action_type"] == "STOP_REQUIRED"
    calls = {"sandbox": 0, "resource": 0}
    def cleanup(_metadata: Path, _session_id: str) -> dict[str, object]:
        calls["sandbox"] += 1
        return {"cleaned": True}
    def release(_session_id: str) -> dict[str, object]:
        calls["resource"] += 1
        return ledger.release(
            _session_id, "terminal test", actor_session_id="sol-main", actor_role="sol",
        )

    pending = converge_terminal(
        run, run_id=run.name, sandbox_cleanup=cleanup, resource_release=release,
    )
    assert pending["cleanup_state"] == "TERMINATION_PENDING"
    assert pending["verified_flag_preserved"] is True
    assert calls == {"sandbox": 0, "resource": 0}
    terminal_milestone = save_milestone(
        run, challenge_id=challenge.id, session_id="race-1", input_fingerprint="fp",
        event_type="CHILD_TERMINAL_RESULT", summary="child stopped after ACCEPTED",
        details={"status": "TERMINATED"},
    )
    assert terminal_milestone["progress"]["terminal_lifecycle"] is True
    assert next(
        row for row in load_plan(run, input_fingerprint="fp")["branches"]
        if row["session_id"] == "race-1"
    )["status"] == "TERMINATED"
    with pytest.raises(Exception, match="immutable"):
        record_candidate(
            run, session_id="sol-main", candidate="CTF{later}", source_type="STATIC",
            confidence="LOW", validation_method="UNVALIDATED",
        )

    clean = converge_terminal(run, run_id=run.name, sandbox_cleanup=cleanup, resource_release=release)
    repeated = converge_terminal(run, run_id=run.name, sandbox_cleanup=cleanup, resource_release=release)
    assert clean["status"] == repeated["status"] == "SEALED_CLEAN"
    assert calls == {"sandbox": 1, "resource": 1}
    assert terminal_status(run)["verified_flag_preserved"] is True


def test_terminal_convergence_tracks_resource_only_sessions(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path, remotes=("tcp://8.8.8.8:31337",))
    ledger = ResourceLedger(run)
    ledger.request(
        default_request(contest="contest", challenge_id=challenge.id, session_id="sol-main", workload_class="quick-recon"),
        actor_session_id="sol-main", actor_role="sol",
    )
    candidate = _remote_flag(run, challenge.id)
    record_submission_result(
        run, run_id=run.name, candidate_id=str(candidate["candidate_id"]), result="accepted",
    )
    pending = converge_terminal(run, run_id=run.name)
    assert pending["status"] == "SEALED"
    assert pending["components"]["sol-main"]["resource"] == "RELEASE_PENDING"

    clean = converge_terminal(
        run, run_id=run.name,
        resource_release=lambda session_id: ledger.release(
            session_id, "accepted", actor_session_id="sol-main", actor_role="sol",
        ),
    )
    assert clean["status"] == "SEALED_CLEAN"


def test_native_stop_receipt_is_an_idempotent_terminal_alternative(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(
        tmp_path, remotes=("tcp://8.8.8.8:31337",),
    )
    _start_one(run, challenge.id)
    candidate = _remote_flag(run, challenge.id, branch_id="race-1")
    record_submission_result(
        run, run_id=run.name, candidate_id=str(candidate["candidate_id"]), result="accepted",
    )
    first = record_native_stop(
        run, run_id=run.name, session_id="race-1", native_receipt={"result": "native stopped"},
    )
    second = record_native_stop(
        run, run_id=run.name, session_id="race-1", native_receipt={"result": "native stopped"},
    )
    assert first["idempotent"] is False and second["idempotent"] is True
    clean = converge_terminal(
        run, run_id=run.name,
        sandbox_cleanup=lambda _path, _session: {"cleaned": True},
        resource_release=lambda _session: {"released": True},
    )
    assert clean["status"] == "SEALED_CLEAN"


def test_cleanup_failure_preserves_flag_and_is_retriable(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(
        tmp_path, remotes=("tcp://8.8.8.8:31337",),
    )
    _start_one(run, challenge.id)
    candidate = _remote_flag(run, challenge.id, branch_id="race-1")
    record_submission_result(
        run, run_id=run.name, candidate_id=str(candidate["candidate_id"]), result="accepted",
    )
    record_native_stop(
        run, run_id=run.name, session_id="race-1", native_receipt={"result": "native stopped"},
    )
    failed = converge_terminal(
        run, run_id=run.name,
        sandbox_cleanup=lambda _path, _session: (_ for _ in ()).throw(RuntimeError("cleanup failed")),
    )
    assert failed["status"] == "SEALED"
    assert failed["verified_flag_preserved"] is True
    assert failed["components"]["race-1"]["sandbox"] == "CLEANUP_FAILED"
    clean = converge_terminal(
        run, run_id=run.name,
        sandbox_cleanup=lambda _path, _session: {"cleaned": True},
    )
    assert clean["status"] == "SEALED_CLEAN"
    assert clean["verified_flag_preserved"] is True


def test_accepted_and_resource_release_do_not_cross_challenge_boundary(tmp_path: Path) -> None:
    _wa, run_a, challenge_a = _run(tmp_path / "a", challenge_id="a", remotes=("tcp://8.8.8.8:31337",))
    _wb, run_b, challenge_b = _run(tmp_path / "b", challenge_id="b")
    _start_one(run_a, challenge_a.id, session_id="a-child")
    _plan_one(run_b, challenge_b.id, session_id="b-child")
    ledger_b = ResourceLedger(run_b)
    ledger_b.request(
        default_request(contest="contest", challenge_id="b", session_id="b-child", workload_class="quick-recon"),
        actor_session_id="sol-main", actor_role="sol",
    )
    resource_b = (run_b / "RESOURCE_STATE.json").read_bytes()
    event = publish_event(
        run_a, challenge_id="a", input_fingerprint="fp", session_id="sol-main",
        event_type="SUPPORTED_FACT", summary="A-only fact", useful_for=["a-child"],
    )
    assert event["challenge_id"] == "a"
    assert insight_packet(run_b, input_fingerprint="fp", target_session_id="b-child")["events"] == []
    candidate = _remote_flag(run_a, challenge_a.id, branch_id="a-child")
    record_submission_result(
        run_a, run_id=run_a.name, candidate_id=str(candidate["candidate_id"]), result="accepted",
    )
    assert next(row for row in load_plan(run_b, input_fingerprint="fp")["branches"] if row["session_id"] == "b-child")["status"] == "PLANNED"
    assert (run_b / "RESOURCE_STATE.json").read_bytes() == resource_b


def test_target_revisions_are_append_only_and_bind_receipts(tmp_path: Path) -> None:
    workspace, first, challenge = _run(tmp_path, remotes=("tcp://8.8.8.8:31337",))
    assert json.loads((first / "STATE.json").read_text())["target_revision"] == 1
    revision = record_target_revision(workspace, ["tcp://8.8.4.4:4444"], source="operator correction")
    assert revision == 2
    changed = _challenge(challenge.id, remotes=("tcp://8.8.4.4:4444",))
    second = bind_input_fingerprint(workspace, changed, "fp", target_revision=revision)
    assert second != first and json.loads((second / "STATE.json").read_text())["target_revision"] == 2
    assert [row["target_revision"] for row in target_revisions(workspace)] == [1, 2]
    with pytest.raises(Exception, match="revision"):
        _remote_flag(second, challenge.id, target_revision=1)


def test_manifest_records_reproducibility_without_guessing_runtime(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    manifest = json.loads((run / "RUN_MANIFEST.json").read_text())
    assert manifest["challenge"] == {
        "challenge_id": challenge.id, "run_id": run.name,
        "input_fingerprint": "fp", "target_revision": 1,
    }
    assert manifest["runtime"]["observed_model"] is None
    assert manifest["runtime"]["observed_reasoning"] is None
    assert manifest["repository"]["commit_sha"] is not None


def test_remote_parser_rejects_newline_port_truncation() -> None:
    with pytest.raises(NetworkPolicyError):
        parse_remotes(("nc example.com\n31337",))
    challenge = _challenge("selector")
    with pytest.raises(SelectionError, match="exact line"):
        resolve_selector((challenge,), "misc/selector\nignored")


def test_cli_closes_prepare_receipt_human_accepted_and_cleanup(repo: Path) -> None:
    write_contest(repo, """# Demo CTF
- Flag format: CTF{...}
### misc/X
- Description: remote-only
- Remote: tcp://8.8.8.8:31337
""")
    base = ["python", "-m", "ctf_os.agent_tools", "--repo", str(repo)]
    prepared = subprocess.run(
        [*base, "prepare-challenge", "misc/X", "--contest", "Demo CTF"],
        capture_output=True, text=True,
    )
    assert prepared.returncode == 0, prepared.stdout + prepared.stderr
    payload = json.loads(prepared.stdout)["result"]
    run = Path(payload["run_root"])
    milestone = subprocess.run([
        *base, "milestone-save", "misc/X", "--contest", "Demo CTF",
        "--type", "DECISIVE_EXPERIMENT", "--summary", "parser theory refuted",
        "--details-json", '{"decision":"KILL"}', "--", "python3", "probe.py",
    ], capture_output=True, text=True)
    assert milestone.returncode == 0, milestone.stdout + milestone.stderr
    milestone_result = json.loads(milestone.stdout)["result"]
    assert milestone_result["session_id"] == "sol-main"
    assert milestone_result["progress"]["counts_as_progress"] is True
    exploit = run / "exploit" / "solve.py"
    exploit.parent.mkdir()
    exploit.write_text("print('CTF{cli_winner}')\n")
    flag = subprocess.run([
        *base, "flag-receipt-save", "--contest", "Demo CTF",
        "--branch", "sol-main", "--host", "8.8.8.8", "--port", "31337",
        "--protocol", "tcp", "--network-observed", "--output", "CTF{cli_winner}",
        "--candidate", "CTF{cli_winner}", "--exploit-artifact", "exploit/solve.py",
        "misc/X", "--", "python3", "exploit/solve.py",
    ], capture_output=True, text=True)
    assert flag.returncode == 0, flag.stdout + flag.stderr
    flag_result = json.loads(flag.stdout)["result"]
    accepted = subprocess.run([
        *base, "submission-result", "misc/X", "--contest", "Demo CTF",
        "--run-id", payload["run_id"], "--candidate-id", flag_result["candidate_id"],
        "--result", "accepted",
    ], capture_output=True, text=True)
    assert accepted.returncode == 0, accepted.stdout + accepted.stderr
    result = json.loads(accepted.stdout)["result"]
    state = json.loads((run / "STATE.json").read_text())
    assert result["result"] == "ACCEPTED"
    assert state["status"] == "SEALED_CLEAN" and state["competition_state"] == "ACCEPTED"
    assert state["submission_history"][0]["candidate_id"] == flag_result["candidate_id"]
