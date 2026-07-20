from __future__ import annotations

from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from ctf_os.candidates import load_candidates
from ctf_os.contest import ChallengeSpec, ContestManifest
from ctf_os.control import (
    ControlActionError, acknowledge_control_action, apply_control_action,
    create_control_action, load_control_actions,
)
from ctf_os.race import RaceBranchSpec, start_race_plan
from ctf_os.milestones import load_milestones, repair_run_projections, save_milestone
from ctf_os.progress import heartbeat_long_compute
from ctf_os.preflight import prepared_input_bytes
from ctf_os.resources.scheduler import GIB, HostCapacity, default_request, plan_allocations
from ctf_os.sandbox.network import parse_remotes
from ctf_os.session_input import (
    parse_session_input, resolve_session_challenge, session_input_fingerprint,
    session_source_paths,
)
from ctf_os.terminal import (
    converge_terminal, record_submission_result, record_terminal_component,
)
from ctf_os.transitions import evaluate_race_transition
from ctf_os.verification import record_remote_flag
from ctf_os.workspace import (
    WorkspaceError, bind_input_fingerprint, recover_run_state, resolve_active_run,
)
from ctf_os.working_poc import (
    WorkingPocError, commit_working_poc, resolve_unknown_working_poc,
)


def _challenge(challenge_id: str = "challenge") -> SimpleNamespace:
    return SimpleNamespace(
        id=challenge_id, key=f"misc/{challenge_id}", category="misc", name=challenge_id,
        remotes=("tcp://8.8.8.8:31337",), description=challenge_id, hint=None,
        flag_format="CTF{...}", flag_pattern=r"\ACTF\{[^}]+\}\Z",
        input_profile="standard",
    )


def _run(tmp_path: Path) -> tuple[Path, Path, SimpleNamespace]:
    workspace = tmp_path / "challenge"
    (workspace / "input").mkdir(parents=True)
    challenge = _challenge()
    return workspace, bind_input_fingerprint(workspace, challenge, "fp"), challenge


def _milestone(run: Path, challenge: SimpleNamespace, **changes):
    values = {
        "challenge_id": challenge.id, "session_id": "sol-main",
        "input_fingerprint": "fp", "event_type": "PRIMITIVE_CONFIRMED",
        "summary": "stable primitive", "command_argv": ["python3", "probe.py"],
        "output": "proved", "details": {"primitive": "oracle"},
        "operation_id": None,
    }
    values.update(changes)
    return save_milestone(run, **values)


def _remote(run: Path, challenge: SimpleNamespace, candidate: str = "CTF{winner}"):
    artifact = run / "exploit" / "solve.py"
    artifact.parent.mkdir(exist_ok=True)
    artifact.write_text("print('flag')\n", encoding="utf-8")
    return record_remote_flag(
        run, challenge_id=challenge.id, input_fingerprint="fp", branch_id="sol-main",
        declared_targets=parse_remotes(challenge.remotes), observed_host="8.8.8.8",
        observed_port=31337, observed_protocol="tcp", network_observed=True,
        output=f"remote: {candidate}", candidate=candidate,
        flag_pattern=challenge.flag_pattern, command_argv=["python3", "exploit/solve.py"],
        exploit_artifact="exploit/solve.py", target_revision=1,
    )


def test_same_milestone_one_hundred_times_has_one_authoritative_receipt(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    ids = {_milestone(run, challenge)["receipt_id"] for _ in range(100)}
    assert len(ids) == 1
    assert len(load_milestones(run)) == 1
    progress = json.loads((run / "progress-state.json").read_text())
    assert progress["sessions"]["sol-main"]["evidence_generation"] == 1


def test_projection_manifest_creation_failure_recovers_same_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    import ctf_os.projections as projections

    fired = False
    def fail_once(name, phase, receipt):
        nonlocal fired
        if not fired and name == "manifest" and phase == "after":
            fired = True
            raise RuntimeError("projection manifest boundary")
    monkeypatch.setattr(projections, "_projection_failpoint", fail_once)
    with pytest.raises(RuntimeError, match="manifest boundary"):
        _milestone(run, challenge, operation_id="manifest-repair")
    assert len(load_milestones(run)) == 1
    repaired = _milestone(run, challenge, operation_id="manifest-repair")
    assert repaired["receipt_id"] == load_milestones(run)[0]["receipt_id"]


def test_operation_id_identity_conflict_and_explicit_repeat(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    first = _milestone(run, challenge, operation_id="oracle-v1")
    same = _milestone(run, challenge, operation_id="oracle-v1")
    assert first["receipt_id"] == same["receipt_id"]
    with pytest.raises(Exception, match="conflicting canonical material"):
        _milestone(
            run, challenge, operation_id="oracle-v1",
            command_argv=["python3", "different.py"],
        )
    repeated = _milestone(run, challenge, operation_id="oracle-v2")
    assert repeated["receipt_id"] != first["receipt_id"]
    assert [row["sequence"] for row in load_milestones(run)] == [1, 2]


@pytest.mark.parametrize("phase", ["before", "after"])
def test_progress_projection_failure_repairs_without_double_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    import ctf_os.projections as projections

    fired = False
    def fail_once(name, observed_phase, receipt):
        nonlocal fired
        if not fired and name == "progress" and observed_phase == phase:
            fired = True
            raise RuntimeError("injected progress boundary")
    monkeypatch.setattr(projections, "_projection_failpoint", fail_once)
    with pytest.raises(RuntimeError, match="injected progress"):
        _milestone(run, challenge, operation_id="repair-progress")
    assert len(load_milestones(run)) == 1
    repaired = _milestone(run, challenge, operation_id="repair-progress")
    assert repaired["receipt_id"] == load_milestones(run)[0]["receipt_id"]
    progress = json.loads((run / "progress-state.json").read_text())
    assert progress["sessions"]["sol-main"]["evidence_generation"] == 1


@pytest.mark.parametrize("projection", ["timing", "race_transition"])
def test_only_failed_projection_is_replayed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, projection: str,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    import ctf_os.projections as projections

    fired = False
    def fail_once(name, phase, receipt):
        nonlocal fired
        if not fired and name == projection and phase == "after":
            fired = True
            raise RuntimeError(f"injected {projection}")
    monkeypatch.setattr(projections, "_projection_failpoint", fail_once)
    with pytest.raises(RuntimeError, match="injected"):
        _milestone(run, challenge, operation_id=f"repair-{projection}")
    repaired = _milestone(run, challenge, operation_id=f"repair-{projection}")
    manifest = json.loads(
        (run / "receipt-projections" / f"{repaired['receipt_id']}.json").read_text()
    )
    assert all(row["status"] in {"APPLIED", "NOT_REQUIRED"} for row in manifest["projections"].values())
    assert len(load_milestones(run)) == 1


@pytest.mark.parametrize(
    ("projection", "phase", "event_type"),
    [
        ("timing", "before", "PRIMITIVE_CONFIRMED"),
        ("timing", "after", "PRIMITIVE_CONFIRMED"),
        ("candidate", "after", "FLAG_CANDIDATE"),
        ("race_transition", "before", "PRIMITIVE_CONFIRMED"),
        ("race_transition", "after", "PRIMITIVE_CONFIRMED"),
        ("state", "before", "PRIMITIVE_CONFIRMED"),
        ("state", "after", "PRIMITIVE_CONFIRMED"),
        ("compatibility", "before", "PRIMITIVE_CONFIRMED"),
        ("compatibility", "after", "PRIMITIVE_CONFIRMED"),
    ],
)
def test_milestone_projection_write_boundaries_are_restartable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    projection: str, phase: str, event_type: str,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    import ctf_os.projections as projections

    fired = False
    def fail_once(name, observed_phase, receipt):
        nonlocal fired
        if not fired and name == projection and observed_phase == phase:
            fired = True
            raise RuntimeError(f"{projection} {phase} boundary")
    monkeypatch.setattr(projections, "_projection_failpoint", fail_once)
    kwargs = {
        "event_type": event_type,
        "operation_id": f"{projection}-{phase}",
    }
    if event_type == "FLAG_CANDIDATE":
        kwargs.update({
            "candidate": "CTF{boundary}", "source_type": "REMOTE_OUTPUT",
            "validation_method": "UNVALIDATED", "confidence": "MEDIUM",
        })
    with pytest.raises(RuntimeError, match="boundary"):
        _milestone(run, challenge, **kwargs)
    repaired = _milestone(run, challenge, **kwargs)
    manifest = json.loads(
        (run / "receipt-projections" / f"{repaired['receipt_id']}.json").read_text()
    )
    assert all(
        row["status"] in {"APPLIED", "NOT_REQUIRED"}
        for row in manifest["projections"].values()
    )
    assert len(load_milestones(run)) == 1


@pytest.mark.parametrize("phase", ["before", "after"])
def test_transition_control_action_projection_boundary_deduplicates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    _plan_unstarted(run, challenge)
    import ctf_os.projections as projections

    fired = False
    def fail_once(name, observed_phase, receipt):
        nonlocal fired
        if not fired and name == "control_action" and observed_phase == phase:
            fired = True
            raise RuntimeError("control action boundary")
    monkeypatch.setattr(projections, "_projection_failpoint", fail_once)
    with pytest.raises(RuntimeError, match="control action boundary"):
        _milestone(
            run, challenge, session_id="race-1",
            operation_id=f"control-{phase}",
        )
    _milestone(
        run, challenge, session_id="race-1",
        operation_id=f"control-{phase}",
    )
    ids = [row["action_id"] for row in load_control_actions(run, current_view=False)]
    assert len(ids) == len(set(ids)) == 1


def test_repair_run_projections_scans_standalone_transition_receipts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    _plan_unstarted(run, challenge)
    import ctf_os.projections as projections

    fired = False
    def fail_once(name, phase, receipt):
        nonlocal fired
        if not fired and name == "control_action" and phase == "before":
            fired = True
            raise RuntimeError("standalone transition projection")
    monkeypatch.setattr(projections, "_projection_failpoint", fail_once)
    with pytest.raises(RuntimeError, match="standalone transition"):
        evaluate_race_transition(
            run,
            {
                "type": "EXPLOIT_PRIMITIVE_CONFIRMED",
                "event_id": "standalone-confirmed",
                "summary": "confirmed oracle",
            },
            "race-1", "fp",
        )

    repaired = repair_run_projections(run)

    assert repaired["race_transitions"]["repaired_transitions"]
    actions = load_control_actions(run, current_view=False)
    assert len({row["action_id"] for row in actions}) == 1


def test_flag_candidate_projection_failure_is_recoverable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    import ctf_os.projections as projections

    fired = False
    def fail_once(name, phase, receipt):
        nonlocal fired
        if not fired and name == "candidate" and phase == "before":
            fired = True
            raise RuntimeError("candidate store unavailable")
    monkeypatch.setattr(projections, "_projection_failpoint", fail_once)
    with pytest.raises(RuntimeError, match="candidate store"):
        _milestone(
            run, challenge, event_type="FLAG_CANDIDATE", summary="flag-shaped output",
            candidate="CTF{maybe}", source_type="REMOTE_OUTPUT",
            validation_method="UNVALIDATED", confidence="MEDIUM",
            operation_id="flag-candidate-one",
        )
    assert load_candidates(run)["candidates"] == []
    receipt = _milestone(
        run, challenge, event_type="FLAG_CANDIDATE", summary="flag-shaped output",
        candidate="CTF{maybe}", source_type="REMOTE_OUTPUT",
        validation_method="UNVALIDATED", confidence="MEDIUM",
        operation_id="flag-candidate-one",
    )
    candidates = load_candidates(run)["candidates"]
    assert len(candidates) == 1 and candidates[0]["receipt_id"] == receipt["receipt_id"]


def test_remote_flag_state_deletion_recovers_submission_recommended(tmp_path: Path) -> None:
    workspace, run, challenge = _run(tmp_path)
    receipt = _remote(run, challenge)
    (run / "STATE.json").unlink()
    assert resolve_active_run(workspace) == run
    state = json.loads((run / "STATE.json").read_text())
    assert state["status"] == "SUBMISSION_RECOMMENDED"
    assert state["flag_candidate"] == "CTF{winner}"
    assert state["remote_flag_receipt"].endswith(f"remote-{Path(str(receipt['receipt'])).stem.removeprefix('remote-')}.json")


def test_remote_receipt_append_failure_repairs_without_flag_downgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    import ctf_os.verification as verification

    fired = False
    def fail_once(boundary, phase, receipt):
        nonlocal fired
        if not fired and boundary == "remote_receipt" and phase == "after":
            fired = True
            raise RuntimeError("remote receipt boundary")
    monkeypatch.setattr(verification, "_verification_failpoint", fail_once)
    with pytest.raises(RuntimeError, match="remote receipt boundary"):
        _remote(run, challenge)
    assert len(list((run / "flag-receipts").glob("remote-*.json"))) == 1
    repaired = _remote(run, challenge)
    assert repaired["state"] == "SUBMISSION_RECOMMENDED"
    assert len(list((run / "flag-receipts").glob("remote-*.json"))) == 1


def test_accepted_and_terminal_state_recover_from_receipts(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    remote = _remote(run, challenge)
    record_submission_result(
        run, run_id=run.name, candidate_id=str(remote["candidate_id"]), result="accepted",
    )
    record_terminal_component(
        run, session_id="sol-main", component="native", status="NOT_REQUIRED",
    )
    record_terminal_component(
        run, session_id="sol-main", component="sandbox", status="NOT_PRESENT",
    )
    record_terminal_component(
        run, session_id="sol-main", component="resource", status="NOT_PRESENT",
    )
    (run / "STATE.json").unlink()
    state = recover_run_state(run)
    assert state["sealed"] is True and state["competition_state"] == "ACCEPTED"
    assert state["status"] == "SEALED_CLEAN"
    assert state["terminal_components"]["sol-main"] == {
        "native": "NOT_REQUIRED", "sandbox": "NOT_PRESENT", "resource": "NOT_PRESENT",
    }
    first = (run / "STATE.json").read_bytes()
    recover_run_state(run)
    assert (run / "STATE.json").read_bytes() == first


def test_wrong_submission_recovery_refutes_only_candidate_and_resumes(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    remote = _remote(run, challenge)
    record_submission_result(
        run, run_id=run.name, candidate_id=str(remote["candidate_id"]), result="wrong",
    )
    (run / "STATE.json").unlink()

    state = recover_run_state(run)

    assert state["status"] == "SOLVING"
    assert state["flag_candidate"] is None
    assert state["remote_flag_receipt"] is None
    candidate = next(row for row in load_candidates(run)["candidates"] if row["candidate_id"] == remote["candidate_id"])
    assert candidate["status"] == "REFUTED"


def test_legacy_display_only_flag_file_is_not_promoted_during_recovery(tmp_path: Path) -> None:
    _workspace, run, _challenge_spec = _run(tmp_path)
    legacy = run / "flag-receipts" / "remote-legacy.json"
    legacy.write_text(json.dumps({"flag": "CTF{display_only}"}), encoding="utf-8")
    (run / "STATE.json").unlink()

    state = recover_run_state(run)

    assert state["status"] == "PREPARED"
    assert state["flag_candidate"] is None
    assert legacy.is_file()


def test_malformed_state_is_preserved_before_recovery(tmp_path: Path) -> None:
    workspace, run, _challenge_spec = _run(tmp_path)
    (run / "STATE.json").write_text("{broken\n", encoding="utf-8")
    assert resolve_active_run(workspace) == run
    assert list(run.glob("STATE.corrupt-*.json"))
    assert json.loads((run / "STATE.json").read_text())["status"] == "PREPARED"


def test_conflicting_submission_receipts_are_corruption(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    remote = _remote(run, challenge)
    accepted = record_submission_result(
        run, run_id=run.name, candidate_id=str(remote["candidate_id"]), result="accepted",
    )
    wrong_id = "f" * 24
    (run / "flag-receipts" / f"submission-{wrong_id}.json").write_text(json.dumps({
        "schema_version": 1, "receipt_id": wrong_id, "run_id": run.name,
        "challenge_id": challenge.id, "input_fingerprint": "fp", "target_revision": 1,
        "session_id": "sol-main", "candidate_id": remote["candidate_id"],
        "candidate": "CTF{winner}", "result": "WRONG", "source": "human",
        "created_at": accepted["created_at"], "automatic_submission_attempted": False,
    }))
    with pytest.raises(WorkspaceError, match="ACCEPTED and WRONG"):
        recover_run_state(run)


def test_empty_terminal_convergence_receipt_recovers_sealed_clean(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    remote = _remote(run, challenge)
    record_submission_result(
        run, run_id=run.name, candidate_id=str(remote["candidate_id"]), result="accepted",
    )
    converged = converge_terminal(run, run_id=run.name)
    assert converged["status"] == "SEALED_CLEAN"
    (run / "STATE.json").unlink()
    assert recover_run_state(run)["status"] == "SEALED_CLEAN"


def test_submission_receipt_append_failure_recovers_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    remote = _remote(run, challenge)
    import ctf_os.terminal as terminal_module

    fired = False
    def fail_once(component, status, receipt):
        nonlocal fired
        if not fired and component == "submission":
            fired = True
            raise RuntimeError("submission receipt boundary")
    monkeypatch.setattr(terminal_module, "_terminal_failpoint", fail_once)
    with pytest.raises(RuntimeError, match="submission receipt boundary"):
        record_submission_result(
            run, run_id=run.name, candidate_id=str(remote["candidate_id"]),
            result="accepted",
        )
    repaired = record_submission_result(
        run, run_id=run.name, candidate_id=str(remote["candidate_id"]),
        result="accepted",
    )
    assert repaired["idempotent"] is True
    assert recover_run_state(run)["competition_state"] == "ACCEPTED"


@pytest.mark.parametrize(
    ("component", "status"),
    [("native", "STOP_RECORDED"), ("sandbox", "CLEANED"), ("resource", "RELEASED")],
)
def test_terminal_component_receipt_boundaries_are_append_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    component: str, status: str,
) -> None:
    _workspace, run, _challenge_spec = _run(tmp_path)
    import ctf_os.terminal as terminal_module

    fired = False
    def fail_once(observed_component, observed_status, receipt):
        nonlocal fired
        if not fired and observed_component == component and observed_status == status:
            fired = True
            raise RuntimeError(f"{component} receipt boundary")
    monkeypatch.setattr(terminal_module, "_terminal_failpoint", fail_once)
    with pytest.raises(RuntimeError, match="receipt boundary"):
        record_terminal_component(
            run, session_id="race-1", component=component, status=status,
            related_receipt={"proof": component},
        )
    repaired = record_terminal_component(
        run, session_id="race-1", component=component, status=status,
        related_receipt={"proof": component},
    )
    rows = [
        row for row in (run / "terminal-components.jsonl").read_text().splitlines()
        if row.strip()
    ]
    assert repaired["idempotent"] is True and len(rows) == 1


def _control_proof(run: Path, action: dict[str, object]) -> dict[str, object]:
    state = json.loads((run / "STATE.json").read_text())
    return {
        "action_id": action["action_id"], "run_id": run.name,
        "challenge_id": state["challenge_id"], "session_id": action["session_id"],
        "input_fingerprint": state["input_fingerprint"],
        "target_revision": state["target_revision"],
        "evidence_generation": action["evidence_generation"],
    }


def _plan_unstarted(run: Path, challenge: SimpleNamespace, session_id: str = "race-1") -> None:
    start_race_plan(
        run, challenge_id=challenge.id, input_fingerprint="fp",
        parent_session_id="sol-main", category="misc", tier=0, tier_reason="test",
        branch_specs=[RaceBranchSpec.from_mapping({
            "session_id": session_id, "role": "independent-full-solve",
            "hypothesis_family": "parser", "hypothesis": "test parser",
            "scope": ["challenge-input"], "tool_strategy": ["probe"],
            "expected_artifacts": ["artifacts/probe.py"],
        }, index=0)],
    )


def test_control_action_cannot_be_applied_by_general_ack(tmp_path: Path) -> None:
    _workspace, run, _challenge_spec = _run(tmp_path)
    action = create_control_action(
        run, session_id="sol-main", action_type="OPERATOR_REVIEW", reason="review",
        triggering_evidence_id="evidence", evidence_generation=0,
    )
    with pytest.raises(ControlActionError, match="control-action-apply"):
        acknowledge_control_action(
            run, action_id=str(action["action_id"]), status="ACKED_APPLIED",
            applied_receipt={"applied": True},
        )
    assert load_control_actions(run)[0]["status"] == "PENDING"


def test_stop_action_requires_exact_terminal_receipt_and_apply_is_idempotent(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    _plan_unstarted(run, challenge)
    action = create_control_action(
        run, session_id="race-1", action_type="STOP_REQUIRED", reason="stop",
        triggering_evidence_id="accepted", evidence_generation=0,
    )
    proof = _control_proof(run, action)
    with pytest.raises(ControlActionError, match="terminal lifecycle"):
        apply_control_action(run, action_id=str(action["action_id"]), proof_receipt=proof)
    assert load_control_actions(run)[0]["status"] == "PENDING"
    terminal_receipt = record_terminal_component(
        run, session_id="race-1", component="native", status="NOT_REQUIRED",
    )
    proof["terminal_receipt_id"] = terminal_receipt["receipt_id"]
    applied = apply_control_action(run, action_id=str(action["action_id"]), proof_receipt=proof)
    again = apply_control_action(run, action_id=str(action["action_id"]), proof_receipt=proof)
    assert applied["status"] == "ACKED_APPLIED" and again["idempotent"] is True
    assert len(load_control_actions(run, current_view=False)) == 2


def test_control_action_rejects_proof_from_another_run(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path / "one")
    _plan_unstarted(run, challenge)
    action = create_control_action(
        run, session_id="race-1", action_type="STOP_REQUIRED", reason="stop",
        triggering_evidence_id="accepted", evidence_generation=0,
    )
    terminal_receipt = record_terminal_component(
        run, session_id="race-1", component="native", status="NOT_REQUIRED",
    )
    proof = _control_proof(run, action)
    proof["terminal_receipt_id"] = terminal_receipt["receipt_id"]
    proof["run_id"] = "run-from-another-challenge"
    with pytest.raises(ControlActionError, match="run_id mismatch"):
        apply_control_action(run, action_id=str(action["action_id"]), proof_receipt=proof)
    assert load_control_actions(run)[0]["status"] == "PENDING"


def _working_poc_inputs(run: Path, challenge: SimpleNamespace):
    artifact = run / "exploit" / "solve.py"
    artifact.parent.mkdir(exist_ok=True)
    artifact.write_text("print('local poc')\n", encoding="utf-8")
    local = save_milestone(
        run, challenge_id=challenge.id, session_id="sol-main", input_fingerprint="fp",
        target_revision=1, event_type="DECISIVE_EXPERIMENT",
        summary="local PoC positive control", command_argv=["python3", "exploit/solve.py"],
        output="local success", artifacts=["exploit/solve.py"],
        details={"local_poc_verified": True, "decision": "PROMOTE"},
        operation_id="local-poc-proof",
    )
    branch = run / "workers" / "sol-main"
    branch.mkdir(parents=True)
    metadata_path = branch / "sandbox.json"
    target = parse_remotes(challenge.remotes)[0]
    metadata = {
        "name": "ctf-os-test-sol-main", "challenge_id": challenge.id,
        "branch": "sol-main", "session_id": "sol-main", "parent_session_id": "sol-main",
        "branch_root": str(branch), "metadata_path": str(metadata_path),
        "input_fingerprint": "fp", "target_revision": 1,
        "authorized_targets": [target.to_dict()],
    }
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    return local, metadata


def _commit_poc(
    run: Path, challenge: SimpleNamespace, local: dict[str, object],
    metadata: dict[str, object], executor, *, operation_id: str = "remote-one",
    argv: tuple[str, ...] = ("python3", "/artifacts/solve.py", "8.8.8.8", "31337"),
):
    return commit_working_poc(
        run, challenge_id=challenge.id, input_fingerprint="fp", target_revision=1,
        session_id="sol-main", sandbox_metadata=metadata,
        local_receipt_id=str(local["receipt_id"]), exploit_artifact="exploit/solve.py",
        remote_argv=argv, declared_targets=parse_remotes(challenge.remotes), target_index=0,
        flag_pattern=challenge.flag_pattern, success_condition="flag in output",
        kill_condition="remote rejects exploit", operation_id=operation_id, executor=executor,
    )


def _working_operation(run: Path) -> dict[str, object]:
    paths = list((run / "working-poc-operations").glob("*.json"))
    assert len(paths) == 1
    return json.loads(paths[0].read_text())


def _unknown_resolution_proof(run: Path) -> dict[str, object]:
    operation = _working_operation(run)
    material = operation["canonical_material"]
    assert isinstance(material, dict)
    return {
        "run_id": run.name, "challenge_id": material["challenge_id"],
        "session_id": material["session_id"],
        "input_fingerprint": material["input_fingerprint"],
        "target_revision": material["target_revision"],
        "operation_id": operation["operation_id"],
        "execution_attempt_id": operation["execution_attempt_id"],
        "command_digest": material["command_digest"],
        "artifact_digest": material["exploit_artifact_digest_before"],
        "target_identity": material["target"],
    }


def test_working_poc_commit_executes_once_and_records_remote_flag(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    local, metadata = _working_poc_inputs(run, challenge)
    calls = 0
    def executor(*args, **kwargs):
        nonlocal calls
        calls += 1
        return {
            "exit_code": 0, "timed_out": False, "stdout": "winner CTF{remote}",
            "stderr": "", "authorized_network_observed": True,
            "input_fingerprint": "fp",
        }
    first = _commit_poc(run, challenge, local, metadata, executor)
    second = _commit_poc(run, challenge, local, metadata, executor)
    assert calls == 1 and second["remote_command_executed"] is False
    assert first["verified_flag"]["state"] == "SUBMISSION_RECOMMENDED"
    types = [row["event_type"] for row in load_milestones(run)]
    assert types.count("REMOTE_ATTEMPT") == 1 and types.count("WORKING_POC") == 1


def test_working_poc_persists_execution_started_before_executor(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    local, metadata = _working_poc_inputs(run, challenge)

    def executor(*args, **kwargs):
        operation = _working_operation(run)
        assert operation["status"] == "EXECUTION_STARTED"
        assert operation["execution_attempt_id"]
        assert operation["command_digest"] == operation["canonical_material"]["command_digest"]
        assert operation["artifact_digest"] == operation["canonical_material"]["exploit_artifact_digest_before"]
        assert operation["target_identity"] == operation["canonical_material"]["target"]
        return {
            "exit_code": 0, "timed_out": False, "stdout": "no flag", "stderr": "",
            "authorized_network_observed": True, "input_fingerprint": "fp",
        }

    _commit_poc(run, challenge, local, metadata, executor, operation_id="intent-first")


def test_working_poc_started_crash_blocks_automatic_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    local, metadata = _working_poc_inputs(run, challenge)
    import ctf_os.working_poc as module
    calls = 0

    def executor(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise RuntimeError("process died after sending remote request")

    with pytest.raises(RuntimeError, match="process died"):
        _commit_poc(run, challenge, local, metadata, executor, operation_id="crash-window")
    result = _commit_poc(run, challenge, local, metadata, executor, operation_id="crash-window")
    assert calls == 1
    assert result["status"] == "EXECUTION_OUTCOME_UNKNOWN"
    assert result["remote_command_executed"] is False
    assert result["automatic_retry_blocked"] is True
    assert result["manual_resolution_required"] is True
    assert result["execution_attempt_id"]
    assert _working_operation(run)["status"] == "EXECUTION_OUTCOME_UNKNOWN"


def test_working_poc_execution_started_failpoint_is_unknown_on_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    local, metadata = _working_poc_inputs(run, challenge)
    import ctf_os.working_poc as module

    def fail(boundary, phase, record):
        if boundary == "execution_started":
            raise RuntimeError("intent persisted then crash")
    monkeypatch.setattr(module, "_working_poc_failpoint", fail)
    with pytest.raises(RuntimeError, match="intent persisted"):
        _commit_poc(
            run, challenge, local, metadata,
            lambda *args, **kwargs: pytest.fail("executor must not start"),
            operation_id="intent-crash",
        )
    monkeypatch.setattr(module, "_working_poc_failpoint", lambda *args: None)
    result = _commit_poc(
        run, challenge, local, metadata,
        lambda *args, **kwargs: pytest.fail("automatic retry must be blocked"),
        operation_id="intent-crash",
    )
    assert result["status"] == "EXECUTION_OUTCOME_UNKNOWN"


def test_working_poc_record_result_validates_receipt_and_repairs_projection(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    local, metadata = _working_poc_inputs(run, challenge)
    with pytest.raises(RuntimeError, match="remote result lost"):
        _commit_poc(
            run, challenge, local, metadata,
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("remote result lost")),
            operation_id="record-result",
        )
    _commit_poc(
        run, challenge, local, metadata,
        lambda *args, **kwargs: pytest.fail("unknown operation must not retry"),
        operation_id="record-result",
    )
    proof = _unknown_resolution_proof(run)
    stdout = "winner CTF{recorded}"
    proof.update({
        "exit_code": 0, "timed_out": False,
        "authorized_network_observed": True,
        "stdout": stdout, "stderr": "",
        "stdout_digest": hashlib.sha256(stdout.encode()).hexdigest(),
        "stderr_digest": hashlib.sha256(b"").hexdigest(),
    })

    result = resolve_unknown_working_poc(
        run, operation_id="record-result", decision="RECORD_RESULT",
        resolution_receipt=proof, declared_targets=parse_remotes(challenge.remotes),
        flag_pattern=challenge.flag_pattern,
    )

    assert result["remote_command_executed"] is False
    assert result["verified_flag"]["state"] == "SUBMISSION_RECOMMENDED"
    assert _working_operation(run)["status"] == "COMPLETED"


def test_working_poc_abandon_prevents_operation_reuse(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    local, metadata = _working_poc_inputs(run, challenge)
    with pytest.raises(RuntimeError):
        _commit_poc(
            run, challenge, local, metadata,
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("lost")),
            operation_id="abandon-one",
        )
    _commit_poc(run, challenge, local, metadata, lambda *a, **k: {}, operation_id="abandon-one")
    proof = _unknown_resolution_proof(run)
    resolved = resolve_unknown_working_poc(
        run, operation_id="abandon-one", decision="ABANDON", resolution_receipt=proof,
    )
    assert resolved["status"] == "ABANDONED"
    with pytest.raises(WorkingPocError, match="ABANDONED"):
        _commit_poc(run, challenge, local, metadata, lambda *a, **k: {}, operation_id="abandon-one")


def test_working_poc_authorize_retry_requires_new_operation_id(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    local, metadata = _working_poc_inputs(run, challenge)
    with pytest.raises(RuntimeError):
        _commit_poc(
            run, challenge, local, metadata,
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("lost")),
            operation_id="unknown-old",
        )
    _commit_poc(run, challenge, local, metadata, lambda *a, **k: {}, operation_id="unknown-old")
    proof = _unknown_resolution_proof(run)
    with pytest.raises(WorkingPocError, match="distinct new operation ID"):
        resolve_unknown_working_poc(
            run, operation_id="unknown-old", decision="AUTHORIZE_RETRY",
            resolution_receipt=proof,
        )
    resolved = resolve_unknown_working_poc(
        run, operation_id="unknown-old", decision="AUTHORIZE_RETRY",
        resolution_receipt=proof, new_operation_id="authorized-new",
    )
    assert resolved["authorized_retry_operation_id"] == "authorized-new"
    retry_records = [
        json.loads(path.read_text())
        for path in (run / "working-poc-operations").glob("*.json")
    ]
    retry = next(row for row in retry_records if row["operation_id"] == "authorized-new")
    assert retry["supersedes_unknown_operation"] == "unknown-old"
    assert retry["operator_authorization_receipt"]


def test_concurrent_working_poc_calls_start_at_most_one_executor(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    local, metadata = _working_poc_inputs(run, challenge)
    entered = threading.Event()
    release = threading.Event()
    calls = 0

    def executor(*args, **kwargs):
        nonlocal calls
        calls += 1
        entered.set()
        assert release.wait(5)
        return {
            "exit_code": 0, "timed_out": False, "stdout": "no flag", "stderr": "",
            "authorized_network_observed": True, "input_fingerprint": "fp",
        }

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(
            _commit_poc, run, challenge, local, metadata, executor,
            operation_id="concurrent-one",
        )
        assert entered.wait(5)
        second = pool.submit(
            _commit_poc, run, challenge, local, metadata, executor,
            operation_id="concurrent-one",
        )
        second_result = second.result(timeout=5)
        release.set()
        first.result(timeout=5)
    assert calls == 1
    assert second_result["status"] == "EXECUTION_STARTED"
    assert second_result["automatic_retry_blocked"] is True


def test_working_poc_operation_conflict_and_undeclared_target_block(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    local, metadata = _working_poc_inputs(run, challenge)
    calls = 0
    def executor(*args, **kwargs):
        nonlocal calls
        calls += 1
        return {
            "exit_code": 1, "timed_out": False, "stdout": "",
            "stderr": "connection refused", "authorized_network_observed": False,
            "input_fingerprint": "fp",
        }
    _commit_poc(run, challenge, local, metadata, executor)
    with pytest.raises(WorkingPocError, match="conflicting remote argv"):
        _commit_poc(
            run, challenge, local, metadata, executor,
            argv=("python3", "/artifacts/other.py", "8.8.8.8", "31337"),
        )
    assert calls == 1

    _workspace2, run2, challenge2 = _run(tmp_path / "scope")
    local2, metadata2 = _working_poc_inputs(run2, challenge2)
    metadata2["authorized_targets"] = []
    Path(str(metadata2["metadata_path"])).write_text(json.dumps(metadata2))
    with pytest.raises(WorkingPocError, match="SCOPE_BLOCKED"):
        _commit_poc(run2, challenge2, local2, metadata2, executor, operation_id="blocked")
    assert calls == 1
    blocker = load_milestones(run2)[-1]
    assert blocker["event_type"] == "TYPED_BLOCKER"
    assert blocker["details"]["blocker_type"] == "SCOPE_BLOCKED"


def test_working_poc_stale_sandbox_records_endpoint_changed_blocker(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    local, metadata = _working_poc_inputs(run, challenge)
    metadata["target_revision"] = 0
    Path(str(metadata["metadata_path"])).write_text(json.dumps(metadata))

    with pytest.raises(WorkingPocError, match="ENDPOINT_CHANGED"):
        _commit_poc(
            run, challenge, local, metadata,
            lambda *args, **kwargs: pytest.fail("stale endpoint must not execute"),
            operation_id="stale-endpoint",
        )

    blocker = load_milestones(run)[-1]
    assert blocker["event_type"] == "TYPED_BLOCKER"
    assert blocker["details"]["blocker_type"] == "ENDPOINT_CHANGED"


def test_working_poc_remote_receipt_failure_retries_without_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    local, metadata = _working_poc_inputs(run, challenge)
    import ctf_os.working_poc as module
    calls = 0
    def executor(*args, **kwargs):
        nonlocal calls
        calls += 1
        return {
            "exit_code": 0, "timed_out": False, "stdout": "no flag",
            "stderr": "", "authorized_network_observed": True,
            "input_fingerprint": "fp",
        }
    fired = False
    def fail_once(boundary, phase, record):
        nonlocal fired
        if not fired and boundary == "remote_receipt":
            fired = True
            raise RuntimeError("remote receipt boundary")
    monkeypatch.setattr(module, "_working_poc_failpoint", fail_once)
    with pytest.raises(RuntimeError, match="remote receipt"):
        _commit_poc(run, challenge, local, metadata, executor, operation_id="repair-remote")
    repaired = _commit_poc(run, challenge, local, metadata, executor, operation_id="repair-remote")
    assert calls == 1 and repaired["remote_attempt_receipt_id"]


def test_working_poc_execution_recorded_failure_repairs_remote_without_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    local, metadata = _working_poc_inputs(run, challenge)
    import ctf_os.working_poc as module
    calls = 0

    def executor(*args, **kwargs):
        nonlocal calls
        calls += 1
        return {
            "exit_code": 0, "timed_out": False, "stdout": "no flag", "stderr": "",
            "authorized_network_observed": True, "input_fingerprint": "fp",
        }

    fired = False
    def fail_once(boundary, phase, record):
        nonlocal fired
        if not fired and boundary == "execution_record":
            fired = True
            raise RuntimeError("execution record boundary")
    monkeypatch.setattr(module, "_working_poc_failpoint", fail_once)
    with pytest.raises(RuntimeError, match="execution record"):
        _commit_poc(run, challenge, local, metadata, executor, operation_id="repair-execution")
    repaired = _commit_poc(run, challenge, local, metadata, executor, operation_id="repair-execution")
    assert calls == 1
    assert repaired["remote_command_executed"] is False
    assert repaired["remote_attempt_receipt_id"]


def test_working_poc_remote_recorded_failure_repairs_flag_projection_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    local, metadata = _working_poc_inputs(run, challenge)
    import ctf_os.working_poc as module
    calls = 0

    def executor(*args, **kwargs):
        nonlocal calls
        calls += 1
        return {
            "exit_code": 0, "timed_out": False, "stdout": "winner CTF{projected}",
            "stderr": "", "authorized_network_observed": True,
            "input_fingerprint": "fp",
        }

    fired = False
    def fail_once(boundary, phase, record):
        nonlocal fired
        if not fired and boundary == "flag_projection":
            fired = True
            raise RuntimeError("flag projection boundary")
    monkeypatch.setattr(module, "_working_poc_failpoint", fail_once)
    with pytest.raises(RuntimeError, match="flag projection"):
        _commit_poc(run, challenge, local, metadata, executor, operation_id="repair-flag")
    repaired = _commit_poc(run, challenge, local, metadata, executor, operation_id="repair-flag")
    assert calls == 1
    assert repaired["remote_command_executed"] is False
    assert repaired["verified_flag"]["state"] == "SUBMISSION_RECOMMENDED"


def test_working_poc_plain_command_error_is_not_mislabeled_target_down(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    local, metadata = _working_poc_inputs(run, challenge)

    result = _commit_poc(
        run, challenge, local, metadata,
        lambda *args, **kwargs: {
            "exit_code": 2, "timed_out": False, "stdout": "",
            "stderr": "python3: syntax error", "authorized_network_observed": False,
            "input_fingerprint": "fp",
        },
        operation_id="local-command-error",
    )

    assert result["blocker"] is None
    assert not any(
        row["event_type"] == "TYPED_BLOCKER" for row in load_milestones(run)
    )


def test_multiple_remote_flag_candidates_are_not_promoted_high(tmp_path: Path) -> None:
    _workspace, run, challenge = _run(tmp_path)
    local, metadata = _working_poc_inputs(run, challenge)
    def executor(*args, **kwargs):
        return {
            "exit_code": 0, "timed_out": False,
            "stdout": "CTF{one}\nCTF{two}\n", "stderr": "",
            "authorized_network_observed": True, "input_fingerprint": "fp",
        }
    result = _commit_poc(run, challenge, local, metadata, executor, operation_id="ambiguous")
    assert result["verified_flag"] is None
    assert len(result["flag_candidates"]) == 2
    assert {row["confidence"] for row in load_candidates(run)["candidates"]} == {"MEDIUM"}


def _long_compute_metadata(run: Path, challenge: SimpleNamespace) -> None:
    path = run / "workers" / "sol-main" / "sandbox.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({
        "name": "ctf-os-long-sol-main", "branch": "sol-main",
        "challenge_id": challenge.id, "input_fingerprint": "fp", "target_revision": 1,
    }))


def _long_compute_receipt(
    run: Path, challenge: SimpleNamespace, *, operation_id: str = "long-one",
):
    return save_milestone(
        run, challenge_id=challenge.id, session_id="sol-main", input_fingerprint="fp",
        event_type="LONG_COMPUTE", summary="bounded solver",
        command_argv=["python3", "solver.py"], operation_id=operation_id,
        details={
            "sandbox_metadata_path": "workers/sol-main/sandbox.json",
            "process_identity": {"process_group_id": 4321},
            "expected_output_artifact": "artifacts/checkpoint.bin",
            "expected_completion_signal": "artifacts/complete.marker",
            "maximum_duration_seconds": 300, "checkpoint_interval_seconds": 60,
            "resource_requirement": {"cpus": 4, "elastic": True},
            "cancel_condition": "no checkpoint", "fallback_plan": "manual solve",
        },
    )


def _observed(*, digest=None, size=0, mtime=None, process=True, completion=False):
    return {
        "container_identity": "container-1", "process_valid": process,
        "process_id": 4321 if process else None,
        "observed_command_argv": ["python3", "solver.py"] if process else None,
        "artifact": {
            "exists": digest is not None, "size": size,
            "mtime_ns": mtime, "digest": digest,
        },
        "completion_signal": completion,
        "completion_marker": {
            "exists": completion, "size": 4 if completion else 0,
            "mtime_ns": 9 if completion else None,
            "digest": "marker-digest" if completion else None,
        },
    }


def _long_review_action(run: Path, receipt: dict[str, object]) -> dict[str, object]:
    progress = json.loads((run / "progress-state.json").read_text())
    generation = progress["sessions"]["sol-main"]["evidence_generation"]
    return create_control_action(
        run, session_id="sol-main", action_type="LONG_COMPUTE_REVIEW",
        reason="review bounded compute", triggering_evidence_id=str(receipt["receipt_id"]),
        evidence_generation=generation,
        metadata={"long_compute_receipt_id": receipt["receipt_id"]},
    )


def _long_review_proof(
    run: Path, action: dict[str, object], receipt: dict[str, object], decision: str,
) -> dict[str, object]:
    proof = _control_proof(run, action)
    proof.update({"decision": decision, "long_compute_receipt_id": receipt["receipt_id"]})
    return proof


def _termination_receipt(
    proof: dict[str, object], receipt: dict[str, object], action: dict[str, object],
) -> dict[str, object]:
    details = receipt["details"]
    assert isinstance(details, dict)
    return {
        "receipt_id": "termination-one",
        **{
            field: proof[field] for field in (
                "run_id", "challenge_id", "session_id", "input_fingerprint",
                "target_revision", "action_id", "long_compute_receipt_id",
            )
        },
        "container_identity": details["container_identity"],
        "process_identity": details["process_identity"],
        "termination_observation": {
            "process_valid": False, "remaining_processes": [],
            "observed_at": datetime.now(timezone.utc).isoformat(),
        },
    }


def test_long_compute_heartbeat_ignores_caller_boolean_and_requires_real_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    _long_compute_metadata(run, challenge)
    import ctf_os.progress as progress_module
    observations = iter([_observed(), _observed(), _observed(digest="new", size=7, mtime=2)])
    monkeypatch.setattr(progress_module, "_observe_long_compute", lambda details: next(observations))
    receipt = _long_compute_receipt(run, challenge)
    created = datetime.fromisoformat(str(receipt["created_at"]).replace("Z", "+00:00"))
    fake = heartbeat_long_compute(
        run, session_id="sol-main", receipt_id=str(receipt["receipt_id"]),
        artifact_changed=True, observed_at=(created + timedelta(seconds=30)).isoformat(),
    )
    assert fake["artifact_changed"] is False
    state = json.loads((run / "progress-state.json").read_text())
    assert state["sessions"]["sol-main"]["long_compute"]["last_heartbeat_at"] == receipt["created_at"]
    real = heartbeat_long_compute(
        run, session_id="sol-main", receipt_id=str(receipt["receipt_id"]),
        artifact_changed=False, observed_at=(created + timedelta(seconds=40)).isoformat(),
    )
    assert real["artifact_changed"] is True
    assert real["last_artifact"]["digest"] == "new"


@pytest.mark.parametrize(
    ("observation", "elapsed", "expected_status"),
    [
        (_observed(process=False, completion=False), 10, "FAILED"),
        (_observed(), 301, "REVIEW_REQUIRED"),
    ],
)
def test_long_compute_exit_or_maximum_duration_creates_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    observation: dict[str, object], elapsed: int, expected_status: str,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    _long_compute_metadata(run, challenge)
    import ctf_os.progress as progress_module
    observations = iter([_observed(), observation])
    monkeypatch.setattr(progress_module, "_observe_long_compute", lambda details: next(observations))
    receipt = _long_compute_receipt(run, challenge)
    created = datetime.fromisoformat(str(receipt["created_at"]).replace("Z", "+00:00"))
    result = heartbeat_long_compute(
        run, session_id="sol-main", receipt_id=str(receipt["receipt_id"]),
        observed_at=(created + timedelta(seconds=elapsed)).isoformat(),
    )
    assert result["status"] == expected_status
    assert result["review_action"]["action_type"] == "LONG_COMPUTE_REVIEW"


def test_long_compute_cancel_requires_termination_receipt_and_no_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    _long_compute_metadata(run, challenge)
    import ctf_os.progress as progress_module
    current = {"value": _observed()}
    monkeypatch.setattr(progress_module, "_observe_long_compute", lambda details: current["value"])
    receipt = _long_compute_receipt(run, challenge)
    action = _long_review_action(run, receipt)
    proof = _long_review_proof(run, action, receipt, "CANCELLED")
    current["value"] = _observed(process=False)
    with pytest.raises(ControlActionError, match="termination receipt"):
        apply_control_action(run, action_id=str(action["action_id"]), proof_receipt=proof)
    proof["process_termination_receipt"] = _termination_receipt(proof, receipt, action)
    current["value"] = _observed()
    with pytest.raises(ControlActionError, match="still running"):
        apply_control_action(run, action_id=str(action["action_id"]), proof_receipt=proof)
    current["value"] = _observed(process=False)
    applied = apply_control_action(run, action_id=str(action["action_id"]), proof_receipt=proof)
    again = apply_control_action(run, action_id=str(action["action_id"]), proof_receipt=proof)
    assert applied["status"] == "ACKED_APPLIED"
    assert again["idempotent"] is True


def test_long_compute_completed_requires_marker_and_stopped_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    _long_compute_metadata(run, challenge)
    import ctf_os.progress as progress_module
    current = {"value": _observed()}
    monkeypatch.setattr(progress_module, "_observe_long_compute", lambda details: current["value"])
    receipt = _long_compute_receipt(run, challenge)
    action = _long_review_action(run, receipt)
    proof = _long_review_proof(run, action, receipt, "COMPLETED")
    artifact = _observed(digest="final", size=12, mtime=8, process=False)["artifact"]
    proof.update({
        "completion_marker_digest": "marker-digest",
        "completion_marker_metadata": _observed(completion=True)["completion_marker"],
        "final_artifact_observation": artifact,
    })
    current["value"] = _observed(digest="final", size=12, mtime=8, process=False)
    with pytest.raises(ControlActionError, match="completion marker is missing"):
        apply_control_action(run, action_id=str(action["action_id"]), proof_receipt=proof)
    current["value"] = _observed(digest="final", size=12, mtime=8, process=True, completion=True)
    with pytest.raises(ControlActionError, match="still running"):
        apply_control_action(run, action_id=str(action["action_id"]), proof_receipt=proof)
    current["value"] = _observed(digest="final", size=12, mtime=8, process=False, completion=True)
    applied = apply_control_action(run, action_id=str(action["action_id"]), proof_receipt=proof)
    assert applied["status"] == "ACKED_APPLIED"


def test_long_compute_continued_rejects_stale_and_accepts_fresh_verified_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    _long_compute_metadata(run, challenge)
    import ctf_os.progress as progress_module
    current = {"value": _observed()}
    monkeypatch.setattr(progress_module, "_observe_long_compute", lambda details: current["value"])
    receipt = _long_compute_receipt(run, challenge)
    created = datetime.fromisoformat(str(receipt["created_at"]).replace("Z", "+00:00"))
    current["value"] = _observed(digest="fresh", size=7, mtime=2)
    heartbeat_long_compute(
        run, session_id="sol-main", receipt_id=str(receipt["receipt_id"]),
        observed_at=(created + timedelta(seconds=1)).isoformat(),
    )
    progress = json.loads((run / "progress-state.json").read_text())
    checkpoint_id = progress["sessions"]["sol-main"]["long_compute"]["verified_checkpoint_receipt_id"]
    action = _long_review_action(run, receipt)
    proof = _long_review_proof(run, action, receipt, "CONTINUED_WITH_VALID_CHECKPOINT")
    proof["verified_checkpoint_receipt_id"] = checkpoint_id
    checkpoint_path = run / "long-compute-checkpoints" / f"{checkpoint_id}.json"
    checkpoint = json.loads(checkpoint_path.read_text())
    checkpoint["valid_until_at"] = "2000-01-01T00:00:00Z"
    checkpoint_path.write_text(json.dumps(checkpoint))
    with pytest.raises(ControlActionError, match="checkpoint is stale"):
        apply_control_action(run, action_id=str(action["action_id"]), proof_receipt=proof)
    checkpoint["valid_until_at"] = "2999-01-01T00:00:00Z"
    checkpoint_path.write_text(json.dumps(checkpoint))
    applied = apply_control_action(run, action_id=str(action["action_id"]), proof_receipt=proof)
    assert applied["status"] == "ACKED_APPLIED"


def test_long_compute_fallback_requires_bound_command_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    _long_compute_metadata(run, challenge)
    import ctf_os.progress as progress_module
    current = {"value": _observed()}
    monkeypatch.setattr(progress_module, "_observe_long_compute", lambda details: current["value"])
    receipt = _long_compute_receipt(run, challenge)
    fallback = save_milestone(
        run, challenge_id=challenge.id, session_id="sol-main", input_fingerprint="fp",
        target_revision=1, event_type="DECISIVE_EXPERIMENT",
        summary="bounded direct fallback", command_argv=["python3", "fallback.py"],
        output="fallback decided", operation_id="long-fallback",
        details={
            "decision": "PROMOTE",
            "fallback_for_long_compute_receipt_id": receipt["receipt_id"],
        },
    )
    action = _long_review_action(run, receipt)
    proof = _long_review_proof(run, action, receipt, "FALLBACK_APPLIED")
    proof.update({
        "fallback_argv": ["python3", "fallback.py"],
        "decisive_experiment_receipt_id": fallback["receipt_id"],
    })
    current["value"] = _observed(process=False)
    with pytest.raises(ControlActionError, match="fallback command receipt"):
        apply_control_action(run, action_id=str(action["action_id"]), proof_receipt=proof)
    proof["fallback_command_receipt_id"] = fallback["receipt_id"]
    applied = apply_control_action(run, action_id=str(action["action_id"]), proof_receipt=proof)
    assert applied["status"] == "ACKED_APPLIED"


def test_long_compute_review_rejects_receipt_from_another_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ctf_os.progress as progress_module
    monkeypatch.setattr(progress_module, "_observe_long_compute", lambda details: _observed())
    _workspace1, run1, challenge1 = _run(tmp_path / "one")
    _long_compute_metadata(run1, challenge1)
    receipt1 = _long_compute_receipt(run1, challenge1, operation_id="other-run-long")
    _workspace2, run2, challenge2 = _run(tmp_path / "two")
    _long_compute_metadata(run2, challenge2)
    receipt2 = _long_compute_receipt(run2, challenge2)
    action = _long_review_action(run2, receipt2)
    proof = _long_review_proof(run2, action, receipt2, "CANCELLED")
    proof["long_compute_receipt_id"] = receipt1["receipt_id"]
    with pytest.raises(ControlActionError, match="authoritative milestone"):
        apply_control_action(run2, action_id=str(action["action_id"]), proof_receipt=proof)


def test_scheduler_scales_only_verified_long_compute() -> None:
    request = default_request(
        contest="c", challenge_id="x", session_id="solver",
        workload_class="symbolic-execution",
    )
    capacity = HostCapacity(
        observation_mode="FULL", degraded_metrics=(), cpu={"usable": 12.0},
        memory={"usable_bytes": 32 * GIB}, storage={"usable_bytes": 100 * GIB},
        gpu={"docker_runtime": False, "devices": []}, load_average=(0.0, 0.0, 0.0),
    )
    unverified = plan_allocations([request], capacity, observations={
        "solver": {
            "classification": "CPU_STARVED", "explicit_long_compute": True,
            "progress": {"progressing": True, "coverage": 10},
        },
    })
    verified = plan_allocations([request], capacity, observations={
        "solver": {
            "classification": "CPU_STARVED",
            "progress": {"verified_long_compute": {
                "active": True, "process_valid": True,
                "fresh_artifact_evidence": True,
                "valid_until_at": "2999-01-01T00:00:00Z",
            }},
        },
    })
    assert unverified["allocations"]["solver"]["cpus"] == request.min_cpus
    assert verified["allocations"]["solver"]["cpus"] > request.min_cpus


def test_resource_ledger_rejects_caller_claimed_long_compute(tmp_path: Path) -> None:
    from ctf_os.resources.scheduler import ResourceLedger, SchedulerError

    ledger = ResourceLedger(tmp_path)
    request = default_request(
        contest="c", challenge_id="x", session_id="solver",
        workload_class="symbolic-execution",
    )
    ledger.request(request, actor_session_id="solver", actor_role="child")
    with pytest.raises(SchedulerError, match="direct process/artifact observation"):
        ledger.update(
            "solver", actor_session_id="solver", actor_role="child",
            changes={"progress": {"verified_long_compute": {
                "active": True, "process_valid": True,
                "fresh_artifact_evidence": True,
                "valid_until_at": "2999-01-01T00:00:00Z",
            }}},
        )


def _session_manifest(tmp_path: Path) -> tuple[ContestManifest, ChallengeSpec]:
    contest_root = tmp_path / "incoming" / "Merge CTF"
    contest_root.mkdir(parents=True)
    manifest_path = contest_root / "contest.md"
    manifest_path.write_text("# Merge CTF\n")
    challenge = ChallengeSpec(
        number=1, id="merge-id", category="misc", name="Merge",
        workspace_name="merge", score=None, description="original description",
        hint="original hint", remotes=("tcp://8.8.8.8:31337",),
        flag_format="OLD{...}", flag_pattern=r"\AOLD\{[^}]+\}\Z",
        input_profile="large", warnings=(),
    )
    return ContestManifest(
        name="Merge CTF", slug="merge-ctf", path=manifest_path, date=None,
        flag_format="DEF{...}", flag_pattern=r"\ADEF\{[^}]+\}\Z",
        input_profile="large-forensic", challenges=(challenge,), warnings=(),
    ), challenge


def test_session_profile_omission_inherits_and_explicit_standard_overrides(tmp_path: Path) -> None:
    manifest, challenge = _session_manifest(tmp_path)
    inherited = resolve_session_challenge(
        tmp_path, manifest, "misc/Merge",
        parse_session_input(json.dumps({"category": "misc", "name": "Merge"})),
    )
    first_fingerprint = session_input_fingerprint(
        tmp_path / "output" / manifest.slug / "misc" / challenge.workspace_name / "SESSION-INPUT.json"
    )
    explicit = resolve_session_challenge(
        tmp_path, manifest, "misc/Merge",
        parse_session_input(json.dumps({
            "category": "misc", "name": "Merge", "input_profile": "standard",
        })),
    )
    second_fingerprint = session_input_fingerprint(
        tmp_path / "output" / manifest.slug / "misc" / challenge.workspace_name / "SESSION-INPUT.json"
    )
    assert inherited.input_profile == "large"
    assert explicit.input_profile == "standard"
    assert first_fingerprint != second_fingerprint


def test_session_packet_omitted_null_and_empty_array_semantics(tmp_path: Path) -> None:
    manifest, challenge = _session_manifest(tmp_path)
    packet = parse_session_input(json.dumps({
        "category": "misc", "name": "Merge", "description": None,
        "remotes": [], "source_paths": [], "flag_format": "NEW{...}",
    }))
    merged = resolve_session_challenge(tmp_path, manifest, "misc/Merge", packet)
    assert merged.description is None
    assert merged.hint == "original hint"
    assert merged.remotes == ()
    assert merged.flag_format == "NEW{...}"
    assert merged.flag_pattern == r"\ANEW\{[^}\r\n]+\}\Z"
    assert session_source_paths(manifest, merged) == []
    with pytest.raises(ValueError, match="empty strings"):
        parse_session_input(json.dumps({
            "category": "misc", "name": "Merge", "hint": "",
        }))


def test_prepared_input_bytes_validates_inventory_and_remote_only() -> None:
    assert prepared_input_bytes({
        "important_metadata": {"total_bytes": 7},
        "files": [{"path": "x", "size": 7}], "authorized_targets": [],
    }) == 7
    assert prepared_input_bytes({
        "important_metadata": {"total_bytes": 0}, "files": [],
        "authorized_targets": [{"host": "8.8.8.8"}],
    }) == 0
    for malformed in (
        {"important_metadata": {"total_bytes": True}, "files": [], "authorized_targets": [{}]},
        {"important_metadata": {"total_bytes": 8}, "files": [{"size": 7}], "authorized_targets": []},
        {"important_metadata": {"total_bytes": 0}, "files": [], "authorized_targets": []},
    ):
        with pytest.raises(ValueError):
            prepared_input_bytes(malformed)


def test_post_commit_remote_projection_failure_repairs_only_missing_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    import ctf_os.projections as projections
    fired = False
    def fail_once(name, phase, receipt):
        nonlocal fired
        if (
            not fired and receipt.get("network_observed") is True
            and name == "verified_event" and phase == "before"
        ):
            fired = True
            raise RuntimeError("event projection offline")
    monkeypatch.setattr(projections, "_projection_failpoint", fail_once)
    result = _remote(run, challenge)
    assert result["state"] == "SUBMISSION_RECOMMENDED"
    assert result["post_commit_warnings"]
    receipt_id = Path(str(result["receipt"])).stem.removeprefix("remote-")
    manifest_path = run / "receipt-projections" / f"{receipt_id}.json"
    before = json.loads(manifest_path.read_text())
    assert before["projections"]["verified_event"]["status"] == "FAILED"
    applied_before = {
        key: row["attempts"] for key, row in before["projections"].items()
        if row["status"] == "APPLIED"
    }
    repair_run_projections(run, declared_remote=True)
    after = json.loads(manifest_path.read_text())
    assert after["projections"]["verified_event"]["status"] == "APPLIED"
    assert all(after["projections"][key]["attempts"] == attempts for key, attempts in applied_before.items())
    assert json.loads((run / "STATE.json").read_text())["status"] == "SUBMISSION_RECOMMENDED"


def test_submission_receipt_survives_state_projection_failure_and_repairs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace, run, challenge = _run(tmp_path)
    remote = _remote(run, challenge)
    import ctf_os.terminal as terminal_module
    original = terminal_module.atomic_json
    fired = False
    def fail_state(path, payload):
        nonlocal fired
        if (
            not fired and path.name == "STATE.json"
            and list((run / "flag-receipts").glob("submission-*.json"))
        ):
            fired = True
            raise RuntimeError("state projection interrupted")
        return original(path, payload)
    monkeypatch.setattr(terminal_module, "atomic_json", fail_state)
    with pytest.raises(RuntimeError, match="state projection"):
        record_submission_result(
            run, run_id=run.name, candidate_id=str(remote["candidate_id"]), result="accepted",
        )
    assert list((run / "flag-receipts").glob("submission-*.json"))
    repair_run_projections(run, declared_remote=True)
    state = json.loads((run / "STATE.json").read_text())
    assert state["competition_state"] == "ACCEPTED" and state["sealed"] is True
