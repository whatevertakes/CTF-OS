from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from ctf_os.modes import SolveMode, SolveModeError, resolve_solve_mode, validate_branch_intents
from ctf_os.control import load_control_actions
from ctf_os.delegation import DelegationError
from ctf_os.race import parse_branch_spec
from ctf_os.race_lineage import (
    LineageError, append_lineage_event, lineage_state, plan_race_generation,
    record_start_failure, recover_lineage_projections,
)
from ctf_os.workspace import start_fresh_attempt
from ctf_os.workspace import append_jsonl_fsync


def _run(tmp_path: Path, mode: SolveMode = SolveMode.ADAPTIVE_RACE) -> Path:
    workspace = tmp_path / "challenge"; (workspace / "input").mkdir(parents=True)
    (workspace / "input" / "x").write_text("x")
    challenge = SimpleNamespace(
        id="c", key="misc/c", category="misc", name="c", remotes=(), description="c",
        hint=None, flag_format="CTF{}", flag_pattern="CTF", input_profile="standard",
    )
    return start_fresh_attempt(workspace, challenge, "fp", mode=mode)


def _branch(name: str, family: str | None = None, **extra):
    return {"branch_id": name, "session_id": name, "hypothesis_family": family or name, **extra}


def _plan(run: Path, mode=SolveMode.ADAPTIVE_RACE, branches=None):
    return plan_race_generation(
        run, race_id="race-1", mode=mode, parent_session_id="sol-main",
        branches=branches or [_branch("one")], frozen_template=mode is SolveMode.FIXED_RACE,
    )


def _ready_running(run: Path, branch="one"):
    append_lineage_event(run, event="CAPACITY_ADMITTED", branch_id=branch, details={"allocation": "r"})
    append_lineage_event(run, event="SANDBOX_READY", branch_id=branch, details={"sandbox": "s"})
    append_lineage_event(run, event="AWAITING_NATIVE_START", branch_id=branch, details={"sandbox": "s"})
    append_lineage_event(run, event="NATIVE_STARTED", branch_id=branch, referenced_receipt={"native": branch})
    append_lineage_event(run, event="RUNNING", branch_id=branch, referenced_receipt={"native": branch})


def test_tier0_maps_to_sol_only_compatibility() -> None:
    assert resolve_solve_mode(tier=0) is SolveMode.SOL_ONLY


def test_legacy_tier_does_not_create_or_start_children(tmp_path: Path) -> None:
    assert resolve_solve_mode(tier=3) is SolveMode.ADAPTIVE_RACE
    assert resolve_solve_mode(tier=3).value == "adaptive-race"
    workspace = tmp_path / "challenge"; (workspace / "input").mkdir(parents=True)
    challenge = SimpleNamespace(
        id="c", key="misc/c", category="misc", name="c", remotes=(), description="c",
        hint=None, flag_format="CTF{}", flag_pattern="CTF", input_profile="standard",
    )
    run = start_fresh_attempt(workspace, challenge, "fp", legacy_tier=3)
    state = json.loads((run / "STATE.json").read_text())
    assert state["solve_mode"] == "adaptive-race" and state["active_child_width"] == 0
    assert state["branches"] == [] and not (run / "RACE_LINEAGE.jsonl").exists()


def test_adaptive_mode_starts_with_zero_active_children(tmp_path: Path) -> None:
    run = _run(tmp_path)
    assert json.loads((run / "STATE.json").read_text())["active_child_width"] == 0


def test_fixed_race_requires_exactly_three_frozen_branch_intents() -> None:
    with pytest.raises(SolveModeError): validate_branch_intents(SolveMode.FIXED_RACE, 2, frozen_template=True)
    with pytest.raises(SolveModeError): validate_branch_intents(SolveMode.FIXED_RACE, 3, frozen_template=False)
    validate_branch_intents(SolveMode.FIXED_RACE, 3, frozen_template=True)
    with pytest.raises(DelegationError, match="frozen category template"):
        parse_branch_spec(
            '[{"session_id":"a"},{"session_id":"b"},{"session_id":"c"}]',
            category="misc", tier=None,
            template_path=Path("ctf_os/resources/delegation-templates.yaml"),
            mode=SolveMode.FIXED_RACE,
        )


def test_benchmark_rejects_tier_as_arm_definition() -> None:
    with pytest.raises(SolveModeError, match="benchmark"):
        resolve_solve_mode("adaptive-race", tier=2, benchmark=True)


def test_conflicting_mode_and_tier_is_rejected() -> None:
    with pytest.raises(SolveModeError, match="conflicting"):
        resolve_solve_mode("sol-only", tier=2)


def test_active_width_counts_only_running_lineage_branches(tmp_path: Path) -> None:
    run = _run(tmp_path); _plan(run, branches=[_branch("a"), _branch("b")])
    _ready_running(run, "a")
    append_lineage_event(run, event="CAPACITY_ADMITTED", branch_id="b", details={"allocation": 1})
    assert lineage_state(run)["active_width"] == 1
    append_lineage_event(run, event="STOP_REQUESTED", branch_id="a", details={"why": "stop"})
    assert lineage_state(run)["active_width"] == 0


def test_initial_and_replacement_branch_use_same_lifecycle(tmp_path: Path) -> None:
    run = _run(tmp_path); _plan(run); _ready_running(run)
    append_lineage_event(run, event="STOP_REQUESTED", branch_id="one", details={"plateau": True})
    append_lineage_event(run, event="NATIVE_STOP_RECORDED", branch_id="one", referenced_receipt={"stop": 1})
    append_jsonl_fsync(run / "RACE_TRANSITIONS.jsonl", {
        "transition_id": "plateau-one", "session_id": "one", "replacement_requests": [],
    })
    append_lineage_event(run, event="PLANNED", branch_id="two", session_id="two", race_id="race-1", generation=1,
                         parent_branch_id="sol-main", supersedes_branch_id="one", hypothesis_family="other",
                         mode=SolveMode.ADAPTIVE_RACE, details={
                             "branch_contract": _branch("two"), "replacement_request_receipt": True,
                             "triggering_receipt_id": "plateau-one", "replacement_trigger_kind": "PLATEAU",
                         })
    _ready_running(run, "two")
    histories = {row["branch_id"]: [e["event"] for e in row["lifecycle_history"]] for row in lineage_state(run)["branches"]}
    assert histories["two"][:6] == histories["one"][:6]


def test_replacement_requires_capacity_sandbox_input_and_native_receipts(tmp_path: Path) -> None:
    run = _run(tmp_path); _plan(run)
    with pytest.raises(LineageError, match="transition"):
        append_lineage_event(run, event="NATIVE_STARTED", branch_id="one", referenced_receipt={"native": 1})


def test_replacement_cannot_start_while_superseded_live_branch_exceeds_width(tmp_path: Path) -> None:
    run = _run(tmp_path); _plan(run, branches=[_branch("a"), _branch("b"), _branch("c")])
    for branch in ("a", "b", "c"): _ready_running(run, branch)
    append_jsonl_fsync(run / "RACE_TRANSITIONS.jsonl", {
        "transition_id": "plateau-a", "session_id": "a", "replacement_requests": [],
    })
    append_lineage_event(run, event="PLANNED", branch_id="d", session_id="d", race_id="race-1", generation=1,
                         parent_branch_id="sol-main", supersedes_branch_id="a", hypothesis_family="d",
                         mode=SolveMode.ADAPTIVE_RACE, details={
                             "branch_contract": _branch("d"), "replacement_request_receipt": True,
                             "triggering_receipt_id": "plateau-a", "replacement_trigger_kind": "PLATEAU",
                         })
    with pytest.raises(LineageError, match="maximum width"):
        append_lineage_event(run, event="CAPACITY_ADMITTED", branch_id="d", details={"allocation": 1})


def test_old_branch_cannot_be_superseded_without_terminal_receipt(tmp_path: Path) -> None:
    run = _run(tmp_path); _plan(run); _ready_running(run)
    with pytest.raises(LineageError, match="transition|terminal receipt"):
        append_lineage_event(run, event="SUPERSEDED", branch_id="one", details={"reason": "plateau"})


def test_started_branch_cannot_be_terminal_before_cleanup_and_release(tmp_path: Path) -> None:
    run = _run(tmp_path); _plan(run); _ready_running(run)
    append_lineage_event(run, event="NATIVE_STOP_RECORDED", branch_id="one", referenced_receipt={"stop": 1})
    with pytest.raises(LineageError, match="sandbox cleanup"):
        append_lineage_event(run, event="TERMINAL", branch_id="one", details={"reason": "early"})


def test_whole_plan_restart_rejected_with_unacknowledged_live_branch(tmp_path: Path) -> None:
    run = _run(tmp_path); _plan(run); _ready_running(run)
    with pytest.raises(LineageError, match="whole-plan restart"):
        plan_race_generation(run, race_id="race-2", mode=SolveMode.ADAPTIVE_RACE,
                             parent_session_id="sol-main", branches=[_branch("two")])
    assert lineage_state(run)["branches"][0]["status"] == "STOP_REQUESTED"
    actions = load_control_actions(run)
    assert actions[0]["action_type"] == "STOP_REQUIRED" and actions[0]["status"] == "PENDING"


def test_unstarted_branch_can_close_with_explicit_not_started_receipt(tmp_path: Path) -> None:
    run = _run(tmp_path); _plan(run)
    append_lineage_event(run, event="SUPERSEDED", branch_id="one", details={"not_started": True})
    append_lineage_event(run, event="TERMINAL", branch_id="one", details={"reason": "NOT_STARTED_SUPERSEDED"})
    assert lineage_state(run)["branches"][0]["terminal"] is True


def test_every_native_session_resolves_to_exactly_one_lineage_branch(tmp_path: Path) -> None:
    run = _run(tmp_path); _plan(run, branches=[_branch("a"), {**_branch("b"), "session_id": "a"}])
    _ready_running(run, "a")
    append_lineage_event(run, event="CAPACITY_ADMITTED", branch_id="b", details={"allocation": 1})
    append_lineage_event(run, event="SANDBOX_READY", branch_id="b", details={"sandbox": 1})
    append_lineage_event(run, event="AWAITING_NATIVE_START", branch_id="b", details={"sandbox": 1})
    with pytest.raises(LineageError, match="native session_id"):
        append_lineage_event(run, event="NATIVE_STARTED", branch_id="b", referenced_receipt={"native": "a"})


def test_lineage_recovery_reconstructs_all_generations(tmp_path: Path) -> None:
    run = _run(tmp_path); _plan(run)
    plan_race_generation(run, race_id="race-2", mode=SolveMode.ADAPTIVE_RACE,
                         parent_session_id="sol-main", branches=[_branch("two")])
    recovered = lineage_state(run)
    assert recovered["generations"] == [1, 2] and recovered["prior_generations"] == [1]


def test_delegation_plan_is_projection_of_lineage(tmp_path: Path) -> None:
    run = _run(tmp_path); _plan(run); _ready_running(run)
    (run / "DELEGATION_PLAN.json").write_text("{broken")
    recover_lineage_projections(run)
    plan = json.loads((run / "DELEGATION_PLAN.json").read_text())
    assert plan["authoritative_source"] == "RACE_LINEAGE.jsonl" and plan["active_width"] == 1


def test_state_branches_are_projection_of_lineage(tmp_path: Path) -> None:
    run = _run(tmp_path); _plan(run)
    state = json.loads((run / "STATE.json").read_text())
    assert state["race_lineage_source"] == "RACE_LINEAGE.jsonl" and state["branches"][0]["status"] == "PLANNED"


def test_terminal_recovery_uses_all_generations_not_only_current_plan(tmp_path: Path) -> None:
    run = _run(tmp_path); _plan(run)
    plan_race_generation(run, race_id="race-2", mode=SolveMode.ADAPTIVE_RACE,
                         parent_session_id="sol-main", branches=[_branch("two")])
    assert {row["branch_id"] for row in lineage_state(run)["branches"]} == {"one", "two"}


def test_quick_lane_start_failure_keeps_sol_running(tmp_path: Path) -> None:
    run = _run(tmp_path); _plan(run)
    record_start_failure(run, branch_id="one", receipt={"failure": "capacity"}, reason="capacity")
    assert json.loads((run / "STATE.json").read_text())["sealed"] is False


def test_adaptive_start_failure_degrades_to_sol_only(tmp_path: Path) -> None:
    run = _run(tmp_path); _plan(run)
    record_start_failure(run, branch_id="one", receipt={"failure": "native"}, reason="native")
    assert lineage_state(run)["active_width"] == 0


def test_fixed_race_start_failure_marks_environment_failure_not_sol_only_success(tmp_path: Path) -> None:
    run = _run(tmp_path, SolveMode.FIXED_RACE)
    _plan(run, SolveMode.FIXED_RACE, [_branch("a"), _branch("b"), _branch("c")])
    record_start_failure(run, branch_id="a", receipt={"failure": "native"}, reason="native")
    outcome = json.loads((run / "RUN_MANIFEST.json").read_text())["outcome"]
    assert outcome["environment_failure"] is True
