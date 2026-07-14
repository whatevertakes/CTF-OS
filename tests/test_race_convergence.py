from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess

import pytest

from ctf_os.agent_tools.__main__ import main
from ctf_os.agent_tools.__main__ import build_parser
import ctf_os.agent_tools.__main__ as agent_tools
from ctf_os.delegation import (
    BranchCandidate, DelegationError, add_branch, branch_utility, confirm_branch_start,
    init_plan, prepare_branch_replacement, record_admission, update_branch,
)
from ctf_os.events import publish_event
from ctf_os.primitives import PrimitiveEvidenceError
from ctf_os.resources.scheduler import GIB, ResourceLedger, default_request, plan_allocations
from ctf_os.sandbox import runtime
from ctf_os.sandbox.runtime import cleanup, execute
from ctf_os.transitions import evaluate_race_transition


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "solve"; root.mkdir()
    (root / "STATE.json").write_text(json.dumps({
        "schema_version": 1, "challenge_id": "challenge", "input_fingerprint": "fp",
        "status": "PREPARED", "branches": [],
    }))
    init_plan(root, challenge_id="challenge", input_fingerprint="fp", parent_session_id="sol-main", tier=2, tier_reason="test")
    for sid, family, hypothesis in (("race-1", "alias", "prove alias primitive"), ("race-2", "alternate", "find alternate mechanism"), ("race-3", "alias-control", "control alias primitive")):
        candidate = BranchCandidate.create(session_id=sid, role="solver", hypothesis_family=family, hypothesis=hypothesis, scope=["input"], tool_strategy=[sid], expected_artifacts=[f"artifacts/{sid}.py"])
        record_admission(root, input_fingerprint="fp", candidate=candidate)
        add_branch(root, input_fingerprint="fp", candidate=candidate, evidence_contract=["receipt"], success_condition="works", kill_condition="control fails", maximum_steps=10, budget_seconds=60, requested_model_role="solver", requested_reasoning="high")
    return root


def _confirmed() -> dict:
    return {
        "claimed_capability": "alias primitive", "positive_assertion_receipt": "positive.json",
        "negative_control_assertion_receipt": "negative.json", "observed_result": "target aliases; control does not",
        "success_condition_satisfied": True, "kill_condition_evaluated": True,
        "artifact_or_command_receipt": "python count16_alias.py --control", "next_poc_linking_experiment": "link alias to leak",
    }


def test_candidate_is_low_confirmed_requires_controls_and_triggers_takeover(tmp_path: Path) -> None:
    root = _root(tmp_path)
    candidate = {
        "claimed_capability": "alias primitive", "positive_observation": "marker changed",
        "decisive_experiment": "target/control", "success_condition": "target only",
        "kill_condition": "control also changes", "next_confirmation_experiment": "run negative control",
    }
    event = publish_event(root, challenge_id="challenge", input_fingerprint="fp", session_id="race-1", event_type="EXPLOIT_PRIMITIVE_CANDIDATE", summary="alias candidate", primitive=candidate)
    assert event["priority"] == "NORMAL"
    advice = branch_utility(json.loads((root / "DELEGATION_PLAN.json").read_text()), session_id="race-1", checkpoints=[event], result=None)
    assert advice["metrics"]["exploit_proximity"] <= .35 and advice["classification"] != "PROGRESSING"
    with pytest.raises(PrimitiveEvidenceError, match="negative_control"):
        publish_event(root, challenge_id="challenge", input_fingerprint="fp", session_id="race-1", event_type="EXPLOIT_PRIMITIVE_CONFIRMED", summary="bad", primitive={"claimed_capability": "alias"})
    confirmed = publish_event(root, challenge_id="challenge", input_fingerprint="fp", session_id="race-3", event_type="EXPLOIT_PRIMITIVE_CONFIRMED", summary="alias confirmed", primitive=_confirmed(), event_id="confirmed-1")
    transition = confirmed["race_transition"]
    assert transition["sol_takeover"]["required"] is True
    assert transition["objective_rewrites"]
    assert json.loads((root / "STATE.json").read_text())["status"] == "PRIMITIVE_CONFIRMED"
    assert len((root / "RACE_TRANSITIONS.jsonl").read_text().splitlines()) >= 2


def test_plateau_refutation_flag_path_and_idempotence(tmp_path: Path) -> None:
    root = _root(tmp_path)
    for index in range(3):
        publish_event(root, challenge_id="challenge", input_fingerprint="fp", session_id="race-2", event_type="SUPPORTED_FACT", summary=f"fact {index}")
    plateau = evaluate_race_transition(root, {"type": "PLATEAU_3", "event_id": "plateau"}, "race-2", "fp")
    assert any(row["session_id"] == "race-2" for row in plateau["replacement_requests"])
    refuted = publish_event(root, challenge_id="challenge", input_fingerprint="fp", session_id="race-1", event_type="EXPLOIT_PRIMITIVE_REFUTED", summary="alias refuted", primitive={"claimed_capability": "alias primitive", "refutation_receipt": "control matched", "kill_condition_evaluated": True})
    assert refuted["race_transition"]["dependent_invalidations"] == ["race-3"]
    poc = publish_event(root, challenge_id="challenge", input_fingerprint="fp", session_id="race-2", event_type="WORKING_POC", summary="minimal PoC")
    assert poc["race_transition"]["utility_results"]["race-2"]["classification"] == "FLAG_PATH"
    again = evaluate_race_transition(root, {"type": "WORKING_POC", "event_id": poc["event_id"]}, "race-2", "fp")
    assert again["idempotent"] is True


@pytest.mark.parametrize("option", ["--session-id", "--timeout", "--timeout-profile", "--parent-session-id", "--recover-stale"])
def test_sandbox_exec_misplaced_control_option_is_blocked(option: str, capsys: pytest.CaptureFixture[str]) -> None:
    value = [] if option == "--recover-stale" else ["x" if option not in {"--timeout", "--timeout-profile"} else "2" if option == "--timeout" else "quick_probe"]
    code = main(["sandbox-exec", "sandbox.json", option, *value, "--", "true"])
    output = json.loads(capsys.readouterr().out)
    assert code == 2 and "Invalid sandbox-exec option placement" in output["error"]


def test_sandbox_exec_canonical_parser_keeps_only_container_argv_after_separator() -> None:
    args = build_parser().parse_args([
        "sandbox-exec", "--metadata", "sandbox.json", "--timeout-profile", "quick_probe",
        "--session-id", "race-1", "--", "python3", "solve.py",
    ])
    assert args.metadata_option == "sandbox.json"
    assert args.timeout_profile == "quick_probe" and args.session_id == "race-1"
    assert args.argv == ["--", "python3", "solve.py"]


def test_timeout_profile_retains_then_reuses_and_quick_cleans(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    branch = tmp_path / "challenge" / "workers" / "worker"; branch.mkdir(parents=True)
    metadata = {"name": "ctf-os-worker", "branch": "worker", "session_id": "worker", "parent_session_id": "sol-main", "branch_root": str(branch), "metadata_path": str(branch / "sandbox.json"), "labels": {}, "authorized_targets": [], "resources": {"cpus": 1, "memory": "1g"}, "resource_profile": "light"}
    calls = []
    def fake_run(argv, timeout):
        calls.append(list(argv))
        if argv[1] == "exec" and "sleep" in argv:
            return subprocess.CompletedProcess(argv, 124, "", "command timed out")
        if argv[1] == "inspect":
            return subprocess.CompletedProcess(argv, 1, "", "No such object")
        if any("ps -o pid=,stat= --sid" in str(part) for part in argv):
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[1:5] == ["exec", "--user", "0:0", "ctf-os-worker"] and "cat" in argv:
            return subprocess.CompletedProcess(argv, 0, "4242\n", "")
        return subprocess.CompletedProcess(argv, 0, "ok", "")
    monkeypatch.setattr(runtime, "_run", fake_run)
    retained = execute(metadata, ["sleep", "3"], 2, timeout_profile="symbolic_slice")
    assert retained["timeout_status"] == "TIMED_OUT_RETAINED" and not any(call[1:3] == ["rm", "--force"] for call in calls)
    assert execute(metadata, ["true"], 2, timeout_profile="symbolic_slice")["exit_code"] == 0
    cleaned = execute(metadata, ["sleep", "3"], 2, timeout_profile="quick_probe")
    assert cleaned["timeout_status"] == "TIMED_OUT_CLEANED"


def test_expired_retention_ttl_is_cleaned_only_by_gc_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    worker = tmp_path / "output" / "c" / "pwn" / "x" / "workers" / "race-1"; worker.mkdir(parents=True)
    (worker / "sandbox.json").write_text("{}")
    (worker / "timeout-receipt.json").write_text(json.dumps({
        "status": "TIMED_OUT_RETAINED", "recorded_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
        "retention_ttl_seconds": 60,
    }))
    monkeypatch.setattr(agent_tools, "_load_metadata", lambda *_: {"name": "ctf-os-old"})
    monkeypatch.setattr(agent_tools, "cleanup", lambda *_, **__: {"removed": True, "container": "ctf-os-old"})
    result = agent_tools._cleanup_expired_timeout_retention(tmp_path, "sol-main")
    assert result == [{"metadata": str(worker / "sandbox.json"), "removed": True, "container": "ctf-os-old"}]


def test_atomic_replacement_start_and_terminal_invariants(tmp_path: Path) -> None:
    root = _root(tmp_path)
    candidate = BranchCandidate.create(session_id="race-4", role="solver", hypothesis_family="write-corruption", hypothesis="use a write mechanism", scope=["input"], tool_strategy=["write-test"], expected_artifacts=["artifacts/write.py"])
    record = prepare_branch_replacement(root, input_fingerprint="fp", superseded_branch_id="race-2", candidate=candidate, kill_reason="plateau", distinct_mechanism_proof="write corruption differs from alternate parsing", evidence_contract=["receipt"], success_condition="write", kill_condition="no write", maximum_steps=5, budget_seconds=30, requested_model_role="solver", requested_reasoning="high")
    plan = json.loads((root / "DELEGATION_PLAN.json").read_text())
    assert record["branch_registration"] and next(row for row in plan["branches"] if row["session_id"] == "race-2")["status"] == "REPLACED"
    with pytest.raises(DelegationError, match="start receipt"):
        update_branch(root, input_fingerprint="fp", session_id="race-4", status="RUNNING")
    with pytest.raises(DelegationError, match="terminal"):
        update_branch(root, input_fingerprint="fp", session_id="race-4", status="ERROR")
    sandbox = root / "workers" / "race-4" / "sandbox.json"; sandbox.parent.mkdir(parents=True); sandbox.write_text("{}")
    receipt = confirm_branch_start(root, input_fingerprint="fp", replacement_request_id=record["replacement_request_id"], session_id="race-4", native_session_observed="native-child-4", runtime_observation_evidence="runtime tree receipt", sandbox_metadata_path="workers/race-4/sandbox.json")
    assert receipt["native_session_observed"] == "native-child-4"


def test_candidate_does_not_scale_and_three_samples_do(tmp_path: Path) -> None:
    request = default_request(contest="c", challenge_id="x", session_id="s", workload_class="symbolic-execution")
    capacity = {"cpu": {"usable": 10, "reserved": 0}, "memory": {"usable_bytes": 24 * GIB, "reserved_bytes": 0}, "storage": {"usable_bytes": 40 * GIB, "reserved_bytes": 0}, "gpu": {"devices": []}}
    candidate = plan_allocations([request], capacity, observations={"s": {"progress": {"primitive_candidate": True}}})
    assert candidate["allocations"]["s"]["cpus"] == request.min_cpus
    starved = plan_allocations([request], capacity, observations={"s": {"classification": "CPU_STARVED", "progress": {"coverage": 10}}})
    assert starved["allocations"]["s"]["cpus"] > request.min_cpus


def test_resize_failure_circuit_breaker(tmp_path: Path) -> None:
    ledger = ResourceLedger(tmp_path)
    request = default_request(contest="c", challenge_id="x", session_id="s", workload_class="symbolic-execution")
    ledger.request(request, actor_session_id="sol-main", actor_role="sol")
    state = ledger.load(); state["allocations"]["s"] = {"cpus": 2, "memory_bytes": 4 * GIB}; state["observations"]["s"].update({"classification": "CPU_STARVED", "progress": {"coverage": 1}})
    (tmp_path / "RESOURCE_STATE.json").write_text(json.dumps(state))
    capacity = {"cpu": {"usable": 10, "reserved": 2}, "memory": {"usable_bytes": 24 * GIB, "reserved_bytes": 4 * GIB}, "storage": {"usable_bytes": 40 * GIB, "reserved_bytes": 0}, "gpu": {"devices": []}}
    for _ in range(2):
        plan = ledger.plan(capacity); ledger.reconcile_apply(plan, [{"session_id": "s", "applied": False, "reason": "permission denied"}])
    assert ledger.load()["observations"]["s"]["resize_circuit"]["state"] == "RESIZE_CIRCUIT_OPEN"
    assert not ledger.plan(capacity)["resize_actions"]
