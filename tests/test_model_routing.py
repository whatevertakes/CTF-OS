from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from ctf_os.delegation import (
    BranchCandidate, DelegationError, add_branch, confirm_branch_start, init_plan,
    load_plan, record_admission, record_branch_sandbox_ready,
    record_capacity_admission, record_start_failure,
    validate_native_start_receipt_binding,
)
from ctf_os.doctor import inspect_codex_routing_capabilities
from ctf_os.model_routing import (
    RoutingError, branch_routing_interpretation, build_native_delegation_packet,
    build_routing_contract, compare_runtime_routing, max_endgame_eligibility,
    max_lease_status, recommend_routing_profile, validate_ultra_guard,
)
from ctf_os.modes import SolveMode
from ctf_os.race import RaceBranchSpec, start_race_plan
from ctf_os.transitions import evaluate_race_transition


def _contract(profile: str, **context: object) -> dict[str, object]:
    base = {
        "role": "worker", "purpose": "parallel-race",
        "hypothesis": "test one concrete sink", "decisive_experiment": "run target and control",
        **context,
    }
    return build_routing_contract(
        profile, routing_reason=f"test {profile}",
        routing_evidence=["receipt:test:1"], branch_evidence=base,
    )


def _race_root(tmp_path: Path, rows: list[dict[str, object]]) -> tuple[Path, list[RaceBranchSpec]]:
    root = tmp_path / "run"
    root.mkdir()
    (root / "input").mkdir()
    (root / "STATE.json").write_text(json.dumps({
        "schema_version": 1, "challenge_id": "challenge", "input_fingerprint": "fp",
        "target_revision": 1, "status": "PREPARED", "branches": [],
    }))
    specs = [RaceBranchSpec.from_mapping(row, index=index) for index, row in enumerate(rows)]
    start_race_plan(
        root, challenge_id="challenge", input_fingerprint="fp",
        parent_session_id="sol-main", category="misc", tier=None,
        tier_reason="routing tests", branch_specs=specs,
        mode=SolveMode.ADAPTIVE_RACE,
    )
    return root, specs


def _ready(root: Path, *session_ids: str) -> None:
    record_capacity_admission(
        root, input_fingerprint="fp", admitted_session_ids=list(session_ids),
    )
    for session_id in session_ids:
        metadata = root / "workers" / session_id / "sandbox.json"
        metadata.parent.mkdir(parents=True)
        metadata.write_text("{}")
        record_branch_sandbox_ready(
            root, input_fingerprint="fp", session_id=session_id,
            sandbox_metadata_path=str(metadata), input_available=True,
        )


def _legacy_max_root(tmp_path: Path) -> Path:
    root = tmp_path / "max-run"
    root.mkdir()
    (root / "STATE.json").write_text(json.dumps({
        "schema_version": 1, "challenge_id": "challenge", "input_fingerprint": "fp",
        "status": "PREPARED", "branches": [],
    }))
    init_plan(
        root, challenge_id="challenge", input_fingerprint="fp",
        parent_session_id="sol-main", tier=0, tier_reason="routing test",
    )
    candidate = BranchCandidate.create(
        session_id="max-lane", role="exact-endgame",
        hypothesis_family="endgame-link", hypothesis="solve exact endgame constraint",
        scope=["challenge"], tool_strategy=["two-decisive-experiments"],
        expected_artifacts=["artifacts/endgame.py"],
    )
    record_admission(root, input_fingerprint="fp", candidate=candidate)
    evidence = {
        "primitive_confirmed": True, "specific_blocker_present": True,
        "blocker_type": "MATH_CONSTRAINT", "xhigh_decisive_experiments": 1,
        "working_poc_present": False, "flag_path_present": False,
    }
    add_branch(
        root, input_fingerprint="fp", candidate=candidate,
        evidence_contract=["receipt:primitive", "receipt:blocker", "receipt:xhigh"],
        success_condition="working PoC", kill_condition="primitive refuted",
        maximum_steps=10, budget_seconds=600,
        requested_model_role="sol-equivalent", requested_reasoning="max",
        routing_contract=build_routing_contract(
            "CONFIRMED_BOTTLENECK", routing_reason="exact confirmed endgame blocker",
            routing_evidence=["receipt:primitive", "receipt:blocker", "receipt:xhigh"],
            branch_evidence=evidence,
        ),
        routing_evidence_context=evidence,
    )
    plan = json.loads((root / "DELEGATION_PLAN.json").read_text())
    branch = plan["branches"][0]
    branch.update({
        "status": "RUNNING", "started_at": "2026-01-01T00:00:00Z",
        "observed_runtime_model": "gpt-5.6-sol", "observed_reasoning": "max",
        "runtime_observation_status": "OBSERVED",
        "routing_classification": "ROUTING_MATCHED", "routing_matched": True,
        "start_receipt": {
            "receipt_id": "native-max-start", "started_at": "2026-01-01T00:00:00Z",
            "observed_model": "gpt-5.6-sol", "observed_reasoning": "max",
            "routing_classification": "ROUTING_MATCHED",
        },
    })
    (root / "DELEGATION_PLAN.json").write_text(json.dumps(plan))
    return root


def _legacy_xhigh_root(tmp_path: Path) -> Path:
    root = tmp_path / "xhigh-run"
    root.mkdir()
    (root / "STATE.json").write_text(json.dumps({
        "schema_version": 1, "challenge_id": "challenge", "input_fingerprint": "fp",
        "status": "PREPARED", "branches": [],
    }))
    init_plan(
        root, challenge_id="challenge", input_fingerprint="fp",
        parent_session_id="sol-main", tier=0, tier_reason="routing test",
    )
    candidate = BranchCandidate.create(
        session_id="deep-lane", role="solver", hypothesis_family="constraint",
        hypothesis="derive a constraint endgame", scope=["challenge"],
        tool_strategy=["decisive-experiment"],
        expected_artifacts=["artifacts/deep.py"],
    )
    record_admission(root, input_fingerprint="fp", candidate=candidate)
    context = {
        "purpose": "independent-full-solve", "hypothesis": candidate.hypothesis,
        "high_complexity_mechanism": True,
    }
    add_branch(
        root, input_fingerprint="fp", candidate=candidate,
        evidence_contract=["receipt:deep"], success_condition="primitive",
        kill_condition="control refutes", maximum_steps=20, budget_seconds=1200,
        requested_model_role="sol-equivalent", requested_reasoning="xhigh",
        routing_contract=build_routing_contract(
            "DEEP_SOLVER", routing_reason="new difficult constraint mechanism",
            routing_evidence=["receipt:deep"], branch_evidence=context,
        ),
        routing_evidence_context=context,
    )
    plan = json.loads((root / "DELEGATION_PLAN.json").read_text())
    branch = plan["branches"][0]
    branch.update({
        "status": "RUNNING", "started_at": "2026-07-21T00:00:00Z",
        "observed_runtime_model": "gpt-5.6-sol", "observed_reasoning": "xhigh",
        "runtime_observation_status": "OBSERVED",
        "routing_classification": "ROUTING_MATCHED", "routing_matched": True,
        "start_receipt": {
            "receipt_id": "native-deep-start", "started_at": "2026-07-21T00:00:00Z",
            "observed_model": "gpt-5.6-sol", "observed_reasoning": "xhigh",
            "routing_classification": "ROUTING_MATCHED",
        },
    })
    (root / "DELEGATION_PLAN.json").write_text(json.dumps(plan))
    milestones = [
        {
            "receipt_id": "primitive-receipt", "session_id": "deep-lane",
            "event_type": "PRIMITIVE_CONFIRMED",
        },
        {
            "receipt_id": "decisive-receipt", "session_id": "deep-lane",
            "event_type": "DECISIVE_EXPERIMENT",
        },
        {
            "receipt_id": "blocker-receipt", "session_id": "deep-lane",
            "event_type": "TYPED_BLOCKER",
            "details": {"blocker_type": "MATH_CONSTRAINT"},
        },
    ]
    (root / "milestone-receipts.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in milestones)
    )
    return root


def test_policy_recommendations_use_mechanism_and_artifact_evidence() -> None:
    mechanical = recommend_routing_profile({
        "role": "helper", "mechanical_only": True,
        "hypothesis": "filter logs and normalize candidate inputs",
    })
    implementation = recommend_routing_profile({
        "role": "builder", "primitive_confirmed": True,
        "implementation_only": True, "hypothesis": "implement minimal exploit script",
    })
    independent = recommend_routing_profile({
        "purpose": "independent-full-solve", "hypothesis": "shortest flag path",
    })
    alternate = recommend_routing_profile({
        "purpose": "alternate-attack-family", "high_complexity_mechanism": True,
        "hypothesis": "derive a distinct heap exploit chain",
    })
    assert mechanical["routing_profile"] == "MECHANICAL"
    mechanical_contract = _contract("MECHANICAL")
    assert mechanical_contract["requested_model_class"] == "luna-equivalent"
    assert mechanical_contract["requested_reasoning"] == "medium"
    assert build_routing_contract(
        "MECHANICAL", routing_reason="bounded fixed batch",
        routing_evidence=["receipt:batch"],
        branch_evidence={"mechanical_only": True, "hypothesis": "normalize inputs"},
        requested_reasoning="high",
    )["requested_reasoning"] == "high"
    mechanical_high = build_routing_contract(
        "MECHANICAL", routing_reason="carefully verify normalized batch",
        routing_evidence=["receipt:batch-high"],
        branch_evidence={"mechanical_only": True, "hypothesis": "normalize inputs"},
        requested_reasoning="high",
    )
    assert build_native_delegation_packet(
        mechanical_high, task_name="batch", child_prompt={"hypothesis": "normalize"},
    )["custom_agent_profile"] == "ctf_mechanical_high"
    assert implementation["routing_profile"] == "IMPLEMENTATION"
    implementation_contract = _contract(
        "IMPLEMENTATION", primitive_confirmed=True,
        implementation_only=True, hypothesis="implement payload",
    )
    assert implementation_contract["requested_model_class"] == "terra-equivalent"
    assert implementation_contract["requested_reasoning"] == "high"
    assert independent["routing_profile"] == "DEEP_SOLVER"
    assert _contract(
        "DEEP_SOLVER", purpose="independent-full-solve",
    )["requested_reasoning"] == "xhigh"
    assert alternate["routing_profile"] == "DEEP_SOLVER"


def test_max_requires_exact_reasoning_bottleneck_and_never_tool_or_compute() -> None:
    exact = {
        "primitive_confirmed": True, "specific_blocker_present": True,
        "blocker_type": "MATH_CONSTRAINT", "xhigh_decisive_experiments": 1,
        "working_poc_present": False, "flag_path_present": False,
    }
    assert max_endgame_eligibility(exact)["eligible"] is True
    max_contract = _contract("CONFIRMED_BOTTLENECK", **exact)
    assert max_contract["requested_model_class"] == "sol-equivalent"
    assert max_contract["requested_reasoning"] == "max"
    for blocker in ("TOOL_FAILURE", "LONG_COMPUTE"):
        status = max_endgame_eligibility({**exact, "blocker_type": blocker})
        assert status["eligible"] is False
    with pytest.raises(RoutingError, match="Max exact trigger"):
        _contract("CONFIRMED_BOTTLENECK", primitive_confirmed=False)
    with pytest.raises(RoutingError, match="active_max_lane"):
        build_routing_contract(
            "CONFIRMED_BOTTLENECK", routing_reason="exact blocker",
            routing_evidence=["receipt:max"], branch_evidence=exact,
            active_max_lanes=1,
        )


def test_luna_independent_and_terra_new_complex_mechanism_are_rejected() -> None:
    with pytest.raises(RoutingError, match="Luna-equivalent"):
        build_routing_contract(
            "MECHANICAL", routing_reason="bad", routing_evidence=["receipt:bad"],
            branch_evidence={
                "purpose": "independent-full-solve", "hypothesis": "independent-full-solve",
            },
        )
    with pytest.raises(RoutingError, match="Terra-equivalent"):
        build_routing_contract(
            "IMPLEMENTATION", routing_reason="bad", routing_evidence=["receipt:bad"],
            branch_evidence={
                "high_complexity_mechanism": True,
                "hypothesis": "derive a new crypto attack",
            },
        )


def test_native_packet_selects_exact_supported_custom_agent() -> None:
    contract = _contract(
        "IMPLEMENTATION", primitive_confirmed=True,
        implementation_only=True, hypothesis="implement payload",
    )
    packet = build_native_delegation_packet(
        contract, task_name="payload-lane", child_prompt={"hypothesis": "write payload"},
    )
    assert packet["custom_agent_profile"] == "ctf_terra_high"
    assert packet["requested_agent_type"] == "ctf_terra_high"
    assert packet["requested_model"] == "gpt-5.6-terra"
    assert packet["requested_reasoning"] == "high"
    assert packet["start_asynchronously"] is True


@pytest.mark.parametrize(
    ("status", "model", "reasoning", "expected"),
    [
        ("OBSERVED", "gpt-5.6-terra", "high", "ROUTING_MATCHED"),
        ("OBSERVED", "gpt-5.6-sol", "xhigh", "FALLBACK_MATCHED"),
        ("OBSERVED", "gpt-5.6-luna", "medium", "ROUTING_MISMATCH"),
        ("NOT_OBSERVABLE", None, None, "RUNTIME_NOT_OBSERVABLE"),
        ("UNSUPPORTED", None, None, "ROUTING_UNSUPPORTED"),
        ("CONFLICT", None, None, "ROUTING_MISMATCH"),
    ],
)
def test_requested_observed_comparison_states(
    status: str, model: str | None, reasoning: str | None, expected: str,
) -> None:
    contract = _contract(
        "IMPLEMENTATION", primitive_confirmed=True,
        implementation_only=True, hypothesis="implement payload",
    )
    result = compare_runtime_routing(
        contract, observed_model=model, observed_reasoning=reasoning,
        runtime_observation_status=status,
        runtime_observation_evidence="thread/start receipt" if status == "OBSERVED" else "surface did not expose identity",
    )
    assert result["routing_classification"] == expected
    assert result["fallback_used"] is (expected == "FALLBACK_MATCHED")
    if expected != "ROUTING_MATCHED":
        assert result["model_routing_matched"] is False


def test_routing_fields_survive_planned_to_native_start_and_observation_is_not_copied(
    tmp_path: Path,
) -> None:
    root, _ = _race_root(tmp_path, [{
        "session_id": "impl", "role": "payload-builder",
        "hypothesis_family": "confirmed-sink", "hypothesis": "implement minimal payload",
        "scope": ["challenge"], "tool_strategy": ["python"],
        "expected_artifacts": ["artifacts/exploit.py"],
        "mechanism_confirmed": True, "implementation_only": True,
        "routing_profile": "IMPLEMENTATION", "routing_reason": "sink is confirmed",
        "routing_evidence": ["receipt:primitive-1"],
    }])
    planned = load_plan(root, input_fingerprint="fp")["branches"][0]
    assert planned["routing_profile"] == "IMPLEMENTATION"
    assert planned["requested_model"] == "gpt-5.6-terra"
    assert planned["observed_runtime_model"] is None
    assert planned["prompt_packet"]["native_delegation_packet"]["custom_agent_profile"] == "ctf_terra_high"
    _ready(root, "impl")
    receipt = confirm_branch_start(
        root, input_fingerprint="fp", replacement_request_id="initial-race",
        session_id="impl", native_session_observed="thread-impl",
        runtime_observation_evidence="thread/start response model and reasoning",
        sandbox_metadata_path="workers/impl/sandbox.json",
        native_start_operation_id="spawn-impl-1",
        observed_model="gpt-5.6-terra", observed_reasoning="high",
        runtime_observation_status="OBSERVED",
    )
    assert receipt["routing_classification"] == "ROUTING_MATCHED"
    assert receipt["run_id"] == root.name
    assert receipt["attempt_id"]
    assert receipt["parent_session_id"] == "sol-main"
    started = load_plan(root, input_fingerprint="fp")["branches"][0]
    assert started["observed_runtime_model"] == "gpt-5.6-terra"
    assert started["routing_matched"] is True


def test_native_start_operation_collision_and_cross_run_binding_are_rejected(
    tmp_path: Path,
) -> None:
    common = {
        "role": "bounded", "hypothesis_family": "sink",
        "hypothesis": "test one concrete sink", "scope": ["challenge"],
        "tool_strategy": ["probe"], "expected_artifacts": ["artifacts/probe.txt"],
        "routing_profile": "BOUNDED_EXPERIMENT", "routing_reason": "one sink",
        "routing_evidence": ["receipt:sink"],
    }
    root, _ = _race_root(tmp_path, [
        {**common, "session_id": "one"},
        {**common, "session_id": "two", "hypothesis_family": "oracle", "hypothesis": "test one concrete oracle"},
    ])
    _ready(root, "one", "two")
    receipt = confirm_branch_start(
        root, input_fingerprint="fp", replacement_request_id="initial-race",
        session_id="one", native_session_observed="thread-one",
        runtime_observation_evidence="thread/start one",
        sandbox_metadata_path="workers/one/sandbox.json",
        native_start_operation_id="spawn-shared",
        observed_model="gpt-5.6-terra", observed_reasoning="high",
        runtime_observation_status="OBSERVED",
    )
    with pytest.raises(DelegationError, match="operation ID conflicts"):
        confirm_branch_start(
            root, input_fingerprint="fp", replacement_request_id="initial-race",
            session_id="two", native_session_observed="thread-two",
            runtime_observation_evidence="thread/start two",
            sandbox_metadata_path="workers/two/sandbox.json",
            native_start_operation_id="spawn-shared",
            observed_model="gpt-5.6-terra", observed_reasoning="high",
            runtime_observation_status="OBSERVED",
        )
    with pytest.raises(DelegationError, match="another run/session"):
        validate_native_start_receipt_binding(
            receipt, run_id="different-run", challenge_id="challenge",
            input_fingerprint="fp", target_revision=1, session_id="one",
        )


def test_legacy_branch_and_receipt_interpretation_remain_unrouted() -> None:
    legacy = compare_runtime_routing(
        None, observed_model=None, observed_reasoning=None,
        runtime_observation_status="NOT_OBSERVABLE",
        runtime_observation_evidence="legacy receipt",
    )
    assert legacy["routing_classification"] == "LEGACY_UNROUTED"
    interpretation = branch_routing_interpretation({
        "session_id": "legacy", "requested_reasoning": "high",
    })
    assert interpretation["routing_classification"] == "LEGACY_UNROUTED"
    assert interpretation["attributed_model"] is None


def test_legacy_plan_receipt_loads_without_new_routing_fields(tmp_path: Path) -> None:
    root = tmp_path / "legacy"
    root.mkdir()
    (root / "STATE.json").write_text(json.dumps({
        "schema_version": 1, "challenge_id": "challenge", "input_fingerprint": "fp",
        "status": "PREPARED", "branches": [],
    }))
    init_plan(
        root, challenge_id="challenge", input_fingerprint="fp",
        parent_session_id="sol-main", tier=1, tier_reason="legacy",
    )
    candidate = BranchCandidate.create(
        session_id="legacy-lane", role="solver", hypothesis_family="legacy",
        hypothesis="legacy hypothesis", scope=["input"], tool_strategy=["probe"],
        expected_artifacts=["artifacts/legacy.py"],
    )
    record_admission(root, input_fingerprint="fp", candidate=candidate)
    add_branch(
        root, input_fingerprint="fp", candidate=candidate,
        evidence_contract=["legacy receipt"], success_condition="works",
        kill_condition="fails", maximum_steps=5, budget_seconds=60,
        requested_model_role="solver", requested_reasoning="high",
    )
    raw = json.loads((root / "DELEGATION_PLAN.json").read_text())
    branch = raw["branches"][0]
    for field in (
        "routing_profile", "requested_model_class", "requested_model", "routing_reason",
        "routing_evidence", "fallback_profile", "fallback_reason", "routing_classification",
        "model_routing_matched", "reasoning_routing_matched", "routing_matched",
        "fallback_used", "fallback_reason_observed", "runtime_observation_status",
    ):
        branch.pop(field, None)
    branch["start_receipt"] = {
        "schema_version": 1, "native_session_observed": "legacy-native",
        "runtime_observation_evidence": "legacy runtime tree",
    }
    (root / "DELEGATION_PLAN.json").write_text(json.dumps(raw))
    loaded = load_plan(root, input_fingerprint="fp")["branches"][0]
    assert loaded["routing_profile"] == "LEGACY_UNROUTED"
    assert loaded["routing_classification"] == "LEGACY_UNROUTED"
    assert loaded["requested_model"] is None


def test_start_failure_never_becomes_routing_success(tmp_path: Path) -> None:
    root, _ = _race_root(tmp_path, [{
        "session_id": "bounded", "role": "bounded",
        "hypothesis_family": "sink", "hypothesis": "test one sink",
        "scope": ["challenge"], "tool_strategy": ["probe"],
        "expected_artifacts": ["artifacts/probe.txt"],
        "routing_profile": "BOUNDED_EXPERIMENT", "routing_reason": "one sink",
        "routing_evidence": ["receipt:sink"],
    }])
    _ready(root, "bounded")
    record_start_failure(
        root, branch_id="bounded",
        receipt={"status": "START_FAILED", "operation_id": "spawn-failed"},
        reason="native spawn rejected",
    )
    branch = load_plan(root, input_fingerprint="fp")["branches"][0]
    assert branch["status"] == "START_FAILED"
    assert branch.get("routing_matched") is False
    assert branch.get("observed_runtime_model") is None


def test_max_lease_expires_on_time_or_two_decisive_experiments() -> None:
    branch = {
        "routing_profile": "CONFIRMED_BOTTLENECK",
        "start_receipt": {"started_at": "2026-01-01T00:00:00Z"},
    }
    assert max_lease_status(branch, decisive_experiments=2)["reason"] == "two_decisive_experiments_completed"


def test_expired_max_lane_recommends_stop_and_reclaim(tmp_path: Path) -> None:
    root = _legacy_max_root(tmp_path)
    transition = evaluate_race_transition(
        root, {"type": "CONTROL_LOOP_TICK", "event_id": "max-expiry"},
        "max-lane", "fp",
    )
    expired = [
        row for row in transition["recommended_actions"]
        if row["action"] == "MAX_LEASE_EXPIRED"
    ]
    assert len(expired) == 1
    assert expired[0]["stop_and_reclaim"] is True


def test_exact_xhigh_receipts_recommend_one_bounded_max_endgame(tmp_path: Path) -> None:
    root = _legacy_xhigh_root(tmp_path)
    transition = evaluate_race_transition(
        root, {"type": "TYPED_BLOCKER", "event_id": "typed-blocker"},
        "deep-lane", "fp",
    )
    actions = {row["action"]: row for row in transition["recommended_actions"]}
    assert "REASONING_ESCALATION_RECOMMENDED" in actions
    assert "MAX_ENDGAME_RECOMMENDED" in actions
    contract = actions["MAX_ENDGAME_RECOMMENDED"]["routing_contract"]
    assert contract["routing_profile"] == "CONFIRMED_BOTTLENECK"
    assert contract["routing_evidence"] == [
        "primitive-receipt", "blocker-receipt", "decisive-receipt",
    ]
    assert contract["max_lease"]["maximum_seconds"] == 600


def test_working_poc_ends_max_lane_and_hands_artifact_to_sol(tmp_path: Path) -> None:
    root = _legacy_max_root(tmp_path)
    transition = evaluate_race_transition(
        root, {"type": "WORKING_POC", "event_id": "max-poc"},
        "max-lane", "fp",
    )
    action_types = [row["action"] for row in transition["recommended_actions"]]
    assert "SOL_TAKEOVER" in action_types
    assert "STOP_LOW_VALUE_BRANCH" in action_types
    assert transition["max_continuation_allowed"] is False


def test_ultra_cannot_nest_with_adaptive_or_fixed_race() -> None:
    assert validate_ultra_guard(
        "adaptive-race", observed_reasoning="ultra",
    )["valid"] is False
    assert validate_ultra_guard(
        "fixed-race", observed_reasoning="ultra",
    )["valid"] is False
    assert validate_ultra_guard(
        "sol-only", observed_reasoning="ultra", separate_experiment=True,
    )["valid"] is True
    assert validate_ultra_guard(
        "adaptive-race", observed_reasoning=None,
    )["status"] == "NOT_OBSERVABLE"


def test_doctor_validates_custom_agents_against_catalog_and_runtime_schema(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    agents = repo / ".codex" / "agents"
    agents.mkdir(parents=True)
    source = Path(".codex/agents")
    for item in source.glob("*.toml"):
        (agents / item.name).write_text(item.read_text())
    models = []
    for slug, efforts in (
        ("gpt-5.6-luna", ["medium", "high"]),
        ("gpt-5.6-terra", ["high"]),
        ("gpt-5.6-sol", ["xhigh", "max"]),
    ):
        models.append({
            "slug": slug,
            "supported_reasoning_levels": [{"effort": effort} for effort in efforts],
        })

    def fake_run(argv: list[str], timeout: int = 30, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[1:] == ["--version"]:
            return subprocess.CompletedProcess(argv, 0, "codex-cli test\n", "")
        if argv[1:] == ["features", "list"]:
            return subprocess.CompletedProcess(argv, 0, "multi_agent stable true\n", "")
        if argv[1:] == ["debug", "models"]:
            return subprocess.CompletedProcess(argv, 0, json.dumps({"models": models}), "")
        if "generate-json-schema" in argv:
            out = Path(argv[-1]); (out / "v2").mkdir(parents=True)
            (out / "codex_app_server_protocol.schemas.json").write_text(
                '{"CollabAgentToolCallThreadItem":{"model":{},"reasoningEffort":{}}}'
            )
            (out / "v2" / "ThreadStartResponse.json").write_text(
                '{"model":{},"reasoningEffort":{}}'
            )
            return subprocess.CompletedProcess(argv, 0, "", "")
        return subprocess.CompletedProcess(argv, 1, "", "unsupported")

    monkeypatch.setattr("ctf_os.doctor.shutil.which", lambda _name: "/usr/bin/codex")
    capabilities = inspect_codex_routing_capabilities(repo, run=fake_run)
    assert capabilities["native_delegation"] == "SUPPORTED"
    assert capabilities["model_override"] == "SUPPORTED"
    assert capabilities["reasoning_override"] == "SUPPORTED"
    assert capabilities["direct_native_override"] == "UNSUPPORTED"
    assert capabilities["custom_agent_profile_selection"] == "SUPPORTED"
    assert capabilities["runtime_identity_observation"] == "SUPPORTED"
    assert capabilities["max_reasoning"] == "SUPPORTED"
    assert capabilities["model_session_launched"] is False
