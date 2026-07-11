from __future__ import annotations

from types import SimpleNamespace

import pytest

from ctf_os.application import LocalApplication, PrerequisiteError
from ctf_os.model_routing import ModelRouter, ModelRoutingError
from ctf_os.solver_engine.category_planner import BranchExecutionSpec, ExecutionContract
from ctf_os.solver_engine.race_plan import RacePlan


def test_router_accepts_only_configured_profile_effort_pair() -> None:
    router = ModelRouter.from_file("config/model-routing.yaml")
    selected = router.select_execution_profile(
        "terra_xhigh", reasoning_effort="max", role="implementer",
    )
    assert (selected.profile, selected.model, selected.reasoning_effort) == (
        "terra_xhigh", "gpt-5.6-terra", "max",
    )
    with pytest.raises(ModelRoutingError, match="must match"):
        router.select_execution_profile(
            "terra_xhigh", reasoning_effort="medium", role="implementer",
        )
    with pytest.raises(ModelRoutingError, match="unknown model profile"):
        router.select_execution_profile(
            "unconfigured", reasoning_effort="max", role="implementer",
        )


def test_contract_timeout_is_the_actual_attempt_timeout() -> None:
    execution = BranchExecutionSpec(
        backend="codex", model_profile="luna_high", reasoning_effort="high",
        prompt_family="recon", timeout_sec=321, tool_strategy="fast_recon", priority=80,
    )
    contract = ExecutionContract(
        id="A", worker="luna_high", session_role="recon", exclusive_scope="headers",
        objective="map routes", first_decisive_action="request root",
        success_condition="route map", stop_condition="routes exhausted", handoff="routes.json",
        execution=execution,
    )
    race = RacePlan.from_solve_plan(SimpleNamespace(contracts=(contract,)), category="web")
    task = SimpleNamespace(race_attempt=race.attempts[0])
    app = object.__new__(LocalApplication)
    assert app._attempt_timeout(task) == 321


def test_contract_timeout_cannot_escape_runtime_bound() -> None:
    execution = BranchExecutionSpec(timeout_sec=5000)
    contract = ExecutionContract(
        id="A", worker="terra_high", exclusive_scope="x", objective="x",
        first_decisive_action="x", success_condition="x", stop_condition="x", handoff="x",
        execution=execution,
    )
    task = SimpleNamespace(race_attempt=SimpleNamespace(contract=contract))
    with pytest.raises(PrerequisiteError, match="between 60 and 3600"):
        object.__new__(LocalApplication)._attempt_timeout(task)


def test_sol_issued_profile_is_not_overridden_by_legacy_failure_promotion() -> None:
    execution = BranchExecutionSpec(
        backend="codex", model_profile="luna_high", reasoning_effort="high",
        prompt_family="recon", timeout_sec=300, tool_strategy="fast_recon", priority=90,
    )
    contract = ExecutionContract(
        id="A", worker="luna_high", session_role="recon", exclusive_scope="one parser fork",
        objective="classify the parser", first_decisive_action="send one discriminating input",
        success_condition="parser family identified", stop_condition="input path exhausted",
        handoff="request and response transcript", execution=execution,
    )
    race_attempt = RacePlan.from_solve_plan(
        SimpleNamespace(contracts=(contract,)), category="web",
    ).attempts[0]
    app = object.__new__(LocalApplication)
    selected = app._primary_selection(
        SimpleNamespace(), SimpleNamespace(), race_attempt,
        router=ModelRouter.from_file("config/model-routing.yaml"),
    )
    assert (selected.profile, selected.model, selected.reasoning_effort) == (
        "luna_high", "gpt-5.6-luna", "high",
    )
