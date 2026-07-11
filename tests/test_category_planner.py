from __future__ import annotations

import json

import pytest

from ctf_os.model_routing import ModelRouter
from ctf_os.solver_engine.category_planner import CategoryPlanner, PlanParseError, SolvePlanParser
from ctf_os.solver_engine.context import ChallengeContextBuilder
from ctf_os.solver_engine.prompt import PromptRenderer, SessionHandoff
from ctf_os.solver_engine.race_plan import RaceAttempt, RacePlan


def _payload(**changes):
    raw = {
        "solve_target": "make the validator disclose the stored flag",
        "representation": "validation",
        "mode": "direct",
        "contracts": [{
            "id": "A", "session_role": "exploit", "exclusive_scope": "validator input path",
            "objective": "build and replay a validator bypass",
            "first_decisive_action": "trace the submitted value to its comparison",
            "success_condition": "a replay.py that reproduces one candidate",
            "stop_condition": "the comparison is proven non-bypassable",
            "handoff": "replay.py and the exact input or the eliminated predicate",
            "execution": {
                "backend": "codex", "model_profile": "terra_high",
                "reasoning_effort": "high", "prompt_family": "implementation",
                "timeout_sec": 1200, "tool_strategy": "exploit_build", "priority": 80,
            },
        }],
        "replan_when": "new decisive result",
        "escalate_when": "two distinct branches fail or conceptual ambiguity remains",
    }
    raw.update(changes)
    return raw


def test_category_planner_renders_bounded_state_and_exact_json_instruction() -> None:
    context = ChallengeContextBuilder().build(
        {"id": "check", "title": "Check", "category": "web", "description": "bypass", "remotes": ["https://ctf.example"]},
        files=["/workspace/app.py"],
    )
    prompt = CategoryPlanner().render(
        context, session_id="s1", session_summary="validator path remains",
        findings=["comparison trims NUL"], failures=["SQLi eliminated"],
    )
    assert "You are Sol, the local solve orchestrator" in prompt
    assert 'files: ["/workspace/app.py"]' in prompt
    assert 'authorized_remotes: ["https://ctf.example"]' in prompt
    assert 'decisive_observations: ["comparison trims NUL"]' in prompt
    assert "session_id: s1" in prompt
    assert "rolling_session_summary: validator path remains" in prompt
    assert "Return exactly one JSON object" in prompt
    assert "private chain-of-thought" not in prompt


def test_strict_plan_parser_builds_contract_race_and_worker_prompt() -> None:
    plan = SolvePlanParser().parse(json.dumps(_payload()))
    race = RacePlan.from_solve_plan(plan, id_factory=lambda: "1", seed_factory=lambda: "s")
    context = ChallengeContextBuilder().build({"id": "check", "category": "web"})
    prompt = PromptRenderer().render(context, race.attempts[0])
    assert race.attempts[0].contract == plan.contracts[0]
    assert race.attempts[0].profile.name == "contract_terra_high"
    assert "You own contract A" in prompt
    assert "trace the submitted value" in prompt
    assert "Model profile: terra_high" in prompt
    assert "Reasoning effort: high" in prompt
    assert "Tool strategy: exploit_build" in prompt
    assert race.attempts[0].profile.max_runtime_sec == 1200
    assert "do not continue broad exploration" in prompt


@pytest.mark.parametrize("output", [
    "preface\n" + json.dumps(_payload()),
    json.dumps({**_payload(), "extra": True}),
    json.dumps(_payload(mode="direct", contracts=_payload()["contracts"] * 2)),
    json.dumps(_payload(mode="parallel")),
    json.dumps(_payload(representation="program state")),
])
def test_strict_plan_parser_rejects_prose_unknown_keys_and_inconsistent_modes(output: str) -> None:
    with pytest.raises(PlanParseError):
        SolvePlanParser().parse(output)


def test_strict_plan_parser_rejects_duplicate_contract_scope() -> None:
    first = _payload()["contracts"][0]
    second = {**first, "id": "B", "session_role": "recon"}
    with pytest.raises(PlanParseError, match="exclusive_scope"):
        SolvePlanParser().parse(json.dumps(_payload(mode="parallel", contracts=[first, second])))


def test_contract_worker_name_selects_the_exact_configured_profile() -> None:
    router = ModelRouter.from_file("config/model-routing.yaml")
    selection = router.select_profile("terra_high", role="implementer")
    assert (selection.profile, selection.model, selection.reasoning_effort) == (
        "terra_high", "gpt-5.6-terra", "high",
    )


@pytest.mark.parametrize("execution,match", [
    ({"backend": "shell"}, "backend"),
    ({"reasoning_effort": "medium"}, "reasoning_effort"),
    ({"prompt_family": "general"}, "prompt_family"),
    ({"timeout_sec": 59}, "timeout_sec"),
    ({"tool_strategy": "use_every_tool"}, "tool_strategy"),
    ({"priority": 101}, "priority"),
])
def test_branch_execution_spec_is_strict_and_bounded(execution, match) -> None:
    contract = _payload()["contracts"][0]
    contract = {**contract, "execution": {**contract["execution"], **execution}}
    with pytest.raises(PlanParseError, match=match):
        SolvePlanParser().parse(json.dumps(_payload(contracts=[contract])))


def test_execution_priority_orders_branches_and_profile_is_explicit() -> None:
    first = _payload()["contracts"][0]
    second = {
        **first, "id": "B", "session_role": "recon", "exclusive_scope": "route discovery",
        "execution": {
            **first["execution"], "model_profile": "luna_high", "reasoning_effort": "high",
            "prompt_family": "recon", "timeout_sec": 300, "tool_strategy": "fast_recon",
            "priority": 95,
        },
    }
    plan = SolvePlanParser().parse(json.dumps(_payload(mode="parallel", contracts=[first, second])))
    race = RacePlan.from_solve_plan(plan, id_factory=lambda: "id", seed_factory=lambda: "seed")
    assert [item.contract.id for item in race.attempts] == ["B", "A"]
    assert race.attempts[0].profile.name == "contract_luna_high"
    assert race.attempts[0].profile.role == "recon"
    assert race.attempts[0].profile.max_runtime_sec == 300


def test_same_session_role_can_use_different_model_families() -> None:
    first = _payload()["contracts"][0]
    second = {
        **first, "id": "B", "exclusive_scope": "independent exploit path",
        "execution": {
            **first["execution"], "model_profile": "sol_xhigh", "reasoning_effort": "max",
            "prompt_family": "deep_solve", "tool_strategy": "deep_analysis",
        },
    }
    plan = SolvePlanParser().parse(json.dumps(_payload(mode="parallel", contracts=[first, second])))
    assert {item.session_role for item in plan.contracts} == {"exploit"}
    assert {item.execution.model_profile for item in plan.contracts if item.execution} == {
        "terra_high", "sol_xhigh",
    }


def test_missing_score_never_becomes_easy_and_hard_categories_start_hard() -> None:
    assert RacePlan.for_score(None, category="web").difficulty == "medium"
    assert RacePlan.for_score(None, category="pwn").difficulty == "hard"
    assert RacePlan.for_score(None, category="cryptography").difficulty == "hard"


def test_contract_attempt_carries_session_category_and_validated_handoff() -> None:
    plan = SolvePlanParser().parse(json.dumps(_payload()))
    attempt = RacePlan.from_solve_plan(
        plan, category="web", session_id="session-1", id_factory=lambda: "branch-1",
        seed_factory=lambda: "seed",
    ).attempts[0]
    prompt = PromptRenderer().render(
        ChallengeContextBuilder().build({"id": "check", "category": "web"}), attempt,
        handoff=SessionHandoff(
            session_summary="validator is the active route",
            validated_findings=("NUL survives decoding",),
            replay_artifacts=("handoff/session-1/A/replay.sh",),
            branch_handoffs=("B eliminated SQL injection",),
        ),
    )
    assert attempt.session_id == "session-1"
    assert attempt.branch_kind == "contract"
    assert attempt.category == "web"
    assert "Controller-validated session state" in prompt
    assert "NUL survives decoding" in prompt


def test_session_leader_is_explicit_persistent_sol_role() -> None:
    attempt = RaceAttempt.session_leader("session-1", category="rev", attempt_id="leader", strategy_seed="s")
    router = ModelRouter.from_file("config/model-routing.yaml")
    selected = router.select(role=attempt.profile.role)
    assert attempt.branch_kind == "leader"
    assert selected.model == "gpt-5.6-sol"
    assert selected.reasoning_effort == "max"
    prompt = PromptRenderer().render(
        ChallengeContextBuilder().build({"id": "rev", "category": "rev"}), attempt,
        handoff=SessionHandoff(session_summary="comparison recovered"),
    )
    assert "Return exactly one JSON object" in prompt
    assert "rolling_session_summary: comparison recovered" in prompt
    assert "[FLAG_CANDIDATE]" not in prompt
