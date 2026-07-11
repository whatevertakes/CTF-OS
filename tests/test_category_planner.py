from __future__ import annotations

import json

import pytest

from ctf_os.model_routing import ModelRouter
from ctf_os.solver_engine.category_planner import CategoryPlanner, PlanParseError, SolvePlanParser
from ctf_os.solver_engine.context import ChallengeContextBuilder
from ctf_os.solver_engine.prompt import PromptRenderer
from ctf_os.solver_engine.race_plan import RacePlan


def _payload(**changes):
    raw = {
        "solve_target": "make the validator disclose the stored flag",
        "representation": "validation",
        "mode": "direct",
        "contracts": [{
            "id": "A", "worker": "terra_high", "exclusive_scope": "validator input path",
            "objective": "build and replay a validator bypass",
            "first_decisive_action": "trace the submitted value to its comparison",
            "success_condition": "a replay.py that reproduces one candidate",
            "stop_condition": "the comparison is proven non-bypassable",
            "handoff": "replay.py and the exact input or the eliminated predicate",
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
    prompt = CategoryPlanner().render(context, findings=["comparison trims NUL"], failures=["SQLi eliminated"])
    assert "You are Sol, the local solve orchestrator" in prompt
    assert 'files: ["/workspace/app.py"]' in prompt
    assert 'authorized_remotes: ["https://ctf.example"]' in prompt
    assert 'decisive_observations: ["comparison trims NUL"]' in prompt
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
    second = {**first, "id": "B", "worker": "luna_medium"}
    with pytest.raises(PlanParseError, match="exclusive_scope"):
        SolvePlanParser().parse(json.dumps(_payload(mode="parallel", contracts=[first, second])))


def test_contract_worker_name_selects_the_exact_configured_profile() -> None:
    router = ModelRouter.from_file("config/model-routing.yaml")
    selection = router.select_profile("terra_high", role="implementer")
    assert (selection.profile, selection.model, selection.reasoning_effort) == (
        "terra_high", "gpt-5.6-terra", "high",
    )
