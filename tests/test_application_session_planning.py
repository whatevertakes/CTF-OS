from __future__ import annotations

from types import SimpleNamespace

from ctf_os.application import LocalApplication
from ctf_os.solver_engine.race_plan import RacePlan


def _challenge(*, category: str, score: int | None):
    return SimpleNamespace(category=category, score=score)


def test_unscored_exploitation_categories_bootstrap_with_sol_primary() -> None:
    for category in ("pwn", "rev", "crypto"):
        plan = LocalApplication._bootstrap_solve_plan(_challenge(category=category, score=None))
        assert plan.contracts[0].worker == "sol_high"
        assert {contract.worker for contract in plan.contracts} == {
            "sol_high", "terra_high", "luna_medium",
        }


def test_unscored_general_category_is_never_the_old_easy_luna_first_race() -> None:
    plan = LocalApplication._bootstrap_solve_plan(_challenge(category="web", score=None))
    assert tuple(contract.worker for contract in plan.contracts) == ("terra_high", "luna_medium")
    race = RacePlan.from_solve_plan(plan, id_factory=lambda: "id", seed_factory=lambda: "seed")
    assert race.difficulty == "contract"
    assert race.attempts[0].profile.name == "contract_terra_high"


def test_contracts_require_replay_artifact_and_sol_handoff() -> None:
    plan = LocalApplication._bootstrap_solve_plan(_challenge(category="pwn", score=None))
    assert all("replay" in contract.success_condition for contract in plan.contracts)
    assert all("Sol challenge session" in contract.handoff for contract in plan.contracts)
