from __future__ import annotations

import unittest

from ctf_os.benchmark import (
    ASSISTED,
    MANAGED_OBSERVE,
    MANAGED_X22_TREATMENT,
    BenchmarkError,
    CohortSample,
    SafetyTotals,
    evaluate_managed_promotion,
    evaluate_x22,
    evaluate_x23,
    evaluate_x24,
    evaluate_x25,
)


def sample(
    cohort: str,
    *,
    consistency=(1.0,) * 20,
    cost=(1.0,) * 20,
    landings=(1.0,) * 20,
    solve_at_3=(1.0,) * 20,
    safety=None,
):
    return CohortSample(
        cohort=cohort,
        budget_mode="bounded",
        consistency=tuple(consistency),
        cost_per_solve=tuple(cost),
        landings_per_hour=tuple(landings),
        solve_at_3=tuple(solve_at_3),
        safety=(
            safety
            if safety is not None
            else SafetyTotals(
                complete_run_records=60,
                terminal_run_records=60,
            )
        ),
    )


class BenchmarkGateTests(unittest.TestCase):
    def test_promotion_requires_safety_noninferiority_and_improvement(self):
        baseline = sample(
            ASSISTED,
            consistency=(0.8,) * 20,
            cost=(10.0,) * 20,
            landings=(1.0,) * 20,
            solve_at_3=(0.8,) * 20,
        )
        managed = sample(
            MANAGED_OBSERVE,
            consistency=(0.86,) * 20,
            cost=(8.9,) * 20,
            landings=(1.11,) * 20,
            solve_at_3=(0.8,) * 20,
        )
        result = evaluate_managed_promotion(baseline, managed)
        self.assertEqual(result["decision"], "promote")
        self.assertFalse(result["default_changed"])

        unsafe = sample(
            MANAGED_OBSERVE,
            consistency=(0.86,) * 20,
            cost=(8.9,) * 20,
            landings=(1.11,) * 20,
            solve_at_3=(0.8,) * 20,
            safety=SafetyTotals(
                orphan_runs=1,
                complete_run_records=59,
                terminal_run_records=60,
            ),
        )
        self.assertEqual(
            evaluate_managed_promotion(baseline, unsafe)["decision"],
            "continue_canary",
        )

    def test_promotion_refuses_x22_and_unbounded_cohort_mixing(self):
        baseline = sample(ASSISTED)
        treatment = sample(MANAGED_X22_TREATMENT)
        with self.assertRaisesRegex(BenchmarkError, "never X22"):
            evaluate_managed_promotion(baseline, treatment)
        managed = sample(MANAGED_OBSERVE)
        unbounded = CohortSample(
            cohort=managed.cohort,
            budget_mode="unbounded",
            consistency=managed.consistency,
            cost_per_solve=managed.cost_per_solve,
            landings_per_hour=managed.landings_per_hour,
            solve_at_3=managed.solve_at_3,
            safety=managed.safety,
        )
        with self.assertRaisesRegex(BenchmarkError, "bounded cohorts"):
            evaluate_managed_promotion(baseline, unbounded)

    def test_experiment_stop_conditions_are_frozen(self):
        x22 = evaluate_x22(
            [100, 100, 100, 100],
            [81, 81, 81, 81],
            [10, 10, 10, 10],
            [9, 9, 9, 9],
        )
        self.assertEqual(x22["decision"], "observe")
        self.assertFalse(x22["production_barrier_changed"])
        self.assertTrue(
            evaluate_x23(valid_role_outputs=8, total_role_outputs=10)
        )
        self.assertFalse(
            evaluate_x23(valid_role_outputs=7, total_role_outputs=10)
        )
        self.assertTrue(evaluate_x24(real_flag_misses=0))
        self.assertFalse(evaluate_x24(real_flag_misses=1))
        self.assertTrue(
            evaluate_x25(
                control_human_interventions=[3, 4],
                treatment_human_interventions=[1, 2],
            )
        )


if __name__ == "__main__":
    unittest.main()
