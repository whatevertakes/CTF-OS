from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import math
import unittest

from ctf_os.benchmark import (
    ASSISTED,
    BLIND,
    CTF_OS_SYSTEM,
    DEV,
    HIDDEN,
    LIVE,
    MANAGED_OBSERVE,
    MANAGED_X22_TREATMENT,
    REGRESSION,
    THIN_SCAFFOLD,
    BenchmarkExecutionFingerprint,
    BlindLivePromotionEvidence,
    BenchmarkError,
    CohortSample,
    FixedBenchmarkBudget,
    PromotionArm,
    PromotionAttempt,
    PromotionCase,
    PromotionCaseResult,
    PromotionSplit,
    SafetyTotals,
    evaluate_blind_live_promotion,
    evaluate_managed_promotion,
    evaluate_x22,
    evaluate_x23,
    evaluate_x24,
    evaluate_x25,
)


PROMOTION_CATEGORIES = (
    "pwn",
    "web",
    "rev",
    "crypto",
    "forensics",
    "misc",
)
PROMOTION_CASES = {
    DEV: (("dev-case", "pwn"),),
    REGRESSION: (("regression-case", "web"),),
    BLIND: tuple(
        (f"blind-{category}", category)
        for category in PROMOTION_CATEGORIES
    ),
    LIVE: tuple(
        (f"live-{category}", category)
        for category in PROMOTION_CATEGORIES
    ),
}


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


def promotion_split(name: str) -> PromotionSplit:
    return PromotionSplit(
        name=name,
        cases=tuple(
            PromotionCase(
                case_id=case_id,
                category=category,
                input_manifest_sha256=hashlib.sha256(
                    case_id.encode("utf-8")
                ).hexdigest(),
            )
            for case_id, category in PROMOTION_CASES[name]
        ),
        trajectory_visible=name == DEV,
        answers_visible=False,
        prior_engine_runs=1 if name == REGRESSION else 0,
    )


def promotion_result(
    case_id: str,
    *,
    seconds: float = 10.0,
    solved: tuple[bool, bool, bool] = (True, True, True),
    proof_evaluated: tuple[bool, bool, bool] = (True, True, True),
    proof: tuple[bool, bool, bool] = (True, True, True),
    reproduction_evaluated: tuple[bool, bool, bool] = (True, True, True),
    reproduced: tuple[bool, bool, bool] = (True, True, True),
    interventions: int = 1,
    run_namespace: str = "candidate",
) -> PromotionCaseResult:
    attempts = tuple(
        PromotionAttempt(
            attempt=index,
            run_id=f"{run_namespace}-{case_id}-run-{index}",
            solved=solved[index - 1],
            proof_evaluated=proof_evaluated[index - 1],
            proof_passed=proof[index - 1],
            reproduction_evaluated=reproduction_evaluated[index - 1],
            reproduced=reproduced[index - 1],
            first_valid_result_seconds=(
                seconds if solved[index - 1] else None
            ),
            solve_wall_seconds_used=seconds,
            model_calls_used=4,
            total_tokens_used=50_000,
            human_interventions=interventions,
        )
        for index in (1, 2, 3)
    )
    return PromotionCaseResult(case_id=case_id, attempts=attempts)


def promotion_evidence() -> BlindLivePromotionEvidence:
    splits = tuple(
        promotion_split(name)
        for name in (DEV, REGRESSION, BLIND, LIVE)
    )
    baseline_results = tuple(
        promotion_result(case_id, run_namespace="baseline")
        for name in (DEV, REGRESSION, BLIND, LIVE)
        for case_id, _category in PROMOTION_CASES[name]
    )
    candidate_results = tuple(
        promotion_result(
            case_id,
            seconds=5.0 if name == LIVE else 10.0,
        )
        for name in (DEV, REGRESSION, BLIND, LIVE)
        for case_id, _category in PROMOTION_CASES[name]
    )
    budget = FixedBenchmarkBudget(
        wall_seconds=60,
        model_call_limit=8,
        total_token_limit=100_000,
    )
    safety = SafetyTotals(
        complete_run_records=7,
        terminal_run_records=7,
    )
    fingerprint = BenchmarkExecutionFingerprint(
        tool_manifest_sha256="1" * 64,
        image_sha256="2" * 64,
        model_config_sha256="3" * 64,
        engine_source_sha256="4" * 64,
    )
    return BlindLivePromotionEvidence(
        splits=splits,
        baseline=PromotionArm(
            system=THIN_SCAFFOLD,
            model_id="same-model",
            budget=budget,
            results=baseline_results,
            safety=safety,
            execution_fingerprint=fingerprint,
        ),
        candidate=PromotionArm(
            system=CTF_OS_SYSTEM,
            model_id="same-model",
            budget=budget,
            results=candidate_results,
            safety=safety,
            execution_fingerprint=fingerprint,
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


class BlindLivePromotionGateTests(unittest.TestCase):
    def test_complete_paired_holdout_improvement_is_manually_eligible(self):
        result = evaluate_blind_live_promotion(promotion_evidence())

        self.assertEqual(
            result["decision"],
            "eligible_for_manual_promotion",
        )
        self.assertTrue(result["promotion_eligible"])
        self.assertTrue(result["complete_evidence"])
        self.assertFalse(result["default_changed"])
        self.assertEqual(result["blockers"], [])
        self.assertEqual(
            result["metrics"]["candidate"]["overall"]["solve@1"]["rate"],
            1.0,
        )
        self.assertEqual(
            result["metrics"]["candidate"]["overall"]["pass^2/3"]["rate"],
            1.0,
        )
        self.assertEqual(
            result["metrics"]["candidate"]["by_split"][LIVE][
                "median_time_to_first_valid_result"
            ]["seconds"],
            5.0,
        )
        self.assertTrue(
            result["comparisons"]["live_hidden_improvement"]
        )
        self.assertTrue(
            result["comparisons"][
                "live_hidden_efficiency_improvement"
            ]
        )
        self.assertEqual(
            result["comparisons"][
                "live_hidden_efficiency_improvement_signals"
            ],
            [
                "live:per_qualified_case:solve_wall_seconds_used",
                "live:per_qualified_attempt:solve_wall_seconds_used",
            ],
        )
        self.assertEqual(
            result["metrics"]["candidate"]["by_split"][LIVE][
                "qualified_solve_efficiency"
            ]["per_qualified_attempt"]["model_calls_used"],
            4.0,
        )

    def test_split_visibility_and_prior_exposure_fail_closed(self):
        evidence = promotion_evidence()
        splits = list(evidence.splits)
        splits[0] = replace(splits[0], trajectory_visible=False)
        splits[1] = replace(splits[1], answers_visible=True)
        splits[2] = replace(
            splits[2],
            trajectory_visible=True,
            prior_engine_runs=1,
        )

        result = evaluate_blind_live_promotion(
            replace(evidence, splits=tuple(splits))
        )

        self.assertFalse(result["promotion_eligible"])
        self.assertIn("dev_trajectory_not_visible", result["blockers"])
        self.assertIn(
            "answer_leakage:regression",
            result["blockers"],
        )
        self.assertIn("trajectory_leakage:blind", result["blockers"])
        self.assertIn("prior_exposure:blind", result["blockers"])
        self.assertFalse(result["default_changed"])

    def test_missing_live_split_and_results_never_promote(self):
        evidence = promotion_evidence()
        splits = tuple(
            split for split in evidence.splits if split.name != LIVE
        )
        live_case_ids = {
            case_id for case_id, _category in PROMOTION_CASES[LIVE]
        }
        baseline_results = tuple(
            result
            for result in evidence.baseline.results
            if result.case_id not in live_case_ids
        )
        candidate_results = tuple(
            result
            for result in evidence.candidate.results
            if result.case_id not in live_case_ids
        )
        safety = SafetyTotals(
            complete_run_records=9,
            terminal_run_records=9,
        )

        result = evaluate_blind_live_promotion(
            replace(
                evidence,
                splits=splits,
                baseline=replace(
                    evidence.baseline,
                    results=baseline_results,
                    safety=safety,
                ),
                candidate=replace(
                    evidence.candidate,
                    results=candidate_results,
                    safety=safety,
                ),
            )
        )

        self.assertEqual(result["decision"], "do_not_promote")
        self.assertIn("missing_required_split:live", result["blockers"])
        self.assertFalse(result["complete_evidence"])

    def test_partial_records_and_partial_markers_fail_closed(self):
        evidence = promotion_evidence()
        candidate_results = list(evidence.candidate.results)
        candidate_results[0] = replace(
            candidate_results[0],
            attempts=candidate_results[0].attempts[:2],
        )

        result = evaluate_blind_live_promotion(
            replace(
                evidence,
                evidence_complete=False,
                candidate=replace(
                    evidence.candidate,
                    evidence_complete=False,
                    results=tuple(candidate_results),
                ),
            )
        )

        self.assertFalse(result["promotion_eligible"])
        self.assertFalse(result["complete_evidence"])
        self.assertIsNone(result["metrics"])
        self.assertIn(
            "promotion_evidence_incomplete",
            result["blockers"],
        )
        self.assertIn(
            "candidate_arm_evidence_incomplete",
            result["blockers"],
        )
        self.assertIn(
            "candidate_attempt_coverage_incomplete",
            result["blockers"],
        )

    def test_boolean_nan_and_wrong_container_types_are_rejected(self):
        evidence = promotion_evidence()
        with self.assertRaisesRegex(BenchmarkError, "wall_seconds"):
            evaluate_blind_live_promotion(
                replace(
                    evidence,
                    baseline=replace(
                        evidence.baseline,
                        budget=replace(
                            evidence.baseline.budget,
                            wall_seconds=True,
                        ),
                    ),
                )
            )
        with self.assertRaisesRegex(BenchmarkError, "finite and positive"):
            first_result = evidence.candidate.results[0]
            attempts = list(first_result.attempts)
            attempts[0] = replace(
                attempts[0],
                first_valid_result_seconds=math.nan,
            )
            evaluate_blind_live_promotion(
                replace(
                    evidence,
                    candidate=replace(
                        evidence.candidate,
                        results=(
                            replace(
                                first_result,
                                attempts=tuple(attempts),
                            ),
                            *evidence.candidate.results[1:],
                        ),
                    ),
                )
            )
        with self.assertRaisesRegex(BenchmarkError, "must be a tuple"):
            evaluate_blind_live_promotion(
                replace(evidence, splits=list(evidence.splits))
            )
        with self.assertRaisesRegex(BenchmarkError, "schema"):
            evaluate_blind_live_promotion(
                replace(evidence, schema_version=True)
            )

    def test_unknown_category_is_rejected_instead_of_becoming_a_floor(self):
        evidence = promotion_evidence()
        first_split = evidence.splits[0]
        typo_case = replace(first_split.cases[0], category="forensic")
        with self.assertRaisesRegex(BenchmarkError, "canonical categories"):
            evaluate_blind_live_promotion(
                replace(
                    evidence,
                    splits=(
                        replace(first_split, cases=(typo_case,)),
                        *evidence.splits[1:],
                    ),
                )
            )

    def test_public_only_improvement_does_not_promote(self):
        evidence = promotion_evidence()
        candidate_results = tuple(
            promotion_result(
                case_id,
                seconds=5.0 if name == DEV else 10.0,
            )
            for name in (DEV, REGRESSION, BLIND, LIVE)
            for case_id, _category in PROMOTION_CASES[name]
        )

        result = evaluate_blind_live_promotion(
            replace(
                evidence,
                candidate=replace(
                    evidence.candidate,
                    results=candidate_results,
                ),
            )
        )

        self.assertTrue(result["comparisons"]["public_improvement"])
        self.assertFalse(
            result["comparisons"]["live_hidden_improvement"]
        )
        self.assertIn(
            "no_live_hidden_improvement",
            result["blockers"],
        )
        self.assertFalse(result["promotion_eligible"])

    def test_category_floor_regression_blocks_promotion(self):
        evidence = promotion_evidence()
        candidate_results = list(evidence.candidate.results)
        live_crypto_case = next(
            case_id
            for case_id, category in PROMOTION_CASES[LIVE]
            if category == "crypto"
        )
        live_index = next(
            index
            for index, result in enumerate(candidate_results)
            if result.case_id == live_crypto_case
        )
        candidate_results[live_index] = promotion_result(
            live_crypto_case,
            seconds=5.0,
            solved=(False, True, True),
            proof=(False, True, True),
            reproduced=(False, True, True),
        )

        result = evaluate_blind_live_promotion(
            replace(
                evidence,
                candidate=replace(
                    evidence.candidate,
                    results=tuple(candidate_results),
                ),
            )
        )

        self.assertIn("category_floor_regression", result["blockers"])
        self.assertFalse(
            result["comparisons"]["category_floor_noninferior"]
        )
        self.assertEqual(
            result["metrics"]["candidate"]["live_hidden"][
                "category_floor"
            ]["rate"],
            0.5,
        )
        self.assertFalse(result["promotion_eligible"])

    def test_holdout_category_coverage_and_split_width_are_mandatory(self):
        evidence = promotion_evidence()
        live_split = next(
            split for split in evidence.splits if split.name == LIVE
        )
        removed_case_id = next(
            case.case_id
            for case in live_split.cases
            if case.category == "misc"
        )
        narrowed_live = replace(
            live_split,
            cases=tuple(
                case
                for case in live_split.cases
                if case.case_id != removed_case_id
            ),
        )
        splits = tuple(
            narrowed_live if split.name == LIVE else split
            for split in evidence.splits
        )
        baseline_results = tuple(
            result
            for result in evidence.baseline.results
            if result.case_id != removed_case_id
        )
        candidate_results = tuple(
            result
            for result in evidence.candidate.results
            if result.case_id != removed_case_id
        )

        result = evaluate_blind_live_promotion(
            replace(
                evidence,
                splits=splits,
                baseline=replace(
                    evidence.baseline,
                    results=baseline_results,
                ),
                candidate=replace(
                    evidence.candidate,
                    results=candidate_results,
                ),
            )
        )

        self.assertIn(
            "insufficient_holdout_split_cases:live",
            result["blockers"],
        )
        self.assertIn(
            "insufficient_holdout_category_cases:misc",
            result["blockers"],
        )
        self.assertEqual(
            result["comparisons"]["holdout_category_case_counts"]["misc"],
            1,
        )
        self.assertFalse(result["promotion_eligible"])

    def test_missing_holdout_category_returns_closed_decision(self):
        evidence = promotion_evidence()
        splits = tuple(
            replace(
                split,
                cases=tuple(
                    replace(case, category="pwn")
                    if case.category == "misc"
                    else case
                    for case in split.cases
                ),
            )
            if split.name in {BLIND, LIVE}
            else split
            for split in evidence.splits
        )

        result = evaluate_blind_live_promotion(
            replace(evidence, splits=splits)
        )

        self.assertEqual(result["decision"], "do_not_promote")
        self.assertIn("missing_holdout_category:misc", result["blockers"])
        self.assertFalse(
            result["comparisons"]["holdout_category_noninferiority"][
                "misc"
            ]["solve@1"]
        )
        self.assertFalse(result["default_changed"])

    def test_model_and_budget_mismatch_block_thin_scaffold_comparison(self):
        evidence = promotion_evidence()
        mismatch = evaluate_blind_live_promotion(
            replace(
                evidence,
                candidate=replace(
                    evidence.candidate,
                    model_id="different-model",
                    budget=replace(
                        evidence.candidate.budget,
                        model_call_limit=9,
                    ),
                ),
            )
        )

        self.assertIn("model_mismatch", mismatch["blockers"])
        self.assertIn("budget_mismatch", mismatch["blockers"])
        self.assertFalse(mismatch["promotion_eligible"])
        self.assertFalse(mismatch["default_changed"])

    def test_unproved_unreproduced_or_unsafe_results_never_promote(self):
        evidence = promotion_evidence()
        candidate_results = list(evidence.candidate.results)
        live_result = candidate_results[-1]
        attempts = list(live_result.attempts)
        attempts[0] = replace(
            attempts[0],
            proof_passed=False,
            reproduced=False,
        )
        candidate_results[-1] = replace(
            live_result,
            attempts=tuple(attempts),
        )
        unsafe = SafetyTotals(
            false_proofs=1,
            complete_run_records=7,
            terminal_run_records=7,
        )

        result = evaluate_blind_live_promotion(
            replace(
                evidence,
                candidate=replace(
                    evidence.candidate,
                    results=tuple(candidate_results),
                    safety=unsafe,
                ),
            )
        )

        self.assertIn("candidate_unproved_solve", result["blockers"])
        self.assertIn("candidate_unreproduced_solve", result["blockers"])
        self.assertIn("candidate_safety_violation", result["blockers"])
        self.assertFalse(result["promotion_eligible"])

    def test_candidate_success_case_requires_two_qualified_attempts(self):
        evidence = promotion_evidence()
        weak_case_id = "blind-pwn"
        pattern = (True, False, False)

        def replace_case(
            results: tuple[PromotionCaseResult, ...],
            *,
            namespace: str,
        ) -> tuple[PromotionCaseResult, ...]:
            return tuple(
                promotion_result(
                    result.case_id,
                    solved=pattern,
                    proof=pattern,
                    reproduced=pattern,
                    run_namespace=namespace,
                )
                if result.case_id == weak_case_id
                else result
                for result in results
            )

        outcome = evaluate_blind_live_promotion(
            replace(
                evidence,
                baseline=replace(
                    evidence.baseline,
                    results=replace_case(
                        evidence.baseline.results,
                        namespace="baseline",
                    ),
                ),
                candidate=replace(
                    evidence.candidate,
                    results=replace_case(
                        evidence.candidate.results,
                        namespace="candidate",
                    ),
                ),
            )
        )

        self.assertFalse(outcome["promotion_eligible"])
        self.assertIn(
            "candidate_success_case_not_qualified_2_of_3:blind-pwn",
            outcome["blockers"],
        )
        self.assertIn(
            "baseline_success_case_not_qualified_2_of_3:blind-pwn",
            outcome["blockers"],
        )
        self.assertEqual(
            outcome["metrics"]["candidate"]["by_split"][BLIND][
                "qualified_solve_efficiency"
            ]["qualified_cases"],
            5,
        )

    def test_unqualified_baseline_uses_zero_to_positive_total_policy(self):
        evidence = promotion_evidence()
        baseline_results = tuple(
            promotion_result(
                result.case_id,
                proof=(False, False, False),
                reproduced=(False, False, False),
                run_namespace="baseline",
            )
            for result in evidence.baseline.results
        )

        result = evaluate_blind_live_promotion(
            replace(
                evidence,
                baseline=replace(
                    evidence.baseline,
                    results=baseline_results,
                ),
            )
        )

        self.assertFalse(result["promotion_eligible"])
        self.assertIn("baseline_unproved_solve", result["blockers"])
        self.assertIn(
            "baseline_success_case_not_qualified_2_of_3:dev-case",
            result["blockers"],
        )
        self.assertFalse(
            any(
                blocker.startswith(
                    "qualified_efficiency_zero_denominator:"
                )
                for blocker in result["blockers"]
            )
        )
        self.assertEqual(
            result["comparisons"][
                "overall_qualified_efficiency_comparison"
            ]["per_qualified_case"]["mode"],
            "baseline_zero_candidate_positive_total_pareto",
        )
        self.assertTrue(
            result["comparisons"][
                "overall_qualified_efficiency_comparison"
            ]["per_qualified_attempt"][
                "outcome_efficiency_improvement"
            ]
        )
        self.assertEqual(
            result["metrics"]["baseline"]["overall"][
                "proof_pass_rate"
            ]["rate"],
            0.0,
        )
        self.assertIsNone(
            result["metrics"]["baseline"]["overall"][
                "qualified_solve_efficiency"
            ]["per_qualified_case"]["model_calls_used"]
        )
        self.assertEqual(
            result["metrics"]["baseline"]["overall"][
                "reproduction_rate"
            ]["rate"],
            0.0,
        )

    def test_zero_baseline_positive_candidate_pareto_can_promote(self):
        evidence = promotion_evidence()
        baseline_results = tuple(
            promotion_result(
                result.case_id,
                solved=(False, False, False),
                proof=(False, False, False),
                reproduced=(False, False, False),
                run_namespace="baseline",
            )
            for result in evidence.baseline.results
        )

        result = evaluate_blind_live_promotion(
            replace(
                evidence,
                baseline=replace(
                    evidence.baseline,
                    results=baseline_results,
                ),
            )
        )

        self.assertTrue(result["promotion_eligible"])
        live_comparison = result["comparisons"][
            "split_qualified_efficiency_comparisons"
        ][LIVE]
        overall_comparison = result["comparisons"][
            "overall_qualified_efficiency_comparison"
        ]
        for comparison in (live_comparison, overall_comparison):
            for denominator in (
                "per_qualified_case",
                "per_qualified_attempt",
            ):
                self.assertEqual(
                    comparison[denominator]["mode"],
                    "baseline_zero_candidate_positive_total_pareto",
                )
                self.assertTrue(
                    comparison[denominator][
                        "outcome_efficiency_improvement"
                    ]
                )
                self.assertTrue(
                    all(
                        comparison[denominator][
                            "noninferiority"
                        ].values()
                    )
                )
        self.assertIn(
            "live:per_qualified_case:outcome_pareto_gain",
            result["comparisons"][
                "live_hidden_efficiency_improvement_signals"
            ],
        )

    def test_split_and_overall_denominator_modes_are_independent(self):
        evidence = promotion_evidence()
        baseline_results = tuple(
            promotion_result(
                result.case_id,
                solved=(False, False, False),
                proof=(False, False, False),
                reproduced=(False, False, False),
                run_namespace="baseline",
            )
            if result.case_id.startswith("live-")
            else result
            for result in evidence.baseline.results
        )

        result = evaluate_blind_live_promotion(
            replace(
                evidence,
                baseline=replace(
                    evidence.baseline,
                    results=baseline_results,
                ),
            )
        )

        self.assertTrue(result["promotion_eligible"])
        self.assertEqual(
            result["comparisons"][
                "split_qualified_efficiency_comparisons"
            ][LIVE]["per_qualified_case"]["mode"],
            "baseline_zero_candidate_positive_total_pareto",
        )
        self.assertEqual(
            result["comparisons"][
                "overall_qualified_efficiency_comparison"
            ]["per_qualified_case"]["mode"],
            "per_qualified_ratio",
        )

    def test_zero_baseline_positive_candidate_requires_total_pareto(self):
        evidence = promotion_evidence()
        baseline_results = tuple(
            promotion_result(
                result.case_id,
                solved=(False, False, False),
                proof=(False, False, False),
                reproduced=(False, False, False),
                run_namespace="baseline",
            )
            for result in evidence.baseline.results
        )
        candidate_results = tuple(
            replace(
                result,
                attempts=tuple(
                    replace(attempt, model_calls_used=5)
                    for attempt in result.attempts
                ),
            )
            for result in evidence.candidate.results
        )

        result = evaluate_blind_live_promotion(
            replace(
                evidence,
                baseline=replace(
                    evidence.baseline,
                    results=baseline_results,
                ),
                candidate=replace(
                    evidence.candidate,
                    results=candidate_results,
                ),
            )
        )

        self.assertFalse(result["promotion_eligible"])
        self.assertIn(
            "split_efficiency_total_regression:"
            "live:per_qualified_case:model_calls_used",
            result["blockers"],
        )
        self.assertIn(
            "overall_efficiency_total_regression:"
            "per_qualified_attempt:model_calls_used",
            result["blockers"],
        )
        self.assertIn(
            "split_category_efficiency_total_regression:"
            "live:pwn:per_qualified_case:model_calls_used",
            result["blockers"],
        )
        self.assertIn(
            "holdout_category_efficiency_total_regression:"
            "pwn:per_qualified_attempt:model_calls_used",
            result["blockers"],
        )
        live_comparison = result["comparisons"][
            "split_qualified_efficiency_comparisons"
        ][LIVE]["per_qualified_attempt"]
        self.assertFalse(
            live_comparison["outcome_efficiency_improvement"]
        )
        self.assertNotIn(
            "live:per_qualified_attempt:outcome_pareto_gain",
            result["comparisons"][
                "live_hidden_efficiency_improvement_signals"
            ],
        )

    def test_both_zero_uses_totals_without_improvement_signal(self):
        evidence = promotion_evidence()

        def zero_results(
            results: tuple[PromotionCaseResult, ...],
            *,
            namespace: str,
            candidate: bool,
        ) -> tuple[PromotionCaseResult, ...]:
            return tuple(
                promotion_result(
                    result.case_id,
                    seconds=(
                        5.0
                        if candidate
                        and result.case_id.startswith("live-")
                        else 10.0
                    ),
                    solved=(False, False, False),
                    proof=(False, False, False),
                    reproduced=(False, False, False),
                    run_namespace=namespace,
                )
                for result in results
            )

        result = evaluate_blind_live_promotion(
            replace(
                evidence,
                baseline=replace(
                    evidence.baseline,
                    results=zero_results(
                        evidence.baseline.results,
                        namespace="baseline",
                        candidate=False,
                    ),
                ),
                candidate=replace(
                    evidence.candidate,
                    results=zero_results(
                        evidence.candidate.results,
                        namespace="candidate",
                        candidate=True,
                    ),
                ),
            )
        )

        self.assertFalse(result["promotion_eligible"])
        for scope_comparison in (
            result["comparisons"][
                "split_qualified_efficiency_comparisons"
            ][LIVE],
            result["comparisons"][
                "overall_qualified_efficiency_comparison"
            ],
        ):
            for denominator in (
                "per_qualified_case",
                "per_qualified_attempt",
            ):
                self.assertEqual(
                    scope_comparison[denominator]["mode"],
                    "both_zero_total_nonincrease",
                )
                self.assertTrue(
                    all(
                        scope_comparison[denominator][
                            "noninferiority"
                        ].values()
                    )
                )
                self.assertFalse(
                    scope_comparison[denominator][
                        "outcome_efficiency_improvement"
                    ]
                )
        self.assertEqual(
            result["comparisons"][
                "live_hidden_efficiency_improvement_signals"
            ],
            [],
        )
        self.assertIn(
            "no_live_hidden_efficiency_improvement",
            result["blockers"],
        )

    def test_positive_baseline_zero_candidate_is_outcome_regression(self):
        evidence = promotion_evidence()
        candidate_results = tuple(
            promotion_result(
                result.case_id,
                solved=(False, False, False),
                proof=(False, False, False),
                reproduced=(False, False, False),
                run_namespace="candidate",
            )
            for result in evidence.candidate.results
        )

        result = evaluate_blind_live_promotion(
            replace(
                evidence,
                candidate=replace(
                    evidence.candidate,
                    results=candidate_results,
                ),
            )
        )

        self.assertFalse(result["promotion_eligible"])
        self.assertIn(
            "qualified_efficiency_outcome_regression:"
            "live:per_qualified_case",
            result["blockers"],
        )
        self.assertIn(
            "qualified_efficiency_outcome_regression:"
            "overall:per_qualified_attempt",
            result["blockers"],
        )
        self.assertIn(
            "split_category_efficiency_outcome_regression:"
            "live:pwn:per_qualified_case",
            result["blockers"],
        )
        self.assertIn(
            "holdout_category_efficiency_outcome_regression:"
            "pwn:per_qualified_attempt",
            result["blockers"],
        )
        self.assertEqual(
            result["comparisons"][
                "split_qualified_efficiency_comparisons"
            ][LIVE]["per_qualified_case"]["mode"],
            "baseline_positive_candidate_zero_regression",
        )

    def test_actual_resource_regression_blocks_faster_candidate(self):
        evidence = promotion_evidence()

        for resource, worse_value in (
            ("model_calls_used", 5),
            ("total_tokens_used", 60_000),
        ):
            with self.subTest(resource=resource):
                candidate_results = tuple(
                    replace(
                        result,
                        attempts=tuple(
                            replace(
                                attempt,
                                **{resource: worse_value},
                            )
                            for attempt in result.attempts
                        ),
                    )
                    if result.case_id.startswith("live-")
                    else result
                    for result in evidence.candidate.results
                )

                outcome = evaluate_blind_live_promotion(
                    replace(
                        evidence,
                        candidate=replace(
                            evidence.candidate,
                            results=candidate_results,
                        ),
                    )
                )

                self.assertFalse(outcome["promotion_eligible"])
                self.assertTrue(
                    outcome["comparisons"]["live_hidden_improvement"]
                )
                self.assertIn(
                    "split_efficiency_regression:live:"
                    f"per_qualified_case:{resource}",
                    outcome["blockers"],
                )
                self.assertIn(
                    "overall_efficiency_regression:"
                    f"per_qualified_attempt:{resource}",
                    outcome["blockers"],
                )

    def test_holdout_category_efficiency_regression_cannot_be_offset(self):
        evidence = promotion_evidence()
        candidate_results = tuple(
            replace(
                result,
                attempts=tuple(
                    replace(
                        attempt,
                        solve_wall_seconds_used=11.0,
                    )
                    for attempt in result.attempts
                ),
            )
            if result.case_id == "live-pwn"
            else result
            for result in evidence.candidate.results
        )

        result = evaluate_blind_live_promotion(
            replace(
                evidence,
                candidate=replace(
                    evidence.candidate,
                    results=candidate_results,
                ),
            )
        )

        self.assertFalse(result["promotion_eligible"])
        self.assertTrue(
            result["comparisons"][
                "split_qualified_efficiency_noninferiority"
            ][LIVE]["per_qualified_case"]["solve_wall_seconds_used"]
        )
        self.assertTrue(
            result["comparisons"][
                "overall_qualified_efficiency_noninferiority"
            ]["per_qualified_attempt"]["solve_wall_seconds_used"]
        )
        self.assertIn(
            "split_category_efficiency_regression:"
            "live:pwn:per_qualified_case:solve_wall_seconds_used",
            result["blockers"],
        )
        self.assertIn(
            "holdout_category_efficiency_regression:"
            "pwn:per_qualified_attempt:solve_wall_seconds_used",
            result["blockers"],
        )
        split_category = result["comparisons"][
            "holdout_split_category_qualified_efficiency_comparisons"
        ][LIVE]["pwn"]["per_qualified_case"]
        aggregate_category = result["comparisons"][
            "holdout_category_qualified_efficiency_comparisons"
        ]["pwn"]["per_qualified_attempt"]
        self.assertEqual(
            split_category["mode"],
            "per_qualified_ratio",
        )
        self.assertFalse(
            split_category["noninferiority"][
                "solve_wall_seconds_used"
            ]
        )
        self.assertFalse(
            aggregate_category["noninferiority"][
                "solve_wall_seconds_used"
            ]
        )

    def test_holdout_category_requires_nonregression_not_improvement(self):
        evidence = promotion_evidence()
        candidate_results = tuple(
            replace(
                result,
                attempts=tuple(
                    replace(
                        attempt,
                        solve_wall_seconds_used=10.0,
                    )
                    for attempt in result.attempts
                ),
            )
            if result.case_id == "live-pwn"
            else result
            for result in evidence.candidate.results
        )

        result = evaluate_blind_live_promotion(
            replace(
                evidence,
                candidate=replace(
                    evidence.candidate,
                    results=candidate_results,
                ),
            )
        )

        self.assertTrue(result["promotion_eligible"])
        pwn_comparison = result["comparisons"][
            "holdout_split_category_qualified_efficiency_comparisons"
        ][LIVE]["pwn"]["per_qualified_attempt"]
        self.assertTrue(
            pwn_comparison["noninferiority"][
                "solve_wall_seconds_used"
            ]
        )
        self.assertFalse(
            pwn_comparison["resource_improvements"][
                "solve_wall_seconds_used"
            ]
        )

    def test_holdout_category_preserves_zero_denominator_policy(self):
        evidence = promotion_evidence()
        baseline_results = tuple(
            promotion_result(
                result.case_id,
                solved=(False, False, False),
                proof=(False, False, False),
                reproduced=(False, False, False),
                run_namespace="baseline",
            )
            if result.case_id == "live-pwn"
            else result
            for result in evidence.baseline.results
        )

        result = evaluate_blind_live_promotion(
            replace(
                evidence,
                baseline=replace(
                    evidence.baseline,
                    results=baseline_results,
                ),
            )
        )

        self.assertTrue(result["promotion_eligible"])
        pwn_comparison = result["comparisons"][
            "holdout_split_category_qualified_efficiency_comparisons"
        ][LIVE]["pwn"]
        for denominator in (
            "per_qualified_case",
            "per_qualified_attempt",
        ):
            self.assertEqual(
                pwn_comparison[denominator]["mode"],
                "baseline_zero_candidate_positive_total_pareto",
            )
            self.assertTrue(
                pwn_comparison[denominator][
                    "outcome_efficiency_improvement"
                ]
            )
        self.assertFalse(
            any(
                blocker.startswith(
                    "split_category_efficiency_"
                )
                and ":live:pwn:" in blocker
                for blocker in result["blockers"]
            )
        )

    def test_per_attempt_efficiency_cannot_hide_behind_case_efficiency(self):
        evidence = promotion_evidence()

        def two_qualified_attempts(
            result: PromotionCaseResult,
        ) -> PromotionCaseResult:
            if not result.case_id.startswith("live-"):
                return result
            changed = promotion_result(
                result.case_id,
                seconds=8.0,
                solved=(True, True, False),
                proof=(True, True, True),
                reproduced=(True, True, True),
            )
            attempts = list(changed.attempts)
            attempts[2] = replace(
                attempts[2],
                first_valid_result_seconds=8.0,
            )
            return replace(changed, attempts=tuple(attempts))

        candidate_results = tuple(
            two_qualified_attempts(result)
            for result in evidence.candidate.results
        )
        outcome = evaluate_blind_live_promotion(
            replace(
                evidence,
                candidate=replace(
                    evidence.candidate,
                    results=candidate_results,
                ),
            )
        )

        baseline_efficiency = outcome["metrics"]["baseline"][
            "by_split"
        ][LIVE]["qualified_solve_efficiency"]
        candidate_efficiency = outcome["metrics"]["candidate"][
            "by_split"
        ][LIVE]["qualified_solve_efficiency"]
        self.assertLess(
            candidate_efficiency["per_qualified_case"][
                "solve_wall_seconds_used"
            ],
            baseline_efficiency["per_qualified_case"][
                "solve_wall_seconds_used"
            ],
        )
        self.assertGreater(
            candidate_efficiency["per_qualified_attempt"][
                "solve_wall_seconds_used"
            ],
            baseline_efficiency["per_qualified_attempt"][
                "solve_wall_seconds_used"
            ],
        )
        self.assertIn(
            "split_efficiency_regression:live:"
            "per_qualified_attempt:solve_wall_seconds_used",
            outcome["blockers"],
        )
        self.assertFalse(outcome["promotion_eligible"])

    def test_ttfvr_improvement_without_efficiency_signal_stays_closed(self):
        evidence = promotion_evidence()
        candidate_results = tuple(
            replace(
                result,
                attempts=tuple(
                    replace(attempt, solve_wall_seconds_used=10.0)
                    for attempt in result.attempts
                ),
            )
            if result.case_id.startswith("live-")
            else result
            for result in evidence.candidate.results
        )

        outcome = evaluate_blind_live_promotion(
            replace(
                evidence,
                candidate=replace(
                    evidence.candidate,
                    results=candidate_results,
                ),
            )
        )

        self.assertTrue(outcome["comparisons"]["live_hidden_improvement"])
        self.assertFalse(
            outcome["comparisons"][
                "live_hidden_efficiency_improvement"
            ]
        )
        self.assertIn(
            "no_live_hidden_efficiency_improvement",
            outcome["blockers"],
        )
        self.assertFalse(outcome["promotion_eligible"])

    def test_live_cost_efficiency_can_supply_the_improvement_signal(self):
        evidence = promotion_evidence()
        candidate_results = tuple(
            replace(
                result,
                attempts=tuple(
                    replace(
                        attempt,
                        first_valid_result_seconds=10.0,
                        solve_wall_seconds_used=10.0,
                        model_calls_used=3,
                    )
                    for attempt in result.attempts
                ),
            )
            if result.case_id.startswith("live-")
            else result
            for result in evidence.candidate.results
        )

        outcome = evaluate_blind_live_promotion(
            replace(
                evidence,
                candidate=replace(
                    evidence.candidate,
                    results=candidate_results,
                ),
            )
        )

        self.assertFalse(
            outcome["comparisons"]["live_hidden_primary_improvement"]
        )
        self.assertTrue(
            outcome["comparisons"][
                "live_hidden_efficiency_improvement"
            ]
        )
        self.assertIn(
            "live:per_qualified_attempt:model_calls_used",
            outcome["comparisons"][
                "live_hidden_efficiency_improvement_signals"
            ],
        )
        self.assertTrue(outcome["promotion_eligible"])

    def test_proof_and_reproduction_observations_are_independent(self):
        proof_only = PromotionAttempt(
            attempt=1,
            run_id="proof-only-run",
            solved=False,
            proof_evaluated=True,
            proof_passed=True,
            reproduction_evaluated=True,
            reproduced=False,
            first_valid_result_seconds=None,
            solve_wall_seconds_used=1.0,
            model_calls_used=1,
            total_tokens_used=1_000,
            human_interventions=0,
        )
        reproduction_only = PromotionAttempt(
            attempt=2,
            run_id="reproduction-only-run",
            solved=False,
            proof_evaluated=True,
            proof_passed=False,
            reproduction_evaluated=True,
            reproduced=True,
            first_valid_result_seconds=None,
            solve_wall_seconds_used=1.0,
            model_calls_used=1,
            total_tokens_used=1_000,
            human_interventions=0,
        )
        proved_and_reproduced = replace(
            proof_only,
            reproduced=True,
            first_valid_result_seconds=2.0,
            solve_wall_seconds_used=2.0,
        )

        proof_only.validate()
        reproduction_only.validate()
        proved_and_reproduced.validate()

    def test_failed_attempt_does_not_require_proof_evaluation(self):
        evidence = promotion_evidence()
        results = list(evidence.candidate.results)
        first = results[0]
        attempts = list(first.attempts)
        attempts[0] = replace(
            attempts[0],
            solved=False,
            proof_evaluated=False,
            proof_passed=False,
            reproduction_evaluated=False,
            reproduced=False,
            first_valid_result_seconds=None,
        )
        results[0] = replace(first, attempts=tuple(attempts))

        result = evaluate_blind_live_promotion(
            replace(
                evidence,
                candidate=replace(
                    evidence.candidate,
                    results=tuple(results),
                ),
            )
        )

        self.assertTrue(result["complete_evidence"])
        self.assertNotIn(
            "candidate_proof_coverage_incomplete",
            result["blockers"],
        )
        self.assertNotIn(
            "candidate_reproduction_coverage_incomplete",
            result["blockers"],
        )
        self.assertEqual(
            result["metrics"]["candidate"]["overall"]["pass^2/3"]["rate"],
            1.0,
        )

    def test_two_of_three_failure_coverage_is_symmetric_between_arms(self):
        evidence = promotion_evidence()

        def two_of_three_results(
            *,
            namespace: str,
            candidate: bool,
        ) -> tuple[PromotionCaseResult, ...]:
            return tuple(
                promotion_result(
                    case_id,
                    seconds=(
                        5.0
                        if candidate and split_name == LIVE
                        else 10.0
                    ),
                    solved=(True, True, False),
                    proof_evaluated=(True, True, False),
                    proof=(True, True, False),
                    reproduction_evaluated=(True, True, False),
                    reproduced=(True, True, False),
                    run_namespace=namespace,
                )
                for split_name in (DEV, REGRESSION, BLIND, LIVE)
                for case_id, _category in PROMOTION_CASES[split_name]
            )

        result = evaluate_blind_live_promotion(
            replace(
                evidence,
                baseline=replace(
                    evidence.baseline,
                    results=two_of_three_results(
                        namespace="baseline",
                        candidate=False,
                    ),
                ),
                candidate=replace(
                    evidence.candidate,
                    results=two_of_three_results(
                        namespace="candidate",
                        candidate=True,
                    ),
                ),
            )
        )

        self.assertTrue(result["complete_evidence"])
        self.assertTrue(result["promotion_eligible"])
        self.assertEqual(
            result["metrics"]["baseline"]["overall"]["pass^2/3"]["rate"],
            1.0,
        )
        self.assertEqual(
            result["metrics"]["candidate"]["overall"]["pass^2/3"]["rate"],
            1.0,
        )
        self.assertFalse(
            any(
                "proof_pass_rate" in blocker
                for blocker in result["blockers"]
            )
        )
        self.assertFalse(
            any(
                "reproduction_rate" in blocker
                for blocker in result["blockers"]
            )
        )

    def test_zero_solve_proof_timing_cannot_promote(self):
        evidence = promotion_evidence()

        def proof_result(
            result: PromotionCaseResult,
            seconds: float,
            run_namespace: str,
        ) -> PromotionCaseResult:
            raw = promotion_result(
                result.case_id,
                solved=(False, False, False),
                proof=(True, True, True),
                reproduced=(True, True, True),
                run_namespace=run_namespace,
            )
            return replace(
                raw,
                attempts=tuple(
                    replace(
                        attempt,
                        first_valid_result_seconds=seconds,
                    )
                    for attempt in raw.attempts
                ),
            )

        baseline_results = tuple(
            proof_result(result, 10.0, "baseline")
            for result in evidence.baseline.results
        )
        candidate_results = tuple(
            proof_result(
                result,
                5.0 if result.case_id.startswith("live-") else 10.0,
                "candidate",
            )
            for result in evidence.candidate.results
        )
        result = evaluate_blind_live_promotion(
            replace(
                evidence,
                baseline=replace(
                    evidence.baseline,
                    results=baseline_results,
                ),
                candidate=replace(
                    evidence.candidate,
                    results=candidate_results,
                ),
            )
        )

        self.assertEqual(result["decision"], "do_not_promote")
        self.assertIn(
            "candidate_holdout_has_no_accepted_solve",
            result["blockers"],
        )
        self.assertIn(
            "no_live_hidden_improvement",
            result["blockers"],
        )
        self.assertFalse(
            any(
                blocker.startswith(
                    "qualified_efficiency_zero_denominator:"
                )
                for blocker in result["blockers"]
            )
        )
        self.assertEqual(
            result["comparisons"][
                "overall_qualified_efficiency_comparison"
            ]["per_qualified_case"]["mode"],
            "both_zero_total_nonincrease",
        )
        self.assertEqual(
            result["metrics"]["candidate"]["overall"]["solve@1"]["rate"],
            0.0,
        )
        self.assertEqual(
            result["metrics"]["candidate"]["overall"]["pass^2/3"]["rate"],
            0.0,
        )

    def test_first_valid_proof_must_also_be_reproduced(self):
        evidence = promotion_evidence()
        first = evidence.candidate.results[0].attempts[0]
        invalid = replace(
            first,
            solved=False,
            proof_passed=True,
            reproduced=False,
            first_valid_result_seconds=1.0,
        )
        results = (
            replace(
                evidence.candidate.results[0],
                attempts=(
                    invalid,
                    *evidence.candidate.results[0].attempts[1:],
                ),
            ),
            *evidence.candidate.results[1:],
        )

        with self.assertRaisesRegex(
            BenchmarkError,
            "proved and reproduced",
        ):
            evaluate_blind_live_promotion(
                replace(
                    evidence,
                    candidate=replace(
                        evidence.candidate,
                        results=results,
                    ),
                )
            )

    def test_observed_result_censoring_cannot_improve_timing(self):
        evidence = promotion_evidence()
        candidate_results = tuple(
            promotion_result(
                result.case_id,
                seconds=1.0,
                solved=(True, True, False),
                proof=(True, True, False),
                reproduced=(True, True, False),
            )
            for result in evidence.candidate.results
        )

        result = evaluate_blind_live_promotion(
            replace(
                evidence,
                candidate=replace(
                    evidence.candidate,
                    results=candidate_results,
                ),
            )
        )

        self.assertFalse(result["promotion_eligible"])
        self.assertIn(
            "overall_regression:first_valid_observed_results",
            result["blockers"],
        )
        self.assertEqual(
            result["metrics"]["candidate"]["overall"][
                "median_time_to_first_valid_result"
            ]["observed_results"],
            28,
        )
        self.assertEqual(
            result["metrics"]["candidate"]["overall"][
                "proof_pass_rate"
            ]["evaluations"],
            42,
        )
        self.assertEqual(
            result["metrics"]["candidate"]["overall"][
                "reproduction_rate"
            ]["evaluations"],
            42,
        )

    def test_category_repeat_regression_cannot_be_offset_elsewhere(self):
        evidence = promotion_evidence()

        def pattern(
            result: PromotionCaseResult,
            arm: str,
        ) -> tuple[bool, bool, bool]:
            if arm == "baseline" and result.case_id.endswith("pwn"):
                return (False, False, False)
            if arm == "candidate" and result.case_id.endswith("crypto"):
                return (True, False, False)
            return (True, True, True)

        def patterned(
            result: PromotionCaseResult,
            arm: str,
        ) -> PromotionCaseResult:
            solved = pattern(result, arm)
            return promotion_result(
                result.case_id,
                seconds=(
                    5.0
                    if arm == "candidate"
                    and result.case_id.startswith("live-")
                    else 10.0
                ),
                solved=solved,
                proof=solved,
                reproduced=solved,
                run_namespace=arm,
            )

        baseline_results = tuple(
            patterned(result, "baseline")
            for result in evidence.baseline.results
        )
        candidate_results = tuple(
            patterned(result, "candidate")
            for result in evidence.candidate.results
        )
        result = evaluate_blind_live_promotion(
            replace(
                evidence,
                baseline=replace(
                    evidence.baseline,
                    results=baseline_results,
                ),
                candidate=replace(
                    evidence.candidate,
                    results=candidate_results,
                ),
            )
        )

        self.assertFalse(result["promotion_eligible"])
        self.assertIn(
            "category_regression:crypto:pass^2/3",
            result["blockers"],
        )
        self.assertFalse(
            result["comparisons"]["holdout_category_noninferiority"][
                "crypto"
            ]["pass^2/3"]
        )

    def test_split_category_regression_cannot_move_between_holdouts(self):
        evidence = promotion_evidence()

        def solved_pattern(case_id: str, arm: str) -> bool:
            changed_cells = {
                ("baseline", "blind-pwn"): False,
                ("baseline", "blind-crypto"): True,
                ("baseline", "live-pwn"): True,
                ("baseline", "live-crypto"): False,
                ("candidate", "blind-pwn"): True,
                ("candidate", "blind-crypto"): False,
                ("candidate", "live-pwn"): False,
                ("candidate", "live-crypto"): True,
            }
            return changed_cells.get((arm, case_id), True)

        def arm_results(arm: str) -> tuple[PromotionCaseResult, ...]:
            return tuple(
                promotion_result(
                    result.case_id,
                    seconds=(
                        5.0
                        if arm == "candidate"
                        and result.case_id.startswith("live-")
                        else 10.0
                    ),
                    solved=(solved, solved, solved),
                    proof=(solved, solved, solved),
                    reproduced=(solved, solved, solved),
                    run_namespace=arm,
                )
                for result in evidence.baseline.results
                for solved in (solved_pattern(result.case_id, arm),)
            )

        outcome = evaluate_blind_live_promotion(
            replace(
                evidence,
                baseline=replace(
                    evidence.baseline,
                    results=arm_results("baseline"),
                ),
                candidate=replace(
                    evidence.candidate,
                    results=arm_results("candidate"),
                ),
            )
        )

        self.assertFalse(outcome["promotion_eligible"])
        self.assertIn(
            "split_category_regression:live:pwn:solve@1",
            outcome["blockers"],
        )
        self.assertIn(
            "split_category_regression:blind:crypto:pass^2/3",
            outcome["blockers"],
        )
        self.assertTrue(outcome["comparisons"]["live_hidden_improvement"])

    def test_category_timing_and_intervention_regressions_cannot_be_offset(
        self,
    ):
        evidence = promotion_evidence()

        baseline_results = tuple(
            replace(
                result,
                attempts=tuple(
                    replace(
                        attempt,
                        first_valid_result_seconds=5.0,
                        human_interventions=0,
                    )
                    for attempt in result.attempts
                ),
            )
            if result.case_id == "live-pwn"
            else result
            for result in evidence.baseline.results
        )
        candidate_results = tuple(
            replace(
                result,
                attempts=tuple(
                    replace(
                        attempt,
                        first_valid_result_seconds=6.0,
                        solve_wall_seconds_used=10.0,
                    )
                    for attempt in result.attempts
                ),
            )
            if result.case_id == "live-pwn"
            else replace(
                result,
                attempts=tuple(
                    replace(attempt, human_interventions=0)
                    for attempt in result.attempts
                ),
            )
            if result.case_id.startswith("live-")
            else result
            for result in evidence.candidate.results
        )

        outcome = evaluate_blind_live_promotion(
            replace(
                evidence,
                baseline=replace(
                    evidence.baseline,
                    results=baseline_results,
                ),
                candidate=replace(
                    evidence.candidate,
                    results=candidate_results,
                ),
            )
        )

        self.assertTrue(
            outcome["comparisons"]["split_noninferiority"][LIVE][
                "median_time_to_first_valid_result"
            ]
        )
        self.assertTrue(
            outcome["comparisons"]["split_noninferiority"][LIVE][
                "human_interventions"
            ]
        )
        for metric in (
            "median_time_to_first_valid_result",
            "human_interventions",
        ):
            self.assertIn(
                f"split_category_regression:live:pwn:{metric}",
                outcome["blockers"],
            )
            self.assertIn(
                f"category_regression:pwn:{metric}",
                outcome["blockers"],
            )
            self.assertFalse(
                outcome["comparisons"][
                    "holdout_split_category_noninferiority"
                ][LIVE]["pwn"][metric]
            )
            self.assertFalse(
                outcome["comparisons"][
                    "holdout_category_noninferiority"
                ]["pwn"][metric]
            )
        self.assertFalse(outcome["promotion_eligible"])

    def test_category_qualified_result_regression_cannot_be_offset(self):
        evidence = promotion_evidence()

        def two_qualified(
            result: PromotionCaseResult,
            *,
            namespace: str,
            seconds: float,
        ) -> PromotionCaseResult:
            changed = promotion_result(
                result.case_id,
                seconds=seconds,
                solved=(True, True, False),
                proof=(True, True, False),
                reproduced=(True, True, False),
                run_namespace=namespace,
            )
            attempts = list(changed.attempts)
            attempts[2] = replace(
                attempts[2],
                solve_wall_seconds_used=0.0,
                model_calls_used=0,
                total_tokens_used=0,
            )
            return replace(changed, attempts=tuple(attempts))

        baseline_results = tuple(
            two_qualified(
                result,
                namespace="baseline",
                seconds=10.0,
            )
            if result.case_id == "live-web"
            else result
            for result in evidence.baseline.results
        )
        candidate_results = tuple(
            two_qualified(
                result,
                namespace="candidate",
                seconds=5.0,
            )
            if result.case_id == "live-pwn"
            else result
            for result in evidence.candidate.results
        )

        outcome = evaluate_blind_live_promotion(
            replace(
                evidence,
                baseline=replace(
                    evidence.baseline,
                    results=baseline_results,
                ),
                candidate=replace(
                    evidence.candidate,
                    results=candidate_results,
                ),
            )
        )

        self.assertTrue(
            outcome["comparisons"]["split_noninferiority"][LIVE][
                "first_valid_observed_results"
            ]
        )
        self.assertIn(
            "split_category_regression:"
            "live:pwn:first_valid_observed_results",
            outcome["blockers"],
        )
        self.assertIn(
            "category_regression:pwn:first_valid_observed_results",
            outcome["blockers"],
        )
        self.assertFalse(
            outcome["comparisons"][
                "holdout_split_category_noninferiority"
            ][LIVE]["pwn"]["first_valid_observed_results"]
        )
        self.assertFalse(
            outcome["comparisons"]["holdout_category_noninferiority"][
                "pwn"
            ]["first_valid_observed_results"]
        )
        self.assertFalse(outcome["promotion_eligible"])

    def test_timing_improvement_requires_stricter_effect_floor(self):
        evidence = promotion_evidence()

        def candidate_with_live_seconds(
            seconds: float,
        ) -> BlindLivePromotionEvidence:
            results = tuple(
                promotion_result(
                    result.case_id,
                    seconds=(
                        seconds
                        if result.case_id.startswith("live-")
                        else 10.0
                    ),
                )
                for result in evidence.candidate.results
            )
            return replace(
                evidence,
                candidate=replace(
                    evidence.candidate,
                    results=results,
                ),
            )

        epsilon = evaluate_blind_live_promotion(
            candidate_with_live_seconds(math.nextafter(10.0, 0.0))
        )
        threshold = evaluate_blind_live_promotion(
            candidate_with_live_seconds(9.0)
        )

        self.assertFalse(epsilon["promotion_eligible"])
        self.assertIn(
            "no_live_hidden_improvement",
            epsilon["blockers"],
        )
        self.assertTrue(threshold["promotion_eligible"])

    def test_blind_only_improvement_is_not_a_live_hidden_signal(self):
        evidence = promotion_evidence()
        results = tuple(
            promotion_result(
                result.case_id,
                seconds=(
                    5.0 if result.case_id.startswith("blind-") else 10.0
                ),
            )
            for result in evidence.candidate.results
        )

        outcome = evaluate_blind_live_promotion(
            replace(
                evidence,
                candidate=replace(
                    evidence.candidate,
                    results=results,
                ),
            )
        )

        self.assertFalse(outcome["promotion_eligible"])
        self.assertIn(
            "no_live_hidden_improvement",
            outcome["blockers"],
        )
        self.assertEqual(
            outcome["comparisons"]["promotion_signal_splits"],
            [LIVE],
        )

    def test_provided_hidden_split_can_supply_the_promotion_signal(self):
        evidence = promotion_evidence()
        hidden_cases = tuple(
            PromotionCase(
                case_id=f"hidden-{category}",
                category=category,
                input_manifest_sha256=hashlib.sha256(
                    f"hidden-{category}".encode("utf-8")
                ).hexdigest(),
            )
            for category in PROMOTION_CATEGORIES
        )
        hidden_split = PromotionSplit(
            name=HIDDEN,
            cases=hidden_cases,
            trajectory_visible=False,
            answers_visible=False,
            prior_engine_runs=0,
        )
        baseline_hidden = tuple(
            promotion_result(
                case.case_id,
                seconds=10.0,
                run_namespace="baseline",
            )
            for case in hidden_cases
        )
        candidate_hidden = tuple(
            promotion_result(case.case_id, seconds=5.0)
            for case in hidden_cases
        )
        candidate_existing = tuple(
            promotion_result(result.case_id, seconds=10.0)
            for result in evidence.candidate.results
        )

        outcome = evaluate_blind_live_promotion(
            replace(
                evidence,
                splits=(*evidence.splits, hidden_split),
                baseline=replace(
                    evidence.baseline,
                    results=(
                        *evidence.baseline.results,
                        *baseline_hidden,
                    ),
                ),
                candidate=replace(
                    evidence.candidate,
                    results=(
                        *candidate_existing,
                        *candidate_hidden,
                    ),
                ),
            )
        )

        self.assertTrue(outcome["promotion_eligible"])
        self.assertEqual(
            outcome["comparisons"]["promotion_signal_splits"],
            [LIVE, HIDDEN],
        )

    def test_execution_fingerprint_is_required_and_must_match(self):
        evidence = promotion_evidence()
        missing = evaluate_blind_live_promotion(
            replace(
                evidence,
                candidate=replace(
                    evidence.candidate,
                    execution_fingerprint=None,
                ),
            )
        )
        changed_fingerprint = replace(
            evidence.candidate.execution_fingerprint,
            image_sha256="4" * 64,
        )
        mismatch = evaluate_blind_live_promotion(
            replace(
                evidence,
                candidate=replace(
                    evidence.candidate,
                    execution_fingerprint=changed_fingerprint,
                ),
            )
        )

        self.assertIn(
            "candidate_execution_fingerprint_missing",
            missing["blockers"],
        )
        self.assertIn(
            "execution_fingerprint_mismatch",
            mismatch["blockers"],
        )
        self.assertFalse(missing["promotion_eligible"])
        self.assertFalse(mismatch["promotion_eligible"])

    def test_actual_attempt_budget_and_unique_run_ids_are_required(self):
        evidence = promotion_evidence()
        results = list(evidence.candidate.results)
        first = results[0]
        attempts = list(first.attempts)
        attempts[0] = replace(
            attempts[0],
            model_calls_used=evidence.candidate.budget.model_call_limit + 1,
        )
        attempts[1] = replace(
            attempts[1],
            run_id=attempts[0].run_id,
        )
        results[0] = replace(first, attempts=tuple(attempts))

        outcome = evaluate_blind_live_promotion(
            replace(
                evidence,
                candidate=replace(
                    evidence.candidate,
                    results=tuple(results),
                ),
            )
        )

        self.assertFalse(outcome["promotion_eligible"])
        self.assertFalse(outcome["complete_evidence"])
        self.assertIn(
            f"candidate_budget_exceeded:{first.case_id}:1",
            outcome["blockers"],
        )
        self.assertIn("candidate_run_id_reused", outcome["blockers"])
        self.assertIsNone(outcome["metrics"])

    def test_run_ids_cannot_be_reused_across_comparison_arms(self):
        evidence = promotion_evidence()
        baseline_run_ids = {
            (result.case_id, attempt.attempt): attempt.run_id
            for result in evidence.baseline.results
            for attempt in result.attempts
        }
        candidate_results = tuple(
            replace(
                result,
                attempts=tuple(
                    replace(
                        attempt,
                        run_id=baseline_run_ids[
                            (result.case_id, attempt.attempt)
                        ],
                    )
                    for attempt in result.attempts
                ),
            )
            for result in evidence.candidate.results
        )

        outcome = evaluate_blind_live_promotion(
            replace(
                evidence,
                candidate=replace(
                    evidence.candidate,
                    results=candidate_results,
                ),
            )
        )

        self.assertFalse(outcome["promotion_eligible"])
        self.assertFalse(outcome["complete_evidence"])
        self.assertIn("run_id_reused_across_arms", outcome["blockers"])

    def test_strict_dict_round_trip_and_adversarial_shapes(self):
        evidence = promotion_evidence()
        raw = evidence.to_dict()

        loaded = BlindLivePromotionEvidence.from_dict(raw)

        self.assertEqual(loaded, evidence)
        self.assertTrue(
            evaluate_blind_live_promotion(loaded)["promotion_eligible"]
        )

        extra = copy.deepcopy(raw)
        extra["unexpected"] = True
        with self.assertRaisesRegex(BenchmarkError, "exactly"):
            BlindLivePromotionEvidence.from_dict(extra)

        boolean_budget = copy.deepcopy(raw)
        boolean_budget["candidate"]["budget"]["wall_seconds"] = True
        with self.assertRaisesRegex(BenchmarkError, "wall_seconds"):
            BlindLivePromotionEvidence.from_dict(boolean_budget)

        nan_time = copy.deepcopy(raw)
        nan_time["candidate"]["results"][0]["attempts"][0][
            "first_valid_result_seconds"
        ] = math.nan
        with self.assertRaisesRegex(BenchmarkError, "finite"):
            BlindLivePromotionEvidence.from_dict(nan_time)

        missing_fingerprint = copy.deepcopy(raw)
        del missing_fingerprint["candidate"]["execution_fingerprint"]
        with self.assertRaisesRegex(BenchmarkError, "exactly"):
            BlindLivePromotionEvidence.from_dict(missing_fingerprint)

        missing_source = copy.deepcopy(raw)
        del missing_source["candidate"]["execution_fingerprint"][
            "engine_source_sha256"
        ]
        with self.assertRaisesRegex(BenchmarkError, "exactly"):
            BlindLivePromotionEvidence.from_dict(missing_source)

        extra_source = copy.deepcopy(raw)
        extra_source["candidate"]["execution_fingerprint"][
            "source_commit"
        ] = "deadbeef"
        with self.assertRaisesRegex(BenchmarkError, "exactly"):
            BlindLivePromotionEvidence.from_dict(extra_source)

        invalid_manifest = copy.deepcopy(raw)
        invalid_manifest["splits"][0]["cases"][0][
            "input_manifest_sha256"
        ] = "not-a-digest"
        with self.assertRaisesRegex(BenchmarkError, "input_manifest_sha256"):
            BlindLivePromotionEvidence.from_dict(invalid_manifest)

        duplicate_manifest = copy.deepcopy(raw)
        duplicate_manifest["splits"][1]["cases"][0][
            "input_manifest_sha256"
        ] = duplicate_manifest["splits"][0]["cases"][0][
            "input_manifest_sha256"
        ]
        with self.assertRaisesRegex(BenchmarkError, "globally unique"):
            BlindLivePromotionEvidence.from_dict(duplicate_manifest)

    def test_validation_normalizes_surrogates_and_huge_integers(self):
        evidence = promotion_evidence()
        with self.assertRaisesRegex(BenchmarkError, "valid Unicode"):
            evaluate_blind_live_promotion(
                replace(
                    evidence,
                    candidate=replace(
                        evidence.candidate,
                        model_id="bad\ud800",
                    ),
                )
            )

        first_result = evidence.candidate.results[0]
        attempts = list(first_result.attempts)
        attempts[0] = replace(
            attempts[0],
            first_valid_result_seconds=10**10_000,
        )
        with self.assertRaisesRegex(BenchmarkError, "finite and positive"):
            evaluate_blind_live_promotion(
                replace(
                    evidence,
                    candidate=replace(
                        evidence.candidate,
                        results=(
                            replace(
                                first_result,
                                attempts=tuple(attempts),
                            ),
                            *evidence.candidate.results[1:],
                        ),
                    ),
                )
            )


if __name__ == "__main__":
    unittest.main()
