"""Deterministic managed-rollout gates over explicitly separated cohorts."""

from __future__ import annotations

import math
from dataclasses import dataclass
from statistics import mean, median, variance
from typing import Any, Sequence


Z_90 = 1.6448536269514722
MANAGED_OBSERVE = "managed-observe"
MANAGED_X22_TREATMENT = "managed-X22-treatment"
ASSISTED = "assisted"
OPERATOR_MANUAL = "operator/manual"
LEGACY = "legacy"
COHORTS = frozenset(
    {
        MANAGED_OBSERVE,
        MANAGED_X22_TREATMENT,
        ASSISTED,
        OPERATOR_MANUAL,
        LEGACY,
    }
)


class BenchmarkError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SafetyTotals:
    orphan_runs: int = 0
    false_proofs: int = 0
    target_violations: int = 0
    secret_or_flag_leaks: int = 0
    complete_run_records: int = 0
    terminal_run_records: int = 0

    def validate(self) -> None:
        values = (
            self.orphan_runs,
            self.false_proofs,
            self.target_violations,
            self.secret_or_flag_leaks,
            self.complete_run_records,
            self.terminal_run_records,
        )
        if any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            for value in values
        ):
            raise BenchmarkError("safety totals must be non-negative integers")
        if self.complete_run_records > self.terminal_run_records:
            raise BenchmarkError(
                "complete run records cannot exceed terminal run records"
            )


@dataclass(frozen=True, slots=True)
class CohortSample:
    cohort: str
    budget_mode: str
    consistency: tuple[float, ...]
    cost_per_solve: tuple[float, ...]
    landings_per_hour: tuple[float, ...]
    solve_at_3: tuple[float, ...]
    safety: SafetyTotals = SafetyTotals()

    def validate(self) -> None:
        if self.cohort not in COHORTS:
            raise BenchmarkError(f"unknown benchmark cohort: {self.cohort}")
        if self.budget_mode not in {"bounded", "unbounded"}:
            raise BenchmarkError(
                "benchmark budget mode must be bounded or unbounded"
            )
        for label, values in (
            ("consistency", self.consistency),
            ("cost_per_solve", self.cost_per_solve),
            ("landings_per_hour", self.landings_per_hour),
            ("solve_at_3", self.solve_at_3),
        ):
            if not values:
                raise BenchmarkError(f"{label} sample cannot be empty")
            if any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or value < 0
                for value in values
            ):
                raise BenchmarkError(
                    f"{label} values must be finite and non-negative"
                )
        for label, values in (
            ("consistency", self.consistency),
            ("solve_at_3", self.solve_at_3),
        ):
            if any(value > 1 for value in values):
                raise BenchmarkError(f"{label} values must be within 0..1")
        self.safety.validate()


def _sample_variance(values: Sequence[float]) -> float:
    return variance(values) if len(values) > 1 else 0.0


def _difference(
    treatment: Sequence[float],
    baseline: Sequence[float],
) -> dict[str, float]:
    point = mean(treatment) - mean(baseline)
    standard_error = math.sqrt(
        _sample_variance(treatment) / len(treatment)
        + _sample_variance(baseline) / len(baseline)
    )
    return {
        "point": point,
        "lower_90": point - Z_90 * standard_error,
        "upper_90": point + Z_90 * standard_error,
    }


def _ratio(
    treatment: Sequence[float],
    baseline: Sequence[float],
) -> dict[str, float]:
    treatment_mean = mean(treatment)
    baseline_mean = mean(baseline)
    if treatment_mean <= 0 or baseline_mean <= 0:
        raise BenchmarkError("ratio metrics require positive cohort means")
    point = treatment_mean / baseline_mean
    log_standard_error = math.sqrt(
        _sample_variance(treatment)
        / (len(treatment) * treatment_mean * treatment_mean)
        + _sample_variance(baseline)
        / (len(baseline) * baseline_mean * baseline_mean)
    )
    return {
        "point": point,
        "lower_90": math.exp(math.log(point) - Z_90 * log_standard_error),
        "upper_90": math.exp(math.log(point) + Z_90 * log_standard_error),
    }


def evaluate_managed_promotion(
    assisted: CohortSample,
    managed: CohortSample,
) -> dict[str, Any]:
    """Apply the frozen promotion thresholds without changing a default."""

    assisted.validate()
    managed.validate()
    if assisted.cohort != ASSISTED:
        raise BenchmarkError("baseline cohort must be assisted")
    if managed.cohort != MANAGED_OBSERVE:
        raise BenchmarkError(
            "promotion treatment must be managed-observe, never X22 treatment"
        )
    if (
        assisted.budget_mode != "bounded"
        or managed.budget_mode != "bounded"
    ):
        raise BenchmarkError(
            "managed promotion requires separate bounded cohorts"
        )

    consistency = _difference(
        managed.consistency,
        assisted.consistency,
    )
    cost = _ratio(
        managed.cost_per_solve,
        assisted.cost_per_solve,
    )
    landings = _ratio(
        managed.landings_per_hour,
        assisted.landings_per_hour,
    )
    solve_at_3 = _difference(
        managed.solve_at_3,
        assisted.solve_at_3,
    )
    safety = managed.safety
    safety_ok = (
        safety.orphan_runs == 0
        and safety.false_proofs == 0
        and safety.target_violations == 0
        and safety.secret_or_flag_leaks == 0
        and safety.terminal_run_records > 0
        and safety.complete_run_records == safety.terminal_run_records
    )
    noninferiority = {
        "consistency": consistency["lower_90"] >= -0.05,
        "cost_per_solve": cost["upper_90"] <= 1.10,
        "landings_per_hour": landings["lower_90"] >= 0.90,
        "solve_at_3": solve_at_3["lower_90"] >= -0.05,
    }
    meaningful_improvement = (
        consistency["point"] >= 0.05
        or cost["point"] <= 0.90
        or landings["point"] >= 1.10
    )
    promote = (
        safety_ok
        and all(noninferiority.values())
        and meaningful_improvement
    )
    return {
        "decision": "promote" if promote else "continue_canary",
        "default_changed": False,
        "cohorts": {
            "baseline": assisted.cohort,
            "treatment": managed.cohort,
            "budget_mode": "bounded",
        },
        "safety_ok": safety_ok,
        "noninferiority": noninferiority,
        "meaningful_improvement": meaningful_improvement,
        "estimates": {
            "consistency_difference": consistency,
            "cost_per_solve_ratio": cost,
            "landings_per_hour_ratio": landings,
            "solve_at_3_difference": solve_at_3,
        },
    }


def evaluate_x22(
    observe_first_candidate_seconds: Sequence[float],
    treatment_first_candidate_seconds: Sequence[float],
    observe_run_counts: Sequence[float],
    treatment_run_counts: Sequence[float],
) -> dict[str, Any]:
    """Evaluate the held-out evaluation-wave treatment without enabling it."""

    groups = (
        observe_first_candidate_seconds,
        treatment_first_candidate_seconds,
        observe_run_counts,
        treatment_run_counts,
    )
    if any(len(group) < 4 for group in groups):
        raise BenchmarkError("X-22 requires at least four cases per arm")
    if any(
        not math.isfinite(float(value)) or value <= 0
        for group in groups
        for value in group
    ):
        raise BenchmarkError("X-22 measurements must be finite and positive")
    observe_time = float(median(observe_first_candidate_seconds))
    treatment_time = float(median(treatment_first_candidate_seconds))
    observe_runs = float(median(observe_run_counts))
    treatment_runs = float(median(treatment_run_counts))
    time_improvement = (observe_time - treatment_time) / observe_time
    enable = (
        time_improvement >= 0.20
        and treatment_runs <= observe_runs
    )
    return {
        "decision": "eligible_for_separate_rollout" if enable else "observe",
        "production_barrier_changed": False,
        "time_improvement": time_improvement,
        "observe_time_median": observe_time,
        "treatment_time_median": treatment_time,
        "observe_run_median": observe_runs,
        "treatment_run_median": treatment_runs,
    }


def evaluate_x23(*, valid_role_outputs: int, total_role_outputs: int) -> bool:
    if total_role_outputs <= 0 or not 0 <= valid_role_outputs <= total_role_outputs:
        raise BenchmarkError("invalid X-23 role-output counts")
    return valid_role_outputs / total_role_outputs >= 0.80


def evaluate_x24(*, real_flag_misses: int) -> bool:
    if real_flag_misses < 0:
        raise BenchmarkError("X-24 miss count cannot be negative")
    return real_flag_misses == 0


def evaluate_x25(
    *,
    control_human_interventions: Sequence[float],
    treatment_human_interventions: Sequence[float],
) -> bool:
    if not control_human_interventions or not treatment_human_interventions:
        raise BenchmarkError("X-25 requires both cohorts")
    if any(
        not math.isfinite(float(value)) or value < 0
        for value in (
            *control_human_interventions,
            *treatment_human_interventions,
        )
    ):
        raise BenchmarkError("X-25 interventions must be finite and non-negative")
    return mean(treatment_human_interventions) < mean(
        control_human_interventions
    )


__all__ = [
    "ASSISTED",
    "BenchmarkError",
    "COHORTS",
    "CohortSample",
    "LEGACY",
    "MANAGED_OBSERVE",
    "MANAGED_X22_TREATMENT",
    "OPERATOR_MANUAL",
    "SafetyTotals",
    "evaluate_managed_promotion",
    "evaluate_x22",
    "evaluate_x23",
    "evaluate_x24",
    "evaluate_x25",
]
