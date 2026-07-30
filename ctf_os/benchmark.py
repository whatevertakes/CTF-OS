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
DEV = "dev"
REGRESSION = "regression"
BLIND = "blind"
LIVE = "live"
HIDDEN = "hidden"
PROMOTION_SPLITS = frozenset({DEV, REGRESSION, BLIND, LIVE, HIDDEN})
REQUIRED_PROMOTION_CATEGORIES = frozenset(
    {"pwn", "web", "rev", "crypto", "forensics", "misc"}
)
MIN_HOLDOUT_CASES_PER_CATEGORY = 2
MIN_HOLDOUT_CASES_PER_SPLIT = 6
MIN_TTFVR_ABSOLUTE_IMPROVEMENT_SECONDS = 1.0
MIN_TTFVR_RELATIVE_IMPROVEMENT = 0.05
THIN_SCAFFOLD = "thin_scaffold"
CTF_OS_SYSTEM = "ctf_os"
BLIND_LIVE_PROMOTION_SCHEMA_VERSION = 3
_MAX_IDENTIFIER_BYTES = 256
_MAX_PROMOTION_CASES = 4096
_MAX_COUNTER = (1 << 63) - 1


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


def _validate_identifier(value: object, label: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise BenchmarkError(f"{label} must be a bounded non-empty string")
    if len(value) > _MAX_IDENTIFIER_BYTES:
        raise BenchmarkError(f"{label} must be a bounded non-empty string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise BenchmarkError(
            f"{label} must be valid Unicode"
        ) from error
    if (
        len(encoded) > _MAX_IDENTIFIER_BYTES
        or any(
            ord(character) < 0x20 or ord(character) == 0x7F
            for character in value
        )
    ):
        raise BenchmarkError(f"{label} must be a bounded non-empty string")


def _validate_count(
    value: object,
    label: str,
    *,
    positive: bool = False,
) -> None:
    minimum = 1 if positive else 0
    if (
        type(value) is not int
        or value < minimum
        or value > _MAX_COUNTER
    ):
        qualifier = "positive" if positive else "non-negative"
        raise BenchmarkError(f"{label} must be a {qualifier} integer")


def _validate_finite_positive_number(value: object, label: str) -> None:
    if type(value) is int:
        valid = 0 < value <= _MAX_COUNTER
    elif type(value) is float:
        valid = math.isfinite(value) and value > 0
    else:
        valid = False
    if not valid:
        raise BenchmarkError(f"{label} must be finite and positive")


def _validate_finite_nonnegative_number(value: object, label: str) -> None:
    if type(value) is int:
        valid = 0 <= value <= _MAX_COUNTER
    elif type(value) is float:
        valid = math.isfinite(value) and value >= 0
    else:
        valid = False
    if not valid:
        raise BenchmarkError(f"{label} must be finite and non-negative")


def _validate_sha256(value: object, label: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise BenchmarkError(f"{label} must be a lowercase SHA-256 digest")


@dataclass(frozen=True, slots=True)
class BenchmarkExecutionFingerprint:
    """Common model/tool/runtime identity required for a fair paired cohort."""

    tool_manifest_sha256: str
    image_sha256: str
    model_config_sha256: str
    engine_source_sha256: str

    def validate(self) -> None:
        _validate_sha256(
            self.tool_manifest_sha256,
            "tool_manifest_sha256",
        )
        _validate_sha256(self.image_sha256, "image_sha256")
        _validate_sha256(
            self.model_config_sha256,
            "model_config_sha256",
        )
        _validate_sha256(
            self.engine_source_sha256,
            "engine_source_sha256",
        )


@dataclass(frozen=True, slots=True)
class FixedBenchmarkBudget:
    """Exact resource envelope shared by both promotion arms."""

    wall_seconds: int
    model_call_limit: int
    total_token_limit: int

    def validate(self) -> None:
        _validate_count(self.wall_seconds, "budget wall_seconds", positive=True)
        _validate_count(
            self.model_call_limit,
            "budget model_call_limit",
            positive=True,
        )
        _validate_count(
            self.total_token_limit,
            "budget total_token_limit",
            positive=True,
        )


@dataclass(frozen=True, slots=True)
class PromotionCase:
    """One immutable benchmark case descriptor."""

    case_id: str
    category: str
    input_manifest_sha256: str

    def validate(self) -> None:
        _validate_identifier(self.case_id, "promotion case_id")
        _validate_identifier(self.category, "promotion category")
        _validate_sha256(
            self.input_manifest_sha256,
            "promotion input_manifest_sha256",
        )
        if self.category not in REQUIRED_PROMOTION_CATEGORIES:
            raise BenchmarkError(
                "promotion category must be one of the canonical categories"
            )


@dataclass(frozen=True, slots=True)
class PromotionSplit:
    """Case membership and pre-evaluation exposure for one split."""

    name: str
    cases: tuple[PromotionCase, ...]
    trajectory_visible: bool
    answers_visible: bool
    prior_engine_runs: int
    evidence_complete: bool = True

    def validate(self) -> None:
        if type(self.name) is not str or self.name not in PROMOTION_SPLITS:
            raise BenchmarkError("unknown promotion split")
        if type(self.cases) is not tuple:
            raise BenchmarkError("promotion split cases must be a tuple")
        if not self.cases:
            raise BenchmarkError("promotion split cannot be empty")
        if len(self.cases) > _MAX_PROMOTION_CASES:
            raise BenchmarkError("promotion split exceeds the case limit")
        case_ids: set[str] = set()
        for case in self.cases:
            if type(case) is not PromotionCase:
                raise BenchmarkError(
                    "promotion split contains an invalid case descriptor"
                )
            case.validate()
            if case.case_id in case_ids:
                raise BenchmarkError("promotion split case_ids must be unique")
            case_ids.add(case.case_id)
        if type(self.trajectory_visible) is not bool:
            raise BenchmarkError("trajectory_visible must be a boolean")
        if type(self.answers_visible) is not bool:
            raise BenchmarkError("answers_visible must be a boolean")
        _validate_count(self.prior_engine_runs, "prior_engine_runs")
        if type(self.evidence_complete) is not bool:
            raise BenchmarkError("split evidence_complete must be a boolean")


@dataclass(frozen=True, slots=True)
class PromotionAttempt:
    """One canonical repeat used to derive, rather than trust, gate metrics."""

    attempt: int
    run_id: str
    solved: bool
    proof_evaluated: bool
    proof_passed: bool
    reproduction_evaluated: bool
    reproduced: bool
    first_valid_result_seconds: float | int | None
    solve_wall_seconds_used: float | int
    model_calls_used: int
    total_tokens_used: int
    human_interventions: int

    def validate(self) -> None:
        if type(self.attempt) is not int or self.attempt not in {1, 2, 3}:
            raise BenchmarkError("promotion attempt must be integer 1, 2, or 3")
        _validate_identifier(self.run_id, "promotion run_id")
        if type(self.solved) is not bool:
            raise BenchmarkError("promotion solved must be a boolean")
        if type(self.proof_evaluated) is not bool:
            raise BenchmarkError("promotion proof_evaluated must be a boolean")
        if type(self.proof_passed) is not bool:
            raise BenchmarkError("promotion proof_passed must be a boolean")
        if type(self.reproduction_evaluated) is not bool:
            raise BenchmarkError(
                "promotion reproduction_evaluated must be a boolean"
            )
        if type(self.reproduced) is not bool:
            raise BenchmarkError("promotion reproduced must be a boolean")
        if self.proof_passed and not self.proof_evaluated:
            raise BenchmarkError("an unevaluated proof cannot pass")
        if self.reproduced and not self.reproduction_evaluated:
            raise BenchmarkError(
                "an unevaluated reproduction cannot pass"
            )
        if self.first_valid_result_seconds is not None:
            _validate_finite_positive_number(
                self.first_valid_result_seconds,
                "first_valid_result_seconds",
            )
            if not (
                self.solved
                or (self.proof_passed and self.reproduced)
            ):
                raise BenchmarkError(
                    "a first valid result requires a solve or a proved and "
                    "reproduced result"
                )
        _validate_finite_nonnegative_number(
            self.solve_wall_seconds_used,
            "solve_wall_seconds_used",
        )
        _validate_count(self.model_calls_used, "model_calls_used")
        _validate_count(self.total_tokens_used, "total_tokens_used")
        if (
            self.first_valid_result_seconds is not None
            and float(self.first_valid_result_seconds)
            > float(self.solve_wall_seconds_used)
        ):
            raise BenchmarkError(
                "first_valid_result_seconds cannot exceed "
                "solve_wall_seconds_used"
            )
        _validate_count(
            self.human_interventions,
            "promotion human_interventions",
        )


@dataclass(frozen=True, slots=True)
class PromotionCaseResult:
    """Bounded results for the three canonical attempts of one case."""

    case_id: str
    attempts: tuple[PromotionAttempt, ...]
    evidence_complete: bool = True

    def validate(self) -> None:
        _validate_identifier(self.case_id, "promotion result case_id")
        if type(self.attempts) is not tuple:
            raise BenchmarkError("promotion attempts must be a tuple")
        if len(self.attempts) > 3:
            raise BenchmarkError("a promotion result has more than three attempts")
        attempt_numbers: set[int] = set()
        for attempt in self.attempts:
            if type(attempt) is not PromotionAttempt:
                raise BenchmarkError(
                    "promotion result contains an invalid attempt"
                )
            attempt.validate()
            if attempt.attempt in attempt_numbers:
                raise BenchmarkError(
                    "promotion attempt numbers must be unique per case"
                )
            attempt_numbers.add(attempt.attempt)
        if type(self.evidence_complete) is not bool:
            raise BenchmarkError(
                "case-result evidence_complete must be a boolean"
            )


@dataclass(frozen=True, slots=True)
class PromotionArm:
    """One system/model/budget arm with raw, paired challenge outcomes."""

    system: str
    model_id: str
    budget: FixedBenchmarkBudget
    results: tuple[PromotionCaseResult, ...]
    safety: SafetyTotals
    evidence_complete: bool = True
    execution_fingerprint: BenchmarkExecutionFingerprint | None = None

    def validate(self) -> None:
        if type(self.system) is not str or self.system not in {
            THIN_SCAFFOLD,
            CTF_OS_SYSTEM,
        }:
            raise BenchmarkError("unknown promotion system")
        _validate_identifier(self.model_id, "promotion model_id")
        if type(self.budget) is not FixedBenchmarkBudget:
            raise BenchmarkError("promotion budget has an invalid type")
        self.budget.validate()
        if type(self.results) is not tuple:
            raise BenchmarkError("promotion results must be a tuple")
        if len(self.results) > _MAX_PROMOTION_CASES:
            raise BenchmarkError("promotion arm exceeds the result limit")
        result_ids: set[str] = set()
        for result in self.results:
            if type(result) is not PromotionCaseResult:
                raise BenchmarkError(
                    "promotion arm contains an invalid result"
                )
            result.validate()
            if result.case_id in result_ids:
                raise BenchmarkError(
                    "promotion arm result case_ids must be unique"
                )
            result_ids.add(result.case_id)
        if type(self.safety) is not SafetyTotals:
            raise BenchmarkError("promotion safety totals have an invalid type")
        self.safety.validate()
        if type(self.evidence_complete) is not bool:
            raise BenchmarkError("arm evidence_complete must be a boolean")
        if self.execution_fingerprint is not None:
            if (
                type(self.execution_fingerprint)
                is not BenchmarkExecutionFingerprint
            ):
                raise BenchmarkError(
                    "execution_fingerprint has an invalid type"
                )
            self.execution_fingerprint.validate()


@dataclass(frozen=True, slots=True)
class BlindLivePromotionEvidence:
    """Complete input to the fail-closed, read-only promotion gate."""

    splits: tuple[PromotionSplit, ...]
    baseline: PromotionArm
    candidate: PromotionArm
    evidence_complete: bool = True
    schema_version: int = BLIND_LIVE_PROMOTION_SCHEMA_VERSION

    @classmethod
    def from_dict(cls, value: object) -> BlindLivePromotionEvidence:
        """Load a strict JSON-shaped object for a future CLI boundary."""

        return _promotion_evidence_from_dict(value)

    def to_dict(self) -> dict[str, object]:
        """Return the complete JSON-shaped evidence without changing state."""

        self.validate()
        return _promotion_evidence_to_dict(self)

    def validate(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != BLIND_LIVE_PROMOTION_SCHEMA_VERSION
        ):
            raise BenchmarkError("unsupported blind/live promotion schema")
        if type(self.splits) is not tuple:
            raise BenchmarkError("promotion splits must be a tuple")
        if len(self.splits) > len(PROMOTION_SPLITS):
            raise BenchmarkError("too many promotion splits")
        split_names: set[str] = set()
        case_ids: set[str] = set()
        manifest_digests: set[str] = set()
        total_cases = 0
        for split in self.splits:
            if type(split) is not PromotionSplit:
                raise BenchmarkError(
                    "promotion evidence contains an invalid split"
                )
            split.validate()
            if split.name in split_names:
                raise BenchmarkError("promotion split names must be unique")
            split_names.add(split.name)
            for case in split.cases:
                if case.case_id in case_ids:
                    raise BenchmarkError(
                        "promotion case_ids must be globally unique"
                    )
                if case.input_manifest_sha256 in manifest_digests:
                    raise BenchmarkError(
                        "promotion input manifest digests must be globally "
                        "unique"
                    )
                case_ids.add(case.case_id)
                manifest_digests.add(case.input_manifest_sha256)
                total_cases += 1
        if total_cases > _MAX_PROMOTION_CASES:
            raise BenchmarkError("promotion evidence exceeds the case limit")
        if type(self.baseline) is not PromotionArm:
            raise BenchmarkError("promotion baseline has an invalid type")
        if type(self.candidate) is not PromotionArm:
            raise BenchmarkError("promotion candidate has an invalid type")
        self.baseline.validate()
        self.candidate.validate()
        if type(self.evidence_complete) is not bool:
            raise BenchmarkError(
                "promotion evidence_complete must be a boolean"
            )


def _strict_dict(
    value: object,
    *,
    keys: frozenset[str],
    label: str,
) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != keys:
        raise BenchmarkError(f"{label} must contain exactly the required fields")
    return value


def _strict_list(
    value: object,
    *,
    label: str,
    maximum: int,
) -> list[object]:
    if type(value) is not list or len(value) > maximum:
        raise BenchmarkError(f"{label} must be a bounded list")
    return value


def _fingerprint_from_dict(value: object) -> BenchmarkExecutionFingerprint:
    raw = _strict_dict(
        value,
        keys=frozenset(
            {
                "tool_manifest_sha256",
                "image_sha256",
                "model_config_sha256",
                "engine_source_sha256",
            }
        ),
        label="execution_fingerprint",
    )
    fingerprint = BenchmarkExecutionFingerprint(
        tool_manifest_sha256=raw["tool_manifest_sha256"],
        image_sha256=raw["image_sha256"],
        model_config_sha256=raw["model_config_sha256"],
        engine_source_sha256=raw["engine_source_sha256"],
    )
    fingerprint.validate()
    return fingerprint


def _case_from_dict(value: object) -> PromotionCase:
    raw = _strict_dict(
        value,
        keys=frozenset(
            {"case_id", "category", "input_manifest_sha256"}
        ),
        label="promotion case",
    )
    case = PromotionCase(
        case_id=raw["case_id"],
        category=raw["category"],
        input_manifest_sha256=raw["input_manifest_sha256"],
    )
    case.validate()
    return case


def _split_from_dict(value: object) -> PromotionSplit:
    raw = _strict_dict(
        value,
        keys=frozenset(
            {
                "name",
                "cases",
                "trajectory_visible",
                "answers_visible",
                "prior_engine_runs",
                "evidence_complete",
            }
        ),
        label="promotion split",
    )
    cases = _strict_list(
        raw["cases"],
        label="promotion split cases",
        maximum=_MAX_PROMOTION_CASES,
    )
    split = PromotionSplit(
        name=raw["name"],
        cases=tuple(_case_from_dict(case) for case in cases),
        trajectory_visible=raw["trajectory_visible"],
        answers_visible=raw["answers_visible"],
        prior_engine_runs=raw["prior_engine_runs"],
        evidence_complete=raw["evidence_complete"],
    )
    split.validate()
    return split


def _attempt_from_dict(value: object) -> PromotionAttempt:
    raw = _strict_dict(
        value,
        keys=frozenset(
            {
                "attempt",
                "run_id",
                "solved",
                "proof_evaluated",
                "proof_passed",
                "reproduction_evaluated",
                "reproduced",
                "first_valid_result_seconds",
                "solve_wall_seconds_used",
                "model_calls_used",
                "total_tokens_used",
                "human_interventions",
            }
        ),
        label="promotion attempt",
    )
    attempt = PromotionAttempt(
        attempt=raw["attempt"],
        run_id=raw["run_id"],
        solved=raw["solved"],
        proof_evaluated=raw["proof_evaluated"],
        proof_passed=raw["proof_passed"],
        reproduction_evaluated=raw["reproduction_evaluated"],
        reproduced=raw["reproduced"],
        first_valid_result_seconds=raw["first_valid_result_seconds"],
        solve_wall_seconds_used=raw["solve_wall_seconds_used"],
        model_calls_used=raw["model_calls_used"],
        total_tokens_used=raw["total_tokens_used"],
        human_interventions=raw["human_interventions"],
    )
    attempt.validate()
    return attempt


def _result_from_dict(value: object) -> PromotionCaseResult:
    raw = _strict_dict(
        value,
        keys=frozenset({"case_id", "attempts", "evidence_complete"}),
        label="promotion case result",
    )
    attempts = _strict_list(
        raw["attempts"],
        label="promotion attempts",
        maximum=3,
    )
    result = PromotionCaseResult(
        case_id=raw["case_id"],
        attempts=tuple(
            _attempt_from_dict(attempt) for attempt in attempts
        ),
        evidence_complete=raw["evidence_complete"],
    )
    result.validate()
    return result


def _budget_from_dict(value: object) -> FixedBenchmarkBudget:
    raw = _strict_dict(
        value,
        keys=frozenset(
            {"wall_seconds", "model_call_limit", "total_token_limit"}
        ),
        label="promotion budget",
    )
    budget = FixedBenchmarkBudget(
        wall_seconds=raw["wall_seconds"],
        model_call_limit=raw["model_call_limit"],
        total_token_limit=raw["total_token_limit"],
    )
    budget.validate()
    return budget


def _safety_from_dict(value: object) -> SafetyTotals:
    raw = _strict_dict(
        value,
        keys=frozenset(
            {
                "orphan_runs",
                "false_proofs",
                "target_violations",
                "secret_or_flag_leaks",
                "complete_run_records",
                "terminal_run_records",
            }
        ),
        label="promotion safety",
    )
    safety = SafetyTotals(
        orphan_runs=raw["orphan_runs"],
        false_proofs=raw["false_proofs"],
        target_violations=raw["target_violations"],
        secret_or_flag_leaks=raw["secret_or_flag_leaks"],
        complete_run_records=raw["complete_run_records"],
        terminal_run_records=raw["terminal_run_records"],
    )
    safety.validate()
    return safety


def _arm_from_dict(value: object) -> PromotionArm:
    raw = _strict_dict(
        value,
        keys=frozenset(
            {
                "system",
                "model_id",
                "budget",
                "results",
                "safety",
                "evidence_complete",
                "execution_fingerprint",
            }
        ),
        label="promotion arm",
    )
    results = _strict_list(
        raw["results"],
        label="promotion results",
        maximum=_MAX_PROMOTION_CASES,
    )
    arm = PromotionArm(
        system=raw["system"],
        model_id=raw["model_id"],
        budget=_budget_from_dict(raw["budget"]),
        results=tuple(_result_from_dict(result) for result in results),
        safety=_safety_from_dict(raw["safety"]),
        evidence_complete=raw["evidence_complete"],
        execution_fingerprint=_fingerprint_from_dict(
            raw["execution_fingerprint"]
        ),
    )
    arm.validate()
    return arm


def _promotion_evidence_from_dict(
    value: object,
) -> BlindLivePromotionEvidence:
    raw = _strict_dict(
        value,
        keys=frozenset(
            {
                "schema_version",
                "splits",
                "baseline",
                "candidate",
                "evidence_complete",
            }
        ),
        label="blind/live promotion evidence",
    )
    splits = _strict_list(
        raw["splits"],
        label="promotion splits",
        maximum=len(PROMOTION_SPLITS),
    )
    evidence = BlindLivePromotionEvidence(
        splits=tuple(_split_from_dict(split) for split in splits),
        baseline=_arm_from_dict(raw["baseline"]),
        candidate=_arm_from_dict(raw["candidate"]),
        evidence_complete=raw["evidence_complete"],
        schema_version=raw["schema_version"],
    )
    evidence.validate()
    return evidence


def _promotion_evidence_to_dict(
    evidence: BlindLivePromotionEvidence,
) -> dict[str, object]:
    def case_to_dict(case: PromotionCase) -> dict[str, object]:
        return {
            "case_id": case.case_id,
            "category": case.category,
            "input_manifest_sha256": case.input_manifest_sha256,
        }

    def attempt_to_dict(attempt: PromotionAttempt) -> dict[str, object]:
        return {
            "attempt": attempt.attempt,
            "run_id": attempt.run_id,
            "solved": attempt.solved,
            "proof_evaluated": attempt.proof_evaluated,
            "proof_passed": attempt.proof_passed,
            "reproduction_evaluated": attempt.reproduction_evaluated,
            "reproduced": attempt.reproduced,
            "first_valid_result_seconds": (
                attempt.first_valid_result_seconds
            ),
            "solve_wall_seconds_used": attempt.solve_wall_seconds_used,
            "model_calls_used": attempt.model_calls_used,
            "total_tokens_used": attempt.total_tokens_used,
            "human_interventions": attempt.human_interventions,
        }

    def arm_to_dict(arm: PromotionArm) -> dict[str, object]:
        fingerprint = arm.execution_fingerprint
        if fingerprint is None:
            raise BenchmarkError(
                "execution_fingerprint is required for serialization"
            )
        return {
            "system": arm.system,
            "model_id": arm.model_id,
            "budget": {
                "wall_seconds": arm.budget.wall_seconds,
                "model_call_limit": arm.budget.model_call_limit,
                "total_token_limit": arm.budget.total_token_limit,
            },
            "results": [
                {
                    "case_id": result.case_id,
                    "attempts": [
                        attempt_to_dict(attempt)
                        for attempt in result.attempts
                    ],
                    "evidence_complete": result.evidence_complete,
                }
                for result in arm.results
            ],
            "safety": {
                "orphan_runs": arm.safety.orphan_runs,
                "false_proofs": arm.safety.false_proofs,
                "target_violations": arm.safety.target_violations,
                "secret_or_flag_leaks": arm.safety.secret_or_flag_leaks,
                "complete_run_records": arm.safety.complete_run_records,
                "terminal_run_records": arm.safety.terminal_run_records,
            },
            "evidence_complete": arm.evidence_complete,
            "execution_fingerprint": {
                "tool_manifest_sha256": (
                    fingerprint.tool_manifest_sha256
                ),
                "image_sha256": fingerprint.image_sha256,
                "model_config_sha256": (
                    fingerprint.model_config_sha256
                ),
                "engine_source_sha256": (
                    fingerprint.engine_source_sha256
                ),
            },
        }

    return {
        "schema_version": evidence.schema_version,
        "splits": [
            {
                "name": split.name,
                "cases": [case_to_dict(case) for case in split.cases],
                "trajectory_visible": split.trajectory_visible,
                "answers_visible": split.answers_visible,
                "prior_engine_runs": split.prior_engine_runs,
                "evidence_complete": split.evidence_complete,
            }
            for split in evidence.splits
        ],
        "baseline": arm_to_dict(evidence.baseline),
        "candidate": arm_to_dict(evidence.candidate),
        "evidence_complete": evidence.evidence_complete,
    }


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


def _append_once(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _promotion_split_policy_blockers(
    split: PromotionSplit,
    blockers: list[str],
) -> None:
    if not split.evidence_complete:
        _append_once(blockers, f"incomplete_split_evidence:{split.name}")
    if split.name == DEV:
        if not split.trajectory_visible:
            _append_once(blockers, "dev_trajectory_not_visible")
        return
    if split.trajectory_visible:
        _append_once(blockers, f"trajectory_leakage:{split.name}")
    if split.answers_visible:
        _append_once(blockers, f"answer_leakage:{split.name}")
    if split.name == REGRESSION:
        if split.prior_engine_runs == 0:
            _append_once(blockers, "regression_not_previously_run")
        return
    if split.name in {BLIND, LIVE, HIDDEN} and split.prior_engine_runs != 0:
        _append_once(blockers, f"prior_exposure:{split.name}")


def _promotion_arm_record_blockers(
    arm: PromotionArm,
    *,
    label: str,
    expected_case_ids: frozenset[str],
    blockers: list[str],
) -> bool:
    """Return whether the arm has all records needed to derive every metric."""

    complete = True
    if not arm.evidence_complete:
        _append_once(blockers, f"{label}_arm_evidence_incomplete")
        complete = False
    results = {result.case_id: result for result in arm.results}
    result_ids = frozenset(results)
    if result_ids != expected_case_ids:
        _append_once(blockers, f"{label}_case_coverage_incomplete")
        complete = False
    run_ids: set[str] = set()
    for case_id in sorted(expected_case_ids & result_ids):
        result = results[case_id]
        if not result.evidence_complete:
            _append_once(blockers, f"{label}_case_evidence_incomplete")
            complete = False
        attempts = {attempt.attempt: attempt for attempt in result.attempts}
        if frozenset(attempts) != frozenset({1, 2, 3}):
            _append_once(blockers, f"{label}_attempt_coverage_incomplete")
            complete = False
        for attempt in attempts.values():
            if attempt.run_id in run_ids:
                _append_once(blockers, f"{label}_run_id_reused")
                complete = False
            run_ids.add(attempt.run_id)
            if label == "candidate" and not attempt.proof_evaluated:
                _append_once(
                    blockers,
                    "candidate_proof_coverage_incomplete",
                )
                complete = False
            if label == "candidate" and not attempt.reproduction_evaluated:
                _append_once(
                    blockers,
                    "candidate_reproduction_coverage_incomplete",
                )
                complete = False
            if (
                (
                    attempt.solved
                    or (attempt.proof_passed and attempt.reproduced)
                )
                and attempt.first_valid_result_seconds is None
            ):
                _append_once(
                    blockers,
                    f"{label}_missing_first_valid_result",
                )
                complete = False
            budget_exceeded = (
                float(attempt.solve_wall_seconds_used)
                > arm.budget.wall_seconds
                or attempt.model_calls_used > arm.budget.model_call_limit
                or attempt.total_tokens_used > arm.budget.total_token_limit
            )
            if budget_exceeded:
                _append_once(
                    blockers,
                    f"{label}_budget_exceeded:{case_id}:{attempt.attempt}",
                )
                complete = False
            if (
                label == "candidate"
                and attempt.solved
                and (
                    not attempt.proof_evaluated
                    or not attempt.proof_passed
                )
            ):
                _append_once(blockers, f"{label}_unproved_solve")
            if (
                label == "candidate"
                and attempt.solved
                and (
                    not attempt.reproduction_evaluated
                    or not attempt.reproduced
                )
            ):
                _append_once(blockers, f"{label}_unreproduced_solve")

    safety = arm.safety
    if (
        safety.terminal_run_records == 0
        or safety.complete_run_records != safety.terminal_run_records
    ):
        _append_once(blockers, f"{label}_safety_records_incomplete")
        complete = False
    if any(
        (
            safety.orphan_runs,
            safety.false_proofs,
            safety.target_violations,
            safety.secret_or_flag_leaks,
        )
    ):
        _append_once(blockers, f"{label}_safety_violation")
    return complete


def _promotion_summary(
    cases: Sequence[PromotionCase],
    results: dict[str, PromotionCaseResult],
) -> dict[str, Any]:
    attempt_one_solved = 0
    two_of_three = 0
    accepted_solve_attempts = 0
    proof_evaluations = 0
    proof_passes = 0
    reproduction_evaluations = 0
    reproductions = 0
    first_valid_seconds: list[float] = []
    human_interventions = 0
    category_solve_at_one: dict[str, list[bool]] = {}
    category_pass_two_of_three: dict[str, list[bool]] = {}

    for case in cases:
        attempts = {
            attempt.attempt: attempt
            for attempt in results[case.case_id].attempts
        }
        first_attempt_solved = attempts[1].solved
        attempt_one_solved += int(first_attempt_solved)
        category_solve_at_one.setdefault(case.category, []).append(
            first_attempt_solved
        )
        solved_for_case = 0
        for attempt_number in (1, 2, 3):
            attempt = attempts[attempt_number]
            human_interventions += attempt.human_interventions
            if attempt.proof_evaluated:
                proof_evaluations += 1
                proof_passes += int(attempt.proof_passed)
            if attempt.reproduction_evaluated:
                reproduction_evaluations += 1
                reproductions += int(attempt.reproduced)
            if attempt.first_valid_result_seconds is not None:
                first_valid_seconds.append(
                    float(attempt.first_valid_result_seconds)
                )
            if not attempt.solved:
                continue
            solved_for_case += 1
            accepted_solve_attempts += 1
        passed_two_of_three = solved_for_case >= 2
        two_of_three += int(passed_two_of_three)
        category_pass_two_of_three.setdefault(
            case.category,
            [],
        ).append(passed_two_of_three)

    case_count = len(cases)
    total_attempts = case_count * 3
    categories = {
        category: {
            "solved_cases": sum(solve_values),
            "eligible_cases": len(solve_values),
            "rate": sum(solve_values) / len(solve_values),
            "solve@1": {
                "solved_cases": sum(solve_values),
                "eligible_cases": len(solve_values),
                "rate": sum(solve_values) / len(solve_values),
            },
            "pass^2/3": {
                "two_of_three_cases": sum(
                    category_pass_two_of_three[category]
                ),
                "eligible_cases": len(
                    category_pass_two_of_three[category]
                ),
                "rate": (
                    sum(category_pass_two_of_three[category])
                    / len(category_pass_two_of_three[category])
                ),
            },
        }
        for category, solve_values in sorted(
            category_solve_at_one.items()
        )
    }
    category_floor = min(
        value["rate"] for value in categories.values()
    )
    floor_categories = [
        category
        for category, value in categories.items()
        if value["rate"] == category_floor
    ]
    return {
        "solve@1": {
            "solved_cases": attempt_one_solved,
            "eligible_cases": case_count,
            "rate": attempt_one_solved / case_count,
        },
        "pass^2/3": {
            "two_of_three_cases": two_of_three,
            "eligible_cases": case_count,
            "rate": two_of_three / case_count,
        },
        "accepted_solve_attempts": accepted_solve_attempts,
        "median_time_to_first_valid_result": {
            "seconds": (
                float(median(first_valid_seconds))
                if first_valid_seconds
                else None
            ),
            "observed_results": len(first_valid_seconds),
            "censored_attempts": total_attempts - len(first_valid_seconds),
        },
        "proof_pass_rate": {
            "passed_evaluations": proof_passes,
            "evaluations": proof_evaluations,
            "rate": (
                proof_passes / proof_evaluations
                if proof_evaluations
                else None
            ),
        },
        "reproduction_rate": {
            "successful_evaluations": reproductions,
            "evaluations": reproduction_evaluations,
            "rate": (
                reproductions / reproduction_evaluations
                if reproduction_evaluations
                else None
            ),
        },
        "human_interventions": human_interventions,
        "category_floor": {
            "rate": category_floor,
            "categories": floor_categories,
            "by_category": categories,
        },
    }


def _time_noninferior(
    candidate_seconds: float | None,
    baseline_seconds: float | None,
) -> bool:
    if baseline_seconds is None:
        return True
    if candidate_seconds is None:
        return False
    return candidate_seconds <= baseline_seconds


def _time_improved(
    candidate_seconds: float | None,
    baseline_seconds: float | None,
) -> bool:
    if baseline_seconds is None:
        return candidate_seconds is not None
    if candidate_seconds is None:
        return False
    required_improvement = max(
        MIN_TTFVR_ABSOLUTE_IMPROVEMENT_SECONDS,
        baseline_seconds * MIN_TTFVR_RELATIVE_IMPROVEMENT,
    )
    return baseline_seconds - candidate_seconds >= required_improvement


def _optional_rate_noninferior(
    candidate_rate: float | None,
    baseline_rate: float | None,
) -> bool:
    if baseline_rate is None:
        return True
    if candidate_rate is None:
        return False
    return candidate_rate >= baseline_rate


def _summary_noninferiority(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, bool]:
    return {
        "solve@1": (
            candidate["solve@1"]["rate"] >= baseline["solve@1"]["rate"]
        ),
        "pass^2/3": (
            candidate["pass^2/3"]["rate"]
            >= baseline["pass^2/3"]["rate"]
        ),
        "median_time_to_first_valid_result": _time_noninferior(
            candidate["median_time_to_first_valid_result"]["seconds"],
            baseline["median_time_to_first_valid_result"]["seconds"],
        ),
        "first_valid_observed_results": (
            candidate["median_time_to_first_valid_result"][
                "observed_results"
            ]
            >= baseline["median_time_to_first_valid_result"][
                "observed_results"
            ]
        ),
        "proof_pass_rate": _optional_rate_noninferior(
            candidate["proof_pass_rate"]["rate"],
            baseline["proof_pass_rate"]["rate"],
        ),
        "reproduction_rate": _optional_rate_noninferior(
            candidate["reproduction_rate"]["rate"],
            baseline["reproduction_rate"]["rate"],
        ),
        "human_interventions": (
            candidate["human_interventions"]
            <= baseline["human_interventions"]
        ),
    }


def _summary_primary_improvement(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
) -> bool:
    return (
        candidate["solve@1"]["rate"] > baseline["solve@1"]["rate"]
        or candidate["pass^2/3"]["rate"]
        > baseline["pass^2/3"]["rate"]
        or (
            _time_improved(
                candidate["median_time_to_first_valid_result"]["seconds"],
                baseline["median_time_to_first_valid_result"]["seconds"],
            )
            and candidate["accepted_solve_attempts"] > 0
        )
    )


def evaluate_blind_live_promotion(
    evidence: BlindLivePromotionEvidence,
) -> dict[str, Any]:
    """Evaluate promotion eligibility without mutating a production default.

    The gate derives all metrics from paired, typed three-attempt records.
    It does not authenticate operator-supplied JSON; an engine-owned collector
    must bind the referenced runs and artifacts before any future automatic
    promotion. Malformed typed input raises :class:`BenchmarkError`;
    well-formed but incomplete, leaked, unsafe, or non-improving evidence
    returns a closed decision with stable blocker codes.
    """

    if type(evidence) is not BlindLivePromotionEvidence:
        raise BenchmarkError(
            "blind/live promotion requires typed promotion evidence"
        )
    evidence.validate()

    blockers: list[str] = []
    if not evidence.evidence_complete:
        _append_once(blockers, "promotion_evidence_incomplete")
    split_by_name = {split.name: split for split in evidence.splits}
    required_splits = (DEV, REGRESSION, BLIND, LIVE)
    for required_split in required_splits:
        if required_split not in split_by_name:
            _append_once(blockers, f"missing_required_split:{required_split}")
    for split in evidence.splits:
        _promotion_split_policy_blockers(split, blockers)

    holdout_split_records = tuple(
        split
        for split in evidence.splits
        if split.name in {BLIND, LIVE, HIDDEN}
    )
    for split in holdout_split_records:
        if len(split.cases) < MIN_HOLDOUT_CASES_PER_SPLIT:
            _append_once(
                blockers,
                f"insufficient_holdout_split_cases:{split.name}",
            )
        for category in sorted(REQUIRED_PROMOTION_CATEGORIES):
            if not any(case.category == category for case in split.cases):
                _append_once(
                    blockers,
                    f"missing_split_category:{split.name}:{category}",
                )
    holdout_category_counts = {
        category: sum(
            case.category == category
            for split in holdout_split_records
            for case in split.cases
        )
        for category in sorted(REQUIRED_PROMOTION_CATEGORIES)
    }
    for category, count in holdout_category_counts.items():
        if count == 0:
            _append_once(
                blockers,
                f"missing_holdout_category:{category}",
            )
        elif count < MIN_HOLDOUT_CASES_PER_CATEGORY:
            _append_once(
                blockers,
                f"insufficient_holdout_category_cases:{category}",
            )

    baseline = evidence.baseline
    candidate = evidence.candidate
    if baseline.system != THIN_SCAFFOLD:
        _append_once(blockers, "baseline_not_thin_scaffold")
    if candidate.system != CTF_OS_SYSTEM:
        _append_once(blockers, "candidate_not_ctf_os")
    if baseline.model_id != candidate.model_id:
        _append_once(blockers, "model_mismatch")
    if baseline.budget != candidate.budget:
        _append_once(blockers, "budget_mismatch")
    if baseline.execution_fingerprint is None:
        _append_once(blockers, "baseline_execution_fingerprint_missing")
    if candidate.execution_fingerprint is None:
        _append_once(blockers, "candidate_execution_fingerprint_missing")
    if (
        baseline.execution_fingerprint is not None
        and candidate.execution_fingerprint is not None
        and baseline.execution_fingerprint
        != candidate.execution_fingerprint
    ):
        _append_once(blockers, "execution_fingerprint_mismatch")

    all_cases = tuple(
        case
        for split in evidence.splits
        for case in split.cases
    )
    holdout_cases = tuple(
        case
        for split in holdout_split_records
        for case in split.cases
    )
    public_cases = tuple(
        case
        for split in evidence.splits
        if split.name in {DEV, REGRESSION}
        for case in split.cases
    )
    expected_case_ids = frozenset(case.case_id for case in all_cases)
    baseline_records_complete = _promotion_arm_record_blockers(
        baseline,
        label="baseline",
        expected_case_ids=expected_case_ids,
        blockers=blockers,
    )
    candidate_records_complete = _promotion_arm_record_blockers(
        candidate,
        label="candidate",
        expected_case_ids=expected_case_ids,
        blockers=blockers,
    )
    baseline_run_ids = frozenset(
        attempt.run_id
        for result in baseline.results
        for attempt in result.attempts
    )
    candidate_run_ids = frozenset(
        attempt.run_id
        for result in candidate.results
        for attempt in result.attempts
    )
    run_ids_disjoint = baseline_run_ids.isdisjoint(candidate_run_ids)
    if not run_ids_disjoint:
        _append_once(blockers, "run_id_reused_across_arms")
    records_complete = (
        evidence.evidence_complete
        and all(split.evidence_complete for split in evidence.splits)
        and baseline_records_complete
        and candidate_records_complete
        and run_ids_disjoint
        and all(name in split_by_name for name in required_splits)
        and baseline.execution_fingerprint is not None
        and candidate.execution_fingerprint is not None
    )

    metrics: dict[str, Any] | None = None
    comparisons: dict[str, Any] | None = None
    if records_complete:
        baseline_results = {
            result.case_id: result for result in baseline.results
        }
        candidate_results = {
            result.case_id: result for result in candidate.results
        }
        baseline_by_split = {
            split.name: _promotion_summary(split.cases, baseline_results)
            for split in evidence.splits
        }
        candidate_by_split = {
            split.name: _promotion_summary(split.cases, candidate_results)
            for split in evidence.splits
        }
        baseline_all = _promotion_summary(all_cases, baseline_results)
        candidate_all = _promotion_summary(all_cases, candidate_results)
        baseline_holdout = _promotion_summary(
            holdout_cases,
            baseline_results,
        )
        candidate_holdout = _promotion_summary(
            holdout_cases,
            candidate_results,
        )
        baseline_public = _promotion_summary(public_cases, baseline_results)
        candidate_public = _promotion_summary(public_cases, candidate_results)

        split_noninferiority: dict[str, dict[str, bool]] = {}
        for split in evidence.splits:
            split_checks = _summary_noninferiority(
                baseline_by_split[split.name],
                candidate_by_split[split.name],
            )
            split_noninferiority[split.name] = split_checks
            for metric, passed in split_checks.items():
                if not passed:
                    _append_once(
                        blockers,
                        f"split_regression:{split.name}:{metric}",
                    )

        holdout_split_category_noninferiority: dict[
            str,
            dict[str, dict[str, bool]],
        ] = {}
        holdout_split_category_floor_noninferiority: dict[str, bool] = {}
        for split in holdout_split_records:
            baseline_split = baseline_by_split[split.name]
            candidate_split = candidate_by_split[split.name]
            floor_noninferior = (
                candidate_split["category_floor"]["rate"]
                >= baseline_split["category_floor"]["rate"]
            )
            holdout_split_category_floor_noninferiority[
                split.name
            ] = floor_noninferior
            if not floor_noninferior:
                _append_once(
                    blockers,
                    f"split_category_floor_regression:{split.name}",
                )

            category_checks: dict[str, dict[str, bool]] = {}
            for category in sorted(REQUIRED_PROMOTION_CATEGORIES):
                baseline_category = baseline_split["category_floor"][
                    "by_category"
                ].get(category)
                candidate_category = candidate_split["category_floor"][
                    "by_category"
                ].get(category)
                if baseline_category is None or candidate_category is None:
                    checks = {
                        "solve@1": False,
                        "pass^2/3": False,
                    }
                else:
                    checks = {
                        "solve@1": (
                            candidate_category["solve@1"]["rate"]
                            >= baseline_category["solve@1"]["rate"]
                        ),
                        "pass^2/3": (
                            candidate_category["pass^2/3"]["rate"]
                            >= baseline_category["pass^2/3"]["rate"]
                        ),
                    }
                category_checks[category] = checks
                for metric, passed in checks.items():
                    if not passed:
                        _append_once(
                            blockers,
                            "split_category_regression:"
                            f"{split.name}:{category}:{metric}",
                        )
            holdout_split_category_noninferiority[
                split.name
            ] = category_checks

        category_floor_noninferior = (
            candidate_holdout["category_floor"]["rate"]
            >= baseline_holdout["category_floor"]["rate"]
        )
        if not category_floor_noninferior:
            _append_once(blockers, "category_floor_regression")

        holdout_category_noninferiority: dict[
            str,
            dict[str, bool],
        ] = {}
        for category in sorted(REQUIRED_PROMOTION_CATEGORIES):
            baseline_category = baseline_holdout["category_floor"][
                "by_category"
            ].get(category)
            candidate_category = candidate_holdout["category_floor"][
                "by_category"
            ].get(category)
            if baseline_category is None or candidate_category is None:
                # Coverage policy already records a precise missing-category
                # blocker. Keep the comparison fail-closed as well instead of
                # allowing malformed benchmark composition to escape as a
                # KeyError at the CLI boundary.
                checks = {
                    "solve@1": False,
                    "pass^2/3": False,
                }
            else:
                checks = {
                    "solve@1": (
                        candidate_category["solve@1"]["rate"]
                        >= baseline_category["solve@1"]["rate"]
                    ),
                    "pass^2/3": (
                        candidate_category["pass^2/3"]["rate"]
                        >= baseline_category["pass^2/3"]["rate"]
                    ),
                }
            holdout_category_noninferiority[category] = checks
            for metric, passed in checks.items():
                if not passed:
                    _append_once(
                        blockers,
                        f"category_regression:{category}:{metric}",
                    )

        if candidate_holdout["accepted_solve_attempts"] == 0:
            _append_once(
                blockers,
                "candidate_holdout_has_no_accepted_solve",
            )
        promotion_signal_splits = [LIVE]
        if HIDDEN in split_by_name:
            promotion_signal_splits.append(HIDDEN)
        public_splits = [
            split.name
            for split in evidence.splits
            if split.name in {DEV, REGRESSION}
        ]
        holdout_improvement = any(
            _summary_primary_improvement(
                baseline_by_split[name],
                candidate_by_split[name],
            )
            for name in promotion_signal_splits
        )
        public_improvement = any(
            _summary_primary_improvement(
                baseline_by_split[name],
                candidate_by_split[name],
            )
            for name in public_splits
        )
        if not holdout_improvement:
            _append_once(blockers, "no_live_hidden_improvement")

        overall_noninferiority = _summary_noninferiority(
            baseline_all,
            candidate_all,
        )
        for metric, passed in overall_noninferiority.items():
            if not passed:
                _append_once(blockers, f"overall_regression:{metric}")

        comparisons = {
            "same_model": baseline.model_id == candidate.model_id,
            "same_fixed_budget": baseline.budget == candidate.budget,
            "same_execution_fingerprint": (
                baseline.execution_fingerprint is not None
                and baseline.execution_fingerprint
                == candidate.execution_fingerprint
            ),
            "paired_case_set": (
                frozenset(baseline_results)
                == frozenset(candidate_results)
                == expected_case_ids
            ),
            "run_ids_disjoint_across_arms": run_ids_disjoint,
            "input_manifests_globally_unique": True,
            "split_noninferiority": split_noninferiority,
            "overall_noninferiority": overall_noninferiority,
            "category_floor_noninferior": category_floor_noninferior,
            "holdout_split_category_floor_noninferiority": (
                holdout_split_category_floor_noninferiority
            ),
            "holdout_split_category_noninferiority": (
                holdout_split_category_noninferiority
            ),
            "holdout_category_noninferiority": (
                holdout_category_noninferiority
            ),
            "holdout_category_case_counts": holdout_category_counts,
            "public_improvement": public_improvement,
            "live_hidden_improvement": holdout_improvement,
            "promotion_signal_splits": promotion_signal_splits,
        }
        metrics = {
            "baseline": {
                "overall": baseline_all,
                "live_hidden": baseline_holdout,
                "public": baseline_public,
                "by_split": baseline_by_split,
            },
            "candidate": {
                "overall": candidate_all,
                "live_hidden": candidate_holdout,
                "public": candidate_public,
                "by_split": candidate_by_split,
            },
        }

    eligible = not blockers
    return {
        "schema_version": BLIND_LIVE_PROMOTION_SCHEMA_VERSION,
        "decision": (
            "eligible_for_manual_promotion"
            if eligible
            else "do_not_promote"
        ),
        "promotion_eligible": eligible,
        "default_changed": False,
        "complete_evidence": records_complete,
        "blockers": blockers,
        "requirements": {
            "required_splits": list(required_splits),
            "blind_prior_engine_runs": 0,
            "fixed_budget": True,
            "same_model_thin_scaffold": True,
            "same_execution_fingerprint": True,
            "actual_attempt_usage_required": True,
            "unique_run_ids_per_arm_and_across_arms_required": True,
            "input_manifest_digest_required": True,
            "candidate_proof_and_reproduction_required": True,
            "safety_violations_allowed": 0,
            "live_hidden_improvement_required": True,
            "candidate_holdout_accepted_solve_required": True,
            "category_floor_regression_allowed": False,
            "required_holdout_categories": sorted(
                REQUIRED_PROMOTION_CATEGORIES
            ),
            "minimum_holdout_cases_per_category": (
                MIN_HOLDOUT_CASES_PER_CATEGORY
            ),
            "minimum_holdout_cases_per_split": MIN_HOLDOUT_CASES_PER_SPLIT,
            "every_holdout_split_requires_every_category": True,
            "minimum_ttfvr_relative_improvement": (
                MIN_TTFVR_RELATIVE_IMPROVEMENT
            ),
            "minimum_ttfvr_absolute_improvement_seconds": (
                MIN_TTFVR_ABSOLUTE_IMPROVEMENT_SECONDS
            ),
            "operator_json_is_trusted": False,
            "engine_derived_collector_required_for_automatic_promotion": True,
        },
        "metrics": metrics,
        "comparisons": comparisons,
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
    "BLIND",
    "BLIND_LIVE_PROMOTION_SCHEMA_VERSION",
    "BenchmarkExecutionFingerprint",
    "BlindLivePromotionEvidence",
    "BenchmarkError",
    "COHORTS",
    "CTF_OS_SYSTEM",
    "CohortSample",
    "DEV",
    "FixedBenchmarkBudget",
    "HIDDEN",
    "LEGACY",
    "LIVE",
    "MANAGED_OBSERVE",
    "MANAGED_X22_TREATMENT",
    "MIN_HOLDOUT_CASES_PER_CATEGORY",
    "MIN_HOLDOUT_CASES_PER_SPLIT",
    "MIN_TTFVR_ABSOLUTE_IMPROVEMENT_SECONDS",
    "MIN_TTFVR_RELATIVE_IMPROVEMENT",
    "OPERATOR_MANUAL",
    "PROMOTION_SPLITS",
    "PromotionArm",
    "PromotionAttempt",
    "PromotionCase",
    "PromotionCaseResult",
    "PromotionSplit",
    "REGRESSION",
    "REQUIRED_PROMOTION_CATEGORIES",
    "SafetyTotals",
    "THIN_SCAFFOLD",
    "evaluate_blind_live_promotion",
    "evaluate_managed_promotion",
    "evaluate_x22",
    "evaluate_x23",
    "evaluate_x24",
    "evaluate_x25",
]
