"""Deterministic, read-only evaluation over canonical CTF-OS records.

The evaluator never starts a model, tool, scheduler, proof, or submission.  It
only reads bounded ``state.json`` files and hash-validated proof-result
artifacts.  A metric is marked partial or unavailable instead of guessing when
the canonical records do not contain the evidence needed to calculate it.
"""

from __future__ import annotations

import hashlib
import heapq
import json
import math
import os
import stat
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from statistics import median
from typing import Any

from ctf_os.models import (
    ArtifactReference,
    ChallengeIdentity,
    ChallengeState,
    ExperimentStatus,
    ModelValidationError,
    RunStatus,
    SubmissionStatus,
)
from ctf_os.store.upgrades import UnsupportedSchemaVersion, upgrade_state

EVALUATION_SCHEMA_VERSION = 1
DEFAULT_MAX_STATES = 1024
MAX_STATE_LIMIT = 4096
MAX_STATE_BYTES = 16 * 1024 * 1024
MAX_PROOF_RESULT_BYTES = 64 * 1024
MAX_DIAGNOSTICS = 128
MAX_DIAGNOSTIC_BYTES = 512
MAX_COMMAND_BYTES = 64 * 1024
MAX_METADATA_ID_BYTES = 256
MAX_BREAKDOWN_ITEMS = 64
MAX_COUNTER_VALUE = (1 << 63) - 1

_METRIC_AVAILABLE = "available"
_METRIC_PARTIAL = "partial"
_METRIC_UNAVAILABLE = "unavailable"
_USAGE_FIELDS = (
    "input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
)
_PROOF_RESULT_KEYS = {
    "passed",
    "candidate",
    "policy_mode",
    "successful_attempts",
    "required_attempts",
    "total_attempts",
    "source_manifest_sha256",
    "failures",
    "run_ids",
}
_EXECUTED_EXPERIMENT_STATUSES = {
    ExperimentStatus.AWAITING_EVALUATION,
    ExperimentStatus.KEPT,
    ExperimentStatus.DROPPED,
    ExperimentStatus.INCONCLUSIVE,
    ExperimentStatus.FAILED,
}


class EvaluationError(RuntimeError):
    """Raised for an invalid evaluation request."""


class EvaluationInputError(EvaluationError):
    """Raised when a bounded canonical input is malformed."""


@dataclass(frozen=True, slots=True)
class EvaluationMetric:
    """One aggregate with explicit evidence availability."""

    status: str
    value: object | None
    sample_size: int
    reason: str | None = None
    evidence: Mapping[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "status": self.status,
            "value": self.value,
            "sample_size": self.sample_size,
        }
        if self.reason is not None:
            result["reason"] = self.reason
        if self.evidence:
            result["evidence"] = dict(self.evidence)
        return result


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    """Bounded JSON-ready evaluation output."""

    scope: Mapping[str, str | None]
    selected_states: int
    evaluated_states: int
    skipped_states: int
    truncated: bool
    metrics: Mapping[str, EvaluationMetric]
    diagnostics: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return not self.truncated and self.skipped_states == 0

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": EVALUATION_SCHEMA_VERSION,
            "scope": dict(self.scope),
            "complete": self.complete,
            "selected_states": self.selected_states,
            "evaluated_states": self.evaluated_states,
            "skipped_states": self.skipped_states,
            "truncated": self.truncated,
            "metrics": {
                name: metric.to_dict()
                for name, metric in sorted(self.metrics.items())
            },
            "diagnostics": list(self.diagnostics),
            "methodology": {
                "solve_success": "manual accepted submission",
                "trial_grouping": (
                    "metadata evaluation_case_id/evaluation_attempt; "
                    "otherwise challenge identity is attempt 1"
                ),
                "clean_reproduction": (
                    "successful/total attempts from bounded, hash-validated "
                    "proof result artifacts"
                ),
                "time_origin": "challenge state created_at",
            },
        }


@dataclass(frozen=True, slots=True)
class _LoadedState:
    state: ChallengeState
    root: Path


@dataclass(frozen=True, slots=True)
class _ProofObservation:
    candidate_id: str
    passed: bool
    successful_attempts: int
    total_attempts: int
    completed_at: str


class _Diagnostics:
    def __init__(self) -> None:
        self._values: list[str] = []
        self._suppressed = 0

    def add(self, value: object) -> None:
        if len(self._values) >= MAX_DIAGNOSTICS:
            self._suppressed += 1
            return
        self._values.append(_bounded_text(value, MAX_DIAGNOSTIC_BYTES))

    def values(self) -> tuple[str, ...]:
        values = list(self._values)
        if self._suppressed:
            values.append(f"{self._suppressed} additional diagnostics suppressed")
        return tuple(values)


def _bounded_text(value: object, maximum_bytes: int) -> str:
    text = " ".join(str(value).replace("\x00", "\N{REPLACEMENT CHARACTER}").split())
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= maximum_bytes:
        return text
    suffix = b"...[truncated]"
    clipped = encoded[: max(0, maximum_bytes - len(suffix))]
    while clipped:
        try:
            return clipped.decode("utf-8") + suffix.decode("ascii")
        except UnicodeDecodeError:
            clipped = clipped[:-1]
    return suffix[:maximum_bytes].decode("ascii", errors="ignore")


def _strict_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvaluationInputError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise EvaluationInputError(f"non-finite JSON number: {value}")


def _read_bounded_descriptor(
    descriptor: int,
    *,
    display_name: str,
    maximum_bytes: int,
) -> tuple[bytes, os.stat_result]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise EvaluationInputError(f"not a regular file: {display_name}")
    if before.st_size > maximum_bytes:
        raise EvaluationInputError(
            f"{display_name} exceeds {maximum_bytes} bytes"
        )
    chunks: list[bytes] = []
    remaining = maximum_bytes + 1
    while remaining:
        chunk = os.read(descriptor, min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    if len(payload) > maximum_bytes:
        raise EvaluationInputError(
            f"{display_name} exceeds {maximum_bytes} bytes"
        )
    after = os.fstat(descriptor)
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_identity != after_identity or len(payload) != after.st_size:
        raise EvaluationInputError(f"{display_name} changed while being read")
    return payload, after


def _read_bounded_regular(path: Path, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        payload, _metadata = _read_bounded_descriptor(
            descriptor,
            display_name=path.name,
            maximum_bytes=maximum_bytes,
        )
        return payload
    finally:
        os.close(descriptor)


def _strict_json_bytes(payload: bytes, display_name: str) -> object:
    try:
        text = payload.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_invalid_constant,
        )
    except UnicodeDecodeError as error:
        raise EvaluationInputError(f"{display_name} is not UTF-8") from error
    except json.JSONDecodeError as error:
        raise EvaluationInputError(
            f"{display_name} is not valid JSON: {error.msg}"
        ) from error


def _read_strict_json(path: Path, maximum_bytes: int) -> object:
    return _strict_json_bytes(
        _read_bounded_regular(path, maximum_bytes),
        path.name,
    )


def _read_verified_artifact(
    challenge_root: Path,
    artifact: ArtifactReference,
    *,
    maximum_bytes: int,
) -> bytes:
    relative = Path(artifact.path)
    if (
        relative.is_absolute()
        or PureWindowsPath(artifact.path).is_absolute()
        or "\\" in artifact.path
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.parts[0] != "proof"
    ):
        raise EvaluationInputError(
            "proof artifact path is not a normalized relative proof path"
        )
    if (
        len(artifact.sha256) != 64
        or any(
            character not in "0123456789abcdefABCDEF"
            for character in artifact.sha256
        )
    ):
        raise EvaluationInputError("proof artifact has an invalid SHA-256")

    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptors: list[int] = []
    try:
        current = os.open(challenge_root, directory_flags)
        descriptors.append(current)
        for component in relative.parts[:-1]:
            current = os.open(
                component,
                directory_flags,
                dir_fd=current,
            )
            descriptors.append(current)
        descriptor = os.open(
            relative.parts[-1],
            file_flags,
            dir_fd=current,
        )
        descriptors.append(descriptor)
        payload, metadata = _read_bounded_descriptor(
            descriptor,
            display_name="proof result artifact",
            maximum_bytes=maximum_bytes,
        )
        if artifact.size is not None and metadata.st_size != artifact.size:
            raise EvaluationInputError(
                "proof artifact size does not match its canonical reference"
            )
        actual_sha256 = hashlib.sha256(payload).hexdigest()
        if actual_sha256.lower() != artifact.sha256.lower():
            raise EvaluationInputError(
                "proof artifact SHA-256 does not match its canonical reference"
            )
        return payload
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _child_directories(path: Path) -> Iterable[Path]:
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                try:
                    if entry.is_dir(follow_symlinks=False):
                        yield Path(entry.path)
                except OSError:
                    continue
    except FileNotFoundError:
        return


def _candidate_state_paths(
    workspace_root: Path,
    *,
    contest_id: str | None,
    category: str | None,
    challenge_id: str | None,
) -> Iterable[Path]:
    contests_root = workspace_root / ".ctfos" / "contests"
    for contest_path in _child_directories(contests_root):
        if contest_id is not None and contest_path.name != contest_id:
            continue
        challenges_root = contest_path / "challenges"
        for category_path in _child_directories(challenges_root):
            if category is not None and category_path.name != category:
                continue
            for challenge_path in _child_directories(category_path):
                if challenge_id is not None and challenge_path.name != challenge_id:
                    continue
                state_path = challenge_path / "state.json"
                try:
                    metadata = state_path.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISREG(metadata.st_mode) and not state_path.is_symlink():
                    yield state_path


def _state_sort_key(workspace_root: Path, path: Path) -> str:
    try:
        return path.relative_to(workspace_root).as_posix()
    except ValueError:
        return path.as_posix()


def _load_state(path: Path) -> _LoadedState:
    raw = _read_strict_json(path, MAX_STATE_BYTES)
    if not isinstance(raw, Mapping):
        raise EvaluationInputError("state.json root must be an object")
    state = ChallengeState.from_dict(upgrade_state(raw))
    state.validate()
    expected = ChallengeIdentity(
        contest_id=path.parents[3].name,
        category=path.parents[1].name,
        challenge_id=path.parent.name,
    )
    if state.identity != expected:
        raise EvaluationInputError(
            "state identity does not match its canonical directory"
        )
    return _LoadedState(state=state, root=path.parent)


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value or len(value) > 64:
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _elapsed_seconds(start: object, end: object) -> float | None:
    start_time = _parse_timestamp(start)
    end_time = _parse_timestamp(end)
    if start_time is None or end_time is None:
        return None
    elapsed = (end_time - start_time).total_seconds()
    if not math.isfinite(elapsed) or elapsed < 0:
        return None
    return elapsed


def _finite_nonnegative(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    converted = float(value)
    if not math.isfinite(converted) or converted < 0:
        return None
    return converted


def _nonnegative_integer(value: object) -> int | None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= MAX_COUNTER_VALUE
    ):
        return None
    return value


def _round(value: float) -> float:
    return round(value, 6)


def _time_summary(values: Sequence[float]) -> dict[str, object]:
    ordered = sorted(values)
    return {
        "count": len(ordered),
        "min_seconds": _round(ordered[0]),
        "median_seconds": _round(float(median(ordered))),
        "mean_seconds": _round(sum(ordered) / len(ordered)),
        "max_seconds": _round(ordered[-1]),
    }


def _metric(
    value: object,
    sample_size: int,
    *,
    partial_reason: str | None = None,
    evidence: Mapping[str, object] | None = None,
) -> EvaluationMetric:
    return EvaluationMetric(
        status=_METRIC_PARTIAL if partial_reason else _METRIC_AVAILABLE,
        value=value,
        sample_size=sample_size,
        reason=partial_reason,
        evidence=evidence,
    )


def _unavailable(
    reason: str,
    *,
    evidence: Mapping[str, object] | None = None,
) -> EvaluationMetric:
    return EvaluationMetric(
        status=_METRIC_UNAVAILABLE,
        value=None,
        sample_size=0,
        reason=reason,
        evidence=evidence,
    )


def _combine_reasons(*values: str | None) -> str | None:
    reasons = [value for value in values if value]
    return "; ".join(dict.fromkeys(reasons)) or None


def _accepted(state: ChallengeState) -> bool:
    return any(
        submission.status is SubmissionStatus.ACCEPTED
        for submission in state.submissions
    )


def _trial_key(
    state: ChallengeState,
) -> tuple[str, int] | None:
    raw_case = state.metadata.get("evaluation_case_id")
    raw_attempt = state.metadata.get("evaluation_attempt")
    if raw_case is None and raw_attempt is None:
        has_attempt_evidence = bool(
            state.runs
            or state.submissions
            or state.progress_markers
            or any(
                experiment.status in _EXECUTED_EXPERIMENT_STATUSES
                for experiment in state.experiments
            )
        )
        if not has_attempt_evidence:
            return None
        return (
            f"{state.contest_id}/{state.category}/{state.challenge_id}",
            1,
        )
    if (
        not isinstance(raw_case, str)
        or not raw_case.strip()
        or "\x00" in raw_case
        or len(raw_case.encode("utf-8")) > MAX_METADATA_ID_BYTES
        or isinstance(raw_attempt, bool)
        or not isinstance(raw_attempt, int)
        or not 1 <= raw_attempt <= 1000
    ):
        return None
    return (f"{state.contest_id}/{raw_case.strip()}", raw_attempt)


def _fixed_wall_budget_seconds(
    state: ChallengeState,
) -> tuple[float | None, str | None]:
    allocated = state.budget.allocated_seconds
    allocated_value = (
        float(allocated)
        if isinstance(allocated, int)
        and not isinstance(allocated, bool)
        and allocated >= 0
        else None
    )
    deadline = _parse_timestamp(state.budget.deadline_utc)
    reset_at = state.metadata.get("budget_reset_at")
    origin = (
        _parse_timestamp(reset_at)
        if reset_at is not None
        else _parse_timestamp(state.created_at)
    )
    deadline_value = (
        (deadline - origin).total_seconds()
        if deadline is not None and origin is not None
        else None
    )
    if deadline_value is not None and (
        not math.isfinite(deadline_value) or deadline_value < 0
    ):
        deadline_value = None
    if (
        allocated_value is not None
        and deadline_value is not None
        and abs(allocated_value - deadline_value) > 2
    ):
        return (
            None,
            "allocated_seconds disagrees with the canonical deadline duration",
        )
    if allocated_value is not None:
        return (_round(allocated_value), None)
    if deadline_value is not None:
        return (_round(deadline_value), None)
    return (None, "no allocated_seconds or derivable deadline duration")


def _solve_metrics(
    records: Sequence[_LoadedState],
) -> tuple[dict[str, EvaluationMetric], int]:
    trials: dict[str, dict[int, tuple[bool, float | None]]] = defaultdict(dict)
    duplicate_keys: set[tuple[str, int]] = set()
    invalid_trials = 0
    duplicate_trials = 0
    budget_errors = 0
    for record in records:
        key = _trial_key(record.state)
        if key is None:
            invalid_trials += 1
            continue
        case_id, attempt = key
        if key in duplicate_keys:
            duplicate_trials += 1
            continue
        if attempt in trials[case_id]:
            duplicate_trials += 1
            trials[case_id].pop(attempt, None)
            duplicate_keys.add(key)
            continue
        budget, budget_error = _fixed_wall_budget_seconds(record.state)
        budget_errors += budget_error is not None
        trials[case_id][attempt] = (_accepted(record.state), budget)

    trial_values = [
        value
        for attempts in trials.values()
        for attempt, value in attempts.items()
        if attempt <= 3
    ]
    budgets = [budget for _solved, budget in trial_values if budget is not None]
    missing_budgets = len(trial_values) - len(budgets)
    distinct_budgets = sorted(set(budgets))
    budget_reason = _combine_reasons(
        (
            f"{missing_budgets} trial(s) lack a trustworthy fixed wall budget"
            if missing_budgets
            else None
        ),
        (
            f"recorded trial wall budgets differ across "
            f"{len(distinct_budgets)} values"
            if len(distinct_budgets) > 1
            else None
        ),
    )
    trial_reason = _combine_reasons(
        (
            f"{invalid_trials} state(s) lack valid trial metadata or "
            "canonical attempt activity"
            if invalid_trials
            else None
        ),
        (
            f"{duplicate_trials} duplicate case/attempt record(s) excluded"
            if duplicate_trials
            else None
        ),
        budget_reason,
    )
    metrics: dict[str, EvaluationMetric] = {}
    budget_value = {
        "comparable": (
            bool(trial_values)
            and not missing_budgets
            and len(distinct_budgets) == 1
        ),
        "recorded_trials": len(trial_values),
        "trials_with_budget": len(budgets),
        "missing_budget_trials": missing_budgets,
        "distinct_budget_seconds": distinct_budgets[:MAX_BREAKDOWN_ITEMS],
        "distinct_budget_count": len(distinct_budgets),
    }
    if not trial_values:
        metrics["fixed_budget_comparability"] = _unavailable(
            "no valid solve trial is recorded"
        )
    elif not budgets:
        metrics["fixed_budget_comparability"] = _unavailable(
            "no solve trial has a trustworthy fixed wall budget",
            evidence={
                "recorded_trials": len(trial_values),
                "budget_errors": budget_errors,
            },
        )
    elif missing_budgets:
        metrics["fixed_budget_comparability"] = _metric(
            budget_value,
            len(trial_values),
            partial_reason=budget_reason,
            evidence={"budget_errors": budget_errors},
        )
    else:
        metrics["fixed_budget_comparability"] = _metric(
            budget_value,
            len(trial_values),
        )

    attempt_one = [
        values[1][0] for values in trials.values() if 1 in values
    ]
    if attempt_one:
        solved = sum(attempt_one)
        metrics["solve@1"] = _metric(
            {
                "solved_cases": solved,
                "eligible_cases": len(attempt_one),
                "rate": _round(solved / len(attempt_one)),
            },
            len(attempt_one),
            partial_reason=trial_reason,
        )
    else:
        metrics["solve@1"] = _unavailable(
            "no valid attempt-1 canonical state"
        )

    complete_three = [
        values
        for values in trials.values()
        if all(attempt in values for attempt in (1, 2, 3))
    ]
    incomplete_three = len(trials) - len(complete_three)
    if complete_three:
        solved = sum(
            any(values[index][0] for index in (1, 2, 3))
            for values in complete_three
        )
        consistent = sum(
            all(values[index][0] for index in (1, 2, 3))
            for values in complete_three
        )
        incomplete_reason = (
            f"{incomplete_three} case(s) lack attempts 1, 2, and 3"
            if incomplete_three
            else None
        )
        combined = _combine_reasons(trial_reason, incomplete_reason)
        metrics["solve@3"] = _metric(
            {
                "solved_cases": solved,
                "eligible_cases": len(complete_three),
                "rate": _round(solved / len(complete_three)),
            },
            len(complete_three),
            partial_reason=combined,
        )
        metrics["consistency"] = _metric(
            {
                "three_of_three_cases": consistent,
                "eligible_cases": len(complete_three),
                "rate": _round(consistent / len(complete_three)),
            },
            len(complete_three),
            partial_reason=combined,
        )
    else:
        unavailable_reason = (
            "no evaluation case has canonical attempts 1, 2, and 3"
        )
        metrics["solve@3"] = _unavailable(
            unavailable_reason,
            evidence={"incomplete_cases": incomplete_three},
        )
        metrics["consistency"] = _unavailable(
            unavailable_reason,
            evidence={"incomplete_cases": incomplete_three},
        )
    return metrics, invalid_trials + duplicate_trials


def _proof_path_candidate(path: str) -> str | None:
    relative = Path(path)
    parts = relative.parts
    if (
        len(parts) == 4
        and parts[0] == "proof"
        and parts[1]
        and parts[2]
        and parts[3] == "result.json"
    ):
        return parts[1]
    return None


def _parse_proof_result(
    record: _LoadedState,
    artifact_id: str,
    candidate_id: str,
) -> _ProofObservation:
    artifact = next(
        item for item in record.state.artifacts if item.id == artifact_id
    )
    raw = _strict_json_bytes(
        _read_verified_artifact(
            record.root,
            artifact,
            maximum_bytes=MAX_PROOF_RESULT_BYTES,
        ),
        "proof result artifact",
    )
    if not isinstance(raw, Mapping) or set(raw) != _PROOF_RESULT_KEYS:
        raise EvaluationInputError("proof result has an unexpected schema")

    passed = raw.get("passed")
    candidate = raw.get("candidate")
    policy_mode = raw.get("policy_mode")
    successful = _nonnegative_integer(raw.get("successful_attempts"))
    required = _nonnegative_integer(raw.get("required_attempts"))
    total = _nonnegative_integer(raw.get("total_attempts"))
    source_hash = raw.get("source_manifest_sha256")
    failures = raw.get("failures")
    run_ids = raw.get("run_ids")
    expected_candidate = next(
        (
            item.value
            for item in record.state.candidates
            if item.id == candidate_id
        ),
        None,
    )
    if (
        not isinstance(passed, bool)
        or not isinstance(candidate, str)
        or candidate != expected_candidate
        or not isinstance(policy_mode, str)
        or not policy_mode
        or successful is None
        or required is None
        or total is None
        or successful > total
        or not isinstance(source_hash, str)
        or len(source_hash) != 64
        or any(character not in "0123456789abcdefABCDEF" for character in source_hash)
        or not isinstance(failures, list)
        or len(failures) > 1024
        or not all(
            isinstance(item, str) and len(item.encode("utf-8")) <= 4096
            for item in failures
        )
        or not isinstance(run_ids, list)
        or len(run_ids) > 1024
        or not all(
            isinstance(item, str)
            and item
            and len(item.encode("utf-8")) <= 255
            for item in run_ids
        )
        or len(run_ids) != total
    ):
        raise EvaluationInputError("proof result fields are invalid")
    return _ProofObservation(
        candidate_id=candidate_id,
        passed=passed,
        successful_attempts=successful,
        total_attempts=total,
        completed_at=artifact.created_at,
    )


def _proof_metrics(
    records: Sequence[_LoadedState],
    diagnostics: _Diagnostics,
) -> dict[str, EvaluationMetric]:
    observations: list[tuple[_LoadedState, _ProofObservation]] = []
    invalid = 0
    for record in records:
        for artifact in record.state.artifacts:
            candidate_id = _proof_path_candidate(artifact.path)
            if candidate_id is None:
                continue
            if not any(
                candidate.id == candidate_id
                for candidate in record.state.candidates
            ):
                invalid += 1
                diagnostics.add(
                    f"{record.state.identity.key}: proof artifact "
                    "references an unknown candidate"
                )
                continue
            try:
                observation = _parse_proof_result(
                    record, artifact.id, candidate_id
                )
            except (
                EvaluationInputError,
                OSError,
            ) as error:
                invalid += 1
                diagnostics.add(
                    f"{record.state.identity.key}: proof result "
                    f"{artifact.id} ignored: {error}"
                )
                continue
            observations.append((record, observation))

    metrics: dict[str, EvaluationMetric] = {}
    successful = sum(
        observation.successful_attempts
        for _record, observation in observations
    )
    total = sum(
        observation.total_attempts
        for _record, observation in observations
    )
    partial_reason = (
        f"{invalid} proof result artifact(s) were invalid"
        if invalid
        else None
    )
    if total:
        metrics["clean_reproduction_rate"] = _metric(
            {
                "successful_attempts": successful,
                "total_attempts": total,
                "rate": _round(successful / total),
                "proof_evaluations": len(observations),
            },
            total,
            partial_reason=partial_reason,
        )
    else:
        metrics["clean_reproduction_rate"] = _unavailable(
            _combine_reasons(
                "no valid proof result contains reproduction attempts",
                partial_reason,
            )
            or "no valid proof result contains reproduction attempts"
        )

    proof_times: list[float] = []
    missing_proof_times = 0
    for record, observation in observations:
        if not observation.passed:
            continue
        elapsed = _elapsed_seconds(
            record.state.created_at, observation.completed_at
        )
        if elapsed is None:
            missing_proof_times += 1
        else:
            proof_times.append(elapsed)
    time_reason = _combine_reasons(
        partial_reason,
        (
            f"{missing_proof_times} passed proof(s) lack a valid timestamp"
            if missing_proof_times
            else None
        ),
    )
    if proof_times:
        metrics["time_to_proof"] = _metric(
            _time_summary(proof_times),
            len(proof_times),
            partial_reason=time_reason,
        )
    else:
        metrics["time_to_proof"] = _unavailable(
            _combine_reasons(
                "no hash-validated passed proof has a usable timestamp",
                time_reason,
            )
            or "no hash-validated passed proof has a usable timestamp"
        )

    audited = 0
    false_proofs = 0
    for record in records:
        for submission in record.state.submissions:
            if not submission.proof_passed:
                continue
            if submission.status not in {
                SubmissionStatus.ACCEPTED,
                SubmissionStatus.REJECTED,
            }:
                continue
            audited += 1
            false_proofs += submission.status is SubmissionStatus.REJECTED
    if audited:
        metrics["false_proof_count"] = _metric(
            {
                "count": false_proofs,
                "audited_proof_submissions": audited,
            },
            audited,
        )
    else:
        metrics["false_proof_count"] = _unavailable(
            (
                "no proof-passed submission has a manual accepted/rejected "
                "outcome"
            )
        )
    return metrics


def _first_primitive_metric(
    records: Sequence[_LoadedState],
) -> EvaluationMetric:
    values: list[float] = []
    missing = 0
    states_with_markers = 0
    for record in records:
        state_values: list[float] = []
        if record.state.progress_markers:
            states_with_markers += 1
        for marker in record.state.progress_markers:
            if marker.elapsed_seconds is not None:
                if marker.elapsed_seconds >= 0:
                    state_values.append(float(marker.elapsed_seconds))
                else:
                    missing += 1
                continue
            elapsed = _elapsed_seconds(
                record.state.created_at, marker.created_at
            )
            if elapsed is None:
                missing += 1
            else:
                state_values.append(elapsed)
        if state_values:
            values.append(min(state_values))
    reason = (
        f"{missing} progress marker(s) lack a usable elapsed time"
        if missing
        else None
    )
    if not values:
        return _unavailable(
            _combine_reasons(
                "no canonical progress marker has a usable elapsed time",
                reason,
            )
            or "no canonical progress marker has a usable elapsed time",
            evidence={"states_with_progress_markers": states_with_markers},
        )
    return _metric(
        _time_summary(values),
        len(values),
        partial_reason=reason,
        evidence={"proxy": "first canonical progress marker"},
    )


def _repeated_command_metric(
    records: Sequence[_LoadedState],
) -> EvaluationMetric:
    executed = 0
    repeated = 0
    invalid = 0
    for record in records:
        counts: Counter[str] = Counter()
        for experiment in record.state.experiments:
            if experiment.status not in _EXECUTED_EXPERIMENT_STATUSES:
                continue
            command = experiment.command.strip()
            if (
                not command
                or "\x00" in command
                or len(command.encode("utf-8")) > MAX_COMMAND_BYTES
            ):
                invalid += 1
                continue
            counts[command] += 1
            executed += 1
        repeated += sum(max(0, count - 1) for count in counts.values())
    return _metric(
        {
            "count": repeated,
            "executed_commands": executed,
            "comparison": "exact command string within each challenge",
        },
        executed,
        partial_reason=(
            f"{invalid} executed command(s) were empty or oversized"
            if invalid
            else None
        ),
    )


def _stall_recovery_metric(
    records: Sequence[_LoadedState],
) -> EvaluationMetric:
    attempted = 0
    states_with_governor = 0
    for record in records:
        governor = record.state.metadata.get("stalled_governor")
        if not isinstance(governor, Mapping):
            continue
        states_with_governor += 1
        actions = governor.get("attempted_recovery_actions")
        if isinstance(actions, list):
            attempted += sum(
                isinstance(value, str) and bool(value.strip())
                for value in actions[:64]
            )
    return _unavailable(
        (
            "canonical state stores the latest stall decision and attempted "
            "actions, but not stall episode outcomes needed for a recovery rate"
        ),
        evidence={
            "states_with_governor_metadata": states_with_governor,
            "attempted_actions_recorded": attempted,
        },
    )


def _model_usage_metric(
    records: Sequence[_LoadedState],
) -> EvaluationMetric:
    totals = {field: 0 for field in _USAGE_FIELDS}
    model_runs = 0
    known = 0
    missing = 0
    for record in records:
        for run in record.state.runs:
            usage = run.extra.get("usage")
            is_model_run = run.model is not None or isinstance(usage, Mapping)
            if not is_model_run:
                continue
            model_runs += 1
            if not isinstance(usage, Mapping):
                missing += 1
                continue
            parsed = {
                field: _nonnegative_integer(usage.get(field))
                for field in _USAGE_FIELDS
            }
            if any(value is None for value in parsed.values()):
                missing += 1
                continue
            known += 1
            for field, value in parsed.items():
                totals[field] += int(value)
    reason = (
        f"{missing} model run(s) lack complete nonnegative usage"
        if missing
        else None
    )
    if not known:
        return _unavailable(
            _combine_reasons("no model run has complete usage", reason)
            or "no model run has complete usage",
            evidence={"model_runs": model_runs},
        )
    return _metric(
        {
            **totals,
            "runs_with_usage": known,
            "model_runs": model_runs,
        },
        known,
        partial_reason=reason,
    )


def _tool_wall_metric(
    records: Sequence[_LoadedState],
) -> EvaluationMetric:
    values: list[float] = []
    tool_runs = 0
    missing = 0
    for record in records:
        for run in record.state.runs:
            if run.role != "tool":
                continue
            tool_runs += 1
            wall = _finite_nonnegative(run.extra.get("wall_seconds"))
            if wall is None:
                missing += 1
            else:
                values.append(wall)
    reason = (
        f"{missing} tool run(s) lack finite nonnegative wall_seconds"
        if missing
        else None
    )
    if not values:
        return _unavailable(
            _combine_reasons("no tool run has wall_seconds", reason)
            or "no tool run has wall_seconds",
            evidence={"tool_runs": tool_runs},
        )
    return _metric(
        {
            "total_seconds": _round(sum(values)),
            "mean_seconds": _round(sum(values) / len(values)),
            "runs_with_wall": len(values),
            "tool_runs": tool_runs,
        },
        len(values),
        partial_reason=reason,
    )


def _refusal_metric(
    records: Sequence[_LoadedState],
) -> EvaluationMetric:
    labels: Counter[str] = Counter()
    other = 0
    for record in records:
        for refusal in record.state.budget.refusals:
            raw = refusal.get("kind")
            label = (
                raw.strip().casefold()
                if isinstance(raw, str)
                and raw.strip()
                and len(raw.encode("utf-8")) <= 256
                else "unknown"
            )
            if label in labels or len(labels) < MAX_BREAKDOWN_ITEMS:
                labels[label] += 1
            else:
                other += 1
    total = sum(labels.values()) + other
    return _metric(
        {
            "count": total,
            "by_kind": dict(sorted(labels.items())),
            "other_records": other,
        },
        total,
    )


def _invalid_contract_metric(
    records: Sequence[_LoadedState],
) -> EvaluationMetric:
    model_runs = 0
    invalid = 0
    for record in records:
        for run in record.state.runs:
            if run.model is None and not isinstance(
                run.extra.get("usage"), Mapping
            ):
                continue
            model_runs += 1
            contract_errors = run.extra.get("contract_errors")
            normalization_error = run.extra.get("normalization_error")
            failures = run.extra.get("failures")
            failure_kind = False
            if isinstance(failures, list):
                failure_kind = any(
                    isinstance(item, Mapping)
                    and item.get("kind")
                    in {
                        "invalid_contract",
                        "contract_validation",
                        "invalid_schema",
                    }
                    for item in failures[:128]
                )
            if (
                run.status is RunStatus.INVALID
                or (
                    isinstance(contract_errors, list)
                    and bool(contract_errors)
                )
                or (
                    isinstance(normalization_error, str)
                    and bool(normalization_error.strip())
                )
                or failure_kind
            ):
                invalid += 1
    return _metric(
        {"count": invalid, "model_runs": model_runs},
        model_runs,
    )


def _manual_points_metric(
    records: Sequence[_LoadedState],
) -> EvaluationMetric:
    accepted = 0
    scored = 0
    missing = 0
    total = 0.0
    for record in records:
        for submission in record.state.submissions:
            if submission.status is not SubmissionStatus.ACCEPTED:
                continue
            accepted += 1
            points = _finite_nonnegative(submission.points)
            if points is None:
                missing += 1
                continue
            scored += 1
            total += points
    reason = (
        f"{missing} accepted submission(s) have no valid manual points"
        if missing
        else None
    )
    return _metric(
        {
            "total": _round(total),
            "accepted_submissions": accepted,
            "scored_submissions": scored,
            "unscored_submissions": missing,
        },
        scored,
        partial_reason=reason,
    )


def _mark_incomplete(
    metrics: Mapping[str, EvaluationMetric],
    reason: str | None,
) -> dict[str, EvaluationMetric]:
    if reason is None:
        return dict(metrics)
    result: dict[str, EvaluationMetric] = {}
    for name, metric in metrics.items():
        if metric.status == _METRIC_UNAVAILABLE:
            result[name] = EvaluationMetric(
                status=metric.status,
                value=metric.value,
                sample_size=metric.sample_size,
                reason=_combine_reasons(metric.reason, reason),
                evidence=metric.evidence,
            )
        else:
            result[name] = EvaluationMetric(
                status=_METRIC_PARTIAL,
                value=metric.value,
                sample_size=metric.sample_size,
                reason=_combine_reasons(metric.reason, reason),
                evidence=metric.evidence,
            )
    return result


def _empty_metrics(reason: str) -> dict[str, EvaluationMetric]:
    names = (
        "solve@1",
        "solve@3",
        "consistency",
        "fixed_budget_comparability",
        "clean_reproduction_rate",
        "false_proof_count",
        "time_to_first_primitive",
        "time_to_proof",
        "repeated_command_count",
        "stall_recovery_rate",
        "model_usage",
        "tool_wall_time",
        "refusal_count",
        "invalid_contract_count",
        "manual_points",
    )
    return {name: _unavailable(reason) for name in names}


def _validate_scope_component(
    value: str | None,
    label: str,
) -> None:
    if value is None:
        return
    if (
        not isinstance(value, str)
        or not value
        or not value.strip()
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or len(value.encode("utf-8")) > 255
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise EvaluationError(f"{label} is not a safe bounded path component")


def evaluate_workspace(
    workspace_root: Path | str,
    *,
    contest_id: str | None = None,
    category: str | None = None,
    challenge_id: str | None = None,
    max_states: int = DEFAULT_MAX_STATES,
) -> EvaluationReport:
    """Aggregate canonical states under one workspace without mutating them."""

    if category is not None and contest_id is None:
        raise EvaluationError("category scope requires contest_id")
    if challenge_id is not None and category is None:
        raise EvaluationError("challenge_id scope requires category")
    _validate_scope_component(contest_id, "contest_id")
    _validate_scope_component(category, "category")
    _validate_scope_component(challenge_id, "challenge_id")
    if (
        isinstance(max_states, bool)
        or not isinstance(max_states, int)
        or not 1 <= max_states <= MAX_STATE_LIMIT
    ):
        raise EvaluationError(
            f"max_states must be between 1 and {MAX_STATE_LIMIT}"
        )

    workspace = Path(workspace_root).expanduser().resolve()
    paths = heapq.nsmallest(
        max_states + 1,
        _candidate_state_paths(
            workspace,
            contest_id=contest_id,
            category=category,
            challenge_id=challenge_id,
        ),
        key=lambda value: _state_sort_key(workspace, value),
    )
    truncated = len(paths) > max_states
    selected_paths = paths[:max_states]
    diagnostics = _Diagnostics()
    loaded: list[_LoadedState] = []
    for path in selected_paths:
        try:
            loaded.append(_load_state(path))
        except (
            EvaluationInputError,
            ModelValidationError,
            UnsupportedSchemaVersion,
            KeyError,
            TypeError,
            ValueError,
            OSError,
        ) as error:
            diagnostics.add(
                f"{_state_sort_key(workspace, path)} skipped: {error}"
            )

    scope = {
        "contest_id": contest_id,
        "category": category,
        "challenge_id": challenge_id,
    }
    skipped = len(selected_paths) - len(loaded)
    if not loaded:
        reason = (
            "no readable canonical state.json matched the requested scope"
        )
        return EvaluationReport(
            scope=scope,
            selected_states=len(selected_paths),
            evaluated_states=0,
            skipped_states=skipped,
            truncated=truncated,
            metrics=_empty_metrics(reason),
            diagnostics=diagnostics.values(),
        )

    solve_metrics, _invalid_trials = _solve_metrics(loaded)
    metrics = dict(solve_metrics)
    metrics.update(_proof_metrics(loaded, diagnostics))
    metrics["time_to_first_primitive"] = _first_primitive_metric(loaded)
    metrics["repeated_command_count"] = _repeated_command_metric(loaded)
    metrics["stall_recovery_rate"] = _stall_recovery_metric(loaded)
    metrics["model_usage"] = _model_usage_metric(loaded)
    metrics["tool_wall_time"] = _tool_wall_metric(loaded)
    metrics["refusal_count"] = _refusal_metric(loaded)
    metrics["invalid_contract_count"] = _invalid_contract_metric(loaded)
    metrics["manual_points"] = _manual_points_metric(loaded)

    incomplete_reason = _combine_reasons(
        (
            f"only the first {max_states} canonical states were evaluated"
            if truncated
            else None
        ),
        (
            f"{skipped} selected canonical state(s) were unreadable"
            if skipped
            else None
        ),
    )
    return EvaluationReport(
        scope=scope,
        selected_states=len(selected_paths),
        evaluated_states=len(loaded),
        skipped_states=skipped,
        truncated=truncated,
        metrics=_mark_incomplete(metrics, incomplete_reason),
        diagnostics=diagnostics.values(),
    )


__all__ = [
    "DEFAULT_MAX_STATES",
    "EVALUATION_SCHEMA_VERSION",
    "EvaluationError",
    "EvaluationInputError",
    "EvaluationMetric",
    "EvaluationReport",
    "evaluate_workspace",
]
