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
import re
import stat
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
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
from ctf_os.contracts.pwn_crash_v1 import (
    PWN_CRASH_V1_ATTEMPT_COUNT,
    PWN_CRASH_V1_CONTRACT_FINGERPRINT,
    PWN_CRASH_V1_CONTRACT_ID,
    PWN_CRASH_V1_CONTRACT_VERSION,
    PWN_CRASH_V1_MAX_DOCUMENT_BYTES,
    PWN_CRASH_V1_MAX_EVIDENCE_BYTES,
    PWN_CRASH_V1_MAX_INPUT_BYTES,
    PWN_CRASH_V1_PROTOCOL,
)
from ctf_os.engine.pwn_crash import (
    PWN_CRASH_INPUT_DESTINATION_LOCATOR,
    PWN_CRASH_NETWORK_POLICY,
    PWN_CRASH_ONE_SHOT,
    PWN_CRASH_PRODUCER_CAPABILITY_NAME,
    PWN_CRASH_PRODUCER_INTERPRETER_PATH,
    PWN_CRASH_PRODUCER_PATH,
    PWN_CRASH_SANDBOX_METHOD,
    PwnCrashCapabilityAttestation,
    PwnCrashGateEvaluation,
    PwnCrashReceiptMetadata,
    PwnCrashRecipe,
    evaluate_pwn_crash_gate,
)
from ctf_os.engine.pwn_ip_control import (
    PWN_IP_CONTROL_MAX_RESULT_BYTES,
    PwnIpControlResult,
    PwnIpControlStatus,
)
from ctf_os.engine.rev_proof import (
    REV_STDIN_PROOF_MAX_ACCEPTED_INPUT_BYTES,
    REV_STDIN_PROOF_MAX_EVIDENCE_BYTES,
    REV_STDIN_PROOF_PROTOCOL,
    verify_rev_proof_evaluation,
)
from ctf_os.director.resources import tool_profile
from ctf_os.schema import RUN_ENVELOPE_SCHEMA_VERSION
from ctf_os.store.atomic import canonical_json_bytes
from ctf_os.store.upgrades import UnsupportedSchemaVersion, upgrade_state

EVALUATION_SCHEMA_VERSION = 3
DEFAULT_MAX_STATES = 1024
MAX_STATE_LIMIT = 4096
MAX_STATE_BYTES = 16 * 1024 * 1024
MAX_PROOF_RESULT_BYTES = 64 * 1024
MAX_TYPED_PROOF_EVALUATION_BYTES = 8 * 1024 * 1024
MAX_DIAGNOSTICS = 128
MAX_DIAGNOSTIC_BYTES = 512
MAX_COMMAND_BYTES = 64 * 1024
MAX_METADATA_ID_BYTES = 256
MAX_BREAKDOWN_ITEMS = 64
MAX_COUNTER_VALUE = (1 << 63) - 1
MAX_PWN_CRASH_REQUEST_BYTES = 1024 * 1024
MAX_PWN_CRASH_CAPABILITY_BYTES = 16 * 1024
MAX_PWN_CRASH_STDERR_BYTES = (
    PWN_CRASH_V1_MAX_EVIDENCE_BYTES
    - (PWN_CRASH_V1_ATTEMPT_COUNT * PWN_CRASH_V1_MAX_DOCUMENT_BYTES)
) // PWN_CRASH_V1_ATTEMPT_COUNT

_METRIC_AVAILABLE = "available"
_METRIC_PARTIAL = "partial"
_METRIC_UNAVAILABLE = "unavailable"
_NO_EXECUTABLE_PRIMITIVE_GATE_REASON = (
    "no engine-owned executable primitive stage gate is recorded"
)
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
_PWN_CRASH_ENGINE_COMMAND = "ctfos-engine:pwn-crash-v1"
_PWN_CRASH_ENGINE_EXECUTOR = "pwn_crash_differential_v1"
_PWN_CRASH_ACTION_KIND = "verify_pwn_crash"
_PWN_IP_CONTROL_ENGINE_EXECUTOR = "pwn_ip_control_v1"
_PWN_IP_CONTROL_RESULT_KEY = "pwn_ip_control_evidence"
_CRYPTO_METAMORPHIC_PROTOCOL = (
    "crypto_solver_metamorphic_variant_v1"
)
_REV_PROOF_ENVELOPE_KEYS = {
    "schema_version",
    "protocol",
    "recipe_sha256",
    "policy_sha256",
    "candidate_id",
    "accepted_input_artifact_id",
    "source_manifest_sha256",
    "image_reference",
    "oracle_binding",
    "evaluation",
    "evaluation_sha256",
    "evaluation_artifact_id",
    "deadline_guard",
}
_REV_PROOF_DEADLINE_GUARD_KEYS = {
    "contract",
    "budget_deadline_utc",
    "attempt_deadlines_utc",
    "evaluated_at_utc",
    "commit_guard",
}
_PWN_CRASH_FLAG_PATTERNS_ENV = "CTF_WRAP_FLAG_PATTERNS_JSON"
_PWN_CRASH_EVIDENCE_KEYS = {
    "schema_version",
    "protocol",
    "recipe_sha256",
    "evaluated_at",
    "evaluation",
    "evaluation_sha256",
    "attempts",
}
_PWN_CRASH_ATTEMPT_KEYS = {
    "ordinal",
    "run_id",
    "receipt_id",
    "stdout_artifact_id",
}
_PWN_CRASH_RUN_RECORD_KEYS = {
    "recipe_sha256",
    "request_sha256",
    "execution_contract",
    "execution_contract_sha256",
    "ordinal",
    "phase",
    "input_sha256",
    "input_size_bytes",
    "receipt",
}
_PWN_CRASH_REQUEST_KEYS = {
    "base_revision",
    "category",
    "challenge_id",
    "contest_id",
    "created_at",
    "execution_contract",
    "execution_contract_sha256",
    "experiment_id",
    "kind",
    "run_id",
    "schema_version",
}
_PWN_CRASH_EXECUTION_CONTRACT_KEYS = {
    "schema_version",
    "contract",
    "protocol",
    "recipe_sha256",
    "configuration_epoch",
    "gate",
    "attempt",
    "input",
    "argv",
    "sandbox",
    "producer",
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
                "pass^2/3": (
                    "accepted in at least two of complete canonical attempts "
                    "1, 2, and 3"
                ),
                "clean_reproduction": (
                    "successful/total attempts from bounded, hash-validated "
                    "proof result artifacts"
                ),
                "pwn_crash_gate_pass_rate": (
                    "confirmed/terminal typed Pwn crash gates after bounded "
                    "nofollow re-reading of the nominated payload, six "
                    "stdout/stderr artifact pairs, capability attestation, "
                    "and six issued run requests; setup failures and "
                    "unverifiable terminal gates remain in the denominator"
                ),
                "first_valid_result": (
                    "earliest hash-validated passed proof or manual accepted "
                    "outcome per state"
                ),
                "first_claimed_progress": (
                    "earliest canonical progress marker per state; this is "
                    "model-claimed and is not an executable primitive proof"
                ),
                "first_verified_primitive": (
                    "earliest independently re-read, hash-validated, "
                    "engine-owned Pwn instruction-pointer-control result; "
                    "progress marker text and arbitrary extra fields are "
                    "never accepted as that gate"
                ),
                "human_interventions": (
                    "explicit state.metadata.human_intervention_count only"
                ),
                "live_hidden": (
                    "attempt-1 states explicitly labeled live, blind, or "
                    "hidden in metadata evaluation_split; differing or "
                    "missing fixed wall budgets make the result partial"
                ),
                "category_floor": (
                    "lowest canonical solve@1 rate among eligible categories; "
                    "fixed-budget or trial gaps make the result partial"
                ),
                "thin_scaffold_uplift": (
                    "within explicit evaluation_model and fixed-wall-budget "
                    "cohorts labeled by metadata evaluation_system"
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
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
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
    except RecursionError as error:
        raise EvaluationInputError(
            f"{display_name} exceeds JSON nesting limits"
        ) from error


def _read_strict_json(path: Path, maximum_bytes: int) -> object:
    return _strict_json_bytes(
        _read_bounded_regular(path, maximum_bytes),
        path.name,
    )


def _normalized_relative_parts(
    value: str,
    *,
    display_name: str,
) -> tuple[str, ...]:
    if not isinstance(value, str):
        raise EvaluationInputError(
            f"{display_name} path is not a normalized relative path"
        )
    try:
        encoded_value = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise EvaluationInputError(
            f"{display_name} path is not a normalized relative path"
        ) from error
    relative = PurePosixPath(value)
    if (
        not value
        or len(encoded_value) > 4096
        or relative.is_absolute()
        or PureWindowsPath(value).is_absolute()
        or "\\" in value
        or "\x00" in value
        or relative.as_posix() != value
        or not relative.parts
        or any(
            part in {"", ".", ".."}
            or len(part.encode("utf-8")) > 255
            for part in relative.parts
        )
    ):
        raise EvaluationInputError(
            f"{display_name} path is not a normalized relative path"
        )
    return relative.parts


def _read_bounded_relative(
    challenge_root: Path,
    relative_path: str,
    *,
    maximum_bytes: int,
    display_name: str,
) -> tuple[bytes, os.stat_result]:
    """Read one challenge-relative regular file without following symlinks."""

    parts = _normalized_relative_parts(
        relative_path,
        display_name=display_name,
    )
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptors: list[int] = []
    try:
        current = os.open(challenge_root, directory_flags)
        descriptors.append(current)
        for component in parts[:-1]:
            current = os.open(
                component,
                directory_flags,
                dir_fd=current,
            )
            descriptors.append(current)
        descriptor = os.open(
            parts[-1],
            file_flags,
            dir_fd=current,
        )
        descriptors.append(descriptor)
        return _read_bounded_descriptor(
            descriptor,
            display_name=display_name,
            maximum_bytes=maximum_bytes,
        )
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _read_verified_reference(
    challenge_root: Path,
    artifact: ArtifactReference,
    *,
    maximum_bytes: int,
    display_name: str,
    require_size: bool = True,
) -> bytes:
    if (
        len(artifact.sha256) != 64
        or any(
            character not in "0123456789abcdefABCDEF"
            for character in artifact.sha256
        )
    ):
        raise EvaluationInputError(
            f"{display_name} has an invalid SHA-256"
        )
    payload, metadata = _read_bounded_relative(
        challenge_root,
        artifact.path,
        maximum_bytes=maximum_bytes,
        display_name=display_name,
    )
    if (
        (require_size and artifact.size is None)
        or (
            artifact.size is not None
            and metadata.st_size != artifact.size
        )
    ):
        raise EvaluationInputError(
            f"{display_name} size does not match its canonical reference"
        )
    actual_sha256 = hashlib.sha256(payload).hexdigest()
    if actual_sha256.lower() != artifact.sha256.lower():
        raise EvaluationInputError(
            f"{display_name} SHA-256 does not match its canonical reference"
        )
    return payload


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
    return _read_verified_reference(
        challenge_root,
        artifact,
        maximum_bytes=maximum_bytes,
        display_name="proof result artifact",
        require_size=False,
    )


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


def _bounded_metadata_text(value: object) -> str | None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or "\x00" in value
        or len(value.encode("utf-8")) > MAX_METADATA_ID_BYTES
        or any(
            ord(character) < 0x20 or ord(character) == 0x7F
            for character in value
        )
    ):
        return None
    return value.strip()


def _unique_attempt_one_states(
    records: Sequence[_LoadedState],
) -> tuple[list[ChallengeState], int, int]:
    states: dict[str, ChallengeState] = {}
    duplicate_cases: set[str] = set()
    invalid = 0
    duplicates = 0
    for record in records:
        key = _trial_key(record.state)
        if key is None:
            invalid += 1
            continue
        case_id, attempt = key
        if attempt != 1:
            continue
        if case_id in duplicate_cases:
            duplicates += 1
            continue
        if case_id in states:
            duplicates += 1
            states.pop(case_id, None)
            duplicate_cases.add(case_id)
            continue
        states[case_id] = record.state
    return list(states.values()), invalid, duplicates


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
    trials: dict[
        str,
        dict[int, tuple[bool, float | None, str, ChallengeState]],
    ] = defaultdict(dict)
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
        trials[case_id][attempt] = (
            _accepted(record.state),
            budget,
            record.state.category,
            record.state,
        )

    trial_values = [
        value
        for attempts in trials.values()
        for attempt, value in attempts.items()
        if attempt <= 3
    ]
    budgets = [
        budget
        for _solved, budget, _category, _state in trial_values
        if budget is not None
    ]
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

    by_category: dict[str, list[bool]] = defaultdict(list)
    for attempts in trials.values():
        if 1 not in attempts:
            continue
        solved, _budget, category, _state = attempts[1]
        by_category[category].append(solved)
    if by_category:
        category_rates = {
            category: {
                "solved_cases": sum(values),
                "eligible_cases": len(values),
                "rate": _round(sum(values) / len(values)),
            }
            for category, values in sorted(by_category.items())
        }
        floor_rate = min(
            float(value["rate"]) for value in category_rates.values()
        )
        floor_categories = [
            category
            for category, value in category_rates.items()
            if value["rate"] == floor_rate
        ]
        breakdown_truncated = (
            len(category_rates) > MAX_BREAKDOWN_ITEMS
            or len(floor_categories) > MAX_BREAKDOWN_ITEMS
        )
        metrics["category_floor"] = _metric(
            {
                "floor_rate": floor_rate,
                "floor_categories": floor_categories[:MAX_BREAKDOWN_ITEMS],
                "eligible_categories": len(category_rates),
                "eligible_cases": sum(
                    len(values) for values in by_category.values()
                ),
                "by_category": dict(
                    list(category_rates.items())[:MAX_BREAKDOWN_ITEMS]
                ),
            },
            len(category_rates),
            partial_reason=_combine_reasons(
                trial_reason,
                (
                    "category breakdown exceeds the bounded output limit"
                    if breakdown_truncated
                    else None
                ),
            ),
        )
    else:
        metrics["category_floor"] = _unavailable(
            "no eligible category has a valid canonical attempt 1"
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
        two_of_three = sum(
            sum(values[index][0] for index in (1, 2, 3)) >= 2
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
        metrics["pass^2/3"] = _metric(
            {
                "two_of_three_cases": two_of_three,
                "eligible_cases": len(complete_three),
                "rate": _round(two_of_three / len(complete_three)),
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
        metrics["pass^2/3"] = _unavailable(
            unavailable_reason,
            evidence={"incomplete_cases": incomplete_three},
        )
    return metrics, invalid_trials + duplicate_trials


def _live_hidden_performance_metric(
    records: Sequence[_LoadedState],
) -> EvaluationMetric:
    attempt_one, invalid_trials, duplicate_trials = (
        _unique_attempt_one_states(records)
    )
    by_split: dict[str, list[bool]] = defaultdict(list)
    missing_split = 0
    invalid_split = 0
    other_split = 0
    budgets: list[float] = []
    missing_budget = 0
    allowed = {"live", "blind", "hidden"}
    for state in attempt_one:
        raw_split = state.metadata.get("evaluation_split")
        if raw_split is None:
            missing_split += 1
            continue
        split = _bounded_metadata_text(raw_split)
        if split is None:
            invalid_split += 1
            continue
        normalized = split.casefold()
        if normalized not in allowed:
            other_split += 1
            continue
        by_split[normalized].append(_accepted(state))
        budget, budget_error = _fixed_wall_budget_seconds(state)
        if budget is None or budget_error is not None:
            missing_budget += 1
        else:
            budgets.append(budget)

    eligible = sum(len(values) for values in by_split.values())
    if not eligible:
        return _unavailable(
            (
                "no valid canonical attempt 1 has an explicit "
                "evaluation_split of live, blind, or hidden"
            ),
            evidence={
                "attempt_one_states": len(attempt_one),
                "missing_split": missing_split,
                "invalid_split": invalid_split,
                "other_split": other_split,
                "invalid_trials": invalid_trials,
                "duplicate_trials": duplicate_trials,
                "missing_budget": missing_budget,
            },
        )
    solved = sum(sum(values) for values in by_split.values())
    breakdown = {
        split: {
            "solved_cases": sum(values),
            "eligible_cases": len(values),
            "rate": _round(sum(values) / len(values)),
        }
        for split, values in sorted(by_split.items())
    }
    reason = _combine_reasons(
        (
            f"{missing_split} attempt-1 state(s) lack evaluation_split"
            if missing_split
            else None
        ),
        (
            f"{invalid_split} attempt-1 state(s) have invalid "
            "evaluation_split metadata"
            if invalid_split
            else None
        ),
        (
            f"{invalid_trials} state(s) lack valid trial metadata or "
            "canonical attempt activity"
            if invalid_trials
            else None
        ),
        (
            f"{duplicate_trials} duplicate attempt-1 record(s) excluded"
            if duplicate_trials
            else None
        ),
        (
            f"{missing_budget} eligible state(s) lack a trustworthy fixed "
            "wall budget"
            if missing_budget
            else None
        ),
        (
            "eligible live/blind/hidden wall budgets differ across "
            f"{len(set(budgets))} values"
            if len(set(budgets)) > 1
            else None
        ),
    )
    return _metric(
        {
            "solved_cases": solved,
            "eligible_cases": eligible,
            "rate": _round(solved / eligible),
            "by_split": breakdown,
            "other_split_states": other_split,
            "distinct_budget_seconds": sorted(set(budgets))[
                :MAX_BREAKDOWN_ITEMS
            ],
        },
        eligible,
        partial_reason=reason,
    )


def _thin_scaffold_uplift_metric(
    records: Sequence[_LoadedState],
) -> EvaluationMetric:
    systems = {"thin_scaffold", "ctf_os"}
    observations: dict[
        tuple[str, str],
        tuple[str, float, bool],
    ] = {}
    duplicate_keys: set[tuple[str, str]] = set()
    missing_system = 0
    invalid_system = 0
    other_system = 0
    missing_model = 0
    missing_budget = 0
    invalid_trials = 0
    duplicate_trials = 0
    for record in records:
        state = record.state
        trial_key = _trial_key(state)
        if trial_key is None:
            invalid_trials += 1
            continue
        case_id, attempt = trial_key
        if attempt != 1:
            continue
        raw_system = state.metadata.get("evaluation_system")
        if raw_system is None:
            missing_system += 1
            continue
        system_text = _bounded_metadata_text(raw_system)
        if system_text is None:
            invalid_system += 1
            continue
        system = system_text.casefold()
        if system not in systems:
            other_system += 1
            continue
        model = _bounded_metadata_text(
            state.metadata.get("evaluation_model")
        )
        if model is None:
            missing_model += 1
            continue
        budget, budget_error = _fixed_wall_budget_seconds(state)
        if budget is None or budget_error is not None:
            missing_budget += 1
            continue
        key = (case_id, system)
        if key in duplicate_keys:
            duplicate_trials += 1
            continue
        if key in observations:
            duplicate_trials += 1
            observations.pop(key, None)
            duplicate_keys.add(key)
            continue
        observations[key] = (model, budget, _accepted(state))

    cohorts: dict[
        tuple[str, float],
        dict[str, dict[str, bool]],
    ] = defaultdict(lambda: defaultdict(dict))
    for (case_id, system), (model, budget, accepted) in observations.items():
        cohorts[(model, budget)][case_id][system] = accepted

    comparable: list[dict[str, object]] = []
    weighted_uplift = 0.0
    total_weight = 0
    excluded_unpaired = 0
    for (model, budget), cases in sorted(cohorts.items()):
        paired = [
            values
            for values in cases.values()
            if set(values) == systems
        ]
        unpaired = len(cases) - len(paired)
        excluded_unpaired += unpaired
        if not paired:
            continue
        baseline = [
            values["thin_scaffold"] for values in paired
        ]
        treatment = [values["ctf_os"] for values in paired]
        baseline_rate = sum(baseline) / len(baseline)
        treatment_rate = sum(treatment) / len(treatment)
        uplift = treatment_rate - baseline_rate
        weight = len(paired)
        weighted_uplift += uplift * weight
        total_weight += weight
        comparable.append(
            {
                "model": model,
                "budget_seconds": budget,
                "thin_scaffold": {
                    "solved_cases": sum(baseline),
                    "eligible_cases": len(baseline),
                    "rate": _round(baseline_rate),
                },
                "ctf_os": {
                    "solved_cases": sum(treatment),
                    "eligible_cases": len(treatment),
                    "rate": _round(treatment_rate),
                },
                "rate_delta": _round(uplift),
                "paired_cases": weight,
                "excluded_unpaired_cases": unpaired,
            }
        )

    if not comparable:
        return _unavailable(
            (
                "no cohort contains both thin_scaffold and ctf_os attempt-1 "
                "records with the same explicit evaluation_model and fixed "
                "wall budget"
            ),
            evidence={
                "candidate_records": len(observations),
                "missing_system": missing_system,
                "invalid_system": invalid_system,
                "other_system": other_system,
                "missing_model": missing_model,
                "missing_budget": missing_budget,
                "invalid_trials": invalid_trials,
                "duplicate_trials": duplicate_trials,
                "excluded_unpaired_cases": excluded_unpaired,
            },
        )

    omitted = max(0, len(comparable) - MAX_BREAKDOWN_ITEMS)
    reason = _combine_reasons(
        (
            f"{missing_system} attempt-1 state(s) lack evaluation_system"
            if missing_system
            else None
        ),
        (
            f"{invalid_system} attempt-1 state(s) have invalid "
            "evaluation_system metadata"
            if invalid_system
            else None
        ),
        (
            f"{missing_model} selected state(s) lack a valid explicit "
            "evaluation_model"
            if missing_model
            else None
        ),
        (
            f"{missing_budget} selected state(s) lack a trustworthy fixed "
            "wall budget"
            if missing_budget
            else None
        ),
        (
            f"{invalid_trials} state(s) lack valid trial metadata or "
            "canonical attempt activity"
            if invalid_trials
            else None
        ),
        (
            f"{duplicate_trials} duplicate system trial(s) excluded"
            if duplicate_trials
            else None
        ),
        (
            f"{excluded_unpaired} unpaired cohort case(s) excluded"
            if excluded_unpaired
            else None
        ),
        (
            f"{omitted} comparable cohort(s) omitted from bounded breakdown"
            if omitted
            else None
        ),
    )
    return _metric(
        {
            "rate_delta": _round(weighted_uplift / total_weight),
            "comparable_cohorts": len(comparable),
            "paired_cases": total_weight,
            "excluded_unpaired_cases": excluded_unpaired,
            "cohorts": comparable[:MAX_BREAKDOWN_ITEMS],
        },
        total_weight,
        partial_reason=reason,
        evidence={
            "aggregation": "paired-case weighting within model/budget cohort"
        },
    )


def _human_intervention_metric(
    records: Sequence[_LoadedState],
) -> EvaluationMetric:
    total = 0
    known = 0
    missing = 0
    invalid = 0
    for record in records:
        raw = record.state.metadata.get("human_intervention_count")
        if raw is None:
            missing += 1
            continue
        value = _nonnegative_integer(raw)
        if value is None:
            invalid += 1
            continue
        total += value
        known += 1
    if not known:
        return _unavailable(
            (
                "no state has explicit nonnegative canonical metadata "
                "human_intervention_count"
            ),
            evidence={
                "missing_states": missing,
                "invalid_states": invalid,
            },
        )
    return _metric(
        {
            "count": total,
            "states_with_count": known,
            "missing_states": missing,
            "invalid_states": invalid,
        },
        known,
        partial_reason=_combine_reasons(
            (
                f"{missing} state(s) lack human_intervention_count metadata"
                if missing
                else None
            ),
            (
                f"{invalid} state(s) have invalid "
                "human_intervention_count metadata"
                if invalid
                else None
            ),
        ),
        evidence={
            "source": "state.metadata.human_intervention_count",
            "submissions_counted": False,
        },
    )


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
        or len(policy_mode.encode("utf-8")) > MAX_METADATA_ID_BYTES
        or successful is None
        or required is None
        or total is None
        or successful > total
        or (passed and successful < required)
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


def _parse_crypto_metamorphic_result(
    record: _LoadedState,
    candidate_id: str,
) -> _ProofObservation:
    candidate = next(
        item
        for item in record.state.candidates
        if item.id == candidate_id
    )
    binding = candidate.extra.get("crypto_metamorphic_proof")
    if type(binding) is not dict:
        raise EvaluationInputError(
            "Crypto metamorphic proof binding is not an object"
        )
    expected_binding_keys = {
        "artifact_id",
        "evaluation",
        "evaluation_sha256",
        "oracle_authority",
        "passed",
        "plan_sha256",
        "proof_result",
        "protocol",
        "run_ids",
    }
    if (
        set(binding) != expected_binding_keys
        or binding.get("protocol") != _CRYPTO_METAMORPHIC_PROTOCOL
        or binding.get("oracle_authority")
        != "explicit_operator_input"
    ):
        raise EvaluationInputError(
            "Crypto metamorphic proof binding is not exact"
        )
    artifact_id = binding.get("artifact_id")
    artifact = next(
        (
            item
            for item in record.state.artifacts
            if item.id == artifact_id
        ),
        None,
    )
    if artifact is None:
        raise EvaluationInputError(
            "Crypto metamorphic evaluation artifact is absent"
        )
    payload = _read_verified_reference(
        record.root,
        artifact,
        maximum_bytes=MAX_TYPED_PROOF_EVALUATION_BYTES,
        display_name="Crypto metamorphic evaluation artifact",
    )
    raw_evaluation = _strict_json_bytes(
        payload,
        "Crypto metamorphic evaluation artifact",
    )
    if (
        raw_evaluation != binding.get("evaluation")
        or payload != canonical_json_bytes(raw_evaluation)
    ):
        raise EvaluationInputError(
            "Crypto metamorphic evaluation bytes are not canonical"
        )
    try:
        semantic_bytes = (
            json.dumps(
                raw_evaluation,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, UnicodeError, ValueError) as error:
        raise EvaluationInputError(
            "Crypto metamorphic evaluation is not commit-safe"
        ) from error
    evaluation_sha256 = hashlib.sha256(semantic_bytes).hexdigest()
    if (
        binding.get("evaluation_sha256") != evaluation_sha256
        or artifact.extra.get("kind")
        != "crypto_metamorphic_evaluation"
        or artifact.extra.get("protocol")
        != _CRYPTO_METAMORPHIC_PROTOCOL
        or artifact.extra.get("candidate_id") != candidate_id
        or artifact.extra.get("evaluation_sha256")
        != evaluation_sha256
    ):
        raise EvaluationInputError(
            "Crypto metamorphic evaluation commitment is inconsistent"
        )

    proof = binding.get("proof_result")
    if type(proof) is not dict or set(proof) != _PROOF_RESULT_KEYS:
        raise EvaluationInputError(
            "Crypto metamorphic ProofResult schema is invalid"
        )
    passed = proof.get("passed")
    successful = _nonnegative_integer(
        proof.get("successful_attempts")
    )
    required = _nonnegative_integer(proof.get("required_attempts"))
    total = _nonnegative_integer(proof.get("total_attempts"))
    failures = proof.get("failures")
    run_ids = proof.get("run_ids")
    if (
        type(passed) is not bool
        or passed is not binding.get("passed")
        or proof.get("candidate") != candidate.value
        or proof.get("policy_mode") != _CRYPTO_METAMORPHIC_PROTOCOL
        or proof.get("source_manifest_sha256")
        != record.state.metadata.get("source_manifest_sha256")
        or successful is None
        or required is None
        or total is None
        or successful > total
        or (passed and successful < required)
        or type(failures) is not list
        or not all(
            type(value) is str
            and len(value.encode("utf-8")) <= 4096
            for value in failures
        )
        or type(run_ids) is not list
        or run_ids != binding.get("run_ids")
        or len(run_ids) != total
        or not all(
            type(value) is str
            and value
            and len(value.encode("utf-8")) <= 255
            for value in run_ids
        )
    ):
        raise EvaluationInputError(
            "Crypto metamorphic ProofResult fields are invalid"
        )
    return _ProofObservation(
        candidate_id=candidate_id,
        passed=passed,
        successful_attempts=successful,
        total_attempts=total,
        completed_at=artifact.created_at,
    )


def _parse_rev_stdin_result(
    record: _LoadedState,
    experiment: object,
) -> _ProofObservation:
    result = getattr(experiment, "result", None)
    recipe = getattr(experiment, "proof_recipe", None)
    if (
        type(result) is not dict
        or set(result) != {"proof_result", "rev_proof_evidence"}
        or recipe is None
    ):
        raise EvaluationInputError(
            "Rev stdin proof result schema is not exact"
        )
    envelope = result["rev_proof_evidence"]
    if (
        type(envelope) is not dict
        or set(envelope) != _REV_PROOF_ENVELOPE_KEYS
        or envelope.get("schema_version") != 1
        or envelope.get("protocol") != REV_STDIN_PROOF_PROTOCOL
        or len(recipe.inputs) != 1
        or recipe.policy.oracle_protocol != REV_STDIN_PROOF_PROTOCOL
        or envelope.get("recipe_sha256") != recipe.recipe_sha256
        or envelope.get("policy_sha256")
        != recipe.policy.policy_sha256
        or envelope.get("candidate_id") != recipe.candidate_id
        or envelope.get("accepted_input_artifact_id")
        != recipe.inputs[0].artifact_id
        or envelope.get("source_manifest_sha256")
        != recipe.source_manifest_sha256
        or envelope.get("image_reference") != recipe.image_reference
        or envelope.get("oracle_binding")
        != (
            recipe.oracle_binding.to_dict()
            if recipe.oracle_binding is not None
            else None
        )
    ):
        raise EvaluationInputError(
            "Rev stdin proof envelope pins are inconsistent"
        )

    candidate = next(
        (
            item
            for item in record.state.candidates
            if item.id == recipe.candidate_id
        ),
        None,
    )
    accepted_artifact = next(
        (
            item
            for item in record.state.artifacts
            if item.id == envelope["accepted_input_artifact_id"]
        ),
        None,
    )
    evaluation_artifact = next(
        (
            item
            for item in record.state.artifacts
            if item.id == envelope["evaluation_artifact_id"]
        ),
        None,
    )
    if (
        candidate is None
        or accepted_artifact is None
        or evaluation_artifact is None
    ):
        raise EvaluationInputError(
            "Rev stdin proof artifact or candidate binding is absent"
        )

    accepted_input = _read_verified_reference(
        record.root,
        accepted_artifact,
        maximum_bytes=REV_STDIN_PROOF_MAX_ACCEPTED_INPUT_BYTES,
        display_name="Rev accepted input artifact",
    )
    evaluation_payload = _read_verified_reference(
        record.root,
        evaluation_artifact,
        maximum_bytes=REV_STDIN_PROOF_MAX_EVIDENCE_BYTES,
        display_name="Rev proof evaluation artifact",
    )
    raw_evaluation = _strict_json_bytes(
        evaluation_payload,
        "Rev proof evaluation artifact",
    )
    try:
        evaluation = verify_rev_proof_evaluation(
            raw_evaluation,
            accepted_input=accepted_input,
        )
    except (TypeError, ValueError) as error:
        raise EvaluationInputError(
            "Rev proof evaluation semantic replay failed"
        ) from error
    if (
        raw_evaluation != envelope.get("evaluation")
        or evaluation_payload != evaluation.canonical_bytes()
        or envelope.get("evaluation_sha256")
        != evaluation.evidence_sha256
        or evaluation_artifact.sha256
        != evaluation.evidence_sha256
        or evaluation_artifact.extra
        != {
            "kind": "rev_proof_evaluation",
            "experiment_id": getattr(experiment, "id", None),
            "candidate_id": recipe.candidate_id,
            "recipe_sha256": recipe.recipe_sha256,
            "policy_sha256": recipe.policy.policy_sha256,
            "protocol": REV_STDIN_PROOF_PROTOCOL,
        }
        or accepted_artifact.sha256 != recipe.inputs[0].sha256
        or accepted_artifact.size != recipe.inputs[0].size
        or evaluation.candidate != candidate.value
        or evaluation.source_manifest_sha256
        != recipe.source_manifest_sha256
        or evaluation.accepted_input_sha256
        != recipe.inputs[0].sha256
        or evaluation.accepted_input_size_bytes
        != recipe.inputs[0].size
        or len(evaluation.plan) != 6
        or len(evaluation.observations) != 6
    ):
        raise EvaluationInputError(
            "Rev proof evaluation commitment is inconsistent"
        )

    proof_result = result["proof_result"]
    expected_proof_result = {
        "passed": evaluation.passed,
        "candidate": evaluation.candidate,
        "policy_mode": REV_STDIN_PROOF_PROTOCOL,
        "successful_attempts": evaluation.positive_successes,
        "required_attempts": 3,
        "total_attempts": len(evaluation.observations),
        "source_manifest_sha256": evaluation.source_manifest_sha256,
        "failures": [
            failure.token() for failure in evaluation.failures
        ],
        "run_ids": [
            observation.run_id
            for observation in evaluation.observations
        ],
    }
    deadline_guard = envelope.get("deadline_guard")
    completed_at = getattr(experiment, "evaluated_at", None)
    if (
        proof_result != expected_proof_result
        or type(deadline_guard) is not dict
        or set(deadline_guard) != _REV_PROOF_DEADLINE_GUARD_KEYS
        or deadline_guard.get("contract")
        != "ctfos_rev_proof_deadline_guard_v1"
        or deadline_guard.get("commit_guard")
        != "state_store_pre_replace_v1"
        or deadline_guard.get("evaluated_at_utc") != completed_at
        or type(completed_at) is not str
        or not completed_at
    ):
        raise EvaluationInputError(
            "Rev proof result or completion guard is inconsistent"
        )
    return _ProofObservation(
        candidate_id=recipe.candidate_id,
        passed=evaluation.passed,
        successful_attempts=evaluation.positive_successes,
        total_attempts=len(evaluation.observations),
        completed_at=completed_at,
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
        for candidate in record.state.candidates:
            if "crypto_metamorphic_proof" not in candidate.extra:
                continue
            try:
                observation = _parse_crypto_metamorphic_result(
                    record,
                    candidate.id,
                )
            except (
                EvaluationInputError,
                OSError,
            ) as error:
                invalid += 1
                diagnostics.add(
                    f"{record.state.identity.key}: Crypto metamorphic "
                    f"proof {candidate.id} ignored: {error}"
                )
                continue
            observations.append((record, observation))
        for experiment in record.state.experiments:
            result = experiment.result
            if (
                type(result) is not dict
                or "rev_proof_evidence" not in result
            ):
                continue
            try:
                observation = _parse_rev_stdin_result(
                    record,
                    experiment,
                )
            except (
                EvaluationInputError,
                OSError,
            ) as error:
                invalid += 1
                diagnostics.add(
                    f"{record.state.identity.key}: Rev stdin proof "
                    f"{experiment.id} ignored: {error}"
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

    passed_evaluations = sum(
        observation.passed for _record, observation in observations
    )
    proof_budgets: list[float] = []
    missing_proof_budgets = 0
    for record, _observation in observations:
        budget, budget_error = _fixed_wall_budget_seconds(record.state)
        if budget is None or budget_error is not None:
            missing_proof_budgets += 1
        else:
            proof_budgets.append(budget)
    proof_budget_values = sorted(set(proof_budgets))
    proof_budget_reason = _combine_reasons(
        (
            f"{missing_proof_budgets} proof evaluation(s) lack a trustworthy "
            "fixed wall budget"
            if missing_proof_budgets
            else None
        ),
        (
            "proof evaluation wall budgets differ across "
            f"{len(proof_budget_values)} values"
            if len(proof_budget_values) > 1
            else None
        ),
    )
    if observations:
        metrics["proof_pass_rate"] = _metric(
            {
                "passed_evaluations": passed_evaluations,
                "proof_evaluations": len(observations),
                "rate": _round(
                    passed_evaluations / len(observations)
                ),
                "distinct_budget_seconds": proof_budget_values[
                    :MAX_BREAKDOWN_ITEMS
                ],
                "missing_budget_evaluations": missing_proof_budgets,
            },
            len(observations),
            partial_reason=_combine_reasons(
                partial_reason,
                proof_budget_reason,
            ),
        )
    else:
        metrics["proof_pass_rate"] = _unavailable(
            _combine_reasons(
                "no hash-validated proof evaluation is recorded",
                partial_reason,
            )
            or "no hash-validated proof evaluation is recorded"
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

    proof_by_state: dict[str, list[_ProofObservation]] = defaultdict(list)
    for record, observation in observations:
        if observation.passed:
            proof_by_state[record.state.identity.key].append(observation)
    first_valid_times: list[float] = []
    proof_first = 0
    manual_first = 0
    tied_first = 0
    missing_valid_timestamps = 0
    states_with_valid_outcome = 0
    first_valid_budgets: list[float] = []
    missing_first_valid_budgets = 0
    for record in records:
        state = record.state
        timed_results: list[tuple[float, str]] = []
        valid_outcomes = 0
        for observation in proof_by_state.get(state.identity.key, []):
            valid_outcomes += 1
            elapsed = _elapsed_seconds(
                state.created_at,
                observation.completed_at,
            )
            if elapsed is None:
                missing_valid_timestamps += 1
            else:
                timed_results.append((elapsed, "proof"))
        for submission in state.submissions:
            if submission.status is not SubmissionStatus.ACCEPTED:
                continue
            valid_outcomes += 1
            elapsed = _elapsed_seconds(
                state.created_at,
                submission.submitted_at,
            )
            if elapsed is None:
                missing_valid_timestamps += 1
            else:
                timed_results.append((elapsed, "manual"))
        if valid_outcomes:
            states_with_valid_outcome += 1
            budget, budget_error = _fixed_wall_budget_seconds(state)
            if budget is None or budget_error is not None:
                missing_first_valid_budgets += 1
            else:
                first_valid_budgets.append(budget)
        if not timed_results:
            continue
        first_elapsed = min(value for value, _source in timed_results)
        first_sources = {
            source
            for value, source in timed_results
            if value == first_elapsed
        }
        first_valid_times.append(first_elapsed)
        if first_sources == {"proof"}:
            proof_first += 1
        elif first_sources == {"manual"}:
            manual_first += 1
        else:
            tied_first += 1
    first_valid_budget_values = sorted(set(first_valid_budgets))
    first_valid_reason = _combine_reasons(
        partial_reason,
        (
            f"{missing_valid_timestamps} valid result(s) lack a usable "
            "canonical timestamp"
            if missing_valid_timestamps
            else None
        ),
        (
            f"{missing_first_valid_budgets} state(s) with a valid outcome "
            "lack a trustworthy fixed wall budget"
            if missing_first_valid_budgets
            else None
        ),
        (
            "valid-result wall budgets differ across "
            f"{len(first_valid_budget_values)} values"
            if len(first_valid_budget_values) > 1
            else None
        ),
    )
    if first_valid_times:
        metrics["median_time_to_first_valid_result"] = _metric(
            {
                **_time_summary(first_valid_times),
                "states_with_valid_outcome": states_with_valid_outcome,
                "proof_first_states": proof_first,
                "manual_first_states": manual_first,
                "tied_first_states": tied_first,
                "distinct_budget_seconds": first_valid_budget_values[
                    :MAX_BREAKDOWN_ITEMS
                ],
                "missing_budget_states": missing_first_valid_budgets,
            },
            len(first_valid_times),
            partial_reason=first_valid_reason,
            evidence={
                "valid_sources": (
                    "hash-validated passed proof or manual accepted outcome"
                )
            },
        )
    else:
        metrics["median_time_to_first_valid_result"] = _unavailable(
            _combine_reasons(
                "no state has a valid result with a usable timestamp",
                first_valid_reason,
            )
            or "no state has a valid result with a usable timestamp",
            evidence={
                "states_with_valid_outcome": states_with_valid_outcome
            },
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


def _pwn_crash_experiment_marker(experiment: object) -> bool:
    command = getattr(experiment, "command", None)
    extra = getattr(experiment, "extra", None)
    result = getattr(experiment, "result", None)
    return (
        command == _PWN_CRASH_ENGINE_COMMAND
        or (
            isinstance(extra, Mapping)
            and (
                extra.get("engine_executor")
                == _PWN_CRASH_ENGINE_EXECUTOR
                or extra.get("managed_action_kind")
                == _PWN_CRASH_ACTION_KIND
                or "pwn_crash_request" in extra
                or "pwn_crash_recipe" in extra
            )
        )
        or (
            isinstance(result, Mapping)
            and "pwn_crash_evidence" in result
        )
    )


def _pwn_crash_canonical_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeEncodeError, ValueError) as error:
        raise EvaluationInputError(
            "Pwn crash execution contract is not canonical JSON"
        ) from error


def _pwn_crash_execution_contract_error(
    contract: object,
    *,
    recipe: PwnCrashRecipe,
    ordinal: int,
    capability_artifact: ArtifactReference,
    experiment_timeout_seconds: int,
    experiment_resource_class: str,
) -> str | None:
    """Return why one issued execution contract is not engine-owned."""

    binding = recipe.attempt_input_binding(ordinal)
    if type(contract) is not dict or set(contract) != (
        _PWN_CRASH_EXECUTION_CONTRACT_KEYS
    ):
        return "execution contract schema is not exact"
    expected_contract = {
        "fingerprint": PWN_CRASH_V1_CONTRACT_FINGERPRINT,
        "id": PWN_CRASH_V1_CONTRACT_ID,
        "version": PWN_CRASH_V1_CONTRACT_VERSION,
    }
    expected_attempt = {
        "ordinal": ordinal,
        "phase": binding["phase"],
    }
    expected_input = {
        "kind": binding["input_kind"],
        "artifact_id": (
            recipe.payload_artifact_id
            if binding["phase"] == "positive"
            else None
        ),
        "sha256": binding["input_sha256"],
        "size_bytes": binding["input_size_bytes"],
        "destination_locator": PWN_CRASH_INPUT_DESTINATION_LOCATOR,
    }
    gate = contract.get("gate")
    sandbox = contract.get("sandbox")
    environment = (
        sandbox.get("environment")
        if type(sandbox) is dict
        else None
    )
    patterns_json = (
        environment.get(_PWN_CRASH_FLAG_PATTERNS_ENV)
        if type(environment) is dict
        else None
    )
    producer = contract.get("producer")
    resource_request = (
        sandbox.get("resource_request")
        if type(sandbox) is dict
        else None
    )
    if (
        contract.get("schema_version") != 1
        or contract.get("contract") != expected_contract
        or contract.get("protocol") != PWN_CRASH_V1_PROTOCOL
        or contract.get("recipe_sha256") != recipe.recipe_sha256
        or contract.get("configuration_epoch")
        != recipe.configuration_epoch
        or contract.get("attempt") != expected_attempt
        or contract.get("input") != expected_input
        or contract.get("argv") != list(recipe.argv_for_attempt(ordinal))
    ):
        return "execution contract does not match its recipe"
    gate_deadline = (
        gate.get("deadline_epoch_seconds")
        if type(gate) is dict
        else None
    )
    if (
        type(gate) is not dict
        or set(gate)
        != {"timeout_seconds", "deadline_epoch_seconds"}
        or gate.get("timeout_seconds") != experiment_timeout_seconds
        or type(gate_deadline) not in {int, float}
        or not math.isfinite(float(gate_deadline))
        or float(gate_deadline) <= 0
    ):
        return "execution contract gate deadline is invalid"
    try:
        patterns = (
            json.loads(patterns_json)
            if type(patterns_json) is str
            and len(patterns_json.encode("utf-8")) <= 64 * 1024
            else None
        )
        patterns_valid = (
            type(patterns) is list
            and 1 <= len(patterns) <= 64
            and all(
                type(pattern) is str
                and 1 <= len(pattern.encode("utf-8")) <= 4096
                for pattern in patterns
            )
            and json.dumps(
                patterns,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            == patterns_json
        )
        if patterns_valid:
            for pattern in patterns:
                re.compile(pattern)
    except (RecursionError, TypeError, UnicodeError, ValueError, re.error):
        patterns_valid = False
    try:
        expected_resource_request = tool_profile(
            experiment_resource_class,
            needs_kvm=False,
            network=False,
        ).as_dict()
    except (TypeError, ValueError):
        return "execution contract resource class is invalid"
    if (
        type(sandbox) is not dict
        or set(sandbox)
        != {
            "method",
            "one_shot",
            "outer_timeout_seconds",
            "environment",
            "resource_request",
            "image",
            "network",
            "network_target",
        }
        or sandbox.get("method") != PWN_CRASH_SANDBOX_METHOD
        or sandbox.get("one_shot") is not PWN_CRASH_ONE_SHOT
        or type(sandbox.get("outer_timeout_seconds")) is not int
        or not 1
        <= sandbox["outer_timeout_seconds"]
        <= min(10, experiment_timeout_seconds)
        or type(environment) is not dict
        or set(environment) != {_PWN_CRASH_FLAG_PATTERNS_ENV}
        or not patterns_valid
        or sandbox.get("image")
        != {
            "reference": recipe.image_reference,
            "digest": recipe.image_digest,
        }
        or sandbox.get("network") != PWN_CRASH_NETWORK_POLICY
        or sandbox.get("network_target") is not None
        or resource_request != expected_resource_request
    ):
        return "execution contract sandbox boundary is not exact"
    if (
        type(producer) is not dict
        or producer
        != {
            "interpreter_path": PWN_CRASH_PRODUCER_INTERPRETER_PATH,
            "path": PWN_CRASH_PRODUCER_PATH,
            "capability_name": PWN_CRASH_PRODUCER_CAPABILITY_NAME,
            "file_sha256": recipe.producer_file_sha256,
            "capability_attestation_artifact_id": (
                capability_artifact.id
            ),
            "capability_attestation_sha256": (
                capability_artifact.sha256
            ),
        }
    ):
        return "execution contract producer binding is not exact"
    return None


def _revalidate_pwn_crash_gate(
    record: _LoadedState,
    experiment: object,
) -> PwnCrashGateEvaluation:
    """Rebuild one terminal Pwn gate from independently read durable bytes."""

    state = record.state
    extra = getattr(experiment, "extra", None)
    result = getattr(experiment, "result", None)
    experiment_id = getattr(experiment, "id", None)
    if (
        type(extra) is not dict
        or type(result) is not dict
        or set(result) != {"pwn_crash_evidence"}
        or type(experiment_id) is not str
    ):
        raise EvaluationInputError(
            "terminal Pwn crash result does not have an exact envelope"
        )
    try:
        recipe = PwnCrashRecipe.from_dict(extra["pwn_crash_recipe"])
    except (KeyError, TypeError, ValueError) as error:
        raise EvaluationInputError(
            "terminal Pwn crash recipe is invalid"
        ) from error
    if recipe.experiment_id != experiment_id:
        raise EvaluationInputError(
            "Pwn crash recipe references a different experiment"
        )

    artifacts = {item.id: item for item in state.artifacts}
    runs = {item.id: item for item in state.runs}
    receipts = {item.id: item for item in state.receipts}
    payload_artifact = artifacts.get(recipe.payload_artifact_id)
    payload_source_run = runs.get(recipe.payload_source_run_id)
    if (
        payload_artifact is None
        or payload_source_run is None
        or payload_artifact.source_run_id != payload_source_run.id
        or payload_artifact.path != recipe.payload_artifact_locator
        or payload_artifact.sha256 != recipe.payload_sha256
        or payload_artifact.size != recipe.payload_size_bytes
    ):
        raise EvaluationInputError(
            "Pwn crash payload source-run binding is inconsistent"
        )
    payload = _read_verified_reference(
        record.root,
        payload_artifact,
        maximum_bytes=PWN_CRASH_V1_MAX_INPUT_BYTES,
        display_name="Pwn crash nominated payload",
    )
    try:
        recipe.validate_payload(payload)
    except (TypeError, ValueError) as error:
        raise EvaluationInputError(
            "Pwn crash nominated payload does not match its recipe"
        ) from error

    evidence = result["pwn_crash_evidence"]
    if type(evidence) is not dict or set(evidence) != _PWN_CRASH_EVIDENCE_KEYS:
        raise EvaluationInputError(
            "Pwn crash evidence envelope schema is not exact"
        )
    attempts = evidence.get("attempts")
    if (
        evidence.get("schema_version") != 1
        or evidence.get("protocol") != PWN_CRASH_V1_PROTOCOL
        or evidence.get("recipe_sha256") != recipe.recipe_sha256
        or type(attempts) is not list
        or len(attempts) != PWN_CRASH_V1_ATTEMPT_COUNT
    ):
        raise EvaluationInputError(
            "Pwn crash evidence envelope values are invalid"
        )

    stdout_payloads: list[bytes] = []
    receipt_metadata: list[PwnCrashReceiptMetadata] = []
    capability_artifact: ArtifactReference | None = None
    shared_gate_binding: dict[str, Any] | None = None
    shared_flag_environment: dict[str, Any] | None = None
    seen_ids: set[str] = set()
    experiment_timeout_seconds = getattr(
        experiment,
        "timeout_seconds",
        None,
    )
    if (
        type(experiment_timeout_seconds) is not int
        or experiment_timeout_seconds <= 0
    ):
        raise EvaluationInputError(
            "Pwn crash experiment timeout is invalid"
        )
    experiment_resource_class = getattr(
        experiment,
        "resource_class",
        None,
    )
    if type(experiment_resource_class) is not str:
        raise EvaluationInputError(
            "Pwn crash experiment resource class is invalid"
        )
    for ordinal, attempt in enumerate(attempts, start=1):
        if (
            type(attempt) is not dict
            or set(attempt) != _PWN_CRASH_ATTEMPT_KEYS
            or attempt.get("ordinal") != ordinal
        ):
            raise EvaluationInputError(
                f"Pwn crash attempt {ordinal} link is not exact"
            )
        run_id = attempt.get("run_id")
        receipt_id = attempt.get("receipt_id")
        stdout_id = attempt.get("stdout_artifact_id")
        if (
            type(run_id) is not str
            or type(receipt_id) is not str
            or type(stdout_id) is not str
            or run_id in seen_ids
            or receipt_id in seen_ids
            or stdout_id in seen_ids
        ):
            raise EvaluationInputError(
                f"Pwn crash attempt {ordinal} reuses an evidence identifier"
            )
        seen_ids.update((run_id, receipt_id, stdout_id))
        run = runs.get(run_id)
        receipt = receipts.get(receipt_id)
        stdout_artifact = artifacts.get(stdout_id)
        if run is None or receipt is None or stdout_artifact is None:
            raise EvaluationInputError(
                f"Pwn crash attempt {ordinal} lacks durable evidence"
            )
        pwn_record = run.extra.get("pwn_crash")
        if (
            type(pwn_record) is not dict
            or set(pwn_record) != _PWN_CRASH_RUN_RECORD_KEYS
            or receipt.extra.get("pwn_crash") != pwn_record
        ):
            raise EvaluationInputError(
                f"Pwn crash attempt {ordinal} run record is not exact"
            )
        try:
            metadata = PwnCrashReceiptMetadata.from_dict(
                pwn_record["receipt"]
            )
        except (KeyError, TypeError, ValueError) as error:
            raise EvaluationInputError(
                f"Pwn crash attempt {ordinal} receipt metadata is invalid"
            ) from error
        stderr_id = receipt.stderr_artifact_id
        stderr_artifact = (
            artifacts.get(stderr_id)
            if type(stderr_id) is str
            else None
        )
        if (
            type(stderr_id) is not str
            or stderr_id in seen_ids
            or stderr_artifact is None
        ):
            raise EvaluationInputError(
                f"Pwn crash attempt {ordinal} lacks distinct stderr evidence"
            )
        seen_ids.add(stderr_id)
        binding = recipe.attempt_input_binding(ordinal)
        if (
            run.extra.get("experiment_id") != experiment_id
            or run.request_path != f"runs/{run.id}/request.json"
            or run.configuration_epoch != recipe.configuration_epoch
            or receipt.experiment_id != experiment_id
            or receipt.run_id != run.id
            or receipt.id != metadata.receipt_id
            or metadata.run_id != run.id
            or receipt.outcome.value != metadata.outcome
            or receipt.exit_code != metadata.exit_code
            or receipt.stdout_artifact_id != stdout_artifact.id
            or receipt.stderr_artifact_id != stderr_artifact.id
            or stdout_artifact.source_run_id != run.id
            or stderr_artifact.source_run_id != run.id
            or stdout_artifact.sha256
            != metadata.stdout_artifact_sha256
            or stdout_artifact.size
            != metadata.stdout_artifact_size_bytes
            or stderr_artifact.sha256
            != metadata.stderr_artifact_sha256
            or stderr_artifact.size
            != metadata.stderr_artifact_size_bytes
            or metadata.stdout_artifact_id != stdout_artifact.id
            or metadata.stderr_artifact_id != stderr_artifact.id
            or stdout_artifact.extra.get("capture_placeholder")
            is not metadata.stdout_artifact_capture_placeholder
            or stderr_artifact.extra.get("capture_placeholder")
            is not metadata.stderr_artifact_capture_placeholder
            or pwn_record.get("recipe_sha256")
            != recipe.recipe_sha256
            or pwn_record.get("ordinal") != ordinal
            or pwn_record.get("phase") != binding["phase"]
            or pwn_record.get("input_sha256")
            != binding["input_sha256"]
            or pwn_record.get("input_size_bytes")
            != binding["input_size_bytes"]
        ):
            raise EvaluationInputError(
                f"Pwn crash attempt {ordinal} state links are inconsistent"
            )

        stdout_payloads.append(
            _read_verified_reference(
                record.root,
                stdout_artifact,
                maximum_bytes=PWN_CRASH_V1_MAX_DOCUMENT_BYTES,
                display_name=f"Pwn crash attempt {ordinal} stdout",
            )
        )
        _read_verified_reference(
            record.root,
            stderr_artifact,
            maximum_bytes=MAX_PWN_CRASH_STDERR_BYTES,
            display_name=f"Pwn crash attempt {ordinal} stderr",
        )
        capability_id = metadata.capability_attestation_artifact_id
        current_capability = artifacts.get(capability_id)
        if current_capability is None:
            raise EvaluationInputError(
                "Pwn crash capability attestation artifact is missing"
            )
        if capability_artifact is None:
            capability_artifact = current_capability
        elif current_capability.id != capability_artifact.id:
            raise EvaluationInputError(
                "Pwn crash attempts use different capability attestations"
            )
        if (
            current_capability.source_run_id is not None
            or current_capability.sha256
            != metadata.capability_attestation_sha256
        ):
            raise EvaluationInputError(
                "Pwn crash capability attestation state link is inconsistent"
            )

        request_payload, _request_metadata = _read_bounded_relative(
            record.root,
            run.request_path,
            maximum_bytes=MAX_PWN_CRASH_REQUEST_BYTES,
            display_name=f"Pwn crash attempt {ordinal} request",
        )
        request_sha256 = hashlib.sha256(request_payload).hexdigest()
        if (
            request_sha256 != pwn_record.get("request_sha256")
            or request_sha256 != metadata.request_sha256
        ):
            raise EvaluationInputError(
                f"Pwn crash attempt {ordinal} request hash changed"
            )
        request = _strict_json_bytes(
            request_payload,
            f"Pwn crash attempt {ordinal} request",
        )
        execution_contract = (
            request.get("execution_contract")
            if type(request) is dict
            else None
        )
        execution_contract_sha256 = hashlib.sha256(
            _pwn_crash_canonical_bytes(execution_contract)
        ).hexdigest()
        if (
            type(request) is not dict
            or set(request) != _PWN_CRASH_REQUEST_KEYS
            or request.get("schema_version")
            != RUN_ENVELOPE_SCHEMA_VERSION
            or request.get("contest_id") != state.contest_id
            or request.get("category") != state.category
            or request.get("challenge_id") != state.challenge_id
            or request.get("run_id") != run.id
            or request.get("base_revision") != run.base_revision
            or type(request.get("created_at")) is not str
            or request.get("kind") != "pwn_crash_gate"
            or request.get("experiment_id") != experiment_id
            or request.get("execution_contract_sha256")
            != execution_contract_sha256
            or pwn_record.get("execution_contract")
            != execution_contract
            or pwn_record.get("execution_contract_sha256")
            != execution_contract_sha256
            or metadata.execution_contract_sha256
            != execution_contract_sha256
        ):
            raise EvaluationInputError(
                f"Pwn crash attempt {ordinal} request binding is invalid"
            )
        contract_error = _pwn_crash_execution_contract_error(
            execution_contract,
            recipe=recipe,
            ordinal=ordinal,
            capability_artifact=current_capability,
            experiment_timeout_seconds=experiment_timeout_seconds,
            experiment_resource_class=experiment_resource_class,
        )
        if contract_error is not None:
            raise EvaluationInputError(
                f"Pwn crash attempt {ordinal} {contract_error}"
            )
        current_gate_binding = execution_contract["gate"]
        if shared_gate_binding is None:
            shared_gate_binding = dict(current_gate_binding)
        elif current_gate_binding != shared_gate_binding:
            raise EvaluationInputError(
                "Pwn crash attempts changed the shared gate deadline"
            )
        current_flag_environment = execution_contract["sandbox"][
            "environment"
        ]
        if shared_flag_environment is None:
            shared_flag_environment = dict(current_flag_environment)
        elif current_flag_environment != shared_flag_environment:
            raise EvaluationInputError(
                "Pwn crash attempts changed the shared flag environment"
            )
        receipt_metadata.append(metadata)

    assert capability_artifact is not None
    capability_payload = _read_verified_reference(
        record.root,
        capability_artifact,
        maximum_bytes=MAX_PWN_CRASH_CAPABILITY_BYTES,
        display_name="Pwn crash capability attestation",
    )
    capability_value = _strict_json_bytes(
        capability_payload,
        "Pwn crash capability attestation",
    )
    try:
        capability = PwnCrashCapabilityAttestation.from_dict(
            capability_value
        )
    except (TypeError, ValueError) as error:
        raise EvaluationInputError(
            "Pwn crash capability attestation is invalid"
        ) from error
    if (
        capability.image_digest != recipe.image_digest
        or capability.recipe_sha256 != recipe.recipe_sha256
        or capability.canonical_bytes() != capability_payload
    ):
        raise EvaluationInputError(
            "Pwn crash capability attestation does not match its recipe"
        )

    stored_value = evidence.get("evaluation")
    try:
        stored = PwnCrashGateEvaluation.from_dict(stored_value)
        rebuilt = evaluate_pwn_crash_gate(
            recipe,
            poc_input=payload,
            stdout_payloads=stdout_payloads,
            receipts=receipt_metadata,
        )
    except (TypeError, ValueError) as error:
        raise EvaluationInputError(
            "Pwn crash gate evaluation cannot be reconstructed"
        ) from error
    expected_status = {
        "CONFIRMED": ExperimentStatus.KEPT,
        "INCONCLUSIVE": ExperimentStatus.INCONCLUSIVE,
        "ERROR": ExperimentStatus.FAILED,
    }[rebuilt.verdict.value]
    expected_reason = (
        f"pwn_crash:{rebuilt.verdict.value}:{rebuilt.reason_code}"
    )[:512]
    if (
        rebuilt.to_dict() != stored.to_dict()
        or rebuilt.evidence_sha256 != evidence.get("evaluation_sha256")
        or getattr(experiment, "status", None) is not expected_status
        or getattr(experiment, "evaluation_reason", None)
        != expected_reason
        or getattr(experiment, "evaluated_at", None)
        != evidence.get("evaluated_at")
    ):
        raise EvaluationInputError(
            "Pwn crash recomputed verdict, hash, or status disagrees"
        )
    return rebuilt


def _pwn_crash_gate_metric(
    records: Sequence[_LoadedState],
    diagnostics: _Diagnostics,
) -> EvaluationMetric:
    counts = {
        "confirmed": 0,
        "inconclusive": 0,
        "semantic_error": 0,
        "transport_error": 0,
        "setup_failed": 0,
        "unverifiable": 0,
    }
    incomplete = 0
    typed = 0
    terminal_statuses = {
        ExperimentStatus.KEPT,
        ExperimentStatus.INCONCLUSIVE,
        ExperimentStatus.FAILED,
    }
    for record in records:
        for experiment in record.state.experiments:
            if not _pwn_crash_experiment_marker(experiment):
                continue
            typed += 1
            if experiment.status not in terminal_statuses:
                incomplete += 1
                continue
            result = experiment.result
            if (
                experiment.status is ExperimentStatus.FAILED
                and type(result) is dict
                and set(result) == {"error"}
                and type(result.get("error")) is str
                and result["error"].startswith(
                    "Pwn crash gate failed closed: "
                )
            ):
                counts["setup_failed"] += 1
                continue
            try:
                rebuilt = _revalidate_pwn_crash_gate(
                    record,
                    experiment,
                )
            except (
                EvaluationInputError,
                OSError,
                KeyError,
                TypeError,
                ValueError,
            ) as error:
                counts["unverifiable"] += 1
                diagnostics.add(
                    f"{record.state.identity.key}: Pwn crash gate "
                    f"{experiment.id} is unverifiable: {error}"
                )
                continue
            if rebuilt.verdict.value == "CONFIRMED":
                counts["confirmed"] += 1
            elif rebuilt.verdict.value == "INCONCLUSIVE":
                counts["inconclusive"] += 1
            elif rebuilt.transport_error is None:
                counts["semantic_error"] += 1
            else:
                counts["transport_error"] += 1

    if not typed:
        return _unavailable(
            "no typed Pwn crash gate experiment is recorded",
            evidence={**counts, "incomplete": 0},
        )
    terminal = sum(counts.values())
    value = {
        **counts,
        "terminal_attempts": terminal,
        "incomplete": incomplete,
        "rate": (
            _round(counts["confirmed"] / terminal)
            if terminal
            else None
        ),
    }
    partial_reason = _combine_reasons(
        (
            f"{counts['setup_failed']} terminal gate(s) failed during setup"
            if counts["setup_failed"]
            else None
        ),
        (
            f"{counts['unverifiable']} terminal gate(s) could not be "
            "independently revalidated"
            if counts["unverifiable"]
            else None
        ),
        (
            f"{incomplete} typed gate(s) are not terminal"
            if incomplete
            else None
        ),
    )
    if not terminal:
        partial_reason = _combine_reasons(
            "no typed Pwn crash gate has reached a terminal state",
            partial_reason,
        )
    return _metric(
        value,
        terminal,
        partial_reason=partial_reason,
        evidence={
            "typed_gate_experiments": typed,
            "denominator": (
                "all terminal typed Pwn crash experiments, including "
                "setup failures and unverifiable results"
            ),
        },
    )


def _first_claimed_progress_metric(
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
                (
                    "no canonical claimed progress marker has a usable "
                    "elapsed time"
                ),
                reason,
            )
            or (
                "no canonical claimed progress marker has a usable elapsed "
                "time"
            ),
            evidence={"states_with_progress_markers": states_with_markers},
        )
    return _metric(
        _time_summary(values),
        len(values),
        partial_reason=reason,
        evidence={"proxy": "first canonical claimed progress marker"},
    )


def _first_primitive_metric(
    records: Sequence[_LoadedState],
) -> EvaluationMetric:
    states_with_claimed_markers = sum(
        bool(record.state.progress_markers) for record in records
    )
    values: list[float] = []
    typed_gates = 0
    proven_gates = 0
    invalid_artifacts = 0
    missing_times = 0
    for record in records:
        artifacts = {
            artifact.id: artifact for artifact in record.state.artifacts
        }
        state_values: list[float] = []
        for experiment in record.state.experiments:
            if (
                experiment.extra.get("engine_executor")
                != _PWN_IP_CONTROL_ENGINE_EXECUTOR
            ):
                continue
            typed_gates += 1
            envelope = (
                experiment.result.get(_PWN_IP_CONTROL_RESULT_KEY)
                if experiment.status is ExperimentStatus.COMPLETED
                and type(experiment.result) is dict
                else None
            )
            if type(envelope) is not dict:
                continue
            try:
                result = PwnIpControlResult.from_dict(
                    envelope.get("result")
                )
            except (TypeError, ValueError):
                # Current-schema state validation rejects this before metrics
                # are evaluated.  Keep this defensive branch for upgraded
                # records and future schema migrations.
                invalid_artifacts += 1
                continue
            if result.status is not PwnIpControlStatus.PROVEN:
                continue
            proven_gates += 1
            result_artifact_id = envelope.get("result_artifact_id")
            artifact = (
                artifacts.get(result_artifact_id)
                if isinstance(result_artifact_id, str)
                else None
            )
            if artifact is None:
                invalid_artifacts += 1
                continue
            try:
                payload = _read_verified_reference(
                    record.root,
                    artifact,
                    maximum_bytes=PWN_IP_CONTROL_MAX_RESULT_BYTES,
                    display_name="Pwn IP-control result artifact",
                )
            except (EvaluationInputError, OSError):
                invalid_artifacts += 1
                continue
            canonical = result.canonical_bytes()
            if (
                payload != canonical
                or envelope.get("result_sha256")
                != result.evidence_sha256
                or artifact.sha256 != result.evidence_sha256
                or artifact.size != len(canonical)
            ):
                invalid_artifacts += 1
                continue
            elapsed = _elapsed_seconds(
                record.state.created_at,
                envelope.get("evaluated_at"),
            )
            if elapsed is None:
                missing_times += 1
                continue
            state_values.append(elapsed)
        if state_values:
            values.append(min(state_values))

    evidence = {
        "engine_owned_gate": _PWN_IP_CONTROL_ENGINE_EXECUTOR,
        "typed_gates": typed_gates,
        "proven_gates": proven_gates,
        "independently_verified_gates": len(values),
        "invalid_or_unreadable_result_artifacts": invalid_artifacts,
        "states_with_claimed_progress_markers": (
            states_with_claimed_markers
        ),
    }
    reason_parts: list[str] = []
    if invalid_artifacts:
        reason_parts.append(
            f"{invalid_artifacts} proven gate result artifact(s) failed "
            "bounded independent verification"
        )
    if missing_times:
        reason_parts.append(
            f"{missing_times} verified gate(s) lack a usable completion time"
        )
    reason = "; ".join(reason_parts) or None
    if not values:
        return _unavailable(
            _combine_reasons(
                (
                    _NO_EXECUTABLE_PRIMITIVE_GATE_REASON
                    if typed_gates == 0
                    else "no engine-owned primitive gate has independently "
                    "verified result bytes and a usable completion time"
                ),
                reason,
            )
            or _NO_EXECUTABLE_PRIMITIVE_GATE_REASON,
            evidence=evidence,
        )
    return _metric(
        _time_summary(values),
        len(values),
        partial_reason=reason,
        evidence=evidence,
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
        "pass^2/3",
        "consistency",
        "category_floor",
        "fixed_budget_comparability",
        "clean_reproduction_rate",
        "pwn_crash_gate_pass_rate",
        "proof_pass_rate",
        "false_proof_count",
        "time_to_first_claimed_progress",
        "time_to_first_primitive",
        "time_to_proof",
        "median_time_to_first_valid_result",
        "human_intervention_count",
        "live_hidden_performance",
        "thin_scaffold_uplift",
        "repeated_command_count",
        "stall_recovery_rate",
        "model_usage",
        "tool_wall_time",
        "refusal_count",
        "invalid_contract_count",
        "manual_points",
    )
    metrics = {name: _unavailable(reason) for name in names}
    metrics["time_to_first_primitive"] = _unavailable(
        _combine_reasons(
            _NO_EXECUTABLE_PRIMITIVE_GATE_REASON,
            reason,
        )
        or _NO_EXECUTABLE_PRIMITIVE_GATE_REASON,
        evidence={"states_with_claimed_progress_markers": 0},
    )
    return metrics


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
    metrics["pwn_crash_gate_pass_rate"] = _pwn_crash_gate_metric(
        loaded,
        diagnostics,
    )
    metrics["human_intervention_count"] = _human_intervention_metric(
        loaded
    )
    metrics["live_hidden_performance"] = (
        _live_hidden_performance_metric(loaded)
    )
    metrics["thin_scaffold_uplift"] = (
        _thin_scaffold_uplift_metric(loaded)
    )
    metrics["time_to_first_claimed_progress"] = (
        _first_claimed_progress_metric(loaded)
    )
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
