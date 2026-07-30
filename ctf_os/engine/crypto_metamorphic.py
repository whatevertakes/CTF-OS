"""Deterministic proof contract for reproducible Crypto solvers.

The execution layer is deliberately separate from this module.  It must run
the same pinned Python or Sage solver in six clean, network-denied workspaces
and return :class:`CryptoMetamorphicObservation` values.  This module then
requires three exact original-case results and three exact results for a
parameter variant whose expected answer differs from the discovered
candidate.

Raw parameters and solver output are never serialized by this contract.  The
evidence surface contains only bounded JSON pointers, sizes, and SHA-256
commitments suitable for ``state.json`` or a resume capsule.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from itertools import islice
from typing import Iterable

from ctf_os.engine.proof import ProofResult
from ctf_os.store.atomic import StrictJSONError, strict_json_loads


CRYPTO_METAMORPHIC_PROOF_PROTOCOL = (
    "crypto_solver_metamorphic_variant_v1"
)
CRYPTO_METAMORPHIC_RUNS_PER_CASE = 3
CRYPTO_METAMORPHIC_MAX_PARAMETER_BYTES = 4 * 1024 * 1024
CRYPTO_METAMORPHIC_MAX_RESULT_BYTES = 1024 * 1024
CRYPTO_METAMORPHIC_MAX_CANDIDATE_BYTES = 16 * 1024
CRYPTO_METAMORPHIC_MAX_CHANGED_POINTERS = 128

_SHA256 = re.compile(r"[0-9a-f]{64}")
_MUTATION_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_EXPECTED_ATTEMPTS = CRYPTO_METAMORPHIC_RUNS_PER_CASE * 2
_ORIGINAL_CASE_ID = "original"
_VARIANT_CASE_ID = "metamorphic-variant"

CRYPTO_METAMORPHIC_FAILURE_CODES = frozenset(
    {
        "artifact_reused",
        "attempt_count_mismatch",
        "attempt_order_mismatch",
        "candidate_contaminates_parameters",
        "candidate_invalid",
        "capture_error",
        "capture_incomplete",
        "capture_truncated",
        "duplicate_run_id",
        "exit_status_mismatch",
        "hash_binding_invalid",
        "mutation_id_invalid",
        "observation_iteration_failed",
        "observation_type_invalid",
        "observations_not_iterable",
        "oracle_not_independent",
        "orchestration_incomplete",
        "parameter_document_invalid",
        "parameter_schema_mismatch",
        "parameter_variant_absent",
        "parameter_variant_too_broad",
        "result_artifact_invalid",
        "result_mismatch",
        "run_id_invalid",
        "solver_or_runtime_mismatch",
        "source_manifest_mismatch",
        "timed_out",
        "variant_expected_output_invalid",
        "variant_output_contains_candidate",
        "workspace_not_clean",
    }
)


class CryptoMetamorphicPreflightError(ValueError):
    """Stable pre-execution rejection for an unsafe or vacuous proof plan."""

    def __init__(self, code: str) -> None:
        if code not in CRYPTO_METAMORPHIC_FAILURE_CODES:
            raise ValueError("unknown Crypto metamorphic failure code")
        super().__init__(code)
        self.code = code


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json_bytes(value: object) -> bytes:
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


def _canonical_parameter_document(payload: object) -> tuple[dict, bytes]:
    if type(payload) is not bytes:
        raise CryptoMetamorphicPreflightError(
            "parameter_document_invalid"
        )
    try:
        decoded = strict_json_loads(
            payload,
            max_bytes=CRYPTO_METAMORPHIC_MAX_PARAMETER_BYTES,
            max_depth=32,
        )
        canonical = _canonical_json_bytes(decoded)
    except (
        StrictJSONError,
        UnicodeError,
        TypeError,
        ValueError,
        RecursionError,
    ) as error:
        raise CryptoMetamorphicPreflightError(
            "parameter_document_invalid"
        ) from error
    if type(decoded) is not dict or not decoded:
        raise CryptoMetamorphicPreflightError(
            "parameter_document_invalid"
        )
    if len(canonical) > CRYPTO_METAMORPHIC_MAX_PARAMETER_BYTES:
        raise CryptoMetamorphicPreflightError(
            "parameter_document_invalid"
        )
    return decoded, canonical


def _json_scalar_kind(value: object) -> type:
    if value is None:
        return type(None)
    if type(value) in {bool, int, float, str}:
        return type(value)
    raise CryptoMetamorphicPreflightError("parameter_document_invalid")


def _pointer_component(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _changed_parameter_pointers(
    original: object,
    variant: object,
) -> tuple[str, ...]:
    """Return changed scalar JSON pointers while requiring one fixed schema."""

    changed: list[str] = []
    changed_pointer_bytes = 0
    pending: list[tuple[object, object, str]] = [
        (original, variant, "")
    ]
    while pending:
        left, right, pointer = pending.pop()
        if type(left) is dict:
            if type(right) is not dict or set(left) != set(right):
                raise CryptoMetamorphicPreflightError(
                    "parameter_schema_mismatch"
                )
            for key in sorted(left, reverse=True):
                child = f"{pointer}/{_pointer_component(key)}"
                pending.append((left[key], right[key], child))
            continue
        if type(left) is list:
            if type(right) is not list or len(left) != len(right):
                raise CryptoMetamorphicPreflightError(
                    "parameter_schema_mismatch"
                )
            for index in range(len(left) - 1, -1, -1):
                pending.append(
                    (left[index], right[index], f"{pointer}/{index}")
                )
            continue
        if type(right) in {dict, list}:
            raise CryptoMetamorphicPreflightError(
                "parameter_schema_mismatch"
            )
        if _json_scalar_kind(left) is not _json_scalar_kind(right):
            raise CryptoMetamorphicPreflightError(
                "parameter_schema_mismatch"
            )
        if (
            type(left) is float
            and (
                not math.isfinite(left)
                or not math.isfinite(right)
            )
        ):
            raise CryptoMetamorphicPreflightError(
                "parameter_document_invalid"
            )
        if left != right:
            changed_pointer = pointer or "/"
            try:
                pointer_bytes = len(changed_pointer.encode("utf-8"))
            except UnicodeEncodeError as error:
                raise CryptoMetamorphicPreflightError(
                    "parameter_variant_too_broad"
                ) from error
            changed_pointer_bytes += pointer_bytes
            changed.append(changed_pointer)
            if (
                len(changed) > CRYPTO_METAMORPHIC_MAX_CHANGED_POINTERS
                or pointer_bytes > 1024
                or changed_pointer_bytes > 16 * 1024
            ):
                raise CryptoMetamorphicPreflightError(
                    "parameter_variant_too_broad"
                )
    if not changed:
        raise CryptoMetamorphicPreflightError(
            "parameter_variant_absent"
        )
    return tuple(changed)


def _candidate_bytes(candidate: object) -> bytes:
    if type(candidate) is not str or not candidate:
        raise CryptoMetamorphicPreflightError("candidate_invalid")
    try:
        encoded = candidate.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise CryptoMetamorphicPreflightError(
            "candidate_invalid"
        ) from error
    if (
        len(encoded) > CRYPTO_METAMORPHIC_MAX_CANDIDATE_BYTES
        or not all(character.isprintable() for character in candidate)
    ):
        raise CryptoMetamorphicPreflightError("candidate_invalid")
    return encoded


def _json_contains_text(value: object, needle: str) -> bool:
    pending = [value]
    while pending:
        item = pending.pop()
        if type(item) is str and needle in item:
            return True
        if type(item) is dict:
            pending.extend(item)
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)
    return False


def _variant_output_bytes(payload: object, candidate: bytes) -> bytes:
    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > CRYPTO_METAMORPHIC_MAX_RESULT_BYTES
    ):
        raise CryptoMetamorphicPreflightError(
            "variant_expected_output_invalid"
        )
    if candidate in payload:
        raise CryptoMetamorphicPreflightError(
            "variant_output_contains_candidate"
        )
    return payload


@dataclass(frozen=True, slots=True)
class CryptoMetamorphicCase:
    case_id: str
    mutation_id: str
    parameters: bytes
    expected_output: bytes
    changed_parameter_pointers: tuple[str, ...]

    @property
    def parameters_sha256(self) -> str:
        return _sha256(self.parameters)

    @property
    def expected_output_sha256(self) -> str:
        return _sha256(self.expected_output)

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "changed_parameter_pointers": list(
                self.changed_parameter_pointers
            ),
            "expected_output_sha256": self.expected_output_sha256,
            "expected_output_size_bytes": len(self.expected_output),
            "mutation_id": self.mutation_id,
            "parameters_sha256": self.parameters_sha256,
            "parameters_size_bytes": len(self.parameters),
        }


@dataclass(frozen=True, slots=True)
class CryptoMetamorphicAttempt:
    ordinal: int
    case_id: str
    mutation_id: str
    parameters_sha256: str
    parameters_size_bytes: int
    expected_output_sha256: str
    expected_output_size_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "expected_output_sha256": self.expected_output_sha256,
            "expected_output_size_bytes": self.expected_output_size_bytes,
            "mutation_id": self.mutation_id,
            "ordinal": self.ordinal,
            "parameters_sha256": self.parameters_sha256,
            "parameters_size_bytes": self.parameters_size_bytes,
        }


@dataclass(frozen=True, slots=True)
class CryptoMetamorphicPlan:
    cases: tuple[CryptoMetamorphicCase, CryptoMetamorphicCase]
    attempts: tuple[CryptoMetamorphicAttempt, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "attempts": [item.to_dict() for item in self.attempts],
            "cases": [item.to_dict() for item in self.cases],
            "protocol": CRYPTO_METAMORPHIC_PROOF_PROTOCOL,
        }

    @property
    def sha256(self) -> str:
        return _sha256(_canonical_json_bytes(self.to_dict()))


def build_crypto_metamorphic_plan(
    candidate: str,
    original_parameters: bytes,
    variant_parameters: bytes,
    variant_expected_output: bytes,
    *,
    mutation_id: str,
) -> CryptoMetamorphicPlan:
    """Build the only six-run input plan accepted by the v1 contract."""

    candidate_bytes = _candidate_bytes(candidate)
    if (
        type(mutation_id) is not str
        or _MUTATION_ID.fullmatch(mutation_id) is None
        or mutation_id == _ORIGINAL_CASE_ID
    ):
        raise CryptoMetamorphicPreflightError(
            "mutation_id_invalid"
        )
    original, original_canonical = _canonical_parameter_document(
        original_parameters
    )
    variant, variant_canonical = _canonical_parameter_document(
        variant_parameters
    )
    changed = _changed_parameter_pointers(original, variant)
    if (
        candidate_bytes in original_canonical
        or candidate_bytes in variant_canonical
        or _json_contains_text(original, candidate)
        or _json_contains_text(variant, candidate)
    ):
        raise CryptoMetamorphicPreflightError(
            "candidate_contaminates_parameters"
        )
    variant_output = _variant_output_bytes(
        variant_expected_output,
        candidate_bytes,
    )
    if variant_output in {original_canonical, variant_canonical}:
        raise CryptoMetamorphicPreflightError(
            "oracle_not_independent"
        )
    original_case = CryptoMetamorphicCase(
        case_id=_ORIGINAL_CASE_ID,
        mutation_id="original-baseline",
        parameters=original_canonical,
        expected_output=candidate_bytes,
        changed_parameter_pointers=(),
    )
    variant_case = CryptoMetamorphicCase(
        case_id=_VARIANT_CASE_ID,
        mutation_id=mutation_id,
        parameters=variant_canonical,
        expected_output=variant_output,
        changed_parameter_pointers=changed,
    )
    attempts: list[CryptoMetamorphicAttempt] = []
    for case in (original_case, variant_case):
        for _repeat in range(CRYPTO_METAMORPHIC_RUNS_PER_CASE):
            attempts.append(
                CryptoMetamorphicAttempt(
                    ordinal=len(attempts) + 1,
                    case_id=case.case_id,
                    mutation_id=case.mutation_id,
                    parameters_sha256=case.parameters_sha256,
                    parameters_size_bytes=len(case.parameters),
                    expected_output_sha256=(
                        case.expected_output_sha256
                    ),
                    expected_output_size_bytes=len(case.expected_output),
                )
            )
    return CryptoMetamorphicPlan(
        cases=(original_case, variant_case),
        attempts=tuple(attempts),
    )


@dataclass(frozen=True, slots=True)
class CryptoMetamorphicObservation:
    run_id: str
    ordinal: int
    case_id: str
    mutation_id: str
    parameters_sha256: str
    parameters_size_bytes: int
    source_manifest_sha256: str
    solver_artifact_sha256: str
    runtime_fingerprint_sha256: str
    oracle_artifact_sha256: str
    clean_workspace: bool
    target_exit_code: int | None
    runner_exit_code: int | None
    ctfwrap_exit_code: int | None
    timed_out: bool
    orchestration_status: str
    result_artifact_id: str | None
    result_artifact_sha256: str | None
    result_artifact_size_bytes: int | None
    capture_complete: bool
    truncation_known: bool
    truncated: bool | None
    capture_error: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "capture_complete": self.capture_complete,
            "capture_error_present": self.capture_error is not None,
            "case_id": self.case_id,
            "clean_workspace": self.clean_workspace,
            "ctfwrap_exit_code": self.ctfwrap_exit_code,
            "mutation_id": self.mutation_id,
            "oracle_artifact_sha256": self.oracle_artifact_sha256,
            "orchestration_status": self.orchestration_status,
            "ordinal": self.ordinal,
            "parameters_sha256": self.parameters_sha256,
            "parameters_size_bytes": self.parameters_size_bytes,
            "result_artifact_id": self.result_artifact_id,
            "result_artifact_sha256": self.result_artifact_sha256,
            "result_artifact_size_bytes": (
                self.result_artifact_size_bytes
            ),
            "run_id": self.run_id,
            "runner_exit_code": self.runner_exit_code,
            "runtime_fingerprint_sha256": (
                self.runtime_fingerprint_sha256
            ),
            "solver_artifact_sha256": self.solver_artifact_sha256,
            "source_manifest_sha256": self.source_manifest_sha256,
            "target_exit_code": self.target_exit_code,
            "timed_out": self.timed_out,
            "truncated": self.truncated,
            "truncation_known": self.truncation_known,
        }


@dataclass(frozen=True, slots=True)
class CryptoMetamorphicEvaluation:
    candidate: str
    source_manifest_sha256: str
    solver_artifact_sha256: str
    runtime_fingerprint_sha256: str
    oracle_artifact_sha256: str
    plan: CryptoMetamorphicPlan | None
    observations: tuple[CryptoMetamorphicObservation, ...]
    failure_codes: tuple[str, ...]
    passed: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "candidate_sha256": (
                _sha256(self.candidate.encode("utf-8"))
                if self.candidate
                else None
            ),
            "failure_codes": list(self.failure_codes),
            "observations": [
                item.to_dict() for item in self.observations
            ],
            "oracle_artifact_sha256": self.oracle_artifact_sha256,
            "passed": self.passed,
            "plan": self.plan.to_dict() if self.plan is not None else None,
            "protocol": CRYPTO_METAMORPHIC_PROOF_PROTOCOL,
            "runtime_fingerprint_sha256": (
                self.runtime_fingerprint_sha256
            ),
            "schema_version": 1,
            "solver_artifact_sha256": self.solver_artifact_sha256,
            "source_manifest_sha256": self.source_manifest_sha256,
        }

    @property
    def sha256(self) -> str:
        return _sha256(_canonical_json_bytes(self.to_dict()))


def _valid_sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _bounded_printable_id(value: object) -> bool:
    if type(value) is not str or not value:
        return False
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return False
    return (
        len(encoded) <= 256
        and all(character.isprintable() for character in value)
    )


def _normalized_observation(
    value: CryptoMetamorphicObservation,
) -> CryptoMetamorphicObservation:
    """Drop unbounded worker text while retaining exact checked commitments."""

    return CryptoMetamorphicObservation(
        run_id=value.run_id if _bounded_printable_id(value.run_id) else "",
        ordinal=value.ordinal if type(value.ordinal) is int else -1,
        case_id=(
            value.case_id
            if _bounded_printable_id(value.case_id)
            else ""
        ),
        mutation_id=(
            value.mutation_id
            if _bounded_printable_id(value.mutation_id)
            else ""
        ),
        parameters_sha256=(
            value.parameters_sha256
            if _valid_sha256(value.parameters_sha256)
            else ""
        ),
        parameters_size_bytes=(
            value.parameters_size_bytes
            if type(value.parameters_size_bytes) is int
            and 0
            <= value.parameters_size_bytes
            <= CRYPTO_METAMORPHIC_MAX_PARAMETER_BYTES
            else -1
        ),
        source_manifest_sha256=(
            value.source_manifest_sha256
            if _valid_sha256(value.source_manifest_sha256)
            else ""
        ),
        solver_artifact_sha256=(
            value.solver_artifact_sha256
            if _valid_sha256(value.solver_artifact_sha256)
            else ""
        ),
        runtime_fingerprint_sha256=(
            value.runtime_fingerprint_sha256
            if _valid_sha256(value.runtime_fingerprint_sha256)
            else ""
        ),
        oracle_artifact_sha256=(
            value.oracle_artifact_sha256
            if _valid_sha256(value.oracle_artifact_sha256)
            else ""
        ),
        clean_workspace=value.clean_workspace is True,
        target_exit_code=(
            value.target_exit_code
            if type(value.target_exit_code) is int
            else None
        ),
        runner_exit_code=(
            value.runner_exit_code
            if type(value.runner_exit_code) is int
            else None
        ),
        ctfwrap_exit_code=(
            value.ctfwrap_exit_code
            if type(value.ctfwrap_exit_code) is int
            else None
        ),
        timed_out=value.timed_out is not False,
        orchestration_status=(
            value.orchestration_status
            if _bounded_printable_id(value.orchestration_status)
            else ""
        ),
        result_artifact_id=(
            value.result_artifact_id
            if _bounded_printable_id(value.result_artifact_id)
            else None
        ),
        result_artifact_sha256=(
            value.result_artifact_sha256
            if _valid_sha256(value.result_artifact_sha256)
            else None
        ),
        result_artifact_size_bytes=(
            value.result_artifact_size_bytes
            if type(value.result_artifact_size_bytes) is int
            and 0
            <= value.result_artifact_size_bytes
            <= CRYPTO_METAMORPHIC_MAX_RESULT_BYTES
            else None
        ),
        capture_complete=value.capture_complete is True,
        truncation_known=value.truncation_known is True,
        truncated=value.truncated if type(value.truncated) is bool else None,
        capture_error=(
            "present" if value.capture_error is not None else None
        ),
    )


def _failure(code: str, ordinal: int | None = None) -> str:
    if ordinal is None:
        return code
    return f"attempt-{ordinal}:{code}"


def _preflight_failure(
    candidate: object,
    source_manifest_sha256: object,
    solver_artifact_sha256: object,
    runtime_fingerprint_sha256: object,
    oracle_artifact_sha256: object,
    code: str,
) -> tuple[ProofResult, CryptoMetamorphicEvaluation]:
    try:
        _candidate_bytes(candidate)
    except CryptoMetamorphicPreflightError:
        safe_candidate = ""
    else:
        assert isinstance(candidate, str)
        safe_candidate = candidate
    bindings = tuple(
        value if _valid_sha256(value) else ""
        for value in (
            source_manifest_sha256,
            solver_artifact_sha256,
            runtime_fingerprint_sha256,
            oracle_artifact_sha256,
        )
    )
    evaluation = CryptoMetamorphicEvaluation(
        candidate=safe_candidate,
        source_manifest_sha256=bindings[0],
        solver_artifact_sha256=bindings[1],
        runtime_fingerprint_sha256=bindings[2],
        oracle_artifact_sha256=bindings[3],
        plan=None,
        observations=(),
        failure_codes=(code,),
        passed=False,
    )
    return (
        ProofResult(
            passed=False,
            candidate=safe_candidate,
            policy_mode=CRYPTO_METAMORPHIC_PROOF_PROTOCOL,
            successful_attempts=0,
            required_attempts=_EXPECTED_ATTEMPTS,
            total_attempts=0,
            source_manifest_sha256=bindings[0],
            failures=(code,),
            run_ids=(),
        ),
        evaluation,
    )


def evaluate_crypto_metamorphic_proof(
    candidate: str,
    original_parameters: bytes,
    variant_parameters: bytes,
    variant_expected_output: bytes,
    *,
    mutation_id: str,
    source_manifest_sha256: str,
    solver_artifact_sha256: str,
    runtime_fingerprint_sha256: str,
    oracle_artifact_sha256: str,
    observations: Iterable[CryptoMetamorphicObservation],
) -> tuple[ProofResult, CryptoMetamorphicEvaluation]:
    """Evaluate a pinned solver against one original and one changed case."""

    try:
        plan = build_crypto_metamorphic_plan(
            candidate,
            original_parameters,
            variant_parameters,
            variant_expected_output,
            mutation_id=mutation_id,
        )
    except CryptoMetamorphicPreflightError as error:
        return _preflight_failure(
            candidate,
            source_manifest_sha256,
            solver_artifact_sha256,
            runtime_fingerprint_sha256,
            oracle_artifact_sha256,
            error.code,
        )
    bindings = (
        source_manifest_sha256,
        solver_artifact_sha256,
        runtime_fingerprint_sha256,
        oracle_artifact_sha256,
    )
    if any(not _valid_sha256(item) for item in bindings):
        return _preflight_failure(
            candidate,
            source_manifest_sha256,
            solver_artifact_sha256,
            runtime_fingerprint_sha256,
            oracle_artifact_sha256,
            "hash_binding_invalid",
        )
    if oracle_artifact_sha256 == solver_artifact_sha256:
        return _preflight_failure(
            candidate,
            source_manifest_sha256,
            solver_artifact_sha256,
            runtime_fingerprint_sha256,
            oracle_artifact_sha256,
            "oracle_not_independent",
        )

    failures: list[str] = []
    try:
        iterator = iter(observations)
    except Exception:
        observed: tuple[object, ...] = ()
        failures.append("observations_not_iterable")
    else:
        try:
            observed = tuple(islice(iterator, _EXPECTED_ATTEMPTS + 1))
        except Exception:
            observed = ()
            failures.append("observation_iteration_failed")
    if (
        len(observed) != _EXPECTED_ATTEMPTS
        and not failures
    ):
        failures.append("attempt_count_mismatch")
    retained = observed[:_EXPECTED_ATTEMPTS]
    typed: list[CryptoMetamorphicObservation] = []
    for ordinal, item in enumerate(retained, start=1):
        if type(item) is not CryptoMetamorphicObservation:
            failures.append(_failure("observation_type_invalid", ordinal))
        else:
            typed.append(item)

    seen_runs: set[str] = set()
    seen_artifacts: set[str] = set()
    successful_ordinals: set[int] = set()
    if (
        len(observed) == _EXPECTED_ATTEMPTS
        and len(typed) == _EXPECTED_ATTEMPTS
    ):
        for expected, observation in zip(
            plan.attempts,
            typed,
            strict=True,
        ):
            before = len(failures)
            ordinal = expected.ordinal
            if not _bounded_printable_id(observation.run_id):
                failures.append(_failure("run_id_invalid", ordinal))
            elif observation.run_id in seen_runs:
                failures.append(_failure("duplicate_run_id", ordinal))
            else:
                seen_runs.add(observation.run_id)
            if (
                type(observation.ordinal) is not int
                or observation.ordinal != ordinal
                or observation.case_id != expected.case_id
                or observation.mutation_id != expected.mutation_id
                or observation.parameters_sha256
                != expected.parameters_sha256
                or type(observation.parameters_size_bytes) is not int
                or observation.parameters_size_bytes
                != expected.parameters_size_bytes
            ):
                failures.append(
                    _failure("attempt_order_mismatch", ordinal)
                )
            if (
                observation.source_manifest_sha256
                != source_manifest_sha256
            ):
                failures.append(
                    _failure("source_manifest_mismatch", ordinal)
                )
            if (
                observation.solver_artifact_sha256
                != solver_artifact_sha256
                or observation.runtime_fingerprint_sha256
                != runtime_fingerprint_sha256
                or observation.oracle_artifact_sha256
                != oracle_artifact_sha256
            ):
                failures.append(
                    _failure("solver_or_runtime_mismatch", ordinal)
                )
            if observation.clean_workspace is not True:
                failures.append(
                    _failure("workspace_not_clean", ordinal)
                )
            if observation.timed_out is not False:
                failures.append(_failure("timed_out", ordinal))
            if (
                type(observation.target_exit_code) is not int
                or observation.target_exit_code != 0
                or type(observation.runner_exit_code) is not int
                or observation.runner_exit_code != 0
                or type(observation.ctfwrap_exit_code) is not int
                or observation.ctfwrap_exit_code != 0
            ):
                failures.append(
                    _failure("exit_status_mismatch", ordinal)
                )
            if observation.orchestration_status != "completed":
                failures.append(
                    _failure("orchestration_incomplete", ordinal)
                )
            if observation.capture_error is not None:
                failures.append(_failure("capture_error", ordinal))
            if (
                observation.capture_complete is not True
                or observation.truncation_known is not True
            ):
                failures.append(
                    _failure("capture_incomplete", ordinal)
                )
            if observation.truncated is not False:
                failures.append(
                    _failure("capture_truncated", ordinal)
                )
            artifact_id = observation.result_artifact_id
            if (
                not _bounded_printable_id(artifact_id)
                or not _valid_sha256(
                    observation.result_artifact_sha256
                )
                or isinstance(
                    observation.result_artifact_size_bytes,
                    bool,
                )
                or not isinstance(
                    observation.result_artifact_size_bytes,
                    int,
                )
                or observation.result_artifact_size_bytes < 0
                or observation.result_artifact_size_bytes
                > CRYPTO_METAMORPHIC_MAX_RESULT_BYTES
            ):
                failures.append(
                    _failure("result_artifact_invalid", ordinal)
                )
            else:
                if artifact_id in seen_artifacts:
                    failures.append(
                        _failure("artifact_reused", ordinal)
                    )
                else:
                    seen_artifacts.add(artifact_id)
                if (
                    observation.result_artifact_sha256
                    != expected.expected_output_sha256
                    or observation.result_artifact_size_bytes
                    != expected.expected_output_size_bytes
                ):
                    failures.append(
                        _failure("result_mismatch", ordinal)
                    )
            if len(failures) == before:
                successful_ordinals.add(ordinal)

    unique_failures = tuple(dict.fromkeys(failures))
    passed = not unique_failures
    normalized_observations = tuple(
        _normalized_observation(item) for item in typed
    )
    evaluation = CryptoMetamorphicEvaluation(
        candidate=candidate,
        source_manifest_sha256=source_manifest_sha256,
        solver_artifact_sha256=solver_artifact_sha256,
        runtime_fingerprint_sha256=runtime_fingerprint_sha256,
        oracle_artifact_sha256=oracle_artifact_sha256,
        plan=plan,
        observations=normalized_observations,
        failure_codes=unique_failures,
        passed=passed,
    )
    return (
        ProofResult(
            passed=passed,
            candidate=candidate,
            policy_mode=CRYPTO_METAMORPHIC_PROOF_PROTOCOL,
            successful_attempts=len(successful_ordinals),
            required_attempts=_EXPECTED_ATTEMPTS,
            total_attempts=len(normalized_observations),
            source_manifest_sha256=source_manifest_sha256,
            failures=unique_failures,
            run_ids=tuple(
                item.run_id for item in normalized_observations
            ),
        ),
        evaluation,
    )


__all__ = [
    "CRYPTO_METAMORPHIC_FAILURE_CODES",
    "CRYPTO_METAMORPHIC_MAX_CHANGED_POINTERS",
    "CRYPTO_METAMORPHIC_PROOF_PROTOCOL",
    "CRYPTO_METAMORPHIC_RUNS_PER_CASE",
    "CryptoMetamorphicAttempt",
    "CryptoMetamorphicCase",
    "CryptoMetamorphicEvaluation",
    "CryptoMetamorphicObservation",
    "CryptoMetamorphicPlan",
    "CryptoMetamorphicPreflightError",
    "build_crypto_metamorphic_plan",
    "evaluate_crypto_metamorphic_proof",
]
