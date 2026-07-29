"""Pure proof contract for Rev binaries driven by exact standard input.

This module deliberately knows nothing about challenge state, sandboxes, or
artifact stores.  The execution layer produces :class:`RevProofObservation`
values; this module checks those values against one deterministic six-run
plan.  Raw output never enters the contract.  It is represented by complete,
durable stream artifacts plus the bounded flag values detected from those
artifacts.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from itertools import islice
from typing import Iterable

from ctf_os.engine.proof import ProofResult


REV_STDIN_PROOF_PROTOCOL = "rev_original_binary_stdin_candidate_v1"
REV_STDIN_PROOF_MAX_ACCEPTED_INPUT_BYTES = 1024 * 1024
REV_STDIN_PROOF_MAX_CANDIDATE_CHARS = 1024
REV_STDIN_PROOF_MAX_CANDIDATE_BYTES = 4 * 1024
REV_STDIN_PROOF_MAX_FLAG_VALUES = 128
REV_STDIN_PROOF_MAX_FLAG_CHARS = 16 * 1024
REV_STDIN_PROOF_MAX_FLAG_BYTES = 16 * 1024
REV_STDIN_PROOF_MAX_STREAM_BYTES = 16 * 1024 * 1024
REV_STDIN_PROOF_MAX_EVIDENCE_BYTES = 512 * 1024
REV_STDIN_PROOF_FLAG_SCANNER_CONTRACT = (
    "ctfos_durable_stream_flag_scan_v1"
)

REV_STDIN_PROOF_POSITIVE_MUTATION_IDS = (
    "accepted-input-repeat-1",
    "accepted-input-repeat-2",
    "accepted-input-repeat-3",
)
REV_STDIN_PROOF_NONEMPTY_NEGATIVE_MUTATION_IDS = (
    "xor-first-01",
    "xor-last-80",
    "truncate-last",
)
REV_STDIN_PROOF_EMPTY_NEGATIVE_MUTATION_IDS = (
    "append-00",
    "append-0a",
    "append-ff",
)

_SHA256 = re.compile(r"[0-9a-f]{64}")
_PHASE_POSITIVE = "positive"
_PHASE_NEGATIVE = "negative"
_EXPECTED_ATTEMPT_COUNT = 6
_TRANSPORT_INCONCLUSIVE_EXIT = 125

# This finite vocabulary is persisted instead of exception text.  A single
# evaluation can contain at most six observations and therefore a bounded
# number of these codes.
REV_STDIN_PROOF_FAILURE_CODES = frozenset(
    {
        "accepted_input_contains_candidate",
        "accepted_input_too_large",
        "accepted_input_type_invalid",
        "attempt_count_mismatch",
        "attempt_order_mismatch",
        "candidate_invalid",
        "capture_error",
        "capture_incomplete",
        "capture_truncated",
        "capture_truncation_unknown",
        "ctfwrap_transport_exit_125",
        "ctfwrap_exit_unavailable",
        "derived_input_contains_candidate",
        "duplicate_run_id",
        "durable_artifact_incomplete",
        "durable_artifact_reused",
        "exit_status_mismatch",
        "flag_evidence_invalid",
        "flag_scan_error",
        "flag_scan_incomplete",
        "flag_scanner_contract_mismatch",
        "flag_values_overflow",
        "input_binding_mismatch",
        "observation_type_invalid",
        "observation_iteration_failed",
        "observations_not_iterable",
        "orchestration_error",
        "orchestration_incomplete",
        "runner_exit_unavailable",
        "runner_transport_exit_125",
        "selected_candidate_not_direct",
        "source_manifest_invalid",
        "source_manifest_mismatch",
        "target_exit_unavailable",
        "target_transport_exit_125",
        "timed_out",
        "run_id_invalid",
        "negative_flag_candidate_observed",
        "workspace_not_clean",
    }
)


class RevProofPreflightError(ValueError):
    """A stable pre-execution rejection of candidate or accepted input."""

    def __init__(self, code: str) -> None:
        if code not in REV_STDIN_PROOF_FAILURE_CODES:
            raise ValueError("unknown Rev proof failure code")
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


def _candidate_bytes(candidate: object) -> bytes:
    if type(candidate) is not str or not candidate:
        raise RevProofPreflightError("candidate_invalid")
    if len(candidate) > REV_STDIN_PROOF_MAX_CANDIDATE_CHARS:
        raise RevProofPreflightError("candidate_invalid")
    try:
        encoded = candidate.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise RevProofPreflightError("candidate_invalid") from error
    if (
        len(encoded) > REV_STDIN_PROOF_MAX_CANDIDATE_BYTES
        or not all(character.isprintable() for character in candidate)
    ):
        raise RevProofPreflightError("candidate_invalid")
    return encoded


def _accepted_input_bytes(accepted_input: object) -> bytes:
    if type(accepted_input) is not bytes:
        raise RevProofPreflightError("accepted_input_type_invalid")
    if len(accepted_input) > REV_STDIN_PROOF_MAX_ACCEPTED_INPUT_BYTES:
        raise RevProofPreflightError("accepted_input_too_large")
    return accepted_input


@dataclass(frozen=True, slots=True)
class RevProofInput:
    """One exact input in the fixed six-run plan.

    ``payload`` is required by the execution layer but intentionally omitted
    from :meth:`to_dict`; persisted evidence contains only its hash and size.
    """

    ordinal: int
    phase: str
    mutation_id: str
    payload: bytes

    @property
    def sha256(self) -> str:
        return _sha256(self.payload)

    @property
    def size_bytes(self) -> int:
        return len(self.payload)

    def to_dict(self) -> dict[str, object]:
        return {
            "input_sha256": self.sha256,
            "input_size_bytes": self.size_bytes,
            "mutation_id": self.mutation_id,
            "ordinal": self.ordinal,
            "phase": self.phase,
        }


def build_rev_stdin_proof_plan(
    candidate: str,
    accepted_input: bytes,
) -> tuple[RevProofInput, ...]:
    """Build the only input plan accepted by the v1 Rev proof protocol."""

    candidate_bytes = _candidate_bytes(candidate)
    payload = _accepted_input_bytes(accepted_input)
    if candidate_bytes in payload:
        raise RevProofPreflightError(
            "accepted_input_contains_candidate"
        )

    if payload:
        xor_first = bytes((payload[0] ^ 0x01,)) + payload[1:]
        xor_last = payload[:-1] + bytes((payload[-1] ^ 0x80,))
        negative_payloads = (xor_first, xor_last, payload[:-1])
        negative_ids = REV_STDIN_PROOF_NONEMPTY_NEGATIVE_MUTATION_IDS
    else:
        negative_payloads = (b"\x00", b"\x0a", b"\xff")
        negative_ids = REV_STDIN_PROOF_EMPTY_NEGATIVE_MUTATION_IDS
    if any(
        candidate_bytes in mutated
        for mutated in negative_payloads
    ):
        raise RevProofPreflightError(
            "derived_input_contains_candidate"
        )

    planned: list[RevProofInput] = []
    for index, mutation_id in enumerate(
        REV_STDIN_PROOF_POSITIVE_MUTATION_IDS,
        start=1,
    ):
        planned.append(
            RevProofInput(
                ordinal=index,
                phase=_PHASE_POSITIVE,
                mutation_id=mutation_id,
                payload=payload,
            )
        )
    for offset, (mutation_id, mutated) in enumerate(
        zip(negative_ids, negative_payloads, strict=True),
        start=4,
    ):
        planned.append(
            RevProofInput(
                ordinal=offset,
                phase=_PHASE_NEGATIVE,
                mutation_id=mutation_id,
                payload=mutated,
            )
        )
    return tuple(planned)


@dataclass(frozen=True, slots=True)
class RevProofStreamEvidence:
    """Completeness metadata for one durable stdout or stderr artifact."""

    artifact_id: str | None
    artifact_sha256: str | None
    artifact_size_bytes: int | None
    capture_complete: bool
    truncation_known: bool
    truncated: bool | None
    capture_error: str | None
    durable_artifact_complete: bool

    def to_dict(self) -> dict[str, object]:
        return _normalized_stream_evidence(self)._to_dict_unchecked()

    def _to_dict_unchecked(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "artifact_size_bytes": self.artifact_size_bytes,
            "capture_complete": self.capture_complete,
            "capture_error": self.capture_error,
            "durable_artifact_complete": self.durable_artifact_complete,
            "truncated": self.truncated,
            "truncation_known": self.truncation_known,
        }


@dataclass(frozen=True, slots=True)
class RevProofObservation:
    """One candidate-unaware execution observation."""

    run_id: str
    phase: str
    mutation_id: str
    input_sha256: str
    input_size_bytes: int
    source_manifest_sha256: str
    clean_workspace: bool
    target_exit_code: int | None
    runner_exit_code: int | None
    ctfwrap_exit_code: int | None
    timed_out: bool
    orchestration_status: str
    orchestration_error: str | None
    stream_capture_error: str | None
    stdout: RevProofStreamEvidence
    stderr: RevProofStreamEvidence
    flag_scanner_contract: str
    flag_scan_complete: bool
    flag_scan_error: str | None
    flag_values_overflow: bool
    flag_values: tuple[str, ...]
    selected_candidate_direct_output: bool

    def __post_init__(self) -> None:
        if type(self.flag_values) is not tuple:
            raise TypeError("flag_values must be an immutable tuple")

    def to_dict(self) -> dict[str, object]:
        return _normalized_observation_evidence(
            self
        )._to_dict_unchecked()

    def _to_dict_unchecked(self) -> dict[str, object]:
        return {
            "clean_workspace": self.clean_workspace,
            "ctfwrap_exit_code": self.ctfwrap_exit_code,
            "flag_scan_complete": self.flag_scan_complete,
            "flag_scan_error": self.flag_scan_error,
            "flag_scanner_contract": self.flag_scanner_contract,
            "flag_values": list(self.flag_values),
            "flag_values_overflow": self.flag_values_overflow,
            "input_sha256": self.input_sha256,
            "input_size_bytes": self.input_size_bytes,
            "mutation_id": self.mutation_id,
            "orchestration_error": self.orchestration_error,
            "orchestration_status": self.orchestration_status,
            "phase": self.phase,
            "run_id": self.run_id,
            "runner_exit_code": self.runner_exit_code,
            "selected_candidate_direct_output": (
                self.selected_candidate_direct_output
            ),
            "source_manifest_sha256": self.source_manifest_sha256,
            "stderr": self.stderr._to_dict_unchecked(),
            "stdout": self.stdout._to_dict_unchecked(),
            "stream_capture_error": self.stream_capture_error,
            "target_exit_code": self.target_exit_code,
            "timed_out": self.timed_out,
        }


@dataclass(frozen=True, slots=True)
class RevProofFailure:
    """One bounded, machine-readable contract failure."""

    code: str
    attempt_ordinal: int | None = None
    run_id: str | None = None
    stream: str | None = None

    def __post_init__(self) -> None:
        if self.code not in REV_STDIN_PROOF_FAILURE_CODES:
            raise ValueError("unknown Rev proof failure code")

    def to_dict(self) -> dict[str, object]:
        return {
            "attempt_ordinal": self.attempt_ordinal,
            "code": self.code,
            "run_id": self.run_id,
            "stream": self.stream,
        }

    def token(self) -> str:
        parts = [self.code]
        if self.attempt_ordinal is not None:
            parts.append(f"attempt={self.attempt_ordinal}")
        if self.run_id is not None:
            parts.append(f"run={self.run_id}")
        if self.stream is not None:
            parts.append(f"stream={self.stream}")
        return ":".join(parts)


@dataclass(frozen=True, slots=True)
class RevProofEvaluation:
    """Structured, raw-output-free evidence for protocol v1."""

    candidate: str
    source_manifest_sha256: str
    accepted_input_sha256: str | None
    accepted_input_size_bytes: int | None
    plan: tuple[RevProofInput, ...]
    observations: tuple[RevProofObservation, ...]
    failures: tuple[RevProofFailure, ...]
    positive_successes: int
    passed: bool
    protocol: str = REV_STDIN_PROOF_PROTOCOL

    @property
    def failure_codes(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(item.code for item in self.failures))

    @property
    def verdict(self) -> str:
        return "CONFIRMED" if self.passed else "INCONCLUSIVE"

    @property
    def transport_inconclusive(self) -> bool:
        return bool(
            {
                "target_transport_exit_125",
                "runner_transport_exit_125",
                "ctfwrap_transport_exit_125",
            }.intersection(self.failure_codes)
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "accepted_input_sha256": self.accepted_input_sha256,
            "accepted_input_size_bytes": self.accepted_input_size_bytes,
            "candidate": self.candidate,
            "failure_codes": list(self.failure_codes),
            "failures": [item.to_dict() for item in self.failures],
            "observations": [
                item.to_dict() for item in self.observations
            ],
            "passed": self.passed,
            "plan": [item.to_dict() for item in self.plan],
            "positive_successes": self.positive_successes,
            "protocol": self.protocol,
            "required_negative_attempts": 3,
            "required_positive_attempts": 3,
            "schema_version": 1,
            "source_manifest_sha256": self.source_manifest_sha256,
            "total_attempts": len(self.observations),
            "transport_inconclusive": self.transport_inconclusive,
            "verdict": self.verdict,
        }

    def canonical_bytes(self) -> bytes:
        payload = _canonical_json_bytes(self.to_dict())
        if len(payload) > REV_STDIN_PROOF_MAX_EVIDENCE_BYTES:
            raise ValueError("Rev proof evidence exceeds its byte limit")
        return payload

    @property
    def evidence_sha256(self) -> str:
        return _sha256(self.canonical_bytes())


@dataclass(frozen=True, slots=True)
class RevProofInputRecord:
    """Payload-free input binding read from persisted proof evidence."""

    ordinal: int
    phase: str
    mutation_id: str
    input_sha256: str
    input_size_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "input_sha256": self.input_sha256,
            "input_size_bytes": self.input_size_bytes,
            "mutation_id": self.mutation_id,
            "ordinal": self.ordinal,
            "phase": self.phase,
        }


@dataclass(frozen=True, slots=True)
class RevProofEvaluationRecord:
    """Strict, immutable representation of persisted Rev proof evidence.

    Unlike :class:`RevProofEvaluation`, this record never invents payloads for
    the persisted plan.  ``verify_rev_proof_evaluation`` rebuilds the live
    payload-bearing plan from the separately supplied accepted input.
    """

    candidate: str
    source_manifest_sha256: str
    accepted_input_sha256: str | None
    accepted_input_size_bytes: int | None
    plan: tuple[RevProofInputRecord, ...]
    observations: tuple[RevProofObservation, ...]
    failures: tuple[RevProofFailure, ...]
    positive_successes: int
    passed: bool
    protocol: str = REV_STDIN_PROOF_PROTOCOL

    @property
    def failure_codes(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(item.code for item in self.failures))

    @property
    def verdict(self) -> str:
        return "CONFIRMED" if self.passed else "INCONCLUSIVE"

    @property
    def transport_inconclusive(self) -> bool:
        return bool(
            {
                "target_transport_exit_125",
                "runner_transport_exit_125",
                "ctfwrap_transport_exit_125",
            }.intersection(self.failure_codes)
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "accepted_input_sha256": self.accepted_input_sha256,
            "accepted_input_size_bytes": self.accepted_input_size_bytes,
            "candidate": self.candidate,
            "failure_codes": list(self.failure_codes),
            "failures": [item.to_dict() for item in self.failures],
            "observations": [
                item.to_dict() for item in self.observations
            ],
            "passed": self.passed,
            "plan": [item.to_dict() for item in self.plan],
            "positive_successes": self.positive_successes,
            "protocol": self.protocol,
            "required_negative_attempts": 3,
            "required_positive_attempts": 3,
            "schema_version": 1,
            "source_manifest_sha256": self.source_manifest_sha256,
            "total_attempts": len(self.observations),
            "transport_inconclusive": self.transport_inconclusive,
            "verdict": self.verdict,
        }

    def canonical_bytes(self) -> bytes:
        payload = _canonical_json_bytes(self.to_dict())
        if len(payload) > REV_STDIN_PROOF_MAX_EVIDENCE_BYTES:
            raise ValueError("Rev proof evidence exceeds its byte limit")
        return payload

    @property
    def evidence_sha256(self) -> str:
        return _sha256(self.canonical_bytes())


def _failure(
    code: str,
    *,
    ordinal: int | None = None,
    observation: RevProofObservation | None = None,
    stream: str | None = None,
) -> RevProofFailure:
    run_id = (
        _bounded_text(
            observation.run_id,
            maximum_bytes=256,
            printable=True,
        )
        if observation is not None
        else None
    )
    return RevProofFailure(
        code=code,
        attempt_ordinal=ordinal,
        run_id=run_id,
        stream=stream,
    )


def _bounded_text(
    value: object,
    *,
    maximum_bytes: int,
    printable: bool = False,
) -> str | None:
    if type(value) is not str:
        return None
    if not value or len(value) > maximum_bytes:
        return None
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return None
    if (
        len(encoded) > maximum_bytes
        or (printable and not all(character.isprintable() for character in value))
    ):
        return None
    return value


def _valid_artifact_field(value: object, *, digest: bool = False) -> bool:
    if digest:
        return type(value) is str and _SHA256.fullmatch(value) is not None
    return (
        _bounded_text(
            value,
            maximum_bytes=256,
            printable=True,
        )
        is not None
    )


def _normalized_stream_evidence(
    stream: object,
) -> RevProofStreamEvidence:
    if type(stream) is not RevProofStreamEvidence:
        return RevProofStreamEvidence(
            artifact_id=None,
            artifact_sha256=None,
            artifact_size_bytes=None,
            capture_complete=False,
            truncation_known=False,
            truncated=None,
            capture_error="<present>",
            durable_artifact_complete=False,
        )
    artifact_id = _bounded_text(
        stream.artifact_id,
        maximum_bytes=256,
        printable=True,
    )
    artifact_sha256 = (
        stream.artifact_sha256
        if type(stream.artifact_sha256) is str
        and _SHA256.fullmatch(stream.artifact_sha256) is not None
        else None
    )
    artifact_size = (
        stream.artifact_size_bytes
        if type(stream.artifact_size_bytes) is int
        and 0
        <= stream.artifact_size_bytes
        <= REV_STDIN_PROOF_MAX_STREAM_BYTES
        else None
    )
    return RevProofStreamEvidence(
        artifact_id=artifact_id,
        artifact_sha256=artifact_sha256,
        artifact_size_bytes=artifact_size,
        capture_complete=stream.capture_complete is True,
        truncation_known=stream.truncation_known is True,
        truncated=(
            stream.truncated
            if type(stream.truncated) is bool
            else None
        ),
        capture_error=(
            None if stream.capture_error is None else "<present>"
        ),
        durable_artifact_complete=(
            stream.durable_artifact_complete is True
        ),
    )


def _bounded_exit_code(value: object) -> int | None:
    if type(value) is int and 0 <= value <= 255:
        return value
    return None


def _normalized_observation_evidence(
    observation: RevProofObservation,
) -> RevProofObservation:
    flags = (
        observation.flag_values
        if _flag_values_are_valid(observation.flag_values)
        else ()
    )
    return replace(
        observation,
        run_id=(
            _bounded_text(
                observation.run_id,
                maximum_bytes=256,
                printable=True,
            )
            or ""
        ),
        phase=(
            _bounded_text(
                observation.phase,
                maximum_bytes=16,
                printable=True,
            )
            or ""
        ),
        mutation_id=(
            _bounded_text(
                observation.mutation_id,
                maximum_bytes=64,
                printable=True,
            )
            or ""
        ),
        input_sha256=(
            observation.input_sha256
            if type(observation.input_sha256) is str
            and _SHA256.fullmatch(observation.input_sha256) is not None
            else ""
        ),
        input_size_bytes=(
            observation.input_size_bytes
            if type(observation.input_size_bytes) is int
            and 0
            <= observation.input_size_bytes
            <= REV_STDIN_PROOF_MAX_ACCEPTED_INPUT_BYTES
            else -1
        ),
        source_manifest_sha256=(
            observation.source_manifest_sha256
            if type(observation.source_manifest_sha256) is str
            and _SHA256.fullmatch(
                observation.source_manifest_sha256
            )
            is not None
            else ""
        ),
        clean_workspace=observation.clean_workspace is True,
        target_exit_code=_bounded_exit_code(
            observation.target_exit_code
        ),
        runner_exit_code=_bounded_exit_code(
            observation.runner_exit_code
        ),
        ctfwrap_exit_code=_bounded_exit_code(
            observation.ctfwrap_exit_code
        ),
        timed_out=observation.timed_out is True,
        orchestration_status=(
            _bounded_text(
                observation.orchestration_status,
                maximum_bytes=64,
                printable=True,
            )
            or ""
        ),
        orchestration_error=(
            None
            if observation.orchestration_error is None
            else "<present>"
        ),
        stream_capture_error=(
            None
            if observation.stream_capture_error is None
            else "<present>"
        ),
        stdout=_normalized_stream_evidence(observation.stdout),
        stderr=_normalized_stream_evidence(observation.stderr),
        flag_scanner_contract=(
            observation.flag_scanner_contract
            if type(observation.flag_scanner_contract) is str
            and observation.flag_scanner_contract
            == REV_STDIN_PROOF_FLAG_SCANNER_CONTRACT
            else ""
        ),
        flag_scan_complete=observation.flag_scan_complete is True,
        flag_scan_error=(
            None
            if observation.flag_scan_error is None
            else "<present>"
        ),
        flag_values_overflow=observation.flag_values_overflow is True,
        flag_values=flags,
        selected_candidate_direct_output=(
            observation.selected_candidate_direct_output is True
        ),
    )


def _stream_failures(
    stream_name: str,
    stream: object,
    *,
    ordinal: int,
    observation: RevProofObservation,
) -> list[RevProofFailure]:
    if type(stream) is not RevProofStreamEvidence:
        return [
            _failure(
                "durable_artifact_incomplete",
                ordinal=ordinal,
                observation=observation,
                stream=stream_name,
            )
        ]

    failures: list[RevProofFailure] = []
    if stream.capture_complete is not True:
        failures.append(
            _failure(
                "capture_incomplete",
                ordinal=ordinal,
                observation=observation,
                stream=stream_name,
            )
        )
    if stream.truncation_known is not True:
        failures.append(
            _failure(
                "capture_truncation_unknown",
                ordinal=ordinal,
                observation=observation,
                stream=stream_name,
            )
        )
    if stream.truncated is not False:
        failures.append(
            _failure(
                "capture_truncated",
                ordinal=ordinal,
                observation=observation,
                stream=stream_name,
            )
        )
    if stream.capture_error is not None:
        failures.append(
            _failure(
                "capture_error",
                ordinal=ordinal,
                observation=observation,
                stream=stream_name,
            )
        )
    artifact_complete = (
        stream.durable_artifact_complete is True
        and _valid_artifact_field(stream.artifact_id)
        and _valid_artifact_field(stream.artifact_sha256, digest=True)
        and type(stream.artifact_size_bytes) is int
        and 0
        <= stream.artifact_size_bytes
        <= REV_STDIN_PROOF_MAX_STREAM_BYTES
    )
    if not artifact_complete:
        failures.append(
            _failure(
                "durable_artifact_incomplete",
                ordinal=ordinal,
                observation=observation,
                stream=stream_name,
            )
        )
    return failures


def _flag_values_are_valid(values: object) -> bool:
    if type(values) is not tuple:
        return False
    if len(values) > REV_STDIN_PROOF_MAX_FLAG_VALUES:
        return False
    total_chars = 0
    total_bytes = 0
    seen: set[str] = set()
    for value in values:
        if type(value) is not str or not value or value in seen:
            return False
        if (
            len(value) > REV_STDIN_PROOF_MAX_CANDIDATE_CHARS
            or not all(character.isprintable() for character in value)
        ):
            return False
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            return False
        if len(encoded) > REV_STDIN_PROOF_MAX_CANDIDATE_BYTES:
            return False
        total_chars += len(value)
        total_bytes += len(encoded)
        if total_chars > REV_STDIN_PROOF_MAX_FLAG_CHARS:
            return False
        if total_bytes > REV_STDIN_PROOF_MAX_FLAG_BYTES:
            return False
        seen.add(value)
    return True


def _observation_failures(
    observation: RevProofObservation,
    expected: RevProofInput,
    *,
    candidate: str,
    source_manifest_sha256: str,
) -> list[RevProofFailure]:
    ordinal = expected.ordinal
    failures: list[RevProofFailure] = []

    if (
        type(observation.phase) is not str
        or observation.phase != expected.phase
        or type(observation.mutation_id) is not str
        or observation.mutation_id != expected.mutation_id
    ):
        failures.append(
            _failure(
                "attempt_order_mismatch",
                ordinal=ordinal,
                observation=observation,
            )
        )
    if (
        type(observation.input_sha256) is not str
        or observation.input_sha256 != expected.sha256
        or type(observation.input_size_bytes) is not int
        or observation.input_size_bytes != expected.size_bytes
    ):
        failures.append(
            _failure(
                "input_binding_mismatch",
                ordinal=ordinal,
                observation=observation,
            )
        )
    if (
        type(observation.source_manifest_sha256) is not str
        or observation.source_manifest_sha256 != source_manifest_sha256
    ):
        failures.append(
            _failure(
                "source_manifest_mismatch",
                ordinal=ordinal,
                observation=observation,
            )
        )
    if observation.clean_workspace is not True:
        failures.append(
            _failure(
                "workspace_not_clean",
                ordinal=ordinal,
                observation=observation,
            )
        )
    if observation.timed_out is not False:
        failures.append(
            _failure(
                "timed_out",
                ordinal=ordinal,
                observation=observation,
            )
        )
    if (
        type(observation.orchestration_status) is not str
        or observation.orchestration_status != "completed"
    ):
        failures.append(
            _failure(
                "orchestration_incomplete",
                ordinal=ordinal,
                observation=observation,
            )
        )
    if observation.orchestration_error is not None:
        failures.append(
            _failure(
                "orchestration_error",
                ordinal=ordinal,
                observation=observation,
            )
        )
    if observation.stream_capture_error is not None:
        failures.append(
            _failure(
                "capture_error",
                ordinal=ordinal,
                observation=observation,
            )
        )
    target_exit = _bounded_exit_code(observation.target_exit_code)
    runner_exit = _bounded_exit_code(observation.runner_exit_code)
    ctfwrap_exit = _bounded_exit_code(observation.ctfwrap_exit_code)
    if target_exit is None:
        failures.append(
            _failure(
                "target_exit_unavailable",
                ordinal=ordinal,
                observation=observation,
            )
        )
    elif target_exit == _TRANSPORT_INCONCLUSIVE_EXIT:
        failures.append(
            _failure(
                "target_transport_exit_125",
                ordinal=ordinal,
                observation=observation,
            )
        )
    if runner_exit is None:
        failures.append(
            _failure(
                "runner_exit_unavailable",
                ordinal=ordinal,
                observation=observation,
            )
        )
    elif runner_exit == _TRANSPORT_INCONCLUSIVE_EXIT:
        failures.append(
            _failure(
                "runner_transport_exit_125",
                ordinal=ordinal,
                observation=observation,
            )
        )
    if ctfwrap_exit is None:
        failures.append(
            _failure(
                "ctfwrap_exit_unavailable",
                ordinal=ordinal,
                observation=observation,
            )
        )
    elif ctfwrap_exit == _TRANSPORT_INCONCLUSIVE_EXIT:
        failures.append(
            _failure(
                "ctfwrap_transport_exit_125",
                ordinal=ordinal,
                observation=observation,
            )
        )
    if (
        target_exit is not None
        and runner_exit is not None
        and ctfwrap_exit is not None
        and not (target_exit == runner_exit == ctfwrap_exit)
    ):
        failures.append(
            _failure(
                "exit_status_mismatch",
                ordinal=ordinal,
                observation=observation,
            )
        )

    failures.extend(
        _stream_failures(
            "stdout",
            observation.stdout,
            ordinal=ordinal,
            observation=observation,
        )
    )
    failures.extend(
        _stream_failures(
            "stderr",
            observation.stderr,
            ordinal=ordinal,
            observation=observation,
        )
    )
    flags_valid = _flag_values_are_valid(observation.flag_values)
    if (
        type(observation.flag_scanner_contract) is not str
        or observation.flag_scanner_contract
        != REV_STDIN_PROOF_FLAG_SCANNER_CONTRACT
    ):
        failures.append(
            _failure(
                "flag_scanner_contract_mismatch",
                ordinal=ordinal,
                observation=observation,
            )
        )
    if observation.flag_scan_complete is not True:
        failures.append(
            _failure(
                "flag_scan_incomplete",
                ordinal=ordinal,
                observation=observation,
            )
        )
    if observation.flag_scan_error is not None:
        failures.append(
            _failure(
                "flag_scan_error",
                ordinal=ordinal,
                observation=observation,
            )
        )
    if observation.flag_values_overflow is not False:
        failures.append(
            _failure(
                "flag_values_overflow",
                ordinal=ordinal,
                observation=observation,
            )
        )
    if not flags_valid:
        failures.append(
            _failure(
                "flag_evidence_invalid",
                ordinal=ordinal,
                observation=observation,
            )
        )

    if expected.phase == _PHASE_POSITIVE:
        if observation.selected_candidate_direct_output is not True:
            failures.append(
                _failure(
                    "selected_candidate_not_direct",
                    ordinal=ordinal,
                    observation=observation,
                )
            )
        if flags_valid and candidate not in observation.flag_values:
            failures.append(
                _failure(
                    "selected_candidate_not_direct",
                    ordinal=ordinal,
                    observation=observation,
                )
            )
    elif (
        observation.selected_candidate_direct_output is not False
        or (flags_valid and bool(observation.flag_values))
    ):
        failures.append(
            _failure(
                "negative_flag_candidate_observed",
                ordinal=ordinal,
                observation=observation,
            )
        )
    return failures


def _artifact_reuse_failures(
    observations: tuple[RevProofObservation, ...],
) -> list[RevProofFailure]:
    failures: list[RevProofFailure] = []
    seen: set[str] = set()
    for ordinal, observation in enumerate(observations, start=1):
        for stream_name, stream in (
            ("stdout", observation.stdout),
            ("stderr", observation.stderr),
        ):
            if type(stream) is not RevProofStreamEvidence:
                continue
            artifact_id = stream.artifact_id
            if not _valid_artifact_field(artifact_id):
                continue
            assert isinstance(artifact_id, str)
            if artifact_id in seen:
                failures.append(
                    _failure(
                        "durable_artifact_reused",
                        ordinal=ordinal,
                        observation=observation,
                        stream=stream_name,
                    )
                )
            else:
                seen.add(artifact_id)
    return failures


def _preflight_failure_result(
    candidate: object,
    source_manifest_sha256: object,
    accepted_input: object,
    code: str,
) -> tuple[ProofResult, RevProofEvaluation]:
    try:
        _candidate_bytes(candidate)
    except RevProofPreflightError:
        safe_candidate = ""
    else:
        assert isinstance(candidate, str)
        safe_candidate = candidate
    safe_manifest = (
        source_manifest_sha256
        if type(source_manifest_sha256) is str
        and _SHA256.fullmatch(source_manifest_sha256) is not None
        else ""
    )
    payload = (
        accepted_input
        if type(accepted_input) is bytes
        and len(accepted_input)
        <= REV_STDIN_PROOF_MAX_ACCEPTED_INPUT_BYTES
        else None
    )
    failure = RevProofFailure(code)
    evaluation = RevProofEvaluation(
        candidate=safe_candidate,
        source_manifest_sha256=safe_manifest,
        accepted_input_sha256=(
            _sha256(payload) if payload is not None else None
        ),
        accepted_input_size_bytes=(
            len(payload) if payload is not None else None
        ),
        plan=(),
        observations=(),
        failures=(failure,),
        positive_successes=0,
        passed=False,
    )
    result = ProofResult(
        passed=False,
        candidate=safe_candidate,
        policy_mode=REV_STDIN_PROOF_PROTOCOL,
        successful_attempts=0,
        required_attempts=3,
        total_attempts=0,
        source_manifest_sha256=safe_manifest,
        failures=(code,),
        run_ids=(),
    )
    return result, evaluation


def evaluate_rev_stdin_proof(
    candidate: str,
    accepted_input: bytes,
    source_manifest_sha256: str,
    observations: Iterable[RevProofObservation],
) -> tuple[ProofResult, RevProofEvaluation]:
    """Evaluate exactly three positive and three mutation-control runs.

    Preflight failures intentionally do not consume ``observations``.  This
    prevents a candidate copied into the accepted-input artifact from ever
    entering the execution/evaluation path.
    """

    try:
        plan = build_rev_stdin_proof_plan(candidate, accepted_input)
    except RevProofPreflightError as error:
        return _preflight_failure_result(
            candidate,
            source_manifest_sha256,
            accepted_input,
            error.code,
        )
    if (
        type(source_manifest_sha256) is not str
        or _SHA256.fullmatch(source_manifest_sha256) is None
    ):
        return _preflight_failure_result(
            candidate,
            source_manifest_sha256,
            accepted_input,
            "source_manifest_invalid",
        )

    failures: list[RevProofFailure] = []
    # Seven is enough to distinguish the valid six-run protocol from an
    # unbounded or oversized iterable while keeping evidence bounded.
    try:
        iterator = iter(observations)
    except Exception:
        observed: tuple[object, ...] = ()
        failures.append(RevProofFailure("observations_not_iterable"))
    else:
        try:
            observed = tuple(
                islice(iterator, _EXPECTED_ATTEMPT_COUNT + 1)
            )
        except Exception:
            observed = ()
            failures.append(
                RevProofFailure("observation_iteration_failed")
            )
    retained = observed[:_EXPECTED_ATTEMPT_COUNT]
    if (
        len(observed) != _EXPECTED_ATTEMPT_COUNT
        and not any(
            item.code
            in {
                "observations_not_iterable",
                "observation_iteration_failed",
            }
            for item in failures
        )
    ):
        failures.append(RevProofFailure("attempt_count_mismatch"))

    typed_observations: list[RevProofObservation] = []
    for index, raw_observation in enumerate(retained, start=1):
        if type(raw_observation) is not RevProofObservation:
            failures.append(
                RevProofFailure(
                    "observation_type_invalid",
                    attempt_ordinal=index,
                )
            )
            continue
        typed_observations.append(raw_observation)

    run_ids: set[str] = set()
    for index, observation in enumerate(typed_observations, start=1):
        if _bounded_text(
            observation.run_id,
            maximum_bytes=256,
            printable=True,
        ) is None:
            failures.append(
                _failure(
                    "run_id_invalid",
                    ordinal=index,
                    observation=observation,
                )
            )
        elif observation.run_id in run_ids:
            failures.append(
                _failure(
                    "duplicate_run_id",
                    ordinal=index,
                    observation=observation,
                )
            )
        else:
            run_ids.add(observation.run_id)

    # Only compare positional observations when all six positions exist and
    # are typed.  Count/type failures otherwise remain the complete bounded
    # explanation instead of assigning an observation to the wrong input.
    if (
        len(observed) == _EXPECTED_ATTEMPT_COUNT
        and len(typed_observations) == _EXPECTED_ATTEMPT_COUNT
    ):
        for expected, observation in zip(
            plan,
            typed_observations,
            strict=True,
        ):
            failures.extend(
                _observation_failures(
                    observation,
                    expected,
                    candidate=candidate,
                    source_manifest_sha256=source_manifest_sha256,
                )
            )
        failures.extend(
            _artifact_reuse_failures(tuple(typed_observations))
        )

    # Exact duplicate failures carry no additional information.  Stable
    # first-occurrence de-duplication also bounds generic ProofResult text.
    unique_failures = tuple(
        {
            (
                item.code,
                item.attempt_ordinal,
                item.run_id,
                item.stream,
            ): item
            for item in failures
        }.values()
    )

    failed_positive_ordinals = {
        item.attempt_ordinal
        for item in unique_failures
        if item.attempt_ordinal in {1, 2, 3}
    }
    positive_successes = (
        3 - len(failed_positive_ordinals)
        if len(observed) == _EXPECTED_ATTEMPT_COUNT
        and len(typed_observations) == _EXPECTED_ATTEMPT_COUNT
        else 0
    )
    passed = not unique_failures
    normalized_observations = tuple(
        _normalized_observation_evidence(item)
        for item in typed_observations
    )
    evaluation = RevProofEvaluation(
        candidate=candidate,
        source_manifest_sha256=source_manifest_sha256,
        accepted_input_sha256=_sha256(accepted_input),
        accepted_input_size_bytes=len(accepted_input),
        plan=plan,
        observations=normalized_observations,
        failures=unique_failures,
        positive_successes=positive_successes,
        passed=passed,
    )
    proof_result = ProofResult(
        passed=passed,
        candidate=candidate,
        policy_mode=REV_STDIN_PROOF_PROTOCOL,
        successful_attempts=positive_successes,
        required_attempts=3,
        total_attempts=len(normalized_observations),
        source_manifest_sha256=source_manifest_sha256,
        failures=tuple(item.token() for item in unique_failures),
        run_ids=tuple(item.run_id for item in normalized_observations),
    )
    return proof_result, evaluation


_REV_PROOF_EVALUATION_KEYS = frozenset(
    {
        "accepted_input_sha256",
        "accepted_input_size_bytes",
        "candidate",
        "failure_codes",
        "failures",
        "observations",
        "passed",
        "plan",
        "positive_successes",
        "protocol",
        "required_negative_attempts",
        "required_positive_attempts",
        "schema_version",
        "source_manifest_sha256",
        "total_attempts",
        "transport_inconclusive",
        "verdict",
    }
)
_REV_PROOF_INPUT_RECORD_KEYS = frozenset(
    {
        "input_sha256",
        "input_size_bytes",
        "mutation_id",
        "ordinal",
        "phase",
    }
)
_REV_PROOF_OBSERVATION_KEYS = frozenset(
    {
        "clean_workspace",
        "ctfwrap_exit_code",
        "flag_scan_complete",
        "flag_scan_error",
        "flag_scanner_contract",
        "flag_values",
        "flag_values_overflow",
        "input_sha256",
        "input_size_bytes",
        "mutation_id",
        "orchestration_error",
        "orchestration_status",
        "phase",
        "run_id",
        "runner_exit_code",
        "selected_candidate_direct_output",
        "source_manifest_sha256",
        "stderr",
        "stdout",
        "stream_capture_error",
        "target_exit_code",
        "timed_out",
    }
)
_REV_PROOF_STREAM_KEYS = frozenset(
    {
        "artifact_id",
        "artifact_sha256",
        "artifact_size_bytes",
        "capture_complete",
        "capture_error",
        "durable_artifact_complete",
        "truncated",
        "truncation_known",
    }
)
_REV_PROOF_FAILURE_KEYS = frozenset(
    {
        "attempt_ordinal",
        "code",
        "run_id",
        "stream",
    }
)
_REV_PROOF_MUTATION_IDS = frozenset(
    (
        *REV_STDIN_PROOF_POSITIVE_MUTATION_IDS,
        *REV_STDIN_PROOF_NONEMPTY_NEGATIVE_MUTATION_IDS,
        *REV_STDIN_PROOF_EMPTY_NEGATIVE_MUTATION_IDS,
    )
)
_REV_PROOF_PREFLIGHT_FAILURE_CODES = frozenset(
    {
        "accepted_input_contains_candidate",
        "accepted_input_too_large",
        "accepted_input_type_invalid",
        "candidate_invalid",
        "derived_input_contains_candidate",
        "source_manifest_invalid",
    }
)
_REV_PROOF_STREAM_FAILURE_CODES = frozenset(
    {
        "capture_error",
        "capture_incomplete",
        "capture_truncated",
        "capture_truncation_unknown",
        "durable_artifact_incomplete",
        "durable_artifact_reused",
    }
)
_REV_PROOF_MAX_FAILURES = (
    _EXPECTED_ATTEMPT_COUNT * len(REV_STDIN_PROOF_FAILURE_CODES)
)
_REV_PROOF_EVIDENCE_ERROR = "invalid persisted Rev proof evidence"


def _reject_persisted_evidence() -> None:
    raise ValueError(_REV_PROOF_EVIDENCE_ERROR)


def _exact_evidence_mapping(
    value: object,
    keys: frozenset[str],
) -> dict[str, object]:
    if type(value) is not dict or len(value) != len(keys):
        _reject_persisted_evidence()
    assert isinstance(value, dict)
    for key in value:
        if (
            type(key) is not str
            or len(key) > 64
            or key not in keys
        ):
            _reject_persisted_evidence()
    return value


def _exact_evidence_list(
    value: object,
    *,
    maximum_items: int,
    exact_items: int | None = None,
) -> list[object]:
    if type(value) is not list:
        _reject_persisted_evidence()
    assert isinstance(value, list)
    item_count = len(value)
    if (
        item_count > maximum_items
        or (
            exact_items is not None
            and item_count != exact_items
        )
    ):
        _reject_persisted_evidence()
    return value


def _exact_evidence_bool(value: object) -> bool:
    if type(value) is not bool:
        _reject_persisted_evidence()
    assert isinstance(value, bool)
    return value


def _exact_evidence_int(
    value: object,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _reject_persisted_evidence()
    assert isinstance(value, int)
    return value


def _exact_evidence_optional_int(
    value: object,
    *,
    minimum: int,
    maximum: int,
) -> int | None:
    if value is None:
        return None
    return _exact_evidence_int(
        value,
        minimum=minimum,
        maximum=maximum,
    )


def _exact_evidence_text(
    value: object,
    *,
    maximum_chars: int,
    maximum_bytes: int,
    allow_empty: bool = False,
    printable: bool = True,
) -> str:
    if (
        type(value) is not str
        or len(value) > maximum_chars
        or (not value and not allow_empty)
    ):
        _reject_persisted_evidence()
    assert isinstance(value, str)
    if printable and not all(character.isprintable() for character in value):
        _reject_persisted_evidence()
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _reject_persisted_evidence()
    if len(encoded) > maximum_bytes:
        _reject_persisted_evidence()
    return value


def _exact_evidence_digest(
    value: object,
    *,
    allow_empty: bool = False,
) -> str:
    if allow_empty and type(value) is str and not value:
        return ""
    if (
        type(value) is not str
        or len(value) != 64
        or _SHA256.fullmatch(value) is None
    ):
        _reject_persisted_evidence()
    assert isinstance(value, str)
    return value


def _exact_present_marker(value: object) -> str | None:
    if value is None:
        return None
    if type(value) is not str or value != "<present>":
        _reject_persisted_evidence()
    return value


def _parse_rev_proof_stream_evidence(
    value: object,
) -> RevProofStreamEvidence:
    mapping = _exact_evidence_mapping(value, _REV_PROOF_STREAM_KEYS)
    artifact_id_value = mapping["artifact_id"]
    artifact_id = (
        None
        if artifact_id_value is None
        else _exact_evidence_text(
            artifact_id_value,
            maximum_chars=256,
            maximum_bytes=256,
        )
    )
    artifact_sha_value = mapping["artifact_sha256"]
    artifact_sha256 = (
        None
        if artifact_sha_value is None
        else _exact_evidence_digest(artifact_sha_value)
    )
    artifact_size_bytes = _exact_evidence_optional_int(
        mapping["artifact_size_bytes"],
        minimum=0,
        maximum=REV_STDIN_PROOF_MAX_STREAM_BYTES,
    )
    truncated_value = mapping["truncated"]
    if truncated_value is not None and type(truncated_value) is not bool:
        _reject_persisted_evidence()
    return RevProofStreamEvidence(
        artifact_id=artifact_id,
        artifact_sha256=artifact_sha256,
        artifact_size_bytes=artifact_size_bytes,
        capture_complete=_exact_evidence_bool(
            mapping["capture_complete"]
        ),
        truncation_known=_exact_evidence_bool(
            mapping["truncation_known"]
        ),
        truncated=truncated_value,
        capture_error=_exact_present_marker(mapping["capture_error"]),
        durable_artifact_complete=_exact_evidence_bool(
            mapping["durable_artifact_complete"]
        ),
    )


def _parse_rev_proof_observation(
    value: object,
) -> RevProofObservation:
    mapping = _exact_evidence_mapping(
        value,
        _REV_PROOF_OBSERVATION_KEYS,
    )
    run_id = _exact_evidence_text(
        mapping["run_id"],
        maximum_chars=256,
        maximum_bytes=256,
        allow_empty=True,
    )
    phase = _exact_evidence_text(
        mapping["phase"],
        maximum_chars=16,
        maximum_bytes=16,
        allow_empty=True,
    )
    mutation_id = _exact_evidence_text(
        mapping["mutation_id"],
        maximum_chars=64,
        maximum_bytes=64,
        allow_empty=True,
    )
    orchestration_status = _exact_evidence_text(
        mapping["orchestration_status"],
        maximum_chars=64,
        maximum_bytes=64,
        allow_empty=True,
    )
    scanner_contract = _exact_evidence_text(
        mapping["flag_scanner_contract"],
        maximum_chars=64,
        maximum_bytes=64,
        allow_empty=True,
    )
    if scanner_contract not in {
        "",
        REV_STDIN_PROOF_FLAG_SCANNER_CONTRACT,
    }:
        _reject_persisted_evidence()

    flag_values_list = _exact_evidence_list(
        mapping["flag_values"],
        maximum_items=REV_STDIN_PROOF_MAX_FLAG_VALUES,
    )
    flag_values: list[str] = []
    for flag_value in flag_values_list:
        flag_values.append(
            _exact_evidence_text(
                flag_value,
                maximum_chars=REV_STDIN_PROOF_MAX_CANDIDATE_CHARS,
                maximum_bytes=REV_STDIN_PROOF_MAX_CANDIDATE_BYTES,
            )
        )
    immutable_flag_values = tuple(flag_values)
    if not _flag_values_are_valid(immutable_flag_values):
        _reject_persisted_evidence()

    return RevProofObservation(
        run_id=run_id,
        phase=phase,
        mutation_id=mutation_id,
        input_sha256=_exact_evidence_digest(
            mapping["input_sha256"],
            allow_empty=True,
        ),
        input_size_bytes=_exact_evidence_int(
            mapping["input_size_bytes"],
            minimum=-1,
            maximum=REV_STDIN_PROOF_MAX_ACCEPTED_INPUT_BYTES,
        ),
        source_manifest_sha256=_exact_evidence_digest(
            mapping["source_manifest_sha256"],
            allow_empty=True,
        ),
        clean_workspace=_exact_evidence_bool(
            mapping["clean_workspace"]
        ),
        target_exit_code=_exact_evidence_optional_int(
            mapping["target_exit_code"],
            minimum=0,
            maximum=255,
        ),
        runner_exit_code=_exact_evidence_optional_int(
            mapping["runner_exit_code"],
            minimum=0,
            maximum=255,
        ),
        ctfwrap_exit_code=_exact_evidence_optional_int(
            mapping["ctfwrap_exit_code"],
            minimum=0,
            maximum=255,
        ),
        timed_out=_exact_evidence_bool(mapping["timed_out"]),
        orchestration_status=orchestration_status,
        orchestration_error=_exact_present_marker(
            mapping["orchestration_error"]
        ),
        stream_capture_error=_exact_present_marker(
            mapping["stream_capture_error"]
        ),
        stdout=_parse_rev_proof_stream_evidence(mapping["stdout"]),
        stderr=_parse_rev_proof_stream_evidence(mapping["stderr"]),
        flag_scanner_contract=scanner_contract,
        flag_scan_complete=_exact_evidence_bool(
            mapping["flag_scan_complete"]
        ),
        flag_scan_error=_exact_present_marker(
            mapping["flag_scan_error"]
        ),
        flag_values_overflow=_exact_evidence_bool(
            mapping["flag_values_overflow"]
        ),
        flag_values=immutable_flag_values,
        selected_candidate_direct_output=_exact_evidence_bool(
            mapping["selected_candidate_direct_output"]
        ),
    )


def _parse_rev_proof_input_record(
    value: object,
) -> RevProofInputRecord:
    mapping = _exact_evidence_mapping(
        value,
        _REV_PROOF_INPUT_RECORD_KEYS,
    )
    phase = _exact_evidence_text(
        mapping["phase"],
        maximum_chars=16,
        maximum_bytes=16,
    )
    if phase not in {_PHASE_POSITIVE, _PHASE_NEGATIVE}:
        _reject_persisted_evidence()
    mutation_id = _exact_evidence_text(
        mapping["mutation_id"],
        maximum_chars=64,
        maximum_bytes=64,
    )
    if mutation_id not in _REV_PROOF_MUTATION_IDS:
        _reject_persisted_evidence()
    return RevProofInputRecord(
        ordinal=_exact_evidence_int(
            mapping["ordinal"],
            minimum=1,
            maximum=_EXPECTED_ATTEMPT_COUNT,
        ),
        phase=phase,
        mutation_id=mutation_id,
        input_sha256=_exact_evidence_digest(
            mapping["input_sha256"]
        ),
        input_size_bytes=_exact_evidence_int(
            mapping["input_size_bytes"],
            minimum=0,
            maximum=REV_STDIN_PROOF_MAX_ACCEPTED_INPUT_BYTES,
        ),
    )


def _parse_rev_proof_failure(value: object) -> RevProofFailure:
    mapping = _exact_evidence_mapping(
        value,
        _REV_PROOF_FAILURE_KEYS,
    )
    code = _exact_evidence_text(
        mapping["code"],
        maximum_chars=64,
        maximum_bytes=64,
    )
    if code not in REV_STDIN_PROOF_FAILURE_CODES:
        _reject_persisted_evidence()
    attempt_ordinal = _exact_evidence_optional_int(
        mapping["attempt_ordinal"],
        minimum=1,
        maximum=_EXPECTED_ATTEMPT_COUNT,
    )
    run_id_value = mapping["run_id"]
    run_id = (
        None
        if run_id_value is None
        else _exact_evidence_text(
            run_id_value,
            maximum_chars=256,
            maximum_bytes=256,
        )
    )
    stream_value = mapping["stream"]
    if stream_value is not None and (
        type(stream_value) is not str
        or stream_value not in {"stdout", "stderr"}
    ):
        _reject_persisted_evidence()
    if (
        attempt_ordinal is None
        and (run_id is not None or stream_value is not None)
    ):
        _reject_persisted_evidence()
    if (
        stream_value is not None
        and code not in _REV_PROOF_STREAM_FAILURE_CODES
    ):
        _reject_persisted_evidence()
    return RevProofFailure(
        code=code,
        attempt_ordinal=attempt_ordinal,
        run_id=run_id,
        stream=stream_value,
    )


def _validate_rev_proof_record_plan(
    record: RevProofEvaluationRecord,
) -> None:
    plan = record.plan
    if len(plan) not in {0, _EXPECTED_ATTEMPT_COUNT}:
        _reject_persisted_evidence()
    if not plan:
        if (
            record.observations
            or record.positive_successes != 0
            or record.passed
            or len(record.failures) != 1
            or record.failures[0].code
            not in _REV_PROOF_PREFLIGHT_FAILURE_CODES
            or record.failures[0].attempt_ordinal is not None
            or record.failures[0].run_id is not None
            or record.failures[0].stream is not None
        ):
            _reject_persisted_evidence()
        return

    if (
        not record.candidate
        or not record.source_manifest_sha256
        or record.accepted_input_sha256 is None
        or record.accepted_input_size_bytes is None
    ):
        _reject_persisted_evidence()
    accepted_size = record.accepted_input_size_bytes
    accepted_sha256 = record.accepted_input_sha256
    assert accepted_size is not None
    assert accepted_sha256 is not None
    negative_ids = (
        REV_STDIN_PROOF_NONEMPTY_NEGATIVE_MUTATION_IDS
        if accepted_size
        else REV_STDIN_PROOF_EMPTY_NEGATIVE_MUTATION_IDS
    )
    expected_ids = (
        *REV_STDIN_PROOF_POSITIVE_MUTATION_IDS,
        *negative_ids,
    )
    expected_phases = (
        *(_PHASE_POSITIVE for _ in range(3)),
        *(_PHASE_NEGATIVE for _ in range(3)),
    )
    negative_sizes = (
        (accepted_size, accepted_size, accepted_size - 1)
        if accepted_size
        else (1, 1, 1)
    )
    expected_sizes = (
        accepted_size,
        accepted_size,
        accepted_size,
        *negative_sizes,
    )
    for index, item in enumerate(plan, start=1):
        if (
            item.ordinal != index
            or item.phase != expected_phases[index - 1]
            or item.mutation_id != expected_ids[index - 1]
            or item.input_size_bytes != expected_sizes[index - 1]
        ):
            _reject_persisted_evidence()
        if index <= 3 and item.input_sha256 != accepted_sha256:
            _reject_persisted_evidence()
    if not accepted_size:
        expected_empty_hashes = (
            _sha256(b""),
            _sha256(b""),
            _sha256(b""),
            _sha256(b"\x00"),
            _sha256(b"\x0a"),
            _sha256(b"\xff"),
        )
        if tuple(item.input_sha256 for item in plan) != (
            expected_empty_hashes
        ):
            _reject_persisted_evidence()


def _validate_rev_proof_record_uniqueness(
    record: RevProofEvaluationRecord,
) -> None:
    failure_identities: set[tuple[object, ...]] = set()
    for failure in record.failures:
        identity = (
            failure.code,
            failure.attempt_ordinal,
            failure.run_id,
            failure.stream,
        )
        if identity in failure_identities:
            _reject_persisted_evidence()
        failure_identities.add(identity)
    if not record.passed:
        return

    run_ids: set[str] = set()
    artifact_ids: set[str] = set()
    for observation in record.observations:
        if observation.run_id in run_ids:
            _reject_persisted_evidence()
        run_ids.add(observation.run_id)
        for stream in (observation.stdout, observation.stderr):
            if stream.artifact_id is None:
                continue
            if stream.artifact_id in artifact_ids:
                _reject_persisted_evidence()
            artifact_ids.add(stream.artifact_id)


def _validate_confirmed_rev_proof_record(
    record: RevProofEvaluationRecord,
) -> None:
    if not record.passed:
        return
    if (
        len(record.plan) != _EXPECTED_ATTEMPT_COUNT
        or len(record.observations) != _EXPECTED_ATTEMPT_COUNT
        or record.positive_successes != 3
    ):
        _reject_persisted_evidence()
    for planned, observation in zip(
        record.plan,
        record.observations,
        strict=True,
    ):
        if (
            observation.phase != planned.phase
            or observation.mutation_id != planned.mutation_id
            or observation.input_sha256 != planned.input_sha256
            or observation.input_size_bytes != planned.input_size_bytes
            or observation.source_manifest_sha256
            != record.source_manifest_sha256
            or observation.clean_workspace is not True
            or observation.timed_out is not False
            or observation.orchestration_status != "completed"
            or observation.orchestration_error is not None
            or observation.stream_capture_error is not None
            or observation.target_exit_code is None
            or observation.target_exit_code == _TRANSPORT_INCONCLUSIVE_EXIT
            or observation.runner_exit_code
            != observation.target_exit_code
            or observation.ctfwrap_exit_code
            != observation.target_exit_code
            or observation.flag_scanner_contract
            != REV_STDIN_PROOF_FLAG_SCANNER_CONTRACT
            or observation.flag_scan_complete is not True
            or observation.flag_scan_error is not None
            or observation.flag_values_overflow is not False
        ):
            _reject_persisted_evidence()
        for stream in (observation.stdout, observation.stderr):
            if (
                stream.capture_complete is not True
                or stream.truncation_known is not True
                or stream.truncated is not False
                or stream.capture_error is not None
                or stream.durable_artifact_complete is not True
                or stream.artifact_id is None
                or stream.artifact_sha256 is None
                or stream.artifact_size_bytes is None
            ):
                _reject_persisted_evidence()
        if planned.phase == _PHASE_POSITIVE:
            if (
                observation.selected_candidate_direct_output is not True
                or record.candidate not in observation.flag_values
            ):
                _reject_persisted_evidence()
        elif (
            observation.selected_candidate_direct_output is not False
            or observation.flag_values
        ):
            _reject_persisted_evidence()


def parse_rev_proof_evaluation_evidence(
    value: object,
) -> RevProofEvaluationRecord:
    """Parse one exact, bounded persisted v1 Rev proof evaluation mapping.

    The parser accepts only JSON-shaped built-in types and never consumes
    arbitrary iterables.  Semantic replay that requires the original accepted
    input is deliberately left to :func:`verify_rev_proof_evaluation`.
    """

    mapping = _exact_evidence_mapping(
        value,
        _REV_PROOF_EVALUATION_KEYS,
    )
    protocol = _exact_evidence_text(
        mapping["protocol"],
        maximum_chars=64,
        maximum_bytes=64,
    )
    if (
        protocol != REV_STDIN_PROOF_PROTOCOL
        or type(mapping["schema_version"]) is not int
        or mapping["schema_version"] != 1
        or type(mapping["required_positive_attempts"]) is not int
        or mapping["required_positive_attempts"] != 3
        or type(mapping["required_negative_attempts"]) is not int
        or mapping["required_negative_attempts"] != 3
    ):
        _reject_persisted_evidence()

    candidate = _exact_evidence_text(
        mapping["candidate"],
        maximum_chars=REV_STDIN_PROOF_MAX_CANDIDATE_CHARS,
        maximum_bytes=REV_STDIN_PROOF_MAX_CANDIDATE_BYTES,
        allow_empty=True,
    )
    accepted_sha_value = mapping["accepted_input_sha256"]
    accepted_input_sha256 = (
        None
        if accepted_sha_value is None
        else _exact_evidence_digest(accepted_sha_value)
    )
    accepted_input_size_bytes = _exact_evidence_optional_int(
        mapping["accepted_input_size_bytes"],
        minimum=0,
        maximum=REV_STDIN_PROOF_MAX_ACCEPTED_INPUT_BYTES,
    )
    if (accepted_input_sha256 is None) != (
        accepted_input_size_bytes is None
    ):
        _reject_persisted_evidence()

    plan_values = _exact_evidence_list(
        mapping["plan"],
        maximum_items=_EXPECTED_ATTEMPT_COUNT,
    )
    if len(plan_values) not in {0, _EXPECTED_ATTEMPT_COUNT}:
        _reject_persisted_evidence()
    plan = tuple(
        _parse_rev_proof_input_record(item)
        for item in plan_values
    )
    observation_values = _exact_evidence_list(
        mapping["observations"],
        maximum_items=_EXPECTED_ATTEMPT_COUNT,
    )
    observations = tuple(
        _parse_rev_proof_observation(item)
        for item in observation_values
    )
    failure_values = _exact_evidence_list(
        mapping["failures"],
        maximum_items=_REV_PROOF_MAX_FAILURES,
    )
    failures = tuple(
        _parse_rev_proof_failure(item) for item in failure_values
    )
    failure_code_values = _exact_evidence_list(
        mapping["failure_codes"],
        maximum_items=len(REV_STDIN_PROOF_FAILURE_CODES),
    )
    parsed_failure_codes: list[str] = []
    for code_value in failure_code_values:
        code = _exact_evidence_text(
            code_value,
            maximum_chars=64,
            maximum_bytes=64,
        )
        if (
            code not in REV_STDIN_PROOF_FAILURE_CODES
            or code in parsed_failure_codes
        ):
            _reject_persisted_evidence()
        parsed_failure_codes.append(code)

    record = RevProofEvaluationRecord(
        candidate=candidate,
        source_manifest_sha256=_exact_evidence_digest(
            mapping["source_manifest_sha256"],
            allow_empty=True,
        ),
        accepted_input_sha256=accepted_input_sha256,
        accepted_input_size_bytes=accepted_input_size_bytes,
        plan=plan,
        observations=observations,
        failures=failures,
        positive_successes=_exact_evidence_int(
            mapping["positive_successes"],
            minimum=0,
            maximum=3,
        ),
        passed=_exact_evidence_bool(mapping["passed"]),
        protocol=protocol,
    )

    expected_positive_successes = (
        3
        - len(
            {
                failure.attempt_ordinal
                for failure in record.failures
                if failure.attempt_ordinal in {1, 2, 3}
            }
        )
        if len(record.observations) == _EXPECTED_ATTEMPT_COUNT
        else 0
    )
    if (
        record.passed != (not record.failures)
        or record.positive_successes != expected_positive_successes
        or parsed_failure_codes != list(record.failure_codes)
        or type(mapping["total_attempts"]) is not int
        or mapping["total_attempts"] != len(record.observations)
        or type(mapping["transport_inconclusive"]) is not bool
        or mapping["transport_inconclusive"]
        != record.transport_inconclusive
        or type(mapping["verdict"]) is not str
        or mapping["verdict"] != record.verdict
    ):
        _reject_persisted_evidence()

    _validate_rev_proof_record_plan(record)
    _validate_rev_proof_record_uniqueness(record)
    _validate_confirmed_rev_proof_record(record)

    try:
        canonical = record.canonical_bytes()
        supplied_canonical = _canonical_json_bytes(mapping)
    except (TypeError, ValueError, UnicodeError):
        _reject_persisted_evidence()
    if (
        len(supplied_canonical)
        > REV_STDIN_PROOF_MAX_EVIDENCE_BYTES
        or supplied_canonical != canonical
    ):
        _reject_persisted_evidence()
    return record


def verify_rev_proof_evaluation(
    value: object,
    *,
    accepted_input: bytes,
) -> RevProofEvaluationRecord:
    """Replay and exact-compare one persisted Rev proof evaluation."""

    record = parse_rev_proof_evaluation_evidence(value)
    if (
        type(accepted_input) is not bytes
        or len(accepted_input)
        > REV_STDIN_PROOF_MAX_ACCEPTED_INPUT_BYTES
    ):
        _reject_persisted_evidence()
    _, replayed = evaluate_rev_stdin_proof(
        record.candidate,
        accepted_input,
        record.source_manifest_sha256,
        record.observations,
    )
    try:
        replayed_canonical = replayed.canonical_bytes()
        recorded_canonical = record.canonical_bytes()
    except (TypeError, ValueError, UnicodeError):
        _reject_persisted_evidence()
    if replayed_canonical != recorded_canonical:
        _reject_persisted_evidence()
    return record
