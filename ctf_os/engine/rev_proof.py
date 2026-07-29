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
