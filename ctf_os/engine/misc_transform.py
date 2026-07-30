"""Pure receipt contract for sandboxed Misc transformation DAGs.

This module does not execute tools.  A challenge-scoped sandbox transport
executes an engine-authored plan and returns the typed observations defined
here.  The evaluator binds every transform to:

* exact immutable source or parent-output artifacts,
* the commitment of every parent node,
* a pinned tool, argv contract, and execution contract,
* complete bounded stdout/stderr artifact pointers, and
* a clean, network-denied execution receipt.

The terminal output must be the exact candidate artifact.  A different pinned
tool then checks that artifact against every original source in three clean
replays.  A successful evaluation authorizes only the statement that the
candidate satisfied the configured original-condition oracle.  Automatic
submission is never authorized.

Raw source bytes, argv values, stream bytes, and candidate text are not
serialized.  Persisted evidence contains bounded identifiers, sizes, and
SHA-256 commitments only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from itertools import islice
from typing import Iterable


MISC_TRANSFORM_PROTOCOL = "misc_sandbox_transform_dag_reverse_v1"
MISC_TRANSFORM_SCHEMA_VERSION = 1
MISC_TRANSFORM_VERIFICATION_REPEATS = 3
MISC_TRANSFORM_MAX_SOURCES = 16
MISC_TRANSFORM_MAX_STEPS = 32
MISC_TRANSFORM_MAX_PARENTS = 16
MISC_TRANSFORM_MAX_SOURCE_BYTES = 4 * 1024 * 1024 * 1024
MISC_TRANSFORM_MAX_OUTPUT_BYTES = 256 * 1024 * 1024
MISC_TRANSFORM_MAX_STREAM_BYTES = 16 * 1024 * 1024
MISC_TRANSFORM_MAX_CANDIDATE_BYTES = 16 * 1024
MISC_TRANSFORM_MAX_EVIDENCE_BYTES = 512 * 1024

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")

MISC_TRANSFORM_FAILURE_CODES = frozenset(
    {
        "artifact_id_reused",
        "candidate_invalid",
        "candidate_output_mismatch",
        "dag_cycle",
        "dag_disconnected",
        "dag_order_invalid",
        "duplicate_run_id",
        "execution_contract_mismatch",
        "exit_status_mismatch",
        "graph_parent_invalid",
        "hash_binding_invalid",
        "input_binding_mismatch",
        "network_not_denied",
        "node_unavailable",
        "observation_count_mismatch",
        "observation_iteration_failed",
        "observation_type_invalid",
        "observations_not_iterable",
        "orchestration_incomplete",
        "output_artifact_invalid",
        "output_artifact_too_large",
        "parent_commitment_mismatch",
        "plan_binding_mismatch",
        "plan_too_large",
        "reverse_candidate_binding_mismatch",
        "reverse_observation_count_mismatch",
        "reverse_observation_iteration_failed",
        "reverse_observation_type_invalid",
        "reverse_observations_not_iterable",
        "reverse_result_mismatch",
        "source_artifact_invalid",
        "source_artifact_too_large",
        "source_count_invalid",
        "source_manifest_mismatch",
        "step_count_invalid",
        "step_definition_invalid",
        "step_order_mismatch",
        "stream_artifact_invalid",
        "stream_artifact_too_large",
        "stream_capture_incomplete",
        "stream_capture_truncated",
        "terminal_step_invalid",
        "timed_out",
        "tool_contract_mismatch",
        "verifier_contract_mismatch",
        "verifier_not_independent",
        "workspace_not_clean",
    }
)


class MiscTransformPreflightError(ValueError):
    """Stable fail-closed rejection for an unsafe or vacuous plan."""

    def __init__(self, code: str) -> None:
        if code not in MISC_TRANSFORM_FAILURE_CODES:
            raise ValueError("unknown Misc transform failure code")
        super().__init__(code)
        self.code = code


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def misc_transform_canonical_json_bytes(value: object) -> bytes:
    """Encode canonical bounded evidence with no model-controlled raw text."""

    try:
        encoded = (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ValueError("Misc transform evidence is not canonical JSON") from error
    if len(encoded) > MISC_TRANSFORM_MAX_EVIDENCE_BYTES:
        raise ValueError("Misc transform evidence exceeds the byte limit")
    return encoded


def _valid_sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _valid_id(value: object) -> bool:
    return type(value) is str and _SAFE_ID.fullmatch(value) is not None


def _valid_size(value: object, maximum: int) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _bounded_tuple(
    values: object,
    maximum: int,
    *,
    failure_code: str,
) -> tuple[object, ...]:
    try:
        iterator = iter(values)  # type: ignore[arg-type]
    except Exception as error:
        raise MiscTransformPreflightError(failure_code) from error
    try:
        bounded = tuple(islice(iterator, maximum + 1))
    except Exception as error:
        raise MiscTransformPreflightError(failure_code) from error
    if len(bounded) > maximum:
        raise MiscTransformPreflightError(failure_code)
    return bounded


@dataclass(frozen=True, slots=True)
class MiscArtifactRef:
    """Exact durable artifact identity; never contains artifact bytes."""

    artifact_id: str
    sha256: str
    size_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }

    @property
    def commitment_sha256(self) -> str:
        return _sha256(
            misc_transform_canonical_json_bytes(
                {"artifact": self.to_dict(), "kind": "source"}
            )
        )


def _validate_artifact(
    value: object,
    *,
    maximum_bytes: int,
    invalid_code: str,
    too_large_code: str,
) -> MiscArtifactRef:
    if type(value) is not MiscArtifactRef:
        raise MiscTransformPreflightError(invalid_code)
    if not _valid_id(value.artifact_id) or not _valid_sha256(value.sha256):
        raise MiscTransformPreflightError(invalid_code)
    if type(value.size_bytes) is not int or value.size_bytes < 0:
        raise MiscTransformPreflightError(invalid_code)
    if value.size_bytes > maximum_bytes:
        raise MiscTransformPreflightError(too_large_code)
    return value


@dataclass(frozen=True, slots=True)
class MiscTransformStepSpec:
    """One engine-authored topological transform step."""

    ordinal: int
    step_id: str
    parent_ids: tuple[str, ...]
    tool_id: str
    tool_artifact_sha256: str
    argv_contract_sha256: str
    execution_contract_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "argv_contract_sha256": self.argv_contract_sha256,
            "execution_contract_sha256": self.execution_contract_sha256,
            "ordinal": self.ordinal,
            "parent_ids": list(self.parent_ids),
            "step_id": self.step_id,
            "tool_artifact_sha256": self.tool_artifact_sha256,
            "tool_id": self.tool_id,
        }


@dataclass(frozen=True, slots=True)
class MiscVerifierSpec:
    """Pinned independent original-condition verifier contract."""

    verifier_id: str
    tool_artifact_sha256: str
    argv_contract_sha256: str
    execution_contract_sha256: str
    oracle_contract_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "argv_contract_sha256": self.argv_contract_sha256,
            "execution_contract_sha256": self.execution_contract_sha256,
            "oracle_contract_sha256": self.oracle_contract_sha256,
            "tool_artifact_sha256": self.tool_artifact_sha256,
            "verifier_id": self.verifier_id,
        }


@dataclass(frozen=True, slots=True)
class MiscTransformPlan:
    """Canonical DAG and reverse-verification plan."""

    candidate_sha256: str
    candidate_size_bytes: int
    source_manifest_sha256: str
    sources: tuple[MiscArtifactRef, ...]
    steps: tuple[MiscTransformStepSpec, ...]
    terminal_step_id: str
    verifier: MiscVerifierSpec

    def to_dict(self) -> dict[str, object]:
        return {
            "candidate_sha256": self.candidate_sha256,
            "candidate_size_bytes": self.candidate_size_bytes,
            "protocol": MISC_TRANSFORM_PROTOCOL,
            "source_manifest_sha256": self.source_manifest_sha256,
            "sources": [item.to_dict() for item in self.sources],
            "steps": [item.to_dict() for item in self.steps],
            "terminal_step_id": self.terminal_step_id,
            "verification_repeats": MISC_TRANSFORM_VERIFICATION_REPEATS,
            "verifier": self.verifier.to_dict(),
        }

    @property
    def sha256(self) -> str:
        return _sha256(misc_transform_canonical_json_bytes(self.to_dict()))


def _candidate_commitment(candidate: object) -> tuple[str, int]:
    if type(candidate) is not str or not candidate:
        raise MiscTransformPreflightError("candidate_invalid")
    try:
        payload = candidate.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise MiscTransformPreflightError("candidate_invalid") from error
    if (
        len(payload) > MISC_TRANSFORM_MAX_CANDIDATE_BYTES
        or not all(character.isprintable() for character in candidate)
    ):
        raise MiscTransformPreflightError("candidate_invalid")
    return _sha256(payload), len(payload)


def _validate_step_spec(
    value: object,
    expected_ordinal: int,
) -> MiscTransformStepSpec:
    if type(value) is not MiscTransformStepSpec:
        raise MiscTransformPreflightError("step_definition_invalid")
    if (
        type(value.ordinal) is not int
        or value.ordinal != expected_ordinal
        or not _valid_id(value.step_id)
        or not _valid_id(value.tool_id)
        or not _valid_sha256(value.tool_artifact_sha256)
        or not _valid_sha256(value.argv_contract_sha256)
        or not _valid_sha256(value.execution_contract_sha256)
        or type(value.parent_ids) is not tuple
        or not 1 <= len(value.parent_ids) <= MISC_TRANSFORM_MAX_PARENTS
        or any(not _valid_id(item) for item in value.parent_ids)
        or len(set(value.parent_ids)) != len(value.parent_ids)
    ):
        raise MiscTransformPreflightError("step_definition_invalid")
    return value


def _validate_verifier(value: object) -> MiscVerifierSpec:
    if type(value) is not MiscVerifierSpec:
        raise MiscTransformPreflightError("verifier_contract_mismatch")
    if (
        not _valid_id(value.verifier_id)
        or not _valid_sha256(value.tool_artifact_sha256)
        or not _valid_sha256(value.argv_contract_sha256)
        or not _valid_sha256(value.execution_contract_sha256)
        or not _valid_sha256(value.oracle_contract_sha256)
    ):
        raise MiscTransformPreflightError("verifier_contract_mismatch")
    return value


def _has_step_cycle(
    steps: tuple[MiscTransformStepSpec, ...],
    step_ids: frozenset[str],
) -> bool:
    parents = {
        step.step_id: tuple(
            parent for parent in step.parent_ids if parent in step_ids
        )
        for step in steps
    }
    state: dict[str, int] = {}

    def visit(step_id: str) -> bool:
        marker = state.get(step_id, 0)
        if marker == 1:
            return True
        if marker == 2:
            return False
        state[step_id] = 1
        for parent in parents[step_id]:
            if visit(parent):
                return True
        state[step_id] = 2
        return False

    return any(visit(step.step_id) for step in steps)


def build_misc_transform_plan(
    candidate: str,
    source_manifest_sha256: str,
    sources: Iterable[MiscArtifactRef],
    steps: Iterable[MiscTransformStepSpec],
    *,
    terminal_step_id: str,
    verifier: MiscVerifierSpec,
) -> MiscTransformPlan:
    """Validate and build the only DAG shape accepted by this protocol."""

    candidate_sha256, candidate_size = _candidate_commitment(candidate)
    if not _valid_sha256(source_manifest_sha256):
        raise MiscTransformPreflightError("hash_binding_invalid")

    raw_sources = _bounded_tuple(
        sources,
        MISC_TRANSFORM_MAX_SOURCES,
        failure_code="source_count_invalid",
    )
    if not raw_sources:
        raise MiscTransformPreflightError("source_count_invalid")
    validated_sources = tuple(
        _validate_artifact(
            item,
            maximum_bytes=MISC_TRANSFORM_MAX_SOURCE_BYTES,
            invalid_code="source_artifact_invalid",
            too_large_code="source_artifact_too_large",
        )
        for item in raw_sources
    )

    raw_steps = _bounded_tuple(
        steps,
        MISC_TRANSFORM_MAX_STEPS,
        failure_code="step_count_invalid",
    )
    if not raw_steps:
        raise MiscTransformPreflightError("step_count_invalid")
    validated_steps = tuple(
        _validate_step_spec(item, ordinal)
        for ordinal, item in enumerate(raw_steps, start=1)
    )
    validated_verifier = _validate_verifier(verifier)

    source_ids = tuple(item.artifact_id for item in validated_sources)
    step_ids = tuple(item.step_id for item in validated_steps)
    all_ids = source_ids + step_ids
    if len(set(all_ids)) != len(all_ids):
        raise MiscTransformPreflightError("source_artifact_invalid")

    known_ids = frozenset(all_ids)
    for step in validated_steps:
        if any(parent not in known_ids for parent in step.parent_ids):
            raise MiscTransformPreflightError("graph_parent_invalid")

    step_id_set = frozenset(step_ids)
    if _has_step_cycle(validated_steps, step_id_set):
        raise MiscTransformPreflightError("dag_cycle")

    ordinal_by_step = {
        step.step_id: step.ordinal for step in validated_steps
    }
    for step in validated_steps:
        if any(
            parent in ordinal_by_step
            and ordinal_by_step[parent] >= step.ordinal
            for parent in step.parent_ids
        ):
            raise MiscTransformPreflightError("dag_order_invalid")

    if terminal_step_id not in step_id_set:
        raise MiscTransformPreflightError("terminal_step_invalid")
    child_parent_ids = {
        parent
        for step in validated_steps
        for parent in step.parent_ids
        if parent in step_id_set
    }
    sinks = step_id_set - child_parent_ids
    if sinks != {terminal_step_id}:
        raise MiscTransformPreflightError("terminal_step_invalid")

    parents_by_step = {
        step.step_id: step.parent_ids for step in validated_steps
    }
    reachable: set[str] = set()
    pending = [terminal_step_id]
    while pending:
        current = pending.pop()
        if current in reachable:
            continue
        reachable.add(current)
        if current in parents_by_step:
            pending.extend(parents_by_step[current])
    if reachable != known_ids:
        raise MiscTransformPreflightError("dag_disconnected")

    if validated_verifier.tool_artifact_sha256 in {
        step.tool_artifact_sha256 for step in validated_steps
    }:
        raise MiscTransformPreflightError("verifier_not_independent")

    plan = MiscTransformPlan(
        candidate_sha256=candidate_sha256,
        candidate_size_bytes=candidate_size,
        source_manifest_sha256=source_manifest_sha256,
        sources=validated_sources,
        steps=validated_steps,
        terminal_step_id=terminal_step_id,
        verifier=validated_verifier,
    )
    try:
        misc_transform_canonical_json_bytes(plan.to_dict())
    except ValueError as error:
        raise MiscTransformPreflightError("plan_too_large") from error
    return plan


@dataclass(frozen=True, slots=True)
class MiscStreamEvidence:
    """Bounded durable stdout or stderr pointer from one sandbox run."""

    artifact_id: str | None
    artifact_sha256: str | None
    artifact_size_bytes: int | None
    capture_complete: bool
    truncation_known: bool
    truncated: bool | None
    capture_error: str | None
    durable_artifact_complete: bool


@dataclass(frozen=True, slots=True)
class MiscTransformObservation:
    """Transport receipt for one transform execution."""

    run_id: str
    ordinal: int
    step_id: str
    plan_sha256: str
    source_manifest_sha256: str
    parent_node_sha256s: tuple[str, ...]
    input_artifacts: tuple[MiscArtifactRef, ...]
    tool_id: str
    tool_artifact_sha256: str
    argv_contract_sha256: str
    execution_contract_sha256: str
    clean_workspace: bool
    network_denied: bool
    target_exit_code: int | None
    runner_exit_code: int | None
    ctfwrap_exit_code: int | None
    timed_out: bool
    orchestration_status: str
    output_artifact: MiscArtifactRef | None
    stdout: MiscStreamEvidence
    stderr: MiscStreamEvidence


@dataclass(frozen=True, slots=True)
class MiscReverseVerificationObservation:
    """Receipt for one independent original-condition replay."""

    run_id: str
    ordinal: int
    plan_sha256: str
    source_manifest_sha256: str
    terminal_node_sha256: str
    candidate_artifact: MiscArtifactRef | None
    source_artifacts: tuple[MiscArtifactRef, ...]
    verifier_id: str
    tool_artifact_sha256: str
    argv_contract_sha256: str
    execution_contract_sha256: str
    oracle_contract_sha256: str
    clean_workspace: bool
    network_denied: bool
    target_exit_code: int | None
    runner_exit_code: int | None
    ctfwrap_exit_code: int | None
    timed_out: bool
    orchestration_status: str
    result_artifact: MiscArtifactRef | None
    stdout: MiscStreamEvidence
    stderr: MiscStreamEvidence


@dataclass(frozen=True, slots=True)
class MiscStreamRecord:
    artifact_id: str | None
    artifact_sha256: str | None
    artifact_size_bytes: int | None
    capture_complete: bool
    truncation_known: bool
    truncated: bool | None
    capture_error_present: bool
    durable_artifact_complete: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "artifact_size_bytes": self.artifact_size_bytes,
            "capture_complete": self.capture_complete,
            "capture_error_present": self.capture_error_present,
            "durable_artifact_complete": self.durable_artifact_complete,
            "truncated": self.truncated,
            "truncation_known": self.truncation_known,
        }


@dataclass(frozen=True, slots=True)
class MiscTransformNodeRecord:
    accepted: bool
    run_id: str
    ordinal: int
    step_id: str
    plan_sha256: str
    source_manifest_sha256: str
    parent_node_sha256s: tuple[str, ...]
    input_artifacts: tuple[MiscArtifactRef, ...]
    tool_id: str
    tool_artifact_sha256: str
    argv_contract_sha256: str
    execution_contract_sha256: str
    clean_workspace: bool
    network_denied: bool
    target_exit_code: int | None
    runner_exit_code: int | None
    ctfwrap_exit_code: int | None
    timed_out: bool
    orchestration_status: str
    output_artifact: MiscArtifactRef | None
    stdout: MiscStreamRecord
    stderr: MiscStreamRecord
    node_sha256: str | None

    def _commitment_dict(self) -> dict[str, object]:
        return {
            "argv_contract_sha256": self.argv_contract_sha256,
            "clean_workspace": self.clean_workspace,
            "ctfwrap_exit_code": self.ctfwrap_exit_code,
            "execution_contract_sha256": self.execution_contract_sha256,
            "input_artifacts": [
                item.to_dict() for item in self.input_artifacts
            ],
            "network_denied": self.network_denied,
            "orchestration_status": self.orchestration_status,
            "ordinal": self.ordinal,
            "output_artifact": (
                self.output_artifact.to_dict()
                if self.output_artifact is not None
                else None
            ),
            "parent_node_sha256s": list(self.parent_node_sha256s),
            "plan_sha256": self.plan_sha256,
            "run_id": self.run_id,
            "runner_exit_code": self.runner_exit_code,
            "source_manifest_sha256": self.source_manifest_sha256,
            "stderr": self.stderr.to_dict(),
            "stdout": self.stdout.to_dict(),
            "step_id": self.step_id,
            "target_exit_code": self.target_exit_code,
            "timed_out": self.timed_out,
            "tool_artifact_sha256": self.tool_artifact_sha256,
            "tool_id": self.tool_id,
        }

    def to_dict(self) -> dict[str, object]:
        value = self._commitment_dict()
        value["accepted"] = self.accepted
        value["node_sha256"] = self.node_sha256
        return value


@dataclass(frozen=True, slots=True)
class MiscReverseVerificationRecord:
    accepted: bool
    run_id: str
    ordinal: int
    plan_sha256: str
    source_manifest_sha256: str
    terminal_node_sha256: str
    candidate_artifact: MiscArtifactRef | None
    source_artifacts: tuple[MiscArtifactRef, ...]
    verifier_id: str
    tool_artifact_sha256: str
    argv_contract_sha256: str
    execution_contract_sha256: str
    oracle_contract_sha256: str
    clean_workspace: bool
    network_denied: bool
    target_exit_code: int | None
    runner_exit_code: int | None
    ctfwrap_exit_code: int | None
    timed_out: bool
    orchestration_status: str
    result_artifact: MiscArtifactRef | None
    stdout: MiscStreamRecord
    stderr: MiscStreamRecord

    def to_dict(self) -> dict[str, object]:
        return {
            "accepted": self.accepted,
            "argv_contract_sha256": self.argv_contract_sha256,
            "candidate_artifact": (
                self.candidate_artifact.to_dict()
                if self.candidate_artifact is not None
                else None
            ),
            "clean_workspace": self.clean_workspace,
            "ctfwrap_exit_code": self.ctfwrap_exit_code,
            "execution_contract_sha256": self.execution_contract_sha256,
            "network_denied": self.network_denied,
            "oracle_contract_sha256": self.oracle_contract_sha256,
            "orchestration_status": self.orchestration_status,
            "ordinal": self.ordinal,
            "plan_sha256": self.plan_sha256,
            "result_artifact": (
                self.result_artifact.to_dict()
                if self.result_artifact is not None
                else None
            ),
            "run_id": self.run_id,
            "runner_exit_code": self.runner_exit_code,
            "source_artifacts": [
                item.to_dict() for item in self.source_artifacts
            ],
            "source_manifest_sha256": self.source_manifest_sha256,
            "stderr": self.stderr.to_dict(),
            "stdout": self.stdout.to_dict(),
            "target_exit_code": self.target_exit_code,
            "terminal_node_sha256": self.terminal_node_sha256,
            "timed_out": self.timed_out,
            "tool_artifact_sha256": self.tool_artifact_sha256,
            "verifier_id": self.verifier_id,
        }


@dataclass(frozen=True, slots=True)
class MiscTransformEvaluation:
    """Raw-free, bounded result of the pure receipt evaluator."""

    plan: MiscTransformPlan | None
    transform_nodes: tuple[MiscTransformNodeRecord, ...]
    reverse_verifications: tuple[MiscReverseVerificationRecord, ...]
    failure_codes: tuple[str, ...]
    passed: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "authorities": {
                "automatic_submission_authorized": False,
                "candidate_original_condition_verified": self.passed,
            },
            "failure_codes": list(self.failure_codes),
            "passed": self.passed,
            "plan": self.plan.to_dict() if self.plan is not None else None,
            "plan_sha256": self.plan.sha256 if self.plan is not None else None,
            "protocol": MISC_TRANSFORM_PROTOCOL,
            "reverse_verifications": [
                item.to_dict() for item in self.reverse_verifications
            ],
            "schema_version": MISC_TRANSFORM_SCHEMA_VERSION,
            "transform_nodes": [
                item.to_dict() for item in self.transform_nodes
            ],
        }

    @property
    def canonical_bytes(self) -> bytes:
        return misc_transform_canonical_json_bytes(self.to_dict())

    @property
    def sha256(self) -> str:
        return _sha256(self.canonical_bytes)


def _safe_id(value: object) -> str:
    return value if _valid_id(value) else ""


def _safe_sha256(value: object) -> str:
    return value if _valid_sha256(value) else ""


def _safe_exit(value: object) -> int | None:
    return (
        value
        if type(value) is int and -(1 << 31) <= value < (1 << 31)
        else None
    )


def _safe_ordinal(value: object, maximum: int) -> int:
    return (
        value
        if type(value) is int and 1 <= value <= maximum
        else -1
    )


def _safe_artifact(
    value: object,
    maximum_bytes: int,
) -> MiscArtifactRef | None:
    if type(value) is not MiscArtifactRef:
        return None
    if (
        not _valid_id(value.artifact_id)
        or not _valid_sha256(value.sha256)
        or not _valid_size(value.size_bytes, maximum_bytes)
    ):
        return None
    return value


def _safe_artifact_tuple(
    value: object,
    *,
    maximum_items: int,
    maximum_bytes: int,
) -> tuple[MiscArtifactRef, ...]:
    if type(value) is not tuple or len(value) > maximum_items:
        return ()
    normalized: list[MiscArtifactRef] = []
    for item in value:
        safe = _safe_artifact(item, maximum_bytes)
        if safe is None:
            return ()
        normalized.append(safe)
    return tuple(normalized)


def _safe_hash_tuple(
    value: object,
    maximum_items: int,
) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) > maximum_items:
        return ()
    if any(not _valid_sha256(item) for item in value):
        return ()
    return value


def _stream_record(value: object) -> MiscStreamRecord:
    if type(value) is not MiscStreamEvidence:
        return MiscStreamRecord(
            artifact_id=None,
            artifact_sha256=None,
            artifact_size_bytes=None,
            capture_complete=False,
            truncation_known=False,
            truncated=None,
            capture_error_present=True,
            durable_artifact_complete=False,
        )
    valid_pointer = (
        _valid_id(value.artifact_id)
        and _valid_sha256(value.artifact_sha256)
        and _valid_size(
            value.artifact_size_bytes,
            MISC_TRANSFORM_MAX_STREAM_BYTES,
        )
    )
    return MiscStreamRecord(
        artifact_id=value.artifact_id if valid_pointer else None,
        artifact_sha256=(
            value.artifact_sha256 if valid_pointer else None
        ),
        artifact_size_bytes=(
            value.artifact_size_bytes if valid_pointer else None
        ),
        capture_complete=value.capture_complete is True,
        truncation_known=value.truncation_known is True,
        truncated=(
            value.truncated if type(value.truncated) is bool else None
        ),
        capture_error_present=value.capture_error is not None,
        durable_artifact_complete=(
            value.durable_artifact_complete is True
        ),
    )


def _validate_stream(
    value: object,
    *,
    failures: list[str],
    prefix: str,
    used_artifact_ids: set[str],
) -> MiscStreamRecord:
    record = _stream_record(value)
    if type(value) is not MiscStreamEvidence:
        failures.append(f"{prefix}:stream_artifact_invalid")
        return record
    if (
        not _valid_id(value.artifact_id)
        or not _valid_sha256(value.artifact_sha256)
        or type(value.artifact_size_bytes) is not int
        or value.artifact_size_bytes < 0
    ):
        failures.append(f"{prefix}:stream_artifact_invalid")
    elif value.artifact_size_bytes > MISC_TRANSFORM_MAX_STREAM_BYTES:
        failures.append(f"{prefix}:stream_artifact_too_large")
    else:
        assert isinstance(value.artifact_id, str)
        if value.artifact_id in used_artifact_ids:
            failures.append(f"{prefix}:artifact_id_reused")
        else:
            used_artifact_ids.add(value.artifact_id)
    if (
        value.capture_complete is not True
        or value.truncation_known is not True
        or value.capture_error is not None
        or value.durable_artifact_complete is not True
    ):
        failures.append(f"{prefix}:stream_capture_incomplete")
    if value.truncated is not False:
        failures.append(f"{prefix}:stream_capture_truncated")
    return record


def _execution_failures(
    observation: object,
    *,
    prefix: str,
    failures: list[str],
) -> None:
    if observation.clean_workspace is not True:
        failures.append(f"{prefix}:workspace_not_clean")
    if observation.network_denied is not True:
        failures.append(f"{prefix}:network_not_denied")
    if observation.timed_out is not False:
        failures.append(f"{prefix}:timed_out")
    if (
        type(observation.target_exit_code) is not int
        or observation.target_exit_code != 0
        or type(observation.runner_exit_code) is not int
        or observation.runner_exit_code != 0
        or type(observation.ctfwrap_exit_code) is not int
        or observation.ctfwrap_exit_code != 0
    ):
        failures.append(f"{prefix}:exit_status_mismatch")
    if observation.orchestration_status != "completed":
        failures.append(f"{prefix}:orchestration_incomplete")


def _provisional_node_record(
    observation: MiscTransformObservation,
    *,
    output_artifact: MiscArtifactRef | None = None,
    stdout: MiscStreamRecord | None = None,
    stderr: MiscStreamRecord | None = None,
) -> MiscTransformNodeRecord:
    return MiscTransformNodeRecord(
        accepted=False,
        run_id=_safe_id(observation.run_id),
        ordinal=_safe_ordinal(
            observation.ordinal,
            MISC_TRANSFORM_MAX_STEPS,
        ),
        step_id=_safe_id(observation.step_id),
        plan_sha256=_safe_sha256(observation.plan_sha256),
        source_manifest_sha256=_safe_sha256(
            observation.source_manifest_sha256
        ),
        parent_node_sha256s=_safe_hash_tuple(
            observation.parent_node_sha256s,
            MISC_TRANSFORM_MAX_PARENTS,
        ),
        input_artifacts=_safe_artifact_tuple(
            observation.input_artifacts,
            maximum_items=MISC_TRANSFORM_MAX_PARENTS,
            maximum_bytes=max(
                MISC_TRANSFORM_MAX_SOURCE_BYTES,
                MISC_TRANSFORM_MAX_OUTPUT_BYTES,
            ),
        ),
        tool_id=_safe_id(observation.tool_id),
        tool_artifact_sha256=_safe_sha256(
            observation.tool_artifact_sha256
        ),
        argv_contract_sha256=_safe_sha256(
            observation.argv_contract_sha256
        ),
        execution_contract_sha256=_safe_sha256(
            observation.execution_contract_sha256
        ),
        clean_workspace=observation.clean_workspace is True,
        network_denied=observation.network_denied is True,
        target_exit_code=_safe_exit(observation.target_exit_code),
        runner_exit_code=_safe_exit(observation.runner_exit_code),
        ctfwrap_exit_code=_safe_exit(observation.ctfwrap_exit_code),
        timed_out=observation.timed_out is not False,
        orchestration_status=(
            observation.orchestration_status
            if observation.orchestration_status == "completed"
            else ""
        ),
        output_artifact=(
            output_artifact
            if output_artifact is not None
            else _safe_artifact(
                observation.output_artifact,
                MISC_TRANSFORM_MAX_OUTPUT_BYTES,
            )
        ),
        stdout=stdout if stdout is not None else _stream_record(
            observation.stdout
        ),
        stderr=stderr if stderr is not None else _stream_record(
            observation.stderr
        ),
        node_sha256=None,
    )


def misc_transform_node_commitment_sha256(
    observation: MiscTransformObservation,
) -> str:
    """Commit to one structurally complete receipt without accepting it.

    The execution layer can use this deterministic helper when constructing
    a later child receipt.  Acceptance still requires the full plan-aware
    evaluator, including exact parent/input and tool contract checks.
    """

    if type(observation) is not MiscTransformObservation:
        raise MiscTransformPreflightError("observation_type_invalid")
    provisional = _provisional_node_record(observation)
    if (
        not _valid_id(provisional.run_id)
        or provisional.ordinal < 1
        or not _valid_id(provisional.step_id)
        or not _valid_sha256(provisional.plan_sha256)
        or not _valid_sha256(provisional.source_manifest_sha256)
        or not provisional.parent_node_sha256s
        or not provisional.input_artifacts
        or not _valid_id(provisional.tool_id)
        or not _valid_sha256(provisional.tool_artifact_sha256)
        or not _valid_sha256(provisional.argv_contract_sha256)
        or not _valid_sha256(provisional.execution_contract_sha256)
        or provisional.clean_workspace is not True
        or provisional.network_denied is not True
        or provisional.target_exit_code != 0
        or provisional.runner_exit_code != 0
        or provisional.ctfwrap_exit_code != 0
        or provisional.timed_out is not False
        or provisional.orchestration_status != "completed"
        or provisional.output_artifact is None
    ):
        raise MiscTransformPreflightError("execution_contract_mismatch")
    for stream in (provisional.stdout, provisional.stderr):
        if (
            stream.artifact_id is None
            or stream.artifact_sha256 is None
            or stream.artifact_size_bytes is None
            or stream.capture_complete is not True
            or stream.truncation_known is not True
            or stream.truncated is not False
            or stream.capture_error_present is not False
            or stream.durable_artifact_complete is not True
        ):
            raise MiscTransformPreflightError(
                "stream_capture_incomplete"
            )
    return _sha256(
        misc_transform_canonical_json_bytes(
            provisional._commitment_dict()
        )
    )


def _expected_reverse_result_bytes(
    plan: MiscTransformPlan,
    terminal_node_sha256: str,
    ordinal: int,
) -> bytes:
    return misc_transform_canonical_json_bytes(
        {
            "accepted": True,
            "candidate_sha256": plan.candidate_sha256,
            "candidate_size_bytes": plan.candidate_size_bytes,
            "oracle_contract_sha256": (
                plan.verifier.oracle_contract_sha256
            ),
            "ordinal": ordinal,
            "original_sources": [
                item.to_dict() for item in plan.sources
            ],
            "plan_sha256": plan.sha256,
            "terminal_node_sha256": terminal_node_sha256,
        }
    )


def expected_misc_reverse_result_artifact(
    plan: MiscTransformPlan,
    terminal_node_sha256: str,
    ordinal: int,
    *,
    artifact_id: str,
) -> MiscArtifactRef:
    """Return the exact success artifact expected from one verifier replay."""

    if (
        type(plan) is not MiscTransformPlan
        or not _valid_sha256(terminal_node_sha256)
        or type(ordinal) is not int
        or not 1 <= ordinal <= MISC_TRANSFORM_VERIFICATION_REPEATS
        or not _valid_id(artifact_id)
    ):
        raise MiscTransformPreflightError("verifier_contract_mismatch")
    payload = _expected_reverse_result_bytes(
        plan,
        terminal_node_sha256,
        ordinal,
    )
    return MiscArtifactRef(
        artifact_id=artifact_id,
        sha256=_sha256(payload),
        size_bytes=len(payload),
    )


def _collect_observations(
    values: object,
    count: int,
    *,
    not_iterable_code: str,
    iteration_failed_code: str,
    count_code: str,
    failures: list[str],
) -> tuple[object, ...]:
    try:
        iterator = iter(values)  # type: ignore[arg-type]
    except Exception:
        failures.append(not_iterable_code)
        return ()
    try:
        observed = tuple(islice(iterator, count + 1))
    except Exception:
        failures.append(iteration_failed_code)
        return ()
    if len(observed) != count:
        failures.append(count_code)
    return observed[:count]


def _preflight_evaluation(
    code: str,
) -> MiscTransformEvaluation:
    return MiscTransformEvaluation(
        plan=None,
        transform_nodes=(),
        reverse_verifications=(),
        failure_codes=(code,),
        passed=False,
    )


def evaluate_misc_transform_receipts(
    candidate: str,
    source_manifest_sha256: str,
    sources: Iterable[MiscArtifactRef],
    steps: Iterable[MiscTransformStepSpec],
    *,
    terminal_step_id: str,
    verifier: MiscVerifierSpec,
    transform_observations: Iterable[MiscTransformObservation],
    reverse_observations: Iterable[
        MiscReverseVerificationObservation
    ],
) -> MiscTransformEvaluation:
    """Evaluate exact transform and reverse-verification transport receipts."""

    try:
        plan = build_misc_transform_plan(
            candidate,
            source_manifest_sha256,
            sources,
            steps,
            terminal_step_id=terminal_step_id,
            verifier=verifier,
        )
    except MiscTransformPreflightError as error:
        return _preflight_evaluation(error.code)

    failures: list[str] = []
    raw_transform = _collect_observations(
        transform_observations,
        len(plan.steps),
        not_iterable_code="observations_not_iterable",
        iteration_failed_code="observation_iteration_failed",
        count_code="observation_count_mismatch",
        failures=failures,
    )
    raw_reverse = _collect_observations(
        reverse_observations,
        MISC_TRANSFORM_VERIFICATION_REPEATS,
        not_iterable_code="reverse_observations_not_iterable",
        iteration_failed_code="reverse_observation_iteration_failed",
        count_code="reverse_observation_count_mismatch",
        failures=failures,
    )

    used_run_ids: set[str] = set()
    used_artifact_ids = {item.artifact_id for item in plan.sources}
    known: dict[str, tuple[MiscArtifactRef, str]] = {
        item.artifact_id: (item, item.commitment_sha256)
        for item in plan.sources
    }
    node_records: list[MiscTransformNodeRecord] = []

    for index, expected in enumerate(plan.steps):
        prefix = f"step-{expected.ordinal}"
        if index >= len(raw_transform):
            continue
        raw = raw_transform[index]
        if type(raw) is not MiscTransformObservation:
            failures.append(f"{prefix}:observation_type_invalid")
            continue
        before = len(failures)

        if not _valid_id(raw.run_id):
            failures.append(f"{prefix}:duplicate_run_id")
        elif raw.run_id in used_run_ids:
            failures.append(f"{prefix}:duplicate_run_id")
        else:
            used_run_ids.add(raw.run_id)
        if (
            type(raw.ordinal) is not int
            or raw.ordinal != expected.ordinal
            or raw.step_id != expected.step_id
        ):
            failures.append(f"{prefix}:step_order_mismatch")
        if raw.plan_sha256 != plan.sha256:
            failures.append(f"{prefix}:plan_binding_mismatch")
        if raw.source_manifest_sha256 != plan.source_manifest_sha256:
            failures.append(f"{prefix}:source_manifest_mismatch")
        if (
            raw.tool_id != expected.tool_id
            or raw.tool_artifact_sha256
            != expected.tool_artifact_sha256
            or raw.argv_contract_sha256
            != expected.argv_contract_sha256
        ):
            failures.append(f"{prefix}:tool_contract_mismatch")
        if (
            raw.execution_contract_sha256
            != expected.execution_contract_sha256
        ):
            failures.append(
                f"{prefix}:execution_contract_mismatch"
            )

        expected_inputs: list[MiscArtifactRef] = []
        expected_parent_hashes: list[str] = []
        upstream_available = True
        for parent_id in expected.parent_ids:
            parent = known.get(parent_id)
            if parent is None:
                upstream_available = False
                break
            expected_inputs.append(parent[0])
            expected_parent_hashes.append(parent[1])
        if not upstream_available:
            failures.append(f"{prefix}:node_unavailable")
        if (
            type(raw.input_artifacts) is not tuple
            or raw.input_artifacts != tuple(expected_inputs)
        ):
            failures.append(f"{prefix}:input_binding_mismatch")
        if (
            type(raw.parent_node_sha256s) is not tuple
            or raw.parent_node_sha256s != tuple(expected_parent_hashes)
        ):
            failures.append(f"{prefix}:parent_commitment_mismatch")

        _execution_failures(raw, prefix=prefix, failures=failures)
        stdout_record = _validate_stream(
            raw.stdout,
            failures=failures,
            prefix=f"{prefix}:stdout",
            used_artifact_ids=used_artifact_ids,
        )
        stderr_record = _validate_stream(
            raw.stderr,
            failures=failures,
            prefix=f"{prefix}:stderr",
            used_artifact_ids=used_artifact_ids,
        )

        output = _safe_artifact(
            raw.output_artifact,
            MISC_TRANSFORM_MAX_OUTPUT_BYTES,
        )
        if type(raw.output_artifact) is not MiscArtifactRef or output is None:
            if (
                type(raw.output_artifact) is MiscArtifactRef
                and type(raw.output_artifact.size_bytes) is int
                and raw.output_artifact.size_bytes
                > MISC_TRANSFORM_MAX_OUTPUT_BYTES
            ):
                failures.append(
                    f"{prefix}:output_artifact_too_large"
                )
            else:
                failures.append(f"{prefix}:output_artifact_invalid")
        else:
            if output.artifact_id in used_artifact_ids:
                failures.append(f"{prefix}:artifact_id_reused")
            else:
                used_artifact_ids.add(output.artifact_id)
            if (
                expected.step_id == plan.terminal_step_id
                and (
                    output.sha256 != plan.candidate_sha256
                    or output.size_bytes != plan.candidate_size_bytes
                )
            ):
                failures.append(
                    f"{prefix}:candidate_output_mismatch"
                )

        provisional = _provisional_node_record(
            raw,
            output_artifact=output,
            stdout=stdout_record,
            stderr=stderr_record,
        )
        accepted = len(failures) == before
        node_sha256 = (
            _sha256(
                misc_transform_canonical_json_bytes(
                    provisional._commitment_dict()
                )
            )
            if accepted
            else None
        )
        record = MiscTransformNodeRecord(
            accepted=accepted,
            run_id=provisional.run_id,
            ordinal=provisional.ordinal,
            step_id=provisional.step_id,
            plan_sha256=provisional.plan_sha256,
            source_manifest_sha256=(
                provisional.source_manifest_sha256
            ),
            parent_node_sha256s=provisional.parent_node_sha256s,
            input_artifacts=provisional.input_artifacts,
            tool_id=provisional.tool_id,
            tool_artifact_sha256=(
                provisional.tool_artifact_sha256
            ),
            argv_contract_sha256=(
                provisional.argv_contract_sha256
            ),
            execution_contract_sha256=(
                provisional.execution_contract_sha256
            ),
            clean_workspace=provisional.clean_workspace,
            network_denied=provisional.network_denied,
            target_exit_code=provisional.target_exit_code,
            runner_exit_code=provisional.runner_exit_code,
            ctfwrap_exit_code=provisional.ctfwrap_exit_code,
            timed_out=provisional.timed_out,
            orchestration_status=provisional.orchestration_status,
            output_artifact=provisional.output_artifact,
            stdout=provisional.stdout,
            stderr=provisional.stderr,
            node_sha256=node_sha256,
        )
        node_records.append(record)
        if accepted and output is not None and node_sha256 is not None:
            known[expected.step_id] = (output, node_sha256)

    terminal = known.get(plan.terminal_step_id)
    reverse_records: list[MiscReverseVerificationRecord] = []
    for index, raw in enumerate(raw_reverse, start=1):
        prefix = f"reverse-{index}"
        if type(raw) is not MiscReverseVerificationObservation:
            failures.append(
                f"{prefix}:reverse_observation_type_invalid"
            )
            continue
        before = len(failures)
        if terminal is None:
            failures.append(f"{prefix}:node_unavailable")
            terminal_artifact = None
            terminal_sha256 = ""
        else:
            terminal_artifact, terminal_sha256 = terminal

        if not _valid_id(raw.run_id):
            failures.append(f"{prefix}:duplicate_run_id")
        elif raw.run_id in used_run_ids:
            failures.append(f"{prefix}:duplicate_run_id")
        else:
            used_run_ids.add(raw.run_id)
        if type(raw.ordinal) is not int or raw.ordinal != index:
            failures.append(
                f"{prefix}:reverse_observation_type_invalid"
            )
        if raw.plan_sha256 != plan.sha256:
            failures.append(f"{prefix}:plan_binding_mismatch")
        if raw.source_manifest_sha256 != plan.source_manifest_sha256:
            failures.append(f"{prefix}:source_manifest_mismatch")
        if raw.terminal_node_sha256 != terminal_sha256:
            failures.append(
                f"{prefix}:parent_commitment_mismatch"
            )
        if (
            raw.candidate_artifact != terminal_artifact
            or type(raw.source_artifacts) is not tuple
            or raw.source_artifacts != plan.sources
        ):
            failures.append(
                f"{prefix}:reverse_candidate_binding_mismatch"
            )
        if (
            raw.verifier_id != plan.verifier.verifier_id
            or raw.tool_artifact_sha256
            != plan.verifier.tool_artifact_sha256
            or raw.argv_contract_sha256
            != plan.verifier.argv_contract_sha256
            or raw.execution_contract_sha256
            != plan.verifier.execution_contract_sha256
            or raw.oracle_contract_sha256
            != plan.verifier.oracle_contract_sha256
        ):
            failures.append(
                f"{prefix}:verifier_contract_mismatch"
            )
        _execution_failures(raw, prefix=prefix, failures=failures)
        stdout_record = _validate_stream(
            raw.stdout,
            failures=failures,
            prefix=f"{prefix}:stdout",
            used_artifact_ids=used_artifact_ids,
        )
        stderr_record = _validate_stream(
            raw.stderr,
            failures=failures,
            prefix=f"{prefix}:stderr",
            used_artifact_ids=used_artifact_ids,
        )
        result_artifact = _safe_artifact(
            raw.result_artifact,
            MISC_TRANSFORM_MAX_STREAM_BYTES,
        )
        if terminal is None:
            expected_result = None
        else:
            expected_payload = _expected_reverse_result_bytes(
                plan,
                terminal_sha256,
                index,
            )
            expected_result = (
                _sha256(expected_payload),
                len(expected_payload),
            )
        if type(raw.result_artifact) is not MiscArtifactRef or result_artifact is None:
            failures.append(f"{prefix}:output_artifact_invalid")
        else:
            if result_artifact.artifact_id in used_artifact_ids:
                failures.append(f"{prefix}:artifact_id_reused")
            else:
                used_artifact_ids.add(result_artifact.artifact_id)
            if (
                expected_result is None
                or result_artifact.sha256 != expected_result[0]
                or result_artifact.size_bytes != expected_result[1]
            ):
                failures.append(f"{prefix}:reverse_result_mismatch")

        accepted = len(failures) == before
        reverse_records.append(
            MiscReverseVerificationRecord(
                accepted=accepted,
                run_id=_safe_id(raw.run_id),
                ordinal=_safe_ordinal(
                    raw.ordinal,
                    MISC_TRANSFORM_VERIFICATION_REPEATS,
                ),
                plan_sha256=_safe_sha256(raw.plan_sha256),
                source_manifest_sha256=_safe_sha256(
                    raw.source_manifest_sha256
                ),
                terminal_node_sha256=_safe_sha256(
                    raw.terminal_node_sha256
                ),
                candidate_artifact=_safe_artifact(
                    raw.candidate_artifact,
                    MISC_TRANSFORM_MAX_OUTPUT_BYTES,
                ),
                source_artifacts=_safe_artifact_tuple(
                    raw.source_artifacts,
                    maximum_items=MISC_TRANSFORM_MAX_SOURCES,
                    maximum_bytes=MISC_TRANSFORM_MAX_SOURCE_BYTES,
                ),
                verifier_id=_safe_id(raw.verifier_id),
                tool_artifact_sha256=_safe_sha256(
                    raw.tool_artifact_sha256
                ),
                argv_contract_sha256=_safe_sha256(
                    raw.argv_contract_sha256
                ),
                execution_contract_sha256=_safe_sha256(
                    raw.execution_contract_sha256
                ),
                oracle_contract_sha256=_safe_sha256(
                    raw.oracle_contract_sha256
                ),
                clean_workspace=raw.clean_workspace is True,
                network_denied=raw.network_denied is True,
                target_exit_code=_safe_exit(raw.target_exit_code),
                runner_exit_code=_safe_exit(raw.runner_exit_code),
                ctfwrap_exit_code=_safe_exit(raw.ctfwrap_exit_code),
                timed_out=raw.timed_out is not False,
                orchestration_status=(
                    raw.orchestration_status
                    if raw.orchestration_status == "completed"
                    else ""
                ),
                result_artifact=result_artifact,
                stdout=stdout_record,
                stderr=stderr_record,
            )
        )

    unique_failures = tuple(dict.fromkeys(failures))
    passed = (
        not unique_failures
        and len(node_records) == len(plan.steps)
        and all(item.accepted for item in node_records)
        and len(reverse_records)
        == MISC_TRANSFORM_VERIFICATION_REPEATS
        and all(item.accepted for item in reverse_records)
    )
    evaluation = MiscTransformEvaluation(
        plan=plan,
        transform_nodes=tuple(node_records),
        reverse_verifications=tuple(reverse_records),
        failure_codes=unique_failures,
        passed=passed,
    )
    try:
        evaluation.canonical_bytes
    except ValueError:
        return MiscTransformEvaluation(
            plan=plan,
            transform_nodes=(),
            reverse_verifications=(),
            failure_codes=("plan_too_large",),
            passed=False,
        )
    return evaluation


def verify_misc_transform_evidence(
    evaluation: MiscTransformEvaluation,
    payload: bytes,
) -> bool:
    """Require the exact canonical recomputed persisted representation."""

    if (
        type(evaluation) is not MiscTransformEvaluation
        or type(payload) is not bytes
        or len(payload) > MISC_TRANSFORM_MAX_EVIDENCE_BYTES
    ):
        return False
    try:
        expected = evaluation.canonical_bytes
    except ValueError:
        return False
    return hmac.compare_digest(expected, payload)


__all__ = [
    "MISC_TRANSFORM_FAILURE_CODES",
    "MISC_TRANSFORM_MAX_CANDIDATE_BYTES",
    "MISC_TRANSFORM_MAX_EVIDENCE_BYTES",
    "MISC_TRANSFORM_MAX_OUTPUT_BYTES",
    "MISC_TRANSFORM_MAX_PARENTS",
    "MISC_TRANSFORM_MAX_SOURCES",
    "MISC_TRANSFORM_MAX_SOURCE_BYTES",
    "MISC_TRANSFORM_MAX_STEPS",
    "MISC_TRANSFORM_MAX_STREAM_BYTES",
    "MISC_TRANSFORM_PROTOCOL",
    "MISC_TRANSFORM_SCHEMA_VERSION",
    "MISC_TRANSFORM_VERIFICATION_REPEATS",
    "MiscArtifactRef",
    "MiscReverseVerificationObservation",
    "MiscReverseVerificationRecord",
    "MiscStreamEvidence",
    "MiscStreamRecord",
    "MiscTransformEvaluation",
    "MiscTransformNodeRecord",
    "MiscTransformObservation",
    "MiscTransformPlan",
    "MiscTransformPreflightError",
    "MiscTransformStepSpec",
    "MiscVerifierSpec",
    "build_misc_transform_plan",
    "evaluate_misc_transform_receipts",
    "expected_misc_reverse_result_artifact",
    "misc_transform_canonical_json_bytes",
    "misc_transform_node_commitment_sha256",
    "verify_misc_transform_evidence",
]
