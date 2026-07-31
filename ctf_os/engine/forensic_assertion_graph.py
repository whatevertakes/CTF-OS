"""Deterministic evidence-backed assertion graph for Forensic sessions.

The complete, transport-bound evidence index remains the immutable root of
trust.  This module extends that root with bounded typed pointers, a claim
dependency DAG, and independently executed tool observations.  It never
parses raw evidence and never treats model prose as proof.

Claim text, cookie-like values, credentials, and raw tool output are not part
of the schema.  Assertions carry only claim commitments; observations carry
only execution and artifact commitments.  A confirmed assertion must meet the
configured evidence-coverage threshold.  Each covered pointer needs two
independent tool families whenever the engine-owned tool registry says two are
available, otherwise one available family is required.

A passing evaluation can authorize only an executed Fact and ProgressMarker.
It cannot create a candidate, prove impact or a challenge flag, transition a
challenge to submission-ready, or submit anything.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from itertools import islice
from typing import TypeAlias

from ctf_os.engine.forensic_index import (
    FORENSIC_INDEX_MAX_FILES,
    ForensicSourceExpectation,
)
from ctf_os.engine.forensic_index_execution import (
    ForensicIndexExecutionEvaluation,
)


FORENSIC_ASSERTION_GRAPH_PROTOCOL = "ctfos.forensic.assertion_graph.v1"
FORENSIC_ASSERTION_GRAPH_SCHEMA_VERSION = 1
FORENSIC_ASSERTION_MIN_COVERAGE_PPM = 800_000
FORENSIC_ASSERTION_MAX_POINTERS = 512
FORENSIC_ASSERTION_MAX_ASSERTIONS = 256
FORENSIC_ASSERTION_MAX_TOOLS = 64
FORENSIC_ASSERTION_MAX_OBSERVATIONS = 1024
FORENSIC_ASSERTION_MAX_REFS_PER_ASSERTION = 128
FORENSIC_ASSERTION_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
FORENSIC_ASSERTION_MAX_PLAN_BYTES = 1024 * 1024
FORENSIC_ASSERTION_MAX_EVALUATION_BYTES = 2 * 1024 * 1024

FORENSIC_POINTER_KINDS = frozenset(
    {
        "file_range",
        "inode",
        "pcap_frame",
        "process",
        "timestamp",
    }
)
FORENSIC_CLAIM_KINDS = frozenset(
    {
        "artifact_identity",
        "causal_link",
        "data_presence",
        "entity_attribution",
        "execution_event",
        "network_event",
        "state_transition",
        "timeline_event",
    }
)
FORENSIC_TIMESTAMP_KINDS = frozenset(
    {
        "email_date",
        "event_created",
        "filesystem_atime",
        "filesystem_ctime",
        "filesystem_mtime",
        "log_event",
        "packet_capture",
        "process_start",
        "registry_write",
    }
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,255}$")
_SIGNED_NS_MIN = -(2**63)
_SIGNED_NS_MAX = 2**63 - 1
_MAX_SOURCE_BYTES = 128 * 1024**3
_MAX_U64 = 2**64 - 1
_NON_AUTHORITIES = {
    "automatic_submission_authorized": False,
    "candidate_authorized": False,
    "challenge_proof_satisfied": False,
    "flag_proven": False,
    "impact_proven": False,
    "self_report_accepted": False,
    "status_transition_authorized": False,
}


class ForensicAssertionPreflightError(ValueError):
    """The engine/operator supplied an invalid assertion graph plan."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ForensicAssertionState(str, Enum):
    HYPOTHESIS = "hypothesis"
    CONFIRMED = "confirmed"


class ForensicAssertionVerdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"


def _canonical_json_bytes(
    value: object,
    *,
    maximum_bytes: int | None = None,
) -> bytes:
    try:
        payload = (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise ValueError("canonical_json_invalid") from error
    if maximum_bytes is not None and len(payload) > maximum_bytes:
        raise ValueError("canonical_json_size_exceeded")
    return payload


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _valid_sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _valid_image_digest(value: object) -> bool:
    return type(value) is str and _IMAGE_DIGEST.fullmatch(value) is not None


def _valid_id(value: object) -> bool:
    return type(value) is str and _OPAQUE_ID.fullmatch(value) is not None


def _valid_int(
    value: object,
    *,
    minimum: int = 0,
    maximum: int = 2**63 - 1,
) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _bounded_tuple(
    values: Iterable[object],
    maximum: int,
    error_code: str,
) -> tuple[object, ...]:
    try:
        result = tuple(islice(iter(values), maximum + 1))
    except Exception as error:
        raise ForensicAssertionPreflightError(error_code) from error
    if len(result) > maximum:
        raise ForensicAssertionPreflightError(error_code)
    return result


@dataclass(frozen=True, slots=True)
class ForensicNormalizedTimestamp:
    """One explicitly timezone-normalized timestamp."""

    timestamp_kind: str
    source_local_epoch_ns: int
    source_utc_offset_minutes: int
    normalized_utc_epoch_ns: int
    precision_ns: int
    normalized_timezone: str = "UTC"

    def to_dict(self) -> dict[str, object]:
        return {
            "normalized_timezone": self.normalized_timezone,
            "normalized_utc_epoch_ns": self.normalized_utc_epoch_ns,
            "precision_ns": self.precision_ns,
            "source_local_epoch_ns": self.source_local_epoch_ns,
            "source_utc_offset_minutes": self.source_utc_offset_minutes,
            "timestamp_kind": self.timestamp_kind,
        }


@dataclass(frozen=True, slots=True)
class ForensicFileRangePointer:
    pointer_id: str
    source_path: str
    source_sha256: str
    offset_bytes: int
    length_bytes: int

    @property
    def kind(self) -> str:
        return "file_range"

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "length_bytes": self.length_bytes,
            "offset_bytes": self.offset_bytes,
            "pointer_id": self.pointer_id,
            "source_path": self.source_path,
            "source_sha256": self.source_sha256,
        }


@dataclass(frozen=True, slots=True)
class ForensicPcapFramePointer:
    pointer_id: str
    source_path: str
    source_sha256: str
    frame_number: int
    packet_offset_bytes: int
    captured_length_bytes: int
    original_length_bytes: int
    packet_sha256: str
    timestamp: ForensicNormalizedTimestamp

    @property
    def kind(self) -> str:
        return "pcap_frame"

    def to_dict(self) -> dict[str, object]:
        return {
            "captured_length_bytes": self.captured_length_bytes,
            "frame_number": self.frame_number,
            "kind": self.kind,
            "original_length_bytes": self.original_length_bytes,
            "packet_offset_bytes": self.packet_offset_bytes,
            "packet_sha256": self.packet_sha256,
            "pointer_id": self.pointer_id,
            "source_path": self.source_path,
            "source_sha256": self.source_sha256,
            "timestamp": self.timestamp.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class ForensicProcessPointer:
    pointer_id: str
    source_path: str
    source_sha256: str
    pid: int
    virtual_address: int
    object_offset_bytes: int
    object_length_bytes: int
    object_sha256: str
    process_start: ForensicNormalizedTimestamp

    @property
    def kind(self) -> str:
        return "process"

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "object_length_bytes": self.object_length_bytes,
            "object_offset_bytes": self.object_offset_bytes,
            "object_sha256": self.object_sha256,
            "pid": self.pid,
            "pointer_id": self.pointer_id,
            "process_start": self.process_start.to_dict(),
            "source_path": self.source_path,
            "source_sha256": self.source_sha256,
            "virtual_address": self.virtual_address,
        }


@dataclass(frozen=True, slots=True)
class ForensicInodePointer:
    pointer_id: str
    source_path: str
    source_sha256: str
    partition_offset_bytes: int
    inode_number: int
    metadata_offset_bytes: int
    metadata_length_bytes: int
    metadata_sha256: str

    @property
    def kind(self) -> str:
        return "inode"

    def to_dict(self) -> dict[str, object]:
        return {
            "inode_number": self.inode_number,
            "kind": self.kind,
            "metadata_length_bytes": self.metadata_length_bytes,
            "metadata_offset_bytes": self.metadata_offset_bytes,
            "metadata_sha256": self.metadata_sha256,
            "partition_offset_bytes": self.partition_offset_bytes,
            "pointer_id": self.pointer_id,
            "source_path": self.source_path,
            "source_sha256": self.source_sha256,
        }


@dataclass(frozen=True, slots=True)
class ForensicTimestampPointer:
    pointer_id: str
    source_path: str
    source_sha256: str
    field_offset_bytes: int
    field_length_bytes: int
    field_sha256: str
    timestamp: ForensicNormalizedTimestamp

    @property
    def kind(self) -> str:
        return "timestamp"

    def to_dict(self) -> dict[str, object]:
        return {
            "field_length_bytes": self.field_length_bytes,
            "field_offset_bytes": self.field_offset_bytes,
            "field_sha256": self.field_sha256,
            "kind": self.kind,
            "pointer_id": self.pointer_id,
            "source_path": self.source_path,
            "source_sha256": self.source_sha256,
            "timestamp": self.timestamp.to_dict(),
        }


ForensicEvidencePointer: TypeAlias = (
    ForensicFileRangePointer
    | ForensicPcapFramePointer
    | ForensicProcessPointer
    | ForensicInodePointer
    | ForensicTimestampPointer
)


@dataclass(frozen=True, slots=True)
class ForensicToolBinding:
    """Engine-owned readiness-registry entry."""

    tool_id: str
    independence_family: str
    tool_version_sha256: str
    runtime_image_digest: str
    supported_pointer_kinds: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "independence_family": self.independence_family,
            "runtime_image_digest": self.runtime_image_digest,
            "supported_pointer_kinds": list(self.supported_pointer_kinds),
            "tool_id": self.tool_id,
            "tool_version_sha256": self.tool_version_sha256,
        }


@dataclass(frozen=True, slots=True)
class ForensicAssertionNode:
    assertion_id: str
    state: ForensicAssertionState
    claim_kind: str
    claim_sha256: str
    depends_on: tuple[str, ...]
    evidence_pointer_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "assertion_id": self.assertion_id,
            "claim_kind": self.claim_kind,
            "claim_sha256": self.claim_sha256,
            "depends_on": list(self.depends_on),
            "evidence_pointer_ids": list(self.evidence_pointer_ids),
            "state": self.state.value,
        }


@dataclass(frozen=True, slots=True)
class ForensicAssertionInventoryRoot:
    source_manifest_sha256: str
    source_inventory_sha256: str
    source_file_count: int
    source_total_bytes: int
    evidence_index_sha256: str
    evidence_tree_sha256: str
    index_execution_evaluation_sha256: str
    index_execution_envelope_sha256: str
    index_run_id: str
    index_receipt_id: str
    index_artifact_id: str
    index_artifact_sha256: str
    index_artifact_size_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "evidence_index_sha256": self.evidence_index_sha256,
            "evidence_tree_sha256": self.evidence_tree_sha256,
            "index_artifact": {
                "artifact_id": self.index_artifact_id,
                "sha256": self.index_artifact_sha256,
                "size_bytes": self.index_artifact_size_bytes,
            },
            "index_execution_envelope_sha256": (
                self.index_execution_envelope_sha256
            ),
            "index_execution_evaluation_sha256": (
                self.index_execution_evaluation_sha256
            ),
            "index_receipt_id": self.index_receipt_id,
            "index_run_id": self.index_run_id,
            "source_file_count": self.source_file_count,
            "source_inventory_sha256": self.source_inventory_sha256,
            "source_manifest_sha256": self.source_manifest_sha256,
            "source_total_bytes": self.source_total_bytes,
        }


@dataclass(frozen=True, slots=True)
class ForensicAssertionGraphPlan:
    """Canonical plan rooted in one confirmed evidence-index execution."""

    index_execution: ForensicIndexExecutionEvaluation
    sources: tuple[ForensicSourceExpectation, ...]
    inventory_root: ForensicAssertionInventoryRoot
    tools: tuple[ForensicToolBinding, ...]
    pointers: tuple[ForensicEvidencePointer, ...]
    assertions: tuple[ForensicAssertionNode, ...]
    coverage_threshold_ppm: int

    @property
    def source_catalog_sha256(self) -> str:
        return _source_inventory_sha256(self.sources)

    def content_dict(self) -> dict[str, object]:
        return {
            "assertions": [item.to_dict() for item in self.assertions],
            "coverage_policy": {
                "coverage_basis": "corroborated_pointer_count",
                "corroboration_scope": "per_pointer",
                "independent_tool_families_when_available": 2,
                "minimum_coverage_ppm": self.coverage_threshold_ppm,
                "single_family_fallback_only_when_registry_has_one": True,
            },
            "inventory_root": self.inventory_root.to_dict(),
            "pointers": [item.to_dict() for item in self.pointers],
            "protocol": FORENSIC_ASSERTION_GRAPH_PROTOCOL,
            "schema_version": FORENSIC_ASSERTION_GRAPH_SCHEMA_VERSION,
            "source_catalog_sha256": self.source_catalog_sha256,
            "tools": [item.to_dict() for item in self.tools],
        }

    @property
    def plan_sha256(self) -> str:
        return _sha256(
            _canonical_json_bytes(
                self.content_dict(),
                maximum_bytes=FORENSIC_ASSERTION_MAX_PLAN_BYTES,
            )
        )

    def to_dict(self) -> dict[str, object]:
        value = self.content_dict()
        value["plan_sha256"] = self.plan_sha256
        return value

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(
            self.to_dict(),
            maximum_bytes=FORENSIC_ASSERTION_MAX_PLAN_BYTES,
        )


@dataclass(frozen=True, slots=True)
class ForensicObservationArtifact:
    artifact_id: str
    sha256: str
    size_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True, slots=True)
class ForensicCorroborationObservation:
    """Engine-derived receipt for one pointer/tool execution."""

    observation_id: str
    pointer_id: str
    tool_id: str
    run_id: str
    receipt_id: str
    receipt_sha256: str
    execution_nonce_sha256: str
    execution_contract_sha256: str
    plan_sha256: str
    source_manifest_sha256: str
    source_inventory_sha256: str
    runtime_image_digest: str
    clean_workspace: bool
    network_disabled: bool
    orchestration_status: str
    exit_code: int | None
    timed_out: bool
    capture_complete: bool
    truncation_known: bool
    truncated: bool | None
    capture_error: str | None
    observation_artifact: ForensicObservationArtifact


@dataclass(frozen=True, slots=True)
class ForensicCorroborationRecord:
    observation_id: str
    pointer_id: str
    pointer_sha256: str
    pointer_kind: str
    tool_id: str
    independence_family: str
    tool_version_sha256: str
    run_id: str
    receipt_id: str
    receipt_sha256: str
    execution_nonce_sha256: str
    execution_contract_sha256: str
    observation_artifact: ForensicObservationArtifact

    def to_dict(self) -> dict[str, object]:
        return {
            "execution_contract_sha256": (
                self.execution_contract_sha256
            ),
            "execution_nonce_sha256": self.execution_nonce_sha256,
            "independence_family": self.independence_family,
            "observation_artifact": self.observation_artifact.to_dict(),
            "observation_id": self.observation_id,
            "pointer_id": self.pointer_id,
            "pointer_kind": self.pointer_kind,
            "pointer_sha256": self.pointer_sha256,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "run_id": self.run_id,
            "tool_id": self.tool_id,
            "tool_version_sha256": self.tool_version_sha256,
            "transport": {
                "capture_complete": True,
                "clean_workspace": True,
                "exit_code": 0,
                "network": "disabled",
                "orchestration_status": "completed",
                "timed_out": False,
                "truncated": False,
                "truncation_known": True,
            },
        }


@dataclass(frozen=True, slots=True)
class ForensicAssertionCoverageRecord:
    assertion_id: str
    state: ForensicAssertionState
    total_pointer_count: int
    covered_pointer_count: int
    coverage_ppm: int
    threshold_ppm: int
    covered_pointer_ids: tuple[str, ...]
    insufficient_pointer_ids: tuple[str, ...]

    @property
    def confirmed_requirement_met(self) -> bool:
        return (
            self.state is ForensicAssertionState.CONFIRMED
            and self.total_pointer_count > 0
            and self.coverage_ppm >= self.threshold_ppm
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "assertion_id": self.assertion_id,
            "confirmed_requirement_met": (
                self.confirmed_requirement_met
            ),
            "coverage_ppm": self.coverage_ppm,
            "covered_pointer_count": self.covered_pointer_count,
            "covered_pointer_ids": list(self.covered_pointer_ids),
            "insufficient_pointer_ids": list(
                self.insufficient_pointer_ids
            ),
            "state": self.state.value,
            "threshold_ppm": self.threshold_ppm,
            "total_pointer_count": self.total_pointer_count,
        }


@dataclass(frozen=True, slots=True)
class ForensicAssertionGraphEvaluation:
    plan: ForensicAssertionGraphPlan | None
    corroboration_records: tuple[ForensicCorroborationRecord, ...]
    coverage_records: tuple[ForensicAssertionCoverageRecord, ...]
    failure_codes: tuple[str, ...]
    verdict: ForensicAssertionVerdict

    @property
    def passed(self) -> bool:
        if (
            self.verdict is not ForensicAssertionVerdict.CONFIRMED
            or self.plan is None
            or self.failure_codes
            or not _plan_is_canonical(self.plan)
            or type(self.corroboration_records) is not tuple
            or not self.corroboration_records
            or any(
                type(item) is not ForensicCorroborationRecord
                for item in self.corroboration_records
            )
            or type(self.coverage_records) is not tuple
            or len(self.coverage_records) != len(self.plan.assertions)
        ):
            return False
        confirmed: list[ForensicAssertionCoverageRecord] = []
        for assertion, coverage in zip(
            self.plan.assertions,
            self.coverage_records,
            strict=True,
        ):
            if type(coverage) is not ForensicAssertionCoverageRecord:
                return False
            if (
                type(coverage.covered_pointer_ids) is not tuple
                or type(coverage.insufficient_pointer_ids) is not tuple
                or any(
                    not _valid_id(pointer_id)
                    for pointer_id in (
                        *coverage.covered_pointer_ids,
                        *coverage.insufficient_pointer_ids,
                    )
                )
                or not _valid_int(coverage.total_pointer_count)
                or not _valid_int(coverage.covered_pointer_count)
                or not _valid_int(
                    coverage.coverage_ppm,
                    maximum=1_000_000,
                )
                or not _valid_int(
                    coverage.threshold_ppm,
                    minimum=FORENSIC_ASSERTION_MIN_COVERAGE_PPM,
                    maximum=1_000_000,
                )
            ):
                return False
            pointer_ids = set(assertion.evidence_pointer_ids)
            covered_ids = set(coverage.covered_pointer_ids)
            insufficient_ids = set(coverage.insufficient_pointer_ids)
            if (
                coverage.assertion_id != assertion.assertion_id
                or coverage.state is not assertion.state
                or coverage.threshold_ppm
                != self.plan.coverage_threshold_ppm
                or coverage.total_pointer_count
                != len(assertion.evidence_pointer_ids)
                or coverage.covered_pointer_count
                != len(coverage.covered_pointer_ids)
                or covered_ids & insufficient_ids
                or covered_ids | insufficient_ids != pointer_ids
                or coverage.coverage_ppm
                != (
                    coverage.covered_pointer_count * 1_000_000
                    // coverage.total_pointer_count
                    if coverage.total_pointer_count
                    else 0
                )
            ):
                return False
            for pointer_id in covered_ids:
                corroborations = [
                    record
                    for record in self.corroboration_records
                    if record.pointer_id == pointer_id
                ]
                if (
                    len(
                        {
                            record.independence_family
                            for record in corroborations
                        }
                    )
                    < 2
                    or len(
                        {
                            record.tool_version_sha256
                            for record in corroborations
                        }
                    )
                    < 2
                ):
                    return False
            if assertion.state is ForensicAssertionState.CONFIRMED:
                confirmed.append(coverage)
        return bool(confirmed) and all(
            item.confirmed_requirement_met for item in confirmed
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "authorities": {
                **_NON_AUTHORITIES,
                "executed_forensic_assertion_fact_authorized": self.passed,
                "forensic_assertion_graph_confirmed": self.passed,
                "progress_marker_authorized": self.passed,
            },
            "corroboration_records": [
                item.to_dict() for item in self.corroboration_records
            ],
            "coverage_records": [
                item.to_dict() for item in self.coverage_records
            ],
            "failure_codes": list(self.failure_codes),
            "passed": self.passed,
            "plan": self.plan.to_dict() if self.plan is not None else None,
            "plan_sha256": (
                self.plan.plan_sha256
                if self.plan is not None
                else None
            ),
            "protocol": FORENSIC_ASSERTION_GRAPH_PROTOCOL,
            "schema_version": FORENSIC_ASSERTION_GRAPH_SCHEMA_VERSION,
            "verdict": self.verdict.value,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(
            self.to_dict(),
            maximum_bytes=FORENSIC_ASSERTION_MAX_EVALUATION_BYTES,
        )

    @property
    def sha256(self) -> str:
        return _sha256(self.canonical_bytes)

    def reduction_projection(self) -> dict[str, object]:
        """Return only the narrow state effects this gate may authorize."""

        if not self.passed:
            return {
                "automatic_submission": False,
                "candidate": None,
                "executed_fact": None,
                "impact": None,
                "progress": None,
                "proof": None,
            }
        assert self.plan is not None
        confirmed_ids = {
            item.assertion_id
            for item in self.coverage_records
            if item.state is ForensicAssertionState.CONFIRMED
        }
        confirmed_pointer_ids = {
            pointer_id
            for assertion in self.plan.assertions
            if assertion.assertion_id in confirmed_ids
            for pointer_id in assertion.evidence_pointer_ids
        }
        evidence = tuple(
            item
            for item in self.corroboration_records
            if item.pointer_id in confirmed_pointer_ids
        )
        first = evidence[0]
        artifact_ids = sorted(
            {
                item.observation_artifact.artifact_id
                for item in evidence
            }
        )
        minimum_coverage = min(
            item.coverage_ppm
            for item in self.coverage_records
            if item.state is ForensicAssertionState.CONFIRMED
        )
        binding = {
            "evaluation_sha256": self.sha256,
            "index_execution_evaluation_sha256": (
                self.plan.inventory_root
                .index_execution_evaluation_sha256
            ),
            "minimum_confirmed_coverage_ppm": minimum_coverage,
            "plan_sha256": self.plan.plan_sha256,
            "source_inventory_sha256": (
                self.plan.inventory_root.source_inventory_sha256
            ),
            "source_manifest_sha256": (
                self.plan.inventory_root.source_manifest_sha256
            ),
        }
        return {
            "automatic_submission": False,
            "candidate": None,
            "executed_fact": {
                "artifact_id": first.observation_artifact.artifact_id,
                "extra": {
                    "forensic_assertion_graph": binding,
                },
                "provenance": "executed",
                "source_run_id": first.run_id,
                "statement": (
                    "Engine-validated Forensic assertion graph confirmed "
                    f"{len(confirmed_ids)} claim commitments at minimum "
                    f"{minimum_coverage} ppm evidence coverage."
                ),
            },
            "impact": None,
            "progress": {
                "artifact_ids": artifact_ids,
                "extra": {
                    "forensic_assertion_graph": binding,
                },
                "run_id": first.run_id,
                "statement": (
                    "Typed Forensic evidence pointers and independent "
                    "corroboration satisfied the assertion graph gate"
                ),
            },
            "proof": None,
        }


def _source_inventory_sha256(
    sources: tuple[ForensicSourceExpectation, ...],
) -> str:
    return _sha256(
        _canonical_json_bytes(
            [item.commitment() for item in sources]
        )
    )


def _normalized_sources(
    values: Iterable[ForensicSourceExpectation],
) -> tuple[ForensicSourceExpectation, ...]:
    raw = _bounded_tuple(
        values,
        FORENSIC_INDEX_MAX_FILES,
        "source_catalog_invalid",
    )
    if any(type(item) is not ForensicSourceExpectation for item in raw):
        raise ForensicAssertionPreflightError("source_catalog_invalid")
    result = tuple(
        sorted(raw, key=lambda item: item.path.encode("utf-8"))
    )
    if len({item.path for item in result}) != len(result):
        raise ForensicAssertionPreflightError("source_catalog_invalid")
    if sum(item.size_bytes for item in result) > _MAX_SOURCE_BYTES:
        raise ForensicAssertionPreflightError("source_catalog_invalid")
    return result


def _inventory_root(
    execution: ForensicIndexExecutionEvaluation,
    sources: tuple[ForensicSourceExpectation, ...],
) -> ForensicAssertionInventoryRoot:
    if (
        type(execution) is not ForensicIndexExecutionEvaluation
        or not execution.confirmed
        or execution.envelope is None
        or execution.semantic_evaluation is None
    ):
        raise ForensicAssertionPreflightError(
            "index_execution_not_confirmed"
        )
    envelope = execution.envelope
    semantic = execution.semantic_evaluation
    source_inventory_sha256 = _source_inventory_sha256(sources)
    if (
        envelope.category != "forensics"
        or source_inventory_sha256 != envelope.source_inventory_sha256
        or source_inventory_sha256
        != semantic.source_inventory_sha256
        or len(sources) != envelope.source_file_count
        or sum(item.size_bytes for item in sources)
        != envelope.source_total_bytes
        or not _valid_sha256(envelope.source_manifest_sha256)
        or not _valid_sha256(semantic.index_sha256)
        or not _valid_sha256(semantic.tree_sha256)
        or not _valid_id(envelope.run_id)
        or not _valid_id(envelope.receipt_id)
        or not _valid_id(envelope.stdout_artifact_id)
        or not _valid_sha256(envelope.stdout_artifact_sha256)
        or not _valid_int(
            envelope.stdout_artifact_size_bytes,
            minimum=1,
            maximum=FORENSIC_ASSERTION_MAX_ARTIFACT_BYTES,
        )
    ):
        raise ForensicAssertionPreflightError(
            "index_execution_inventory_mismatch"
        )
    return ForensicAssertionInventoryRoot(
        source_manifest_sha256=envelope.source_manifest_sha256,
        source_inventory_sha256=source_inventory_sha256,
        source_file_count=len(sources),
        source_total_bytes=sum(item.size_bytes for item in sources),
        evidence_index_sha256=str(semantic.index_sha256),
        evidence_tree_sha256=str(semantic.tree_sha256),
        index_execution_evaluation_sha256=execution.sha256,
        index_execution_envelope_sha256=envelope.sha256,
        index_run_id=envelope.run_id,
        index_receipt_id=envelope.receipt_id,
        index_artifact_id=envelope.stdout_artifact_id,
        index_artifact_sha256=envelope.stdout_artifact_sha256,
        index_artifact_size_bytes=envelope.stdout_artifact_size_bytes,
    )


def _timestamp_valid(
    value: object,
    *,
    expected_kind: str | None = None,
) -> bool:
    if (
        type(value) is not ForensicNormalizedTimestamp
        or type(value.timestamp_kind) is not str
        or value.timestamp_kind not in FORENSIC_TIMESTAMP_KINDS
        or (
            expected_kind is not None
            and value.timestamp_kind != expected_kind
        )
        or not _valid_int(
            value.source_local_epoch_ns,
            minimum=_SIGNED_NS_MIN,
            maximum=_SIGNED_NS_MAX,
        )
        or not _valid_int(
            value.source_utc_offset_minutes,
            minimum=-14 * 60,
            maximum=14 * 60,
        )
        or not _valid_int(
            value.normalized_utc_epoch_ns,
            minimum=_SIGNED_NS_MIN,
            maximum=_SIGNED_NS_MAX,
        )
        or not _valid_int(
            value.precision_ns,
            minimum=1,
            maximum=86_400 * 1_000_000_000,
        )
        or value.normalized_timezone != "UTC"
    ):
        return False
    normalized = (
        value.source_local_epoch_ns
        - value.source_utc_offset_minutes * 60 * 1_000_000_000
    )
    return (
        normalized == value.normalized_utc_epoch_ns
        and normalized % value.precision_ns == 0
    )


def _pointer_kind(pointer: ForensicEvidencePointer) -> str:
    return pointer.kind


def _pointer_dict(
    pointer: ForensicEvidencePointer,
) -> dict[str, object]:
    return pointer.to_dict()


def forensic_evidence_pointer_sha256(
    pointer: ForensicEvidencePointer,
) -> str:
    """Commit one exact typed pointer."""

    if type(pointer) not in {
        ForensicFileRangePointer,
        ForensicPcapFramePointer,
        ForensicProcessPointer,
        ForensicInodePointer,
        ForensicTimestampPointer,
    }:
        raise TypeError("pointer must be an exact Forensic pointer type")
    return _sha256(_canonical_json_bytes(_pointer_dict(pointer)))


def _pointer_common(
    pointer: ForensicEvidencePointer,
) -> tuple[str, str, str] | None:
    if not _valid_id(pointer.pointer_id):
        return None
    if type(pointer.source_path) is not str or not pointer.source_path:
        return None
    if not _valid_sha256(pointer.source_sha256):
        return None
    return (
        pointer.pointer_id,
        pointer.source_path,
        pointer.source_sha256,
    )


def _pointer_span(
    pointer: ForensicEvidencePointer,
) -> tuple[tuple[object, ...], int, int]:
    if type(pointer) is ForensicFileRangePointer:
        return (
            (pointer.kind, pointer.source_path),
            pointer.offset_bytes,
            pointer.offset_bytes + pointer.length_bytes,
        )
    if type(pointer) is ForensicPcapFramePointer:
        return (
            (pointer.kind, pointer.source_path, pointer.frame_number),
            pointer.packet_offset_bytes,
            pointer.packet_offset_bytes
            + pointer.captured_length_bytes,
        )
    if type(pointer) is ForensicProcessPointer:
        return (
            (
                pointer.kind,
                pointer.source_path,
                pointer.pid,
                pointer.process_start.normalized_utc_epoch_ns,
            ),
            pointer.object_offset_bytes,
            pointer.object_offset_bytes + pointer.object_length_bytes,
        )
    if type(pointer) is ForensicInodePointer:
        return (
            (
                pointer.kind,
                pointer.source_path,
                pointer.partition_offset_bytes,
                pointer.inode_number,
            ),
            pointer.metadata_offset_bytes,
            pointer.metadata_offset_bytes
            + pointer.metadata_length_bytes,
        )
    assert type(pointer) is ForensicTimestampPointer
    return (
        (
            pointer.kind,
            pointer.source_path,
            pointer.timestamp.timestamp_kind,
        ),
        pointer.field_offset_bytes,
        pointer.field_offset_bytes + pointer.field_length_bytes,
    )


def _pointer_valid(
    pointer: object,
    sources: dict[str, ForensicSourceExpectation],
) -> bool:
    if type(pointer) not in {
        ForensicFileRangePointer,
        ForensicPcapFramePointer,
        ForensicProcessPointer,
        ForensicInodePointer,
        ForensicTimestampPointer,
    }:
        return False
    common = _pointer_common(pointer)
    if common is None:
        return False
    _, path, sha256 = common
    source = sources.get(path)
    if source is None or source.sha256 != sha256:
        return False
    if type(pointer) is ForensicFileRangePointer:
        return (
            _valid_int(pointer.offset_bytes, maximum=source.size_bytes)
            and _valid_int(
                pointer.length_bytes,
                minimum=1,
                maximum=source.size_bytes,
            )
            and pointer.offset_bytes + pointer.length_bytes
            <= source.size_bytes
        )
    if type(pointer) is ForensicPcapFramePointer:
        return (
            _valid_int(pointer.frame_number, minimum=1)
            and _valid_int(
                pointer.packet_offset_bytes,
                maximum=source.size_bytes,
            )
            and _valid_int(
                pointer.captured_length_bytes,
                minimum=1,
                maximum=source.size_bytes,
            )
            and pointer.packet_offset_bytes
            + pointer.captured_length_bytes
            <= source.size_bytes
            and _valid_int(
                pointer.original_length_bytes,
                minimum=pointer.captured_length_bytes,
                maximum=2**32 - 1,
            )
            and _valid_sha256(pointer.packet_sha256)
            and _timestamp_valid(
                pointer.timestamp,
                expected_kind="packet_capture",
            )
        )
    if type(pointer) is ForensicProcessPointer:
        return (
            _valid_int(pointer.pid, minimum=1, maximum=2**32 - 1)
            and _valid_int(pointer.virtual_address, maximum=_MAX_U64)
            and _valid_int(
                pointer.object_offset_bytes,
                maximum=source.size_bytes,
            )
            and _valid_int(
                pointer.object_length_bytes,
                minimum=1,
                maximum=source.size_bytes,
            )
            and pointer.object_offset_bytes
            + pointer.object_length_bytes
            <= source.size_bytes
            and _valid_sha256(pointer.object_sha256)
            and _timestamp_valid(
                pointer.process_start,
                expected_kind="process_start",
            )
        )
    if type(pointer) is ForensicInodePointer:
        return (
            _valid_int(
                pointer.partition_offset_bytes,
                maximum=source.size_bytes,
            )
            and _valid_int(pointer.inode_number, minimum=1, maximum=_MAX_U64)
            and _valid_int(
                pointer.metadata_offset_bytes,
                minimum=pointer.partition_offset_bytes,
                maximum=source.size_bytes,
            )
            and _valid_int(
                pointer.metadata_length_bytes,
                minimum=1,
                maximum=source.size_bytes,
            )
            and pointer.metadata_offset_bytes
            + pointer.metadata_length_bytes
            <= source.size_bytes
            and _valid_sha256(pointer.metadata_sha256)
        )
    assert type(pointer) is ForensicTimestampPointer
    return (
        _valid_int(
            pointer.field_offset_bytes,
            maximum=source.size_bytes,
        )
        and _valid_int(
            pointer.field_length_bytes,
            minimum=1,
            maximum=source.size_bytes,
        )
        and pointer.field_offset_bytes + pointer.field_length_bytes
        <= source.size_bytes
        and _valid_sha256(pointer.field_sha256)
        and _timestamp_valid(pointer.timestamp)
    )


def _normalized_tools(
    values: Iterable[ForensicToolBinding],
) -> tuple[ForensicToolBinding, ...]:
    raw = _bounded_tuple(
        values,
        FORENSIC_ASSERTION_MAX_TOOLS,
        "tool_registry_invalid",
    )
    if not raw or any(type(item) is not ForensicToolBinding for item in raw):
        raise ForensicAssertionPreflightError("tool_registry_invalid")
    for item in raw:
        if (
            not _valid_id(item.tool_id)
            or not _valid_id(item.independence_family)
            or not _valid_sha256(item.tool_version_sha256)
            or not _valid_image_digest(item.runtime_image_digest)
            or type(item.supported_pointer_kinds) is not tuple
            or not item.supported_pointer_kinds
            or any(
                type(kind) is not str
                or kind not in FORENSIC_POINTER_KINDS
                for kind in item.supported_pointer_kinds
            )
            or item.supported_pointer_kinds
            != tuple(sorted(set(item.supported_pointer_kinds)))
        ):
            raise ForensicAssertionPreflightError("tool_registry_invalid")
    result = tuple(sorted(raw, key=lambda item: item.tool_id))
    if len({item.tool_id for item in result}) != len(result):
        raise ForensicAssertionPreflightError("tool_registry_invalid")
    return result


def _normalized_pointers(
    values: Iterable[ForensicEvidencePointer],
    sources: tuple[ForensicSourceExpectation, ...],
) -> tuple[ForensicEvidencePointer, ...]:
    raw = _bounded_tuple(
        values,
        FORENSIC_ASSERTION_MAX_POINTERS,
        "pointer_schema_invalid",
    )
    if not raw:
        raise ForensicAssertionPreflightError("pointer_schema_invalid")
    source_map = {item.path: item for item in sources}
    if any(not _pointer_valid(item, source_map) for item in raw):
        raise ForensicAssertionPreflightError("pointer_schema_invalid")
    result = tuple(sorted(raw, key=lambda item: item.pointer_id))
    if len({item.pointer_id for item in result}) != len(result):
        raise ForensicAssertionPreflightError("pointer_id_duplicate")
    spans = sorted(
        (_pointer_span(item), item.pointer_id)
        for item in result
    )
    previous_by_domain: dict[tuple[object, ...], tuple[int, str]] = {}
    for (domain, start, end), pointer_id in spans:
        previous = previous_by_domain.get(domain)
        if previous is not None and start < previous[0]:
            raise ForensicAssertionPreflightError("pointer_overlap")
        previous_by_domain[domain] = (end, pointer_id)
    return result


def _graph_cycle(
    assertions: tuple[ForensicAssertionNode, ...],
) -> bool:
    dependencies = {
        item.assertion_id: item.depends_on for item in assertions
    }
    colors: dict[str, int] = {}

    def visit(assertion_id: str) -> bool:
        color = colors.get(assertion_id, 0)
        if color == 1:
            return True
        if color == 2:
            return False
        colors[assertion_id] = 1
        for dependency in dependencies[assertion_id]:
            if visit(dependency):
                return True
        colors[assertion_id] = 2
        return False

    return any(visit(item.assertion_id) for item in assertions)


def _normalized_assertions(
    values: Iterable[ForensicAssertionNode],
    pointers: tuple[ForensicEvidencePointer, ...],
) -> tuple[ForensicAssertionNode, ...]:
    raw = _bounded_tuple(
        values,
        FORENSIC_ASSERTION_MAX_ASSERTIONS,
        "assertion_schema_invalid",
    )
    if not raw or any(type(item) is not ForensicAssertionNode for item in raw):
        raise ForensicAssertionPreflightError("assertion_schema_invalid")
    for item in raw:
        if (
            not _valid_id(item.assertion_id)
            or type(item.state) is not ForensicAssertionState
            or type(item.claim_kind) is not str
            or item.claim_kind not in FORENSIC_CLAIM_KINDS
            or not _valid_sha256(item.claim_sha256)
            or type(item.depends_on) is not tuple
            or type(item.evidence_pointer_ids) is not tuple
            or len(item.depends_on)
            > FORENSIC_ASSERTION_MAX_REFS_PER_ASSERTION
            or len(item.evidence_pointer_ids)
            > FORENSIC_ASSERTION_MAX_REFS_PER_ASSERTION
            or any(not _valid_id(value) for value in item.depends_on)
            or any(
                not _valid_id(value)
                for value in item.evidence_pointer_ids
            )
        ):
            raise ForensicAssertionPreflightError(
                "assertion_schema_invalid"
            )
    result = tuple(sorted(raw, key=lambda item: item.assertion_id))
    ids = {item.assertion_id for item in result}
    pointer_ids = {item.pointer_id for item in pointers}
    if (
        len(ids) != len(result)
        or len({item.claim_sha256 for item in result}) != len(result)
    ):
        raise ForensicAssertionPreflightError("assertion_id_or_claim_duplicate")
    referenced_pointers: set[str] = set()
    for item in result:
        if (
            item.depends_on != tuple(sorted(set(item.depends_on)))
            or item.evidence_pointer_ids
            != tuple(sorted(set(item.evidence_pointer_ids)))
            or item.assertion_id in item.depends_on
        ):
            raise ForensicAssertionPreflightError(
                "assertion_schema_invalid"
            )
        if any(dependency not in ids for dependency in item.depends_on):
            raise ForensicAssertionPreflightError(
                "assertion_dependency_unknown"
            )
        if any(
            pointer_id not in pointer_ids
            for pointer_id in item.evidence_pointer_ids
        ):
            raise ForensicAssertionPreflightError(
                "assertion_pointer_unknown"
            )
        if (
            item.state is ForensicAssertionState.CONFIRMED
            and not item.evidence_pointer_ids
        ):
            raise ForensicAssertionPreflightError(
                "confirmed_assertion_without_evidence"
            )
        referenced_pointers.update(item.evidence_pointer_ids)
    if referenced_pointers != pointer_ids:
        raise ForensicAssertionPreflightError("pointer_unreferenced")
    if _graph_cycle(result):
        raise ForensicAssertionPreflightError("assertion_cycle")
    states = {item.assertion_id: item.state for item in result}
    for item in result:
        if (
            item.state is ForensicAssertionState.CONFIRMED
            and any(
                states[dependency]
                is not ForensicAssertionState.CONFIRMED
                for dependency in item.depends_on
            )
        ):
            raise ForensicAssertionPreflightError(
                "confirmed_depends_on_hypothesis"
            )
    return result


def build_forensic_assertion_graph_plan(
    *,
    index_execution: ForensicIndexExecutionEvaluation,
    expected_sources: Iterable[ForensicSourceExpectation],
    tools: Iterable[ForensicToolBinding],
    pointers: Iterable[ForensicEvidencePointer],
    assertions: Iterable[ForensicAssertionNode],
    coverage_threshold_ppm: int = FORENSIC_ASSERTION_MIN_COVERAGE_PPM,
) -> ForensicAssertionGraphPlan:
    """Build a canonical assertion graph rooted in a confirmed index run."""

    if not _valid_int(
        coverage_threshold_ppm,
        minimum=FORENSIC_ASSERTION_MIN_COVERAGE_PPM,
        maximum=1_000_000,
    ):
        raise ForensicAssertionPreflightError(
            "coverage_threshold_invalid"
        )
    source_values = _normalized_sources(expected_sources)
    root = _inventory_root(index_execution, source_values)
    tool_values = _normalized_tools(tools)
    pointer_values = _normalized_pointers(pointers, source_values)
    assertion_values = _normalized_assertions(
        assertions,
        pointer_values,
    )
    plan = ForensicAssertionGraphPlan(
        index_execution=index_execution,
        sources=source_values,
        inventory_root=root,
        tools=tool_values,
        pointers=pointer_values,
        assertions=assertion_values,
        coverage_threshold_ppm=coverage_threshold_ppm,
    )
    try:
        plan.canonical_bytes
    except ValueError as error:
        raise ForensicAssertionPreflightError(
            "plan_size_exceeded"
        ) from error
    return plan


def _plan_error(plan: object) -> str | None:
    if type(plan) is not ForensicAssertionGraphPlan:
        return "plan_type_invalid"
    try:
        sources = _normalized_sources(plan.sources)
        if sources != plan.sources:
            return "source_catalog_noncanonical"
        root = _inventory_root(plan.index_execution, sources)
        if root != plan.inventory_root:
            return "inventory_root_mismatch"
        tools = _normalized_tools(plan.tools)
        if tools != plan.tools:
            return "tool_registry_noncanonical"
        pointers = _normalized_pointers(plan.pointers, sources)
        if pointers != plan.pointers:
            return "pointers_noncanonical"
        assertions = _normalized_assertions(plan.assertions, pointers)
        if assertions != plan.assertions:
            return "assertions_noncanonical"
        if not _valid_int(
            plan.coverage_threshold_ppm,
            minimum=FORENSIC_ASSERTION_MIN_COVERAGE_PPM,
            maximum=1_000_000,
        ):
            return "coverage_threshold_invalid"
        plan.canonical_bytes
    except (ForensicAssertionPreflightError, ValueError):
        return "plan_invalid"
    return None


def _plan_is_canonical(plan: object) -> bool:
    return _plan_error(plan) is None


def forensic_corroboration_execution_contract_sha256(
    plan: ForensicAssertionGraphPlan,
    *,
    pointer_id: str,
    tool_id: str,
    execution_nonce_sha256: str,
) -> str:
    """Derive one exact clean, networkless corroboration run contract."""

    if not _plan_is_canonical(plan):
        raise TypeError("plan must be a canonical assertion graph plan")
    if not _valid_id(pointer_id):
        raise ValueError("pointer_id is invalid")
    if not _valid_id(tool_id):
        raise ValueError("tool_id is invalid")
    pointer_by_id = {item.pointer_id: item for item in plan.pointers}
    tool_by_id = {item.tool_id: item for item in plan.tools}
    pointer = pointer_by_id.get(pointer_id)
    tool = tool_by_id.get(tool_id)
    if pointer is None:
        raise ValueError("pointer_id is not declared")
    if tool is None:
        raise ValueError("tool_id is not declared")
    if _pointer_kind(pointer) not in tool.supported_pointer_kinds:
        raise ValueError("tool does not support pointer kind")
    if not _valid_sha256(execution_nonce_sha256):
        raise ValueError("execution nonce is invalid")
    return _corroboration_execution_contract_sha256(
        plan,
        pointer=pointer,
        tool=tool,
        execution_nonce_sha256=execution_nonce_sha256,
    )


def _corroboration_execution_contract_sha256(
    plan: ForensicAssertionGraphPlan,
    *,
    pointer: ForensicEvidencePointer,
    tool: ForensicToolBinding,
    execution_nonce_sha256: str,
) -> str:
    """Hash a contract after the caller has validated plan and lookup."""

    return _sha256(
        _canonical_json_bytes(
            {
                "capture_policy": {
                    "complete": True,
                    "truncation_known": True,
                    "truncated": False,
                },
                "execution_nonce_sha256": execution_nonce_sha256,
                "inventory_root": plan.inventory_root.to_dict(),
                "network_policy": "none",
                "plan_sha256": plan.plan_sha256,
                "pointer_kind": _pointer_kind(pointer),
                "pointer_sha256": forensic_evidence_pointer_sha256(
                    pointer
                ),
                "runtime_image_digest": tool.runtime_image_digest,
                "tool_id": tool.tool_id,
                "tool_version_sha256": tool.tool_version_sha256,
                "workspace_policy": "fresh",
            }
        )
    )


def _valid_artifact(value: object) -> bool:
    return (
        type(value) is ForensicObservationArtifact
        and _valid_id(value.artifact_id)
        and _valid_sha256(value.sha256)
        and _valid_int(
            value.size_bytes,
            minimum=1,
            maximum=FORENSIC_ASSERTION_MAX_ARTIFACT_BYTES,
        )
    )


def _failure(code: str, position: int | None = None) -> str:
    return code if position is None else f"observation-{position}:{code}"


def evaluate_forensic_assertion_graph(
    plan: ForensicAssertionGraphPlan,
    observations: Iterable[ForensicCorroborationObservation],
) -> ForensicAssertionGraphEvaluation:
    """Evaluate executed corroborations and promote only confirmed nodes."""

    if not _plan_is_canonical(plan):
        return ForensicAssertionGraphEvaluation(
            plan=None,
            corroboration_records=(),
            coverage_records=(),
            failure_codes=("plan_invalid",),
            verdict=ForensicAssertionVerdict.REJECTED,
        )
    try:
        raw_values = tuple(
            islice(
                iter(observations),
                FORENSIC_ASSERTION_MAX_OBSERVATIONS + 1,
            )
        )
    except Exception:
        return ForensicAssertionGraphEvaluation(
            plan=plan,
            corroboration_records=(),
            coverage_records=(),
            failure_codes=("observations_not_iterable",),
            verdict=ForensicAssertionVerdict.REJECTED,
        )
    failures: list[str] = []
    if len(raw_values) > FORENSIC_ASSERTION_MAX_OBSERVATIONS:
        failures.append("observation_count_exceeded")
    values = raw_values[:FORENSIC_ASSERTION_MAX_OBSERVATIONS]
    pointer_by_id = {item.pointer_id: item for item in plan.pointers}
    tool_by_id = {item.tool_id: item for item in plan.tools}
    used_observation_ids: set[str] = set()
    used_pointer_tool_pairs: set[tuple[str, str]] = set()
    used_pointer_families: set[tuple[str, str]] = set()
    used_pointer_versions: set[tuple[str, str]] = set()
    used_run_ids: set[str] = set()
    used_receipt_ids: set[str] = set()
    used_receipt_hashes: set[str] = set()
    used_nonces: set[str] = set()
    used_artifact_ids: set[str] = set()
    records: list[ForensicCorroborationRecord] = []
    for position, raw in enumerate(values, start=1):
        if type(raw) is not ForensicCorroborationObservation:
            failures.append(_failure("observation_type_invalid", position))
            continue
        pointer_id_valid = _valid_id(raw.pointer_id)
        tool_id_valid = _valid_id(raw.tool_id)
        pointer = (
            pointer_by_id.get(raw.pointer_id)
            if pointer_id_valid
            else None
        )
        tool = (
            tool_by_id.get(raw.tool_id)
            if tool_id_valid
            else None
        )
        before = len(failures)
        if pointer is None:
            failures.append(_failure("pointer_unknown", position))
        if tool is None:
            failures.append(_failure("tool_unknown", position))
        if (
            pointer is not None
            and tool is not None
            and _pointer_kind(pointer)
            not in tool.supported_pointer_kinds
        ):
            failures.append(_failure("tool_kind_unsupported", position))
        if (
            not _valid_id(raw.observation_id)
            or raw.observation_id in used_observation_ids
        ):
            failures.append(
                _failure("observation_id_invalid_or_reused", position)
            )
        else:
            used_observation_ids.add(raw.observation_id)
        if pointer_id_valid and tool_id_valid:
            pair = (raw.pointer_id, raw.tool_id)
            if pair in used_pointer_tool_pairs:
                failures.append(_failure("pointer_tool_reused", position))
            else:
                used_pointer_tool_pairs.add(pair)
        if tool is not None and pointer_id_valid:
            family_pair = (
                raw.pointer_id,
                tool.independence_family,
            )
            if family_pair in used_pointer_families:
                failures.append(
                    _failure("pointer_tool_family_reused", position)
                )
            else:
                used_pointer_families.add(family_pair)
            version_pair = (
                raw.pointer_id,
                tool.tool_version_sha256,
            )
            if version_pair in used_pointer_versions:
                failures.append(
                    _failure("pointer_tool_version_reused", position)
                )
            else:
                used_pointer_versions.add(version_pair)
        for value, used, code in (
            (raw.run_id, used_run_ids, "run_id_invalid_or_reused"),
            (
                raw.receipt_id,
                used_receipt_ids,
                "receipt_id_invalid_or_reused",
            ),
        ):
            if not _valid_id(value) or value in used:
                failures.append(_failure(code, position))
            else:
                used.add(value)
        for value, used, code in (
            (
                raw.receipt_sha256,
                used_receipt_hashes,
                "receipt_hash_invalid_or_reused",
            ),
            (
                raw.execution_nonce_sha256,
                used_nonces,
                "execution_nonce_invalid_or_reused",
            ),
        ):
            if not _valid_sha256(value) or value in used:
                failures.append(_failure(code, position))
            else:
                used.add(value)
        expected_contract: str | None = None
        if (
            pointer is not None
            and tool is not None
            and _pointer_kind(pointer) in tool.supported_pointer_kinds
            and _valid_sha256(raw.execution_nonce_sha256)
        ):
            expected_contract = _corroboration_execution_contract_sha256(
                plan,
                pointer=pointer,
                tool=tool,
                execution_nonce_sha256=raw.execution_nonce_sha256,
            )
        if (
            expected_contract is None
            or raw.execution_contract_sha256 != expected_contract
            or raw.plan_sha256 != plan.plan_sha256
            or raw.source_manifest_sha256
            != plan.inventory_root.source_manifest_sha256
            or raw.source_inventory_sha256
            != plan.inventory_root.source_inventory_sha256
            or tool is None
            or raw.runtime_image_digest != tool.runtime_image_digest
        ):
            failures.append(_failure("execution_binding_mismatch", position))
        if (
            raw.clean_workspace is not True
            or raw.network_disabled is not True
            or raw.orchestration_status != "completed"
            or type(raw.exit_code) is not int
            or raw.exit_code != 0
            or raw.timed_out is not False
            or raw.capture_complete is not True
            or raw.truncation_known is not True
            or raw.truncated is not False
            or raw.capture_error is not None
        ):
            failures.append(_failure("transport_invalid", position))
        if not _valid_artifact(raw.observation_artifact):
            failures.append(_failure("artifact_invalid", position))
        elif (
            raw.observation_artifact.artifact_id
            in used_artifact_ids
        ):
            failures.append(_failure("artifact_id_reused", position))
        else:
            used_artifact_ids.add(
                raw.observation_artifact.artifact_id
            )
        if (
            len(failures) == before
            and pointer is not None
            and tool is not None
        ):
            records.append(
                ForensicCorroborationRecord(
                    observation_id=raw.observation_id,
                    pointer_id=raw.pointer_id,
                    pointer_sha256=(
                        forensic_evidence_pointer_sha256(pointer)
                    ),
                    pointer_kind=_pointer_kind(pointer),
                    tool_id=raw.tool_id,
                    independence_family=tool.independence_family,
                    tool_version_sha256=tool.tool_version_sha256,
                    run_id=raw.run_id,
                    receipt_id=raw.receipt_id,
                    receipt_sha256=raw.receipt_sha256,
                    execution_nonce_sha256=(
                        raw.execution_nonce_sha256
                    ),
                    execution_contract_sha256=(
                        raw.execution_contract_sha256
                    ),
                    observation_artifact=raw.observation_artifact,
                )
            )
    families_observed: dict[str, set[str]] = {
        pointer.pointer_id: set() for pointer in plan.pointers
    }
    versions_observed: dict[str, set[str]] = {
        pointer.pointer_id: set() for pointer in plan.pointers
    }
    for record in records:
        families_observed[record.pointer_id].add(
            record.independence_family
        )
        versions_observed[record.pointer_id].add(
            record.tool_version_sha256
        )
    coverage_records: list[ForensicAssertionCoverageRecord] = []
    for assertion in plan.assertions:
        covered: list[str] = []
        insufficient: list[str] = []
        for pointer_id in assertion.evidence_pointer_ids:
            if (
                len(families_observed[pointer_id]) >= 2
                and len(versions_observed[pointer_id]) >= 2
            ):
                covered.append(pointer_id)
            else:
                insufficient.append(pointer_id)
        total = len(assertion.evidence_pointer_ids)
        coverage_ppm = (
            len(covered) * 1_000_000 // total
            if total
            else 0
        )
        coverage = ForensicAssertionCoverageRecord(
            assertion_id=assertion.assertion_id,
            state=assertion.state,
            total_pointer_count=total,
            covered_pointer_count=len(covered),
            coverage_ppm=coverage_ppm,
            threshold_ppm=plan.coverage_threshold_ppm,
            covered_pointer_ids=tuple(covered),
            insufficient_pointer_ids=tuple(insufficient),
        )
        coverage_records.append(coverage)
        if (
            assertion.state is ForensicAssertionState.CONFIRMED
            and not coverage.confirmed_requirement_met
        ):
            failures.append(
                f"assertion-{assertion.assertion_id}:"
                "coverage_or_corroboration_insufficient"
            )
    if not any(
        item.state is ForensicAssertionState.CONFIRMED
        for item in plan.assertions
    ):
        failures.append("no_confirmed_assertion")
    passed = not failures
    evaluation = ForensicAssertionGraphEvaluation(
        plan=plan,
        corroboration_records=tuple(records),
        coverage_records=tuple(coverage_records),
        failure_codes=tuple(failures),
        verdict=(
            ForensicAssertionVerdict.CONFIRMED
            if passed
            else ForensicAssertionVerdict.REJECTED
        ),
    )
    try:
        evaluation.canonical_bytes
    except ValueError:
        return ForensicAssertionGraphEvaluation(
            plan=plan,
            corroboration_records=(),
            coverage_records=(),
            failure_codes=("evaluation_size_exceeded",),
            verdict=ForensicAssertionVerdict.REJECTED,
        )
    return evaluation


__all__ = [
    "FORENSIC_ASSERTION_GRAPH_PROTOCOL",
    "FORENSIC_ASSERTION_MIN_COVERAGE_PPM",
    "ForensicAssertionCoverageRecord",
    "ForensicAssertionGraphEvaluation",
    "ForensicAssertionGraphPlan",
    "ForensicAssertionInventoryRoot",
    "ForensicAssertionNode",
    "ForensicAssertionPreflightError",
    "ForensicAssertionState",
    "ForensicAssertionVerdict",
    "ForensicCorroborationObservation",
    "ForensicCorroborationRecord",
    "ForensicEvidencePointer",
    "ForensicFileRangePointer",
    "ForensicInodePointer",
    "ForensicNormalizedTimestamp",
    "ForensicObservationArtifact",
    "ForensicPcapFramePointer",
    "ForensicProcessPointer",
    "ForensicTimestampPointer",
    "ForensicToolBinding",
    "build_forensic_assertion_graph_plan",
    "evaluate_forensic_assertion_graph",
    "forensic_corroboration_execution_contract_sha256",
    "forensic_evidence_pointer_sha256",
]
