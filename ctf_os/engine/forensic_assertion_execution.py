"""Transport-bound execution for the Forensic assertion graph.

The semantic gate in :mod:`ctf_os.engine.forensic_assertion_graph` accepts
engine-derived corroboration observations.  This module builds those
observations only after checking a stricter transport boundary:

* a canonical, bounded, value-free operator specification is rooted in one
  confirmed evidence-index execution and the complete current tool-readiness
  registry;
* one request/run/observation/receipt/artifact identity and fresh nonce are
  issued for every required pointer/tool-family pair before results are
  considered;
* every request commits to a fixed argv template, read-only evidence access, a
  fresh workspace, no network, exact source/index/readiness roots, and an exact
  output path;
* a canonical observation document is checked by path, size, and hash, while
  the separately retained raw tool artifact is re-hashed independently; and
* only the resulting value-free commitments are delegated to
  :func:`evaluate_forensic_assertion_graph`.

Raw tool output and model prose never enter any serialised object here.  They
are accepted only as bounded bytes for independent hashing.  A passing result
inherits the assertion graph's narrow Fact/Progress authority and can never
authorize a flag, candidate, impact, status transition, or submission.

Temporal limitation
-------------------
This is a pure transport contract.  It makes post-hoc substitution and
cherry-picking detectable *given a durably persisted pre-issued plan*, but a
pure function cannot prove wall-clock ordering.  The engine/store hot path must
persist :class:`ForensicAssertionExecutionPlan` before launching any request
and must reject plans first observed after an output exists.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from itertools import islice

from ctf_os.engine.forensic_assertion_graph import (
    FORENSIC_ASSERTION_MAX_ARTIFACT_BYTES,
    FORENSIC_ASSERTION_MAX_ASSERTIONS,
    FORENSIC_ASSERTION_MAX_OBSERVATIONS,
    FORENSIC_ASSERTION_MAX_POINTERS,
    FORENSIC_ASSERTION_MAX_REFS_PER_ASSERTION,
    FORENSIC_ASSERTION_MAX_TOOLS,
    FORENSIC_ASSERTION_MIN_COVERAGE_PPM,
    FORENSIC_CLAIM_KINDS,
    FORENSIC_POINTER_KINDS,
    ForensicAssertionGraphEvaluation,
    ForensicAssertionGraphPlan,
    ForensicAssertionNode,
    ForensicAssertionPreflightError,
    ForensicAssertionState,
    ForensicAssertionVerdict,
    ForensicCorroborationObservation,
    ForensicEvidencePointer,
    ForensicFileRangePointer,
    ForensicInodePointer,
    ForensicNormalizedTimestamp,
    ForensicObservationArtifact,
    ForensicPcapFramePointer,
    ForensicProcessPointer,
    ForensicTimestampPointer,
    ForensicToolBinding,
    build_forensic_assertion_graph_plan,
    evaluate_forensic_assertion_graph,
    forensic_corroboration_execution_contract_sha256,
    forensic_evidence_pointer_sha256,
)
from ctf_os.engine.forensic_index import ForensicSourceExpectation
from ctf_os.engine.forensic_index_execution import (
    ForensicIndexExecutionEvaluation,
)
from ctf_os.store.atomic import StrictJSONError, strict_json_loads


FORENSIC_ASSERTION_OPERATOR_SPEC_PROTOCOL = (
    "ctfos.forensic.assertion.operator.v1"
)
FORENSIC_ASSERTION_EXECUTION_PROTOCOL = (
    "ctfos.forensic.assertion.execution.v1"
)
FORENSIC_ASSERTION_EXECUTION_SCHEMA_VERSION = 1

FORENSIC_ASSERTION_OPERATOR_SPEC_MAX_BYTES = 1024 * 1024
FORENSIC_ASSERTION_EXECUTION_REQUEST_MAX_BYTES = 128 * 1024
FORENSIC_ASSERTION_OBSERVATION_DOCUMENT_MAX_BYTES = 128 * 1024
FORENSIC_ASSERTION_EXECUTION_PLAN_MAX_BYTES = 8 * 1024 * 1024
FORENSIC_ASSERTION_EXECUTION_EVALUATION_MAX_BYTES = 8 * 1024 * 1024
FORENSIC_ASSERTION_EXECUTION_MAX_CAPTURE_BYTES = 256 * 1024 * 1024
FORENSIC_ASSERTION_NONCE_MIN_BYTES = 16
FORENSIC_ASSERTION_NONCE_MAX_BYTES = 64
FORENSIC_ASSERTION_COMMAND_MAX_TOKENS = 32
FORENSIC_ASSERTION_COMMAND_TOKEN_MAX_BYTES = 256
FORENSIC_ASSERTION_READINESS_ARTIFACT_MAX_BYTES = 1024 * 1024

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,255}$")
_ABSOLUTE_EXECUTABLE = re.compile(r"^/[A-Za-z0-9._/-]+$")
_FIXED_ARGV_TOKEN = re.compile(r"^[-A-Za-z0-9_./:=+@]+$")
_SHELL_EXECUTABLES = frozenset(
    {"ash", "bash", "dash", "fish", "ksh", "sh", "zsh"}
)
_INLINE_CODE_SWITCHES = frozenset({"-c", "-e", "--eval"})
_INLINE_CODE_RUNTIMES = frozenset(
    {
        "node",
        "nodejs",
        "perl",
        "php",
        "python",
        "python3",
        "ruby",
    }
)

_COMMAND_PLACEHOLDERS = (
    "{request_path}",
    "{observation_path}",
    "{artifact_path}",
)
_REQUIRED_COMMAND_PLACEHOLDERS = frozenset(_COMMAND_PLACEHOLDERS)
_OBSERVATION_STATUSES = frozenset(
    {"completed", "failed", "interrupted"}
)
_CAPTURE_ERROR_CODES = frozenset(
    {"capture_error", "interrupted", "sandbox_error", "timeout"}
)
_NON_AUTHORITIES = {
    "automatic_submission_authorized": False,
    "candidate_authorized": False,
    "challenge_proof_satisfied": False,
    "flag_proven": False,
    "impact_proven": False,
    "self_report_accepted": False,
    "status_transition_authorized": False,
}

_OPERATOR_ROOT_KEYS = frozenset(
    {
        "assertions",
        "coverage_threshold_ppm",
        "index_root",
        "pointers",
        "protocol",
        "readiness_registry_sha256",
        "schema_version",
        "source_catalog_sha256",
        "tools",
    }
)
_ASSERTION_KEYS = frozenset(
    {
        "assertion_id",
        "claim_kind",
        "claim_sha256",
        "depends_on",
        "evidence_pointer_ids",
        "state",
    }
)
_TIMESTAMP_KEYS = frozenset(
    {
        "normalized_timezone",
        "normalized_utc_epoch_ns",
        "precision_ns",
        "source_local_epoch_ns",
        "source_utc_offset_minutes",
        "timestamp_kind",
    }
)
_POINTER_KEYS = {
    "file_range": frozenset(
        {
            "kind",
            "length_bytes",
            "offset_bytes",
            "pointer_id",
            "source_path",
            "source_sha256",
        }
    ),
    "inode": frozenset(
        {
            "inode_number",
            "kind",
            "metadata_length_bytes",
            "metadata_offset_bytes",
            "metadata_sha256",
            "partition_offset_bytes",
            "pointer_id",
            "source_path",
            "source_sha256",
        }
    ),
    "pcap_frame": frozenset(
        {
            "captured_length_bytes",
            "frame_number",
            "kind",
            "original_length_bytes",
            "packet_offset_bytes",
            "packet_sha256",
            "pointer_id",
            "source_path",
            "source_sha256",
            "timestamp",
        }
    ),
    "process": frozenset(
        {
            "kind",
            "object_length_bytes",
            "object_offset_bytes",
            "object_sha256",
            "pid",
            "pointer_id",
            "process_start",
            "source_path",
            "source_sha256",
            "virtual_address",
        }
    ),
    "timestamp": frozenset(
        {
            "field_length_bytes",
            "field_offset_bytes",
            "field_sha256",
            "kind",
            "pointer_id",
            "source_path",
            "source_sha256",
            "timestamp",
        }
    ),
}
_READINESS_KEYS = frozenset(
    {
        "command_template",
        "independence_family",
        "readiness_artifact",
        "readiness_generation",
        "readiness_status",
        "runtime_image_digest",
        "supported_pointer_kinds",
        "tool_id",
        "tool_version_sha256",
    }
)
_READINESS_ARTIFACT_KEYS = frozenset(
    {"artifact_id", "sha256", "size_bytes"}
)
_OBSERVATION_KEYS = frozenset(
    {
        "artifact",
        "capture",
        "command_argv_sha256",
        "command_template_sha256",
        "execution_nonce_sha256",
        "index_execution_evaluation_sha256",
        "independence_family",
        "observation_id",
        "operator_spec_sha256",
        "plan_sha256",
        "pointer_id",
        "pointer_kind",
        "pointer_sha256",
        "protocol",
        "readiness_registry_sha256",
        "receipt_id",
        "request_id",
        "request_sha256",
        "run_id",
        "runtime_image_digest",
        "schema_version",
        "semantic_execution_contract_sha256",
        "source_inventory_sha256",
        "source_manifest_sha256",
        "tool_id",
        "tool_version_sha256",
        "transport",
        "transport_execution_contract_sha256",
    }
)
_OBSERVATION_ARTIFACT_KEYS = frozenset(
    {"artifact_id", "path", "sha256", "size_bytes"}
)
_OBSERVATION_CAPTURE_KEYS = frozenset(
    {
        "capture_complete",
        "capture_error_code",
        "truncated",
        "truncation_known",
    }
)
_OBSERVATION_TRANSPORT_KEYS = frozenset(
    {
        "clean_workspace",
        "evidence_read_only",
        "exit_code",
        "network_disabled",
        "orchestration_status",
        "timed_out",
    }
)


class ForensicAssertionExecutionPreflightError(ValueError):
    """A specification, readiness registry, or pre-issued plan is invalid."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ForensicAssertionExecutionVerdict(str, Enum):
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


def _exact_dict(
    value: object,
    keys: frozenset[str],
    code: str,
) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise ForensicAssertionExecutionPreflightError(code)
    return value


def _bounded_tuple(
    values: Iterable[object],
    maximum: int,
    code: str,
) -> tuple[object, ...]:
    try:
        result = tuple(islice(iter(values), maximum + 1))
    except Exception as error:
        raise ForensicAssertionExecutionPreflightError(code) from error
    if len(result) > maximum:
        raise ForensicAssertionExecutionPreflightError(code)
    return result


def _strict_same(left: object, right: object) -> bool:
    """Compare JSON values without Python's ``True == 1`` coercion."""

    try:
        return _canonical_json_bytes(left) == _canonical_json_bytes(right)
    except ValueError:
        return False


def _safe_relative_path(value: object) -> bool:
    return (
        type(value) is str
        and bool(value)
        and not value.startswith("/")
        and "\\" not in value
        and all(part not in {"", ".", ".."} for part in value.split("/"))
    )


def _command_template_valid(value: object) -> bool:
    if (
        type(value) is not tuple
        or not 4 <= len(value) <= FORENSIC_ASSERTION_COMMAND_MAX_TOKENS
        or any(type(token) is not str or not token for token in value)
    ):
        return False
    try:
        if any(
            len(token.encode("ascii"))
            > FORENSIC_ASSERTION_COMMAND_TOKEN_MAX_BYTES
            for token in value
        ):
            return False
    except UnicodeError:
        return False
    executable = value[0]
    if (
        _ABSOLUTE_EXECUTABLE.fullmatch(executable) is None
        or "//" in executable
        or any(part in {"", ".", ".."} for part in executable.split("/")[1:])
    ):
        return False
    executable_name = executable.rsplit("/", 1)[-1]
    if (
        executable_name in _SHELL_EXECUTABLES
        or executable_name == "env"
        or (
            (
                executable_name in _INLINE_CODE_RUNTIMES
                or executable_name.startswith("python")
            )
            and any(token in _INLINE_CODE_SWITCHES for token in value[1:])
        )
    ):
        return False
    placeholders: list[str] = []
    for token in value[1:]:
        if token in _REQUIRED_COMMAND_PLACEHOLDERS:
            placeholders.append(token)
        elif _FIXED_ARGV_TOKEN.fullmatch(token) is None:
            return False
    return (
        len(placeholders) == len(_REQUIRED_COMMAND_PLACEHOLDERS)
        and frozenset(placeholders) == _REQUIRED_COMMAND_PLACEHOLDERS
    )


def _command_template_sha256(template: tuple[str, ...]) -> str:
    return _sha256(_canonical_json_bytes(list(template)))


@dataclass(frozen=True, slots=True)
class ForensicToolReadiness:
    """One engine-owned, probe-backed executable tool registration."""

    tool_id: str
    independence_family: str
    tool_version_sha256: str
    runtime_image_digest: str
    supported_pointer_kinds: tuple[str, ...]
    command_template: tuple[str, ...]
    readiness_generation: int
    readiness_artifact_id: str
    readiness_artifact_sha256: str
    readiness_artifact_size_bytes: int

    @property
    def tool_binding(self) -> ForensicToolBinding:
        return ForensicToolBinding(
            tool_id=self.tool_id,
            independence_family=self.independence_family,
            tool_version_sha256=self.tool_version_sha256,
            runtime_image_digest=self.runtime_image_digest,
            supported_pointer_kinds=self.supported_pointer_kinds,
        )

    @property
    def command_template_sha256(self) -> str:
        return _command_template_sha256(self.command_template)

    def to_dict(self) -> dict[str, object]:
        return {
            "command_template": list(self.command_template),
            "independence_family": self.independence_family,
            "readiness_artifact": {
                "artifact_id": self.readiness_artifact_id,
                "sha256": self.readiness_artifact_sha256,
                "size_bytes": self.readiness_artifact_size_bytes,
            },
            "readiness_generation": self.readiness_generation,
            "readiness_status": "ready",
            "runtime_image_digest": self.runtime_image_digest,
            "supported_pointer_kinds": list(
                self.supported_pointer_kinds
            ),
            "tool_id": self.tool_id,
            "tool_version_sha256": self.tool_version_sha256,
        }


def _normalized_readiness(
    values: Iterable[ForensicToolReadiness],
) -> tuple[ForensicToolReadiness, ...]:
    raw = _bounded_tuple(
        values,
        FORENSIC_ASSERTION_MAX_TOOLS,
        "readiness_registry_invalid",
    )
    if not raw or any(type(item) is not ForensicToolReadiness for item in raw):
        raise ForensicAssertionExecutionPreflightError(
            "readiness_registry_invalid"
        )
    for item in raw:
        if (
            not _valid_id(item.tool_id)
            or not _valid_id(item.independence_family)
            or not _valid_sha256(item.tool_version_sha256)
            or not _valid_image_digest(item.runtime_image_digest)
            or type(item.supported_pointer_kinds) is not tuple
            or not item.supported_pointer_kinds
            or item.supported_pointer_kinds
            != tuple(sorted(set(item.supported_pointer_kinds)))
            or any(
                type(kind) is not str
                or kind not in FORENSIC_POINTER_KINDS
                for kind in item.supported_pointer_kinds
            )
            or not _command_template_valid(item.command_template)
            or not _valid_int(item.readiness_generation)
            or not _valid_id(item.readiness_artifact_id)
            or not _valid_sha256(item.readiness_artifact_sha256)
            or not _valid_int(
                item.readiness_artifact_size_bytes,
                minimum=1,
                maximum=FORENSIC_ASSERTION_READINESS_ARTIFACT_MAX_BYTES,
            )
        ):
            raise ForensicAssertionExecutionPreflightError(
                "readiness_registry_invalid"
            )
    result = tuple(sorted(raw, key=lambda item: item.tool_id))
    if (
        len({item.tool_id for item in result}) != len(result)
        or len({item.readiness_artifact_id for item in result})
        != len(result)
    ):
        raise ForensicAssertionExecutionPreflightError(
            "readiness_registry_duplicate"
        )
    return result


def forensic_tool_readiness_registry_sha256(
    readiness: Iterable[ForensicToolReadiness],
) -> str:
    values = _normalized_readiness(readiness)
    return _sha256(
        _canonical_json_bytes(
            {
                "kind": "complete_current_forensic_tool_readiness_v1",
                "tools": [item.to_dict() for item in values],
            }
        )
    )


@dataclass(frozen=True, slots=True)
class ForensicAssertionExecutionSpecification:
    """Parsed operator intent bound to engine-owned index/readiness roots."""

    plan: ForensicAssertionGraphPlan
    readiness: tuple[ForensicToolReadiness, ...]
    readiness_registry_sha256: str
    operator_spec_sha256: str
    operator_spec_size_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "index_execution_evaluation_sha256": (
                self.plan.inventory_root
                .index_execution_evaluation_sha256
            ),
            "operator_spec_sha256": self.operator_spec_sha256,
            "operator_spec_size_bytes": self.operator_spec_size_bytes,
            "plan_sha256": self.plan.plan_sha256,
            "protocol": FORENSIC_ASSERTION_EXECUTION_PROTOCOL,
            "readiness_registry_sha256": (
                self.readiness_registry_sha256
            ),
            "schema_version": (
                FORENSIC_ASSERTION_EXECUTION_SCHEMA_VERSION
            ),
            "source_catalog_sha256": self.plan.source_catalog_sha256,
            "source_inventory_sha256": (
                self.plan.inventory_root.source_inventory_sha256
            ),
            "source_manifest_sha256": (
                self.plan.inventory_root.source_manifest_sha256
            ),
            "tool_count": len(self.readiness),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(self.to_dict())

    @property
    def specification_sha256(self) -> str:
        return _sha256(self.canonical_bytes)


def _timestamp_from_raw(
    value: object,
    code: str,
) -> ForensicNormalizedTimestamp:
    raw = _exact_dict(value, _TIMESTAMP_KEYS, code)
    try:
        return ForensicNormalizedTimestamp(
            timestamp_kind=raw["timestamp_kind"],
            source_local_epoch_ns=raw["source_local_epoch_ns"],
            source_utc_offset_minutes=raw[
                "source_utc_offset_minutes"
            ],
            normalized_utc_epoch_ns=raw["normalized_utc_epoch_ns"],
            precision_ns=raw["precision_ns"],
            normalized_timezone=raw["normalized_timezone"],
        )
    except TypeError as error:
        raise ForensicAssertionExecutionPreflightError(code) from error


def _pointer_from_raw(
    value: object,
    position: int,
) -> ForensicEvidencePointer:
    code = f"pointer-{position}:schema_invalid"
    if type(value) is not dict or type(value.get("kind")) is not str:
        raise ForensicAssertionExecutionPreflightError(code)
    kind = value["kind"]
    keys = _POINTER_KEYS.get(kind)
    if keys is None:
        raise ForensicAssertionExecutionPreflightError(code)
    raw = _exact_dict(value, keys, code)
    try:
        if kind == "file_range":
            return ForensicFileRangePointer(
                pointer_id=raw["pointer_id"],
                source_path=raw["source_path"],
                source_sha256=raw["source_sha256"],
                offset_bytes=raw["offset_bytes"],
                length_bytes=raw["length_bytes"],
            )
        if kind == "inode":
            return ForensicInodePointer(
                pointer_id=raw["pointer_id"],
                source_path=raw["source_path"],
                source_sha256=raw["source_sha256"],
                partition_offset_bytes=raw["partition_offset_bytes"],
                inode_number=raw["inode_number"],
                metadata_offset_bytes=raw["metadata_offset_bytes"],
                metadata_length_bytes=raw["metadata_length_bytes"],
                metadata_sha256=raw["metadata_sha256"],
            )
        if kind == "pcap_frame":
            return ForensicPcapFramePointer(
                pointer_id=raw["pointer_id"],
                source_path=raw["source_path"],
                source_sha256=raw["source_sha256"],
                frame_number=raw["frame_number"],
                packet_offset_bytes=raw["packet_offset_bytes"],
                captured_length_bytes=raw["captured_length_bytes"],
                original_length_bytes=raw["original_length_bytes"],
                packet_sha256=raw["packet_sha256"],
                timestamp=_timestamp_from_raw(
                    raw["timestamp"],
                    f"pointer-{position}:timestamp_invalid",
                ),
            )
        if kind == "process":
            return ForensicProcessPointer(
                pointer_id=raw["pointer_id"],
                source_path=raw["source_path"],
                source_sha256=raw["source_sha256"],
                pid=raw["pid"],
                virtual_address=raw["virtual_address"],
                object_offset_bytes=raw["object_offset_bytes"],
                object_length_bytes=raw["object_length_bytes"],
                object_sha256=raw["object_sha256"],
                process_start=_timestamp_from_raw(
                    raw["process_start"],
                    f"pointer-{position}:process_start_invalid",
                ),
            )
        return ForensicTimestampPointer(
            pointer_id=raw["pointer_id"],
            source_path=raw["source_path"],
            source_sha256=raw["source_sha256"],
            field_offset_bytes=raw["field_offset_bytes"],
            field_length_bytes=raw["field_length_bytes"],
            field_sha256=raw["field_sha256"],
            timestamp=_timestamp_from_raw(
                raw["timestamp"],
                f"pointer-{position}:timestamp_invalid",
            ),
        )
    except (KeyError, TypeError) as error:
        raise ForensicAssertionExecutionPreflightError(code) from error


def _assertion_from_raw(
    value: object,
    position: int,
) -> ForensicAssertionNode:
    code = f"assertion-{position}:schema_invalid"
    raw = _exact_dict(value, _ASSERTION_KEYS, code)
    depends_on = raw["depends_on"]
    pointer_ids = raw["evidence_pointer_ids"]
    if (
        type(depends_on) is not list
        or len(depends_on) > FORENSIC_ASSERTION_MAX_REFS_PER_ASSERTION
        or any(type(item) is not str for item in depends_on)
        or type(pointer_ids) is not list
        or len(pointer_ids) > FORENSIC_ASSERTION_MAX_REFS_PER_ASSERTION
        or any(type(item) is not str for item in pointer_ids)
        or type(raw["state"]) is not str
        or type(raw["claim_kind"]) is not str
        or raw["claim_kind"] not in FORENSIC_CLAIM_KINDS
        or not _valid_sha256(raw["claim_sha256"])
    ):
        raise ForensicAssertionExecutionPreflightError(code)
    try:
        state = ForensicAssertionState(raw["state"])
        return ForensicAssertionNode(
            assertion_id=raw["assertion_id"],
            state=state,
            claim_kind=raw["claim_kind"],
            claim_sha256=raw["claim_sha256"],
            depends_on=tuple(depends_on),
            evidence_pointer_ids=tuple(pointer_ids),
        )
    except (TypeError, ValueError) as error:
        raise ForensicAssertionExecutionPreflightError(code) from error


def parse_forensic_assertion_operator_spec(
    payload: bytes,
    *,
    current_index_execution: ForensicIndexExecutionEvaluation,
    current_sources: Iterable[ForensicSourceExpectation],
    current_readiness: Iterable[ForensicToolReadiness],
) -> ForensicAssertionExecutionSpecification:
    """Parse operator intent without accepting prose or raw evidence."""

    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > FORENSIC_ASSERTION_OPERATOR_SPEC_MAX_BYTES
    ):
        raise ForensicAssertionExecutionPreflightError(
            "operator_spec_payload_invalid"
        )
    try:
        document = strict_json_loads(
            payload,
            max_bytes=FORENSIC_ASSERTION_OPERATOR_SPEC_MAX_BYTES,
            max_depth=24,
        )
        canonical = _canonical_json_bytes(
            document,
            maximum_bytes=FORENSIC_ASSERTION_OPERATOR_SPEC_MAX_BYTES,
        )
    except (
        StrictJSONError,
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as error:
        raise ForensicAssertionExecutionPreflightError(
            "operator_spec_json_invalid"
        ) from error
    if payload != canonical:
        raise ForensicAssertionExecutionPreflightError(
            "operator_spec_not_canonical"
        )
    root = _exact_dict(
        document,
        _OPERATOR_ROOT_KEYS,
        "operator_spec_schema_invalid",
    )
    if (
        root["protocol"] != FORENSIC_ASSERTION_OPERATOR_SPEC_PROTOCOL
        or type(root["schema_version"]) is not int
        or root["schema_version"]
        != FORENSIC_ASSERTION_EXECUTION_SCHEMA_VERSION
    ):
        raise ForensicAssertionExecutionPreflightError(
            "operator_spec_protocol_invalid"
        )
    readiness = _normalized_readiness(current_readiness)
    readiness_sha256 = forensic_tool_readiness_registry_sha256(
        readiness
    )
    expected_tool_docs = [item.to_dict() for item in readiness]
    if (
        not _valid_sha256(root["readiness_registry_sha256"])
        or root["readiness_registry_sha256"] != readiness_sha256
        or not _strict_same(root["tools"], expected_tool_docs)
    ):
        raise ForensicAssertionExecutionPreflightError(
            "operator_readiness_binding_mismatch"
        )
    pointer_raw = root["pointers"]
    assertion_raw = root["assertions"]
    if (
        type(pointer_raw) is not list
        or not pointer_raw
        or len(pointer_raw) > FORENSIC_ASSERTION_MAX_POINTERS
    ):
        raise ForensicAssertionExecutionPreflightError(
            "operator_pointer_count_invalid"
        )
    if (
        type(assertion_raw) is not list
        or not assertion_raw
        or len(assertion_raw) > FORENSIC_ASSERTION_MAX_ASSERTIONS
    ):
        raise ForensicAssertionExecutionPreflightError(
            "operator_assertion_count_invalid"
        )
    pointers = tuple(
        _pointer_from_raw(item, position)
        for position, item in enumerate(pointer_raw, start=1)
    )
    assertions = tuple(
        _assertion_from_raw(item, position)
        for position, item in enumerate(assertion_raw, start=1)
    )
    try:
        plan = build_forensic_assertion_graph_plan(
            index_execution=current_index_execution,
            expected_sources=current_sources,
            tools=tuple(item.tool_binding for item in readiness),
            pointers=pointers,
            assertions=assertions,
            coverage_threshold_ppm=root["coverage_threshold_ppm"],
        )
    except ForensicAssertionPreflightError as error:
        raise ForensicAssertionExecutionPreflightError(
            f"assertion_graph_{error.code}"
        ) from error
    except (TypeError, ValueError) as error:
        raise ForensicAssertionExecutionPreflightError(
            "assertion_graph_invalid"
        ) from error
    if (
        not _strict_same(root["index_root"], plan.inventory_root.to_dict())
        or root["source_catalog_sha256"] != plan.source_catalog_sha256
    ):
        raise ForensicAssertionExecutionPreflightError(
            "operator_index_binding_mismatch"
        )
    for pointer in plan.pointers:
        families = {
            item.independence_family
            for item in readiness
            if pointer.kind in item.supported_pointer_kinds
        }
        if not families:
            raise ForensicAssertionExecutionPreflightError(
                f"pointer-{pointer.pointer_id}:tool_readiness_missing"
            )
    specification = ForensicAssertionExecutionSpecification(
        plan=plan,
        readiness=readiness,
        readiness_registry_sha256=readiness_sha256,
        operator_spec_sha256=_sha256(payload),
        operator_spec_size_bytes=len(payload),
    )
    try:
        specification.canonical_bytes
    except ValueError as error:
        raise ForensicAssertionExecutionPreflightError(
            "execution_specification_size_exceeded"
        ) from error
    return specification


@dataclass(frozen=True, slots=True)
class ForensicObservationIssue:
    """Engine-owned identities and raw entropy allocated before execution."""

    request_id: str
    run_id: str
    observation_id: str
    receipt_id: str
    artifact_id: str
    execution_nonce: bytes


@dataclass(frozen=True, slots=True)
class ForensicObservationRequest:
    """One canonical, pre-issued pointer/tool execution request."""

    request_id: str
    run_id: str
    observation_id: str
    receipt_id: str
    artifact_id: str
    request_path: str
    observation_path: str
    artifact_path: str
    pointer: ForensicEvidencePointer
    pointer_id: str
    pointer_kind: str
    pointer_sha256: str
    tool_id: str
    independence_family: str
    tool_version_sha256: str
    runtime_image_digest: str
    command_template_sha256: str
    command_argv: tuple[str, ...]
    command_argv_sha256: str
    execution_nonce_sha256: str
    semantic_execution_contract_sha256: str
    transport_execution_contract_sha256: str
    operator_spec_sha256: str
    plan_sha256: str
    readiness_registry_sha256: str
    index_execution_evaluation_sha256: str
    source_manifest_sha256: str
    source_inventory_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact": {
                "artifact_id": self.artifact_id,
                "maximum_size_bytes": (
                    FORENSIC_ASSERTION_MAX_ARTIFACT_BYTES
                ),
                "path": self.artifact_path,
            },
            "command": {
                "argv": list(self.command_argv),
                "argv_sha256": self.command_argv_sha256,
                "template_sha256": self.command_template_sha256,
            },
            "execution_nonce_sha256": self.execution_nonce_sha256,
            "index_execution_evaluation_sha256": (
                self.index_execution_evaluation_sha256
            ),
            "observation": {
                "observation_id": self.observation_id,
                "path": self.observation_path,
                "receipt_id": self.receipt_id,
            },
            "operator_spec_sha256": self.operator_spec_sha256,
            "plan_sha256": self.plan_sha256,
            "pointer": {
                **self.pointer.to_dict(),
                "sha256": self.pointer_sha256,
            },
            "protocol": FORENSIC_ASSERTION_EXECUTION_PROTOCOL,
            "readiness_registry_sha256": (
                self.readiness_registry_sha256
            ),
            "request_id": self.request_id,
            "request_path": self.request_path,
            "run_id": self.run_id,
            "schema_version": (
                FORENSIC_ASSERTION_EXECUTION_SCHEMA_VERSION
            ),
            "semantic_execution_contract_sha256": (
                self.semantic_execution_contract_sha256
            ),
            "source": {
                "evidence_root": "/challenge",
                "evidence_root_access": "read_only",
                "inventory_sha256": self.source_inventory_sha256,
                "manifest_sha256": self.source_manifest_sha256,
            },
            "tool": {
                "independence_family": self.independence_family,
                "runtime_image_digest": self.runtime_image_digest,
                "tool_id": self.tool_id,
                "tool_version_sha256": self.tool_version_sha256,
            },
            "transport_contract": {
                "artifact_capture": "complete_exact_bytes",
                "evidence_access": "read_only",
                "network": "none",
                "observation_document": "canonical_value_free_json",
                "transport_execution_contract_sha256": (
                    self.transport_execution_contract_sha256
                ),
                "workspace": "fresh",
            },
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(
            self.to_dict(),
            maximum_bytes=FORENSIC_ASSERTION_EXECUTION_REQUEST_MAX_BYTES,
        )

    @property
    def request_sha256(self) -> str:
        return _sha256(self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class ForensicAssertionExecutionPlan:
    """Complete request wave that the store must persist before launch."""

    specification: ForensicAssertionExecutionSpecification
    requests: tuple[ForensicObservationRequest, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "operator_spec_sha256": (
                self.specification.operator_spec_sha256
            ),
            "plan_sha256": self.specification.plan.plan_sha256,
            "protocol": FORENSIC_ASSERTION_EXECUTION_PROTOCOL,
            "readiness_registry_sha256": (
                self.specification.readiness_registry_sha256
            ),
            "requests": [
                {**item.to_dict(), "request_sha256": item.request_sha256}
                for item in self.requests
            ],
            "schema_version": (
                FORENSIC_ASSERTION_EXECUTION_SCHEMA_VERSION
            ),
            "specification_sha256": (
                self.specification.specification_sha256
            ),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(
            self.to_dict(),
            maximum_bytes=FORENSIC_ASSERTION_EXECUTION_PLAN_MAX_BYTES,
        )

    @property
    def execution_plan_sha256(self) -> str:
        return _sha256(self.canonical_bytes)


def _required_pointer_tool_pairs(
    specification: ForensicAssertionExecutionSpecification,
) -> tuple[tuple[ForensicEvidencePointer, ForensicToolReadiness], ...]:
    """Choose one tool from the first two available independent families."""

    result: list[
        tuple[ForensicEvidencePointer, ForensicToolReadiness]
    ] = []
    for pointer in specification.plan.pointers:
        by_family: dict[str, list[ForensicToolReadiness]] = {}
        for readiness in specification.readiness:
            if pointer.kind in readiness.supported_pointer_kinds:
                by_family.setdefault(
                    readiness.independence_family,
                    [],
                ).append(readiness)
        selected_families = sorted(by_family)[:2]
        for family in selected_families:
            selected = min(
                by_family[family],
                key=lambda item: item.tool_id,
            )
            result.append((pointer, selected))
    return tuple(result)


def _issued_paths(
    issue: ForensicObservationIssue,
) -> tuple[str, str, str]:
    return (
        f"runs/{issue.run_id}/forensic-assertion/request.json",
        (
            "artifacts/forensic-assertion-observations/"
            f"{issue.observation_id}.json"
        ),
        (
            "artifacts/forensic-assertion-tool-output/"
            f"{issue.artifact_id}.bin"
        ),
    )


def _expand_command(
    readiness: ForensicToolReadiness,
    *,
    request_path: str,
    observation_path: str,
    artifact_path: str,
) -> tuple[str, ...]:
    replacements = {
        "{request_path}": request_path,
        "{observation_path}": observation_path,
        "{artifact_path}": artifact_path,
    }
    return tuple(
        replacements.get(token, token)
        for token in readiness.command_template
    )


def _transport_execution_contract_sha256(
    specification: ForensicAssertionExecutionSpecification,
    *,
    issue: ForensicObservationIssue,
    request_path: str,
    observation_path: str,
    artifact_path: str,
    pointer: ForensicEvidencePointer,
    readiness: ForensicToolReadiness,
    command_argv_sha256: str,
    execution_nonce_sha256: str,
    semantic_execution_contract_sha256: str,
) -> str:
    return _sha256(
        _canonical_json_bytes(
            {
                "artifact": {
                    "artifact_id": issue.artifact_id,
                    "maximum_size_bytes": (
                        FORENSIC_ASSERTION_MAX_ARTIFACT_BYTES
                    ),
                    "path": artifact_path,
                },
                "command_argv_sha256": command_argv_sha256,
                "command_template_sha256": (
                    readiness.command_template_sha256
                ),
                "execution_nonce_sha256": execution_nonce_sha256,
                "index_root": (
                    specification.plan.inventory_root.to_dict()
                ),
                "observation_id": issue.observation_id,
                "observation_path": observation_path,
                "operator_spec_sha256": (
                    specification.operator_spec_sha256
                ),
                "plan_sha256": specification.plan.plan_sha256,
                "pointer_sha256": (
                    forensic_evidence_pointer_sha256(pointer)
                ),
                "readiness_registry_sha256": (
                    specification.readiness_registry_sha256
                ),
                "receipt_id": issue.receipt_id,
                "request_id": issue.request_id,
                "request_path": request_path,
                "run_id": issue.run_id,
                "semantic_execution_contract_sha256": (
                    semantic_execution_contract_sha256
                ),
                "tool": readiness.to_dict(),
                "transport": {
                    "artifact_capture": "complete_exact_bytes",
                    "evidence_access": "read_only",
                    "network": "none",
                    "observation_document": (
                        "canonical_value_free_json"
                    ),
                    "workspace": "fresh",
                },
            }
        )
    )


def plan_forensic_assertion_execution(
    specification: ForensicAssertionExecutionSpecification,
    issues: Iterable[ForensicObservationIssue],
) -> ForensicAssertionExecutionPlan:
    """Create every required request before accepting any observation.

    The caller, not this pure function, is responsible for durably committing
    the returned plan before a sandbox process starts.
    """

    if (
        type(specification) is not ForensicAssertionExecutionSpecification
        or not _specification_is_canonical(specification)
    ):
        raise ForensicAssertionExecutionPreflightError(
            "execution_specification_invalid"
        )
    pairs = _required_pointer_tool_pairs(specification)
    issue_values = _bounded_tuple(
        issues,
        FORENSIC_ASSERTION_MAX_OBSERVATIONS,
        "observation_issue_count_invalid",
    )
    if len(issue_values) != len(pairs):
        raise ForensicAssertionExecutionPreflightError(
            "observation_issue_count_mismatch"
        )
    all_ids: set[str] = {
        specification.plan.inventory_root.index_run_id,
        specification.plan.inventory_root.index_receipt_id,
        specification.plan.inventory_root.index_artifact_id,
        *(
            item.readiness_artifact_id
            for item in specification.readiness
        ),
    }
    nonce_hashes: set[str] = set()
    requests: list[ForensicObservationRequest] = []
    for position, (raw, pair) in enumerate(
        zip(issue_values, pairs, strict=True),
        start=1,
    ):
        pointer, readiness = pair
        prefix = f"observation-{position}:"
        if type(raw) is not ForensicObservationIssue:
            raise ForensicAssertionExecutionPreflightError(
                prefix + "issue_type_invalid"
            )
        identifiers = (
            raw.request_id,
            raw.run_id,
            raw.observation_id,
            raw.receipt_id,
            raw.artifact_id,
        )
        if (
            any(not _valid_id(value) for value in identifiers)
            or len(set(identifiers)) != len(identifiers)
            or any(value in all_ids for value in identifiers)
        ):
            raise ForensicAssertionExecutionPreflightError(
                prefix + "issued_identifier_invalid_or_reused"
            )
        if (
            type(raw.execution_nonce) is not bytes
            or not FORENSIC_ASSERTION_NONCE_MIN_BYTES
            <= len(raw.execution_nonce)
            <= FORENSIC_ASSERTION_NONCE_MAX_BYTES
        ):
            raise ForensicAssertionExecutionPreflightError(
                prefix + "execution_nonce_invalid"
            )
        nonce_sha256 = _sha256(raw.execution_nonce)
        if nonce_sha256 in nonce_hashes:
            raise ForensicAssertionExecutionPreflightError(
                prefix + "execution_nonce_reused"
            )
        request_path, observation_path, artifact_path = _issued_paths(raw)
        if not all(
            _safe_relative_path(path)
            for path in (request_path, observation_path, artifact_path)
        ):
            raise ForensicAssertionExecutionPreflightError(
                prefix + "issued_path_invalid"
            )
        argv = _expand_command(
            readiness,
            request_path=request_path,
            observation_path=observation_path,
            artifact_path=artifact_path,
        )
        argv_sha256 = _sha256(_canonical_json_bytes(list(argv)))
        semantic_contract = (
            forensic_corroboration_execution_contract_sha256(
                specification.plan,
                pointer_id=pointer.pointer_id,
                tool_id=readiness.tool_id,
                execution_nonce_sha256=nonce_sha256,
            )
        )
        transport_contract = _transport_execution_contract_sha256(
            specification,
            issue=raw,
            request_path=request_path,
            observation_path=observation_path,
            artifact_path=artifact_path,
            pointer=pointer,
            readiness=readiness,
            command_argv_sha256=argv_sha256,
            execution_nonce_sha256=nonce_sha256,
            semantic_execution_contract_sha256=semantic_contract,
        )
        request = ForensicObservationRequest(
            request_id=raw.request_id,
            run_id=raw.run_id,
            observation_id=raw.observation_id,
            receipt_id=raw.receipt_id,
            artifact_id=raw.artifact_id,
            request_path=request_path,
            observation_path=observation_path,
            artifact_path=artifact_path,
            pointer=pointer,
            pointer_id=pointer.pointer_id,
            pointer_kind=pointer.kind,
            pointer_sha256=forensic_evidence_pointer_sha256(pointer),
            tool_id=readiness.tool_id,
            independence_family=readiness.independence_family,
            tool_version_sha256=readiness.tool_version_sha256,
            runtime_image_digest=readiness.runtime_image_digest,
            command_template_sha256=(
                readiness.command_template_sha256
            ),
            command_argv=argv,
            command_argv_sha256=argv_sha256,
            execution_nonce_sha256=nonce_sha256,
            semantic_execution_contract_sha256=semantic_contract,
            transport_execution_contract_sha256=transport_contract,
            operator_spec_sha256=specification.operator_spec_sha256,
            plan_sha256=specification.plan.plan_sha256,
            readiness_registry_sha256=(
                specification.readiness_registry_sha256
            ),
            index_execution_evaluation_sha256=(
                specification.plan.inventory_root
                .index_execution_evaluation_sha256
            ),
            source_manifest_sha256=(
                specification.plan.inventory_root
                .source_manifest_sha256
            ),
            source_inventory_sha256=(
                specification.plan.inventory_root
                .source_inventory_sha256
            ),
        )
        try:
            request.canonical_bytes
        except ValueError as error:
            raise ForensicAssertionExecutionPreflightError(
                prefix + "request_size_exceeded"
            ) from error
        all_ids.update(identifiers)
        nonce_hashes.add(nonce_sha256)
        requests.append(request)
    if (
        len({item.request_sha256 for item in requests}) != len(requests)
        or len(
            {
                item.transport_execution_contract_sha256
                for item in requests
            }
        )
        != len(requests)
    ):
        raise ForensicAssertionExecutionPreflightError(
            "issued_request_commitment_reused"
        )
    plan = ForensicAssertionExecutionPlan(
        specification=specification,
        requests=tuple(requests),
    )
    try:
        plan.canonical_bytes
    except ValueError as error:
        raise ForensicAssertionExecutionPreflightError(
            "execution_plan_size_exceeded"
        ) from error
    return plan


@dataclass(frozen=True, slots=True)
class ForensicCapturedArtifact:
    """Raw bytes retained only for independent path/size/hash validation."""

    artifact_id: str
    path: str
    payload: bytes


@dataclass(frozen=True, slots=True)
class ForensicToolObservationDocument:
    """Canonical, value-free sandbox result for one issued request."""

    request_id: str
    request_sha256: str
    run_id: str
    observation_id: str
    receipt_id: str
    artifact_id: str
    artifact_path: str
    artifact_sha256: str
    artifact_size_bytes: int
    pointer_id: str
    pointer_kind: str
    pointer_sha256: str
    tool_id: str
    independence_family: str
    tool_version_sha256: str
    runtime_image_digest: str
    command_template_sha256: str
    command_argv_sha256: str
    execution_nonce_sha256: str
    semantic_execution_contract_sha256: str
    transport_execution_contract_sha256: str
    operator_spec_sha256: str
    plan_sha256: str
    readiness_registry_sha256: str
    index_execution_evaluation_sha256: str
    source_manifest_sha256: str
    source_inventory_sha256: str
    orchestration_status: str
    exit_code: int | None
    timed_out: bool
    clean_workspace: bool
    evidence_read_only: bool
    network_disabled: bool
    capture_complete: bool
    truncation_known: bool
    truncated: bool | None
    capture_error_code: str | None

    def __post_init__(self) -> None:
        for value in (
            self.request_id,
            self.run_id,
            self.observation_id,
            self.receipt_id,
            self.artifact_id,
            self.pointer_id,
            self.tool_id,
            self.independence_family,
        ):
            if not _valid_id(value):
                raise ValueError("observation_identifier_invalid")
        for value in (
            self.request_sha256,
            self.artifact_sha256,
            self.pointer_sha256,
            self.tool_version_sha256,
            self.command_template_sha256,
            self.command_argv_sha256,
            self.execution_nonce_sha256,
            self.semantic_execution_contract_sha256,
            self.transport_execution_contract_sha256,
            self.operator_spec_sha256,
            self.plan_sha256,
            self.readiness_registry_sha256,
            self.index_execution_evaluation_sha256,
            self.source_manifest_sha256,
            self.source_inventory_sha256,
        ):
            if not _valid_sha256(value):
                raise ValueError("observation_hash_invalid")
        if (
            not _safe_relative_path(self.artifact_path)
            or not _valid_int(
                self.artifact_size_bytes,
                minimum=1,
                maximum=FORENSIC_ASSERTION_MAX_ARTIFACT_BYTES,
            )
            or self.pointer_kind not in FORENSIC_POINTER_KINDS
            or not _valid_image_digest(self.runtime_image_digest)
            or self.orchestration_status not in _OBSERVATION_STATUSES
        ):
            raise ValueError("observation_binding_invalid")
        if self.exit_code is not None and (
            type(self.exit_code) is not int
            or not -255 <= self.exit_code <= 255
        ):
            raise ValueError("observation_exit_code_invalid")
        for value in (
            self.timed_out,
            self.clean_workspace,
            self.evidence_read_only,
            self.network_disabled,
            self.capture_complete,
            self.truncation_known,
        ):
            if type(value) is not bool:
                raise ValueError("observation_boolean_invalid")
        if self.truncated is not None and type(self.truncated) is not bool:
            raise ValueError("observation_truncated_invalid")
        if (
            self.capture_error_code is not None
            and self.capture_error_code not in _CAPTURE_ERROR_CODES
        ):
            raise ValueError("observation_capture_error_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact": {
                "artifact_id": self.artifact_id,
                "path": self.artifact_path,
                "sha256": self.artifact_sha256,
                "size_bytes": self.artifact_size_bytes,
            },
            "capture": {
                "capture_complete": self.capture_complete,
                "capture_error_code": self.capture_error_code,
                "truncated": self.truncated,
                "truncation_known": self.truncation_known,
            },
            "command_argv_sha256": self.command_argv_sha256,
            "command_template_sha256": self.command_template_sha256,
            "execution_nonce_sha256": self.execution_nonce_sha256,
            "index_execution_evaluation_sha256": (
                self.index_execution_evaluation_sha256
            ),
            "independence_family": self.independence_family,
            "observation_id": self.observation_id,
            "operator_spec_sha256": self.operator_spec_sha256,
            "plan_sha256": self.plan_sha256,
            "pointer_id": self.pointer_id,
            "pointer_kind": self.pointer_kind,
            "pointer_sha256": self.pointer_sha256,
            "protocol": FORENSIC_ASSERTION_EXECUTION_PROTOCOL,
            "readiness_registry_sha256": (
                self.readiness_registry_sha256
            ),
            "receipt_id": self.receipt_id,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "run_id": self.run_id,
            "runtime_image_digest": self.runtime_image_digest,
            "schema_version": (
                FORENSIC_ASSERTION_EXECUTION_SCHEMA_VERSION
            ),
            "semantic_execution_contract_sha256": (
                self.semantic_execution_contract_sha256
            ),
            "source_inventory_sha256": (
                self.source_inventory_sha256
            ),
            "source_manifest_sha256": self.source_manifest_sha256,
            "tool_id": self.tool_id,
            "tool_version_sha256": self.tool_version_sha256,
            "transport": {
                "clean_workspace": self.clean_workspace,
                "evidence_read_only": self.evidence_read_only,
                "exit_code": self.exit_code,
                "network_disabled": self.network_disabled,
                "orchestration_status": self.orchestration_status,
                "timed_out": self.timed_out,
            },
            "transport_execution_contract_sha256": (
                self.transport_execution_contract_sha256
            ),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(
            self.to_dict(),
            maximum_bytes=(
                FORENSIC_ASSERTION_OBSERVATION_DOCUMENT_MAX_BYTES
            ),
        )

    @property
    def sha256(self) -> str:
        return _sha256(self.canonical_bytes)

    @classmethod
    def from_payload(
        cls,
        payload: bytes,
    ) -> "ForensicToolObservationDocument":
        if (
            type(payload) is not bytes
            or not payload
            or len(payload)
            > FORENSIC_ASSERTION_OBSERVATION_DOCUMENT_MAX_BYTES
        ):
            raise ValueError("observation_payload_invalid")
        try:
            document = strict_json_loads(
                payload,
                max_bytes=(
                    FORENSIC_ASSERTION_OBSERVATION_DOCUMENT_MAX_BYTES
                ),
                max_depth=12,
            )
        except (
            StrictJSONError,
            RecursionError,
            UnicodeError,
            ValueError,
        ) as error:
            raise ValueError("observation_json_invalid") from error
        root = _observation_exact_dict(
            document,
            _OBSERVATION_KEYS,
        )
        if (
            root["protocol"] != FORENSIC_ASSERTION_EXECUTION_PROTOCOL
            or type(root["schema_version"]) is not int
            or root["schema_version"]
            != FORENSIC_ASSERTION_EXECUTION_SCHEMA_VERSION
        ):
            raise ValueError("observation_protocol_invalid")
        artifact = _observation_exact_dict(
            root["artifact"],
            _OBSERVATION_ARTIFACT_KEYS,
        )
        capture = _observation_exact_dict(
            root["capture"],
            _OBSERVATION_CAPTURE_KEYS,
        )
        transport = _observation_exact_dict(
            root["transport"],
            _OBSERVATION_TRANSPORT_KEYS,
        )
        try:
            result = cls(
                request_id=root["request_id"],
                request_sha256=root["request_sha256"],
                run_id=root["run_id"],
                observation_id=root["observation_id"],
                receipt_id=root["receipt_id"],
                artifact_id=artifact["artifact_id"],
                artifact_path=artifact["path"],
                artifact_sha256=artifact["sha256"],
                artifact_size_bytes=artifact["size_bytes"],
                pointer_id=root["pointer_id"],
                pointer_kind=root["pointer_kind"],
                pointer_sha256=root["pointer_sha256"],
                tool_id=root["tool_id"],
                independence_family=root["independence_family"],
                tool_version_sha256=root["tool_version_sha256"],
                runtime_image_digest=root["runtime_image_digest"],
                command_template_sha256=root[
                    "command_template_sha256"
                ],
                command_argv_sha256=root["command_argv_sha256"],
                execution_nonce_sha256=root[
                    "execution_nonce_sha256"
                ],
                semantic_execution_contract_sha256=root[
                    "semantic_execution_contract_sha256"
                ],
                transport_execution_contract_sha256=root[
                    "transport_execution_contract_sha256"
                ],
                operator_spec_sha256=root["operator_spec_sha256"],
                plan_sha256=root["plan_sha256"],
                readiness_registry_sha256=root[
                    "readiness_registry_sha256"
                ],
                index_execution_evaluation_sha256=root[
                    "index_execution_evaluation_sha256"
                ],
                source_manifest_sha256=root[
                    "source_manifest_sha256"
                ],
                source_inventory_sha256=root[
                    "source_inventory_sha256"
                ],
                orchestration_status=transport[
                    "orchestration_status"
                ],
                exit_code=transport["exit_code"],
                timed_out=transport["timed_out"],
                clean_workspace=transport["clean_workspace"],
                evidence_read_only=transport["evidence_read_only"],
                network_disabled=transport["network_disabled"],
                capture_complete=capture["capture_complete"],
                truncation_known=capture["truncation_known"],
                truncated=capture["truncated"],
                capture_error_code=capture["capture_error_code"],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("observation_fields_invalid") from error
        if payload != result.canonical_bytes:
            raise ValueError("observation_not_canonical")
        return result


def _observation_exact_dict(
    value: object,
    keys: frozenset[str],
) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise ValueError("observation_schema_invalid")
    return value


def build_forensic_tool_observation_document(
    request: ForensicObservationRequest,
    artifact_payload: bytes,
    *,
    orchestration_status: str = "completed",
    exit_code: int | None = 0,
    timed_out: bool = False,
    clean_workspace: bool = True,
    evidence_read_only: bool = True,
    network_disabled: bool = True,
    capture_complete: bool = True,
    truncation_known: bool = True,
    truncated: bool | None = False,
    capture_error_code: str | None = None,
) -> ForensicToolObservationDocument:
    """Build the raw-free observation document after one sandbox run."""

    if type(request) is not ForensicObservationRequest:
        raise ForensicAssertionExecutionPreflightError(
            "issued_request_invalid"
        )
    if (
        type(artifact_payload) is not bytes
        or not 1
        <= len(artifact_payload)
        <= FORENSIC_ASSERTION_MAX_ARTIFACT_BYTES
    ):
        raise ForensicAssertionExecutionPreflightError(
            "artifact_payload_invalid"
        )
    try:
        return ForensicToolObservationDocument(
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            run_id=request.run_id,
            observation_id=request.observation_id,
            receipt_id=request.receipt_id,
            artifact_id=request.artifact_id,
            artifact_path=request.artifact_path,
            artifact_sha256=_sha256(artifact_payload),
            artifact_size_bytes=len(artifact_payload),
            pointer_id=request.pointer_id,
            pointer_kind=request.pointer_kind,
            pointer_sha256=request.pointer_sha256,
            tool_id=request.tool_id,
            independence_family=request.independence_family,
            tool_version_sha256=request.tool_version_sha256,
            runtime_image_digest=request.runtime_image_digest,
            command_template_sha256=request.command_template_sha256,
            command_argv_sha256=request.command_argv_sha256,
            execution_nonce_sha256=request.execution_nonce_sha256,
            semantic_execution_contract_sha256=(
                request.semantic_execution_contract_sha256
            ),
            transport_execution_contract_sha256=(
                request.transport_execution_contract_sha256
            ),
            operator_spec_sha256=request.operator_spec_sha256,
            plan_sha256=request.plan_sha256,
            readiness_registry_sha256=(
                request.readiness_registry_sha256
            ),
            index_execution_evaluation_sha256=(
                request.index_execution_evaluation_sha256
            ),
            source_manifest_sha256=request.source_manifest_sha256,
            source_inventory_sha256=request.source_inventory_sha256,
            orchestration_status=orchestration_status,
            exit_code=exit_code,
            timed_out=timed_out,
            clean_workspace=clean_workspace,
            evidence_read_only=evidence_read_only,
            network_disabled=network_disabled,
            capture_complete=capture_complete,
            truncation_known=truncation_known,
            truncated=truncated,
            capture_error_code=capture_error_code,
        )
    except (TypeError, ValueError) as error:
        raise ForensicAssertionExecutionPreflightError(
            "observation_document_fields_invalid"
        ) from error


@dataclass(frozen=True, slots=True)
class ForensicToolObservationTransport:
    """One exact issued request, canonical document, and raw capture."""

    request_path: str
    request_payload: bytes
    observation_path: str
    observation_payload: bytes
    artifact: ForensicCapturedArtifact


@dataclass(frozen=True, slots=True)
class ForensicAssertionExecutionRecord:
    request_id: str
    request_sha256: str
    request_path: str
    run_id: str
    observation_id: str
    observation_path: str
    observation_document_sha256: str
    observation_document_size_bytes: int
    receipt_id: str
    receipt_sha256: str
    pointer_id: str
    pointer_sha256: str
    tool_id: str
    independence_family: str
    artifact: ForensicObservationArtifact
    artifact_path: str

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact": {
                **self.artifact.to_dict(),
                "path": self.artifact_path,
            },
            "independence_family": self.independence_family,
            "observation_document": {
                "observation_id": self.observation_id,
                "path": self.observation_path,
                "sha256": self.observation_document_sha256,
                "size_bytes": self.observation_document_size_bytes,
            },
            "pointer_id": self.pointer_id,
            "pointer_sha256": self.pointer_sha256,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "request_id": self.request_id,
            "request_path": self.request_path,
            "request_sha256": self.request_sha256,
            "run_id": self.run_id,
            "tool_id": self.tool_id,
        }


@dataclass(frozen=True, slots=True)
class ForensicAssertionExecutionEvaluation:
    """Raw-free transport verdict plus the reused semantic evaluation."""

    verdict: ForensicAssertionExecutionVerdict
    reason_codes: tuple[str, ...]
    execution_plan_sha256: str | None
    records: tuple[ForensicAssertionExecutionRecord, ...]
    semantic_evaluation: ForensicAssertionGraphEvaluation | None

    @property
    def confirmed(self) -> bool:
        return (
            self.verdict is ForensicAssertionExecutionVerdict.CONFIRMED
            and not self.reason_codes
            and self.execution_plan_sha256 is not None
            and self.semantic_evaluation is not None
            and self.semantic_evaluation.verdict
            is ForensicAssertionVerdict.CONFIRMED
            and self.semantic_evaluation.passed
            and len(self.records)
            == len(self.semantic_evaluation.corroboration_records)
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "authorities": {
                **_NON_AUTHORITIES,
                "executed_forensic_assertion_fact_authorized": (
                    self.confirmed
                ),
                "forensic_assertion_transport_confirmed": self.confirmed,
                "progress_marker_authorized": self.confirmed,
            },
            "confirmed": self.confirmed,
            "execution_plan_sha256": self.execution_plan_sha256,
            "protocol": FORENSIC_ASSERTION_EXECUTION_PROTOCOL,
            "reason_codes": list(self.reason_codes),
            "records": [item.to_dict() for item in self.records],
            "schema_version": (
                FORENSIC_ASSERTION_EXECUTION_SCHEMA_VERSION
            ),
            "semantic_evaluation": (
                self.semantic_evaluation.to_dict()
                if self.semantic_evaluation is not None
                else None
            ),
            "semantic_evaluation_sha256": (
                self.semantic_evaluation.sha256
                if self.semantic_evaluation is not None
                else None
            ),
            "verdict": self.verdict.value,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(
            self.to_dict(),
            maximum_bytes=(
                FORENSIC_ASSERTION_EXECUTION_EVALUATION_MAX_BYTES
            ),
        )

    @property
    def sha256(self) -> str:
        return _sha256(self.canonical_bytes)

    def reduction_projection(self) -> dict[str, object]:
        if not self.confirmed or self.semantic_evaluation is None:
            return {
                "automatic_submission": False,
                "candidate": None,
                "executed_fact": None,
                "impact": None,
                "progress": None,
                "proof": None,
            }
        result = dict(self.semantic_evaluation.reduction_projection())
        result["automatic_submission"] = False
        result["candidate"] = None
        result["impact"] = None
        result["proof"] = None
        return result


def _rejected(
    code: str,
    *,
    execution_plan: ForensicAssertionExecutionPlan | None = None,
    records: tuple[ForensicAssertionExecutionRecord, ...] = (),
    semantic: ForensicAssertionGraphEvaluation | None = None,
) -> ForensicAssertionExecutionEvaluation:
    return ForensicAssertionExecutionEvaluation(
        verdict=ForensicAssertionExecutionVerdict.REJECTED,
        reason_codes=(code,),
        execution_plan_sha256=(
            execution_plan.execution_plan_sha256
            if execution_plan is not None
            else None
        ),
        records=records,
        semantic_evaluation=semantic,
    )


def _graph_plan_rebuilds(plan: object) -> bool:
    if type(plan) is not ForensicAssertionGraphPlan:
        return False
    try:
        rebuilt = build_forensic_assertion_graph_plan(
            index_execution=plan.index_execution,
            expected_sources=plan.sources,
            tools=plan.tools,
            pointers=plan.pointers,
            assertions=plan.assertions,
            coverage_threshold_ppm=plan.coverage_threshold_ppm,
        )
    except (ForensicAssertionPreflightError, TypeError, ValueError):
        return False
    return rebuilt == plan


def _specification_is_canonical(
    specification: object,
) -> bool:
    if type(specification) is not ForensicAssertionExecutionSpecification:
        return False
    try:
        readiness = _normalized_readiness(specification.readiness)
        readiness_sha256 = forensic_tool_readiness_registry_sha256(
            readiness
        )
        return (
            readiness == specification.readiness
            and readiness_sha256
            == specification.readiness_registry_sha256
            and _valid_sha256(specification.operator_spec_sha256)
            and _valid_int(
                specification.operator_spec_size_bytes,
                minimum=1,
                maximum=FORENSIC_ASSERTION_OPERATOR_SPEC_MAX_BYTES,
            )
            and _graph_plan_rebuilds(specification.plan)
            and specification.plan.tools
            == tuple(item.tool_binding for item in readiness)
            and bool(specification.canonical_bytes)
        )
    except (AttributeError, TypeError, ValueError):
        return False


def _request_matches_rebuilt(
    specification: ForensicAssertionExecutionSpecification,
    request: object,
    pointer: ForensicEvidencePointer,
    readiness: ForensicToolReadiness,
) -> bool:
    if type(request) is not ForensicObservationRequest:
        return False
    issue = ForensicObservationIssue(
        request_id=request.request_id,
        run_id=request.run_id,
        observation_id=request.observation_id,
        receipt_id=request.receipt_id,
        artifact_id=request.artifact_id,
        execution_nonce=b"",
    )
    request_path, observation_path, artifact_path = _issued_paths(issue)
    argv = _expand_command(
        readiness,
        request_path=request_path,
        observation_path=observation_path,
        artifact_path=artifact_path,
    )
    argv_sha256 = _sha256(_canonical_json_bytes(list(argv)))
    try:
        semantic = forensic_corroboration_execution_contract_sha256(
            specification.plan,
            pointer_id=pointer.pointer_id,
            tool_id=readiness.tool_id,
            execution_nonce_sha256=request.execution_nonce_sha256,
        )
        transport = _transport_execution_contract_sha256(
            specification,
            issue=issue,
            request_path=request_path,
            observation_path=observation_path,
            artifact_path=artifact_path,
            pointer=pointer,
            readiness=readiness,
            command_argv_sha256=argv_sha256,
            execution_nonce_sha256=request.execution_nonce_sha256,
            semantic_execution_contract_sha256=semantic,
        )
        canonical = request.canonical_bytes
    except (AttributeError, TypeError, ValueError):
        return False
    root = specification.plan.inventory_root
    return (
        request.request_path == request_path
        and request.observation_path == observation_path
        and request.artifact_path == artifact_path
        and request.pointer == pointer
        and request.pointer_id == pointer.pointer_id
        and request.pointer_kind == pointer.kind
        and request.pointer_sha256
        == forensic_evidence_pointer_sha256(pointer)
        and request.tool_id == readiness.tool_id
        and request.independence_family
        == readiness.independence_family
        and request.tool_version_sha256
        == readiness.tool_version_sha256
        and request.runtime_image_digest
        == readiness.runtime_image_digest
        and request.command_template_sha256
        == readiness.command_template_sha256
        and request.command_argv == argv
        and request.command_argv_sha256 == argv_sha256
        and _valid_sha256(request.execution_nonce_sha256)
        and request.semantic_execution_contract_sha256 == semantic
        and request.transport_execution_contract_sha256 == transport
        and request.operator_spec_sha256
        == specification.operator_spec_sha256
        and request.plan_sha256 == specification.plan.plan_sha256
        and request.readiness_registry_sha256
        == specification.readiness_registry_sha256
        and request.index_execution_evaluation_sha256
        == root.index_execution_evaluation_sha256
        and request.source_manifest_sha256
        == root.source_manifest_sha256
        and request.source_inventory_sha256
        == root.source_inventory_sha256
        and bool(canonical)
    )


def _preissued_plan_is_canonical(
    execution_plan: ForensicAssertionExecutionPlan,
) -> bool:
    specification = execution_plan.specification
    if not _specification_is_canonical(specification):
        return False
    pairs = _required_pointer_tool_pairs(specification)
    if (
        type(execution_plan.requests) is not tuple
        or len(execution_plan.requests) != len(pairs)
        or not execution_plan.requests
    ):
        return False
    all_ids: set[str] = {
        specification.plan.inventory_root.index_run_id,
        specification.plan.inventory_root.index_receipt_id,
        specification.plan.inventory_root.index_artifact_id,
        *(
            item.readiness_artifact_id
            for item in specification.readiness
        ),
    }
    nonce_hashes: set[str] = set()
    request_hashes: set[str] = set()
    transport_hashes: set[str] = set()
    for request, (pointer, readiness) in zip(
        execution_plan.requests,
        pairs,
        strict=True,
    ):
        if type(request) is not ForensicObservationRequest:
            return False
        identifiers = (
            request.request_id,
            request.run_id,
            request.observation_id,
            request.receipt_id,
            request.artifact_id,
        )
        if (
            any(not _valid_id(value) for value in identifiers)
            or len(set(identifiers)) != len(identifiers)
            or any(value in all_ids for value in identifiers)
            or not _valid_sha256(request.execution_nonce_sha256)
            or request.execution_nonce_sha256 in nonce_hashes
            or not _request_matches_rebuilt(
                specification,
                request,
                pointer,
                readiness,
            )
        ):
            return False
        try:
            request_hash = request.request_sha256
        except (AttributeError, TypeError, ValueError):
            return False
        if (
            request_hash in request_hashes
            or request.transport_execution_contract_sha256
            in transport_hashes
        ):
            return False
        all_ids.update(identifiers)
        nonce_hashes.add(request.execution_nonce_sha256)
        request_hashes.add(request_hash)
        transport_hashes.add(
            request.transport_execution_contract_sha256
        )
    try:
        execution_plan.canonical_bytes
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def forensic_assertion_execution_plan_is_canonical(
    execution_plan: object,
) -> bool:
    """Return whether every pre-issued identity retains its exact binding."""

    try:
        return (
            type(execution_plan) is ForensicAssertionExecutionPlan
            and _preissued_plan_is_canonical(execution_plan)
        )
    except (AttributeError, TypeError, ValueError):
        return False


def _observation_matches_request(
    request: ForensicObservationRequest,
    observation: ForensicToolObservationDocument,
) -> bool:
    return (
        observation.request_id == request.request_id
        and observation.request_sha256 == request.request_sha256
        and observation.run_id == request.run_id
        and observation.observation_id == request.observation_id
        and observation.receipt_id == request.receipt_id
        and observation.artifact_id == request.artifact_id
        and observation.artifact_path == request.artifact_path
        and observation.pointer_id == request.pointer_id
        and observation.pointer_kind == request.pointer_kind
        and observation.pointer_sha256 == request.pointer_sha256
        and observation.tool_id == request.tool_id
        and observation.independence_family
        == request.independence_family
        and observation.tool_version_sha256
        == request.tool_version_sha256
        and observation.runtime_image_digest
        == request.runtime_image_digest
        and observation.command_template_sha256
        == request.command_template_sha256
        and observation.command_argv_sha256
        == request.command_argv_sha256
        and observation.execution_nonce_sha256
        == request.execution_nonce_sha256
        and observation.semantic_execution_contract_sha256
        == request.semantic_execution_contract_sha256
        and observation.transport_execution_contract_sha256
        == request.transport_execution_contract_sha256
        and observation.operator_spec_sha256
        == request.operator_spec_sha256
        and observation.plan_sha256 == request.plan_sha256
        and observation.readiness_registry_sha256
        == request.readiness_registry_sha256
        and observation.index_execution_evaluation_sha256
        == request.index_execution_evaluation_sha256
        and observation.source_manifest_sha256
        == request.source_manifest_sha256
        and observation.source_inventory_sha256
        == request.source_inventory_sha256
    )


def _transport_succeeded(
    observation: ForensicToolObservationDocument,
) -> bool:
    return (
        observation.orchestration_status == "completed"
        and type(observation.exit_code) is int
        and observation.exit_code == 0
        and observation.timed_out is False
        and observation.clean_workspace is True
        and observation.evidence_read_only is True
        and observation.network_disabled is True
        and observation.capture_complete is True
        and observation.truncation_known is True
        and observation.truncated is False
        and observation.capture_error_code is None
    )


def evaluate_forensic_assertion_execution(
    execution_plan: ForensicAssertionExecutionPlan,
    transports: Iterable[ForensicToolObservationTransport],
    *,
    operator_spec_payload: bytes,
    current_index_execution: ForensicIndexExecutionEvaluation,
    current_sources: Iterable[ForensicSourceExpectation],
    current_readiness: Iterable[ForensicToolReadiness],
) -> ForensicAssertionExecutionEvaluation:
    """Verify transport evidence, then invoke the assertion graph oracle."""

    if (
        type(execution_plan) is not ForensicAssertionExecutionPlan
        or not _preissued_plan_is_canonical(execution_plan)
    ):
        return _rejected("execution_plan_invalid")
    try:
        reparsed = parse_forensic_assertion_operator_spec(
            operator_spec_payload,
            current_index_execution=current_index_execution,
            current_sources=current_sources,
            current_readiness=current_readiness,
        )
    except (
        ForensicAssertionExecutionPreflightError,
        TypeError,
        ValueError,
    ):
        return _rejected(
            "current_binding_or_operator_spec_revalidation_failed",
            execution_plan=execution_plan,
        )
    if reparsed != execution_plan.specification:
        return _rejected(
            "operator_spec_or_current_binding_rebound",
            execution_plan=execution_plan,
        )
    expected_count = len(execution_plan.requests)
    try:
        values = tuple(islice(iter(transports), expected_count + 1))
    except Exception:
        return _rejected(
            "transports_not_iterable",
            execution_plan=execution_plan,
        )
    if len(values) != expected_count:
        return _rejected(
            "transport_count_mismatch",
            execution_plan=execution_plan,
        )
    used_document_hashes: set[str] = set()
    total_capture_bytes = 0
    observations: list[ForensicCorroborationObservation] = []
    records: list[ForensicAssertionExecutionRecord] = []
    for position, (request, raw) in enumerate(
        zip(execution_plan.requests, values, strict=True),
        start=1,
    ):
        prefix = f"observation-{position}:"
        if type(raw) is not ForensicToolObservationTransport:
            return _rejected(
                prefix + "transport_type_invalid",
                execution_plan=execution_plan,
                records=tuple(records),
            )
        if (
            raw.request_path != request.request_path
            or not _safe_relative_path(raw.request_path)
            or type(raw.request_payload) is not bytes
            or raw.request_payload != request.canonical_bytes
            or _sha256(raw.request_payload) != request.request_sha256
        ):
            return _rejected(
                prefix + "issued_request_mismatch",
                execution_plan=execution_plan,
                records=tuple(records),
            )
        if (
            raw.observation_path != request.observation_path
            or not _safe_relative_path(raw.observation_path)
        ):
            return _rejected(
                prefix + "observation_path_mismatch",
                execution_plan=execution_plan,
                records=tuple(records),
            )
        try:
            document = ForensicToolObservationDocument.from_payload(
                raw.observation_payload
            )
        except (TypeError, ValueError):
            return _rejected(
                prefix + "observation_document_invalid",
                execution_plan=execution_plan,
                records=tuple(records),
            )
        if not _observation_matches_request(request, document):
            return _rejected(
                prefix + "observation_request_binding_mismatch",
                execution_plan=execution_plan,
                records=tuple(records),
            )
        if not _transport_succeeded(document):
            return _rejected(
                prefix + "transport_not_clean_read_only_success",
                execution_plan=execution_plan,
                records=tuple(records),
            )
        document_sha256 = _sha256(raw.observation_payload)
        if (
            document_sha256 != document.sha256
            or document_sha256 in used_document_hashes
        ):
            return _rejected(
                prefix + "observation_document_hash_reused",
                execution_plan=execution_plan,
                records=tuple(records),
            )
        artifact = raw.artifact
        if (
            type(artifact) is not ForensicCapturedArtifact
            or artifact.artifact_id != request.artifact_id
            or artifact.path != request.artifact_path
            or not _safe_relative_path(artifact.path)
            or type(artifact.payload) is not bytes
            or not 1
            <= len(artifact.payload)
            <= FORENSIC_ASSERTION_MAX_ARTIFACT_BYTES
            or len(artifact.payload) != document.artifact_size_bytes
            or _sha256(artifact.payload) != document.artifact_sha256
        ):
            return _rejected(
                prefix + "artifact_capture_binding_mismatch",
                execution_plan=execution_plan,
                records=tuple(records),
            )
        total_capture_bytes += (
            len(raw.observation_payload) + len(artifact.payload)
        )
        if (
            total_capture_bytes
            > FORENSIC_ASSERTION_EXECUTION_MAX_CAPTURE_BYTES
        ):
            return _rejected(
                "capture_total_size_exceeded",
                execution_plan=execution_plan,
                records=tuple(records),
            )
        used_document_hashes.add(document_sha256)
        semantic_artifact = ForensicObservationArtifact(
            artifact_id=document.artifact_id,
            sha256=document.artifact_sha256,
            size_bytes=document.artifact_size_bytes,
        )
        observations.append(
            ForensicCorroborationObservation(
                observation_id=document.observation_id,
                pointer_id=document.pointer_id,
                tool_id=document.tool_id,
                run_id=document.run_id,
                receipt_id=document.receipt_id,
                receipt_sha256=document.sha256,
                execution_nonce_sha256=(
                    document.execution_nonce_sha256
                ),
                execution_contract_sha256=(
                    document.semantic_execution_contract_sha256
                ),
                plan_sha256=document.plan_sha256,
                source_manifest_sha256=(
                    document.source_manifest_sha256
                ),
                source_inventory_sha256=(
                    document.source_inventory_sha256
                ),
                runtime_image_digest=document.runtime_image_digest,
                clean_workspace=document.clean_workspace,
                network_disabled=document.network_disabled,
                orchestration_status=document.orchestration_status,
                exit_code=document.exit_code,
                timed_out=document.timed_out,
                capture_complete=document.capture_complete,
                truncation_known=document.truncation_known,
                truncated=document.truncated,
                capture_error=document.capture_error_code,
                observation_artifact=semantic_artifact,
            )
        )
        records.append(
            ForensicAssertionExecutionRecord(
                request_id=request.request_id,
                request_sha256=request.request_sha256,
                request_path=request.request_path,
                run_id=request.run_id,
                observation_id=request.observation_id,
                observation_path=request.observation_path,
                observation_document_sha256=document_sha256,
                observation_document_size_bytes=len(
                    raw.observation_payload
                ),
                receipt_id=document.receipt_id,
                receipt_sha256=document.sha256,
                pointer_id=request.pointer_id,
                pointer_sha256=request.pointer_sha256,
                tool_id=request.tool_id,
                independence_family=request.independence_family,
                artifact=semantic_artifact,
                artifact_path=request.artifact_path,
            )
        )
    semantic = evaluate_forensic_assertion_graph(
        execution_plan.specification.plan,
        tuple(observations),
    )
    if not semantic.passed:
        return _rejected(
            "semantic_evaluation_rejected",
            execution_plan=execution_plan,
            records=tuple(records),
            semantic=semantic,
        )
    result = ForensicAssertionExecutionEvaluation(
        verdict=ForensicAssertionExecutionVerdict.CONFIRMED,
        reason_codes=(),
        execution_plan_sha256=execution_plan.execution_plan_sha256,
        records=tuple(records),
        semantic_evaluation=semantic,
    )
    try:
        result.canonical_bytes
    except ValueError:
        return _rejected(
            "execution_evaluation_size_exceeded",
            execution_plan=execution_plan,
        )
    return result


__all__ = [
    "FORENSIC_ASSERTION_EXECUTION_EVALUATION_MAX_BYTES",
    "FORENSIC_ASSERTION_EXECUTION_MAX_CAPTURE_BYTES",
    "FORENSIC_ASSERTION_EXECUTION_PLAN_MAX_BYTES",
    "FORENSIC_ASSERTION_EXECUTION_PROTOCOL",
    "FORENSIC_ASSERTION_EXECUTION_REQUEST_MAX_BYTES",
    "FORENSIC_ASSERTION_NONCE_MAX_BYTES",
    "FORENSIC_ASSERTION_NONCE_MIN_BYTES",
    "FORENSIC_ASSERTION_OBSERVATION_DOCUMENT_MAX_BYTES",
    "FORENSIC_ASSERTION_OPERATOR_SPEC_MAX_BYTES",
    "FORENSIC_ASSERTION_OPERATOR_SPEC_PROTOCOL",
    "ForensicAssertionExecutionEvaluation",
    "ForensicAssertionExecutionPlan",
    "ForensicAssertionExecutionPreflightError",
    "ForensicAssertionExecutionRecord",
    "ForensicAssertionExecutionSpecification",
    "ForensicAssertionExecutionVerdict",
    "ForensicCapturedArtifact",
    "ForensicObservationIssue",
    "ForensicObservationRequest",
    "ForensicToolObservationDocument",
    "ForensicToolObservationTransport",
    "ForensicToolReadiness",
    "build_forensic_tool_observation_document",
    "evaluate_forensic_assertion_execution",
    "forensic_assertion_execution_plan_is_canonical",
    "forensic_tool_readiness_registry_sha256",
    "parse_forensic_assertion_operator_spec",
    "plan_forensic_assertion_execution",
]
