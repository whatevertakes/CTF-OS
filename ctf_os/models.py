"""Domain models for the filesystem-backed CTF-OS state.

The state file is deliberately represented with standard-library dataclasses.
Keeping this layer dependency-free makes recovery possible even when the rest of
the runtime (or its virtual environment) is damaged during a contest.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import shlex
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from ctf_os.candidates import candidate_value_is_valid
from ctf_os.contracts import resolve_rev_inventory_contract
from ctf_os.contracts.pwn_crash_v1 import (
    PWN_CRASH_V1_ATTEMPT_COUNT,
    PWN_CRASH_V1_CONTRACT_FINGERPRINT,
    PWN_CRASH_V1_CONTRACT_ID,
    PWN_CRASH_V1_CONTRACT_VERSION,
    PWN_CRASH_V1_MAX_INPUT_BYTES,
    PWN_CRASH_V1_MAX_SOURCE_BYTES,
    PWN_CRASH_V1_PROTOCOL,
)
from ctf_os.contracts.pwn_runtime_snapshot_v1 import (
    PWN_RUNTIME_SNAPSHOT_V1_PROTOCOL,
    PWN_RUNTIME_SNAPSHOT_V1_TARGET_TIMEOUT_SECONDS,
)
from ctf_os.contracts.rev_inventory_v1 import (
    REV_INVENTORY_V1_CONTRACT_FINGERPRINT,
    REV_INVENTORY_V1_CONTRACT_ID,
    REV_INVENTORY_V1_CONTRACT_VERSION,
    REV_INVENTORY_V1_DOCUMENT_TRANSPORT,
    REV_INVENTORY_V1_SEED_TEMPLATE_ID,
    RevInventoryV1ContractError,
    build_rev_inventory_v1_seed_extra,
    build_rev_inventory_v1_source_binding,
    build_rev_inventory_v1_source_snapshot,
    rev_inventory_v1_oracle_descriptor,
    rev_inventory_v1_seed_command,
)
from ctf_os.contracts.rev_inventory_v2 import (
    REV_INVENTORY_V2_ADAPTER_SEED_CONTRACT_VERSION,
    REV_INVENTORY_V2_CONTRACT_FINGERPRINT,
    REV_INVENTORY_V2_CONTRACT_ID,
    REV_INVENTORY_V2_CONTRACT_VERSION,
    REV_INVENTORY_V2_DOCUMENT_TRANSPORT,
    REV_INVENTORY_V2_MAX_BYTES,
    REV_INVENTORY_V2_SEED_DROP_CONDITION,
    REV_INVENTORY_V2_SEED_EXPECTED_OBSERVATION,
    REV_INVENTORY_V2_SEED_KEEP_CONDITION,
    REV_INVENTORY_V2_SEED_REQUIRES_EXPLICIT_EXECUTION,
    REV_INVENTORY_V2_SEED_RESOURCE_CLASS,
    REV_INVENTORY_V2_SEED_TEMPLATE_ID,
    REV_INVENTORY_V2_SEED_TIMEOUT_SECONDS,
    RevInventoryV2ContractError,
    build_rev_inventory_v2_seed_extra,
    build_rev_inventory_v2_source_binding,
    build_rev_inventory_v2_source_snapshot,
    rev_inventory_v2_oracle_descriptor,
    rev_inventory_v2_seed_command,
    validate_rev_inventory_v2_result_mapping,
)
from ctf_os.managed_continuity import (
    THREAD_CONTINUITY_CONTRACT_VERSION,
    THREAD_CONTINUITY_RUN_KEY,
    THREAD_CONTINUITY_SESSION_KEY,
    run_audit_errors,
    session_metadata_errors,
)
from ctf_os.schema import STATE_SCHEMA_VERSION

# Compatibility alias for callers that still construct or inspect v1 state.
# Unrelated protocols must import their own constant from ``ctf_os.schema``.
CURRENT_SCHEMA_VERSION = 1
MAX_REPEATED_FIELD_ITEMS = 16_384
MAX_RECORDS_PER_COLLECTION = MAX_REPEATED_FIELD_ITEMS
MAX_EXPERIMENT_TIMEOUT_SECONDS = 8 * 60 * 60
MAX_RECEIPT_STREAM_EVIDENCE_BYTES = 4096
MAX_RECEIPT_STREAM_EVIDENCE_TOTAL_BYTES = (
    2 * MAX_RECEIPT_STREAM_EVIDENCE_BYTES + 256
)
MAX_RECEIPT_SAMPLE_BYTES = 1024
MAX_RECEIPT_EXCERPT_JSON_CHARS = 512
MAX_PROOF_RECIPE_INPUTS = 256
MAX_PROOF_ATTEMPTS = 11
MAX_PROOF_POLICY_STRING_BYTES = 256
MAX_PROOF_POLICY_NOTES_BYTES = 64 * 1024
MAX_PROOF_DESTINATION_BYTES = 4096
MAX_MANAGED_PROOF_INPUT_BYTES = 64 * 1024 * 1024
MANAGED_SHELL_COMMAND_PROTOCOL = "posix_sh_lc_v1"
MANAGED_SHELL_ARGV_PREFIX = ("/bin/sh", "-lc")

JSONValue = (
    None
    | bool
    | int
    | float
    | str
    | list["JSONValue"]
    | dict[str, "JSONValue"]
)


class ModelValidationError(ValueError):
    """Raised when a state model violates an invariant."""


class StringEnum(str, Enum):
    """A JSON-friendly enum whose string form is its value."""

    def __str__(self) -> str:
        return self.value


class Provenance(StringEnum):
    EXECUTED = "executed"
    TOOL_INFERRED = "tool_inferred"
    MODEL_CLAIMED = "model_claimed"
    EXTERNAL_DOC = "external_doc"
    OPERATOR = "operator"

    @classmethod
    def parse(cls, value: str | "Provenance") -> "Provenance":
        if isinstance(value, cls):
            return value
        aliases = {
            "tool-inferred": cls.TOOL_INFERRED.value,
            "model-claimed": cls.MODEL_CLAIMED.value,
            "external-doc": cls.EXTERNAL_DOC.value,
        }
        return cls(aliases.get(value, value))


class ChallengeStatus(StringEnum):
    NEW = "NEW"
    TRIAGING = "TRIAGING"
    ACTIVE = "ACTIVE"
    STALLED = "STALLED"
    NEEDS_RESEARCH = "NEEDS_RESEARCH"
    NEEDS_HUMAN = "NEEDS_HUMAN"
    PAUSED = "PAUSED"
    PROVING = "PROVING"
    READY_TO_SUBMIT = "READY_TO_SUBMIT"
    SOLVED = "SOLVED"
    ABANDONED = "ABANDONED"


class HypothesisStatus(StringEnum):
    OPEN = "open"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    CONFIRMED = "confirmed"


ACTIVE_HYPOTHESIS_STATUSES = frozenset(
    {
        HypothesisStatus.OPEN,
        HypothesisStatus.SUPPORTED,
    }
)


class ExperimentStatus(StringEnum):
    REGISTERED = "registered"
    RUNNING = "running"
    AWAITING_EVALUATION = "awaiting_evaluation"
    KEPT = "kept"
    DROPPED = "dropped"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"
    CANCELLED = "cancelled"
    COMPLETED = "completed"


class PwnDisclosurePhase(StringEnum):
    AWAITING_EXPECTATION = "awaiting_expectation"
    EXPECTATION_COMMITTED = "expectation_committed"
    COMPLETE = "complete"


class GoalStatus(StringEnum):
    PENDING = "pending"
    ACTIVE = "active"
    DONE = "done"
    BLOCKED = "blocked"
    PARKED = "parked"
    CANCELLED = "cancelled"


class CandidateStatus(StringEnum):
    OBSERVED_CANDIDATE = "OBSERVED_CANDIDATE"
    PATH_VALIDATED = "PATH_VALIDATED"
    LOCALLY_REPRODUCED = "LOCALLY_REPRODUCED"
    REMOTELY_REPRODUCED = "REMOTELY_REPRODUCED"
    READY_TO_SUBMIT = "READY_TO_SUBMIT"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"


class SubmissionStatus(StringEnum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    ERROR = "error"
    DRY_RUN = "dry_run"


class RunStatus(StringEnum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    INVALID = "invalid"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


class FactKind(StringEnum):
    OBSERVATION = "observation"
    LEGACY = "legacy"


class ExperimentKind(StringEnum):
    PROBE = "probe"
    STRATEGIC = "strategic"
    PROOF = "proof"
    LEGACY = "legacy"


class ReceiptOutcome(StringEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


class CandidateTier(StringEnum):
    EXACT = "exact"
    CONTEST = "contest"
    GENERIC = "generic"
    LEGACY_UNKNOWN = "legacy_unknown"


class BudgetMode(StringEnum):
    BOUNDED = "bounded"
    OPERATOR_UNBOUNDED = "operator_unbounded"
    LEGACY_UNARMED = "legacy_unarmed"


class RunOrigin(StringEnum):
    MANAGED_MODEL = "managed_model"
    MANAGED_TOOL = "managed_tool"
    ASSISTED_MODEL = "assisted_model"
    OPERATOR_TOOL = "operator_tool"
    PROOF = "proof"
    COMPATIBILITY = "compatibility"


class SessionMode(StringEnum):
    MANAGED = "managed"
    ASSISTED = "assisted"
    MANUAL = "manual"


class SessionStatus(StringEnum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    PAUSED = "paused"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


class WaveKind(StringEnum):
    DISCOVERY = "discovery"
    ATTACK = "attack"
    PROOF = "proof"
    EVALUATION = "evaluation"


class TargetStatus(StringEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class ClosureCompleteness(StringEnum):
    COMPLETE = "complete"
    LEGACY_PARTIAL = "legacy_partial"
    INCOMPLETE = "incomplete"


def utc_now() -> str:
    """Return a stable RFC 3339 UTC timestamp."""

    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _enum_value(value: StringEnum | str) -> str:
    return value.value if isinstance(value, StringEnum) else str(value)


def _extra(data: Mapping[str, Any], known: Iterable[str]) -> dict[str, Any]:
    known_set = set(known)
    return {key: value for key, value in data.items() if key not in known_set}


def _with_extra(extra: Mapping[str, Any], **canonical: Any) -> dict[str, Any]:
    result = dict(extra)
    result.update(canonical)
    return result


def _records(value: Any) -> list[dict[str, Any]]:
    """Accept canonical arrays and legacy maps keyed by record ID."""

    if value is None:
        return []
    if isinstance(value, Mapping):
        if len(value) > MAX_RECORDS_PER_COLLECTION:
            raise ModelValidationError(
                "record collection exceeds "
                f"{MAX_RECORDS_PER_COLLECTION} items"
            )
        records: list[dict[str, Any]] = []
        for record_id, record in value.items():
            if not isinstance(record, Mapping):
                raise ModelValidationError("record maps must contain objects")
            item = dict(record)
            item.setdefault("id", str(record_id))
            records.append(item)
        return records
    if not isinstance(value, list):
        raise ModelValidationError("record collection must be an array or map")
    if len(value) > MAX_RECORDS_PER_COLLECTION:
        raise ModelValidationError(
            "record collection exceeds "
            f"{MAX_RECORDS_PER_COLLECTION} items"
        )
    if not all(isinstance(item, Mapping) for item in value):
        raise ModelValidationError("record arrays must contain objects")
    return [dict(item) for item in value]


def _repeated_items(value: Any, label: str) -> list[Any]:
    """Validate a typed repeated field before copying or coercing its items."""

    if value is None:
        return []
    if not isinstance(value, list):
        raise ModelValidationError(f"{label} must be an array")
    if len(value) > MAX_REPEATED_FIELD_ITEMS:
        raise ModelValidationError(
            f"{label} exceeds {MAX_REPEATED_FIELD_ITEMS} items"
        )
    return value


@dataclass(frozen=True)
class ChallengeIdentity:
    contest_id: str
    category: str
    challenge_id: str

    @property
    def key(self) -> str:
        return f"{self.category}/{self.challenge_id}"

    def to_dict(self) -> dict[str, str]:
        return {
            "contest_id": self.contest_id,
            "category": self.category,
            "challenge_id": self.challenge_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ChallengeIdentity":
        return cls(
            contest_id=str(data["contest_id"]),
            category=str(data["category"]),
            challenge_id=str(data["challenge_id"]),
        )


@dataclass
class SourceFile:
    path: str
    sha256: str
    size: int
    kind: str = "file"
    artifact_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return _with_extra(
            self.extra,
            path=self.path,
            sha256=self.sha256,
            size=self.size,
            kind=self.kind,
            artifact_id=self.artifact_id,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SourceFile":
        known = {"path", "sha256", "hash", "size", "kind", "artifact_id"}
        return cls(
            path=str(data["path"]),
            sha256=str(data.get("sha256", data.get("hash", ""))),
            size=int(data.get("size", 0)),
            kind=str(data.get("kind", "file")),
            artifact_id=(
                str(data["artifact_id"])
                if data.get("artifact_id") is not None
                else None
            ),
            extra=_extra(data, known),
        )


@dataclass
class ArtifactReference:
    id: str
    path: str
    sha256: str
    source_run_id: str | None = None
    created_at: str = field(default_factory=utc_now)
    media_type: str | None = None
    size: int | None = None
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return _with_extra(
            self.extra,
            id=self.id,
            path=self.path,
            sha256=self.sha256,
            source_run_id=self.source_run_id,
            created_at=self.created_at,
            media_type=self.media_type,
            size=self.size,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ArtifactReference":
        known = {
            "id",
            "artifact_id",
            "path",
            "sha256",
            "hash",
            "source_run_id",
            "run_id",
            "created_at",
            "media_type",
            "size",
        }
        return cls(
            id=str(data.get("id", data.get("artifact_id", ""))),
            path=str(data["path"]),
            sha256=str(data.get("sha256", data.get("hash", ""))),
            source_run_id=(
                str(data.get("source_run_id", data.get("run_id")))
                if data.get("source_run_id", data.get("run_id")) is not None
                else None
            ),
            created_at=str(data.get("created_at", utc_now())),
            media_type=(
                str(data["media_type"])
                if data.get("media_type") is not None
                else None
            ),
            size=int(data["size"]) if data.get("size") is not None else None,
            extra=_extra(data, known),
        )


@dataclass
class RunReference:
    id: str
    base_revision: int
    status: RunStatus = RunStatus.CREATED
    request_path: str | None = None
    result_path: str | None = None
    validation_path: str | None = None
    role: str | None = None
    model: str | None = None
    context_hash: str | None = None
    origin: RunOrigin = RunOrigin.COMPATIBILITY
    idempotency_key: str | None = None
    session_id: str | None = None
    cycle_id: str | None = None
    wave_id: str | None = None
    configuration_epoch: int | None = None
    created_at: str = field(default_factory=utc_now)
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self, *, v2: bool = False) -> dict[str, Any]:
        canonical = {
            "id": self.id,
            "base_revision": self.base_revision,
            "status": _enum_value(self.status),
            "request_path": self.request_path,
            "result_path": self.result_path,
            "validation_path": self.validation_path,
            "role": self.role,
            "model": self.model,
            "context_hash": self.context_hash,
            "created_at": self.created_at,
        }
        if v2:
            canonical.update(
                origin=_enum_value(self.origin),
                idempotency_key=self.idempotency_key,
                session_id=self.session_id,
                cycle_id=self.cycle_id,
                wave_id=self.wave_id,
                configuration_epoch=self.configuration_epoch,
            )
        return _with_extra(
            self.extra,
            **canonical,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RunReference":
        known = {
            "id",
            "run_id",
            "base_revision",
            "revision",
            "status",
            "request_path",
            "result_path",
            "validation_path",
            "role",
            "model",
            "context_hash",
            "origin",
            "idempotency_key",
            "session_id",
            "cycle_id",
            "wave_id",
            "configuration_epoch",
            "created_at",
        }
        return cls(
            id=str(data.get("id", data.get("run_id", ""))),
            base_revision=int(
                data.get("base_revision", data.get("revision", 0))
            ),
            status=RunStatus(str(data.get("status", RunStatus.CREATED.value))),
            request_path=(
                str(data["request_path"])
                if data.get("request_path") is not None
                else None
            ),
            result_path=(
                str(data["result_path"])
                if data.get("result_path") is not None
                else None
            ),
            validation_path=(
                str(data["validation_path"])
                if data.get("validation_path") is not None
                else None
            ),
            role=str(data["role"]) if data.get("role") is not None else None,
            model=(
                str(data["model"]) if data.get("model") is not None else None
            ),
            context_hash=(
                str(data["context_hash"])
                if data.get("context_hash") is not None
                else None
            ),
            origin=RunOrigin(
                str(data.get("origin", RunOrigin.COMPATIBILITY.value))
            ),
            idempotency_key=(
                str(data["idempotency_key"])
                if data.get("idempotency_key") is not None
                else None
            ),
            session_id=(
                str(data["session_id"])
                if data.get("session_id") is not None
                else None
            ),
            cycle_id=(
                str(data["cycle_id"])
                if data.get("cycle_id") is not None
                else None
            ),
            wave_id=(
                str(data["wave_id"])
                if data.get("wave_id") is not None
                else None
            ),
            configuration_epoch=(
                int(data["configuration_epoch"])
                if data.get("configuration_epoch") is not None
                else None
            ),
            created_at=str(data.get("created_at", utc_now())),
            extra=_extra(data, known),
        )


@dataclass
class Fact:
    id: str
    statement: str
    provenance: Provenance
    kind: FactKind = FactKind.OBSERVATION
    challenge_id: str = ""
    source_run_id: str | None = None
    artifact_id: str | None = None
    locator: str | None = None
    created_at: str = field(default_factory=utc_now)
    supersedes_id: str | None = None
    supports: list[str] = field(default_factory=list)
    contradicts: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(
        self,
        *,
        default_challenge_id: str | None = None,
        v2: bool = False,
    ) -> dict[str, Any]:
        canonical = {
            "id": self.id,
            "challenge_id": self.challenge_id or default_challenge_id or "",
            "statement": self.statement,
            "provenance": _enum_value(self.provenance),
            "source_run_id": self.source_run_id,
            "artifact_id": self.artifact_id,
            "locator": self.locator,
            "created_at": self.created_at,
            "supersedes_id": self.supersedes_id,
            "supports": list(self.supports),
            "contradicts": list(self.contradicts),
        }
        if v2:
            canonical["kind"] = _enum_value(self.kind)
        return _with_extra(
            self.extra,
            **canonical,
        )

    @classmethod
    def from_dict(
        cls, data: Mapping[str, Any], *, default_challenge_id: str = ""
    ) -> "Fact":
        known = {
            "id",
            "challenge_id",
            "statement",
            "claim",
            "provenance",
            "confidence",
            "kind",
            "source_run_id",
            "run_id",
            "artifact_id",
            "locator",
            "raw",
            "created_at",
            "observed_at",
            "supersedes_id",
            "supports",
            "contradicts",
        }
        provenance = data.get("provenance", data.get("confidence"))
        if provenance is None:
            raise ModelValidationError(f"fact {data.get('id')!r} lacks provenance")
        locator = data.get("locator", data.get("raw"))
        return cls(
            id=str(data["id"]),
            challenge_id=str(data.get("challenge_id", default_challenge_id)),
            statement=str(data.get("statement", data.get("claim", ""))),
            provenance=Provenance.parse(str(provenance)),
            kind=FactKind(str(data.get("kind", FactKind.OBSERVATION.value))),
            source_run_id=(
                str(data.get("source_run_id", data.get("run_id")))
                if data.get("source_run_id", data.get("run_id")) is not None
                else None
            ),
            artifact_id=(
                str(data["artifact_id"])
                if data.get("artifact_id") is not None
                else None
            ),
            locator=str(locator) if locator is not None else None,
            created_at=str(
                data.get("created_at", data.get("observed_at", utc_now()))
            ),
            supersedes_id=(
                str(data["supersedes_id"])
                if data.get("supersedes_id") is not None
                else None
            ),
            supports=[
                str(item)
                for item in _repeated_items(
                    data.get("supports", []),
                    "fact supports",
                )
            ],
            contradicts=[
                str(item)
                for item in _repeated_items(
                    data.get("contradicts", []),
                    "fact contradicts",
                )
            ],
            extra=_extra(data, known),
        )


@dataclass
class Falsifier:
    description: str
    command: str | None = None
    expect_if_false: str | None = None
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return _with_extra(
            self.extra,
            description=self.description,
            command=self.command,
            expect_if_false=self.expect_if_false,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Falsifier":
        known = {
            "description",
            "desc",
            "command",
            "cmd",
            "expect_if_false",
        }
        return cls(
            description=str(data.get("description", data.get("desc", ""))),
            command=(
                str(data.get("command", data.get("cmd")))
                if data.get("command", data.get("cmd")) is not None
                else None
            ),
            expect_if_false=(
                str(data["expect_if_false"])
                if data.get("expect_if_false") is not None
                else None
            ),
            extra=_extra(data, known),
        )


@dataclass
class Hypothesis:
    id: str
    statement: str
    falsifier: Falsifier
    paradigm: str | None = None
    status: HypothesisStatus = HypothesisStatus.OPEN
    evidence_fact_ids: list[str] = field(default_factory=list)
    evidence_artifact_ids: list[str] = field(default_factory=list)
    evidence_run_ids: list[str] = field(default_factory=list)
    evidence_receipt_ids: list[str] = field(default_factory=list)
    confidence: float | None = None
    refuted_by: str | None = None
    source_run_id: str | None = None
    created_at: str = field(default_factory=utc_now)
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self, *, v2: bool = False) -> dict[str, Any]:
        canonical = {
            "id": self.id,
            "statement": self.statement,
            "paradigm": self.paradigm,
            "falsifier": self.falsifier.to_dict(),
            "status": _enum_value(self.status),
            "evidence_fact_ids": list(self.evidence_fact_ids),
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
            "evidence_run_ids": list(self.evidence_run_ids),
            "confidence": self.confidence,
            "refuted_by": self.refuted_by,
            "source_run_id": self.source_run_id,
            "created_at": self.created_at,
        }
        if v2:
            canonical["evidence_receipt_ids"] = list(
                self.evidence_receipt_ids
            )
        return _with_extra(
            self.extra,
            **canonical,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Hypothesis":
        known = {
            "id",
            "statement",
            "paradigm",
            "falsifier",
            "status",
            "evidence_fact_ids",
            "evidence_artifact_ids",
            "evidence_run_ids",
            "evidence_receipt_ids",
            "evidence",
            "confidence",
            "refuted_by",
            "source_run_id",
            "created_at",
            "cost_spent_s",
        }
        falsifier = data.get("falsifier", {})
        if isinstance(falsifier, str):
            falsifier = {"description": falsifier}
        if not isinstance(falsifier, Mapping):
            raise ModelValidationError("hypothesis falsifier must be an object")
        return cls(
            id=str(data["id"]),
            statement=str(data.get("statement", "")),
            paradigm=(
                str(data["paradigm"])
                if data.get("paradigm") is not None
                else None
            ),
            falsifier=Falsifier.from_dict(falsifier),
            status=HypothesisStatus(
                str(data.get("status", HypothesisStatus.OPEN.value))
            ),
            evidence_fact_ids=[
                str(item)
                for item in _repeated_items(
                    data.get(
                        "evidence_fact_ids", data.get("evidence", [])
                    ),
                    "hypothesis evidence_fact_ids",
                )
            ],
            evidence_artifact_ids=[
                str(item)
                for item in _repeated_items(
                    data.get("evidence_artifact_ids", []),
                    "hypothesis evidence_artifact_ids",
                )
            ],
            evidence_run_ids=[
                str(item)
                for item in _repeated_items(
                    data.get("evidence_run_ids", []),
                    "hypothesis evidence_run_ids",
                )
            ],
            evidence_receipt_ids=[
                str(item)
                for item in _repeated_items(
                    data.get("evidence_receipt_ids", []),
                    "hypothesis evidence_receipt_ids",
                )
            ],
            confidence=(
                float(data["confidence"])
                if data.get("confidence") is not None
                else None
            ),
            refuted_by=(
                str(data["refuted_by"])
                if data.get("refuted_by") is not None
                else None
            ),
            source_run_id=(
                str(data["source_run_id"])
                if data.get("source_run_id") is not None
                else None
            ),
            created_at=str(data.get("created_at", utc_now())),
            extra=_extra(data, known),
        )


def hypothesis_has_complete_discriminators(
    hypothesis: Hypothesis,
) -> bool:
    """Return whether one active hypothesis is safe to route beyond discovery."""

    unknowns = hypothesis.extra.get("unknowns")
    experiment = hypothesis.extra.get(
        "experiment",
        hypothesis.extra.get("cheapest_experiment"),
    )
    success_oracle = hypothesis.extra.get("success_oracle")
    has_evidence = bool(
        hypothesis.evidence_fact_ids
        or hypothesis.evidence_artifact_ids
        or hypothesis.evidence_run_ids
        or hypothesis.evidence_receipt_ids
    )
    return (
        hypothesis.status in ACTIVE_HYPOTHESIS_STATUSES
        and bool(hypothesis.statement.strip())
        and has_evidence
        and isinstance(unknowns, list)
        and bool(unknowns)
        and all(
            isinstance(item, str) and bool(item.strip())
            for item in unknowns
        )
        and isinstance(experiment, str)
        and bool(experiment.strip())
        and isinstance(success_oracle, str)
        and bool(success_oracle.strip())
        and bool(hypothesis.falsifier.description.strip())
    )


def distinct_complete_active_hypotheses(
    hypotheses: Iterable[Hypothesis],
) -> tuple[Hypothesis, ...]:
    """Keep one complete active hypothesis per normalized claim."""

    distinct: list[Hypothesis] = []
    claims: set[str] = set()
    for hypothesis in hypotheses:
        if not hypothesis_has_complete_discriminators(hypothesis):
            continue
        normalized_claim = " ".join(
            hypothesis.statement.split()
        ).casefold()
        if normalized_claim in claims:
            continue
        claims.add(normalized_claim)
        distinct.append(hypothesis)
    return tuple(distinct)


_PROOF_RECIPE_INPUT_PURPOSES = frozenset(
    {
        "reproducer",
        "fixture",
        "variant_generator",
        "verifier",
        "accepted_input",
    }
)
_PWN_PROOF_RECIPE_INPUT_PURPOSES = frozenset(
    {"reproducer", "fixture", "variant_generator", "verifier"}
)
_PWN_PROOF_PROTOCOL = "remote_pwn_replay_negative_control_v1"
_REV_STDIN_PROOF_PROTOCOL = "rev_original_binary_stdin_candidate_v1"
_REV_STDIN_ORACLE_BINDING_KIND = "rev_original_binary_stdin_v1"
_REV_STDIN_ACCEPTED_INPUT_DESTINATION = "oracle/accepted-input.bin"
_REV_STDIN_MAX_ACCEPTED_INPUT_BYTES = 1024 * 1024
_REV_STDIN_RUNNER_PREFIX = (
    "/usr/bin/python3",
    "/opt/ctf-templates/rev/stdin_exec.py",
    "--binary",
)
_REV_STDIN_RUNNER_INPUT_SUFFIX = (
    "--input",
    "/work/oracle/accepted-input.bin",
)


def _canonical_record_sha256(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class ProofRecipeInput:
    """One immutable canonical artifact staged into a clean proof workspace."""

    artifact_id: str
    destination: str
    purpose: str
    sha256: str
    size: int
    source_run_id: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "destination": self.destination,
            "purpose": self.purpose,
            "sha256": self.sha256,
            "size": self.size,
            "source_run_id": self.source_run_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ProofRecipeInput":
        expected = {
            "artifact_id",
            "destination",
            "purpose",
            "sha256",
            "size",
            "source_run_id",
        }
        if set(data) != expected:
            raise ModelValidationError(
                "proof recipe input has a non-canonical schema"
            )
        if (
            not all(
                isinstance(data.get(field), str)
                for field in (
                    "artifact_id",
                    "destination",
                    "purpose",
                    "sha256",
                )
            )
            or isinstance(data.get("size"), bool)
            or not isinstance(data.get("size"), int)
            or (
                data.get("source_run_id") is not None
                and not isinstance(data.get("source_run_id"), str)
            )
        ):
            raise ModelValidationError(
                "proof recipe input contains a non-canonical type"
            )
        return cls(
            artifact_id=data["artifact_id"],
            destination=data["destination"],
            purpose=data["purpose"],
            sha256=data["sha256"],
            size=data["size"],
            source_run_id=(
                data["source_run_id"]
                if data.get("source_run_id") is not None
                else None
            ),
        )


def _proof_binding_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _proof_binding_identifier(value: object) -> bool:
    return (
        type(value) is str
        and bool(value)
        and value == value.strip()
        and "\x00" not in value
        and len(value.encode("utf-8")) <= 1024
    )


def _proof_binding_utc_timestamp(value: object) -> bool:
    return _proof_binding_utc_datetime(value) is not None


def _proof_binding_utc_datetime(value: object) -> datetime | None:
    if type(value) is not str or not value:
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
        or parsed.utcoffset().total_seconds() != 0
    ):
        return None
    return parsed


@dataclass(frozen=True, slots=True)
class RevStdinOracleBinding:
    """Exact inventory and source pins for a managed Rev stdin proof."""

    protocol: str
    inventory_contract_id: str
    inventory_contract_version: int
    inventory_contract_fingerprint: str
    inventory_experiment_id: str
    inventory_run_id: str
    inventory_stdout_artifact_id: str
    inventory_stdout_sha256: str
    inventory_stdout_size_bytes: int
    source_binding: Mapping[str, JSONValue]
    source_snapshot: Mapping[str, JSONValue]
    budget_deadline_utc: str
    schema_version: int = 1
    kind: str = _REV_STDIN_ORACLE_BINDING_KIND

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != 1
            or self.kind != _REV_STDIN_ORACLE_BINDING_KIND
            or self.protocol != _REV_STDIN_PROOF_PROTOCOL
            or self.inventory_contract_id
            != REV_INVENTORY_V2_CONTRACT_ID
            or type(self.inventory_contract_version) is not int
            or self.inventory_contract_version
            != REV_INVENTORY_V2_CONTRACT_VERSION
            or self.inventory_contract_fingerprint
            != REV_INVENTORY_V2_CONTRACT_FINGERPRINT
            or not all(
                _proof_binding_identifier(value)
                for value in (
                    self.inventory_experiment_id,
                    self.inventory_run_id,
                    self.inventory_stdout_artifact_id,
                )
            )
            or not _proof_binding_sha256(self.inventory_stdout_sha256)
            or type(self.inventory_stdout_size_bytes) is not int
            or not 0
            <= self.inventory_stdout_size_bytes
            <= REV_INVENTORY_V2_MAX_BYTES
            or not _proof_binding_utc_timestamp(self.budget_deadline_utc)
            or not isinstance(self.source_binding, Mapping)
            or not isinstance(self.source_snapshot, Mapping)
        ):
            raise ModelValidationError(
                "Rev stdin oracle binding contains an invalid scalar"
            )
        try:
            expected_source_binding = build_rev_inventory_v2_source_binding(
                manifest_generation=self.source_binding.get(
                    "manifest_generation"
                ),  # type: ignore[arg-type]
                manifest_sha256=self.source_binding.get(
                    "manifest_sha256"
                ),  # type: ignore[arg-type]
                path=self.source_binding.get("path"),  # type: ignore[arg-type]
                source_sha256=self.source_binding.get(
                    "sha256"
                ),  # type: ignore[arg-type]
                source_size_bytes=self.source_binding.get(
                    "size_bytes"
                ),  # type: ignore[arg-type]
            )
            expected_source_snapshot = (
                build_rev_inventory_v2_source_snapshot(
                    expected_source_binding
                )
            )
        except RevInventoryV2ContractError as error:
            raise ModelValidationError(
                "Rev stdin oracle binding has an invalid source pin"
            ) from error
        if (
            dict(self.source_binding) != expected_source_binding
            or dict(self.source_snapshot) != expected_source_snapshot
        ):
            raise ModelValidationError(
                "Rev stdin oracle binding has a non-canonical source pin"
            )
        object.__setattr__(
            self,
            "source_binding",
            MappingProxyType(dict(expected_source_binding)),
        )
        object.__setattr__(
            self,
            "source_snapshot",
            MappingProxyType(dict(expected_source_snapshot)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "protocol": self.protocol,
            "inventory_contract_id": self.inventory_contract_id,
            "inventory_contract_version": (
                self.inventory_contract_version
            ),
            "inventory_contract_fingerprint": (
                self.inventory_contract_fingerprint
            ),
            "inventory_experiment_id": self.inventory_experiment_id,
            "inventory_run_id": self.inventory_run_id,
            "inventory_stdout_artifact_id": (
                self.inventory_stdout_artifact_id
            ),
            "inventory_stdout_sha256": self.inventory_stdout_sha256,
            "inventory_stdout_size_bytes": (
                self.inventory_stdout_size_bytes
            ),
            "source_binding": dict(self.source_binding),
            "source_snapshot": dict(self.source_snapshot),
            "budget_deadline_utc": self.budget_deadline_utc,
        }

    def __deepcopy__(
        self,
        memo: dict[int, object],
    ) -> "RevStdinOracleBinding":
        del memo
        return self

    @classmethod
    def create(
        cls,
        *,
        protocol: str,
        inventory_contract_id: str,
        inventory_contract_version: int,
        inventory_contract_fingerprint: str,
        inventory_experiment_id: str,
        inventory_run_id: str,
        inventory_stdout_artifact_id: str,
        inventory_stdout_sha256: str,
        inventory_stdout_size_bytes: int,
        source_binding: Mapping[str, JSONValue],
        source_snapshot: Mapping[str, JSONValue],
        budget_deadline_utc: str,
    ) -> "RevStdinOracleBinding":
        return cls(
            protocol=protocol,
            inventory_contract_id=inventory_contract_id,
            inventory_contract_version=inventory_contract_version,
            inventory_contract_fingerprint=(
                inventory_contract_fingerprint
            ),
            inventory_experiment_id=inventory_experiment_id,
            inventory_run_id=inventory_run_id,
            inventory_stdout_artifact_id=inventory_stdout_artifact_id,
            inventory_stdout_sha256=inventory_stdout_sha256,
            inventory_stdout_size_bytes=inventory_stdout_size_bytes,
            source_binding=source_binding,
            source_snapshot=source_snapshot,
            budget_deadline_utc=budget_deadline_utc,
        )

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
    ) -> "RevStdinOracleBinding":
        expected = {
            "schema_version",
            "kind",
            "protocol",
            "inventory_contract_id",
            "inventory_contract_version",
            "inventory_contract_fingerprint",
            "inventory_experiment_id",
            "inventory_run_id",
            "inventory_stdout_artifact_id",
            "inventory_stdout_sha256",
            "inventory_stdout_size_bytes",
            "source_binding",
            "source_snapshot",
            "budget_deadline_utc",
        }
        if set(data) != expected:
            raise ModelValidationError(
                "Rev stdin oracle binding has a non-canonical schema"
            )
        source_binding = data.get("source_binding")
        source_snapshot = data.get("source_snapshot")
        if (
            not isinstance(source_binding, Mapping)
            or not isinstance(source_snapshot, Mapping)
            or type(data.get("schema_version")) is not int
            or type(data.get("inventory_contract_version")) is not int
            or type(data.get("inventory_stdout_size_bytes")) is not int
            or any(
                type(data.get(field)) is not str
                for field in (
                    "kind",
                    "protocol",
                    "inventory_contract_id",
                    "inventory_contract_fingerprint",
                    "inventory_experiment_id",
                    "inventory_run_id",
                    "inventory_stdout_artifact_id",
                    "inventory_stdout_sha256",
                    "budget_deadline_utc",
                )
            )
        ):
            raise ModelValidationError(
                "Rev stdin oracle binding contains a non-canonical type"
            )
        return cls(
            schema_version=data["schema_version"],
            kind=data["kind"],
            protocol=data["protocol"],
            inventory_contract_id=data["inventory_contract_id"],
            inventory_contract_version=data[
                "inventory_contract_version"
            ],
            inventory_contract_fingerprint=data[
                "inventory_contract_fingerprint"
            ],
            inventory_experiment_id=data["inventory_experiment_id"],
            inventory_run_id=data["inventory_run_id"],
            inventory_stdout_artifact_id=data[
                "inventory_stdout_artifact_id"
            ],
            inventory_stdout_sha256=data["inventory_stdout_sha256"],
            inventory_stdout_size_bytes=data[
                "inventory_stdout_size_bytes"
            ],
            source_binding=dict(source_binding),
            source_snapshot=dict(source_snapshot),
            budget_deadline_utc=data["budget_deadline_utc"],
        )


@dataclass(frozen=True, slots=True)
class ProofPolicySnapshot:
    """Engine-owned category policy bound to a managed proof recipe."""

    mode: str
    oracle_protocol: str
    clean_repetitions: int
    remote_repetitions: int
    trial_count: int
    negative_control_repetitions: int
    negative_control_timeout_seconds: int
    minimum_success_rate: float | None
    notes: str
    policy_sha256: str

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "oracle_protocol": self.oracle_protocol,
            "clean_repetitions": self.clean_repetitions,
            "remote_repetitions": self.remote_repetitions,
            "trial_count": self.trial_count,
            "negative_control_repetitions": (
                self.negative_control_repetitions
            ),
            "negative_control_timeout_seconds": (
                self.negative_control_timeout_seconds
            ),
            "minimum_success_rate": self.minimum_success_rate,
            "notes": self.notes,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_dict(),
            "policy_sha256": self.policy_sha256,
        }

    def computed_sha256(self) -> str:
        return _canonical_record_sha256(self._unsigned_dict())

    @classmethod
    def create(
        cls,
        *,
        mode: str,
        oracle_protocol: str,
        clean_repetitions: int,
        remote_repetitions: int,
        trial_count: int,
        negative_control_repetitions: int,
        negative_control_timeout_seconds: int,
        minimum_success_rate: float | None,
        notes: str,
    ) -> "ProofPolicySnapshot":
        unsigned = {
            "mode": mode,
            "oracle_protocol": oracle_protocol,
            "clean_repetitions": clean_repetitions,
            "remote_repetitions": remote_repetitions,
            "trial_count": trial_count,
            "negative_control_repetitions": (
                negative_control_repetitions
            ),
            "negative_control_timeout_seconds": (
                negative_control_timeout_seconds
            ),
            "minimum_success_rate": minimum_success_rate,
            "notes": notes,
        }
        return cls(
            **unsigned,
            policy_sha256=_canonical_record_sha256(unsigned),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ProofPolicySnapshot":
        expected = {
            "mode",
            "oracle_protocol",
            "clean_repetitions",
            "remote_repetitions",
            "trial_count",
            "negative_control_repetitions",
            "negative_control_timeout_seconds",
            "minimum_success_rate",
            "notes",
            "policy_sha256",
        }
        if set(data) != expected:
            raise ModelValidationError(
                "proof policy snapshot has a non-canonical schema"
            )
        minimum = data.get("minimum_success_rate")
        if (
            not all(
                isinstance(data.get(field), str)
                for field in (
                    "mode",
                    "oracle_protocol",
                    "notes",
                    "policy_sha256",
                )
            )
            or any(
                isinstance(data.get(field), bool)
                or not isinstance(data.get(field), int)
                for field in (
                    "clean_repetitions",
                    "remote_repetitions",
                    "trial_count",
                    "negative_control_repetitions",
                    "negative_control_timeout_seconds",
                )
            )
            or (
                minimum is not None
                and (
                    isinstance(minimum, bool)
                    or not isinstance(minimum, (int, float))
                    or not math.isfinite(float(minimum))
                )
            )
        ):
            raise ModelValidationError(
                "proof policy snapshot contains a non-canonical type"
            )
        return cls(
            mode=data["mode"],
            oracle_protocol=data["oracle_protocol"],
            clean_repetitions=data["clean_repetitions"],
            remote_repetitions=data["remote_repetitions"],
            trial_count=data["trial_count"],
            negative_control_repetitions=data[
                "negative_control_repetitions"
            ],
            negative_control_timeout_seconds=data[
                "negative_control_timeout_seconds"
            ],
            minimum_success_rate=minimum,
            notes=data["notes"],
            policy_sha256=data["policy_sha256"],
        )


@dataclass(frozen=True, slots=True)
class ProofRecipe:
    """Canonical candidate, inputs, target, and policy for one proof action."""

    candidate_id: str
    source_experiment_id: str
    source_run_id: str
    argv: tuple[str, ...]
    inputs: tuple[ProofRecipeInput, ...]
    network_target_id: str | None
    network_target_generation: int | None
    network_endpoint: str | None
    configuration_epoch: int
    source_manifest_sha256: str
    source_request_sha256: str
    image_reference: str
    policy: ProofPolicySnapshot
    recipe_sha256: str
    oracle_binding: RevStdinOracleBinding | None = None

    def _unsigned_dict(self) -> dict[str, Any]:
        value = {
            "candidate_id": self.candidate_id,
            "source_experiment_id": self.source_experiment_id,
            "source_run_id": self.source_run_id,
            "argv": list(self.argv),
            "inputs": [item.to_dict() for item in self.inputs],
            "network_target_id": self.network_target_id,
            "network_target_generation": self.network_target_generation,
            "network_endpoint": self.network_endpoint,
            "configuration_epoch": self.configuration_epoch,
            "source_manifest_sha256": self.source_manifest_sha256,
            "source_request_sha256": self.source_request_sha256,
            "image_reference": self.image_reference,
            "policy": self.policy.to_dict(),
        }
        if self.oracle_binding is not None:
            value["oracle_binding"] = self.oracle_binding.to_dict()
        return value

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_dict(),
            "recipe_sha256": self.recipe_sha256,
        }

    def computed_sha256(self) -> str:
        return _canonical_record_sha256(self._unsigned_dict())

    @classmethod
    def create(
        cls,
        *,
        candidate_id: str,
        source_experiment_id: str,
        source_run_id: str,
        argv: Iterable[str],
        inputs: Iterable[ProofRecipeInput],
        network_target_id: str | None,
        network_target_generation: int | None,
        network_endpoint: str | None,
        configuration_epoch: int,
        source_manifest_sha256: str,
        source_request_sha256: str,
        image_reference: str,
        policy: ProofPolicySnapshot,
        oracle_binding: RevStdinOracleBinding | None = None,
    ) -> "ProofRecipe":
        provisional = cls(
            candidate_id=candidate_id,
            source_experiment_id=source_experiment_id,
            source_run_id=source_run_id,
            argv=tuple(argv),
            inputs=tuple(inputs),
            network_target_id=network_target_id,
            network_target_generation=network_target_generation,
            network_endpoint=network_endpoint,
            configuration_epoch=configuration_epoch,
            source_manifest_sha256=source_manifest_sha256,
            source_request_sha256=source_request_sha256,
            image_reference=image_reference,
            policy=policy,
            recipe_sha256="",
            oracle_binding=oracle_binding,
        )
        return cls(
            candidate_id=provisional.candidate_id,
            source_experiment_id=provisional.source_experiment_id,
            source_run_id=provisional.source_run_id,
            argv=provisional.argv,
            inputs=provisional.inputs,
            network_target_id=provisional.network_target_id,
            network_target_generation=(
                provisional.network_target_generation
            ),
            network_endpoint=provisional.network_endpoint,
            configuration_epoch=provisional.configuration_epoch,
            source_manifest_sha256=(
                provisional.source_manifest_sha256
            ),
            source_request_sha256=(
                provisional.source_request_sha256
            ),
            image_reference=provisional.image_reference,
            policy=provisional.policy,
            recipe_sha256=provisional.computed_sha256(),
            oracle_binding=provisional.oracle_binding,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ProofRecipe":
        legacy_expected = {
            "candidate_id",
            "source_experiment_id",
            "source_run_id",
            "argv",
            "inputs",
            "network_target_id",
            "network_target_generation",
            "network_endpoint",
            "configuration_epoch",
            "source_manifest_sha256",
            "source_request_sha256",
            "image_reference",
            "policy",
            "recipe_sha256",
        }
        expected_with_binding = {
            *legacy_expected,
            "oracle_binding",
        }
        if frozenset(data) not in {
            frozenset(legacy_expected),
            frozenset(expected_with_binding),
        }:
            raise ModelValidationError(
                "proof recipe has a non-canonical schema"
            )
        raw_oracle_binding = data.get("oracle_binding")
        if "oracle_binding" in data and not isinstance(
            raw_oracle_binding,
            Mapping,
        ):
            raise ModelValidationError(
                "proof recipe oracle_binding must be a canonical object"
            )
        policy = data.get("policy")
        inputs = data.get("inputs", [])
        argv = data.get("argv", [])
        if (
            not all(
                isinstance(data.get(field), str)
                for field in (
                    "candidate_id",
                    "source_experiment_id",
                    "source_run_id",
                    "source_manifest_sha256",
                    "source_request_sha256",
                    "image_reference",
                    "recipe_sha256",
                )
            )
            or not isinstance(argv, list)
            or any(not isinstance(item, str) for item in argv)
            or not isinstance(inputs, list)
            or any(not isinstance(item, Mapping) for item in inputs)
            or not isinstance(policy, Mapping)
            or isinstance(data.get("configuration_epoch"), bool)
            or not isinstance(data.get("configuration_epoch"), int)
            or (
                data.get("network_target_id") is not None
                and not isinstance(data.get("network_target_id"), str)
            )
            or (
                data.get("network_target_generation") is not None
                and (
                    isinstance(
                        data.get("network_target_generation"), bool
                    )
                    or not isinstance(
                        data.get("network_target_generation"), int
                    )
                )
            )
            or (
                data.get("network_endpoint") is not None
                and not isinstance(data.get("network_endpoint"), str)
            )
        ):
            raise ModelValidationError(
                "proof recipe contains a non-canonical type"
            )
        return cls(
            candidate_id=data["candidate_id"],
            source_experiment_id=data["source_experiment_id"],
            source_run_id=data["source_run_id"],
            argv=tuple(argv),
            inputs=tuple(
                ProofRecipeInput.from_dict(item)
                for item in inputs
            ),
            network_target_id=(
                data["network_target_id"]
                if data.get("network_target_id") is not None
                else None
            ),
            network_target_generation=(
                data["network_target_generation"]
                if data.get("network_target_generation") is not None
                else None
            ),
            network_endpoint=(
                data["network_endpoint"]
                if data.get("network_endpoint") is not None
                else None
            ),
            configuration_epoch=data["configuration_epoch"],
            source_manifest_sha256=data["source_manifest_sha256"],
            source_request_sha256=data["source_request_sha256"],
            image_reference=data["image_reference"],
            policy=ProofPolicySnapshot.from_dict(policy),
            recipe_sha256=data["recipe_sha256"],
            oracle_binding=(
                RevStdinOracleBinding.from_dict(raw_oracle_binding)
                if isinstance(raw_oracle_binding, Mapping)
                else None
            ),
        )


_PWN_RUNTIME_SNAPSHOT_DISCLOSURE_ENVELOPE_KEYS = frozenset(
    {
        "schema_version",
        "phase",
        "expectation_source_state_revision",
        "trusted_receipt_expectation",
        "trusted_receipt_expectation_sha256",
        "evaluation_source_state_revision",
        "result",
        "result_sha256",
    }
)


def _state_only_pwn_disclosure_result(value: object) -> object:
    """Reconstruct one canonical diagnostic result without reading artifacts.

    This validates the exact persisted contract, including its all-false
    authorities, but deliberately does not claim that the referenced bytes
    were reread.  The filesystem-backed validator must later recompute the
    expected result and compare it byte-for-byte.
    """

    try:
        from ctf_os.engine.pwn_disclosure import (
            PWN_DISCLOSURE_MAX_CANDIDATES,
            PwnDisclosureCandidate,
            PwnDisclosureResult,
            PwnDisclosureResultBinding,
            PwnDisclosureStatus,
            _require_current_contract_fingerprint,
        )

        _require_current_contract_fingerprint()
        if type(value) is not dict:
            raise ValueError("result is not an exact object")
        raw_candidates = value.get("candidates")
        if (
            type(raw_candidates) is not list
            or len(raw_candidates) > PWN_DISCLOSURE_MAX_CANDIDATES
        ):
            raise ValueError("result candidates are not an exact array")
        expected = PwnDisclosureResult(
            status=PwnDisclosureStatus(value.get("status")),
            reason_code=value.get("reason_code"),
            binding=PwnDisclosureResultBinding.from_dict(
                value.get("binding")
            ),
            candidates=tuple(
                PwnDisclosureCandidate.from_dict(item)
                for item in raw_candidates
            ),
        )
        return PwnDisclosureResult.from_dict(
            value,
            expected_result=expected,
        )
    except (ImportError, KeyError, TypeError, ValueError) as error:
        raise ModelValidationError(
            "Pwn disclosure result is not an exact canonical diagnostic"
        ) from error


@dataclass(frozen=True, slots=True)
class PwnRuntimeSnapshotDisclosureEnvelope:
    """State-only, non-authoritative lifecycle for one disclosure diagnostic."""

    schema_version: int
    phase: PwnDisclosurePhase
    expectation_source_state_revision: int | None
    trusted_receipt_expectation: object | None
    trusted_receipt_expectation_sha256: str | None
    evaluation_source_state_revision: int | None
    result: object | None
    result_sha256: str | None

    def __post_init__(self) -> None:
        try:
            from ctf_os.engine.pwn_disclosure import (
                PWN_DISCLOSURE_SCHEMA_VERSION,
                PwnDisclosureResult,
                PwnDisclosureTrustedReceiptExpectation,
                _require_current_contract_fingerprint,
            )

            _require_current_contract_fingerprint()
        except (ImportError, TypeError, ValueError) as error:
            raise ModelValidationError(
                "Pwn disclosure contract dependency is unavailable or drifted"
            ) from error

        expectation = self.trusted_receipt_expectation
        result = self.result
        expectation_revision = self.expectation_source_state_revision
        evaluation_revision = self.evaluation_source_state_revision
        if (
            type(self.schema_version) is not int
            or self.schema_version != PWN_DISCLOSURE_SCHEMA_VERSION
            or type(self.phase) is not PwnDisclosurePhase
        ):
            raise ModelValidationError(
                "Pwn disclosure envelope identity is not canonical"
            )
        for revision in (expectation_revision, evaluation_revision):
            if revision is not None and (
                type(revision) is not int or revision < 0
            ):
                raise ModelValidationError(
                    "Pwn disclosure source revision is invalid"
                )

        if self.phase is PwnDisclosurePhase.AWAITING_EXPECTATION:
            valid = (
                expectation_revision is None
                and expectation is None
                and self.trusted_receipt_expectation_sha256 is None
                and evaluation_revision is None
                and result is None
                and self.result_sha256 is None
            )
        elif self.phase is PwnDisclosurePhase.EXPECTATION_COMMITTED:
            valid = (
                expectation_revision is not None
                and type(expectation)
                is PwnDisclosureTrustedReceiptExpectation
                and self.trusted_receipt_expectation_sha256
                == expectation.evidence_sha256
                and evaluation_revision is None
                and result is None
                and self.result_sha256 is None
            )
        else:
            valid = (
                expectation_revision is not None
                and type(expectation)
                is PwnDisclosureTrustedReceiptExpectation
                and self.trusted_receipt_expectation_sha256
                == expectation.evidence_sha256
                and evaluation_revision is not None
                and evaluation_revision == expectation_revision + 1
                and type(result) is PwnDisclosureResult
                and self.result_sha256 == result.evidence_sha256
                and (
                    result.binding.upstream
                    .trusted_receipt_expectation_sha256
                    == expectation.evidence_sha256
                )
                and result.binding.upstream.positive_receipts
                == expectation.positive_receipts
                and result.binding.upstream.runtime_snapshot_receipt
                == expectation.runtime_snapshot_receipt
            )
        if not valid:
            raise ModelValidationError(
                "Pwn disclosure envelope phase fields are inconsistent"
            )

    def validate_state_revision(self, state_revision: int) -> None:
        if type(state_revision) is not int or state_revision < 0:
            raise ModelValidationError(
                "Pwn disclosure state revision is invalid"
            )
        if self.phase is PwnDisclosurePhase.AWAITING_EXPECTATION:
            valid = True
        elif self.phase is PwnDisclosurePhase.EXPECTATION_COMMITTED:
            valid = (
                self.expectation_source_state_revision
                == state_revision - 1
            )
        else:
            valid = (
                self.expectation_source_state_revision is not None
                and self.evaluation_source_state_revision
                == self.expectation_source_state_revision + 1
                and state_revision
                >= self.evaluation_source_state_revision + 1
            )
        if not valid:
            raise ModelValidationError(
                "Pwn disclosure source revisions must match consecutive "
                "canonical state replacements"
            )

    def to_dict(self) -> dict[str, object]:
        expectation = self.trusted_receipt_expectation
        result = self.result
        return {
            "schema_version": self.schema_version,
            "phase": self.phase.value,
            "expectation_source_state_revision": (
                self.expectation_source_state_revision
            ),
            "trusted_receipt_expectation": (
                expectation.to_dict()
                if expectation is not None
                else None
            ),
            "trusted_receipt_expectation_sha256": (
                self.trusted_receipt_expectation_sha256
            ),
            "evaluation_source_state_revision": (
                self.evaluation_source_state_revision
            ),
            "result": (
                result.to_dict() if result is not None else None
            ),
            "result_sha256": self.result_sha256,
        }

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
    ) -> "PwnRuntimeSnapshotDisclosureEnvelope":
        if (
            type(value) is not dict
            or set(value)
            != _PWN_RUNTIME_SNAPSHOT_DISCLOSURE_ENVELOPE_KEYS
        ):
            raise ModelValidationError(
                "Pwn disclosure envelope schema is not exact"
            )
        try:
            from ctf_os.engine.pwn_disclosure import (
                PwnDisclosureTrustedReceiptExpectation,
            )

            raw_expectation = value["trusted_receipt_expectation"]
            raw_result = value["result"]
            envelope = cls(
                schema_version=value["schema_version"],
                phase=PwnDisclosurePhase(value["phase"]),
                expectation_source_state_revision=value[
                    "expectation_source_state_revision"
                ],
                trusted_receipt_expectation=(
                    PwnDisclosureTrustedReceiptExpectation.from_dict(
                        raw_expectation
                    )
                    if raw_expectation is not None
                    else None
                ),
                trusted_receipt_expectation_sha256=value[
                    "trusted_receipt_expectation_sha256"
                ],
                evaluation_source_state_revision=value[
                    "evaluation_source_state_revision"
                ],
                result=(
                    _state_only_pwn_disclosure_result(raw_result)
                    if raw_result is not None
                    else None
                ),
                result_sha256=value["result_sha256"],
            )
        except (
            ImportError,
            KeyError,
            TypeError,
            ValueError,
        ) as error:
            raise ModelValidationError(
                "Pwn disclosure envelope is not canonical"
            ) from error
        if value != envelope.to_dict():
            raise ModelValidationError(
                "Pwn disclosure envelope is not reconstructable"
            )
        return envelope


@dataclass
class Experiment:
    id: str
    hypothesis_ids: list[str]
    command: str
    expected_observation: str
    keep_if: str
    drop_if: str
    timeout_seconds: int
    resource_class: str = "light"
    kind: ExperimentKind = ExperimentKind.STRATEGIC
    status: ExperimentStatus = ExperimentStatus.REGISTERED
    result: Any = None
    source_run_id: str | None = None
    artifact_ids: list[str] = field(default_factory=list)
    evidence_fact_ids: list[str] = field(default_factory=list)
    evidence_run_ids: list[str] = field(default_factory=list)
    evidence_receipt_ids: list[str] = field(default_factory=list)
    evaluation_reason: str | None = None
    evaluated_at: str | None = None
    proof_recipe: ProofRecipe | None = None
    created_at: str = field(default_factory=utc_now)
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self, *, v2: bool = False) -> dict[str, Any]:
        canonical = {
            "id": self.id,
            "hypothesis_ids": list(self.hypothesis_ids),
            "command": self.command,
            "expected_observation": self.expected_observation,
            "keep_if": self.keep_if,
            "drop_if": self.drop_if,
            "timeout_seconds": self.timeout_seconds,
            "resource_class": self.resource_class,
            "status": _enum_value(self.status),
            "result": self.result,
            "source_run_id": self.source_run_id,
            "artifact_ids": list(self.artifact_ids),
            "evidence_fact_ids": list(self.evidence_fact_ids),
            "evidence_run_ids": list(self.evidence_run_ids),
            "evaluation_reason": self.evaluation_reason,
            "evaluated_at": self.evaluated_at,
            "created_at": self.created_at,
        }
        if v2:
            canonical["kind"] = _enum_value(self.kind)
            canonical["evidence_receipt_ids"] = list(
                self.evidence_receipt_ids
            )
            canonical["proof_recipe"] = (
                self.proof_recipe.to_dict()
                if self.proof_recipe is not None
                else None
            )
        return _with_extra(
            self.extra,
            **canonical,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Experiment":
        raw_proof_recipe = data.get("proof_recipe")
        if (
            raw_proof_recipe is not None
            and not isinstance(raw_proof_recipe, Mapping)
        ):
            raise ModelValidationError(
                "experiment proof_recipe must be a canonical object or null"
            )
        known = {
            "id",
            "hypothesis_ids",
            "discriminates",
            "command",
            "cmd",
            "expected_observation",
            "expected",
            "keep_if",
            "drop_if",
            "timeout_seconds",
            "max_seconds",
            "resource_class",
            "kind",
            "status",
            "result",
            "source_run_id",
            "artifact_ids",
            "evidence_fact_ids",
            "evidence_run_ids",
            "evidence_receipt_ids",
            "evaluation_reason",
            "evaluated_at",
            "proof_recipe",
            "created_at",
            "max_runs",
            "oracle",
        }
        return cls(
            id=str(data["id"]),
            hypothesis_ids=[
                str(item)
                for item in _repeated_items(
                    data.get(
                        "hypothesis_ids", data.get("discriminates", [])
                    ),
                    "experiment hypothesis_ids",
                )
            ],
            command=str(data.get("command", data.get("cmd", ""))),
            expected_observation=str(
                data.get("expected_observation", data.get("expected", ""))
            ),
            keep_if=str(data.get("keep_if", "")),
            drop_if=str(data.get("drop_if", "")),
            timeout_seconds=data.get(  # type: ignore[arg-type]
                "timeout_seconds",
                data.get("max_seconds", 0),
            ),
            resource_class=str(data.get("resource_class", "light")),
            kind=ExperimentKind(
                str(data.get("kind", ExperimentKind.STRATEGIC.value))
            ),
            status=ExperimentStatus(
                str(data.get("status", ExperimentStatus.REGISTERED.value))
            ),
            result=data.get("result"),
            source_run_id=(
                str(data["source_run_id"])
                if data.get("source_run_id") is not None
                else None
            ),
            artifact_ids=[
                str(item)
                for item in _repeated_items(
                    data.get("artifact_ids", []),
                    "experiment artifact_ids",
                )
            ],
            evidence_fact_ids=[
                str(item)
                for item in _repeated_items(
                    data.get("evidence_fact_ids", []),
                    "experiment evidence_fact_ids",
                )
            ],
            evidence_run_ids=[
                str(item)
                for item in _repeated_items(
                    data.get("evidence_run_ids", []),
                    "experiment evidence_run_ids",
                )
            ],
            evidence_receipt_ids=[
                str(item)
                for item in _repeated_items(
                    data.get("evidence_receipt_ids", []),
                    "experiment evidence_receipt_ids",
                )
            ],
            evaluation_reason=(
                str(data["evaluation_reason"])
                if data.get("evaluation_reason") is not None
                else None
            ),
            evaluated_at=(
                str(data["evaluated_at"])
                if data.get("evaluated_at") is not None
                else None
            ),
            proof_recipe=(
                ProofRecipe.from_dict(data["proof_recipe"])
                if isinstance(raw_proof_recipe, Mapping)
                else None
            ),
            created_at=str(data.get("created_at", utc_now())),
            extra=_extra(data, known),
        )


@dataclass
class Goal:
    id: str
    description: str
    status: GoalStatus = GoalStatus.PENDING
    depends_on: list[str] = field(default_factory=list)
    artifact_ids: list[str] = field(default_factory=list)
    blocked_reason: str | None = None
    created_at: str = field(default_factory=utc_now)
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return _with_extra(
            self.extra,
            id=self.id,
            description=self.description,
            status=_enum_value(self.status),
            depends_on=list(self.depends_on),
            artifact_ids=list(self.artifact_ids),
            blocked_reason=self.blocked_reason,
            created_at=self.created_at,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Goal":
        known = {
            "id",
            "description",
            "goal",
            "status",
            "depends_on",
            "artifact_ids",
            "artifact",
            "blocked_reason",
            "created_at",
        }
        artifact_ids = list(
            _repeated_items(
                data.get("artifact_ids", []),
                "goal artifact_ids",
            )
        )
        if data.get("artifact") is not None:
            if len(artifact_ids) >= MAX_REPEATED_FIELD_ITEMS:
                raise ModelValidationError(
                    "goal artifact_ids exceeds "
                    f"{MAX_REPEATED_FIELD_ITEMS} items"
                )
            artifact_ids.append(data["artifact"])
        return cls(
            id=str(data["id"]),
            description=str(data.get("description", data.get("goal", ""))),
            status=GoalStatus(
                str(data.get("status", GoalStatus.PENDING.value))
            ),
            depends_on=[
                str(item)
                for item in _repeated_items(
                    data.get("depends_on", []),
                    "goal depends_on",
                )
            ],
            artifact_ids=[str(item) for item in artifact_ids],
            blocked_reason=(
                str(data["blocked_reason"])
                if data.get("blocked_reason") is not None
                else None
            ),
            created_at=str(data.get("created_at", utc_now())),
            extra=_extra(data, known),
        )


@dataclass
class ProgressMarker:
    id: str
    statement: str
    created_at: str = field(default_factory=utc_now)
    elapsed_seconds: int | None = None
    goal_id: str | None = None
    run_id: str | None = None
    artifact_ids: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return _with_extra(
            self.extra,
            id=self.id,
            statement=self.statement,
            created_at=self.created_at,
            elapsed_seconds=self.elapsed_seconds,
            goal_id=self.goal_id,
            run_id=self.run_id,
            artifact_ids=list(self.artifact_ids),
        )

    @classmethod
    def from_dict(
        cls, data: Mapping[str, Any], *, default_id: str = ""
    ) -> "ProgressMarker":
        known = {
            "id",
            "statement",
            "marker",
            "created_at",
            "elapsed_seconds",
            "t",
            "goal_id",
            "run_id",
            "artifact_ids",
        }
        return cls(
            id=str(data.get("id", default_id)),
            statement=str(data.get("statement", data.get("marker", ""))),
            created_at=str(data.get("created_at", utc_now())),
            elapsed_seconds=(
                int(data.get("elapsed_seconds", data.get("t")))
                if data.get("elapsed_seconds", data.get("t")) is not None
                else None
            ),
            goal_id=(
                str(data["goal_id"])
                if data.get("goal_id") is not None
                else None
            ),
            run_id=(
                str(data["run_id"]) if data.get("run_id") is not None else None
            ),
            artifact_ids=[
                str(item)
                for item in _repeated_items(
                    data.get("artifact_ids", []),
                    "progress marker artifact_ids",
                )
            ],
            extra=_extra(data, known),
        )


@dataclass
class Budget:
    deadline_utc: str | None = None
    allocated_seconds: int | None = None
    spent_seconds: int = 0
    no_progress_since_seconds: int | None = None
    model_tier: str | None = None
    abort_rule: dict[str, Any] = field(default_factory=dict)
    refusals: list[dict[str, Any]] = field(default_factory=list)
    curve_profile: str | None = None
    mode: BudgetMode = BudgetMode.LEGACY_UNARMED
    unbounded_reason: str | None = None
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def remaining_seconds(self) -> int | None:
        if self.allocated_seconds is None:
            return None
        return max(0, self.allocated_seconds - self.spent_seconds)

    def to_dict(self, *, v2: bool = False) -> dict[str, Any]:
        canonical = {
            "deadline_utc": self.deadline_utc,
            "allocated_seconds": self.allocated_seconds,
            "spent_seconds": self.spent_seconds,
            "no_progress_since_seconds": self.no_progress_since_seconds,
            "model_tier": self.model_tier,
            "abort_rule": dict(self.abort_rule),
            "refusals": list(self.refusals),
            "curve_profile": self.curve_profile,
        }
        if v2:
            canonical.update(
                mode=_enum_value(self.mode),
                unbounded_reason=self.unbounded_reason,
            )
        return _with_extra(
            self.extra,
            **canonical,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> "Budget":
        data = data or {}
        known = {
            "deadline_utc",
            "allocated_seconds",
            "allocated_s",
            "spent_seconds",
            "spent_s",
            "no_progress_since_seconds",
            "no_progress_since_s",
            "model_tier",
            "abort_rule",
            "refusals",
            "curve_profile",
            "progress_markers",
            "mode",
            "unbounded_reason",
        }
        return cls(
            deadline_utc=(
                str(data["deadline_utc"])
                if data.get("deadline_utc") is not None
                else None
            ),
            allocated_seconds=(
                int(data.get("allocated_seconds", data.get("allocated_s")))
                if data.get("allocated_seconds", data.get("allocated_s"))
                is not None
                else None
            ),
            spent_seconds=int(
                data.get("spent_seconds", data.get("spent_s", 0))
            ),
            no_progress_since_seconds=(
                int(
                    data.get(
                        "no_progress_since_seconds",
                        data.get("no_progress_since_s"),
                    )
                )
                if data.get(
                    "no_progress_since_seconds",
                    data.get("no_progress_since_s"),
                )
                is not None
                else None
            ),
            model_tier=(
                str(data["model_tier"])
                if data.get("model_tier") is not None
                else None
            ),
            abort_rule=dict(data.get("abort_rule", {})),
            refusals=[
                dict(item)
                for item in _repeated_items(
                    data.get("refusals", []),
                    "budget refusals",
                )
                if isinstance(item, Mapping)
            ],
            curve_profile=(
                str(data["curve_profile"])
                if data.get("curve_profile") is not None
                else None
            ),
            mode=BudgetMode(
                str(data.get("mode", BudgetMode.LEGACY_UNARMED.value))
            ),
            unbounded_reason=(
                str(data["unbounded_reason"])
                if data.get("unbounded_reason") is not None
                else None
            ),
            extra=_extra(data, known),
        )


@dataclass
class FlagCandidate:
    id: str
    value: str
    status: CandidateStatus = CandidateStatus.OBSERVED_CANDIDATE
    source_run_id: str | None = None
    artifact_id: str | None = None
    locator: str | None = None
    created_at: str = field(default_factory=utc_now)
    proof_run_ids: list[str] = field(default_factory=list)
    tier: CandidateTier = CandidateTier.GENERIC
    format_epoch: int | None = None
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self, *, v2: bool = False) -> dict[str, Any]:
        canonical = {
            "id": self.id,
            "value": self.value,
            "status": _enum_value(self.status),
            "source_run_id": self.source_run_id,
            "artifact_id": self.artifact_id,
            "locator": self.locator,
            "created_at": self.created_at,
            "proof_run_ids": list(self.proof_run_ids),
        }
        if v2:
            canonical.update(
                tier=_enum_value(self.tier),
                format_epoch=self.format_epoch,
            )
        return _with_extra(
            self.extra,
            **canonical,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "FlagCandidate":
        known = {
            "id",
            "value",
            "flag",
            "status",
            "source_run_id",
            "artifact_id",
            "locator",
            "created_at",
            "proof_run_ids",
            "tier",
            "format_epoch",
        }
        return cls(
            id=str(data["id"]),
            value=str(data.get("value", data.get("flag", ""))),
            status=CandidateStatus(
                str(
                    data.get(
                        "status", CandidateStatus.OBSERVED_CANDIDATE.value
                    )
                )
            ),
            source_run_id=(
                str(data["source_run_id"])
                if data.get("source_run_id") is not None
                else None
            ),
            artifact_id=(
                str(data["artifact_id"])
                if data.get("artifact_id") is not None
                else None
            ),
            locator=(
                str(data["locator"])
                if data.get("locator") is not None
                else None
            ),
            created_at=str(data.get("created_at", utc_now())),
            proof_run_ids=[
                str(item)
                for item in _repeated_items(
                    data.get("proof_run_ids", []),
                    "candidate proof_run_ids",
                )
            ],
            tier=CandidateTier(
                str(data.get("tier", CandidateTier.GENERIC.value))
            ),
            format_epoch=(
                int(data["format_epoch"])
                if data.get("format_epoch") is not None
                else None
            ),
            extra=_extra(data, known),
        )


# A concise alias is convenient in engine code and preserves the terminology in
# the implementation report.
Candidate = FlagCandidate


@dataclass
class SubmissionOverride:
    kind: str
    actor: str
    reason: str
    timestamp: str = field(default_factory=utc_now)
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return _with_extra(
            self.extra,
            kind=self.kind,
            actor=self.actor,
            reason=self.reason,
            timestamp=self.timestamp,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SubmissionOverride":
        known = {"kind", "actor", "reason", "timestamp"}
        return cls(
            kind=str(data.get("kind", "")),
            actor=str(data.get("actor", "")),
            reason=str(data.get("reason", "")),
            timestamp=str(data.get("timestamp", utc_now())),
            extra=_extra(data, known),
        )


@dataclass
class SubmissionReference:
    id: str
    candidate_id: str
    status: SubmissionStatus = SubmissionStatus.PENDING
    submitted_at: str | None = None
    response: str | None = None
    attempt: int = 1
    proof_passed: bool = False
    format_ok: bool = False
    points: int | float | None = None
    override: SubmissionOverride | None = None
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self, *, v2: bool = False) -> dict[str, Any]:
        canonical = {
            "id": self.id,
            "candidate_id": self.candidate_id,
            "status": _enum_value(self.status),
            "submitted_at": self.submitted_at,
            "response": self.response,
            "attempt": self.attempt,
            "proof_passed": self.proof_passed,
            "format_ok": self.format_ok,
            "points": self.points,
        }
        if v2:
            canonical["override"] = (
                self.override.to_dict() if self.override is not None else None
            )
        return _with_extra(
            self.extra,
            **canonical,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SubmissionReference":
        known = {
            "id",
            "candidate_id",
            "status",
            "submitted_at",
            "ts",
            "response",
            "attempt",
            "proof_passed",
            "format_ok",
            "points",
            "override",
        }
        status = data.get("status")
        if status is None:
            response = str(data.get("response", "")).lower()
            status = (
                SubmissionStatus.ACCEPTED.value
                if response in {"correct", "accepted"}
                else SubmissionStatus.REJECTED.value
                if response in {"incorrect", "wrong", "rejected"}
                else SubmissionStatus.PENDING.value
            )
        return cls(
            id=str(data["id"]),
            candidate_id=str(data["candidate_id"]),
            status=SubmissionStatus(str(status)),
            submitted_at=(
                str(data.get("submitted_at", data.get("ts")))
                if data.get("submitted_at", data.get("ts")) is not None
                else None
            ),
            response=(
                str(data["response"])
                if data.get("response") is not None
                else None
            ),
            attempt=int(data.get("attempt", 1)),
            proof_passed=bool(data.get("proof_passed", False)),
            format_ok=bool(data.get("format_ok", False)),
            points=data.get("points"),
            override=(
                SubmissionOverride.from_dict(data["override"])
                if isinstance(data.get("override"), Mapping)
                else None
            ),
            extra=_extra(data, known),
        )


Submission = SubmissionReference


@dataclass
class ExecutionReceipt:
    id: str
    experiment_id: str
    run_id: str
    outcome: ReceiptOutcome
    exit_code: int | None = None
    wall_seconds: float = 0.0
    stdout_artifact_id: str | None = None
    stderr_artifact_id: str | None = None
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    stdout_lines: int = 0
    stderr_lines: int = 0
    preview: str = ""
    created_at: str = field(default_factory=utc_now)
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return _with_extra(
            self.extra,
            id=self.id,
            experiment_id=self.experiment_id,
            run_id=self.run_id,
            outcome=_enum_value(self.outcome),
            exit_code=self.exit_code,
            wall_seconds=self.wall_seconds,
            stdout_artifact_id=self.stdout_artifact_id,
            stderr_artifact_id=self.stderr_artifact_id,
            stdout_bytes=self.stdout_bytes,
            stderr_bytes=self.stderr_bytes,
            stdout_lines=self.stdout_lines,
            stderr_lines=self.stderr_lines,
            preview=self.preview,
            created_at=self.created_at,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ExecutionReceipt":
        known = {
            "id",
            "experiment_id",
            "run_id",
            "outcome",
            "exit_code",
            "wall_seconds",
            "stdout_artifact_id",
            "stderr_artifact_id",
            "stdout_bytes",
            "stderr_bytes",
            "stdout_lines",
            "stderr_lines",
            "preview",
            "created_at",
        }
        return cls(
            id=str(data.get("id", "")),
            experiment_id=str(data.get("experiment_id", "")),
            run_id=str(data.get("run_id", "")),
            outcome=ReceiptOutcome(str(data.get("outcome", "failed"))),
            exit_code=(
                int(data["exit_code"])
                if data.get("exit_code") is not None
                else None
            ),
            wall_seconds=float(data.get("wall_seconds", 0.0)),
            stdout_artifact_id=(
                str(data["stdout_artifact_id"])
                if data.get("stdout_artifact_id") is not None
                else None
            ),
            stderr_artifact_id=(
                str(data["stderr_artifact_id"])
                if data.get("stderr_artifact_id") is not None
                else None
            ),
            stdout_bytes=int(data.get("stdout_bytes", 0)),
            stderr_bytes=int(data.get("stderr_bytes", 0)),
            stdout_lines=int(data.get("stdout_lines", 0)),
            stderr_lines=int(data.get("stderr_lines", 0)),
            preview=str(data.get("preview", "")),
            created_at=str(data.get("created_at", utc_now())),
            extra=_extra(data, known),
        )


def _receipt_stream_evidence_errors(
    receipt: ExecutionReceipt,
    artifacts: Mapping[str, ArtifactReference],
) -> list[str]:
    """Validate the optional, bounded receipt-to-artifact evidence chain."""

    errors: list[str] = []
    raw_evidence = receipt.extra.get("stream_evidence")
    line_count_basis = receipt.extra.get("line_count_basis")
    if raw_evidence is None:
        if line_count_basis is not None:
            errors.append(
                f"receipt {receipt.id} line_count_basis requires "
                "stream_evidence"
            )
        return errors
    if line_count_basis != "transport_summary_tail":
        errors.append(
            f"receipt {receipt.id} has invalid line_count_basis"
        )
    if not isinstance(raw_evidence, dict):
        errors.append(
            f"receipt {receipt.id} stream_evidence must be an object"
        )
        return errors
    try:
        encoded_evidence = json.dumps(
            raw_evidence,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        errors.append(
            f"receipt {receipt.id} stream_evidence is not canonical JSON"
        )
        return errors
    if len(encoded_evidence) > MAX_RECEIPT_STREAM_EVIDENCE_TOTAL_BYTES:
        errors.append(
            f"receipt {receipt.id} stream_evidence exceeds its size bound"
        )

    expected_streams = {
        stream: artifact_id
        for stream, artifact_id in (
            ("stdout", receipt.stdout_artifact_id),
            ("stderr", receipt.stderr_artifact_id),
        )
        if artifact_id is not None
    }
    if set(raw_evidence) != set(expected_streams):
        errors.append(
            f"receipt {receipt.id} stream_evidence keys do not match "
            "its stream artifacts"
        )

    allowed_record_keys = {
        "schema_version",
        "stream",
        "artifact_id",
        "path",
        "sha256",
        "drained_bytes",
        "stored_bytes",
        "limit_bytes",
        "capture_complete",
        "truncation_known",
        "truncated",
        "coverage",
        "transport_summary_truncated",
        "stream_error_present",
        "capture_error_present",
        "sample_policy",
        "head",
        "tail",
        "omitted_stored_bytes",
        "redaction_count",
        "binary_sample_omitted",
    }

    def valid_nonnegative_integer(value: object) -> bool:
        return (
            not isinstance(value, bool)
            and isinstance(value, int)
            and value >= 0
        )

    for stream, expected_artifact_id in expected_streams.items():
        label = f"receipt {receipt.id} {stream} evidence"
        evidence = raw_evidence.get(stream)
        if not isinstance(evidence, dict):
            errors.append(f"{label} must be an object")
            continue
        try:
            encoded_stream = json.dumps(
                evidence,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
                allow_nan=False,
            ).encode("ascii")
        except (TypeError, ValueError, UnicodeError):
            errors.append(f"{label} is not canonical JSON")
            continue
        if len(encoded_stream) > MAX_RECEIPT_STREAM_EVIDENCE_BYTES:
            errors.append(f"{label} exceeds its size bound")
        if set(evidence) != allowed_record_keys:
            errors.append(f"{label} has an invalid nested schema")

        if (
            isinstance(evidence.get("schema_version"), bool)
            or evidence.get("schema_version") != 1
        ):
            errors.append(f"{label} has an invalid schema_version")
        if evidence.get("stream") != stream:
            errors.append(f"{label} has a mismatched stream name")
        if evidence.get("artifact_id") != expected_artifact_id:
            errors.append(f"{label} has a mismatched artifact_id")

        artifact = artifacts.get(expected_artifact_id)
        if artifact is None:
            errors.append(f"{label} references an unknown artifact")
        else:
            if evidence.get("path") != artifact.path:
                errors.append(f"{label} path does not match its artifact")
            if evidence.get("sha256") != artifact.sha256:
                errors.append(f"{label} SHA-256 does not match its artifact")
            if evidence.get("stored_bytes") != artifact.size:
                errors.append(f"{label} size does not match its artifact")
            if artifact.source_run_id != receipt.run_id:
                errors.append(f"{label} artifact/run chain is mismatched")
            if artifact.extra.get("stream") != stream:
                errors.append(f"{label} artifact stream is mismatched")

        drained_bytes = evidence.get("drained_bytes")
        stored_bytes = evidence.get("stored_bytes")
        limit_bytes = evidence.get("limit_bytes")
        receipt_bytes = (
            receipt.stdout_bytes
            if stream == "stdout"
            else receipt.stderr_bytes
        )
        if (
            not valid_nonnegative_integer(drained_bytes)
            or drained_bytes != receipt_bytes
        ):
            errors.append(f"{label} has an invalid drained byte count")
        if not valid_nonnegative_integer(stored_bytes):
            errors.append(f"{label} has an invalid stored byte count")
        if limit_bytes is not None and (
            not valid_nonnegative_integer(limit_bytes)
            or (
                valid_nonnegative_integer(stored_bytes)
                and limit_bytes < stored_bytes
            )
        ):
            errors.append(f"{label} has an invalid capture limit")

        capture_complete = evidence.get("capture_complete")
        truncation_known = evidence.get("truncation_known")
        truncated = evidence.get("truncated")
        for name in (
            "capture_complete",
            "truncation_known",
            "transport_summary_truncated",
            "stream_error_present",
            "capture_error_present",
            "binary_sample_omitted",
        ):
            if not isinstance(evidence.get(name), bool):
                errors.append(f"{label} {name} must be a boolean")
        if truncated is not None and not isinstance(truncated, bool):
            errors.append(f"{label} truncated must be boolean or null")
        if truncation_known is True and not isinstance(truncated, bool):
            errors.append(
                f"{label} known truncation requires a boolean value"
            )
        if (
            truncation_known is True
            and isinstance(truncated, bool)
            and valid_nonnegative_integer(drained_bytes)
            and valid_nonnegative_integer(stored_bytes)
            and truncated != (drained_bytes > stored_bytes)
        ):
            errors.append(
                f"{label} truncation value is inconsistent with byte counts"
            )
        if capture_complete is True and truncation_known is not True:
            errors.append(
                f"{label} complete capture requires known truncation"
            )

        coverage = evidence.get("coverage")
        if coverage not in {
            "complete_stream",
            "retained_prefix_only",
            "incomplete_capture",
            "unknown",
        }:
            errors.append(f"{label} has an invalid coverage value")
        if (
            coverage == "complete_stream"
            and not (
                capture_complete is True
                and truncation_known is True
                and truncated is False
                and stored_bytes == drained_bytes
            )
        ):
            errors.append(f"{label} falsely claims complete coverage")
        if (
            coverage == "retained_prefix_only"
            and (
                not valid_nonnegative_integer(stored_bytes)
                or not valid_nonnegative_integer(drained_bytes)
                or stored_bytes >= drained_bytes
            )
        ):
            errors.append(f"{label} has invalid retained-prefix coverage")
        if (
            coverage == "incomplete_capture"
            and capture_complete is not False
        ):
            errors.append(f"{label} has invalid incomplete coverage")
        if coverage == "unknown" and capture_complete is not False:
            errors.append(f"{label} has invalid unknown coverage")

        if evidence.get("sample_policy") != (
            "immutable_snapshot_head_tail"
        ):
            errors.append(f"{label} has an invalid sample policy")

        def validate_sample(
            name: str,
            sample: object,
        ) -> tuple[int, int, bool] | None:
            sample_label = f"{label} {name}"
            if not isinstance(sample, dict):
                errors.append(f"{sample_label} must be an object")
                return None
            encoding = sample.get("encoding")
            common_keys = {"byte_start", "byte_end", "encoding"}
            if encoding == "utf-8":
                expected_keys = {
                    *common_keys,
                    "text",
                    "text_truncated",
                }
                text = sample.get("text")
                if not isinstance(text, str):
                    errors.append(f"{sample_label} text must be a string")
                else:
                    encoded_text = json.dumps(
                        text,
                        ensure_ascii=True,
                        separators=(",", ":"),
                    )
                    if (
                        len(encoded_text)
                        > MAX_RECEIPT_EXCERPT_JSON_CHARS
                    ):
                        errors.append(
                            f"{sample_label} text exceeds its size bound"
                        )
                if not isinstance(sample.get("text_truncated"), bool):
                    errors.append(
                        f"{sample_label} text_truncated must be boolean"
                    )
                binary = False
            elif encoding == "binary-omitted":
                expected_keys = {*common_keys, "sample_sha256"}
                digest = sample.get("sample_sha256")
                if (
                    not isinstance(digest, str)
                    or len(digest) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in digest
                    )
                ):
                    errors.append(
                        f"{sample_label} has an invalid sample SHA-256"
                    )
                binary = True
            else:
                errors.append(f"{sample_label} has an invalid encoding")
                expected_keys = common_keys
                binary = False
            if set(sample) != expected_keys:
                errors.append(f"{sample_label} has an invalid schema")
            byte_start = sample.get("byte_start")
            byte_end = sample.get("byte_end")
            if (
                not valid_nonnegative_integer(byte_start)
                or not valid_nonnegative_integer(byte_end)
                or byte_start > byte_end
                or byte_end - byte_start > MAX_RECEIPT_SAMPLE_BYTES
                or (
                    valid_nonnegative_integer(stored_bytes)
                    and byte_end > stored_bytes
                )
            ):
                errors.append(f"{sample_label} has an invalid byte range")
                return None
            return byte_start, byte_end, binary

        head = validate_sample("head", evidence.get("head"))
        tail_value = evidence.get("tail")
        tail = (
            validate_sample("tail", tail_value)
            if tail_value is not None
            else None
        )
        if head is not None and head[0] != 0:
            errors.append(f"{label} head must start at byte zero")
        if (
            tail is not None
            and valid_nonnegative_integer(stored_bytes)
            and tail[1] != stored_bytes
        ):
            errors.append(f"{label} tail must end at the artifact size")
        if head is not None and tail is not None and head[1] > tail[0]:
            errors.append(f"{label} head and tail ranges overlap")

        omitted = evidence.get("omitted_stored_bytes")
        redaction_count = evidence.get("redaction_count")
        if not valid_nonnegative_integer(omitted):
            errors.append(f"{label} has an invalid omitted byte count")
        if not valid_nonnegative_integer(redaction_count):
            errors.append(f"{label} has an invalid redaction count")
        if (
            head is not None
            and valid_nonnegative_integer(stored_bytes)
            and valid_nonnegative_integer(omitted)
        ):
            sampled_bytes = head[1] - head[0]
            if tail is not None:
                sampled_bytes += tail[1] - tail[0]
            if omitted != stored_bytes - sampled_bytes:
                errors.append(f"{label} omitted byte count is inconsistent")
        binary_present = bool(
            (head is not None and head[2])
            or (tail is not None and tail[2])
        )
        if evidence.get("binary_sample_omitted") is not binary_present:
            errors.append(f"{label} binary omission marker is inconsistent")
    return errors


@dataclass
class SolveSession:
    id: str
    mode: SessionMode
    status: SessionStatus
    configuration_epoch: int
    start_revision: int
    end_revision: int | None = None
    budget_snapshot: dict[str, Any] = field(default_factory=dict)
    run_ids: list[str] = field(default_factory=list)
    wave_ids: list[str] = field(default_factory=list)
    evaluation_policy: str = "observe"
    stop_reason: str | None = None
    created_at: str = field(default_factory=utc_now)
    started_at: str | None = None
    ended_at: str | None = None
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return _with_extra(
            self.extra,
            id=self.id,
            mode=_enum_value(self.mode),
            status=_enum_value(self.status),
            configuration_epoch=self.configuration_epoch,
            start_revision=self.start_revision,
            end_revision=self.end_revision,
            budget_snapshot=dict(self.budget_snapshot),
            run_ids=list(self.run_ids),
            wave_ids=list(self.wave_ids),
            evaluation_policy=self.evaluation_policy,
            stop_reason=self.stop_reason,
            created_at=self.created_at,
            started_at=self.started_at,
            ended_at=self.ended_at,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SolveSession":
        known = {
            "id",
            "mode",
            "status",
            "configuration_epoch",
            "start_revision",
            "end_revision",
            "budget_snapshot",
            "run_ids",
            "wave_ids",
            "evaluation_policy",
            "stop_reason",
            "created_at",
            "started_at",
            "ended_at",
        }
        return cls(
            id=str(data.get("id", "")),
            mode=SessionMode(str(data.get("mode", SessionMode.MANUAL.value))),
            status=SessionStatus(
                str(data.get("status", SessionStatus.CREATED.value))
            ),
            configuration_epoch=int(data.get("configuration_epoch", 0)),
            start_revision=int(data.get("start_revision", 0)),
            end_revision=(
                int(data["end_revision"])
                if data.get("end_revision") is not None
                else None
            ),
            budget_snapshot=dict(data.get("budget_snapshot", {})),
            run_ids=[
                str(item)
                for item in _repeated_items(data.get("run_ids", []), "session run_ids")
            ],
            wave_ids=[
                str(item)
                for item in _repeated_items(data.get("wave_ids", []), "session wave_ids")
            ],
            evaluation_policy=str(data.get("evaluation_policy", "observe")),
            stop_reason=(
                str(data["stop_reason"])
                if data.get("stop_reason") is not None
                else None
            ),
            created_at=str(data.get("created_at", utc_now())),
            started_at=(
                str(data["started_at"])
                if data.get("started_at") is not None
                else None
            ),
            ended_at=(
                str(data["ended_at"])
                if data.get("ended_at") is not None
                else None
            ),
            extra=_extra(data, known),
        )


@dataclass
class ManagedCycle:
    id: str
    session_id: str
    ordinal: int
    phase: str
    configuration_epoch: int
    captain_run_id: str | None = None
    wave_id: str | None = None
    selected_action_ids: list[str] = field(default_factory=list)
    checkpoint_id: str | None = None
    created_at: str = field(default_factory=utc_now)
    completed_at: str | None = None
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return _with_extra(
            self.extra,
            id=self.id,
            session_id=self.session_id,
            ordinal=self.ordinal,
            phase=self.phase,
            configuration_epoch=self.configuration_epoch,
            captain_run_id=self.captain_run_id,
            wave_id=self.wave_id,
            selected_action_ids=list(self.selected_action_ids),
            checkpoint_id=self.checkpoint_id,
            created_at=self.created_at,
            completed_at=self.completed_at,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ManagedCycle":
        known = {
            "id",
            "session_id",
            "ordinal",
            "phase",
            "configuration_epoch",
            "captain_run_id",
            "wave_id",
            "selected_action_ids",
            "checkpoint_id",
            "created_at",
            "completed_at",
        }
        return cls(
            id=str(data.get("id", "")),
            session_id=str(data.get("session_id", "")),
            ordinal=int(data.get("ordinal", 0)),
            phase=str(data.get("phase", "created")),
            configuration_epoch=int(data.get("configuration_epoch", 0)),
            captain_run_id=(
                str(data["captain_run_id"])
                if data.get("captain_run_id") is not None
                else None
            ),
            wave_id=(
                str(data["wave_id"])
                if data.get("wave_id") is not None
                else None
            ),
            selected_action_ids=[
                str(item)
                for item in _repeated_items(
                    data.get("selected_action_ids", []),
                    "cycle selected_action_ids",
                )
            ],
            checkpoint_id=(
                str(data["checkpoint_id"])
                if data.get("checkpoint_id") is not None
                else None
            ),
            created_at=str(data.get("created_at", utc_now())),
            completed_at=(
                str(data["completed_at"])
                if data.get("completed_at") is not None
                else None
            ),
            extra=_extra(data, known),
        )


@dataclass
class ManagedWave:
    id: str
    session_id: str
    cycle_id: str
    kind: WaveKind
    role_run_ids: dict[str, str]
    snapshot_revision: int
    configuration_epoch: int
    status: str = "created"
    created_at: str = field(default_factory=utc_now)
    reduced_at: str | None = None
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return _with_extra(
            self.extra,
            id=self.id,
            session_id=self.session_id,
            cycle_id=self.cycle_id,
            kind=_enum_value(self.kind),
            role_run_ids=dict(self.role_run_ids),
            snapshot_revision=self.snapshot_revision,
            configuration_epoch=self.configuration_epoch,
            status=self.status,
            created_at=self.created_at,
            reduced_at=self.reduced_at,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ManagedWave":
        known = {
            "id",
            "session_id",
            "cycle_id",
            "kind",
            "role_run_ids",
            "snapshot_revision",
            "configuration_epoch",
            "status",
            "created_at",
            "reduced_at",
        }
        roles = data.get("role_run_ids", {})
        if not isinstance(roles, Mapping):
            raise ModelValidationError("wave role_run_ids must be an object")
        return cls(
            id=str(data.get("id", "")),
            session_id=str(data.get("session_id", "")),
            cycle_id=str(data.get("cycle_id", "")),
            kind=WaveKind(str(data.get("kind", WaveKind.DISCOVERY.value))),
            role_run_ids={str(key): str(value) for key, value in roles.items()},
            snapshot_revision=int(data.get("snapshot_revision", 0)),
            configuration_epoch=int(data.get("configuration_epoch", 0)),
            status=str(data.get("status", "created")),
            created_at=str(data.get("created_at", utc_now())),
            reduced_at=(
                str(data["reduced_at"])
                if data.get("reduced_at") is not None
                else None
            ),
            extra=_extra(data, known),
        )


_FAILURE_CAPSULE_OMITTED_COUNT_FIELDS = (
    "run_ids",
    "failed_experiment_ids",
    "fact_ids",
    "artifact_ids",
    "receipt_ids",
    "unresolved_hypothesis_ids",
    "next_experiment_ids",
)
_FAILURE_CAPSULE_FIELDS = frozenset(
    {
        "schema_version",
        "reason_code",
        "stage",
        "state_revision_before",
        "state_revision_after",
        "fingerprint_sha256",
        "content_sha256",
        "run_ids",
        "failed_experiment_ids",
        "fact_ids",
        "artifact_ids",
        "receipt_ids",
        "unresolved_hypothesis_ids",
        "next_experiment_ids",
        "omitted_counts",
    }
)


def _empty_failure_capsule_omitted_counts() -> dict[str, int]:
    return {
        field_name: 0
        for field_name in _FAILURE_CAPSULE_OMITTED_COUNT_FIELDS
    }


@dataclass
class FailureCapsule:
    reason_code: str
    stage: str
    state_revision_before: int
    state_revision_after: int
    fingerprint_sha256: str
    content_sha256: str
    run_ids: list[str]
    failed_experiment_ids: list[str]
    fact_ids: list[str]
    artifact_ids: list[str]
    receipt_ids: list[str]
    unresolved_hypothesis_ids: list[str]
    next_experiment_ids: list[str]
    omitted_counts: dict[str, int] = field(
        default_factory=_empty_failure_capsule_omitted_counts
    )
    schema_version: int = 1

    def content_payload(self) -> dict[str, Any]:
        """Canonical immutable capture protected by content_sha256."""

        return {
            "artifact_ids": list(self.artifact_ids),
            "failed_experiment_ids": list(self.failed_experiment_ids),
            "fact_ids": list(self.fact_ids),
            "fingerprint_sha256": self.fingerprint_sha256,
            "next_experiment_ids": list(self.next_experiment_ids),
            "omitted_counts": {
                key: self.omitted_counts[key]
                for key in _FAILURE_CAPSULE_OMITTED_COUNT_FIELDS
            },
            "reason_code": self.reason_code,
            "receipt_ids": list(self.receipt_ids),
            "run_ids": list(self.run_ids),
            "schema_version": self.schema_version,
            "stage": self.stage,
            "state_revision_after": self.state_revision_after,
            "state_revision_before": self.state_revision_before,
            "unresolved_hypothesis_ids": list(
                self.unresolved_hypothesis_ids
            ),
        }

    def computed_content_sha256(self) -> str:
        encoded = json.dumps(
            self.content_payload(),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("ascii")
        return hashlib.sha256(encoded).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "reason_code": self.reason_code,
            "stage": self.stage,
            "state_revision_before": self.state_revision_before,
            "state_revision_after": self.state_revision_after,
            "fingerprint_sha256": self.fingerprint_sha256,
            "content_sha256": self.content_sha256,
            "run_ids": list(self.run_ids),
            "failed_experiment_ids": list(self.failed_experiment_ids),
            "fact_ids": list(self.fact_ids),
            "artifact_ids": list(self.artifact_ids),
            "receipt_ids": list(self.receipt_ids),
            "unresolved_hypothesis_ids": list(
                self.unresolved_hypothesis_ids
            ),
            "next_experiment_ids": list(self.next_experiment_ids),
            "omitted_counts": dict(self.omitted_counts),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "FailureCapsule":
        if set(data) != _FAILURE_CAPSULE_FIELDS:
            raise ModelValidationError(
                "failure capsule has a non-canonical schema"
            )
        string_fields = (
            "reason_code",
            "stage",
            "fingerprint_sha256",
            "content_sha256",
        )
        revision_fields = (
            "schema_version",
            "state_revision_before",
            "state_revision_after",
        )
        repeated_fields = (
            "run_ids",
            "failed_experiment_ids",
            "fact_ids",
            "artifact_ids",
            "receipt_ids",
            "unresolved_hypothesis_ids",
            "next_experiment_ids",
        )
        omitted_counts = data.get("omitted_counts")
        if (
            any(type(data.get(name)) is not str for name in string_fields)
            or any(type(data.get(name)) is not int for name in revision_fields)
            or any(
                type(data.get(name)) is not list
                or any(
                    type(item) is not str
                    for item in data.get(name, ())
                )
                for name in repeated_fields
            )
            or type(omitted_counts) is not dict
            or set(omitted_counts)
            != set(_FAILURE_CAPSULE_OMITTED_COUNT_FIELDS)
            or any(
                type(value) is not int or value < 0
                for value in omitted_counts.values()
            )
        ):
            raise ModelValidationError(
                "failure capsule contains a non-canonical type"
            )
        return cls(
            reason_code=data["reason_code"],
            stage=data["stage"],
            state_revision_before=data["state_revision_before"],
            state_revision_after=data["state_revision_after"],
            fingerprint_sha256=data["fingerprint_sha256"],
            content_sha256=data["content_sha256"],
            run_ids=list(data["run_ids"]),
            failed_experiment_ids=list(data["failed_experiment_ids"]),
            fact_ids=list(data["fact_ids"]),
            artifact_ids=list(data["artifact_ids"]),
            receipt_ids=list(data["receipt_ids"]),
            unresolved_hypothesis_ids=list(
                data["unresolved_hypothesis_ids"]
            ),
            next_experiment_ids=list(data["next_experiment_ids"]),
            omitted_counts=dict(omitted_counts),
            schema_version=data["schema_version"],
        )


@dataclass
class Checkpoint:
    id: str
    session_id: str | None
    cycle_id: str | None
    active_goal_id: str | None
    open_hypothesis_ids: list[str] = field(default_factory=list)
    observation_fact_ids: list[str] = field(default_factory=list)
    next_actions: list[str] = field(default_factory=list)
    do_not_repeat: list[str] = field(default_factory=list)
    artifact_ids: list[str] = field(default_factory=list)
    receipt_ids: list[str] = field(default_factory=list)
    note: str | None = None
    created_at: str = field(default_factory=utc_now)
    extra: dict[str, Any] = field(default_factory=dict, repr=False)
    failure_capsule: FailureCapsule | None = None

    def to_dict(self) -> dict[str, Any]:
        canonical = {
            "id": self.id,
            "session_id": self.session_id,
            "cycle_id": self.cycle_id,
            "active_goal_id": self.active_goal_id,
            "open_hypothesis_ids": list(self.open_hypothesis_ids),
            "observation_fact_ids": list(self.observation_fact_ids),
            "next_actions": list(self.next_actions),
            "do_not_repeat": list(self.do_not_repeat),
            "artifact_ids": list(self.artifact_ids),
            "receipt_ids": list(self.receipt_ids),
            "note": self.note,
            "created_at": self.created_at,
        }
        extra = dict(self.extra)
        if self.failure_capsule is not None:
            canonical["failure_capsule"] = self.failure_capsule.to_dict()
            extra.pop("failure_capsule", None)
        return _with_extra(extra, **canonical)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Checkpoint":
        raw_failure_capsule = data.get("failure_capsule")
        typed_failure_capsule = (
            isinstance(raw_failure_capsule, Mapping)
            and bool(
                set(raw_failure_capsule).intersection(
                    _FAILURE_CAPSULE_FIELDS
                )
            )
        )
        if (
            raw_failure_capsule is not None
            and not isinstance(raw_failure_capsule, Mapping)
        ):
            raise ModelValidationError(
                "checkpoint failure_capsule must be a canonical object or null"
            )
        known = {
            "id",
            "session_id",
            "cycle_id",
            "active_goal_id",
            "open_hypothesis_ids",
            "observation_fact_ids",
            "next_actions",
            "do_not_repeat",
            "artifact_ids",
            "receipt_ids",
            "note",
            "created_at",
            "failure_capsule",
        }

        def strings(name: str) -> list[str]:
            return [
                str(item)
                for item in _repeated_items(data.get(name, []), f"checkpoint {name}")
            ]

        return cls(
            id=str(data.get("id", "")),
            session_id=(
                str(data["session_id"])
                if data.get("session_id") is not None
                else None
            ),
            cycle_id=(
                str(data["cycle_id"])
                if data.get("cycle_id") is not None
                else None
            ),
            active_goal_id=(
                str(data["active_goal_id"])
                if data.get("active_goal_id") is not None
                else None
            ),
            open_hypothesis_ids=strings("open_hypothesis_ids"),
            observation_fact_ids=strings("observation_fact_ids"),
            next_actions=strings("next_actions"),
            do_not_repeat=strings("do_not_repeat"),
            artifact_ids=strings("artifact_ids"),
            receipt_ids=strings("receipt_ids"),
            note=str(data["note"]) if data.get("note") is not None else None,
            created_at=str(data.get("created_at", utc_now())),
            extra=_extra(
                data,
                (
                    known
                    if typed_failure_capsule
                    or raw_failure_capsule is None
                    else known - {"failure_capsule"}
                ),
            ),
            failure_capsule=(
                FailureCapsule.from_dict(raw_failure_capsule)
                if typed_failure_capsule
                else None
            ),
        )


@dataclass
class TargetRecord:
    id: str
    endpoint: str
    status: TargetStatus
    enforcement: str
    docker_network: str
    purpose: str
    generation: int
    provenance: str
    created_at: str = field(default_factory=utc_now)
    expires_at: str | None = None
    revoked_at: str | None = None
    revoke_reason: str | None = None
    last_preflight: dict[str, Any] | None = None
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return _with_extra(
            self.extra,
            id=self.id,
            endpoint=self.endpoint,
            status=_enum_value(self.status),
            enforcement=self.enforcement,
            docker_network=self.docker_network,
            purpose=self.purpose,
            generation=self.generation,
            provenance=self.provenance,
            created_at=self.created_at,
            expires_at=self.expires_at,
            revoked_at=self.revoked_at,
            revoke_reason=self.revoke_reason,
            last_preflight=(
                dict(self.last_preflight)
                if self.last_preflight is not None
                else None
            ),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TargetRecord":
        known = {
            "id",
            "endpoint",
            "status",
            "enforcement",
            "docker_network",
            "purpose",
            "generation",
            "provenance",
            "created_at",
            "expires_at",
            "revoked_at",
            "revoke_reason",
            "last_preflight",
        }
        preflight = data.get("last_preflight")
        return cls(
            id=str(data.get("id", "")),
            endpoint=str(data.get("endpoint", "")),
            status=TargetStatus(
                str(data.get("status", TargetStatus.ACTIVE.value))
            ),
            enforcement=str(data.get("enforcement", "declared")),
            docker_network=str(data.get("docker_network", "bridge")),
            purpose=str(data.get("purpose", "")),
            generation=int(data.get("generation", 1)),
            provenance=str(data.get("provenance", "operator")),
            created_at=str(data.get("created_at", utc_now())),
            expires_at=(
                str(data["expires_at"])
                if data.get("expires_at") is not None
                else None
            ),
            revoked_at=(
                str(data["revoked_at"])
                if data.get("revoked_at") is not None
                else None
            ),
            revoke_reason=(
                str(data["revoke_reason"])
                if data.get("revoke_reason") is not None
                else None
            ),
            last_preflight=dict(preflight) if isinstance(preflight, Mapping) else None,
            extra=_extra(data, known),
        )


@dataclass
class ClosureBundle:
    id: str
    completeness: ClosureCompleteness
    portability: str
    source_artifact_ids: list[str] = field(default_factory=list)
    image_reference: str | None = None
    solver_artifact_ids: list[str] = field(default_factory=list)
    report_artifact_ids: list[str] = field(default_factory=list)
    proof_run_ids: list[str] = field(default_factory=list)
    submission_ids: list[str] = field(default_factory=list)
    target_ids: list[str] = field(default_factory=list)
    checkpoint_ids: list[str] = field(default_factory=list)
    side_effect_receipt_ids: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now)
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return _with_extra(
            self.extra,
            id=self.id,
            completeness=_enum_value(self.completeness),
            portability=self.portability,
            source_artifact_ids=list(self.source_artifact_ids),
            image_reference=self.image_reference,
            solver_artifact_ids=list(self.solver_artifact_ids),
            report_artifact_ids=list(self.report_artifact_ids),
            proof_run_ids=list(self.proof_run_ids),
            submission_ids=list(self.submission_ids),
            target_ids=list(self.target_ids),
            checkpoint_ids=list(self.checkpoint_ids),
            side_effect_receipt_ids=list(self.side_effect_receipt_ids),
            created_at=self.created_at,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ClosureBundle":
        known = {
            "id",
            "completeness",
            "portability",
            "source_artifact_ids",
            "image_reference",
            "solver_artifact_ids",
            "report_artifact_ids",
            "proof_run_ids",
            "submission_ids",
            "target_ids",
            "checkpoint_ids",
            "side_effect_receipt_ids",
            "created_at",
        }

        def strings(name: str) -> list[str]:
            return [
                str(item)
                for item in _repeated_items(data.get(name, []), f"closure {name}")
            ]

        return cls(
            id=str(data.get("id", "")),
            completeness=ClosureCompleteness(
                str(
                    data.get(
                        "completeness",
                        ClosureCompleteness.INCOMPLETE.value,
                    )
                )
            ),
            portability=str(data.get("portability", "referential")),
            source_artifact_ids=strings("source_artifact_ids"),
            image_reference=(
                str(data["image_reference"])
                if data.get("image_reference") is not None
                else None
            ),
            solver_artifact_ids=strings("solver_artifact_ids"),
            report_artifact_ids=strings("report_artifact_ids"),
            proof_run_ids=strings("proof_run_ids"),
            submission_ids=strings("submission_ids"),
            target_ids=strings("target_ids"),
            checkpoint_ids=strings("checkpoint_ids"),
            side_effect_receipt_ids=strings("side_effect_receipt_ids"),
            created_at=str(data.get("created_at", utc_now())),
            extra=_extra(data, known),
        )


@dataclass
class WorkspacePublish:
    id: str
    run_id: str
    staged_path: str
    destination: str
    sha256: str
    base_sha256: str | None
    base_workspace_revision: int
    published_workspace_revision: int | None = None
    status: str = "proposed"
    created_at: str = field(default_factory=utc_now)
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return _with_extra(
            self.extra,
            id=self.id,
            run_id=self.run_id,
            staged_path=self.staged_path,
            destination=self.destination,
            sha256=self.sha256,
            base_sha256=self.base_sha256,
            base_workspace_revision=self.base_workspace_revision,
            published_workspace_revision=self.published_workspace_revision,
            status=self.status,
            created_at=self.created_at,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "WorkspacePublish":
        known = {
            "id",
            "run_id",
            "staged_path",
            "destination",
            "sha256",
            "base_sha256",
            "base_workspace_revision",
            "published_workspace_revision",
            "status",
            "created_at",
        }
        return cls(
            id=str(data.get("id", "")),
            run_id=str(data.get("run_id", "")),
            staged_path=str(data.get("staged_path", "")),
            destination=str(data.get("destination", "")),
            sha256=str(data.get("sha256", "")),
            base_sha256=(
                str(data["base_sha256"])
                if data.get("base_sha256") is not None
                else None
            ),
            base_workspace_revision=int(data.get("base_workspace_revision", 0)),
            published_workspace_revision=(
                int(data["published_workspace_revision"])
                if data.get("published_workspace_revision") is not None
                else None
            ),
            status=str(data.get("status", "proposed")),
            created_at=str(data.get("created_at", utc_now())),
            extra=_extra(data, known),
        )


_REV_INVENTORY_ORACLE_ID = REV_INVENTORY_V2_CONTRACT_ID
_REV_INVENTORY_V2_CONTRACT_FINGERPRINT = (
    REV_INVENTORY_V2_CONTRACT_FINGERPRINT
)
_REV_INVENTORY_V2_OUTCOME_KEYS = {
    "evaluated_at",
    "evaluation_status",
    "execution_binding",
    "image_reference",
    "rejection_code",
    "request_sha256",
    "result",
    "schema_version",
    "source_binding",
    "stdout_artifact_id",
    "transport_succeeded",
}
_REV_INVENTORY_V2_EXECUTION_BINDING_KEYS = {
    "argv",
    "base_revision",
    "configuration_epoch",
    "experiment",
    "image",
    "network",
    "oracle",
    "request",
    "resource_request",
    "schema_version",
    "source_binding",
    "source_snapshot",
    "source_snapshot_execution_binding",
    "stdout_artifact",
}


def _rev_inventory_exact_mapping(
    value: object,
    keys: set[str],
    label: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ModelValidationError(
            f"{label} has missing or unknown fields"
        )
    return value


def _rev_inventory_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _rev_inventory_image_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and _rev_inventory_sha256(value.removeprefix("sha256:"))
    )


def _validate_rev_inventory_v2_outcome_shape(
    value: object,
    *,
    label: str,
) -> Mapping[str, Any]:
    outcome = _rev_inventory_exact_mapping(
        value,
        _REV_INVENTORY_V2_OUTCOME_KEYS,
        label,
    )
    if outcome["schema_version"] != 2:
        raise ModelValidationError(f"{label} has invalid schema_version")
    if type(outcome["transport_succeeded"]) is not bool:
        raise ModelValidationError(
            f"{label} transport_succeeded must be boolean"
        )
    evaluation_status = outcome["evaluation_status"]
    if (
        not isinstance(evaluation_status, str)
        or evaluation_status
        not in {
            "evaluated",
            "not_evaluated",
            "rejected",
        }
    ):
        raise ModelValidationError(
            f"{label} has invalid evaluation_status"
        )
    if (
        outcome["rejection_code"] is not None
        and (
            not isinstance(outcome["rejection_code"], str)
            or not outcome["rejection_code"]
            or len(outcome["rejection_code"]) > 128
        )
    ):
        raise ModelValidationError(
            f"{label} has invalid rejection_code"
        )
    if (
        outcome["request_sha256"] is not None
        and not _rev_inventory_sha256(outcome["request_sha256"])
    ):
        raise ModelValidationError(
            f"{label} has invalid request_sha256"
        )
    for key in (
        "image_reference",
        "stdout_artifact_id",
        "evaluated_at",
    ):
        if outcome[key] is not None and not isinstance(
            outcome[key],
            str,
        ):
            raise ModelValidationError(f"{label} has invalid {key}")

    result_value = outcome["result"]
    if result_value is None:
        result = None
    else:
        try:
            result = validate_rev_inventory_v2_result_mapping(
                result_value
            )
        except RevInventoryV2ContractError as error:
            raise ModelValidationError(
                f"{label} has invalid semantic result: {error}"
            ) from error

    binding = _rev_inventory_exact_mapping(
        outcome["execution_binding"],
        _REV_INVENTORY_V2_EXECUTION_BINDING_KEYS,
        f"{label} execution_binding",
    )
    if (
        binding["schema_version"] != 2
        or not isinstance(binding["argv"], list)
        or not all(isinstance(item, str) for item in binding["argv"])
        or isinstance(binding["base_revision"], bool)
        or not isinstance(binding["base_revision"], int)
        or binding["base_revision"] < 0
        or isinstance(binding["configuration_epoch"], bool)
        or not isinstance(binding["configuration_epoch"], int)
        or binding["configuration_epoch"] < 0
    ):
        raise ModelValidationError(
            f"{label} has invalid execution binding scalars"
        )
    experiment_binding = _rev_inventory_exact_mapping(
        binding["experiment"],
        {
            "adapter_name",
            "adapter_seed",
            "adapter_seed_contract_version",
            "adapter_seed_order",
            "adapter_spec_id",
            "adapter_spec_sha256",
            "adapter_spec_template_id",
            "id",
            "requires_explicit_execution",
            "resource_class",
        },
        f"{label} experiment binding",
    )
    image_binding = _rev_inventory_exact_mapping(
        binding["image"],
        {"digest", "name", "reference"},
        f"{label} image binding",
    )
    network_binding = _rev_inventory_exact_mapping(
        binding["network"],
        {"target", "target_generation", "target_id"},
        f"{label} network binding",
    )
    request_binding = _rev_inventory_exact_mapping(
        binding["request"],
        {"path", "sha256"},
        f"{label} request binding",
    )
    stdout_binding = _rev_inventory_exact_mapping(
        binding["stdout_artifact"],
        {"id", "path", "sha256", "size"},
        f"{label} stdout binding",
    )
    if (
        experiment_binding["adapter_name"] != "reversing"
        or experiment_binding["adapter_seed"] is not True
        or experiment_binding["adapter_seed_contract_version"]
        != REV_INVENTORY_V2_ADAPTER_SEED_CONTRACT_VERSION
        or isinstance(experiment_binding["adapter_seed_order"], bool)
        or not isinstance(
            experiment_binding["adapter_seed_order"],
            int,
        )
        or experiment_binding["adapter_seed_order"] < 0
        or experiment_binding["adapter_spec_template_id"]
        != REV_INVENTORY_V2_SEED_TEMPLATE_ID
        or not isinstance(experiment_binding["adapter_spec_id"], str)
        or not _rev_inventory_sha256(
            experiment_binding["adapter_spec_sha256"]
        )
        or not experiment_binding["adapter_spec_id"].endswith(
            f"@{experiment_binding['adapter_spec_sha256']}"
        )
        or experiment_binding["requires_explicit_execution"]
        is not REV_INVENTORY_V2_SEED_REQUIRES_EXPLICIT_EXECUTION
        or not isinstance(experiment_binding["id"], str)
        or experiment_binding["resource_class"]
        != REV_INVENTORY_V2_SEED_RESOURCE_CLASS
        or not isinstance(image_binding["name"], str)
        or not isinstance(image_binding["reference"], str)
        or any(value is not None for value in network_binding.values())
        or not isinstance(request_binding["path"], str)
        or request_binding["sha256"] != outcome["request_sha256"]
        or (
            request_binding["sha256"] is not None
            and not _rev_inventory_sha256(request_binding["sha256"])
        )
        or not isinstance(binding["resource_request"], Mapping)
        or not isinstance(stdout_binding["id"], str)
        or not isinstance(stdout_binding["path"], str)
        or not _rev_inventory_sha256(stdout_binding["sha256"])
        or isinstance(stdout_binding["size"], bool)
        or not isinstance(stdout_binding["size"], int)
        or stdout_binding["size"] < 0
        or outcome["stdout_artifact_id"] != stdout_binding["id"]
        or outcome["source_binding"] != binding["source_binding"]
    ):
        raise ModelValidationError(
            f"{label} has invalid exact execution pins"
        )
    resource_request = binding["resource_request"]
    if (
        set(resource_request)
        != {"cpu", "gpu", "kvm", "memory_mib", "network"}
        or any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            for value in resource_request.values()
        )
        or resource_request["network"] != 0
        or dict(resource_request)
        != {
            "cpu": 1,
            "gpu": 0,
            "kvm": 0,
            "memory_mib": 2048,
            "network": 0,
        }
    ):
        raise ModelValidationError(
            f"{label} has invalid resource request binding"
        )
    snapshot_execution = _rev_inventory_exact_mapping(
        binding["source_snapshot_execution_binding"],
        {"enforced", "mode", "scope_fingerprint", "snapshot_id"},
        f"{label} source snapshot execution binding",
    )
    if (
        type(snapshot_execution["enforced"]) is not bool
        or not isinstance(snapshot_execution["mode"], str)
        or snapshot_execution["mode"]
        not in {
                "production_read_only_snapshot_scope",
                "trusted_injected_sandbox",
            }
        or not _rev_inventory_sha256(
            snapshot_execution["scope_fingerprint"]
        )
        or not isinstance(snapshot_execution["snapshot_id"], str)
        or snapshot_execution["enforced"]
        is not (
            snapshot_execution["mode"]
            == "production_read_only_snapshot_scope"
        )
    ):
        raise ModelValidationError(
            f"{label} has invalid source snapshot execution binding"
        )
    oracle = binding["oracle"]
    if (
        not isinstance(oracle, Mapping)
        or set(oracle)
        != {
            "contract_fingerprint",
            "document_transport",
            "oracle_id",
            "oracle_version",
        }
        or oracle.get("oracle_id") != _REV_INVENTORY_ORACLE_ID
        or oracle.get("oracle_version")
        != REV_INVENTORY_V2_CONTRACT_VERSION
        or oracle.get("document_transport")
        != REV_INVENTORY_V2_DOCUMENT_TRANSPORT
        or oracle.get("contract_fingerprint")
        != _REV_INVENTORY_V2_CONTRACT_FINGERPRINT
    ):
        raise ModelValidationError(
            f"{label} has invalid oracle binding"
        )
    if result is not None and (
        result["oracle_id"] != oracle["oracle_id"]
        or result["oracle_version"] != oracle["oracle_version"]
        or result["contract_fingerprint"]
        != oracle["contract_fingerprint"]
    ):
        raise ModelValidationError(
            f"{label} semantic result/oracle binding mismatch"
        )
    source_binding = _rev_inventory_exact_mapping(
        binding["source_binding"],
        {
            "manifest_generation",
            "manifest_sha256",
            "path",
            "sha256",
            "size_bytes",
        },
        f"{label} source binding",
    )
    try:
        expected_source_binding = build_rev_inventory_v2_source_binding(
            manifest_generation=source_binding["manifest_generation"],
            manifest_sha256=source_binding["manifest_sha256"],
            path=source_binding["path"],
            source_sha256=source_binding["sha256"],
            source_size_bytes=source_binding["size_bytes"],
        )
    except RevInventoryV2ContractError as error:
        raise ModelValidationError(
            f"{label} has invalid source binding"
        ) from error
    if dict(source_binding) != expected_source_binding:
        raise ModelValidationError(
            f"{label} has invalid source binding"
        )
    source_snapshot = _rev_inventory_exact_mapping(
        binding["source_snapshot"],
        {
            "binding_sha256",
            "challenge_dir",
            "directory_mode",
            "file_mode",
            "id",
            "mount_requirement",
            "publish",
            "sha256",
            "size_bytes",
            "source_locator",
            "tree_contract",
        },
        f"{label} source snapshot",
    )
    try:
        expected_source_snapshot = (
            build_rev_inventory_v2_source_snapshot(
                expected_source_binding
            )
        )
    except RevInventoryV2ContractError as error:
        raise ModelValidationError(
            f"{label} has invalid source snapshot binding"
        ) from error
    if (
        dict(source_snapshot) != expected_source_snapshot
        or snapshot_execution["snapshot_id"]
        != expected_source_snapshot["id"]
    ):
        raise ModelValidationError(
            f"{label} has invalid source snapshot binding"
        )
    source_mismatch_error = result is not None and (
        result["verdict"] == "ERROR"
        and result["reason_code"]
        in {"source_hash_mismatch", "source_size_mismatch"}
    )
    if result is not None and not source_mismatch_error and (
        (
            result["source_sha256"] is not None
            and result["source_sha256"] != source_binding.get("sha256")
        )
        or (
            result["source_size_bytes"] is not None
            and result["source_size_bytes"]
            != source_binding.get("size_bytes")
        )
        or (
            result["verdict"]
            in {"CONFIRMED", "INCONCLUSIVE", "NOT_APPLICABLE"}
            and (
                result["source_sha256"] != source_binding.get("sha256")
                or result["source_size_bytes"]
                != source_binding.get("size_bytes")
            )
        )
    ):
        raise ModelValidationError(
            f"{label} semantic result/source binding mismatch"
        )
    if (
        evaluation_status == "evaluated"
        and (
            outcome["transport_succeeded"] is not True
            or outcome["rejection_code"] is not None
            or result is None
        )
    ) or (
        evaluation_status == "rejected"
        and (
            outcome["transport_succeeded"] is not True
            or not isinstance(outcome["rejection_code"], str)
            or result is not None
        )
    ) or (
        evaluation_status == "not_evaluated"
        and (
            outcome["transport_succeeded"] is not False
            or outcome["rejection_code"] != "transport_failed"
            or result is not None
        )
    ):
        raise ModelValidationError(
            f"{label} transport/semantic axes are inconsistent"
        )
    if evaluation_status == "evaluated" and (
        not _rev_inventory_image_digest(image_binding["digest"])
        or image_binding["reference"] != image_binding["digest"]
        or outcome["image_reference"] != image_binding["digest"]
    ):
        raise ModelValidationError(
            f"{label} evaluated result lacks an exact image digest"
        )
    if (
        not isinstance(outcome["evaluated_at"], str)
        or not outcome["evaluated_at"]
    ):
        raise ModelValidationError(
            f"{label} lacks an evaluation timestamp"
        )
    return outcome


def _rev_inventory_v2_active_seed_errors(
    state: "ChallengeState",
    experiment: Experiment,
    *,
    descriptor: Mapping[str, Any],
) -> list[str]:
    """Validate the exact deterministic inventory seed before it can run."""

    label = f"Rev inventory experiment {experiment.id}"
    errors: list[str] = []
    if dict(descriptor) != rev_inventory_v2_oracle_descriptor():
        return [f"{label} has an invalid v2 oracle descriptor"]
    manifest = state.metadata.get("source_manifest_sha256")
    history = state.metadata.get("source_manifest_history", [])
    primary_path = state.metadata.get("adapter_primary_source")
    matching_sources = [
        source
        for source in state.source_inventory
        if source.path == primary_path
    ]
    if (
        not _rev_inventory_sha256(manifest)
        or not isinstance(history, list)
        or not isinstance(primary_path, str)
        or not primary_path
        or len(matching_sources) != 1
    ):
        return [f"{label} lacks its canonical active source metadata"]
    primary = matching_sources[0]
    if (
        not _rev_inventory_sha256(primary.sha256)
        or isinstance(primary.size, bool)
        or not isinstance(primary.size, int)
        or primary.size < 0
    ):
        return [f"{label} has an invalid active primary source"]

    try:
        source_binding = build_rev_inventory_v2_source_binding(
            manifest_generation=len(history) + 1,
            manifest_sha256=manifest,
            path=primary.path,
            source_sha256=primary.sha256,
            source_size_bytes=primary.size,
        )
        source_snapshot = build_rev_inventory_v2_source_snapshot(
            source_binding
        )
        expected_extra = build_rev_inventory_v2_seed_extra(
            source_binding,
            source_snapshot,
        )
        expected_command = rev_inventory_v2_seed_command(primary.path)
    except RevInventoryV2ContractError:
        return [f"{label} has an invalid active seed contract"]
    allowed_extra = {
        *expected_extra,
        "orphan_recovered_at",
        "orphan_recovery",
    }
    if (
        state.metadata.get("adapter_name") != "reversing"
        or state.metadata.get("adapter_seed_source_binding")
        != source_binding
        or experiment.kind is not ExperimentKind.PROBE
        or experiment.hypothesis_ids
        or experiment.command != expected_command
        or experiment.expected_observation
        != REV_INVENTORY_V2_SEED_EXPECTED_OBSERVATION
        or experiment.keep_if != REV_INVENTORY_V2_SEED_KEEP_CONDITION
        or experiment.drop_if != REV_INVENTORY_V2_SEED_DROP_CONDITION
        or experiment.resource_class
        != REV_INVENTORY_V2_SEED_RESOURCE_CLASS
        or experiment.timeout_seconds < 1
        or experiment.timeout_seconds
        > REV_INVENTORY_V2_SEED_TIMEOUT_SECONDS
        or experiment.source_run_id is not None
        or experiment.artifact_ids
        or experiment.evidence_fact_ids
        or experiment.evidence_run_ids
        or experiment.evidence_receipt_ids
        or experiment.evaluation_reason is not None
        or experiment.evaluated_at is not None
        or experiment.proof_recipe is not None
        or set(experiment.extra) - allowed_extra
        or any(
            experiment.extra.get(key) != value
            for key, value in expected_extra.items()
        )
    ):
        errors.append(f"{label} active seed contract is inconsistent")
    if (
        "orphan_recovery" in experiment.extra
        and experiment.extra.get("orphan_recovery")
        != "retryable_without_canonical_outcome"
    ):
        errors.append(f"{label} has invalid orphan recovery metadata")
    if (
        "orphan_recovered_at" in experiment.extra
        and (
            not isinstance(
                experiment.extra.get("orphan_recovered_at"),
                str,
            )
            or not experiment.extra.get("orphan_recovered_at")
            or len(experiment.extra["orphan_recovered_at"]) > 128
        )
    ):
        errors.append(f"{label} has invalid orphan recovery timestamp")
    if (
        ("orphan_recovery" in experiment.extra)
        != ("orphan_recovered_at" in experiment.extra)
    ):
        errors.append(f"{label} has incomplete orphan recovery metadata")
    return errors


def _rev_inventory_seed_id(adapter_spec_id: str) -> str:
    normalized = adapter_spec_id.replace("@", "-")
    return f"E-adapter-reversing-{normalized}"


def _rev_inventory_seed_identity(
    experiment: Experiment,
    *,
    version: int,
) -> bool:
    """Recognize a deterministic seed even if its mutable markers drift."""

    source_binding = experiment.extra.get("source_binding")
    source_snapshot = experiment.extra.get("source_snapshot")
    if not isinstance(source_binding, Mapping) or not isinstance(
        source_snapshot,
        Mapping,
    ):
        return False
    try:
        if version == REV_INVENTORY_V1_CONTRACT_VERSION:
            expected_binding = build_rev_inventory_v1_source_binding(
                manifest_generation=source_binding.get(
                    "manifest_generation"
                ),
                manifest_sha256=source_binding.get("manifest_sha256"),
                path=source_binding.get("path"),
                source_sha256=source_binding.get("sha256"),
                source_size_bytes=source_binding.get("size_bytes"),
            )
            expected_snapshot = build_rev_inventory_v1_source_snapshot(
                expected_binding
            )
            expected_extra = build_rev_inventory_v1_seed_extra(
                expected_binding,
                expected_snapshot,
            )
        elif version == REV_INVENTORY_V2_CONTRACT_VERSION:
            expected_binding = build_rev_inventory_v2_source_binding(
                manifest_generation=source_binding.get(
                    "manifest_generation"
                ),
                manifest_sha256=source_binding.get("manifest_sha256"),
                path=source_binding.get("path"),
                source_sha256=source_binding.get("sha256"),
                source_size_bytes=source_binding.get("size_bytes"),
            )
            expected_snapshot = build_rev_inventory_v2_source_snapshot(
                expected_binding
            )
            expected_extra = build_rev_inventory_v2_seed_extra(
                expected_binding,
                expected_snapshot,
            )
        else:
            return False
    except (
        RevInventoryV1ContractError,
        RevInventoryV2ContractError,
    ):
        return False
    return (
        dict(source_binding) == expected_binding
        and dict(source_snapshot) == expected_snapshot
        and experiment.id
        == _rev_inventory_seed_id(
            str(expected_extra["adapter_spec_id"])
        )
    )


def _rev_inventory_legacy_v1_seed_errors(
    experiment: Experiment,
    *,
    descriptor: Mapping[str, Any],
) -> list[str]:
    """Validate only the immutable internal identity of historical v1."""

    label = f"legacy Rev inventory experiment {experiment.id}"
    if dict(descriptor) != rev_inventory_v1_oracle_descriptor():
        return [f"{label} has an invalid v1 oracle descriptor"]
    source_binding = experiment.extra.get("source_binding")
    source_snapshot = experiment.extra.get("source_snapshot")
    if not isinstance(source_binding, Mapping) or not isinstance(
        source_snapshot,
        Mapping,
    ):
        return [f"{label} lacks its historical source binding"]
    try:
        expected_binding = build_rev_inventory_v1_source_binding(
            manifest_generation=source_binding.get(
                "manifest_generation"
            ),
            manifest_sha256=source_binding.get("manifest_sha256"),
            path=source_binding.get("path"),
            source_sha256=source_binding.get("sha256"),
            source_size_bytes=source_binding.get("size_bytes"),
        )
        expected_snapshot = build_rev_inventory_v1_source_snapshot(
            expected_binding
        )
        expected_extra = build_rev_inventory_v1_seed_extra(
            expected_binding,
            expected_snapshot,
        )
        expected_command = rev_inventory_v1_seed_command(
            str(expected_binding["path"])
        )
    except RevInventoryV1ContractError:
        return [f"{label} has an invalid historical seed contract"]
    allowed_extra = {
        *expected_extra,
        "cancelled_at",
        "cancelled_reason",
        "orphan_recovered_at",
        "orphan_recovery",
    }
    errors: list[str] = []
    if (
        dict(source_binding) != expected_binding
        or dict(source_snapshot) != expected_snapshot
        or experiment.id
        != _rev_inventory_seed_id(
            str(expected_extra["adapter_spec_id"])
        )
        or experiment.kind is not ExperimentKind.PROBE
        or experiment.hypothesis_ids
        or experiment.command != expected_command
        or set(experiment.extra) - allowed_extra
        or any(
            experiment.extra.get(key) != value
            for key, value in expected_extra.items()
        )
    ):
        errors.append(f"{label} internal identity is inconsistent")
    return errors


def _rev_inventory_contract_marker(
    value: object,
) -> tuple[str, int, str] | None:
    if not isinstance(value, Mapping):
        return None
    oracle_id = value.get("oracle_id")
    oracle_version = value.get("oracle_version")
    fingerprint = value.get("contract_fingerprint")
    if (
        type(oracle_id) is str
        and type(oracle_version) is int
        and type(fingerprint) is str
    ):
        return oracle_id, oracle_version, fingerprint
    result = value.get("result")
    if isinstance(result, Mapping):
        oracle_id = result.get("oracle_id")
        oracle_version = result.get("oracle_version")
        fingerprint = result.get("contract_fingerprint")
        if (
            type(oracle_id) is str
            and type(oracle_version) is int
            and type(fingerprint) is str
        ):
            return oracle_id, oracle_version, fingerprint
    return None


def _has_rev_inventory_v2_outcome_marker(value: object) -> bool:
    marker = _rev_inventory_contract_marker(value)
    if marker is None:
        return False
    contract = resolve_rev_inventory_contract(*marker)
    return contract is not None and (
        contract.oracle_version == REV_INVENTORY_V2_CONTRACT_VERSION
    )


def _has_rev_inventory_outcome_marker(value: object) -> bool:
    """Compatibility name used by structural linearity tests."""

    return _has_rev_inventory_v2_outcome_marker(value)


def _has_rev_inventory_v1_outcome_marker(value: object) -> bool:
    marker = _rev_inventory_contract_marker(value)
    if marker is None:
        return False
    contract = resolve_rev_inventory_contract(*marker)
    return contract is not None and (
        contract.oracle_version == REV_INVENTORY_V1_CONTRACT_VERSION
    )


def _has_rev_inventory_oracle_id_marker(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    if value.get("oracle_id") == _REV_INVENTORY_ORACLE_ID:
        return True
    result = value.get("result")
    return (
        isinstance(result, Mapping)
        and result.get("oracle_id") == _REV_INVENTORY_ORACLE_ID
    )


@dataclass(frozen=True, slots=True)
class _RevInventoryLinkIndex:
    linked_run_ids_by_experiment: Mapping[str, frozenset[str]]
    marked_run_or_receipt_experiment_ids: frozenset[str]
    marked_fact_ids: frozenset[str]
    marked_fact_source_run_ids: frozenset[str]
    oracle_copy_fact_source_run_ids: frozenset[str]
    oracle_copy_experiment_ids: frozenset[str]


def _rev_inventory_link_index(
    state: "ChallengeState",
) -> _RevInventoryLinkIndex:
    """Index Rev outcome markers and links in one pass per collection."""

    linked_run_ids: dict[str, set[str]] = {}
    marked_run_or_receipt_experiment_ids: set[str] = set()
    oracle_copy_experiment_ids: set[str] = set()

    for run in state.runs:
        outcome = run.extra.get("partial_oracle_result")
        binding = (
            outcome.get("execution_binding")
            if isinstance(outcome, Mapping)
            else None
        )
        experiment_binding = (
            binding.get("experiment")
            if isinstance(binding, Mapping)
            else None
        )
        linked_experiment_ids = {
            value
            for value in (
                run.extra.get("experiment_id"),
                (
                    experiment_binding.get("id")
                    if isinstance(experiment_binding, Mapping)
                    else None
                ),
            )
            if isinstance(value, str)
        }
        for experiment_id in linked_experiment_ids:
            linked_run_ids.setdefault(experiment_id, set()).add(run.id)
            if _has_rev_inventory_outcome_marker(outcome):
                marked_run_or_receipt_experiment_ids.add(
                    experiment_id
                )
        direct_experiment_id = run.extra.get("experiment_id")
        if (
            isinstance(direct_experiment_id, str)
            and outcome is not None
        ):
            oracle_copy_experiment_ids.add(direct_experiment_id)

    for receipt in state.receipts:
        experiment_id = receipt.experiment_id
        linked_run_ids.setdefault(experiment_id, set()).add(
            receipt.run_id
        )
        outcome = receipt.extra.get("partial_oracle_result")
        if _has_rev_inventory_outcome_marker(outcome):
            marked_run_or_receipt_experiment_ids.add(experiment_id)
        if outcome is not None:
            oracle_copy_experiment_ids.add(experiment_id)

    marked_fact_ids: set[str] = set()
    marked_fact_source_run_ids: set[str] = set()
    oracle_copy_fact_source_run_ids: set[str] = set()
    for fact in state.facts:
        outcome = fact.extra.get("partial_oracle_result")
        if outcome is not None and isinstance(fact.source_run_id, str):
            oracle_copy_fact_source_run_ids.add(fact.source_run_id)
        if not _has_rev_inventory_outcome_marker(outcome):
            continue
        marked_fact_ids.add(fact.id)
        if isinstance(fact.source_run_id, str):
            marked_fact_source_run_ids.add(fact.source_run_id)

    return _RevInventoryLinkIndex(
        linked_run_ids_by_experiment={
            experiment_id: frozenset(run_ids)
            for experiment_id, run_ids in linked_run_ids.items()
        },
        marked_run_or_receipt_experiment_ids=frozenset(
            marked_run_or_receipt_experiment_ids
        ),
        marked_fact_ids=frozenset(marked_fact_ids),
        marked_fact_source_run_ids=frozenset(
            marked_fact_source_run_ids
        ),
        oracle_copy_fact_source_run_ids=frozenset(
            oracle_copy_fact_source_run_ids
        ),
        oracle_copy_experiment_ids=frozenset(
            oracle_copy_experiment_ids
        ),
    )


def _rev_inventory_state_errors(
    state: "ChallengeState",
    *,
    runs: Mapping[str, RunReference],
    receipts: Mapping[str, ExecutionReceipt],
    artifacts: Mapping[str, ArtifactReference],
    facts: Mapping[str, Fact],
) -> list[str]:
    errors: list[str] = []
    link_index = _rev_inventory_link_index(state)

    for experiment in state.experiments:
        descriptor = experiment.extra.get("partial_oracle")
        has_generic_adapter_identity = (
            experiment.extra.get("adapter_seed") is True
            and experiment.extra.get("adapter_name") == "reversing"
            and experiment.extra.get("adapter_spec_template_id")
            == REV_INVENTORY_V2_SEED_TEMPLATE_ID
        )
        has_v1_seed_identity = _rev_inventory_seed_identity(
            experiment,
            version=REV_INVENTORY_V1_CONTRACT_VERSION,
        )
        has_v2_seed_identity = _rev_inventory_seed_identity(
            experiment,
            version=REV_INVENTORY_V2_CONTRACT_VERSION,
        )
        descriptor_contract = (
            resolve_rev_inventory_contract(
                descriptor.get("oracle_id"),
                descriptor.get("oracle_version"),
                descriptor.get("contract_fingerprint"),
            )
            if isinstance(descriptor, Mapping)
            else None
        )
        descriptor_is_v1 = descriptor_contract is not None and (
            descriptor_contract.oracle_version
            == REV_INVENTORY_V1_CONTRACT_VERSION
        )
        descriptor_is_v2 = descriptor_contract is not None and (
            descriptor_contract.oracle_version
            == REV_INVENTORY_V2_CONTRACT_VERSION
        )
        descriptor_marks_rev_inventory_id = (
            isinstance(descriptor, Mapping)
            and descriptor.get("oracle_id") == _REV_INVENTORY_ORACLE_ID
        )
        experiment_outcome = (
            experiment.result.get("partial_oracle")
            if isinstance(experiment.result, Mapping)
            else None
        )
        linked_run_ids = link_index.linked_run_ids_by_experiment.get(
            experiment.id,
            frozenset(),
        )
        linked_outcome_marks_rev_inventory = (
            _has_rev_inventory_outcome_marker(experiment_outcome)
            or experiment.id
            in link_index.marked_run_or_receipt_experiment_ids
            or any(
                fact_id in link_index.marked_fact_ids
                for fact_id in experiment.evidence_fact_ids
            )
            or not linked_run_ids.isdisjoint(
                link_index.marked_fact_source_run_ids
            )
        )
        linked_has_oracle_copy = (
            experiment.id in link_index.oracle_copy_experiment_ids
            or not linked_run_ids.isdisjoint(
                link_index.oracle_copy_fact_source_run_ids
            )
        )
        is_legacy_v1 = (
            (has_v1_seed_identity or descriptor_is_v1)
            and not has_v2_seed_identity
            and not descriptor_is_v2
            and not linked_outcome_marks_rev_inventory
        )
        if is_legacy_v1:
            label = f"legacy Rev inventory experiment {experiment.id}"
            if isinstance(descriptor, Mapping):
                errors.extend(
                    _rev_inventory_legacy_v1_seed_errors(
                        experiment,
                        descriptor=descriptor,
                    )
                )
            else:
                errors.append(f"{label} lacks its v1 oracle descriptor")
            if (
                (
                    isinstance(experiment.result, Mapping)
                    and "partial_oracle" in experiment.result
                )
                or linked_has_oracle_copy
            ):
                errors.append(
                    f"{label} cannot contain a typed oracle outcome or Fact"
                )
            continue
        if not (
            has_generic_adapter_identity
            or has_v2_seed_identity
            or descriptor_marks_rev_inventory_id
            or linked_outcome_marks_rev_inventory
        ):
            continue
        expected_descriptor = rev_inventory_v2_oracle_descriptor()
        if not (has_v2_seed_identity or descriptor_is_v2):
            errors.append(
                f"Rev inventory experiment {experiment.id} has an "
                "invalid v2 deterministic seed identity"
            )
        if descriptor != expected_descriptor:
            errors.append(
                f"Rev inventory experiment {experiment.id} has an "
                "invalid oracle descriptor"
            )
        if experiment.status in {
            ExperimentStatus.REGISTERED,
            ExperimentStatus.RUNNING,
        }:
            if experiment.result is not None:
                errors.append(
                    f"Rev inventory experiment {experiment.id} has a "
                    "premature result"
                )
            if isinstance(descriptor, Mapping):
                errors.extend(
                    _rev_inventory_v2_active_seed_errors(
                        state,
                        experiment,
                        descriptor=descriptor,
                    )
                )
            continue
        label = f"Rev inventory experiment {experiment.id}"
        if (
            not isinstance(experiment.result, Mapping)
            or "partial_oracle" not in experiment.result
        ):
            has_oracle_copy = (
                experiment.id
                in link_index.oracle_copy_experiment_ids
            )
            if (
                experiment.status
                not in {
                    ExperimentStatus.CANCELLED,
                    ExperimentStatus.FAILED,
                }
                or has_oracle_copy
            ):
                errors.append(
                    f"{label} lacks its canonical oracle outcome"
                )
            continue
        try:
            experiment_result = _rev_inventory_exact_mapping(
                experiment.result,
                {
                    "exit_code",
                    "partial_oracle",
                    "receipt_id",
                    "run_id",
                    "timed_out",
                },
                f"{label} result",
            )
            outcome = _validate_rev_inventory_v2_outcome_shape(
                experiment_result["partial_oracle"],
                label=f"{label} outcome",
            )
            run_id = experiment_result["run_id"]
            receipt_id = experiment_result["receipt_id"]
            if not isinstance(run_id, str) or not isinstance(
                receipt_id,
                str,
            ):
                raise ModelValidationError(
                    f"{label} has invalid run/receipt ids"
                )
            run = runs.get(run_id)
            receipt = receipts.get(receipt_id)
            if (
                run is None
                or receipt is None
                or receipt.run_id != run_id
                or receipt.experiment_id != experiment.id
            ):
                raise ModelValidationError(
                    f"{label} has an invalid run/receipt chain"
                )
            run_outcome = run.extra.get("partial_oracle_result")
            receipt_outcome = receipt.extra.get(
                "partial_oracle_result"
            )
            if run_outcome != outcome or receipt_outcome != outcome:
                raise ModelValidationError(
                    f"{label} outcome copies do not match"
                )
            binding = outcome["execution_binding"]
            stdout_binding = binding["stdout_artifact"]
            stdout_artifact = artifacts.get(stdout_binding["id"])
            experiment_binding = binding["experiment"]
            source_binding = binding["source_binding"]
            source_snapshot = binding["source_snapshot"]
            snapshot_execution = binding[
                "source_snapshot_execution_binding"
            ]
            if (
                run.extra.get("experiment_id") != experiment.id
                or binding["experiment"]["id"] != experiment.id
                or binding["experiment"]["resource_class"]
                != experiment.resource_class
                or any(
                    experiment_binding.get(key)
                    != experiment.extra.get(key)
                    for key in (
                        "adapter_name",
                        "adapter_seed",
                        "adapter_seed_contract_version",
                        "adapter_seed_order",
                        "adapter_spec_id",
                        "adapter_spec_sha256",
                        "adapter_spec_template_id",
                        "requires_explicit_execution",
                    )
                )
                or any(
                    run.extra.get(key) != experiment.extra.get(key)
                    for key in (
                        "adapter_name",
                        "adapter_seed",
                        "adapter_seed_contract_version",
                        "adapter_seed_order",
                        "adapter_spec_id",
                        "adapter_spec_sha256",
                        "adapter_spec_template_id",
                        "partial_oracle",
                        "requires_explicit_execution",
                        "source_binding",
                        "source_snapshot",
                    )
                )
                or binding["base_revision"] != run.base_revision
                or binding["configuration_epoch"]
                != run.configuration_epoch
                or binding["request"]["path"] != run.request_path
                or binding["source_binding"]
                != experiment.extra.get("source_binding")
                or binding["source_snapshot"]
                != experiment.extra.get("source_snapshot")
                or binding["oracle"] != descriptor
                or binding["source_snapshot_execution_binding"]
                != run.extra.get(
                    "source_snapshot_execution_binding"
                )
                or not isinstance(source_binding, Mapping)
                or set(source_binding)
                != {
                    "manifest_generation",
                    "manifest_sha256",
                    "path",
                    "sha256",
                    "size_bytes",
                }
                or not isinstance(source_snapshot, Mapping)
                or set(source_snapshot)
                != {
                    "binding_sha256",
                    "challenge_dir",
                    "directory_mode",
                    "file_mode",
                    "id",
                    "mount_requirement",
                    "publish",
                    "sha256",
                    "size_bytes",
                    "source_locator",
                    "tree_contract",
                }
                or source_snapshot.get("id")
                != snapshot_execution.get("snapshot_id")
                or source_snapshot.get("source_locator")
                != source_binding.get("path")
                or source_snapshot.get("sha256")
                != source_binding.get("sha256")
                or source_snapshot.get("size_bytes")
                != source_binding.get("size_bytes")
                or not isinstance(experiment.command, str)
                or binding["argv"] != shlex.split(experiment.command)
                or stdout_artifact is None
                or stdout_artifact.source_run_id != run.id
                or stdout_artifact.path != stdout_binding["path"]
                or stdout_artifact.sha256 != stdout_binding["sha256"]
                or stdout_artifact.size != stdout_binding["size"]
                or receipt.stdout_artifact_id != stdout_artifact.id
                or outcome["stdout_artifact_id"] != stdout_artifact.id
                or stdout_artifact.id not in experiment.artifact_ids
            ):
                raise ModelValidationError(
                    f"{label} exact execution binding is inconsistent"
                )
            transport_succeeded = outcome["transport_succeeded"]
            if (
                type(experiment_result["timed_out"]) is not bool
                or experiment_result["exit_code"] != receipt.exit_code
                or (
                    transport_succeeded
                    and (
                        experiment_result["exit_code"] != 0
                        or experiment_result["timed_out"] is not False
                    )
                )
            ):
                raise ModelValidationError(
                    f"{label} result/receipt transport mismatch"
                )
            if transport_succeeded:
                if (
                    run.status is not RunStatus.COMPLETED
                    or receipt.outcome is not ReceiptOutcome.SUCCEEDED
                ):
                    raise ModelValidationError(
                        f"{label} transport/run/receipt mismatch"
                    )
            else:
                expected_run_status = (
                    RunStatus.TIMED_OUT
                    if experiment_result["timed_out"] is True
                    else RunStatus.FAILED
                )
                expected_receipt_outcome = (
                    ReceiptOutcome.TIMED_OUT
                    if experiment_result["timed_out"] is True
                    else ReceiptOutcome.FAILED
                )
                if (
                    run.status is not expected_run_status
                    or receipt.outcome is not expected_receipt_outcome
                ):
                    raise ModelValidationError(
                        f"{label} failed transport status mismatch"
                    )

            semantic = outcome["result"]
            verdict = (
                semantic["verdict"]
                if isinstance(semantic, Mapping)
                else None
            )
            fact_required = verdict in {
                "CONFIRMED",
                "INCONCLUSIVE",
                "NOT_APPLICABLE",
            }
            expected_status = (
                ExperimentStatus.COMPLETED
                if verdict == "CONFIRMED"
                else ExperimentStatus.INCONCLUSIVE
                if fact_required
                else ExperimentStatus.FAILED
            )
            if experiment.status is not expected_status:
                raise ModelValidationError(
                    f"{label} verdict/status mismatch"
                )
            expected_fact_id = f"F-{run.id}-rev-inventory"
            if fact_required:
                if experiment.evidence_fact_ids != [expected_fact_id]:
                    raise ModelValidationError(
                        f"{label} lacks its deterministic Fact"
                    )
                fact = facts.get(expected_fact_id)
                if (
                    fact is None
                    or fact.provenance is not Provenance.EXECUTED
                    or fact.source_run_id != run.id
                    or fact.artifact_id != stdout_artifact.id
                    or fact.locator != stdout_artifact.path
                    or fact.extra.get("partial_oracle_result")
                    != outcome
                    or fact.extra.get("receipt_id") != receipt.id
                ):
                    raise ModelValidationError(
                        f"{label} has an invalid oracle Fact chain"
                    )
            elif (
                experiment.evidence_fact_ids
                or run.id
                in link_index.oracle_copy_fact_source_run_ids
            ):
                raise ModelValidationError(
                    f"{label} error/rejection cannot create a Fact"
                )
            if (
                experiment.evidence_run_ids != [run.id]
                or experiment.evidence_receipt_ids != [receipt.id]
            ):
                raise ModelValidationError(
                    f"{label} evidence links are not exact"
                )
            if experiment.status in {
                ExperimentStatus.FAILED,
                ExperimentStatus.INCONCLUSIVE,
            }:
                semantic_reason = (
                    (
                        f"{semantic['verdict']}/"
                        f"{semantic['reason_code']}"
                    )
                    if isinstance(semantic, Mapping)
                    else (
                        outcome["rejection_code"]
                        or "no_semantic_result"
                    )
                )
                expected_reason = (
                    "rev_inventory:"
                    f"{outcome['evaluation_status']}:"
                    f"{semantic_reason}"
                )[:512]
                if (
                    experiment.evaluation_reason != expected_reason
                    or experiment.evaluated_at
                    != outcome["evaluated_at"]
                ):
                    raise ModelValidationError(
                        f"{label} has an invalid semantic "
                        "reason/timestamp"
                    )
            elif (
                experiment.evaluation_reason is not None
                or experiment.evaluated_at is not None
            ):
                raise ModelValidationError(
                    f"{label} confirmed result retains negative "
                    "evaluation metadata"
                )
        except (
            KeyError,
            ModelValidationError,
            TypeError,
            ValueError,
        ) as error:
            errors.append(f"{label} is invalid: {error}")
    return errors


_PWN_CRASH_ENGINE_COMMAND = "ctfos-engine:pwn-crash-v1"
_PWN_CRASH_ENGINE_EXECUTOR = "pwn_crash_differential_v1"
_PWN_CRASH_ACTION_KIND = "verify_pwn_crash"
_PWN_CRASH_FLAG_PATTERNS_ENV = "CTF_WRAP_FLAG_PATTERNS_JSON"
_PWN_CRASH_RESULT_KEY = "pwn_crash_evidence"
_PWN_CRASH_REQUEST_KEYS = frozenset(
    {
        "schema_version",
        "contract_id",
        "contract_version",
        "contract_fingerprint",
        "protocol",
        "configuration_epoch",
        "payload_artifact_id",
        "payload_reported_locator",
        "payload_sha256",
        "payload_size_bytes",
        "hypothesis_id",
        "source_builder_run_id",
    }
)
_PWN_CRASH_EVIDENCE_KEYS = frozenset(
    {
        "schema_version",
        "protocol",
        "recipe_sha256",
        "evaluated_at",
        "evaluation",
        "evaluation_sha256",
        "attempts",
    }
)
_PWN_CRASH_ATTEMPT_LINK_KEYS = frozenset(
    {
        "ordinal",
        "run_id",
        "receipt_id",
        "stdout_artifact_id",
    }
)
_PWN_CRASH_RUN_RECORD_KEYS = frozenset(
    {
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
)


def _pwn_crash_exact_dict(
    value: object,
    expected_keys: frozenset[str],
    label: str,
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected_keys:
        raise ModelValidationError(
            f"{label} has missing or unknown fields"
        )
    return value


def _pwn_crash_experiment_marker(experiment: Experiment) -> bool:
    result = experiment.result
    return (
        experiment.command == _PWN_CRASH_ENGINE_COMMAND
        or experiment.extra.get("engine_executor")
        == _PWN_CRASH_ENGINE_EXECUTOR
        or experiment.extra.get("managed_action_kind")
        == _PWN_CRASH_ACTION_KIND
        or "pwn_crash_request" in experiment.extra
        or "pwn_crash_recipe" in experiment.extra
        or (
            isinstance(result, Mapping)
            and _PWN_CRASH_RESULT_KEY in result
        )
    )


def _web_impact_state_marker(value: object) -> bool:
    """Identify records whose stricter graph is validated after generic rules.

    Keep this local to avoid importing the Web graph module while model types
    are being defined.  The exact graph validator is invoked at the end of
    ``ChallengeState.validate`` and rejects forged or orphaned markers.
    """

    extra = getattr(value, "extra", None)
    return (
        type(extra) is dict
        and (
            extra.get("engine_executor")
            == "web_impact_execution_state_v1"
            or "web_impact_state" in extra
        )
    )


def _pwn_exploit_effect_state_marker(value: object) -> bool:
    """Identify the exact multi-replay Pwn E graph for later validation."""

    extra = getattr(value, "extra", None)
    return (
        type(extra) is dict
        and "pwn_exploit_effect_state" in extra
    )


def _forensic_assertion_state_marker(value: object) -> bool:
    """Identify records delegated to the exact Forensic graph validator."""

    extra = getattr(value, "extra", None)
    return (
        type(extra) is dict
        and (
            extra.get("engine_executor")
            == "forensic_assertion_execution_state_v1"
            or "forensic_assertion_state" in extra
        )
    )


def _rev_acceptance_state_marker(value: object) -> bool:
    """Identify candidate-free Rev evidence for exact lazy validation."""

    extra = getattr(value, "extra", None)
    result = getattr(value, "result", None)
    return (
        type(extra) is dict
        and (
            extra.get("engine_executor")
            == "rev_accepted_input_state_v1"
            or "rev_acceptance_state" in extra
        )
    ) or (
        isinstance(result, Mapping)
        and "rev_acceptance_evidence" in result
    )


def _pwn_crash_safe_locator(value: object) -> bool:
    if (
        type(value) is not str
        or not value
        or value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or "\x00" in value
        or len(value.encode("utf-8")) > 4096
    ):
        return False
    parts = value.split("/")
    return (
        all(
            part not in {"", ".", ".."}
            and len(part.encode("utf-8")) <= 255
            for part in parts
        )
        and PurePosixPath(value).as_posix() == value
    )


def _pwn_crash_registered_binding(
    state: "ChallengeState",
    experiment: Experiment,
    *,
    runs: Mapping[str, RunReference],
    artifacts: Mapping[str, ArtifactReference],
    hypotheses: Mapping[str, Hypothesis],
) -> tuple[
    Mapping[str, Any] | None,
    RunReference | None,
    ArtifactReference | None,
    list[str],
]:
    """Validate the model nomination without granting it execution control."""

    label = f"Pwn crash experiment {experiment.id}"
    pre_execution = experiment.status in {
        ExperimentStatus.REGISTERED,
        ExperimentStatus.RUNNING,
    }
    errors: list[str] = []
    raw_request = experiment.extra.get("pwn_crash_request")
    if type(raw_request) is not dict or set(raw_request) != (
        _PWN_CRASH_REQUEST_KEYS
    ):
        return None, None, None, [
            f"{label} request has missing or unknown fields"
        ]
    request = raw_request
    if (
        state.schema_version < STATE_SCHEMA_VERSION
        or state.category.strip().casefold() != "pwn"
        or experiment.kind is not ExperimentKind.STRATEGIC
        or experiment.command != _PWN_CRASH_ENGINE_COMMAND
        or experiment.proof_recipe is not None
        or experiment.extra.get("managed_contract_version") != 2
        or experiment.extra.get("managed_action_kind")
        != _PWN_CRASH_ACTION_KIND
        or experiment.extra.get("engine_executor")
        != _PWN_CRASH_ENGINE_EXECUTOR
    ):
        errors.append(f"{label} lacks its exact engine-owned identity")
    configuration_epoch = request.get("configuration_epoch")
    payload_size = request.get("payload_size_bytes")
    if (
        type(request.get("schema_version")) is not int
        or request["schema_version"] != 1
        or request.get("contract_id") != PWN_CRASH_V1_CONTRACT_ID
        or type(request.get("contract_version")) is not int
        or request["contract_version"] != PWN_CRASH_V1_CONTRACT_VERSION
        or request.get("contract_fingerprint")
        != PWN_CRASH_V1_CONTRACT_FINGERPRINT
        or request.get("protocol") != PWN_CRASH_V1_PROTOCOL
        or type(configuration_epoch) is not int
        or not 0 <= configuration_epoch <= state.configuration_epoch
        or (
            pre_execution
            and configuration_epoch != state.configuration_epoch
        )
        or experiment.extra.get("configuration_epoch")
        != configuration_epoch
        or not _proof_binding_identifier(request.get("hypothesis_id"))
        or not _proof_binding_identifier(
            request.get("source_builder_run_id")
        )
        or not _proof_binding_identifier(
            request.get("payload_artifact_id")
        )
        or not _pwn_crash_safe_locator(
            request.get("payload_reported_locator")
        )
        or not _proof_binding_sha256(request.get("payload_sha256"))
        or type(payload_size) is not int
        or not 1 <= payload_size <= PWN_CRASH_V1_MAX_INPUT_BYTES
    ):
        errors.append(f"{label} request values are invalid")

    hypothesis_id = request.get("hypothesis_id")
    source_run_id = request.get("source_builder_run_id")
    payload_id = request.get("payload_artifact_id")
    hypothesis = (
        hypotheses.get(hypothesis_id)
        if isinstance(hypothesis_id, str)
        else None
    )
    source_run = (
        runs.get(source_run_id)
        if isinstance(source_run_id, str)
        else None
    )
    payload = (
        artifacts.get(payload_id)
        if isinstance(payload_id, str)
        else None
    )
    if (
        hypothesis is None
        or experiment.hypothesis_ids != [hypothesis_id]
        or (
            pre_execution
            and hypothesis.status not in ACTIVE_HYPOTHESIS_STATUSES
        )
    ):
        errors.append(
            f"{label} does not bind one eligible hypothesis"
        )
    if (
        source_run is None
        or source_run.status is not RunStatus.COMPLETED
        or source_run.origin is not RunOrigin.MANAGED_MODEL
        or source_run.role != "builder"
        or source_run.configuration_epoch != configuration_epoch
        or source_run.extra.get("semantic_merge") is not True
        or experiment.source_run_id != source_run_id
    ):
        errors.append(f"{label} does not bind its completed Builder run")
    if (
        payload is None
        or payload.source_run_id != source_run_id
        or payload.sha256 != request.get("payload_sha256")
        or payload.size != payload_size
        or type(payload.size) is not int
        or payload.extra.get("reported_locator")
        != request.get("payload_reported_locator")
    ):
        errors.append(f"{label} does not bind its canonical payload")
    return request, source_run, payload, errors


def _pwn_crash_recipe_binding(
    state: "ChallengeState",
    experiment: Experiment,
    *,
    request: Mapping[str, Any],
    payload: ArtifactReference,
) -> tuple[Any | None, list[str]]:
    """Parse the exact engine recipe and bind it back to canonical state."""

    label = f"Pwn crash experiment {experiment.id}"
    raw_recipe = experiment.extra.get("pwn_crash_recipe")
    if type(raw_recipe) is not dict:
        return None, [f"{label} lacks its canonical execution recipe"]
    try:
        from ctf_os.engine.pwn_crash import (  # local: avoids cycle
            PwnCrashRecipe,
        )

        recipe = PwnCrashRecipe.from_dict(raw_recipe)
    except (
        ImportError,
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        # PwnCrashRecipeError is a ValueError subclass.  Keeping this bounded
        # exception list also lets old recovery environments fail closed.
        return None, [f"{label} recipe is invalid: {error}"]

    manifest = state.metadata.get("source_manifest_sha256")
    primary_locator = state.metadata.get("adapter_primary_source")
    matching_sources = [
        source
        for source in state.source_inventory
        if source.path == primary_locator
    ]
    errors: list[str] = []
    if (
        recipe.experiment_id != experiment.id
        or recipe.hypothesis_id != request.get("hypothesis_id")
        or recipe.configuration_epoch
        != request.get("configuration_epoch")
        or recipe.payload_artifact_id != payload.id
        or recipe.payload_source_run_id != payload.source_run_id
        or recipe.payload_artifact_locator != payload.path
        or recipe.payload_sha256 != payload.sha256
        or recipe.payload_size_bytes != payload.size
    ):
        errors.append(f"{label} recipe request/payload binding changed")
    if (
        not _proof_binding_sha256(manifest)
        or not isinstance(primary_locator, str)
        or len(matching_sources) != 1
    ):
        errors.append(f"{label} has no exact current primary source")
    else:
        primary = matching_sources[0]
        if (
            primary.kind != "file"
            or not _proof_binding_sha256(primary.sha256)
            or type(primary.size) is not int
            or not 1 <= primary.size <= PWN_CRASH_V1_MAX_SOURCE_BYTES
            or recipe.primary_elf_locator != primary.path
            or recipe.source_manifest_sha256 != manifest
            or recipe.source_sha256 != primary.sha256
            or recipe.source_size_bytes != primary.size
        ):
            errors.append(f"{label} recipe source binding changed")
    if (
        not isinstance(recipe.image_reference, str)
        or not recipe.image_reference
        or not isinstance(recipe.image_digest, str)
        or not recipe.image_digest.startswith("sha256:")
        or not _proof_binding_sha256(
            recipe.image_digest.removeprefix("sha256:")
        )
    ):
        errors.append(f"{label} recipe image binding is not digest-pinned")
    return recipe, errors


def _pwn_crash_gate_binding(
    value: object,
    *,
    recipe: Any,
) -> tuple[Any | None, list[str]]:
    """Parse one aggregate verdict and bind its semantic pins to the recipe."""

    try:
        from ctf_os.engine.pwn_crash import (  # local: avoids cycle
            PwnCrashGateEvaluation,
        )

        evaluation = PwnCrashGateEvaluation.from_dict(value)
    except (
        ImportError,
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        return None, [f"Pwn crash gate evaluation is invalid: {error}"]

    errors: list[str] = []
    if evaluation.to_dict() != value:
        errors.append("Pwn crash gate evaluation is not canonical")
    semantic = evaluation.semantic_evaluation
    if semantic is not None and (
        semantic.recipe_sha256 != recipe.recipe_sha256
        or semantic.source_manifest_sha256
        != recipe.source_manifest_sha256
        or semantic.source_sha256 != recipe.source_sha256
        or semantic.source_size_bytes != recipe.source_size_bytes
        or semantic.poc_sha256 != recipe.payload_sha256
        or semantic.poc_size_bytes != recipe.payload_size_bytes
    ):
        errors.append(
            "Pwn crash gate evaluation changed its recipe/source/payload "
            "binding"
        )
    return evaluation, errors


def _pwn_crash_run_marker(run: RunReference) -> bool:
    return (
        run.role == "pwn_crash_gate"
        or "pwn_crash" in run.extra
    )


def _pwn_crash_artifact_marker(artifact: ArtifactReference) -> bool:
    return (
        artifact.extra.get("engine_executor")
        == _PWN_CRASH_ENGINE_EXECUTOR
        or artifact.extra.get("kind")
        == "pwn_crash_capability_attestation"
    )


def _pwn_crash_precommit_failure_errors(
    experiment: Experiment,
    *,
    payload: ArtifactReference,
    linked_runs: list[RunReference],
    linked_receipts: list[ExecutionReceipt],
    linked_artifacts: list[ArtifactReference],
) -> list[str]:
    label = f"Pwn crash experiment {experiment.id}"
    errors: list[str] = []
    result = experiment.result
    reason = (
        result.get("error")
        if type(result) is dict and set(result) == {"error"}
        else None
    )
    if (
        experiment.status is not ExperimentStatus.FAILED
        or type(reason) is not str
        or not reason.startswith("Pwn crash gate failed closed: ")
        or len(reason.encode("utf-8")) > 4096
    ):
        errors.append(f"{label} has an invalid pre-commit failure result")
    if (
        experiment.artifact_ids != [payload.id]
        or experiment.evidence_fact_ids
        or experiment.evidence_run_ids
        or experiment.evidence_receipt_ids
        or experiment.evaluation_reason is not None
        or experiment.evaluated_at is not None
        or linked_runs
        or linked_receipts
        or linked_artifacts
    ):
        errors.append(
            f"{label} pre-commit failure retained execution evidence"
        )
    return errors


def _pwn_crash_execution_contract_errors(
    value: object,
    *,
    supplied_sha256: object,
    experiment: Experiment,
    recipe: Any,
    ordinal: int,
    capability_artifact_id: str,
    capability_sha256: str,
) -> list[str]:
    """Reconstruct every engine-owned execution field except issued timeout."""

    label = f"Pwn crash experiment {experiment.id} attempt {ordinal}"
    if type(value) is not dict:
        return [f"{label} execution contract is not an object"]
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
    except (RecursionError, TypeError, UnicodeError, ValueError):
        return [f"{label} execution contract is not canonical JSON"]
    if (
        len(encoded) > 256 * 1024
        or not _proof_binding_sha256(supplied_sha256)
        or hashlib.sha256(encoded).hexdigest() != supplied_sha256
    ):
        return [f"{label} execution contract hash does not match"]

    gate = value.get("gate")
    sandbox = value.get("sandbox")
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
    if (
        type(environment) is not dict
        or set(environment) != {_PWN_CRASH_FLAG_PATTERNS_ENV}
        or not patterns_valid
    ):
        return [f"{label} flag scan environment is invalid"]
    gate_deadline = (
        gate.get("deadline_epoch_seconds")
        if type(gate) is dict
        else None
    )
    if (
        type(gate) is not dict
        or set(gate)
        != {"timeout_seconds", "deadline_epoch_seconds"}
        or gate.get("timeout_seconds") != experiment.timeout_seconds
        or type(gate_deadline) not in {int, float}
        or not math.isfinite(float(gate_deadline))
        or float(gate_deadline) <= 0
    ):
        return [f"{label} gate deadline binding is invalid"]
    outer_timeout = (
        sandbox.get("outer_timeout_seconds")
        if type(sandbox) is dict
        else None
    )
    if (
        type(outer_timeout) is not int
        or not 1 <= outer_timeout <= min(10, experiment.timeout_seconds)
    ):
        return [f"{label} execution timeout is invalid"]
    try:
        from ctf_os.director.resources import tool_profile
        from ctf_os.engine.pwn_crash import (
            PWN_CRASH_INPUT_DESTINATION_LOCATOR,
            PWN_CRASH_NETWORK_POLICY,
            PWN_CRASH_ONE_SHOT,
            PWN_CRASH_PRODUCER_CAPABILITY_NAME,
            PWN_CRASH_PRODUCER_INTERPRETER_PATH,
            PWN_CRASH_PRODUCER_PATH,
            PWN_CRASH_SANDBOX_METHOD,
        )

        binding = recipe.attempt_input_binding(ordinal)
        expected = {
            "schema_version": 1,
            "contract": {
                "id": PWN_CRASH_V1_CONTRACT_ID,
                "version": PWN_CRASH_V1_CONTRACT_VERSION,
                "fingerprint": PWN_CRASH_V1_CONTRACT_FINGERPRINT,
            },
            "protocol": PWN_CRASH_V1_PROTOCOL,
            "recipe_sha256": recipe.recipe_sha256,
            "configuration_epoch": recipe.configuration_epoch,
            "gate": {
                "timeout_seconds": experiment.timeout_seconds,
                "deadline_epoch_seconds": gate_deadline,
            },
            "attempt": {
                "ordinal": ordinal,
                "phase": binding["phase"],
            },
            "input": {
                "kind": binding["input_kind"],
                "artifact_id": (
                    recipe.payload_artifact_id
                    if binding["phase"] == "positive"
                    else None
                ),
                "sha256": binding["input_sha256"],
                "size_bytes": binding["input_size_bytes"],
                "destination_locator": (
                    PWN_CRASH_INPUT_DESTINATION_LOCATOR
                ),
            },
            "argv": list(recipe.argv_for_attempt(ordinal)),
            "sandbox": {
                "method": PWN_CRASH_SANDBOX_METHOD,
                "one_shot": PWN_CRASH_ONE_SHOT,
                "outer_timeout_seconds": outer_timeout,
                "environment": dict(environment),
                "resource_request": tool_profile(
                    experiment.resource_class,
                    needs_kvm=False,
                    network=False,
                ).as_dict(),
                "image": {
                    "reference": recipe.image_reference,
                    "digest": recipe.image_digest,
                },
                "network": PWN_CRASH_NETWORK_POLICY,
                "network_target": None,
            },
            "producer": {
                "interpreter_path": (
                    PWN_CRASH_PRODUCER_INTERPRETER_PATH
                ),
                "path": PWN_CRASH_PRODUCER_PATH,
                "capability_name": (
                    PWN_CRASH_PRODUCER_CAPABILITY_NAME
                ),
                "file_sha256": recipe.producer_file_sha256,
                "capability_attestation_artifact_id": (
                    capability_artifact_id
                ),
                "capability_attestation_sha256": capability_sha256,
            },
        }
    except (ImportError, KeyError, TypeError, ValueError) as error:
        return [f"{label} execution contract cannot be rebuilt: {error}"]
    if value != expected:
        return [f"{label} execution contract changed"]
    return []


def _pwn_crash_attempt_graph_errors(
    experiment: Experiment,
    *,
    recipe: Any,
    source_run: RunReference,
    attempts: list[Mapping[str, Any]],
    runs: Mapping[str, RunReference],
    receipts: Mapping[str, ExecutionReceipt],
    artifacts: Mapping[str, ArtifactReference],
    artifacts_by_run: Mapping[str, list[ArtifactReference]],
) -> tuple[list[str], str | None]:
    """Validate six state-level run/receipt/artifact chains.

    Semantic classification remains owned by ``PwnCrashGateEvaluation``.
    This helper only verifies that its six attempt links point at the exact
    durable execution records declared by the engine.
    """

    label = f"Pwn crash experiment {experiment.id}"
    errors: list[str] = []
    capability_id: str | None = None
    seen_runs: set[str] = set()
    seen_receipts: set[str] = set()
    seen_stdout: set[str] = set()
    seen_requests: set[str] = set()
    seen_execution_contracts: set[str] = set()
    shared_gate_binding: Mapping[str, Any] | None = None
    shared_flag_environment: Mapping[str, Any] | None = None

    try:
        from ctf_os.engine.pwn_crash import (  # local: avoids cycle
            PWN_CRASH_NETWORK_POLICY,
            PWN_CRASH_ONE_SHOT,
            PWN_CRASH_PRODUCER_CAPABILITY_NAME,
            PWN_CRASH_SANDBOX_METHOD,
            PwnCrashReceiptMetadata,
        )
    except ImportError as error:
        return [f"{label} cannot load its receipt contract: {error}"], None

    for expected_ordinal, attempt in enumerate(attempts, start=1):
        attempt_label = f"{label} attempt {expected_ordinal}"
        if (
            type(attempt) is not dict
            or set(attempt) != _PWN_CRASH_ATTEMPT_LINK_KEYS
        ):
            errors.append(f"{attempt_label} link is not canonical")
            continue
        ordinal = attempt.get("ordinal")
        run_id = attempt.get("run_id")
        receipt_id = attempt.get("receipt_id")
        stdout_id = attempt.get("stdout_artifact_id")
        if (
            type(ordinal) is not int
            or ordinal != expected_ordinal
            or not _proof_binding_identifier(run_id)
            or not _proof_binding_identifier(receipt_id)
            or not _proof_binding_identifier(stdout_id)
        ):
            errors.append(f"{attempt_label} link values are invalid")
            continue
        assert isinstance(run_id, str)
        assert isinstance(receipt_id, str)
        assert isinstance(stdout_id, str)
        if (
            run_id in seen_runs
            or receipt_id in seen_receipts
            or stdout_id in seen_stdout
        ):
            errors.append(f"{attempt_label} reuses an evidence record")
        seen_runs.add(run_id)
        seen_receipts.add(receipt_id)
        seen_stdout.add(stdout_id)

        run = runs.get(run_id)
        receipt = receipts.get(receipt_id)
        stdout = artifacts.get(stdout_id)
        if run is None or receipt is None or stdout is None:
            errors.append(f"{attempt_label} has a missing evidence record")
            continue
        pwn_record = run.extra.get("pwn_crash")
        receipt_record = receipt.extra.get("pwn_crash")
        raw_metadata = (
            pwn_record.get("receipt")
            if type(pwn_record) is dict
            else None
        )
        try:
            metadata = PwnCrashReceiptMetadata.from_dict(raw_metadata)
        except (TypeError, ValueError) as error:
            errors.append(
                f"{attempt_label} receipt metadata is invalid: {error}"
            )
            continue
        binding = recipe.attempt_input_binding(expected_ordinal)
        request_sha256 = (
            pwn_record.get("request_sha256")
            if type(pwn_record) is dict
            else None
        )
        execution_contract_sha256 = (
            pwn_record.get("execution_contract_sha256")
            if type(pwn_record) is dict
            else None
        )
        if (
            type(pwn_record) is not dict
            or set(pwn_record) != _PWN_CRASH_RUN_RECORD_KEYS
            or pwn_record != receipt_record
            or pwn_record.get("recipe_sha256")
            != recipe.recipe_sha256
            or pwn_record.get("ordinal") != expected_ordinal
            or pwn_record.get("phase") != binding["phase"]
            or pwn_record.get("input_sha256")
            != binding["input_sha256"]
            or pwn_record.get("input_size_bytes")
            != binding["input_size_bytes"]
            or not _proof_binding_sha256(request_sha256)
            or metadata.request_sha256 != request_sha256
            or not _proof_binding_sha256(execution_contract_sha256)
            or metadata.execution_contract_sha256
            != execution_contract_sha256
        ):
            errors.append(
                f"{attempt_label} run/receipt binding is inconsistent"
            )
        if isinstance(request_sha256, str):
            if request_sha256 in seen_requests:
                errors.append(f"{attempt_label} reuses a request hash")
            seen_requests.add(request_sha256)
        if isinstance(execution_contract_sha256, str):
            if execution_contract_sha256 in seen_execution_contracts:
                errors.append(
                    f"{attempt_label} reuses an execution-contract hash"
                )
            seen_execution_contracts.add(execution_contract_sha256)

        current_capability_id = (
            metadata.capability_attestation_artifact_id
        )
        current_capability_sha256 = (
            metadata.capability_attestation_sha256
        )
        if capability_id is None and isinstance(
            current_capability_id,
            str,
        ):
            capability_id = current_capability_id
        if (
            not _proof_binding_identifier(current_capability_id)
            or not _proof_binding_sha256(current_capability_sha256)
            or current_capability_id != capability_id
        ):
            errors.append(
                f"{attempt_label} capability binding is inconsistent"
            )
        errors.extend(
            _pwn_crash_execution_contract_errors(
                pwn_record.get("execution_contract"),
                supplied_sha256=execution_contract_sha256,
                experiment=experiment,
                recipe=recipe,
                ordinal=expected_ordinal,
                capability_artifact_id=current_capability_id,
                capability_sha256=current_capability_sha256,
            )
        )
        execution_contract = pwn_record.get("execution_contract")
        current_gate_binding = (
            execution_contract.get("gate")
            if type(execution_contract) is dict
            else None
        )
        if type(current_gate_binding) is dict:
            if shared_gate_binding is None:
                shared_gate_binding = dict(current_gate_binding)
            elif current_gate_binding != shared_gate_binding:
                errors.append(
                    f"{attempt_label} changed the shared gate deadline"
                )
        current_sandbox = (
            execution_contract.get("sandbox")
            if type(execution_contract) is dict
            else None
        )
        current_flag_environment = (
            current_sandbox.get("environment")
            if type(current_sandbox) is dict
            else None
        )
        if type(current_flag_environment) is dict:
            if shared_flag_environment is None:
                shared_flag_environment = dict(
                    current_flag_environment
                )
            elif current_flag_environment != shared_flag_environment:
                errors.append(
                    f"{attempt_label} changed the shared flag environment"
                )

        if (
            run.origin is not RunOrigin.MANAGED_TOOL
            or run.role != "pwn_crash_gate"
            or run.extra.get("experiment_id") != experiment.id
            or run.configuration_epoch != recipe.configuration_epoch
            or run.session_id != source_run.session_id
            or run.cycle_id != source_run.cycle_id
            or run.wave_id != source_run.wave_id
            or not _pwn_crash_safe_locator(run.request_path)
            or not _pwn_crash_safe_locator(run.result_path)
            or not _pwn_crash_safe_locator(run.validation_path)
            or receipt.experiment_id != experiment.id
            or receipt.run_id != run.id
            or receipt.id != metadata.receipt_id
            or receipt.run_id != metadata.run_id
            or receipt.outcome.value != metadata.outcome
            or receipt.exit_code != metadata.exit_code
            or receipt.stdout_artifact_id != stdout.id
            or receipt.stderr_artifact_id
            != metadata.stderr_artifact_id
            or receipt.stdout_bytes != metadata.stdout_drained_bytes
            or stdout.source_run_id != run.id
            or stdout.sha256 != metadata.stdout_artifact_sha256
            or stdout.size != metadata.stdout_artifact_size_bytes
            or metadata.stdout_artifact_id != stdout.id
            or metadata.ordinal != expected_ordinal
            or metadata.configuration_epoch != recipe.configuration_epoch
            or metadata.image_digest != recipe.image_digest
            or metadata.recipe_sha256 != recipe.recipe_sha256
            or metadata.producer_capability_name
            != PWN_CRASH_PRODUCER_CAPABILITY_NAME
            or metadata.producer_file_sha256
            != recipe.producer_file_sha256
            or metadata.one_shot is not PWN_CRASH_ONE_SHOT
            or metadata.sandbox_method != PWN_CRASH_SANDBOX_METHOD
            or metadata.network != PWN_CRASH_NETWORK_POLICY
        ):
            errors.append(
                f"{attempt_label} durable execution chain is inconsistent"
            )

        stderr = (
            artifacts.get(receipt.stderr_artifact_id)
            if isinstance(receipt.stderr_artifact_id, str)
            else None
        )
        per_run_artifacts = artifacts_by_run.get(run.id, [])
        if (
            stderr is None
            or stderr.source_run_id != run.id
            or stderr.id != metadata.stderr_artifact_id
            or stderr.sha256 != metadata.stderr_artifact_sha256
            or stderr.size != metadata.stderr_artifact_size_bytes
            or stdout.id == stderr.id
            or {item.id for item in per_run_artifacts}
            != {stdout.id, stderr.id}
            or stdout.id not in experiment.artifact_ids
            or stderr.id in experiment.artifact_ids
        ):
            errors.append(
                f"{attempt_label} stdout/stderr artifact graph is invalid"
            )
        expected_stream_extra = {
            "engine_executor": _PWN_CRASH_ENGINE_EXECUTOR,
            "recipe_sha256": recipe.recipe_sha256,
            "ordinal": expected_ordinal,
            "phase": binding["phase"],
        }
        for stream, artifact in (("stdout", stdout), ("stderr", stderr)):
            if artifact is None:
                continue
            extra = artifact.extra
            expected_placeholder = (
                metadata.stdout_artifact_capture_placeholder
                if stream == "stdout"
                else metadata.stderr_artifact_capture_placeholder
            )
            if (
                set(extra)
                != {
                    "stream",
                    "engine_executor",
                    "recipe_sha256",
                    "ordinal",
                    "phase",
                    "capture_placeholder",
                }
                or extra.get("stream") != stream
                or any(
                    extra.get(key) != value
                    for key, value in expected_stream_extra.items()
                )
                or type(extra.get("capture_placeholder")) is not bool
                or extra.get("capture_placeholder")
                is not expected_placeholder
            ):
                errors.append(
                    f"{attempt_label} {stream} artifact is not canonical"
                )
    return errors, capability_id


def _pwn_crash_state_errors(
    state: "ChallengeState",
    *,
    runs: Mapping[str, RunReference],
    receipts: Mapping[str, ExecutionReceipt],
    artifacts: Mapping[str, ArtifactReference],
    facts: Mapping[str, Fact],
    hypotheses: Mapping[str, Hypothesis],
) -> list[str]:
    """Validate the typed six-attempt Pwn crash state graph."""

    errors: list[str] = []
    receipts_by_experiment: dict[str, list[ExecutionReceipt]] = {}
    artifacts_by_run: dict[str, list[ArtifactReference]] = {}
    for receipt in state.receipts:
        receipts_by_experiment.setdefault(
            receipt.experiment_id,
            [],
        ).append(receipt)
    for artifact in state.artifacts:
        if artifact.source_run_id is not None:
            artifacts_by_run.setdefault(
                artifact.source_run_id,
                [],
            ).append(artifact)

    marked_experiments = {
        experiment.id: experiment
        for experiment in state.experiments
        if _pwn_crash_experiment_marker(experiment)
    }
    marked_run_ids = {
        run.id for run in state.runs if _pwn_crash_run_marker(run)
    }
    terminal_recipe_hashes: set[str] = set()

    for run in state.runs:
        if not _pwn_crash_run_marker(run):
            continue
        experiment_id = run.extra.get("experiment_id")
        if (
            type(experiment_id) is not str
            or experiment_id not in marked_experiments
        ):
            errors.append(
                f"Pwn crash run {run.id} has no typed experiment"
            )
    for receipt in state.receipts:
        if (
            "pwn_crash" in receipt.extra
            and receipt.experiment_id not in marked_experiments
        ):
            errors.append(
                f"Pwn crash receipt {receipt.id} has no typed experiment"
            )

    for experiment in marked_experiments.values():
        label = f"Pwn crash experiment {experiment.id}"
        request, source_run, payload, binding_errors = (
            _pwn_crash_registered_binding(
                state,
                experiment,
                runs=runs,
                artifacts=artifacts,
                hypotheses=hypotheses,
            )
        )
        errors.extend(binding_errors)
        if request is None or source_run is None or payload is None:
            continue
        linked_receipts = receipts_by_experiment.get(
            experiment.id,
            [],
        )
        linked_runs = [
            run
            for run in state.runs
            if (
                run.extra.get("experiment_id") == experiment.id
                and (
                    run.origin is RunOrigin.MANAGED_TOOL
                    or _pwn_crash_run_marker(run)
                )
            )
        ]
        if experiment.status not in {
            ExperimentStatus.REGISTERED,
            ExperimentStatus.RUNNING,
        }:
            source_cycle = (
                next(
                    (
                        cycle
                        for cycle in state.cycles
                        if (
                            source_run.cycle_id is not None
                            and cycle.id == source_run.cycle_id
                            and cycle.session_id == source_run.session_id
                        )
                    ),
                    None,
                )
                if source_run is not None
                else None
            )
            if (
                source_cycle is None
                or experiment.id
                not in source_cycle.selected_action_ids
            ):
                errors.append(
                    f"{label} terminal evidence is not a selected "
                    "cycle action"
                )
        raw_recipe = experiment.extra.get("pwn_crash_recipe")
        recipe = None
        recipe_errors: list[str] = []
        if raw_recipe is not None:
            recipe, recipe_errors = _pwn_crash_recipe_binding(
                state,
                experiment,
                request=request,
                payload=payload,
            )
            errors.extend(recipe_errors)
        linked_artifacts = [
            artifact
            for artifact in state.artifacts
            if (
                _pwn_crash_artifact_marker(artifact)
                and (
                    artifact.source_run_id
                    in {run.id for run in linked_runs}
                    or (
                        recipe is not None
                        and artifact.extra.get("recipe_sha256")
                        == recipe.recipe_sha256
                    )
                )
            )
        ]

        if experiment.status in {
            ExperimentStatus.REGISTERED,
            ExperimentStatus.RUNNING,
        }:
            if (
                experiment.result is not None
                or experiment.artifact_ids != [payload.id]
                or experiment.evidence_fact_ids
                or experiment.evidence_run_ids
                or experiment.evidence_receipt_ids
                or experiment.evaluation_reason is not None
                or experiment.evaluated_at is not None
                or linked_runs
                or linked_receipts
                or linked_artifacts
                or (
                    experiment.status is ExperimentStatus.REGISTERED
                    and raw_recipe is not None
                )
                or (
                    experiment.status is ExperimentStatus.RUNNING
                    and recipe is None
                )
            ):
                errors.append(
                    f"{label} active lifecycle/evidence is inconsistent"
                )
            continue

        result = experiment.result
        has_gate_evidence = (
            type(result) is dict
            and set(result) == {_PWN_CRASH_RESULT_KEY}
        )
        if not has_gate_evidence:
            if raw_recipe is not None and recipe is None:
                # A malformed recipe was already reported above.
                continue
            errors.extend(
                _pwn_crash_precommit_failure_errors(
                    experiment,
                    payload=payload,
                    linked_runs=linked_runs,
                    linked_receipts=linked_receipts,
                    linked_artifacts=linked_artifacts,
                )
            )
            continue
        if recipe is None:
            errors.append(f"{label} terminal evidence lacks its recipe")
            continue

        raw_evidence = result[_PWN_CRASH_RESULT_KEY]
        if (
            type(raw_evidence) is not dict
            or set(raw_evidence) != _PWN_CRASH_EVIDENCE_KEYS
        ):
            errors.append(f"{label} result envelope is not canonical")
            continue
        evaluation, evaluation_errors = _pwn_crash_gate_binding(
            raw_evidence.get("evaluation"),
            recipe=recipe,
        )
        errors.extend(f"{label}: {item}" for item in evaluation_errors)
        attempts = raw_evidence.get("attempts")
        evaluated_at = raw_evidence.get("evaluated_at")
        if (
            type(raw_evidence.get("schema_version")) is not int
            or raw_evidence.get("schema_version") != 1
            or raw_evidence.get("protocol") != PWN_CRASH_V1_PROTOCOL
            or raw_evidence.get("recipe_sha256")
            != recipe.recipe_sha256
            or not _proof_binding_utc_timestamp(evaluated_at)
            or type(attempts) is not list
            or len(attempts) != PWN_CRASH_V1_ATTEMPT_COUNT
        ):
            errors.append(f"{label} result envelope values are invalid")
            continue
        if evaluation is None:
            continue
        if (
            raw_evidence.get("evaluation_sha256")
            != evaluation.evidence_sha256
        ):
            errors.append(f"{label} evaluation hash does not match")
        expected_status = {
            "CONFIRMED": ExperimentStatus.KEPT,
            "INCONCLUSIVE": ExperimentStatus.INCONCLUSIVE,
            "ERROR": ExperimentStatus.FAILED,
        }.get(evaluation.verdict.value)
        if (
            expected_status is None
            or experiment.status is not expected_status
            or experiment.evaluation_reason
            != (
                "pwn_crash:"
                f"{evaluation.verdict.value}:"
                f"{evaluation.reason_code}"
            )[:512]
            or experiment.evaluated_at != evaluated_at
            or experiment.evidence_fact_ids
        ):
            errors.append(f"{label} verdict/status metadata is inconsistent")

        attempt_errors, capability_id = (
            _pwn_crash_attempt_graph_errors(
                experiment,
                recipe=recipe,
                source_run=source_run,
                attempts=attempts,
                runs=runs,
                receipts=receipts,
                artifacts=artifacts,
                artifacts_by_run=artifacts_by_run,
            )
        )
        errors.extend(attempt_errors)
        run_ids = [
            item.get("run_id")
            for item in attempts
            if isinstance(item, Mapping)
        ]
        receipt_ids = [
            item.get("receipt_id")
            for item in attempts
            if isinstance(item, Mapping)
        ]
        stdout_ids = [
            item.get("stdout_artifact_id")
            for item in attempts
            if isinstance(item, Mapping)
        ]
        if (
            experiment.evidence_run_ids != run_ids
            or experiment.evidence_receipt_ids != receipt_ids
            or experiment.artifact_ids != [payload.id, *stdout_ids]
            or {item.id for item in linked_receipts}
            != set(receipt_ids)
            or len(linked_receipts) != PWN_CRASH_V1_ATTEMPT_COUNT
        ):
            errors.append(f"{label} evidence lists are not exact")

        hypothesis = hypotheses.get(recipe.hypothesis_id)
        if hypothesis is not None:
            evidence_sets = (
                (hypothesis.evidence_run_ids, run_ids),
                (hypothesis.evidence_receipt_ids, receipt_ids),
                (hypothesis.evidence_artifact_ids, stdout_ids),
            )
            if evaluation.verdict.value == "CONFIRMED":
                if any(
                    not set(expected).issubset(actual)
                    for actual, expected in evidence_sets
                ):
                    errors.append(
                        f"{label} does not support its hypothesis with all "
                        "six evidence chains"
                    )
            elif any(
                not set(actual).isdisjoint(expected)
                for actual, expected in evidence_sets
            ):
                errors.append(
                    f"{label} non-confirmation promoted its hypothesis"
                )

        if capability_id is None:
            errors.append(f"{label} lacks a capability attestation link")
        else:
            try:
                from ctf_os.engine.pwn_crash import (
                    PwnCrashCapabilityAttestation,
                )

                expected_attestation = PwnCrashCapabilityAttestation(
                    image_digest=recipe.image_digest,
                    recipe_sha256=recipe.recipe_sha256,
                )
                capability = artifacts.get(capability_id)
                if (
                    capability is None
                    or capability.source_run_id is not None
                    or capability.sha256
                    != expected_attestation.evidence_sha256
                    or capability.size
                    != len(expected_attestation.canonical_bytes())
                    or capability.media_type != "application/json"
                    or capability.extra
                    != {
                        "kind": "pwn_crash_capability_attestation",
                        "engine_executor": _PWN_CRASH_ENGINE_EXECUTOR,
                        "recipe_sha256": recipe.recipe_sha256,
                    }
                    or capability.id in experiment.artifact_ids
                ):
                    errors.append(
                        f"{label} capability attestation artifact is invalid"
                    )
            except (ImportError, TypeError, ValueError) as error:
                errors.append(
                    f"{label} capability attestation is invalid: {error}"
                )
        terminal_recipe_hashes.add(recipe.recipe_sha256)

    for artifact in state.artifacts:
        if not _pwn_crash_artifact_marker(artifact):
            continue
        if artifact.source_run_id is not None:
            if artifact.source_run_id not in marked_run_ids:
                errors.append(
                    f"Pwn crash artifact {artifact.id} has no typed run"
                )
        elif (
            artifact.extra.get("recipe_sha256")
            not in terminal_recipe_hashes
        ):
            errors.append(
                f"Pwn crash capability artifact {artifact.id} is orphaned"
            )

    pwn_artifact_ids = {
        artifact.id
        for artifact in state.artifacts
        if _pwn_crash_artifact_marker(artifact)
    }
    for fact in facts.values():
        if (
            "pwn_crash" in fact.extra
            or fact.source_run_id in marked_run_ids
            or fact.artifact_id in pwn_artifact_ids
        ):
            errors.append(
                f"Pwn crash evidence cannot be copied into Fact {fact.id}"
            )
    return errors


_PWN_RUNTIME_SNAPSHOT_ENGINE_COMMAND = (
    "ctfos-engine:pwn-runtime-snapshot-v1"
)
_PWN_RUNTIME_SNAPSHOT_ENGINE_EXECUTOR = "pwn_runtime_snapshot_v1"
_PWN_RUNTIME_SNAPSHOT_RESULT_KEY = "pwn_runtime_snapshot_evidence"
_PWN_RUNTIME_SNAPSHOT_EXPECTED_OBSERVATION = (
    "capture exact registers and mappings at the confirmed crash signal"
)
_PWN_RUNTIME_SNAPSHOT_KEEP_CONDITION = (
    "typed runtime snapshot result is CAPTURED"
)
_PWN_RUNTIME_SNAPSHOT_DROP_CONDITION = (
    "typed runtime snapshot result is INCONCLUSIVE or ERROR"
)
_PWN_RUNTIME_SNAPSHOT_EXPERIMENT_EXTRA_KEYS = frozenset(
    {
        "managed_contract_version",
        "engine_executor",
        "parent_experiment_id",
        "pwn_runtime_snapshot_recipe",
    }
)
_PWN_RUNTIME_SNAPSHOT_DISCLOSURE_KEY = "pwn_disclosure"
_PWN_RUNTIME_SNAPSHOT_V2_EXPERIMENT_EXTRA_KEYS = (
    _PWN_RUNTIME_SNAPSHOT_EXPERIMENT_EXTRA_KEYS
    | {_PWN_RUNTIME_SNAPSHOT_DISCLOSURE_KEY}
)
_PWN_RUNTIME_SNAPSHOT_RECOVERY_EXTRA_KEYS = frozenset(
    {"orphan_recovered_at", "orphan_recovery"}
)
_PWN_RUNTIME_SNAPSHOT_RESULT_KEYS = frozenset(
    {
        "schema_version",
        "protocol",
        "recipe_sha256",
        "evaluated_at",
        "evaluation",
        "evaluation_sha256",
        "run_id",
        "receipt_id",
        "capability_attestation_artifact_id",
        "stdout_artifact_id",
        "stderr_artifact_id",
    }
)
_PWN_RUNTIME_SNAPSHOT_RECORD_KEYS = frozenset(
    {
        "recipe_sha256",
        "request_sha256",
        "execution_contract",
        "execution_contract_sha256",
        "receipt",
    }
)
_PWN_RUNTIME_SNAPSHOT_EXECUTION_KEYS = frozenset(
    {
        "schema_version",
        "engine_executor",
        "protocol",
        "recipe_sha256",
        "configuration_epoch",
        "parent_experiment_id",
        "child_experiment_id",
        "source",
        "payload",
        "argv",
        "sandbox",
        "producer",
    }
)
_PWN_RUNTIME_SNAPSHOT_EXECUTION_SOURCE_KEYS = frozenset(
    {"locator", "manifest_sha256", "sha256", "size_bytes"}
)
_PWN_RUNTIME_SNAPSHOT_EXECUTION_PAYLOAD_KEYS = frozenset(
    {
        "artifact_id",
        "source_run_id",
        "sha256",
        "size_bytes",
        "destination_locator",
    }
)
_PWN_RUNTIME_SNAPSHOT_EXECUTION_SANDBOX_KEYS = frozenset(
    {
        "method",
        "one_shot",
        "outer_timeout_seconds",
        "resource_request",
        "image",
        "network",
        "network_target",
    }
)
_PWN_RUNTIME_SNAPSHOT_EXECUTION_IMAGE_KEYS = frozenset(
    {"reference", "digest"}
)
_PWN_RUNTIME_SNAPSHOT_EXECUTION_PRODUCER_KEYS = frozenset(
    {
        "interpreter_path",
        "path",
        "capability_name",
        "file_sha256",
        "capability_attestation_artifact_id",
        "capability_attestation_sha256",
    }
)


def _pwn_runtime_snapshot_experiment_marker(
    experiment: Experiment,
) -> bool:
    result = experiment.result
    return (
        experiment.command == _PWN_RUNTIME_SNAPSHOT_ENGINE_COMMAND
        or experiment.extra.get("engine_executor")
        == _PWN_RUNTIME_SNAPSHOT_ENGINE_EXECUTOR
        or "pwn_runtime_snapshot_recipe" in experiment.extra
        or _PWN_RUNTIME_SNAPSHOT_DISCLOSURE_KEY in experiment.extra
        or (
            isinstance(result, Mapping)
            and _PWN_RUNTIME_SNAPSHOT_RESULT_KEY in result
        )
    )


def _pwn_runtime_snapshot_run_marker(run: RunReference) -> bool:
    return (
        run.role == "pwn_runtime_snapshot"
        or "pwn_runtime_snapshot" in run.extra
    )


def _pwn_runtime_snapshot_artifact_marker(
    artifact: ArtifactReference,
) -> bool:
    return (
        artifact.extra.get("engine_executor")
        == _PWN_RUNTIME_SNAPSHOT_ENGINE_EXECUTOR
        or artifact.extra.get("kind")
        == "pwn_runtime_snapshot_capability_attestation"
    )


def _pwn_runtime_snapshot_recipe_binding(
    state: "ChallengeState",
    child: Experiment,
    *,
    experiments: Mapping[str, Experiment],
    runs: Mapping[str, RunReference],
    artifacts: Mapping[str, ArtifactReference],
) -> tuple[Any | None, Experiment | None, ArtifactReference | None, list[str]]:
    """Bind one diagnostic recipe to an unchanged confirmed crash graph."""

    label = f"Pwn runtime snapshot experiment {child.id}"
    errors: list[str] = []
    if type(child.extra) is not dict:
        return None, None, None, [
            f"{label} has missing or unknown engine-owned fields"
        ]
    extra_keys = set(child.extra)
    managed_contract_version = child.extra.get(
        "managed_contract_version"
    )
    expected_extra_keys = (
        _PWN_RUNTIME_SNAPSHOT_EXPERIMENT_EXTRA_KEYS
        if managed_contract_version == 1
        else _PWN_RUNTIME_SNAPSHOT_V2_EXPERIMENT_EXTRA_KEYS
        if managed_contract_version == 2
        else frozenset()
    )
    has_recovery = (
        extra_keys
        == (
            expected_extra_keys
            | _PWN_RUNTIME_SNAPSHOT_RECOVERY_EXTRA_KEYS
        )
    )
    if (
        not (
            expected_extra_keys
            and (
                extra_keys == expected_extra_keys
                or has_recovery
            )
        )
        or (
            has_recovery
            and (
                child.status is not ExperimentStatus.FAILED
                or type(child.result) is not dict
                or set(child.result) != {"error"}
                or type(child.result.get("error")) is not str
                or not child.result["error"].startswith(
                    "Pwn runtime snapshot failed closed: orphaned "
                )
                or not _proof_binding_utc_timestamp(
                    child.extra.get("orphan_recovered_at")
                )
                or child.extra.get("orphan_recovery")
                != "failed_closed_without_canonical_evidence"
            )
        )
    ):
        return None, None, None, [
            f"{label} has missing or unknown engine-owned fields"
        ]
    raw_recipe = child.extra.get("pwn_runtime_snapshot_recipe")
    try:
        from ctf_os.engine.pwn_crash import (
            PwnCrashGateEvaluation,
            PwnCrashRecipe,
        )
        from ctf_os.engine.pwn_runtime_snapshot import (
            PWN_RUNTIME_SNAPSHOT_PRODUCER_FILE_SHA256,
            PwnRuntimeSnapshotRecipe,
            pwn_runtime_snapshot_child_experiment_id,
        )

        if type(raw_recipe) is not dict:
            raise ValueError("recipe is not an exact object")
        recipe = PwnRuntimeSnapshotRecipe.from_dict(raw_recipe)
    except (ImportError, KeyError, TypeError, ValueError) as error:
        return None, None, None, [
            f"{label} recipe is invalid: {error}"
        ]

    parent_id = child.extra.get("parent_experiment_id")
    parent = (
        experiments.get(parent_id)
        if isinstance(parent_id, str)
        else None
    )
    if (
        state.schema_version < STATE_SCHEMA_VERSION
        or state.category.strip().casefold() != "pwn"
        or child.id
        != pwn_runtime_snapshot_child_experiment_id(
            recipe.parent_experiment_id
        )
        or parent_id != recipe.parent_experiment_id
        or managed_contract_version not in {1, 2}
        or child.extra.get("engine_executor")
        != _PWN_RUNTIME_SNAPSHOT_ENGINE_EXECUTOR
        or child.kind is not ExperimentKind.PROBE
        or child.command != _PWN_RUNTIME_SNAPSHOT_ENGINE_COMMAND
        or child.hypothesis_ids
        or child.proof_recipe is not None
        or child.expected_observation
        != _PWN_RUNTIME_SNAPSHOT_EXPECTED_OBSERVATION
        or child.keep_if != _PWN_RUNTIME_SNAPSHOT_KEEP_CONDITION
        or child.drop_if != _PWN_RUNTIME_SNAPSHOT_DROP_CONDITION
        or child.resource_class != "standard"
        or child.evaluation_reason is not None
        or child.evaluated_at is not None
        or recipe.producer_file_sha256
        != PWN_RUNTIME_SNAPSHOT_PRODUCER_FILE_SHA256
        or recipe.configuration_epoch != state.configuration_epoch
    ):
        errors.append(f"{label} lacks its exact diagnostic identity")

    if (
        parent is None
        or not _pwn_crash_experiment_marker(parent)
        or parent.status is not ExperimentStatus.KEPT
    ):
        errors.append(
            f"{label} does not bind one confirmed Pwn crash parent"
        )
        return recipe, parent, None, errors

    expected_timeout = max(
        parent.timeout_seconds,
        int(PWN_RUNTIME_SNAPSHOT_V1_TARGET_TIMEOUT_SECONDS) + 10,
    )
    if child.timeout_seconds != expected_timeout:
        errors.append(f"{label} timeout is not engine-derived")

    parent_recipe = None
    parent_evaluation = None
    parent_evidence = (
        parent.result.get(_PWN_CRASH_RESULT_KEY)
        if type(parent.result) is dict
        and set(parent.result) == {_PWN_CRASH_RESULT_KEY}
        else None
    )
    try:
        raw_parent_recipe = parent.extra.get("pwn_crash_recipe")
        if type(raw_parent_recipe) is not dict:
            raise ValueError("parent recipe is absent")
        parent_recipe = PwnCrashRecipe.from_dict(raw_parent_recipe)
        if (
            type(parent_evidence) is not dict
            or set(parent_evidence) != _PWN_CRASH_EVIDENCE_KEYS
            or type(parent_evidence.get("evaluation")) is not dict
        ):
            raise ValueError("parent evidence is not canonical")
        parent_evaluation = PwnCrashGateEvaluation.from_dict(
            parent_evidence["evaluation"]
        )
    except (KeyError, TypeError, ValueError) as error:
        errors.append(f"{label} parent evidence is invalid: {error}")

    payload = artifacts.get(recipe.payload_artifact_id)
    source_run = runs.get(recipe.payload_source_run_id)
    manifest = state.metadata.get("source_manifest_sha256")
    primary_locator = state.metadata.get("adapter_primary_source")
    matching_sources = [
        source
        for source in state.source_inventory
        if source.path == primary_locator
    ]
    if (
        payload is None
        or source_run is None
        or source_run.status is not RunStatus.COMPLETED
        or source_run.origin is not RunOrigin.MANAGED_MODEL
        or source_run.role != "builder"
        or source_run.configuration_epoch != recipe.configuration_epoch
        or source_run.extra.get("semantic_merge") is not True
        or payload.source_run_id != source_run.id
        or payload.path != recipe.payload_artifact_locator
        or payload.sha256 != recipe.payload_sha256
        or payload.size != recipe.payload_size_bytes
        or child.source_run_id != source_run.id
    ):
        errors.append(f"{label} payload/Builder binding changed")
    if (
        not _proof_binding_sha256(manifest)
        or not isinstance(primary_locator, str)
        or len(matching_sources) != 1
        or matching_sources[0].kind != "file"
        or matching_sources[0].sha256 != recipe.source_sha256
        or matching_sources[0].size != recipe.source_size_bytes
        or recipe.primary_elf_locator != primary_locator
        or recipe.source_manifest_sha256 != manifest
    ):
        errors.append(f"{label} immutable source binding changed")

    if parent_recipe is not None and (
        recipe.configuration_epoch != parent_recipe.configuration_epoch
        or recipe.primary_elf_locator
        != parent_recipe.primary_elf_locator
        or recipe.source_manifest_sha256
        != parent_recipe.source_manifest_sha256
        or recipe.source_sha256 != parent_recipe.source_sha256
        or recipe.source_size_bytes != parent_recipe.source_size_bytes
        or recipe.payload_artifact_id
        != parent_recipe.payload_artifact_id
        or recipe.payload_source_run_id
        != parent_recipe.payload_source_run_id
        or recipe.payload_artifact_locator
        != parent_recipe.payload_artifact_locator
        or recipe.payload_sha256 != parent_recipe.payload_sha256
        or recipe.payload_size_bytes
        != parent_recipe.payload_size_bytes
        or recipe.parent_crash_recipe_sha256
        != parent_recipe.recipe_sha256
        or recipe.image_reference != parent_recipe.image_reference
        or recipe.image_digest != parent_recipe.image_digest
    ):
        errors.append(f"{label} parent recipe binding changed")

    if parent_evaluation is not None:
        semantic = parent_evaluation.semantic_evaluation
        counts = (
            semantic.positive_signal_counts
            if semantic is not None
            else ()
        )
        maximum = max((count for _signal, count in counts), default=0)
        expected_signals = [
            signal
            for signal, count in counts
            if count == maximum and count >= 2
        ]
        if (
            parent_evaluation.verdict.value != "CONFIRMED"
            or len(expected_signals) != 1
            or recipe.expected_signal_number != expected_signals[0]
            or recipe.parent_crash_evaluation_sha256
            != parent_evaluation.evidence_sha256
            or parent_evidence is None
            or parent_evidence.get("evaluation_sha256")
            != parent_evaluation.evidence_sha256
        ):
            errors.append(f"{label} parent gate binding changed")
    return recipe, parent, payload, errors


def _pwn_runtime_snapshot_canonical_sha256(
    value: object,
) -> str | None:
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
    except (RecursionError, TypeError, UnicodeError, ValueError):
        return None
    if len(encoded) > 256 * 1024:
        return None
    return hashlib.sha256(encoded).hexdigest()


def _pwn_runtime_snapshot_execution_contract_errors(
    value: object,
    *,
    supplied_sha256: object,
    child: Experiment,
    recipe: Any,
    capability: ArtifactReference,
) -> list[str]:
    """Reconstruct the fixed clean, networkless one-shot invocation."""

    label = f"Pwn runtime snapshot experiment {child.id}"
    if (
        type(value) is not dict
        or set(value) != _PWN_RUNTIME_SNAPSHOT_EXECUTION_KEYS
    ):
        return [f"{label} execution contract is not exact"]
    source = value.get("source")
    payload = value.get("payload")
    sandbox = value.get("sandbox")
    producer = value.get("producer")
    image = (
        sandbox.get("image")
        if type(sandbox) is dict
        else None
    )
    if (
        type(source) is not dict
        or set(source)
        != _PWN_RUNTIME_SNAPSHOT_EXECUTION_SOURCE_KEYS
        or type(payload) is not dict
        or set(payload)
        != _PWN_RUNTIME_SNAPSHOT_EXECUTION_PAYLOAD_KEYS
        or type(sandbox) is not dict
        or set(sandbox)
        != _PWN_RUNTIME_SNAPSHOT_EXECUTION_SANDBOX_KEYS
        or type(image) is not dict
        or set(image) != _PWN_RUNTIME_SNAPSHOT_EXECUTION_IMAGE_KEYS
        or type(producer) is not dict
        or set(producer)
        != _PWN_RUNTIME_SNAPSHOT_EXECUTION_PRODUCER_KEYS
    ):
        return [f"{label} execution contract nested schema is not exact"]
    computed_sha256 = _pwn_runtime_snapshot_canonical_sha256(value)
    if (
        computed_sha256 is None
        or not _proof_binding_sha256(supplied_sha256)
        or supplied_sha256 != computed_sha256
    ):
        return [f"{label} execution contract hash does not match"]
    try:
        from ctf_os.director.resources import tool_profile
        from ctf_os.engine.pwn_runtime_snapshot import (
            PWN_RUNTIME_SNAPSHOT_INPUT_DESTINATION_LOCATOR,
            PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY,
            PWN_RUNTIME_SNAPSHOT_ONE_SHOT,
            PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME,
            PWN_RUNTIME_SNAPSHOT_PRODUCER_INTERPRETER_PATH,
            PWN_RUNTIME_SNAPSHOT_PRODUCER_PATH,
            PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD,
        )

        expected_resource = tool_profile(
            child.resource_class,
            needs_kvm=False,
            network=False,
        ).as_dict()
    except (ImportError, KeyError, TypeError, ValueError) as error:
        return [f"{label} execution policy cannot be rebuilt: {error}"]
    outer_timeout = sandbox.get("outer_timeout_seconds")
    expected = {
        "schema_version": 1,
        "engine_executor": _PWN_RUNTIME_SNAPSHOT_ENGINE_EXECUTOR,
        "protocol": PWN_RUNTIME_SNAPSHOT_V1_PROTOCOL,
        "recipe_sha256": recipe.recipe_sha256,
        "configuration_epoch": recipe.configuration_epoch,
        "parent_experiment_id": recipe.parent_experiment_id,
        "child_experiment_id": recipe.child_experiment_id,
        "source": {
            "locator": recipe.primary_elf_locator,
            "manifest_sha256": recipe.source_manifest_sha256,
            "sha256": recipe.source_sha256,
            "size_bytes": recipe.source_size_bytes,
        },
        "payload": {
            "artifact_id": recipe.payload_artifact_id,
            "source_run_id": recipe.payload_source_run_id,
            "sha256": recipe.payload_sha256,
            "size_bytes": recipe.payload_size_bytes,
            "destination_locator": (
                PWN_RUNTIME_SNAPSHOT_INPUT_DESTINATION_LOCATOR
            ),
        },
        "argv": list(recipe.argv()),
        "sandbox": {
            "method": PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD,
            "one_shot": PWN_RUNTIME_SNAPSHOT_ONE_SHOT,
            "outer_timeout_seconds": outer_timeout,
            "resource_request": expected_resource,
            "image": {
                "reference": recipe.image_reference,
                "digest": recipe.image_digest,
            },
            "network": PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY,
            "network_target": None,
        },
        "producer": {
            "interpreter_path": (
                PWN_RUNTIME_SNAPSHOT_PRODUCER_INTERPRETER_PATH
            ),
            "path": PWN_RUNTIME_SNAPSHOT_PRODUCER_PATH,
            "capability_name": (
                PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME
            ),
            "file_sha256": recipe.producer_file_sha256,
            "capability_attestation_artifact_id": capability.id,
            "capability_attestation_sha256": capability.sha256,
        },
    }
    if (
        type(outer_timeout) is not int
        or not 1 <= outer_timeout <= child.timeout_seconds
        or value != expected
    ):
        return [f"{label} execution policy binding changed"]
    return []


def _pwn_runtime_snapshot_terminal_errors(
    child: Experiment,
    *,
    recipe: Any,
    payload: ArtifactReference,
    linked_runs: list[RunReference],
    linked_receipts: list[ExecutionReceipt],
    linked_artifacts: list[ArtifactReference],
    source_run: RunReference,
) -> tuple[list[str], set[str]]:
    """Validate the one-run diagnostic graph and return its artifact ids."""

    label = f"Pwn runtime snapshot experiment {child.id}"
    errors: list[str] = []
    result = child.result
    evidence = (
        result.get(_PWN_RUNTIME_SNAPSHOT_RESULT_KEY)
        if type(result) is dict
        and set(result) == {_PWN_RUNTIME_SNAPSHOT_RESULT_KEY}
        else None
    )
    if (
        type(evidence) is not dict
        or set(evidence) != _PWN_RUNTIME_SNAPSHOT_RESULT_KEYS
    ):
        return [f"{label} result envelope is not exact"], set()
    if len(linked_runs) != 1 or len(linked_receipts) != 1:
        return [
            f"{label} must own exactly one run and receipt"
        ], set()
    run = linked_runs[0]
    receipt = linked_receipts[0]
    stdout_id = evidence.get("stdout_artifact_id")
    stderr_id = evidence.get("stderr_artifact_id")
    capability_id = evidence.get(
        "capability_attestation_artifact_id"
    )
    artifact_map = {artifact.id: artifact for artifact in linked_artifacts}
    stdout = (
        artifact_map.get(stdout_id)
        if isinstance(stdout_id, str)
        else None
    )
    stderr = (
        artifact_map.get(stderr_id)
        if isinstance(stderr_id, str)
        else None
    )
    capability = (
        artifact_map.get(capability_id)
        if isinstance(capability_id, str)
        else None
    )
    expected_ids = {
        value
        for value in (stdout_id, stderr_id, capability_id)
        if isinstance(value, str)
    }
    if (
        stdout is None
        or stderr is None
        or capability is None
        or len(expected_ids) != 3
        or {artifact.id for artifact in linked_artifacts}
        != expected_ids
    ):
        return [
            f"{label} does not own exact stdout/stderr/capability artifacts"
        ], expected_ids

    try:
        from ctf_os.engine.pwn_runtime_snapshot import (
            PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY,
            PWN_RUNTIME_SNAPSHOT_ONE_SHOT,
            PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME,
            PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD,
            PwnRuntimeSnapshotCapabilityAttestation,
            PwnRuntimeSnapshotGateEvaluation,
            PwnRuntimeSnapshotReceiptMetadata,
        )

        raw_evaluation = evidence.get("evaluation")
        if type(raw_evaluation) is not dict:
            raise ValueError("evaluation is not an exact object")
        evaluation = PwnRuntimeSnapshotGateEvaluation.from_dict(
            raw_evaluation,
            recipe=recipe,
        )
        raw_run_record = run.extra.get("pwn_runtime_snapshot")
        raw_receipt_record = receipt.extra.get(
            "pwn_runtime_snapshot"
        )
        if (
            type(raw_run_record) is not dict
            or set(raw_run_record) != _PWN_RUNTIME_SNAPSHOT_RECORD_KEYS
            or raw_receipt_record != raw_run_record
        ):
            raise ValueError("run/receipt record is not exact")
        metadata = PwnRuntimeSnapshotReceiptMetadata.from_dict(
            raw_run_record["receipt"]
        )
        expected_capability = PwnRuntimeSnapshotCapabilityAttestation(
            image_digest=recipe.image_digest,
            recipe_sha256=recipe.recipe_sha256,
        )
    except (ImportError, KeyError, TypeError, ValueError) as error:
        return [f"{label} terminal contract is invalid: {error}"], expected_ids

    evaluated_at = evidence.get("evaluated_at")
    if (
        evidence.get("schema_version") != 1
        or evidence.get("protocol") != PWN_RUNTIME_SNAPSHOT_V1_PROTOCOL
        or evidence.get("recipe_sha256") != recipe.recipe_sha256
        or not _proof_binding_utc_timestamp(evaluated_at)
        or evidence.get("evaluation_sha256")
        != evaluation.evidence_sha256
        or evidence.get("run_id") != run.id
        or evidence.get("receipt_id") != receipt.id
        or child.status is not ExperimentStatus.COMPLETED
        or child.result is not result
        or child.artifact_ids
        != [payload.id, stdout.id, stderr.id]
        or child.evidence_run_ids != [run.id]
        or child.evidence_receipt_ids != [receipt.id]
        or child.evidence_fact_ids
        or child.evaluation_reason is not None
        or child.evaluated_at is not None
    ):
        errors.append(f"{label} result/evidence lists are inconsistent")

    run_record = run.extra.get("pwn_runtime_snapshot")
    assert isinstance(run_record, dict)
    errors.extend(
        _pwn_runtime_snapshot_execution_contract_errors(
            run_record.get("execution_contract"),
            supplied_sha256=run_record.get(
                "execution_contract_sha256"
            ),
            child=child,
            recipe=recipe,
            capability=capability,
        )
    )
    expected_run_extra = {
        "experiment_id": child.id,
        "pwn_runtime_snapshot": run_record,
    }
    if (
        run.extra != expected_run_extra
        or run.role != "pwn_runtime_snapshot"
        or run.origin is not RunOrigin.MANAGED_TOOL
        or run.configuration_epoch != recipe.configuration_epoch
        or run.session_id != source_run.session_id
        or run.cycle_id != source_run.cycle_id
        or run.wave_id != source_run.wave_id
        or not _pwn_crash_safe_locator(run.request_path)
        or not _pwn_crash_safe_locator(run.result_path)
        or not _pwn_crash_safe_locator(run.validation_path)
        or run.model is not None
        or run.context_hash is not None
        or run.status
        is not {
            "succeeded": RunStatus.COMPLETED,
            "failed": RunStatus.FAILED,
            "timed_out": RunStatus.TIMED_OUT,
        }.get(metadata.outcome)
    ):
        errors.append(f"{label} run identity/provenance is inconsistent")

    expected_outcome = {
        "succeeded": ReceiptOutcome.SUCCEEDED,
        "failed": ReceiptOutcome.FAILED,
        "timed_out": ReceiptOutcome.TIMED_OUT,
    }.get(metadata.outcome)
    if (
        receipt.extra != {"pwn_runtime_snapshot": run_record}
        or receipt.id != metadata.receipt_id
        or receipt.run_id != metadata.run_id
        or receipt.experiment_id != child.id
        or receipt.outcome is not expected_outcome
        or receipt.exit_code != metadata.exit_code
        or receipt.stdout_artifact_id != stdout.id
        or receipt.stderr_artifact_id != stderr.id
        or receipt.stdout_bytes != metadata.stdout_drained_bytes
        or receipt.stderr_bytes != stderr.size
        or receipt.stdout_lines != 0
        or receipt.stderr_lines != 0
        or receipt.preview
        != (
            "Pwn runtime snapshot "
            f"{evaluation.status.value}:{evaluation.reason_code}"
        )[:160]
        or metadata.timed_out
        is not (metadata.outcome == "timed_out")
        or metadata.recipe_sha256 != recipe.recipe_sha256
        or metadata.request_sha256 != run_record.get("request_sha256")
        or metadata.execution_contract_sha256
        != run_record.get("execution_contract_sha256")
        or metadata.configuration_epoch != recipe.configuration_epoch
        or metadata.image_digest != recipe.image_digest
        or metadata.clean_workspace is not True
        or metadata.one_shot is not PWN_RUNTIME_SNAPSHOT_ONE_SHOT
        or metadata.sandbox_method != PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD
        or metadata.network != PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY
        or metadata.producer_capability_name
        != PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME
        or metadata.producer_file_sha256
        != recipe.producer_file_sha256
        or metadata.capability_attestation_artifact_id != capability.id
        or metadata.capability_attestation_sha256 != capability.sha256
        or metadata.stdout_artifact_id != stdout.id
        or metadata.stdout_artifact_sha256 != stdout.sha256
        or metadata.stdout_artifact_size_bytes != stdout.size
        or metadata.stderr_artifact_id != stderr.id
        or metadata.stderr_artifact_sha256 != stderr.sha256
        or metadata.stderr_artifact_size_bytes != stderr.size
        or metadata.stderr_capture_placeholder
        is not stderr.extra.get("capture_placeholder")
    ):
        errors.append(f"{label} receipt binding is inconsistent")

    if (
        capability.source_run_id is not None
        or capability.sha256 != expected_capability.evidence_sha256
        or capability.size != len(expected_capability.canonical_bytes())
        or capability.media_type != "application/json"
        or capability.extra
        != {
            "kind": "pwn_runtime_snapshot_capability_attestation",
            "engine_executor": _PWN_RUNTIME_SNAPSHOT_ENGINE_EXECUTOR,
            "recipe_sha256": recipe.recipe_sha256,
        }
        or capability.id in child.artifact_ids
    ):
        errors.append(f"{label} capability artifact is invalid")
    expected_root = (
        "artifacts/snapshots/"
        f"pwn-runtime-snapshot-{recipe.recipe_sha256}"
    )
    if capability.path != f"{expected_root}/capability-attestation.json":
        errors.append(f"{label} capability artifact path is invalid")
    for stream, artifact in (("stdout", stdout), ("stderr", stderr)):
        placeholder = artifact.extra.get("capture_placeholder")
        if (
            artifact.source_run_id != run.id
            or not _proof_binding_sha256(artifact.sha256)
            or type(artifact.size) is not int
            or artifact.size < 0
            or type(placeholder) is not bool
            or artifact.extra
            != {
                "stream": stream,
                "engine_executor": (
                    _PWN_RUNTIME_SNAPSHOT_ENGINE_EXECUTOR
                ),
                "recipe_sha256": recipe.recipe_sha256,
                "capture_placeholder": placeholder,
            }
            or (placeholder and artifact.size != 0)
            or (
                placeholder
                and artifact.sha256
                != hashlib.sha256(b"").hexdigest()
            )
            or artifact.path
            != f"{expected_root}/{run.id}-{stream}.log"
            or artifact.media_type
            != (
                "application/json"
                if stream == "stdout"
                else "text/plain"
            )
        ):
            errors.append(
                f"{label} {stream} artifact binding is inconsistent"
            )
    if (
        stdout.extra.get("capture_placeholder") is True
        and (
            metadata.durable_stdout_artifact_complete
            or metadata.stdout_capture_complete
            or metadata.stream_capture_error is None
        )
    ):
        errors.append(
            f"{label} stdout placeholder metadata is inconsistent"
        )
    semantic_result = evaluation.semantic_result
    if semantic_result is not None:
        semantic_bytes = semantic_result.canonical_bytes()
        if (
            metadata.outcome != "succeeded"
            or metadata.exit_code != 0
            or metadata.timed_out
            or metadata.orchestration_error is not None
            or not metadata.stdout_capture_complete
            or not metadata.stdout_truncation_known
            or metadata.stdout_truncated is not False
            or metadata.stdout_error is not None
            or metadata.stream_capture_error is not None
            or not metadata.durable_stdout_artifact_complete
            or stdout.extra.get("capture_placeholder") is not False
            or stdout.sha256
            != hashlib.sha256(semantic_bytes).hexdigest()
            or stdout.size != len(semantic_bytes)
            or metadata.stdout_drained_bytes != len(semantic_bytes)
            or metadata.stdout_stored_bytes != len(semantic_bytes)
        ):
            errors.append(
                f"{label} semantic gate/stdout binding is inconsistent"
            )
    return errors, expected_ids


def _pwn_runtime_snapshot_disclosure_errors(
    state: "ChallengeState",
    child: Experiment,
    *,
    parent: Experiment,
    snapshot_recipe: Any,
    receipts: Mapping[str, ExecutionReceipt],
    state_revision: int,
) -> list[str]:
    """Validate only persisted disclosure structure and canonical crosslinks.

    Artifact bytes are intentionally out of scope here.  A filesystem-backed
    engine validator must reread those bytes, recompute the exact result, and
    compare it before completing the lifecycle.
    """

    label = f"Pwn runtime snapshot experiment {child.id} disclosure"
    version = child.extra.get("managed_contract_version")
    if version == 1:
        return []
    if version != 2:
        return [f"{label} has an unsupported managed contract version"]
    try:
        envelope = PwnRuntimeSnapshotDisclosureEnvelope.from_dict(
            child.extra.get(_PWN_RUNTIME_SNAPSHOT_DISCLOSURE_KEY)
        )
        envelope.validate_state_revision(state_revision)
    except (ModelValidationError, TypeError, ValueError) as error:
        return [f"{label} envelope is invalid: {error}"]

    if (
        child.status is not ExperimentStatus.COMPLETED
        and envelope.phase
        is not PwnDisclosurePhase.AWAITING_EXPECTATION
    ):
        return [
            f"{label} cannot advance before the runtime snapshot completes"
        ]
    if envelope.phase is PwnDisclosurePhase.AWAITING_EXPECTATION:
        return []

    try:
        from ctf_os.engine.pwn_crash import (
            PwnCrashGateEvaluation,
            PwnCrashReceiptMetadata,
            PwnCrashRecipe,
        )
        from ctf_os.engine.pwn_disclosure import (
            PWN_DISCLOSURE_POSITIVE_CRASH_REPLAYS,
            PwnDisclosureResult,
            _result_binding,
            build_pwn_disclosure_trusted_receipt_expectation,
        )
        from ctf_os.engine.pwn_runtime_snapshot import (
            PwnRuntimeSnapshotGateEvaluation,
            PwnRuntimeSnapshotReceiptMetadata,
        )

        raw_parent_recipe = parent.extra.get("pwn_crash_recipe")
        raw_parent_evidence = (
            parent.result.get(_PWN_CRASH_RESULT_KEY)
            if type(parent.result) is dict
            and set(parent.result) == {_PWN_CRASH_RESULT_KEY}
            else None
        )
        raw_snapshot_evidence = (
            child.result.get(_PWN_RUNTIME_SNAPSHOT_RESULT_KEY)
            if type(child.result) is dict
            and set(child.result)
            == {_PWN_RUNTIME_SNAPSHOT_RESULT_KEY}
            else None
        )
        if (
            type(raw_parent_recipe) is not dict
            or type(raw_parent_evidence) is not dict
            or type(raw_parent_evidence.get("evaluation")) is not dict
            or type(raw_parent_evidence.get("attempts")) is not list
            or type(raw_snapshot_evidence) is not dict
            or type(raw_snapshot_evidence.get("evaluation")) is not dict
        ):
            raise ValueError("upstream evidence is not canonical")
        parent_recipe = PwnCrashRecipe.from_dict(raw_parent_recipe)
        parent_evaluation = PwnCrashGateEvaluation.from_dict(
            raw_parent_evidence["evaluation"]
        )
        snapshot_evaluation = (
            PwnRuntimeSnapshotGateEvaluation.from_dict(
                raw_snapshot_evidence["evaluation"],
                recipe=snapshot_recipe,
            )
        )
        attempts = raw_parent_evidence["attempts"]
        positive_metadata: list[Any] = []
        for ordinal in range(
            1,
            PWN_DISCLOSURE_POSITIVE_CRASH_REPLAYS + 1,
        ):
            attempt = attempts[ordinal - 1]
            if (
                type(attempt) is not dict
                or attempt.get("ordinal") != ordinal
                or type(attempt.get("receipt_id")) is not str
            ):
                raise ValueError(
                    "positive crash receipt order is not canonical"
                )
            receipt = receipts.get(attempt["receipt_id"])
            raw_record = (
                receipt.extra.get("pwn_crash")
                if receipt is not None
                else None
            )
            if (
                type(raw_record) is not dict
                or type(raw_record.get("receipt")) is not dict
            ):
                raise ValueError(
                    "positive crash receipt metadata is unavailable"
                )
            positive_metadata.append(
                PwnCrashReceiptMetadata.from_dict(
                    raw_record["receipt"]
                )
            )
        snapshot_receipt = receipts.get(
            raw_snapshot_evidence.get("receipt_id")
        )
        snapshot_record = (
            snapshot_receipt.extra.get("pwn_runtime_snapshot")
            if snapshot_receipt is not None
            else None
        )
        if (
            type(snapshot_record) is not dict
            or type(snapshot_record.get("receipt")) is not dict
        ):
            raise ValueError(
                "runtime snapshot receipt metadata is unavailable"
            )
        snapshot_metadata = PwnRuntimeSnapshotReceiptMetadata.from_dict(
            snapshot_record["receipt"]
        )
        expected_expectation = (
            build_pwn_disclosure_trusted_receipt_expectation(
                positive_crash_receipts=tuple(positive_metadata),
                snapshot_receipt=snapshot_metadata,
            )
        )
        expected_binding = _result_binding(
            crash_recipe=parent_recipe,
            crash_evaluation=parent_evaluation,
            snapshot_recipe=snapshot_recipe,
            snapshot_evaluation=snapshot_evaluation,
            trusted_receipt_expectation=expected_expectation,
        )
    except (
        ImportError,
        IndexError,
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        return [f"{label} upstream binding is invalid: {error}"]

    if envelope.trusted_receipt_expectation != expected_expectation:
        return [
            f"{label} trusted receipt expectation does not match "
            "canonical prior state"
        ]
    if envelope.phase is PwnDisclosurePhase.COMPLETE:
        result = envelope.result
        if (
            type(result) is not PwnDisclosureResult
            or result.binding != expected_binding
        ):
            return [
                f"{label} result binding does not match canonical prior state"
            ]
    return []


def _pwn_runtime_snapshot_state_errors(
    state: "ChallengeState",
    *,
    experiments: Mapping[str, Experiment],
    runs: Mapping[str, RunReference],
    receipts: Mapping[str, ExecutionReceipt],
    artifacts: Mapping[str, ArtifactReference],
    facts: Mapping[str, Fact],
    hypotheses: Mapping[str, Hypothesis],
    candidates: Mapping[str, FlagCandidate],
    disclosure_state_revision: int,
) -> list[str]:
    """Validate diagnostic child identity and its isolated lifecycle."""

    errors: list[str] = []
    children = {
        experiment.id: experiment
        for experiment in state.experiments
        if _pwn_runtime_snapshot_experiment_marker(experiment)
    }
    children_by_parent: dict[str, list[str]] = {}
    claimed_artifact_ids: set[str] = set()
    disclosure_terminal_artifact_ids: set[str] = set()

    for child in children.values():
        label = f"Pwn runtime snapshot experiment {child.id}"
        recipe, parent, payload, binding_errors = (
            _pwn_runtime_snapshot_recipe_binding(
                state,
                child,
                experiments=experiments,
                runs=runs,
                artifacts=artifacts,
            )
        )
        errors.extend(binding_errors)
        if recipe is None or parent is None or payload is None:
            continue
        children_by_parent.setdefault(parent.id, []).append(child.id)
        errors.extend(
            _pwn_runtime_snapshot_disclosure_errors(
                state,
                child,
                parent=parent,
                snapshot_recipe=recipe,
                receipts=receipts,
                state_revision=disclosure_state_revision,
            )
        )

        linked_runs = [
            run
            for run in state.runs
            if run.extra.get("experiment_id") == child.id
            or _pwn_runtime_snapshot_run_marker(run)
            and run.extra.get("experiment_id") == child.id
        ]
        linked_receipts = [
            receipt
            for receipt in state.receipts
            if receipt.experiment_id == child.id
        ]
        linked_artifacts = [
            artifact
            for artifact in state.artifacts
            if (
                artifact.source_run_id
                in {run.id for run in linked_runs}
                or (
                    _pwn_runtime_snapshot_artifact_marker(artifact)
                    and artifact.extra.get("recipe_sha256")
                    == recipe.recipe_sha256
                )
            )
        ]
        if child.status in {
            ExperimentStatus.REGISTERED,
            ExperimentStatus.RUNNING,
        }:
            if (
                child.result is not None
                or child.artifact_ids != [payload.id]
                or child.evidence_fact_ids
                or child.evidence_run_ids
                or child.evidence_receipt_ids
                or linked_runs
                or linked_receipts
                or linked_artifacts
            ):
                errors.append(
                    f"{label} active lifecycle/evidence is inconsistent"
                )
            continue
        if child.status is ExperimentStatus.FAILED:
            reason = (
                child.result.get("error")
                if type(child.result) is dict
                and set(child.result) == {"error"}
                else None
            )
            if (
                type(reason) is not str
                or not reason
                or not reason.startswith(
                    "Pwn runtime snapshot failed closed: "
                )
                or len(reason.encode("utf-8")) > 4096
                or child.artifact_ids != [payload.id]
                or child.evidence_fact_ids
                or child.evidence_run_ids
                or child.evidence_receipt_ids
                or linked_runs
                or linked_receipts
                or linked_artifacts
            ):
                errors.append(
                    f"{label} failed-closed lifecycle is inconsistent"
                )
            continue
        if child.status is not ExperimentStatus.COMPLETED:
            errors.append(
                f"{label} has a non-canonical terminal status"
            )
            continue
        source_run = runs.get(recipe.payload_source_run_id)
        if source_run is None:
            errors.append(f"{label} has no bound Builder run")
            continue
        terminal_errors, terminal_artifact_ids = (
            _pwn_runtime_snapshot_terminal_errors(
                child,
                recipe=recipe,
                payload=payload,
                linked_runs=linked_runs,
                linked_receipts=linked_receipts,
                linked_artifacts=linked_artifacts,
                source_run=source_run,
            )
        )
        errors.extend(terminal_errors)
        claimed_artifact_ids.update(terminal_artifact_ids)
        if child.extra.get("managed_contract_version") == 2:
            disclosure_terminal_artifact_ids.update(
                terminal_artifact_ids
            )

    for parent_id, child_ids in children_by_parent.items():
        if len(child_ids) != 1:
            errors.append(
                f"Confirmed Pwn crash {parent_id} has duplicate runtime "
                "snapshot children"
            )

    for run in state.runs:
        if _PWN_RUNTIME_SNAPSHOT_DISCLOSURE_KEY in run.extra:
            errors.append(
                f"Pwn disclosure cannot own Run {run.id}"
            )
        if (
            _pwn_runtime_snapshot_run_marker(run)
            and run.extra.get("experiment_id") not in children
        ):
            errors.append(
                f"Pwn runtime snapshot run {run.id} has no typed child"
            )
    for receipt in state.receipts:
        if _PWN_RUNTIME_SNAPSHOT_DISCLOSURE_KEY in receipt.extra:
            errors.append(
                f"Pwn disclosure cannot own receipt {receipt.id}"
            )
        if (
            "pwn_runtime_snapshot" in receipt.extra
            and receipt.experiment_id not in children
        ):
            errors.append(
                f"Pwn runtime snapshot receipt {receipt.id} has no typed child"
            )
    snapshot_run_ids = {
        run.id
        for run in state.runs
        if _pwn_runtime_snapshot_run_marker(run)
    }
    snapshot_artifact_ids = {
        artifact.id
        for artifact in state.artifacts
        if _pwn_runtime_snapshot_artifact_marker(artifact)
    }
    disclosure_child_ids = {
        child.id
        for child in children.values()
        if child.extra.get("managed_contract_version") == 2
    }
    disclosure_snapshot_run_ids = {
        run.id
        for run in state.runs
        if run.extra.get("experiment_id") in disclosure_child_ids
    }
    disclosure_snapshot_artifact_ids = (
        disclosure_terminal_artifact_ids
    )
    for artifact in state.artifacts:
        if _PWN_RUNTIME_SNAPSHOT_DISCLOSURE_KEY in artifact.extra:
            errors.append(
                f"Pwn disclosure cannot own artifact {artifact.id}"
            )
        if (
            _pwn_runtime_snapshot_artifact_marker(artifact)
            and (
                artifact.id not in claimed_artifact_ids
                or (
                    artifact.source_run_id is not None
                    and artifact.source_run_id not in snapshot_run_ids
                )
            )
        ):
            errors.append(
                f"Pwn runtime snapshot artifact {artifact.id} is orphaned"
            )
    for fact in facts.values():
        if (
            fact.source_run_id in snapshot_run_ids
            or fact.artifact_id in snapshot_artifact_ids
            or "pwn_runtime_snapshot" in fact.extra
            or _PWN_RUNTIME_SNAPSHOT_DISCLOSURE_KEY in fact.extra
        ):
            errors.append(
                f"Pwn runtime snapshot cannot promote Fact {fact.id}"
            )
    for hypothesis in hypotheses.values():
        if (
            _PWN_RUNTIME_SNAPSHOT_DISCLOSURE_KEY in hypothesis.extra
            or not set(hypothesis.evidence_run_ids).isdisjoint(
                snapshot_run_ids
            )
            or not set(hypothesis.evidence_artifact_ids).isdisjoint(
                snapshot_artifact_ids
            )
            or any(
                receipt_id in receipts
                and receipts[receipt_id].experiment_id in children
                for receipt_id in hypothesis.evidence_receipt_ids
            )
        ):
            errors.append(
                f"Pwn runtime snapshot cannot promote Hypothesis "
                f"{hypothesis.id}"
            )
    for candidate in candidates.values():
        if (
            _PWN_RUNTIME_SNAPSHOT_DISCLOSURE_KEY in candidate.extra
            or candidate.source_run_id in disclosure_snapshot_run_ids
            or candidate.artifact_id in disclosure_snapshot_artifact_ids
            or not set(candidate.proof_run_ids).isdisjoint(
                disclosure_snapshot_run_ids
            )
        ):
            errors.append(
                f"Pwn runtime snapshot disclosure cannot promote candidate "
                f"{candidate.id}"
            )
    for experiment in state.experiments:
        proof_recipe = experiment.proof_recipe
        if (
            experiment.kind is ExperimentKind.PROOF
            and proof_recipe is not None
            and (
                proof_recipe.source_experiment_id
                in disclosure_child_ids
                or proof_recipe.source_run_id
                in disclosure_snapshot_run_ids
                or any(
                    item.artifact_id
                    in disclosure_snapshot_artifact_ids
                    or item.source_run_id
                    in disclosure_snapshot_run_ids
                    for item in proof_recipe.inputs
                )
            )
        ):
            errors.append(
                f"Pwn runtime snapshot disclosure cannot satisfy proof "
                f"{experiment.id}"
            )
    return errors


_PWN_IP_CONTROL_ENGINE_COMMAND = "ctfos-engine:pwn-ip-control-v1"
_PWN_IP_CONTROL_ENGINE_EXECUTOR = "pwn_ip_control_v1"
_PWN_IP_CONTROL_REPLAY_PROTOCOL = (
    "pwn_ip_control_metamorphic_replay_v1"
)
_PWN_IP_CONTROL_RESULT_KEY = "pwn_ip_control_evidence"
_PWN_IP_CONTROL_EXPECTED_OBSERVATION = (
    "three clean replays move the full x86_64 RIP to three engine-derived "
    "unmapped addresses"
)
_PWN_IP_CONTROL_KEEP_CONDITION = (
    "typed result proves full-width instruction-pointer control"
)
_PWN_IP_CONTROL_DROP_CONDITION = (
    "any replay, binding, signal, RIP, or maps check is unverifiable"
)
_PWN_IP_CONTROL_EXPERIMENT_EXTRA_KEYS = frozenset(
    {
        "managed_contract_version",
        "engine_executor",
        "baseline_experiment_id",
        "pwn_ip_control_plan",
    }
)
_PWN_IP_CONTROL_RESULT_ENVELOPE_KEYS = frozenset(
    {
        "schema_version",
        "baseline_experiment_id",
        "plan_recipe_sha256",
        "evaluated_at",
        "result",
        "result_sha256",
        "run_ids",
        "receipt_ids",
        "result_artifact_id",
    }
)
_PWN_IP_CONTROL_REPLAY_RECORD_KEYS = frozenset(
    {
        "schema_version",
        "plan_recipe_sha256",
        "ordinal",
        "transport_recipe",
        "request_sha256",
        "execution_contract",
        "execution_contract_sha256",
        "receipt",
        "evaluation",
        "evaluation_sha256",
    }
)
_PWN_IP_CONTROL_EXECUTION_KEYS = frozenset(
    {
        "schema_version",
        "engine_executor",
        "protocol",
        "plan_recipe_sha256",
        "ordinal",
        "baseline_experiment_id",
        "ip_control_experiment_id",
        "transport_recipe_sha256",
        "configuration_epoch",
        "source",
        "payload",
        "argv",
        "sandbox",
        "producer",
    }
)
_PWN_IP_CONTROL_VARIANT_EXTRA_KEYS = frozenset(
    {
        "kind",
        "engine_executor",
        "plan_recipe_sha256",
        "ordinal",
        "target_value_sha256",
    }
)
_PWN_IP_CONTROL_CAPABILITY_EXTRA_KEYS = frozenset(
    {
        "kind",
        "engine_executor",
        "plan_recipe_sha256",
        "ordinal",
        "transport_recipe_sha256",
    }
)
_PWN_IP_CONTROL_STREAM_EXTRA_KEYS = frozenset(
    {
        "stream",
        "engine_executor",
        "plan_recipe_sha256",
        "ordinal",
        "transport_recipe_sha256",
        "capture_placeholder",
    }
)
_PWN_IP_CONTROL_RESULT_ARTIFACT_EXTRA_KEYS = frozenset(
    {
        "kind",
        "engine_executor",
        "plan_recipe_sha256",
        "result_sha256",
    }
)
_PWN_IP_CONTROL_AUTHORITY_KEYS = frozenset(
    {
        "experiment_id",
        "plan_recipe_sha256",
        "result_sha256",
        "controlled_offset",
        "controlled_width_bytes",
    }
)


def _pwn_ip_control_experiment_marker(
    experiment: Experiment,
) -> bool:
    result = experiment.result
    return (
        experiment.command == _PWN_IP_CONTROL_ENGINE_COMMAND
        or experiment.extra.get("engine_executor")
        == _PWN_IP_CONTROL_ENGINE_EXECUTOR
        or "pwn_ip_control_plan" in experiment.extra
        or (
            isinstance(result, Mapping)
            and _PWN_IP_CONTROL_RESULT_KEY in result
        )
    )


def _pwn_ip_control_run_marker(run: RunReference) -> bool:
    return (
        run.role == "pwn_ip_control"
        or "pwn_ip_control_replay" in run.extra
    )


def _pwn_ip_control_artifact_marker(
    artifact: ArtifactReference,
) -> bool:
    return (
        artifact.extra.get("engine_executor")
        == _PWN_IP_CONTROL_ENGINE_EXECUTOR
        or artifact.extra.get("kind")
        in {
            "pwn_ip_control_variant_payload",
            "pwn_ip_control_capability_attestation",
            "pwn_ip_control_result",
        }
    )


def _pwn_ip_control_fact_marker(fact: Fact) -> bool:
    return "pwn_ip_control" in fact.extra


def _pwn_ip_control_authority_record(
    value: object,
    *,
    child_id: str,
    plan_sha256: str,
    result_sha256: str,
    controlled_offset: int,
) -> bool:
    return (
        type(value) is dict
        and set(value) == _PWN_IP_CONTROL_AUTHORITY_KEYS
        and value
        == {
            "experiment_id": child_id,
            "plan_recipe_sha256": plan_sha256,
            "result_sha256": result_sha256,
            "controlled_offset": controlled_offset,
            "controlled_width_bytes": 8,
        }
    )


def _pwn_ip_control_execution_contract_errors(
    value: object,
    *,
    supplied_sha256: object,
    child: Experiment,
    baseline_experiment_id: str,
    plan_sha256: str,
    ordinal: int,
    recipe: Any,
    run: RunReference,
    capability: ArtifactReference,
) -> list[str]:
    """Reconstruct one fixed clean, networkless IP-control replay."""

    label = f"Pwn IP-control replay {ordinal}"
    if (
        type(value) is not dict
        or set(value) != _PWN_IP_CONTROL_EXECUTION_KEYS
    ):
        return [f"{label} execution contract is not exact"]
    source = value.get("source")
    payload = value.get("payload")
    sandbox = value.get("sandbox")
    producer = value.get("producer")
    image = (
        sandbox.get("image")
        if type(sandbox) is dict
        else None
    )
    if (
        type(source) is not dict
        or set(source)
        != _PWN_RUNTIME_SNAPSHOT_EXECUTION_SOURCE_KEYS
        or type(payload) is not dict
        or set(payload)
        != _PWN_RUNTIME_SNAPSHOT_EXECUTION_PAYLOAD_KEYS
        or type(sandbox) is not dict
        or set(sandbox)
        != _PWN_RUNTIME_SNAPSHOT_EXECUTION_SANDBOX_KEYS
        or type(image) is not dict
        or set(image) != _PWN_RUNTIME_SNAPSHOT_EXECUTION_IMAGE_KEYS
        or type(producer) is not dict
        or set(producer)
        != _PWN_RUNTIME_SNAPSHOT_EXECUTION_PRODUCER_KEYS
    ):
        return [f"{label} execution contract nested schema is not exact"]
    computed_sha256 = _pwn_runtime_snapshot_canonical_sha256(value)
    if (
        computed_sha256 is None
        or not _proof_binding_sha256(supplied_sha256)
        or supplied_sha256 != computed_sha256
    ):
        return [f"{label} execution contract hash does not match"]
    try:
        from ctf_os.director.resources import tool_profile
        from ctf_os.engine.pwn_runtime_snapshot import (
            PWN_RUNTIME_SNAPSHOT_INPUT_DESTINATION_LOCATOR,
            PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY,
            PWN_RUNTIME_SNAPSHOT_ONE_SHOT,
            PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME,
            PWN_RUNTIME_SNAPSHOT_PRODUCER_INTERPRETER_PATH,
            PWN_RUNTIME_SNAPSHOT_PRODUCER_PATH,
            PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD,
        )

        expected_resource = tool_profile(
            child.resource_class,
            needs_kvm=False,
            network=False,
        ).as_dict()
    except (ImportError, KeyError, TypeError, ValueError) as error:
        return [f"{label} execution policy cannot be rebuilt: {error}"]
    outer_timeout = sandbox.get("outer_timeout_seconds")
    expected = {
        "schema_version": 1,
        "engine_executor": _PWN_IP_CONTROL_ENGINE_EXECUTOR,
        "protocol": _PWN_IP_CONTROL_REPLAY_PROTOCOL,
        "plan_recipe_sha256": plan_sha256,
        "ordinal": ordinal,
        "baseline_experiment_id": baseline_experiment_id,
        "ip_control_experiment_id": child.id,
        "transport_recipe_sha256": recipe.recipe_sha256,
        "configuration_epoch": recipe.configuration_epoch,
        "source": {
            "locator": recipe.primary_elf_locator,
            "manifest_sha256": recipe.source_manifest_sha256,
            "sha256": recipe.source_sha256,
            "size_bytes": recipe.source_size_bytes,
        },
        "payload": {
            "artifact_id": recipe.payload_artifact_id,
            "source_run_id": run.id,
            "sha256": recipe.payload_sha256,
            "size_bytes": recipe.payload_size_bytes,
            "destination_locator": (
                PWN_RUNTIME_SNAPSHOT_INPUT_DESTINATION_LOCATOR
            ),
        },
        "argv": list(recipe.argv()),
        "sandbox": {
            "method": PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD,
            "one_shot": PWN_RUNTIME_SNAPSHOT_ONE_SHOT,
            "outer_timeout_seconds": outer_timeout,
            "resource_request": expected_resource,
            "image": {
                "reference": recipe.image_reference,
                "digest": recipe.image_digest,
            },
            "network": PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY,
            "network_target": None,
        },
        "producer": {
            "interpreter_path": (
                PWN_RUNTIME_SNAPSHOT_PRODUCER_INTERPRETER_PATH
            ),
            "path": PWN_RUNTIME_SNAPSHOT_PRODUCER_PATH,
            "capability_name": (
                PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME
            ),
            "file_sha256": recipe.producer_file_sha256,
            "capability_attestation_artifact_id": capability.id,
            "capability_attestation_sha256": capability.sha256,
        },
    }
    if (
        type(outer_timeout) is not int
        or not 1 <= outer_timeout <= child.timeout_seconds
        or value != expected
    ):
        return [f"{label} execution policy binding changed"]
    return []


def _pwn_ip_control_state_errors(
    state: "ChallengeState",
    *,
    experiments: Mapping[str, Experiment],
    runs: Mapping[str, RunReference],
    receipts: Mapping[str, ExecutionReceipt],
    artifacts: Mapping[str, ArtifactReference],
    facts: Mapping[str, Fact],
    candidates: Mapping[str, FlagCandidate],
) -> list[str]:
    """Validate the three-replay instruction-pointer partial oracle graph."""

    errors: list[str] = []
    children = {
        experiment.id: experiment
        for experiment in state.experiments
        if _pwn_ip_control_experiment_marker(experiment)
    }
    claimed_run_ids: set[str] = set()
    claimed_receipt_ids: set[str] = set()
    claimed_artifact_ids: set[str] = set()
    claimed_fact_ids: set[str] = set()
    claimed_marker_ids: set[str] = set()

    for child in children.values():
        label = f"Pwn IP-control experiment {child.id}"
        raw_plan = child.extra.get("pwn_ip_control_plan")
        try:
            from ctf_os.engine.pwn_ip_control import (
                PWN_IP_CONTROL_REPLAY_COUNT,
                PwnIpControlResult,
                PwnIpControlStatus,
                pwn_ip_control_child_experiment_id,
                validate_pwn_ip_control_plan_document,
            )
            from ctf_os.engine.pwn_runtime_snapshot import (
                PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY,
                PWN_RUNTIME_SNAPSHOT_ONE_SHOT,
                PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME,
                PWN_RUNTIME_SNAPSHOT_PRODUCER_FILE_SHA256,
                PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD,
                PwnRuntimeSnapshotCapabilityAttestation,
                PwnRuntimeSnapshotGateEvaluation,
                PwnRuntimeSnapshotReceiptMetadata,
                PwnRuntimeSnapshotRecipe,
            )

            plan = validate_pwn_ip_control_plan_document(raw_plan)
            plan_sha256 = plan["recipe_sha256"]
        except (
            ImportError,
            KeyError,
            TypeError,
            ValueError,
        ) as error:
            errors.append(f"{label} plan is invalid: {error}")
            continue

        baseline_id = child.extra.get("baseline_experiment_id")
        baseline = (
            experiments.get(baseline_id)
            if isinstance(baseline_id, str)
            else None
        )
        if (
            type(child.extra) is not dict
            or set(child.extra)
            != _PWN_IP_CONTROL_EXPERIMENT_EXTRA_KEYS
            or child.extra.get("managed_contract_version") != 1
            or child.extra.get("engine_executor")
            != _PWN_IP_CONTROL_ENGINE_EXECUTOR
            or state.category.strip().casefold() != "pwn"
            or not isinstance(baseline_id, str)
            or child.id
            != pwn_ip_control_child_experiment_id(baseline_id)
            or baseline is None
            or not _pwn_runtime_snapshot_experiment_marker(baseline)
            or baseline.status is not ExperimentStatus.COMPLETED
            or child.kind is not ExperimentKind.PROBE
            or child.command != _PWN_IP_CONTROL_ENGINE_COMMAND
            or child.hypothesis_ids
            != (baseline.hypothesis_ids if baseline is not None else [])
            or child.expected_observation
            != _PWN_IP_CONTROL_EXPECTED_OBSERVATION
            or child.keep_if != _PWN_IP_CONTROL_KEEP_CONDITION
            or child.drop_if != _PWN_IP_CONTROL_DROP_CONDITION
            or child.timeout_seconds != 30
            or child.resource_class != "light"
            or child.source_run_id is not None
            or child.proof_recipe is not None
            or child.evaluation_reason is not None
            or child.evaluated_at is not None
        ):
            errors.append(f"{label} lacks its exact managed identity")
        if baseline is None:
            continue

        baseline_raw_recipe = baseline.extra.get(
            "pwn_runtime_snapshot_recipe"
        )
        baseline_envelope = baseline.result
        baseline_evidence = (
            baseline_envelope.get(_PWN_RUNTIME_SNAPSHOT_RESULT_KEY)
            if type(baseline_envelope) is dict
            and set(baseline_envelope)
            == {_PWN_RUNTIME_SNAPSHOT_RESULT_KEY}
            else None
        )
        try:
            if (
                type(baseline_raw_recipe) is not dict
                or type(baseline_evidence) is not dict
                or type(baseline_evidence.get("evaluation")) is not dict
            ):
                raise ValueError("baseline evidence is unavailable")
            baseline_recipe = PwnRuntimeSnapshotRecipe.from_dict(
                baseline_raw_recipe
            )
            baseline_evaluation = (
                PwnRuntimeSnapshotGateEvaluation.from_dict(
                    baseline_evidence["evaluation"],
                    recipe=baseline_recipe,
                )
            )
            baseline_receipt = receipts.get(
                baseline_evidence.get("receipt_id")
            )
            baseline_record = (
                baseline_receipt.extra.get("pwn_runtime_snapshot")
                if baseline_receipt is not None
                else None
            )
            if (
                type(baseline_record) is not dict
                or type(baseline_record.get("receipt")) is not dict
            ):
                raise ValueError("baseline receipt is unavailable")
            baseline_metadata = (
                PwnRuntimeSnapshotReceiptMetadata.from_dict(
                    baseline_record["receipt"]
                )
            )
            baseline_payload = artifacts.get(
                baseline_recipe.payload_artifact_id
            )
            baseline_stdout = artifacts.get(
                baseline_metadata.stdout_artifact_id
            )
            baseline_capability = artifacts.get(
                baseline_metadata.capability_attestation_artifact_id
            )
            if (
                not baseline_evaluation.captured
                or baseline_payload is None
                or baseline_stdout is None
                or baseline_capability is None
            ):
                raise ValueError("baseline snapshot was not captured")
        except (
            KeyError,
            TypeError,
            ValueError,
        ) as error:
            errors.append(f"{label} baseline is invalid: {error}")
            continue

        plan_binding = plan["binding"]
        if (
            plan_binding["baseline_recipe_sha256"]
            != baseline_recipe.recipe_sha256
            or plan_binding["baseline_evaluation_sha256"]
            != baseline_evaluation.evidence_sha256
            or plan_binding["original_payload_sha256"]
            != baseline_recipe.payload_sha256
            or plan_binding["original_payload_size_bytes"]
            != baseline_recipe.payload_size_bytes
            or plan_binding["parent_crash_recipe_sha256"]
            != baseline_recipe.parent_crash_recipe_sha256
            or plan_binding["parent_crash_evaluation_sha256"]
            != baseline_recipe.parent_crash_evaluation_sha256
        ):
            errors.append(f"{label} plan does not bind its baseline")

        root = f"artifacts/snapshots/pwn-ip-control-{plan_sha256}"
        plan_replays = plan["replays"]
        variants: list[ArtifactReference] = []
        for ordinal, plan_replay in enumerate(plan_replays, start=1):
            matches = [
                artifact
                for artifact in state.artifacts
                if (
                    artifact.extra.get("kind")
                    == "pwn_ip_control_variant_payload"
                    and artifact.extra.get("plan_recipe_sha256")
                    == plan_sha256
                    and artifact.extra.get("ordinal") == ordinal
                )
            ]
            if len(matches) != 1:
                errors.append(
                    f"{label} must own one exact variant {ordinal}"
                )
                continue
            variant = matches[0]
            variants.append(variant)
            if (
                set(variant.extra) != _PWN_IP_CONTROL_VARIANT_EXTRA_KEYS
                or variant.extra.get("engine_executor")
                != _PWN_IP_CONTROL_ENGINE_EXECUTOR
                or variant.extra.get("target_value_sha256")
                != plan_replay["target_value_sha256"]
                or variant.source_run_id is not None
                or variant.sha256 != plan_replay["payload_sha256"]
                or variant.size != plan_replay["payload_size_bytes"]
                or variant.media_type != "application/octet-stream"
                or variant.path
                != f"{root}/{ordinal:02d}-payload.bin"
            ):
                errors.append(
                    f"{label} variant {ordinal} binding is invalid"
                )
            claimed_artifact_ids.add(variant.id)
        if len(variants) != PWN_IP_CONTROL_REPLAY_COUNT:
            continue

        linked_runs = [
            run
            for run in state.runs
            if run.extra.get("experiment_id") == child.id
        ]
        linked_receipts = [
            receipt
            for receipt in state.receipts
            if receipt.experiment_id == child.id
        ]
        linked_artifacts = [
            artifact
            for artifact in state.artifacts
            if (
                _pwn_ip_control_artifact_marker(artifact)
                and artifact.extra.get("plan_recipe_sha256")
                == plan_sha256
            )
        ]
        variant_ids = [artifact.id for artifact in variants]
        matching_facts = [
            fact
            for fact in state.facts
            if (
                fact.source_run_id in {run.id for run in linked_runs}
                or fact.artifact_id
                in {artifact.id for artifact in linked_artifacts}
                or (
                    type(fact.extra.get("pwn_ip_control")) is dict
                    and fact.extra["pwn_ip_control"].get("experiment_id")
                    == child.id
                )
            )
        ]
        matching_markers = [
            marker
            for marker in state.progress_markers
            if (
                marker.run_id in {run.id for run in linked_runs}
                or not set(marker.artifact_ids).isdisjoint(
                    {artifact.id for artifact in linked_artifacts}
                )
                or (
                    type(marker.extra.get("pwn_ip_control")) is dict
                    and marker.extra["pwn_ip_control"].get(
                        "experiment_id"
                    )
                    == child.id
                )
            )
        ]

        if child.status in {
            ExperimentStatus.REGISTERED,
            ExperimentStatus.RUNNING,
        }:
            if (
                child.result is not None
                or child.artifact_ids != variant_ids
                or child.evidence_fact_ids
                or child.evidence_run_ids
                or child.evidence_receipt_ids
                or linked_runs
                or linked_receipts
                or len(linked_artifacts) != 3
                or matching_facts
                or matching_markers
            ):
                errors.append(
                    f"{label} active lifecycle is inconsistent"
                )
            continue

        if child.status is ExperimentStatus.FAILED:
            failure = (
                child.result.get("error")
                if type(child.result) is dict
                and set(child.result) == {"error"}
                else None
            )
            if (
                type(failure) is not str
                or not failure.startswith(
                    "Pwn IP control failed closed: "
                )
                or len(failure.encode("utf-8")) > 4096
                or child.artifact_ids != variant_ids
                or child.evidence_fact_ids
                or child.evidence_run_ids
                or child.evidence_receipt_ids
                or linked_runs
                or linked_receipts
                or len(linked_artifacts) != 3
                or matching_facts
                or matching_markers
            ):
                errors.append(
                    f"{label} failed-closed lifecycle is inconsistent"
                )
            continue

        if child.status is not ExperimentStatus.COMPLETED:
            errors.append(f"{label} has a non-canonical status")
            continue

        result_envelope = (
            child.result.get(_PWN_IP_CONTROL_RESULT_KEY)
            if type(child.result) is dict
            and set(child.result) == {_PWN_IP_CONTROL_RESULT_KEY}
            else None
        )
        try:
            if (
                type(result_envelope) is not dict
                or set(result_envelope)
                != _PWN_IP_CONTROL_RESULT_ENVELOPE_KEYS
                or result_envelope.get("schema_version") != 1
                or result_envelope.get("baseline_experiment_id")
                != baseline_id
                or result_envelope.get("plan_recipe_sha256")
                != plan_sha256
                or not _proof_binding_utc_timestamp(
                    result_envelope.get("evaluated_at")
                )
                or type(result_envelope.get("run_ids")) is not list
                or type(result_envelope.get("receipt_ids")) is not list
            ):
                raise ValueError("result envelope is not exact")
            result = PwnIpControlResult.from_dict(
                result_envelope["result"]
            )
            result_sha256 = result.evidence_sha256
            if (
                result_envelope.get("result_sha256")
                != result_sha256
                or result.plan_recipe_sha256 != plan_sha256
                or result.source_manifest_sha256
                != baseline_recipe.source_manifest_sha256
                or result.source_sha256 != baseline_recipe.source_sha256
                or result.source_size_bytes
                != baseline_recipe.source_size_bytes
                or result.parent_crash_recipe_sha256
                != baseline_recipe.parent_crash_recipe_sha256
                or result.parent_crash_evaluation_sha256
                != baseline_recipe.parent_crash_evaluation_sha256
                or result.controlled_offset
                != plan_binding["controlled_offset"]
                or result.derivation_seed_sha256
                != plan_binding["derivation_seed_sha256"]
            ):
                raise ValueError("result binding is inconsistent")
        except (
            KeyError,
            TypeError,
            ValueError,
        ) as error:
            errors.append(f"{label} result is invalid: {error}")
            continue

        baseline_receipt_sha256 = (
            _pwn_runtime_snapshot_canonical_sha256(
                baseline_metadata.to_dict()
            )
        )
        baseline_source_run = runs.get(
            baseline_recipe.payload_source_run_id
        )
        expected_baseline_commitment = {
            "capability_attestation_artifact_id": (
                baseline_capability.id
            ),
            "capability_attestation_sha256": baseline_capability.sha256,
            "evaluation_sha256": baseline_evaluation.evidence_sha256,
            "payload_artifact_id": baseline_payload.id,
            "payload_sha256": baseline_payload.sha256,
            "payload_size_bytes": baseline_payload.size,
            "receipt_sha256": baseline_receipt_sha256,
            "recipe_sha256": baseline_recipe.recipe_sha256,
            "stdout_artifact_id": baseline_stdout.id,
            "stdout_artifact_sha256": baseline_stdout.sha256,
            "stdout_artifact_size_bytes": baseline_stdout.size,
        }
        if result.baseline.to_dict() != expected_baseline_commitment:
            errors.append(
                f"{label} result baseline commitment is inconsistent"
            )

        run_ids = result_envelope["run_ids"]
        receipt_ids = result_envelope["receipt_ids"]
        if (
            len(run_ids) != PWN_IP_CONTROL_REPLAY_COUNT
            or len(set(run_ids)) != PWN_IP_CONTROL_REPLAY_COUNT
            or len(receipt_ids) != PWN_IP_CONTROL_REPLAY_COUNT
            or len(set(receipt_ids)) != PWN_IP_CONTROL_REPLAY_COUNT
            or child.evidence_run_ids != run_ids
            or child.evidence_receipt_ids != receipt_ids
            or {run.id for run in linked_runs} != set(run_ids)
            or {receipt.id for receipt in linked_receipts}
            != set(receipt_ids)
        ):
            errors.append(f"{label} replay evidence lists are not exact")

        ordered_artifact_ids = list(variant_ids)
        replay_commitments: list[dict[str, object]] = []
        seen_request_sha256: set[str] = set()
        seen_execution_sha256: set[str] = set()
        for ordinal, (run_id, receipt_id, variant) in enumerate(
            zip(run_ids, receipt_ids, variants, strict=True),
            start=1,
        ):
            run = runs.get(run_id)
            receipt = receipts.get(receipt_id)
            if run is None or receipt is None:
                errors.append(
                    f"{label} replay {ordinal} is unavailable"
                )
                continue
            raw_record = run.extra.get("pwn_ip_control_replay")
            if (
                type(raw_record) is not dict
                or set(raw_record)
                != _PWN_IP_CONTROL_REPLAY_RECORD_KEYS
                or receipt.extra
                != {"pwn_ip_control_replay": raw_record}
                or run.extra
                != {
                    "experiment_id": child.id,
                    "pwn_ip_control_replay": raw_record,
                }
                or raw_record.get("schema_version") != 1
                or raw_record.get("plan_recipe_sha256")
                != plan_sha256
                or raw_record.get("ordinal") != ordinal
            ):
                errors.append(
                    f"{label} replay {ordinal} record is not exact"
                )
                continue
            try:
                transport_recipe = PwnRuntimeSnapshotRecipe.from_dict(
                    raw_record["transport_recipe"]
                )
                evaluation = PwnRuntimeSnapshotGateEvaluation.from_dict(
                    raw_record["evaluation"],
                    recipe=transport_recipe,
                )
                metadata = PwnRuntimeSnapshotReceiptMetadata.from_dict(
                    raw_record["receipt"]
                )
            except (
                KeyError,
                TypeError,
                ValueError,
            ) as error:
                errors.append(
                    f"{label} replay {ordinal} is invalid: {error}"
                )
                continue
            capability = artifacts.get(
                metadata.capability_attestation_artifact_id
            )
            stdout = artifacts.get(metadata.stdout_artifact_id)
            stderr = artifacts.get(metadata.stderr_artifact_id)
            if capability is None or stdout is None or stderr is None:
                errors.append(
                    f"{label} replay {ordinal} artifacts are incomplete"
                )
                continue
            ordered_artifact_ids.extend(
                (capability.id, stdout.id, stderr.id)
            )
            claimed_run_ids.add(run.id)
            claimed_receipt_ids.add(receipt.id)
            claimed_artifact_ids.update(
                (capability.id, stdout.id, stderr.id)
            )

            same_runtime = all(
                getattr(transport_recipe, field)
                == getattr(baseline_recipe, field)
                for field in (
                    "configuration_epoch",
                    "child_experiment_id",
                    "parent_experiment_id",
                    "primary_elf_locator",
                    "source_manifest_sha256",
                    "source_sha256",
                    "source_size_bytes",
                    "parent_crash_recipe_sha256",
                    "parent_crash_evaluation_sha256",
                    "expected_signal_number",
                    "image_reference",
                    "image_digest",
                    "producer_file_sha256",
                )
            )
            plan_replay = plan_replays[ordinal - 1]
            if (
                not same_runtime
                or transport_recipe.payload_artifact_id != variant.id
                or transport_recipe.payload_source_run_id != run.id
                or transport_recipe.payload_artifact_locator
                != variant.path
                or transport_recipe.payload_sha256 != variant.sha256
                or transport_recipe.payload_size_bytes != variant.size
                or raw_record.get("evaluation_sha256")
                != evaluation.evidence_sha256
                or metadata.recipe_sha256
                != transport_recipe.recipe_sha256
                or metadata.request_sha256
                != raw_record.get("request_sha256")
                or metadata.execution_contract_sha256
                != raw_record.get("execution_contract_sha256")
            ):
                errors.append(
                    f"{label} replay {ordinal} transport binding changed"
                )

            errors.extend(
                _pwn_ip_control_execution_contract_errors(
                    raw_record.get("execution_contract"),
                    supplied_sha256=raw_record.get(
                        "execution_contract_sha256"
                    ),
                    child=child,
                    baseline_experiment_id=baseline_id,
                    plan_sha256=plan_sha256,
                    ordinal=ordinal,
                    recipe=transport_recipe,
                    run=run,
                    capability=capability,
                )
            )
            expected_run_status = {
                "succeeded": RunStatus.COMPLETED,
                "failed": RunStatus.FAILED,
                "timed_out": RunStatus.TIMED_OUT,
            }.get(metadata.outcome)
            expected_receipt_outcome = {
                "succeeded": ReceiptOutcome.SUCCEEDED,
                "failed": ReceiptOutcome.FAILED,
                "timed_out": ReceiptOutcome.TIMED_OUT,
            }.get(metadata.outcome)
            if (
                run.role != "pwn_ip_control"
                or run.origin is not RunOrigin.MANAGED_TOOL
                or run.configuration_epoch != state.configuration_epoch
                or baseline_source_run is None
                or run.session_id != baseline_source_run.session_id
                or run.cycle_id != baseline_source_run.cycle_id
                or run.wave_id != baseline_source_run.wave_id
                or run.model is not None
                or run.context_hash is not None
                or not _pwn_crash_safe_locator(run.request_path)
                or not _pwn_crash_safe_locator(run.result_path)
                or not _pwn_crash_safe_locator(run.validation_path)
                or run.status is not expected_run_status
                or receipt.id != metadata.receipt_id
                or receipt.run_id != run.id
                or receipt.experiment_id != child.id
                or receipt.outcome is not expected_receipt_outcome
                or receipt.exit_code != metadata.exit_code
                or receipt.stdout_artifact_id != stdout.id
                or receipt.stderr_artifact_id != stderr.id
                or receipt.stdout_bytes
                != metadata.stdout_drained_bytes
                or receipt.stderr_bytes != metadata.stderr_artifact_size_bytes
                or receipt.stdout_lines != 0
                or receipt.stderr_lines != 0
                or receipt.preview
                != (
                    f"Pwn IP control replay {ordinal} "
                    f"{evaluation.status.value}:"
                    f"{evaluation.reason_code}"
                )[:160]
            ):
                errors.append(
                    f"{label} replay {ordinal} durable chain is inconsistent"
                )

            expected_attestation = (
                PwnRuntimeSnapshotCapabilityAttestation(
                    image_digest=transport_recipe.image_digest,
                    recipe_sha256=transport_recipe.recipe_sha256,
                )
            )
            if (
                metadata.timed_out
                is not (metadata.outcome == "timed_out")
                or metadata.clean_workspace is not True
                or metadata.one_shot is not PWN_RUNTIME_SNAPSHOT_ONE_SHOT
                or metadata.sandbox_method
                != PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD
                or metadata.network != PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY
                or metadata.configuration_epoch
                != transport_recipe.configuration_epoch
                or metadata.image_digest != transport_recipe.image_digest
                or metadata.producer_capability_name
                != PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME
                or metadata.producer_file_sha256
                != PWN_RUNTIME_SNAPSHOT_PRODUCER_FILE_SHA256
                or metadata.capability_attestation_artifact_id
                != capability.id
                or metadata.capability_attestation_sha256
                != capability.sha256
                or metadata.stdout_artifact_id != stdout.id
                or metadata.stdout_artifact_sha256 != stdout.sha256
                or metadata.stdout_artifact_size_bytes != stdout.size
                or metadata.stderr_artifact_id != stderr.id
                or metadata.stderr_artifact_sha256 != stderr.sha256
                or metadata.stderr_artifact_size_bytes != stderr.size
            ):
                errors.append(
                    f"{label} replay {ordinal} receipt binding changed"
                )

            expected_transport_sha = transport_recipe.recipe_sha256
            if (
                capability.source_run_id is not None
                or capability.sha256
                != expected_attestation.evidence_sha256
                or capability.size
                != len(expected_attestation.canonical_bytes())
                or capability.media_type != "application/json"
                or set(capability.extra)
                != _PWN_IP_CONTROL_CAPABILITY_EXTRA_KEYS
                or capability.extra
                != {
                    "kind": "pwn_ip_control_capability_attestation",
                    "engine_executor": (
                        _PWN_IP_CONTROL_ENGINE_EXECUTOR
                    ),
                    "plan_recipe_sha256": plan_sha256,
                    "ordinal": ordinal,
                    "transport_recipe_sha256": expected_transport_sha,
                }
                or capability.path
                != f"{root}/{ordinal:02d}-capability-attestation.json"
            ):
                errors.append(
                    f"{label} replay {ordinal} capability is invalid"
                )
            for stream, artifact in (
                ("stdout", stdout),
                ("stderr", stderr),
            ):
                placeholder = artifact.extra.get("capture_placeholder")
                if (
                    artifact.source_run_id != run.id
                    or type(placeholder) is not bool
                    or set(artifact.extra)
                    != _PWN_IP_CONTROL_STREAM_EXTRA_KEYS
                    or artifact.extra
                    != {
                        "stream": stream,
                        "engine_executor": (
                            _PWN_IP_CONTROL_ENGINE_EXECUTOR
                        ),
                        "plan_recipe_sha256": plan_sha256,
                        "ordinal": ordinal,
                        "transport_recipe_sha256": (
                            expected_transport_sha
                        ),
                        "capture_placeholder": placeholder,
                    }
                    or artifact.path
                    != (
                        f"{root}/{ordinal:02d}-{run.id}-"
                        f"{stream}.log"
                    )
                    or artifact.media_type
                    != (
                        "application/json"
                        if stream == "stdout"
                        else "text/plain"
                    )
                    or (placeholder and artifact.size != 0)
                    or (
                        placeholder
                        and artifact.sha256
                        != hashlib.sha256(b"").hexdigest()
                    )
                ):
                    errors.append(
                        f"{label} replay {ordinal} {stream} is invalid"
                    )
            per_run_artifacts = {
                artifact.id
                for artifact in state.artifacts
                if artifact.source_run_id == run.id
            }
            if per_run_artifacts != {stdout.id, stderr.id}:
                errors.append(
                    f"{label} replay {ordinal} owns unexpected artifacts"
                )
            if (
                metadata.stderr_capture_placeholder
                is not stderr.extra.get("capture_placeholder")
            ):
                errors.append(
                    f"{label} replay {ordinal} stderr capture changed"
                )
            semantic_result = evaluation.semantic_result
            if semantic_result is not None:
                semantic_bytes = semantic_result.canonical_bytes()
                if (
                    metadata.outcome != "succeeded"
                    or metadata.exit_code != 0
                    or metadata.timed_out
                    or metadata.orchestration_error is not None
                    or not metadata.stdout_capture_complete
                    or not metadata.stdout_truncation_known
                    or metadata.stdout_truncated is not False
                    or metadata.stdout_error is not None
                    or metadata.stream_capture_error is not None
                    or not metadata.durable_stdout_artifact_complete
                    or stdout.extra.get("capture_placeholder") is not False
                    or stdout.sha256
                    != hashlib.sha256(semantic_bytes).hexdigest()
                    or stdout.size != len(semantic_bytes)
                    or metadata.stdout_drained_bytes
                    != len(semantic_bytes)
                    or metadata.stdout_stored_bytes
                    != len(semantic_bytes)
                ):
                    errors.append(
                        f"{label} replay {ordinal} semantic stdout changed"
                    )

            request_sha = raw_record.get("request_sha256")
            execution_sha = raw_record.get(
                "execution_contract_sha256"
            )
            if (
                not _proof_binding_sha256(request_sha)
                or request_sha in seen_request_sha256
                or not _proof_binding_sha256(execution_sha)
                or execution_sha in seen_execution_sha256
            ):
                errors.append(
                    f"{label} replay {ordinal} reused an execution identity"
                )
            else:
                seen_request_sha256.add(request_sha)
                seen_execution_sha256.add(execution_sha)

            receipt_sha256 = _pwn_runtime_snapshot_canonical_sha256(
                metadata.to_dict()
            )
            replay_commitments.append(
                {
                    "capability_attestation_artifact_id": capability.id,
                    "capability_attestation_sha256": capability.sha256,
                    "evaluation_sha256": evaluation.evidence_sha256,
                    "ordinal": ordinal,
                    "payload_artifact_id": variant.id,
                    "payload_sha256": variant.sha256,
                    "payload_size_bytes": variant.size,
                    "receipt_sha256": receipt_sha256,
                    "recipe_sha256": transport_recipe.recipe_sha256,
                    "stdout_artifact_id": stdout.id,
                    "stdout_artifact_sha256": stdout.sha256,
                    "stdout_artifact_size_bytes": stdout.size,
                    "target_value_sha256": (
                        plan_replay["target_value_sha256"]
                    ),
                }
            )

        result_artifact_id = result_envelope["result_artifact_id"]
        result_artifact = artifacts.get(result_artifact_id)
        if result_artifact is None:
            errors.append(f"{label} result artifact is unavailable")
            continue
        ordered_artifact_ids.append(result_artifact.id)
        claimed_artifact_ids.add(result_artifact.id)
        result_bytes = result.canonical_bytes()
        if (
            result_artifact.source_run_id is not None
            or result_artifact.sha256
            != hashlib.sha256(result_bytes).hexdigest()
            or result_artifact.size != len(result_bytes)
            or result_artifact.media_type != "application/json"
            or set(result_artifact.extra)
            != _PWN_IP_CONTROL_RESULT_ARTIFACT_EXTRA_KEYS
            or result_artifact.extra
            != {
                "kind": "pwn_ip_control_result",
                "engine_executor": _PWN_IP_CONTROL_ENGINE_EXECUTOR,
                "plan_recipe_sha256": plan_sha256,
                "result_sha256": result_sha256,
            }
            or result_artifact.path != f"{root}/result.json"
        ):
            errors.append(f"{label} result artifact is invalid")
        if (
            child.artifact_ids != ordered_artifact_ids
            or len(linked_artifacts) != 13
            or {artifact.id for artifact in linked_artifacts}
            != set(ordered_artifact_ids)
            or child.evidence_run_ids != run_ids
            or child.evidence_receipt_ids != receipt_ids
        ):
            errors.append(f"{label} terminal artifact graph is not exact")

        if result.replays:
            expected_replays = replay_commitments[
                : len(result.replays)
            ]
            if [
                replay.to_dict() for replay in result.replays
            ] != expected_replays:
                errors.append(
                    f"{label} result replay commitments are inconsistent"
                )
        elif result.status is PwnIpControlStatus.PROVEN:
            errors.append(f"{label} proven result has no replay commitments")

        proven = result.status is PwnIpControlStatus.PROVEN
        if proven:
            offset = result.controlled_offset
            assert isinstance(offset, int)
            authority = {
                "experiment_id": child.id,
                "plan_recipe_sha256": plan_sha256,
                "result_sha256": result_sha256,
                "controlled_offset": offset,
                "controlled_width_bytes": 8,
            }
            fact_id = (
                f"F-{child.id}-instruction-pointer-control"
            )
            marker_id = (
                f"P-{child.id}-instruction-pointer-control"
            )
            statement = (
                "Engine-owned metamorphic replays proved full-width x86_64 "
                "instruction-pointer control at payload offset "
                f"{offset}."
            )
            matching_fact = facts.get(fact_id)
            matching_marker = next(
                (
                    marker
                    for marker in state.progress_markers
                    if marker.id == marker_id
                ),
                None,
            )
            last_run_id = run_ids[-1]
            if (
                len(matching_facts) != 1
                or matching_fact is None
                or matching_fact not in matching_facts
                or matching_fact.statement != statement
                or matching_fact.provenance is not Provenance.EXECUTED
                or matching_fact.kind is not FactKind.OBSERVATION
                or matching_fact.challenge_id != state.challenge_id
                or matching_fact.source_run_id != last_run_id
                or matching_fact.artifact_id != result_artifact.id
                or matching_fact.locator != result_artifact.path
                or matching_fact.supersedes_id is not None
                or matching_fact.supports
                or matching_fact.contradicts
                or matching_fact.extra != {"pwn_ip_control": authority}
                or child.evidence_fact_ids != [matching_fact.id]
            ):
                errors.append(f"{label} proven Fact is not exact")
            if (
                len(matching_markers) != 1
                or matching_marker is None
                or matching_marker not in matching_markers
                or matching_marker.statement
                not in {
                    statement,
                    "Full-width x86_64 instruction-pointer control "
                    "reproduced in three clean replays",
                }
                or matching_marker.run_id != last_run_id
                or matching_marker.goal_id is not None
                or matching_marker.artifact_ids
                != [result_artifact.id]
                or matching_marker.extra
                != {"pwn_ip_control": authority}
            ):
                errors.append(
                    f"{label} proven progress marker is not exact"
                )
            if matching_fact is not None:
                claimed_fact_ids.add(matching_fact.id)
            if matching_marker is not None:
                claimed_marker_ids.add(matching_marker.id)
        elif (
            child.evidence_fact_ids
            or matching_facts
            or matching_markers
        ):
            errors.append(
                f"{label} unverified result promoted authority"
            )

    for run in state.runs:
        if (
            _pwn_ip_control_run_marker(run)
            and run.id not in claimed_run_ids
        ):
            errors.append(f"Pwn IP-control run {run.id} is orphaned")
    for receipt in state.receipts:
        if (
            "pwn_ip_control_replay" in receipt.extra
            and receipt.id not in claimed_receipt_ids
        ):
            errors.append(
                f"Pwn IP-control receipt {receipt.id} is orphaned"
            )
    pwn_artifact_ids = {
        artifact.id
        for artifact in state.artifacts
        if _pwn_ip_control_artifact_marker(artifact)
    }
    for artifact in state.artifacts:
        if (
            _pwn_ip_control_artifact_marker(artifact)
            and artifact.id not in claimed_artifact_ids
        ):
            errors.append(
                f"Pwn IP-control artifact {artifact.id} is orphaned"
            )
    for fact in state.facts:
        if (
            (
                _pwn_ip_control_fact_marker(fact)
                or fact.source_run_id in claimed_run_ids
                or fact.artifact_id in pwn_artifact_ids
            )
            and fact.id not in claimed_fact_ids
        ):
            errors.append(f"Pwn IP-control Fact {fact.id} is unauthorized")
    for marker in state.progress_markers:
        if (
            (
                "pwn_ip_control" in marker.extra
                or marker.run_id in claimed_run_ids
                or not set(marker.artifact_ids).isdisjoint(
                    pwn_artifact_ids
                )
            )
            and marker.id not in claimed_marker_ids
        ):
            errors.append(
                f"Pwn IP-control progress marker {marker.id} is unauthorized"
            )
    for candidate in candidates.values():
        if (
            "pwn_ip_control" in candidate.extra
            or candidate.source_run_id in claimed_run_ids
            or candidate.artifact_id in pwn_artifact_ids
            or not set(candidate.proof_run_ids).isdisjoint(
                claimed_run_ids
            )
        ):
            errors.append(
                f"Pwn IP-control evidence cannot promote candidate "
                f"{candidate.id}"
            )
    for experiment in state.experiments:
        proof_recipe = experiment.proof_recipe
        if (
            experiment.kind is ExperimentKind.PROOF
            and proof_recipe is not None
            and (
                proof_recipe.source_experiment_id in children
                or proof_recipe.source_run_id in claimed_run_ids
                or any(
                    item.artifact_id in pwn_artifact_ids
                    or item.source_run_id in claimed_run_ids
                    for item in proof_recipe.inputs
                )
            )
        ):
            errors.append(
                f"Pwn IP-control evidence cannot satisfy proof "
                f"{experiment.id}"
            )
    return errors


_REV_PROOF_ENVELOPE_KEYS = frozenset(
    {
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
)
_REV_PROOF_DEADLINE_GUARD_KEYS = frozenset(
    {
        "contract",
        "budget_deadline_utc",
        "attempt_deadlines_utc",
        "evaluated_at_utc",
        "commit_guard",
    }
)
_REV_PROOF_SEMANTIC_FALSIFICATION_CODES = frozenset(
    {
        "negative_flag_candidate_observed",
        "selected_candidate_not_direct",
    }
)


@dataclass(frozen=True, slots=True)
class _RevProofLinkIndex:
    proof_runs_by_experiment_id: Mapping[
        str,
        tuple[RunReference, ...],
    ]
    artifact_ids_by_source_run_id: Mapping[str, frozenset[str]]
    candidate_proof_run_ids: Mapping[str, tuple[str, ...]]
    candidate_proof_run_positions: Mapping[str, Mapping[str, int]]


def _rev_proof_link_index(state: "ChallengeState") -> _RevProofLinkIndex:
    """Build the Rev proof graph indexes in one pass per collection."""

    proof_runs: dict[str, list[RunReference]] = {}
    for run in state.runs:
        experiment_id = run.extra.get("experiment_id")
        if (
            run.origin is RunOrigin.PROOF
            and isinstance(experiment_id, str)
        ):
            proof_runs.setdefault(experiment_id, []).append(run)
    artifact_ids_by_run: dict[str, set[str]] = {}
    for artifact in state.artifacts:
        if isinstance(artifact.source_run_id, str):
            artifact_ids_by_run.setdefault(
                artifact.source_run_id,
                set(),
            ).add(artifact.id)
    return _RevProofLinkIndex(
        proof_runs_by_experiment_id={
            experiment_id: tuple(linked_runs)
            for experiment_id, linked_runs in proof_runs.items()
        },
        artifact_ids_by_source_run_id={
            run_id: frozenset(artifact_ids)
            for run_id, artifact_ids in artifact_ids_by_run.items()
        },
        candidate_proof_run_ids={
            candidate.id: tuple(candidate.proof_run_ids)
            for candidate in state.candidates
        },
        candidate_proof_run_positions={
            candidate.id: {
                run_id: position
                for position, run_id in enumerate(
                    candidate.proof_run_ids
                )
            }
            for candidate in state.candidates
        },
    )


def _rev_proof_state_errors(
    state: "ChallengeState",
    *,
    runs: Mapping[str, RunReference],
    artifacts: Mapping[str, ArtifactReference],
    candidates: Mapping[str, FlagCandidate],
) -> list[str]:
    """Validate persisted Rev proof evidence without reading artifact bytes."""

    errors: list[str] = []
    link_index = _rev_proof_link_index(state)
    passing_slices_by_candidate: dict[
        str,
        set[tuple[str, ...]],
    ] = {}
    evaluated_slices_by_candidate: dict[
        str,
        dict[tuple[str, ...], bool],
    ] = {}
    for experiment in state.experiments:
        recipe = experiment.proof_recipe
        if (
            experiment.kind is not ExperimentKind.PROOF
            or recipe is None
            or recipe.policy.oracle_protocol
            != _REV_STDIN_PROOF_PROTOCOL
        ):
            continue
        label = f"Rev stdin proof experiment {experiment.id}"
        if len(recipe.inputs) != 1:
            errors.append(f"{label} does not have one accepted input")
            continue
        result = experiment.result
        raw_envelope = (
            result.get("rev_proof_evidence")
            if isinstance(result, Mapping)
            else None
        )
        if raw_envelope is None:
            if experiment.status in {
                ExperimentStatus.COMPLETED,
                ExperimentStatus.INCONCLUSIVE,
            }:
                errors.append(f"{label} lacks canonical proof evidence")
            continue
        try:
            if (
                not isinstance(result, Mapping)
                or set(result)
                != {"proof_result", "rev_proof_evidence"}
                or not isinstance(raw_envelope, Mapping)
                or set(raw_envelope) != _REV_PROOF_ENVELOPE_KEYS
            ):
                raise ModelValidationError(
                    "proof result/envelope schema is not exact"
                )
            envelope = raw_envelope
            binding = recipe.oracle_binding
            if binding is None:
                raise ModelValidationError("oracle binding is absent")
            if (
                type(envelope["schema_version"]) is not int
                or envelope["schema_version"] != 1
                or any(
                    type(envelope[field]) is not str
                    for field in (
                        "protocol",
                        "recipe_sha256",
                        "policy_sha256",
                        "candidate_id",
                        "accepted_input_artifact_id",
                        "source_manifest_sha256",
                        "image_reference",
                        "evaluation_sha256",
                        "evaluation_artifact_id",
                    )
                )
                or envelope["protocol"] != _REV_STDIN_PROOF_PROTOCOL
                or envelope["recipe_sha256"] != recipe.recipe_sha256
                or envelope["policy_sha256"]
                != recipe.policy.policy_sha256
                or envelope["candidate_id"] != recipe.candidate_id
                or envelope["accepted_input_artifact_id"]
                != recipe.inputs[0].artifact_id
                or envelope["source_manifest_sha256"]
                != recipe.source_manifest_sha256
                or envelope["image_reference"] != recipe.image_reference
                or envelope["oracle_binding"] != binding.to_dict()
                or not _proof_binding_sha256(
                    envelope["evaluation_sha256"]
                )
                or not _proof_binding_identifier(
                    envelope["evaluation_artifact_id"]
                )
            ):
                raise ModelValidationError(
                    "proof envelope pins do not match its recipe"
                )
            from ctf_os.engine.rev_proof import (  # local: avoids cycle
                parse_rev_proof_evaluation_evidence,
            )

            evaluation = parse_rev_proof_evaluation_evidence(
                envelope["evaluation"]
            )
            if (
                evaluation.protocol != _REV_STDIN_PROOF_PROTOCOL
                or evaluation.evidence_sha256
                != envelope["evaluation_sha256"]
                or evaluation.candidate
                != candidates[recipe.candidate_id].value
                or evaluation.source_manifest_sha256
                != recipe.source_manifest_sha256
                or evaluation.accepted_input_sha256
                != recipe.inputs[0].sha256
                or evaluation.accepted_input_size_bytes
                != recipe.inputs[0].size
                or len(evaluation.plan) != 6
                or len(evaluation.observations) != 6
            ):
                raise ModelValidationError(
                    "proof evaluation does not match its recipe"
                )
            proof_result = result["proof_result"]
            if (
                not isinstance(proof_result, Mapping)
                or set(proof_result)
                != {
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
                or type(proof_result["failures"]) not in {list, tuple}
                or type(proof_result["run_ids"]) not in {list, tuple}
                or type(proof_result["passed"]) is not bool
                or any(
                    type(proof_result[field]) is not str
                    for field in (
                        "candidate",
                        "policy_mode",
                        "source_manifest_sha256",
                    )
                )
                or any(
                    type(proof_result[field]) is not int
                    for field in (
                        "successful_attempts",
                        "required_attempts",
                        "total_attempts",
                    )
                )
                or proof_result["passed"] is not evaluation.passed
                or proof_result["candidate"] != evaluation.candidate
                or proof_result["policy_mode"]
                != _REV_STDIN_PROOF_PROTOCOL
                or proof_result["successful_attempts"]
                != evaluation.positive_successes
                or proof_result["required_attempts"] != 3
                or proof_result["total_attempts"] != 6
                or proof_result["source_manifest_sha256"]
                != evaluation.source_manifest_sha256
                or tuple(proof_result["failures"])
                != tuple(
                    failure.token()
                    for failure in evaluation.failures
                )
                or tuple(proof_result["run_ids"])
                != tuple(
                    observation.run_id
                    for observation in evaluation.observations
                )
            ):
                raise ModelValidationError(
                    "proof result contradicts its evaluation"
                )
            evaluation_artifact = artifacts.get(
                envelope["evaluation_artifact_id"]
            )
            if (
                evaluation_artifact is None
                or evaluation_artifact.sha256
                != evaluation.evidence_sha256
                or type(evaluation_artifact.size) is not int
                or evaluation_artifact.size
                != len(evaluation.canonical_bytes())
                or evaluation_artifact.source_run_id is not None
                or evaluation_artifact.id
                not in experiment.artifact_ids
                or evaluation_artifact.extra
                != {
                    "kind": "rev_proof_evaluation",
                    "experiment_id": experiment.id,
                    "candidate_id": recipe.candidate_id,
                    "recipe_sha256": recipe.recipe_sha256,
                    "policy_sha256": recipe.policy.policy_sha256,
                    "protocol": _REV_STDIN_PROOF_PROTOCOL,
                }
            ):
                raise ModelValidationError(
                    "proof evaluation artifact is not exact"
                )
            deadline_guard = envelope["deadline_guard"]
            if (
                not isinstance(deadline_guard, Mapping)
                or set(deadline_guard)
                != _REV_PROOF_DEADLINE_GUARD_KEYS
                or deadline_guard["contract"]
                != "ctfos_rev_proof_deadline_guard_v1"
                or deadline_guard["commit_guard"]
                != "state_store_pre_replace_v1"
                or deadline_guard["budget_deadline_utc"]
                != binding.budget_deadline_utc
                or type(deadline_guard["attempt_deadlines_utc"])
                is not list
                or len(deadline_guard["attempt_deadlines_utc"]) != 6
                or experiment.evaluated_at
                != deadline_guard["evaluated_at_utc"]
            ):
                raise ModelValidationError(
                    "proof deadline guard is not exact"
                )
            budget_deadline = _proof_binding_utc_datetime(
                binding.budget_deadline_utc
            )
            evaluated_at = _proof_binding_utc_datetime(
                deadline_guard["evaluated_at_utc"]
            )
            attempt_deadlines = tuple(
                _proof_binding_utc_datetime(item)
                for item in deadline_guard["attempt_deadlines_utc"]
            )
            if (
                budget_deadline is None
                or evaluated_at is None
                or evaluated_at > budget_deadline
                or any(
                    attempt_deadline is None
                    or attempt_deadline > budget_deadline
                    for attempt_deadline in attempt_deadlines
                )
            ):
                raise ModelValidationError(
                    "proof deadline evidence exceeds its budget"
                )
            observation_run_ids = tuple(
                observation.run_id
                for observation in evaluation.observations
            )
            if (
                experiment.evidence_run_ids
                != list(observation_run_ids)
                or tuple(
                    run.id
                    for run in link_index.proof_runs_by_experiment_id.get(
                        experiment.id,
                        (),
                    )
                )
                != observation_run_ids
            ):
                raise ModelValidationError(
                    "proof observation run links are not exact"
                )
            stream_artifact_ids: set[str] = set()
            ordered_artifact_ids = [recipe.inputs[0].artifact_id]
            for index, (planned, observation) in enumerate(
                zip(
                    evaluation.plan,
                    evaluation.observations,
                    strict=True,
                )
            ):
                run = runs.get(observation.run_id)
                structural_attempt_failure = any(
                    failure.attempt_ordinal == planned.ordinal
                    and failure.code
                    not in _REV_PROOF_SEMANTIC_FALSIFICATION_CODES
                    for failure in evaluation.failures
                )
                expected_run_status = (
                    RunStatus.TIMED_OUT
                    if observation.timed_out
                    else (
                        RunStatus.FAILED
                        if structural_attempt_failure
                        else RunStatus.COMPLETED
                    )
                )
                if (
                    run is None
                    or run.origin is not RunOrigin.PROOF
                    or run.role != "proof"
                    or run.status is not expected_run_status
                    or run.result_path is None
                    or run.validation_path is None
                    or type(run.configuration_epoch) is not int
                    or run.configuration_epoch
                    != recipe.configuration_epoch
                    or run.extra.get("experiment_id") != experiment.id
                    or run.extra.get("rev_proof_protocol")
                    != _REV_STDIN_PROOF_PROTOCOL
                    or run.extra.get("rev_proof_recipe_sha256")
                    != recipe.recipe_sha256
                    or run.extra.get("rev_proof_attempt_ordinal")
                    != planned.ordinal
                    or type(
                        run.extra.get("rev_proof_attempt_ordinal")
                    )
                    is not int
                    or run.extra.get("rev_proof_phase")
                    != planned.phase
                    or run.extra.get("rev_proof_mutation_id")
                    != planned.mutation_id
                    or run.extra.get("rev_proof_input_sha256")
                    != planned.input_sha256
                    or run.extra.get("rev_proof_input_size_bytes")
                    != planned.input_size_bytes
                    or type(
                        run.extra.get("rev_proof_input_size_bytes")
                    )
                    is not int
                    or run.extra.get(
                        "rev_proof_attempt_deadline_utc"
                    )
                    != deadline_guard["attempt_deadlines_utc"][index]
                    or run.extra.get("rev_proof_observation")
                    != observation.to_dict()
                ):
                    raise ModelValidationError(
                        "proof observation Run binding is inconsistent"
                    )
                run_stream_artifact_ids: set[str] = set()
                for stream_name, stream in (
                    ("stdout", observation.stdout),
                    ("stderr", observation.stderr),
                ):
                    if (
                        stream.artifact_id is None
                        or stream.artifact_sha256 is None
                        or stream.artifact_size_bytes is None
                    ):
                        raise ModelValidationError(
                            "proof stream artifact binding is incomplete"
                        )
                    artifact = artifacts.get(stream.artifact_id)
                    if (
                        artifact is None
                        or artifact.source_run_id != observation.run_id
                        or artifact.sha256 != stream.artifact_sha256
                        or type(artifact.size) is not int
                        or artifact.size != stream.artifact_size_bytes
                        or artifact.id not in experiment.artifact_ids
                        or artifact.id in stream_artifact_ids
                        or artifact.extra.get("stream") != stream_name
                        or artifact.extra.get("rev_proof_protocol")
                        != _REV_STDIN_PROOF_PROTOCOL
                        or artifact.extra.get("experiment_id")
                        != experiment.id
                        or artifact.extra.get(
                            "rev_proof_attempt_ordinal"
                        )
                        != planned.ordinal
                        or type(
                            artifact.extra.get(
                                "rev_proof_attempt_ordinal"
                            )
                        )
                        is not int
                    ):
                        raise ModelValidationError(
                            "proof stream artifact binding is inconsistent"
                        )
                    stream_artifact_ids.add(artifact.id)
                    run_stream_artifact_ids.add(artifact.id)
                    ordered_artifact_ids.append(artifact.id)
                if (
                    link_index.artifact_ids_by_source_run_id.get(
                        observation.run_id,
                        frozenset(),
                    )
                    != frozenset(run_stream_artifact_ids)
                ):
                    raise ModelValidationError(
                        "proof Run has an unexpected linked artifact"
                    )
            ordered_artifact_ids.append(evaluation_artifact.id)
            if experiment.artifact_ids != ordered_artifact_ids:
                raise ModelValidationError(
                    "proof artifact links are not exact or ordered"
                )
            candidate = candidates[recipe.candidate_id]
            candidate_history = (
                link_index.candidate_proof_run_ids.get(
                    candidate.id,
                    (),
                )
            )
            positions = link_index.candidate_proof_run_positions.get(
                candidate.id,
                {},
            )
            observation_positions = tuple(
                positions.get(run_id)
                for run_id in observation_run_ids
            )
            if (
                len(positions) != len(candidate_history)
                or any(
                    position is None
                    for position in observation_positions
                )
                or observation_positions
                != tuple(
                    range(
                        observation_positions[0],  # type: ignore[arg-type]
                        observation_positions[0] + 6,  # type: ignore[operator]
                    )
                )
            ):
                raise ModelValidationError(
                    "candidate proof history lacks a contiguous evaluation"
                )
            structural_evaluation_failure = any(
                failure.code
                not in _REV_PROOF_SEMANTIC_FALSIFICATION_CODES
                for failure in evaluation.failures
            )
            evaluated_slices_by_candidate.setdefault(
                candidate.id,
                {},
            )[observation_run_ids] = evaluation.passed
            if evaluation.passed:
                passing_slices_by_candidate.setdefault(
                    candidate.id,
                    set(),
                ).add(observation_run_ids)
                if (
                    experiment.status is not ExperimentStatus.COMPLETED
                ):
                    raise ModelValidationError(
                        "confirmed proof is not atomically promoted"
                    )
            else:
                expected_experiment_status = (
                    ExperimentStatus.FAILED
                    if structural_evaluation_failure
                    else ExperimentStatus.COMPLETED
                )
                if (
                    experiment.status is not expected_experiment_status
                ):
                    raise ModelValidationError(
                        "inconclusive proof has invalid terminal state"
                    )
        except (
            KeyError,
            IndexError,
            ModelValidationError,
            TypeError,
            ValueError,
        ) as error:
            errors.append(f"{label} is invalid: {error}")
    accepted_submission_candidate_ids = {
        submission.candidate_id
        for submission in state.submissions
        if submission.status is SubmissionStatus.ACCEPTED
        and submission.proof_passed is True
    }
    rejected_submission_candidate_ids = {
        submission.candidate_id
        for submission in state.submissions
        if submission.status is SubmissionStatus.REJECTED
        and submission.proof_passed is True
    }
    for candidate_id in evaluated_slices_by_candidate:
        candidate = candidates.get(candidate_id)
        if candidate is None:
            continue
        passing_slices = passing_slices_by_candidate.get(
            candidate_id,
            set(),
        )
        latest_slice = tuple(candidate.proof_run_ids[-6:])
        if candidate.status is CandidateStatus.READY_TO_SUBMIT:
            ready_challenge_state = (
                state.status is ChallengeStatus.READY_TO_SUBMIT
                or state.status is ChallengeStatus.SOLVED
                or (
                    state.status is ChallengeStatus.PAUSED
                    and state.resume_status
                    is ChallengeStatus.READY_TO_SUBMIT
                )
                or state.status is ChallengeStatus.ABANDONED
            )
            if (
                not ready_challenge_state
                or latest_slice not in passing_slices
            ):
                errors.append(
                    f"Rev stdin proof candidate {candidate_id} READY state "
                    "does not match its latest passing evaluation"
                )
        elif candidate.status is CandidateStatus.ACCEPTED:
            if (
                state.status is not ChallengeStatus.SOLVED
                or latest_slice not in passing_slices
                or candidate_id
                not in accepted_submission_candidate_ids
            ):
                errors.append(
                    f"Rev stdin proof candidate {candidate_id} ACCEPTED "
                    "state does not match its latest passing evaluation"
                )
        elif candidate.status is CandidateStatus.REJECTED:
            if candidate_id not in rejected_submission_candidate_ids:
                errors.append(
                    f"Rev stdin proof candidate {candidate_id} REJECTED "
                    "state lacks its manual false-proof outcome"
                )
    return errors


_CRYPTO_METAMORPHIC_PROTOCOL = (
    "crypto_solver_metamorphic_variant_v1"
)
_CRYPTO_METAMORPHIC_BINDING_KEYS = frozenset(
    {
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
)
_CRYPTO_METAMORPHIC_MANAGED_BINDING_KEYS = frozenset(
    {*_CRYPTO_METAMORPHIC_BINDING_KEYS, "oracle_preissue_id"}
)
_CRYPTO_METAMORPHIC_EVALUATION_KEYS = frozenset(
    {
        "candidate_sha256",
        "failure_codes",
        "observations",
        "oracle_artifact_sha256",
        "passed",
        "plan",
        "protocol",
        "runtime_fingerprint_sha256",
        "schema_version",
        "solver_artifact_sha256",
        "source_manifest_sha256",
    }
)
_CRYPTO_METAMORPHIC_OBSERVATION_KEYS = frozenset(
    {
        "capture_complete",
        "capture_error_present",
        "case_id",
        "clean_workspace",
        "ctfwrap_exit_code",
        "mutation_id",
        "oracle_artifact_sha256",
        "orchestration_status",
        "ordinal",
        "parameters_sha256",
        "parameters_size_bytes",
        "result_artifact_id",
        "result_artifact_sha256",
        "result_artifact_size_bytes",
        "run_id",
        "runner_exit_code",
        "runtime_fingerprint_sha256",
        "solver_artifact_sha256",
        "source_manifest_sha256",
        "target_exit_code",
        "timed_out",
        "truncated",
        "truncation_known",
    }
)
_CRYPTO_METAMORPHIC_PROOF_RESULT_KEYS = frozenset(
    {
        "candidate",
        "failures",
        "passed",
        "policy_mode",
        "required_attempts",
        "run_ids",
        "source_manifest_sha256",
        "successful_attempts",
        "total_attempts",
    }
)
_CRYPTO_METAMORPHIC_PLAN_KEYS = frozenset(
    {"attempts", "cases", "protocol"}
)
_CRYPTO_METAMORPHIC_CASE_KEYS = frozenset(
    {
        "case_id",
        "changed_parameter_pointers",
        "expected_output_sha256",
        "expected_output_size_bytes",
        "mutation_id",
        "parameters_sha256",
        "parameters_size_bytes",
    }
)
_CRYPTO_METAMORPHIC_ATTEMPT_KEYS = frozenset(
    set(_CRYPTO_METAMORPHIC_CASE_KEYS)
    - {"changed_parameter_pointers"}
    | {"ordinal"}
)


def _crypto_compact_bytes(value: object) -> bytes:
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


def _crypto_artifact_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _crypto_exact_mapping(
    value: object,
    keys: frozenset[str],
) -> Mapping[str, Any] | None:
    return value if type(value) is dict and set(value) == keys else None


def _crypto_nonnegative_int(value: object, *, maximum: int) -> bool:
    return (
        type(value) is int
        and 0 <= value <= maximum
    )


def _crypto_metamorphic_state_errors(
    state: "ChallengeState",
    *,
    runs: Mapping[str, RunReference],
    artifacts: Mapping[str, ArtifactReference],
    candidates: Mapping[str, FlagCandidate],
) -> list[str]:
    """Revalidate the persisted Crypto proof graph without trusting READY."""

    if state.category.strip().casefold() not in {"crypto", "cryptography"}:
        return []
    errors: list[str] = []
    for candidate in candidates.values():
        raw_binding = candidate.extra.get("crypto_metamorphic_proof")
        authoritative = candidate.status in {
            CandidateStatus.READY_TO_SUBMIT,
            CandidateStatus.ACCEPTED,
        }
        if raw_binding is None:
            if authoritative:
                errors.append(
                    f"Crypto candidate {candidate.id} lacks its typed "
                    "metamorphic proof binding"
                )
            continue
        label = f"Crypto candidate {candidate.id} metamorphic proof"
        try:
            if (
                type(raw_binding) is not dict
                or frozenset(raw_binding)
                not in {
                    _CRYPTO_METAMORPHIC_BINDING_KEYS,
                    _CRYPTO_METAMORPHIC_MANAGED_BINDING_KEYS,
                }
            ):
                raise ModelValidationError("binding schema is not exact")
            binding = raw_binding
            managed_oracle = (
                frozenset(binding)
                == _CRYPTO_METAMORPHIC_MANAGED_BINDING_KEYS
            )
            oracle_authority = (
                "managed_oracle_preissue_v1"
                if managed_oracle
                else "explicit_operator_input"
            )
            evaluation = _crypto_exact_mapping(
                binding["evaluation"],
                _CRYPTO_METAMORPHIC_EVALUATION_KEYS,
            )
            proof_result = _crypto_exact_mapping(
                binding["proof_result"],
                _CRYPTO_METAMORPHIC_PROOF_RESULT_KEYS,
            )
            if evaluation is None or proof_result is None:
                raise ModelValidationError(
                    "evaluation or ProofResult schema is not exact"
                )
            run_ids = binding["run_ids"]
            observations = evaluation["observations"]
            failure_codes = evaluation["failure_codes"]
            if (
                binding["protocol"] != _CRYPTO_METAMORPHIC_PROTOCOL
                or evaluation["protocol"]
                != _CRYPTO_METAMORPHIC_PROTOCOL
                or binding["oracle_authority"] != oracle_authority
                or type(binding["passed"]) is not bool
                or type(evaluation["passed"]) is not bool
                or binding["passed"] is not evaluation["passed"]
                or type(run_ids) is not list
                or len(run_ids) != 6
                or len(set(run_ids)) != 6
                or any(
                    not _proof_binding_identifier(run_id)
                    for run_id in run_ids
                )
                or type(observations) is not list
                or len(observations) != 6
                or type(failure_codes) is not list
                or any(type(code) is not str for code in failure_codes)
                or type(evaluation["schema_version"]) is not int
                or evaluation["schema_version"] != 1
                or any(
                    not _proof_binding_sha256(evaluation[field])
                    for field in (
                        "candidate_sha256",
                        "oracle_artifact_sha256",
                        "runtime_fingerprint_sha256",
                        "solver_artifact_sha256",
                        "source_manifest_sha256",
                    )
                )
                or evaluation["candidate_sha256"]
                != hashlib.sha256(
                    candidate.value.encode("utf-8")
                ).hexdigest()
                or evaluation["source_manifest_sha256"]
                != state.metadata.get("source_manifest_sha256")
            ):
                raise ModelValidationError(
                    "evaluation bindings are invalid"
                )
            if managed_oracle:
                preissue_id = binding["oracle_preissue_id"]
                history = state.extra.get("managed_oracle_preissues")
                preissue = (
                    history.get(preissue_id)
                    if type(history) is dict
                    and type(preissue_id) is str
                    else None
                )
                if (
                    not _proof_binding_identifier(preissue_id)
                    or not isinstance(preissue, Mapping)
                    or preissue.get("preissue_id") != preissue_id
                    or preissue.get("kind") != "crypto"
                    or preissue.get("status") != "consumed"
                    or preissue.get("issuer") != "operator"
                    or preissue.get("configuration_epoch")
                    != state.configuration_epoch
                    or preissue.get("source_manifest_sha256")
                    != state.metadata.get("source_manifest_sha256")
                ):
                    raise ModelValidationError(
                        "managed oracle preissue binding is invalid"
                    )
            semantic_bytes = _crypto_compact_bytes(evaluation)
            semantic_sha256 = hashlib.sha256(semantic_bytes).hexdigest()
            if (
                not _proof_binding_sha256(binding["evaluation_sha256"])
                or binding["evaluation_sha256"] != semantic_sha256
            ):
                raise ModelValidationError(
                    "evaluation commitment is invalid"
                )

            plan = _crypto_exact_mapping(
                evaluation["plan"],
                _CRYPTO_METAMORPHIC_PLAN_KEYS,
            )
            if plan is None:
                raise ModelValidationError("passing plan is absent")
            cases = plan["cases"]
            attempts = plan["attempts"]
            if (
                plan["protocol"] != _CRYPTO_METAMORPHIC_PROTOCOL
                or type(cases) is not list
                or len(cases) != 2
                or type(attempts) is not list
                or len(attempts) != 6
                or binding["plan_sha256"]
                != hashlib.sha256(_crypto_compact_bytes(plan)).hexdigest()
            ):
                raise ModelValidationError("plan binding is invalid")
            parsed_cases: list[Mapping[str, Any]] = []
            for case in cases:
                parsed = _crypto_exact_mapping(
                    case,
                    _CRYPTO_METAMORPHIC_CASE_KEYS,
                )
                if (
                    parsed is None
                    or not _proof_binding_sha256(
                        parsed["parameters_sha256"]
                    )
                    or not _proof_binding_sha256(
                        parsed["expected_output_sha256"]
                    )
                    or not _crypto_nonnegative_int(
                        parsed["parameters_size_bytes"],
                        maximum=4 * 1024 * 1024,
                    )
                    or not _crypto_nonnegative_int(
                        parsed["expected_output_size_bytes"],
                        maximum=1024 * 1024,
                    )
                    or type(parsed["changed_parameter_pointers"])
                    is not list
                    or len(parsed["changed_parameter_pointers"]) > 128
                    or any(
                        type(pointer) is not str
                        for pointer
                        in parsed["changed_parameter_pointers"]
                    )
                ):
                    raise ModelValidationError("case schema is invalid")
                parsed_cases.append(parsed)
            original, variant = parsed_cases
            candidate_bytes = candidate.value.encode("utf-8")
            if (
                original["case_id"] != "original"
                or original["mutation_id"] != "original-baseline"
                or original["changed_parameter_pointers"] != []
                or original["expected_output_sha256"]
                != hashlib.sha256(candidate_bytes).hexdigest()
                or original["expected_output_size_bytes"]
                != len(candidate_bytes)
                or variant["case_id"] != "metamorphic-variant"
                or not variant["changed_parameter_pointers"]
                or variant["parameters_sha256"]
                == original["parameters_sha256"]
                or variant["expected_output_sha256"]
                != evaluation["oracle_artifact_sha256"]
                or variant["expected_output_sha256"]
                == original["expected_output_sha256"]
            ):
                raise ModelValidationError(
                    "original/variant cases are not independent"
                )
            for ordinal, attempt in enumerate(attempts, start=1):
                parsed = _crypto_exact_mapping(
                    attempt,
                    _CRYPTO_METAMORPHIC_ATTEMPT_KEYS,
                )
                expected_case = original if ordinal <= 3 else variant
                if (
                    parsed is None
                    or parsed["ordinal"] != ordinal
                    or any(
                        parsed[field] != expected_case[field]
                        for field in (
                            "case_id",
                            "expected_output_sha256",
                            "expected_output_size_bytes",
                            "mutation_id",
                            "parameters_sha256",
                            "parameters_size_bytes",
                        )
                    )
                ):
                    raise ModelValidationError(
                        "attempt plan order is invalid"
                    )

            expected_run_ids: list[str] = []
            result_artifact_ids: set[str] = set()
            for ordinal, raw_observation in enumerate(
                observations,
                start=1,
            ):
                observation = _crypto_exact_mapping(
                    raw_observation,
                    _CRYPTO_METAMORPHIC_OBSERVATION_KEYS,
                )
                expected_attempt = attempts[ordinal - 1]
                if (
                    observation is None
                    or observation["ordinal"] != ordinal
                    or any(
                        observation[field] != expected_attempt[field]
                        for field in (
                            "case_id",
                            "mutation_id",
                            "parameters_sha256",
                            "parameters_size_bytes",
                        )
                    )
                    or observation["source_manifest_sha256"]
                    != evaluation["source_manifest_sha256"]
                    or observation["solver_artifact_sha256"]
                    != evaluation["solver_artifact_sha256"]
                    or observation["runtime_fingerprint_sha256"]
                    != evaluation["runtime_fingerprint_sha256"]
                    or observation["oracle_artifact_sha256"]
                    != evaluation["oracle_artifact_sha256"]
                    or not _proof_binding_identifier(
                        observation["run_id"]
                    )
                    or not _proof_binding_identifier(
                        observation["result_artifact_id"]
                    )
                    or not _proof_binding_sha256(
                        observation["result_artifact_sha256"]
                    )
                    or not _crypto_nonnegative_int(
                        observation["result_artifact_size_bytes"],
                        maximum=1024 * 1024,
                    )
                ):
                    raise ModelValidationError(
                        "observation binding is invalid"
                    )
                expected_run_ids.append(observation["run_id"])
                if observation["result_artifact_id"] in result_artifact_ids:
                    raise ModelValidationError(
                        "result artifact identity is reused"
                    )
                result_artifact_ids.add(
                    observation["result_artifact_id"]
                )
                run = runs.get(observation["run_id"])
                stdout_artifact = artifacts.get(
                    observation["result_artifact_id"]
                )
                linked_streams = [
                    artifact
                    for artifact in artifacts.values()
                    if artifact.source_run_id == observation["run_id"]
                    and artifact.extra.get("kind")
                    == "crypto_metamorphic_stream"
                    and artifact.extra.get("protocol")
                    == _CRYPTO_METAMORPHIC_PROTOCOL
                ]
                if (
                    run is None
                    or run.origin is not RunOrigin.PROOF
                    or run.role != "crypto_metamorphic_proof"
                    or run.configuration_epoch
                    != state.configuration_epoch
                    or run.extra.get("crypto_metamorphic_protocol")
                    != _CRYPTO_METAMORPHIC_PROTOCOL
                    or run.extra.get("plan_sha256")
                    != binding["plan_sha256"]
                    or run.extra.get("attempt_ordinal") != ordinal
                    or run.extra.get("observation") != observation
                    or stdout_artifact is None
                    or stdout_artifact.source_run_id != run.id
                    or stdout_artifact.sha256
                    != observation["result_artifact_sha256"]
                    or stdout_artifact.size
                    != observation["result_artifact_size_bytes"]
                    or stdout_artifact.extra.get("stream") != "stdout"
                    or len(linked_streams) != 2
                    or {
                        artifact.extra.get("stream")
                        for artifact in linked_streams
                    }
                    != {"stdout", "stderr"}
                    or any(
                        artifact.extra.get("attempt_ordinal") != ordinal
                        or artifact.extra.get("plan_sha256")
                        != binding["plan_sha256"]
                        or (
                            managed_oracle
                            and artifact.extra.get("context_visibility")
                            != "engine_private"
                        )
                        for artifact in linked_streams
                    )
                ):
                    raise ModelValidationError(
                        f"run {ordinal} evidence graph is invalid"
                    )
            if expected_run_ids != run_ids:
                raise ModelValidationError(
                    "candidate run order differs from evaluation"
                )

            artifact_id = binding["artifact_id"]
            evaluation_artifact = artifacts.get(artifact_id)
            if (
                not _proof_binding_identifier(artifact_id)
                or evaluation_artifact is None
                or evaluation_artifact.source_run_id is not None
                or evaluation_artifact.sha256
                != hashlib.sha256(
                    _crypto_artifact_bytes(evaluation)
                ).hexdigest()
                or evaluation_artifact.size
                != len(_crypto_artifact_bytes(evaluation))
                or evaluation_artifact.extra
                != {
                    "candidate_id": candidate.id,
                    "evaluation_sha256": semantic_sha256,
                    "kind": "crypto_metamorphic_evaluation",
                    "plan_sha256": binding["plan_sha256"],
                    "protocol": _CRYPTO_METAMORPHIC_PROTOCOL,
                }
            ):
                raise ModelValidationError(
                    "evaluation artifact is not exact"
                )
            evaluation_parent = PurePosixPath(
                evaluation_artifact.path
            ).parent
            proof_inputs = [
                artifact
                for artifact in artifacts.values()
                if (
                    artifact.extra.get("protocol")
                    == _CRYPTO_METAMORPHIC_PROTOCOL
                    and PurePosixPath(artifact.path).is_relative_to(
                        evaluation_parent
                    )
                    and artifact.id != evaluation_artifact.id
                    and artifact.extra.get("kind")
                    in {
                        "crypto_metamorphic_input",
                        "crypto_metamorphic_input_manifest",
                    }
                )
            ]
            purposes = {
                artifact.extra.get("purpose"): artifact
                for artifact in proof_inputs
                if artifact.extra.get("kind")
                == "crypto_metamorphic_input"
            }
            manifests = [
                artifact
                for artifact in proof_inputs
                if artifact.extra.get("kind")
                == "crypto_metamorphic_input_manifest"
            ]
            if (
                len(proof_inputs) != (6 if managed_oracle else 5)
                or set(purposes)
                != {
                    "solver",
                    "original_parameters",
                    "variant_parameters",
                    "variant_expected_output",
                }
                or len(manifests) != (2 if managed_oracle else 1)
                or purposes["solver"].sha256
                != evaluation["solver_artifact_sha256"]
                or purposes["original_parameters"].sha256
                != original["parameters_sha256"]
                or purposes["original_parameters"].size
                != original["parameters_size_bytes"]
                or purposes["variant_parameters"].sha256
                != variant["parameters_sha256"]
                or purposes["variant_parameters"].size
                != variant["parameters_size_bytes"]
                or purposes["variant_expected_output"].sha256
                != evaluation["oracle_artifact_sha256"]
                or purposes["variant_expected_output"].size
                != variant["expected_output_size_bytes"]
                or any(
                    artifact.source_run_id is not None
                    for artifact in proof_inputs
                )
                or purposes["variant_expected_output"].extra.get(
                    "context_visibility"
                )
                != "engine_private"
                or (
                    {
                        tuple(sorted(artifact.extra.items()))
                        for artifact in manifests
                    }
                    != (
                        {
                            tuple(
                                sorted(
                                    {
                                        "context_visibility": (
                                            "engine_private"
                                        ),
                                        "kind": (
                                            "crypto_metamorphic_input_manifest"
                                        ),
                                        "protocol": (
                                            _CRYPTO_METAMORPHIC_PROTOCOL
                                        ),
                                    }.items()
                                )
                            ),
                            tuple(
                                sorted(
                                    {
                                        "context_visibility": (
                                            "engine_private"
                                        ),
                                        "kind": (
                                            "crypto_metamorphic_input_manifest"
                                        ),
                                        "protocol": (
                                            _CRYPTO_METAMORPHIC_PROTOCOL
                                        ),
                                        "oracle_preissue_id": (
                                            binding[
                                                "oracle_preissue_id"
                                            ]
                                        ),
                                    }.items()
                                )
                            ),
                        }
                        if managed_oracle
                        else {
                            tuple(
                                sorted(
                                    {
                                        "context_visibility": (
                                            "engine_private"
                                        ),
                                        "kind": (
                                            "crypto_metamorphic_input_manifest"
                                        ),
                                        "protocol": (
                                            _CRYPTO_METAMORPHIC_PROTOCOL
                                        ),
                                    }.items()
                                )
                            )
                        }
                    )
                )
                or (
                    managed_oracle
                    and (
                        purposes["variant_parameters"].extra.get(
                            "context_visibility"
                        )
                        != "engine_private"
                        or purposes["variant_parameters"].extra.get(
                            "oracle_preissue_id"
                        )
                        != binding["oracle_preissue_id"]
                        or purposes["variant_expected_output"].extra.get(
                            "oracle_preissue_id"
                        )
                        != binding["oracle_preissue_id"]
                    )
                )
            ):
                raise ModelValidationError(
                    "proof input artifact graph is invalid"
                )

            if (
                proof_result["passed"] is not evaluation["passed"]
                or proof_result["candidate"] != candidate.value
                or proof_result["policy_mode"]
                != _CRYPTO_METAMORPHIC_PROTOCOL
                or proof_result["source_manifest_sha256"]
                != evaluation["source_manifest_sha256"]
                or type(proof_result["run_ids"]) not in {list, tuple}
                or tuple(proof_result["run_ids"]) != tuple(run_ids)
                or type(proof_result["failures"]) not in {list, tuple}
                or tuple(proof_result["failures"])
                != tuple(failure_codes)
                or type(proof_result["successful_attempts"]) is not int
                or type(proof_result["required_attempts"]) is not int
                or proof_result["required_attempts"] != 6
                or type(proof_result["total_attempts"]) is not int
                or proof_result["total_attempts"] != 6
            ):
                raise ModelValidationError(
                    "ProofResult contradicts evaluation"
                )
            if authoritative:
                if (
                    evaluation["passed"] is not True
                    or failure_codes
                    or proof_result["successful_attempts"] != 6
                    or tuple(candidate.proof_run_ids[-6:])
                    != tuple(run_ids)
                    or any(
                        runs[run_id].status is not RunStatus.COMPLETED
                        for run_id in run_ids
                    )
                    or any(
                        observation[field] is not expected
                        for observation in observations
                        for field, expected in (
                            ("capture_complete", True),
                            ("capture_error_present", False),
                            ("clean_workspace", True),
                            ("timed_out", False),
                            ("truncated", False),
                            ("truncation_known", True),
                        )
                    )
                    or any(
                        observation[field] != expected
                        for observation in observations
                        for field, expected in (
                            ("ctfwrap_exit_code", 0),
                            ("orchestration_status", "completed"),
                            ("runner_exit_code", 0),
                            ("target_exit_code", 0),
                        )
                    )
                    or any(
                        observation["result_artifact_sha256"]
                        != attempts[index][
                            "expected_output_sha256"
                        ]
                        or observation["result_artifact_size_bytes"]
                        != attempts[index][
                            "expected_output_size_bytes"
                        ]
                        for index, observation in enumerate(observations)
                    )
                ):
                    raise ModelValidationError(
                        "authoritative READY evidence does not pass"
                    )
                matching_markers = [
                    marker
                    for marker in state.progress_markers
                    if (
                        marker.extra.get("adapter_marker")
                        == "metamorphic_variant_verified"
                        and marker.extra.get("protocol")
                        == _CRYPTO_METAMORPHIC_PROTOCOL
                        and marker.extra.get("oracle_authority")
                        == oracle_authority
                        and marker.run_id == run_ids[-1]
                        and marker.artifact_ids
                        == [evaluation_artifact.id]
                    )
                ]
                if len(matching_markers) != 1:
                    raise ModelValidationError(
                        "authoritative proof lacks one exact progress marker"
                    )
        except (
            KeyError,
            ModelValidationError,
            TypeError,
            UnicodeError,
            ValueError,
        ) as error:
            errors.append(f"{label} is invalid: {error}")
    return errors


_FORENSIC_INDEX_EXECUTION_PROTOCOL = (
    "forensic_evidence_index_execution_v1"
)
_FORENSIC_INDEX_PROTOCOL = "forensic_evidence_index_v1"
_FORENSIC_INDEX_EVALUATION_KEYS = frozenset(
    {
        "authorities",
        "confirmed",
        "envelope",
        "envelope_sha256",
        "protocol",
        "reason_code",
        "schema_version",
        "semantic_evaluation",
        "semantic_evaluation_sha256",
        "verdict",
    }
)
_FORENSIC_INDEX_AUTHORITY_KEYS = frozenset(
    {
        "automatic_submission_authorized",
        "candidate_authorized",
        "challenge_proof_satisfied",
        "executed_evidence_index_fact_authorized",
        "impact_proven",
        "progress_marker_authorized",
    }
)
_FORENSIC_INDEX_ENVELOPE_KEYS = frozenset(
    {
        "category",
        "challenge_id",
        "configuration_epoch",
        "contest_id",
        "experiment_id",
        "image",
        "prefix_coverage_ppm",
        "protocol",
        "receipt",
        "request",
        "run",
        "schema_version",
        "source",
        "stdout_artifact",
        "transport",
    }
)
_FORENSIC_INDEX_SEMANTIC_KEYS = frozenset(
    {
        "claims",
        "index_sha256",
        "indexed_bytes",
        "indexed_files",
        "modality_counts",
        "pointer_coverage_ppm",
        "protocol",
        "reason_code",
        "schema_version",
        "source_inventory_sha256",
        "tree_sha256",
        "verdict",
    }
)
_FORENSIC_INDEX_SEED_COPY_KEYS = (
    "adapter_name",
    "adapter_seed",
    "adapter_seed_contract_version",
    "adapter_seed_order",
    "adapter_spec_id",
    "adapter_spec_sha256",
    "adapter_spec_template_id",
    "partial_oracle",
    "requires_explicit_execution",
    "source_binding",
    "source_snapshot",
)
_FORENSIC_INDEX_RUN_EXTRA_KEYS = frozenset(
    {
        *_FORENSIC_INDEX_SEED_COPY_KEYS,
        "experiment_id",
        "forensic_index_execution",
        "wall_seconds",
    }
)
_FORENSIC_INDEX_RECEIPT_EXTRA_KEYS = frozenset(
    {
        "forensic_index_execution",
        "line_count_basis",
        "stream_evidence",
    }
)
_FORENSIC_INDEX_SOURCE_BINDING_KEYS = frozenset(
    {
        "adapter_plan_sha256",
        "manifest_sha256",
        "path",
        "schema_version",
        "sha256",
        "size_bytes",
    }
)
_FORENSIC_INDEX_EXPERIMENT_RESULT_KEYS = frozenset(
    {
        "exit_code",
        "forensic_index_evaluation_artifact_id",
        "forensic_index_execution",
        "receipt_id",
        "run_id",
        "timed_out",
    }
)
_FORENSIC_INDEX_EVALUATION_ARTIFACT_EXTRA_KEYS = frozenset(
    {
        "context_visibility",
        "evaluation_sha256",
        "experiment_id",
        "kind",
        "protocol",
    }
)
_FORENSIC_INDEX_MAX_EVALUATION_BYTES = 1024 * 1024
_FORENSIC_INDEX_MAX_SOURCE_BYTES = 128 * 1024**3


def _forensic_index_exact_dict(
    value: object,
    keys: frozenset[str],
    label: str,
) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != keys:
        raise ModelValidationError(
            f"{label} has missing or unknown fields"
        )
    return value


def _forensic_index_sha256(value: object) -> bool:
    return (
        type(value) is str
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _forensic_index_image_digest(value: object) -> bool:
    return (
        type(value) is str
        and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
    )


def _forensic_index_identifier(value: object) -> bool:
    return (
        type(value) is str
        and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,511}",
            value,
        )
        is not None
    )


def _forensic_index_locator(value: object) -> bool:
    if (
        type(value) is not str
        or not value
        or len(value.encode("utf-8", errors="strict")) > 4096
        or "\\" in value
    ):
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _forensic_index_nonnegative_int(
    value: object,
    *,
    maximum: int = 2**63 - 1,
) -> bool:
    return (
        type(value) is int
        and 0 <= value <= maximum
    )


def _forensic_index_bounded_text(
    value: object,
    *,
    maximum_bytes: int = 512,
) -> bool:
    if type(value) is not str or not value:
        return False
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        return False
    return len(encoded) <= maximum_bytes and all(
        character.isprintable() for character in value
    )


def _forensic_index_execution_from_mapping(
    value: object,
) -> tuple[object, bytes]:
    """Reconstruct one exact raw-free execution evaluation mapping."""

    try:
        from ctf_os.engine.forensic_index import (
            FORENSIC_INDEX_MAX_BYTES,
            FORENSIC_INDEX_MAX_FILES,
            ForensicIndexEvaluation,
            ForensicIndexVerdict,
        )
        from ctf_os.engine.forensic_index_execution import (
            FORENSIC_INDEX_EXECUTION_SCHEMA_VERSION,
            FORENSIC_INDEX_REQUEST_MAX_BYTES,
            ForensicIndexExecutionEnvelope,
            ForensicIndexExecutionEvaluation,
            ForensicIndexExecutionVerdict,
        )
    except (ImportError, ValueError) as error:
        raise ModelValidationError(
            f"Forensic index execution validator unavailable: {error}"
        ) from error

    document = _forensic_index_exact_dict(
        value,
        _FORENSIC_INDEX_EVALUATION_KEYS,
        "Forensic index evaluation",
    )
    if (
        document["protocol"] != _FORENSIC_INDEX_EXECUTION_PROTOCOL
        or type(document["schema_version"]) is not int
        or document["schema_version"]
        != FORENSIC_INDEX_EXECUTION_SCHEMA_VERSION
        or type(document["confirmed"]) is not bool
        or not _forensic_index_bounded_text(document["reason_code"])
    ):
        raise ModelValidationError(
            "Forensic index evaluation header is invalid"
        )

    raw_semantic = document["semantic_evaluation"]
    semantic: object | None
    if raw_semantic is None:
        semantic = None
        if document["semantic_evaluation_sha256"] is not None:
            raise ModelValidationError(
                "Forensic semantic hash exists without its evaluation"
            )
    else:
        semantic_mapping = _forensic_index_exact_dict(
            raw_semantic,
            _FORENSIC_INDEX_SEMANTIC_KEYS,
            "Forensic semantic evaluation",
        )
        claims = _forensic_index_exact_dict(
            semantic_mapping["claims"],
            frozenset(
                {
                    "candidate_ready",
                    "challenge_proof_satisfied",
                    "evidence_index_verified",
                    "impact_proven",
                }
            ),
            "Forensic semantic claims",
        )
        modalities = semantic_mapping["modality_counts"]
        if (
            semantic_mapping["protocol"] != _FORENSIC_INDEX_PROTOCOL
            or type(semantic_mapping["schema_version"]) is not int
            or semantic_mapping["schema_version"] != 1
            or type(modalities) is not dict
            or len(modalities) > 256
            or any(
                not _forensic_index_bounded_text(
                    key,
                    maximum_bytes=128,
                )
                or not _forensic_index_nonnegative_int(count)
                for key, count in modalities.items()
            )
            or not _forensic_index_bounded_text(
                semantic_mapping["reason_code"]
            )
            or not _forensic_index_sha256(
                semantic_mapping["source_inventory_sha256"]
            )
            or not _forensic_index_nonnegative_int(
                semantic_mapping["indexed_files"],
                maximum=FORENSIC_INDEX_MAX_FILES,
            )
            or not _forensic_index_nonnegative_int(
                semantic_mapping["indexed_bytes"],
                maximum=_FORENSIC_INDEX_MAX_SOURCE_BYTES,
            )
            or not _forensic_index_nonnegative_int(
                semantic_mapping["pointer_coverage_ppm"],
                maximum=1_000_000,
            )
            or type(semantic_mapping["verdict"]) is not str
        ):
            raise ModelValidationError(
                "Forensic semantic evaluation fields are invalid"
            )
        try:
            semantic_verdict = ForensicIndexVerdict(
                semantic_mapping["verdict"]
            )
        except (TypeError, ValueError) as error:
            raise ModelValidationError(
                "Forensic semantic verdict is invalid"
            ) from error
        verified = semantic_verdict is ForensicIndexVerdict.CONFIRMED
        expected_claims = {
            "candidate_ready": False,
            "challenge_proof_satisfied": False,
            "evidence_index_verified": verified,
            "impact_proven": False,
        }
        if claims != expected_claims:
            raise ModelValidationError(
                "Forensic semantic claims widened authority"
            )
        if any(type(value) is not bool for value in claims.values()):
            raise ModelValidationError(
                "Forensic semantic claims are not exact booleans"
            )
        if verified:
            if (
                semantic_mapping["reason_code"]
                != "complete_hash_bound_index"
                or not _forensic_index_sha256(
                    semantic_mapping["tree_sha256"]
                )
                or not _forensic_index_sha256(
                    semantic_mapping["index_sha256"]
                )
                or semantic_mapping["pointer_coverage_ppm"]
                != 1_000_000
            ):
                raise ModelValidationError(
                    "confirmed Forensic semantic evaluation is incomplete"
                )
        elif (
            semantic_mapping["tree_sha256"] is not None
            or semantic_mapping["index_sha256"] is not None
            or semantic_mapping["indexed_files"] != 0
            or semantic_mapping["indexed_bytes"] != 0
            or semantic_mapping["pointer_coverage_ppm"] != 0
            or modalities
        ):
            raise ModelValidationError(
                "rejected Forensic semantic evaluation retained authority"
            )
        semantic = ForensicIndexEvaluation(
            verdict=semantic_verdict,
            reason_code=semantic_mapping["reason_code"],
            source_inventory_sha256=(
                semantic_mapping["source_inventory_sha256"]
            ),
            tree_sha256=semantic_mapping["tree_sha256"],
            index_sha256=semantic_mapping["index_sha256"],
            indexed_files=semantic_mapping["indexed_files"],
            indexed_bytes=semantic_mapping["indexed_bytes"],
            pointer_coverage_ppm=(
                semantic_mapping["pointer_coverage_ppm"]
            ),
            modality_counts=tuple(sorted(modalities.items())),
        )
        if (
            semantic_mapping != semantic.to_dict()
            or document["semantic_evaluation_sha256"]
            != semantic.sha256
        ):
            raise ModelValidationError(
                "Forensic semantic evaluation is not canonical"
            )

    raw_envelope = document["envelope"]
    envelope: object | None
    if raw_envelope is None:
        envelope = None
        if document["envelope_sha256"] is not None:
            raise ModelValidationError(
                "Forensic envelope hash exists without its envelope"
            )
    else:
        envelope_mapping = _forensic_index_exact_dict(
            raw_envelope,
            _FORENSIC_INDEX_ENVELOPE_KEYS,
            "Forensic index execution envelope",
        )
        image = _forensic_index_exact_dict(
            envelope_mapping["image"],
            frozenset({"digest", "name"}),
            "Forensic image binding",
        )
        receipt = _forensic_index_exact_dict(
            envelope_mapping["receipt"],
            frozenset({"exit_code", "id", "outcome"}),
            "Forensic receipt binding",
        )
        request = _forensic_index_exact_dict(
            envelope_mapping["request"],
            frozenset({"path", "sha256", "size_bytes"}),
            "Forensic request binding",
        )
        run = _forensic_index_exact_dict(
            envelope_mapping["run"],
            frozenset(
                {
                    "id",
                    "origin",
                    "result_path",
                    "status",
                    "validation_path",
                }
            ),
            "Forensic run binding",
        )
        source = _forensic_index_exact_dict(
            envelope_mapping["source"],
            frozenset(
                {
                    "file_count",
                    "inventory_sha256",
                    "manifest_sha256",
                    "total_bytes",
                }
            ),
            "Forensic source binding",
        )
        stdout = _forensic_index_exact_dict(
            envelope_mapping["stdout_artifact"],
            frozenset(
                {
                    "id",
                    "path",
                    "sha256",
                    "size_bytes",
                    "source_run_id",
                }
            ),
            "Forensic stdout binding",
        )
        transport = _forensic_index_exact_dict(
            envelope_mapping["transport"],
            frozenset(
                {
                    "capture_complete",
                    "coverage",
                    "network",
                    "truncated",
                    "truncation_known",
                }
            ),
            "Forensic transport binding",
        )
        if (
            envelope_mapping["category"] != "forensics"
            or envelope_mapping["protocol"]
            != _FORENSIC_INDEX_EXECUTION_PROTOCOL
            or type(envelope_mapping["schema_version"]) is not int
            or envelope_mapping["schema_version"]
            != FORENSIC_INDEX_EXECUTION_SCHEMA_VERSION
            or not _forensic_index_bounded_text(
                envelope_mapping["contest_id"]
            )
            or not _forensic_index_bounded_text(
                envelope_mapping["challenge_id"]
            )
            or not _forensic_index_bounded_text(
                envelope_mapping["experiment_id"]
            )
            or not _forensic_index_nonnegative_int(
                envelope_mapping["configuration_epoch"]
            )
            or envelope_mapping["prefix_coverage_ppm"] != 1_000_000
            or not _forensic_index_bounded_text(image["name"])
            or not _forensic_index_image_digest(image["digest"])
            or type(receipt["exit_code"]) is not int
            or receipt["exit_code"] != 0
            or type(receipt["outcome"]) is not str
            or receipt["outcome"] != ReceiptOutcome.SUCCEEDED.value
            or not _forensic_index_identifier(receipt["id"])
            or not _forensic_index_locator(request["path"])
            or not _forensic_index_sha256(request["sha256"])
            or not _forensic_index_nonnegative_int(
                request["size_bytes"],
                maximum=FORENSIC_INDEX_REQUEST_MAX_BYTES,
            )
            or request["size_bytes"] < 1
            or not _forensic_index_identifier(run["id"])
            or type(run["origin"]) is not str
            or run["origin"]
            not in {
                RunOrigin.MANAGED_TOOL.value,
                RunOrigin.OPERATOR_TOOL.value,
            }
            or type(run["status"]) is not str
            or run["status"] != RunStatus.COMPLETED.value
            or not _forensic_index_locator(run["result_path"])
            or not _forensic_index_locator(run["validation_path"])
            or len(
                {
                    request["path"],
                    run["result_path"],
                    run["validation_path"],
                }
            )
            != 3
            or not _forensic_index_sha256(source["manifest_sha256"])
            or not _forensic_index_sha256(source["inventory_sha256"])
            or not _forensic_index_nonnegative_int(
                source["file_count"],
                maximum=FORENSIC_INDEX_MAX_FILES,
            )
            or not _forensic_index_nonnegative_int(
                source["total_bytes"],
                maximum=_FORENSIC_INDEX_MAX_SOURCE_BYTES,
            )
            or not _forensic_index_identifier(stdout["id"])
            or not _forensic_index_locator(stdout["path"])
            or not _forensic_index_sha256(stdout["sha256"])
            or not _forensic_index_nonnegative_int(
                stdout["size_bytes"],
                maximum=FORENSIC_INDEX_MAX_BYTES,
            )
            or stdout["size_bytes"] < 1
            or stdout["source_run_id"] != run["id"]
            or any(
                type(transport[field]) is not bool
                for field in (
                    "capture_complete",
                    "truncated",
                    "truncation_known",
                )
            )
            or type(transport["coverage"]) is not str
            or type(transport["network"]) is not str
            or transport
            != {
                "capture_complete": True,
                "coverage": "complete_stream",
                "network": "none",
                "truncated": False,
                "truncation_known": True,
            }
        ):
            raise ModelValidationError(
                "Forensic execution envelope fields are invalid"
            )
        envelope = ForensicIndexExecutionEnvelope(
            category=envelope_mapping["category"],
            contest_id=envelope_mapping["contest_id"],
            challenge_id=envelope_mapping["challenge_id"],
            configuration_epoch=(
                envelope_mapping["configuration_epoch"]
            ),
            experiment_id=envelope_mapping["experiment_id"],
            run_id=run["id"],
            run_origin=run["origin"],
            request_path=request["path"],
            request_sha256=request["sha256"],
            request_size_bytes=request["size_bytes"],
            result_path=run["result_path"],
            validation_path=run["validation_path"],
            receipt_id=receipt["id"],
            image_name=image["name"],
            image_digest=image["digest"],
            source_manifest_sha256=source["manifest_sha256"],
            source_inventory_sha256=source["inventory_sha256"],
            source_file_count=source["file_count"],
            source_total_bytes=source["total_bytes"],
            prefix_coverage_ppm=(
                envelope_mapping["prefix_coverage_ppm"]
            ),
            stdout_artifact_id=stdout["id"],
            stdout_artifact_path=stdout["path"],
            stdout_artifact_sha256=stdout["sha256"],
            stdout_artifact_size_bytes=stdout["size_bytes"],
        )
        if (
            envelope_mapping != envelope.to_dict()
            or document["envelope_sha256"] != envelope.sha256
        ):
            raise ModelValidationError(
                "Forensic execution envelope is not canonical"
            )

    if envelope is None and semantic is not None:
        raise ModelValidationError(
            "Forensic semantic evaluation lacks its execution envelope"
        )
    if envelope is not None and semantic is None:
        raise ModelValidationError(
            "Forensic execution envelope lacks its semantic evaluation"
        )
    if (
        envelope is not None
        and semantic is not None
        and (
            semantic.source_inventory_sha256
            != envelope.source_inventory_sha256
            or (
                semantic.verdict is ForensicIndexVerdict.CONFIRMED
                and (
                    semantic.indexed_files != envelope.source_file_count
                    or semantic.indexed_bytes
                    != envelope.source_total_bytes
                )
            )
        )
    ):
        raise ModelValidationError(
            "Forensic semantic/source inventory binding is inconsistent"
        )
    try:
        if type(document["verdict"]) is not str:
            raise ModelValidationError(
                "Forensic execution verdict is not an exact string"
            )
        evaluation = ForensicIndexExecutionEvaluation(
            verdict=ForensicIndexExecutionVerdict(document["verdict"]),
            reason_code=document["reason_code"],
            envelope=envelope,
            semantic_evaluation=semantic,
        )
    except (TypeError, ValueError) as error:
        raise ModelValidationError(
            "Forensic execution verdict is invalid"
        ) from error
    authorities = _forensic_index_exact_dict(
        document["authorities"],
        _FORENSIC_INDEX_AUTHORITY_KEYS,
        "Forensic execution authorities",
    )
    expected_authorities = {
        "automatic_submission_authorized": False,
        "candidate_authorized": False,
        "challenge_proof_satisfied": False,
        "executed_evidence_index_fact_authorized": evaluation.confirmed,
        "impact_proven": False,
        "progress_marker_authorized": evaluation.confirmed,
    }
    if (
        any(type(value) is not bool for value in authorities.values())
        or authorities != expected_authorities
        or document["confirmed"] is not evaluation.confirmed
        or document != evaluation.to_dict()
        or (
            evaluation.confirmed
            and evaluation.reason_code
            != "complete_executed_evidence_index"
        )
        or (
            evaluation.confirmed
            and evaluation.verdict
            is not ForensicIndexExecutionVerdict.CONFIRMED
        )
        or (
            not evaluation.confirmed
            and evaluation.verdict
            is not ForensicIndexExecutionVerdict.REJECTED
        )
    ):
        raise ModelValidationError(
            "Forensic execution evaluation is inconsistent"
        )
    encoded = evaluation.canonical_bytes
    if len(encoded) > _FORENSIC_INDEX_MAX_EVALUATION_BYTES:
        raise ModelValidationError(
            "Forensic execution evaluation exceeds its size bound"
        )
    return evaluation, encoded


def _forensic_index_seed_binding_errors(
    state: "ChallengeState",
    experiment: Experiment,
    run: RunReference,
) -> list[str]:
    errors: list[str] = []
    label = f"Forensic index experiment {experiment.id}"
    manifest = state.metadata.get("source_manifest_sha256")
    source_binding = experiment.extra.get("source_binding")
    if (
        state.category != "forensics"
        or experiment.kind is not ExperimentKind.PROBE
        or experiment.hypothesis_ids
        or experiment.extra.get("adapter_seed") is not True
        or experiment.extra.get("adapter_name") != "forensics"
        or type(
            experiment.extra.get("adapter_seed_contract_version")
        )
        is not int
        or experiment.extra.get("adapter_seed_contract_version") != 1
        or type(experiment.extra.get("adapter_seed_order")) is not int
        or experiment.extra.get("adapter_seed_order") != 0
        or experiment.extra.get("adapter_spec_template_id")
        != "file_inventory"
        or experiment.extra.get("requires_explicit_execution") is not True
        or experiment.extra.get("partial_oracle") is not None
        or experiment.extra.get("source_snapshot") is not None
        or not _forensic_index_sha256(
            experiment.extra.get("adapter_spec_sha256")
        )
        or experiment.extra.get("adapter_spec_id")
        != "file_inventory@"
        + str(experiment.extra.get("adapter_spec_sha256"))
        or not _forensic_index_sha256(manifest)
        or type(source_binding) is not dict
        or frozenset(source_binding)
        != _FORENSIC_INDEX_SOURCE_BINDING_KEYS
        or type(source_binding.get("schema_version")) is not int
        or source_binding.get("schema_version") != 1
        or source_binding.get("manifest_sha256") != manifest
        or not _forensic_index_sha256(
            source_binding.get("adapter_plan_sha256")
        )
        or state.metadata.get("adapter_seed_source_binding")
        != source_binding
        or state.metadata.get("adapter_seed_plan_sha256")
        != source_binding.get("adapter_plan_sha256")
        or (
            source_binding.get("path") is not None
            and type(source_binding.get("path")) is not str
        )
        or (
            source_binding.get("sha256") is not None
            and not _forensic_index_sha256(
                source_binding.get("sha256")
            )
        )
        or (
            source_binding.get("size_bytes") is not None
            and not _forensic_index_nonnegative_int(
                source_binding.get("size_bytes"),
                maximum=_FORENSIC_INDEX_MAX_SOURCE_BYTES,
            )
        )
    ):
        errors.append(f"{label} seed/source binding is invalid")
        return errors
    primary_path = source_binding.get("path")
    if state.source_inventory:
        matching = [
            source
            for source in state.source_inventory
            if source.path == primary_path
        ]
        if (
            len(matching) != 1
            or source_binding.get("sha256") != matching[0].sha256
            or source_binding.get("size_bytes") != matching[0].size
        ):
            errors.append(f"{label} primary source binding is invalid")
    elif any(
        source_binding.get(key) is not None
        for key in ("path", "sha256", "size_bytes")
    ):
        errors.append(f"{label} empty source binding is invalid")
    if (
        run.extra.get("experiment_id") != experiment.id
        or any(
            run.extra.get(key) != experiment.extra.get(key)
            for key in _FORENSIC_INDEX_SEED_COPY_KEYS
        )
    ):
        errors.append(f"{label} run seed binding is invalid")
    return errors


def _forensic_index_execution_state_errors(
    state: "ChallengeState",
    *,
    experiments: Mapping[str, Experiment],
    runs: Mapping[str, RunReference],
    receipts: Mapping[str, ExecutionReceipt],
    artifacts: Mapping[str, ArtifactReference],
    facts: Mapping[str, Fact],
) -> list[str]:
    """Validate the exact durable Forensic index execution state graph."""

    errors: list[str] = []
    bindings_by_artifact: dict[str, dict[str, object]] = {}
    bound_run_ids: set[str] = set()
    bound_receipt_ids: set[str] = set()
    bound_fact_ids: set[str] = set()
    bound_progress_ids: set[str] = set()

    global_owners: dict[str, list[str]] = {}
    for collection_name, records in (
        ("experiment", state.experiments),
        ("run", state.runs),
        ("receipt", state.receipts),
        ("artifact", state.artifacts),
        ("fact", state.facts),
        ("progress", state.progress_markers),
        ("hypothesis", state.hypotheses),
        ("goal", state.goals),
        ("candidate", state.candidates),
        ("submission", state.submissions),
        ("session", state.sessions),
        ("cycle", state.cycles),
        ("wave", state.waves),
        ("checkpoint", state.checkpoints),
        ("target", state.targets),
        ("workspace_publish", state.workspace_publishes),
    ):
        for record in records:
            global_owners.setdefault(record.id, []).append(
                collection_name
            )

    for experiment in state.experiments:
        result = experiment.result
        has_execution = (
            type(result) is dict
            and (
                "forensic_index_execution" in result
                or "forensic_index_evaluation_artifact_id" in result
            )
        )
        if not has_execution:
            continue
        label = f"Forensic index experiment {experiment.id}"
        try:
            result_mapping = _forensic_index_exact_dict(
                result,
                _FORENSIC_INDEX_EXPERIMENT_RESULT_KEYS,
                f"{label} result",
            )
            run_id = result_mapping["run_id"]
            receipt_id = result_mapping["receipt_id"]
            evaluation_artifact_id = result_mapping[
                "forensic_index_evaluation_artifact_id"
            ]
            if (
                not _forensic_index_identifier(run_id)
                or not _forensic_index_identifier(receipt_id)
                or not _forensic_index_identifier(
                    evaluation_artifact_id
                )
                or type(result_mapping["exit_code"]) is not int
                or type(result_mapping["timed_out"]) is not bool
            ):
                raise ModelValidationError(
                    "result run/receipt/transport fields are invalid"
                )
            if (
                not _forensic_index_nonnegative_int(
                    state.configuration_epoch
                )
                or not _forensic_index_sha256(
                    state.metadata.get("source_manifest_sha256")
                )
                or any(
                    type(source.path) is not str
                    or not _forensic_index_locator(source.path)
                    or not _forensic_index_sha256(source.sha256)
                    or not _forensic_index_nonnegative_int(
                        source.size,
                        maximum=_FORENSIC_INDEX_MAX_SOURCE_BYTES,
                    )
                    or source.kind != "file"
                    for source in state.source_inventory
                )
            ):
                raise ModelValidationError(
                    "canonical state source/configuration is invalid"
                )
            if evaluation_artifact_id in bindings_by_artifact:
                raise ModelValidationError(
                    "evaluation artifact is bound more than once"
                )
            run = runs.get(run_id)
            receipt = receipts.get(receipt_id)
            evaluation_artifact = artifacts.get(
                evaluation_artifact_id
            )
            if (
                run is None
                or receipt is None
                or evaluation_artifact is None
            ):
                raise ModelValidationError(
                    "run, receipt, or evaluation artifact is missing"
                )
            evaluation, encoded = (
                _forensic_index_execution_from_mapping(
                    result_mapping["forensic_index_execution"]
                )
            )
            evaluation_payload = evaluation.to_dict()
            evaluation_sha256 = hashlib.sha256(encoded).hexdigest()
            if (
                run.extra.get("forensic_index_execution")
                != evaluation_payload
                or receipt.extra.get("forensic_index_execution")
                != evaluation_payload
                or frozenset(run.extra)
                != _FORENSIC_INDEX_RUN_EXTRA_KEYS
                or frozenset(receipt.extra)
                != _FORENSIC_INDEX_RECEIPT_EXTRA_KEYS
            ):
                raise ModelValidationError(
                    "evaluation copies were stripped or rebound"
                )
            errors.extend(
                _forensic_index_seed_binding_errors(
                    state,
                    experiment,
                    run,
                )
            )
            expected_run_status = (
                RunStatus.TIMED_OUT
                if result_mapping["timed_out"]
                else RunStatus.COMPLETED
                if result_mapping["exit_code"] == 0
                else RunStatus.FAILED
            )
            expected_receipt_outcome = (
                ReceiptOutcome.TIMED_OUT
                if result_mapping["timed_out"]
                else ReceiptOutcome.SUCCEEDED
                if result_mapping["exit_code"] == 0
                else ReceiptOutcome.FAILED
            )
            stdout_artifact = artifacts.get(
                receipt.stdout_artifact_id or ""
            )
            stderr_artifact = artifacts.get(
                receipt.stderr_artifact_id or ""
            )
            stream_evidence = receipt.extra.get("stream_evidence")
            stdout_stream = (
                stream_evidence.get("stdout")
                if type(stream_evidence) is dict
                else None
            )
            stderr_stream = (
                stream_evidence.get("stderr")
                if type(stream_evidence) is dict
                else None
            )
            if (
                run.status is not expected_run_status
                or run.role != "tool"
                or run.origin
                not in {
                    RunOrigin.MANAGED_TOOL,
                    RunOrigin.OPERATOR_TOOL,
                }
                or type(run.configuration_epoch) is not int
                or run.configuration_epoch != state.configuration_epoch
                or receipt.experiment_id != experiment.id
                or receipt.run_id != run.id
                or receipt.outcome is not expected_receipt_outcome
                or type(receipt.exit_code) is not int
                or receipt.exit_code != result_mapping["exit_code"]
                or stdout_artifact is None
                or stdout_artifact.source_run_id != run.id
                or frozenset(stdout_artifact.extra)
                != {"source_locator", "stream"}
                or stdout_artifact.extra.get("stream") != "stdout"
                or not _forensic_index_locator(
                    stdout_artifact.extra.get("source_locator")
                )
                or PurePosixPath(
                    stdout_artifact.extra["source_locator"]
                ).name
                != "stdout.log"
                or type(stdout_artifact.size) is not int
                or type(receipt.stdout_bytes) is not int
                or stdout_artifact.size != receipt.stdout_bytes
                or stderr_artifact is None
                or stderr_artifact.source_run_id != run.id
                or frozenset(stderr_artifact.extra)
                != {"source_locator", "stream"}
                or stderr_artifact.extra.get("stream") != "stderr"
                or not _forensic_index_locator(
                    stderr_artifact.extra.get("source_locator")
                )
                or PurePosixPath(
                    stderr_artifact.extra["source_locator"]
                ).name
                != "stderr.log"
                or type(stderr_artifact.size) is not int
                or type(receipt.stderr_bytes) is not int
                or stderr_artifact.size != receipt.stderr_bytes
                or type(stream_evidence) is not dict
                or frozenset(stream_evidence) != {"stdout", "stderr"}
                or type(stdout_stream) is not dict
                or type(stderr_stream) is not dict
                or stdout_stream.get("artifact_id")
                != stdout_artifact.id
                or stdout_stream.get("path") != stdout_artifact.path
                or stdout_stream.get("sha256")
                != stdout_artifact.sha256
                or stdout_stream.get("stored_bytes")
                != stdout_artifact.size
                or stdout_stream.get("drained_bytes")
                != receipt.stdout_bytes
                or stdout_stream.get("stream") != "stdout"
                or stderr_stream.get("artifact_id")
                != stderr_artifact.id
                or stderr_stream.get("path") != stderr_artifact.path
                or stderr_stream.get("sha256")
                != stderr_artifact.sha256
                or stderr_stream.get("stored_bytes")
                != stderr_artifact.size
                or stderr_stream.get("drained_bytes")
                != receipt.stderr_bytes
                or stderr_stream.get("stream") != "stderr"
                or receipt.extra.get("line_count_basis")
                != "transport_summary_tail"
                or stdout_artifact.id not in experiment.artifact_ids
                or run.id not in experiment.evidence_run_ids
                or receipt.id not in experiment.evidence_receipt_ids
            ):
                raise ModelValidationError(
                    "run/receipt/stdout state binding is invalid"
                )
            if (
                type(run.extra.get("wall_seconds")) not in {int, float}
                or isinstance(run.extra.get("wall_seconds"), bool)
                or run.extra.get("wall_seconds") < 0
                or type(receipt.wall_seconds) not in {int, float}
                or isinstance(receipt.wall_seconds, bool)
                or receipt.wall_seconds < 0
                or run.extra.get("wall_seconds")
                != receipt.wall_seconds
            ):
                raise ModelValidationError(
                    "run/receipt wall time binding is invalid"
                )
            if (
                experiment.evidence_run_ids != [run.id]
                or experiment.evidence_receipt_ids != [receipt.id]
                or experiment.artifact_ids
                != [
                    stdout_artifact.id,
                    stderr_artifact.id,
                    evaluation_artifact.id,
                ]
            ):
                raise ModelValidationError(
                    "experiment evidence references are not exact"
                )
            if (
                evaluation_artifact.path
                != (
                    "artifacts/snapshots/"
                    f"{evaluation_artifact.id}.json"
                )
                or evaluation_artifact.source_run_id != run.id
                or evaluation_artifact.sha256 != evaluation_sha256
                or type(evaluation_artifact.size) is not int
                or evaluation_artifact.size != len(encoded)
                or evaluation_artifact.extra
                != {
                    "context_visibility": "model_visible",
                    "evaluation_sha256": evaluation_sha256,
                    "experiment_id": experiment.id,
                    "kind": (
                        "forensic_index_execution_evaluation"
                    ),
                    "protocol": _FORENSIC_INDEX_EXECUTION_PROTOCOL,
                    **(
                        {"run_id": run.id}
                        if "run_id" in evaluation_artifact.extra
                        else {}
                    ),
                }
                or frozenset(evaluation_artifact.extra)
                not in {
                    _FORENSIC_INDEX_EVALUATION_ARTIFACT_EXTRA_KEYS,
                    _FORENSIC_INDEX_EVALUATION_ARTIFACT_EXTRA_KEYS
                    | {"run_id"},
                }
            ):
                raise ModelValidationError(
                    "evaluation artifact binding is invalid"
                )
            expected_status = (
                ExperimentStatus.COMPLETED
                if evaluation.confirmed
                else ExperimentStatus.FAILED
            )
            expected_reason = (
                "forensic_index:"
                f"{evaluation.verdict.value}:"
                f"{evaluation.reason_code}"
            )[:512]
            if (
                experiment.status is not expected_status
                or experiment.evaluation_reason != expected_reason
                or not _forensic_index_bounded_text(
                    experiment.evaluated_at,
                    maximum_bytes=128,
                )
            ):
                raise ModelValidationError(
                    "experiment status/evaluation binding is invalid"
                )
            envelope = evaluation.envelope
            if envelope is not None:
                if (
                    result_mapping["exit_code"] != 0
                    or result_mapping["timed_out"] is not False
                    or run.status is not RunStatus.COMPLETED
                    or receipt.outcome is not ReceiptOutcome.SUCCEEDED
                    or receipt.exit_code != 0
                    or envelope.contest_id != state.contest_id
                    or envelope.challenge_id != state.challenge_id
                    or envelope.experiment_id != experiment.id
                    or envelope.configuration_epoch
                    != state.configuration_epoch
                    or envelope.run_id != run.id
                    or envelope.run_origin != run.origin.value
                    or envelope.request_path != run.request_path
                    or envelope.result_path != run.result_path
                    or envelope.validation_path != run.validation_path
                    or envelope.receipt_id != receipt.id
                    or envelope.source_manifest_sha256
                    != state.metadata.get("source_manifest_sha256")
                    or envelope.source_file_count
                    != len(state.source_inventory)
                    or envelope.source_total_bytes
                    != sum(
                        source.size for source in state.source_inventory
                    )
                    or envelope.stdout_artifact_id
                    != stdout_artifact.id
                    or envelope.stdout_artifact_path
                    != stdout_artifact.path
                    or envelope.stdout_artifact_sha256
                    != stdout_artifact.sha256
                    or envelope.stdout_artifact_size_bytes
                    != stdout_artifact.size
                ):
                    raise ModelValidationError(
                        "execution envelope was rebound to state"
                    )
            elif evaluation.confirmed:
                raise ModelValidationError(
                    "confirmed evaluation lacks its envelope"
                )

            reduction = evaluation.reduction_projection()
            matching_facts = [
                fact
                for fact in state.facts
                if "forensic_evidence_index" in fact.extra
                and (
                    fact.extra.get("forensic_evidence_index")
                    == (
                        reduction["executed_fact"] or {}
                    ).get("extra", {}).get(
                        "forensic_evidence_index"
                    )
                )
            ]
            matching_markers = [
                marker
                for marker in state.progress_markers
                if "forensic_evidence_index" in marker.extra
                and (
                    marker.extra.get("forensic_evidence_index")
                    == (
                        reduction["progress"] or {}
                    ).get("extra", {}).get(
                        "forensic_evidence_index"
                    )
                )
            ]
            if evaluation.confirmed:
                fact_payload = reduction["executed_fact"]
                progress_payload = reduction["progress"]
                if (
                    type(fact_payload) is not dict
                    or type(progress_payload) is not dict
                    or len(matching_facts) != 1
                    or len(matching_markers) != 1
                ):
                    raise ModelValidationError(
                        "confirmed evaluation lacks exact fact/progress"
                    )
                fact = matching_facts[0]
                marker = matching_markers[0]
                if (
                    fact.provenance is not Provenance.EXECUTED
                    or fact.kind is not FactKind.OBSERVATION
                    or fact.challenge_id != state.challenge_id
                    or fact.statement != fact_payload["statement"]
                    or fact.source_run_id
                    != fact_payload["source_run_id"]
                    or fact.artifact_id != fact_payload["artifact_id"]
                    or fact.locator != fact_payload["locator"]
                    or fact.extra != fact_payload["extra"]
                    or fact.supersedes_id is not None
                    or fact.supports
                    or fact.contradicts
                    or marker.statement
                    != progress_payload["statement"]
                    or marker.run_id != progress_payload["run_id"]
                    or marker.artifact_ids
                    != progress_payload["artifact_ids"]
                    or marker.extra != progress_payload["extra"]
                    or marker.goal_id is not None
                    or marker.elapsed_seconds is not None
                    or experiment.evidence_fact_ids != [fact.id]
                ):
                    raise ModelValidationError(
                        "fact/progress reduction was stripped or rebound"
                    )
                bound_fact_ids.add(fact.id)
                bound_progress_ids.add(marker.id)
                graph_ids = {
                    experiment.id,
                    run.id,
                    receipt.id,
                    stdout_artifact.id,
                    evaluation_artifact.id,
                    stderr_artifact.id,
                    fact.id,
                    marker.id,
                }
            else:
                if (
                    matching_facts
                    or matching_markers
                    or experiment.evidence_fact_ids
                ):
                    raise ModelValidationError(
                        "rejected evaluation retained fact/progress authority"
                    )
                graph_ids = {
                    experiment.id,
                    run.id,
                    receipt.id,
                    stdout_artifact.id,
                    evaluation_artifact.id,
                    stderr_artifact.id,
                }
            if len(graph_ids) != (
                8 if evaluation.confirmed else 6
            ) or any(
                len(global_owners.get(record_id, [])) != 1
                for record_id in graph_ids
            ):
                raise ModelValidationError(
                    "Forensic graph ids are duplicated globally"
                )
            bindings_by_artifact[evaluation_artifact.id] = {
                "experiment_id": experiment.id,
                "evaluation_sha256": evaluation_sha256,
                "run_id": run.id,
            }
            bound_run_ids.add(run.id)
            bound_receipt_ids.add(receipt.id)
        except (
            KeyError,
            ModelValidationError,
            TypeError,
            UnicodeError,
            ValueError,
        ) as error:
            errors.append(f"{label} is invalid: {error}")

    for artifact in state.artifacts:
        if (
            artifact.extra.get("kind")
            == "forensic_index_execution_evaluation"
            or artifact.extra.get("protocol")
            == _FORENSIC_INDEX_EXECUTION_PROTOCOL
        ) and artifact.id not in bindings_by_artifact:
            errors.append(
                f"orphan Forensic index evaluation artifact {artifact.id}"
            )
    for run in state.runs:
        if (
            "forensic_index_execution" in run.extra
            and run.id not in bound_run_ids
        ):
            errors.append(f"orphan Forensic index run {run.id}")
    for receipt in state.receipts:
        if (
            "forensic_index_execution" in receipt.extra
            and receipt.id not in bound_receipt_ids
        ):
            errors.append(f"orphan Forensic index receipt {receipt.id}")
    for fact in state.facts:
        if (
            "forensic_evidence_index" in fact.extra
            and fact.id not in bound_fact_ids
        ):
            errors.append(f"orphan Forensic index fact {fact.id}")
    for marker in state.progress_markers:
        if (
            "forensic_evidence_index" in marker.extra
            and marker.id not in bound_progress_ids
        ):
            errors.append(
                f"orphan Forensic index progress marker {marker.id}"
            )
    return errors


_MISC_TRANSFORM_PROTOCOL = "misc_sandbox_transform_dag_reverse_v1"
_MISC_TRANSFORM_BINDING_KEYS = frozenset(
    {
        "artifact_id",
        "automatic_submission_authorized",
        "candidate_sha256",
        "evaluation",
        "evaluation_sha256",
        "misc_evaluation_id",
        "oracle_authority",
        "passed",
        "plan_sha256",
        "protocol",
        "run_ids",
        "source_manifest_sha256",
    }
)
_MISC_TRANSFORM_MANAGED_BINDING_KEYS = frozenset(
    {
        *_MISC_TRANSFORM_BINDING_KEYS,
        "oracle_preissue_id",
        "oracle_control_run_ids",
        "oracle_control_status",
        "oracle_negative_control_passed",
    }
)


def _misc_transform_state_errors(
    state: "ChallengeState",
    *,
    runs: Mapping[str, RunReference],
    artifacts: Mapping[str, ArtifactReference],
    facts: Mapping[str, Fact],
    candidates: Mapping[str, FlagCandidate],
) -> list[str]:
    """Validate the durable executable Misc receipt graph.

    Failed/interrupted attempts may retain input artifacts and terminal runs.
    A finalized evaluation, especially a passed one, is accepted only when its
    candidate, immutable sources, ordered run matrix, exact record copies,
    evaluation artifact, fact, and progress marker all remain bound.
    """

    errors: list[str] = []
    try:
        from ctf_os.engine.misc_transform import (
            MISC_TRANSFORM_MAX_EVIDENCE_BYTES,
            MISC_TRANSFORM_SCHEMA_VERSION,
            MISC_TRANSFORM_VERIFICATION_REPEATS,
            misc_transform_canonical_json_bytes,
        )
    except (ImportError, ValueError) as error:
        return [f"Misc transform validator unavailable: {error}"]

    bindings: dict[str, tuple[FlagCandidate, Mapping[str, object]]] = {}
    for candidate in state.candidates:
        raw = candidate.extra.get("misc_transform_evidence")
        if raw is None:
            continue
        label = f"Misc candidate {candidate.id} transform evidence"
        if not isinstance(raw, Mapping):
            errors.append(f"{label} must be an object")
            continue
        evaluation_id = raw.get("misc_evaluation_id")
        if type(evaluation_id) is not str or not evaluation_id:
            errors.append(f"{label} has an invalid evaluation id")
            continue
        if evaluation_id in bindings:
            errors.append(
                f"Misc evaluation id {evaluation_id} is bound more than once"
            )
            continue
        bindings[evaluation_id] = (candidate, raw)

    for evaluation_id, (candidate, binding) in bindings.items():
        label = f"Misc evaluation {evaluation_id}"
        try:
            binding_keys = frozenset(binding)
            if binding_keys not in {
                _MISC_TRANSFORM_BINDING_KEYS,
                _MISC_TRANSFORM_MANAGED_BINDING_KEYS,
            }:
                raise ModelValidationError(
                    "binding has unknown or missing fields"
                )
            managed_oracle = (
                binding_keys == _MISC_TRANSFORM_MANAGED_BINDING_KEYS
            )
            evaluation = binding["evaluation"]
            run_ids = binding["run_ids"]
            if (
                binding["protocol"] != _MISC_TRANSFORM_PROTOCOL
                or binding["oracle_authority"]
                != (
                    "managed_oracle_preissue_v1"
                    if managed_oracle
                    else "explicit_operator_exit_status"
                )
                or binding["automatic_submission_authorized"] is not False
                or type(binding["passed"]) is not bool
                or type(binding["evaluation_sha256"]) is not str
                or not re.fullmatch(
                    r"[0-9a-f]{64}",
                    binding["evaluation_sha256"],
                )
                or type(binding["plan_sha256"]) is not str
                or not re.fullmatch(
                    r"[0-9a-f]{64}",
                    binding["plan_sha256"],
                )
                or type(binding["candidate_sha256"]) is not str
                or binding["candidate_sha256"]
                != hashlib.sha256(
                    candidate.value.encode("utf-8", errors="strict")
                ).hexdigest()
                or type(binding["source_manifest_sha256"]) is not str
                or binding["source_manifest_sha256"]
                != state.metadata.get("source_manifest_sha256")
                or type(run_ids) is not list
                or not run_ids
                or any(type(run_id) is not str for run_id in run_ids)
                or len(set(run_ids)) != len(run_ids)
                or not isinstance(evaluation, Mapping)
            ):
                raise ModelValidationError("binding fields are inconsistent")
            if managed_oracle:
                preissue_id = binding["oracle_preissue_id"]
                control_run_ids = binding["oracle_control_run_ids"]
                control_status = binding["oracle_control_status"]
                control_passed = binding[
                    "oracle_negative_control_passed"
                ]
                history = state.extra.get("managed_oracle_preissues")
                preissue = (
                    history.get(preissue_id)
                    if type(history) is dict
                    and type(preissue_id) is str
                    else None
                )
                if (
                    type(preissue_id) is not str
                    or not re.fullmatch(
                        r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}",
                        preissue_id,
                    )
                    or type(control_run_ids) is not list
                    or len(control_run_ids) not in {0, 1}
                    or any(
                        type(run_id) is not str
                        for run_id in control_run_ids
                    )
                    or control_status
                    not in {"not_run", "passed", "failed"}
                    or type(control_passed) is not bool
                    or not isinstance(preissue, Mapping)
                    or preissue.get("preissue_id") != preissue_id
                    or preissue.get("kind") != "misc"
                    or preissue.get("status") != "consumed"
                    or preissue.get("issuer") != "operator"
                    or preissue.get("configuration_epoch")
                    != state.configuration_epoch
                    or preissue.get("source_manifest_sha256")
                    != state.metadata.get("source_manifest_sha256")
                ):
                    raise ModelValidationError(
                        "managed oracle binding is inconsistent"
                    )
                if (
                    (
                        control_status == "not_run"
                        and (
                            control_run_ids
                            or control_passed
                            or binding["passed"]
                        )
                    )
                    or (
                        control_status == "passed"
                        and (
                            len(control_run_ids) != 1
                            or control_passed is not True
                        )
                    )
                    or (
                        control_status == "failed"
                        and (
                            len(control_run_ids) != 1
                            or control_passed is not False
                            or binding["passed"]
                        )
                    )
                ):
                    raise ModelValidationError(
                        "managed oracle control status is inconsistent"
                    )
                if control_run_ids:
                    control_run = runs.get(control_run_ids[0])
                    control_streams = [
                        artifact
                        for artifact in artifacts.values()
                        if (
                            artifact.source_run_id == control_run_ids[0]
                            and artifact.extra.get("kind")
                            == "misc_transform_stream"
                            and artifact.extra.get("phase")
                            == "oracle-control"
                            and artifact.extra.get("misc_evaluation_id")
                            == evaluation_id
                        )
                    ]
                    if (
                        control_run is None
                        or control_run.extra.get("phase")
                        != "oracle-control"
                        or control_run.extra.get("misc_evaluation_id")
                        != evaluation_id
                        or control_run.extra.get("oracle_preissue_id")
                        != preissue_id
                        or control_run.extra.get(
                            "negative_control_rejected"
                        )
                        is not control_passed
                        or len(control_streams) != 2
                        or {
                            artifact.extra.get("stream")
                            for artifact in control_streams
                        }
                        != {"stdout", "stderr"}
                        or any(
                            artifact.extra.get("context_visibility")
                            != "engine_private"
                            for artifact in control_streams
                        )
                    ):
                        raise ModelValidationError(
                            "managed oracle control run is inconsistent"
                        )
            expected_evaluation_keys = frozenset(
                {
                    "authorities",
                    "failure_codes",
                    "passed",
                    "plan",
                    "plan_sha256",
                    "protocol",
                    "reverse_verifications",
                    "schema_version",
                    "transform_nodes",
                }
            )
            if frozenset(evaluation) != expected_evaluation_keys:
                raise ModelValidationError(
                    "evaluation has unknown or missing fields"
                )
            if (
                evaluation["protocol"] != _MISC_TRANSFORM_PROTOCOL
                or evaluation["schema_version"]
                != MISC_TRANSFORM_SCHEMA_VERSION
                or evaluation["passed"] is not binding["passed"]
                or evaluation["plan_sha256"] != binding["plan_sha256"]
                or not isinstance(evaluation["plan"], Mapping)
                or type(evaluation["failure_codes"]) is not list
                or any(
                    type(code) is not str
                    for code in evaluation["failure_codes"]
                )
                or type(evaluation["transform_nodes"]) is not list
                or type(evaluation["reverse_verifications"]) is not list
                or evaluation["authorities"]
                != {
                    "automatic_submission_authorized": False,
                    "candidate_original_condition_verified": (
                        binding["passed"]
                    ),
                }
            ):
                raise ModelValidationError("evaluation fields are inconsistent")
            if (
                managed_oracle
                and binding["oracle_control_status"]
                in {"not_run", "failed"}
                and (
                    binding["passed"]
                    or not evaluation["failure_codes"]
                )
            ):
                raise ModelValidationError(
                    "managed oracle control failure lacks a failed evaluation"
                )
            encoded = misc_transform_canonical_json_bytes(evaluation)
            if (
                len(encoded) > MISC_TRANSFORM_MAX_EVIDENCE_BYTES
                or hashlib.sha256(encoded).hexdigest()
                != binding["evaluation_sha256"]
            ):
                raise ModelValidationError(
                    "evaluation canonical hash does not match"
                )
            plan = evaluation["plan"]
            assert isinstance(plan, Mapping)
            if (
                plan.get("protocol") != _MISC_TRANSFORM_PROTOCOL
                or plan.get("candidate_sha256")
                != binding["candidate_sha256"]
                or plan.get("candidate_size_bytes")
                != len(candidate.value.encode("utf-8", errors="strict"))
                or plan.get("source_manifest_sha256")
                != binding["source_manifest_sha256"]
                or hashlib.sha256(
                    misc_transform_canonical_json_bytes(plan)
                ).hexdigest()
                != binding["plan_sha256"]
                or type(plan.get("sources")) is not list
                or not plan["sources"]
                or type(plan.get("steps")) is not list
                or not plan["steps"]
                or plan.get("verification_repeats")
                != MISC_TRANSFORM_VERIFICATION_REPEATS
            ):
                raise ModelValidationError("plan binding is inconsistent")

            for source in plan["sources"]:
                if (
                    not isinstance(source, Mapping)
                    or frozenset(source)
                    != {"artifact_id", "sha256", "size_bytes"}
                    or type(source["artifact_id"]) is not str
                    or source["artifact_id"] not in artifacts
                ):
                    raise ModelValidationError(
                        "source artifact binding is invalid"
                    )
                artifact = artifacts[source["artifact_id"]]
                incoming_path = artifact.extra.get("incoming_path")
                incoming = next(
                    (
                        item
                        for item in state.source_inventory
                        if item.path == incoming_path
                    ),
                    None,
                )
                if (
                    artifact.sha256 != source["sha256"]
                    or artifact.size != source["size_bytes"]
                    or artifact.extra.get("kind")
                    != "misc_transform_input"
                    or artifact.extra.get("purpose") != "source"
                    or artifact.extra.get("protocol")
                    != _MISC_TRANSFORM_PROTOCOL
                    or artifact.extra.get("misc_evaluation_id")
                    != evaluation_id
                    or artifact.extra.get("immutable_incoming") is not True
                    or incoming is None
                    or incoming.sha256 != artifact.sha256
                    or incoming.size != artifact.size
                ):
                    raise ModelValidationError(
                        "source artifact was stripped or rebound"
                    )

            for step in plan["steps"]:
                if (
                    not isinstance(step, Mapping)
                    or type(step.get("step_id")) is not str
                    or type(step.get("tool_artifact_sha256")) is not str
                ):
                    raise ModelValidationError(
                        "transform tool plan binding is invalid"
                    )
                matching_tools = [
                    artifact
                    for artifact in state.artifacts
                    if (
                        artifact.extra.get("kind")
                        == "misc_transform_input"
                        and artifact.extra.get("purpose")
                        == "transform_tool"
                        and artifact.extra.get("logical_id")
                        == step["step_id"]
                        and artifact.extra.get("protocol")
                        == _MISC_TRANSFORM_PROTOCOL
                        and artifact.extra.get("misc_evaluation_id")
                        == evaluation_id
                    )
                ]
                if (
                    len(matching_tools) != 1
                    or matching_tools[0].sha256
                    != step["tool_artifact_sha256"]
                    or matching_tools[0].size is None
                ):
                    raise ModelValidationError(
                        "transform tool artifact was stripped or rebound"
                    )
            verifier = plan.get("verifier")
            if not isinstance(verifier, Mapping):
                raise ModelValidationError(
                    "verifier tool plan binding is invalid"
                )
            matching_verifiers = [
                artifact
                for artifact in state.artifacts
                if (
                    artifact.extra.get("kind")
                    == "misc_transform_input"
                    and artifact.extra.get("purpose") == "verifier_tool"
                    and artifact.extra.get("logical_id")
                    == verifier.get("verifier_id")
                    and artifact.extra.get("protocol")
                    == _MISC_TRANSFORM_PROTOCOL
                    and artifact.extra.get("misc_evaluation_id")
                    == evaluation_id
                )
            ]
            if (
                len(matching_verifiers) != 1
                or matching_verifiers[0].sha256
                != verifier.get("tool_artifact_sha256")
                or matching_verifiers[0].size is None
            ):
                raise ModelValidationError(
                    "verifier tool artifact was stripped or rebound"
                )
            operator_specs = [
                artifact
                for artifact in state.artifacts
                if (
                    artifact.extra.get("kind")
                    == "misc_transform_input"
                    and artifact.extra.get("purpose") == "operator_spec"
                    and artifact.extra.get("protocol")
                    == _MISC_TRANSFORM_PROTOCOL
                    and artifact.extra.get("misc_evaluation_id")
                    == evaluation_id
                )
            ]
            input_manifests = [
                artifact
                for artifact in state.artifacts
                if (
                    artifact.extra.get("kind")
                    == "misc_transform_input_manifest"
                    and artifact.extra.get("protocol")
                    == _MISC_TRANSFORM_PROTOCOL
                    and artifact.extra.get("misc_evaluation_id")
                    == evaluation_id
                )
            ]
            if (
                len(operator_specs) != 1
                or len(input_manifests) != (3 if managed_oracle else 2)
                or {
                    artifact.extra.get("purpose")
                    for artifact in input_manifests
                }
                != (
                    {
                        "operator_spec",
                        "payloads",
                        "preissued_oracle",
                    }
                    if managed_oracle
                    else {"operator_spec", "payloads"}
                )
            ):
                raise ModelValidationError(
                    "operator spec or input manifests were stripped"
                )

            records = [
                *evaluation["transform_nodes"],
                *evaluation["reverse_verifications"],
            ]
            if len(run_ids) != len(records):
                raise ModelValidationError(
                    "run ids do not match evaluation records"
                )
            marked_run_ids = [
                run.id
                for run in state.runs
                if (
                    run.extra.get("misc_transform_protocol")
                    == _MISC_TRANSFORM_PROTOCOL
                    and run.extra.get("misc_evaluation_id")
                    == evaluation_id
                )
            ]
            expected_marked_run_ids = list(run_ids)
            if managed_oracle:
                transform_count = len(evaluation["transform_nodes"])
                expected_marked_run_ids = [
                    *run_ids[:transform_count],
                    *binding["oracle_control_run_ids"],
                    *run_ids[transform_count:],
                ]
            if marked_run_ids != expected_marked_run_ids:
                raise ModelValidationError(
                    "evaluation run set was stripped, reordered, or extended"
                )
            transform_record_count = len(evaluation["transform_nodes"])
            for record_index, (run_id, record) in enumerate(
                zip(run_ids, records, strict=True)
            ):
                if run_id not in runs or not isinstance(record, Mapping):
                    raise ModelValidationError(
                        "evaluation references an unknown run or record"
                    )
                run = runs[run_id]
                if (
                    run.role != "misc_transform"
                    or run.origin is not RunOrigin.PROOF
                    or type(run.configuration_epoch) is not int
                    or run.extra.get("misc_transform_protocol")
                    != _MISC_TRANSFORM_PROTOCOL
                    or run.extra.get("misc_evaluation_id") != evaluation_id
                    or run.extra.get("plan_sha256")
                    != binding["plan_sha256"]
                    or run.extra.get("misc_transform_record") != record
                    or record.get("run_id") != run_id
                    or record.get("plan_sha256")
                    != binding["plan_sha256"]
                    or record.get("source_manifest_sha256")
                    != binding["source_manifest_sha256"]
                ):
                    raise ModelValidationError(
                        "run record was stripped or rebound"
                    )
                for stream_name in ("stdout", "stderr"):
                    stream = record.get(stream_name)
                    if not isinstance(stream, Mapping):
                        raise ModelValidationError(
                            "stream evidence is not an object"
                        )
                    artifact_id = stream.get("artifact_id")
                    if (
                        type(artifact_id) is not str
                        or artifact_id not in artifacts
                    ):
                        raise ModelValidationError(
                            "stream artifact is missing"
                        )
                    artifact = artifacts[artifact_id]
                    if (
                        artifact.source_run_id != run_id
                        or artifact.sha256
                        != stream.get("artifact_sha256")
                        or artifact.size
                        != stream.get("artifact_size_bytes")
                        or artifact.extra.get("kind")
                        != "misc_transform_stream"
                        or artifact.extra.get("misc_evaluation_id")
                        != evaluation_id
                        or artifact.extra.get("plan_sha256")
                        != binding["plan_sha256"]
                        or (
                            managed_oracle
                            and record_index >= transform_record_count
                            and artifact.extra.get("context_visibility")
                            != "engine_private"
                        )
                    ):
                        raise ModelValidationError(
                            "stream artifact was stripped or rebound"
                        )
                output = record.get(
                    "output_artifact",
                    record.get("result_artifact"),
                )
                if output is not None:
                    if (
                        not isinstance(output, Mapping)
                        or type(output.get("artifact_id")) is not str
                        or output["artifact_id"] not in artifacts
                    ):
                        raise ModelValidationError(
                            "output artifact is missing"
                        )
                    artifact = artifacts[output["artifact_id"]]
                    if (
                        artifact.source_run_id != run_id
                        or artifact.sha256 != output.get("sha256")
                        or artifact.size != output.get("size_bytes")
                        or artifact.extra.get("misc_evaluation_id")
                        != evaluation_id
                        or artifact.extra.get("plan_sha256")
                        != binding["plan_sha256"]
                    ):
                        raise ModelValidationError(
                            "output artifact was stripped or rebound"
                        )

            evaluation_artifact_id = binding["artifact_id"]
            if (
                type(evaluation_artifact_id) is not str
                or evaluation_artifact_id not in artifacts
            ):
                raise ModelValidationError("evaluation artifact is missing")
            evaluation_artifact = artifacts[evaluation_artifact_id]
            if (
                evaluation_artifact.sha256
                != binding["evaluation_sha256"]
                or evaluation_artifact.size != len(encoded)
                or evaluation_artifact.extra
                != {
                    "kind": "misc_transform_evaluation",
                    "protocol": _MISC_TRANSFORM_PROTOCOL,
                    "misc_evaluation_id": evaluation_id,
                    "candidate_id": candidate.id,
                    "plan_sha256": binding["plan_sha256"],
                    "evaluation_sha256": (
                        binding["evaluation_sha256"]
                    ),
                }
                or evaluation_artifact.source_run_id
                != run_ids[-1]
            ):
                raise ModelValidationError(
                    "evaluation artifact was stripped or rebound"
                )

            passed = binding["passed"] is True
            if passed:
                if (
                    (
                        managed_oracle
                        and binding["oracle_negative_control_passed"]
                        is not True
                    )
                    or
                    candidate.status
                    is CandidateStatus.READY_TO_SUBMIT
                    or evaluation["failure_codes"]
                    or len(evaluation["transform_nodes"])
                    != len(plan["steps"])
                    or len(evaluation["reverse_verifications"])
                    != MISC_TRANSFORM_VERIFICATION_REPEATS
                    or any(
                        not isinstance(record, Mapping)
                        or record.get("accepted") is not True
                        for record in records
                    )
                    or any(
                        runs[run_id].status is not RunStatus.COMPLETED
                        for run_id in run_ids
                    )
                ):
                    raise ModelValidationError(
                        "passed evaluation is incomplete or promoted as proof"
                    )
                matching_facts = [
                    fact
                    for fact in state.facts
                    if (
                        isinstance(
                            fact.extra.get("misc_transform_evidence"),
                            Mapping,
                        )
                        and fact.extra["misc_transform_evidence"].get(
                            "misc_evaluation_id"
                        )
                        == evaluation_id
                    )
                ]
                if (
                    len(matching_facts) != 1
                    or matching_facts[0].provenance
                    is not Provenance.EXECUTED
                    or matching_facts[0].source_run_id != run_ids[-1]
                    or matching_facts[0].artifact_id
                    != evaluation_artifact_id
                    or matching_facts[0].locator
                    != evaluation_artifact.path
                    or matching_facts[0].extra
                    != {
                        "misc_transform_evidence": {
                            "candidate_id": candidate.id,
                            "evaluation_sha256": (
                                binding["evaluation_sha256"]
                            ),
                            "misc_evaluation_id": evaluation_id,
                            "plan_sha256": binding["plan_sha256"],
                            "protocol": _MISC_TRANSFORM_PROTOCOL,
                        }
                    }
                ):
                    raise ModelValidationError(
                        "passed evaluation lacks its exact executed fact"
                    )
                matching_markers = [
                    marker
                    for marker in state.progress_markers
                    if marker.extra.get("misc_evaluation_id")
                    == evaluation_id
                ]
                if (
                    len(matching_markers) != 1
                    or matching_markers[0].run_id != run_ids[-1]
                    or matching_markers[0].artifact_ids
                    != [evaluation_artifact_id]
                    or matching_markers[0].extra
                    != {
                        "adapter_marker": (
                            "misc_original_condition_verified"
                        ),
                        "candidate_id": candidate.id,
                        "evaluation_sha256": (
                            binding["evaluation_sha256"]
                        ),
                        "misc_evaluation_id": evaluation_id,
                        "plan_sha256": binding["plan_sha256"],
                        "protocol": _MISC_TRANSFORM_PROTOCOL,
                        "automatic_submission_authorized": False,
                    }
                ):
                    raise ModelValidationError(
                        "passed evaluation lacks its exact progress marker"
                    )
        except (
            KeyError,
            ModelValidationError,
            TypeError,
            UnicodeError,
            ValueError,
        ) as error:
            errors.append(f"{label} is invalid: {error}")

    for artifact in state.artifacts:
        if (
            artifact.extra.get("kind") == "misc_transform_evaluation"
            and artifact.extra.get("protocol") == _MISC_TRANSFORM_PROTOCOL
            and artifact.extra.get("misc_evaluation_id") not in bindings
        ):
            errors.append(
                f"orphan Misc transform evaluation artifact {artifact.id}"
            )
    for fact in state.facts:
        marker = fact.extra.get("misc_transform_evidence")
        if (
            isinstance(marker, Mapping)
            and marker.get("protocol") == _MISC_TRANSFORM_PROTOCOL
            and marker.get("misc_evaluation_id") not in bindings
        ):
            errors.append(f"orphan Misc transform fact {fact.id}")
    for marker in state.progress_markers:
        if (
            marker.extra.get("protocol") == _MISC_TRANSFORM_PROTOCOL
            and marker.extra.get("misc_evaluation_id") not in bindings
        ):
            errors.append(f"orphan Misc transform progress marker {marker.id}")
    return errors


@dataclass
class ChallengeState:
    contest_id: str
    category: str
    challenge_id: str
    schema_version: int = CURRENT_SCHEMA_VERSION
    revision: int = 0
    updated_at: str = field(default_factory=utc_now)
    created_at: str = field(default_factory=utc_now)
    status: ChallengeStatus = ChallengeStatus.NEW
    resume_status: ChallengeStatus | None = None
    description: str = ""
    prompt: str = ""
    source_path: str | None = None
    source_inventory: list[SourceFile] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    active_goal_id: str | None = None
    goals: list[Goal] = field(default_factory=list)
    facts: list[Fact] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    experiments: list[Experiment] = field(default_factory=list)
    progress_markers: list[ProgressMarker] = field(default_factory=list)
    budget: Budget = field(default_factory=Budget)
    candidates: list[FlagCandidate] = field(default_factory=list)
    submissions: list[SubmissionReference] = field(default_factory=list)
    artifacts: list[ArtifactReference] = field(default_factory=list)
    runs: list[RunReference] = field(default_factory=list)
    configuration_epoch: int = 0
    workspace_revision: int = 0
    receipts: list[ExecutionReceipt] = field(default_factory=list)
    sessions: list[SolveSession] = field(default_factory=list)
    cycles: list[ManagedCycle] = field(default_factory=list)
    waves: list[ManagedWave] = field(default_factory=list)
    checkpoints: list[Checkpoint] = field(default_factory=list)
    targets: list[TargetRecord] = field(default_factory=list)
    primary_target_id: str | None = None
    closure: ClosureBundle | None = None
    workspace_publishes: list[WorkspacePublish] = field(default_factory=list)
    active_managed_session_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def identity(self) -> ChallengeIdentity:
        return ChallengeIdentity(
            contest_id=self.contest_id,
            category=self.category,
            challenge_id=self.challenge_id,
        )

    @property
    def active_goal(self) -> Goal | None:
        if self.active_goal_id is None:
            return None
        return next(
            (goal for goal in self.goals if goal.id == self.active_goal_id),
            None,
        )

    def to_dict(self) -> dict[str, Any]:
        v2 = self.schema_version >= STATE_SCHEMA_VERSION
        canonical: dict[str, Any] = {
            "schema_version": self.schema_version,
            "revision": self.revision,
            "updated_at": self.updated_at,
            "created_at": self.created_at,
            "contest_id": self.contest_id,
            "category": self.category,
            "challenge_id": self.challenge_id,
            "identity": self.identity.to_dict(),
            "status": _enum_value(self.status),
            "resume_status": (
                _enum_value(self.resume_status)
                if self.resume_status is not None
                else None
            ),
            "description": self.description,
            "prompt": self.prompt,
            "source_path": self.source_path,
            "source_inventory": [
                item.to_dict() for item in self.source_inventory
            ],
            "metadata": dict(self.metadata),
            "active_goal_id": self.active_goal_id,
            "goals": [item.to_dict() for item in self.goals],
            "facts": [
                item.to_dict(
                    default_challenge_id=self.challenge_id,
                    v2=v2,
                )
                for item in self.facts
            ],
            "hypotheses": [
                item.to_dict(v2=v2) for item in self.hypotheses
            ],
            "experiments": [
                item.to_dict(v2=v2) for item in self.experiments
            ],
            "progress_markers": [
                item.to_dict() for item in self.progress_markers
            ],
            "budget": self.budget.to_dict(v2=v2),
            "candidates": [
                item.to_dict(v2=v2) for item in self.candidates
            ],
            "submissions": [
                item.to_dict(v2=v2) for item in self.submissions
            ],
            "artifacts": [item.to_dict() for item in self.artifacts],
            "runs": [item.to_dict(v2=v2) for item in self.runs],
        }
        if v2:
            canonical.update(
                configuration_epoch=self.configuration_epoch,
                workspace_revision=self.workspace_revision,
                receipts=[item.to_dict() for item in self.receipts],
                sessions=[item.to_dict() for item in self.sessions],
                cycles=[item.to_dict() for item in self.cycles],
                waves=[item.to_dict() for item in self.waves],
                checkpoints=[item.to_dict() for item in self.checkpoints],
                targets=[item.to_dict() for item in self.targets],
                primary_target_id=self.primary_target_id,
                closure=(
                    self.closure.to_dict()
                    if self.closure is not None
                    else None
                ),
                workspace_publishes=[
                    item.to_dict() for item in self.workspace_publishes
                ],
                active_managed_session_id=self.active_managed_session_id,
            )
        return _with_extra(self.extra, **canonical)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ChallengeState":
        identity = data.get("identity", {})
        if not isinstance(identity, Mapping):
            identity = {}
        contest_id = str(data.get("contest_id", identity.get("contest_id", "")))
        category = str(data.get("category", identity.get("category", "")))
        challenge_id = str(
            data.get("challenge_id", identity.get("challenge_id", ""))
        )

        budget_data = data.get("budget", {})
        if not isinstance(budget_data, Mapping):
            raise ModelValidationError("budget must be an object")
        progress_data = data.get("progress_markers")
        if progress_data is None:
            progress_data = budget_data.get("progress_markers", [])
        progress_records = _records(progress_data)

        known = {
            "schema_version",
            "revision",
            "updated_at",
            "created_at",
            "contest_id",
            "category",
            "challenge_id",
            "identity",
            "status",
            "resume_status",
            "paused_from_status",
            "description",
            "prompt",
            "source_path",
            "source_inventory",
            "metadata",
            "active_goal_id",
            "active_goal",
            "goals",
            "deps",
            "facts",
            "hypotheses",
            "experiments",
            "progress_markers",
            "budget",
            "candidates",
            "flag_candidates",
            "submissions",
            "artifacts",
            "runs",
            "configuration_epoch",
            "workspace_revision",
            "receipts",
            "sessions",
            "cycles",
            "waves",
            "checkpoints",
            "targets",
            "primary_target_id",
            "closure",
            "workspace_publishes",
            "active_managed_session_id",
        }

        active_goal = data.get("active_goal_id", data.get("active_goal"))
        if isinstance(active_goal, Mapping):
            active_goal = active_goal.get("id")

        state = cls(
            schema_version=int(
                data.get("schema_version", CURRENT_SCHEMA_VERSION)
            ),
            revision=int(data.get("revision", 0)),
            updated_at=str(data.get("updated_at", utc_now())),
            created_at=str(data.get("created_at", utc_now())),
            contest_id=contest_id,
            category=category,
            challenge_id=challenge_id,
            status=ChallengeStatus(
                str(data.get("status", ChallengeStatus.NEW.value))
            ),
            resume_status=(
                ChallengeStatus(
                    str(
                        data.get(
                            "resume_status", data.get("paused_from_status")
                        )
                    )
                )
                if data.get(
                    "resume_status", data.get("paused_from_status")
                )
                is not None
                else None
            ),
            description=str(data.get("description", "")),
            prompt=str(data.get("prompt", "")),
            source_path=(
                str(data["source_path"])
                if data.get("source_path") is not None
                else None
            ),
            source_inventory=[
                SourceFile.from_dict(record)
                for record in _records(data.get("source_inventory", []))
            ],
            metadata=dict(data.get("metadata", {})),
            active_goal_id=str(active_goal) if active_goal is not None else None,
            goals=[
                Goal.from_dict(record)
                for record in _records(data.get("goals", data.get("deps", [])))
            ],
            facts=[
                Fact.from_dict(record, default_challenge_id=challenge_id)
                for record in _records(data.get("facts", []))
            ],
            hypotheses=[
                Hypothesis.from_dict(record)
                for record in _records(data.get("hypotheses", []))
            ],
            experiments=[
                Experiment.from_dict(record)
                for record in _records(data.get("experiments", []))
            ],
            progress_markers=[
                ProgressMarker.from_dict(
                    record, default_id=f"PM-{index:04d}"
                )
                for index, record in enumerate(progress_records, start=1)
            ],
            budget=Budget.from_dict(budget_data),
            candidates=[
                FlagCandidate.from_dict(record)
                for record in _records(
                    data.get("candidates", data.get("flag_candidates", []))
                )
            ],
            submissions=[
                SubmissionReference.from_dict(record)
                for record in _records(data.get("submissions", []))
            ],
            artifacts=[
                ArtifactReference.from_dict(record)
                for record in _records(data.get("artifacts", []))
            ],
            runs=[
                RunReference.from_dict(record)
                for record in _records(data.get("runs", []))
            ],
            configuration_epoch=int(data.get("configuration_epoch", 0)),
            workspace_revision=int(data.get("workspace_revision", 0)),
            receipts=[
                ExecutionReceipt.from_dict(record)
                for record in _records(data.get("receipts", []))
            ],
            sessions=[
                SolveSession.from_dict(record)
                for record in _records(data.get("sessions", []))
            ],
            cycles=[
                ManagedCycle.from_dict(record)
                for record in _records(data.get("cycles", []))
            ],
            waves=[
                ManagedWave.from_dict(record)
                for record in _records(data.get("waves", []))
            ],
            checkpoints=[
                Checkpoint.from_dict(record)
                for record in _records(data.get("checkpoints", []))
            ],
            targets=[
                TargetRecord.from_dict(record)
                for record in _records(data.get("targets", []))
            ],
            primary_target_id=(
                str(data["primary_target_id"])
                if data.get("primary_target_id") is not None
                else None
            ),
            closure=(
                ClosureBundle.from_dict(data["closure"])
                if isinstance(data.get("closure"), Mapping)
                else None
            ),
            workspace_publishes=[
                WorkspacePublish.from_dict(record)
                for record in _records(data.get("workspace_publishes", []))
            ],
            active_managed_session_id=(
                str(data["active_managed_session_id"])
                if data.get("active_managed_session_id") is not None
                else None
            ),
            extra=_extra(data, known),
        )
        return state

    def validate(
        self,
        *,
        _allow_precommit_failure_capsules: bool = False,
        _pwn_disclosure_state_revision: int | None = None,
    ) -> None:
        """Validate referential and state invariants before persistence."""

        if _pwn_disclosure_state_revision is None:
            disclosure_state_revision = self.revision
        elif (
            type(_pwn_disclosure_state_revision) is not int
            or _pwn_disclosure_state_revision < 0
        ):
            raise ModelValidationError(
                "Pwn disclosure validation revision is invalid"
            )
        else:
            disclosure_state_revision = (
                _pwn_disclosure_state_revision
            )
        errors: list[str] = []
        for name, records in (
            ("source_inventory", self.source_inventory),
            ("goals", self.goals),
            ("facts", self.facts),
            ("hypotheses", self.hypotheses),
            ("experiments", self.experiments),
            ("progress_markers", self.progress_markers),
            ("candidates", self.candidates),
            ("submissions", self.submissions),
            ("artifacts", self.artifacts),
            ("runs", self.runs),
            ("receipts", self.receipts),
            ("sessions", self.sessions),
            ("cycles", self.cycles),
            ("waves", self.waves),
            ("checkpoints", self.checkpoints),
            ("targets", self.targets),
            ("workspace_publishes", self.workspace_publishes),
        ):
            if len(records) > MAX_RECORDS_PER_COLLECTION:
                raise ModelValidationError(
                    f"{name} exceeds {MAX_RECORDS_PER_COLLECTION} items"
                )
        for fact in self.facts:
            _repeated_items(fact.supports, f"fact {fact.id} supports")
            _repeated_items(
                fact.contradicts,
                f"fact {fact.id} contradicts",
            )
        for hypothesis in self.hypotheses:
            _repeated_items(
                hypothesis.evidence_fact_ids,
                f"hypothesis {hypothesis.id} evidence_fact_ids",
            )
            _repeated_items(
                hypothesis.evidence_artifact_ids,
                f"hypothesis {hypothesis.id} evidence_artifact_ids",
            )
            _repeated_items(
                hypothesis.evidence_run_ids,
                f"hypothesis {hypothesis.id} evidence_run_ids",
            )
            _repeated_items(
                hypothesis.evidence_receipt_ids,
                f"hypothesis {hypothesis.id} evidence_receipt_ids",
            )
        for experiment in self.experiments:
            _repeated_items(
                experiment.hypothesis_ids,
                f"experiment {experiment.id} hypothesis_ids",
            )
            _repeated_items(
                experiment.artifact_ids,
                f"experiment {experiment.id} artifact_ids",
            )
            _repeated_items(
                experiment.evidence_fact_ids,
                f"experiment {experiment.id} evidence_fact_ids",
            )
            _repeated_items(
                experiment.evidence_run_ids,
                f"experiment {experiment.id} evidence_run_ids",
            )
            _repeated_items(
                experiment.evidence_receipt_ids,
                f"experiment {experiment.id} evidence_receipt_ids",
            )
            if (
                experiment.proof_recipe is not None
                and len(experiment.proof_recipe.inputs)
                > MAX_PROOF_RECIPE_INPUTS
            ):
                raise ModelValidationError(
                    f"experiment {experiment.id} proof inputs exceed "
                    f"{MAX_PROOF_RECIPE_INPUTS} items"
                )
        for goal in self.goals:
            _repeated_items(goal.depends_on, f"goal {goal.id} depends_on")
            _repeated_items(
                goal.artifact_ids,
                f"goal {goal.id} artifact_ids",
            )
        for marker in self.progress_markers:
            _repeated_items(
                marker.artifact_ids,
                f"progress marker {marker.id} artifact_ids",
            )
        _repeated_items(self.budget.refusals, "budget refusals")
        for candidate in self.candidates:
            _repeated_items(
                candidate.proof_run_ids,
                f"candidate {candidate.id} proof_run_ids",
            )
        if self.schema_version not in {
            CURRENT_SCHEMA_VERSION,
            STATE_SCHEMA_VERSION,
        }:
            errors.append(
                "schema_version must be one of "
                f"{CURRENT_SCHEMA_VERSION}, {STATE_SCHEMA_VERSION}; "
                f"got {self.schema_version}"
            )
        if self.revision < 0:
            errors.append("revision cannot be negative")
        if self.resume_status == ChallengeStatus.PAUSED:
            errors.append("resume_status cannot itself be PAUSED")
        if self.resume_status in {
            ChallengeStatus.SOLVED,
            ChallengeStatus.ABANDONED,
        }:
            errors.append("resume_status cannot be a terminal status")
        if (
            self.status == ChallengeStatus.PAUSED
            and self.resume_status is None
        ):
            errors.append("PAUSED state requires resume_status")
        if (
            self.status is not ChallengeStatus.PAUSED
            and self.resume_status is not None
        ):
            errors.append("resume_status is valid only while PAUSED")
        for label, value in (
            ("contest_id", self.contest_id),
            ("category", self.category),
            ("challenge_id", self.challenge_id),
        ):
            if not value or not value.strip():
                errors.append(f"{label} cannot be empty")

        def id_map(name: str, records: Iterable[Any]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for record in records:
                record_id = str(getattr(record, "id", ""))
                if not record_id:
                    errors.append(f"{name} record has an empty id")
                elif record_id in result:
                    errors.append(f"duplicate {name} id: {record_id}")
                result[record_id] = record
            return result

        artifacts = id_map("artifact", self.artifacts)
        runs = id_map("run", self.runs)
        facts = id_map("fact", self.facts)
        hypotheses = id_map("hypothesis", self.hypotheses)
        experiments = id_map("experiment", self.experiments)
        goals = id_map("goal", self.goals)
        markers = id_map("progress marker", self.progress_markers)
        candidates = id_map("candidate", self.candidates)
        id_map("submission", self.submissions)
        receipts = id_map("receipt", self.receipts)
        sessions = id_map("session", self.sessions)
        cycles = id_map("cycle", self.cycles)
        waves = id_map("wave", self.waves)
        checkpoints = id_map("checkpoint", self.checkpoints)
        targets = id_map("target", self.targets)
        id_map("workspace publish", self.workspace_publishes)
        del markers  # uniqueness is the only marker-level map invariant

        for artifact in self.artifacts:
            if not artifact.path:
                errors.append(f"artifact {artifact.id} has an empty path")
            if not artifact.sha256:
                errors.append(f"artifact {artifact.id} has no sha256")
            if artifact.source_run_id and artifact.source_run_id not in runs:
                errors.append(
                    f"artifact {artifact.id} references unknown run "
                    f"{artifact.source_run_id}"
                )

        for fact in self.facts:
            if fact.challenge_id and fact.challenge_id != self.challenge_id:
                errors.append(
                    f"fact {fact.id} belongs to challenge "
                    f"{fact.challenge_id}, not {self.challenge_id}"
                )
            if not fact.statement:
                errors.append(f"fact {fact.id} has an empty statement")
            if fact.source_run_id and fact.source_run_id not in runs:
                errors.append(
                    f"fact {fact.id} references unknown run "
                    f"{fact.source_run_id}"
                )
            if fact.artifact_id and fact.artifact_id not in artifacts:
                errors.append(
                    f"fact {fact.id} references unknown artifact "
                    f"{fact.artifact_id}"
                )
            if fact.provenance is Provenance.EXECUTED:
                if fact.source_run_id is None:
                    errors.append(
                        f"executed fact {fact.id} requires a source run"
                    )
                elif fact.source_run_id in runs and runs[
                    fact.source_run_id
                ].status in {RunStatus.CREATED, RunStatus.RUNNING}:
                    errors.append(
                        f"executed fact {fact.id} requires a terminal run"
                    )
                if fact.artifact_id is None:
                    errors.append(
                        f"executed fact {fact.id} requires an artifact"
                    )
                elif fact.artifact_id in artifacts and (
                    artifacts[fact.artifact_id].source_run_id
                    != fact.source_run_id
                    and not (
                        self.schema_version >= STATE_SCHEMA_VERSION
                        and _pwn_ip_control_fact_marker(fact)
                    )
                ):
                    errors.append(
                        f"executed fact {fact.id} artifact/run mismatch"
                    )
            if fact.supersedes_id and fact.supersedes_id not in facts:
                errors.append(
                    f"fact {fact.id} supersedes unknown fact "
                    f"{fact.supersedes_id}"
                )
            for hypothesis_id in fact.supports + fact.contradicts:
                if hypothesis_id not in hypotheses:
                    errors.append(
                        f"fact {fact.id} references unknown hypothesis "
                        f"{hypothesis_id}"
                    )

        for hypothesis in self.hypotheses:
            if not hypothesis.statement:
                errors.append(
                    f"hypothesis {hypothesis.id} has an empty statement"
                )
            if not hypothesis.falsifier.description:
                errors.append(
                    f"hypothesis {hypothesis.id} requires a falsifier"
                )
            for fact_id in hypothesis.evidence_fact_ids:
                if fact_id not in facts:
                    errors.append(
                        f"hypothesis {hypothesis.id} references unknown fact "
                        f"{fact_id}"
                    )
            for artifact_id in hypothesis.evidence_artifact_ids:
                if artifact_id not in artifacts:
                    errors.append(
                        f"hypothesis {hypothesis.id} references unknown artifact "
                        f"{artifact_id}"
                    )
            for run_id in hypothesis.evidence_run_ids:
                if run_id not in runs:
                    errors.append(
                        f"hypothesis {hypothesis.id} references unknown run "
                        f"{run_id}"
                    )
            for receipt_id in hypothesis.evidence_receipt_ids:
                if receipt_id not in receipts:
                    errors.append(
                        f"hypothesis {hypothesis.id} references unknown "
                        f"receipt {receipt_id}"
                    )
            if hypothesis.source_run_id and hypothesis.source_run_id not in runs:
                errors.append(
                    f"hypothesis {hypothesis.id} references unknown run "
                    f"{hypothesis.source_run_id}"
                )
            if hypothesis.refuted_by and (
                hypothesis.refuted_by not in facts
                and hypothesis.refuted_by not in experiments
            ):
                errors.append(
                    f"hypothesis {hypothesis.id} has unknown refuter "
                    f"{hypothesis.refuted_by}"
                )
            if (
                hypothesis.status == HypothesisStatus.REFUTED
                and not hypothesis.refuted_by
            ):
                errors.append(
                    f"refuted hypothesis {hypothesis.id} requires a refuter"
                )
            if (
                hypothesis.status != HypothesisStatus.REFUTED
                and hypothesis.refuted_by is not None
            ):
                errors.append(
                    f"non-refuted hypothesis {hypothesis.id} cannot retain "
                    "a refuter"
                )
            if hypothesis.status != HypothesisStatus.OPEN:
                has_executed_chain = any(
                    fact_id in facts
                    and facts[fact_id].provenance == Provenance.EXECUTED
                    and facts[fact_id].source_run_id in runs
                    and runs[facts[fact_id].source_run_id].status
                    == RunStatus.COMPLETED
                    and facts[fact_id].artifact_id in artifacts
                    and artifacts[
                        facts[fact_id].artifact_id
                    ].source_run_id
                    == facts[fact_id].source_run_id
                    for fact_id in hypothesis.evidence_fact_ids
                )
                has_executed_chain = has_executed_chain or any(
                    receipt_id in receipts
                    and receipts[receipt_id].outcome
                    is ReceiptOutcome.SUCCEEDED
                    and receipts[receipt_id].run_id in runs
                    and runs[receipts[receipt_id].run_id].status
                    is RunStatus.COMPLETED
                    and receipts[receipt_id].stdout_artifact_id in artifacts
                    for receipt_id in hypothesis.evidence_receipt_ids
                )
                if not has_executed_chain:
                    errors.append(
                        f"hypothesis {hypothesis.id} cannot be "
                        f"{hypothesis.status.value} without an executed "
                        "fact/artifact/run evidence chain"
                    )

        for experiment in self.experiments:
            for hypothesis_id in experiment.hypothesis_ids:
                if hypothesis_id not in hypotheses:
                    errors.append(
                        f"experiment {experiment.id} references unknown "
                        f"hypothesis {hypothesis_id}"
                    )
            for artifact_id in experiment.artifact_ids:
                if artifact_id not in artifacts:
                    errors.append(
                        f"experiment {experiment.id} references unknown "
                        f"artifact {artifact_id}"
                    )
            for fact_id in experiment.evidence_fact_ids:
                if fact_id not in facts:
                    errors.append(
                        f"experiment {experiment.id} references unknown fact "
                        f"{fact_id}"
                    )
            for run_id in experiment.evidence_run_ids:
                if run_id not in runs:
                    errors.append(
                        f"experiment {experiment.id} references unknown run "
                        f"{run_id}"
                    )
            for receipt_id in experiment.evidence_receipt_ids:
                if receipt_id not in receipts:
                    errors.append(
                        f"experiment {experiment.id} references unknown "
                        f"receipt {receipt_id}"
                    )
            if (
                not experiment.command
                or not experiment.expected_observation
                or not experiment.keep_if
                or not experiment.drop_if
                or isinstance(experiment.timeout_seconds, bool)
                or not isinstance(experiment.timeout_seconds, int)
                or not (
                    1
                    <= experiment.timeout_seconds
                    <= MAX_EXPERIMENT_TIMEOUT_SECONDS
                )
            ):
                errors.append(
                    f"experiment {experiment.id} is not fully pre-registered"
                )
            if experiment.source_run_id and experiment.source_run_id not in runs:
                errors.append(
                    f"experiment {experiment.id} references unknown run "
                    f"{experiment.source_run_id}"
                )
            managed_shell_protocol = experiment.extra.get(
                "managed_command_protocol"
            )
            if managed_shell_protocol is not None:
                source_run = (
                    runs.get(experiment.source_run_id)
                    if experiment.source_run_id is not None
                    else None
                )
                try:
                    managed_shell_argv = tuple(
                        shlex.split(experiment.command)
                    )
                except ValueError:
                    managed_shell_argv = ()
                if (
                    managed_shell_protocol
                    != MANAGED_SHELL_COMMAND_PROTOCOL
                    or source_run is None
                    or source_run.origin is not RunOrigin.MANAGED_MODEL
                    or experiment.kind is ExperimentKind.PROOF
                    or experiment.proof_recipe is not None
                    or experiment.extra.get("engine_executor") is not None
                    or len(managed_shell_argv) != 3
                    or managed_shell_argv[:2]
                    != MANAGED_SHELL_ARGV_PREFIX
                    or not managed_shell_argv[2].strip()
                    or experiment.command
                    != shlex.join(managed_shell_argv)
                ):
                    errors.append(
                        f"experiment {experiment.id} has an invalid managed "
                        "POSIX shell command binding"
                    )
            evaluated_statuses = {
                ExperimentStatus.KEPT,
                ExperimentStatus.DROPPED,
                ExperimentStatus.INCONCLUSIVE,
            }
            if (
                experiment.status in evaluated_statuses
                and (
                    not experiment.evaluation_reason
                    or not experiment.evaluated_at
                )
            ):
                errors.append(
                    f"experiment {experiment.id} semantic evaluation requires "
                    "a reason and timestamp"
                )
            if (
                experiment.status in evaluated_statuses
                and not _pwn_crash_experiment_marker(experiment)
                and not _web_impact_state_marker(experiment)
                and not _forensic_assertion_state_marker(experiment)
            ):
                result_run_id = (
                    experiment.result.get("run_id")
                    if isinstance(experiment.result, Mapping)
                    else None
                )
                if (
                    not isinstance(result_run_id, str)
                    or result_run_id not in runs
                    or runs[result_run_id].status is not RunStatus.COMPLETED
                ):
                    errors.append(
                        f"experiment {experiment.id} semantic evaluation "
                        "requires its own completed result run"
                    )
                has_executed_chain = any(
                    fact_id in facts
                    and facts[fact_id].provenance == Provenance.EXECUTED
                    and facts[fact_id].source_run_id == result_run_id
                    and facts[fact_id].artifact_id in artifacts
                    and facts[fact_id].artifact_id
                    in experiment.artifact_ids
                    and artifacts[
                        facts[fact_id].artifact_id
                    ].source_run_id == result_run_id
                    for fact_id in experiment.evidence_fact_ids
                )
                has_executed_chain = has_executed_chain or any(
                    receipt_id in receipts
                    and receipts[receipt_id].experiment_id == experiment.id
                    and receipts[receipt_id].run_id == result_run_id
                    and receipts[receipt_id].outcome
                    is ReceiptOutcome.SUCCEEDED
                    and receipts[receipt_id].stdout_artifact_id in artifacts
                    for receipt_id in experiment.evidence_receipt_ids
                )
                if not has_executed_chain:
                    errors.append(
                        f"experiment {experiment.id} semantic evaluation "
                        "requires an executed fact/artifact chain from its own "
                        "result run"
                    )

        for goal in self.goals:
            if not goal.description:
                errors.append(f"goal {goal.id} has an empty description")
            for dependency_id in goal.depends_on:
                if dependency_id not in goals:
                    errors.append(
                        f"goal {goal.id} depends on unknown goal "
                        f"{dependency_id}"
                    )
                if dependency_id == goal.id:
                    errors.append(f"goal {goal.id} depends on itself")
            for artifact_id in goal.artifact_ids:
                if artifact_id not in artifacts:
                    errors.append(
                        f"goal {goal.id} references unknown artifact "
                        f"{artifact_id}"
                    )
            if (
                goal.status == GoalStatus.BLOCKED
                and not (goal.blocked_reason or "").strip()
            ):
                errors.append(f"blocked goal {goal.id} requires a reason")
            if (
                goal.status != GoalStatus.BLOCKED
                and goal.blocked_reason is not None
            ):
                errors.append(
                    f"non-blocked goal {goal.id} cannot retain a blocked reason"
                )

        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(goal_id: str) -> None:
            if goal_id in visited or goal_id not in goals:
                return
            if goal_id in visiting:
                errors.append(f"goal dependency cycle includes {goal_id}")
                return
            visiting.add(goal_id)
            for dependency_id in goals[goal_id].depends_on:
                visit(dependency_id)
            visiting.remove(goal_id)
            visited.add(goal_id)

        for goal_id in goals:
            visit(goal_id)

        if self.active_goal_id is not None:
            active = goals.get(self.active_goal_id)
            if active is None:
                errors.append(
                    f"active_goal_id references unknown goal "
                    f"{self.active_goal_id}"
                )
            elif active.status != GoalStatus.ACTIVE:
                errors.append(
                    f"active goal {active.id} must have status active"
                )
            elif any(
                dependency_id in goals
                and goals[dependency_id].status != GoalStatus.DONE
                for dependency_id in active.depends_on
            ):
                errors.append(
                    f"active goal {active.id} has incomplete dependencies"
                )
        active_goals = [
            goal.id for goal in self.goals if goal.status == GoalStatus.ACTIVE
        ]
        if len(active_goals) > 1:
            errors.append(
                "only one goal may be active: " + ", ".join(active_goals)
            )
        if active_goals and active_goals[0] != self.active_goal_id:
            errors.append(
                "the goal with status active must match active_goal_id"
            )

        for marker in self.progress_markers:
            if not marker.statement:
                errors.append(
                    f"progress marker {marker.id} has an empty statement"
                )
            if marker.goal_id and marker.goal_id not in goals:
                errors.append(
                    f"progress marker {marker.id} references unknown goal "
                    f"{marker.goal_id}"
                )
            if marker.run_id and marker.run_id not in runs:
                errors.append(
                    f"progress marker {marker.id} references unknown run "
                    f"{marker.run_id}"
                )
            for artifact_id in marker.artifact_ids:
                if artifact_id not in artifacts:
                    errors.append(
                        f"progress marker {marker.id} references unknown "
                        f"artifact {artifact_id}"
                    )

        if self.budget.spent_seconds < 0:
            errors.append("budget spent_seconds cannot be negative")
        if (
            self.budget.allocated_seconds is not None
            and self.budget.allocated_seconds < 0
        ):
            errors.append("budget allocated_seconds cannot be negative")

        for candidate in self.candidates:
            if not candidate_value_is_valid(candidate.value):
                errors.append(
                    f"candidate {candidate.id} value must be 1..1024 "
                    "printable characters and at most 4096 UTF-8 bytes"
                )
            if candidate.source_run_id and candidate.source_run_id not in runs:
                errors.append(
                    f"candidate {candidate.id} references unknown run "
                    f"{candidate.source_run_id}"
                )
            if candidate.artifact_id and candidate.artifact_id not in artifacts:
                errors.append(
                    f"candidate {candidate.id} references unknown artifact "
                    f"{candidate.artifact_id}"
                )
            for run_id in candidate.proof_run_ids:
                if run_id not in runs:
                    errors.append(
                        f"candidate {candidate.id} references unknown proof "
                        f"run {run_id}"
                    )

        for submission in self.submissions:
            if submission.candidate_id not in candidates:
                errors.append(
                    f"submission {submission.id} references unknown candidate "
                    f"{submission.candidate_id}"
                )
            if submission.attempt < 1:
                errors.append(
                    f"submission {submission.id} has invalid attempt "
                    f"{submission.attempt}"
                )
            if submission.status is SubmissionStatus.ACCEPTED:
                accepted_candidate = candidates.get(
                    submission.candidate_id
                )
                if (
                    accepted_candidate is not None
                    and accepted_candidate.status
                    != CandidateStatus.ACCEPTED
                ):
                    errors.append(
                        f"accepted submission {submission.id} requires an "
                        "accepted candidate"
                    )
                if self.status is not ChallengeStatus.SOLVED:
                    errors.append(
                        f"accepted submission {submission.id} requires a "
                        "SOLVED challenge"
                    )

        if (
            any(
                candidate.status == CandidateStatus.ACCEPTED
                for candidate in self.candidates
            )
            and self.status is not ChallengeStatus.SOLVED
        ):
            errors.append("an accepted candidate requires a SOLVED challenge")

        if self.schema_version < STATE_SCHEMA_VERSION:
            for experiment in self.experiments:
                if (
                    experiment.kind is ExperimentKind.PROOF
                    or experiment.proof_recipe is not None
                ):
                    errors.append(
                        f"managed proof experiment {experiment.id} requires "
                        f"state schema v{STATE_SCHEMA_VERSION}"
                    )

        if self.schema_version >= STATE_SCHEMA_VERSION:
            if self.configuration_epoch < 0:
                errors.append("configuration_epoch cannot be negative")
            if self.workspace_revision < 0:
                errors.append("workspace_revision cannot be negative")

            terminal_challenge = self.status in {
                ChallengeStatus.SOLVED,
                ChallengeStatus.ABANDONED,
            }
            if terminal_challenge and self.active_goal_id is not None:
                errors.append("terminal challenge cannot retain an active goal")
            if (
                terminal_challenge
                and self.active_managed_session_id is not None
            ):
                errors.append(
                    "terminal challenge cannot retain an active managed session"
                )

            for fact in self.facts:
                if (
                    fact.kind is FactKind.OBSERVATION
                    and fact.provenance is Provenance.EXECUTED
                    and not (fact.locator or "").strip()
                    and not _web_impact_state_marker(fact)
                    and not _forensic_assertion_state_marker(fact)
                ):
                    errors.append(
                        f"executed observation fact {fact.id} requires a locator"
                    )

            for experiment in self.experiments:
                if experiment.kind is ExperimentKind.PROBE:
                    if experiment.hypothesis_ids:
                        errors.append(
                            f"probe experiment {experiment.id} cannot name "
                            "hypotheses"
                        )
                    if experiment.status is ExperimentStatus.KEPT or (
                        experiment.status is ExperimentStatus.DROPPED
                    ):
                        errors.append(
                            f"probe experiment {experiment.id} completes "
                            "without semantic keep/drop"
                        )
                elif experiment.kind is ExperimentKind.STRATEGIC:
                    if not experiment.hypothesis_ids:
                        errors.append(
                            f"strategic experiment {experiment.id} requires "
                            "at least one hypothesis"
                        )
                    if (
                        self.active_goal_id is None
                        and experiment.status
                        in {
                            ExperimentStatus.REGISTERED,
                            ExperimentStatus.RUNNING,
                        }
                    ):
                        errors.append(
                            f"strategic experiment {experiment.id} requires "
                            "an active goal"
                        )
                    if experiment.proof_recipe is not None:
                        errors.append(
                            f"strategic experiment {experiment.id} cannot "
                            "contain a proof recipe"
                        )
                elif experiment.kind is ExperimentKind.PROOF:
                    recipe = experiment.proof_recipe
                    if recipe is None:
                        errors.append(
                            f"proof experiment {experiment.id} requires a "
                            "typed proof recipe"
                        )
                        continue
                    if experiment.hypothesis_ids:
                        errors.append(
                            f"proof experiment {experiment.id} cannot name "
                            "hypotheses"
                        )
                    if recipe.candidate_id not in candidates:
                        errors.append(
                            f"proof experiment {experiment.id} references "
                            f"unknown candidate {recipe.candidate_id}"
                        )
                    bound_candidate = candidates.get(recipe.candidate_id)
                    source_experiment = experiments.get(
                        recipe.source_experiment_id
                    )
                    source_run = runs.get(recipe.source_run_id)
                    if (
                        bound_candidate is None
                        or bound_candidate.source_run_id
                        != recipe.source_run_id
                    ):
                        errors.append(
                            f"proof experiment {experiment.id} candidate "
                            "does not match its source tool run"
                        )
                    if (
                        source_run is None
                        or source_run.status is not RunStatus.COMPLETED
                        or source_run.origin is not RunOrigin.MANAGED_TOOL
                        or source_run.extra.get("experiment_id")
                        != recipe.source_experiment_id
                    ):
                        errors.append(
                            f"proof experiment {experiment.id} requires a "
                            "completed managed tool source run"
                        )
                    if (
                        source_experiment is None
                        or source_experiment.kind is ExperimentKind.PROOF
                        or not isinstance(
                            source_experiment.result, Mapping
                        )
                        or source_experiment.result.get("run_id")
                        != recipe.source_run_id
                    ):
                        errors.append(
                            f"proof experiment {experiment.id} source run "
                            "is not linked by its source experiment"
                        )
                    elif (
                        recipe.policy.oracle_protocol
                        != _REV_STDIN_PROOF_PROTOCOL
                    ):
                        try:
                            source_argv = tuple(
                                shlex.split(source_experiment.command)
                            )
                        except ValueError:
                            source_argv = ()
                        if source_argv != recipe.argv:
                            errors.append(
                                f"proof experiment {experiment.id} argv "
                                "does not replay its source experiment"
                            )
                    if (
                        bound_candidate is not None
                        and any(
                            bound_candidate.value in argument
                            for argument in recipe.argv
                        )
                    ):
                        errors.append(
                            f"proof experiment {experiment.id} argv embeds "
                            "the candidate literal"
                        )
                    if (
                        not recipe.argv
                        or len(recipe.argv) > 4096
                        or any(
                            not isinstance(argument, str)
                            or "\x00" in argument
                            or len(argument.encode("utf-8"))
                            > 1024 * 1024
                            for argument in recipe.argv
                        )
                        or sum(
                            len(argument.encode("utf-8"))
                            for argument in recipe.argv
                            if isinstance(argument, str)
                        )
                        > 1024 * 1024
                    ):
                        errors.append(
                            f"proof experiment {experiment.id} has invalid "
                            "canonical argv"
                        )
                    if (
                        isinstance(recipe.configuration_epoch, bool)
                        or not isinstance(recipe.configuration_epoch, int)
                        or recipe.configuration_epoch < 0
                        or recipe.configuration_epoch
                        > self.configuration_epoch
                    ):
                        errors.append(
                            f"proof experiment {experiment.id} has invalid "
                            "configuration epoch"
                        )
                    if (
                        len(recipe.source_manifest_sha256) != 64
                        or recipe.source_manifest_sha256
                        != recipe.source_manifest_sha256.lower()
                        or any(
                            character not in "0123456789abcdef"
                            for character in (
                                recipe.source_manifest_sha256.lower()
                            )
                        )
                    ):
                        errors.append(
                            f"proof experiment {experiment.id} has invalid "
                            "source manifest sha256"
                        )
                    if (
                        len(recipe.source_request_sha256) != 64
                        or recipe.source_request_sha256
                        != recipe.source_request_sha256.lower()
                        or any(
                            character not in "0123456789abcdef"
                            for character in recipe.source_request_sha256
                        )
                    ):
                        errors.append(
                            f"proof experiment {experiment.id} has invalid "
                            "source request sha256"
                        )
                    if (
                        not recipe.image_reference
                        or "\x00" in recipe.image_reference
                        or len(recipe.image_reference.encode("utf-8"))
                        > 1024
                    ):
                        errors.append(
                            f"proof experiment {experiment.id} has invalid "
                            "image reference pin"
                        )
                    target_fields = (
                        recipe.network_target_id,
                        recipe.network_target_generation,
                        recipe.network_endpoint,
                    )
                    if any(item is None for item in target_fields) and any(
                        item is not None for item in target_fields
                    ):
                        errors.append(
                            f"proof experiment {experiment.id} target id, "
                            "generation, and endpoint must be bound together"
                        )
                    if (
                        recipe.network_target_generation is not None
                        and (
                            isinstance(
                                recipe.network_target_generation, bool
                            )
                            or not isinstance(
                                recipe.network_target_generation, int
                            )
                            or recipe.network_target_generation < 1
                        )
                    ):
                        errors.append(
                            f"proof experiment {experiment.id} has invalid "
                            "target generation"
                        )
                    if recipe.network_target_id is not None:
                        bound_target = targets.get(
                            recipe.network_target_id
                        )
                        if (
                            bound_target is None
                            or bound_target.generation
                            != recipe.network_target_generation
                            or bound_target.endpoint
                            != recipe.network_endpoint
                        ):
                            errors.append(
                                f"proof experiment {experiment.id} target "
                                "pin does not match a canonical target record"
                            )
                    policy = recipe.policy
                    policy_counts = (
                        policy.clean_repetitions,
                        policy.remote_repetitions,
                        policy.trial_count,
                        policy.negative_control_repetitions,
                    )
                    if any(
                        isinstance(value, bool)
                        or not isinstance(value, int)
                        or value < 0
                        for value in policy_counts
                    ):
                        errors.append(
                            f"proof experiment {experiment.id} has invalid "
                            "policy repetition counts"
                        )
                    if (
                        isinstance(
                            policy.negative_control_timeout_seconds,
                            bool,
                        )
                        or not isinstance(
                            policy.negative_control_timeout_seconds,
                            int,
                        )
                        or not 1
                        <= policy.negative_control_timeout_seconds
                        <= 30
                    ):
                        errors.append(
                            f"proof experiment {experiment.id} has invalid "
                            "negative-control timeout"
                        )
                    supported_policy_modes = {
                        "deterministic",
                        "success_distribution",
                        "remote_independent",
                        "sample_matrix",
                        "hash_chain",
                    }
                    if (
                        policy.mode not in supported_policy_modes
                        or len(policy.mode.encode("utf-8"))
                        > MAX_PROOF_POLICY_STRING_BYTES
                        or not policy.oracle_protocol
                        or len(policy.oracle_protocol.encode("utf-8"))
                        > MAX_PROOF_POLICY_STRING_BYTES
                        or len(policy.notes.encode("utf-8"))
                        > MAX_PROOF_POLICY_NOTES_BYTES
                    ):
                        errors.append(
                            f"proof experiment {experiment.id} has invalid "
                            "policy strings"
                        )
                    effective_attempts = (
                        policy.trial_count
                        if policy.mode == "success_distribution"
                        else policy.clean_repetitions
                        + policy.remote_repetitions
                    )
                    minimum_rate = policy.minimum_success_rate
                    if (
                        minimum_rate is not None
                        and (
                            isinstance(minimum_rate, bool)
                            or not isinstance(minimum_rate, (int, float))
                            or not math.isfinite(float(minimum_rate))
                        )
                    ):
                        errors.append(
                            f"proof experiment {experiment.id} has invalid "
                            "minimum success rate"
                        )
                    if (
                        policy.mode == "success_distribution"
                        and (
                            policy.trial_count < 1
                            or minimum_rate is None
                            or isinstance(minimum_rate, bool)
                            or not isinstance(minimum_rate, (int, float))
                            or not math.isfinite(float(minimum_rate))
                            or not 0
                            <= minimum_rate
                            <= 1
                        )
                    ):
                        errors.append(
                            f"proof experiment {experiment.id} has invalid "
                            "success distribution policy"
                        )
                    if (
                        policy.mode != "success_distribution"
                        and (
                            effective_attempts < 1
                            or policy.trial_count != 0
                            or minimum_rate is not None
                        )
                    ):
                        errors.append(
                            f"proof experiment {experiment.id} has invalid "
                            "non-distribution policy"
                        )
                    if (
                        effective_attempts
                        + policy.negative_control_repetitions
                        > MAX_PROOF_ATTEMPTS
                    ):
                        errors.append(
                            f"proof experiment {experiment.id} exceeds the "
                            f"{MAX_PROOF_ATTEMPTS}-attempt proof limit"
                        )
                    if policy.oracle_protocol not in {
                        _PWN_PROOF_PROTOCOL,
                        _REV_STDIN_PROOF_PROTOCOL,
                    }:
                        errors.append(
                            f"proof experiment {experiment.id} uses an "
                            "unsupported oracle protocol"
                        )
                    if policy.oracle_protocol == _PWN_PROOF_PROTOCOL and (
                        policy.mode != "success_distribution"
                        or policy.negative_control_repetitions != 1
                        or recipe.network_endpoint is None
                        or recipe.oracle_binding is not None
                    ):
                        errors.append(
                            f"proof experiment {experiment.id} lacks the "
                            "required remote negative-control policy"
                        )
                    if (
                        policy.oracle_protocol
                        == _REV_STDIN_PROOF_PROTOCOL
                        and (
                            policy.mode != "deterministic"
                            or policy.clean_repetitions != 3
                            or policy.remote_repetitions != 0
                            or policy.trial_count != 0
                            or policy.negative_control_repetitions != 3
                            or policy.negative_control_timeout_seconds != 30
                            or policy.minimum_success_rate is not None
                            or recipe.network_target_id is not None
                            or recipe.network_target_generation is not None
                            or recipe.network_endpoint is not None
                            or recipe.oracle_binding is None
                        )
                    ):
                        errors.append(
                            f"proof experiment {experiment.id} lacks the "
                            "required deterministic Rev stdin policy"
                        )
                    if policy.policy_sha256 != policy.computed_sha256():
                        errors.append(
                            f"proof experiment {experiment.id} policy hash "
                            "does not match its canonical snapshot"
                        )
                    if recipe.recipe_sha256 != recipe.computed_sha256():
                        errors.append(
                            f"proof experiment {experiment.id} recipe hash "
                            "does not match its canonical payload"
                        )
                    artifact_ids: set[str] = set()
                    destinations: set[str] = set()
                    total_input_bytes = 0
                    for proof_input in recipe.inputs:
                        raw_segments = proof_input.destination.split("/")
                        path = PurePosixPath(proof_input.destination)
                        destination_valid = (
                            bool(proof_input.destination)
                            and proof_input.destination != "."
                            and "\x00" not in proof_input.destination
                            and "\\" not in proof_input.destination
                            and len(
                                proof_input.destination.encode("utf-8")
                            )
                            <= MAX_PROOF_DESTINATION_BYTES
                            and all(
                                segment not in {"", ".", ".."}
                                and len(segment.encode("utf-8")) <= 255
                                for segment in raw_segments
                            )
                            and not path.is_absolute()
                            and ".." not in path.parts
                        )
                        if (
                            not destination_valid
                            or proof_input.destination in destinations
                        ):
                            errors.append(
                                f"proof experiment {experiment.id} has "
                                "unsafe or duplicate input destination "
                                f"{proof_input.destination!r}"
                            )
                        destinations.add(proof_input.destination)
                        if proof_input.artifact_id in artifact_ids:
                            errors.append(
                                f"proof experiment {experiment.id} has "
                                "duplicate input artifact "
                                f"{proof_input.artifact_id}"
                            )
                        artifact_ids.add(proof_input.artifact_id)
                        if (
                            proof_input.purpose
                            not in _PROOF_RECIPE_INPUT_PURPOSES
                        ):
                            errors.append(
                                f"proof experiment {experiment.id} has "
                                f"invalid input purpose {proof_input.purpose}"
                            )
                        artifact = artifacts.get(
                            proof_input.artifact_id
                        )
                        if (
                            not isinstance(proof_input.size, bool)
                            and isinstance(proof_input.size, int)
                            and proof_input.size >= 0
                        ):
                            total_input_bytes += proof_input.size
                        if artifact is None:
                            errors.append(
                                f"proof experiment {experiment.id} input "
                                "references unknown artifact "
                                f"{proof_input.artifact_id}"
                            )
                        elif (
                            len(proof_input.sha256) != 64
                            or any(
                                character not in "0123456789abcdef"
                                for character in proof_input.sha256
                            )
                            or proof_input.sha256
                            != proof_input.sha256.lower()
                            or artifact.sha256.lower()
                            != proof_input.sha256
                            or artifact.size != proof_input.size
                            or isinstance(proof_input.size, bool)
                            or not isinstance(proof_input.size, int)
                            or proof_input.size < 0
                        ):
                            errors.append(
                                f"proof experiment {experiment.id} input "
                                f"{proof_input.artifact_id} hash/size mismatch"
                            )
                        if (
                            not isinstance(proof_input.size, bool)
                            and isinstance(proof_input.size, int)
                            and proof_input.size
                            > MAX_MANAGED_PROOF_INPUT_BYTES
                        ):
                            errors.append(
                                f"proof experiment {experiment.id} input "
                                f"{proof_input.artifact_id} exceeds the "
                                "managed proof byte limit"
                            )
                        if (
                            artifact is not None
                            and artifact.source_run_id
                            != proof_input.source_run_id
                        ):
                            errors.append(
                                f"proof experiment {experiment.id} input "
                                f"{proof_input.artifact_id} source run mismatch"
                            )
                        if (
                            proof_input.artifact_id
                            not in experiment.artifact_ids
                        ):
                            errors.append(
                                f"proof experiment {experiment.id} input "
                                f"{proof_input.artifact_id} is not linked "
                                "through experiment artifact_ids"
                            )
                    if total_input_bytes > MAX_MANAGED_PROOF_INPUT_BYTES:
                        errors.append(
                            f"proof experiment {experiment.id} inputs exceed "
                            "the aggregate managed proof byte limit"
                        )
                    if policy.oracle_protocol == _PWN_PROOF_PROTOCOL and any(
                        proof_input.purpose
                        not in _PWN_PROOF_RECIPE_INPUT_PURPOSES
                        for proof_input in recipe.inputs
                    ):
                        errors.append(
                            f"proof experiment {experiment.id} uses a "
                            "non-Pwn proof input purpose"
                        )
                    if policy.oracle_protocol == _REV_STDIN_PROOF_PROTOCOL:
                        binding = recipe.oracle_binding
                        expected_argv: tuple[str, ...] = ()
                        if binding is not None:
                            source_locator = binding.source_binding.get(
                                "path"
                            )
                            if isinstance(source_locator, str):
                                expected_argv = (
                                    *_REV_STDIN_RUNNER_PREFIX,
                                    f"/challenge/{source_locator}",
                                    *_REV_STDIN_RUNNER_INPUT_SUFFIX,
                                )
                            inventory_experiment = experiments.get(
                                binding.inventory_experiment_id
                            )
                            inventory_run = runs.get(
                                binding.inventory_run_id
                            )
                            inventory_stdout = artifacts.get(
                                binding.inventory_stdout_artifact_id
                            )
                            inventory_result = (
                                inventory_experiment.result
                                if inventory_experiment is not None
                                else None
                            )
                            inventory_outcome = (
                                inventory_result.get("partial_oracle")
                                if isinstance(
                                    inventory_result,
                                    Mapping,
                                )
                                else None
                            )
                            semantic_result = (
                                inventory_outcome.get("result")
                                if isinstance(
                                    inventory_outcome,
                                    Mapping,
                                )
                                else None
                            )
                            inventory_receipt = (
                                receipts.get(
                                    inventory_result.get("receipt_id")
                                )
                                if isinstance(
                                    inventory_result,
                                    Mapping,
                                )
                                and isinstance(
                                    inventory_result.get("receipt_id"),
                                    str,
                                )
                                else None
                            )
                            if (
                                binding.protocol
                                != _REV_STDIN_PROOF_PROTOCOL
                                or binding.budget_deadline_utc
                                != self.budget.deadline_utc
                                or binding.source_binding.get(
                                    "manifest_sha256"
                                )
                                != recipe.source_manifest_sha256
                                or inventory_experiment is None
                                or inventory_experiment.status
                                is not ExperimentStatus.COMPLETED
                                or inventory_run is None
                                or inventory_run.status
                                is not RunStatus.COMPLETED
                                or inventory_run.origin
                                is not RunOrigin.MANAGED_TOOL
                                or inventory_run.extra.get("experiment_id")
                                != binding.inventory_experiment_id
                                or not isinstance(
                                    inventory_result,
                                    Mapping,
                                )
                                or inventory_result.get("run_id")
                                != binding.inventory_run_id
                                or binding.source_binding
                                != inventory_experiment.extra.get(
                                    "source_binding"
                                )
                                or binding.source_snapshot
                                != inventory_experiment.extra.get(
                                    "source_snapshot"
                                )
                                or not isinstance(
                                    semantic_result,
                                    Mapping,
                                )
                                or semantic_result.get("verdict")
                                != "CONFIRMED"
                                or not isinstance(
                                    inventory_outcome,
                                    Mapping,
                                )
                                or inventory_outcome.get(
                                    "stdout_artifact_id"
                                )
                                != binding.inventory_stdout_artifact_id
                                or inventory_receipt is None
                                or inventory_receipt.run_id
                                != binding.inventory_run_id
                                or inventory_receipt.experiment_id
                                != binding.inventory_experiment_id
                                or inventory_receipt.stdout_artifact_id
                                != binding.inventory_stdout_artifact_id
                                or inventory_stdout is None
                                or inventory_stdout.source_run_id
                                != binding.inventory_run_id
                                or inventory_stdout.sha256
                                != binding.inventory_stdout_sha256
                                or type(inventory_stdout.size) is not int
                                or inventory_stdout.size
                                != binding.inventory_stdout_size_bytes
                            ):
                                errors.append(
                                    f"proof experiment {experiment.id} has "
                                    "an invalid Rev inventory binding"
                                )
                        if (
                            len(recipe.inputs) != 1
                            or recipe.inputs[0].purpose != "accepted_input"
                            or recipe.inputs[0].destination
                            != _REV_STDIN_ACCEPTED_INPUT_DESTINATION
                            or type(recipe.inputs[0].size) is not int
                            or recipe.inputs[0].size < 0
                            or recipe.inputs[0].size
                            > _REV_STDIN_MAX_ACCEPTED_INPUT_BYTES
                            or recipe.argv != expected_argv
                        ):
                            errors.append(
                                f"proof experiment {experiment.id} has an "
                                "invalid Rev accepted-input recipe"
                            )
                elif experiment.proof_recipe is not None:
                    errors.append(
                        f"{experiment.kind.value} experiment "
                        f"{experiment.id} cannot contain a proof recipe"
                    )

            terminal_run_statuses = {
                RunStatus.COMPLETED,
                RunStatus.INVALID,
                RunStatus.FAILED,
                RunStatus.TIMED_OUT,
                RunStatus.CANCELLED,
                RunStatus.INTERRUPTED,
            }
            idempotency_keys: dict[str, str] = {}
            for run in self.runs:
                if run.configuration_epoch is not None and (
                    run.configuration_epoch < 0
                    or run.configuration_epoch > self.configuration_epoch
                ):
                    errors.append(
                        f"run {run.id} has invalid configuration epoch"
                    )
                if run.idempotency_key:
                    prior = idempotency_keys.get(run.idempotency_key)
                    if prior is not None and prior != run.id:
                        errors.append(
                            "duplicate run idempotency key "
                            f"{run.idempotency_key}: {prior}, {run.id}"
                        )
                    idempotency_keys[run.idempotency_key] = run.id
                if (
                    run.origin
                    in {RunOrigin.MANAGED_MODEL, RunOrigin.MANAGED_TOOL}
                    and run.status in terminal_run_statuses
                    and (
                        run.result_path is None
                        or run.validation_path is None
                    )
                ):
                    errors.append(
                        f"terminal managed run {run.id} requires result and "
                        "validation paths"
                    )
                continuity_audit = run.extra.get(
                    THREAD_CONTINUITY_RUN_KEY
                )
                bound_session = (
                    sessions.get(run.session_id)
                    if run.session_id is not None
                    else None
                )
                session_continuity = (
                    bound_session.extra.get(
                        THREAD_CONTINUITY_SESSION_KEY
                    )
                    if bound_session is not None
                    else None
                )
                if continuity_audit is not None:
                    audit_issues = run_audit_errors(
                        continuity_audit
                    )
                    if audit_issues:
                        errors.append(
                            f"run {run.id} has invalid managed thread "
                            "continuity audit: "
                            + "; ".join(audit_issues)
                        )
                    elif not isinstance(
                        continuity_audit,
                        Mapping,
                    ):
                        errors.append(
                            f"run {run.id} continuity audit is invalid"
                        )
                    else:
                        if (
                            run.origin is not RunOrigin.MANAGED_MODEL
                            or bound_session is None
                            or session_continuity is None
                            or continuity_audit.get("session_id")
                            != run.session_id
                            or continuity_audit.get(
                                "configuration_epoch"
                            )
                            != run.configuration_epoch
                            or continuity_audit.get("logical_role")
                            != run.role
                            or continuity_audit.get("model") != run.model
                            or continuity_audit.get(
                                "contract_version"
                            )
                            != run.extra.get("contract_version")
                        ):
                            errors.append(
                                f"run {run.id} continuity audit is not bound "
                                "to its managed run"
                            )
                        elif isinstance(
                            session_continuity,
                            Mapping,
                        ):
                            for key in (
                                "policy",
                                "configuration_epoch",
                                "configuration_fingerprint_sha256",
                                "contract_version",
                                "source_manifest_sha256",
                                "source_generation",
                                "target_id",
                                "target_generation",
                            ):
                                if continuity_audit.get(
                                    key
                                ) != session_continuity.get(key):
                                    errors.append(
                                        f"run {run.id} continuity audit "
                                        "does not match its session"
                                    )
                                    break
                        if (
                            continuity_audit.get("decision")
                            == "resume"
                        ):
                            source_run = runs.get(
                                continuity_audit.get("source_run_id")
                            )
                            source_audit = (
                                source_run.extra.get(
                                    THREAD_CONTINUITY_RUN_KEY
                                )
                                if source_run is not None
                                else None
                            )
                            if (
                                source_run is None
                                or source_run.status
                                is not RunStatus.COMPLETED
                                or source_run.origin
                                is not RunOrigin.MANAGED_MODEL
                                or source_run.session_id != run.session_id
                                or source_run.configuration_epoch
                                != run.configuration_epoch
                                or source_run.role != run.role
                                or source_run.model != run.model
                                or source_run.extra.get(
                                    "contract_version"
                                )
                                != THREAD_CONTINUITY_CONTRACT_VERSION
                                or source_run.extra.get(
                                    "produced_thread_id_sha256"
                                )
                                != continuity_audit.get(
                                    "thread_id_sha256"
                                )
                                or run_audit_errors(source_audit)
                                or not isinstance(
                                    source_audit,
                                    Mapping,
                                )
                                or source_audit.get(
                                    "lane_identity_sha256"
                                )
                                != continuity_audit.get(
                                    "lane_identity_sha256"
                                )
                                or source_audit.get(
                                    "workspace_owner_run_id"
                                )
                                != continuity_audit.get(
                                    "workspace_owner_run_id"
                                )
                            ):
                                errors.append(
                                    f"run {run.id} continuity resume source "
                                    "is invalid"
                                )
                        if (
                            run.wave_id in waves
                            and waves[run.wave_id].kind
                            is WaveKind.PROOF
                            and (
                                continuity_audit.get("decision")
                                != "fresh"
                                or continuity_audit.get("reason")
                                != "proof_wave_forced_fresh"
                                or continuity_audit.get("stable_lane")
                                is not False
                            )
                        ):
                            errors.append(
                                f"proof run {run.id} must use a fresh "
                                "isolated model thread"
                            )
                    if "thread_id" in run.extra:
                        errors.append(
                            f"managed continuity run {run.id} exposes a raw "
                            "provider thread id in canonical state"
                        )
                    produced_digest = run.extra.get(
                        "produced_thread_id_sha256"
                    )
                    secret_path = run.extra.get("thread_secret_path")
                    if (produced_digest is None) != (
                        secret_path is None
                    ):
                        errors.append(
                            f"run {run.id} thread secret pointer/hash are "
                            "incomplete"
                        )
                    elif produced_digest is not None and (
                        type(produced_digest) is not str
                        or re.fullmatch(
                            r"[0-9a-f]{64}",
                            produced_digest,
                        )
                        is None
                        or secret_path
                        != f"runs/{run.id}/thread-secret.json"
                    ):
                        errors.append(
                            f"run {run.id} thread secret pointer/hash are "
                            "invalid"
                        )
                elif (
                    run.origin is RunOrigin.MANAGED_MODEL
                    and session_continuity is not None
                ):
                    errors.append(
                        f"managed run {run.id} requires a thread continuity "
                        "audit"
                    )

            expected_run_status = {
                ReceiptOutcome.SUCCEEDED: RunStatus.COMPLETED,
                ReceiptOutcome.FAILED: RunStatus.FAILED,
                ReceiptOutcome.TIMED_OUT: RunStatus.TIMED_OUT,
                ReceiptOutcome.CANCELLED: RunStatus.CANCELLED,
                ReceiptOutcome.INTERRUPTED: RunStatus.INTERRUPTED,
            }
            seen_receipt_runs: set[str] = set()
            seen_receipt_experiments: set[str] = set()
            for receipt in self.receipts:
                run = runs.get(receipt.run_id)
                experiment = experiments.get(receipt.experiment_id)
                if run is None or run.status not in terminal_run_statuses:
                    errors.append(
                        f"receipt {receipt.id} requires one terminal run"
                    )
                elif run.status is not expected_run_status[receipt.outcome]:
                    errors.append(
                        f"receipt {receipt.id} outcome does not match run "
                        f"{run.id} status"
                    )
                if experiment is None:
                    errors.append(
                        f"receipt {receipt.id} references unknown experiment "
                        f"{receipt.experiment_id}"
                    )
                if receipt.run_id in seen_receipt_runs:
                    errors.append(
                        f"run {receipt.run_id} has more than one receipt"
                    )
                if (
                    receipt.experiment_id in seen_receipt_experiments
                    and (
                        experiment is None
                        or (
                            not _pwn_crash_experiment_marker(experiment)
                            and not (
                                self.schema_version >= STATE_SCHEMA_VERSION
                                and _pwn_ip_control_experiment_marker(
                                    experiment
                                )
                            )
                            and not _web_impact_state_marker(experiment)
                            and not _pwn_exploit_effect_state_marker(
                                experiment
                            )
                            and not _forensic_assertion_state_marker(
                                experiment
                            )
                            and not _rev_acceptance_state_marker(
                                experiment
                            )
                        )
                    )
                ):
                    errors.append(
                        f"experiment {receipt.experiment_id} has more than "
                        "one receipt"
                    )
                seen_receipt_runs.add(receipt.run_id)
                seen_receipt_experiments.add(receipt.experiment_id)
                for artifact_id in (
                    receipt.stdout_artifact_id,
                    receipt.stderr_artifact_id,
                ):
                    if artifact_id is not None and artifact_id not in artifacts:
                        errors.append(
                            f"receipt {receipt.id} references unknown artifact "
                            f"{artifact_id}"
                        )
                if len(receipt.preview) > 160:
                    errors.append(
                        f"receipt {receipt.id} preview exceeds 160 characters"
                    )
                for label, value in (
                    ("wall_seconds", receipt.wall_seconds),
                    ("stdout_bytes", receipt.stdout_bytes),
                    ("stderr_bytes", receipt.stderr_bytes),
                    ("stdout_lines", receipt.stdout_lines),
                    ("stderr_lines", receipt.stderr_lines),
                ):
                    if value < 0:
                        errors.append(
                            f"receipt {receipt.id} {label} cannot be negative"
                        )
                errors.extend(
                    _receipt_stream_evidence_errors(
                        receipt,
                        artifacts,
                    )
                )

            for session in self.sessions:
                if session.configuration_epoch > self.configuration_epoch:
                    errors.append(
                        f"session {session.id} has a future configuration epoch"
                    )
                for run_id in session.run_ids:
                    if run_id not in runs:
                        errors.append(
                            f"session {session.id} references unknown run "
                            f"{run_id}"
                        )
                for wave_id in session.wave_ids:
                    if wave_id not in waves:
                        errors.append(
                            f"session {session.id} references unknown wave "
                            f"{wave_id}"
                        )
                if session.status in {
                    SessionStatus.COMPLETED,
                    SessionStatus.PAUSED,
                    SessionStatus.FAILED,
                    SessionStatus.INTERRUPTED,
                } and session.end_revision is None:
                    errors.append(
                        f"terminal session {session.id} requires end_revision"
                    )
                continuity_metadata = session.extra.get(
                    THREAD_CONTINUITY_SESSION_KEY
                )
                if continuity_metadata is not None:
                    metadata_issues = session_metadata_errors(
                        continuity_metadata
                    )
                    if metadata_issues:
                        errors.append(
                            f"session {session.id} has invalid managed thread "
                            "continuity metadata: "
                            + "; ".join(metadata_issues)
                        )
                    elif (
                        not isinstance(
                            continuity_metadata,
                            Mapping,
                        )
                        or session.mode is not SessionMode.MANAGED
                        or continuity_metadata.get(
                            "configuration_epoch"
                        )
                        != session.configuration_epoch
                    ):
                        errors.append(
                            f"session {session.id} thread continuity "
                            "metadata is not bound to the session"
                        )

            if self.active_managed_session_id is not None:
                active_session = sessions.get(self.active_managed_session_id)
                if active_session is None:
                    errors.append(
                        "active_managed_session_id references unknown session "
                        f"{self.active_managed_session_id}"
                    )
                elif (
                    active_session.mode is not SessionMode.MANAGED
                    or active_session.status
                    not in {SessionStatus.CREATED, SessionStatus.RUNNING}
                ):
                    errors.append(
                        f"active managed session {active_session.id} is not "
                        "managed and nonterminal"
                    )
            active_managed = [
                session.id
                for session in self.sessions
                if session.mode is SessionMode.MANAGED
                and session.status
                in {SessionStatus.CREATED, SessionStatus.RUNNING}
            ]
            if len(active_managed) > 1:
                errors.append(
                    "only one managed session may be active: "
                    + ", ".join(active_managed)
                )

            expected_roles = {
                WaveKind.DISCOVERY: {"recon", "specialist", "extractor"},
                WaveKind.ATTACK: {"builder", "falsifier", "reproducer"},
                WaveKind.PROOF: {
                    "validator",
                    "reproducer",
                    "evidence_auditor",
                },
                WaveKind.EVALUATION: {
                    "falsifier",
                    "validator",
                    "evidence_auditor",
                },
            }
            for wave in self.waves:
                if wave.session_id not in sessions:
                    errors.append(
                        f"wave {wave.id} references unknown session "
                        f"{wave.session_id}"
                    )
                if wave.cycle_id not in cycles:
                    errors.append(
                        f"wave {wave.id} references unknown cycle "
                        f"{wave.cycle_id}"
                    )
                if set(wave.role_run_ids) != expected_roles[wave.kind]:
                    errors.append(
                        f"wave {wave.id} must contain exactly the three "
                        f"{wave.kind.value} roles"
                    )
                if len(set(wave.role_run_ids.values())) != 3:
                    errors.append(
                        f"wave {wave.id} must reference three distinct runs"
                    )
                for role, run_id in wave.role_run_ids.items():
                    run = runs.get(run_id)
                    if run is None:
                        errors.append(
                            f"wave {wave.id} role {role} references unknown "
                            f"run {run_id}"
                        )
                    elif (
                        run.role != role
                        or run.wave_id != wave.id
                        or run.session_id != wave.session_id
                        or run.cycle_id != wave.cycle_id
                    ):
                        errors.append(
                            f"wave {wave.id} role/run binding mismatch for "
                            f"{role}"
                        )

            for cycle in self.cycles:
                if cycle.session_id not in sessions:
                    errors.append(
                        f"cycle {cycle.id} references unknown session "
                        f"{cycle.session_id}"
                    )
                if cycle.captain_run_id is not None:
                    captain_run = runs.get(cycle.captain_run_id)
                    if (
                        captain_run is None
                        or captain_run.role != "captain"
                        or captain_run.session_id != cycle.session_id
                        or captain_run.cycle_id != cycle.id
                    ):
                        errors.append(
                            f"cycle {cycle.id} captain run binding is invalid"
                        )
                if cycle.wave_id is not None and cycle.wave_id not in waves:
                    errors.append(
                        f"cycle {cycle.id} references unknown wave "
                        f"{cycle.wave_id}"
                    )
                if (
                    cycle.checkpoint_id is not None
                    and cycle.checkpoint_id not in checkpoints
                ):
                    errors.append(
                        f"cycle {cycle.id} references unknown checkpoint "
                        f"{cycle.checkpoint_id}"
                    )

            def failure_capsule_machine_token(value: object) -> bool:
                return (
                    type(value) is str
                    and 1 <= len(value) <= 64
                    and "a" <= value[0] <= "z"
                    and all(
                        ("a" <= character <= "z")
                        or character in "0123456789_"
                        for character in value
                    )
                )

            failure_capsule_id_limits = {
                "run_ids": 16,
                "failed_experiment_ids": 16,
                "fact_ids": 32,
                "artifact_ids": 32,
                "receipt_ids": 32,
                "unresolved_hypothesis_ids": 32,
                "next_experiment_ids": 3,
            }
            failure_capsule_bindings: dict[
                tuple[str, str],
                str,
            ] = {}
            for checkpoint in self.checkpoints:
                if (
                    checkpoint.active_goal_id is not None
                    and checkpoint.active_goal_id not in goals
                ):
                    errors.append(
                        f"checkpoint {checkpoint.id} references unknown goal "
                        f"{checkpoint.active_goal_id}"
                    )
                for hypothesis_id in checkpoint.open_hypothesis_ids:
                    if hypothesis_id not in hypotheses:
                        errors.append(
                            f"checkpoint {checkpoint.id} references unknown "
                            f"hypothesis {hypothesis_id}"
                        )
                for fact_id in checkpoint.observation_fact_ids:
                    if fact_id not in facts:
                        errors.append(
                            f"checkpoint {checkpoint.id} references unknown "
                            f"fact {fact_id}"
                        )
                for artifact_id in checkpoint.artifact_ids:
                    if artifact_id not in artifacts:
                        errors.append(
                            f"checkpoint {checkpoint.id} references unknown "
                            f"artifact {artifact_id}"
                        )
                for receipt_id in checkpoint.receipt_ids:
                    if receipt_id not in receipts:
                        errors.append(
                            f"checkpoint {checkpoint.id} references unknown "
                            f"receipt {receipt_id}"
                        )
                capsule = checkpoint.failure_capsule
                if capsule is None:
                    continue
                if not isinstance(capsule, FailureCapsule):
                    errors.append(
                        f"checkpoint {checkpoint.id} failure capsule must be "
                        "canonical"
                    )
                    continue
                bound_cycle = None
                if (
                    checkpoint.session_id is None
                    or checkpoint.cycle_id is None
                ):
                    errors.append(
                        f"checkpoint {checkpoint.id} failure capsule requires "
                        "session_id and cycle_id"
                    )
                else:
                    session = sessions.get(checkpoint.session_id)
                    cycle = cycles.get(checkpoint.cycle_id)
                    if session is None:
                        errors.append(
                            f"checkpoint {checkpoint.id} failure capsule "
                            f"references unknown session "
                            f"{checkpoint.session_id}"
                        )
                    if cycle is None:
                        errors.append(
                            f"checkpoint {checkpoint.id} failure capsule "
                            f"references unknown cycle {checkpoint.cycle_id}"
                        )
                    else:
                        bound_cycle = cycle
                        if cycle.session_id != checkpoint.session_id:
                            errors.append(
                                f"checkpoint {checkpoint.id} failure capsule "
                                "cycle does not bind its session"
                            )
                        if cycle.checkpoint_id != checkpoint.id:
                            errors.append(
                                f"checkpoint {checkpoint.id} failure capsule "
                                "is not the cycle checkpoint"
                            )
                    binding = (
                        checkpoint.session_id,
                        checkpoint.cycle_id,
                    )
                    prior_checkpoint_id = failure_capsule_bindings.get(
                        binding
                    )
                    if prior_checkpoint_id is not None:
                        errors.append(
                            f"failure capsule checkpoints "
                            f"{prior_checkpoint_id} and {checkpoint.id} share "
                            "a session/cycle binding"
                        )
                    else:
                        failure_capsule_bindings[binding] = checkpoint.id
                if (
                    type(capsule.schema_version) is not int
                    or capsule.schema_version != 1
                ):
                    errors.append(
                        f"checkpoint {checkpoint.id} failure capsule "
                        "schema_version must be 1"
                    )
                for label, value in (
                    ("reason_code", capsule.reason_code),
                    ("stage", capsule.stage),
                ):
                    if not failure_capsule_machine_token(value):
                        errors.append(
                            f"checkpoint {checkpoint.id} failure capsule "
                            f"{label} is not a machine token"
                        )
                if not _proof_binding_sha256(
                    capsule.fingerprint_sha256
                ):
                    errors.append(
                        f"checkpoint {checkpoint.id} failure capsule has an "
                        "invalid fingerprint_sha256"
                    )
                if not _proof_binding_sha256(capsule.content_sha256):
                    errors.append(
                        f"checkpoint {checkpoint.id} failure capsule has an "
                        "invalid content_sha256"
                    )
                if (
                    type(capsule.state_revision_before) is not int
                    or type(capsule.state_revision_after) is not int
                ):
                    errors.append(
                        f"checkpoint {checkpoint.id} failure capsule "
                        "revisions must be non-boolean integers"
                    )
                elif not (
                    0
                    <= capsule.state_revision_before
                    <= capsule.state_revision_after
                    <= self.revision
                    + (1 if _allow_precommit_failure_capsules else 0)
                ):
                    errors.append(
                        f"checkpoint {checkpoint.id} failure capsule has an "
                        "invalid revision range"
                    )
                omitted_counts_are_canonical = (
                    isinstance(capsule.omitted_counts, dict)
                    and set(capsule.omitted_counts)
                    == set(_FAILURE_CAPSULE_OMITTED_COUNT_FIELDS)
                    and all(
                        type(value) is int and value >= 0
                        for value in capsule.omitted_counts.values()
                    )
                )
                if not omitted_counts_are_canonical:
                    errors.append(
                        f"checkpoint {checkpoint.id} failure capsule "
                        "omitted_counts is not canonical"
                    )
                elif (
                    _proof_binding_sha256(capsule.content_sha256)
                    and capsule.content_sha256
                    != capsule.computed_content_sha256()
                ):
                    errors.append(
                        f"checkpoint {checkpoint.id} failure capsule "
                        "content_sha256 does not match its capture"
                    )
                valid_capsule_ids: dict[str, list[str]] = {}
                for field_name, limit in failure_capsule_id_limits.items():
                    values = getattr(capsule, field_name)
                    valid_values: list[str] = []
                    valid_capsule_ids[field_name] = valid_values
                    if not isinstance(values, list):
                        errors.append(
                            f"checkpoint {checkpoint.id} failure capsule "
                            f"{field_name} must be an array"
                        )
                        continue
                    if len(values) > limit:
                        errors.append(
                            f"checkpoint {checkpoint.id} failure capsule "
                            f"{field_name} exceeds {limit} items"
                        )
                    seen_ids: set[str] = set()
                    for value in values:
                        if type(value) is not str or not value.strip():
                            errors.append(
                                f"checkpoint {checkpoint.id} failure capsule "
                                f"{field_name} contains an empty or non-string "
                                "id"
                            )
                            continue
                        valid_values.append(value)
                        if value in seen_ids:
                            errors.append(
                                f"checkpoint {checkpoint.id} failure capsule "
                                f"{field_name} contains duplicate id {value}"
                            )
                        seen_ids.add(value)

                for run_id in valid_capsule_ids["run_ids"]:
                    run = runs.get(run_id)
                    if run is None:
                        errors.append(
                            f"checkpoint {checkpoint.id} failure capsule "
                            f"references unknown run {run_id}"
                        )
                    elif (
                        run.session_id != checkpoint.session_id
                        or run.cycle_id != checkpoint.cycle_id
                    ):
                        errors.append(
                            f"checkpoint {checkpoint.id} failure capsule run "
                            f"{run_id} does not bind its session and cycle"
                        )
                for field_name in (
                    "failed_experiment_ids",
                    "next_experiment_ids",
                ):
                    for experiment_id in valid_capsule_ids[field_name]:
                        if experiment_id not in experiments:
                            errors.append(
                                f"checkpoint {checkpoint.id} failure capsule "
                                f"references unknown experiment "
                                f"{experiment_id}"
                            )
                for field_name, records, label in (
                    ("fact_ids", facts, "fact"),
                    ("artifact_ids", artifacts, "artifact"),
                    ("receipt_ids", receipts, "receipt"),
                    (
                        "unresolved_hypothesis_ids",
                        hypotheses,
                        "hypothesis",
                    ),
                ):
                    for record_id in valid_capsule_ids[field_name]:
                        if record_id not in records:
                            errors.append(
                                f"checkpoint {checkpoint.id} failure capsule "
                                f"references unknown {label} {record_id}"
                            )
                if bound_cycle is not None:
                    try:
                        from ctf_os.engine.failure_capsule import (
                            validate_pwn_failure_capsule_binding,
                        )

                        validate_pwn_failure_capsule_binding(
                            self,
                            capsule,
                            cycle=bound_cycle,
                        )
                    except ModelValidationError as error:
                        errors.append(
                            f"checkpoint {checkpoint.id}: {error}"
                        )

            if self.primary_target_id is not None:
                primary = targets.get(self.primary_target_id)
                if primary is None:
                    errors.append(
                        f"primary_target_id references unknown target "
                        f"{self.primary_target_id}"
                    )
                elif primary.status is not TargetStatus.ACTIVE:
                    errors.append(
                        f"primary target {primary.id} is not active"
                    )
            target_endpoints: set[tuple[str, int]] = set()
            for target in self.targets:
                if not target.endpoint or target.generation < 1:
                    errors.append(
                        f"target {target.id} requires endpoint and positive "
                        "generation"
                    )
                key = (target.endpoint, target.generation)
                if key in target_endpoints:
                    errors.append(
                        f"duplicate target endpoint/generation: "
                        f"{target.endpoint} generation {target.generation}"
                    )
                target_endpoints.add(key)
                if (
                    target.status is TargetStatus.REVOKED
                    and (
                        not target.revoked_at
                        or not (target.revoke_reason or "").strip()
                    )
                ):
                    errors.append(
                        f"revoked target {target.id} requires timestamp and "
                        "reason"
                    )

            for submission in self.submissions:
                if (
                    submission.status
                    in {SubmissionStatus.ACCEPTED, SubmissionStatus.REJECTED}
                    and not submission.proof_passed
                    and submission.override is None
                ):
                    errors.append(
                        f"unproved terminal submission {submission.id} "
                        "requires an override"
                    )
                if submission.override is not None and (
                    not submission.override.kind.strip()
                    or not submission.override.actor.strip()
                    or not submission.override.reason.strip()
                ):
                    errors.append(
                        f"submission {submission.id} override requires kind, "
                        "actor, and reason"
                    )

            if self.closure is not None:
                if self.closure.portability not in {
                    "portable",
                    "referential",
                }:
                    errors.append(
                        "closure portability must be portable or referential"
                    )
                for run_id in self.closure.proof_run_ids:
                    if run_id not in runs:
                        errors.append(
                            f"closure references unknown proof run {run_id}"
                        )
                for target_id in self.closure.target_ids:
                    if target_id not in targets:
                        errors.append(
                            f"closure references unknown target {target_id}"
                        )
                for checkpoint_id in self.closure.checkpoint_ids:
                    if checkpoint_id not in checkpoints:
                        errors.append(
                            f"closure references unknown checkpoint "
                            f"{checkpoint_id}"
                        )

            for publish in self.workspace_publishes:
                if publish.run_id not in runs:
                    errors.append(
                        f"workspace publish {publish.id} references unknown "
                        f"run {publish.run_id}"
                    )
                if (
                    publish.base_workspace_revision < 0
                    or (
                        publish.published_workspace_revision is not None
                        and publish.published_workspace_revision
                        > self.workspace_revision
                    )
                ):
                    errors.append(
                        f"workspace publish {publish.id} has invalid revision"
                    )

        if self.schema_version >= STATE_SCHEMA_VERSION:
            errors.extend(
                _rev_inventory_state_errors(
                    self,
                    runs=runs,
                    receipts=receipts,
                    artifacts=artifacts,
                    facts=facts,
                )
            )
            errors.extend(
                _pwn_crash_state_errors(
                    self,
                    runs=runs,
                    receipts=receipts,
                    artifacts=artifacts,
                    facts=facts,
                    hypotheses=hypotheses,
                )
            )
            errors.extend(
                _pwn_runtime_snapshot_state_errors(
                    self,
                    experiments=experiments,
                    runs=runs,
                    receipts=receipts,
                    artifacts=artifacts,
                    facts=facts,
                    hypotheses=hypotheses,
                    candidates=candidates,
                    disclosure_state_revision=(
                        disclosure_state_revision
                    ),
                )
            )
            errors.extend(
                _pwn_ip_control_state_errors(
                    self,
                    experiments=experiments,
                    runs=runs,
                    receipts=receipts,
                    artifacts=artifacts,
                    facts=facts,
                    candidates=candidates,
                )
            )
            errors.extend(
                _rev_proof_state_errors(
                    self,
                    runs=runs,
                    artifacts=artifacts,
                    candidates=candidates,
                )
            )
            errors.extend(
                _crypto_metamorphic_state_errors(
                    self,
                    runs=runs,
                    artifacts=artifacts,
                    candidates=candidates,
                )
            )
            errors.extend(
                _forensic_index_execution_state_errors(
                    self,
                    experiments=experiments,
                    runs=runs,
                    receipts=receipts,
                    artifacts=artifacts,
                    facts=facts,
                )
            )
            errors.extend(
                _misc_transform_state_errors(
                    self,
                    runs=runs,
                    artifacts=artifacts,
                    facts=facts,
                    candidates=candidates,
                )
            )
            # Imported lazily because the exact Web graph module constructs
            # typed state objects from this module.  Persistence must still
            # reject an orphaned/rebound graph, not merely explicit callers.
            from ctf_os.engine.web_impact_state import (
                web_impact_state_graph_errors,
            )

            errors.extend(web_impact_state_graph_errors(self))

            # Bounded race and sandbox-local OOB probes own an exact six-run
            # vulnerable3/control3 graph.  Revalidate its preissued
            # identities and all raw-free record links on every state load so
            # a copied or rehashed marker cannot create executed authority.
            from ctf_os.engine.web_active_probe_state import (
                web_active_probe_state_graph_errors,
            )

            errors.extend(
                web_active_probe_state_graph_errors(self)
            )

            # As above, the Forensic projection uses model types while its
            # exact validator owns the authorized multi-receipt graph and
            # raw-free executed assertion Fact.  Generic exceptions are
            # therefore marker-gated and every marker is checked here.
            from ctf_os.engine.forensic_assertion_state import (
                forensic_assertion_state_graph_errors,
            )

            errors.extend(forensic_assertion_state_graph_errors(self))

            # Pwn exploit-effect execution is a single child with six
            # receipts.  The generic multi-receipt exception is marker-gated;
            # this lazy exact validator makes a copied marker insufficient by
            # reconstructing the complete PREISSUED or FINAL graph.
            from ctf_os.engine.pwn_exploit_effect_state import (
                pwn_exploit_effect_state_graph_errors,
            )

            errors.extend(
                pwn_exploit_effect_state_graph_errors(self)
            )

            # A FINAL production exploit effect must also be bound to the
            # exact D->V->(L|N/A)->P->E dependency closure.  Keeping this
            # validator at the persistence boundary makes a removed, copied,
            # stale, or rehashed graph fail closed during every state load.
            from ctf_os.engine.pwn_dependency_state import (
                pwn_dependency_state_graph_errors,
            )

            errors.extend(pwn_dependency_state_graph_errors(self))

            # A managed admission record is authoritative only when it binds a
            # completed Captain to either all three role runs or a typed
            # Captain-stage pause capsule. Provider limits alter serial
            # batches, never logical width.
            from ctf_os.managed_budget import (
                managed_wave_budget_state_errors,
            )

            errors.extend(managed_wave_budget_state_errors(self))

            # Candidate-free Rev accepted-input evidence owns one fixed 3+3
            # multi-receipt graph.  The local generic exception above is
            # marker-scoped; this exact validator rejects copied, rebound, or
            # orphaned markers and never grants candidate/submission authority.
            from ctf_os.engine.rev_acceptance_state import (
                rev_acceptance_state_graph_errors,
            )

            errors.extend(rev_acceptance_state_graph_errors(self))
        if errors:
            raise ModelValidationError("; ".join(errors))


def validate_forensic_index_execution_state_graph(
    state: ChallengeState,
) -> None:
    """Validate only the durable Forensic evidence-index execution graph.

    This public entry point is useful at explicit trust boundaries that already
    hold a fully parsed ``ChallengeState``.  Normal persistence paths should
    continue to call :meth:`ChallengeState.validate`, which includes this
    contract plus every generic state invariant.
    """

    if type(state) is not ChallengeState:
        raise ModelValidationError(
            "Forensic index state graph requires ChallengeState"
        )
    errors = _forensic_index_execution_state_errors(
        state,
        experiments={item.id: item for item in state.experiments},
        runs={item.id: item for item in state.runs},
        receipts={item.id: item for item in state.receipts},
        artifacts={item.id: item for item in state.artifacts},
        facts={item.id: item for item in state.facts},
    )
    if errors:
        raise ModelValidationError("; ".join(errors))


def new_challenge_state(
    identity: ChallengeIdentity,
    *,
    description: str = "",
    prompt: str = "",
    source_path: str | None = None,
    metadata: Mapping[str, Any] | None = None,
    budget: Budget | Mapping[str, Any] | None = None,
    schema_version: int = CURRENT_SCHEMA_VERSION,
) -> ChallengeState:
    """Construct a validated revision-zero challenge state."""

    if budget is None:
        parsed_budget = Budget()
    elif isinstance(budget, Budget):
        parsed_budget = budget
    else:
        parsed_budget = Budget.from_dict(budget)
    state = ChallengeState(
        contest_id=identity.contest_id,
        category=identity.category,
        challenge_id=identity.challenge_id,
        description=description,
        prompt=prompt,
        source_path=source_path,
        metadata=dict(metadata or {}),
        budget=parsed_budget,
        schema_version=schema_version,
    )
    state.validate()
    return state


__all__ = [
    "ACTIVE_HYPOTHESIS_STATUSES",
    "ArtifactReference",
    "Budget",
    "BudgetMode",
    "CURRENT_SCHEMA_VERSION",
    "Candidate",
    "CandidateStatus",
    "CandidateTier",
    "Checkpoint",
    "ChallengeIdentity",
    "ChallengeState",
    "ChallengeStatus",
    "ClosureBundle",
    "ClosureCompleteness",
    "distinct_complete_active_hypotheses",
    "ExecutionReceipt",
    "Experiment",
    "ExperimentKind",
    "ExperimentStatus",
    "Fact",
    "FactKind",
    "FailureCapsule",
    "FlagCandidate",
    "Falsifier",
    "Goal",
    "GoalStatus",
    "Hypothesis",
    "HypothesisStatus",
    "hypothesis_has_complete_discriminators",
    "ModelValidationError",
    "ManagedCycle",
    "ManagedWave",
    "MANAGED_SHELL_ARGV_PREFIX",
    "MANAGED_SHELL_COMMAND_PROTOCOL",
    "MAX_MANAGED_PROOF_INPUT_BYTES",
    "ProgressMarker",
    "ProofPolicySnapshot",
    "ProofRecipe",
    "ProofRecipeInput",
    "Provenance",
    "PwnDisclosurePhase",
    "PwnRuntimeSnapshotDisclosureEnvelope",
    "ReceiptOutcome",
    "RevStdinOracleBinding",
    "RunReference",
    "RunOrigin",
    "RunStatus",
    "SessionMode",
    "SessionStatus",
    "SolveSession",
    "SourceFile",
    "Submission",
    "SubmissionOverride",
    "SubmissionReference",
    "SubmissionStatus",
    "TargetRecord",
    "TargetStatus",
    "WaveKind",
    "WorkspacePublish",
    "new_challenge_state",
    "utc_now",
    "validate_forensic_index_execution_state_graph",
]
