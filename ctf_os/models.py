"""Domain models for the filesystem-backed CTF-OS state.

The state file is deliberately represented with standard-library dataclasses.
Keeping this layer dependency-free makes recovery possible even when the rest of
the runtime (or its virtual environment) is damaged during a contest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Mapping

from ctf_os.candidates import candidate_value_is_valid

CURRENT_SCHEMA_VERSION = 1
MAX_REPEATED_FIELD_ITEMS = 16_384
MAX_RECORDS_PER_COLLECTION = MAX_REPEATED_FIELD_ITEMS
MAX_EXPERIMENT_TIMEOUT_SECONDS = 8 * 60 * 60

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


class ExperimentStatus(StringEnum):
    REGISTERED = "registered"
    RUNNING = "running"
    AWAITING_EVALUATION = "awaiting_evaluation"
    KEPT = "kept"
    DROPPED = "dropped"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"
    CANCELLED = "cancelled"


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
    created_at: str = field(default_factory=utc_now)
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return _with_extra(
            self.extra,
            id=self.id,
            base_revision=self.base_revision,
            status=_enum_value(self.status),
            request_path=self.request_path,
            result_path=self.result_path,
            validation_path=self.validation_path,
            role=self.role,
            model=self.model,
            context_hash=self.context_hash,
            created_at=self.created_at,
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
            created_at=str(data.get("created_at", utc_now())),
            extra=_extra(data, known),
        )


@dataclass
class Fact:
    id: str
    statement: str
    provenance: Provenance
    challenge_id: str = ""
    source_run_id: str | None = None
    artifact_id: str | None = None
    locator: str | None = None
    created_at: str = field(default_factory=utc_now)
    supersedes_id: str | None = None
    supports: list[str] = field(default_factory=list)
    contradicts: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self, *, default_challenge_id: str | None = None) -> dict[str, Any]:
        return _with_extra(
            self.extra,
            id=self.id,
            challenge_id=self.challenge_id or default_challenge_id or "",
            statement=self.statement,
            provenance=_enum_value(self.provenance),
            source_run_id=self.source_run_id,
            artifact_id=self.artifact_id,
            locator=self.locator,
            created_at=self.created_at,
            supersedes_id=self.supersedes_id,
            supports=list(self.supports),
            contradicts=list(self.contradicts),
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
    confidence: float | None = None
    refuted_by: str | None = None
    source_run_id: str | None = None
    created_at: str = field(default_factory=utc_now)
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return _with_extra(
            self.extra,
            id=self.id,
            statement=self.statement,
            paradigm=self.paradigm,
            falsifier=self.falsifier.to_dict(),
            status=_enum_value(self.status),
            evidence_fact_ids=list(self.evidence_fact_ids),
            evidence_artifact_ids=list(self.evidence_artifact_ids),
            evidence_run_ids=list(self.evidence_run_ids),
            confidence=self.confidence,
            refuted_by=self.refuted_by,
            source_run_id=self.source_run_id,
            created_at=self.created_at,
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
    status: ExperimentStatus = ExperimentStatus.REGISTERED
    result: Any = None
    source_run_id: str | None = None
    artifact_ids: list[str] = field(default_factory=list)
    evidence_fact_ids: list[str] = field(default_factory=list)
    evidence_run_ids: list[str] = field(default_factory=list)
    evaluation_reason: str | None = None
    evaluated_at: str | None = None
    created_at: str = field(default_factory=utc_now)
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return _with_extra(
            self.extra,
            id=self.id,
            hypothesis_ids=list(self.hypothesis_ids),
            command=self.command,
            expected_observation=self.expected_observation,
            keep_if=self.keep_if,
            drop_if=self.drop_if,
            timeout_seconds=self.timeout_seconds,
            resource_class=self.resource_class,
            status=_enum_value(self.status),
            result=self.result,
            source_run_id=self.source_run_id,
            artifact_ids=list(self.artifact_ids),
            evidence_fact_ids=list(self.evidence_fact_ids),
            evidence_run_ids=list(self.evidence_run_ids),
            evaluation_reason=self.evaluation_reason,
            evaluated_at=self.evaluated_at,
            created_at=self.created_at,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Experiment":
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
            "status",
            "result",
            "source_run_id",
            "artifact_ids",
            "evidence_fact_ids",
            "evidence_run_ids",
            "evaluation_reason",
            "evaluated_at",
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
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def remaining_seconds(self) -> int | None:
        if self.allocated_seconds is None:
            return None
        return max(0, self.allocated_seconds - self.spent_seconds)

    def to_dict(self) -> dict[str, Any]:
        return _with_extra(
            self.extra,
            deadline_utc=self.deadline_utc,
            allocated_seconds=self.allocated_seconds,
            spent_seconds=self.spent_seconds,
            no_progress_since_seconds=self.no_progress_since_seconds,
            model_tier=self.model_tier,
            abort_rule=dict(self.abort_rule),
            refusals=list(self.refusals),
            curve_profile=self.curve_profile,
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
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return _with_extra(
            self.extra,
            id=self.id,
            value=self.value,
            status=_enum_value(self.status),
            source_run_id=self.source_run_id,
            artifact_id=self.artifact_id,
            locator=self.locator,
            created_at=self.created_at,
            proof_run_ids=list(self.proof_run_ids),
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
            extra=_extra(data, known),
        )


# A concise alias is convenient in engine code and preserves the terminology in
# the implementation report.
Candidate = FlagCandidate


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
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return _with_extra(
            self.extra,
            id=self.id,
            candidate_id=self.candidate_id,
            status=_enum_value(self.status),
            submitted_at=self.submitted_at,
            response=self.response,
            attempt=self.attempt,
            proof_passed=self.proof_passed,
            format_ok=self.format_ok,
            points=self.points,
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
            extra=_extra(data, known),
        )


Submission = SubmissionReference


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
        return _with_extra(
            self.extra,
            schema_version=self.schema_version,
            revision=self.revision,
            updated_at=self.updated_at,
            created_at=self.created_at,
            contest_id=self.contest_id,
            category=self.category,
            challenge_id=self.challenge_id,
            identity=self.identity.to_dict(),
            status=_enum_value(self.status),
            resume_status=(
                _enum_value(self.resume_status)
                if self.resume_status is not None
                else None
            ),
            description=self.description,
            prompt=self.prompt,
            source_path=self.source_path,
            source_inventory=[item.to_dict() for item in self.source_inventory],
            metadata=dict(self.metadata),
            active_goal_id=self.active_goal_id,
            goals=[item.to_dict() for item in self.goals],
            facts=[
                item.to_dict(default_challenge_id=self.challenge_id)
                for item in self.facts
            ],
            hypotheses=[item.to_dict() for item in self.hypotheses],
            experiments=[item.to_dict() for item in self.experiments],
            progress_markers=[
                item.to_dict() for item in self.progress_markers
            ],
            budget=self.budget.to_dict(),
            candidates=[item.to_dict() for item in self.candidates],
            submissions=[item.to_dict() for item in self.submissions],
            artifacts=[item.to_dict() for item in self.artifacts],
            runs=[item.to_dict() for item in self.runs],
        )

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
            extra=_extra(data, known),
        )
        return state

    def validate(self) -> None:
        """Validate referential and state invariants before persistence."""

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
        if self.schema_version != CURRENT_SCHEMA_VERSION:
            errors.append(
                f"schema_version must be {CURRENT_SCHEMA_VERSION}, "
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
            if experiment.status in evaluated_statuses:
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
    )
    state.validate()
    return state


__all__ = [
    "ArtifactReference",
    "Budget",
    "CURRENT_SCHEMA_VERSION",
    "Candidate",
    "CandidateStatus",
    "ChallengeIdentity",
    "ChallengeState",
    "ChallengeStatus",
    "Experiment",
    "ExperimentStatus",
    "Fact",
    "FlagCandidate",
    "Falsifier",
    "Goal",
    "GoalStatus",
    "Hypothesis",
    "HypothesisStatus",
    "ModelValidationError",
    "ProgressMarker",
    "Provenance",
    "RunReference",
    "RunStatus",
    "SourceFile",
    "Submission",
    "SubmissionReference",
    "SubmissionStatus",
    "new_challenge_state",
    "utc_now",
]
