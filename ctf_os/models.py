"""Typed, local-first data models shared by the CTF-OS foundation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from hashlib import sha256
from typing import Any, Mapping
from uuid import uuid4


def utc_now() -> datetime:
    """Return an aware UTC timestamp."""
    return datetime.now(timezone.utc)


def ensure_utc(value: datetime | str | None = None) -> datetime:
    """Parse a timestamp and normalize it to aware UTC.

    Naive datetimes are rejected so local state never silently depends on a
    machine's timezone.
    """
    if value is None:
        return utc_now()
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return value.astimezone(timezone.utc)


def timestamp_text(value: datetime | str | None = None) -> str:
    return ensure_utc(value).isoformat(timespec="microseconds")


def stable_id(*parts: str, prefix: str = "") -> str:
    """Return a deterministic, opaque identifier from stable logical keys."""
    material = "\x1f".join(part.strip().casefold() for part in parts)
    digest = sha256(material.encode("utf-8")).hexdigest()[:24]
    return f"{prefix}{digest}" if prefix else digest


def slugify(value: str) -> str:
    """Create a stable filesystem-friendly slug without locale dependencies."""
    cleaned = []
    previous_dash = False
    for char in value.strip().casefold():
        if char.isalnum():
            cleaned.append(char)
            previous_dash = False
        elif not previous_dash:
            cleaned.append("-")
            previous_dash = True
    result = "".join(cleaned).strip("-")
    if not result:
        raise ValueError("value cannot produce an empty slug")
    return result


class ChallengeStatus(StrEnum):
    DISCOVERED = "DISCOVERED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    STUCK = "STUCK"
    HINTING = "HINTING"
    FLAG_CANDIDATE = "FLAG_CANDIDATE"
    VERIFYING = "VERIFYING"
    SOLVED = "SOLVED"
    FAILED = "FAILED"
    PAUSED = "PAUSED"


class AttemptStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    STOPPED = "STOPPED"


class SessionStatus(StrEnum):
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"


class ContractTaskStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


@dataclass(frozen=True, slots=True)
class Challenge:
    contest: str
    category: str
    name: str
    score: int | None = None
    remote: str | None = None
    description: str | None = None
    hint: str | None = None
    flag_format: str | None = None
    flag_pattern: str | None = None
    status: ChallengeStatus = ChallengeStatus.DISCOVERED
    assignee: str | None = None
    flag: str | None = None
    # Synthetic results are intentionally carried all the way through local
    # state.  A mock result must never become indistinguishable from a real
    # team solve after a restart.
    synthetic: bool = False
    id: str = ""
    slug: str = ""
    challenge_key: str = ""
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        contest, category, name = self.contest.strip(), self.category.strip(), self.name.strip()
        if not contest or not category or not name:
            raise ValueError("challenge contest, category, and name are required")
        if self.score is not None and self.score < 0:
            raise ValueError("challenge score cannot be negative")
        object.__setattr__(self, "contest", contest)
        object.__setattr__(self, "category", category)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "id", self.id or stable_id(contest, category, name, prefix="chal_"))
        object.__setattr__(self, "slug", self.slug or slugify(f"{category}-{name}"))
        object.__setattr__(self, "challenge_key", self.challenge_key or ":".join(
            (slugify(contest), slugify(category), slugify(name))
        ))
        object.__setattr__(self, "created_at", ensure_utc(self.created_at))
        object.__setattr__(self, "updated_at", ensure_utc(self.updated_at))


@dataclass(frozen=True, slots=True)
class Attempt:
    challenge_id: str
    profile: str
    role: str
    backend: str
    workdir: str
    id: str = field(default_factory=lambda: f"attempt_{uuid4().hex}")
    model: str | None = None
    # These are the active routing selection, separate from ``profile``
    # above which is the immutable RacePlan attempt kind used for leasing.
    # A bounded fallback can therefore update the actual model selection
    # without changing the attempt's scheduling identity.
    model_profile: str | None = None
    reasoning_effort: str | None = None
    pid: int | None = None
    container_name: str | None = None
    status: AttemptStatus | str = AttemptStatus.QUEUED
    started_at: datetime | None = None
    ended_at: datetime | None = None
    token_total: int = 0
    synthetic: bool = False
    cleanup_status: str | None = None
    cleanup_message: str | None = None
    # Lease identity is persisted with an attempt so late workers cannot use a
    # newer owner's reservation after expiry/reclaim.
    lease_owner: str | None = None
    fencing_token: int | None = None
    # Codex CLI session identities are optional transport metadata.  Keeping
    # them on the durable attempt lets an operator resume a real local run
    # after a restart without changing its scheduling or lease identity.
    session_id: str | None = None
    resume_id: str | None = None

    def __post_init__(self) -> None:
        if not all((self.challenge_id, self.profile, self.role, self.backend, self.workdir)):
            raise ValueError("attempt fields challenge_id, profile, role, backend, and workdir are required")
        if self.token_total < 0:
            raise ValueError("token_total cannot be negative")
        if self.fencing_token is not None and self.fencing_token < 1:
            raise ValueError("fencing_token must be positive when set")
        object.__setattr__(self, "started_at", ensure_utc(self.started_at) if self.started_at else None)
        object.__setattr__(self, "ended_at", ensure_utc(self.ended_at) if self.ended_at else None)


@dataclass(frozen=True, slots=True)
class ChallengeSession:
    """Durable controller state for one Sol-owned challenge lifecycle."""

    challenge_id: str
    leader_model: str
    leader_profile: str = "sol"
    reasoning_effort: str = "xhigh"
    id: str = ""
    status: SessionStatus | str = SessionStatus.ACTIVE
    leader_session_id: str | None = None
    leader_resume_id: str | None = None
    execution_contract: Mapping[str, Any] = field(default_factory=dict)
    summary_state: Mapping[str, Any] = field(default_factory=dict)
    generation: int = 0
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if not self.challenge_id.strip() or not self.leader_model.strip():
            raise ValueError("session challenge_id and leader_model are required")
        if self.generation < 0:
            raise ValueError("session generation cannot be negative")
        object.__setattr__(self, "id", self.id or stable_id(self.challenge_id, prefix="session_"))
        object.__setattr__(self, "status", SessionStatus(str(self.status).upper()))
        object.__setattr__(self, "execution_contract", dict(self.execution_contract))
        object.__setattr__(self, "summary_state", dict(self.summary_state))
        object.__setattr__(self, "created_at", ensure_utc(self.created_at))
        object.__setattr__(self, "updated_at", ensure_utc(self.updated_at))


@dataclass(frozen=True, slots=True)
class ContractTask:
    """One branch issued by a challenge session under an execution contract."""

    session_id: str
    challenge_id: str
    branch: str
    role: str
    objective: str
    id: str = field(default_factory=lambda: f"task_{uuid4().hex}")
    status: ContractTaskStatus | str = ContractTaskStatus.PENDING
    success_criteria: tuple[str, ...] = ()
    deliverables: tuple[str, ...] = ()
    failure_handoff: str | None = None
    depends_on: tuple[str, ...] = ()
    assigned_attempt_id: str | None = None
    result_summary: str | None = None
    evidence_ids: tuple[str, ...] = ()
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if not all((self.session_id.strip(), self.challenge_id.strip(), self.branch.strip(), self.role.strip(), self.objective.strip())):
            raise ValueError("contract task session, challenge, branch, role, and objective are required")
        object.__setattr__(self, "status", ContractTaskStatus(str(self.status).upper()))
        for name in ("success_criteria", "deliverables", "depends_on", "evidence_ids"):
            object.__setattr__(self, name, tuple(str(item) for item in getattr(self, name)))
        object.__setattr__(self, "created_at", ensure_utc(self.created_at))
        object.__setattr__(self, "updated_at", ensure_utc(self.updated_at))


@dataclass(frozen=True, slots=True)
class Event:
    team_id: str
    member: str
    contest: str
    type: str
    id: str = field(default_factory=lambda: f"event_{uuid4().hex}")
    timestamp: datetime = field(default_factory=utc_now)
    category: str | None = None
    challenge: str | None = None
    challenge_id: str | None = None
    challenge_key: str | None = None
    attempt_id: str | None = None
    message: str | None = None
    payload: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not all((self.id, self.team_id, self.member, self.contest, self.type)):
            raise ValueError("event id, team_id, member, contest, and type are required")
        object.__setattr__(self, "timestamp", ensure_utc(self.timestamp))
        object.__setattr__(self, "payload", dict(self.payload))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "timestamp": timestamp_text(self.timestamp),
            "team_id": self.team_id, "member": self.member, "contest": self.contest,
            "type": self.type, "category": self.category, "challenge": self.challenge,
            "challenge_id": self.challenge_id, "attempt_id": self.attempt_id,
            "challenge_key": self.challenge_key,
            "message": self.message, "payload": dict(self.payload),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Event":
        try:
            return cls(
                id=str(data["id"]), timestamp=str(data["timestamp"]),
                team_id=str(data["team_id"]), member=str(data["member"]),
                contest=str(data["contest"]), type=str(data["type"]),
                category=_optional_text(data.get("category")), challenge=_optional_text(data.get("challenge")),
                challenge_id=_optional_text(data.get("challenge_id")), attempt_id=_optional_text(data.get("attempt_id")),
                challenge_key=_optional_text(data.get("challenge_key")),
                message=_optional_text(data.get("message")),
                payload=data.get("payload") if isinstance(data.get("payload"), Mapping) else {},
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"invalid event record: {exc}") from exc


@dataclass(frozen=True, slots=True)
class FlagCandidate:
    challenge_id: str
    value: str
    challenge_key: str | None = None
    id: str = field(default_factory=lambda: f"flag_{uuid4().hex}")
    attempt_id: str | None = None
    source: str | None = None
    confidence: float | None = None
    verified: bool = False
    verification_status: str = "CANDIDATE"
    verification_reason: str | None = None
    synthetic: bool = False
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if not self.challenge_id or not self.value:
            raise ValueError("flag candidate challenge_id and value are required")
        if self.confidence is not None and not 0 <= self.confidence <= 1:
            raise ValueError("flag candidate confidence must be between zero and one")
        object.__setattr__(self, "created_at", ensure_utc(self.created_at))


def _optional_text(value: Any) -> str | None:
    return str(value) if value is not None else None
