"""Append-only, challenge-local race event and operator-hint storage."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .delegation import utc_now
from .workspace import atomic_json, state_lock


EVENT_TYPES = frozenset({
    "SUPPORTED_FACT", "REJECTED_HYPOTHESIS", "EXPLOIT_PRIMITIVE", "BLOCKER",
    "ARTIFACT_READY", "WORKING_POC", "NEXT_EXPERIMENT", "FLAG_CANDIDATE", "REMOTE_FLAG_OBTAINED",
    "SERVICE_CRASHED", "ENVIRONMENT_DISCOVERY", "NEED_HELP", "OPERATOR_HINT",
})
PRIORITIES = frozenset({"LOW", "NORMAL", "HIGH", "CRITICAL"})
HIGH_TYPES = frozenset({"FLAG_CANDIDATE", "WORKING_POC", "EXPLOIT_PRIMITIVE"})
CRITICAL_TYPES = frozenset({"REMOTE_FLAG_OBTAINED"})
TERMINAL_BRANCH_STATES = frozenset({"SUPPORTED", "REFUTED", "PARTIAL", "INCONCLUSIVE", "TERMINATED", "ERROR", "STALE"})


class RaceEventError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RaceEvent:
    event_id: str
    session_id: str
    priority: str
    type: str
    summary: str
    evidence: tuple[str, ...]
    artifacts: tuple[str, ...]
    useful_for: tuple[str, ...]
    recommended_action: str
    created_at: str
    input_fingerprint: str
    challenge_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id, "session_id": self.session_id,
            "priority": self.priority, "type": self.type, "summary": self.summary,
            "evidence": list(self.evidence), "artifacts": list(self.artifacts),
            "useful_for": list(self.useful_for), "recommended_action": self.recommended_action,
            "created_at": self.created_at, "input_fingerprint": self.input_fingerprint,
            "challenge_id": self.challenge_id,
        }


def publish_event(
    root: Path, *, challenge_id: str, input_fingerprint: str, session_id: str,
    event_type: str, summary: str, priority: str = "NORMAL",
    evidence: Sequence[str] = (), artifacts: Sequence[str] = (),
    useful_for: Sequence[str] = (), recommended_action: str = "",
    event_id: str | None = None,
) -> dict[str, Any]:
    normalized_type = event_type.strip().upper()
    if normalized_type not in EVENT_TYPES:
        raise RaceEventError(f"event type must be one of {sorted(EVENT_TYPES)}")
    normalized_priority = priority.strip().upper()
    if normalized_priority not in PRIORITIES:
        raise RaceEventError(f"priority must be one of {sorted(PRIORITIES)}")
    if normalized_type in CRITICAL_TYPES:
        normalized_priority = "CRITICAL"
    elif normalized_type in HIGH_TYPES and normalized_priority in {"LOW", "NORMAL"}:
        normalized_priority = "HIGH"
    created = utc_now()
    material = {
        "session_id": _short(session_id, "session_id", 128),
        "type": normalized_type, "summary": _short(summary, "summary", 4000),
        "evidence": _list(evidence, "evidence"), "artifacts": _relative_list(artifacts, "artifacts"),
        "useful_for": _list(useful_for, "useful_for"),
        "recommended_action": recommended_action.strip()[:2000],
        "input_fingerprint": _short(input_fingerprint, "input_fingerprint", 256),
        "challenge_id": _short(challenge_id, "challenge_id", 256),
    }
    identifier = event_id or hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:24]
    event = RaceEvent(
        event_id=_short(identifier, "event_id", 128), priority=normalized_priority,
        created_at=created, **material,
    )
    path = root / "race-events.jsonl"
    with state_lock(root):
        existing = {row.get("event_id"): row for row in _read_jsonl(path)}
        if event.event_id in existing:
            if _without_time(existing[event.event_id]) != _without_time(event.to_dict()):
                raise RaceEventError("event_id already exists with conflicting content")
            return {**existing[event.event_id], "idempotent": True}
        _append_jsonl(path, event.to_dict())
    result = {**event.to_dict(), "idempotent": False}
    # Resource scheduling is event-driven, but remains advisory: this records a
    # rebalance request and priority signal without touching native sessions.
    from .resources.scheduler import note_race_event
    note_race_event(root, result)
    return result


def show_events(
    root: Path, *, input_fingerprint: str, since: str | None = None,
    priorities: Sequence[str] = (), event_types: Sequence[str] = (),
) -> list[dict[str, Any]]:
    rows = [row for row in _read_jsonl(root / "race-events.jsonl") if row.get("input_fingerprint") == input_fingerprint]
    wanted_priorities = {value.upper() for value in priorities}
    wanted_types = {value.upper() for value in event_types}
    if since:
        rows = [row for row in rows if str(row.get("created_at", "")) > since]
    if wanted_priorities:
        rows = [row for row in rows if row.get("priority") in wanted_priorities]
    if wanted_types:
        rows = [row for row in rows if row.get("type") in wanted_types]
    return sorted(rows, key=lambda row: (str(row.get("created_at", "")), str(row.get("event_id", ""))))


def acknowledge_event(root: Path, *, event_id: str, session_id: str, input_fingerprint: str) -> dict[str, Any]:
    matches = [row for row in show_events(root, input_fingerprint=input_fingerprint) if row.get("event_id") == event_id]
    if len(matches) != 1:
        raise RaceEventError("event does not exist in the active challenge fingerprint")
    path = root / "race-event-acks.json"
    with state_lock(root):
        payload = _read_json(path, {"schema_version": 1, "acks": []})
        key = (event_id, session_id)
        existing = {(row.get("event_id"), row.get("session_id")) for row in payload["acks"]}
        if key not in existing:
            payload["acks"].append({"event_id": event_id, "session_id": session_id, "acknowledged_at": utc_now()})
            payload["acks"].sort(key=lambda row: (row["event_id"], row["session_id"]))
            atomic_json(path, payload)
    return {"event_id": event_id, "session_id": session_id, "acknowledged": True}


def insight_packet(
    root: Path, *, input_fingerprint: str, target_session_id: str,
    plan: Mapping[str, Any] | None = None, limit: int = 20,
) -> dict[str, Any]:
    if not 1 <= limit <= 100:
        raise RaceEventError("insight packet limit must be from 1 through 100")
    events = show_events(root, input_fingerprint=input_fingerprint)
    acks = _read_json(root / "race-event-acks.json", {"acks": []})["acks"]
    acknowledged = {
        row.get("event_id") for row in acks if row.get("session_id") == target_session_id
    }
    relevant = []
    for event in events:
        if event.get("session_id") == target_session_id or event.get("event_id") in acknowledged:
            continue
        targets = event.get("useful_for") or []
        if targets and target_session_id not in targets and "all" not in targets and "*" not in targets:
            continue
        relevant.append(event)
    rank = {"CRITICAL": 0, "HIGH": 1, "NORMAL": 2, "LOW": 3}
    relevant.sort(key=lambda row: (rank.get(str(row.get("priority")), 9), str(row.get("created_at", ""))))
    branch = None
    if plan:
        branch = next((row for row in plan.get("branches", []) if row.get("session_id") == target_session_id), None)
    return {
        "schema_version": 1, "target_session_id": target_session_id,
        "challenge_id": branch.get("prompt_packet", {}).get("challenge_id") if isinstance(branch, Mapping) else None,
        "input_fingerprint": input_fingerprint, "events": relevant[:limit],
        "instruction": "Apply only insights that shorten the leading exploit path; run the next decisive experiment and publish a working PoC or flag before narrative summary.",
        "generated_at": utc_now(),
    }


def save_operator_hint(
    root: Path, *, challenge_id: str, input_fingerprint: str, summary: str,
    active_branches: Sequence[Mapping[str, Any]], targets: Sequence[str] = (),
    operator_id: str = "human-operator",
) -> dict[str, Any]:
    active = {
        str(row.get("session_id")) for row in active_branches
        if row.get("session_id") and row.get("status") not in TERMINAL_BRANCH_STATES
    }
    requested = set(targets)
    recipients = sorted(active if not requested else active & requested)
    event = publish_event(
        root, challenge_id=challenge_id, input_fingerprint=input_fingerprint,
        session_id=operator_id, event_type="OPERATOR_HINT", priority="HIGH",
        summary=summary, useful_for=recipients,
        recommended_action="Sol should forward this hint to the listed active branches immediately.",
    )
    return {"hint": event, "recipients": recipients, "ignored_inactive_targets": sorted(requested - active)}


def operator_hints(root: Path, *, input_fingerprint: str) -> list[dict[str, Any]]:
    return show_events(root, input_fingerprint=input_fingerprint, event_types=["OPERATOR_HINT"])


def _append_jsonl(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise RaceEventError("event ledger must not be a symlink")
    descriptor = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(dict(payload), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file():
        raise RaceEventError("event ledger is missing or unsafe")
    rows = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RaceEventError(f"event ledger line {line_number} is malformed") from exc
        if not isinstance(row, dict):
            raise RaceEventError(f"event ledger line {line_number} is not an object")
        rows.append(row)
    return rows


def _read_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return default
    if path.is_symlink() or not path.is_file():
        raise RaceEventError("race event state is missing or unsafe")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RaceEventError("race event state is malformed") from exc
    if not isinstance(raw, dict):
        raise RaceEventError("race event state is not an object")
    return raw


def _without_time(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key not in {"created_at", "idempotent"}}


def _short(value: str, field: str, limit: int) -> str:
    text = str(value).strip()
    if not text or len(text) > limit or any(char in text for char in "\0\r"):
        raise RaceEventError(f"{field} must be a non-empty string of at most {limit} characters")
    return text


def _list(values: Sequence[str], field: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or len(values) > 64:
        raise RaceEventError(f"{field} must be an array of at most 64 strings")
    return tuple(_short(str(value), field, 1000) for value in values)


def _relative_list(values: Sequence[str], field: str) -> tuple[str, ...]:
    rows = _list(values, field)
    for value in rows:
        path = Path(value)
        if path.is_absolute() or ".." in path.parts:
            raise RaceEventError(f"{field} contains an unsafe relative path")
    return rows
