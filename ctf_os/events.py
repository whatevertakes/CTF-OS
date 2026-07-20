"""Append-only, challenge-local race event and operator-hint storage."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

from .delegation import utc_now
from .primitives import validate_primitive
from .workspace import (
    append_jsonl_fsync, atomic_json, ensure_run_mutable, read_jsonl_strict,
    resolve_active_run, state_lock,
)


EVENT_TYPES = frozenset({
    "SUPPORTED_FACT", "REJECTED_HYPOTHESIS", "EXPLOIT_PRIMITIVE", "BLOCKER",
    "EXPLOIT_PRIMITIVE_CANDIDATE", "EXPLOIT_PRIMITIVE_CONFIRMED", "EXPLOIT_PRIMITIVE_REFUTED",
    "ARTIFACT_READY", "WORKING_POC", "NEXT_EXPERIMENT", "FLAG_CANDIDATE", "REMOTE_FLAG_OBTAINED",
    "SUBMISSION_RECOMMENDED", "ACCEPTED",
    "SERVICE_CRASHED", "ENVIRONMENT_DISCOVERY", "NEED_HELP", "OPERATOR_HINT",
})
PRIORITIES = frozenset({"LOW", "NORMAL", "HIGH", "CRITICAL"})
HIGH_TYPES = frozenset({"FLAG_CANDIDATE", "WORKING_POC", "EXPLOIT_PRIMITIVE_CONFIRMED"})
CRITICAL_TYPES = frozenset({"REMOTE_FLAG_OBTAINED", "SUBMISSION_RECOMMENDED", "ACCEPTED"})
PROTECTED_TYPES = CRITICAL_TYPES
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
    primitive: dict[str, Any]
    receipt_reference: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id, "session_id": self.session_id,
            "priority": self.priority, "type": self.type, "summary": self.summary,
            "evidence": list(self.evidence), "artifacts": list(self.artifacts),
            "useful_for": list(self.useful_for), "recommended_action": self.recommended_action,
            "created_at": self.created_at, "input_fingerprint": self.input_fingerprint,
            "challenge_id": self.challenge_id,
            "primitive": self.primitive,
            "receipt_reference": self.receipt_reference,
        }


def publish_event(
    root: Path, *, challenge_id: str, input_fingerprint: str, session_id: str,
    event_type: str, summary: str, priority: str = "NORMAL",
    evidence: Sequence[str] = (), artifacts: Sequence[str] = (),
    useful_for: Sequence[str] = (), recommended_action: str = "",
    event_id: str | None = None,
    primitive: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return _publish_event(
        root, challenge_id=challenge_id, input_fingerprint=input_fingerprint,
        session_id=session_id, event_type=event_type, summary=summary,
        priority=priority, evidence=evidence, artifacts=artifacts,
        useful_for=useful_for, recommended_action=recommended_action,
        event_id=event_id, primitive=primitive, receipt_reference=None,
    )


def publish_verified_event(
    root: Path, *, receipt: Mapping[str, Any], event_type: str, summary: str,
) -> dict[str, Any]:
    """Publish a protected event only from a stored, run-bound receipt."""

    normalized = event_type.strip().upper()
    if normalized not in {"REMOTE_FLAG_OBTAINED", "SUBMISSION_RECOMMENDED", "FLAG_CANDIDATE"}:
        raise RaceEventError("verified receipt publisher supports only remote flag lifecycle events")
    required = {
        "receipt_id", "run_id", "challenge_id", "input_fingerprint", "target_revision",
        "branch_id", "candidate_id", "candidate", "network_observed",
    }
    if required.difference(receipt) or receipt.get("network_observed") is not True:
        raise RaceEventError("verified remote event requires a complete receipt")
    root = resolve_active_run(
        root, input_fingerprint=str(receipt["input_fingerprint"]),
        target_revision=int(receipt["target_revision"]),
    )
    try:
        run_state = json.loads((root / "STATE.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RaceEventError("verified remote event run state is malformed") from exc
    expected_relative = f"flag-receipts/remote-{receipt['receipt_id']}.json"
    state_receipt_field = (
        "remote_candidate_receipt" if normalized == "FLAG_CANDIDATE" else "remote_flag_receipt"
    )
    if (
        run_state.get("run_id") != receipt.get("run_id")
        or run_state.get("challenge_id") != receipt.get("challenge_id")
        or run_state.get(state_receipt_field) != expected_relative
    ):
        raise RaceEventError("verified remote receipt does not match the current run state")
    receipt_path = root / "flag-receipts" / f"remote-{receipt['receipt_id']}.json"
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise RaceEventError("verified remote receipt is not stored in this run")
    try:
        saved = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RaceEventError("verified remote receipt is malformed") from exc
    if saved != dict(receipt):
        raise RaceEventError("verified remote receipt content does not match stored receipt")
    reference = {
        "receipt_id": receipt["receipt_id"], "candidate_id": receipt["candidate_id"],
        "target_revision": receipt["target_revision"],
        "path": str(receipt_path.relative_to(root)),
    }
    return _publish_event(
        root, challenge_id=str(receipt["challenge_id"]),
        input_fingerprint=str(receipt["input_fingerprint"]),
        session_id=str(receipt["branch_id"]), event_type=normalized,
        summary=summary, priority="CRITICAL" if normalized != "FLAG_CANDIDATE" else "HIGH",
        evidence=[str(receipt_path.relative_to(root))], artifacts=[str(receipt["exploit_artifact"])],
        useful_for=(), recommended_action="Human submission only after this verified receipt",
        event_id=f"verified-{receipt['receipt_id']}-{normalized.lower()}",
        primitive=None, receipt_reference=reference,
    )


def _publish_event(
    root: Path, *, challenge_id: str, input_fingerprint: str, session_id: str,
    event_type: str, summary: str, priority: str,
    evidence: Sequence[str], artifacts: Sequence[str], useful_for: Sequence[str],
    recommended_action: str, event_id: str | None,
    primitive: Mapping[str, Any] | None,
    receipt_reference: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if receipt_reference:
        root = resolve_active_run(root, input_fingerprint=input_fingerprint)
    else:
        root = ensure_run_mutable(root)
    normalized_type = event_type.strip().upper()
    if normalized_type not in EVENT_TYPES:
        raise RaceEventError(f"event type must be one of {sorted(EVENT_TYPES)}")
    if normalized_type in PROTECTED_TYPES and receipt_reference is None:
        raise RaceEventError(f"{normalized_type} may be published only by a verified receipt path")
    normalized_priority = priority.strip().upper()
    if normalized_priority not in PRIORITIES:
        raise RaceEventError(f"priority must be one of {sorted(PRIORITIES)}")
    if normalized_type in CRITICAL_TYPES:
        normalized_priority = "CRITICAL"
    elif normalized_type in HIGH_TYPES and normalized_priority in {"LOW", "NORMAL"}:
        normalized_priority = "HIGH"
    created = utc_now()
    primitive_record = validate_primitive(normalized_type, primitive, legacy_ok=True)
    material = {
        "session_id": _short(session_id, "session_id", 128),
        "type": normalized_type, "summary": _short(summary, "summary", 4000),
        "evidence": _list(evidence, "evidence"), "artifacts": _relative_list(artifacts, "artifacts"),
        "useful_for": _list(useful_for, "useful_for"),
        "recommended_action": recommended_action.strip()[:2000],
        "input_fingerprint": _short(input_fingerprint, "input_fingerprint", 256),
        "challenge_id": _short(challenge_id, "challenge_id", 256),
        "primitive": primitive_record,
        "receipt_reference": dict(receipt_reference or {}),
    }
    identifier = event_id or hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:24]
    event = RaceEvent(
        event_id=_short(identifier, "event_id", 128), priority=normalized_priority,
        created_at=created, **material,
    )
    path = root / "race-events.jsonl"
    idempotent = False
    with state_lock(root):
        existing = {row.get("event_id"): row for row in _read_jsonl(path)}
        if event.event_id in existing:
            if _without_time(existing[event.event_id]) != _without_time(event.to_dict()):
                raise RaceEventError("event_id already exists with conflicting content")
            event_record = existing[event.event_id]
            idempotent = True
        else:
            event_record = event.to_dict()
            _append_jsonl(path, event_record)
    result = {**event_record, "idempotent": idempotent}
    # Resource scheduling is event-driven, but remains advisory: this records a
    # rebalance request and priority signal without touching native sessions.
    from .resources.scheduler import note_race_event
    post_commit_warnings: list[str] = []
    try:
        note_race_event(root, result)
    except Exception as exc:
        post_commit_warnings.append(f"scheduler event projection failed: {exc}")
        append_jsonl_fsync(root / "scheduler-errors.jsonl", {
            "event": "RACE_EVENT_SCHEDULER_UPDATE_FAILED",
            "event_id": event.event_id, "error": str(exc), "created_at": utc_now(),
        }, label="scheduler error ledger")
    from .transitions import evaluate_race_transition
    result["race_transition"] = evaluate_race_transition(
        root, result, session_id, input_fingerprint,
    )
    result["post_commit_warnings"] = post_commit_warnings
    return result


def show_events(
    root: Path, *, input_fingerprint: str, since: str | None = None,
    priorities: Sequence[str] = (), event_types: Sequence[str] = (),
) -> list[dict[str, Any]]:
    root = resolve_active_run(root, input_fingerprint=input_fingerprint)
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
    root = resolve_active_run(root, input_fingerprint=input_fingerprint)
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
    root = resolve_active_run(root, input_fingerprint=input_fingerprint)
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
    try:
        append_jsonl_fsync(path, payload, label="race event ledger")
    except ValueError as exc:
        raise RaceEventError(str(exc)) from exc


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        return read_jsonl_strict(path, "race event ledger")
    except ValueError as exc:
        raise RaceEventError(str(exc)) from exc


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
