"""Append-only, deduplicated lifecycle actions for Sol to apply."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .workspace import append_jsonl_fsync, read_jsonl_strict, resolve_active_run, state_lock, utc_now


CONTROL_ACTION_SCHEMA_VERSION = 1
ACTION_STATUSES = frozenset({"PENDING", "ACKED_APPLIED", "ACKED_DECLINED", "SUPERSEDED", "EXPIRED"})
ACTION_TYPES = frozenset({
    "CONTINUE_WITH_EVIDENCE", "SOL_TAKEOVER", "REPLACE_ATTACK_FAMILY", "STOP_REQUIRED",
    "LONG_COMPUTE_REVIEW", "REMOTE_ATTEMPT_REQUIRED", "OPERATOR_REVIEW",
    "RETARGET_TO_POC", "STOP_LOW_VALUE_BRANCH", "REVIEW_CANDIDATE_DEPENDENCY",
})


class ControlActionError(ValueError):
    pass


def create_control_action(
    root: Path, *, session_id: str, action_type: str, reason: str,
    triggering_evidence_id: str, evidence_generation: int,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    run = resolve_active_run(root)
    action = action_type.strip().upper()
    if action not in ACTION_TYPES:
        raise ControlActionError(f"action_type must be one of {sorted(ACTION_TYPES)}")
    if not isinstance(evidence_generation, int) or evidence_generation < 0:
        raise ControlActionError("evidence_generation must be a non-negative integer")
    with state_lock(run):
        state = _state(run)
        if state.get("sealed") and action != "STOP_REQUIRED":
            raise ControlActionError("sealed run accepts only terminal STOP_REQUIRED actions")
        if state.get("remote_flag_receipt") and action not in {
            "STOP_REQUIRED", "STOP_LOW_VALUE_BRANCH", "REVIEW_CANDIDATE_DEPENDENCY",
        }:
            raise ControlActionError(
                "verified remote flag run accepts only convergence stop actions"
            )
        run_id = str(state.get("run_id") or run.name)
        key = {
            "run_id": run_id, "session_id": _text(session_id, "session_id", 128),
            "action_type": action, "evidence_generation": evidence_generation,
        }
        action_id = hashlib.sha256(
            json.dumps(key, sort_keys=True, separators=(",", ":")).encode(),
        ).hexdigest()[:24]
        rows = load_control_actions(run)
        duplicate = next((
            row for row in rows
            if all(row.get(field) == value for field, value in key.items())
        ), None)
        if duplicate:
            return {**duplicate, "idempotent": True}
        record = {
            "schema_version": CONTROL_ACTION_SCHEMA_VERSION, "action_id": action_id,
            **key, "status": "PENDING", "reason": _text(reason, "reason", 2000),
            "triggering_evidence_id": _text(triggering_evidence_id, "triggering_evidence_id", 256),
            "metadata": dict(metadata or {}), "created_at": utc_now(),
            "acknowledged_at": None, "applied_receipt": None,
        }
        append_jsonl_fsync(run / "control-actions.jsonl", record, label="control action ledger")
    return {**record, "idempotent": False}


def acknowledge_control_action(
    root: Path, *, action_id: str, status: str, applied_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    run = resolve_active_run(root)
    normalized = status.strip().upper()
    if normalized not in ACTION_STATUSES - {"PENDING"}:
        raise ControlActionError("control action acknowledgement status is invalid")
    with state_lock(run):
        rows = load_control_actions(run)
        current = _current(rows, action_id)
        if current is None:
            raise ControlActionError("control action does not exist")
        if current.get("status") != "PENDING":
            if current.get("status") == normalized:
                return {**current, "idempotent": True}
            raise ControlActionError("control action is already terminal")
        record = {
            **current, "ledger_event": "STATUS_CHANGED", "status": normalized,
            "acknowledged_at": utc_now(), "applied_receipt": dict(applied_receipt or {}) or None,
        }
        append_jsonl_fsync(run / "control-actions.jsonl", record, label="control action ledger")
    return {**record, "idempotent": False}


def load_control_actions(root: Path, *, current_view: bool = True) -> list[dict[str, Any]]:
    run = resolve_active_run(root)
    rows = read_jsonl_strict(run / "control-actions.jsonl", "control action ledger")
    if not current_view:
        return rows
    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row.get("schema_version") != CONTROL_ACTION_SCHEMA_VERSION or not row.get("action_id"):
            raise ControlActionError("control action ledger contains an unsupported row")
        latest[str(row["action_id"])] = row
    return sorted(latest.values(), key=lambda row: (str(row.get("created_at", "")), str(row.get("action_id", ""))))


def pending_control_actions(root: Path, *, session_id: str | None = None) -> list[dict[str, Any]]:
    rows = [row for row in load_control_actions(root) if row.get("status") == "PENDING"]
    if session_id is not None:
        rows = [row for row in rows if row.get("session_id") == session_id]
    return rows


def _current(rows: list[dict[str, Any]], action_id: str) -> dict[str, Any] | None:
    return next((row for row in reversed(rows) if row.get("action_id") == action_id), None)


def _state(run: Path) -> dict[str, Any]:
    try:
        state = json.loads((run / "STATE.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ControlActionError("run state is malformed") from exc
    if not isinstance(state, dict):
        raise ControlActionError("run state is not an object")
    return state


def _text(value: Any, field: str, maximum: int) -> str:
    text = str(value).strip()
    if not text or len(text) > maximum or any(char in text for char in "\0\r"):
        raise ControlActionError(f"{field} is invalid")
    return text
