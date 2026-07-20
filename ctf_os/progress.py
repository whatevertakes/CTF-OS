"""Command-only drift gate, bounded long compute, and PoC-to-remote deadlines."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from .control import create_control_action
from .workspace import atomic_json, ensure_run_mutable, resolve_active_run, state_lock, utc_now


PROGRESS_SCHEMA_VERSION = 1
PROGRESS_TYPES = frozenset({
    "PRIMITIVE_CONFIRMED", "WORKING_POC", "REMOTE_ATTEMPT", "FLAG_CANDIDATE",
    "PRIMITIVE_REFUTED", "TYPED_BLOCKER", "LONG_COMPUTE",
})
REMOTE_SATISFACTION_TYPES = frozenset({
    "REMOTE_ATTEMPT", "REMOTE_FLAG_OBTAINED", "TARGET_DOWN", "AUTH_BLOCKED",
    "RATE_LIMITED", "ENDPOINT_CHANGED", "PROTOCOL_MISMATCH", "LOCAL_ONLY_CHALLENGE",
})


class ProgressGateError(ValueError):
    pass


def load_solve_policy(path: Path | None = None) -> dict[str, Any]:
    selected = path or Path(__file__).parent / "resources" / "solve-policy.yaml"
    if selected.is_symlink() or not selected.is_file():
        raise ProgressGateError("solve policy is missing or unsafe")
    try:
        payload = yaml.safe_load(selected.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ProgressGateError("solve policy is malformed") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ProgressGateError("solve policy schema is unsupported")
    return payload


def record_command(
    root: Path, *, session_id: str, command_argv: Sequence[str], category: str,
    observed_at: str | None = None,
) -> dict[str, Any]:
    run = ensure_run_mutable(root)
    argv = _argv(command_argv)
    now = _parse_time(observed_at or utc_now())
    with state_lock(run):
        state = _load_state(run)
        session = _session(state, session_id, now)
        session["commands_without_progress"] = int(session.get("commands_without_progress", 0)) + 1
        session["last_command_at"] = _format_time(now)
        session["last_command_digest"] = hashlib.sha256(
            json.dumps(argv, separators=(",", ":")).encode(),
        ).hexdigest()
        atomic_json(run / "progress-state.json", state)
    gate = evaluate_progress_gate(run, session_id=session_id, category=category, now=_format_time(now))
    return {"session_id": session_id, "command": argv, "gate": gate}


def register_milestone(
    root: Path, receipt: Mapping[str, Any], *, declared_remote: bool,
) -> dict[str, Any]:
    run = ensure_run_mutable(root)
    event_type = str(receipt.get("event_type", "")).upper()
    session_id = str(receipt.get("session_id", ""))
    created = _parse_time(str(receipt.get("created_at") or utc_now()))
    progress = event_type in PROGRESS_TYPES
    # A decisive experiment resets drift only when it actually kills a family.
    if event_type == "DECISIVE_EXPERIMENT":
        details = receipt.get("details") if isinstance(receipt.get("details"), Mapping) else {}
        progress = str(details.get("decision", "")).upper() in {"KILL", "REFUTED"}
    with state_lock(run):
        state = _load_state(run)
        session = _session(state, session_id, created)
        if progress:
            session["commands_without_progress"] = 0
            session["last_progress_at"] = _format_time(created)
            session["last_progress_receipt_id"] = receipt.get("receipt_id")
            session["evidence_generation"] = int(session.get("evidence_generation", 0)) + 1
        if event_type == "LONG_COMPUTE":
            details = dict(receipt.get("details") or {})
            session["long_compute"] = {
                "receipt_id": receipt.get("receipt_id"), "started_at": _format_time(created),
                "last_heartbeat_at": _format_time(created), "details": details,
                "status": "ACTIVE",
            }
        elif event_type in {"WORKING_POC", "REMOTE_ATTEMPT", "FLAG_CANDIDATE", "TYPED_BLOCKER"}:
            if isinstance(session.get("long_compute"), dict):
                session["long_compute"]["status"] = "COMPLETED"
        remote = state.setdefault("remote_transition", {})
        if event_type == "WORKING_POC" and declared_remote:
            policy = load_solve_policy()["remote_transition"]
            remote[session_id] = {
                "working_poc_receipt_id": receipt.get("receipt_id"),
                "created_at": _format_time(created),
                "soft_deadline_at": _format_time(created.timestamp() + int(policy["soft_deadline_seconds"])),
                "hard_deadline_at": _format_time(created.timestamp() + int(policy["hard_deadline_seconds"])),
                "status": "PENDING", "satisfied_by": None,
            }
        satisfaction_type = event_type
        if event_type == "TYPED_BLOCKER":
            details = receipt.get("details") if isinstance(receipt.get("details"), Mapping) else {}
            satisfaction_type = str(details.get("blocker_type") or "").upper()
        if satisfaction_type in REMOTE_SATISFACTION_TYPES:
            deadline = remote.get(session_id)
            if isinstance(deadline, dict) and deadline.get("status") == "PENDING":
                deadline["status"] = "SATISFIED"
                deadline["satisfied_by"] = receipt.get("receipt_id")
                deadline["satisfaction_type"] = satisfaction_type
        atomic_json(run / "progress-state.json", state)
    return {
        "counts_as_progress": progress,
        "evidence_generation": int(session.get("evidence_generation", 0)),
        "remote_transition": state.get("remote_transition", {}).get(session_id),
    }


def heartbeat_long_compute(
    root: Path, *, session_id: str, receipt_id: str,
    artifact_changed: bool, completion_signal_observed: bool = False,
    observed_at: str | None = None,
) -> dict[str, Any]:
    run = ensure_run_mutable(root)
    now = _parse_time(observed_at or utc_now())
    with state_lock(run):
        state = _load_state(run)
        session = _session(state, session_id, now)
        compute = session.get("long_compute")
        if not isinstance(compute, dict) or compute.get("receipt_id") != receipt_id:
            raise ProgressGateError("LONG_COMPUTE receipt is not active for this run and session")
        if compute.get("status") != "ACTIVE":
            return {**compute, "idempotent": True}
        compute["last_heartbeat_at"] = _format_time(now)
        compute["artifact_changed"] = bool(artifact_changed)
        if completion_signal_observed:
            compute["status"] = "COMPLETED"
        atomic_json(run / "progress-state.json", state)
    return {**compute, "idempotent": False}


def evaluate_progress_gate(
    root: Path, *, session_id: str, category: str, now: str | None = None,
) -> dict[str, Any]:
    run = resolve_active_run(root)
    current = _parse_time(now or utc_now())
    state = _load_state(run)
    session = _session(state, session_id, current)
    policy = _progress_policy(category)
    commands = int(session.get("commands_without_progress", 0))
    last = _parse_time(str(session.get("last_progress_at") or session.get("started_at")))
    elapsed = max(0.0, (current - last).total_seconds())
    compute = session.get("long_compute")
    if isinstance(compute, Mapping) and compute.get("status") == "ACTIVE":
        validity = _long_compute_valid(compute, current)
        if validity["valid"]:
            return {"triggered": False, "long_compute": validity, "commands_without_progress": commands, "seconds_without_progress": elapsed}
        action = create_control_action(
            run, session_id=session_id, action_type="LONG_COMPUTE_REVIEW",
            reason=str(validity["reason"]), triggering_evidence_id=str(compute.get("receipt_id")),
            evidence_generation=int(session.get("evidence_generation", 0)), metadata=validity,
        )
        return {"triggered": True, "action": action, "long_compute": validity}
    triggered = commands >= int(policy["max_commands_without_progress"]) or elapsed >= int(policy["max_seconds_without_progress"])
    if not triggered:
        return {"triggered": False, "commands_without_progress": commands, "seconds_without_progress": elapsed, "thresholds": policy}
    action_type = "CONTINUE_WITH_EVIDENCE"
    if session_id != "sol-main":
        action_type = "SOL_TAKEOVER"
    elif commands >= int(policy["max_commands_without_progress"]) * 2:
        action_type = "REPLACE_ATTACK_FAMILY"
    evidence_id = str(session.get("last_command_digest") or f"plateau:{session_id}")
    action = create_control_action(
        run, session_id=session_id, action_type=action_type,
        reason=f"{commands} commands and {int(elapsed)} seconds without typed exploit progress",
        triggering_evidence_id=evidence_id,
        evidence_generation=int(session.get("evidence_generation", 0)),
        metadata={"commands_without_progress": commands, "seconds_without_progress": elapsed, "thresholds": policy},
    )
    return {"triggered": True, "action": action, "commands_without_progress": commands, "seconds_without_progress": elapsed}


def evaluate_remote_transition(
    root: Path, *, session_id: str, now: str | None = None,
) -> dict[str, Any]:
    run = resolve_active_run(root)
    current = _parse_time(now or utc_now())
    state = _load_state(run)
    deadline = state.get("remote_transition", {}).get(session_id)
    if not isinstance(deadline, Mapping) or deadline.get("status") != "PENDING":
        return {"triggered": False, "deadline": deadline}
    hard = _parse_time(str(deadline["hard_deadline_at"]))
    soft = _parse_time(str(deadline["soft_deadline_at"]))
    session = _session(state, session_id, current)
    if current >= hard:
        action_type = "OPERATOR_REVIEW"
        reason = "WORKING_POC hard remote deadline expired; record a typed blocker or attempt the declared remote"
    elif current >= soft:
        action_type = "REMOTE_ATTEMPT_REQUIRED" if session_id == "sol-main" else "SOL_TAKEOVER"
        reason = "WORKING_POC soft remote deadline expired without a remote attempt or typed blocker"
    else:
        return {"triggered": False, "deadline": dict(deadline)}
    action = create_control_action(
        run, session_id=session_id, action_type=action_type, reason=reason,
        triggering_evidence_id=str(deadline["working_poc_receipt_id"]),
        evidence_generation=int(session.get("evidence_generation", 0)),
        metadata={"deadline": dict(deadline)},
    )
    return {"triggered": True, "action": action, "deadline": dict(deadline)}


def _load_state(run: Path) -> dict[str, Any]:
    path = run / "progress-state.json"
    if not path.exists():
        return {"schema_version": PROGRESS_SCHEMA_VERSION, "sessions": {}, "remote_transition": {}}
    if path.is_symlink() or not path.is_file():
        raise ProgressGateError("progress state is missing or unsafe")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProgressGateError("progress state is malformed") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != PROGRESS_SCHEMA_VERSION:
        raise ProgressGateError("progress state schema is unsupported")
    return payload


def _session(state: dict[str, Any], session_id: str, now: datetime) -> dict[str, Any]:
    sessions = state.setdefault("sessions", {})
    session = sessions.setdefault(session_id, {
        "started_at": _format_time(now), "last_progress_at": _format_time(now),
        "last_command_at": None, "last_command_digest": None,
        "commands_without_progress": 0, "evidence_generation": 0,
        "last_progress_receipt_id": None, "long_compute": None,
    })
    return session


def _progress_policy(category: str) -> dict[str, int]:
    gate = load_solve_policy()["progress_gate"]
    result = {
        "max_commands_without_progress": int(gate["max_commands_without_progress"]),
        "max_seconds_without_progress": int(gate["max_seconds_without_progress"]),
    }
    override = gate.get("category_overrides", {}).get(category)
    if isinstance(override, Mapping):
        result.update({key: int(value) for key, value in override.items() if key in result})
    return result


def _long_compute_valid(compute: Mapping[str, Any], now: datetime) -> dict[str, Any]:
    details = compute.get("details") if isinstance(compute.get("details"), Mapping) else {}
    started = _parse_time(str(compute.get("started_at")))
    heartbeat = _parse_time(str(compute.get("last_heartbeat_at")))
    maximum = int(details.get("maximum_duration_seconds", 0) or 0)
    interval = int(details.get("checkpoint_interval_seconds", 0) or 0)
    expires = started + timedelta(seconds=maximum)
    if maximum < 1 or now > expires:
        return {"valid": False, "reason": "LONG_COMPUTE maximum duration expired"}
    if interval < 1 or (now - heartbeat).total_seconds() > interval:
        return {"valid": False, "reason": "LONG_COMPUTE heartbeat or artifact checkpoint is stale"}
    return {"valid": True, "reason": "bounded LONG_COMPUTE receipt remains live", "expires_at": _format_time(expires)}


def _argv(values: Sequence[str]) -> list[str]:
    if isinstance(values, (str, bytes)) or not values or len(values) > 256:
        raise ProgressGateError("command_argv must be a non-empty direct argv array")
    forbidden = {";", "&&", "||", "|", ">", ">>", "<", "&"}
    result = [str(value) for value in values]
    if any(not value or value in forbidden or any(char in value for char in "\0\r\n") for value in result):
        raise ProgressGateError("command_argv contains a shell operator or invalid value")
    return result


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProgressGateError("timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ProgressGateError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _format_time(value: datetime | float) -> str:
    if isinstance(value, (int, float)):
        value = datetime.fromtimestamp(float(value), tz=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
