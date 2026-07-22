"""Minimal first-to-flag swarm state for one isolated challenge attempt.

Python prepares native delegation packets and records what happened.  It never
starts or stops a model, approves an exploit, executes a remote payload, or
submits a flag.  Native child lifecycle remains owned by the user-opened Sol
session.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from typing import Any

from .flags import matches_flag
from .workspace import append_jsonl_fsync, atomic_json, atomic_text, state_lock, utc_now


SWARM_SCHEMA_VERSION = 1
ATTACK_EVENT_SCHEMA_VERSION = 1
DEFAULT_BUDGET_SECONDS = 90 * 60
PLATEAU_SECONDS = 30 * 60
ENDGAME_SECONDS = 60 * 60
MAX_NATIVE_CONCURRENCY = 4
INITIAL_LANES = (
    ("independent", "independent"),
    ("exploit-first", "exploit-first"),
    ("tool-driven", "tool-driven"),
)
EVENT_TYPES = frozenset({
    "SPAWNED", "COMMAND_EXECUTED", "ATTACK_PATH_FOUND", "EXPLOIT_ATTEMPTED",
    "PRIMITIVE", "POC", "WORKING_POC", "REMOTE_ATTEMPT", "REMOTE_RESULT",
    "USEFUL_FAILURE", "BLOCKER", "FLAG_FOUND", "STOPPED",
})
HIGH_VALUE_EVENTS = frozenset({
    "PRIMITIVE", "POC", "WORKING_POC", "REMOTE_RESULT", "FLAG_FOUND",
    "BLOCKER", "USEFUL_FAILURE",
})
SHAREABLE_EVENTS = frozenset({
    "PRIMITIVE", "WORKING_POC", "REMOTE_RESULT", "FLAG_FOUND", "BLOCKER",
    "USEFUL_FAILURE",
})


class SwarmError(ValueError):
    pass


def initialize_swarm(
    run: Path,
    *,
    challenge: Any,
    record: Mapping[str, object],
    root_session: str = "sol-main",
    now: datetime | None = None,
) -> dict[str, Any]:
    """Create the one live engine and its three immediate native spawn packets."""

    run = _run_root(run)
    state = _read_object(run / "STATE.json", "run state")
    existing = run / "SWARM.json"
    if existing.is_file() and not existing.is_symlink():
        swarm = _read_object(existing, "swarm state")
        _assert_identity(swarm, state)
        return _public_swarm(swarm)

    started = _as_utc(now)
    deadline = started + timedelta(seconds=DEFAULT_BUDGET_SECONDS)
    input_path = Path(str(record.get("prepared_input") or "")).resolve(strict=False)
    if not input_path.is_dir() or input_path.is_symlink():
        raise SwarmError("prepared challenge input is missing or unsafe")
    artifacts = run / "artifacts"
    artifacts.mkdir(exist_ok=True)
    terminal = bool(
        state.get("sealed")
        or state.get("submission_recommended")
        or state.get("status") in {"ACCEPTED", "SEALED", "SEALED_CLEAN", "SUBMISSION_RECOMMENDED"}
    )
    problem = _problem_context(challenge, record)
    if terminal:
        swarm = {
            "schema_version": SWARM_SCHEMA_VERSION,
            "run_id": state.get("run_id") or run.name,
            "challenge_id": state.get("challenge_id"),
            "attempt_id": state.get("attempt_id"),
            "challenge_instance_id": state.get("challenge_instance_id"),
            "input_fingerprint": state.get("input_fingerprint"),
            "started_at": _timestamp(started), "deadline": _timestamp(deadline),
            "budget_seconds": DEFAULT_BUDGET_SECONDS, "root_session": root_session,
            "root_lane": {"id": "root", "role": "lead-attacker", "native_session": root_session,
                          "status": "STOPPED", "must_continue_after_spawn": False},
            "challenge_context": problem, "maximum_native_concurrency": MAX_NATIVE_CONCURRENCY,
            "lanes": [], "spawn_queue": [],
            "winner": ({"lane": "legacy", "native_session": None,
                        "candidate": state.get("flag_candidate"), "receipt": state.get("remote_flag_receipt"),
                        "found_at": state.get("updated_at") or _timestamp(started), "source": "preserved run state"}
                       if state.get("flag_candidate") else None),
            "status": "ACCEPTED" if state.get("sealed") else "FLAG_FOUND",
            "generation": 1, "replacement_count": 0, "automatic_extension": False,
            "manual_submission_only": True, "updated_at": _timestamp(started),
        }
        atomic_json(existing, swarm)
        return _public_swarm(swarm)
    lanes: list[dict[str, Any]] = []
    queue: list[dict[str, Any]] = []
    for lane_id, role in INITIAL_LANES:
        lane_root = run / "workers" / lane_id
        for directory in (lane_root / "work", lane_root / "evidence", lane_root / "artifacts"):
            directory.mkdir(parents=True, exist_ok=True)
        packet = _spawn_packet(
            run=run, challenge=challenge, record=record, lane_id=lane_id, role=role,
            root_session=root_session, deadline=_timestamp(deadline),
        )
        lanes.append({
            "id": lane_id, "role": role, "native_session": None,
            "status": "PENDING_SPAWN", "spawn_attempts": 0,
            "last_high_value_event": None, "sandbox": packet["sandbox"],
        })
        queue.append(packet)
    swarm = {
        "schema_version": SWARM_SCHEMA_VERSION,
        "run_id": state.get("run_id") or run.name,
        "challenge_id": state.get("challenge_id"),
        "attempt_id": state.get("attempt_id"),
        "challenge_instance_id": state.get("challenge_instance_id"),
        "input_fingerprint": state.get("input_fingerprint"),
        "started_at": _timestamp(started), "deadline": _timestamp(deadline),
        "budget_seconds": DEFAULT_BUDGET_SECONDS,
        "root_session": root_session, "challenge_context": problem,
        "root_lane": {
            "id": "root", "role": "lead-attacker", "native_session": root_session,
            "status": "RUNNING", "must_continue_after_spawn": True,
        },
        "maximum_native_concurrency": MAX_NATIVE_CONCURRENCY,
        "lanes": lanes, "spawn_queue": queue, "winner": None,
        "status": "SPAWN_REQUIRED", "generation": 1,
        "replacement_count": 0, "automatic_extension": False,
        "manual_submission_only": True,
        "updated_at": _timestamp(started),
    }
    with state_lock(run):
        atomic_json(existing, swarm)
        state.update({
            "status": "SWARM_READY", "solve_engine": "first-to-flag",
            "active_child_width": 0, "planned_child_width": len(INITIAL_LANES),
            "updated_at": utc_now(),
        })
        atomic_json(run / "STATE.json", state)
    return _public_swarm(swarm)


def confirm_native_spawn(
    run: Path, *, lane_id: str, native_session: str, operation_id: str | None = None,
) -> dict[str, Any]:
    """Mark a child RUNNING only after the native surface returned an identity."""

    native_session = _text(native_session, "native_session", 256)
    run = _run_root(run)
    with state_lock(run):
        swarm = _load_swarm(run)
        _apply_deadline_unlocked(run, swarm)
        lane = _lane(swarm, lane_id)
        if swarm["status"] in {"TIMED_OUT", "FLAG_FOUND", "ACCEPTED"}:
            raise SwarmError("terminal swarm cannot start another child")
        duplicate = next((
            row for row in swarm["lanes"]
            if row.get("native_session") == native_session and row.get("id") != lane_id
        ), None)
        if duplicate:
            raise SwarmError("native session is already bound to another lane")
        live_children = sum(
            bool(row.get("native_session")) and row.get("status") in {"RUNNING", "CANCEL_REQUIRED"}
            for row in swarm["lanes"]
        )
        if lane.get("status") != "RUNNING" and live_children + 1 >= MAX_NATIVE_CONCURRENCY:
            raise SwarmError("native concurrency would exceed Root plus three children")
        if lane.get("status") == "RUNNING":
            if lane.get("native_session") != native_session:
                raise SwarmError("lane is already bound to another native session")
            return {"lane": dict(lane), "idempotent": True}
        lane.update({
            "native_session": native_session, "status": "RUNNING",
            "spawn_attempts": int(lane.get("spawn_attempts") or 0) + 1,
            "native_start_operation_id": operation_id or native_session,
            "started_at": utc_now(),
        })
        swarm["spawn_queue"] = [
            row for row in swarm["spawn_queue"] if row.get("lane") != lane_id
        ]
        if all(row.get("status") == "RUNNING" for row in swarm["lanes"][:3]):
            swarm["status"] = "ACTIVE"
        swarm["updated_at"] = utc_now()
        _write_swarm(run, swarm)
        _sync_width(run, swarm)
        warning = _append_event_unlocked(run, swarm, {
            "type": "SPAWNED", "lane": lane_id,
            "summary": "native child started", "native_session": native_session,
            "operation_id": operation_id or native_session,
        }, best_effort=True)
    return {"lane": dict(lane), "idempotent": False, "record_warning": warning}


def record_spawn_failure(
    run: Path, *, lane_id: str, error: str,
) -> dict[str, Any]:
    run = _run_root(run)
    with state_lock(run):
        swarm = _load_swarm(run)
        lane = _lane(swarm, lane_id)
        attempts = int(lane.get("spawn_attempts") or 0) + 1
        lane.update({
            "status": "SPAWN_FAILED", "spawn_attempts": attempts,
            "last_error": _short(error, 2000), "updated_at": utc_now(),
        })
        retry_allowed = attempts < 2 and swarm.get("status") not in {
            "TIMED_OUT", "FLAG_FOUND", "ACCEPTED",
        }
        packet = next((
            row for row in swarm.get("spawn_queue", []) if row.get("lane") == lane_id
        ), None)
        if retry_allowed and packet is None:
            raise SwarmError("spawn retry packet is missing")
        swarm["status"] = "ACTIVE_WITH_SPAWN_FAILURE"
        swarm["updated_at"] = utc_now()
        _write_swarm(run, swarm)
    return {
        "lane": dict(lane), "retry_allowed": retry_allowed,
        "retry_packet": packet if retry_allowed else None,
        "root_attack_continues": True,
    }


def record_attack_event(
    run: Path,
    *,
    lane_id: str,
    event_type: str,
    summary: str,
    command: Sequence[str] = (),
    artifact: str | None = None,
    observed_output: str | None = None,
    next_attack: str | None = None,
    best_effort: bool = False,
) -> dict[str, Any]:
    """Record an observation after execution; this function is never an attack gate."""

    run = _run_root(run)
    event_type = event_type.strip().upper()
    if event_type not in EVENT_TYPES - {"FLAG_FOUND", "SPAWNED", "STOPPED"}:
        raise SwarmError(f"unsupported attack event type: {event_type}")
    payload = {
        "type": event_type, "lane": lane_id, "summary": _short(summary, 4000),
        "command": [_short(str(value), 1000) for value in command],
        "artifact": _relative_artifact(run, artifact),
        "observed_output": _short(observed_output or "", 4000) or None,
        "next_attack": _short(next_attack or "", 2000) or None,
    }
    try:
        with state_lock(run):
            swarm = _load_swarm(run)
            _apply_deadline_unlocked(run, swarm)
            if swarm.get("status") in {"TIMED_OUT", "FLAG_FOUND", "ACCEPTED"}:
                raise SwarmError("terminal swarm accepts no new attack events")
            _lane_or_root(swarm, lane_id)
            warning = _append_event_unlocked(run, swarm, payload, best_effort=best_effort)
            lane = _lane_or_root(swarm, lane_id)
            swarm_changed = False
            if event_type in HIGH_VALUE_EVENTS:
                lane["last_high_value_event"] = {
                    "type": event_type, "summary": payload["summary"], "created_at": utc_now(),
                }
                swarm_changed = True
            if lane.get("role") == "max-endgame" and event_type in {"EXPLOIT_ATTEMPTED", "REMOTE_ATTEMPT"}:
                lane["endgame_attacks"] = int(lane.get("endgame_attacks") or 0) + 1
                if lane["endgame_attacks"] >= 2:
                    lane["status"] = "CANCEL_REQUIRED"
                    lane["cancel_reason"] = "bounded Sol max attack limit reached"
                swarm_changed = True
            if swarm_changed:
                _write_swarm(run, swarm)
        return {**payload, "persisted": warning is None, "record_warning": warning}
    except Exception as exc:
        if not best_effort:
            raise
        return {**payload, "persisted": False, "record_warning": str(exc)}


def record_command_after_execution(
    run: Path, *, lane_id: str, command: Sequence[str], result: Mapping[str, Any],
) -> dict[str, Any]:
    """Best-effort command receipt intentionally called only after the command returned."""

    output = result.get("stdout") or result.get("output") or result.get("stderr") or ""
    return record_attack_event(
        run, lane_id=lane_id, event_type="COMMAND_EXECUTED",
        summary="command executed", command=command, observed_output=str(output),
        best_effort=True,
    )


def replace_lane(
    run: Path,
    *,
    lane_id: str,
    replacement_role: str,
    reason: str,
    native_stop_session: str | None,
    actual_failure: str,
    untried_family: str,
) -> dict[str, Any]:
    """Replace a stopped/failed lane without a lifetime replacement-count gate."""

    if replacement_role not in {"alternate-family", "failure-analysis", "striker"}:
        raise SwarmError("replacement role must be alternate-family, failure-analysis, or striker")
    run = _run_root(run)
    with state_lock(run):
        swarm = _load_swarm(run)
        _apply_deadline_unlocked(run, swarm)
        old = _lane(swarm, lane_id)
        if old.get("status") == "RUNNING":
            if not native_stop_session or native_stop_session != old.get("native_session"):
                raise SwarmError("running lane replacement requires its exact stopped native session")
        old.update({"status": "STOPPED", "stopped_at": utc_now(), "stop_reason": _short(reason, 2000)})
        count = int(swarm.get("replacement_count") or 0) + 1
        replacement_id = f"{replacement_role}-{count}"
        if any(row.get("id") == replacement_id for row in swarm["lanes"]):
            raise SwarmError("replacement lane identity collision")
        source_packet = next((
            row for row in swarm.get("spawn_queue", []) if row.get("lane") == lane_id
        ), None)
        base = (
            source_packet.get("context", {}) if isinstance(source_packet, Mapping)
            else swarm.get("challenge_context", {})
        )
        packet = _replacement_packet(
            run=run, lane_id=replacement_id, role=replacement_role,
            root_session=str(swarm["root_session"]), deadline=str(swarm["deadline"]),
            base_context=base, actual_failure=actual_failure,
            untried_family=untried_family,
        )
        lane_root = run / "workers" / replacement_id
        for directory in (lane_root / "work", lane_root / "evidence", lane_root / "artifacts"):
            directory.mkdir(parents=True, exist_ok=True)
        swarm["lanes"].append({
            "id": replacement_id, "role": replacement_role, "native_session": None,
            "status": "PENDING_SPAWN", "spawn_attempts": 0,
            "last_high_value_event": None, "sandbox": packet["sandbox"],
        })
        swarm["spawn_queue"] = [
            row for row in swarm.get("spawn_queue", []) if row.get("lane") != lane_id
        ] + [packet]
        swarm["replacement_count"] = count
        swarm["status"] = "SPAWN_REQUIRED"
        swarm["updated_at"] = utc_now()
        _append_event_unlocked(run, swarm, {
            "type": "STOPPED", "lane": lane_id, "summary": _short(reason, 4000),
            "observed_output": _short(actual_failure, 4000),
        }, best_effort=True)
        _write_swarm(run, swarm)
        _sync_width(run, swarm)
    return {
        "stopped_lane": lane_id, "replacement_lane": replacement_id,
        "spawn_packet": packet, "replacement_limit": None,
        "root_attack_continues": True,
    }


def start_max_endgame(
    run: Path, *, lane_id: str, native_stop_session: str, now: datetime | None = None,
) -> dict[str, Any]:
    """Replace one qualified 60-minute lane with a bounded Sol max endgame."""

    run = _run_root(run)
    current = _as_utc(now)
    with state_lock(run):
        swarm = _load_swarm(run)
        _apply_deadline_unlocked(run, swarm, now=current)
        elapsed = int((current - _parse_time(str(swarm["started_at"]))).total_seconds())
        if elapsed < ENDGAME_SECONDS or elapsed >= DEFAULT_BUDGET_SECONDS:
            raise SwarmError("Sol max endgame is available only from minute 60 until cutoff")
        if any(row.get("role") == "max-endgame" for row in swarm["lanes"]):
            raise SwarmError("this attempt already used its one Sol max endgame lane")
        old = _lane(swarm, lane_id)
        if old.get("status") != "RUNNING" or old.get("native_session") != native_stop_session:
            raise SwarmError("max endgame requires the exact stopped native session")
        events = [row for row in _read_events(run) if row.get("lane") == lane_id]
        attempts = sum(row.get("type") in {"EXPLOIT_ATTEMPTED", "REMOTE_ATTEMPT"} for row in events)
        has_path = any(row.get("type") in {"ATTACK_PATH_FOUND", "PRIMITIVE", "POC", "WORKING_POC"} for row in events)
        blocker = next((row for row in reversed(events) if row.get("type") == "BLOCKER"), None)
        if attempts < 2 or not has_path or blocker is None:
            raise SwarmError("max endgame requires a partial path, two actual attacks, and an exact blocker")
        blocker_text = " ".join(str(blocker.get(key) or "") for key in ("summary", "observed_output")).casefold()
        if any(word in blocker_text for word in (
            "docker", "dependency", "target down", "rate limit", "tool failure", "connection refused",
        )):
            raise SwarmError("environment, dependency, target, rate-limit, and tool failures do not qualify for Sol max")
        old.update({"status": "STOPPED", "stopped_at": utc_now(), "stop_reason": "promoted to bounded max endgame"})
        count = int(swarm.get("replacement_count") or 0) + 1
        replacement_id = f"max-endgame-{count}"
        packet = _replacement_packet(
            run=run, lane_id=replacement_id, role="max-endgame",
            root_session=str(swarm["root_session"]), deadline=str(swarm["deadline"]),
            base_context=swarm.get("challenge_context", {}),
            actual_failure=str(blocker.get("observed_output") or blocker.get("summary") or ""),
            untried_family=str(blocker.get("next_attack") or "finish the executable endgame"),
        )
        lease_deadline = min(_parse_time(str(swarm["deadline"])), current + timedelta(minutes=10))
        packet["model_request"] = {"model": "gpt-5.6-sol", "reasoning_effort": "max"}
        packet["lease"] = {"deadline": _timestamp(lease_deadline), "maximum_actual_attacks": 2}
        lane_root = run / "workers" / replacement_id
        for directory in (lane_root / "work", lane_root / "evidence", lane_root / "artifacts"):
            directory.mkdir(parents=True, exist_ok=True)
        swarm["lanes"].append({
            "id": replacement_id, "role": "max-endgame", "native_session": None,
            "status": "PENDING_SPAWN", "spawn_attempts": 0, "endgame_attacks": 0,
            "lease_deadline": _timestamp(lease_deadline),
            "last_high_value_event": old.get("last_high_value_event"), "sandbox": packet["sandbox"],
        })
        swarm["spawn_queue"] = [row for row in swarm.get("spawn_queue", []) if row.get("lane") != lane_id] + [packet]
        swarm["replacement_count"] = count
        swarm["status"] = "SPAWN_REQUIRED"
        swarm["updated_at"] = utc_now()
        _append_event_unlocked(run, swarm, {
            "type": "STOPPED", "lane": lane_id,
            "summary": "promoted to bounded Sol max endgame", "observed_output": blocker_text,
        }, best_effort=True)
        _write_swarm(run, swarm)
        _sync_width(run, swarm)
    return {
        "stopped_lane": lane_id, "max_lane": replacement_id,
        "spawn_packet": packet, "root_attack_continues": True,
    }


def flag_found(
    run: Path,
    *,
    lane_id: str,
    candidate: str,
    flag_pattern: str | None,
    challenge_key: str,
    command: Sequence[str],
    observed_output: str,
    artifact: str | None,
    source: str,
) -> dict[str, Any]:
    """Select the first format-valid, target-observed candidate and stop the race."""

    if not matches_flag(candidate, flag_pattern):
        raise SwarmError("flag candidate does not match the challenge format or is a placeholder")
    if candidate not in observed_output:
        raise SwarmError("flag candidate is absent from the actual target output")
    if not command:
        raise SwarmError("flag provenance requires the exact executed command")
    run = _run_root(run)
    with state_lock(run):
        swarm = _load_swarm(run)
        existing = swarm.get("winner")
        if existing:
            return _winner_result(swarm, challenge_key, idempotent=True)
        lane = _lane_or_root(swarm, lane_id)
        digest = hashlib.sha256(
            json.dumps({
                "run_id": swarm["run_id"], "lane": lane_id, "candidate": candidate,
                "command": list(command), "output": observed_output,
            }, ensure_ascii=False, sort_keys=True).encode()
        ).hexdigest()[:24]
        receipt = {
            "schema_version": 1, "receipt_id": digest, "run_id": swarm["run_id"],
            "challenge_id": swarm["challenge_id"], "lane": lane_id,
            "candidate": candidate, "command": list(command),
            "observed_output": _short(observed_output, 8000),
            "artifact": _relative_artifact(run, artifact), "source": _short(source, 1000),
            "created_at": utc_now(), "manual_submission_only": True,
        }
        receipt_path = run / "artifacts" / f"flag-{digest}.json"
        atomic_json(receipt_path, receipt)
        winner = {
            "lane": lane_id, "native_session": lane.get("native_session"),
            "candidate": candidate, "receipt": str(receipt_path.relative_to(run)),
            "found_at": receipt["created_at"], "source": receipt["source"],
        }
        swarm["winner"] = winner
        swarm["status"] = "FLAG_FOUND"
        cancel = []
        for other in swarm["lanes"]:
            if other.get("id") != lane_id and other.get("status") == "RUNNING":
                other["status"] = "CANCEL_REQUIRED"
                cancel.append({
                    "lane": other["id"], "native_session": other.get("native_session"),
                })
        swarm["spawn_queue"] = []
        swarm["updated_at"] = utc_now()
        _append_event_unlocked(run, swarm, {
            "type": "FLAG_FOUND", "lane": lane_id,
            "summary": "format-valid flag observed in actual target output",
            "command": list(command), "artifact": receipt["artifact"],
            "observed_output": receipt["observed_output"], "candidate": candidate,
        }, best_effort=True)
        _write_swarm(run, swarm)
        state = _read_object(run / "STATE.json", "run state")
        state.update({
            "status": "SUBMISSION_RECOMMENDED", "competition_state": "FLAG_FOUND",
            "flag_candidate": candidate, "submission_recommended": True,
            "solve_engine": "first-to-flag", "updated_at": utc_now(),
        })
        atomic_json(run / "STATE.json", state)
    result = _winner_result(swarm, challenge_key, idempotent=False)
    result["cancel_queue"] = cancel
    result["stop_additional_analysis"] = True
    return result


def stop_confirmed(run: Path, *, lane_id: str, native_session: str) -> dict[str, Any]:
    run = _run_root(run)
    with state_lock(run):
        swarm = _load_swarm(run)
        lane = _lane(swarm, lane_id)
        if lane.get("native_session") != native_session:
            raise SwarmError("stop receipt does not match the lane native session")
        lane.update({"status": "STOPPED", "stopped_at": utc_now()})
        _write_swarm(run, swarm)
        _sync_width(run, swarm)
    return {"lane": lane_id, "native_session": native_session, "status": "STOPPED"}


def submission_result(
    run: Path, *, candidate: str, result: str,
) -> dict[str, Any]:
    """Record only the human oracle; never contact a scoreboard."""

    normalized = result.strip().upper()
    if normalized not in {"WRONG", "ACCEPTED"}:
        raise SwarmError("submission result must be WRONG or ACCEPTED")
    run = _run_root(run)
    with state_lock(run):
        swarm = _load_swarm(run)
        winner = swarm.get("winner")
        if not isinstance(winner, Mapping) or winner.get("candidate") != candidate:
            raise SwarmError("submission result does not match the current winning candidate")
        history = list(swarm.get("submission_history") or [])
        history.append({"candidate": candidate, "result": normalized, "recorded_at": utc_now()})
        swarm["submission_history"] = history
        state = _read_object(run / "STATE.json", "run state")
        if normalized == "ACCEPTED":
            swarm["status"] = "ACCEPTED"
            state.update({
                "status": "ACCEPTED", "competition_state": "ACCEPTED",
                "submission_recommended": False, "sealed": True,
            })
            spawn_packet = None
        else:
            swarm["winner"] = None
            swarm["status"] = "SPAWN_REQUIRED"
            state.update({
                "status": "SWARM_ACTIVE", "competition_state": "SOLVING",
                "flag_candidate": None, "submission_recommended": False,
            })
            count = int(swarm.get("replacement_count") or 0) + 1
            lane_id = f"striker-{count}"
            prior = next((row for row in swarm["lanes"] if row.get("id") == winner.get("lane")), {})
            packet = _replacement_packet(
                run=run, lane_id=lane_id, role="striker",
                root_session=str(swarm["root_session"]), deadline=str(swarm["deadline"]),
                base_context=swarm.get("challenge_context", {}),
                actual_failure=f"human rejected candidate {candidate}",
                untried_family="fresh exploit path or strongest surviving path",
            )
            swarm["lanes"].append({
                "id": lane_id, "role": "striker", "native_session": None,
                "status": "PENDING_SPAWN", "spawn_attempts": 0,
                "last_high_value_event": prior.get("last_high_value_event"),
                "sandbox": packet["sandbox"],
            })
            swarm["spawn_queue"] = [packet]
            swarm["replacement_count"] = count
            spawn_packet = packet
        swarm["updated_at"] = utc_now()
        state["updated_at"] = utc_now()
        _write_swarm(run, swarm)
        atomic_json(run / "STATE.json", state)
    return {
        "result": normalized, "candidate": candidate,
        "spawn_packet": spawn_packet, "automatic_submission": False,
    }


def swarm_status(run: Path, *, now: datetime | None = None) -> dict[str, Any]:
    run = _run_root(run)
    with state_lock(run):
        swarm = _load_swarm(run)
        cutoff = _apply_deadline_unlocked(run, swarm, now=now)
        elapsed = max(0, int((_as_utc(now) - _parse_time(str(swarm["started_at"]))).total_seconds()))
        events = _read_events(run)
        endgame_cancel_queue = []
        for lane in swarm["lanes"]:
            if (
                lane.get("role") == "max-endgame" and lane.get("status") == "RUNNING"
                and lane.get("lease_deadline")
                and _as_utc(now) >= _parse_time(str(lane["lease_deadline"]))
            ):
                lane["status"] = "CANCEL_REQUIRED"
                lane["cancel_reason"] = "bounded Sol max lease expired"
                endgame_cancel_queue.append({"lane": lane["id"], "native_session": lane.get("native_session")})
        if endgame_cancel_queue:
            swarm["updated_at"] = utc_now()
            _write_swarm(run, swarm)
            _sync_width(run, swarm)
        replacement_candidates: list[str] = []
        if elapsed >= PLATEAU_SECONDS and swarm.get("status") not in {"TIMED_OUT", "FLAG_FOUND", "ACCEPTED"}:
            for lane in swarm["lanes"]:
                if lane.get("status") != "RUNNING":
                    continue
                values = [row["type"] for row in events if row.get("lane") == lane.get("id")]
                if not set(values).intersection({"PRIMITIVE", "POC", "WORKING_POC", "REMOTE_RESULT"}):
                    replacement_candidates.append(str(lane["id"]))
                if len(replacement_candidates) == 2:
                    break
        endgame = []
        if elapsed >= ENDGAME_SECONDS and elapsed < DEFAULT_BUDGET_SECONDS:
            for lane in swarm["lanes"]:
                lane_events = [row for row in events if row.get("lane") == lane.get("id")]
                attempts = sum(row.get("type") in {"EXPLOIT_ATTEMPTED", "REMOTE_ATTEMPT"} for row in lane_events)
                has_path = any(row.get("type") in {"ATTACK_PATH_FOUND", "PRIMITIVE", "POC", "WORKING_POC"} for row in lane_events)
                has_blocker = any(row.get("type") == "BLOCKER" for row in lane_events)
                if attempts >= 2 and has_path and has_blocker:
                    endgame.append(str(lane["id"]))
        status = _public_swarm(swarm)
        status.update({
            "elapsed_seconds": elapsed, "plateau_replacement_candidates": replacement_candidates,
            "max_endgame_candidates": endgame[:1], "endgame_cancel_queue": endgame_cancel_queue,
            "cutoff": cutoff,
        })
        return status


def high_value_events(run: Path, *, since: str | None = None) -> list[dict[str, Any]]:
    rows = [row for row in _read_events(_run_root(run)) if row.get("type") in SHAREABLE_EVENTS]
    if since:
        rows = [row for row in rows if str(row.get("created_at")) > since]
    return rows


def _apply_deadline_unlocked(
    run: Path, swarm: dict[str, Any], *, now: datetime | None = None,
) -> dict[str, Any] | None:
    current = _as_utc(now)
    if current < _parse_time(str(swarm["deadline"])):
        return None
    if swarm.get("status") in {"FLAG_FOUND", "ACCEPTED", "TIMED_OUT"}:
        return None
    events = _read_events(run)
    cancel = []
    for lane in swarm["lanes"]:
        if lane.get("status") == "RUNNING":
            lane["status"] = "CANCEL_REQUIRED"
            cancel.append({"lane": lane["id"], "native_session": lane.get("native_session")})
    swarm["status"] = "TIMED_OUT"
    swarm["spawn_queue"] = []
    swarm["updated_at"] = _timestamp(current)
    leading = next((row for row in reversed(events) if row.get("type") in {"WORKING_POC", "POC", "PRIMITIVE", "ATTACK_PATH_FOUND"}), None)
    blocker = next((row for row in reversed(events) if row.get("type") == "BLOCKER"), None)
    executed = [row for row in events if row.get("type") in {"COMMAND_EXECUTED", "EXPLOIT_ATTEMPTED", "REMOTE_ATTEMPT"}]
    handoff = [
        f"# Solve timeout — {swarm.get('challenge_id')}", "",
        f"- Run: `{swarm.get('run_id')}`", f"- Deadline: `{swarm.get('deadline')}`",
        f"- Leading attack path: {leading.get('summary') if leading else 'none established'}",
        f"- Exact blocker: {blocker.get('summary') if blocker else 'none recorded'}", "",
        "## Executed attacks", "",
    ]
    for row in executed[-20:]:
        handoff.append(f"- `{row.get('lane')}`: {row.get('command') or row.get('summary')}")
    handoff.extend(["", "## Next attack", "", str((blocker or leading or {}).get("next_attack") or "Run one fresh executable attack family."), ""])
    path = run / "artifacts" / "TIMEOUT_HANDOFF.md"
    atomic_text(path, "\n".join(handoff))
    _write_swarm(run, swarm)
    state = _read_object(run / "STATE.json", "run state")
    state.update({"status": "TIMED_OUT", "submission_recommended": False, "updated_at": utc_now()})
    atomic_json(run / "STATE.json", state)
    return {"cancel_queue": cancel, "handoff": str(path), "automatic_extension": False}


def _spawn_packet(
    *, run: Path, challenge: Any, record: Mapping[str, object], lane_id: str,
    role: str, root_session: str, deadline: str,
) -> dict[str, Any]:
    problem = _problem_context(challenge, record)
    sandbox = {
        "image": str(record.get("recommended_image") or "ctf-os-sandbox:base"),
        "metadata_path": str(run / "workers" / lane_id / "sandbox.json"),
        "work": str(run / "workers" / lane_id / "work"),
        "evidence": str(run / "workers" / lane_id / "evidence"),
        "artifacts": str(run / "workers" / lane_id / "artifacts"),
        "input_read_only": True,
    }
    contract = {
        "independent": "Solve independently. Do not use or request Root's analysis or hypotheses.",
        "exploit-first": "Do not produce a report. Do not seek complete understanding. Find, build, and run the smallest plausible exploit.",
        "tool-driven": "Your progress must be commands, scripts, payloads, runtime observations, or exact blockers from actual execution.",
    }[role]
    message = _worker_message(problem, sandbox, role, contract, root_session, deadline)
    return {
        "lane": lane_id, "role": role, "deadline": deadline,
        "model_request": {"model": "gpt-5.6-sol", "reasoning_effort": "xhigh"},
        "spawn_agent_args": {"task_name": lane_id.replace("-", "_"), "fork_turns": "none", "message": message},
        "context": problem, "sandbox": sandbox,
    }


def _problem_context(challenge: Any, record: Mapping[str, object]) -> dict[str, Any]:
    return {
        "name": str(getattr(challenge, "name", "")),
        "category": str(getattr(challenge, "category", "misc")),
        "description": getattr(challenge, "description", None),
        "hint": getattr(challenge, "hint", None),
        "flag_format": getattr(challenge, "flag_format", None),
        "flag_pattern": getattr(challenge, "flag_pattern", None),
        "challenge_files": str(record.get("prepared_input") or ""),
        "remote": list(getattr(challenge, "remotes", ()) or ()),
    }


def _replacement_packet(
    *, run: Path, lane_id: str, role: str, root_session: str, deadline: str,
    base_context: Mapping[str, Any], actual_failure: str, untried_family: str,
) -> dict[str, Any]:
    sandbox = {
        "metadata_path": str(run / "workers" / lane_id / "sandbox.json"),
        "work": str(run / "workers" / lane_id / "work"),
        "evidence": str(run / "workers" / lane_id / "evidence"),
        "artifacts": str(run / "workers" / lane_id / "artifacts"),
        "input_read_only": True,
    }
    message = (
        "You are a replacement lane in an authorized timed CTF first-to-flag race.\n"
        f"Role: {role}\nDeadline: {deadline}\nRoot: {root_session}\n"
        f"Challenge context: {json.dumps(dict(base_context), ensure_ascii=False)}\n"
        f"Actual failed command/output: {_short(actual_failure, 6000)}\n"
        f"Untried attack family: {_short(untried_family, 2000)}\n"
        f"Writable paths: {json.dumps(sandbox, ensure_ascii=False)}\n"
        "Use actual tools immediately. Change the attack family or apply the failure output; do not write a report. "
        "Share only PRIMITIVE, WORKING_POC, REMOTE_RESULT, FLAG_CANDIDATE, EXACT_BLOCKER, or USEFUL_FAILURE."
    )
    return {
        "lane": lane_id, "role": role, "deadline": deadline,
        "model_request": {"model": "gpt-5.6-sol", "reasoning_effort": "xhigh"},
        "spawn_agent_args": {"task_name": lane_id.replace("-", "_"), "fork_turns": "none", "message": message},
        "context": dict(base_context), "sandbox": sandbox,
    }


def _worker_message(
    problem: Mapping[str, Any], sandbox: Mapping[str, Any], role: str,
    contract: str, root_session: str, deadline: str,
) -> str:
    return (
        "You are a Sol xhigh child in an authorized timed CTF first-to-flag race.\n"
        f"Lane: {role}\nRoot session: {root_session}\nDeadline: {deadline}\n"
        f"Problem: {json.dumps(dict(problem), ensure_ascii=False)}\n"
        f"Sandbox and writable paths: {json.dumps(dict(sandbox), ensure_ascii=False)}\n"
        f"Lane contract: {contract}\n"
        "Immediately use tools. Loop: MINIMAL OBSERVATION -> ONE ATTACK PATH -> SMALLEST EXECUTABLE ATTACK -> RUN -> READ REAL OUTPUT -> MUTATE OR REPLACE -> REMOTE -> FLAG. "
        "After ATTACK_PATH_FOUND, execute a PoC, payload, solver, or remote attack within the next two meaningful tool actions. "
        "Share PRIMITIVE, WORKING_POC, REMOTE_RESULT, FLAG_CANDIDATE, EXACT_BLOCKER, or USEFUL_FAILURE immediately; omit general summaries and unexecuted hypotheses. "
        "Never attack undeclared targets, access host credentials/personal files, or submit a flag."
    )


def _append_event_unlocked(
    run: Path, swarm: Mapping[str, Any], payload: Mapping[str, Any], *, best_effort: bool,
) -> str | None:
    event = {
        "schema_version": ATTACK_EVENT_SCHEMA_VERSION,
        "event_id": hashlib.sha256(
            json.dumps({**payload, "run_id": swarm.get("run_id"), "nonce": utc_now()}, sort_keys=True, default=str).encode()
        ).hexdigest()[:24],
        "run_id": swarm.get("run_id"), "challenge_id": swarm.get("challenge_id"),
        "created_at": utc_now(), **payload,
    }
    try:
        append_jsonl_fsync(run / "ATTACK_EVENTS.jsonl", event, label="attack event ledger")
        return None
    except Exception as exc:
        if not best_effort:
            raise
        return str(exc)


def _sync_width(run: Path, swarm: Mapping[str, Any]) -> None:
    state = _read_object(run / "STATE.json", "run state")
    state["active_child_width"] = sum(row.get("status") == "RUNNING" for row in swarm["lanes"])
    state["planned_child_width"] = sum(row.get("status") == "PENDING_SPAWN" for row in swarm["lanes"])
    state["updated_at"] = utc_now()
    atomic_json(run / "STATE.json", state)


def _public_swarm(swarm: Mapping[str, Any]) -> dict[str, Any]:
    return {
        **dict(swarm),
        "native_children_running": sum(row.get("status") == "RUNNING" for row in swarm.get("lanes", [])),
        "root_direct_attack_required": True,
        "spawn_before_recon": bool(swarm.get("spawn_queue")),
    }


def _winner_result(swarm: Mapping[str, Any], challenge_key: str, *, idempotent: bool) -> dict[str, Any]:
    winner = dict(swarm["winner"])
    display = (
        "REMOTE FLAG OBTAINED\n"
        f"Challenge: {challenge_key}\n"
        f"Flag: {winner['candidate']}\n"
        f"Source: {winner['lane']} / {winner['source']}\n"
        "Recommendation: submit immediately"
    )
    return {"winner": winner, "display": display, "manual_submission_only": True, "idempotent": idempotent}


def _load_swarm(run: Path) -> dict[str, Any]:
    swarm = _read_object(run / "SWARM.json", "swarm state")
    state = _read_object(run / "STATE.json", "run state")
    _assert_identity(swarm, state)
    return swarm


def _assert_identity(swarm: Mapping[str, Any], state: Mapping[str, Any]) -> None:
    for field in ("run_id", "challenge_id", "input_fingerprint"):
        if swarm.get(field) != state.get(field):
            raise SwarmError(f"swarm {field} does not match the exact attempt")


def _lane(swarm: Mapping[str, Any], lane_id: str) -> dict[str, Any]:
    matches = [row for row in swarm.get("lanes", []) if row.get("id") == lane_id]
    if len(matches) != 1:
        raise SwarmError("lane does not exist in this swarm")
    return matches[0]


def _lane_or_root(swarm: Mapping[str, Any], lane_id: str) -> dict[str, Any]:
    if lane_id == "root":
        return swarm["root_lane"]
    return _lane(swarm, lane_id)


def _read_events(run: Path) -> list[dict[str, Any]]:
    path = run / "ATTACK_EVENTS.jsonl"
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file():
        raise SwarmError("attack event ledger is unsafe")
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            value = json.loads(line)
            if not isinstance(value, dict):
                raise SwarmError("attack event ledger contains a non-object")
            rows.append(value)
    return rows


def _write_swarm(run: Path, swarm: Mapping[str, Any]) -> None:
    atomic_json(run / "SWARM.json", dict(swarm))


def _run_root(run: Path) -> Path:
    value = run.resolve(strict=False)
    if value.is_symlink() or not (value / "STATE.json").is_file():
        raise SwarmError("exact run root is missing or unsafe")
    return value


def _read_object(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise SwarmError(f"{label} is missing or unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SwarmError(f"{label} is malformed") from exc
    if not isinstance(value, dict):
        raise SwarmError(f"{label} must be an object")
    return value


def _relative_artifact(run: Path, artifact: str | None) -> str | None:
    if not artifact:
        return None
    raw = Path(artifact)
    resolved = raw.resolve(strict=False) if raw.is_absolute() else (run / raw).resolve(strict=False)
    try:
        relative = resolved.relative_to(run)
    except ValueError as exc:
        raise SwarmError("artifact must stay inside the exact run") from exc
    if ".." in relative.parts:
        raise SwarmError("artifact path escapes the exact run")
    return str(relative)


def _text(value: str, label: str, maximum: int) -> str:
    result = str(value).strip()
    if not result or len(result.encode()) > maximum:
        raise SwarmError(f"{label} must be non-empty and at most {maximum} bytes")
    return result


def _short(value: str, maximum: int) -> str:
    raw = str(value).encode("utf-8")
    return raw[:maximum].decode("utf-8", errors="ignore")


def _as_utc(value: datetime | None) -> datetime:
    selected = value or datetime.now(timezone.utc)
    if selected.tzinfo is None:
        selected = selected.replace(tzinfo=timezone.utc)
    return selected.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return _as_utc(value).isoformat().replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError as exc:
        raise SwarmError("swarm timestamp is malformed") from exc
