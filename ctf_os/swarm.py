"""Dynamic first-to-flag worker state for one isolated challenge attempt.

Python prepares native delegation packets and records post-execution facts. It
never starts or stops a model, chooses a worker for Root, approves an attack, or
submits a flag. Native child lifecycle remains owned by the user-opened Root Sol
session.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from typing import Any

from .flags import matches_flag
from .workspace import append_jsonl_fsync, atomic_json, atomic_text, state_lock, utc_now


SWARM_SCHEMA_VERSION = 2
ATTACK_EVENT_SCHEMA_VERSION = 1
DEFAULT_BUDGET_SECONDS = 90 * 60
ENDGAME_SECONDS = 60 * 60
MAX_NATIVE_CONCURRENCY = 4
MAX_NATIVE_CHILDREN = MAX_NATIVE_CONCURRENCY - 1
GENERAL_MODEL_PROFILES = ("sol-xhigh", "terra-high", "luna-high")
MODEL_PROFILES: dict[str, dict[str, str]] = {
    "sol-xhigh": {
        "agent_profile": "ctf_sol_xhigh",
        "model": "gpt-5.6-sol",
        "reasoning_effort": "xhigh",
        "contract": (
            "Use actual tools immediately and drive one attack path to an executable payload, "
            "solver, PoC, or remote request. Read real output and mutate the attack or change "
            "family. Return a primitive, working PoC, remote result, flag candidate, useful "
            "failure, or exact blocker; do not lead with a report."
        ),
    },
    "terra-high": {
        "agent_profile": "ctf_terra_high",
        "model": "gpt-5.6-terra",
        "reasoning_effort": "high",
        "contract": (
            "Turn the supplied attack direction into an executable artifact. Minimal direct "
            "checks for missing values are allowed, but do not return to broad vulnerability "
            "recon. Run the artifact and adapt it to the declared remote. Return the artifact "
            "and actual result, a useful refutation, or an exact blocker."
        ),
    },
    "luna-high": {
        "agent_profile": "ctf_luna_high",
        "model": "gpt-5.6-luna",
        "reasoning_effort": "high",
        "contract": (
            "Perform only the assigned mechanical extraction, filtering, normalization, "
            "batching, repetition, comparison, brute-force, or decode task. Run real commands "
            "and return reusable normalized output. If broader judgment is required, stop with "
            "an exact blocker instead of independently solving the challenge."
        ),
    },
    "sol-max": {
        "agent_profile": "ctf_sol_max",
        "model": "gpt-5.6-sol",
        "reasoning_effort": "max",
        "contract": (
            "Work only from the supplied executed partial exploit, two actual attack outputs, "
            "exact reasoning blocker, and concrete next attack. Run at most two actual attacks "
            "or stop after ten minutes."
        ),
    },
}
EVENT_TYPES = frozenset({
    "SPAWNED", "COMMAND_EXECUTED", "ATTACK_PATH_FOUND", "EXPLOIT_ATTEMPTED",
    "PRIMITIVE", "POC", "WORKING_POC", "REMOTE_ATTEMPT", "REMOTE_RESULT",
    "USEFUL_FAILURE", "BLOCKER", "FLAG_FOUND", "STOPPED",
})
HIGH_VALUE_EVENTS = frozenset({
    "COMMAND_EXECUTED", "PRIMITIVE", "POC", "WORKING_POC", "REMOTE_RESULT",
    "FLAG_FOUND", "BLOCKER", "USEFUL_FAILURE",
})
SHAREABLE_EVENTS = frozenset({
    "PRIMITIVE", "WORKING_POC", "REMOTE_RESULT", "FLAG_FOUND", "BLOCKER",
    "USEFUL_FAILURE",
})
TERMINAL_STATUSES = frozenset({"TIMED_OUT", "FLAG_FOUND", "ACCEPTED", "HANDOFF", "SUPERSEDED"})
ACTIVE_WORKER_STATUSES = frozenset({"PENDING_SPAWN", "RUNNING", "CANCEL_REQUIRED"})
ENVIRONMENT_BLOCKERS = (
    "docker", "dependency", "target down", "rate limit", "rate-limit", "tool failure",
    "connection refused", "connection failure", "network failure", "service unavailable",
)


class SwarmError(ValueError):
    pass


def ensure_prepare_scope(output_root: Path, *, challenge_id: str) -> None:
    """Refuse preparation that would disturb another live native Solve."""

    output_root = output_root.resolve(strict=False)
    if output_root.is_symlink():
        raise SwarmError("machine output root is unsafe")
    output_root.mkdir(parents=True, exist_ok=True)
    with state_lock(output_root):
        current = _as_utc(None)
        for path in output_root.rglob("SWARM.json"):
            if path.parent.parent.name != "runs":
                continue
            other = _read_object(path, "active worker state")
            if other.get("status") in TERMINAL_STATUSES:
                continue
            deadline = other.get("deadline")
            if deadline and current >= _parse_time(str(deadline)):
                continue
            same_without_child = (
                other.get("challenge_id") == challenge_id
                and _live_native_children(other) == 0
            )
            if not same_without_child:
                raise SwarmError(
                    "another challenge attempt already owns this machine: "
                    f"{other.get('challenge_id') or path.parent.name}"
                )


def initialize_swarm(
    run: Path,
    *,
    challenge: Any,
    record: Mapping[str, object],
    root_session: str = "sol-main",
    now: datetime | None = None,
) -> dict[str, Any]:
    """Prepare the machine's only active challenge for immediate Root attack."""

    run = _run_root(run)
    output_root = _machine_output_root(run)
    lock = state_lock(output_root) if output_root is not None else nullcontext()
    with lock:
        if output_root is not None:
            _assert_no_other_active_solve(output_root, run, now=now)
        return _initialize_swarm(
            run, challenge=challenge, record=record, root_session=root_session, now=now,
        )


def _initialize_swarm(
    run: Path,
    *,
    challenge: Any,
    record: Mapping[str, object],
    root_session: str = "sol-main",
    now: datetime | None = None,
) -> dict[str, Any]:
    """Create Root-only active state with no mandatory child packets."""

    run = _run_root(run)
    state = _read_object(run / "STATE.json", "run state")
    existing = run / "SWARM.json"
    if existing.is_file() and not existing.is_symlink():
        swarm = _read_object(existing, "worker state")
        _assert_identity(swarm, state)
        _assert_schema(swarm)
        return _public_swarm(swarm)

    started = _as_utc(now)
    deadline = started + timedelta(seconds=DEFAULT_BUDGET_SECONDS)
    input_path = Path(str(record.get("prepared_input") or "")).resolve(strict=False)
    if not input_path.is_dir() or input_path.is_symlink():
        raise SwarmError("prepared challenge input is missing or unsafe")
    (run / "artifacts").mkdir(exist_ok=True)
    terminal = bool(
        state.get("sealed")
        or state.get("submission_recommended")
        or state.get("status") in {"ACCEPTED", "SEALED", "SEALED_CLEAN", "SUBMISSION_RECOMMENDED"}
    )
    problem = _problem_context(challenge, record)
    root_status = "STOPPED" if terminal else "RUNNING"
    swarm: dict[str, Any] = {
        "schema_version": SWARM_SCHEMA_VERSION,
        "run_id": state.get("run_id") or run.name,
        "challenge_id": state.get("challenge_id"),
        "attempt_id": state.get("attempt_id"),
        "challenge_instance_id": state.get("challenge_instance_id"),
        "input_fingerprint": state.get("input_fingerprint"),
        "started_at": _timestamp(started),
        "deadline": _timestamp(deadline),
        "budget_seconds": DEFAULT_BUDGET_SECONDS,
        "root_session": root_session,
        "challenge_context": problem,
        "root_lane": {
            "id": "root", "model_profile": "sol-xhigh", "role": "lead-attacker",
            "native_session": root_session, "status": root_status, "coordinator_only": False,
        },
        "maximum_native_concurrency": MAX_NATIVE_CONCURRENCY,
        "lanes": [],
        "winner": (
            {
                "lane": "preserved", "native_session": None,
                "candidate": state.get("flag_candidate"),
                "receipt": state.get("remote_flag_receipt"),
                "found_at": state.get("updated_at") or _timestamp(started),
                "source": "preserved run state",
            }
            if terminal and state.get("flag_candidate") else None
        ),
        "status": ("ACCEPTED" if state.get("sealed") else "FLAG_FOUND") if terminal else "ACTIVE",
        "updated_at": _timestamp(started),
    }
    with state_lock(run):
        atomic_json(existing, swarm)
        if not terminal:
            state.update({
                "status": "SWARM_ACTIVE", "solve_engine": "first-to-flag",
                "active_child_width": 0, "updated_at": utc_now(),
            })
            atomic_json(run / "STATE.json", state)
    return _public_swarm(swarm)


def create_worker_packet(
    run: Path,
    *,
    model_profile: str,
    role: str,
    task: str,
    context_mode: str,
    facts: Sequence[str] = (),
    failure_command: Sequence[str] = (),
    failure_output: str | None = None,
    artifact: str | None = None,
    exact_blocker: str | None = None,
) -> dict[str, Any]:
    """Add one optional worker and return its native spawn packet without starting it."""

    run = _run_root(run)
    with state_lock(run):
        swarm = _load_swarm(run)
        _apply_deadline_unlocked(run, swarm)
        packet = _add_worker_unlocked(
            run, swarm, model_profile=model_profile, role=role, task=task,
            context_mode=context_mode, facts=facts, failure_command=failure_command,
            failure_output=failure_output, artifact=artifact, exact_blocker=exact_blocker,
            allow_max=False,
        )
        swarm["updated_at"] = utc_now()
        _write_swarm(run, swarm)
        _sync_width(run, swarm)
    return packet


def confirm_native_spawn(
    run: Path, *, lane_id: str, native_session: str, operation_id: str | None = None,
) -> dict[str, Any]:
    """Mark a worker RUNNING only after the native surface returned an identity."""

    native_session = _text(native_session, "native_session", 256)
    run = _run_root(run)
    with state_lock(run):
        swarm = _load_swarm(run)
        _apply_deadline_unlocked(run, swarm)
        if swarm["status"] in TERMINAL_STATUSES:
            raise SwarmError("terminal worker state cannot start another child")
        lane = _lane(swarm, lane_id)
        duplicate = next((
            row for row in swarm["lanes"]
            if row.get("native_session") == native_session and row.get("id") != lane_id
        ), None)
        if duplicate:
            raise SwarmError("native session is already bound to another worker")
        if lane.get("status") == "RUNNING":
            if lane.get("native_session") != native_session:
                raise SwarmError("worker is already bound to another native session")
            return {"worker": _public_worker(lane), "idempotent": True}
        if lane.get("status") != "PENDING_SPAWN":
            raise SwarmError("worker is not pending native spawn")
        live_children = _live_native_children(swarm)
        if live_children >= MAX_NATIVE_CHILDREN:
            raise SwarmError("native concurrency would exceed Root plus three children")
        lane.update({
            "native_session": native_session, "status": "RUNNING",
            "spawn_attempts": int(lane.get("spawn_attempts") or 0) + 1,
            "native_start_operation_id": operation_id or native_session,
            "started_at": utc_now(),
        })
        swarm["updated_at"] = utc_now()
        _write_swarm(run, swarm)
        _sync_width(run, swarm)
        warning = _append_event_unlocked(run, swarm, {
            "type": "SPAWNED", "lane": lane_id,
            "summary": "native child started", "native_session": native_session,
            "operation_id": operation_id or native_session,
        }, best_effort=True)
    return {"worker": _public_worker(lane), "idempotent": False, "record_warning": warning}


def record_spawn_failure(run: Path, *, lane_id: str, error: str) -> dict[str, Any]:
    run = _run_root(run)
    with state_lock(run):
        swarm = _load_swarm(run)
        lane = _lane(swarm, lane_id)
        if lane.get("status") != "PENDING_SPAWN":
            raise SwarmError("only a pending worker can record a native spawn failure")
        attempts = int(lane.get("spawn_attempts") or 0) + 1
        retry_allowed = attempts < 2 and swarm.get("status") not in TERMINAL_STATUSES
        lane.update({
            "status": "PENDING_SPAWN" if retry_allowed else "SPAWN_FAILED",
            "spawn_attempts": attempts, "last_error": _short(error, 2000),
            "updated_at": utc_now(),
        })
        swarm["updated_at"] = utc_now()
        _write_swarm(run, swarm)
        _sync_width(run, swarm)
        retry_packet = _packet_for_lane(swarm, lane) if retry_allowed else None
    return {
        "worker": _public_worker(lane), "retry_allowed": retry_allowed,
        "retry_packet": retry_packet, "root_attack_continues": True,
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
            if swarm.get("status") in TERMINAL_STATUSES:
                raise SwarmError("terminal worker state accepts no new attack events")
            lane = _lane_or_root(swarm, lane_id)
            warning = _append_event_unlocked(run, swarm, payload, best_effort=best_effort)
            if (
                lane.get("model_profile") == "sol-max"
                and event_type in {"EXPLOIT_ATTEMPTED", "REMOTE_ATTEMPT"}
                and payload["command"] and payload["observed_output"]
            ):
                lane["endgame_attacks"] = int(lane.get("endgame_attacks") or 0) + 1
                if lane["endgame_attacks"] >= 2:
                    lane["status"] = "CANCEL_REQUIRED"
                    lane["cancel_reason"] = "bounded Sol max attack limit reached"
                _write_swarm(run, swarm)
                _sync_width(run, swarm)
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


def replace_worker(
    run: Path,
    *,
    lane_id: str,
    model_profile: str,
    role: str,
    task: str,
    context_mode: str,
    reason: str,
    native_stop_session: str | None = None,
    facts: Sequence[str] = (),
    failure_command: Sequence[str] = (),
    failure_output: str | None = None,
    artifact: str | None = None,
    exact_blocker: str | None = None,
) -> dict[str, Any]:
    """Stop one worker in state and replace it with any general worker profile."""

    run = _run_root(run)
    with state_lock(run):
        swarm = _load_swarm(run)
        _apply_deadline_unlocked(run, swarm)
        old = _lane(swarm, lane_id)
        if old.get("status") in {"RUNNING", "CANCEL_REQUIRED"}:
            if not native_stop_session or native_stop_session != old.get("native_session"):
                raise SwarmError("running worker replacement requires its exact stopped native session")
        old.update({"status": "STOPPED", "stopped_at": utc_now(), "stop_reason": _short(reason, 2000)})
        packet = _add_worker_unlocked(
            run, swarm, model_profile=model_profile, role=role, task=task,
            context_mode=context_mode, facts=facts, failure_command=failure_command,
            failure_output=failure_output, artifact=artifact, exact_blocker=exact_blocker,
            allow_max=False,
        )
        swarm["updated_at"] = utc_now()
        _append_event_unlocked(run, swarm, {
            "type": "STOPPED", "lane": lane_id, "summary": _short(reason, 4000),
            "observed_output": _short(failure_output or "", 4000) or None,
        }, best_effort=True)
        _write_swarm(run, swarm)
        _sync_width(run, swarm)
    return {
        "stopped_worker": lane_id, "replacement_worker": packet["lane_id"],
        "spawn_packet": packet, "root_attack_continues": True,
    }


def start_max_endgame(
    run: Path, *, lane_id: str, native_stop_session: str, now: datetime | None = None,
) -> dict[str, Any]:
    """Replace one qualified lane with the single bounded Sol max endgame worker."""

    run = _run_root(run)
    current = _as_utc(now)
    with state_lock(run):
        swarm = _load_swarm(run)
        _apply_deadline_unlocked(run, swarm, now=current)
        elapsed = int((current - _parse_time(str(swarm["started_at"]))).total_seconds())
        if elapsed < ENDGAME_SECONDS or elapsed >= DEFAULT_BUDGET_SECONDS:
            raise SwarmError("Sol max endgame is available only from minute 60 until cutoff")
        if any(row.get("model_profile") == "sol-max" for row in swarm["lanes"]):
            raise SwarmError("this attempt already used its one Sol max endgame worker")
        old = _lane(swarm, lane_id)
        if old.get("status") != "RUNNING" or old.get("native_session") != native_stop_session:
            raise SwarmError("Sol max must replace the exact stopped native worker")
        qualification = _endgame_qualification(
            [row for row in _read_events(run) if row.get("lane") == lane_id]
        )
        if qualification is None:
            raise SwarmError(
                "Sol max requires an executable partial path, two actual attack outputs, "
                "an exact reasoning blocker, and a concrete next attack"
            )
        old.update({"status": "STOPPED", "stopped_at": utc_now(), "stop_reason": "Sol max replacement"})
        blocker = qualification["blocker"]
        last_attack = qualification["attacks"][-1]
        partial = qualification["partial"]
        packet = _add_worker_unlocked(
            run, swarm, model_profile="sol-max", role="endgame",
            task=str(blocker["next_attack"]), context_mode="directed",
            facts=(str(partial.get("summary") or "executable partial attack path"),),
            failure_command=tuple(str(value) for value in last_attack.get("command") or ()),
            failure_output=str(last_attack.get("observed_output") or ""),
            artifact=str(partial.get("artifact") or "") or None,
            exact_blocker=" — ".join(filter(None, (
                str(blocker.get("summary") or ""), str(blocker.get("observed_output") or ""),
            ))),
            allow_max=True,
        )
        max_lane = _lane(swarm, packet["lane_id"])
        max_lane["context"]["directed"]["actual_attacks"] = [
            {
                "type": row.get("type"), "summary": row.get("summary"),
                "command": row.get("command"), "observed_output": row.get("observed_output"),
            }
            for row in qualification["attacks"][-2:]
        ]
        lease_deadline = min(_parse_time(str(swarm["deadline"])), current + timedelta(minutes=10))
        max_lane.update({
            "lease_deadline": _timestamp(lease_deadline), "endgame_attacks": 0,
        })
        packet = _packet_for_lane(swarm, max_lane)
        swarm["updated_at"] = utc_now()
        _append_event_unlocked(run, swarm, {
            "type": "STOPPED", "lane": lane_id, "summary": "replaced by bounded Sol max",
            "observed_output": _short(str(blocker.get("observed_output") or ""), 4000) or None,
        }, best_effort=True)
        _write_swarm(run, swarm)
        _sync_width(run, swarm)
    return {
        "stopped_worker": lane_id, "max_worker": packet["lane_id"],
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
        if swarm.get("winner"):
            return _winner_result(swarm, challenge_key, idempotent=True)
        if swarm.get("status") in TERMINAL_STATUSES:
            raise SwarmError("terminal worker state cannot accept a flag candidate")
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
        swarm["winner"] = {
            "lane": lane_id, "native_session": lane.get("native_session"),
            "candidate": candidate, "receipt": str(receipt_path.relative_to(run)),
            "found_at": receipt["created_at"], "source": receipt["source"],
        }
        swarm["status"] = "FLAG_FOUND"
        cancel = []
        for other in swarm["lanes"]:
            if other.get("id") != lane_id and other.get("status") in {"RUNNING", "CANCEL_REQUIRED"}:
                other["status"] = "CANCEL_REQUIRED"
                cancel.append({"lane": other["id"], "native_session": other.get("native_session")})
            elif other.get("status") == "PENDING_SPAWN":
                other["status"] = "STOPPED"
                other["stop_reason"] = "first valid flag won"
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
            raise SwarmError("stop receipt does not match the worker native session")
        if lane.get("status") == "STOPPED":
            return {"lane": lane_id, "native_session": native_session, "status": "STOPPED", "idempotent": True}
        lane.update({"status": "STOPPED", "stopped_at": utc_now()})
        _write_swarm(run, swarm)
        _sync_width(run, swarm)
    return {"lane": lane_id, "native_session": native_session, "status": "STOPPED", "idempotent": False}


def submission_result(run: Path, *, candidate: str, result: str) -> dict[str, Any]:
    """Record human feedback without allowing two challenges to become active."""

    run = _run_root(run)
    output_root = _machine_output_root(run)
    lock = (
        state_lock(output_root)
        if result.strip().upper() == "WRONG" and output_root is not None
        else nullcontext()
    )
    with lock:
        if result.strip().upper() == "WRONG" and output_root is not None:
            _assert_no_other_active_solve(output_root, run, now=None)
        return _record_submission_result(run, candidate=candidate, result=result)


def _record_submission_result(run: Path, *, candidate: str, result: str) -> dict[str, Any]:
    """Record only the human oracle; never contact a scoreboard or force a worker."""

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
        cancel_queue = []
        if normalized == "ACCEPTED":
            swarm["status"] = "ACCEPTED"
            for lane in swarm["lanes"]:
                if lane.get("status") in {"RUNNING", "CANCEL_REQUIRED"} and lane.get("native_session"):
                    lane["status"] = "CANCEL_REQUIRED"
                    cancel_queue.append({"lane": lane["id"], "native_session": lane["native_session"]})
            state.update({
                "status": "ACCEPTED", "competition_state": "ACCEPTED",
                "submission_recommended": False, "sealed": True,
            })
        else:
            swarm["winner"] = None
            swarm["status"] = "ACTIVE"
            state.update({
                "status": "SWARM_ACTIVE", "competition_state": "SOLVING",
                "flag_candidate": None, "submission_recommended": False,
            })
        swarm["updated_at"] = utc_now()
        state["updated_at"] = utc_now()
        _write_swarm(run, swarm)
        atomic_json(run / "STATE.json", state)
    return {
        "result": normalized, "candidate": candidate,
        "worker_spawn_available": normalized == "WRONG",
        "root_attack_continues": normalized == "WRONG",
        "cancel_queue": cancel_queue, "automatic_submission": False,
    }


def terminate_for_handoff(run: Path) -> dict[str, Any]:
    """End the Solve in state and return native children Root must interrupt."""

    run = _run_root(run)
    with state_lock(run):
        cancel_queue = []
        path = run / "SWARM.json"
        if path.is_file() and not path.is_symlink():
            swarm = _load_swarm(run)
            for lane in swarm["lanes"]:
                if lane.get("status") in {"RUNNING", "CANCEL_REQUIRED"} and lane.get("native_session"):
                    lane["status"] = "CANCEL_REQUIRED"
                    cancel_queue.append({"lane": lane["id"], "native_session": lane["native_session"]})
                elif lane.get("status") == "PENDING_SPAWN":
                    lane["status"] = "STOPPED"
                    lane["stop_reason"] = "manual Claude handoff"
            swarm["root_lane"]["status"] = "STOPPED"
            swarm["status"] = "HANDOFF"
            swarm["updated_at"] = utc_now()
            _write_swarm(run, swarm)
        state = _read_object(run / "STATE.json", "run state")
        state.update({
            "status": "HANDOFF", "competition_state": "HANDOFF",
            "submission_recommended": False, "updated_at": utc_now(),
        })
        atomic_json(run / "STATE.json", state)
    return {"status": "HANDOFF", "cancel_queue": cancel_queue, "automatic_continuation": False}


def worker_status(run: Path, *, now: datetime | None = None) -> dict[str, Any]:
    """Return compact worker/output state for Root's keep, stop, or replace judgment."""

    run = _run_root(run)
    current = _as_utc(now)
    with state_lock(run):
        swarm = _load_swarm(run)
        cutoff = _apply_deadline_unlocked(run, swarm, now=current)
        events = _read_events(run)
        endgame_cancel_queue = []
        for lane in swarm["lanes"]:
            if (
                lane.get("model_profile") == "sol-max" and lane.get("status") == "RUNNING"
                and lane.get("lease_deadline")
                and current >= _parse_time(str(lane["lease_deadline"]))
            ):
                lane["status"] = "CANCEL_REQUIRED"
                lane["cancel_reason"] = "bounded Sol max lease expired"
                endgame_cancel_queue.append({"lane": lane["id"], "native_session": lane.get("native_session")})
        if endgame_cancel_queue:
            swarm["updated_at"] = utc_now()
            _write_swarm(run, swarm)
            _sync_width(run, swarm)
        elapsed = max(0, int((current - _parse_time(str(swarm["started_at"]))).total_seconds()))
        max_candidates = []
        if (
            ENDGAME_SECONDS <= elapsed < DEFAULT_BUDGET_SECONDS
            and not any(row.get("model_profile") == "sol-max" for row in swarm["lanes"])
        ):
            for lane in swarm["lanes"]:
                if lane.get("status") != "RUNNING":
                    continue
                lane_events = [row for row in events if row.get("lane") == lane.get("id")]
                if _endgame_qualification(lane_events) is not None:
                    max_candidates.append(str(lane["id"]))
                    break
        workers = [
            _worker_status_row(lane, [row for row in events if row.get("lane") == lane.get("id")])
            for lane in swarm["lanes"]
        ]
        return {
            "schema_version": swarm["schema_version"], "run_id": swarm["run_id"],
            "challenge_id": swarm["challenge_id"], "status": swarm["status"],
            "started_at": swarm["started_at"], "deadline": swarm["deadline"],
            "elapsed_seconds": elapsed, "root_lane": dict(swarm["root_lane"]),
            "workers": workers,
            "native_children_running": _live_native_children(swarm),
            "maximum_native_concurrency": MAX_NATIVE_CONCURRENCY,
            "max_endgame_candidates": max_candidates,
            "endgame_cancel_queue": endgame_cancel_queue,
            "winner": swarm.get("winner"), "cutoff": cutoff,
        }


def high_value_events(run: Path, *, since: str | None = None) -> list[dict[str, Any]]:
    rows = [row for row in _read_events(_run_root(run)) if row.get("type") in SHAREABLE_EVENTS]
    if since:
        rows = [row for row in rows if str(row.get("created_at")) > since]
    return rows


def _add_worker_unlocked(
    run: Path,
    swarm: dict[str, Any],
    *,
    model_profile: str,
    role: str,
    task: str,
    context_mode: str,
    facts: Sequence[str],
    failure_command: Sequence[str],
    failure_output: str | None,
    artifact: str | None,
    exact_blocker: str | None,
    allow_max: bool,
) -> dict[str, Any]:
    if swarm.get("status") in TERMINAL_STATUSES:
        raise SwarmError("terminal worker state cannot create another child packet")
    if model_profile not in MODEL_PROFILES or (model_profile == "sol-max" and not allow_max):
        allowed = ", ".join(GENERAL_MODEL_PROFILES)
        raise SwarmError(f"model_profile must be one of: {allowed}")
    if sum(row.get("status") in ACTIVE_WORKER_STATUSES for row in swarm["lanes"]) >= MAX_NATIVE_CHILDREN:
        raise SwarmError("worker capacity is Root plus at most three native children")
    role = _text(role, "role", 120)
    task = _text(task, "task", 4000)
    context_mode = context_mode.strip().casefold()
    if context_mode not in {"fresh", "directed"}:
        raise SwarmError("context_mode must be fresh or directed")
    lane_id = _next_lane_id(swarm, model_profile)
    worker_paths = _worker_paths(run, lane_id, swarm["challenge_context"])
    for key in ("work", "evidence", "artifacts"):
        Path(worker_paths[key]).mkdir(parents=True, exist_ok=True)
    context = dict(swarm["challenge_context"])
    if context_mode == "directed":
        directed: dict[str, Any] = {}
        bounded_facts = [_short(str(value), 1000) for value in facts[:16] if str(value).strip()]
        if bounded_facts:
            directed["facts"] = bounded_facts
        command = [_short(str(value), 1000) for value in failure_command[:64]]
        output = _short(failure_output or "", 4000)
        if command or output:
            directed["actual_failure"] = {"command": command, "output": output or None}
        relative_artifact = _relative_artifact(run, artifact)
        if relative_artifact:
            directed["artifact"] = relative_artifact
        blocker = _short(exact_blocker or "", 2000)
        if blocker:
            directed["exact_blocker"] = blocker
        if directed:
            context["directed"] = directed
    lane = {
        "id": lane_id, "model_profile": model_profile, "role": role, "task": task,
        "context_mode": context_mode, "context": context, "worker_paths": worker_paths,
        "deadline": swarm["deadline"], "native_session": None,
        "status": "PENDING_SPAWN", "spawn_attempts": 0,
    }
    swarm["lanes"].append(lane)
    return _packet_for_lane(swarm, lane)


def _packet_for_lane(swarm: Mapping[str, Any], lane: Mapping[str, Any]) -> dict[str, Any]:
    profile = MODEL_PROFILES[str(lane["model_profile"])]
    message = _worker_message(
        lane=lane, root_session=str(swarm["root_session"]), contract=profile["contract"],
    )
    packet = {
        "lane_id": lane["id"], "model_profile": lane["model_profile"],
        "role": lane["role"], "task": lane["task"], "context_mode": lane["context_mode"],
        "challenge_context": dict(lane["context"]),
        "worker_paths": dict(lane["worker_paths"]), "deadline": lane["deadline"],
        "agent_profile": profile["agent_profile"],
        "model_request": {"model": profile["model"], "reasoning_effort": profile["reasoning_effort"]},
        "spawn_agent_args": {
            "task_name": str(lane["id"]).replace("-", "_"),
            "fork_turns": "none", "message": message,
        },
    }
    if lane.get("lease_deadline"):
        packet["lease"] = {
            "deadline": lane["lease_deadline"], "maximum_actual_attacks": 2,
        }
    return packet


def _worker_message(
    *, lane: Mapping[str, Any], root_session: str, contract: str,
) -> str:
    return (
        "You are a native child in an authorized one-challenge CTF first-to-flag solve.\n"
        f"Lane: {lane['id']}\nModel profile: {lane['model_profile']}\nRole: {lane['role']}\n"
        f"Task: {lane['task']}\nContext mode: {lane['context_mode']}\n"
        f"Deadline: {lane['deadline']}\nRoot session: {root_session}\n"
        f"Challenge context: {json.dumps(dict(lane['context']), ensure_ascii=False)}\n"
        f"Worker-private paths: {json.dumps(dict(lane['worker_paths']), ensure_ascii=False)}\n"
        f"Role contract: {contract}\n"
        "Use actual tools immediately and report only actual commands, an executable artifact, "
        "a primitive, working PoC, remote result, useful failure, exact blocker, or flag candidate. "
        "The challenge input is read-only. Write only to your private paths. Never attack an "
        "undeclared target, access host/personal credentials or files, or submit a flag."
    )


def _problem_context(challenge: Any, record: Mapping[str, object]) -> dict[str, Any]:
    return {
        "name": str(getattr(challenge, "name", "")),
        "category": str(getattr(challenge, "category", "misc")),
        "description": getattr(challenge, "description", None),
        "hint": getattr(challenge, "hint", None),
        "flag_format": getattr(challenge, "flag_format", None),
        "flag_pattern": getattr(challenge, "flag_pattern", None),
        "prepared_input": str(record.get("prepared_input") or ""),
        "declared_remote": list(getattr(challenge, "remotes", ()) or ()),
    }


def _worker_paths(run: Path, lane_id: str, context: Mapping[str, Any]) -> dict[str, Any]:
    root = run / "workers" / lane_id
    return {
        "input": str(context.get("prepared_input") or ""), "input_read_only": True,
        "metadata_path": str(root / "sandbox.json"), "work": str(root / "work"),
        "evidence": str(root / "evidence"), "artifacts": str(root / "artifacts"),
    }


def _next_lane_id(swarm: Mapping[str, Any], model_profile: str) -> str:
    prefix = model_profile.split("-", 1)[0]
    used = {str(row.get("id")) for row in swarm.get("lanes", [])}
    number = 1
    while f"{prefix}-{number}" in used:
        number += 1
    return f"{prefix}-{number}"


def _endgame_qualification(events: Sequence[Mapping[str, Any]]) -> dict[str, Any] | None:
    attacks = [
        row for row in events
        if row.get("type") in {"EXPLOIT_ATTEMPTED", "REMOTE_ATTEMPT"}
        and bool(row.get("command")) and bool(row.get("observed_output"))
    ]
    partial = next((
        row for row in reversed(events)
        if row.get("type") in {"ATTACK_PATH_FOUND", "PRIMITIVE", "POC", "WORKING_POC"}
        and (bool(row.get("artifact")) or (bool(row.get("command")) and bool(row.get("observed_output"))))
    ), None)
    blocker = next((row for row in reversed(events) if row.get("type") == "BLOCKER"), None)
    if len(attacks) < 2 or partial is None or blocker is None:
        return None
    blocker_text = " ".join(str(blocker.get(key) or "") for key in ("summary", "observed_output")).strip()
    next_attack = str(blocker.get("next_attack") or "").strip()
    if not blocker_text or not next_attack:
        return None
    if any(word in blocker_text.casefold() for word in ENVIRONMENT_BLOCKERS):
        return None
    return {"attacks": attacks, "partial": partial, "blocker": blocker}


def _worker_status_row(lane: Mapping[str, Any], events: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    actual = [
        row for row in events
        if row.get("type") in {"COMMAND_EXECUTED", "EXPLOIT_ATTEMPTED", "REMOTE_ATTEMPT"}
        and bool(row.get("command"))
    ]
    valuable = [row for row in events if row.get("type") in HIGH_VALUE_EVENTS]
    last = events[-1] if events else None
    return {
        **_public_worker(lane),
        "actual_command_count": len(actual), "high_value_output_count": len(valuable),
        "last_event": _compact_event(last) if last else None,
    }


def _compact_event(event: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: event.get(key)
        for key in ("type", "summary", "command", "artifact", "observed_output", "next_attack", "created_at")
        if event.get(key) not in (None, [], "")
    }


def _public_worker(lane: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: lane.get(key)
        for key in (
            "id", "model_profile", "role", "task", "context_mode", "status",
            "native_session", "spawn_attempts", "last_error", "cancel_reason",
            "lease_deadline", "endgame_attacks",
        )
        if lane.get(key) is not None
    }


def _public_swarm(swarm: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": swarm["schema_version"], "run_id": swarm["run_id"],
        "challenge_id": swarm["challenge_id"], "attempt_id": swarm.get("attempt_id"),
        "challenge_instance_id": swarm.get("challenge_instance_id"),
        "started_at": swarm["started_at"], "deadline": swarm["deadline"],
        "budget_seconds": swarm["budget_seconds"], "status": swarm["status"],
        "root_lane": dict(swarm["root_lane"]), "challenge_context": dict(swarm["challenge_context"]),
        "workers": [_public_worker(row) for row in swarm["lanes"]],
        "native_children_running": _live_native_children(swarm),
        "maximum_native_concurrency": MAX_NATIVE_CONCURRENCY,
        "winner": swarm.get("winner"), "root_direct_attack_required": True,
    }


def _apply_deadline_unlocked(
    run: Path, swarm: dict[str, Any], *, now: datetime | None = None,
) -> dict[str, Any] | None:
    current = _as_utc(now)
    if current < _parse_time(str(swarm["deadline"])):
        return None
    if swarm.get("status") in TERMINAL_STATUSES:
        return None
    events = _read_events(run)
    cancel = []
    for lane in swarm["lanes"]:
        if lane.get("status") in {"RUNNING", "CANCEL_REQUIRED"}:
            lane["status"] = "CANCEL_REQUIRED"
            cancel.append({"lane": lane["id"], "native_session": lane.get("native_session")})
        elif lane.get("status") == "PENDING_SPAWN":
            lane["status"] = "STOPPED"
            lane["stop_reason"] = "90-minute cutoff"
    swarm["status"] = "TIMED_OUT"
    swarm["updated_at"] = _timestamp(current)
    leading = next((
        row for row in reversed(events)
        if row.get("type") in {"WORKING_POC", "POC", "PRIMITIVE", "ATTACK_PATH_FOUND"}
    ), None)
    blocker = next((row for row in reversed(events) if row.get("type") == "BLOCKER"), None)
    executed = [
        row for row in events
        if row.get("type") in {"COMMAND_EXECUTED", "EXPLOIT_ATTEMPTED", "REMOTE_ATTEMPT"}
    ]
    handoff = [
        f"# Solve timeout — {swarm.get('challenge_id')}", "",
        f"- Run: `{swarm.get('run_id')}`", f"- Deadline: `{swarm.get('deadline')}`",
        f"- Leading attack path: {leading.get('summary') if leading else 'none established'}",
        f"- Exact blocker: {blocker.get('summary') if blocker else 'none recorded'}", "",
        "## Executed attacks", "",
    ]
    for row in executed[-20:]:
        handoff.append(f"- `{row.get('lane')}`: {row.get('command') or row.get('summary')}")
    handoff.extend([
        "", "## Next attack", "",
        str((blocker or leading or {}).get("next_attack") or "Run one fresh executable attack family."), "",
    ])
    path = run / "artifacts" / "TIMEOUT_HANDOFF.md"
    atomic_text(path, "\n".join(handoff))
    _write_swarm(run, swarm)
    state = _read_object(run / "STATE.json", "run state")
    state.update({"status": "TIMED_OUT", "submission_recommended": False, "updated_at": utc_now()})
    atomic_json(run / "STATE.json", state)
    return {"cancel_queue": cancel, "handoff": str(path), "automatic_extension": False}


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
    state["active_child_width"] = _live_native_children(swarm)
    state["updated_at"] = utc_now()
    atomic_json(run / "STATE.json", state)


def _live_native_children(swarm: Mapping[str, Any]) -> int:
    return sum(
        bool(row.get("native_session")) and row.get("status") in {"RUNNING", "CANCEL_REQUIRED"}
        for row in swarm["lanes"]
    )


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
    swarm = _read_object(run / "SWARM.json", "worker state")
    state = _read_object(run / "STATE.json", "run state")
    _assert_identity(swarm, state)
    _assert_schema(swarm)
    return swarm


def _assert_no_other_active_solve(
    output_root: Path, run: Path, *, now: datetime | None,
) -> None:
    current = _as_utc(now)
    selected = _read_object(run / "STATE.json", "selected run state")
    for path in output_root.rglob("SWARM.json"):
        if path.parent.parent.name != "runs" or path.parent == run:
            continue
        if path.is_symlink() or not path.is_file():
            raise SwarmError("another solve has an unsafe worker state path")
        other = _read_object(path, "other active worker state")
        if other.get("status") in TERMINAL_STATUSES:
            continue
        deadline = other.get("deadline")
        if deadline and current >= _parse_time(str(deadline)):
            continue
        if other.get("challenge_id") == selected.get("challenge_id") and _live_native_children(other) == 0:
            for lane in other.get("lanes", []):
                if lane.get("status") == "PENDING_SPAWN":
                    lane["status"] = "STOPPED"
                    lane["stop_reason"] = "new isolated attempt for the same challenge"
            if isinstance(other.get("root_lane"), dict):
                other["root_lane"]["status"] = "STOPPED"
            other["status"] = "SUPERSEDED"
            other["updated_at"] = utc_now()
            atomic_json(path, other)
            other_state_path = path.parent / "STATE.json"
            other_state = _read_object(other_state_path, "superseded run state")
            other_state.update({"status": "SUPERSEDED", "updated_at": utc_now()})
            atomic_json(other_state_path, other_state)
            continue
        raise SwarmError(
            "another challenge attempt already owns this machine: "
            f"{other.get('challenge_id') or path.parent.name}"
        )


def _machine_output_root(run: Path) -> Path | None:
    return next((parent for parent in run.parents if parent.name == "output"), None)


def _assert_schema(swarm: Mapping[str, Any]) -> None:
    if swarm.get("schema_version") != SWARM_SCHEMA_VERSION:
        raise SwarmError("worker state uses an unsupported engine schema")


def _assert_identity(swarm: Mapping[str, Any], state: Mapping[str, Any]) -> None:
    for field in ("run_id", "challenge_id", "input_fingerprint"):
        if swarm.get(field) != state.get(field):
            raise SwarmError(f"worker state {field} does not match the exact attempt")


def _lane(swarm: Mapping[str, Any], lane_id: str) -> dict[str, Any]:
    matches = [row for row in swarm.get("lanes", []) if row.get("id") == lane_id]
    if len(matches) != 1:
        raise SwarmError("worker does not exist in this attempt")
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
        raise SwarmError("worker timestamp is malformed") from exc
