"""Verified asynchronous portfolio race state and lane lifecycle."""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .blackboard import (
    HIGH_VALUE_TYPES,
    duplicate_signals,
    events,
    shared_artifacts,
    verified_delta,
)
from .contest import ContestError, compile_flag_pattern
from .sandbox.session import session_liveness
from .workspace import atomic_json, read_json, state_lock, utc_now

RACE_SCHEMA_VERSION = 2
MAX_CONCURRENCY = 4
MAX_CHILDREN = 3
RACE_SECONDS = 90 * 60
LANE_STATES = frozenset({
    "PREPARED", "RUNNING", "EXECUTING", "PRIMITIVE_FOUND", "BUILDING_EXPLOIT",
    "REMOTE_TESTING", "STAGNANT", "CANCEL_REQUIRED", "STOPPING",
    "CLEANUP_FAILED", "STOPPED", "WON",
})
NON_EXECUTING_LANE_STATES = frozenset({
    "STOPPING", "CLEANUP_FAILED", "STOPPED", "WON",
})
TERMINAL_STATUSES = frozenset({"WON", "TIMED_OUT", "HANDOFF", "STOPPED"})
MODEL_PROFILES = frozenset({
    "sol-ultra", "sol-max", "sol-xhigh", "terra-high", "luna-high",
})
ROOT_MODEL_PROFILES = frozenset({"sol-ultra", "sol-max", "sol-xhigh"})
REMOTE_EXECUTION_MODES = frozenset({"agent", "human-relay"})
SPAWN_CONFIGS: dict[str, dict[str, str]] = {
    "sol-ultra": {
        "agent_type": "default",
        "model": "gpt-5.6-sol",
        "reasoning_effort": "ultra",
    },
    "sol-xhigh": {"agent_type": "ctf_sol_xhigh"},
    "terra-high": {"agent_type": "ctf_terra_high"},
    "luna-high": {"agent_type": "ctf_luna_high"},
    "sol-max": {"agent_type": "ctf_sol_max"},
}
TIMESTAMP_FIELDS = (
    "challenge_selected_at", "input_ready_at", "root_sandbox_ready_at",
    "root_first_command_at", "worker_spawn_requested_at", "worker_first_command_at",
    "first_primitive_at", "first_remote_attempt_at", "first_flag_candidate_at",
)


class RaceError(ValueError):
    pass


def initialize_race(
    run_root: Path,
    *,
    run_manifest: Mapping[str, Any],
    input_record: Mapping[str, Any],
    image: Mapping[str, Any],
    service: Mapping[str, Any],
    selected_at: str,
    input_ready_at: str,
    root_model_profile: str = "sol-ultra",
    root_model_profile_source: str = "policy-default",
    service_isolation: str = "per-lane",
    remote_execution: str = "agent",
) -> dict[str, Any]:
    if root_model_profile not in ROOT_MODEL_PROFILES:
        raise RaceError(
            "root model profile must be sol-ultra, sol-max, or sol-xhigh"
        )
    if root_model_profile_source not in {"explicit-cli", "policy-default"}:
        raise RaceError("root model profile source is invalid")
    if service_isolation not in {"per-lane", "shared"}:
        raise RaceError("service isolation must be per-lane or shared")
    if remote_execution not in REMOTE_EXECUTION_MODES:
        raise RaceError("remote execution must be agent or human-relay")
    now = _parse_time(input_ready_at)
    challenge = dict(run_manifest["challenge"])
    try:
        compile_flag_pattern(challenge.get("flag_pattern"))
    except ContestError as exc:
        raise RaceError(str(exc)) from exc
    lease = lease_seconds(str(challenge["category"]))
    state: dict[str, Any] = {
        "schema_version": RACE_SCHEMA_VERSION,
        "run_id": run_manifest["run_id"],
        "attempt_id": run_manifest["attempt_id"],
        "challenge_instance_id": run_manifest["challenge_instance_id"],
        "contest": dict(run_manifest["contest"]),
        "challenge": challenge,
        "input_fingerprint": run_manifest["input_fingerprint"],
        "prepared_input": input_record["prepared_input"],
        "priority_files": list(input_record.get("priority_files", [])),
        "declared_targets": list(input_record.get("declared_targets", [])),
        "flag_pattern": challenge.get("flag_pattern"),
        "selected_image": image.get("selected_image"),
        "image_status": image.get("status"),
        "service_endpoints": list(service.get("endpoints", [])),
        "service_network": service.get("network"),
        "service_context": dict(service),
        "service_isolation": service_isolation,
        "remote_execution": remote_execution,
        "service_instances": {},
        "status": "PREPARING",
        "attack_ready": False,
        "started_at": selected_at,
        "deadline": (now + timedelta(seconds=RACE_SECONDS)).isoformat(),
        "lease_seconds": lease,
        "winner": None,
        "lanes": [{
            "lane_id": "root",
            "model_profile": root_model_profile,
            "model_profile_source": root_model_profile_source,
            "role": "lead-attacker",
            "task": "execute the highest-probability attack immediately",
            "context_mode": "root",
            "attack_family": "root-primary",
            "status": "PREPARED",
            "sandbox": None,
            "native_session": None,
            "prepared_at": input_ready_at,
            "lease_seconds": lease,
            "status_checks_without_command": 0,
            "last_status_command_count": 0,
        }],
        "timestamps": {field: None for field in TIMESTAMP_FIELDS},
    }
    state["timestamps"]["challenge_selected_at"] = selected_at
    state["timestamps"]["input_ready_at"] = input_ready_at
    atomic_json(run_root / "RACE.json", state)
    return state


def mark_root_ready(run_root: Path, sandbox: Mapping[str, Any]) -> dict[str, Any]:
    with state_lock(run_root):
        race = load_race(run_root)
        root = _lane(race, "root")
        _validate_sandbox_identity(race, root, sandbox)
        root["sandbox"] = dict(sandbox)
        root["status"] = "RUNNING"
        race["status"] = "ACTIVE"
        race["attack_ready"] = True
        race["timestamps"]["root_sandbox_ready_at"] = str(sandbox.get("created_at") or utc_now())
        _write(run_root, race)
        return race


def set_service_context(run_root: Path, service: Mapping[str, Any]) -> dict[str, Any]:
    with state_lock(run_root):
        race = load_race(run_root)
        if race["status"] != "PREPARING":
            raise RaceError("service context is fixed before the Root sandbox starts")
        race["service_endpoints"] = list(service.get("endpoints", []))
        race["service_network"] = service.get("network")
        race["service_status"] = service.get("status")
        race["service_context"] = dict(service)
        if service.get("status") in {"READY", "CLEANUP_FAILED"}:
            race["service_instances"]["root"] = {
                "status": service.get("status"),
                "instance_id": service.get("instance_id", "root"),
                "network": service.get("network"),
                "endpoints": list(service.get("endpoints", [])),
                "metadata_path": service.get("metadata_path"),
            }
        _write(run_root, race)
        return race


def set_lane_service_context(
    run_root: Path,
    *,
    lane_id: str,
    service: Mapping[str, Any],
) -> dict[str, Any]:
    """Attach one Root-created private challenge-service instance to a lane."""

    with state_lock(run_root):
        race = load_race(run_root)
        lane = _lane(race, lane_id)
        if lane_id == "root":
            raise RaceError("use set_service_context for Root")
        if lane["status"] != "PREPARED" or lane.get("sandbox") is not None:
            raise RaceError("lane service context is fixed before its sandbox starts")
        if race.get("service_isolation") != "per-lane":
            raise RaceError("private lane service requires per-lane isolation")
        if service.get("status") != "READY":
            raise RaceError("private lane service is not READY")
        if service.get("instance_id") != lane_id:
            raise RaceError("private service instance does not match its lane")
        race["service_instances"][lane_id] = {
            "status": "READY",
            "instance_id": lane_id,
            "network": service.get("network"),
            "endpoints": list(service.get("endpoints", [])),
            "metadata_path": service.get("metadata_path"),
        }
        _write(run_root, race)
        return dict(race["service_instances"][lane_id])


def mark_prepare_failed(run_root: Path, reason: str) -> dict[str, Any]:
    with state_lock(run_root):
        race = load_race(run_root)
        race["status"] = "STOPPED"
        race["attack_ready"] = False
        race["prepare_blocker"] = reason[:4096]
        race["ended_at"] = utc_now()
        _lane(race, "root")["status"] = "STOPPED"
        _write(run_root, race)
        return race


def reserve_lanes(run_root: Path, specifications: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if not specifications or len(specifications) > MAX_CHILDREN:
        raise RaceError("race-bootstrap requires one to three lane specifications")
    normalized = [_normalize_specification(row) for row in specifications]
    if len({row["attack_family"] for row in normalized}) != len(normalized):
        raise RaceError("bootstrap lanes must use distinct attack_family values")
    with state_lock(run_root):
        race = load_race(run_root)
        _require_active(race)
        root_receipts = _receipts(run_root, "root")
        if not root_receipts:
            raise RaceError(
                "race-bootstrap requires Root to complete and record an actual "
                "sandbox attack command first"
            )
        if race["timestamps"].get("root_first_command_at") is None:
            first_finished_at = str(root_receipts[0].get("finished_at") or "")
            _parse_time(first_finished_at)
            race["timestamps"]["root_first_command_at"] = first_finished_at
        active = [
            lane for lane in race["lanes"]
            if lane["lane_id"] != "root" and lane["status"] != "STOPPED"
        ]
        if len(active) + len(normalized) > MAX_CHILDREN:
            raise RaceError("Root plus native children may not exceed concurrency four")
        used_families = {str(lane["attack_family"]) for lane in race["lanes"]}
        overlap = used_families.intersection(str(row["attack_family"]) for row in normalized)
        if overlap:
            raise RaceError(f"attack_family already used in this race: {', '.join(sorted(overlap))}")
        next_number = max(
            [int(match.group(1)) for lane in race["lanes"] if (match := re.fullmatch(r"lane-(\d+)", str(lane["lane_id"])))],
            default=0,
        )
        now = utc_now()
        reserved: list[dict[str, Any]] = []
        for offset, row in enumerate(normalized, 1):
            lane = dict(row) | {
                "lane_id": f"lane-{next_number + offset}",
                "status": "PREPARED",
                "sandbox": None,
                "native_session": None,
                "prepared_at": now,
                "lease_seconds": race["lease_seconds"],
                "status_checks_without_command": 0,
                "last_status_command_count": 0,
            }
            race["lanes"].append(lane)
            reserved.append(dict(lane))
        if race["timestamps"]["worker_spawn_requested_at"] is None:
            race["timestamps"]["worker_spawn_requested_at"] = now
        _write(run_root, race)
        return reserved


def reserve_max_endgame(
    run_root: Path,
    *,
    replaced_lane_id: str,
    task: str,
    attack_family: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Reserve the one bounded Max lane only from an executable endgame state."""

    current = now or datetime.now(UTC)
    if not task.strip() or len(task) > 4096:
        raise RaceError("Sol max requires one bounded concrete next attack")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", attack_family):
        raise RaceError("Sol max attack_family must be a bounded lowercase identifier")
    with state_lock(run_root):
        race = load_race(run_root)
        _require_active(race)
        if (current - _parse_time(str(race["started_at"]))).total_seconds() < 60 * 60:
            raise RaceError("Sol max is unavailable before minute 60")
        if any(lane.get("model_profile") == "sol-max" for lane in race["lanes"]):
            raise RaceError("this race already used its one Sol max lane")
        replaced = _lane(race, replaced_lane_id)
        if replaced_lane_id == "root" or replaced.get("status") != "STOPPED":
            raise RaceError("Sol max must replace one confirmed-stopped native child")
        ledger = events(run_root)
        working = [row for row in ledger if row.get("event_type") == "WORKING_POC" and row.get("artifact_hash")]
        actual_attacks = {
            row.get("receipt_id") for row in ledger
            if row.get("event_type") in {"WORKING_POC", "REMOTE_RESULT"}
        }
        blockers = [row for row in ledger if row.get("event_type") == "EXACT_BLOCKER"]
        blocker = blockers[-1] if blockers else None
        environment_words = (
            "environment", "dependency", "docker", "image", "network", "connection",
            "rate limit", "target down", "tool missing", "permission",
        )
        if not working:
            raise RaceError("Sol max requires an executable partial path with an artifact")
        if len(actual_attacks) < 2:
            raise RaceError("Sol max requires two actual attack outputs")
        if blocker is None or any(word in str(blocker.get("observed_output", "")).casefold() for word in environment_words):
            raise RaceError("Sol max requires an exact non-environment reasoning blocker")
        if attack_family in {str(lane["attack_family"]) for lane in race["lanes"]}:
            raise RaceError("Sol max requires a new attack_family")
        next_number = max(
            [int(match.group(1)) for lane in race["lanes"] if (match := re.fullmatch(r"lane-(\d+)", str(lane["lane_id"])))],
            default=0,
        )
        lane = {
            "lane_id": f"lane-{next_number + 1}",
            "model_profile": "sol-max",
            "role": "bounded-endgame-attacker",
            "task": task.strip(),
            "context_mode": "directed",
            "attack_family": attack_family,
            "status": "PREPARED",
            "sandbox": None,
            "native_session": None,
            "prepared_at": current.isoformat(),
            "lease_seconds": 600,
            "max_actual_attacks": 2,
            "replaces_lane_id": replaced_lane_id,
            "status_checks_without_command": 0,
            "last_status_command_count": 0,
        }
        race["lanes"].append(lane)
        _write(run_root, race)
        return dict(lane)


def attach_lane_sandbox(
    run_root: Path,
    *,
    lane_id: str,
    sandbox: Mapping[str, Any],
) -> dict[str, Any]:
    with state_lock(run_root):
        race = load_race(run_root)
        lane = _lane(race, lane_id)
        if lane_id == "root":
            raise RaceError("use mark_root_ready for Root")
        if lane["status"] != "PREPARED" or lane.get("sandbox") is not None:
            raise RaceError("lane sandbox can only be attached once while PREPARED")
        _validate_sandbox_identity(race, lane, sandbox)
        lane["sandbox"] = dict(sandbox)
        packet = _spawn_packet(run_root, race, lane)
        lane["spawn_agent_args"] = packet["spawn_agent_args"]
        _write(run_root, race)
        return packet


def mark_lane_prepare_failed(
    run_root: Path,
    *,
    lane_id: str,
    reason: str,
    cleanup_failed: bool = False,
) -> dict[str, Any]:
    with state_lock(run_root):
        race = load_race(run_root)
        lane = _lane(race, lane_id)
        lane["status"] = "CLEANUP_FAILED" if cleanup_failed else "STOPPED"
        lane["exact_blocker"] = reason[:4096]
        now = utc_now()
        if cleanup_failed:
            lane["cleanup_error"] = reason[:4096]
            lane["cleanup_failed_at"] = now
            lane["cleanup_attempts"] = int(lane.get("cleanup_attempts", 0)) + 1
        else:
            lane["stopped_at"] = now
        instance = race.get("service_instances", {}).get(lane_id)
        if isinstance(instance, dict):
            instance["status"] = "CLEANUP_FAILED" if cleanup_failed else "STOPPED"
            instance[
                "cleanup_failed_at" if cleanup_failed else "stopped_at"
            ] = now
        _write(run_root, race)
        return dict(lane)


def begin_lane_cleanup_retry(run_root: Path, *, lane_id: str) -> dict[str, Any]:
    """Retry controller cleanup for a lane whose native thread is already absent."""

    with state_lock(run_root):
        race = load_race(run_root)
        lane = _lane(race, lane_id)
        if lane_id == "root" or lane["status"] != "CLEANUP_FAILED":
            raise RaceError("lane cleanup retry requires a child in CLEANUP_FAILED")
        lane["status"] = "STOPPING"
        lane["cleanup_attempts"] = int(lane.get("cleanup_attempts", 0)) + 1
        _write(run_root, race)
        return dict(lane)


def confirm_native_spawn(run_root: Path, *, lane_id: str, native_session: str) -> dict[str, Any]:
    if not _valid_native_session(native_session):
        raise RaceError("native session identity is invalid")
    with state_lock(run_root):
        race = load_race(run_root)
        lane = _lane(race, lane_id)
        if any(
            row.get("native_session") == native_session
            for row in race.get("lanes", [])
            if row.get("lane_id") != lane_id
        ):
            raise RaceError("native session identity is already attached to another lane")
        attached = lane.get("native_session")
        if attached is not None:
            if attached != native_session:
                raise RaceError("lane is already attached to a different native session")
            return dict(lane)
        if (
            lane["status"] in {"STOPPING", "CLEANUP_FAILED", "STOPPED"}
            or not isinstance(lane.get("sandbox"), Mapping)
        ):
            raise RaceError("native spawn requires a prepared, READY private sandbox")
        if lane["sandbox"].get("status") != "READY":
            raise RaceError("native spawn requires a READY private sandbox")
        lane["native_session"] = native_session
        if lane["status"] == "PREPARED":
            lane["status"] = "RUNNING"
        if lane.get("spawned_at") is None:
            lane["spawned_at"] = utc_now()
        _write(run_root, race)
        return dict(lane)


def note_event(run_root: Path, event: Mapping[str, Any]) -> None:
    with state_lock(run_root):
        race = load_race(run_root)
        lane = _lane(race, str(event["lane_id"]))
        timestamp = str(event["timestamp"])
        if lane["lane_id"] == "root" and race["timestamps"]["root_first_command_at"] is None:
            race["timestamps"]["root_first_command_at"] = timestamp
        if lane["lane_id"] != "root" and race["timestamps"]["worker_first_command_at"] is None:
            race["timestamps"]["worker_first_command_at"] = timestamp
        event_type = str(event["event_type"])
        transitions = {
            "COMMAND_RESULT": "EXECUTING",
            "PRIMITIVE": "PRIMITIVE_FOUND",
            "WORKING_POC": "BUILDING_EXPLOIT",
            "REMOTE_RESULT": "REMOTE_TESTING",
        }
        if (
            event_type in transitions
            and lane["status"] not in NON_EXECUTING_LANE_STATES | {"CANCEL_REQUIRED"}
        ):
            lane["status"] = transitions[event_type]
        if event_type == "PRIMITIVE" and race["timestamps"]["first_primitive_at"] is None:
            race["timestamps"]["first_primitive_at"] = timestamp
        if event_type == "REMOTE_RESULT" and race["timestamps"]["first_remote_attempt_at"] is None:
            race["timestamps"]["first_remote_attempt_at"] = timestamp
        lane["last_verified_at"] = timestamp
        _write(run_root, race)


def note_command_receipt(run_root: Path, receipt: Mapping[str, Any]) -> None:
    """Record performance/lane state from execution, independently of the blackboard."""

    with state_lock(run_root):
        race = load_race(run_root)
        lane = _lane(race, str(receipt["lane_id"]))
        if receipt.get("run_id") != race["run_id"]:
            raise RaceError("command receipt does not belong to this exact run")
        timestamp = str(receipt.get("finished_at") or utc_now())
        _parse_time(timestamp)
        key = "root_first_command_at" if lane["lane_id"] == "root" else "worker_first_command_at"
        if race["timestamps"][key] is None:
            race["timestamps"][key] = timestamp
        local_identity = f"challenge:{race['challenge']['id']}"
        if (
            receipt.get("target_observed") is True
            and receipt.get("target_identity") != local_identity
            and race["timestamps"]["first_remote_attempt_at"] is None
        ):
            race["timestamps"]["first_remote_attempt_at"] = timestamp
        if lane["status"] not in NON_EXECUTING_LANE_STATES | {"CANCEL_REQUIRED"}:
            lane["status"] = "EXECUTING"
        lane["last_verified_at"] = timestamp
        _write(run_root, race)


def record_winner(
    run_root: Path,
    *,
    lane_id: str,
    candidate: str,
    receipt_id: str,
    target_identity: str,
    timestamp: str,
) -> dict[str, Any]:
    with state_lock(run_root):
        race = load_race(run_root)
        if race.get("winner") is not None:
            return {
                "won": False,
                "first": False,
                "winner": dict(race["winner"]),
                "cancel_targets": cancel_targets(race),
            }
        if race.get("status") != "ACTIVE":
            raise RaceError("a flag candidate cannot win a non-active race")
        observed_at = _parse_time(timestamp)
        if observed_at > _parse_time(str(race["deadline"])):
            raise RaceError("flag candidate arrived after the 90-minute race deadline")
        lane = _lane(race, lane_id)
        winner = {
            "lane_id": lane_id,
            "candidate": candidate,
            "receipt_id": receipt_id,
            "target_identity": target_identity,
            "observed_at": timestamp,
        }
        race["winner"] = winner
        race["status"] = "WON"
        race["attack_ready"] = False
        race["timestamps"]["first_flag_candidate_at"] = timestamp
        if lane_id == "root":
            # Root is the lead attacker, not a native child; it is ended through
            # timeout, handoff, or the exact-run cleanup path.
            lane["status"] = "WON"
        elif lane["status"] not in NON_EXECUTING_LANE_STATES:
            # A winning native child is still a live native thread. The win is
            # preserved in the race-level winner record above, but the child must
            # still be interrupted and its private sandbox cleaned before any
            # controller cleanup, exactly like its siblings.
            lane["status"] = "CANCEL_REQUIRED"
        for sibling in race["lanes"]:
            if (
                sibling["lane_id"] != lane_id
                and sibling["status"] not in NON_EXECUTING_LANE_STATES
            ):
                sibling["status"] = "CANCEL_REQUIRED"
        # Every live native child, including the winner, is a cancel target.
        targets = cancel_targets(race)
        _write(run_root, race)
        return {"won": True, "first": True, "winner": winner, "cancel_targets": targets}


def status(run_root: Path, *, now: datetime | None = None) -> dict[str, Any]:
    current = now or datetime.now(UTC)
    with state_lock(run_root):
        race = load_race(run_root)
        if race["status"] not in TERMINAL_STATUSES and current >= _parse_time(str(race["deadline"])):
            race["status"] = "TIMED_OUT"
            race["attack_ready"] = False
            for lane in race["lanes"]:
                if lane["status"] not in NON_EXECUTING_LANE_STATES:
                    lane["status"] = "CANCEL_REQUIRED"
        ledger = events(run_root)
        duplicates = duplicate_signals(run_root)
        rows: list[dict[str, Any]] = []
        for lane in race["lanes"]:
            lane_events = [row for row in ledger if row.get("lane_id") == lane["lane_id"]]
            lane_receipts = _receipts(run_root, str(lane["lane_id"]))
            commands = len(lane_receipts)
            new_outputs = len({row.get("output_hash") for row in lane_receipts})
            high = sum(row.get("event_type") in HIGH_VALUE_TYPES for row in lane_events)
            running = _running_commands(run_root, str(lane["lane_id"]), current)
            sessions = _running_sessions(run_root, str(lane["lane_id"]), current)
            lane["last_status_command_count"] = commands
            signals = _stagnation_signals(
                race, lane, lane_events, lane_receipts, duplicates, current,
                in_flight=bool(running or sessions),
            )
            max_exhausted = (
                lane.get("lane_id") != "root"
                and lane.get("model_profile") == "sol-max"
                and (
                    commands >= int(lane.get("max_actual_attacks", 2))
                    or current
                    >= _parse_time(
                        str(lane.get("spawned_at") or lane["prepared_at"])
                    )
                    + timedelta(seconds=600)
                )
            )
            if (
                max_exhausted
                and not (running or sessions)
                and lane["status"] not in NON_EXECUTING_LANE_STATES | {"PREPARED"}
            ):
                signals.append("sol-max-lease-exhausted")
                lane["status"] = "CANCEL_REQUIRED"
            elif (
                not (running or sessions)
                and any(signal in {
                    "repeated-command-result",
                    "artifact-hash-unchanged",
                    "duplicate-other-lane",
                    "remote-ready-without-remote-attempt",
                    "lease-expired-without-command",
                    # A lane that ran once and then idled past its lease emits
                    # this signal; without it the idle lane would hold its slot
                    # until the 90-minute deadline.
                    "no-new-output-hash",
                } for signal in signals)
                and lane["status"]
                not in NON_EXECUTING_LANE_STATES | {"PREPARED", "CANCEL_REQUIRED"}
            ):
                lane["status"] = "STAGNANT"
            rows.append({
                "lane_id": lane["lane_id"],
                "status": lane["status"],
                "cleanup_error": lane.get("cleanup_error"),
                "attack_family": lane["attack_family"],
                "actual_command_count": commands,
                "new_output_count": new_outputs,
                "high_value_event_count": high,
                "duplicate_fingerprints": [row for row in duplicates if row["lane_id"] == lane["lane_id"]],
                "stagnation_signals": signals,
                "in_flight": bool(running or sessions),
                "running_commands": running,
                "running_sessions": sessions,
                "last_verified_delta": _last_delta(lane_events),
                "cancel_target": lane.get("native_session") if lane["status"] in {"STAGNANT", "CANCEL_REQUIRED"} else None,
            })
        _write(run_root, race)
        native_actions = _native_actions(race)
        controller_actions = _controller_actions(race)
        return {
            "run_id": race["run_id"],
            "status": race["status"],
            "deadline": race["deadline"],
            "remote_execution": race.get("remote_execution", "agent"),
            "winner": race.get("winner"),
            "lanes": rows,
            "cancel_targets": cancel_targets(race),
            "verified_delta": verified_delta(run_root),
            "native_actions": native_actions,
            "controller_actions": controller_actions,
            "controller_reconcile_required": bool(native_actions or controller_actions),
            "metrics": metrics(
                race,
                ledger,
                current,
                [receipt for lane in race["lanes"] for receipt in _receipts(run_root, str(lane["lane_id"]))],
            ),
        }


def stop_confirmed(run_root: Path, *, lane_id: str, native_session: str) -> dict[str, Any]:
    """Record native termination and reserve the lane until sandbox cleanup finishes."""

    with state_lock(run_root):
        race = load_race(run_root)
        lane = _lane(race, lane_id)
        if lane_id == "root":
            raise RaceError("Root is ended through timeout, handoff, or cleanup")
        if lane.get("native_session") != native_session:
            raise RaceError("native stop confirmation does not match the lane")
        if lane["status"] in {"STOPPED", "WON"}:
            raise RaceError(f"lane cannot begin cleanup from {lane['status']}")
        lane["status"] = "STOPPING"
        lane["native_stopped_at"] = lane.get("native_stopped_at") or utc_now()
        lane["cleanup_attempts"] = int(lane.get("cleanup_attempts", 0)) + 1
        _write(run_root, race)
        return dict(lane)


def finish_lane_cleanup(
    run_root: Path,
    *,
    lane_id: str,
    error: str | None = None,
) -> dict[str, Any]:
    """Persist the sandbox cleanup result before a lane can free its slot."""

    with state_lock(run_root):
        race = load_race(run_root)
        lane = _lane(race, lane_id)
        if lane_id == "root":
            raise RaceError("Root is ended through timeout, handoff, or cleanup")
        if lane["status"] != "STOPPING":
            raise RaceError("lane cleanup result requires a STOPPING lane")
        now = utc_now()
        if error is None:
            lane["status"] = "STOPPED"
            lane["stopped_at"] = now
            lane["cleanup_completed_at"] = now
            lane.pop("cleanup_error", None)
            lane.pop("cleanup_failed_at", None)
            instance = race.get("service_instances", {}).get(lane_id)
            if isinstance(instance, dict):
                instance["status"] = "STOPPED"
                instance["stopped_at"] = now
        else:
            lane["status"] = "CLEANUP_FAILED"
            lane["cleanup_error"] = error[:4096]
            lane["cleanup_failed_at"] = now
            instance = race.get("service_instances", {}).get(lane_id)
            if isinstance(instance, dict):
                instance["status"] = "CLEANUP_FAILED"
                instance["cleanup_failed_at"] = now
        _write(run_root, race)
        return dict(lane)


def terminate(run_root: Path, *, reason: str) -> dict[str, Any]:
    if reason not in {"HANDOFF", "TIMED_OUT", "STOPPED"}:
        raise RaceError("invalid race termination reason")
    with state_lock(run_root):
        race = load_race(run_root)
        if race["status"] == "WON" and reason != "STOPPED":
            raise RaceError("a won race cannot be rewritten as timeout or handoff")
        race["status"] = reason
        race["attack_ready"] = False
        race["ended_at"] = utc_now()
        for lane in race["lanes"]:
            if lane["status"] not in NON_EXECUTING_LANE_STATES:
                lane["status"] = "CANCEL_REQUIRED"
        targets = cancel_targets(race)
        _write(run_root, race)
        return {"run_id": race["run_id"], "status": reason, "cancel_targets": targets}


def load_race(run_root: Path) -> dict[str, Any]:
    race = read_json(run_root / "RACE.json", "race state")
    if race.get("schema_version") != RACE_SCHEMA_VERSION:
        raise RaceError("unsupported race schema")
    if race.get("run_id") != run_root.name:
        raise RaceError("race state does not belong to this exact run")
    return race


def cancel_targets(race: Mapping[str, Any], *, excluding: str | None = None) -> list[dict[str, str]]:
    return [
        {"lane_id": str(lane["lane_id"]), "native_session": str(lane["native_session"])}
        for lane in race.get("lanes", [])
        if isinstance(lane, Mapping)
        and lane.get("lane_id") != excluding
        and lane.get("lane_id") != "root"
        and lane.get("native_session")
        and lane.get("status") not in NON_EXECUTING_LANE_STATES
    ]


def lease_seconds(category: str) -> int:
    return {
        "pwn": 240, "web": 240, "rev": 360, "crypto": 360,
        "forensic": 480, "ai": 480, "cloud": 360, "osint": 300,
        "misc": 300, "base": 300,
    }.get(category, 300)


def metrics(
    race: Mapping[str, Any],
    ledger: Sequence[Mapping[str, Any]],
    now: datetime,
    receipts: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    stamps = race["timestamps"]
    selected = _optional_time(stamps.get("challenge_selected_at"))
    input_ready = _optional_time(stamps.get("input_ready_at"))
    first_command = _optional_time(stamps.get("root_first_command_at")) or _optional_time(stamps.get("worker_first_command_at"))
    primitive = _optional_time(stamps.get("first_primitive_at"))
    remote = _optional_time(stamps.get("first_remote_attempt_at"))
    flag = _optional_time(stamps.get("first_flag_candidate_at"))
    time_to_flag = _elapsed(selected, flag)
    duplicates = duplicate_signals_from_rows(ledger)
    command_receipts = {row.get("receipt_id") for row in receipts if row.get("receipt_id")}
    idle: dict[str, float] = {}
    for lane in race["lanes"]:
        lane_rows = [row for row in receipts if row.get("lane_id") == lane["lane_id"]]
        last = _optional_time(lane_rows[-1].get("finished_at")) if lane_rows else _optional_time(lane.get("prepared_at"))
        idle[str(lane["lane_id"])] = round(max(0.0, (now - (last or now)).total_seconds()), 3)
    return {
        "timestamps": dict(stamps),
        "prepare_latency_seconds": _elapsed(selected, input_ready),
        "time_to_first_command_seconds": _elapsed(selected, first_command),
        "time_to_first_primitive_seconds": _elapsed(selected, primitive),
        "time_to_first_remote_attempt_seconds": _elapsed(selected, remote),
        "time_to_first_valid_flag_seconds": time_to_flag,
        "flag_window_indicators": {
            "within_1_minute": time_to_flag is not None and time_to_flag <= 60,
            "within_5_minutes": time_to_flag is not None and time_to_flag <= 300,
            "within_15_minutes": time_to_flag is not None and time_to_flag <= 900,
            "within_90_minutes": time_to_flag is not None and time_to_flag <= RACE_SECONDS,
        },
        "duplicate_attack_ratio": round(len(duplicates) / max(1, len(command_receipts)), 6),
        "idle_lane_seconds": idle,
        "model_portfolio": {
            str(lane["lane_id"]): str(lane["model_profile"])
            for lane in race["lanes"]
        },
        "root_model_profile": str(_lane(race, "root")["model_profile"]),
        "root_model_profile_source": str(
            _lane(race, "root").get("model_profile_source", "unknown")
        ),
        "remote_execution": str(race.get("remote_execution", "agent")),
        "shared_artifact_count": sum(
            row.get("shared_artifact_path") is not None for row in ledger
        ),
    }


def duplicate_signals_from_rows(rows: Sequence[Mapping[str, Any]]) -> list[tuple[str, str]]:
    seen_family: dict[tuple[Any, ...], str] = {}
    seen_execution: dict[tuple[Any, ...], str] = {}
    duplicates: list[tuple[str, str]] = []
    for row in rows:
        family_key = (row.get("attack_family"), row.get("output_hash"))
        execution_key = (
            row.get("argv_family"), row.get("target_identity"),
            row.get("exit_code"), row.get("output_hash"),
        )
        lane = str(row.get("lane_id"))
        other = seen_family.get(family_key) or seen_execution.get(execution_key)
        if other and other != lane:
            duplicates.append((lane, other))
        seen_family.setdefault(family_key, lane)
        seen_execution.setdefault(execution_key, lane)
    return duplicates


def _spawn_packet(run_root: Path, race: Mapping[str, Any], lane: Mapping[str, Any]) -> dict[str, Any]:
    sandbox = dict(lane["sandbox"])
    remote_execution = str(race.get("remote_execution", "agent"))
    context: dict[str, Any] = {
        "run_id": race["run_id"],
        "challenge": race["challenge"],
        "prepared_input": {"container_path": "/challenge", "read_only": True, "fingerprint": race["input_fingerprint"]},
        "declared_targets": race["declared_targets"],
        "remote_execution": remote_execution,
        "service_endpoints": list(sandbox.get("service_endpoints", [])),
        "flag_pattern": race["flag_pattern"],
        "priority_files": race["priority_files"],
        "deadline": race["deadline"],
        "lane_id": lane["lane_id"],
        "attack_family": lane["attack_family"],
        "sandbox": {
            "metadata_path": sandbox["metadata_path"],
            "exec_command_prefix": sandbox["exec_command_prefix"],
        },
        "shared_artifacts": {
            "container_path": "/shared-artifacts",
            "read_only": True,
            "manifests": shared_artifacts(run_root),
        },
    }
    if remote_execution == "human-relay":
        context["human_remote_relay"] = {
            "agent_network_requests_forbidden": True,
            "action_marker": "HUMAN_REMOTE_ACTION",
            "result_marker": "HUMAN_REMOTE_RESULT",
            "result_provenance": "participant-provided-unverified",
        }
    if lane["context_mode"] == "directed":
        context["verified_blackboard_delta"] = verified_delta(run_root)
    remote_instruction = (
        " Organizer-hosted remote requests are human-relayed: never send one through any "
        "agent tool, host tool, web/browser tool, connector, socket, or sandbox command. "
        "When a remote attempt is needed, return a HUMAN_REMOTE_ACTION block containing "
        "the exact cwd, argv, timeout, and full-output capture command for the participant. "
        "Analyze HUMAN_REMOTE_RESULT text as unverified external input; never claim it is "
        "an execution-verified receipt or append it to the verified blackboard."
        if remote_execution == "human-relay"
        else ""
    )
    message = (
        "You are one native CTF race lane. Execute only through the supplied sandbox prefix. "
        "Do not inspect host files, start other agents, submit flags, or share reasoning."
        f"{remote_instruction} "
        "Inspect /shared-artifacts for newly verified immutable artifacts before reimplementing work. "
        "Return only actual commands, bounded observed output, executable artifacts, verified primitives, "
        "remote results, killed hypotheses, exact blockers, or the required human-relay block.\n\n"
        f"Role: {lane['role']}\nTask: {lane['task']}\n"
        f"Context JSON: {json.dumps(context, ensure_ascii=False, sort_keys=True)}"
    )
    task_name = _native_task_name(
        str(lane["lane_id"]),
        str(race["attempt_id"]),
    )
    spawn_args: dict[str, str] = {
        "task_name": task_name,
        "fork_turns": "none",
        "message": message,
    }
    spawn_args.update(SPAWN_CONFIGS[str(lane["model_profile"])])
    return {
        "lane_id": lane["lane_id"],
        "model_profile": lane["model_profile"],
        "selected_image": race["selected_image"],
        "worker_paths": sandbox["paths"] | {"metadata_path": sandbox["metadata_path"]},
        "deadline": race["deadline"],
        "challenge_context": context,
        "spawn_agent_args": spawn_args,
    }


def _normalize_specification(row: Mapping[str, Any]) -> dict[str, str]:
    required = {"model_profile", "role", "task", "context_mode", "attack_family"}
    if set(row) != required:
        raise RaceError(f"lane specification must contain exactly: {', '.join(sorted(required))}")
    values = {key: str(row[key]).strip() for key in required}
    if values["model_profile"] not in MODEL_PROFILES:
        raise RaceError(
            "bootstrap model_profile must be sol-ultra, sol-max, sol-xhigh, "
            "terra-high, or luna-high"
        )
    if values["context_mode"] not in {"fresh", "directed"}:
        raise RaceError("context_mode must be fresh or directed")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", values["attack_family"]):
        raise RaceError("attack_family must be a bounded lowercase identifier")
    for field in ("role", "task"):
        if not values[field] or len(values[field]) > (128 if field == "role" else 4096):
            raise RaceError(f"lane {field} is empty or too long")
    return values


def _valid_native_session(value: str) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= 256:
        return False
    if not re.fullmatch(r"[A-Za-z0-9_.:/-]+", value):
        return False
    if "/" not in value:
        return value[0].isalnum()
    parts = value.split("/")
    if value.startswith("/"):
        parts = parts[1:]
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return False
    return all(re.fullmatch(r"[A-Za-z0-9_.:-]+", part) for part in parts)


def _native_task_name(lane_id: str, attempt_id: str) -> str:
    lane = re.sub(r"[^a-z0-9_]+", "_", lane_id.casefold()).strip("_")
    attempt = re.sub(r"[^a-z0-9_]+", "_", attempt_id.casefold()).strip("_")
    if not lane or not attempt:
        raise RaceError("native task identity cannot be derived")
    return f"{lane}_{attempt[:16]}"[:63]


def _stagnation_signals(
    race: Mapping[str, Any],
    lane: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    receipts: Sequence[Mapping[str, Any]],
    duplicates: Sequence[Mapping[str, Any]],
    now: datetime,
    *,
    in_flight: bool = False,
) -> list[str]:
    signals: list[str] = []
    lease = int(lane.get("lease_seconds", race["lease_seconds"]))
    last = (
        _optional_time(receipts[-1].get("finished_at"))
        if receipts else _optional_time(lane.get("prepared_at"))
    )
    if (
        not in_flight
        and last
        and (now - last).total_seconds() >= lease
    ):
        signals.append(
            "lease-expired-without-command" if not receipts else "no-new-output-hash"
        )
    fingerprints = [(
        row.get("argv_family"), row.get("target_identity"),
        row.get("exit_code"), row.get("output_hash"),
    ) for row in receipts]
    if len(fingerprints) != len(set(fingerprints)):
        signals.append("repeated-command-result")
    artifacts = [row.get("artifact_hash") for row in rows if row.get("artifact_hash")]
    if len(artifacts) >= 2 and artifacts[-1] == artifacts[-2]:
        signals.append("artifact-hash-unchanged")
    if any(row.get("lane_id") == lane["lane_id"] for row in duplicates):
        signals.append("duplicate-other-lane")
    has_primitive = any(row.get("event_type") in {"PRIMITIVE", "WORKING_POC"} for row in rows)
    local_identity = f"challenge:{race['challenge']['id']}"
    remote = any(
        row.get("target_observed") is True and row.get("target_identity") != local_identity
        for row in receipts
    )
    agent_reachable_target = bool(race.get("service_endpoints")) or (
        race.get("remote_execution", "agent") == "agent"
        and bool(race.get("declared_targets"))
    )
    if (
        has_primitive
        and not in_flight
        and agent_reachable_target
        and not remote
        and last
        and (now - last).total_seconds() >= 60
    ):
        signals.append("remote-ready-without-remote-attempt")
    return signals


def _running_commands(
    run_root: Path,
    lane_id: str,
    now: datetime,
) -> list[dict[str, Any]]:
    root = run_root / "workers" / lane_id / "logs" / "running"
    if not root.exists():
        return []
    if root.is_symlink() or not root.is_dir():
        raise RaceError("running command state directory is unsafe")
    rows: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.json")):
        if path.is_symlink():
            raise RaceError("running command state is a symlink")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RaceError("running command state is unreadable") from exc
        if (
            not isinstance(value, dict)
            or value.get("run_id") != run_root.name
            or value.get("lane_id") != lane_id
            or value.get("receipt_id") != path.stem
            or value.get("status") != "RUNNING"
        ):
            raise RaceError("running command state identity mismatch")
        heartbeat = _optional_time(value.get("heartbeat_at"))
        stale = heartbeat is None or (now - heartbeat).total_seconds() > 30
        rows.append({
            "receipt_id": value.get("receipt_id"),
            "argv": value.get("argv"),
            "argv_family": value.get("argv_family"),
            "started_at": value.get("started_at"),
            "heartbeat_at": value.get("heartbeat_at"),
            "last_output_at": value.get("last_output_at"),
            "observed_bytes": value.get("observed_bytes"),
            "heartbeat_stale": stale,
        })
    return [row for row in rows if row["heartbeat_stale"] is False]


def _running_sessions(
    run_root: Path,
    lane_id: str,
    now: datetime,
    *,
    docker: str = "docker",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[dict[str, Any]]:
    lane_root = run_root / "workers" / lane_id
    root = lane_root / "sessions"
    if not root.exists():
        return []
    if root.is_symlink() or not root.is_dir():
        raise RaceError("persistent session state directory is unsafe")
    now_epoch = now.timestamp()
    rows: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.json")):
        if path.is_symlink():
            raise RaceError("persistent session state is a symlink")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RaceError("persistent session state is unreadable") from exc
        if (
            not isinstance(value, dict)
            or value.get("run_id") != run_root.name
            or value.get("lane_id") != lane_id
            or value.get("status") != "RUNNING"
        ):
            continue
        # Only a session with a fresh, identity-matched heartbeat is really live
        # and may suppress stagnation; a dead or stale one never counts.
        liveness = session_liveness(
            lane_root,
            value,
            now_epoch=now_epoch,
            docker=docker,
            runner=runner,
        )
        if not liveness["live"]:
            continue
        rows.append({
            "session_id": value.get("session_id"),
            "kind": value.get("kind"),
            "argv": value.get("argv"),
            "opened_at": value.get("opened_at"),
            "last_read_at": value.get("last_read_at"),
            "heartbeat_at": liveness.get("heartbeat_at"),
            "pid": liveness.get("pid"),
        })
    return rows


def _native_actions(race: Mapping[str, Any]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    for lane in race.get("lanes", []):
        if not isinstance(lane, Mapping) or lane.get("lane_id") == "root":
            continue
        if (
            lane.get("status") == "PREPARED"
            and isinstance(lane.get("sandbox"), Mapping)
            and lane["sandbox"].get("status") == "READY"
            and isinstance(lane.get("spawn_agent_args"), Mapping)
        ):
            actions.append({
                "action": "SPAWN",
                "lane_id": lane["lane_id"],
                "spawn_agent_args": dict(lane["spawn_agent_args"]),
            })
        elif (
            lane.get("status") in {"STAGNANT", "CANCEL_REQUIRED"}
            and lane.get("native_session")
        ):
            actions.append({
                "action": "INTERRUPT",
                "lane_id": lane["lane_id"],
                "native_session": lane["native_session"],
            })
    return actions


def _controller_actions(race: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "action": "RETRY_CLEANUP",
            "lane_id": lane["lane_id"],
            "exec_command": [
                "uv", "run", "python", "-m", "ctf_os.agent_tools",
                "race-lane-cleanup", "--run-id", race["run_id"],
                "--lane", lane["lane_id"],
            ],
        }
        for lane in race.get("lanes", [])
        if isinstance(lane, Mapping)
        and lane.get("lane_id") != "root"
        and lane.get("status") == "CLEANUP_FAILED"
    ]


def _receipts(run_root: Path, lane_id: str) -> list[dict[str, Any]]:
    root = run_root / "workers" / lane_id / "logs"
    if not root.exists():
        return []
    if root.is_symlink() or not root.is_dir():
        raise RaceError("lane receipt directory is unsafe")
    rows: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.json")):
        if path.is_symlink():
            raise RaceError("lane receipt path is a symlink")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RaceError(f"lane receipt is unreadable: {path.name}") from exc
        if (
            isinstance(value, dict)
            and value.get("schema_version") == 1
            and value.get("run_id") == run_root.name
            and value.get("lane_id") == lane_id
            and value.get("receipt_id") == path.stem
            and re.fullmatch(r"[0-9a-f]{64}", str(value.get("output_hash", "")))
        ):
            rows.append(value)
    rows.sort(key=lambda row: str(row.get("finished_at", "")))
    return rows


def _last_delta(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any] | None:
    if not rows:
        return None
    row = rows[-1]
    return {key: row.get(key) for key in (
        "event_type", "argv", "exit_code", "observed_output", "output_hash", "artifact_path",
        "artifact_hash", "target_identity", "timestamp",
    )}


def _validate_sandbox_identity(race: Mapping[str, Any], lane: Mapping[str, Any], sandbox: Mapping[str, Any]) -> None:
    if sandbox.get("status") != "READY":
        raise RaceError("sandbox is not READY")
    for field, expected in (
        ("run_id", race["run_id"]), ("challenge_id", race["challenge"]["id"]),
        ("lane_id", lane["lane_id"]), ("image", race["selected_image"]),
    ):
        if sandbox.get(field) != expected:
            raise RaceError(f"sandbox {field} identity mismatch")


def _lane(race: Mapping[str, Any], lane_id: str) -> dict[str, Any]:
    for lane in race.get("lanes", []):
        if isinstance(lane, dict) and lane.get("lane_id") == lane_id:
            return lane
    raise RaceError(f"unknown race lane: {lane_id}")


def _require_active(race: Mapping[str, Any]) -> None:
    if race.get("status") not in {"ACTIVE", "PREPARING"}:
        raise RaceError(f"race is not active: {race.get('status')}")
    if _parse_time(str(race["deadline"])) <= datetime.now(UTC):
        raise RaceError("race deadline has passed")


def _write(run_root: Path, race: Mapping[str, Any]) -> None:
    atomic_json(run_root / "RACE.json", dict(race))


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise RaceError("race timestamp must include a timezone")
    return parsed.astimezone(UTC)


def _optional_time(value: object) -> datetime | None:
    if not value:
        return None
    try:
        return _parse_time(str(value))
    except (RaceError, ValueError):
        return None


def _elapsed(start: datetime | None, end: datetime | None) -> float | None:
    if start is None or end is None:
        return None
    return round(max(0.0, (end - start).total_seconds()), 6)
