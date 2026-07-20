"""Command-only drift gate, bounded long compute, and PoC-to-remote deadlines."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any, Mapping, Sequence

import yaml

from .control import create_control_action
from .workspace import (
    append_jsonl_fsync, atomic_json, ensure_run_mutable, resolve_active_run,
    safe_under, state_lock, utc_now,
)


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
        applied = session.setdefault("applied_milestone_receipts", [])
        if not isinstance(applied, list):
            raise ProgressGateError("progress applied receipt index is malformed")
        receipt_id = str(receipt.get("receipt_id") or "")
        if receipt_id in applied:
            return {
                "counts_as_progress": progress,
                "evidence_generation": int(session.get("evidence_generation", 0)),
                "remote_transition": state.get("remote_transition", {}).get(session_id),
                "idempotent": True,
            }
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
                "last_artifact": details.get("artifact_initial", _empty_artifact()),
                "last_observation": details.get("initial_observation"),
                "verified_checkpoint": False, "status": "ACTIVE",
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
        applied.append(receipt_id)
        atomic_json(run / "progress-state.json", state)
    return {
        "counts_as_progress": progress,
        "evidence_generation": int(session.get("evidence_generation", 0)),
        "remote_transition": state.get("remote_transition", {}).get(session_id),
        "idempotent": False,
    }


def heartbeat_long_compute(
    root: Path, *, session_id: str, receipt_id: str,
    artifact_changed: bool | None = None, completion_signal_observed: bool | None = None,
    observed_at: str | None = None,
) -> dict[str, Any]:
    run = ensure_run_mutable(root)
    now = _parse_time(observed_at or utc_now())
    review: tuple[str, int] | None = None
    verified_update: dict[str, Any] | None = None
    with state_lock(run):
        state = _load_state(run)
        session = _session(state, session_id, now)
        compute = session.get("long_compute")
        if not isinstance(compute, dict) or compute.get("receipt_id") != receipt_id:
            raise ProgressGateError("LONG_COMPUTE receipt is not active for this run and session")
        if compute.get("status") != "ACTIVE":
            return {**compute, "idempotent": True}
        details = compute.get("details") if isinstance(compute.get("details"), Mapping) else {}
        observation = _observe_long_compute(details)
        prior = compute.get("last_artifact") if isinstance(compute.get("last_artifact"), Mapping) else {}
        changed = _artifact_observation_changed(prior, observation.get("artifact"))
        process_valid = observation.get("process_valid") is True
        completion = observation.get("completion_signal") is True
        started = _parse_time(str(compute.get("started_at")))
        maximum = int(details.get("maximum_duration_seconds", 0) or 0)
        interval = int(details.get("checkpoint_interval_seconds", 0) or 0)
        if not process_valid and completion:
            compute["status"] = "COMPLETED"
            compute["completed_at"] = _format_time(now)
        elif not process_valid:
            compute["status"] = "FAILED"
            compute["failure_reason"] = "process exited without the expected completion signal"
            review = (str(compute["failure_reason"]), int(session.get("evidence_generation", 0)))
        elif maximum < 1 or (now - started).total_seconds() > maximum:
            compute["status"] = "REVIEW_REQUIRED"
            compute["failure_reason"] = "LONG_COMPUTE maximum duration expired"
            review = (str(compute["failure_reason"]), int(session.get("evidence_generation", 0)))
        elif changed:
            compute["last_heartbeat_at"] = _format_time(now)
            compute["last_artifact"] = observation.get("artifact")
            compute["last_observation"] = observation
            compute["verified_checkpoint"] = True
            verified_update = {
                "receipt_id": receipt_id, "active": True, "process_valid": True,
                "fresh_artifact_evidence": True, "observed_at": _format_time(now),
                "valid_until_at": _format_time(now + timedelta(seconds=interval)),
            }
        elif interval < 1 or (now - _parse_time(str(compute.get("last_heartbeat_at")))).total_seconds() > interval:
            compute["status"] = "REVIEW_REQUIRED"
            compute["failure_reason"] = "LONG_COMPUTE heartbeat or artifact checkpoint is stale"
            review = (str(compute["failure_reason"]), int(session.get("evidence_generation", 0)))
        compute["caller_artifact_changed_ignored"] = artifact_changed is not None
        compute["caller_completion_signal_ignored"] = completion_signal_observed is not None
        atomic_json(run / "progress-state.json", state)
    if verified_update is not None:
        _publish_verified_long_compute(run, session_id, verified_update)
    action = None
    if review is not None:
        reason, generation = review
        action = create_control_action(
            run, session_id=session_id, action_type="LONG_COMPUTE_REVIEW",
            reason=reason, triggering_evidence_id=receipt_id,
            evidence_generation=generation,
            metadata={"long_compute_receipt_id": receipt_id},
        )
    return {
        **compute, "observation": observation, "artifact_changed": changed,
        "review_action": action, "idempotent": False,
    }


def prepare_long_compute_details(
    root: Path, *, session_id: str, command_argv: Sequence[str],
    details: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind a LONG_COMPUTE receipt to a live sandbox process and artifact."""

    run = resolve_active_run(root)
    result = dict(details)
    metadata_reference = Path(str(result.get("sandbox_metadata_path") or ""))
    expected_reference = Path(str(result.get("expected_output_artifact") or ""))
    completion_reference = Path(str(result.get("expected_completion_signal") or ""))
    for reference, label in (
        (metadata_reference, "sandbox_metadata_path"),
        (expected_reference, "expected_output_artifact"),
        (completion_reference, "expected_completion_signal"),
    ):
        if reference.is_absolute() or any(part in {"", ".", ".."} for part in reference.parts):
            raise ProgressGateError(f"{label} must be a safe run-relative path")
    expected_metadata = Path("workers") / session_id / "sandbox.json"
    if metadata_reference != expected_metadata:
        raise ProgressGateError("LONG_COMPUTE sandbox metadata is not owned by this session")
    if expected_reference.parts[0] not in {"artifacts", "work", "evidence"}:
        raise ProgressGateError("LONG_COMPUTE artifact must stay in its branch sandbox namespace")
    if completion_reference.parts[0] not in {"artifacts", "work", "evidence"}:
        raise ProgressGateError("LONG_COMPUTE completion signal must stay in its branch sandbox namespace")
    metadata_path = safe_under(run, metadata_reference)
    if metadata_path.is_symlink() or not metadata_path.is_file():
        raise ProgressGateError("LONG_COMPUTE sandbox metadata is missing or unsafe")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProgressGateError("LONG_COMPUTE sandbox metadata is malformed") from exc
    if not isinstance(metadata, dict):
        raise ProgressGateError("LONG_COMPUTE sandbox metadata is not an object")
    state = json.loads((run / "STATE.json").read_text(encoding="utf-8"))
    if (
        metadata.get("branch") != session_id
        or metadata.get("challenge_id") != state.get("challenge_id")
        or metadata.get("input_fingerprint") != state.get("input_fingerprint")
        or metadata.get("target_revision") != state.get("target_revision")
    ):
        raise ProgressGateError("LONG_COMPUTE sandbox metadata identity is stale")
    process = result.get("process_identity")
    if not isinstance(process, Mapping) or not any(
        isinstance(process.get(key), int) and not isinstance(process.get(key), bool) and int(process[key]) > 0
        for key in ("pid", "process_group_id")
    ):
        raise ProgressGateError("LONG_COMPUTE requires a verified pid or process_group_id")
    result["command_argv"] = _argv(command_argv)
    result["command_digest"] = hashlib.sha256(
        json.dumps(result["command_argv"], separators=(",", ":")).encode(),
    ).hexdigest()
    result["sandbox_metadata_identity"] = {
        "path": metadata_reference.as_posix(), "name": metadata.get("name"),
        "branch": metadata.get("branch"),
        "digest": hashlib.sha256(metadata_path.read_bytes()).hexdigest(),
    }
    result["container_name"] = metadata.get("name")
    observation = _observe_long_compute(result)
    if observation.get("process_valid") is not True:
        raise ProgressGateError("LONG_COMPUTE process identity is not live in the declared sandbox")
    result["container_identity"] = observation.get("container_identity")
    result["artifact_initial"] = observation.get("artifact")
    result["initial_observation"] = observation
    return result


def _observe_long_compute(details: Mapping[str, Any]) -> dict[str, Any]:
    container = str(details.get("container_name") or "")
    process = details.get("process_identity") if isinstance(details.get("process_identity"), Mapping) else {}
    if not container or not process:
        raise ProgressGateError("LONG_COMPUTE observation identity is incomplete")
    inspected = _docker_command(["docker", "inspect", "--format", "{{.Id}}", container])
    container_id = inspected.stdout.strip()
    if inspected.returncode or not container_id:
        return {
            "container_identity": None, "process_valid": False,
            "artifact": _empty_artifact(), "completion_signal": False,
        }
    expected_container = details.get("container_identity")
    if expected_container and expected_container != container_id:
        raise ProgressGateError("LONG_COMPUTE container identity changed")
    processes = _docker_command([
        "docker", "exec", container, "ps", "-e", "-o", "pid=,pgid=,args=",
    ])
    process_valid = False
    matched_pid: int | None = None
    if processes.returncode == 0:
        pid = process.get("pid")
        pgid = process.get("process_group_id")
        for line in processes.stdout.splitlines():
            fields = line.strip().split(None, 2)
            if len(fields) < 2 or not fields[0].isdigit() or not fields[1].isdigit():
                continue
            if (isinstance(pid, int) and int(fields[0]) == pid) or (
                isinstance(pgid, int) and int(fields[1]) == pgid
            ):
                matched_pid = int(fields[0])
                break
    observed_argv: list[str] | None = None
    if matched_pid is not None:
        # Keep argv direct while decoding the NUL-separated process command in
        # the sandbox. The compact Python expression emits a JSON array.
        code = (
            "import json,sys; p='/proc/'+sys.argv[1]+'/cmdline'; "
            "print(json.dumps([x.decode(errors='replace') for x in open(p,'rb').read().split(b'\\0') if x]))"
        )
        command = _docker_command([
            "docker", "exec", container, "python3", "-c", code, str(matched_pid),
        ])
        if command.returncode == 0:
            try:
                decoded = json.loads(command.stdout)
            except json.JSONDecodeError as exc:
                raise ProgressGateError(
                    "sandbox returned malformed LONG_COMPUTE process argv"
                ) from exc
            if isinstance(decoded, list) and all(isinstance(item, str) for item in decoded):
                observed_argv = decoded
    expected_argv = details.get("command_argv")
    process_valid = (
        matched_pid is not None and isinstance(expected_argv, list)
        and observed_argv == expected_argv
    )
    artifact = _container_file_observation(container, str(details.get("expected_output_artifact") or ""))
    completion = _container_file_observation(container, str(details.get("expected_completion_signal") or ""))["exists"]
    return {
        "container_identity": container_id, "process_valid": process_valid,
        "process_id": matched_pid, "observed_command_argv": observed_argv,
        "artifact": artifact, "completion_signal": completion,
    }


def _container_file_observation(container: str, reference: str) -> dict[str, Any]:
    path = "/" + reference.lstrip("/")
    code = (
        "import hashlib,json,os,sys; p=sys.argv[1]; "
        "e=os.path.isfile(p); s=os.stat(p) if e else None; "
        "h=hashlib.sha256(open(p,'rb').read()).hexdigest() if e else None; "
        "print(json.dumps({'exists':e,'size':s.st_size if s else 0,'mtime_ns':s.st_mtime_ns if s else None,'digest':h}))"
    )
    observed = _docker_command(["docker", "exec", container, "python3", "-c", code, path])
    if observed.returncode:
        return _empty_artifact()
    try:
        payload = json.loads(observed.stdout)
    except json.JSONDecodeError as exc:
        raise ProgressGateError("sandbox returned malformed artifact observation") from exc
    if not isinstance(payload, dict):
        raise ProgressGateError("sandbox artifact observation is not an object")
    return payload


def _docker_command(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(list(argv), capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProgressGateError(f"cannot observe LONG_COMPUTE sandbox: {exc}") from exc


def _empty_artifact() -> dict[str, Any]:
    return {"exists": False, "size": 0, "mtime_ns": None, "digest": None}


def _artifact_observation_changed(previous: Mapping[str, Any], current: Any) -> bool:
    if not isinstance(current, Mapping):
        return False
    return any(previous.get(key) != current.get(key) for key in ("exists", "size", "mtime_ns", "digest"))


def _publish_verified_long_compute(
    run: Path, session_id: str, evidence: Mapping[str, Any],
) -> None:
    try:
        from .resources.scheduler import ResourceLedger
        ledger = ResourceLedger(run)
        if ledger.state_path.exists():
            ledger.update(
                session_id, actor_session_id=session_id, actor_role="child",
                changes={"progress": {"verified_long_compute": dict(evidence)}},
                verified_long_compute=True,
            )
    except Exception as exc:
        append_jsonl_fsync(run / "scheduler-errors.jsonl", {
            "event": "LONG_COMPUTE_VERIFIED_UPDATE_FAILED", "session_id": session_id,
            "error": str(exc)[:2000], "created_at": utc_now(),
        }, label="scheduler error ledger")


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
        "applied_milestone_receipts": [],
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
