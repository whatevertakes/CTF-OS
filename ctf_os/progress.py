"""Command-only drift gate, bounded long compute, and PoC-to-remote deadlines."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
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
            checkpoint = _record_long_compute_checkpoint(
                run, session_id=session_id, receipt_id=receipt_id,
                observation=observation, observed_at=now,
                valid_until=now + timedelta(seconds=interval),
            )
            compute["verified_checkpoint_receipt_id"] = checkpoint["receipt_id"]
            verified_update = {
                "receipt_id": receipt_id, "active": True, "process_valid": True,
                "fresh_artifact_evidence": True, "observed_at": _format_time(now),
                "valid_until_at": _format_time(now + timedelta(seconds=interval)),
                "checkpoint_receipt_id": checkpoint["receipt_id"],
                "artifact": observation.get("artifact"),
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
    completion_marker = _container_file_observation(
        container, str(details.get("expected_completion_signal") or ""),
    )
    completion = completion_marker["exists"]
    return {
        "container_identity": container_id, "process_valid": process_valid,
        "process_id": matched_pid, "observed_command_argv": observed_argv,
        "artifact": artifact, "completion_signal": completion,
        "completion_marker": completion_marker,
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


def _record_long_compute_checkpoint(
    run: Path, *, session_id: str, receipt_id: str,
    observation: Mapping[str, Any], observed_at: datetime, valid_until: datetime,
) -> dict[str, Any]:
    artifact = observation.get("artifact")
    if not isinstance(artifact, Mapping) or not artifact.get("exists") or not artifact.get("digest"):
        raise ProgressGateError("verified LONG_COMPUTE checkpoint lacks a real artifact digest")
    run_state = _run_identity_state(run)
    material = {
        "run_id": run_state.get("run_id") or run.name,
        "challenge_id": run_state.get("challenge_id"), "session_id": session_id,
        "input_fingerprint": run_state.get("input_fingerprint"),
        "target_revision": run_state.get("target_revision"),
        "long_compute_receipt_id": receipt_id,
        "container_identity": observation.get("container_identity"),
        "process_id": observation.get("process_id"),
        "observed_command_argv": observation.get("observed_command_argv"),
        "artifact": dict(artifact), "observed_at": _format_time(observed_at),
        "valid_until_at": _format_time(valid_until),
    }
    checkpoint_id = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode(),
    ).hexdigest()[:24]
    receipt = {
        "schema_version": 1, "receipt_id": checkpoint_id, **material,
        "process_valid": True, "fresh_artifact_evidence": True,
    }
    atomic_json(run / "long-compute-checkpoints" / f"{checkpoint_id}.json", receipt)
    return receipt


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


def validate_long_compute_review_proof(
    run: Path, *, action: Mapping[str, Any], proof: Mapping[str, Any],
    long_compute_receipt: Mapping[str, Any], milestones: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Re-observe decision-specific evidence instead of trusting caller claims."""

    progress_state = _load_state(run)
    run_state = _run_identity_state(run)
    session_id = str(action.get("session_id") or "")
    receipt_id = str(long_compute_receipt.get("receipt_id") or "")
    common = {
        "run_id": run_state.get("run_id") or run.name,
        "challenge_id": run_state.get("challenge_id"), "session_id": session_id,
        "input_fingerprint": run_state.get("input_fingerprint"),
        "target_revision": run_state.get("target_revision"),
    }
    for field, value in common.items():
        if long_compute_receipt.get(field) != value:
            raise ProgressGateError(f"LONG_COMPUTE receipt {field} mismatch")
    if proof.get("long_compute_receipt_id") != receipt_id:
        raise ProgressGateError("LONG_COMPUTE review receipt ID mismatch")
    metadata = action.get("metadata") if isinstance(action.get("metadata"), Mapping) else {}
    if metadata.get("long_compute_receipt_id") not in {None, receipt_id}:
        raise ProgressGateError("LONG_COMPUTE review action references another receipt")
    session = progress_state.get("sessions", {}).get(session_id)
    compute = session.get("long_compute") if isinstance(session, Mapping) else None
    if not isinstance(compute, Mapping) or compute.get("receipt_id") != receipt_id:
        raise ProgressGateError("LONG_COMPUTE progress evidence is missing for this session")
    details = long_compute_receipt.get("details")
    if not isinstance(details, Mapping):
        raise ProgressGateError("LONG_COMPUTE receipt details are malformed")
    observation = _observe_long_compute(details)
    decision = str(proof.get("decision") or "").upper()
    binding = {
        **common, "action_id": action.get("action_id"),
        "long_compute_receipt_id": receipt_id, "decision": decision,
        "observed_at": utc_now(), "live_observation": observation,
    }

    if decision == "CANCELLED":
        termination = proof.get("process_termination_receipt")
        if not isinstance(termination, Mapping):
            raise ProgressGateError("CANCELLED requires a process termination receipt")
        _validate_review_receipt_binding(termination, binding)
        if not str(termination.get("receipt_id") or ""):
            raise ProgressGateError("process termination receipt ID is missing")
        if termination.get("container_identity") != details.get("container_identity"):
            raise ProgressGateError("process termination container identity mismatch")
        if termination.get("process_identity") != details.get("process_identity"):
            raise ProgressGateError("process termination process identity mismatch")
        termination_observation = termination.get("termination_observation")
        if not isinstance(termination_observation, Mapping):
            raise ProgressGateError("process termination observation is missing")
        if termination_observation.get("process_valid") is not False:
            raise ProgressGateError("process termination receipt does not observe termination")
        if termination_observation.get("remaining_processes") != []:
            raise ProgressGateError("CANCELLED still has remaining long-compute processes")
        if observation.get("container_identity") != details.get("container_identity"):
            raise ProgressGateError("CANCELLED container identity cannot be re-observed")
        if observation.get("process_valid") is not False:
            raise ProgressGateError("CANCELLED long-compute process is still running")
        binding["process_termination_receipt"] = dict(termination)
        return binding

    if decision == "COMPLETED":
        marker = observation.get("completion_marker")
        artifact = observation.get("artifact")
        if observation.get("process_valid") is not False:
            raise ProgressGateError("COMPLETED long-compute process is still running")
        if not isinstance(marker, Mapping) or marker.get("exists") is not True or not marker.get("digest"):
            raise ProgressGateError("COMPLETED expected completion marker is missing")
        if not isinstance(artifact, Mapping) or artifact.get("exists") is not True or not artifact.get("digest"):
            raise ProgressGateError("COMPLETED final artifact observation is missing")
        if proof.get("completion_marker_digest") != marker.get("digest"):
            raise ProgressGateError("COMPLETED completion marker digest mismatch")
        if proof.get("completion_marker_metadata") != dict(marker):
            raise ProgressGateError("COMPLETED completion marker metadata mismatch")
        if proof.get("final_artifact_observation") != dict(artifact):
            raise ProgressGateError("COMPLETED final artifact observation mismatch")
        binding["completion_marker"] = dict(marker)
        binding["final_artifact"] = dict(artifact)
        return binding

    if decision == "CONTINUED_WITH_VALID_CHECKPOINT":
        checkpoint_id = str(proof.get("verified_checkpoint_receipt_id") or "")
        if not checkpoint_id or compute.get("verified_checkpoint_receipt_id") != checkpoint_id:
            raise ProgressGateError("CONTINUED requires the current verified checkpoint receipt")
        checkpoint = _load_checkpoint(run, checkpoint_id)
        for field, value in {**common, "long_compute_receipt_id": receipt_id}.items():
            if checkpoint.get(field) != value:
                raise ProgressGateError(f"verified checkpoint {field} mismatch")
        expires = _parse_time(str(checkpoint.get("valid_until_at") or ""))
        if expires <= datetime.now(timezone.utc):
            raise ProgressGateError("verified LONG_COMPUTE checkpoint is stale")
        artifact = checkpoint.get("artifact")
        if not isinstance(artifact, Mapping) or not all(
            artifact.get(field) is not None for field in ("digest", "size", "mtime_ns")
        ):
            raise ProgressGateError("verified checkpoint lacks digest/size/mtime evidence")
        if observation.get("process_valid") is not True:
            raise ProgressGateError("CONTINUED long-compute process identity is not live")
        if observation.get("container_identity") != checkpoint.get("container_identity"):
            raise ProgressGateError("CONTINUED checkpoint container identity changed")
        if observation.get("artifact") != dict(artifact):
            raise ProgressGateError("CONTINUED checkpoint artifact is no longer current")
        binding["verified_checkpoint_receipt"] = checkpoint
        return binding

    if decision == "FALLBACK_APPLIED":
        fallback_id = str(proof.get("fallback_command_receipt_id") or "")
        fallback = next((
            row for row in milestones
            if row.get("receipt_id") == fallback_id
            and row.get("event_type") == "DECISIVE_EXPERIMENT"
        ), None)
        if fallback is None:
            raise ProgressGateError("FALLBACK_APPLIED requires a fallback command receipt")
        for field, value in common.items():
            if fallback.get(field) != value:
                raise ProgressGateError(f"fallback command receipt {field} mismatch")
        argv = _argv(proof.get("fallback_argv", []))
        command_digest = hashlib.sha256(
            json.dumps(argv, separators=(",", ":")).encode(),
        ).hexdigest()
        if (
            fallback.get("command_argv") != argv
            or fallback.get("command_digest") != command_digest
        ):
            raise ProgressGateError("fallback command receipt exact argv mismatch")
        fallback_details = fallback.get("details") if isinstance(fallback.get("details"), Mapping) else {}
        if fallback_details.get("fallback_for_long_compute_receipt_id") != receipt_id:
            raise ProgressGateError("fallback command receipt is not bound to this LONG_COMPUTE")
        fallback_artifact = proof.get("fallback_artifact")
        decisive_id = proof.get("decisive_experiment_receipt_id")
        if fallback_artifact:
            reference = str(fallback_artifact)
            if reference not in fallback.get("artifacts", []):
                raise ProgressGateError("fallback artifact is not bound to the command receipt")
            path = safe_under(run, Path(reference))
            if path.is_symlink() or not path.is_file():
                raise ProgressGateError("fallback artifact is missing or unsafe")
            if _sha256_file(path) != (fallback.get("artifact_digests") or {}).get(reference):
                raise ProgressGateError("fallback artifact digest changed")
        elif decisive_id != fallback_id:
            raise ProgressGateError("fallback requires an artifact or decisive experiment receipt")
        if observation.get("process_valid") is not False:
            raise ProgressGateError("original LONG_COMPUTE process still runs after fallback")
        binding["fallback_command_receipt"] = dict(fallback)
        return binding

    raise ProgressGateError("LONG_COMPUTE_REVIEW decision is invalid")


def _validate_review_receipt_binding(
    receipt: Mapping[str, Any], binding: Mapping[str, Any],
) -> None:
    for field in (
        "run_id", "challenge_id", "session_id", "input_fingerprint",
        "target_revision", "action_id", "long_compute_receipt_id",
    ):
        if receipt.get(field) != binding.get(field):
            raise ProgressGateError(f"LONG_COMPUTE review evidence {field} mismatch")


def _load_checkpoint(run: Path, receipt_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{24}", receipt_id):
        raise ProgressGateError("verified checkpoint receipt ID is invalid")
    path = run / "long-compute-checkpoints" / f"{receipt_id}.json"
    if path.is_symlink() or not path.is_file():
        raise ProgressGateError("verified checkpoint receipt is missing or unsafe")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProgressGateError("verified checkpoint receipt is malformed") from exc
    if not isinstance(payload, dict) or payload.get("receipt_id") != receipt_id:
        raise ProgressGateError("verified checkpoint receipt identity is malformed")
    return payload


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _run_identity_state(run: Path) -> dict[str, Any]:
    path = run / "STATE.json"
    if path.is_symlink() or not path.is_file():
        raise ProgressGateError("run state is missing or unsafe")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProgressGateError("run state is malformed") from exc
    if not isinstance(payload, dict):
        raise ProgressGateError("run state is not an object")
    return payload


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
