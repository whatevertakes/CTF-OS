"""Explicit one-shot WORKING_POC to declared-remote execution path."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, BinaryIO, Callable, Iterator
import uuid

from .flags import matches_flag
from .milestones import load_milestones, save_milestone
from .sandbox.network import Target
from .sandbox.runtime import execute
from .verification import record_remote_flag
from .workspace import atomic_json, resolve_active_run, safe_under, utc_now


class WorkingPocError(RuntimeError):
    pass


def commit_working_poc(
    root: Path, *, challenge_id: str, input_fingerprint: str,
    target_revision: int, session_id: str, sandbox_metadata: Mapping[str, Any],
    local_receipt_id: str, exploit_artifact: str, remote_argv: Sequence[str],
    declared_targets: Sequence[Target], target_index: int,
    flag_pattern: str | None, success_condition: str, kill_condition: str,
    operation_id: str, timeout: int = 300,
    executor: Callable[..., Mapping[str, Any]] = execute,
) -> dict[str, Any]:
    run = resolve_active_run(
        root, input_fingerprint=input_fingerprint, target_revision=target_revision,
    )
    state = _json(run / "STATE.json", "run state")
    if state.get("challenge_id") != challenge_id or state.get("run_id") != run.name:
        raise WorkingPocError("working PoC run identity mismatch")
    session = _token(session_id, "session_id")
    operation = _text(operation_id, "operation_id", 256)
    argv = _argv(remote_argv)
    artifact = _artifact(run, exploit_artifact)
    artifact_digest_before = _sha256(artifact)
    metadata = dict(sandbox_metadata)
    try:
        _validate_metadata(
            run, metadata, challenge_id, input_fingerprint, target_revision, session,
        )
    except WorkingPocError as exc:
        if str(exc).startswith("ENDPOINT_CHANGED:"):
            _record_preflight_blocker(
                run, challenge_id=challenge_id, session_id=session,
                input_fingerprint=input_fingerprint, target_revision=target_revision,
                operation_id=operation, blocker_type="ENDPOINT_CHANGED",
                reason=str(exc), argv=argv, artifact=exploit_artifact,
                details={"sandbox_target_revision": metadata.get("target_revision")},
            )
        raise
    try:
        target = _selected_target(declared_targets, target_index)
        _validate_authorized_target(metadata, target)
    except WorkingPocError as exc:
        if str(exc).startswith("SCOPE_BLOCKED:"):
            _record_preflight_blocker(
                run, challenge_id=challenge_id, session_id=session,
                input_fingerprint=input_fingerprint, target_revision=target_revision,
                operation_id=operation, blocker_type="SCOPE_BLOCKED",
                reason=str(exc), argv=argv, artifact=exploit_artifact,
                details={"target_index": target_index},
            )
        raise
    local_receipt = _local_poc_receipt(
        run, local_receipt_id, session, exploit_artifact, artifact_digest_before,
    )
    material = {
        "run_id": run.name, "challenge_id": challenge_id,
        "input_fingerprint": input_fingerprint, "target_revision": target_revision,
        "session_id": session, "operation_id": operation,
        "sandbox": {
            "name": metadata.get("name"), "branch": metadata.get("branch"),
            "metadata_path": metadata.get("metadata_path"),
        },
        "local_receipt_id": local_receipt_id,
        "exploit_artifact": exploit_artifact,
        "exploit_artifact_digest_before": artifact_digest_before,
        "remote_argv": argv, "command_digest": _command_digest(argv),
        "target_index": target_index, "target": target.to_dict(),
        "success_condition": _text(success_condition, "success_condition", 2000),
        "kill_condition": _text(kill_condition, "kill_condition", 2000),
    }
    operation_path = _operation_path(run, operation)
    with _operation_lock(run):
        operation_record = _load_operation(operation_path)
        if operation_record is None:
            operation_record = {
                "schema_version": 2, "operation_id": operation,
                "canonical_material": material, "status": "PREPARED",
                "working_poc_receipt_id": None, "execution_attempt_id": None,
                "execution_started_at": None, "execution": None,
                "remote_attempt_receipt_id": None, "response": None,
                "resolution": None,
            }
            atomic_json(operation_path, operation_record)
        else:
            _validate_operation_material(operation_record, material)
            terminal = _terminal_operation_response(operation_record)
            if terminal is not None:
                return terminal
            uncertain = _handle_uncertain_operation(run, operation_path, operation_record)
            if uncertain is not None:
                return uncertain

    working_id = operation_record.get("working_poc_receipt_id")
    if working_id:
        working = _milestone_by_id(run, str(working_id), "WORKING_POC")
    else:
        working = save_milestone(
            run, challenge_id=challenge_id, session_id=session,
            input_fingerprint=input_fingerprint, target_revision=target_revision,
            event_type="WORKING_POC", summary="local PoC explicitly committed for declared remote execution",
            evidence=[f"milestone-receipts.jsonl#{local_receipt_id}"],
            artifacts=[exploit_artifact], command_argv=local_receipt.get("command_argv", []),
            output=str(local_receipt.get("output_excerpt") or ""), exploit_proximity=.85,
            details={
                "local_receipt_id": local_receipt_id,
                "success_condition": material["success_condition"],
                "kill_condition": material["kill_condition"],
            },
            declared_remote=True, operation_id=f"{operation}:working-poc",
        )
        with _operation_lock(run):
            operation_record = _required_operation(operation_path, material)
            terminal = _terminal_operation_response(operation_record)
            if terminal is not None:
                return terminal
            uncertain = _handle_uncertain_operation(run, operation_path, operation_record)
            if uncertain is not None:
                return uncertain
            if not operation_record.get("working_poc_receipt_id"):
                operation_record["working_poc_receipt_id"] = working["receipt_id"]
                operation_record["status"] = "WORKING_POC_RECORDED"
                atomic_json(operation_path, operation_record)
            else:
                working = _milestone_by_id(
                    run, str(operation_record["working_poc_receipt_id"]), "WORKING_POC",
                )

    command_executed = False
    execution_guard: BinaryIO | None = None
    with _operation_lock(run):
        operation_record = _required_operation(operation_path, material)
        terminal = _terminal_operation_response(operation_record)
        if terminal is not None:
            return terminal
        uncertain = _handle_uncertain_operation(run, operation_path, operation_record)
        if uncertain is not None:
            return uncertain
        execution = operation_record.get("execution")
        if not isinstance(execution, Mapping):
            execution_guard = _try_execution_guard(run, operation)
            if execution_guard is None:
                raise WorkingPocError("working PoC execution guard is unexpectedly busy")
            attempt_id = uuid.uuid4().hex
            operation_record.update({
                "status": "EXECUTION_STARTED",
                "execution_attempt_id": attempt_id,
                "execution_started_at": utc_now(),
                "command_digest": material["command_digest"],
                "artifact_digest": artifact_digest_before,
                "target_identity": material["target"],
            })
            atomic_json(operation_path, operation_record)
        else:
            attempt_id = str(operation_record.get("execution_attempt_id") or "")

    if execution_guard is not None:
        try:
            _working_poc_failpoint("execution_started", "after", operation_record)
            result = dict(executor(
                metadata, argv, timeout,
                session_id=str(metadata.get("parent_session_id") or "sol-main"),
                session_role="sol",
            ))
            command_executed = True
            artifact_digest_after = _sha256(artifact)
            stdout = str(result.get("stdout") or "")[-64_000:]
            stderr = str(result.get("stderr") or "")[-64_000:]
            execution = {
                "execution_attempt_id": attempt_id,
                "command_argv": argv, "command_digest": material["command_digest"],
                "exit_code": result.get("exit_code"), "timed_out": bool(result.get("timed_out")),
                "stdout": stdout, "stderr": stderr,
                "stdout_digest": hashlib.sha256(stdout.encode()).hexdigest(),
                "stderr_digest": hashlib.sha256(stderr.encode()).hexdigest(),
                "authorized_network_observed": result.get("authorized_network_observed") is True,
                "input_fingerprint": result.get("input_fingerprint"),
                "exploit_artifact_digest_before": artifact_digest_before,
                "exploit_artifact_digest_after": artifact_digest_after,
                "target_identity": material["target"],
                "recorded_at": utc_now(),
            }
            with _operation_lock(run):
                operation_record = _required_operation(operation_path, material)
                if operation_record.get("execution_attempt_id") != attempt_id:
                    raise WorkingPocError("working PoC execution attempt identity changed")
                if execution["input_fingerprint"] != input_fingerprint:
                    operation_record["status"] = "EXECUTION_OUTCOME_UNKNOWN"
                    operation_record["execution_validation_error"] = (
                        "remote execution receipt input fingerprint mismatch"
                    )
                    atomic_json(operation_path, operation_record)
                    raise WorkingPocError("remote execution receipt input fingerprint mismatch")
                operation_record["execution"] = execution
                operation_record["status"] = "EXECUTION_RECORDED"
                atomic_json(operation_path, operation_record)
            _working_poc_failpoint("execution_record", "after", operation_record)
        finally:
            _release_execution_guard(execution_guard)

    with _operation_lock(run):
        operation_record = _required_operation(operation_path, material)
        execution = operation_record.get("execution")
        if not isinstance(execution, Mapping):
            raise WorkingPocError("working PoC execution outcome is not recorded")

    combined_output = str(execution.get("stdout") or "") + "\n" + str(execution.get("stderr") or "")
    remote_id = operation_record.get("remote_attempt_receipt_id")
    if remote_id:
        remote_attempt = _milestone_by_id(run, str(remote_id), "REMOTE_ATTEMPT")
    else:
        remote_attempt = save_milestone(
            run, challenge_id=challenge_id, session_id=session,
            input_fingerprint=input_fingerprint, target_revision=target_revision,
            event_type="REMOTE_ATTEMPT", summary="explicit declared remote PoC attempt",
            evidence=[f"working-poc-operations/{operation_path.name}"],
            artifacts=[exploit_artifact], command_argv=argv, output=combined_output,
            exploit_proximity=.92,
            details={
                "working_poc_receipt_id": working["receipt_id"],
                "target": target.to_dict(),
                "authorized_network_observed": execution.get("authorized_network_observed") is True,
                "exit_code": execution.get("exit_code"),
                "artifact_digest_before": execution.get("exploit_artifact_digest_before"),
                "artifact_digest_after": execution.get("exploit_artifact_digest_after"),
            }, declared_remote=True, operation_id=f"{operation}:remote-attempt",
        )
        with _operation_lock(run):
            operation_record = _required_operation(operation_path, material)
            if not operation_record.get("remote_attempt_receipt_id"):
                operation_record["remote_attempt_receipt_id"] = remote_attempt["receipt_id"]
                operation_record["status"] = "REMOTE_ATTEMPT_RECORDED"
                atomic_json(operation_path, operation_record)
            else:
                remote_attempt = _milestone_by_id(
                    run, str(operation_record["remote_attempt_receipt_id"]), "REMOTE_ATTEMPT",
                )
        _working_poc_failpoint("remote_receipt", "after", operation_record)

    candidates = _flag_candidates(combined_output, flag_pattern)
    verified: dict[str, Any] | None = None
    projected_candidates: list[dict[str, Any]] = []
    if execution.get("authorized_network_observed") is True and len(candidates) == 1:
        candidate = candidates[0]
        verified = record_remote_flag(
            run, challenge_id=challenge_id, input_fingerprint=input_fingerprint,
            branch_id=session, declared_targets=declared_targets,
            observed_host=target.host, observed_port=target.port,
            observed_protocol=target.protocol, network_observed=True,
            output=combined_output, candidate=candidate, flag_pattern=flag_pattern,
            command_argv=argv, exploit_artifact=exploit_artifact,
            target_revision=target_revision,
        )
    elif candidates:
        for candidate in candidates:
            receipt = save_milestone(
                run, challenge_id=challenge_id, session_id=session,
                input_fingerprint=input_fingerprint, target_revision=target_revision,
                event_type="FLAG_CANDIDATE", summary="remote output contained an ambiguous flag candidate",
                evidence=[f"milestone-receipts.jsonl#{remote_attempt['receipt_id']}"],
                artifacts=[exploit_artifact], command_argv=argv, output=combined_output,
                exploit_proximity=.95, details={"ambiguous_candidate_count": len(candidates)},
                declared_remote=True,
                operation_id=f"{operation}:candidate:{hashlib.sha256(candidate.encode()).hexdigest()[:12]}",
                candidate=candidate, source_type="REMOTE_OUTPUT",
                validation_method="UNVALIDATED", confidence="MEDIUM",
            )
            projected_candidates.append({
                "candidate": candidate, "receipt_id": receipt["receipt_id"],
                "confidence": "MEDIUM",
            })

    blocker = None
    if execution.get("authorized_network_observed") is not True:
        blocker_type = _classify_blocker(execution)
        if blocker_type:
            blocker = save_milestone(
                run, challenge_id=challenge_id, session_id=session,
                input_fingerprint=input_fingerprint, target_revision=target_revision,
                event_type="TYPED_BLOCKER", summary=f"declared remote attempt blocked: {blocker_type}",
                evidence=[f"milestone-receipts.jsonl#{remote_attempt['receipt_id']}"],
                command_argv=argv, output=combined_output, exploit_proximity=.82,
                details={"blocker_type": blocker_type, "exit_code": execution.get("exit_code")},
                declared_remote=True, operation_id=f"{operation}:blocker",
            )

    _working_poc_failpoint("flag_projection", "after", operation_record)

    response = {
        "run_id": run.name, "operation_id": operation,
        "working_poc_receipt_id": working["receipt_id"],
        "remote_attempt_receipt_id": remote_attempt["receipt_id"],
        "execution": dict(execution), "flag_candidates": projected_candidates,
        "verified_flag": verified, "blocker": blocker,
        "state": verified.get("state") if verified else "REMOTE_ATTEMPT",
        "idempotent": False, "remote_command_executed": command_executed,
    }
    with _operation_lock(run):
        operation_record = _required_operation(operation_path, material)
        terminal = _terminal_operation_response(operation_record)
        if terminal is not None:
            return terminal
        operation_record["status"] = "COMPLETED"
        operation_record["response"] = response
        atomic_json(operation_path, operation_record)
    return response


def resolve_unknown_working_poc(
    root: Path, *, operation_id: str, decision: str,
    resolution_receipt: Mapping[str, Any], new_operation_id: str | None = None,
    declared_targets: Sequence[Target] = (), flag_pattern: str | None = None,
) -> dict[str, Any]:
    """Resolve an uncertain remote attempt without ever replaying its operation ID."""

    run = resolve_active_run(root)
    operation = _text(operation_id, "operation_id", 256)
    normalized = str(decision or "").strip().upper()
    if normalized not in {"RECORD_RESULT", "ABANDON", "AUTHORIZE_RETRY"}:
        raise WorkingPocError(
            "unknown outcome decision must be RECORD_RESULT, ABANDON, or AUTHORIZE_RETRY"
        )
    path = _operation_path(run, operation)
    proof = dict(resolution_receipt)
    retry_operation = (
        _text(new_operation_id, "new_operation_id", 256)
        if new_operation_id is not None else None
    )
    with _operation_lock(run):
        record = _load_operation(path)
        if record is None:
            raise WorkingPocError("unknown working PoC operation does not exist")
        if record.get("status") not in {"EXECUTION_STARTED", "EXECUTION_OUTCOME_UNKNOWN"}:
            raise WorkingPocError("working PoC operation is not awaiting unknown-outcome resolution")
        guard = _try_execution_guard(run, operation)
        if guard is None:
            raise WorkingPocError("working PoC executor is still active; unknown outcome cannot be resolved")
        try:
            material = record.get("canonical_material")
            if not isinstance(material, Mapping):
                raise WorkingPocError("working PoC operation canonical material is malformed")
            _validate_resolution_identity(run, record, proof)
            execution: dict[str, Any] | None = None
            if normalized == "RECORD_RESULT":
                execution = _operator_execution(run, material, record, proof)
            if normalized == "AUTHORIZE_RETRY" and (
                retry_operation is None or retry_operation == operation
            ):
                raise WorkingPocError("AUTHORIZE_RETRY requires a distinct new operation ID")
            resolution = _resolution_record(
                run, record, normalized, proof, new_operation_id=retry_operation,
            )
            receipt_path = (
                run / "working-poc-resolution-receipts" / f"{resolution['receipt_id']}.json"
            )
            atomic_json(receipt_path, resolution)
            if normalized == "RECORD_RESULT":
                assert execution is not None
                record["execution"] = execution
                record["status"] = "EXECUTION_RECORDED"
            elif normalized == "ABANDON":
                record["status"] = "ABANDONED"
            else:
                assert retry_operation is not None
                retry_path = _operation_path(run, retry_operation)
                if _load_operation(retry_path) is not None:
                    raise WorkingPocError("authorized retry operation ID already exists")
                retry_material = dict(material)
                retry_material["operation_id"] = retry_operation
                retry_record = {
                    "schema_version": 2, "operation_id": retry_operation,
                    "canonical_material": retry_material, "status": "PREPARED",
                    "working_poc_receipt_id": None, "execution_attempt_id": None,
                    "execution_started_at": None, "execution": None,
                    "remote_attempt_receipt_id": None, "response": None,
                    "resolution": None,
                    "supersedes_unknown_operation": operation,
                    "operator_authorization_receipt": str(receipt_path.relative_to(run)),
                }
                atomic_json(retry_path, retry_record)
                record["status"] = "ABANDONED"
                record["authorized_retry_operation_id"] = retry_operation
            record["resolution"] = {
                "decision": normalized,
                "receipt_id": resolution["receipt_id"],
                "path": str(receipt_path.relative_to(run)),
            }
            atomic_json(path, record)
        finally:
            _release_execution_guard(guard)

    if normalized != "RECORD_RESULT":
        return {
            "run_id": run.name, "operation_id": operation, "status": record["status"],
            "decision": normalized, "remote_command_executed": False,
            "authorized_retry_operation_id": record.get("authorized_retry_operation_id"),
            "operator_authorization_receipt": record["resolution"],
        }

    material = dict(record["canonical_material"])
    metadata_path = Path(str((material.get("sandbox") or {}).get("metadata_path") or ""))
    metadata = _json(metadata_path, "sandbox metadata")
    return commit_working_poc(
        run, challenge_id=str(material["challenge_id"]),
        input_fingerprint=str(material["input_fingerprint"]),
        target_revision=int(material["target_revision"]),
        session_id=str(material["session_id"]), sandbox_metadata=metadata,
        local_receipt_id=str(material["local_receipt_id"]),
        exploit_artifact=str(material["exploit_artifact"]),
        remote_argv=list(material["remote_argv"]), declared_targets=declared_targets,
        target_index=int(material["target_index"]), flag_pattern=flag_pattern,
        success_condition=str(material["success_condition"]),
        kill_condition=str(material["kill_condition"]), operation_id=operation,
        executor=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            WorkingPocError("resolved unknown operation attempted an automatic retry")
        ),
    )


def _validate_operation_material(
    record: Mapping[str, Any], material: Mapping[str, Any],
) -> None:
    if record.get("canonical_material") != material:
        raise WorkingPocError(
            "operation_id already exists with conflicting remote argv, target, or artifact digest"
        )


def _required_operation(path: Path, material: Mapping[str, Any]) -> dict[str, Any]:
    record = _load_operation(path)
    if record is None:
        raise WorkingPocError("working PoC operation disappeared")
    _validate_operation_material(record, material)
    return record


def _terminal_operation_response(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("status") == "COMPLETED":
        response = record.get("response")
        if not isinstance(response, dict):
            raise WorkingPocError("completed working PoC operation has no response")
        return {**response, "idempotent": True, "remote_command_executed": False}
    if record.get("status") == "ABANDONED":
        raise WorkingPocError("working PoC operation is ABANDONED and cannot be reused")
    return None


def _handle_uncertain_operation(
    run: Path, path: Path, record: dict[str, Any],
) -> dict[str, Any] | None:
    status = str(record.get("status") or "")
    if status not in {"EXECUTION_STARTED", "EXECUTION_OUTCOME_UNKNOWN"}:
        return None
    guard = _try_execution_guard(run, str(record.get("operation_id") or ""))
    if guard is None:
        return _unknown_response(record, active=True)
    try:
        if status == "EXECUTION_STARTED":
            record["status"] = "EXECUTION_OUTCOME_UNKNOWN"
            record["outcome_marked_unknown_at"] = utc_now()
            atomic_json(path, record)
        return _unknown_response(record, active=False)
    finally:
        _release_execution_guard(guard)


def _unknown_response(record: Mapping[str, Any], *, active: bool) -> dict[str, Any]:
    return {
        "run_id": (record.get("canonical_material") or {}).get("run_id"),
        "operation_id": record.get("operation_id"),
        "execution_attempt_id": record.get("execution_attempt_id"),
        "status": "EXECUTION_STARTED" if active else "EXECUTION_OUTCOME_UNKNOWN",
        "remote_command_executed": False,
        "automatic_retry_blocked": True,
        "manual_resolution_required": not active,
        "executor_active": active,
        "idempotent": True,
    }


@contextmanager
def _operation_lock(run: Path) -> Iterator[None]:
    lock_path = run / ".WORKING_POC.lock"
    if lock_path.is_symlink():
        raise WorkingPocError("working PoC operation lock is unsafe")
    descriptor = os.open(
        lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600,
    )
    with os.fdopen(descriptor, "a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _try_execution_guard(run: Path, operation_id: str) -> BinaryIO | None:
    digest = hashlib.sha256(operation_id.encode()).hexdigest()[:32]
    path = run / "working-poc-operations" / f"{digest}.execution.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise WorkingPocError("working PoC execution guard is unsafe")
    descriptor = os.open(
        path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600,
    )
    handle = os.fdopen(descriptor, "a+b")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        return None
    return handle


def _release_execution_guard(handle: BinaryIO) -> None:
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def _validate_resolution_identity(
    run: Path, record: Mapping[str, Any], proof: Mapping[str, Any],
) -> None:
    material = record.get("canonical_material")
    if not isinstance(material, Mapping):
        raise WorkingPocError("working PoC canonical material is malformed")
    expected = {
        "run_id": run.name, "challenge_id": material.get("challenge_id"),
        "session_id": material.get("session_id"),
        "input_fingerprint": material.get("input_fingerprint"),
        "target_revision": material.get("target_revision"),
        "operation_id": record.get("operation_id"),
        "execution_attempt_id": record.get("execution_attempt_id"),
        "command_digest": material.get("command_digest"),
        "artifact_digest": material.get("exploit_artifact_digest_before"),
        "target_identity": material.get("target"),
    }
    for field, value in expected.items():
        if proof.get(field) != value:
            raise WorkingPocError(f"unknown outcome resolution {field} mismatch")


def _operator_execution(
    run: Path, material: Mapping[str, Any], record: Mapping[str, Any],
    proof: Mapping[str, Any],
) -> dict[str, Any]:
    exit_code = proof.get("exit_code")
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        raise WorkingPocError("RECORD_RESULT requires an integer exit status")
    if not isinstance(proof.get("authorized_network_observed"), bool):
        raise WorkingPocError("RECORD_RESULT requires a boolean network observation")
    stdout = str(proof.get("stdout") or "")
    stderr = str(proof.get("stderr") or "")
    if len(stdout) > 64_000 or len(stderr) > 64_000:
        raise WorkingPocError("RECORD_RESULT preserved output exceeds the execution receipt limit")
    stdout_digest = hashlib.sha256(stdout.encode()).hexdigest()
    stderr_digest = hashlib.sha256(stderr.encode()).hexdigest()
    if proof.get("stdout_digest") != stdout_digest or proof.get("stderr_digest") != stderr_digest:
        raise WorkingPocError("RECORD_RESULT stdout/stderr digest mismatch")
    artifact_path = _artifact(run, str(material.get("exploit_artifact") or ""))
    if _sha256(artifact_path) != material.get("exploit_artifact_digest_before"):
        raise WorkingPocError("RECORD_RESULT exploit artifact no longer matches the attempted artifact")
    artifact_after = proof.get("artifact_digest_after", proof.get("artifact_digest"))
    if not isinstance(artifact_after, str) or not re.fullmatch(r"[0-9a-f]{64}", artifact_after):
        raise WorkingPocError("RECORD_RESULT artifact digest is invalid")
    return {
        "execution_attempt_id": record.get("execution_attempt_id"),
        "command_argv": list(material.get("remote_argv") or []),
        "command_digest": material.get("command_digest"),
        "exit_code": exit_code, "timed_out": proof.get("timed_out") is True,
        "stdout": stdout, "stderr": stderr,
        "stdout_digest": stdout_digest, "stderr_digest": stderr_digest,
        "authorized_network_observed": proof["authorized_network_observed"],
        "input_fingerprint": material.get("input_fingerprint"),
        "exploit_artifact_digest_before": material.get("exploit_artifact_digest_before"),
        "exploit_artifact_digest_after": artifact_after,
        "target_identity": material.get("target"),
        "recorded_at": utc_now(), "source": "OPERATOR_RECORD_RESULT",
    }


def _resolution_record(
    run: Path, operation: Mapping[str, Any], decision: str,
    proof: Mapping[str, Any], *, new_operation_id: str | None,
) -> dict[str, Any]:
    material = {
        "run_id": run.name, "operation_id": operation.get("operation_id"),
        "execution_attempt_id": operation.get("execution_attempt_id"),
        "decision": decision, "proof": dict(proof),
        "new_operation_id": new_operation_id,
    }
    receipt_id = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode(),
    ).hexdigest()[:24]
    return {
        "schema_version": 1, "receipt_id": receipt_id, **material,
        "created_at": utc_now(), "automatic_retry_performed": False,
    }


def _local_poc_receipt(
    run: Path, receipt_id: str, session_id: str, artifact: str, artifact_digest: str,
) -> dict[str, Any]:
    receipt = next((row for row in load_milestones(run) if row.get("receipt_id") == receipt_id), None)
    if receipt is None or receipt.get("session_id") != session_id:
        raise WorkingPocError("local PoC receipt does not exist for this session")
    valid = receipt.get("event_type") == "WORKING_POC" or (
        receipt.get("event_type") == "DECISIVE_EXPERIMENT"
        and isinstance(receipt.get("details"), Mapping)
        and receipt["details"].get("local_poc_verified") is True
    )
    if not valid or not receipt.get("command_digest"):
        raise WorkingPocError("local receipt does not prove a command-backed working PoC")
    if artifact not in receipt.get("artifacts", []):
        raise WorkingPocError("local PoC receipt is not linked to the exploit artifact")
    digest = (receipt.get("artifact_digests") or {}).get(artifact)
    if digest != artifact_digest:
        raise WorkingPocError("exploit artifact digest differs from the local PoC receipt")
    return receipt


def _milestone_by_id(run: Path, receipt_id: str, event_type: str) -> dict[str, Any]:
    receipt = next((row for row in load_milestones(run) if row.get("receipt_id") == receipt_id), None)
    if receipt is None or receipt.get("event_type") != event_type:
        raise WorkingPocError("working PoC operation references a missing milestone receipt")
    return receipt


def _validate_metadata(
    run: Path, metadata: Mapping[str, Any], challenge_id: str,
    fingerprint: str, revision: int, session_id: str,
) -> None:
    branch_root = Path(str(metadata.get("branch_root") or "")).resolve()
    expected = (run / "workers" / session_id).resolve()
    if branch_root != expected or metadata.get("branch") != session_id:
        raise WorkingPocError("sandbox metadata is not owned by the selected branch")
    if metadata.get("challenge_id") != challenge_id or metadata.get("input_fingerprint") != fingerprint:
        raise WorkingPocError("sandbox metadata challenge fingerprint is stale")
    if metadata.get("target_revision") != revision:
        raise WorkingPocError("ENDPOINT_CHANGED: sandbox target revision is stale")
    metadata_path = Path(str(metadata.get("metadata_path") or "")).resolve()
    if metadata_path != expected / "sandbox.json" or metadata_path.is_symlink() or not metadata_path.is_file():
        raise WorkingPocError("sandbox metadata identity is missing or unsafe")


def _selected_target(targets: Sequence[Target], index: int) -> Target:
    if not isinstance(index, int) or isinstance(index, bool) or index < 0 or index >= len(targets):
        raise WorkingPocError("SCOPE_BLOCKED: declared target index is invalid")
    return targets[index]


def _validate_authorized_target(metadata: Mapping[str, Any], target: Target) -> None:
    rows = metadata.get("authorized_targets")
    if not isinstance(rows, list) or not any(
        isinstance(row, Mapping)
        and row.get("declared") == target.declared
        and row.get("host") == target.host
        and row.get("port") == target.port
        and row.get("protocol") == target.protocol
        for row in rows
    ):
        raise WorkingPocError("SCOPE_BLOCKED: target is not authorized by sandbox metadata")


def _flag_candidates(output: str, pattern: str | None) -> list[str]:
    if not pattern:
        return []
    searchable = pattern.replace(r"\A", "").replace(r"\Z", "")
    try:
        regex = re.compile(searchable)
    except re.error as exc:
        raise WorkingPocError("flag pattern is invalid") from exc
    values = []
    for match in regex.finditer(output):
        candidate = match.group(0)
        if candidate not in values and matches_flag(candidate, pattern):
            values.append(candidate)
    return values


def _classify_blocker(execution: Mapping[str, Any]) -> str | None:
    text = (str(execution.get("stdout") or "") + "\n" + str(execution.get("stderr") or "")).casefold()
    if "429" in text or "rate limit" in text or "too many requests" in text:
        return "RATE_LIMITED"
    if any(token in text for token in ("authentication required", "missing credential", "unauthorized", "forbidden")):
        return "AUTH_BLOCKED"
    if any(token in text for token in (
        "connection refused", "connection timed out", "connection timeout",
        "connect timeout", "socket.timeout", "no route to host",
        "network is unreachable", "name or service not known",
    )):
        return "TARGET_DOWN"
    if any(token in text for token in ("protocol mismatch", "wrong version number", "handshake failure", "unexpected protocol")):
        return "PROTOCOL_MISMATCH"
    return None


def _record_preflight_blocker(
    run: Path, *, challenge_id: str, session_id: str,
    input_fingerprint: str, target_revision: int, operation_id: str,
    blocker_type: str, reason: str, argv: Sequence[str], artifact: str,
    details: Mapping[str, Any],
) -> None:
    save_milestone(
        run, challenge_id=challenge_id, session_id=session_id,
        input_fingerprint=input_fingerprint, target_revision=target_revision,
        event_type="TYPED_BLOCKER", summary=reason,
        evidence=["working-poc preflight validation"], artifacts=[artifact],
        command_argv=argv, output=reason, exploit_proximity=.82,
        details={"blocker_type": blocker_type, **dict(details)},
        declared_remote=True,
        operation_id=f"{operation_id}:preflight:{blocker_type.casefold()}",
    )


def _operation_path(run: Path, operation_id: str) -> Path:
    digest = hashlib.sha256(operation_id.encode()).hexdigest()[:32]
    return run / "working-poc-operations" / f"{digest}.json"


def _load_operation(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return _json(path, "working PoC operation")


def _artifact(run: Path, value: str) -> Path:
    reference = Path(value)
    if reference.is_absolute() or any(part in {"", ".", ".."} for part in reference.parts):
        raise WorkingPocError("exploit artifact must be a safe run-relative path")
    path = safe_under(run, reference)
    if path.is_symlink() or not path.is_file():
        raise WorkingPocError("exploit artifact is missing or unsafe")
    return path


def _argv(values: Sequence[str]) -> list[str]:
    if isinstance(values, (str, bytes)) or not values or len(values) > 256:
        raise WorkingPocError("remote command must be a non-empty direct argv array")
    forbidden = {";", "&&", "||", "|", ">", ">>", "<", "&"}
    result = [str(value) for value in values]
    if any(not value or value in forbidden or any(char in value for char in "\0\r\n") for value in result):
        raise WorkingPocError("remote command contains a shell operator or invalid argv")
    return result


def _command_digest(argv: Sequence[str]) -> str:
    return hashlib.sha256(json.dumps(list(argv), separators=(",", ":")).encode()).hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise WorkingPocError(f"{label} is missing or unsafe")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkingPocError(f"{label} is malformed") from exc
    if not isinstance(payload, dict):
        raise WorkingPocError(f"{label} is not an object")
    return payload


def _text(value: Any, field: str, maximum: int) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum or any(char in text for char in "\0\r\n"):
        raise WorkingPocError(f"{field} is invalid")
    return text


def _token(value: Any, field: str) -> str:
    text = _text(value, field, 128)
    if any(char in text for char in "/\\"):
        raise WorkingPocError(f"{field} is invalid")
    return text


def _working_poc_failpoint(
    boundary: str, phase: str, record: Mapping[str, Any],
) -> None:
    """Private no-op seam used only by fault-injection tests."""
