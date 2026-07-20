"""Explicit one-shot WORKING_POC to declared-remote execution path."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Callable

from .flags import matches_flag
from .milestones import load_milestones, save_milestone
from .sandbox.network import Target
from .sandbox.runtime import execute
from .verification import record_remote_flag
from .workspace import atomic_json, resolve_active_run, safe_under


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
    existing = _load_operation(operation_path)
    if existing is not None:
        if existing.get("canonical_material") != material:
            raise WorkingPocError(
                "operation_id already exists with conflicting remote argv, target, or artifact digest"
            )
        if existing.get("status") == "COMPLETED":
            response = existing.get("response")
            if not isinstance(response, dict):
                raise WorkingPocError("completed working PoC operation has no response")
            return {**response, "idempotent": True, "remote_command_executed": False}
        operation_record = existing
    else:
        operation_record = {
            "schema_version": 1, "operation_id": operation,
            "canonical_material": material, "status": "PREPARED",
            "working_poc_receipt_id": None, "execution": None,
            "remote_attempt_receipt_id": None, "response": None,
        }
        atomic_json(operation_path, operation_record)

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
        operation_record["working_poc_receipt_id"] = working["receipt_id"]
        operation_record["status"] = "WORKING_POC_RECORDED"
        atomic_json(operation_path, operation_record)

    execution = operation_record.get("execution")
    command_executed = False
    if not isinstance(execution, Mapping):
        result = dict(executor(
            metadata, argv, timeout,
            session_id=str(metadata.get("parent_session_id") or "sol-main"),
            session_role="sol",
        ))
        command_executed = True
        artifact_digest_after = _sha256(artifact)
        execution = {
            "command_argv": argv, "command_digest": material["command_digest"],
            "exit_code": result.get("exit_code"), "timed_out": bool(result.get("timed_out")),
            "stdout": str(result.get("stdout") or "")[-64_000:],
            "stderr": str(result.get("stderr") or "")[-64_000:],
            "authorized_network_observed": result.get("authorized_network_observed") is True,
            "input_fingerprint": result.get("input_fingerprint"),
            "exploit_artifact_digest_before": artifact_digest_before,
            "exploit_artifact_digest_after": artifact_digest_after,
        }
        if execution["input_fingerprint"] != input_fingerprint:
            raise WorkingPocError("remote execution receipt input fingerprint mismatch")
        operation_record["execution"] = execution
        operation_record["status"] = "EXECUTION_RECORDED"
        atomic_json(operation_path, operation_record)
        _working_poc_failpoint("execution_record", "after", operation_record)

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
        operation_record["remote_attempt_receipt_id"] = remote_attempt["receipt_id"]
        operation_record["status"] = "REMOTE_ATTEMPT_RECORDED"
        atomic_json(operation_path, operation_record)
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

    response = {
        "run_id": run.name, "operation_id": operation,
        "working_poc_receipt_id": working["receipt_id"],
        "remote_attempt_receipt_id": remote_attempt["receipt_id"],
        "execution": dict(execution), "flag_candidates": projected_candidates,
        "verified_flag": verified, "blocker": blocker,
        "state": verified.get("state") if verified else "REMOTE_ATTEMPT",
        "idempotent": False, "remote_command_executed": command_executed,
    }
    operation_record["status"] = "COMPLETED"
    operation_record["response"] = response
    atomic_json(operation_path, operation_record)
    return response


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
