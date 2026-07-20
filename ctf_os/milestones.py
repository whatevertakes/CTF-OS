"""Compact typed milestone receipts shared by Sol and native children."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path
from typing import Any

from .workspace import (
    append_jsonl_fsync, atomic_json, read_jsonl_strict, resolve_active_run, state_lock,
    update_run_manifest_timing, utc_now,
)


MILESTONE_SCHEMA_VERSION = 1
MILESTONE_TYPES = frozenset({
    "DECISIVE_EXPERIMENT", "PRIMITIVE_CANDIDATE", "PRIMITIVE_CONFIRMED",
    "PRIMITIVE_REFUTED", "WORKING_POC", "REMOTE_ATTEMPT", "FLAG_CANDIDATE",
    "TYPED_BLOCKER", "LONG_COMPUTE", "CHILD_TERMINAL_RESULT",
})
TIMING_FIELDS = {
    "DECISIVE_EXPERIMENT": "first_decisive_experiment_at",
    "PRIMITIVE_CONFIRMED": "primitive_confirmed_at",
    "WORKING_POC": "working_poc_at", "REMOTE_ATTEMPT": "first_remote_attempt_at",
    "FLAG_CANDIDATE": "flag_observed_at",
}
LONG_COMPUTE_FIELDS = frozenset({
    "process_identity", "expected_output_artifact", "expected_completion_signal",
    "maximum_duration_seconds", "checkpoint_interval_seconds", "resource_requirement",
    "cancel_condition", "fallback_plan",
})


class MilestoneError(ValueError):
    pass


def save_milestone(
    root: Path, *, challenge_id: str, session_id: str,
    input_fingerprint: str, event_type: str, summary: str,
    evidence: Sequence[str] = (), artifacts: Sequence[str] = (),
    command_argv: Sequence[str] = (), output: str = "",
    exploit_proximity: float = 0.0, details: Mapping[str, Any] | None = None,
    target_revision: int | None = None, declared_remote: bool = False,
) -> dict[str, Any]:
    run = resolve_active_run(root, input_fingerprint=input_fingerprint, target_revision=target_revision)
    normalized_type = event_type.strip().upper()
    if normalized_type not in MILESTONE_TYPES:
        raise MilestoneError(f"event_type must be one of {sorted(MILESTONE_TYPES)}")
    if not isinstance(exploit_proximity, (int, float)) or isinstance(exploit_proximity, bool) or not 0 <= float(exploit_proximity) <= 1:
        raise MilestoneError("exploit_proximity must be from 0 through 1")
    argv = _argv(command_argv)
    detail = dict(details or {})
    if normalized_type == "LONG_COMPUTE":
        missing = sorted(LONG_COMPUTE_FIELDS.difference(detail))
        if missing:
            raise MilestoneError("LONG_COMPUTE is missing: " + ", ".join(missing))
        _positive_int(detail["maximum_duration_seconds"], "maximum_duration_seconds")
        _positive_int(detail["checkpoint_interval_seconds"], "checkpoint_interval_seconds")
        if int(detail["checkpoint_interval_seconds"]) > int(detail["maximum_duration_seconds"]):
            raise MilestoneError("LONG_COMPUTE checkpoint interval exceeds maximum duration")
        _artifacts([str(detail["expected_output_artifact"])])
    if normalized_type == "REMOTE_ATTEMPT" and not argv:
        raise MilestoneError("REMOTE_ATTEMPT requires the exact direct command argv")
    if normalized_type == "TYPED_BLOCKER":
        blocker = str(detail.get("blocker_type") or "").upper()
        allowed = {
            "TARGET_DOWN", "AUTH_BLOCKED", "RATE_LIMITED", "ENDPOINT_CHANGED",
            "PROTOCOL_MISMATCH", "LOCAL_ONLY_CHALLENGE", "INPUT_UNAVAILABLE",
            "TOOL_UNAVAILABLE", "SCOPE_BLOCKED",
        }
        if blocker not in allowed:
            raise MilestoneError(f"TYPED_BLOCKER details.blocker_type must be one of {sorted(allowed)}")
        detail["blocker_type"] = blocker
    with state_lock(run):
        state = _state(run)
        if state.get("challenge_id") != challenge_id:
            raise MilestoneError("milestone challenge identity mismatch")
        if state.get("input_fingerprint") != input_fingerprint:
            raise MilestoneError("milestone fingerprint mismatch")
        if target_revision is not None and state.get("target_revision") != target_revision:
            raise MilestoneError("milestone target revision mismatch")
        terminal_only = normalized_type == "CHILD_TERMINAL_RESULT"
        immutable_terminal = terminal_only and bool(state.get("sealed") or state.get("remote_flag_receipt"))
        if state.get("sealed") and not terminal_only:
            raise MilestoneError("sealed run is immutable")
        if state.get("remote_flag_receipt") and not terminal_only:
            raise MilestoneError("verified remote flag run is immutable pending human submission feedback")
        rows = load_milestones(run)
        sequence = 1 + max(
            (int(row.get("sequence", 0)) for row in rows if row.get("session_id") == session_id),
            default=0,
        )
        command_digest = hashlib.sha256(
            json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode(),
        ).hexdigest() if argv else None
        output_digest = hashlib.sha256(output.encode()).hexdigest() if output else None
        material = {
            "run_id": str(state.get("run_id") or run.name), "challenge_id": challenge_id,
            "session_id": _text(session_id, "session_id", 128),
            "input_fingerprint": input_fingerprint,
            "target_revision": int(state.get("target_revision") or 1),
            "sequence": sequence, "event_type": normalized_type,
            "summary": _text(summary, "summary", 2000),
            "evidence": _strings(evidence, "evidence"),
            "artifacts": _artifacts(artifacts), "command_argv": argv,
            "command_digest": command_digest, "output_digest": output_digest,
            "output_excerpt": _excerpt(output), "exploit_proximity": round(float(exploit_proximity), 4),
            "details": detail,
        }
        receipt_id = hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode(),
        ).hexdigest()[:24]
        existing = next((row for row in rows if row.get("receipt_id") == receipt_id), None)
        receipt = dict(existing) if existing else {
            "schema_version": MILESTONE_SCHEMA_VERSION, "receipt_id": receipt_id,
            **material, "created_at": utc_now(),
        }
        if existing is None:
            append_jsonl_fsync(run / "milestone-receipts.jsonl", receipt, label="milestone receipt ledger")
    if normalized_type == "CHILD_TERMINAL_RESULT":
        _project_child_terminal_result(run, receipt)
        if existing is not None:
            return {
                **receipt,
                "progress": {"counts_as_progress": False, "terminal_lifecycle": True},
                "race_transition": None, "idempotent": True,
            }
    if immutable_terminal:
        return {
            **receipt, "progress": {"counts_as_progress": False, "terminal_lifecycle": True},
            "race_transition": None, "idempotent": False,
        }
    timing = TIMING_FIELDS.get(normalized_type)
    if timing:
        update_run_manifest_timing(run, timing, receipt["created_at"])
    from .progress import register_milestone
    receipt["progress"] = register_milestone(
        run, receipt, declared_remote=declared_remote,
    )
    from .transitions import evaluate_race_transition
    receipt["race_transition"] = evaluate_race_transition(
        run, {
            "type": _transition_type(normalized_type), "event_id": receipt_id,
            "summary": receipt["summary"], "milestone_receipt_id": receipt_id,
        }, session_id, input_fingerprint,
    )
    return {**receipt, "idempotent": False}


def load_milestones(root: Path) -> list[dict[str, Any]]:
    run = resolve_active_run(root)
    rows = read_jsonl_strict(run / "milestone-receipts.jsonl", "milestone receipt ledger")
    for row in rows:
        if row.get("schema_version") != MILESTONE_SCHEMA_VERSION or row.get("event_type") not in MILESTONE_TYPES:
            raise MilestoneError("milestone receipt ledger contains an unsupported row")
    return rows


def _transition_type(event_type: str) -> str:
    return {
        "PRIMITIVE_CANDIDATE": "EXPLOIT_PRIMITIVE_CANDIDATE",
        "PRIMITIVE_CONFIRMED": "EXPLOIT_PRIMITIVE_CONFIRMED",
        "PRIMITIVE_REFUTED": "EXPLOIT_PRIMITIVE_REFUTED",
    }.get(event_type, event_type)


def _state(run: Path) -> dict[str, Any]:
    try:
        payload = json.loads((run / "STATE.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MilestoneError("run state is malformed") from exc
    if not isinstance(payload, dict):
        raise MilestoneError("run state is not an object")
    return payload


def _project_child_terminal_result(run: Path, receipt: Mapping[str, Any]) -> None:
    """Bind a terminal child result to its exact delegation branch.

    This is a terminal lifecycle projection, so it remains allowed after the
    run is sealed. A retry repairs a receipt that was appended before this
    projection without duplicating either record.
    """

    path = run / "DELEGATION_PLAN.json"
    if not path.exists() and not path.is_symlink():
        return
    with state_lock(run):
        if path.is_symlink() or not path.is_file():
            raise MilestoneError("delegation plan is missing or unsafe")
        try:
            plan = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise MilestoneError("delegation plan is malformed") from exc
        if not isinstance(plan, dict) or not isinstance(plan.get("branches"), list):
            raise MilestoneError("delegation plan schema is incomplete")
        if (
            plan.get("run_id") not in {None, receipt.get("run_id")}
            or plan.get("challenge_id") != receipt.get("challenge_id")
            or plan.get("input_fingerprint") != receipt.get("input_fingerprint")
            or plan.get("target_revision") not in {None, receipt.get("target_revision")}
        ):
            raise MilestoneError("terminal result does not match delegation plan identity")
        session_id = str(receipt.get("session_id") or "")
        branch = next(
            (row for row in plan["branches"] if isinstance(row, dict) and row.get("session_id") == session_id),
            None,
        )
        if branch is None:
            raise MilestoneError("terminal result session does not exist in the delegation plan")
        if branch.get("terminal_result_receipt_id") == receipt.get("receipt_id"):
            return
        if branch.get("terminal_result_receipt_id"):
            raise MilestoneError("branch already has a conflicting terminal result receipt")
        detail = receipt.get("details") if isinstance(receipt.get("details"), Mapping) else {}
        outcome = str(detail.get("status") or "TERMINAL").upper()
        failure_states = {
            "START_FAILED", "SANDBOX_FAILED", "INPUT_UNAVAILABLE", "TIMED_OUT",
            "TERMINATED", "ERROR", "STALE",
        }
        branch["status"] = outcome if outcome in failure_states else "TERMINAL"
        branch["terminal_outcome"] = outcome
        branch["terminal_result_receipt_id"] = receipt.get("receipt_id")
        branch["finished_at"] = receipt.get("created_at")
        branch.setdefault("lifecycle_history", []).append({
            "status": branch["status"], "created_at": receipt.get("created_at"),
            "receipt_id": receipt.get("receipt_id"),
        })
        plan["updated_at"] = utc_now()
        atomic_json(path, plan)


def _argv(values: Sequence[str]) -> list[str]:
    if isinstance(values, (str, bytes)) or len(values) > 256:
        raise MilestoneError("command_argv must be an array of at most 256 values")
    result = []
    forbidden = {";", "&&", "||", "|", ">", ">>", "<", "&"}
    for value in values:
        text = str(value)
        if not text or text in forbidden or any(char in text for char in "\0\r\n"):
            raise MilestoneError("command_argv must be direct argv without shell operators")
        result.append(text)
    return result


def _strings(values: Sequence[str], field: str) -> list[str]:
    if isinstance(values, (str, bytes)) or len(values) > 32:
        raise MilestoneError(f"{field} must be an array of at most 32 strings")
    return [_text(value, field, 1000) for value in values]


def _artifacts(values: Sequence[str]) -> list[str]:
    rows = _strings(values, "artifacts")
    for value in rows:
        path = Path(value)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise MilestoneError("artifact reference must be a safe relative path")
    return rows


def _text(value: Any, field: str, maximum: int) -> str:
    text = str(value).strip()
    if not text or len(text) > maximum or any(char in text for char in "\0\r"):
        raise MilestoneError(f"{field} is invalid")
    return text


def _positive_int(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise MilestoneError(f"{field} must be a positive integer")
    return value


def _excerpt(output: str) -> str:
    clean = str(output).replace("\x00", "\\0")
    return clean[:1024]
