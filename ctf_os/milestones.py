"""Compact typed milestone receipts shared by Sol and native children."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path
from typing import Any

from .workspace import (
    append_jsonl_fsync, atomic_json, challenge_workspace, is_run_root,
    read_jsonl_strict, resolve_active_run, state_lock, safe_under,
    update_run_manifest_timing, utc_now,
)
from .projections import apply_projection, ensure_projection_manifest, mark_not_required


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
    "sandbox_metadata_path", "process_identity", "expected_output_artifact",
    "expected_completion_signal",
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
    operation_id: str | None = None, candidate: str | None = None,
    source_type: str = "STATIC_ANALYSIS", validation_method: str = "UNVALIDATED",
    confidence: str = "LOW",
) -> dict[str, Any]:
    run = resolve_active_run(root, input_fingerprint=input_fingerprint, target_revision=target_revision)
    normalized_type = event_type.strip().upper()
    if normalized_type not in MILESTONE_TYPES:
        raise MilestoneError(f"event_type must be one of {sorted(MILESTONE_TYPES)}")
    if not isinstance(exploit_proximity, (int, float)) or isinstance(exploit_proximity, bool) or not 0 <= float(exploit_proximity) <= 1:
        raise MilestoneError("exploit_proximity must be from 0 through 1")
    argv = _argv(command_argv)
    detail = _normalized_details(details or {})
    if normalized_type == "LONG_COMPUTE":
        missing = sorted(LONG_COMPUTE_FIELDS.difference(detail))
        if missing:
            raise MilestoneError("LONG_COMPUTE is missing: " + ", ".join(missing))
        _positive_int(detail["maximum_duration_seconds"], "maximum_duration_seconds")
        _positive_int(detail["checkpoint_interval_seconds"], "checkpoint_interval_seconds")
        if int(detail["checkpoint_interval_seconds"]) > int(detail["maximum_duration_seconds"]):
            raise MilestoneError("LONG_COMPUTE checkpoint interval exceeds maximum duration")
        if not argv:
            raise MilestoneError("LONG_COMPUTE requires the exact direct command argv")
        from .progress import prepare_long_compute_details
        detail = prepare_long_compute_details(
            run, session_id=session_id, command_argv=argv, details=detail,
        )
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
    candidate_projection: dict[str, Any] | None = None
    if normalized_type == "FLAG_CANDIDATE":
        if candidate is None:
            raise MilestoneError("FLAG_CANDIDATE requires candidate provenance")
        candidate_projection = {
            "candidate": _text(candidate, "candidate", 4096),
            "source_type": _text(source_type, "source_type", 128).upper(),
            "confidence": _text(confidence, "confidence", 32).upper(),
            "validation_method": _text(
                validation_method, "validation_method", 128,
            ).upper(),
        }
    elif candidate is not None:
        raise MilestoneError("candidate provenance is valid only for FLAG_CANDIDATE")
    normalized_operation = (
        _text(operation_id, "operation_id", 256) if operation_id is not None else None
    )
    normalized_session = _text(session_id, "session_id", 128)
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
        rows = _load_milestones_raw(run)
        command_digest = hashlib.sha256(
            json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode(),
        ).hexdigest() if argv else None
        output_digest = hashlib.sha256(output.encode()).hexdigest()
        artifact_references = _artifacts(artifacts)
        artifact_digests = _artifact_material(run, artifact_references)
        identity_material = {
            "run_id": str(state.get("run_id") or run.name), "challenge_id": challenge_id,
            "session_id": normalized_session,
            "input_fingerprint": input_fingerprint,
            "target_revision": int(state.get("target_revision") or 1),
            "event_type": normalized_type,
            "summary": _text(summary, "summary", 2000),
            "evidence": _strings(evidence, "evidence"),
            "artifacts": artifact_references, "artifact_digests": artifact_digests,
            "command_argv": argv,
            "command_digest": command_digest, "output_digest": output_digest,
            "exploit_proximity": round(float(exploit_proximity), 4),
            "details": detail, "candidate_projection": candidate_projection,
            "operation_id": normalized_operation,
        }
        receipt_id = hashlib.sha256(
            json.dumps(identity_material, sort_keys=True, separators=(",", ":")).encode(),
        ).hexdigest()[:24]
        if normalized_operation is not None:
            same_operation = next((
                row for row in rows if row.get("operation_id") == normalized_operation
            ), None)
            if same_operation is not None and _receipt_identity(same_operation) != identity_material:
                raise MilestoneError(
                    "operation_id already exists with conflicting canonical material"
                )
        existing = next((row for row in rows if row.get("receipt_id") == receipt_id), None)
        sequence = (
            int(existing["sequence"]) if existing is not None else
            1 + max(
                (int(row.get("sequence", 0)) for row in rows if row.get("session_id") == normalized_session),
                default=0,
            )
        )
        required = _required_projections(normalized_type, candidate_projection)
        receipt = dict(existing) if existing else {
            "schema_version": MILESTONE_SCHEMA_VERSION, "receipt_id": receipt_id,
            **identity_material, "sequence": sequence, "output_excerpt": _excerpt(output),
            "required_projections": required, "created_at": utc_now(),
        }
        if existing is None:
            append_jsonl_fsync(run / "milestone-receipts.jsonl", receipt, label="milestone receipt ledger")
            _milestone_failpoint("receipt_append", "after", receipt)
    required = list(receipt.get("required_projections") or _required_projections(
        normalized_type, candidate_projection,
    ))
    ensure_projection_manifest(run, receipt, required)
    projected = repair_receipt_projections(
        run, receipt, declared_remote=declared_remote,
        allow_immutable_terminal=immutable_terminal,
    )
    return {**receipt, **projected, "idempotent": existing is not None}


def load_milestones(root: Path) -> list[dict[str, Any]]:
    run = resolve_active_run(root)
    return _load_milestones_raw(run)


def _load_milestones_raw(run: Path) -> list[dict[str, Any]]:
    rows = read_jsonl_strict(run / "milestone-receipts.jsonl", "milestone receipt ledger")
    for row in rows:
        if row.get("schema_version") != MILESTONE_SCHEMA_VERSION or row.get("event_type") not in MILESTONE_TYPES:
            raise MilestoneError("milestone receipt ledger contains an unsupported row")
    return rows


def repair_receipt_projections(
    root: Path, receipt: Mapping[str, Any], *, declared_remote: bool = False,
    allow_immutable_terminal: bool = False,
) -> dict[str, Any]:
    """Replay only PENDING/FAILED projections for one milestone receipt."""

    run = resolve_active_run(root)
    event_type = str(receipt.get("event_type") or "").upper()
    candidate_projection = (
        dict(receipt["candidate_projection"])
        if isinstance(receipt.get("candidate_projection"), Mapping) else None
    )
    required = list(receipt.get("required_projections") or _required_projections(
        event_type, candidate_projection,
    ))
    ensure_projection_manifest(run, receipt, required)
    result: dict[str, Any] = {}
    if event_type == "CHILD_TERMINAL_RESULT":
        value, _ = apply_projection(
            run, receipt, required, "terminal_lifecycle",
            lambda: _project_child_terminal_result(run, receipt),
        )
        result["terminal_lifecycle"] = value
    else:
        if "terminal_lifecycle" in required:
            mark_not_required(run, receipt, required, "terminal_lifecycle")

    timing = TIMING_FIELDS.get(event_type)
    if timing:
        value, _ = apply_projection(
            run, receipt, required, "timing",
            lambda: update_run_manifest_timing(run, timing, str(receipt["created_at"])),
        )
        result["timing"] = value
    else:
        mark_not_required(run, receipt, required, "timing")

    if allow_immutable_terminal or event_type == "CHILD_TERMINAL_RESULT":
        for name in ("progress", "candidate", "race_transition", "state", "compatibility"):
            mark_not_required(run, receipt, required, name)
        return result | {
            "progress": {"counts_as_progress": False, "terminal_lifecycle": True},
            "race_transition": None,
        }

    from .progress import register_milestone
    value, _ = apply_projection(
        run, receipt, required, "progress",
        lambda: register_milestone(run, receipt, declared_remote=declared_remote),
    )
    result["progress"] = value

    if candidate_projection is not None:
        value, _ = apply_projection(
            run, receipt, required, "candidate",
            lambda: _project_candidate(run, receipt, candidate_projection),
        )
        result["candidate"] = value
    else:
        mark_not_required(run, receipt, required, "candidate")

    from .transitions import evaluate_race_transition
    value, _ = apply_projection(
        run, receipt, required, "race_transition",
        lambda: evaluate_race_transition(
            run, {
                "type": _transition_type(event_type), "event_id": receipt["receipt_id"],
                "summary": receipt["summary"],
                "milestone_receipt_id": receipt["receipt_id"],
            }, str(receipt.get("session_id") or ""), str(receipt.get("input_fingerprint") or ""),
        ),
    )
    result["race_transition"] = value
    apply_projection(
        run, receipt, required, "state",
        lambda: _project_milestone_state(run, receipt),
    )
    apply_projection(
        run, receipt, required, "compatibility",
        lambda: _project_compatibility_state(run),
    )
    return result


def repair_run_projections(root: Path, *, declared_remote: bool = False) -> dict[str, Any]:
    run = resolve_active_run(root)
    lineage = None
    if (run / "RACE_LINEAGE.jsonl").is_file():
        from .race_lineage import recover_lineage_projections

        lineage = recover_lineage_projections(run)
    try:
        current_state = _state(run)
    except MilestoneError:
        current_state = {}
    immutable = bool(current_state.get("sealed") or current_state.get("remote_flag_receipt"))
    repaired: list[str] = []
    deferred: list[str] = []
    for receipt in _load_milestones_raw(run):
        required = list(receipt.get("required_projections") or _required_projections(
            str(receipt.get("event_type") or ""),
            receipt.get("candidate_projection") if isinstance(receipt.get("candidate_projection"), Mapping) else None,
        ))
        manifest = ensure_projection_manifest(run, receipt, required)
        if any(
            isinstance(row, Mapping) and row.get("status") in {"PENDING", "FAILED"}
            for row in manifest.get("projections", {}).values()
        ):
            if immutable and receipt.get("event_type") != "CHILD_TERMINAL_RESULT":
                deferred.append(str(receipt.get("receipt_id")))
                continue
            repair_receipt_projections(
                run, receipt, declared_remote=declared_remote,
            )
            repaired.append(str(receipt.get("receipt_id")))
    from .terminal import repair_submission_receipt_projections
    from .transitions import repair_run_transition_projections
    from .verification import repair_remote_receipt_projections
    transitions = repair_run_transition_projections(
        run, suppress_errors=immutable,
    )
    remote = repair_remote_receipt_projections(run, suppress_errors=immutable)
    submission = repair_submission_receipt_projections(run, suppress_errors=immutable)
    return {
        "run_id": run.name, "repaired_receipts": repaired,
        "deferred_immutable_receipts": deferred,
        "race_transitions": transitions,
        "race_lineage": lineage,
        "remote_receipts": remote, "submission_receipts": submission,
    }


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
    if (run / "RACE_LINEAGE.jsonl").is_file():
        from .race_lineage import append_lineage_event, lineage_state

        session_id = str(receipt.get("session_id") or "")
        branch = next((
            row for row in lineage_state(run)["branches"]
            if row.get("session_id") == session_id
        ), None)
        if branch is None:
            raise MilestoneError("terminal result session does not exist in race lineage")
        detail = receipt.get("details") if isinstance(receipt.get("details"), Mapping) else {}
        outcome = str(detail.get("status") or "TERMINAL").upper()
        append_lineage_event(
            run, event="CHILD_TERMINAL_RESULT_RECORDED",
            branch_id=str(branch["branch_id"]), referenced_receipt=receipt,
            details={
                "result_status": outcome,
                "terminal_result_receipt_id": receipt.get("receipt_id"),
                "terminal_result_receipt": dict(receipt),
            },
        )
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


def _required_projections(
    event_type: str, candidate_projection: Mapping[str, Any] | None,
) -> list[str]:
    # Keep a fixed manifest shape so repair tooling and operators can inspect
    # every possible destination without guessing from an interrupted call.
    return [
        "terminal_lifecycle", "timing", "progress", "candidate",
        "race_transition", "state", "compatibility",
    ]


def _receipt_identity(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Return only canonical identity fields, excluding ordering/display data."""

    return {
        "run_id": receipt.get("run_id"), "challenge_id": receipt.get("challenge_id"),
        "session_id": receipt.get("session_id"),
        "input_fingerprint": receipt.get("input_fingerprint"),
        "target_revision": receipt.get("target_revision"),
        "event_type": receipt.get("event_type"), "summary": receipt.get("summary"),
        "evidence": receipt.get("evidence", []), "artifacts": receipt.get("artifacts", []),
        "artifact_digests": receipt.get("artifact_digests", {}),
        "command_argv": receipt.get("command_argv", []),
        "command_digest": receipt.get("command_digest"),
        "output_digest": receipt.get("output_digest"),
        "exploit_proximity": receipt.get("exploit_proximity", 0.0),
        "details": receipt.get("details", {}),
        "candidate_projection": receipt.get("candidate_projection"),
        "operation_id": receipt.get("operation_id"),
    }


def _artifact_material(run: Path, artifacts: Sequence[str]) -> dict[str, str]:
    digests: dict[str, str] = {}
    for reference in artifacts:
        try:
            path = safe_under(run, Path(reference))
        except ValueError as exc:
            raise MilestoneError("artifact reference is unsafe") from exc
        if path.is_file() and not path.is_symlink():
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
            digests[reference] = digest.hexdigest()
    return digests


def _normalized_details(details: Mapping[str, Any]) -> dict[str, Any]:
    try:
        encoded = json.dumps(
            dict(details), ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        )
        decoded = json.loads(encoded)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise MilestoneError("details must be a finite JSON object") from exc
    if not isinstance(decoded, dict):
        raise MilestoneError("details must be a JSON object")
    return decoded


def _project_candidate(
    run: Path, receipt: Mapping[str, Any], candidate: Mapping[str, Any],
) -> dict[str, Any]:
    from .candidates import build_candidate, load_candidates, upsert_candidate_payload

    record = build_candidate(
        run_id=str(receipt.get("run_id") or run.name),
        session_id=str(receipt.get("session_id") or ""),
        candidate=str(candidate.get("candidate") or ""),
        source_type=str(candidate.get("source_type") or "STATIC_ANALYSIS"),
        receipt_id=str(receipt.get("receipt_id") or ""),
        confidence=str(candidate.get("confidence") or "LOW"),
        validation_method=str(candidate.get("validation_method") or "UNVALIDATED"),
        status="PROPOSED",
        created_at=str(receipt.get("created_at") or utc_now()),
    )
    with state_lock(run):
        payload = load_candidates(run)
        saved, changed = upsert_candidate_payload(payload, record)
        if changed:
            atomic_json(run / "candidates.json", payload)
        state = _state(run)
        projected = [
            {
                "candidate_id": row.get("candidate_id"), "status": row.get("status"),
                "confidence": row.get("confidence"), "session_id": row.get("session_id"),
            }
            for row in payload.get("candidates", []) if isinstance(row, Mapping)
        ]
        if state.get("candidates") != projected:
            state["candidates"] = projected
            state["updated_at"] = receipt.get("created_at") or state.get("updated_at")
            atomic_json(run / "STATE.json", state)
    return {**saved, "idempotent": not changed}


def _project_milestone_state(run: Path, receipt: Mapping[str, Any]) -> None:
    mapping = {
        "DECISIVE_EXPERIMENT": "SOLVING", "PRIMITIVE_CANDIDATE": "PRIMITIVE_CANDIDATE",
        "PRIMITIVE_CONFIRMED": "PRIMITIVE_CONFIRMED", "WORKING_POC": "POC_BUILDING",
        "REMOTE_ATTEMPT": "POC_BUILDING", "FLAG_CANDIDATE": "FLAG_CANDIDATE",
        "LONG_COMPUTE": "SOLVING", "TYPED_BLOCKER": "SOLVING",
    }
    projected = mapping.get(str(receipt.get("event_type") or "").upper())
    if projected is None:
        return
    order = [
        "PREPARED", "SOLVING", "RACE_RUNNING", "PRIMITIVE_CANDIDATE",
        "PRIMITIVE_CONFIRMED", "POC_BUILDING", "FLAG_CANDIDATE",
        "SUBMISSION_RECOMMENDED", "ACCEPTED", "SEALED", "TERMINATION_PENDING",
        "SEALED_CLEAN",
    ]
    with state_lock(run):
        state = _state(run)
        current = str(state.get("status") or "PREPARED")
        if state.get("sealed") or state.get("remote_flag_receipt"):
            return
        if current not in order or order.index(projected) > order.index(current):
            state["status"] = projected
            state["updated_at"] = receipt.get("created_at") or state.get("updated_at")
            atomic_json(run / "STATE.json", state)


def _project_compatibility_state(run: Path) -> None:
    if not is_run_root(run):
        return
    workspace = challenge_workspace(run)
    path = workspace / "STATE.json"
    if not path.is_file() or path.is_symlink():
        return
    state = _state(run)
    projected = dict(state)
    projected["compatibility_view"] = True
    projected["authoritative_state"] = str((run / "STATE.json").relative_to(workspace))
    try:
        existing = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        existing = None
    if existing != projected:
        atomic_json(path, projected)


def _milestone_failpoint(
    boundary: str, phase: str, receipt: Mapping[str, Any],
) -> None:
    """Private no-op seam used only by fault-injection tests."""


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
