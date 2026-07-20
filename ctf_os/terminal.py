"""Human submission feedback and idempotent terminal convergence."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterator

from .candidates import load_candidates
from .control import create_control_action
from .projections import apply_projection, ensure_projection_manifest, mark_not_required
from .workspace import (
    append_jsonl_fsync, atomic_json, atomic_text, challenge_workspace,
    read_jsonl_strict, recover_run_state, resolve_active_run, safe_under, state_lock,
    update_run_manifest_timing, utc_now,
)


SUBMISSION_SCHEMA_VERSION = 1
SUBMISSION_PROJECTIONS = (
    "candidate_state", "result", "timing", "terminal_requests",
    "control_action", "compatibility",
)
TERMINAL_COMPONENT_SCHEMA_VERSION = 1
TERMINAL_COMPONENT_STATUSES = {
    "native": frozenset({"STOP_REQUESTED", "STOP_RECORDED", "NOT_REQUIRED"}),
    "sandbox": frozenset({
        "CLEANUP_PENDING", "CLEANUP_STARTED", "CLEANED", "CLEANUP_FAILED", "NOT_PRESENT",
    }),
    "resource": frozenset({
        "RELEASE_PENDING", "RELEASE_STARTED", "RELEASED", "RELEASE_FAILED", "NOT_PRESENT",
    }),
    "terminal": frozenset({"CONVERGENCE_COMPLETE"}),
}
ACTIVE_BRANCH_STATUSES = frozenset({
    "CAPACITY_ADMITTED", "SANDBOX_READY", "AWAITING_NATIVE_START", "NATIVE_STARTED",
    "RUNNING", "CHECKPOINTED",
})
TERMINAL_BRANCH_STATUSES = frozenset({
    "TERMINAL", "START_FAILED", "SANDBOX_FAILED", "INPUT_UNAVAILABLE", "TIMED_OUT",
    "TERMINATED", "ERROR", "STALE", "COMPLETED", "SUPPORTED", "REFUTED",
    "PARTIAL", "INCONCLUSIVE", "REPLACED",
})


class SubmissionError(ValueError):
    pass


def record_submission_result(
    root: Path, *, run_id: str, candidate_id: str, result: str,
) -> dict[str, Any]:
    run = _specific_run(root, run_id)
    # A prior attempt may have committed the authoritative submission receipt
    # but crashed before its STATE/candidate projections.
    repair_submission_receipt_projections(run, suppress_errors=True)
    normalized = result.strip().upper()
    if normalized not in {"WRONG", "ACCEPTED"}:
        raise SubmissionError("submission result must be accepted or wrong")
    receipt_id = hashlib.sha256(f"{run_id}\0{candidate_id}\0{normalized}".encode()).hexdigest()[:24]
    receipt_path = run / "flag-receipts" / f"submission-{receipt_id}.json"
    stop_sessions: list[str] = []
    wrong_was_active = False
    with state_lock(run):
        state = _state(run)
        if state.get("run_id") != run_id:
            raise SubmissionError("run_id does not match run state")
        candidate_payload = load_candidates(run)
        candidate = next((row for row in candidate_payload["candidates"] if row.get("candidate_id") == candidate_id), None)
        if candidate is None:
            raise SubmissionError("candidate_id does not exist in this run")
        contradictory = next((
            row for row in state.get("submission_history", [])
            if isinstance(row, Mapping) and row.get("candidate_id") == candidate_id
            and row.get("result") != normalized
        ), None)
        if contradictory:
            raise SubmissionError(
                "candidate already has a contradictory human submission result in this run"
            )
        receipt_preexisting = receipt_path.exists()
        if receipt_preexisting:
            receipt = _json(receipt_path, "submission receipt")
            if (
                receipt.get("run_id") != run_id or receipt.get("candidate_id") != candidate_id
                or receipt.get("result") != normalized
            ):
                raise SubmissionError("submission receipt conflicts with requested feedback")
            if any(
                isinstance(row, Mapping) and row.get("receipt_id") == receipt_id
                for row in state.get("submission_history", [])
            ):
                return {**receipt, "idempotent": True}
            if state.get("sealed") and not (
                normalized == "ACCEPTED" and state.get("active_candidate_id") == candidate_id
            ):
                raise SubmissionError("sealed run is immutable")
        elif state.get("sealed"):
            raise SubmissionError("sealed run is immutable")
        else:
            receipt = {
                "schema_version": SUBMISSION_SCHEMA_VERSION, "receipt_id": receipt_id,
                "run_id": run_id, "challenge_id": state.get("challenge_id"),
                "input_fingerprint": state.get("input_fingerprint"),
                "target_revision": state.get("target_revision"),
                "session_id": candidate.get("session_id") or "sol-main",
                "candidate_id": candidate_id, "candidate": candidate.get("candidate"),
                "result": normalized, "source": "human", "created_at": utc_now(),
                "automatic_submission_attempted": False,
                "required_projections": list(SUBMISSION_PROJECTIONS),
            }
        # Stage every dependent projection first and commit STATE.json last.
        if not receipt_preexisting:
            atomic_json(receipt_path, receipt)
            _terminal_failpoint("submission", "RECEIPT_SAVED", receipt)
        candidate["status"] = "ACCEPTED" if normalized == "ACCEPTED" else "REFUTED"
        candidate["updated_at"] = receipt["created_at"]
        atomic_json(run / "candidates.json", candidate_payload)
        if normalized == "WRONG":
            wrong_was_active = state.get("active_candidate_id") == candidate_id
            _wrong_state(state, candidate_id)
            _mark_candidate_dependencies(run, candidate, candidate_id)
        else:
            _accepted_state(state, candidate, receipt)
            _request_branch_stops_unlocked(run)
            stop_sessions = [
                str(row.get("session_id")) for row in _plan(run, missing_ok=True).get("branches", [])
                if row.get("status") == "STOP_REQUESTED" and row.get("session_id")
            ]
            atomic_text(run / "RESULT.md", _accepted_result(state, candidate, receipt))
        history = state.setdefault("submission_history", [])
        if not any(isinstance(row, Mapping) and row.get("receipt_id") == receipt_id for row in history):
            history.append({
                "receipt_id": receipt_id, "candidate_id": candidate_id,
                "result": normalized, "created_at": receipt["created_at"],
            })
        state["updated_at"] = receipt["created_at"]
        atomic_json(run / "STATE.json", state)
    update_run_manifest_timing(run, "submission_result_at", receipt["created_at"])
    if normalized == "WRONG":
        action = create_control_action(
            run, session_id=str(candidate.get("session_id") or "sol-main"),
            action_type="REPLACE_ATTACK_FAMILY" if wrong_was_active else "REVIEW_CANDIDATE_DEPENDENCY",
            reason=(
                "human submission marked the active candidate WRONG"
                if wrong_was_active else "human submission refuted a non-active candidate provenance"
            ),
            triggering_evidence_id=receipt_id, evidence_generation=_evidence_generation(run, str(candidate.get("session_id") or "sol-main")),
            metadata={"candidate_id": candidate_id},
        )
        repaired = repair_submission_receipt_projections(
            run, receipt_ids={receipt_id}, suppress_errors=True,
        )
        return {
            **receipt, "state": state["status"], "control_action": action,
            "post_commit_warnings": repaired["errors"], "idempotent": False,
        }
    stop_actions = [
        create_control_action(
            run, session_id=session_id, action_type="STOP_REQUIRED",
            reason="human submission ACCEPTED; stop this run's native branch",
            triggering_evidence_id=receipt_id,
            evidence_generation=_evidence_generation(run, session_id),
            metadata={"run_id": run_id, "candidate_id": candidate_id},
        )
        for session_id in stop_sessions
    ]
    repaired = repair_submission_receipt_projections(
        run, receipt_ids={receipt_id}, suppress_errors=True,
    )
    return {
        **receipt, "state": "SEALED", "terminal_convergence": terminal_status(run),
        "stop_actions": stop_actions, "post_commit_warnings": repaired["errors"],
        "idempotent": False,
    }


def repair_submission_receipt_projections(
    root: Path, *, receipt_ids: set[str] | None = None,
    suppress_errors: bool = False,
) -> dict[str, Any]:
    run = resolve_active_run(root)
    repaired: list[str] = []
    errors: list[str] = []
    receipt_root = run / "flag-receipts"
    for path in sorted(receipt_root.glob("submission-*.json")) if receipt_root.is_dir() else []:
        receipt = _json(path, "submission receipt")
        receipt_id = str(receipt.get("receipt_id") or "")
        if receipt_ids is not None and receipt_id not in receipt_ids:
            continue
        required = list(receipt.get("required_projections") or SUBMISSION_PROJECTIONS)
        ensure_projection_manifest(run, receipt, required)
        result = str(receipt.get("result") or "").upper()
        stages = [
            ("candidate_state", lambda: recover_run_state(run, force=True)),
            ("result", lambda r=receipt: _repair_submission_result(run, r)),
            ("timing", lambda r=receipt: update_run_manifest_timing(
                run, "submission_result_at", str(r.get("created_at")),
            )),
            ("terminal_requests", lambda r=receipt: _repair_terminal_requests(run, r)),
            ("control_action", lambda r=receipt: _repair_submission_control(run, r)),
            ("compatibility", lambda: _repair_submission_compatibility(run)),
        ]
        for name, callback in stages:
            if result == "WRONG" and name in {"result", "terminal_requests"}:
                mark_not_required(run, receipt, required, name)
                continue
            try:
                _value, skipped = apply_projection(run, receipt, required, name, callback)
                if not skipped and receipt_id not in repaired:
                    repaired.append(receipt_id)
            except Exception as exc:
                message = f"{receipt_id}:{name}: {exc}"
                errors.append(message[:2000])
                append_jsonl_fsync(run / "post-commit-errors.jsonl", {
                    "event": "SUBMISSION_RECEIPT_PROJECTION_FAILED",
                    "receipt_id": receipt_id, "projection": name,
                    "error": str(exc)[:2000], "created_at": utc_now(),
                }, label="post-commit error ledger")
                if not suppress_errors:
                    raise SubmissionError(message) from exc
    return {"run_id": run.name, "repaired_receipts": repaired, "errors": errors}


def _repair_submission_result(run: Path, receipt: Mapping[str, Any]) -> None:
    if str(receipt.get("result") or "").upper() != "ACCEPTED":
        return
    state = _state(run)
    candidate = next((
        row for row in load_candidates(run).get("candidates", [])
        if row.get("candidate_id") == receipt.get("candidate_id")
    ), None)
    if candidate is None:
        raise SubmissionError("accepted receipt candidate projection is missing")
    content = _accepted_result(state, candidate, receipt)
    path = run / "RESULT.md"
    if not path.exists() or path.read_text(encoding="utf-8") != content:
        atomic_text(path, content)


def _repair_terminal_requests(run: Path, receipt: Mapping[str, Any]) -> None:
    if str(receipt.get("result") or "").upper() != "ACCEPTED":
        return
    with state_lock(run):
        _request_branch_stops_unlocked(run)


def _repair_submission_control(run: Path, receipt: Mapping[str, Any]) -> None:
    candidate = next((
        row for row in load_candidates(run).get("candidates", [])
        if row.get("candidate_id") == receipt.get("candidate_id")
    ), None)
    if candidate is None:
        raise SubmissionError("submission control projection candidate is missing")
    session_id = str(candidate.get("session_id") or "sol-main")
    if str(receipt.get("result") or "").upper() == "ACCEPTED":
        plan = _plan(run, missing_ok=True)
        for branch in plan.get("branches", []):
            if branch.get("status") == "STOP_REQUESTED" and branch.get("session_id"):
                create_control_action(
                    run, session_id=str(branch["session_id"]), action_type="STOP_REQUIRED",
                    reason="human submission ACCEPTED; stop this run's native branch",
                    triggering_evidence_id=str(receipt.get("receipt_id")),
                    evidence_generation=_evidence_generation(run, str(branch["session_id"])),
                    metadata={
                        "run_id": run.name, "candidate_id": receipt.get("candidate_id"),
                    },
                )
        return
    create_control_action(
        run, session_id=session_id, action_type="REVIEW_CANDIDATE_DEPENDENCY",
        reason="human submission refuted candidate provenance",
        triggering_evidence_id=str(receipt.get("receipt_id")),
        evidence_generation=_evidence_generation(run, session_id),
        metadata={"candidate_id": receipt.get("candidate_id")},
    )


def _repair_submission_compatibility(run: Path) -> None:
    workspace = challenge_workspace(run)
    path = workspace / "STATE.json"
    if workspace == run or not path.is_file() or path.is_symlink():
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


def record_native_stop(
    root: Path, *, run_id: str, session_id: str, native_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    run = _specific_run(root, run_id)
    if not native_receipt or {"session_id", "observed_at", "idempotent"}.intersection(native_receipt):
        raise SubmissionError("native stop receipt is empty or contains reserved lifecycle fields")
    with state_lock(run):
        plan = _plan(run)
        branch = next((row for row in plan.get("branches", []) if row.get("session_id") == session_id), None)
        if branch is None:
            raise SubmissionError("branch does not exist in this run")
        if not (branch.get("start_receipt") or branch.get("native_start_receipt") or branch.get("started_at")):
            raise SubmissionError("native stop receipt requires a previously started native branch")
        if branch.get("native_stop_receipt"):
            saved = branch["native_stop_receipt"]
            if (
                saved.get("session_id") != session_id
                or any(saved.get(key) != value for key, value in native_receipt.items())
            ):
                raise SubmissionError("native stop receipt conflicts with existing receipt")
            return {**saved, "idempotent": True}
        receipt = {"session_id": session_id, "observed_at": utc_now(), **dict(native_receipt)}
        branch["native_stop_receipt"] = receipt
        branch["status"] = "TERMINAL"
        branch["finished_at"] = receipt["observed_at"]
        atomic_json(run / "DELEGATION_PLAN.json", plan)
        _record_terminal_component_unlocked(
            run, session_id=session_id, component="native", status="STOP_RECORDED",
            related_receipt=receipt,
        )
    return {**receipt, "idempotent": False}


def record_terminal_component(
    root: Path, *, session_id: str, component: str, status: str,
    related_receipt: Mapping[str, Any] | None = None, error: str | None = None,
) -> dict[str, Any]:
    run = resolve_active_run(root)
    with state_lock(run):
        return _record_terminal_component_unlocked(
            run, session_id=session_id, component=component, status=status,
            related_receipt=related_receipt, error=error,
        )


def load_terminal_components(root: Path) -> list[dict[str, Any]]:
    run = resolve_active_run(root)
    rows = read_jsonl_strict(
        run / "terminal-components.jsonl", "terminal component receipt ledger",
    )
    for row in rows:
        component = str(row.get("component") or "")
        if (
            row.get("schema_version") != TERMINAL_COMPONENT_SCHEMA_VERSION
            or component not in TERMINAL_COMPONENT_STATUSES
            or row.get("status") not in TERMINAL_COMPONENT_STATUSES[component]
        ):
            raise SubmissionError("terminal component receipt ledger contains an unsupported row")
    return rows


def _record_terminal_component_unlocked(
    run: Path, *, session_id: str, component: str, status: str,
    related_receipt: Mapping[str, Any] | None = None, error: str | None = None,
) -> dict[str, Any]:
    normalized_component = str(component).strip().lower()
    normalized_status = str(status).strip().upper()
    if (
        normalized_component not in TERMINAL_COMPONENT_STATUSES
        or normalized_status not in TERMINAL_COMPONENT_STATUSES[normalized_component]
    ):
        raise SubmissionError("terminal component status is invalid")
    session = str(session_id).strip()
    if not session or len(session) > 128 or any(char in session for char in "/\\\0\r\n"):
        raise SubmissionError("terminal component session_id is invalid")
    state = _state(run)
    related = dict(related_receipt or {}) or None
    material = {
        "run_id": state.get("run_id") or run.name,
        "challenge_id": state.get("challenge_id"),
        "input_fingerprint": state.get("input_fingerprint"),
        "target_revision": state.get("target_revision"),
        "session_id": session, "component": normalized_component,
        "status": normalized_status, "related_receipt": related,
        "error": str(error)[:2000] if error else None,
    }
    receipt_id = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode(),
    ).hexdigest()[:24]
    rows = read_jsonl_strict(
        run / "terminal-components.jsonl", "terminal component receipt ledger",
    )
    existing = next((row for row in rows if row.get("receipt_id") == receipt_id), None)
    if existing:
        return {**existing, "idempotent": True}
    record = {
        "schema_version": TERMINAL_COMPONENT_SCHEMA_VERSION,
        "receipt_id": receipt_id, **material, "created_at": utc_now(),
    }
    append_jsonl_fsync(
        run / "terminal-components.jsonl", record,
        label="terminal component receipt ledger",
    )
    _terminal_failpoint(normalized_component, normalized_status, record)
    return {**record, "idempotent": False}


def converge_terminal(
    root: Path, *, run_id: str,
    sandbox_cleanup: Callable[[Path, str], Mapping[str, Any]] | None = None,
    resource_release: Callable[[str], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    run = _specific_run(root, run_id)
    with _terminal_convergence_lock(run):
        sandbox_tasks: list[tuple[str, Path]] = []
        with state_lock(run):
            state = _state(run)
            if state.get("competition_state") != "ACCEPTED":
                raise SubmissionError("terminal convergence requires an ACCEPTED run")
            plan = _plan(run, missing_ok=True)
            branches, sandbox_sessions, resource_sessions, released_resources = _terminal_sessions(run, plan)
            cleanup_rows = state.setdefault("terminal_components", {})
            session_ids = set(branches) | sandbox_sessions | resource_sessions | released_resources | set(cleanup_rows)
            for session_id in sorted(session_ids):
                component = cleanup_rows.setdefault(session_id, {
                    "native": "NOT_REQUIRED", "sandbox": "NOT_PRESENT", "resource": "NOT_PRESENT",
                })
                branch = branches.get(session_id)
                component["native"] = _native_component_state(branch)
                _record_terminal_component_unlocked(
                    run, session_id=session_id, component="native",
                    status=(
                        "STOP_RECORDED" if component["native"] == "TERMINAL_RECORDED"
                        else "STOP_REQUESTED" if component["native"] == "TERMINATION_PENDING"
                        else "NOT_REQUIRED"
                    ),
                )
                native_ready = component["native"] in {"NOT_REQUIRED", "TERMINAL_RECORDED"}
                metadata = run / "workers" / session_id / "sandbox.json"
                if session_id not in sandbox_sessions and component.get("sandbox") in {
                    "CLEANUP_IN_PROGRESS", "CLEANUP_FAILED", "CLEANUP_PENDING",
                }:
                    component["sandbox"] = "CLEANED"
                    component["sandbox_receipt"] = {"recovered": True, "reason": "sandbox metadata no longer exists"}
                    _record_terminal_component_unlocked(
                        run, session_id=session_id, component="sandbox", status="CLEANED",
                        related_receipt=component["sandbox_receipt"],
                    )
                if session_id in sandbox_sessions and component.get("sandbox") != "CLEANED":
                    if not native_ready or sandbox_cleanup is None:
                        component["sandbox"] = "CLEANUP_PENDING"
                        _record_terminal_component_unlocked(
                            run, session_id=session_id, component="sandbox", status="CLEANUP_PENDING",
                        )
                    else:
                        component["sandbox"] = "CLEANUP_IN_PROGRESS"
                        _record_terminal_component_unlocked(
                            run, session_id=session_id, component="sandbox", status="CLEANUP_STARTED",
                        )
                        sandbox_tasks.append((session_id, metadata))
                elif session_id not in sandbox_sessions and component.get("sandbox") == "NOT_PRESENT":
                    _record_terminal_component_unlocked(
                        run, session_id=session_id, component="sandbox", status="NOT_PRESENT",
                    )
                has_resource = session_id in resource_sessions
                if session_id in released_resources and component.get("resource") != "RELEASED":
                    component["resource"] = "RELEASED"
                    component["resource_receipt"] = {"recovered": True, "reason": "resource ledger records RELEASED"}
                    _record_terminal_component_unlocked(
                        run, session_id=session_id, component="resource", status="RELEASED",
                        related_receipt=component["resource_receipt"],
                    )
                if has_resource and component.get("resource") != "RELEASED":
                    component["resource"] = "RELEASE_PENDING"
                    _record_terminal_component_unlocked(
                        run, session_id=session_id, component="resource", status="RELEASE_PENDING",
                    )
                elif not has_resource and session_id not in released_resources:
                    _record_terminal_component_unlocked(
                        run, session_id=session_id, component="resource", status="NOT_PRESENT",
                    )
            state["cleanup_state"] = "TERMINATION_PENDING"
            state["status"] = "SEALED"
            state["updated_at"] = utc_now()
            atomic_json(run / "STATE.json", state)

        sandbox_results: dict[str, tuple[str, dict[str, Any] | str]] = {}
        for session_id, metadata in sandbox_tasks:
            try:
                sandbox_results[session_id] = ("CLEANED", dict(sandbox_cleanup(metadata, session_id)))  # type: ignore[misc]
            except Exception as exc:
                sandbox_results[session_id] = ("CLEANUP_FAILED", str(exc))

        # Commit sandbox outcomes before resource release. This preserves the
        # required native -> sandbox -> resource ordering across crashes.
        resource_tasks: list[str] = []
        with state_lock(run):
            state = _state(run)
            plan = _plan(run, missing_ok=True)
            branches, _sandbox_sessions, resource_sessions, released_resources = _terminal_sessions(run, plan)
            cleanup_rows = state.setdefault("terminal_components", {})
            for session_id, (status, result) in sandbox_results.items():
                component = cleanup_rows[session_id]
                component["sandbox"] = status
                if status == "CLEANED":
                    component["sandbox_receipt"] = result
                    component.pop("sandbox_error", None)
                    _record_terminal_component_unlocked(
                        run, session_id=session_id, component="sandbox", status="CLEANED",
                        related_receipt=result if isinstance(result, Mapping) else None,
                    )
                else:
                    component["sandbox_error"] = result
                    _record_terminal_component_unlocked(
                        run, session_id=session_id, component="sandbox", status="CLEANUP_FAILED",
                        error=str(result),
                    )
            for session_id, component in cleanup_rows.items():
                component["native"] = _native_component_state(branches.get(session_id))
                if session_id in released_resources and component.get("resource") != "RELEASED":
                    component["resource"] = "RELEASED"
                    component["resource_receipt"] = {
                        "recovered": True, "reason": "resource ledger records RELEASED",
                    }
                if session_id not in resource_sessions or component.get("resource") == "RELEASED":
                    continue
                ordered_ready = (
                    component["native"] in {"NOT_REQUIRED", "TERMINAL_RECORDED"}
                    and component.get("sandbox") in {"NOT_PRESENT", "CLEANED"}
                )
                if ordered_ready and resource_release is not None:
                    component["resource"] = "RELEASE_IN_PROGRESS"
                    _record_terminal_component_unlocked(
                        run, session_id=session_id, component="resource", status="RELEASE_STARTED",
                    )
                    resource_tasks.append(session_id)
                else:
                    component["resource"] = "RELEASE_PENDING"
                    _record_terminal_component_unlocked(
                        run, session_id=session_id, component="resource", status="RELEASE_PENDING",
                    )
            state["updated_at"] = utc_now()
            atomic_json(run / "STATE.json", state)

        resource_results: dict[str, tuple[str, dict[str, Any] | str]] = {}
        for session_id in resource_tasks:
            try:
                resource_results[session_id] = ("RELEASED", dict(resource_release(session_id)))  # type: ignore[misc]
            except Exception as exc:
                resource_results[session_id] = ("RELEASE_FAILED", str(exc))

        with state_lock(run):
            state = _state(run)
            plan = _plan(run, missing_ok=True)
            branches = {
                str(branch.get("session_id")): branch for branch in plan.get("branches", [])
                if branch.get("session_id")
            }
            cleanup_rows = state.setdefault("terminal_components", {})
            for session_id, (status, result) in resource_results.items():
                component = cleanup_rows[session_id]
                component["resource"] = status
                if status == "RELEASED":
                    component["resource_receipt"] = result
                    component.pop("resource_error", None)
                    _record_terminal_component_unlocked(
                        run, session_id=session_id, component="resource", status="RELEASED",
                        related_receipt=result if isinstance(result, Mapping) else None,
                    )
                else:
                    component["resource_error"] = result
                    _record_terminal_component_unlocked(
                        run, session_id=session_id, component="resource", status="RELEASE_FAILED",
                        error=str(result),
                    )
            for session_id, branch in branches.items():
                component = cleanup_rows.setdefault(session_id, {
                    "native": "NOT_REQUIRED", "sandbox": "NOT_PRESENT", "resource": "NOT_PRESENT",
                })
                component["native"] = _native_component_state(branch)
            clean = all(
                row.get("native") in {"NOT_REQUIRED", "TERMINAL_RECORDED"}
                and row.get("sandbox") in {"NOT_PRESENT", "CLEANED"}
                and row.get("resource") in {"NOT_PRESENT", "RELEASED"}
                for row in cleanup_rows.values()
            )
            state["cleanup_state"] = "SEALED_CLEAN" if clean else "TERMINATION_PENDING"
            state["status"] = "SEALED_CLEAN" if clean else "SEALED"
            state["updated_at"] = utc_now()
            if clean:
                _record_terminal_component_unlocked(
                    run, session_id="run", component="terminal", status="CONVERGENCE_COMPLETE",
                    related_receipt={"terminal_components": sorted(cleanup_rows)},
                )
            atomic_json(run / "STATE.json", state)
    return terminal_status(run)


def _native_component_state(branch: Mapping[str, Any] | None) -> str:
    if not branch or not (
        branch.get("start_receipt") or branch.get("native_start_receipt") or branch.get("started_at")
    ):
        return "NOT_REQUIRED"
    if branch.get("native_stop_receipt") or branch.get("status") in TERMINAL_BRANCH_STATUSES:
        return "TERMINAL_RECORDED"
    return "TERMINATION_PENDING"


def _terminal_sessions(
    run: Path, plan: Mapping[str, Any],
) -> tuple[dict[str, Mapping[str, Any]], set[str], set[str], set[str]]:
    branches = {
        str(branch.get("session_id")): branch for branch in plan.get("branches", [])
        if isinstance(branch, Mapping) and branch.get("session_id")
    }
    sandbox_sessions = {
        path.parent.name for path in (run / "workers").glob("*/sandbox.json")
        if path.is_file() and not path.is_symlink()
    } if (run / "workers").is_dir() else set()
    resource_sessions: set[str] = set()
    released_resources: set[str] = set()
    resource_path = run / "RESOURCE_STATE.json"
    if resource_path.exists():
        resource_state = _json(resource_path, "resource state")
        requests = resource_state.get("requests", {})
        observations = resource_state.get("observations", {})
        if not isinstance(requests, dict) or not isinstance(observations, dict):
            raise SubmissionError("resource state rows are malformed during terminal convergence")
        resource_sessions = {
            str(session_id) for session_id in requests
            if not isinstance(observations.get(session_id), Mapping)
            or observations.get(session_id, {}).get("state") != "RELEASED"
        }
        released_resources = {
            str(session_id) for session_id in requests
            if isinstance(observations.get(session_id), Mapping)
            and observations.get(session_id, {}).get("state") == "RELEASED"
        }
    return branches, sandbox_sessions, resource_sessions, released_resources


@contextmanager
def _terminal_convergence_lock(run: Path) -> Iterator[None]:
    path = challenge_workspace(run) / ".TERMINAL.lock"
    if path.is_symlink():
        raise SubmissionError("terminal convergence lock must not be a symlink")
    descriptor = os.open(
        path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600,
    )
    with os.fdopen(descriptor, "a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def terminal_status(root: Path) -> dict[str, Any]:
    run = resolve_active_run(root)
    state = _state(run)
    return {
        "run_id": state.get("run_id"), "status": state.get("status"),
        "cleanup_state": state.get("cleanup_state"),
        "components": state.get("terminal_components", {}),
        "verified_flag_preserved": bool(
            state.get("flag_candidate")
            and (state.get("remote_flag_receipt") or state.get("competition_state") == "ACCEPTED")
        ),
    }


def _wrong_state(state: dict[str, Any], candidate_id: str) -> None:
    if state.get("active_candidate_id") == candidate_id:
        state["active_candidate_id"] = None
        state["flag_candidate"] = None
        state["submission_recommended"] = False
        state["remote_flag"] = None
        state["remote_flag_receipt"] = None
        state["remote_candidate_receipt"] = None
        state["status"] = "RACE_RUNNING" if any(row.get("status") == "RUNNING" for row in state.get("branches", [])) else "SOLVING"
        state["competition_state"] = None


def _accepted_state(state: dict[str, Any], candidate: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
    state.update({
        "status": "SEALED", "solve_status": "SOLVED", "sealed": True,
        "sealed_at": receipt["created_at"], "competition_state": "ACCEPTED",
        "active_candidate_id": candidate["candidate_id"], "flag_candidate": candidate["candidate"],
        "submission_recommended": False, "submission_receipt": f"flag-receipts/submission-{receipt['receipt_id']}.json",
        "cleanup_state": "TERMINATION_PENDING",
    })


def _request_branch_stops_unlocked(run: Path) -> None:
    plan = _plan(run, missing_ok=True)
    changed = False
    for branch in plan.get("branches", []):
        status = str(branch.get("status", ""))
        if status in ACTIVE_BRANCH_STATUSES or status in {"PLANNED", "ADMITTED", "AWAITING_NATIVE_START"}:
            if status in {"PLANNED", "ADMITTED", "AWAITING_NATIVE_START"} and not branch.get("started_at"):
                branch["status"] = "TERMINATED"
                _record_terminal_component_unlocked(
                    run, session_id=str(branch.get("session_id")), component="native",
                    status="NOT_REQUIRED", related_receipt={"reason": "branch never started"},
                )
            else:
                branch["status"] = "STOP_REQUESTED"
                branch["stop_requested_at"] = utc_now()
                branch["native_action_owner"] = "sol"
                _record_terminal_component_unlocked(
                    run, session_id=str(branch.get("session_id")), component="native",
                    status="STOP_REQUESTED",
                    related_receipt={"stop_requested_at": branch["stop_requested_at"]},
                )
            changed = True
    if changed:
        plan["updated_at"] = utc_now()
        atomic_json(run / "DELEGATION_PLAN.json", plan)


def _mark_candidate_dependencies(run: Path, candidate: Mapping[str, Any], candidate_id: str) -> None:
    plan = _plan(run, missing_ok=True)
    changed = False
    for branch in plan.get("branches", []):
        if branch.get("session_id") == candidate.get("session_id") or branch.get("candidate_id") == candidate_id:
            branch["review_required"] = True
            branch["refuted_candidate_id"] = candidate_id
            changed = True
    if changed:
        atomic_json(run / "DELEGATION_PLAN.json", plan)


def _specific_run(root: Path, run_id: str) -> Path:
    if resolve_active_run(root).name == run_id:
        return resolve_active_run(root)
    workspace = challenge_workspace(root)
    run = safe_under(workspace / "runs", Path(run_id))
    if run.is_symlink() or not run.is_dir():
        raise SubmissionError("run_id does not exist in this challenge workspace")
    return run


def _state(run: Path) -> dict[str, Any]:
    return _json(run / "STATE.json", "run state")


def _plan(run: Path, *, missing_ok: bool = False) -> dict[str, Any]:
    path = run / "DELEGATION_PLAN.json"
    if not path.exists() and missing_ok:
        return {"branches": []}
    return _json(path, "delegation plan")


def _json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise SubmissionError(f"{label} is missing or unsafe")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SubmissionError(f"{label} is malformed") from exc
    if not isinstance(payload, dict):
        raise SubmissionError(f"{label} is not an object")
    return payload


def _accepted_result(state: Mapping[str, Any], candidate: Mapping[str, Any], receipt: Mapping[str, Any]) -> str:
    return (
        f"# Accepted flag — {state.get('challenge_id')}\n\n"
        f"- Run: `{state.get('run_id')}`\n- Candidate: `{candidate.get('candidate_id')}`\n"
        f"- Flag: `{candidate.get('candidate')}`\n- Human submission: **ACCEPTED**\n"
        f"- Submission receipt: `flag-receipts/submission-{receipt.get('receipt_id')}.json`\n\n"
        "Terminal convergence has started. Native session lifecycle remains owned by Sol.\n"
    )


def _evidence_generation(run: Path, session_id: str) -> int:
    path = run / "progress-state.json"
    if not path.is_file():
        return 0
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return int(payload.get("sessions", {}).get(session_id, {}).get("evidence_generation", 0))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return 0


def _terminal_failpoint(
    component: str, status: str, receipt: Mapping[str, Any],
) -> None:
    """Private no-op seam used only by fault-injection tests."""
