"""Append-only, deduplicated lifecycle actions for Sol to apply."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .workspace import (
    append_jsonl_fsync, atomic_json, read_jsonl_strict, resolve_active_run,
    safe_under, state_lock, utc_now,
)


CONTROL_ACTION_SCHEMA_VERSION = 1
ACTION_STATUSES = frozenset({"PENDING", "ACKED_APPLIED", "ACKED_DECLINED", "SUPERSEDED", "EXPIRED"})
ACTION_TYPES = frozenset({
    "CONTINUE_WITH_EVIDENCE", "SOL_TAKEOVER", "REPLACE_ATTACK_FAMILY", "STOP_REQUIRED",
    "LONG_COMPUTE_REVIEW", "REMOTE_ATTEMPT_REQUIRED", "OPERATOR_REVIEW",
    "RETARGET_TO_POC", "STOP_LOW_VALUE_BRANCH", "REVIEW_CANDIDATE_DEPENDENCY",
    "ROUTING_PROFILE_RECOMMENDED", "REASONING_ESCALATION_RECOMMENDED",
    "MAX_ENDGAME_RECOMMENDED", "MAX_LEASE_EXPIRED",
    "ROUTING_FALLBACK_RECORDED", "ROUTING_MISMATCH_REVIEW",
})


class ControlActionError(ValueError):
    pass


def create_control_action(
    root: Path, *, session_id: str, action_type: str, reason: str,
    triggering_evidence_id: str, evidence_generation: int,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    run = resolve_active_run(root)
    action = action_type.strip().upper()
    if action not in ACTION_TYPES:
        raise ControlActionError(f"action_type must be one of {sorted(ACTION_TYPES)}")
    if not isinstance(evidence_generation, int) or evidence_generation < 0:
        raise ControlActionError("evidence_generation must be a non-negative integer")
    with state_lock(run):
        state = _state(run)
        if state.get("sealed") and action != "STOP_REQUIRED":
            raise ControlActionError("sealed run accepts only terminal STOP_REQUIRED actions")
        if state.get("remote_flag_receipt") and action not in {
            "STOP_REQUIRED", "STOP_LOW_VALUE_BRANCH", "REVIEW_CANDIDATE_DEPENDENCY",
        }:
            raise ControlActionError(
                "verified remote flag run accepts only convergence stop actions"
            )
        run_id = str(state.get("run_id") or run.name)
        key = {
            "run_id": run_id, "session_id": _text(session_id, "session_id", 128),
            "challenge_id": state.get("challenge_id"),
            "input_fingerprint": state.get("input_fingerprint"),
            "target_revision": state.get("target_revision"),
            "action_type": action, "evidence_generation": evidence_generation,
        }
        action_id = hashlib.sha256(
            json.dumps(key, sort_keys=True, separators=(",", ":")).encode(),
        ).hexdigest()[:24]
        rows = load_control_actions(run)
        duplicate = next((
            row for row in rows
            if all(row.get(field) == value for field, value in key.items())
        ), None)
        if duplicate:
            return {**duplicate, "idempotent": True}
        record = {
            "schema_version": CONTROL_ACTION_SCHEMA_VERSION, "action_id": action_id,
            **key, "status": "PENDING", "reason": _text(reason, "reason", 2000),
            "triggering_evidence_id": _text(triggering_evidence_id, "triggering_evidence_id", 256),
            "metadata": dict(metadata or {}), "created_at": utc_now(),
            "acknowledged_at": None, "applied_receipt": None,
        }
        append_jsonl_fsync(run / "control-actions.jsonl", record, label="control action ledger")
    return {**record, "idempotent": False}


def acknowledge_control_action(
    root: Path, *, action_id: str, status: str, applied_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    run = resolve_active_run(root)
    normalized = status.strip().upper()
    allowed = {"ACKED_DECLINED", "SUPERSEDED", "EXPIRED"}
    if normalized not in allowed:
        raise ControlActionError(
            "control-action-ack accepts only declined, superseded, or expired; "
            "use control-action-apply for applied actions"
        )
    with state_lock(run):
        rows = load_control_actions(run)
        current = _current(rows, action_id)
        if current is None:
            raise ControlActionError("control action does not exist")
        if current.get("status") != "PENDING":
            if current.get("status") == normalized:
                return {**current, "idempotent": True}
            raise ControlActionError("control action is already terminal")
        record = {
            **current, "ledger_event": "STATUS_CHANGED", "status": normalized,
            "acknowledged_at": utc_now(), "applied_receipt": dict(applied_receipt or {}) or None,
        }
        append_jsonl_fsync(run / "control-actions.jsonl", record, label="control action ledger")
    return {**record, "idempotent": False}


def apply_control_action(
    root: Path, *, action_id: str, proof_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Apply an action only when run-local authoritative evidence proves it."""

    run = resolve_active_run(root)
    proof = dict(proof_receipt)
    with state_lock(run):
        state = _state(run)
        rows = load_control_actions(run, current_view=False)
        current = _current(rows, action_id)
        if current is None:
            raise ControlActionError("control action does not exist")
        if current.get("status") != "PENDING":
            if current.get("status") == "ACKED_APPLIED":
                saved = _application_receipt(run, action_id)
                if _submitted_proof(saved) != proof:
                    raise ControlActionError("control action apply proof conflicts with prior receipt")
                return {**current, "application_receipt": saved, "idempotent": True}
            raise ControlActionError("control action is already terminal")
        expected = {
            "action_id": action_id, "run_id": state.get("run_id") or run.name,
            "challenge_id": state.get("challenge_id"),
            "session_id": current.get("session_id"),
            "input_fingerprint": state.get("input_fingerprint"),
            "target_revision": state.get("target_revision"),
            "evidence_generation": current.get("evidence_generation"),
        }
        for field, value in expected.items():
            if proof.get(field) != value:
                raise ControlActionError(f"control action apply proof {field} mismatch")
        authoritative_evidence = _validate_action_proof(run, current, proof)
        receipt = {
            "schema_version": 1, **proof, "action_type": current.get("action_type"),
            "created_at": utc_now(),
        }
        if authoritative_evidence is not None:
            receipt["authoritative_evidence"] = authoritative_evidence
        receipt_path = run / "control-application-receipts" / f"{action_id}.json"
        if receipt_path.exists():
            saved = _application_receipt(run, action_id)
            if (
                _submitted_proof(saved) != proof
                or saved.get("action_type") != current.get("action_type")
            ):
                raise ControlActionError("control action application receipt conflicts")
            receipt = saved
        else:
            atomic_json(receipt_path, receipt)
        record = {
            **current, "ledger_event": "STATUS_CHANGED", "status": "ACKED_APPLIED",
            "acknowledged_at": receipt["created_at"],
            "applied_receipt": {
                "path": str(receipt_path.relative_to(run)),
                "digest": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
            },
        }
        append_jsonl_fsync(run / "control-actions.jsonl", record, label="control action ledger")
    return {**record, "application_receipt": receipt, "idempotent": False}


def _validate_action_proof(
    run: Path, action: Mapping[str, Any], proof: Mapping[str, Any],
) -> dict[str, Any] | None:
    action_type = str(action.get("action_type") or "")
    session_id = str(action.get("session_id") or "")
    plan = _json_optional(run / "DELEGATION_PLAN.json")
    branches = plan.get("branches", []) if isinstance(plan.get("branches"), list) else []
    branch = next((
        row for row in branches
        if isinstance(row, Mapping) and row.get("session_id") == session_id
    ), None)
    milestones = read_jsonl_strict(run / "milestone-receipts.jsonl", "milestone receipt ledger")
    terminal = read_jsonl_strict(
        run / "terminal-components.jsonl", "terminal component receipt ledger",
    )

    if action_type in {"STOP_REQUIRED", "STOP_LOW_VALUE_BRANCH"}:
        if branch is None:
            raise ControlActionError("stop action target branch does not exist")
        if action_type == "STOP_LOW_VALUE_BRANCH" and proof.get("branch_id") != session_id:
            raise ControlActionError("stop-low-value proof branch does not match action target")
        started = bool(
            branch.get("start_receipt") or branch.get("native_start_receipt")
            or branch.get("started_at")
        )
        if started:
            native = proof.get("native_stop_receipt")
            child_id = str(proof.get("child_terminal_receipt_id") or "")
            child = next((
                row for row in milestones
                if row.get("receipt_id") == child_id
                and row.get("event_type") == "CHILD_TERMINAL_RESULT"
                and row.get("session_id") == session_id
            ), None)
            if not (
                isinstance(native, Mapping) and branch.get("native_stop_receipt") == dict(native)
            ) and child is None:
                raise ControlActionError(
                    "started stop action requires its native stop or CHILD_TERMINAL_RESULT receipt"
                )
        else:
            terminal_id = str(proof.get("terminal_receipt_id") or "")
            match = next((
                row for row in terminal
                if row.get("receipt_id") == terminal_id
                and row.get("session_id") == session_id
                and row.get("component") == "native"
                and row.get("status") in {"NOT_REQUIRED", "STOP_RECORDED"}
            ), None)
            if match is None:
                raise ControlActionError(
                    "unstarted stop action requires a verified terminal lifecycle receipt"
                )
        return

    if action_type == "SOL_TAKEOVER":
        receipt_id = str(proof.get("primitive_receipt_id") or proof.get("working_poc_receipt_id") or "")
        evidence = next((
            row for row in milestones if row.get("receipt_id") == receipt_id
            and row.get("event_type") in {"PRIMITIVE_CONFIRMED", "WORKING_POC"}
        ), None)
        if (
            evidence is None
            or proof.get("leading_path_session_id") != evidence.get("session_id")
            or proof.get("leading_path_session_id") != session_id
        ):
            raise ControlActionError("SOL_TAKEOVER requires a confirmed leading-path receipt")
        _required_text(proof.get("takeover_objective"), "takeover_objective")
        artifact = proof.get("takeover_artifact")
        experiment = proof.get("next_experiment")
        if artifact:
            path = safe_under(run, Path(str(artifact)))
            if path.is_symlink() or not path.is_file():
                raise ControlActionError("takeover artifact is missing or unsafe")
        elif not isinstance(experiment, list) or not experiment or any(not str(item) for item in experiment):
            raise ControlActionError("SOL_TAKEOVER requires an artifact or exact next experiment argv")
        return

    if action_type == "RETARGET_TO_POC":
        if branch is None or proof.get("branch_id") != session_id:
            raise ControlActionError("RETARGET_TO_POC branch does not match the action")
        if proof.get("existing_objective") != branch.get("objective"):
            raise ControlActionError("RETARGET_TO_POC existing objective mismatch")
        _required_text(proof.get("new_objective"), "new_objective")
        _require_milestone_reference(
            milestones, proof.get("linked_receipt_id"),
            {"PRIMITIVE_CONFIRMED", "WORKING_POC"},
        )
        transition_id = _required_text(
            proof.get("objective_revision_receipt"), "objective_revision_receipt",
        )
        transitions = read_jsonl_strict(
            run / "RACE_TRANSITIONS.jsonl", "race transition ledger",
        )
        revision = next((
            row for row in transitions
            if row.get("transition_id") == transition_id
            and any(
                isinstance(item, Mapping)
                and item.get("session_id") == session_id
                and item.get("objective") == proof.get("new_objective")
                for item in row.get("objective_rewrites", [])
            )
        ), None)
        if revision is None:
            raise ControlActionError(
                "RETARGET_TO_POC objective revision receipt is not authoritative"
            )
        return

    if action_type == "REPLACE_ATTACK_FAMILY":
        request_id = str(proof.get("replacement_request_id") or "")
        requests = plan.get("replacement_requests", []) if isinstance(plan.get("replacement_requests"), list) else []
        request = next((
            row for row in requests
            if isinstance(row, Mapping) and row.get("replacement_request_id") == request_id
        ), None)
        if request is None:
            raise ControlActionError("replacement request receipt does not exist")
        superseded = next((
            row for row in branches
            if isinstance(row, Mapping)
            and row.get("session_id") == request.get("superseded_branch_id")
        ), None)
        fields = {
            "superseded_branch_id": request.get("superseded_branch_id"),
            "new_branch_id": request.get("new_session_id"),
            "old_hypothesis_family": (
                superseded.get("hypothesis_family") if superseded else None
            ),
            "new_hypothesis_family": request.get("new_hypothesis_family"),
            "distinct_mechanism_proof": request.get("distinct_mechanism_proof"),
        }
        if any(proof.get(field) != value for field, value in fields.items()):
            raise ControlActionError("replacement proof does not match the recorded request")
        if str(fields["old_hypothesis_family"]).casefold() == str(fields["new_hypothesis_family"]).casefold():
            raise ControlActionError("replacement attack family is not a distinct mechanism")
        return

    if action_type == "REMOTE_ATTEMPT_REQUIRED":
        _require_milestone_reference(
            milestones, proof.get("evidence_receipt_id"), {"REMOTE_ATTEMPT", "TYPED_BLOCKER"},
            blockers={
                "TARGET_DOWN", "AUTH_BLOCKED", "RATE_LIMITED", "ENDPOINT_CHANGED",
                "PROTOCOL_MISMATCH", "LOCAL_ONLY_CHALLENGE",
            },
        )
        return

    if action_type == "LONG_COMPUTE_REVIEW":
        decision = str(proof.get("decision") or "").upper()
        if decision not in {
            "CANCELLED", "CONTINUED_WITH_VALID_CHECKPOINT", "FALLBACK_APPLIED", "COMPLETED",
        }:
            raise ControlActionError("LONG_COMPUTE_REVIEW decision is invalid")
        long_compute = _require_milestone_reference(
            milestones, proof.get("long_compute_receipt_id"), {"LONG_COMPUTE"},
        )
        try:
            from .progress import ProgressGateError, validate_long_compute_review_proof
            return validate_long_compute_review_proof(
                run, action=action, proof=proof,
                long_compute_receipt=long_compute, milestones=milestones,
            )
        except ProgressGateError as exc:
            raise ControlActionError(str(exc)) from exc

    if action_type in {"ROUTING_FALLBACK_RECORDED", "ROUTING_MISMATCH_REVIEW"}:
        if branch is None:
            raise ControlActionError("routing review target branch does not exist")
        start = branch.get("start_receipt") or branch.get("native_start_receipt")
        if (
            not isinstance(start, Mapping)
            or start.get("receipt_id") != proof.get("native_start_receipt_id")
        ):
            raise ControlActionError("routing review requires the exact native start receipt")
        expected = (
            "FALLBACK_MATCHED" if action_type == "ROUTING_FALLBACK_RECORDED"
            else "ROUTING_MISMATCH"
        )
        if start.get("routing_classification") != expected:
            raise ControlActionError("native start receipt does not prove the routing action")
        return dict(start)

    if action_type == "MAX_LEASE_EXPIRED":
        if branch is None or branch.get("routing_profile") != "CONFIRMED_BOTTLENECK":
            raise ControlActionError("Max lease action target is not a Max lane")
        start = branch.get("start_receipt") or branch.get("native_start_receipt")
        if not isinstance(start, Mapping) or start.get("receipt_id") != proof.get("native_start_receipt_id"):
            raise ControlActionError("Max lease expiry requires the exact native start receipt")
        if proof.get("lease_reason") not in {
            "lease_expired", "two_decisive_experiments_completed",
        }:
            raise ControlActionError("Max lease expiry reason is invalid")
        return dict(start)

    _require_milestone_reference(
        milestones, proof.get("evidence_receipt_id"),
        {"DECISIVE_EXPERIMENT", "PRIMITIVE_CONFIRMED", "PRIMITIVE_REFUTED", "WORKING_POC", "TYPED_BLOCKER"},
    )


def _require_milestone_reference(
    rows: list[dict[str, Any]], receipt_id: Any, event_types: set[str],
    *, blockers: set[str] | None = None,
) -> dict[str, Any]:
    match = next((
        row for row in rows
        if row.get("receipt_id") == str(receipt_id or "")
        and row.get("event_type") in event_types
    ), None)
    if match is None:
        raise ControlActionError("control action proof references no matching authoritative milestone")
    if match.get("event_type") == "TYPED_BLOCKER" and blockers is not None:
        detail = match.get("details") if isinstance(match.get("details"), Mapping) else {}
        if str(detail.get("blocker_type") or "").upper() not in blockers:
            raise ControlActionError("typed blocker does not satisfy this control action")
    return match


def _application_receipt(run: Path, action_id: str) -> dict[str, Any]:
    path = run / "control-application-receipts" / f"{action_id}.json"
    if path.is_symlink() or not path.is_file():
        raise ControlActionError("control action application receipt is missing or unsafe")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ControlActionError("control action application receipt is malformed") from exc
    if not isinstance(payload, dict):
        raise ControlActionError("control action application receipt is not an object")
    return payload


def _json_optional(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    if path.is_symlink() or not path.is_file():
        raise ControlActionError(f"control proof source is unsafe: {path.name}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ControlActionError(f"control proof source is malformed: {path.name}") from exc
    if not isinstance(payload, dict):
        raise ControlActionError(f"control proof source is not an object: {path.name}")
    return payload


def _required_text(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 2000 or any(char in text for char in "\0\r\n"):
        raise ControlActionError(f"{field} is invalid")
    return text


def _submitted_proof(value: Mapping[str, Any]) -> dict[str, Any]:
    ignored = {"schema_version", "created_at", "action_type", "authoritative_evidence"}
    return {key: item for key, item in value.items() if key not in ignored}


def load_control_actions(root: Path, *, current_view: bool = True) -> list[dict[str, Any]]:
    run = resolve_active_run(root)
    rows = read_jsonl_strict(run / "control-actions.jsonl", "control action ledger")
    if not current_view:
        return rows
    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row.get("schema_version") != CONTROL_ACTION_SCHEMA_VERSION or not row.get("action_id"):
            raise ControlActionError("control action ledger contains an unsupported row")
        latest[str(row["action_id"])] = row
    return sorted(latest.values(), key=lambda row: (str(row.get("created_at", "")), str(row.get("action_id", ""))))


def pending_control_actions(root: Path, *, session_id: str | None = None) -> list[dict[str, Any]]:
    rows = [row for row in load_control_actions(root) if row.get("status") == "PENDING"]
    if session_id is not None:
        rows = [row for row in rows if row.get("session_id") == session_id]
    return rows


def _current(rows: list[dict[str, Any]], action_id: str) -> dict[str, Any] | None:
    return next((row for row in reversed(rows) if row.get("action_id") == action_id), None)


def _state(run: Path) -> dict[str, Any]:
    try:
        state = json.loads((run / "STATE.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ControlActionError("run state is malformed") from exc
    if not isinstance(state, dict):
        raise ControlActionError("run state is not an object")
    return state


def _text(value: Any, field: str, maximum: int) -> str:
    text = str(value).strip()
    if not text or len(text) > maximum or any(char in text for char in "\0\r"):
        raise ControlActionError(f"{field} is invalid")
    return text
