"""Automatic, append-only race convergence control loop.

This module records recommendations and prompt/lifecycle packets only.  It
never creates, supervises, or terminates native child sessions.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
from typing import Any

from .delegation import branch_utility, load_plan, utc_now
from .primitives import PRIMITIVE_CONFIRMED, PRIMITIVE_REFUTED
from .worker import collect_worker_checkpoints, load_worker_result
from .workspace import (
    atomic_json, challenge_workspace, ensure_run_mutable, is_run_root,
    resolve_active_run, state_lock,
)
from .workspace import append_jsonl_fsync, read_jsonl_strict
from .projections import apply_projection, ensure_projection_manifest


TRANSITION_PROJECTIONS = ("control_action", "plan", "state", "compatibility", "scheduler")


HIGH_VALUE_TYPES = frozenset({
    "BLOCKER", "EXPLOIT_PRIMITIVE_CANDIDATE", "EXPLOIT_PRIMITIVE_CONFIRMED",
    "EXPLOIT_PRIMITIVE_REFUTED", "WORKING_POC", "FLAG_CANDIDATE",
    "REMOTE_FLAG_OBTAINED", "CHILD_TERMINAL_RESULT", "BRANCH_TERMINAL",
    "BUDGET_50", "BUDGET_100", "PLATEAU_3", "DUPLICATE_BLOCKER_2",
    "DUPLICATE_COMMAND_FAMILY_2", "CONTROL_LOOP_TICK",
    "DECISIVE_EXPERIMENT", "PRIMITIVE_CANDIDATE", "PRIMITIVE_CONFIRMED",
    "PRIMITIVE_REFUTED", "REMOTE_ATTEMPT", "TYPED_BLOCKER", "LONG_COMPUTE",
})


def evaluate_race_transition(
    solve_root: Path, triggering_event: Mapping[str, Any] | str,
    affected_session_id: str | None = None, input_fingerprint: str | None = None,
) -> dict[str, Any]:
    root = resolve_active_run(solve_root, input_fingerprint=input_fingerprint)
    event = dict(triggering_event) if isinstance(triggering_event, Mapping) else {"type": str(triggering_event)}
    trigger = str(event.get("type") or event.get("trigger") or "").upper()
    receipt_reference = event.get("receipt_reference") if isinstance(event.get("receipt_reference"), Mapping) else {}
    if trigger in {"REMOTE_FLAG_OBTAINED", "SUBMISSION_RECOMMENDED", "ACCEPTED"}:
        if not receipt_reference.get("receipt_id"):
            raise ValueError(f"{trigger} transition requires a verified lifecycle receipt")
        state = json.loads((root / "STATE.json").read_text(encoding="utf-8"))
        expected = f"flag-receipts/remote-{receipt_reference['receipt_id']}.json"
        if state.get("remote_flag_receipt") != expected:
            raise ValueError("verified transition receipt does not match run state")
    else:
        ensure_run_mutable(root)
    event_key = str(event.get("event_id") or event.get("checkpoint_id") or event.get("result_id") or "")
    if not event_key:
        event_key = hashlib.sha256(json.dumps(event, sort_keys=True, default=str).encode()).hexdigest()[:24]
    transition_id = hashlib.sha256(f"{trigger}:{event_key}:{affected_session_id or ''}".encode()).hexdigest()[:24]
    existing = _transition_by_id(root / "RACE_TRANSITIONS.jsonl", transition_id)
    if existing:
        projected = repair_transition_projections(root, existing)
        return {
            **existing, "control_actions": projected["control_actions"],
            "idempotent": True,
        }
    if trigger not in HIGH_VALUE_TYPES:
        return {
            "transition_id": transition_id, "trigger": trigger, "triggered": False,
            "evaluated_branches": [], "utility_results": {}, "recommended_actions": [],
            "sol_takeover": None, "replacement_requests": [], "objective_rewrites": [],
            "branches_to_finalize": [], "branches_to_reclaim": [], "idempotent": False,
        }
    delegation_path = root / "DELEGATION_PLAN.json"
    if not delegation_path.exists() and not delegation_path.is_symlink():
        return {
            "transition_id": transition_id, "trigger": trigger, "triggered": False,
            "reason": "no current delegation plan", "evaluated_branches": [],
            "utility_results": {}, "recommended_actions": [], "sol_takeover": None,
            "replacement_requests": [], "objective_rewrites": [],
            "branches_to_finalize": [], "branches_to_reclaim": [], "idempotent": False,
        }
    # A present but malformed/stale plan is authoritative state corruption,
    # not equivalent to an optional plan that has never been created.
    plan = load_plan(root, input_fingerprint=input_fingerprint)
    from .progress import load_solve_policy
    maximum_verifiers = int(
        load_solve_policy()["remote_transition"]["maximum_optional_verifiers"]
    )
    fingerprint = input_fingerprint or str(plan.get("input_fingerprint", ""))
    checkpoints = collect_worker_checkpoints(root / "workers", input_fingerprint=fingerprint)
    # Race events participate in utility without duplicating worker checkpoints.
    checkpoints.extend(_read_jsonl(root / "race-events.jsonl"))
    utility: dict[str, Any] = {}
    evaluated: list[str] = []
    for branch in plan.get("branches", []):
        session_id = str(branch.get("session_id", ""))
        if not session_id:
            continue
        result_path = root / "workers" / session_id / "result.json"
        result = load_worker_result(result_path) if result_path.is_file() else None
        utility[session_id] = branch_utility(plan, session_id=session_id, checkpoints=checkpoints, result=result)
        evaluated.append(session_id)
    confirmed = trigger == PRIMITIVE_CONFIRMED
    refuted = trigger == PRIMITIVE_REFUTED
    claimed = _primitive_claim(event)
    dependent = _dependent_branches(plan, claimed, exclude=affected_session_id) if refuted else []
    actions: list[dict[str, Any]] = []
    replacements: list[dict[str, Any]] = []
    rewrites: list[dict[str, Any]] = []
    finalize: list[str] = []
    reclaim: list[str] = []
    takeover = None
    if confirmed:
        takeover = {
            "session_id": affected_session_id, "claimed_capability": claimed,
            "next_objective": "Build the minimal PoC or exploit endgame, then run the declared remote",
            "native_action_owner": "sol", "required": True,
        }
        actions.append({"action": "SOL_TAKEOVER", **takeover})
        family = _branch_family(plan, affected_session_id)
        verifier_kept = 0
        for branch in plan.get("branches", []):
            sid = str(branch.get("session_id", ""))
            duplicate_claim = any(
                row.get("session_id") == sid
                and str(row.get("type", "")).upper() in {"EXPLOIT_PRIMITIVE", "EXPLOIT_PRIMITIVE_CANDIDATE"}
                and _primitive_claim(row).casefold() == claimed.casefold()
                for row in checkpoints
            )
            if sid != affected_session_id and ((family and branch.get("hypothesis_family") == family) or duplicate_claim):
                rewrites.append({
                    "session_id": sid, "objective": "Implement or link the confirmed primitive to a minimal PoC",
                    "reason": "duplicate primitive discovery is no longer useful",
                })
            elif sid != affected_session_id:
                verifier = bool(branch.get("independent_verification"))
                if verifier and verifier_kept < maximum_verifiers:
                    verifier_kept += 1
                else:
                    actions.append({
                        "action": "STOP_LOW_VALUE_BRANCH", "session_id": sid,
                        "reason": "confirmed primitive converges the race on the leading path",
                        "native_action_owner": "sol",
                    })
    if refuted:
        for sid in dependent:
            actions.append({"action": "REVIEW_REQUIRED", "session_id": sid, "invalidated_primitive": claimed})
            replacements.append(_replacement_packet(plan, sid, "primitive refuted; choose a distinct mechanism"))
    if trigger == "REMOTE_FLAG_OBTAINED":
        verifier_kept = 0
        for branch in plan.get("branches", []):
            sid = str(branch.get("session_id", ""))
            if not sid or sid == affected_session_id:
                continue
            if branch.get("independent_verification") and verifier_kept < maximum_verifiers:
                verifier_kept += 1
                continue
            actions.append({
                "action": "STOP_LOW_VALUE_BRANCH", "session_id": sid,
                "reason": "verified remote flag obtained; retain at most one independent verifier",
                "native_action_owner": "sol",
            })
    if trigger != "REMOTE_FLAG_OBTAINED":
        for sid, advice in utility.items():
            classification = advice.get("classification")
            if classification == "FLAG_PATH":
                actions.append({
                    "action": "FLAG_PATH", "session_id": sid,
                    "maximum_optional_verifiers": maximum_verifiers,
                })
                reclaim.extend(other for other in evaluated if other != sid and other not in reclaim)
            elif classification == "SOL_TAKEOVER" and takeover is None:
                takeover = {"session_id": sid, "next_objective": "minimal PoC or exploit endgame", "native_action_owner": "sol", "required": True}
                actions.append({"action": "SOL_TAKEOVER", **takeover})
            elif classification == "REPLACE_ATTACK_FAMILY":
                replacements.append(_replacement_packet(plan, sid, str(advice.get("recommendation", "plateau"))))
            elif classification == "BUMP_AND_RETRY":
                actions.append({"action": "CONTINUE_WITH_EVIDENCE", "session_id": sid, "maximum_retries": 1, "require_changed_decisive_experiment": True})
            elif classification == "DEAD_BRANCH":
                finalize.append(sid); reclaim.append(sid)
                actions.append({"action": "FINALIZE_AND_RECLAIM", "session_id": sid, "native_action_owner": "sol"})
    result = {
        "schema_version": 1, "transition_id": transition_id, "trigger": trigger,
        "run_id": plan.get("run_id") or root.name,
        "challenge_id": plan.get("challenge_id"),
        "target_revision": plan.get("target_revision"),
        "triggering_event_id": event_key, "affected_session_id": affected_session_id,
        "input_fingerprint": fingerprint, "triggered": True,
        "evaluated_branches": evaluated, "utility_results": utility,
        "recommended_actions": actions, "sol_takeover": takeover,
        "replacement_requests": _dedupe(replacements, "session_id"),
        "objective_rewrites": _dedupe(rewrites, "session_id"),
        "branches_to_finalize": sorted(set(finalize)),
        "branches_to_reclaim": sorted(set(reclaim)),
        "dependent_invalidations": dependent, "created_at": utc_now(), "idempotent": False,
        "required_projections": list(TRANSITION_PROJECTIONS),
    }
    with state_lock(root):
        if not _transition_by_id(root / "RACE_TRANSITIONS.jsonl", transition_id):
            _append_jsonl(root / "RACE_TRANSITIONS.jsonl", result)
    projected = repair_transition_projections(root, result)
    return {**result, "control_actions": projected["control_actions"]}


def repair_transition_projections(root: Path, result: Mapping[str, Any]) -> dict[str, Any]:
    run = resolve_active_run(root)
    receipt = {**dict(result), "receipt_id": result.get("transition_id")}
    required = list(result.get("required_projections") or TRANSITION_PROJECTIONS)
    ensure_projection_manifest(run, receipt, required)
    applied: list[str] = []
    controls, skipped = apply_projection(
        run, receipt, required, "control_action",
        lambda: _verify_transition_controls(run, result),
    )
    if skipped:
        controls = _stored_transition_controls(run, result)
    else:
        applied.append("control_action")
    projected = {**dict(result), "control_actions": controls}
    action_by_session_and_type = {
        (row.get("session_id"), row.get("action_type")): row.get("action_id")
        for row in controls
    }
    projected["objective_rewrites"] = [dict(row) for row in result.get("objective_rewrites", [])]
    for rewrite in projected["objective_rewrites"]:
        rewrite["control_action_id"] = action_by_session_and_type.get(
            (rewrite.get("session_id"), "RETARGET_TO_POC"),
        )
    if isinstance(result.get("sol_takeover"), Mapping):
        projected["sol_takeover"] = dict(result["sol_takeover"])
        projected["sol_takeover"]["control_action_id"] = action_by_session_and_type.get(
            (result.get("affected_session_id"), "SOL_TAKEOVER"),
        )
    stages = (
        ("plan", lambda: _apply_plan_recommendations(run, projected)),
        ("state", lambda: _project_state(run, str(result.get("trigger") or ""), projected)),
        ("compatibility", lambda: _project_legacy_transition_view(run, projected)),
        ("scheduler", lambda: _apply_scheduler_recommendations(
            run, str(result.get("trigger") or ""), projected, strict=True,
        )),
    )
    for name, callback in stages:
        _value, skipped = apply_projection(run, receipt, required, name, callback)
        if not skipped:
            applied.append(name)
    return {
        "transition_id": result.get("transition_id"), "applied": applied,
        "control_actions": controls,
    }


def repair_run_transition_projections(
    root: Path, *, suppress_errors: bool = False,
) -> dict[str, Any]:
    """Replay pending projections for standalone transition receipts too."""

    run = resolve_active_run(root)
    repaired: list[str] = []
    errors: list[str] = []
    for transition in _read_jsonl(run / "RACE_TRANSITIONS.jsonl"):
        transition_id = str(transition.get("transition_id") or "")
        if not transition_id:
            raise ValueError("race transition ledger contains a receipt without transition_id")
        receipt = {**transition, "receipt_id": transition_id}
        required = list(transition.get("required_projections") or TRANSITION_PROJECTIONS)
        manifest = ensure_projection_manifest(run, receipt, required)
        if not any(
            isinstance(row, Mapping) and row.get("status") in {"PENDING", "FAILED"}
            for row in manifest.get("projections", {}).values()
        ):
            continue
        try:
            repair_transition_projections(run, transition)
            repaired.append(transition_id)
        except Exception as exc:
            message = f"{transition_id}: {exc}"[:2000]
            errors.append(message)
            append_jsonl_fsync(run / "post-commit-errors.jsonl", {
                "event": "RACE_TRANSITION_PROJECTION_FAILED",
                "transition_id": transition_id, "error": str(exc)[:2000],
                "created_at": utc_now(),
            }, label="post-commit error ledger")
            if not suppress_errors:
                raise
    return {"repaired_transitions": repaired, "errors": errors}


def _verify_transition_controls(root: Path, result: Mapping[str, Any]) -> list[dict[str, Any]]:
    stored = {
        str(row.get("action_id")) for row in result.get("control_actions", [])
        if isinstance(row, Mapping)
    }
    from .control import load_control_actions
    ledger_ids = {
        str(row.get("action_id")) for row in load_control_actions(root, current_view=False)
    }
    if stored and stored <= ledger_ids:
        return [dict(row) for row in result.get("control_actions", []) if isinstance(row, Mapping)]
    expected = _materialize_control_actions(
        root, result, str(result.get("triggering_event_id") or ""),
    )
    actual = {str(row.get("action_id")) for row in expected}
    if stored and stored != actual:
        raise ValueError("transition control action projection conflicts with transition receipt")
    return expected


def _stored_transition_controls(
    root: Path, result: Mapping[str, Any],
) -> list[dict[str, Any]]:
    from .control import load_control_actions

    expected = _expected_control_pairs(result)
    rows = [
        row for row in load_control_actions(root)
        if (str(row.get("session_id")), str(row.get("action_type"))) in expected
    ]
    actual = {(str(row.get("session_id")), str(row.get("action_type"))) for row in rows}
    if not expected <= actual:
        raise ValueError(
            "transition control action projection is APPLIED but its destination is missing"
        )
    return rows


def _expected_control_pairs(result: Mapping[str, Any]) -> set[tuple[str, str]]:
    mapping = {
        "SOL_TAKEOVER": "SOL_TAKEOVER",
        "CONTINUE_WITH_EVIDENCE": "CONTINUE_WITH_EVIDENCE",
        "STOP_LOW_VALUE_BRANCH": "STOP_LOW_VALUE_BRANCH",
        "FINALIZE_AND_RECLAIM": "STOP_REQUIRED",
        "REVIEW_REQUIRED": "REVIEW_CANDIDATE_DEPENDENCY",
    }
    pairs = {
        (
            str(action.get("session_id") or result.get("affected_session_id") or "sol-main"),
            mapping[str(action.get("action"))],
        )
        for action in result.get("recommended_actions", [])
        if isinstance(action, Mapping) and str(action.get("action")) in mapping
    }
    pairs.update(
        (str(row.get("session_id")), "REPLACE_ATTACK_FAMILY")
        for row in result.get("replacement_requests", []) if isinstance(row, Mapping)
    )
    pairs.update(
        (str(row.get("session_id")), "RETARGET_TO_POC")
        for row in result.get("objective_rewrites", []) if isinstance(row, Mapping)
    )
    return pairs


def _project_legacy_transition_view(root: Path, result: Mapping[str, Any]) -> None:
    """Keep pre-run direct callers readable without making the view authoritative."""

    if not is_run_root(root):
        return
    workspace = challenge_workspace(root)
    legacy_state = workspace / "STATE.json"
    if not legacy_state.is_file() or legacy_state.is_symlink():
        return
    projected = json.loads((root / "STATE.json").read_text(encoding="utf-8"))
    projected["compatibility_view"] = True
    projected["authoritative_state"] = str((root / "STATE.json").relative_to(workspace))
    atomic_json(legacy_state, projected)
    path = workspace / "RACE_TRANSITIONS.jsonl"
    if not any(row.get("transition_id") == result.get("transition_id") for row in _read_jsonl(path)):
        _append_jsonl(path, result)


def maybe_evaluate_checkpoint(solve_root: Path, checkpoint: Mapping[str, Any]) -> dict[str, Any] | None:
    kind = str(checkpoint.get("type", "")).upper()
    trigger = kind if kind in HIGH_VALUE_TYPES else _derived_checkpoint_trigger(solve_root, checkpoint)
    if not trigger:
        return None
    event = {**dict(checkpoint), "type": trigger, "checkpoint_id": f"{checkpoint.get('session_id')}:{checkpoint.get('sequence')}"}
    return evaluate_race_transition(solve_root, event, str(checkpoint.get("session_id") or ""), str(checkpoint.get("input_fingerprint") or ""))


def control_loop_tick(solve_root: Path, *, input_fingerprint: str, session_id: str | None = None) -> dict[str, Any]:
    result = evaluate_race_transition(solve_root, {"type": "CONTROL_LOOP_TICK", "event_id": f"tick:{utc_now()}"}, session_id, input_fingerprint)
    current_plan = (
        load_plan(solve_root, input_fingerprint=input_fingerprint)
        if result.get("utility_results") else {"branches": []}
    )
    for sid, advice in result.get("utility_results", {}).items():
        ratio = float(advice.get("metrics", {}).get("elapsed_budget_ratio", 0) or 0)
        branch = next(
            (row for row in current_plan.get("branches", []) if row.get("session_id") == sid),
            None,
        )
        stable = str((branch or {}).get("started_at") or (branch or {}).get("created_at") or "unknown")
        if ratio >= 1:
            evaluate_race_transition(solve_root, {"type": "BUDGET_100", "event_id": f"budget100:{sid}:{stable}"}, sid, input_fingerprint)
        elif ratio >= .5:
            evaluate_race_transition(solve_root, {"type": "BUDGET_50", "event_id": f"budget50:{sid}:{stable}"}, sid, input_fingerprint)
    try:
        from .progress import evaluate_remote_transition
        progress_path = solve_root / "progress-state.json"
        progress = json.loads(progress_path.read_text(encoding="utf-8")) if progress_path.is_file() else {}
        sessions = set(progress.get("remote_transition", {}))
        if session_id:
            sessions.add(session_id)
        result["remote_transitions"] = {
            sid: evaluate_remote_transition(solve_root, session_id=sid) for sid in sorted(sessions)
        }
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        result["remote_transition_error"] = str(exc)
    return result


def _derived_checkpoint_trigger(root: Path, checkpoint: Mapping[str, Any]) -> str | None:
    worker = root / "workers" / str(checkpoint.get("session_id", "")) / "checkpoints"
    rows = _read_checkpoint_dir(worker)
    proximity = [float(row.get("exploit_proximity", 0) or 0) for row in rows]
    if len(rows) >= 3 and max(proximity[-3:], default=0) <= max(proximity[:-3], default=0):
        if all(str(row.get("type", "")) in {"SUPPORTED_FACT", "ARTIFACT_READY", "REJECTED_HYPOTHESIS", "ENVIRONMENT_DISCOVERY"} for row in rows[-3:]):
            return "PLATEAU_3"
    blockers = Counter(str(row.get("summary", "")).strip().casefold() for row in rows if row.get("type") == "BLOCKER")
    if blockers and max(blockers.values()) >= 2:
        return "DUPLICATE_BLOCKER_2"
    if sum(bool(row.get("repeated_command")) for row in rows[-3:]) >= 2:
        return "DUPLICATE_COMMAND_FAMILY_2"
    return None


def _project_state(root: Path, trigger: str, result: Mapping[str, Any]) -> None:
    path = root / "STATE.json"
    if not path.is_file() or path.is_symlink():
        return
    state = json.loads(path.read_text(encoding="utf-8"))
    mapping = {
        "EXPLOIT_PRIMITIVE_CANDIDATE": "PRIMITIVE_CANDIDATE",
        "EXPLOIT_PRIMITIVE_CONFIRMED": "PRIMITIVE_CONFIRMED",
        "WORKING_POC": "POC_BUILDING", "FLAG_CANDIDATE": "FLAG_CANDIDATE",
        "REMOTE_FLAG_OBTAINED": "SUBMISSION_RECOMMENDED",
    }
    projected = mapping.get(trigger)
    if trigger == "EXPLOIT_PRIMITIVE_REFUTED" and str(state.get("status")) in {"PRIMITIVE_CANDIDATE", "PRIMITIVE_CONFIRMED"}:
        state["status"] = "RACE_RUNNING"
        projected = None
    if projected:
        order = ["PREPARED", "RACE_RUNNING", "PRIMITIVE_CANDIDATE", "PRIMITIVE_CONFIRMED", "POC_BUILDING", "REMOTE_READY", "FLAG_CANDIDATE", "SUBMISSION_RECOMMENDED", "FULLY_VERIFIED"]
        current = str(state.get("status", "PREPARED"))
        if current not in order or order.index(projected) >= order.index(current):
            state["status"] = projected
    state["last_race_transition_id"] = result.get("transition_id")
    state["updated_at"] = utc_now()
    atomic_json(path, state)


def _primitive_claim(event: Mapping[str, Any]) -> str:
    evidence = event.get("primitive") if isinstance(event.get("primitive"), Mapping) else event
    return str(evidence.get("claimed_capability") or event.get("summary") or "unknown primitive")


def _branch_family(plan: Mapping[str, Any], session_id: str | None) -> str | None:
    return next((str(row.get("hypothesis_family")) for row in plan.get("branches", []) if row.get("session_id") == session_id), None)


def _dependent_branches(plan: Mapping[str, Any], claim: str, *, exclude: str | None) -> list[str]:
    tokens = {word for word in claim.casefold().split() if len(word) > 3}
    return sorted(str(row.get("session_id")) for row in plan.get("branches", []) if row.get("session_id") != exclude and tokens & set(str(row.get("hypothesis", "")).casefold().split()))


def _replacement_packet(plan: Mapping[str, Any], session_id: str, reason: str) -> dict[str, Any]:
    old = next((row for row in plan.get("branches", []) if row.get("session_id") == session_id), {})
    return {"session_id": session_id, "superseded_family": old.get("hypothesis_family"), "kill_reason": reason, "distinct_mechanism_required": True, "native_action_owner": "sol", "lifecycle_command": "branch-replacement-prepare"}


def _apply_plan_recommendations(root: Path, result: Mapping[str, Any]) -> None:
    path = root / "DELEGATION_PLAN.json"
    if not path.is_file() or path.is_symlink():
        return
    plan = json.loads(path.read_text(encoding="utf-8"))
    utility = result.get("utility_results", {})
    rewrites = {row.get("session_id"): row for row in result.get("objective_rewrites", [])}
    replacements = {row.get("session_id"): row for row in result.get("replacement_requests", [])}
    invalid = set(result.get("dependent_invalidations", []))
    control_by_session: dict[str, list[Mapping[str, Any]]] = {}
    for action in result.get("control_actions", []):
        if isinstance(action, Mapping):
            control_by_session.setdefault(str(action.get("session_id")), []).append(action)
    for branch in plan.get("branches", []):
        sid = branch.get("session_id")
        advice = utility.get(sid) if isinstance(utility, Mapping) else None
        if isinstance(advice, Mapping):
            branch["utility_classification"] = advice.get("classification")
            branch["utility_evaluated_at"] = result.get("created_at")
        if sid in rewrites:
            branch["recommended_objective"] = rewrites[sid].get("objective")
            branch["objective_rewrite_pending_sol_action"] = rewrites[sid].get("control_action_id")
        if sid in replacements:
            branch["replacement_recommendation"] = replacements[sid]
        if sid in invalid:
            branch["review_required"] = True
            branch["invalidated_primitive"] = result.get("recommended_actions", [{}])[0].get("invalidated_primitive") if result.get("recommended_actions") else None
        for action in control_by_session.get(str(sid), []):
            if action.get("action_type") == "STOP_LOW_VALUE_BRANCH":
                branch["stop_request_pending_action_id"] = action.get("action_id")
                if branch.get("status") not in {"TERMINAL", "TERMINATED", "COMPLETED", "ERROR", "STALE"}:
                    branch["status"] = "STOP_REQUESTED"
                    branch["stop_requested_at"] = result.get("created_at")
                    branch["native_action_owner"] = "sol"
            if action.get("action_type") == "RETARGET_TO_POC":
                branch["objective_rewrite_pending_sol_action"] = action.get("action_id")
    if result.get("trigger") == "EXPLOIT_PRIMITIVE_CONFIRMED":
        plan["leading_path"] = {
            "session_id": result.get("affected_session_id"),
            "primitive": (result.get("sol_takeover") or {}).get("claimed_capability"),
            "transition_id": result.get("transition_id"),
            "control_action_id": (result.get("sol_takeover") or {}).get("control_action_id"),
        }
    plan["last_transition_id"] = result.get("transition_id")
    plan["updated_at"] = result.get("created_at")
    atomic_json(path, plan)


def _apply_scheduler_recommendations(
    root: Path, trigger: str, result: Mapping[str, Any], *, strict: bool = False,
) -> None:
    try:
        from .resources.scheduler import ResourceLedger
        ledger = ResourceLedger(root)
        state = ledger.load()
        for sid, advice in result.get("utility_results", {}).items():
            if sid not in state.get("requests", {}):
                continue
            classification = str(advice.get("classification", "INSUFFICIENT_DATA"))
            metrics = advice.get("metrics") if isinstance(advice.get("metrics"), Mapping) else {}
            changes: dict[str, Any] = {
                "utility_classification": classification,
                "scheduler_recommendation": advice.get("recommendation"),
                "progress": {
                    "progressing": classification in {"PROGRESSING", "FLAG_PATH"},
                    "exploit_proximity": metrics.get("exploit_proximity", 0),
                    "working_poc_present": metrics.get("working_poc_present", False),
                    "remote_ready": metrics.get("remote_ready", False),
                },
            }
            affected = result.get("affected_session_id")
            if trigger == "EXPLOIT_PRIMITIVE_CONFIRMED" and sid == affected: changes["priority"] = "HIGH"
            if trigger in {"WORKING_POC", "FLAG_CANDIDATE", "REMOTE_FLAG_OBTAINED"} and sid == affected: changes["priority"] = "CRITICAL"
            if trigger == "EXPLOIT_PRIMITIVE_REFUTED" and (sid == affected or sid in result.get("dependent_invalidations", [])): changes["priority"] = "LOW"
            ledger.update(sid, actor_session_id="sol-main", actor_role="sol", changes=changes)
    except Exception as exc:
        # Transition advice remains authoritative and replayable even if the
        # optional resource ledger is absent or temporarily malformed.
        append_jsonl_fsync(root / "scheduler-errors.jsonl", {
            "event": "TRANSITION_SCHEDULER_UPDATE_FAILED", "trigger": trigger,
            "transition_id": result.get("transition_id"), "error": str(exc),
            "created_at": utc_now(),
        }, label="scheduler error ledger")
        if strict:
            raise


def _dedupe(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    return list({str(row.get(key)): row for row in rows}.values())


def _read_checkpoint_dir(path: Path) -> list[dict[str, Any]]:
    rows = []
    for item in sorted(path.glob("*.json")) if path.is_dir() else []:
        try:
            row = json.loads(item.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"worker checkpoint is malformed: {item}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"worker checkpoint is not an object: {item}")
        rows.append(row)
    return rows


def _transition_by_id(path: Path, transition_id: str) -> dict[str, Any] | None:
    return next((row for row in _read_jsonl(path) if row.get("transition_id") == transition_id), None)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return read_jsonl_strict(path, path.name)


def _append_jsonl(path: Path, row: Mapping[str, Any]) -> None:
    append_jsonl_fsync(path, row, label=path.name)


def _materialize_control_actions(
    root: Path, result: Mapping[str, Any], triggering_evidence_id: str,
) -> list[dict[str, Any]]:
    from .control import create_control_action

    progress_path = root / "progress-state.json"
    try:
        progress = json.loads(progress_path.read_text(encoding="utf-8")) if progress_path.is_file() else {}
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("progress state is malformed during control action generation") from exc
    generations = progress.get("sessions", {}) if isinstance(progress, Mapping) else {}
    requested: list[tuple[str, str, str, dict[str, Any]]] = []
    mapping = {
        "SOL_TAKEOVER": "SOL_TAKEOVER", "CONTINUE_WITH_EVIDENCE": "CONTINUE_WITH_EVIDENCE",
        "STOP_LOW_VALUE_BRANCH": "STOP_LOW_VALUE_BRANCH", "FINALIZE_AND_RECLAIM": "STOP_REQUIRED",
        "REVIEW_REQUIRED": "REVIEW_CANDIDATE_DEPENDENCY",
    }
    for action in result.get("recommended_actions", []):
        kind = mapping.get(str(action.get("action")))
        session_id = str(action.get("session_id") or result.get("affected_session_id") or "sol-main")
        if kind:
            requested.append((session_id, kind, str(action.get("reason") or action.get("next_objective") or action.get("action")), dict(action)))
    for replacement in result.get("replacement_requests", []):
        requested.append((str(replacement.get("session_id")), "REPLACE_ATTACK_FAMILY", str(replacement.get("kill_reason") or "replace plateaued family"), dict(replacement)))
    for rewrite in result.get("objective_rewrites", []):
        requested.append((str(rewrite.get("session_id")), "RETARGET_TO_POC", str(rewrite.get("reason")), dict(rewrite)))
    records = []
    for session_id, action_type, reason, metadata in requested:
        generation = int(generations.get(session_id, {}).get("evidence_generation", 0)) if isinstance(generations, Mapping) else 0
        records.append(create_control_action(
            root, session_id=session_id, action_type=action_type, reason=reason,
            triggering_evidence_id=triggering_evidence_id, evidence_generation=generation,
            metadata=metadata,
        ))
    return records
