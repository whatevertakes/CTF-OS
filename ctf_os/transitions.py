"""Automatic, append-only race convergence control loop.

This module records recommendations and prompt/lifecycle packets only.  It
never creates, supervises, or terminates native child sessions.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .delegation import branch_utility, load_plan, utc_now
from .primitives import PRIMITIVE_CONFIRMED, PRIMITIVE_REFUTED
from .worker import collect_worker_checkpoints, load_worker_result
from .workspace import atomic_json, state_lock


HIGH_VALUE_TYPES = frozenset({
    "BLOCKER", "EXPLOIT_PRIMITIVE_CANDIDATE", "EXPLOIT_PRIMITIVE_CONFIRMED",
    "EXPLOIT_PRIMITIVE_REFUTED", "WORKING_POC", "FLAG_CANDIDATE",
    "REMOTE_FLAG_OBTAINED", "CHILD_TERMINAL_RESULT", "BRANCH_TERMINAL",
    "BUDGET_50", "BUDGET_100", "PLATEAU_3", "DUPLICATE_BLOCKER_2",
    "DUPLICATE_COMMAND_FAMILY_2", "CONTROL_LOOP_TICK",
})


def evaluate_race_transition(
    solve_root: Path, triggering_event: Mapping[str, Any] | str,
    affected_session_id: str | None = None, input_fingerprint: str | None = None,
) -> dict[str, Any]:
    root = solve_root.resolve()
    event = dict(triggering_event) if isinstance(triggering_event, Mapping) else {"type": str(triggering_event)}
    trigger = str(event.get("type") or event.get("trigger") or "").upper()
    event_key = str(event.get("event_id") or event.get("checkpoint_id") or event.get("result_id") or "")
    if not event_key:
        event_key = hashlib.sha256(json.dumps(event, sort_keys=True, default=str).encode()).hexdigest()[:24]
    transition_id = hashlib.sha256(f"{trigger}:{event_key}:{affected_session_id or ''}".encode()).hexdigest()[:24]
    existing = _transition_by_id(root / "RACE_TRANSITIONS.jsonl", transition_id)
    if existing:
        return {**existing, "idempotent": True}
    if trigger not in HIGH_VALUE_TYPES:
        return {
            "transition_id": transition_id, "trigger": trigger, "triggered": False,
            "evaluated_branches": [], "utility_results": {}, "recommended_actions": [],
            "sol_takeover": None, "replacement_requests": [], "objective_rewrites": [],
            "branches_to_finalize": [], "branches_to_reclaim": [], "idempotent": False,
        }
    try:
        plan = load_plan(root, input_fingerprint=input_fingerprint)
    except Exception:
        return {
            "transition_id": transition_id, "trigger": trigger, "triggered": False,
            "reason": "no current delegation plan", "evaluated_branches": [],
            "utility_results": {}, "recommended_actions": [], "sol_takeover": None,
            "replacement_requests": [], "objective_rewrites": [],
            "branches_to_finalize": [], "branches_to_reclaim": [], "idempotent": False,
        }
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
    if refuted:
        for sid in dependent:
            actions.append({"action": "REVIEW_REQUIRED", "session_id": sid, "invalidated_primitive": claimed})
            replacements.append(_replacement_packet(plan, sid, "primitive refuted; choose a distinct mechanism"))
    for sid, advice in utility.items():
        classification = advice.get("classification")
        if classification == "FLAG_PATH":
            actions.append({"action": "FLAG_PATH", "session_id": sid, "maximum_optional_verifiers": 1})
            reclaim.extend(other for other in evaluated if other != sid and other not in reclaim)
        elif classification == "SOL_TAKEOVER" and takeover is None:
            takeover = {"session_id": sid, "next_objective": "minimal PoC or exploit endgame", "native_action_owner": "sol", "required": True}
            actions.append({"action": "SOL_TAKEOVER", **takeover})
        elif classification == "REPLACE_ATTACK_FAMILY":
            replacements.append(_replacement_packet(plan, sid, str(advice.get("recommendation", "plateau"))))
        elif classification == "BUMP_AND_RETRY":
            actions.append({"action": "BUMP_AND_RETRY", "session_id": sid, "maximum_retries": 1, "require_changed_decisive_experiment": True})
        elif classification == "DEAD_BRANCH":
            finalize.append(sid); reclaim.append(sid)
            actions.append({"action": "FINALIZE_AND_RECLAIM", "session_id": sid, "native_action_owner": "sol"})
    result = {
        "schema_version": 1, "transition_id": transition_id, "trigger": trigger,
        "triggering_event_id": event_key, "affected_session_id": affected_session_id,
        "input_fingerprint": fingerprint, "triggered": True,
        "evaluated_branches": evaluated, "utility_results": utility,
        "recommended_actions": actions, "sol_takeover": takeover,
        "replacement_requests": _dedupe(replacements, "session_id"),
        "objective_rewrites": _dedupe(rewrites, "session_id"),
        "branches_to_finalize": sorted(set(finalize)),
        "branches_to_reclaim": sorted(set(reclaim)),
        "dependent_invalidations": dependent, "created_at": utc_now(), "idempotent": False,
    }
    with state_lock(root):
        if not _transition_by_id(root / "RACE_TRANSITIONS.jsonl", transition_id):
            _append_jsonl(root / "RACE_TRANSITIONS.jsonl", result)
            _apply_plan_recommendations(root, result)
            _project_state(root, trigger, result)
    _apply_scheduler_recommendations(root, trigger, result)
    return result


def maybe_evaluate_checkpoint(solve_root: Path, checkpoint: Mapping[str, Any]) -> dict[str, Any] | None:
    kind = str(checkpoint.get("type", "")).upper()
    trigger = kind if kind in HIGH_VALUE_TYPES else _derived_checkpoint_trigger(solve_root, checkpoint)
    if not trigger:
        return None
    event = {**dict(checkpoint), "type": trigger, "checkpoint_id": f"{checkpoint.get('session_id')}:{checkpoint.get('sequence')}"}
    return evaluate_race_transition(solve_root, event, str(checkpoint.get("session_id") or ""), str(checkpoint.get("input_fingerprint") or ""))


def control_loop_tick(solve_root: Path, *, input_fingerprint: str, session_id: str | None = None) -> dict[str, Any]:
    result = evaluate_race_transition(solve_root, {"type": "CONTROL_LOOP_TICK", "event_id": f"tick:{utc_now()}"}, session_id, input_fingerprint)
    for sid, advice in result.get("utility_results", {}).items():
        ratio = float(advice.get("metrics", {}).get("elapsed_budget_ratio", 0) or 0)
        branch = None
        try:
            branch = next(row for row in load_plan(solve_root, input_fingerprint=input_fingerprint).get("branches", []) if row.get("session_id") == sid)
        except Exception:
            pass
        stable = str((branch or {}).get("started_at") or (branch or {}).get("created_at") or "unknown")
        if ratio >= 1:
            evaluate_race_transition(solve_root, {"type": "BUDGET_100", "event_id": f"budget100:{sid}:{stable}"}, sid, input_fingerprint)
        elif ratio >= .5:
            evaluate_race_transition(solve_root, {"type": "BUDGET_50", "event_id": f"budget50:{sid}:{stable}"}, sid, input_fingerprint)
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
    for branch in plan.get("branches", []):
        sid = branch.get("session_id")
        advice = utility.get(sid) if isinstance(utility, Mapping) else None
        if isinstance(advice, Mapping):
            branch["utility_classification"] = advice.get("classification")
            branch["utility_evaluated_at"] = result.get("created_at")
        if sid in rewrites:
            branch["recommended_objective"] = rewrites[sid].get("objective")
            branch["objective_rewrite_pending_sol_action"] = True
        if sid in replacements:
            branch["replacement_recommendation"] = replacements[sid]
        if sid in invalid:
            branch["review_required"] = True
            branch["invalidated_primitive"] = result.get("recommended_actions", [{}])[0].get("invalidated_primitive") if result.get("recommended_actions") else None
    plan["last_transition_id"] = result.get("transition_id")
    plan["updated_at"] = result.get("created_at")
    atomic_json(path, plan)


def _apply_scheduler_recommendations(root: Path, trigger: str, result: Mapping[str, Any]) -> None:
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
    except Exception:
        # Transition advice remains authoritative and replayable even if the
        # optional resource ledger is absent or temporarily malformed.
        return


def _dedupe(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    return list({str(row.get(key)): row for row in rows}.values())


def _read_checkpoint_dir(path: Path) -> list[dict[str, Any]]:
    rows = []
    for item in sorted(path.glob("*.json")) if path.is_dir() else []:
        try: rows.append(json.loads(item.read_text(encoding="utf-8")))
        except Exception: continue
    return rows


def _transition_by_id(path: Path, transition_id: str) -> dict[str, Any] | None:
    return next((row for row in _read_jsonl(path) if row.get("transition_id") == transition_id), None)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file() or path.is_symlink(): return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
            if isinstance(row, dict): rows.append(row)
        except json.JSONDecodeError: continue
    return rows


def _append_jsonl(path: Path, row: Mapping[str, Any]) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(dict(row), sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush(); os.fsync(handle.fileno())
