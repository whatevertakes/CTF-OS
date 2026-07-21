"""Deterministic records and recommendations for Sol-native delegation.

This module never creates, supervises, or terminates a child session.  It only
persists Sol's plan and computes reproducible admission/utility advice.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import hashlib
from pathlib import Path
import re
from typing import Any

import yaml

from .categories import playbook_category
from .modes import SolveMode
from .model_routing import (
    ROUTING_PROFILES, RoutingError, branch_routing_interpretation,
    build_native_delegation_packet, compare_runtime_routing,
    validate_routing_contract,
)
from .race_lineage import (
    append_lineage_event, lineage_state, recover_lineage_projections,
    record_start_failure,
)
from .workspace import (
    atomic_json, challenge_workspace, ensure_run_mutable, read_jsonl_strict, state_lock,
)


PLAN_SCHEMA_VERSION = 1
BRANCH_STATUSES = frozenset({
    "PLANNED", "ADMITTED", "CAPACITY_ADMITTED", "SANDBOX_READY",
    "AWAITING_NATIVE_START", "NATIVE_STARTED", "RUNNING", "CHECKPOINTED",
    "COMPLETED", "SUPPORTED", "REFUTED", "REPLACED", "PARTIAL", "INCONCLUSIVE",
    "FLAG_CANDIDATE", "STOP_REQUESTED", "TERMINAL", "START_FAILED",
    "SANDBOX_FAILED", "INPUT_UNAVAILABLE", "TIMED_OUT", "TERMINATED", "ERROR", "STALE",
})
NATIVE_BRANCH_TRANSITIONS = {
    "PLANNED": {"CAPACITY_ADMITTED", "START_FAILED", "SANDBOX_FAILED", "INPUT_UNAVAILABLE", "TERMINATED", "ERROR", "STALE"},
    "CAPACITY_ADMITTED": {"SANDBOX_READY", "AWAITING_NATIVE_START", "START_FAILED", "SANDBOX_FAILED", "INPUT_UNAVAILABLE", "TERMINATED", "ERROR", "STALE"},
    "SANDBOX_READY": {"AWAITING_NATIVE_START", "START_FAILED", "INPUT_UNAVAILABLE", "TERMINATED", "ERROR", "STALE"},
    "AWAITING_NATIVE_START": {"NATIVE_STARTED", "RUNNING", "START_FAILED", "TIMED_OUT", "TERMINATED", "ERROR", "STALE"},
    "NATIVE_STARTED": {"RUNNING", "STOP_REQUESTED", "TIMED_OUT", "TERMINATED", "ERROR"},
    "RUNNING": {"CHECKPOINTED", "FLAG_CANDIDATE", "STOP_REQUESTED", "TERMINAL", "COMPLETED", "SUPPORTED", "REFUTED", "PARTIAL", "INCONCLUSIVE", "TIMED_OUT", "TERMINATED", "ERROR", "STALE"},
    "CHECKPOINTED": {"RUNNING", "FLAG_CANDIDATE", "STOP_REQUESTED", "TERMINAL", "COMPLETED", "SUPPORTED", "REFUTED", "PARTIAL", "INCONCLUSIVE", "TIMED_OUT", "TERMINATED", "ERROR", "STALE"},
    "FLAG_CANDIDATE": {"RUNNING", "STOP_REQUESTED", "TERMINAL", "COMPLETED", "SUPPORTED", "REFUTED", "TERMINATED", "ERROR"},
    "STOP_REQUESTED": {"TERMINAL", "COMPLETED", "TERMINATED", "TIMED_OUT", "ERROR"},
}
ADMISSION_EXCEPTIONS = frozenset({
    "independent-verification", "clean-room-verifier", "clean-room-verification",
    "alternate-attack-family", "independent-full-solve", "parallel-race",
    "alternate-model-role", "alternate-implementation", "plateau-escape",
})
UTILITY_CLASSIFICATIONS = frozenset({
    "PROGRESSING", "NEEDS_SIBLING_INSIGHT", "BUMP_AND_RETRY",
    "REPLACE_ATTACK_FAMILY", "SOL_TAKEOVER", "FLAG_PATH", "DEAD_BRANCH",
    "INSUFFICIENT_DATA",
})
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")


class DelegationError(ValueError):
    """Raised for an unsafe or malformed delegation record."""


@dataclass(frozen=True)
class BranchCandidate:
    session_id: str
    role: str
    hypothesis_family: str
    hypothesis: str
    scope: tuple[str, ...]
    tool_strategy: tuple[str, ...]
    expected_artifacts: tuple[str, ...]

    @classmethod
    def create(
        cls, *, session_id: str, role: str, hypothesis_family: str, hypothesis: str,
        scope: Sequence[str], tool_strategy: Sequence[str], expected_artifacts: Sequence[str],
    ) -> "BranchCandidate":
        return cls(
            _identifier(session_id, "session_id"), _short(role, "role"),
            _short(hypothesis_family, "hypothesis_family"), _bounded(hypothesis, "hypothesis", 1000),
            tuple(_string_list(scope, "scope", maximum=32)),
            tuple(_string_list(tool_strategy, "tool_strategy", maximum=32)),
            tuple(_relative_names(expected_artifacts, "expected_artifacts", maximum=32)),
        )


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def plan_path(solve_root: Path) -> Path:
    return solve_root / "DELEGATION_PLAN.json"


def init_plan(
    solve_root: Path, *, challenge_id: str, input_fingerprint: str,
    parent_session_id: str, tier: int, tier_reason: str,
) -> dict[str, Any]:
    solve_root = ensure_run_mutable(solve_root)
    if not isinstance(tier, int) or tier not in range(0, 5):
        raise DelegationError("tier must be an integer from 0 through 4")
    now = utc_now()
    payload = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "challenge_id": _short(challenge_id, "challenge_id"),
        "input_fingerprint": _short(input_fingerprint, "input_fingerprint"),
        "parent_session_id": _identifier(parent_session_id, "parent_session_id"),
        "tier": tier, "tier_reason": _bounded(tier_reason, "tier_reason", 2000),
        "created_at": now, "updated_at": now, "branches": [],
        "admission_decisions": [],
    }
    with state_lock(solve_root):
        path = plan_path(solve_root)
        if path.is_symlink():
            raise DelegationError("delegation plan must not be a symlink")
        if path.exists():
            existing = _load_plan_unlocked(path)
            if existing["input_fingerprint"] == input_fingerprint:
                raise DelegationError("a current delegation plan already exists")
            _mark_stale(existing)
            stale_name = f"DELEGATION_PLAN.stale-{str(existing['input_fingerprint'])[:12]}.json"
            stale_path = solve_root / stale_name
            if stale_path.is_symlink():
                raise DelegationError("stale delegation archive must not be a symlink")
            atomic_json(stale_path, existing)
        atomic_json(path, payload)
    return payload


def load_plan(solve_root: Path, *, input_fingerprint: str | None = None) -> dict[str, Any]:
    with state_lock(solve_root):
        plan = _load_plan_unlocked(plan_path(solve_root))
        if input_fingerprint is not None and plan["input_fingerprint"] != input_fingerprint:
            _mark_stale(plan)
            atomic_json(plan_path(solve_root), plan)
            raise DelegationError("delegation plan is stale: input fingerprint changed")
        return plan


def admit_branch(
    plan: Mapping[str, Any], candidate: BranchCandidate, *, threshold: float = 0.95,
    purpose: str | None = None, race_override_reason: str | None = None,
) -> dict[str, Any]:
    if not isinstance(threshold, (int, float)) or not 0.0 <= float(threshold) <= 1.0:
        raise DelegationError("threshold must be between 0 and 1")
    normalized_purpose = purpose.strip().casefold() if isinstance(purpose, str) and purpose.strip() else None
    comparisons: list[dict[str, Any]] = []
    maximum = 0.0
    duplicate_session = False
    exact_duplicate = False
    for existing in plan.get("branches", []):
        if not isinstance(existing, Mapping) or existing.get("status") == "STALE":
            continue
        duplicate_session = duplicate_session or existing.get("session_id") == candidate.session_id
        exact_duplicate = exact_duplicate or _is_exact_duplicate(existing, candidate)
        score, components, reasons = _overlap(existing, candidate)
        maximum = max(maximum, score)
        comparisons.append({
            "session_id": existing.get("session_id"), "overlap_score": score,
            "components": components, "reasons": reasons,
        })
    comparisons.sort(key=lambda row: (-row["overlap_score"], str(row["session_id"])))
    exception = normalized_purpose in ADMISSION_EXCEPTIONS or candidate.role.casefold() in ADMISSION_EXCEPTIONS
    override = bool(race_override_reason and race_override_reason.strip())
    admitted = not duplicate_session and (not exact_duplicate or exception)
    if duplicate_session:
        reason = f"Duplicate branch session_id: {candidate.session_id}"
    elif exception and maximum >= float(threshold):
        reason = f"Overlap exception allowed for explicit purpose: {normalized_purpose or candidate.role}"
    elif exact_duplicate:
        reason = "Exact duplicate branch: hypothesis, scope, tools, artifact, and role are identical"
    elif override and maximum >= float(threshold):
        reason = f"Race-value override recorded: {race_override_reason.strip()}"
    elif comparisons:
        reason = "Admitted for parallel race; overlap is advisory unless every material dimension is identical"
    else:
        reason = "No existing active branch to overlap"
    return {
        "admitted": admitted, "novelty_score": round(1.0 - maximum, 4),
        "maximum_overlap_score": round(maximum, 4), "threshold": round(float(threshold), 4),
        "compared_with": comparisons, "reason": reason,
        "exception_purpose": normalized_purpose if exception else None,
        "exact_duplicate": exact_duplicate, "duplicate_session_id": duplicate_session,
        "race_override_reason": race_override_reason.strip() if override else None,
        "advisory_overlap": maximum >= float(threshold) and admitted,
    }


def record_admission(
    solve_root: Path, *, input_fingerprint: str, candidate: BranchCandidate,
    threshold: float = 0.95, purpose: str | None = None,
    race_override_reason: str | None = None,
) -> dict[str, Any]:
    solve_root = ensure_run_mutable(solve_root)
    with state_lock(solve_root):
        plan = _load_current_unlocked(solve_root, input_fingerprint)
        result = admit_branch(
            plan, candidate, threshold=threshold, purpose=purpose,
            race_override_reason=race_override_reason,
        )
        decisions = [
            item for item in plan.get("admission_decisions", [])
            if not (isinstance(item, Mapping) and item.get("session_id") == candidate.session_id)
        ]
        decisions.append({
            "session_id": candidate.session_id, "candidate": _candidate_dict(candidate),
            "purpose": purpose, "race_override_reason": race_override_reason,
            "evaluated_at": utc_now(), "result": result,
        })
        plan["admission_decisions"] = decisions
        plan["updated_at"] = utc_now()
        atomic_json(plan_path(solve_root), plan)
    return result


def add_branch(
    solve_root: Path, *, input_fingerprint: str, candidate: BranchCandidate,
    evidence_contract: Sequence[str], success_condition: str, kill_condition: str,
    maximum_steps: int, budget_seconds: int, requested_model_role: str,
    requested_reasoning: str, purpose: str | None = None,
    routing_contract: Mapping[str, Any] | None = None,
    routing_evidence_context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    solve_root = ensure_run_mutable(solve_root)
    if not isinstance(maximum_steps, int) or not 1 <= maximum_steps <= 10000:
        raise DelegationError("maximum_steps must be between 1 and 10000")
    if not isinstance(budget_seconds, int) or not 1 <= budget_seconds <= 86400:
        raise DelegationError("budget_seconds must be between 1 and 86400")
    with state_lock(solve_root):
        plan = _load_current_unlocked(solve_root, input_fingerprint)
        if any(item.get("session_id") == candidate.session_id for item in plan["branches"]):
            raise DelegationError(f"duplicate branch session_id: {candidate.session_id}")
        decision = next((
            item for item in reversed(plan.get("admission_decisions", []))
            if isinstance(item, Mapping) and item.get("session_id") == candidate.session_id
            and item.get("candidate") == _candidate_dict(candidate)
        ), None)
        # Recompute against the current branch set so a previously admitted
        # candidate cannot become a duplicate while Sol is opening another
        # native branch between admit and add.
        saved_result = decision.get("result") if isinstance(decision, Mapping) else None
        saved_threshold = saved_result.get("threshold", .95) if isinstance(saved_result, Mapping) else .95
        saved_purpose = decision.get("purpose") if isinstance(decision, Mapping) else purpose
        saved_override = decision.get("race_override_reason") if isinstance(decision, Mapping) else None
        admission = admit_branch(
            plan, candidate, threshold=float(saved_threshold), purpose=saved_purpose,
            race_override_reason=saved_override,
        )
        if not admission["admitted"]:
            raise DelegationError(f"branch admission denied: {admission['reason']}")
        routing = _validated_routing(
            plan, routing_contract, branch_evidence=(routing_evidence_context or {
                **_candidate_dict(candidate), "purpose": purpose,
            }),
        )
        now = utc_now()
        branch = {
            **_candidate_dict(candidate),
            "evidence_contract": _string_list(evidence_contract, "evidence_contract", maximum=32),
            "success_condition": _bounded(success_condition, "success_condition", 2000),
            "kill_condition": _bounded(kill_condition, "kill_condition", 2000),
            "maximum_steps": maximum_steps, "budget_seconds": budget_seconds,
            "requested_model_role": _short(requested_model_role, "requested_model_role"),
            "requested_reasoning": _short(
                routing.get("requested_reasoning", requested_reasoning), "requested_reasoning",
            ),
            **_routing_branch_defaults(routing),
            "observed_runtime_model": None, "observed_reasoning": None,
            "runtime_observation_status": None, "runtime_observation_evidence": None,
            "pinning_verified": False, "independent_verification": bool(
                purpose in {"independent-verification", "clean-room-verifier", "clean-room-verification"}
            ),
            "purpose": purpose, "admission": admission, "status": "ADMITTED",
            "created_at": now, "started_at": None, "finished_at": None,
        }
        plan["branches"].append(branch)
        plan["updated_at"] = now
        atomic_json(plan_path(solve_root), plan)
    return branch


def update_branch(
    solve_root: Path, *, input_fingerprint: str, session_id: str, status: str,
    observed_runtime_model: str | None = None, observed_reasoning: str | None = None,
    pinning_verified: bool | None = None, runtime_observation_evidence: str | None = None,
) -> dict[str, Any]:
    solve_root = ensure_run_mutable(solve_root)
    if status not in BRANCH_STATUSES:
        raise DelegationError(f"status must be one of {sorted(BRANCH_STATUSES)}")
    if observed_runtime_model is not None or observed_reasoning is not None:
        raise DelegationError(
            "observed runtime identity may be recorded only by branch-start-confirm with exact native evidence"
        )
    lineage_file = solve_root / "RACE_LINEAGE.jsonl"
    if lineage_file.is_file():
        result_path = solve_root / "workers" / session_id / "result.json"
        checkpoint_dir = solve_root / "workers" / session_id / "checkpoints"
        terminal_statuses = {
            "COMPLETED", "SUPPORTED", "REFUTED", "REPLACED", "PARTIAL", "INCONCLUSIVE",
            "FLAG_CANDIDATE", "TERMINAL", "START_FAILED", "SANDBOX_FAILED",
            "INPUT_UNAVAILABLE", "TIMED_OUT", "TERMINATED", "ERROR", "STALE",
        }
        if status in terminal_statuses and status != "START_FAILED" and (
            not result_path.is_file() and not any(checkpoint_dir.glob("*.json"))
        ):
            raise DelegationError("terminal branch requires result.json or a compact terminal checkpoint")
        if status == "RUNNING":
            raise DelegationError(
                "invalid native branch transition: PLANNED -> RUNNING; "
                "use branch-start-confirm with native start evidence"
            )
        if status == "START_FAILED":
            record_start_failure(
                solve_root, branch_id=session_id,
                receipt={"status": status, "session_id": session_id},
                reason=runtime_observation_evidence or "native start failed",
            )
        elif status in {"CHECKPOINTED", "STOP_REQUESTED"}:
            append_lineage_event(
                solve_root, event=status, branch_id=session_id,
                details={
                    "observed_runtime_model": observed_runtime_model,
                    "observed_reasoning": observed_reasoning,
                    "runtime_observation_evidence": runtime_observation_evidence,
                    "pinning_verified": pinning_verified,
                },
            )
        elif status in terminal_statuses:
            append_lineage_event(
                solve_root, event="CHILD_TERMINAL_RESULT_RECORDED", branch_id=session_id,
                details={
                    "result_status": status,
                    "result_path": str(result_path.relative_to(solve_root)) if result_path.is_file() else None,
                    "checkpoint_present": any(checkpoint_dir.glob("*.json")),
                },
            )
        else:
            raise DelegationError(f"lineage lifecycle status must use a dedicated receipt: {status}")
        projected = recover_lineage_projections(solve_root)
        return next(row for row in projected["branches"] if row["session_id"] == session_id)
    with state_lock(solve_root):
        plan = _load_current_unlocked(solve_root, input_fingerprint)
        matches = [item for item in plan["branches"] if item["session_id"] == session_id]
        if len(matches) != 1:
            raise DelegationError(f"unknown branch session_id: {session_id}")
        branch = matches[0]
        current_status = str(branch.get("status") or "")
        if branch.get("native_delegation_required") and status != current_status:
            allowed = NATIVE_BRANCH_TRANSITIONS.get(current_status, set())
            if status not in allowed:
                raise DelegationError(f"invalid native branch transition: {current_status} -> {status}")
        if status == "RUNNING" and branch.get("native_delegation_required") and not branch.get("start_receipt"):
            raise DelegationError("RUNNING requires a native start receipt; use branch-start-confirm")
        terminal_statuses = {"COMPLETED", "SUPPORTED", "REFUTED", "REPLACED", "PARTIAL", "INCONCLUSIVE", "FLAG_CANDIDATE", "TERMINAL", "START_FAILED", "SANDBOX_FAILED", "INPUT_UNAVAILABLE", "TIMED_OUT", "TERMINATED", "ERROR", "STALE"}
        if status in terminal_statuses and branch.get("native_delegation_required"):
            result_path = solve_root / "workers" / session_id / "result.json"
            checkpoint_dir = solve_root / "workers" / session_id / "checkpoints"
            if not result_path.is_file() and not any(checkpoint_dir.glob("*.json")):
                raise DelegationError("terminal branch requires result.json or a compact terminal checkpoint")
        branch["status"] = status
        now = utc_now()
        if status == "RUNNING" and branch["started_at"] is None:
            branch["started_at"] = now
        if status in terminal_statuses:
            branch["finished_at"] = now
        if observed_runtime_model is not None:
            branch["observed_runtime_model"] = _short(observed_runtime_model, "observed_runtime_model")
        if observed_reasoning is not None:
            branch["observed_reasoning"] = _short(observed_reasoning, "observed_reasoning")
        if runtime_observation_evidence is not None:
            branch["runtime_observation_evidence"] = _bounded(runtime_observation_evidence, "runtime_observation_evidence", 1000)
        if (observed_runtime_model is not None or observed_reasoning is not None) and not branch.get("runtime_observation_evidence"):
            raise DelegationError("observed runtime fields require explicit runtime observation evidence")
        if pinning_verified is not None:
            if pinning_verified and not (branch["observed_runtime_model"] and branch["observed_reasoning"] and branch.get("runtime_observation_evidence")):
                raise DelegationError("pinning_verified requires both observed runtime fields and explicit evidence")
            branch["pinning_verified"] = bool(pinning_verified)
        elif not (branch["observed_runtime_model"] and branch["observed_reasoning"]):
            branch["pinning_verified"] = False
        plan["updated_at"] = now
        atomic_json(plan_path(solve_root), plan)
    if status in terminal_statuses:
        from .transitions import evaluate_race_transition
        branch["race_transition"] = evaluate_race_transition(
            solve_root, {"type": "BRANCH_TERMINAL", "event_id": f"{session_id}:{status}:{now}"},
            session_id, input_fingerprint,
        )
    return branch


def prepare_branch_replacement(
    solve_root: Path, *, input_fingerprint: str, superseded_branch_id: str,
    candidate: BranchCandidate, kill_reason: str, distinct_mechanism_proof: str,
    evidence_contract: Sequence[str], success_condition: str, kill_condition: str,
    maximum_steps: int, budget_seconds: int, requested_model_role: str,
    requested_reasoning: str, triggering_receipt_id: str | None = None,
    routing_contract: Mapping[str, Any] | None = None,
    routing_evidence_context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Atomically admit/register a replacement and persist its prompt intent."""
    if not isinstance(maximum_steps, int) or not 1 <= maximum_steps <= 10000:
        raise DelegationError("maximum_steps must be between 1 and 10000")
    if not isinstance(budget_seconds, int) or not 1 <= budget_seconds <= 86400:
        raise DelegationError("budget_seconds must be between 1 and 86400")
    if not distinct_mechanism_proof.strip():
        raise DelegationError("replacement requires distinct mechanism proof")
    if (solve_root / "RACE_LINEAGE.jsonl").is_file():
        current = lineage_state(solve_root)
        old = next((row for row in current["branches"] if row.get("branch_id") == superseded_branch_id), None)
        if old is None:
            raise DelegationError("superseded branch does not exist")
        mode = SolveMode(str(old["mode"]))
        if mode is SolveMode.FIXED_RACE:
            raise DelegationError("fixed-race forbids replacement")
        if mode is SolveMode.SOL_ONLY:
            raise DelegationError("sol-only mode has no replaceable child lanes")
        replacements = [row for row in current["branches"] if row.get("supersedes_branch_id")]
        if replacements:
            raise DelegationError("adaptive-race permits at most one replacement")
        if str(old.get("hypothesis_family", "")).casefold() == candidate.hypothesis_family.casefold():
            raise DelegationError("replacement must use a genuinely different hypothesis family")
        trigger_kind = _validate_replacement_trigger(
            solve_root, branch_id=superseded_branch_id,
            triggering_receipt_id=triggering_receipt_id,
        )
        now = utc_now()
        routing = _validated_routing(
            {"branches": current["branches"]}, routing_contract,
            branch_evidence=(routing_evidence_context or {
                **_candidate_dict(candidate), "purpose": "alternate-attack-family",
            }),
        )
        request_id = hashlib.sha256(
            f"{superseded_branch_id}:{candidate.session_id}:{now}".encode()
        ).hexdigest()[:24]
        contract = {
            **_candidate_dict(candidate),
            "branch_id": candidate.session_id,
            "evidence_contract": _string_list(evidence_contract, "evidence_contract", maximum=32),
            "success_condition": _bounded(success_condition, "success_condition", 2000),
            "kill_condition": _bounded(kill_condition, "kill_condition", 2000),
            "maximum_steps": maximum_steps, "budget_seconds": budget_seconds,
            "requested_model_role": _short(requested_model_role, "requested_model_role"),
            "requested_reasoning": _short(
                routing.get("requested_reasoning", requested_reasoning), "requested_reasoning",
            ),
            **_routing_branch_defaults(routing),
            "purpose": "alternate-attack-family", "replacement_request_id": request_id,
            "supersedes_branch_id": superseded_branch_id,
            "kill_reason": _bounded(kill_reason, "kill_reason", 2000),
            "distinct_mechanism_proof": _bounded(
                distinct_mechanism_proof, "distinct_mechanism_proof", 2000,
            ),
            "expected_sandbox_identity": f"workers/{candidate.session_id}/sandbox.json",
        }
        prompt = {
            "session_id": candidate.session_id,
            "challenge_id": old.get("challenge_id"),
            "run_id": old.get("run_id"),
            "hypothesis_family": candidate.hypothesis_family,
            "hypothesis": candidate.hypothesis,
            "objective": "Run a distinct decisive exploit experiment; then minimal PoC and declared remote",
            "kill_reason": kill_reason,
            "distinct_mechanism_proof": distinct_mechanism_proof,
            **routing,
        }
        if routing:
            prompt["native_delegation_packet"] = build_native_delegation_packet(
                routing, task_name=candidate.session_id, child_prompt=prompt,
            )
        contract["prompt_packet"] = prompt
        event = append_lineage_event(
            solve_root, event="PLANNED", branch_id=candidate.session_id,
            session_id=candidate.session_id, race_id=str(old["race_id"]),
            generation=int(old["generation"]), lineage_id=str(old["lineage_id"]),
            parent_branch_id=str(old.get("parent_branch_id") or "sol-main"),
            supersedes_branch_id=superseded_branch_id,
            hypothesis_family=candidate.hypothesis_family, mode=mode,
            details={
                "branch_contract": contract, "replacement_request_id": request_id,
                "kill_reason": kill_reason,
                "distinct_mechanism_proof": distinct_mechanism_proof,
                "replacement_request_receipt": True,
                "triggering_receipt_id": triggering_receipt_id,
                "replacement_trigger_kind": trigger_kind,
            },
        )
        return {
            "replacement_request_id": request_id,
            "superseded_branch_id": superseded_branch_id,
            "new_session_id": candidate.session_id,
            "new_hypothesis_family": candidate.hypothesis_family,
            "kill_reason": kill_reason,
            "distinct_mechanism_proof": distinct_mechanism_proof,
            "triggering_receipt_id": triggering_receipt_id,
            "replacement_trigger_kind": trigger_kind,
            "lineage_event_id": event["lineage_event_id"],
            "status": "PLANNED", "native_delegation_required": True,
            **routing, "prompt_packet": prompt,
            "created_at": event["created_at"],
        }
    with state_lock(solve_root):
        plan = _load_current_unlocked(solve_root, input_fingerprint)
        old = next((row for row in plan["branches"] if row.get("session_id") == superseded_branch_id), None)
        if old is None:
            raise DelegationError("superseded branch does not exist")
        if str(old.get("hypothesis_family", "")).casefold() == candidate.hypothesis_family.casefold():
            raise DelegationError("replacement must use a genuinely different hypothesis family")
        admission = admit_branch(plan, candidate, purpose="alternate-attack-family")
        if not admission["admitted"]:
            raise DelegationError(f"replacement admission denied: {admission['reason']}")
        now = utc_now()
        routing = _validated_routing(
            plan, routing_contract, branch_evidence=(routing_evidence_context or {
                **_candidate_dict(candidate), "purpose": "alternate-attack-family",
            }),
        )
        request_id = hashlib.sha256(f"{superseded_branch_id}:{candidate.session_id}:{now}".encode()).hexdigest()[:24]
        prompt = {
            "session_id": candidate.session_id, "parent_session_id": plan["parent_session_id"],
            "challenge_id": plan["challenge_id"], "input_fingerprint": input_fingerprint,
            "hypothesis_family": candidate.hypothesis_family, "hypothesis": candidate.hypothesis,
            "objective": "Run a distinct decisive exploit experiment; then minimal PoC and declared remote",
            "kill_reason": kill_reason, "distinct_mechanism_proof": distinct_mechanism_proof,
        }
        if routing:
            prompt["native_delegation_packet"] = build_native_delegation_packet(
                routing, task_name=candidate.session_id, child_prompt=prompt,
            )
        branch = {
            **_candidate_dict(candidate), "evidence_contract": _string_list(evidence_contract, "evidence_contract", maximum=32),
            "success_condition": _bounded(success_condition, "success_condition", 2000),
            "kill_condition": _bounded(kill_condition, "kill_condition", 2000),
            "maximum_steps": maximum_steps, "budget_seconds": budget_seconds,
            "requested_model_role": _short(requested_model_role, "requested_model_role"),
            "requested_reasoning": _short(
                routing.get("requested_reasoning", requested_reasoning), "requested_reasoning",
            ),
            **_routing_branch_defaults(routing),
            "observed_runtime_model": None, "observed_reasoning": None,
            "runtime_observation_status": None, "runtime_observation_evidence": None,
            "pinning_verified": False,
            "independent_verification": False, "purpose": "alternate-attack-family",
            "admission": admission, "status": "AWAITING_NATIVE_START",
            "created_at": now, "started_at": None, "finished_at": None,
            "replacement_request_id": request_id, "superseded_branch_id": superseded_branch_id,
            "kill_reason": _bounded(kill_reason, "kill_reason", 2000),
            "distinct_mechanism_proof": _bounded(distinct_mechanism_proof, "distinct_mechanism_proof", 2000),
            "prompt_packet": prompt, "native_delegation_required": True,
            "expected_start_receipt": True,
            "expected_sandbox_identity": f"workers/{candidate.session_id}/sandbox.json",
            "start_receipt": None,
        }
        old["status"] = "REPLACED"; old["replacement_request_id"] = request_id; old["finished_at"] = now
        plan["branches"].append(branch)
        record = {
            "replacement_request_id": request_id, "superseded_branch_id": superseded_branch_id,
            "kill_reason": kill_reason, "new_session_id": candidate.session_id,
            "new_hypothesis_family": candidate.hypothesis_family,
            "distinct_mechanism_proof": distinct_mechanism_proof, "admission_decision": admission,
            "branch_registration": True, "prompt_packet": prompt,
            "native_delegation_required": True, "expected_start_receipt": True,
            "expected_sandbox_identity": branch["expected_sandbox_identity"], "created_at": now,
        }
        plan.setdefault("admission_decisions", []).append({
            "session_id": candidate.session_id, "candidate": _candidate_dict(candidate),
            "purpose": "alternate-attack-family", "race_override_reason": None,
            "evaluated_at": now, "result": admission, "replacement_request_id": request_id,
        })
        plan.setdefault("replacement_requests", []).append(record)
        plan["updated_at"] = now
        atomic_json(plan_path(solve_root), plan)
    return record


def _validate_replacement_trigger(
    solve_root: Path, *, branch_id: str, triggering_receipt_id: str | None,
) -> str:
    receipt_id = str(triggering_receipt_id or "").strip()
    if not receipt_id:
        raise DelegationError("adaptive replacement requires an exact plateau/refutation receipt ID")
    milestones = read_jsonl_strict(
        solve_root / "milestone-receipts.jsonl", "milestone receipt ledger",
    )
    refutation = next((
        row for row in milestones
        if row.get("receipt_id") == receipt_id
        and row.get("event_type") == "PRIMITIVE_REFUTED"
        and row.get("session_id") == branch_id
    ), None)
    if refutation is not None:
        return "REFUTATION"
    transitions = read_jsonl_strict(
        solve_root / "RACE_TRANSITIONS.jsonl", "race transition ledger",
    )
    plateau = next((
        row for row in transitions
        if receipt_id in {str(row.get("transition_id") or ""), str(row.get("event_id") or "")}
        and (
            row.get("session_id") == branch_id
            or any(
                isinstance(item, Mapping) and item.get("session_id") == branch_id
                for item in row.get("replacement_requests", []) or []
            )
        )
    ), None)
    if plateau is not None:
        return "PLATEAU"
    actions = read_jsonl_strict(solve_root / "control-actions.jsonl", "control action ledger")
    action = next((
        row for row in actions
        if row.get("action_id") == receipt_id
        and row.get("action_type") == "REPLACE_ATTACK_FAMILY"
        and row.get("session_id") == branch_id
    ), None)
    if action is not None:
        return "PLATEAU"
    raise DelegationError("replacement trigger is not an authoritative plateau/refutation receipt")


def confirm_branch_start(
    solve_root: Path, *, input_fingerprint: str, replacement_request_id: str,
    session_id: str, native_session_observed: str, runtime_observation_evidence: str,
    sandbox_metadata_path: str, native_start_operation_id: str | None = None,
    observed_model: str | None = None, observed_reasoning: str | None = None,
    runtime_observation_status: str | None = None,
) -> dict[str, Any]:
    solve_root = ensure_run_mutable(solve_root)
    if not all(str(value).strip() for value in (native_session_observed, runtime_observation_evidence, sandbox_metadata_path)):
        raise DelegationError("branch start confirmation requires native, runtime, and sandbox evidence")
    lineage_enabled = (solve_root / "RACE_LINEAGE.jsonl").is_file()
    with state_lock(solve_root):
        plan = _load_current_unlocked(solve_root, input_fingerprint)
        branch = next((
            row for row in plan["branches"]
            if row.get("session_id") == session_id
            and (
                row.get("replacement_request_id") == replacement_request_id
                or (not row.get("replacement_request_id") and replacement_request_id in {"", "initial-race"})
            )
        ), None)
        if branch is None:
            raise DelegationError("replacement request and session do not match")
        routed = branch.get("routing_profile") in ROUTING_PROFILES
        operation_id = str(native_start_operation_id or "").strip() or None
        inferred_status = runtime_observation_status or (
            "OBSERVED" if observed_model is not None or observed_reasoning is not None
            else "NOT_OBSERVABLE"
        )
        if routed and operation_id is None and inferred_status == "OBSERVED":
            raise DelegationError("observed routed native start requires native_start_operation_id")
        contract = (
            {key: branch.get(key) for key in (
                "routing_profile", "requested_model_class", "requested_model",
                "requested_reasoning", "routing_reason", "routing_evidence",
                "fallback_profile", "fallback_reason", "max_lease",
            ) if key in branch}
            if routed else None
        )
        try:
            routing_result = compare_runtime_routing(
                contract, observed_model=observed_model,
                observed_reasoning=observed_reasoning,
                runtime_observation_status=inferred_status,
                runtime_observation_evidence=runtime_observation_evidence,
            )
        except RoutingError as exc:
            raise DelegationError(str(exc)) from exc
        if branch.get("start_receipt"):
            saved = branch["start_receipt"]
            if (
                saved.get("native_session_observed") == native_session_observed
                and saved.get("runtime_observation_evidence") == runtime_observation_evidence
                and saved.get("native_start_operation_id") == operation_id
                and saved.get("observed_model") == observed_model
                and saved.get("observed_reasoning") == observed_reasoning
                and saved.get("runtime_observation_status") == inferred_status
            ):
                return {**saved, "idempotent": True}
            raise DelegationError("branch already has a conflicting native start receipt")
        if branch.get("status") not in {"AWAITING_NATIVE_START", "SANDBOX_READY"}:
            raise DelegationError("native start requires a sandbox-ready awaiting branch")
        if branch.get("input_available") is False:
            raise DelegationError("native start requires available challenge input")
        expected = solve_root / str(branch.get("expected_sandbox_identity"))
        supplied = Path(sandbox_metadata_path)
        if not supplied.is_absolute(): supplied = solve_root / supplied
        if supplied.resolve() != expected.resolve():
            raise DelegationError("sandbox metadata path does not match expected sandbox identity")
        if supplied.is_symlink() or not supplied.is_file():
            raise DelegationError("sandbox metadata path is missing or unsafe")
        for other in plan.get("branches", []):
            saved = other.get("start_receipt") or other.get("native_start_receipt")
            if not isinstance(saved, Mapping):
                continue
            if operation_id and saved.get("native_start_operation_id") == operation_id:
                raise DelegationError(
                    "native start operation ID conflicts with another run/session runtime identity"
                )
            if (
                other.get("session_id") != session_id
                and saved.get("native_session_observed") == native_session_observed
            ):
                raise DelegationError("one observed native session cannot start multiple branches")
        receipt = {
            "schema_version": 2,
            "replacement_request_id": replacement_request_id, "session_id": session_id,
            "run_id": plan.get("run_id"), "challenge_id": plan.get("challenge_id"),
            "attempt_id": plan.get("attempt_id"),
            "parent_session_id": plan.get("parent_session_id"),
            "input_fingerprint": plan.get("input_fingerprint"),
            "target_revision": plan.get("target_revision"),
            "native_start_operation_id": operation_id,
            "native_session_observed": native_session_observed,
            **routing_result,
            "sandbox_metadata_path": str(supplied), "started_at": utc_now(),
        }
        receipt["receipt_id"] = hashlib.sha256(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()[:24]
        validate_native_start_receipt_binding(
            receipt, run_id=plan.get("run_id"), challenge_id=plan.get("challenge_id"),
            attempt_id=plan.get("attempt_id"),
            parent_session_id=plan.get("parent_session_id"),
            input_fingerprint=plan.get("input_fingerprint"),
            target_revision=plan.get("target_revision"), session_id=session_id,
        )
        if lineage_enabled:
            pass
        else:
            branch["start_receipt"] = receipt
        if not lineage_enabled:
            branch.setdefault("lifecycle_history", []).extend([
                {"status": "NATIVE_STARTED", "created_at": receipt["started_at"], "receipt": receipt},
                {"status": "RUNNING", "created_at": receipt["started_at"]},
            ])
            branch["status"] = "RUNNING"; branch["started_at"] = receipt["started_at"]
            branch["observed_runtime_model"] = receipt.get("observed_model")
            branch["observed_reasoning"] = receipt.get("observed_reasoning")
            branch["runtime_observation_status"] = receipt.get("runtime_observation_status")
            branch["runtime_observation_evidence"] = receipt.get("runtime_observation_evidence")
            branch["routing_classification"] = receipt.get("routing_classification")
            branch["model_routing_matched"] = receipt.get("model_routing_matched", False)
            branch["reasoning_routing_matched"] = receipt.get("reasoning_routing_matched", False)
            branch["routing_matched"] = receipt.get("routing_matched", False)
            branch["fallback_used"] = receipt.get("fallback_used", False)
            branch["fallback_reason_observed"] = receipt.get("fallback_reason")
            branch["pinning_verified"] = receipt.get("routing_classification") == "ROUTING_MATCHED"
            plan.setdefault("branch_start_receipts", []).append(receipt)
            plan["updated_at"] = utc_now(); atomic_json(plan_path(solve_root), plan)
    if lineage_enabled:
        append_lineage_event(
            solve_root, event="NATIVE_STARTED", branch_id=session_id,
            referenced_receipt=receipt, details=receipt, operation_id=operation_id,
            project=False,
        )
        append_lineage_event(
            solve_root, event="RUNNING", branch_id=session_id,
            referenced_receipt={"native_start_receipt_id": hashlib.sha256(
                json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()},
            details={"native_start_receipt": receipt},
        )
    return receipt


def validate_native_start_receipt_binding(
    receipt: Mapping[str, Any], *, run_id: str | None, challenge_id: str | None,
    input_fingerprint: str | None, target_revision: int | None, session_id: str,
    attempt_id: str | None = None, parent_session_id: str | None = None,
) -> None:
    """Reject reuse of a native start receipt across run, attempt, or branch identity."""

    expected = {
        "run_id": run_id, "challenge_id": challenge_id,
        "input_fingerprint": input_fingerprint,
        "target_revision": target_revision, "session_id": session_id,
    }
    for field, value in expected.items():
        if receipt.get(field) != value:
            raise DelegationError(f"native start receipt {field} belongs to another run/session")
    for field, value in {
        "attempt_id": attempt_id, "parent_session_id": parent_session_id,
    }.items():
        if value is not None and receipt.get(field) != value:
            raise DelegationError(f"native start receipt {field} belongs to another run/session")
    if receipt.get("schema_version") not in {None, 1, 2}:
        raise DelegationError("native start receipt schema version is unsupported")


def record_capacity_admission(
    solve_root: Path, *, input_fingerprint: str, admitted_session_ids: Sequence[str],
) -> dict[str, Any]:
    """Project scheduler admission without claiming a native child exists."""

    solve_root = ensure_run_mutable(solve_root)
    admitted = set(admitted_session_ids)
    if (solve_root / "RACE_LINEAGE.jsonl").is_file():
        changed = []
        current = lineage_state(solve_root)
        for branch in current["current_branches"]:
            if branch["session_id"] in admitted and branch["status"] == "PLANNED":
                append_lineage_event(
                    solve_root, event="CAPACITY_ADMITTED", branch_id=str(branch["branch_id"]),
                    details={"resource_allocation_receipt": True},
                )
                changed.append(str(branch["session_id"]))
        return {"capacity_admitted": sorted(changed), "native_children_started": False}
    with state_lock(solve_root):
        plan = _load_current_unlocked(solve_root, input_fingerprint)
        changed = []
        for branch in plan.get("branches", []):
            if branch.get("session_id") in admitted and branch.get("status") == "PLANNED":
                branch["status"] = "CAPACITY_ADMITTED"
                stamp = utc_now()
                branch["capacity_admitted_at"] = stamp
                branch.setdefault("lifecycle_history", []).append({"status": "CAPACITY_ADMITTED", "created_at": stamp})
                changed.append(str(branch["session_id"]))
        plan["updated_at"] = utc_now()
        atomic_json(plan_path(solve_root), plan)
    return {"capacity_admitted": sorted(changed), "native_children_started": False}


def record_branch_sandbox_ready(
    solve_root: Path, *, input_fingerprint: str, session_id: str,
    sandbox_metadata_path: str, input_available: bool,
) -> dict[str, Any]:
    """Record branch-private input/sandbox readiness before native start."""

    solve_root = ensure_run_mutable(solve_root)
    lineage_enabled = (solve_root / "RACE_LINEAGE.jsonl").is_file()
    with state_lock(solve_root):
        plan = _load_current_unlocked(solve_root, input_fingerprint)
        branch = next((row for row in plan.get("branches", []) if row.get("session_id") == session_id), None)
        if branch is None:
            raise DelegationError("sandbox branch does not exist in the current plan")
        if branch.get("status") not in {"CAPACITY_ADMITTED", "SANDBOX_READY", "AWAITING_NATIVE_START"}:
            raise DelegationError("sandbox can be readied only after capacity admission")
        supplied = Path(sandbox_metadata_path)
        if not supplied.is_absolute():
            supplied = solve_root / supplied
        expected = solve_root / str(branch.get("expected_sandbox_identity"))
        if supplied.resolve() != expected.resolve():
            raise DelegationError("sandbox metadata path does not match expected sandbox identity")
        if input_available and (supplied.is_symlink() or not supplied.is_file()):
            raise DelegationError("sandbox metadata path is missing or unsafe")
        prepared_input = challenge_workspace(solve_root) / "input"
        if input_available and (prepared_input.is_symlink() or not prepared_input.is_dir()):
            raise DelegationError("current challenge input is unavailable or unsafe")
        stamp = utc_now()
        receipt = {
            "session_id": session_id, "sandbox_metadata_path": str(supplied),
            "input_available": bool(input_available), "created_at": stamp,
        }
        if lineage_enabled:
            pass
        elif not input_available:
            branch["status"] = "INPUT_UNAVAILABLE"
            branch["finished_at"] = stamp
        else:
            branch["sandbox_ready_receipt"] = receipt
            branch["input_available"] = True
            branch.setdefault("lifecycle_history", []).extend([
                {"status": "SANDBOX_READY", "created_at": stamp, "receipt": receipt},
                {"status": "AWAITING_NATIVE_START", "created_at": stamp},
            ])
            branch["status"] = "AWAITING_NATIVE_START"
        if not lineage_enabled:
            plan["updated_at"] = stamp
            atomic_json(plan_path(solve_root), plan)
    if lineage_enabled:
        if not input_available:
            record_start_failure(
                solve_root, branch_id=session_id, receipt=receipt,
                reason="challenge input unavailable",
            )
        else:
            metadata_digest = hashlib.sha256(supplied.read_bytes()).hexdigest()
            append_lineage_event(
                solve_root, event="SANDBOX_READY", branch_id=session_id,
                referenced_receipt=receipt,
                details={**receipt, "sandbox_metadata_digest": metadata_digest},
                project=False,
            )
            append_lineage_event(
                solve_root, event="AWAITING_NATIVE_START", branch_id=session_id,
                referenced_receipt={"sandbox_metadata_digest": metadata_digest},
                details={"sandbox_metadata_digest": metadata_digest},
            )
    return receipt


def load_templates(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise DelegationError(f"delegation template resource is missing or unsafe: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise DelegationError("delegation template YAML is malformed") from exc
    required = {"pwn", "web", "rev", "crypto", "forensic", "misc", "osint", "cloud", "ai"}
    if not isinstance(raw, Mapping) or not required.issubset(raw):
        raise DelegationError("delegation templates must contain every required category")
    result: dict[str, Any] = {}
    for category, tiers in raw.items():
        if not isinstance(category, str) or not isinstance(tiers, Mapping):
            raise DelegationError("template category entries must be mappings")
        normalized_tiers: dict[str, Any] = {}
        for tier in range(1, 5):
            key = f"tier_{tier}"
            rows = tiers.get(key)
            if not isinstance(rows, list) or not rows:
                raise DelegationError(f"template {category}.{key} must be a non-empty array")
            normalized = []
            for row in rows:
                if not isinstance(row, Mapping) or set(row) != {"role", "hypothesis_family"}:
                    raise DelegationError(f"template {category}.{key} rows require role and hypothesis_family")
                normalized.append({"role": _short(row["role"], "role"), "hypothesis_family": _short(row["hypothesis_family"], "hypothesis_family")})
            normalized_tiers[key] = normalized
        result[category] = normalized_tiers
    return result


def template_recommendation(path: Path, *, category: str, tier: int) -> dict[str, Any]:
    if tier not in range(1, 5):
        raise DelegationError("template tier must be from 1 through 4")
    templates = load_templates(path)
    normalized = playbook_category(category)
    selected = normalized if normalized in templates else "misc"
    return {
        "original_category": category, "template_category": selected, "fallback_used": selected != category,
        "tier": tier, "branches": templates[selected][f"tier_{tier}"],
        "advisory_only": True, "branches_created": False,
    }


def branch_utility(
    plan: Mapping[str, Any], *, session_id: str, checkpoints: Sequence[Mapping[str, Any]],
    result: Mapping[str, Any] | None, now: datetime | None = None,
) -> dict[str, Any]:
    branches = [item for item in plan.get("branches", []) if item.get("session_id") == session_id]
    if len(branches) != 1:
        raise DelegationError(f"unknown branch session_id: {session_id}")
    branch = branches[0]
    routing_interpretation = branch_routing_interpretation(branch)
    relevant = [item for item in checkpoints if item.get("session_id") == session_id]
    if not relevant and result is None:
        return {
            "session_id": session_id, "utility_score": None,
            "classification": "INSUFFICIENT_DATA",
            "recommendation": "Collect a bounded checkpoint or worker result before judging utility",
            "metrics": {}, "routing_interpretation": routing_interpretation,
        }
    counts = {name: 0 for name in (
        "supported_facts", "exploit_relevant_facts", "useful_artifacts",
        "documentation_artifacts", "primitive_candidates", "exploit_primitives", "refuted_primitives", "flag_candidates",
        "rejected_hypotheses", "repeated_failures", "policy_violations",
        "repeated_commands", "tool_failures", "sibling_insights", "family_changes",
        "decisive_experiment_count", "failed_decisive_experiments",
    )}
    proximity = 0.0
    last_increase_index: int | None = None
    for index, item in enumerate(relevant):
        kind = str(item.get("type") or "").upper()
        item_proximity = _checkpoint_proximity(item)
        if item_proximity > proximity:
            proximity = item_proximity
            last_increase_index = index
        decisive = bool(str(item.get("decisive_experiment_performed") or "").strip()) or kind in {
            "EXPLOIT_PRIMITIVE", "EXPLOIT_PRIMITIVE_CANDIDATE", "EXPLOIT_PRIMITIVE_CONFIRMED",
            "EXPLOIT_PRIMITIVE_REFUTED", "WORKING_POC", "FLAG_CANDIDATE", "REMOTE_FLAG_OBTAINED",
        }
        if decisive:
            counts["decisive_experiment_count"] += 1
        if str(item.get("decision") or "").upper() == "KILL" or item.get("failed_decisive_experiment") is True:
            counts["failed_decisive_experiments"] += 1
        if kind == "SUPPORTED_FACT":
            counts["supported_facts"] += 1
            if item.get("exploit_relevant") is True or item_proximity > 0:
                counts["exploit_relevant_facts"] += 1
        if kind == "ARTIFACT_READY":
            if item.get("working_poc_present") or item.get("remote_ready") or item.get("exploit_relevant"):
                counts["useful_artifacts"] += max(1, len(item.get("artifacts", [])))
            else:
                counts["documentation_artifacts"] += max(1, len(item.get("artifacts", [])))
        if kind == "WORKING_POC":
            counts["useful_artifacts"] += max(1, len(item.get("artifacts", [])))
        if kind in {"EXPLOIT_PRIMITIVE", "EXPLOIT_PRIMITIVE_CANDIDATE"}: counts["primitive_candidates"] += 1
        if kind == "EXPLOIT_PRIMITIVE_CONFIRMED": counts["exploit_primitives"] += 1
        if kind == "EXPLOIT_PRIMITIVE_REFUTED": counts["refuted_primitives"] += 1
        if kind in {"FLAG_CANDIDATE", "REMOTE_FLAG_OBTAINED"}: counts["flag_candidates"] += 1
        if kind == "REJECTED_HYPOTHESIS": counts["rejected_hypotheses"] += 1
        if kind == "BLOCKER": counts["repeated_failures"] += 1
        if kind == "ENVIRONMENT_DISCOVERY" and item.get("recommended_action") == "TOOL_FAILURE": counts["tool_failures"] += 1
        if item.get("sibling_insight_applied"): counts["sibling_insights"] += 1
        if item.get("hypothesis_family_changed"): counts["family_changes"] += 1
        counts["repeated_commands"] += int(item.get("repeated_command", False))
    if result:
        result_poc = bool(result.get("working_poc_present"))
        result_remote = bool(result.get("remote_ready"))
        if result_poc or result_remote:
            counts["useful_artifacts"] += len(result.get("artifacts", []))
        else:
            counts["documentation_artifacts"] += len(result.get("artifacts", []))
        counts["flag_candidates"] += len(result.get("flag_candidates", []))
        counts["rejected_hypotheses"] += sum(1 for h in result.get("hypotheses", []) if h.get("status") == "REFUTED")
        counts["policy_violations"] += len(result.get("policy_violations", []))
        if result.get("status") == "ERROR": counts["repeated_failures"] += 1
        if result_poc: proximity = max(proximity, .82)
        if result_remote: proximity = max(proximity, .92)
        if result.get("flag_candidates"): proximity = 1.0
    if counts["refuted_primitives"] and not any(
        str(item.get("type") or "").upper() == "EXPLOIT_PRIMITIVE_CONFIRMED"
        for item in relevant[max(index for index, item in enumerate(relevant) if str(item.get("type") or "").upper() == "EXPLOIT_PRIMITIVE_REFUTED") + 1:]
    ):
        proximity = 0.0
    overlap = float(branch.get("admission", {}).get("maximum_overlap_score", 0.0))
    elapsed_ratio = _elapsed_ratio(branch, now or datetime.now(timezone.utc))
    information_events = sum(
        str(item.get("type") or "").upper() in {
            "SUPPORTED_FACT", "REJECTED_HYPOTHESIS", "EXPLOIT_PRIMITIVE", "EXPLOIT_PRIMITIVE_CANDIDATE",
            "EXPLOIT_PRIMITIVE_CONFIRMED", "EXPLOIT_PRIMITIVE_REFUTED",
            "ARTIFACT_READY", "WORKING_POC", "FLAG_CANDIDATE", "REMOTE_FLAG_OBTAINED",
        }
        for item in relevant
    ) + int(bool(result and (
        result.get("artifacts") or result.get("flag_candidates")
        or any(h.get("status") in {"SUPPORTED", "REFUTED"} for h in result.get("hypotheses", []))
    )))
    rate = _new_information_rate(relevant, result, information_events)
    observations = max(1, len(relevant) + (1 if result else 0))
    recent = relevant[-8:]
    blocker_summaries = Counter(
        str(item.get("summary", "")).strip().casefold()
        for item in recent if item.get("type") == "BLOCKER" and str(item.get("summary", "")).strip()
    )
    same_error_repeats = max(blocker_summaries.values(), default=0)
    repeat_ratio = round(counts["repeated_commands"] / observations, 4)
    tool_failure_ratio = round(counts["tool_failures"] / observations, 4)
    steps_since_increase = len(relevant) if last_increase_index is None else len(relevant) - last_increase_index - 1
    working_poc = any(
        item.get("type") == "WORKING_POC" or item.get("working_poc_present") is True for item in relevant
    ) or bool(result and result.get("working_poc_present"))
    remote_ready = any(
        item.get("type") == "REMOTE_FLAG_OBTAINED" or item.get("remote_ready") is True for item in relevant
    ) or bool(result and result.get("remote_ready"))
    drift_reasons = _research_drift_reasons(relevant, last_increase_index, proximity)
    research_drift = bool(drift_reasons)
    score = round(
        100.0 * counts["flag_candidates"] + 60.0 * working_poc + 70.0 * remote_ready
        + 30.0 * counts["exploit_primitives"] + 4.0 * counts["primitive_candidates"] + 40.0 * proximity
        + 3.0 * counts["decisive_experiment_count"] + 2.0 * counts["exploit_relevant_facts"]
        - 8.0 * counts["failed_decisive_experiments"] - 4.0 * counts["repeated_failures"]
        - 3.0 * counts["repeated_commands"] - 3.0 * counts["tool_failures"]
        - 2.0 * counts["supported_facts"]
        - 3.0 * counts["documentation_artifacts"] - 30.0 * research_drift
        - 2.0 * overlap - 1.5 * elapsed_ratio - 20.0 * counts["policy_violations"], 3,
    )
    if counts["flag_candidates"] or remote_ready or working_poc:
        classification, recommendation = "FLAG_PATH", "Run the minimal exploit or solver against the declared remote now and surface the flag"
    elif counts["primitive_candidates"] and not counts["exploit_primitives"] and not research_drift:
        classification, recommendation = "BUMP_AND_RETRY", "Run the stated positive/negative control once to confirm or refute the primitive candidate"
    elif counts["policy_violations"]:
        classification, recommendation = "DEAD_BRANCH", "Stop the out-of-scope branch and reuse its slot"
    elif counts["exploit_primitives"] and (research_drift or elapsed_ratio >= 1.0 or steps_since_increase > 2):
        classification, recommendation = "SOL_TAKEOVER", "Sol should take over the proven primitive and finish the minimal PoC"
    elif research_drift:
        classification, recommendation = "REPLACE_ATTACK_FAMILY", "Replace research drift with a distinct executable exploit mechanism"
    elif (same_error_repeats >= 2 or counts["repeated_failures"] >= 3) and counts["sibling_insights"]:
        classification, recommendation = "REPLACE_ATTACK_FAMILY", "Sibling insight did not change the repeated failure; replace the attack family"
    elif counts["failed_decisive_experiments"] >= 2 or (counts["decisive_experiment_count"] >= 3 and proximity == 0):
        classification, recommendation = "REPLACE_ATTACK_FAMILY", "The family failed decisive experiments without improving exploit proximity"
    elif counts["repeated_failures"] >= 2 and not counts["sibling_insights"]:
        classification, recommendation = "NEEDS_SIBLING_INSIGHT", "Request only sibling evidence that directly resolves the current blocker"
    elif counts["decisive_experiment_count"] == 0:
        classification, recommendation = "INSUFFICIENT_DATA", "Run the cheapest decisive experiment before judging progress"
    elif proximity >= .45 and (elapsed_ratio >= 1.0 or steps_since_increase > 2):
        classification, recommendation = "SOL_TAKEOVER", "Sol should convert the promising primitive into the minimal PoC"
    elif proximity > 0 and steps_since_increase <= 2:
        classification, recommendation = "PROGRESSING", "Run the next one to three exploit-completing experiments"
    elif counts["failed_decisive_experiments"] == 1 or elapsed_ratio >= 1.0 or repeat_ratio >= .6 or tool_failure_ratio >= .6:
        classification, recommendation = "BUMP_AND_RETRY", "Retry this objective once with a different decisive experiment"
    else:
        classification, recommendation = "BUMP_AND_RETRY", "Change the decisive experiment once; do not broaden into research"
    metrics = {
        **counts, "elapsed_budget_ratio": round(elapsed_ratio, 4),
        "elapsed_seconds": round(elapsed_ratio * int(branch.get("budget_seconds", 0)), 3),
        "overlap_score": round(overlap, 4), "new_information_rate": rate,
        "repeated_command_ratio": repeat_ratio, "tool_failure_ratio": tool_failure_ratio,
        "artifact_changed": bool(counts["useful_artifacts"]),
        "hypothesis_family_changed": bool(counts["family_changes"]),
        "sibling_insight_applied": bool(counts["sibling_insights"]),
        "exploit_proximity": round(proximity, 4), "flag_proximity": round(proximity, 4),
        "time_or_steps_since_proximity_increase": steps_since_increase,
        "working_poc_present": working_poc, "remote_ready": remote_ready,
        "research_drift_detected": research_drift, "research_drift_reasons": drift_reasons,
        "recent_window_size": len(recent),
        "recent_supported_facts": sum(item.get("type") == "SUPPORTED_FACT" for item in recent),
        "same_error_repeat_count": same_error_repeats,
    }
    return {
        "session_id": session_id, "utility_score": score,
        "classification": classification, "recommendation": recommendation,
        "metrics": metrics, "routing_interpretation": routing_interpretation,
    }


def _checkpoint_proximity(item: Mapping[str, Any]) -> float:
    explicit = item.get("exploit_proximity")
    explicit_value = (
        float(explicit)
        if isinstance(explicit, (int, float)) and not isinstance(explicit, bool) and 0 <= float(explicit) <= 1
        else 0.0
    )
    kind = str(item.get("type") or "").upper()
    if kind in {"FLAG_CANDIDATE", "REMOTE_FLAG_OBTAINED"}: return 1.0
    if item.get("remote_ready") is True: return max(explicit_value, .92)
    if kind == "WORKING_POC" or item.get("working_poc_present") is True: return max(explicit_value, .82)
    if kind in {"EXPLOIT_PRIMITIVE", "EXPLOIT_PRIMITIVE_CANDIDATE"}:
        # Legacy primitive rows are deliberately candidate-grade.  Summary
        # wording and an optimistic explicit score cannot confirm a primitive.
        return min(max(explicit_value, .2), .35)
    if kind == "EXPLOIT_PRIMITIVE_CONFIRMED":
        summary = str(item.get("summary") or "").casefold()
        if any(term in summary for term in ("code execution", "rce", "shell", "arbitrary write")): return max(explicit_value, .72)
        if any(term in summary for term in ("arbitrary read", "address leak", "data leak", "auth bypass", "logic bypass")): return max(explicit_value, .62)
        if any(term in summary for term in ("input control", "crash", "oracle", "rip control", "pc control")): return max(explicit_value, .52)
        return max(explicit_value, .5)
    if kind == "EXPLOIT_PRIMITIVE_REFUTED":
        return 0.0
    if kind == "SERVICE_CRASHED" and str(item.get("decisive_experiment_performed") or "").strip():
        return max(explicit_value, .52)
    if item.get("remote_interaction_proved_primitive") is True:
        return max(explicit_value, .65)
    if item.get("constraint_reduction") or item.get("deterministic_extraction_progress"):
        return max(explicit_value, .35)
    return explicit_value


def _research_drift_reasons(
    checkpoints: Sequence[Mapping[str, Any]], last_increase_index: int | None, proximity: float,
) -> list[str]:
    reasons: list[str] = []
    if any(item.get("research_drift_detected") is True for item in checkpoints):
        reasons.append("explicit research-drift checkpoint")
    drift_terms = (
        "comprehensive", "full source review", "entire attack surface", "enumerate all",
        "architecture document", "refactor", "framework", "reusable library", "understand everything",
        "more understanding", "broad recon",
    )
    if any(
        any(term in f"{item.get('summary', '')} {item.get('recommended_action', '')}".casefold() for term in drift_terms)
        for item in checkpoints
    ):
        reasons.append("research-oriented action after a bounded solve should have started")
    tail = checkpoints if last_increase_index is None else checkpoints[last_increase_index + 1:]
    tail_information = sum(
        str(item.get("type") or "").upper() in {
            "SUPPORTED_FACT", "REJECTED_HYPOTHESIS", "ARTIFACT_READY", "ENVIRONMENT_DISCOVERY",
        }
        for item in tail
    )
    if tail_information >= 3:
        reasons.append("three information events without exploit-proximity increase")
    if proximity >= .5 and sum(bool(item.get("repeated_command")) for item in tail) >= 2:
        reasons.append("repeated command family after primitive confirmation")
    return reasons


def _overlap(existing: Mapping[str, Any], candidate: BranchCandidate) -> tuple[float, dict[str, float], list[str]]:
    components = {
        "hypothesis_family": _exact(existing.get("hypothesis_family"), candidate.hypothesis_family),
        "hypothesis_tokens": _jaccard(_tokens(existing.get("hypothesis", "")), _tokens(candidate.hypothesis)),
        "scope": _jaccard(_normalized_set(existing.get("scope", [])), _normalized_set(candidate.scope)),
        "tool_strategy": _jaccard(_normalized_set(existing.get("tool_strategy", [])), _normalized_set(candidate.tool_strategy)),
        "expected_artifacts": _artifact_overlap(existing.get("expected_artifacts", []), candidate.expected_artifacts),
        "role": _exact(existing.get("role"), candidate.role),
    }
    weights = {"hypothesis_family": .25, "hypothesis_tokens": .25, "scope": .15, "tool_strategy": .10, "expected_artifacts": .15, "role": .10}
    score = round(sum(components[key] * weights[key] for key in weights), 4)
    reasons = []
    if components["hypothesis_family"]: reasons.append("same hypothesis family")
    else: reasons.append("different hypothesis family")
    common_scope = sorted(_normalized_set(existing.get("scope", [])) & _normalized_set(candidate.scope))
    if common_scope: reasons.append("scope overlap: " + ", ".join(common_scope))
    if components["expected_artifacts"]: reasons.append("expected artifact overlap")
    else: reasons.append("different expected artifact")
    return score, {key: round(value, 4) for key, value in components.items()}, reasons


def _is_exact_duplicate(existing: Mapping[str, Any], candidate: BranchCandidate) -> bool:
    """Reject only a race branch that is materially identical in every dimension."""
    return bool(
        _exact(existing.get("hypothesis_family"), candidate.hypothesis_family)
        and _exact(existing.get("hypothesis"), candidate.hypothesis)
        and _normalized_set(existing.get("scope", [])) == _normalized_set(candidate.scope)
        and _normalized_set(existing.get("tool_strategy", [])) == _normalized_set(candidate.tool_strategy)
        and {Path(str(item)).as_posix().casefold() for item in existing.get("expected_artifacts", [])}
        == {Path(str(item)).as_posix().casefold() for item in candidate.expected_artifacts}
        and _exact(existing.get("role"), candidate.role)
    )


def _candidate_dict(candidate: BranchCandidate) -> dict[str, Any]:
    return {"session_id": candidate.session_id, "role": candidate.role, "hypothesis_family": candidate.hypothesis_family, "hypothesis": candidate.hypothesis, "scope": list(candidate.scope), "tool_strategy": list(candidate.tool_strategy), "expected_artifacts": list(candidate.expected_artifacts)}


def _load_current_unlocked(solve_root: Path, fingerprint: str) -> dict[str, Any]:
    plan = _load_plan_unlocked(plan_path(solve_root))
    if plan["input_fingerprint"] != fingerprint:
        _mark_stale(plan)
        atomic_json(plan_path(solve_root), plan)
        raise DelegationError("delegation plan is stale: input fingerprint changed")
    return plan


def _load_plan_unlocked(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise DelegationError("delegation plan is missing or unsafe; run delegation-plan-init")
    try: raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc: raise DelegationError("delegation plan is not valid JSON") from exc
    if not isinstance(raw, dict) or raw.get("schema_version") != PLAN_SCHEMA_VERSION:
        raise DelegationError(f"delegation plan schema_version must be {PLAN_SCHEMA_VERSION}")
    required = {"challenge_id", "input_fingerprint", "parent_session_id", "tier", "tier_reason", "created_at", "updated_at", "branches"}
    if not required.issubset(raw) or not isinstance(raw["branches"], list):
        raise DelegationError("delegation plan schema is incomplete")
    if raw["tier"] is not None and raw["tier"] not in range(0, 5):
        raise DelegationError("delegation plan contains invalid tier")
    seen: set[str] = set()
    for branch in raw["branches"]:
        if not isinstance(branch, dict) or branch.get("status") not in BRANCH_STATUSES: raise DelegationError("delegation plan contains an invalid branch")
        branch_required = {
            "session_id", "role", "hypothesis_family", "hypothesis", "scope", "tool_strategy",
            "expected_artifacts", "evidence_contract", "success_condition", "kill_condition",
            "maximum_steps", "budget_seconds", "requested_model_role", "requested_reasoning",
            "observed_runtime_model", "observed_reasoning", "pinning_verified", "admission",
            "runtime_observation_evidence",
            "created_at", "started_at", "finished_at",
        }
        if not branch_required.issubset(branch): raise DelegationError("delegation plan branch schema is incomplete")
        BranchCandidate.create(
            session_id=branch["session_id"], role=branch["role"],
            hypothesis_family=branch["hypothesis_family"], hypothesis=branch["hypothesis"],
            scope=branch["scope"], tool_strategy=branch["tool_strategy"],
            expected_artifacts=branch["expected_artifacts"],
        )
        _string_list(branch["evidence_contract"], "evidence_contract", maximum=32)
        if not isinstance(branch["maximum_steps"], int) or not 1 <= branch["maximum_steps"] <= 10000: raise DelegationError("delegation plan contains invalid maximum_steps")
        if not isinstance(branch["budget_seconds"], int) or not 1 <= branch["budget_seconds"] <= 86400: raise DelegationError("delegation plan contains invalid budget_seconds")
        if not isinstance(branch["admission"], Mapping) or not isinstance(branch["admission"].get("admitted"), bool): raise DelegationError("delegation plan contains invalid admission data")
        if not isinstance(branch["pinning_verified"], bool): raise DelegationError("pinning_verified must be a boolean")
        session_id = branch.get("session_id")
        if session_id in seen: raise DelegationError("delegation plan contains duplicate session IDs")
        seen.add(session_id)
        if branch.get("pinning_verified") and not (branch.get("observed_runtime_model") and branch.get("observed_reasoning")):
            raise DelegationError("pinning_verified lacks observed runtime evidence")
        _upgrade_legacy_routing_fields(branch)
    raw.setdefault("admission_decisions", [])
    return raw


def _validated_routing(
    plan: Mapping[str, Any], contract: Mapping[str, Any] | None,
    *, branch_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    if contract is None:
        return {}
    active_max = sum(
        row.get("routing_profile") == "CONFIRMED_BOTTLENECK"
        and row.get("status") not in {
            "TERMINAL", "TERMINATED", "COMPLETED", "ERROR", "START_FAILED",
            "TIMED_OUT", "STALE", "REFUTED",
        }
        for row in plan.get("branches", []) if isinstance(row, Mapping)
    )
    try:
        validate_routing_contract(
            contract, branch_evidence=branch_evidence, active_max_lanes=active_max,
        )
    except RoutingError as exc:
        raise DelegationError(str(exc)) from exc
    return dict(contract)


def _routing_branch_defaults(routing: Mapping[str, Any]) -> dict[str, Any]:
    if not routing:
        return {
            "routing_profile": "LEGACY_UNROUTED",
            "requested_model_class": None, "requested_model": None,
            "routing_reason": None, "routing_evidence": [],
            "fallback_profile": None, "fallback_reason": None,
            "routing_classification": "LEGACY_UNROUTED",
            "model_routing_matched": False, "reasoning_routing_matched": False,
            "routing_matched": False, "fallback_used": False,
            "fallback_reason_observed": None,
        }
    return {
        **dict(routing), "routing_classification": None,
        "model_routing_matched": False, "reasoning_routing_matched": False,
        "routing_matched": False, "fallback_used": False,
        "fallback_reason_observed": None,
    }


def _upgrade_legacy_routing_fields(branch: dict[str, Any]) -> None:
    if branch.get("routing_profile") in ROUTING_PROFILES:
        branch.setdefault("requested_model", None)
        branch.setdefault("requested_model_class", None)
        branch.setdefault("runtime_observation_status", None)
        branch.setdefault("routing_classification", None)
        branch.setdefault("model_routing_matched", False)
        branch.setdefault("reasoning_routing_matched", False)
        branch.setdefault("routing_matched", False)
        branch.setdefault("fallback_used", False)
        branch.setdefault("fallback_reason_observed", None)
        return
    branch.setdefault("routing_profile", "LEGACY_UNROUTED")
    branch.setdefault("requested_model_class", None)
    branch.setdefault("requested_model", None)
    branch.setdefault("routing_reason", None)
    branch.setdefault("routing_evidence", [])
    branch.setdefault("fallback_profile", None)
    branch.setdefault("fallback_reason", None)
    branch.setdefault("runtime_observation_status", None)
    branch.setdefault("routing_classification", "LEGACY_UNROUTED")
    branch.setdefault("model_routing_matched", False)
    branch.setdefault("reasoning_routing_matched", False)
    branch.setdefault("routing_matched", False)
    branch.setdefault("fallback_used", False)
    branch.setdefault("fallback_reason_observed", None)


def _mark_stale(plan: dict[str, Any]) -> None:
    for branch in plan.get("branches", []): branch["status"] = "STALE"
    plan["updated_at"] = utc_now()


def _elapsed_ratio(branch: Mapping[str, Any], now: datetime) -> float:
    started = branch.get("started_at")
    budget = branch.get("budget_seconds")
    if not started or not isinstance(budget, int) or budget <= 0: return 0.0
    try: parsed = datetime.fromisoformat(str(started).replace("Z", "+00:00"))
    except ValueError: return 0.0
    return max(0.0, (now - parsed).total_seconds() / budget)


def _new_information_rate(
    checkpoints: Sequence[Mapping[str, Any]], result: Mapping[str, Any] | None,
    fallback_information_events: int,
) -> float:
    """Return the informative fraction in the recent half of timestamped events.

    The midpoint window makes a sequence of old discoveries followed by blockers
    visibly plateau, while remaining deterministic.  Legacy/mocked observations
    without timestamps use the all-observation fraction.
    """
    informative_types = {"SUPPORTED_FACT", "REJECTED_HYPOTHESIS", "EXPLOIT_PRIMITIVE", "ARTIFACT_READY", "FLAG_CANDIDATE"}
    events: list[tuple[datetime, bool]] = []
    for item in checkpoints:
        stamp = _optional_datetime(item.get("created_at"))
        if stamp is not None:
            events.append((stamp, item.get("type") in informative_types))
    if result is not None:
        stamp = _optional_datetime(result.get("finished_at"))
        if stamp is not None:
            informative = bool(
                result.get("artifacts") or result.get("flag_candidates")
                or any(h.get("status") in {"SUPPORTED", "REFUTED"} for h in result.get("hypotheses", []))
            )
            events.append((stamp, informative))
    if not events:
        total = len(checkpoints) + (1 if result else 0)
        return round(fallback_information_events / total, 4) if total else 0.0
    events.sort(key=lambda row: row[0])
    midpoint = events[0][0] + (events[-1][0] - events[0][0]) / 2
    recent = [informative for stamp, informative in events if stamp >= midpoint]
    return round(sum(recent) / len(recent), 4) if recent else 0.0


def _optional_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _tokens(value: Any) -> set[str]: return set(_TOKEN_RE.findall(str(value).casefold()))
def _normalized_set(values: Any) -> set[str]:
    if not isinstance(values, (list, tuple)): return set()
    return {" ".join(_TOKEN_RE.findall(str(item).casefold())) for item in values if str(item).strip()}
def _jaccard(left: set[str], right: set[str]) -> float:
    return len(left & right) / len(left | right) if left or right else 1.0
def _exact(left: Any, right: Any) -> float: return 1.0 if " ".join(_TOKEN_RE.findall(str(left).casefold())) == " ".join(_TOKEN_RE.findall(str(right).casefold())) else 0.0
def _artifact_overlap(left: Any, right: Any) -> float:
    def normalize(values: Any) -> set[str]:
        return {Path(str(item)).name.casefold() for item in values} if isinstance(values, (list, tuple)) else set()
    return _jaccard(normalize(left), normalize(right))


def _identifier(value: Any, field: str) -> str:
    text = _short(value, field)
    if not _IDENTIFIER_RE.fullmatch(text): raise DelegationError(f"{field} contains unsupported characters")
    return text
def _short(value: Any, field: str) -> str: return _bounded(value, field, 128)
def _bounded(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > maximum or any(c in value for c in "\0\r"):
        raise DelegationError(f"{field} must be a non-empty string of at most {maximum} characters")
    return value.strip()
def _string_list(value: Sequence[str], field: str, *, maximum: int) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence) or not 1 <= len(value) <= maximum:
        raise DelegationError(f"{field} must contain 1 through {maximum} values")
    return [_bounded(item, f"{field}[{index}]", 512) for index, item in enumerate(value)]
def _relative_names(value: Sequence[str], field: str, *, maximum: int) -> list[str]:
    rows = _string_list(value, field, maximum=maximum)
    for raw in rows:
        path = Path(raw)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise DelegationError(f"{field} contains an unsafe relative path: {raw!r}")
    return rows
