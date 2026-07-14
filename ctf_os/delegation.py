"""Deterministic records and recommendations for Sol-native delegation.

This module never creates, supervises, or terminates a child session.  It only
persists Sol's plan and computes reproducible admission/utility advice.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any

import yaml

from .categories import playbook_category
from .workspace import atomic_json, state_lock


PLAN_SCHEMA_VERSION = 1
BRANCH_STATUSES = frozenset({
    "PLANNED", "ADMITTED", "RUNNING", "CHECKPOINTED", "SUPPORTED", "REFUTED",
    "PARTIAL", "INCONCLUSIVE", "FLAG_CANDIDATE", "TERMINATED", "ERROR", "STALE",
})
ADMISSION_EXCEPTIONS = frozenset({
    "independent-verification", "clean-room-verifier", "clean-room-verification",
    "alternate-attack-family",
})
UTILITY_CLASSIFICATIONS = frozenset({
    "CONTINUE", "CONTINUE_ONCE", "CROSS_POLLINATE", "SOL_TAKEOVER_CANDIDATE",
    "TERMINATE_CANDIDATE", "COMPLETE", "INSUFFICIENT_DATA",
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
    plan: Mapping[str, Any], candidate: BranchCandidate, *, threshold: float = 0.70,
    purpose: str | None = None,
) -> dict[str, Any]:
    if not isinstance(threshold, (int, float)) or not 0.0 <= float(threshold) <= 1.0:
        raise DelegationError("threshold must be between 0 and 1")
    normalized_purpose = purpose.strip().casefold() if isinstance(purpose, str) and purpose.strip() else None
    comparisons: list[dict[str, Any]] = []
    maximum = 0.0
    for existing in plan.get("branches", []):
        if not isinstance(existing, Mapping) or existing.get("status") == "STALE":
            continue
        score, components, reasons = _overlap(existing, candidate)
        maximum = max(maximum, score)
        comparisons.append({
            "session_id": existing.get("session_id"), "overlap_score": score,
            "components": components, "reasons": reasons,
        })
    comparisons.sort(key=lambda row: (-row["overlap_score"], str(row["session_id"])))
    exception = normalized_purpose in ADMISSION_EXCEPTIONS or candidate.role.casefold() in ADMISSION_EXCEPTIONS
    admitted = maximum < float(threshold) or exception
    if exception and maximum >= float(threshold):
        reason = f"Overlap exception allowed for explicit purpose: {normalized_purpose or candidate.role}"
    elif admitted and comparisons:
        reason = "Candidate is materially distinct under deterministic weighted comparison"
    elif admitted:
        reason = "No existing active branch to overlap"
    else:
        reason = f"Maximum overlap {maximum:.2f} meets or exceeds threshold {float(threshold):.2f}"
    return {
        "admitted": admitted, "novelty_score": round(1.0 - maximum, 4),
        "maximum_overlap_score": round(maximum, 4), "threshold": round(float(threshold), 4),
        "compared_with": comparisons, "reason": reason,
        "exception_purpose": normalized_purpose if exception else None,
    }


def record_admission(
    solve_root: Path, *, input_fingerprint: str, candidate: BranchCandidate,
    threshold: float = 0.70, purpose: str | None = None,
) -> dict[str, Any]:
    with state_lock(solve_root):
        plan = _load_current_unlocked(solve_root, input_fingerprint)
        result = admit_branch(plan, candidate, threshold=threshold, purpose=purpose)
        decisions = [
            item for item in plan.get("admission_decisions", [])
            if not (isinstance(item, Mapping) and item.get("session_id") == candidate.session_id)
        ]
        decisions.append({
            "session_id": candidate.session_id, "candidate": _candidate_dict(candidate),
            "purpose": purpose, "evaluated_at": utc_now(), "result": result,
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
) -> dict[str, Any]:
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
        saved_threshold = saved_result.get("threshold", .70) if isinstance(saved_result, Mapping) else .70
        saved_purpose = decision.get("purpose") if isinstance(decision, Mapping) else purpose
        admission = admit_branch(plan, candidate, threshold=float(saved_threshold), purpose=saved_purpose)
        if not admission["admitted"]:
            raise DelegationError(f"branch admission denied: {admission['reason']}")
        now = utc_now()
        branch = {
            **_candidate_dict(candidate),
            "evidence_contract": _string_list(evidence_contract, "evidence_contract", maximum=32),
            "success_condition": _bounded(success_condition, "success_condition", 2000),
            "kill_condition": _bounded(kill_condition, "kill_condition", 2000),
            "maximum_steps": maximum_steps, "budget_seconds": budget_seconds,
            "requested_model_role": _short(requested_model_role, "requested_model_role"),
            "requested_reasoning": _short(requested_reasoning, "requested_reasoning"),
            "observed_runtime_model": None, "observed_reasoning": None,
            "runtime_observation_evidence": None,
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
    if status not in BRANCH_STATUSES:
        raise DelegationError(f"status must be one of {sorted(BRANCH_STATUSES)}")
    with state_lock(solve_root):
        plan = _load_current_unlocked(solve_root, input_fingerprint)
        matches = [item for item in plan["branches"] if item["session_id"] == session_id]
        if len(matches) != 1:
            raise DelegationError(f"unknown branch session_id: {session_id}")
        branch = matches[0]
        branch["status"] = status
        now = utc_now()
        if status == "RUNNING" and branch["started_at"] is None:
            branch["started_at"] = now
        if status in {"SUPPORTED", "REFUTED", "PARTIAL", "INCONCLUSIVE", "FLAG_CANDIDATE", "TERMINATED", "ERROR", "STALE"}:
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
    return branch


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
    relevant = [item for item in checkpoints if item.get("session_id") == session_id]
    if not relevant and result is None:
        return {"session_id": session_id, "utility_score": None, "classification": "INSUFFICIENT_DATA", "recommendation": "Collect a bounded checkpoint or worker result before judging utility", "metrics": {}}
    counts = {name: 0 for name in (
        "supported_facts", "useful_artifacts", "exploit_primitives", "flag_candidates",
        "rejected_hypotheses", "repeated_failures", "policy_violations",
    )}
    for item in relevant:
        kind = item.get("type")
        if kind == "SUPPORTED_FACT": counts["supported_facts"] += 1
        if kind == "ARTIFACT_READY": counts["useful_artifacts"] += max(1, len(item.get("artifacts", [])))
        if kind == "EXPLOIT_PRIMITIVE": counts["exploit_primitives"] += 1
        if kind == "FLAG_CANDIDATE": counts["flag_candidates"] += 1
        if kind == "REJECTED_HYPOTHESIS": counts["rejected_hypotheses"] += 1
        if kind == "BLOCKER": counts["repeated_failures"] += 1
    if result:
        counts["useful_artifacts"] += len(result.get("artifacts", []))
        counts["flag_candidates"] += len(result.get("flag_candidates", []))
        counts["rejected_hypotheses"] += sum(1 for h in result.get("hypotheses", []) if h.get("status") == "REFUTED")
        counts["policy_violations"] += len(result.get("policy_violations", []))
        if result.get("status") == "ERROR": counts["repeated_failures"] += 1
    overlap = float(branch.get("admission", {}).get("maximum_overlap_score", 0.0))
    elapsed_ratio = _elapsed_ratio(branch, now or datetime.now(timezone.utc))
    information_events = counts["supported_facts"] + counts["useful_artifacts"] + counts["exploit_primitives"] + counts["flag_candidates"] + counts["rejected_hypotheses"]
    rate = _new_information_rate(relevant, result, information_events)
    score = round(
        3.0 * counts["supported_facts"] + 2.0 * counts["useful_artifacts"]
        + 4.0 * counts["exploit_primitives"] + 5.0 * counts["flag_candidates"]
        + counts["rejected_hypotheses"] - 2.0 * counts["repeated_failures"]
        - 2.0 * overlap - 1.5 * elapsed_ratio - 5.0 * counts["policy_violations"], 3,
    )
    if counts["flag_candidates"]:
        classification, recommendation = "COMPLETE", "Return the candidate to Sol for clean replay; do not submit automatically"
    elif counts["policy_violations"]:
        classification, recommendation = "TERMINATE_CANDIDATE", "Sol should review the policy violation before any further execution"
    elif counts["supported_facts"] + counts["exploit_primitives"] and rate >= 0.5:
        classification, recommendation = "CROSS_POLLINATE", "Merge the new fact and send only the compact checkpoint to relevant branches"
    elif elapsed_ratio >= 1.0 and score <= 0:
        classification, recommendation = "TERMINATE_CANDIDATE", "Budget is exhausted with low utility; Sol decides whether to terminate"
    elif counts["repeated_failures"] >= 2 and rate < 0.5:
        classification, recommendation = "SOL_TAKEOVER_CANDIDATE", "Sol should inspect the compact evidence and consider takeover"
    elif score > 0:
        classification, recommendation = "CONTINUE", "Continue for one bounded experiment"
    else:
        classification, recommendation = "CONTINUE_ONCE", "Run one final bounded experiment, then reassess"
    metrics = {**counts, "elapsed_budget_ratio": round(elapsed_ratio, 4), "overlap_score": round(overlap, 4), "new_information_rate": rate}
    return {"session_id": session_id, "utility_score": score, "classification": classification, "recommendation": recommendation, "metrics": metrics}


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
    if raw["tier"] not in range(0, 5): raise DelegationError("delegation plan contains invalid tier")
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
    raw.setdefault("admission_decisions", [])
    return raw


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
