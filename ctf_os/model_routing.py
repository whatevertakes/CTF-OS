"""Evidence-driven model routing policy for Sol-native CTF race branches.

This module only recommends and validates routing records.  It never creates,
starts, supervises, or stops a model session.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from datetime import datetime, timezone
import re
from typing import Any


ROUTING_PROFILES = frozenset({
    "MECHANICAL", "BOUNDED_EXPERIMENT", "IMPLEMENTATION", "DEEP_SOLVER",
    "CONFIRMED_BOTTLENECK",
})
MODEL_CLASSES = frozenset({"luna-equivalent", "terra-equivalent", "sol-equivalent"})
RUNTIME_OBSERVATION_STATUSES = frozenset({
    "OBSERVED", "NOT_OBSERVABLE", "UNSUPPORTED", "CONFLICT",
})
ROUTING_INTERPRETATIONS = frozenset({
    "ROUTING_MATCHED", "FALLBACK_MATCHED", "ROUTING_MISMATCH",
    "RUNTIME_NOT_OBSERVABLE", "ROUTING_UNSUPPORTED", "LEGACY_UNROUTED",
})

# These identifiers were resolved from the installed Codex model catalog.  The
# doctor revalidates them against the current runtime before a live solve may
# treat profile routing as supported.
VERIFIED_RUNTIME_MODELS = {
    "luna-equivalent": "gpt-5.6-luna",
    "terra-equivalent": "gpt-5.6-terra",
    "sol-equivalent": "gpt-5.6-sol",
}

PROFILE_POLICIES: dict[str, dict[str, Any]] = {
    "MECHANICAL": {
        "model_class": "luna-equivalent", "model": "gpt-5.6-luna",
        "reasoning": "medium", "allowed_reasoning": ("medium", "high"),
        "agent_profile": "ctf_mechanical", "fallback_profile": "BOUNDED_EXPERIMENT",
        "agent_profiles": {
            "medium": "ctf_mechanical", "high": "ctf_mechanical_high",
        },
        "fallback_reason": "Luna profile unavailable; use the bounded Terra lane without expanding the task",
    },
    "BOUNDED_EXPERIMENT": {
        "model_class": "terra-equivalent", "model": "gpt-5.6-terra",
        "reasoning": "high", "allowed_reasoning": ("high",),
        "agent_profile": "ctf_terra_high", "fallback_profile": "DEEP_SOLVER",
        "fallback_reason": "Terra profile unavailable; use a bounded Sol xhigh child on the same experiment",
    },
    "IMPLEMENTATION": {
        "model_class": "terra-equivalent", "model": "gpt-5.6-terra",
        "reasoning": "high", "allowed_reasoning": ("high",),
        "agent_profile": "ctf_terra_high", "fallback_profile": "DEEP_SOLVER",
        "fallback_reason": "Terra profile unavailable; use Sol xhigh only to finish the same confirmed artifact",
    },
    "DEEP_SOLVER": {
        "model_class": "sol-equivalent", "model": "gpt-5.6-sol",
        "reasoning": "xhigh", "allowed_reasoning": ("xhigh",),
        "agent_profile": "ctf_deep_solver", "fallback_profile": None,
        "fallback_reason": None,
    },
    "CONFIRMED_BOTTLENECK": {
        "model_class": "sol-equivalent", "model": "gpt-5.6-sol",
        "reasoning": "max", "allowed_reasoning": ("max",),
        "agent_profile": "ctf_max_endgame", "fallback_profile": "DEEP_SOLVER",
        "fallback_reason": "Max unavailable; return the same exact blocker to a bounded Sol xhigh lane",
    },
}

MAX_LEASE = {
    "maximum_seconds": 600,
    "maximum_decisive_experiments": 2,
    "required_start_condition": {
        "primitive_confirmed": True,
        "specific_blocker_present": True,
    },
    "stop_conditions": [
        "WORKING_POC", "REMOTE_ATTEMPT", "FLAG_CANDIDATE", "PRIMITIVE_REFUTED",
        "lease_expired", "two_decisive_experiments_completed",
    ],
}

_MAX_BLOCKERS = frozenset({
    "MATH_CONSTRAINT", "CONSTRAINT_BLOCKER", "EXPLOIT_CHAIN", "ENDGAME_LINK",
    "REMOTE_SEMANTIC_DIFFERENCE", "REMOTE_DIFFERENCE", "CRYPTO_DERIVATION",
    "HEAP_CHAIN", "ROP_CHAIN", "DEOBFUSCATION_CORE", "AI_INVERSION_DESIGN",
})
_NON_MAX_BLOCKERS = frozenset({
    "DOCKER_ERROR", "DEPENDENCY_ERROR", "TOOL_INSTALLATION", "TOOL_FAILURE",
    "TARGET_DOWN", "RATE_LIMITED", "AUTH_BLOCKED", "ENVIRONMENT_FAILURE",
    "LONG_COMPUTE", "BROAD_RECON", "GENERIC_RESEARCH",
})
_HIGH_COMPLEXITY_PATTERNS = (
    r"\bheap\b", r"\brop\b", r"\bexploit[- ]chain\b", r"\bdeobfuscat\w*\b",
    r"\bobfuscat\w*\b", r"\bnew crypto\b", r"\blattice attack\b",
    r"\balgebraic attack\b", r"\binversion\b", r"\bagent exploit\b",
    r"\balternate attack\b", r"\bdistinct attack\b", r"\bnew mechanism\b",
    r"\bindependent-full-solve\b",
)
_MECHANICAL_TERMS = (
    "list files", "inventory", "extract strings", "metadata", "filter logs", "batch run",
    "normalize", "deduplicate", "repeat command", "candidate inputs",
)
_IMPLEMENTATION_TERMS = (
    "implement", "payload", "exploit script", "solver", "minimal poc", "adapt remote",
    "remote adaptation", "finish artifact", "complete artifact",
)


class RoutingError(ValueError):
    """Raised when a branch routing contract violates the bounded policy."""


def recommend_routing_profile(evidence: Mapping[str, Any]) -> dict[str, str]:
    """Recommend a profile from mechanism, experiment, artifacts, and blocker evidence."""

    max_status = max_endgame_eligibility(evidence)
    if max_status["eligible"]:
        return {
            "routing_profile": "CONFIRMED_BOTTLENECK",
            "routing_reason": "confirmed primitive and typed endgame blocker remain after an xhigh decisive experiment",
        }
    text = _evidence_text(evidence)
    purpose = str(evidence.get("purpose") or "").casefold()
    independent = purpose == "independent-full-solve" or "independent-full-solve" in text
    complex_mechanism = (
        evidence.get("high_complexity_mechanism") is True
        or _contains_high_complexity(text)
    )
    if independent or complex_mechanism:
        return {
            "routing_profile": "DEEP_SOLVER",
            "routing_reason": "branch owns an independent or high-complexity exploit mechanism",
        }
    mechanical = evidence.get("mechanical_only") is True or any(
        term in text for term in _MECHANICAL_TERMS
    )
    if mechanical and not _contains_high_complexity(text):
        return {
            "routing_profile": "MECHANICAL",
            "routing_reason": "branch performs bounded extraction, batching, or normalization without mechanism discovery",
        }
    implementation = evidence.get("mechanism_confirmed") is True or evidence.get("primitive_confirmed") is True
    implementation = implementation and (
        evidence.get("implementation_only") is True
        or any(term in text for term in _IMPLEMENTATION_TERMS)
    )
    if implementation:
        return {
            "routing_profile": "IMPLEMENTATION",
            "routing_reason": "confirmed primitive or mechanism only needs a minimal payload, solver, or adaptation",
        }
    if evidence.get("bounded_experiment") is True or str(evidence.get("decisive_experiment") or "").strip():
        return {
            "routing_profile": "BOUNDED_EXPERIMENT",
            "routing_reason": "branch tests one concrete hypothesis with a bounded decisive experiment",
        }
    return {
        "routing_profile": "DEEP_SOLVER",
        "routing_reason": "branch must derive a new exploit mechanism rather than execute a fixed task",
    }


def build_routing_contract(
    routing_profile: str,
    *,
    routing_reason: str,
    routing_evidence: Sequence[str],
    branch_evidence: Mapping[str, Any] | None = None,
    requested_model: str | None = None,
    requested_reasoning: str | None = None,
    fallback_profile: str | None | object = ...,
    fallback_reason: str | None | object = ...,
    active_max_lanes: int = 0,
) -> dict[str, Any]:
    """Build and validate the JSON routing contract stored from PLANNED onward."""

    profile = str(routing_profile).strip().upper()
    if profile not in ROUTING_PROFILES:
        raise RoutingError(f"routing_profile must be one of {sorted(ROUTING_PROFILES)}")
    policy = PROFILE_POLICIES[profile]
    selected_fallback = policy["fallback_profile"] if fallback_profile is ... else fallback_profile
    selected_fallback_reason = policy["fallback_reason"] if fallback_reason is ... else fallback_reason
    contract: dict[str, Any] = {
        "routing_profile": profile,
        "requested_model_class": policy["model_class"],
        "requested_model": policy["model"] if requested_model is None else requested_model,
        "requested_reasoning": policy["reasoning"] if requested_reasoning is None else requested_reasoning,
        "routing_reason": _bounded_text(routing_reason, "routing_reason", 1000),
        "routing_evidence": _references(routing_evidence),
        "fallback_profile": selected_fallback,
        "fallback_reason": selected_fallback_reason,
    }
    if profile == "CONFIRMED_BOTTLENECK":
        contract["max_lease"] = deepcopy(MAX_LEASE)
    validate_routing_contract(
        contract, branch_evidence=branch_evidence or {}, active_max_lanes=active_max_lanes,
    )
    return contract


def validate_routing_contract(
    contract: Mapping[str, Any], *, branch_evidence: Mapping[str, Any], active_max_lanes: int = 0,
) -> None:
    profile = str(contract.get("routing_profile") or "").upper()
    if profile not in ROUTING_PROFILES:
        raise RoutingError("routing contract has an unsupported profile")
    policy = PROFILE_POLICIES[profile]
    if contract.get("requested_model_class") != policy["model_class"]:
        raise RoutingError("routing profile requested_model_class is outside its allowed class")
    if contract.get("requested_model") not in {None, policy["model"]}:
        raise RoutingError("routing profile requested_model is not the resolved supported identifier")
    if contract.get("requested_reasoning") not in policy["allowed_reasoning"]:
        raise RoutingError("routing profile requested_reasoning is outside its allowed range")
    _bounded_text(contract.get("routing_reason"), "routing_reason", 1000)
    _references(contract.get("routing_evidence") or [])
    fallback = contract.get("fallback_profile")
    if fallback is not None:
        if fallback != policy["fallback_profile"] or fallback not in ROUTING_PROFILES:
            raise RoutingError("routing fallback profile is not allowed for the requested profile")
        _bounded_text(contract.get("fallback_reason"), "fallback_reason", 1000)
    elif contract.get("fallback_reason") is not None:
        raise RoutingError("fallback_reason requires fallback_profile")
    text = _evidence_text(branch_evidence)
    purpose = str(branch_evidence.get("purpose") or "").casefold()
    independent = purpose == "independent-full-solve" or "independent-full-solve" in text
    if independent and policy["model_class"] == "luna-equivalent":
        raise RoutingError("Luna-equivalent cannot run independent-full-solve")
    high_complexity = (
        branch_evidence.get("high_complexity_mechanism") is True
        or _contains_high_complexity(text)
    )
    if high_complexity and policy["model_class"] == "terra-equivalent":
        raise RoutingError("Terra-equivalent cannot be assigned new high-complexity mechanism discovery")
    if profile == "CONFIRMED_BOTTLENECK":
        if contract.get("max_lease") != MAX_LEASE:
            raise RoutingError("CONFIRMED_BOTTLENECK requires the exact bounded Max lease")
        status = max_endgame_eligibility(branch_evidence, active_max_lanes=active_max_lanes)
        if not status["eligible"]:
            raise RoutingError("Max exact trigger not satisfied: " + ", ".join(status["reasons"]))
    elif contract.get("max_lease") is not None:
        raise RoutingError("max_lease is allowed only for CONFIRMED_BOTTLENECK")


def max_endgame_eligibility(
    evidence: Mapping[str, Any], *, active_max_lanes: int = 0,
) -> dict[str, Any]:
    """Return exact Max eligibility without treating tools or long compute as reasoning blockers."""

    reasons: list[str] = []
    if evidence.get("primitive_confirmed") is not True:
        reasons.append("primitive_not_confirmed")
    blocker = str(evidence.get("blocker_type") or "").strip().upper()
    if evidence.get("specific_blocker_present") is not True or blocker not in _MAX_BLOCKERS:
        reasons.append("specific_typed_blocker_absent")
    if blocker in _NON_MAX_BLOCKERS or evidence.get("environment_or_tool_blocker") is True:
        reasons.append("environment_tool_or_target_blocker")
    if evidence.get("working_poc_present") is True or evidence.get("flag_path_present") is True:
        reasons.append("poc_or_flag_path_already_present")
    xhigh_experiments = int(evidence.get("xhigh_decisive_experiments") or 0)
    if xhigh_experiments < 1:
        reasons.append("no_xhigh_decisive_experiment")
    if active_max_lanes > 0:
        reasons.append("active_max_lane_exists")
    return {
        "eligible": not reasons, "reasons": reasons, "blocker_type": blocker or None,
        "xhigh_decisive_experiments": xhigh_experiments,
    }


def build_native_delegation_packet(
    contract: Mapping[str, Any], *, task_name: str, child_prompt: Mapping[str, Any],
) -> dict[str, Any]:
    """Render the native spawn intent; Sol still owns the actual tool call."""

    profile = str(contract["routing_profile"])
    policy = PROFILE_POLICIES[profile]
    agent_profile = policy.get("agent_profiles", {}).get(
        str(contract["requested_reasoning"]), policy["agent_profile"],
    )
    prompt = dict(child_prompt)
    prompt["routing_contract"] = dict(contract)
    prompt["routing_limits"] = {
        "do_not_change_profile": True,
        "publish_primitive_or_poc_before_summary": True,
        "native_lifecycle_owner": "sol",
        "stop_at_max_lease": profile == "CONFIRMED_BOTTLENECK",
    }
    return {
        "schema_version": 1,
        "native_delegation_surface": "spawn_agent",
        "selection_transport": "PROJECT_CUSTOM_AGENT",
        "custom_agent_profile": agent_profile,
        "requested_agent_type": agent_profile,
        "requested_model_class": contract["requested_model_class"],
        "requested_model": contract["requested_model"],
        "requested_reasoning": contract["requested_reasoning"],
        "task_name": task_name,
        "fork_turns": "all",
        "message": prompt,
        "start_asynchronously": True,
        "requires_native_start_receipt": True,
        "unsupported_action": "record ROUTING_UNSUPPORTED; do not claim the requested runtime was applied",
    }


def compare_runtime_routing(
    contract: Mapping[str, Any] | None,
    *,
    observed_model: str | None,
    observed_reasoning: str | None,
    runtime_observation_status: str,
    runtime_observation_evidence: str | None,
) -> dict[str, Any]:
    """Compare requested and observed identity without copying requested values into observed fields."""

    if not contract or contract.get("routing_profile") not in ROUTING_PROFILES:
        return {
            "routing_classification": "LEGACY_UNROUTED",
            "routing_profile": "LEGACY_UNROUTED", "requested_model_class": None,
            "requested_model": None, "requested_reasoning": None,
            "observed_model": observed_model, "observed_reasoning": observed_reasoning,
            "runtime_observation_status": runtime_observation_status,
            "runtime_observation_evidence": runtime_observation_evidence,
            "model_routing_matched": False, "reasoning_routing_matched": False,
            "routing_matched": False, "fallback_used": False, "fallback_reason": None,
        }
    status = str(runtime_observation_status).upper()
    if status not in RUNTIME_OBSERVATION_STATUSES:
        raise RoutingError("unsupported runtime_observation_status")
    if status == "OBSERVED":
        if not observed_model or not observed_reasoning or not runtime_observation_evidence:
            raise RoutingError("OBSERVED routing requires actual model, reasoning, and exact evidence")
    elif observed_model is not None or observed_reasoning is not None:
        raise RoutingError("unobserved or unsupported routing must keep observed identity null")
    requested_model = contract.get("requested_model")
    requested_reasoning = contract.get("requested_reasoning")
    model_match = status == "OBSERVED" and observed_model == requested_model
    reasoning_match = status == "OBSERVED" and observed_reasoning == requested_reasoning
    fallback = contract.get("fallback_profile")
    fallback_match = False
    if status == "OBSERVED" and fallback in ROUTING_PROFILES:
        fallback_policy = PROFILE_POLICIES[str(fallback)]
        fallback_match = (
            observed_model == fallback_policy["model"]
            and observed_reasoning == fallback_policy["reasoning"]
        )
    if status == "UNSUPPORTED":
        classification = "ROUTING_UNSUPPORTED"
    elif status == "NOT_OBSERVABLE":
        classification = "RUNTIME_NOT_OBSERVABLE"
    elif status == "OBSERVED" and model_match and reasoning_match:
        classification = "ROUTING_MATCHED"
    elif status == "OBSERVED" and fallback_match:
        classification = "FALLBACK_MATCHED"
    else:
        classification = "ROUTING_MISMATCH"
    return {
        "routing_classification": classification,
        "routing_profile": contract["routing_profile"],
        "requested_model_class": contract["requested_model_class"],
        "requested_model": requested_model, "requested_reasoning": requested_reasoning,
        "observed_model": observed_model, "observed_reasoning": observed_reasoning,
        "runtime_observation_status": status,
        "runtime_observation_evidence": runtime_observation_evidence,
        "model_routing_matched": bool(model_match),
        "reasoning_routing_matched": bool(reasoning_match),
        "routing_matched": classification in {"ROUTING_MATCHED", "FALLBACK_MATCHED"},
        "fallback_used": classification == "FALLBACK_MATCHED",
        "fallback_reason": contract.get("fallback_reason") if classification == "FALLBACK_MATCHED" else None,
    }


def branch_routing_interpretation(branch: Mapping[str, Any]) -> dict[str, Any]:
    """Interpret branch performance against the actual observed runtime identity."""

    receipt = branch.get("start_receipt") or branch.get("native_start_receipt")
    routing = dict(receipt) if isinstance(receipt, Mapping) else {}
    classification = str(
        routing.get("routing_classification")
        or branch.get("routing_classification")
        or ("LEGACY_UNROUTED" if not branch.get("routing_profile") else "RUNTIME_NOT_OBSERVABLE")
    )
    observed_model = routing.get("observed_model", branch.get("observed_runtime_model"))
    observed_reasoning = routing.get("observed_reasoning", branch.get("observed_reasoning"))
    return {
        "routing_classification": classification,
        "requested_profile_credit_eligible": classification == "ROUTING_MATCHED",
        "fallback_profile_credit_eligible": classification == "FALLBACK_MATCHED",
        "attributed_model": observed_model if classification in {
            "ROUTING_MATCHED", "FALLBACK_MATCHED", "ROUTING_MISMATCH",
        } else None,
        "attributed_reasoning": observed_reasoning if classification in {
            "ROUTING_MATCHED", "FALLBACK_MATCHED", "ROUTING_MISMATCH",
        } else None,
        "requested_model": routing.get("requested_model", branch.get("requested_model")),
        "requested_reasoning": routing.get("requested_reasoning", branch.get("requested_reasoning")),
        "routing_failure_is_solver_failure": False,
    }


def max_lease_status(
    branch: Mapping[str, Any], *, decisive_experiments: int, now: datetime | None = None,
) -> dict[str, Any]:
    """Evaluate the bounded Max endgame lease from the observed native start time."""

    if branch.get("routing_profile") != "CONFIRMED_BOTTLENECK":
        return {"active": False, "expired": False, "reason": "not_a_max_lane"}
    receipt = branch.get("start_receipt") or branch.get("native_start_receipt")
    started = receipt.get("started_at") if isinstance(receipt, Mapping) else branch.get("started_at")
    if not started:
        return {"active": False, "expired": False, "reason": "not_started"}
    try:
        parsed = datetime.fromisoformat(str(started).replace("Z", "+00:00"))
    except ValueError:
        return {"active": False, "expired": True, "reason": "invalid_start_time"}
    elapsed = max(0.0, ((now or datetime.now(timezone.utc)) - parsed).total_seconds())
    time_expired = elapsed >= int(MAX_LEASE["maximum_seconds"])
    experiment_expired = decisive_experiments >= int(MAX_LEASE["maximum_decisive_experiments"])
    return {
        "active": not (time_expired or experiment_expired),
        "expired": time_expired or experiment_expired,
        "reason": (
            "two_decisive_experiments_completed" if experiment_expired else
            "lease_expired" if time_expired else "within_lease"
        ),
        "elapsed_seconds": round(elapsed, 3),
        "decisive_experiments": decisive_experiments,
    }


def validate_ultra_guard(
    solve_mode: str, *, observed_reasoning: str | None, separate_experiment: bool = False,
) -> dict[str, Any]:
    """Reject hidden Ultra fan-out from a CTF-OS race when it is observable."""

    mode = str(solve_mode)
    if observed_reasoning is None:
        return {"status": "NOT_OBSERVABLE", "valid": None, "observed_reasoning": None}
    ultra = observed_reasoning.casefold() == "ultra"
    valid = not ultra or (mode == "sol-only" and separate_experiment)
    return {
        "status": "OBSERVED", "valid": valid, "observed_reasoning": observed_reasoning,
        "reason": None if valid else f"{mode} cannot be nested with Ultra delegation",
    }


def _evidence_text(evidence: Mapping[str, Any]) -> str:
    fields = (
        "role", "purpose", "hypothesis", "hypothesis_family", "mechanism",
        "decisive_experiment", "expected_artifacts", "tool_strategy", "blocker_type",
    )
    return " ".join(str(evidence.get(field) or "") for field in fields).casefold()


def _contains_high_complexity(text: str) -> bool:
    return any(re.search(pattern, text) is not None for pattern in _HIGH_COMPLEXITY_PATTERNS)


def _references(values: Sequence[str]) -> list[str]:
    if isinstance(values, (str, bytes, bytearray)) or not isinstance(values, Sequence):
        raise RoutingError("routing_evidence must be an array of receipt/event/artifact references")
    result = [_bounded_text(value, "routing_evidence", 500) for value in values]
    if not result:
        raise RoutingError("routing_evidence requires at least one exact reference")
    return result


def _bounded_text(value: Any, field: str, maximum: int) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum or any(character in text for character in "\0\r\n"):
        raise RoutingError(f"{field} must be non-empty bounded single-line text")
    return text
