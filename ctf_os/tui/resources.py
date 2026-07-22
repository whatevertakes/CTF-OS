from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def resource_panel(capacity: Mapping[str, Any], state: Mapping[str, Any]) -> dict[str, Any]:
    """Build the resource section for live process and sandbox management."""
    requests = state.get("requests", {}) if isinstance(state.get("requests"), Mapping) else {}
    allocations = state.get("allocations", {}) if isinstance(state.get("allocations"), Mapping) else {}
    observations = state.get("observations", {}) if isinstance(state.get("observations"), Mapping) else {}
    released = state.get("released", {}) if isinstance(state.get("released"), Mapping) else {}
    actions = {
        str(item.get("session_id")): item for item in state.get("last_plan", {}).get("resize_actions", [])
        if isinstance(item, Mapping) and item.get("session_id")
    }
    branches = {}
    for session_id in sorted(set(requests) | set(allocations) | set(observations) | set(released)):
        request = requests.get(session_id, {})
        allocation = allocations.get(session_id, {})
        observation = observations.get(session_id, {})
        branches[session_id] = {
            "workload_class": request.get("workload_class"), "priority": request.get("priority"),
            "requested": {
                "cpus": [request.get("min_cpus"), request.get("preferred_cpus"), request.get("max_cpus")],
                "memory_bytes": [request.get("min_memory_bytes"), request.get("preferred_memory_bytes"), request.get("max_memory_bytes")],
                "storage_bytes": request.get("storage_bytes"), "gpu_memory_bytes": request.get("gpu_memory_bytes"),
            },
            "allocation": allocation,
            "measured_utilization": (observation.get("samples") or [None])[-1],
            "progress_signal": observation.get("progress"),
            "classification": observation.get("classification", "UNKNOWN"),
            "last_resize": observation.get("last_resize"),
            "scheduler_recommendation": actions.get(session_id),
            "resource_release": released.get(session_id),
        }
    return {
        "host": {
            "cpu": capacity.get("cpu", {}), "memory": capacity.get("memory", {}),
            "storage": capacity.get("storage", {}), "gpu": capacity.get("gpu", {}),
            "observation_mode": capacity.get("observation_mode", "DEGRADED"),
            "degraded_metrics": capacity.get("degraded_metrics", []),
        },
        "branches": branches, "remaining": state.get("last_plan", {}).get("remaining", {}),
        "rebalance_required": state.get("rebalance_required", False),
        "rebalance_reason": state.get("rebalance_reason"),
    }
