"""State schema upgrades.

Version zero covers the pre-09 report examples: split-file field names, nested
identity, and hyphenated provenance values.  Upgrades are pure and idempotent;
the caller decides when to persist their result.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from ctf_os.models import CURRENT_SCHEMA_VERSION
from ctf_os.schema import STATE_SCHEMA_VERSION


class UnsupportedSchemaVersion(ValueError):
    """Raised when a state was produced by a newer incompatible runtime."""


def _upgrade_v0(data: dict[str, Any]) -> dict[str, Any]:
    identity = data.get("identity")
    if isinstance(identity, Mapping):
        for field in ("contest_id", "category", "challenge_id"):
            if field not in data and field in identity:
                data[field] = identity[field]

    if "flag_candidates" in data and "candidates" not in data:
        data["candidates"] = data.pop("flag_candidates")
    if "active_goal" in data and "active_goal_id" not in data:
        active = data.pop("active_goal")
        data["active_goal_id"] = (
            active.get("id") if isinstance(active, Mapping) else active
        )
    deps = data.get("deps")
    if (
        "goals" not in data
        and isinstance(deps, Mapping)
        and isinstance(deps.get("goals"), list)
    ):
        data["goals"] = deps["goals"]
    if str(data.get("status", "")).upper() == "PAUSED":
        data.setdefault(
            "resume_status",
            data.get("paused_from_status") or "ACTIVE",
        )

    facts = data.get("facts", [])
    if isinstance(facts, Mapping):
        facts = list(facts.values())
    if isinstance(facts, list):
        for fact in facts:
            if not isinstance(fact, dict):
                continue
            if "statement" not in fact and "claim" in fact:
                fact["statement"] = fact["claim"]
            if "provenance" not in fact and "confidence" in fact:
                fact["provenance"] = fact["confidence"]
            provenance = fact.get("provenance")
            if isinstance(provenance, str):
                fact["provenance"] = provenance.replace("-", "_")

    experiments = data.get("experiments", [])
    if isinstance(experiments, Mapping):
        experiments = list(experiments.values())
    if isinstance(experiments, list):
        for experiment in experiments:
            if not isinstance(experiment, dict):
                continue
            experiment.setdefault(
                "expected_observation",
                experiment.get("oracle", experiment.get("keep_if", "")),
            )

    budget = data.get("budget")
    if isinstance(budget, dict):
        aliases = {
            "allocated_s": "allocated_seconds",
            "spent_s": "spent_seconds",
            "no_progress_since_s": "no_progress_since_seconds",
        }
        for old, new in aliases.items():
            if new not in budget and old in budget:
                budget[new] = budget[old]
        if (
            "progress_markers" not in data
            and "progress_markers" in budget
        ):
            data["progress_markers"] = budget["progress_markers"]

    data["schema_version"] = 1
    return data


def upgrade_state(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Read v0/v1 compatibility state without silently migrating to v2."""

    data = deepcopy(dict(raw))
    version = int(data.get("schema_version", 0))
    if version == STATE_SCHEMA_VERSION:
        return data
    if version > STATE_SCHEMA_VERSION:
        raise UnsupportedSchemaVersion(
            f"state schema {version} is newer than supported "
            f"{STATE_SCHEMA_VERSION}"
        )
    while version < CURRENT_SCHEMA_VERSION:
        if version == 0:
            data = _upgrade_v0(data)
        else:
            raise UnsupportedSchemaVersion(
                f"no upgrade path from state schema {version}"
            )
        version = int(data["schema_version"])
    return data


V2_TOP_LEVEL_FIELDS = frozenset(
    {
        "configuration_epoch",
        "workspace_revision",
        "receipts",
        "sessions",
        "cycles",
        "waves",
        "checkpoints",
        "targets",
        "primary_target_id",
        "closure",
        "workspace_publishes",
        "active_managed_session_id",
    }
)


def validate_state_protocol_shape(raw: Mapping[str, Any]) -> int:
    """Reject mixed v1/v2 state before model coercion can hide omissions."""

    version = int(raw.get("schema_version", 0))
    if version in {0, CURRENT_SCHEMA_VERSION}:
        mixed = sorted(V2_TOP_LEVEL_FIELDS.intersection(raw))
        if mixed:
            raise UnsupportedSchemaVersion(
                "v1 state contains v2-only fields: " + ", ".join(mixed)
            )
        return version
    if version == STATE_SCHEMA_VERSION:
        missing = sorted(V2_TOP_LEVEL_FIELDS.difference(raw))
        if missing:
            raise UnsupportedSchemaVersion(
                "v2 state omits required top-level fields: "
                + ", ".join(missing)
            )
        return version
    raise UnsupportedSchemaVersion(
        f"unsupported state schema version {version}"
    )


__all__ = [
    "UnsupportedSchemaVersion",
    "V2_TOP_LEVEL_FIELDS",
    "upgrade_state",
    "validate_state_protocol_shape",
]
