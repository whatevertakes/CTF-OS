"""Primitive-state validation shared by events, checkpoints, and race control."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


PRIMITIVE_CANDIDATE = "EXPLOIT_PRIMITIVE_CANDIDATE"
PRIMITIVE_CONFIRMED = "EXPLOIT_PRIMITIVE_CONFIRMED"
PRIMITIVE_REFUTED = "EXPLOIT_PRIMITIVE_REFUTED"
LEGACY_PRIMITIVE = "EXPLOIT_PRIMITIVE"
PRIMITIVE_TYPES = frozenset({PRIMITIVE_CANDIDATE, PRIMITIVE_CONFIRMED, PRIMITIVE_REFUTED})


class PrimitiveEvidenceError(ValueError):
    pass


def validate_primitive(kind: str, evidence: Mapping[str, Any] | None, *, legacy_ok: bool = True) -> dict[str, Any]:
    """Validate additive primitive evidence and return a JSON-safe mapping.

    Legacy records remain readable, but are always candidate-grade and can
    never independently authorize takeover or scheduler priority.
    """
    normalized = kind.strip().upper()
    raw = dict(evidence or {})
    if normalized == LEGACY_PRIMITIVE:
        if not legacy_ok:
            raise PrimitiveEvidenceError(
                "EXPLOIT_PRIMITIVE is deprecated; publish EXPLOIT_PRIMITIVE_CANDIDATE or EXPLOIT_PRIMITIVE_CONFIRMED"
            )
        return {**raw, "primitive_state": "CANDIDATE", "legacy_candidate": True}
    if normalized not in PRIMITIVE_TYPES:
        return raw
    required_candidate = (
        "claimed_capability", "positive_observation", "decisive_experiment",
        "success_condition", "kill_condition", "next_confirmation_experiment",
    )
    if normalized == PRIMITIVE_CANDIDATE:
        _require_nonempty(raw, required_candidate)
        raw["primitive_state"] = "CANDIDATE"
        return raw
    if normalized == PRIMITIVE_CONFIRMED:
        required = (
            "claimed_capability", "positive_assertion_receipt",
            "negative_control_assertion_receipt", "observed_result",
            "artifact_or_command_receipt", "next_poc_linking_experiment",
        )
        _require_nonempty(raw, required)
        if raw.get("success_condition_satisfied") is not True:
            raise PrimitiveEvidenceError("confirmed primitive requires success_condition_satisfied=true")
        if raw.get("kill_condition_evaluated") is not True:
            raise PrimitiveEvidenceError("confirmed primitive requires kill_condition_evaluated=true")
        raw["primitive_state"] = "CONFIRMED"
        return raw
    _require_nonempty(raw, ("claimed_capability", "refutation_receipt", "kill_condition_evaluated"))
    raw["primitive_state"] = "REFUTED"
    return raw


def _require_nonempty(raw: Mapping[str, Any], fields: tuple[str, ...]) -> None:
    missing = [field for field in fields if raw.get(field) in (None, "", [], {})]
    if missing:
        raise PrimitiveEvidenceError("primitive evidence is missing: " + ", ".join(missing))
