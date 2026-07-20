"""Authoritative solve modes and deterministic legacy-tier compatibility."""

from __future__ import annotations

from enum import Enum


class SolveMode(str, Enum):
    SOL_ONLY = "sol-only"
    FIXED_RACE = "fixed-race"
    ADAPTIVE_RACE = "adaptive-race"


DEFAULT_LIVE_MODE = SolveMode.ADAPTIVE_RACE
FIXED_RACE_CHILDREN = 3
MAXIMUM_MODEL_CONCURRENCY = 4


class SolveModeError(ValueError):
    pass


def legacy_tier_mode(tier: int) -> SolveMode:
    """Map a legacy tier without treating it as an active-width decision."""

    if not isinstance(tier, int) or isinstance(tier, bool) or tier not in range(5):
        raise SolveModeError("tier must be an integer from 0 through 4")
    return SolveMode.SOL_ONLY if tier == 0 else SolveMode.ADAPTIVE_RACE


def legacy_maximum_child_hint(tier: int | None) -> int:
    if tier is None:
        return 3
    legacy_tier_mode(tier)
    return min(3, max(0, tier))


def resolve_solve_mode(
    mode: SolveMode | str | None = None,
    *,
    tier: int | None = None,
    benchmark: bool = False,
) -> SolveMode:
    """Resolve mode explicitly and reject ambiguous/conflicting treatment input."""

    if benchmark and tier is not None:
        raise SolveModeError("benchmark treatment must use an explicit arm/mode; tier is forbidden")
    explicit: SolveMode | None
    try:
        explicit = SolveMode(mode) if mode is not None else None
    except ValueError as exc:
        raise SolveModeError(f"unsupported solve mode: {mode}") from exc
    if tier is None:
        return explicit or DEFAULT_LIVE_MODE
    compatible = legacy_tier_mode(tier)
    if explicit is not None and explicit is not compatible:
        raise SolveModeError(
            f"conflicting --mode {explicit.value} and legacy --tier {tier} ({compatible.value})"
        )
    return explicit or compatible


def maximum_child_width(mode: SolveMode | str, *, tier_hint: int | None = None) -> int:
    selected = SolveMode(mode)
    if selected is SolveMode.SOL_ONLY:
        return 0
    if selected is SolveMode.FIXED_RACE:
        return FIXED_RACE_CHILDREN
    return legacy_maximum_child_hint(tier_hint)


def validate_branch_intents(
    mode: SolveMode | str,
    count: int,
    *,
    frozen_template: bool = False,
) -> None:
    selected = SolveMode(mode)
    if selected is SolveMode.SOL_ONLY and count:
        raise SolveModeError("sol-only mode forbids child branch intents")
    if selected is SolveMode.FIXED_RACE and (
        count != FIXED_RACE_CHILDREN or not frozen_template
    ):
        raise SolveModeError(
            "fixed-race requires exactly three frozen category-template child intents"
        )
    if selected is SolveMode.ADAPTIVE_RACE and not 0 <= count <= 3:
        raise SolveModeError("adaptive-race permits zero through three child intents")
