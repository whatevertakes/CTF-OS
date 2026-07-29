"""Challenge lifecycle validation.

The store guarantees atomicity; this module guarantees that lifecycle changes
are meaningful.  Semantic gates (for example, proof evidence) are passed
explicitly instead of being inferred from hooks or prose.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class TransitionError(ValueError):
    pass


TRANSITIONS: dict[str, frozenset[str]] = {
    # A human-reported accepted contest outcome may close any nonterminal
    # solving state, including an explicitly paused or unproved workflow.
    # `validate_transition` still requires operator evidence for every SOLVED
    # edge, and ABANDONED remains terminal.
    "NEW": frozenset({"TRIAGING", "PAUSED", "SOLVED", "ABANDONED"}),
    "TRIAGING": frozenset(
        {"ACTIVE", "NEEDS_HUMAN", "PAUSED", "SOLVED", "ABANDONED"}
    ),
    "ACTIVE": frozenset(
        {
            "PROVING",
            "STALLED",
            "NEEDS_RESEARCH",
            "NEEDS_HUMAN",
            "PAUSED",
            "SOLVED",
            "ABANDONED",
        }
    ),
    "STALLED": frozenset(
        {"ACTIVE", "NEEDS_HUMAN", "PAUSED", "SOLVED", "ABANDONED"}
    ),
    "NEEDS_RESEARCH": frozenset(
        {"ACTIVE", "NEEDS_HUMAN", "PAUSED", "SOLVED", "ABANDONED"}
    ),
    "NEEDS_HUMAN": frozenset(
        {"ACTIVE", "PAUSED", "SOLVED", "ABANDONED"}
    ),
    "PROVING": frozenset(
        {
            "ACTIVE",
            "READY_TO_SUBMIT",
            "NEEDS_HUMAN",
            "PAUSED",
            "SOLVED",
        }
    ),
    "READY_TO_SUBMIT": frozenset(
        {"SOLVED", "ACTIVE", "PAUSED", "ABANDONED"}
    ),
    "PAUSED": frozenset(
        {
            "TRIAGING",
            "NEW",
            "ACTIVE",
            "STALLED",
            "NEEDS_RESEARCH",
            "NEEDS_HUMAN",
            "PROVING",
            "READY_TO_SUBMIT",
            "SOLVED",
            "ABANDONED",
        }
    ),
    "SOLVED": frozenset(),
    "ABANDONED": frozenset(),
}


def _value(status: Any) -> str:
    value = status.value if isinstance(status, Enum) else status
    if not isinstance(value, str):
        raise TransitionError(f"invalid challenge status: {status!r}")
    return value.upper()


@dataclass(frozen=True, slots=True)
class TransitionEvidence:
    proof_passed: bool = False
    operator_outcome: str | None = None
    pause_resume_target: str | None = None


def validate_transition(
    current: Any,
    target: Any,
    *,
    evidence: TransitionEvidence | None = None,
) -> None:
    """Validate one lifecycle transition, including proof/manual gates."""

    source = _value(current)
    destination = _value(target)
    if source not in TRANSITIONS:
        raise TransitionError(f"unknown current state: {source}")
    if destination not in TRANSITIONS:
        raise TransitionError(f"unknown target state: {destination}")
    if source == destination:
        return
    if destination not in TRANSITIONS[source]:
        raise TransitionError(f"transition not allowed: {source} -> {destination}")

    supplied = evidence or TransitionEvidence()
    if destination == "READY_TO_SUBMIT" and not supplied.proof_passed:
        raise TransitionError(
            "READY_TO_SUBMIT requires an independently passed proof"
        )
    if destination == "SOLVED" and supplied.operator_outcome != "accepted":
        raise TransitionError("SOLVED requires operator outcome 'accepted'")
    if source == "READY_TO_SUBMIT" and destination == "ACTIVE":
        if supplied.operator_outcome not in {"rejected", "proof_invalidated"}:
            raise TransitionError(
                "READY_TO_SUBMIT -> ACTIVE requires rejected or "
                "proof_invalidated outcome"
            )
    if source == "PAUSED" and supplied.pause_resume_target is not None:
        expected = _value(supplied.pause_resume_target)
        if destination != expected:
            raise TransitionError(
                f"pause must resume to {expected}, not {destination}"
            )
