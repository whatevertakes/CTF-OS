"""Shared, externally observable solver-engine types.

The engine deliberately models actions and observations, not model reasoning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class SolverEvent:
    """A structured record that is safe to persist or share with a team."""

    kind: str
    content: str
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BackendResult:
    """The externally visible result of one backend attempt."""

    status: str
    output: str = ""
    events: tuple[SolverEvent, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
