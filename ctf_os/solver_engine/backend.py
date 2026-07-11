"""Minimal protocol shared by real and test solver backends."""

from __future__ import annotations

from typing import Callable, Protocol

from .types import BackendResult, SolverEvent


EventCallback = Callable[[SolverEvent], None]


class SolverBackend(Protocol):
    """A backend that executes a rendered prompt and streams external events."""

    def run(self, prompt: str, *, on_event: EventCallback | None = None) -> BackendResult:
        """Run an attempt and return its externally observable result."""
