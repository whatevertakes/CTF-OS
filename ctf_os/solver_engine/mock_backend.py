"""Deterministic streamed backend for integration tests and local demos."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from .backend import EventCallback
from .parser import ActionObservationParser
from .types import BackendResult, SolverEvent


class MockBackend:
    def __init__(self, output: Iterable[str] = (), *, status: str = "completed") -> None:
        self.output = tuple(output)
        self.status = status
        self.prompts: list[str] = []

    def run(
        self,
        prompt: str,
        *,
        on_event: EventCallback | None = None,
        on_output: Callable[[str], None] | None = None,
    ) -> BackendResult:
        self.prompts.append(prompt)
        parser = ActionObservationParser()
        events: list[SolverEvent] = []
        for line in self.output:
            if on_output:
                on_output(line)
            parsed = parser.parse_line(line)
            if parsed:
                events.append(parsed)
                if on_event:
                    on_event(parsed)
        return BackendResult(self.status, "\n".join(self.output), tuple(events))
