"""Detect repeated external attempts and request an explicit strategy shift."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass


def _normalise(value: str) -> str:
    return " ".join(value.casefold().split())


@dataclass(frozen=True)
class LoopSignal:
    shift_required: bool
    reason: str = ""
    count: int = 0


class LoopDetector:
    def __init__(self, *, repeat_threshold: int = 2) -> None:
        if repeat_threshold < 2:
            raise ValueError("repeat_threshold must be at least two")
        self.repeat_threshold = repeat_threshold
        self._commands: Counter[str] = Counter()
        self._failures: Counter[str] = Counter()

    def observe_command(self, command: str) -> LoopSignal:
        return self._observe(self._commands, command, "repeated command")

    def observe_failure(self, failure: str) -> LoopSignal:
        return self._observe(self._failures, failure, "repeated failure")

    def observe(self, kind: str, content: str) -> LoopSignal:
        if kind.lower() == "action":
            return self.observe_command(content)
        if kind.lower() == "fail":
            return self.observe_failure(content)
        return LoopSignal(False)

    def _observe(self, records: Counter[str], value: str, label: str) -> LoopSignal:
        key = _normalise(value)
        if not key:
            return LoopSignal(False)
        records[key] += 1
        count = records[key]
        return LoopSignal(count >= self.repeat_threshold, f"{label}: {value}" if count >= self.repeat_threshold else "", count)
