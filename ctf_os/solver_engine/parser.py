"""Parser for safe, structured records emitted by a solver worker."""

from __future__ import annotations

import re

from .types import SolverEvent

_TAG = re.compile(r"^\s*\[([A-Z_]+)]\s*(.*)$")
_PERSISTED_TAGS = frozenset({"PLAN", "HYPOTHESIS", "ACTION", "OBSERVATION", "FINDING", "FAIL", "SHIFT", "FLAG_CANDIDATE", "ARTIFACT", "TASK_DONE"})


class ActionObservationParser:
    """Persist concise, structured external work records from solver output."""

    def parse_line(self, line: str) -> SolverEvent | None:
        match = _TAG.match(line)
        if not match:
            return None
        tag, content = match.groups()
        if tag not in _PERSISTED_TAGS or not content.strip():
            return None
        return SolverEvent(kind=tag.lower(), content=content.strip())

    def parse(self, output: str) -> list[SolverEvent]:
        return [event for line in output.splitlines() if (event := self.parse_line(line))]
