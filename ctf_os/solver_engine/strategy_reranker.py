"""Small deterministic local strategy ordering from persisted external evidence."""

from __future__ import annotations

from collections.abc import Iterable

from .race_plan import RaceAttempt


class StrategyReranker:
    """Prefer diversity after failures without inventing a new attack plan."""

    def rerank(self, attempts: Iterable[RaceAttempt], *, findings: Iterable[str] = (), failures: Iterable[str] = ()) -> tuple[RaceAttempt, ...]:
        failed = " ".join(failures).casefold()
        evidence = " ".join(findings).casefold()

        def score(item: RaceAttempt) -> int:
            name = item.profile.name
            value = 0
            if name == "exploit_alt" and failed:
                value -= 3
            if name == "fallback" and failed:
                value -= 2
            if name == "exploit_main" and evidence:
                value -= 1
            return value

        # Python's stable sort retains the authored race-plan order when there
        # is no evidence-based reason to move a strategy.
        return tuple(sorted(attempts, key=score))
