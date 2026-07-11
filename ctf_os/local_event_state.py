"""Deterministic read model for events persisted in local SQLite."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .models import Event


@dataclass(frozen=True)
class LocalChallengeProjection:
    key: str
    contest: str
    category: str | None
    name: str | None
    status: str
    solved_flag: str | None
    candidate_flag: str | None
    running_members: tuple[str, ...]
    duplicate_running: bool
    events: tuple[Event, ...]


class LocalEventState:
    """Read-only reduction of one node's locally persisted events."""

    def __init__(self, events: Iterable[Event] = ()) -> None:
        self.events = tuple(sorted(events, key=lambda event: (event.timestamp, event.id)))
        self.challenges = _merge(self.events)

    @classmethod
    def from_events(cls, events: Iterable[Event]) -> "LocalEventState":
        return cls(events)

    def get(self, challenge_id: str) -> LocalChallengeProjection | None:
        direct = self.challenges.get(challenge_id)
        if direct is not None:
            return direct
        return next((item for item in self.challenges.values()
                     if any(event.challenge_id == challenge_id for event in item.events)), None)

    @property
    def duplicate_warnings(self) -> tuple[LocalChallengeProjection, ...]:
        return tuple(item for item in self.challenges.values() if item.duplicate_running)


def _event_key(event: Event) -> str:
    if event.challenge_key:
        return event.challenge_key
    if event.challenge_id:
        return event.challenge_id
    return "\x1f".join((event.contest, event.category or "", event.challenge or ""))


def _merge(events: tuple[Event, ...]) -> dict[str, LocalChallengeProjection]:
    grouped: dict[str, list[Event]] = {}
    for event in events:
        # Mock fixtures are useful local diagnostics but must never become a
        # local solve/flag/status in the operational read model.
        if isinstance(event.payload, dict) and event.payload.get("synthetic") is True:
            continue
        if event.challenge_key or event.challenge_id or event.challenge:
            grouped.setdefault(_event_key(event), []).append(event)
    result: dict[str, LocalChallengeProjection] = {}
    for key, history in grouped.items():
        active_attempts: dict[str, str] = {}
        candidate: str | None = None
        solved: str | None = None
        lifecycle: Event | None = None
        for event in history:
            attempt_key = event.attempt_id or f"legacy:{event.member}"
            if event.type in {"RUNNING", "WORKER_STARTED", "CLAIMED"}:
                active_attempts[attempt_key] = event.member
            elif event.type in {"WORKER_STOPPED", "FAILED"}:
                active_attempts.pop(attempt_key, None)
            elif event.type == "PAUSED":
                # PAUSED closes this node member's prior local attempt claims
                # for this one challenge.
                active_attempts = {
                    item_key: member for item_key, member in active_attempts.items()
                    if member != event.member
                }
            if event.type == "FLAG_CANDIDATE":
                candidate = _event_flag(event) or candidate
            if event.type == "SOLVED":
                solved = _event_flag(event) or solved
                active_attempts.clear()
            if event.type in {"QUEUED", "RUNNING", "STUCK", "HINTING", "PAUSED", "FAILED", "RESUMED", "SOLVED"}:
                lifecycle = event
        active = tuple(sorted(set(active_attempts.values())))
        last = history[-1]
        has_solved = any(event.type == "SOLVED" for event in history)
        status = "SOLVED" if solved is not None or has_solved else (
            "FLAG_CANDIDATE" if candidate is not None else
            "QUEUED" if lifecycle is not None and lifecycle.type == "RESUMED" else
            lifecycle.type if lifecycle is not None else last.type
        )
        # A confirmed solve wins the read model outright. Historical RUNNING
        # records remain visible in ``events``, but are not an active duplicate
        # claim after a solve.
        result[key] = LocalChallengeProjection(
            key=key, contest=last.contest, category=last.category, name=last.challenge,
            status=status, solved_flag=solved, candidate_flag=candidate,
            running_members=active, duplicate_running=not has_solved and len(active) > 1, events=tuple(history),
        )
    return result


def _event_flag(event: Event) -> str | None:
    value = event.payload.get("flag") if isinstance(event.payload, dict) else None
    return str(value) if value else None
