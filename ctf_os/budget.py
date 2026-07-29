"""Wall-clock budget helpers shared by Live, Batch, and tool execution."""

from __future__ import annotations

import math
import time
from datetime import UTC, datetime, timedelta

from ctf_os.models import Budget


class BudgetExhausted(TimeoutError):
    """The challenge's operator-issued wall-clock budget has expired."""


def deadline_utc_after(
    seconds: float,
    *,
    now_epoch: float | None = None,
) -> str:
    if (
        isinstance(seconds, bool)
        or not isinstance(seconds, (int, float))
        or not math.isfinite(float(seconds))
        or seconds <= 0
    ):
        raise ValueError("budget seconds must be positive and finite")
    now = time.time() if now_epoch is None else float(now_epoch)
    if not math.isfinite(now):
        raise ValueError("budget clock must be finite")
    try:
        deadline = datetime.fromtimestamp(now, UTC) + timedelta(
            seconds=float(seconds)
        )
    except (OverflowError, OSError, ValueError) as error:
        raise ValueError(
            "budget deadline is outside the supported datetime range"
        ) from error
    return deadline.isoformat(timespec="microseconds").replace("+00:00", "Z")


def deadline_epoch(deadline_utc: str | None) -> float | None:
    if deadline_utc is None:
        return None
    if not isinstance(deadline_utc, str) or not deadline_utc:
        raise BudgetExhausted("challenge budget deadline is invalid")
    normalized = (
        deadline_utc[:-1] + "+00:00"
        if deadline_utc.endswith("Z")
        else deadline_utc
    )
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise BudgetExhausted(
            "challenge budget deadline is invalid"
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise BudgetExhausted("challenge budget deadline must include a timezone")
    try:
        value = parsed.timestamp()
    except (OverflowError, OSError, ValueError) as error:
        raise BudgetExhausted(
            "challenge budget deadline is invalid"
        ) from error
    if not math.isfinite(value):
        raise BudgetExhausted("challenge budget deadline is invalid")
    return value


def remaining_seconds(
    budget: Budget,
    *,
    now_epoch: float | None = None,
) -> float | None:
    """Return the strictest remaining accounting/wall-clock bound."""

    candidates: list[float] = []
    if budget.allocated_seconds is not None:
        candidates.append(
            float(max(0, budget.allocated_seconds - budget.spent_seconds))
        )
    absolute = deadline_epoch(budget.deadline_utc)
    if absolute is not None:
        now = time.time() if now_epoch is None else float(now_epoch)
        if not math.isfinite(now):
            raise BudgetExhausted("challenge budget clock is invalid")
        candidates.append(max(0.0, absolute - now))
    if not candidates:
        return None
    return min(candidates)


def require_remaining_seconds(
    budget: Budget,
    *,
    now_epoch: float | None = None,
) -> float | None:
    remaining = remaining_seconds(budget, now_epoch=now_epoch)
    if remaining is not None and remaining <= 0:
        raise BudgetExhausted("challenge wall-clock budget is exhausted")
    return remaining


__all__ = [
    "BudgetExhausted",
    "deadline_epoch",
    "deadline_utc_after",
    "remaining_seconds",
    "require_remaining_seconds",
]
