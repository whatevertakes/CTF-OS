"""Shared trust-boundary rules for possible flag values."""

from __future__ import annotations

CANDIDATE_VALUE_MAX_CHARS = 1024
CANDIDATE_VALUE_MAX_BYTES = 4096


class FlagNotificationError(RuntimeError):
    """A detected candidate could not be durably and visibly reported."""


def flag_notification_error(error: Exception) -> FlagNotificationError:
    detail = str(error)[:1024]
    return FlagNotificationError(
        "flag candidate notification failed: "
        f"{type(error).__name__}: {detail}"
    )


def candidate_value_is_valid(value: object) -> bool:
    """Return whether a value is safe to persist as a flag candidate."""

    if not isinstance(value, str):
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return bool(
        value
        and len(value) <= CANDIDATE_VALUE_MAX_CHARS
        and len(encoded) <= CANDIDATE_VALUE_MAX_BYTES
        and all(character.isprintable() for character in value)
    )
