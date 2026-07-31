"""Shared pure primitives for bounded data-only interaction contracts.

This module deliberately contains no process, path, command, environment, or
network handling.  Pwn and category-neutral interaction contracts can share
the exact canonical transport without sharing any category-specific authority
or effect semantics.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from ctf_os.store.atomic import StrictJSONError, strict_json_loads


class InteractionDataCommonError(ValueError):
    """A canonical interaction transport rejected untrusted input."""


def canonical_ascii_json_bytes(value: object) -> bytes:
    """Return canonical ASCII JSON followed by exactly one newline."""

    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeEncodeError, ValueError) as error:
        raise InteractionDataCommonError(
            "value is outside canonical ASCII JSON"
        ) from error


def parse_canonical_ascii_json(
    payload: bytes,
    *,
    maximum_bytes: int,
    maximum_depth: int,
) -> Any:
    """Strictly parse one bounded canonical ASCII JSON document."""

    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > maximum_bytes
    ):
        raise InteractionDataCommonError("document size is invalid")
    try:
        payload.decode("ascii")
        value = strict_json_loads(
            payload,
            max_bytes=maximum_bytes,
            max_depth=maximum_depth,
        )
    except (StrictJSONError, UnicodeError, ValueError) as error:
        raise InteractionDataCommonError(
            "document is not strict ASCII JSON"
        ) from error
    if canonical_ascii_json_bytes(value) != payload:
        raise InteractionDataCommonError("document is not canonical JSON")
    return value


def translate_common_error(
    operation: Callable[[], bytes],
    error_factory: Callable[[BaseException], BaseException],
) -> bytes:
    """Translate the shared transport error into a contract-specific error."""

    try:
        return operation()
    except InteractionDataCommonError as error:
        raise error_factory(error) from error


__all__ = [
    "InteractionDataCommonError",
    "canonical_ascii_json_bytes",
    "parse_canonical_ascii_json",
    "translate_common_error",
]
