"""The image-backed categories understood by the race engine."""

from __future__ import annotations

import re

CATEGORIES = (
    "base", "pwn", "web", "rev", "crypto", "forensic", "misc", "osint", "ai", "cloud",
)

_ALIASES = {
    "base": "base",
    "pwn": "pwn", "binary": "pwn", "binary exploitation": "pwn",
    "web": "web", "web exploitation": "web",
    "rev": "rev", "reverse": "rev", "reversing": "rev",
    "crypto": "crypto", "cryptography": "crypto",
    "forensic": "forensic", "forensics": "forensic",
    "misc": "misc", "miscellaneous": "misc",
    "osint": "osint", "open source intelligence": "osint",
    "ai": "ai", "machine learning": "ai", "ml": "ai",
    "cloud": "cloud",
}


def canonical_category(value: str) -> str:
    key = re.sub(r"\s+", " ", re.sub(r"[_-]+", " ", value.strip().casefold()))
    try:
        return _ALIASES[key]
    except KeyError as exc:
        raise ValueError(
            f"unsupported challenge category: {value!r}; supported: {', '.join(CATEGORIES)}"
        ) from exc
