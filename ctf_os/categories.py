from __future__ import annotations

import re

_ALIASES = {
    "pwn": "pwn", "binary": "pwn", "binary exploitation": "pwn",
    "web": "web", "web exploitation": "web",
    "rev": "rev", "reverse": "rev", "reversing": "rev",
    "crypto": "crypto", "cryptography": "crypto",
    "forensic": "forensic", "forensics": "forensic",
    "misc": "misc", "miscellaneous": "misc",
    "cloud": "cloud",
}


def canonical_category(value: str) -> str:
    key = re.sub(r"[_-]+", " ", value.strip().casefold())
    key = re.sub(r"\s+", " ", key)
    if key not in _ALIASES:
        raise ValueError(f"unsupported challenge category: {value!r}")
    return _ALIASES[key]


CATEGORIES = tuple(dict.fromkeys(_ALIASES.values()))
