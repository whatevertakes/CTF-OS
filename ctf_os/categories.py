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
    "mobile": "mobile", "android": "mobile", "ios": "mobile",
    "osint": "osint", "open source intelligence": "osint",
    "hardware": "hardware", "hw": "hardware",
    "blockchain": "blockchain", "smart contract": "blockchain", "web3": "blockchain",
    "jail": "jail", "sandbox escape": "jail", "pyjail": "jail",
    "windows": "windows", "win": "windows",
    "ai": "ai", "machine learning": "ai", "ml": "ai",
}

_GENERIC_CATEGORIES = frozenset({"mobile", "hardware", "blockchain", "jail", "windows"})


def canonical_category(value: str) -> str:
    key = re.sub(r"[_-]+", " ", value.strip().casefold())
    key = re.sub(r"\s+", " ", key)
    if key not in _ALIASES:
        raise ValueError(f"unsupported challenge category: {value!r}")
    return _ALIASES[key]


CATEGORIES = tuple(dict.fromkeys(_ALIASES.values()))


def playbook_category(category: str) -> str:
    """Return the compact built-in playbook used for a canonical category."""
    return "misc" if category in _GENERIC_CATEGORIES else category
