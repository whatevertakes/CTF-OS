"""One canonical category registry for intake, planning, and knowledge lookup."""

from __future__ import annotations


SOLVER_CATEGORIES = frozenset({"pwn", "web", "rev", "crypto", "forensics", "misc", "cloud"})

_ALIASES = {
    "binary": "pwn",
    "binary exploitation": "pwn",
    "binexp": "pwn",
    "pwnable": "pwn",
    "re": "rev",
    "reverse": "rev",
    "reversing": "rev",
    "reverse engineering": "rev",
    "cryptography": "crypto",
    "forensic": "forensics",
    "dfir": "forensics",
    "stego": "forensics",
    "steganography": "forensics",
    "osint": "misc",
}


def canonical_category(value: str | None) -> str:
    category = (value or "misc").strip().casefold().replace("_", " ").replace("-", " ")
    category = " ".join(category.split())
    return _ALIASES.get(category, category)


def canonical_solver_category(value: str | None) -> str:
    category = canonical_category(value)
    return category if category in SOLVER_CATEGORIES else "misc"
