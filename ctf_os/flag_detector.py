"""Candidate-only flag extraction with conservative placeholder filtering."""

from __future__ import annotations

import re
from collections.abc import Iterable

from .models import FlagCandidate


DEFAULT_FLAG_PATTERNS = (
    r"SCA\{[^}\r\n]+\}", r"KISIA\{[^}\r\n]+\}", r"HACKTHEON\{[^}\r\n]+\}",
    r"CODEGATE\{[^}\r\n]+\}", r"SSTF\{[^}\r\n]+\}", r"HSPACE\{[^}\r\n]+\}",
    r"LAYER7\{[^}\r\n]+\}", r"FLAG\{[^}\r\n]+\}", r"CTF\{[^}\r\n]+\}",
    r"[A-Z0-9_]+\{[^}\r\n]+\}",
)

_PLACEHOLDER_WORDS = frozenset({"example", "fake", "test", "demo", "mock", "placeholder", "sample", "dummy", "todo", "flag"})


class FlagDetector:
    """Find plausible flags but never treats a match as a solved challenge."""

    def __init__(self, contest_patterns: Iterable[str] = (), *, ignore_placeholders: bool = True) -> None:
        custom = tuple(contest_patterns)
        self.contest_patterns = custom
        self.ignore_placeholders = ignore_placeholders
        self._custom = _compile_patterns(custom)
        self._default = _compile_patterns(DEFAULT_FLAG_PATTERNS)

    def detect(self, text: str) -> list[str]:
        """Return unique candidate values, trying contest patterns before defaults."""
        if not isinstance(text, str):
            raise TypeError("flag detection input must be text")
        found: list[str] = []
        seen: set[str] = set()
        for pattern in (*self._custom, *self._default):
            for match in pattern.finditer(text):
                value = match.group(0).strip()
                if value in seen or (self.ignore_placeholders and is_placeholder(value)):
                    continue
                seen.add(value)
                found.append(value)
        return found

    find_candidates = detect

    def detect_candidates(
        self, text: str, *, challenge_id: str, attempt_id: str | None = None,
        challenge_key: str | None = None, source: str | None = None, confidence: float | None = None,
    ) -> list[FlagCandidate]:
        return [FlagCandidate(
            challenge_id=challenge_id, challenge_key=challenge_key, attempt_id=attempt_id, source=source,
            confidence=confidence, value=value,
        ) for value in self.detect(text)]


def is_placeholder(value: str) -> bool:
    """Reject examples such as ``SCA{...}``, ``FLAG{fake_flag}``, and prose."""
    normalized = value.strip().casefold()
    if not normalized:
        return True
    if "..." in normalized or "…" in normalized or "<" in normalized or ">" in normalized:
        return True
    if "{" not in normalized or not normalized.endswith("}"):
        return any(token in normalized for token in ("example flag", "fake flag", "test flag", "demo flag", "placeholder"))
    content = normalized.split("{", 1)[1][:-1].strip()
    if not content:
        return True
    tokens = {token for token in re.split(r"[^a-z0-9]+", content) if token}
    return bool(tokens & _PLACEHOLDER_WORDS)


def _compile_patterns(patterns: Iterable[str]) -> tuple[re.Pattern[str], ...]:
    compiled: list[re.Pattern[str]] = []
    for raw in patterns:
        if not isinstance(raw, str) or not raw:
            raise ValueError("flag pattern must be a non-empty string")
        try:
            compiled.append(re.compile(raw))
        except re.error as exc:
            raise ValueError(f"invalid flag pattern {raw!r}: {exc}") from exc
    return tuple(compiled)
