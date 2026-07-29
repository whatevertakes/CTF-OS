"""Safe challenge/contest flag-format selection and candidate tiering."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from ctf_os.models import CandidateTier, ChallengeState


class FlagFormatError(ValueError):
    pass


@dataclass(frozen=True)
class FlagFormatPolicy:
    patterns: tuple[str, ...]
    tier: CandidateTier
    source: str
    configuration_epoch: int

    def matches(self, value: str) -> bool:
        return any(re.fullmatch(pattern, value) for pattern in self.patterns)

    def tier_for(self, value: str) -> CandidateTier:
        if self.matches(value):
            return self.tier
        return CandidateTier.GENERIC


def _prefix_brace_pattern(value: Mapping[str, Any]) -> str:
    prefix = value.get("prefix")
    if (
        not isinstance(prefix, str)
        or not 1 <= len(prefix) <= 64
        or not re.fullmatch(r"[A-Za-z0-9_.:-]+", prefix)
    ):
        raise FlagFormatError(
            "flag format prefix must be 1..64 safe ASCII characters"
        )
    minimum = value.get("min_inner", 1)
    maximum = value.get("max_inner", 512)
    if (
        isinstance(minimum, bool)
        or isinstance(maximum, bool)
        or not isinstance(minimum, int)
        or not isinstance(maximum, int)
        or not 1 <= minimum <= maximum <= 512
    ):
        raise FlagFormatError(
            "flag format inner bounds must satisfy 1 <= min <= max <= 512"
        )
    alphabet = value.get("alphabet", "printable")
    classes = {
        "printable": r"[^{}\r\n]",
        "alnum_": r"[A-Za-z0-9_]",
        "hex": r"[0-9A-Fa-f]",
        "base64url": r"[A-Za-z0-9_-]",
    }
    if alphabet not in classes:
        raise FlagFormatError(
            "flag format alphabet must be printable, alnum_, hex, or base64url"
        )
    return (
        rf"{re.escape(prefix)}\{{"
        rf"{classes[str(alphabet)]}{{{minimum},{maximum}}}"
        rf"\}}"
    )


def _format_patterns(value: object) -> tuple[str, ...] | None:
    if value is None:
        return None
    records = value if isinstance(value, list) else [value]
    patterns: list[str] = []
    for record in records:
        if not isinstance(record, Mapping):
            raise FlagFormatError(
                "flag format must be a prefix-brace object or array"
            )
        if str(record.get("kind", "prefix_brace")) != "prefix_brace":
            raise FlagFormatError("only the prefix_brace flag DSL is supported")
        patterns.append(_prefix_brace_pattern(record))
    return tuple(patterns)


def validate_flag_format(value: object) -> None:
    """Validate the safe prefix-brace DSL without compiling free-form input."""

    if _format_patterns(value) is None:
        raise FlagFormatError("flag format must not be null")


def resolve_flag_format(
    state: ChallengeState,
    runtime_patterns: Sequence[str],
) -> FlagFormatPolicy:
    """Resolve challenge > contest > runtime without using descriptions."""

    challenge_value = state.metadata.get("challenge_flag_format")
    contest_value = state.metadata.get("contest_flag_format")
    patterns = _format_patterns(challenge_value)
    if patterns:
        return FlagFormatPolicy(
            patterns,
            CandidateTier.EXACT,
            "challenge",
            state.configuration_epoch,
        )
    patterns = _format_patterns(contest_value)
    if patterns:
        return FlagFormatPolicy(
            patterns,
            CandidateTier.CONTEST,
            "contest",
            state.configuration_epoch,
        )
    compiled = tuple(str(pattern) for pattern in runtime_patterns)
    for pattern in compiled:
        re.compile(pattern)
    return FlagFormatPolicy(
        compiled,
        CandidateTier.GENERIC,
        "runtime",
        state.configuration_epoch,
    )


__all__ = [
    "FlagFormatError",
    "FlagFormatPolicy",
    "resolve_flag_format",
    "validate_flag_format",
]
