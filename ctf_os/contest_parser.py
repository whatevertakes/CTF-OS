"""Parser for the human-maintained ``incoming/<contest>/contest.md`` manifest."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .models import Challenge, slugify
from .categories import canonical_category


class ContestParseError(ValueError):
    """Raised when a contest manifest is malformed or path-unsafe."""


@dataclass(frozen=True, slots=True)
class ContestManifest:
    name: str
    path: Path
    challenges: tuple[Challenge, ...]
    date: str | None = None
    flag_format: str | None = None
    flag_patterns: tuple[str, ...] = ()
    team: str | None = None

    @property
    def slug(self) -> str:
        return slugify(self.name)

    def owned_by(self, categories: Iterable[str]) -> tuple[Challenge, ...]:
        return tuple(filter_challenges(self.challenges, categories))


class ContestParser:
    def parse(self, path: str | Path) -> ContestManifest:
        return parse_contest(path)


_H1 = re.compile(r"^#\s*(?:대회명|contest(?:\s+name)?)\s*:\s*(.+?)\s*$", re.I)
_H3 = re.compile(r"^###\s+(.+?)\s*$")
_BULLET = re.compile(r"^\s*-\s*([^:：]+)\s*[:：]\s*(.*?)\s*$")


def parse_contest(path: str | Path) -> ContestManifest:
    manifest_path = Path(path)
    if manifest_path.name != "contest.md":
        raise ContestParseError("contest manifest must be named contest.md")
    if not manifest_path.is_file():
        raise ContestParseError(f"contest manifest not found: {manifest_path}")
    try:
        content = manifest_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ContestParseError("contest.md must be UTF-8") from exc
    except PermissionError as exc:
        raise ContestParseError(f"permission denied reading contest manifest: {manifest_path}") from exc
    except OSError as exc:
        raise ContestParseError(f"cannot read contest manifest {manifest_path}: {exc}") from exc

    name: str | None = None
    metadata: dict[str, list[str]] = {}
    raw_challenges: list[tuple[str, dict[str, list[str]]]] = []
    current: dict[str, list[str]] | None = None
    current_heading: str | None = None
    last_key: str | None = None
    in_challenge = False

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.rstrip()
        title = _H1.match(line)
        if title:
            if name is not None:
                raise ContestParseError("contest name appears more than once")
            name = title.group(1).strip()
            last_key = None
            continue
        heading = _H3.match(line)
        if heading:
            if current is not None and current_heading is not None:
                raw_challenges.append((current_heading, current))
            current_heading, current, last_key, in_challenge = heading.group(1), {}, None, True
            continue
        bullet = _BULLET.match(line)
        if bullet:
            target = current if in_challenge and current is not None else metadata
            key, value = _normal_key(bullet.group(1)), bullet.group(2).strip()
            target.setdefault(key, []).append(value)
            last_key = key
            continue
        if line.strip() and last_key is not None and raw_line[:1].isspace():
            target = current if in_challenge and current is not None else metadata
            target[last_key][-1] = f"{target[last_key][-1]}\n{line.strip()}".strip()
        elif line.strip():
            last_key = None

    if current is not None and current_heading is not None:
        raw_challenges.append((current_heading, current))
    if not name:
        raise ContestParseError("expected '# 대회명: <name>' heading")
    if not raw_challenges:
        raise ContestParseError("contest manifest has no '### category/name' challenges")

    flag_format = _first(metadata, "flag_format")
    patterns = _all(metadata, "flag_pattern")
    if flag_format and not patterns:
        patterns = [_format_to_pattern(flag_format)]
    challenges: list[Challenge] = []
    seen: set[tuple[str, str]] = set()
    seen_keys: dict[str, str] = {}
    seen_slugs: dict[str, str] = {}
    for heading, fields in raw_challenges:
        category, challenge_name = _parse_challenge_heading(heading)
        key = (category.casefold(), challenge_name.casefold())
        if key in seen:
            raise ContestParseError(f"duplicate challenge: {category}/{challenge_name}")
        seen.add(key)
        score_text = _first(fields, "score")
        score = _parse_score(score_text, heading) if score_text is not None else None
        challenge = Challenge(
            contest=name, category=category, name=challenge_name, score=score,
            remote=_first(fields, "remote"), description=_first(fields, "description"),
            hint=_first(fields, "hint"), flag_format=_first(fields, "flag_format") or flag_format,
            flag_pattern=_first(fields, "flag_pattern") or (patterns[0] if patterns else None),
        )
        previous = seen_keys.get(challenge.challenge_key)
        if previous is not None:
            raise ContestParseError(
                f"challenge identifier collision: {previous!r} and {heading!r} "
                f"both normalize to {challenge.challenge_key!r}"
            )
        previous = seen_slugs.get(challenge.slug)
        if previous is not None:
            raise ContestParseError(
                f"challenge workspace collision: {previous!r} and {heading!r} "
                f"both normalize to {challenge.slug!r}"
            )
        seen_keys[challenge.challenge_key] = heading
        seen_slugs[challenge.slug] = heading
        challenges.append(challenge)
    return ContestManifest(
        name=name, path=manifest_path, challenges=tuple(challenges),
        date=_first(metadata, "date"), flag_format=flag_format,
        flag_patterns=tuple(patterns), team=_first(metadata, "team"),
    )


def filter_challenges(challenges: Iterable[Challenge], owned_categories: Iterable[str]) -> list[Challenge]:
    owned = {canonical_category(category) for category in owned_categories if category.strip()}
    return [challenge for challenge in challenges if canonical_category(challenge.category) in owned]


def _normal_key(value: str) -> str:
    key = re.sub(r"\s+", " ", value.strip().casefold())
    aliases = {
        "날짜": "date", "date": "date", "팀": "team", "team": "team",
        "플래그 형식": "flag_format", "flag format": "flag_format",
        "flag_format": "flag_format", "플래그 패턴": "flag_pattern",
        "flag pattern": "flag_pattern", "flag_pattern": "flag_pattern",
        "점수": "score", "score": "score", "원격": "remote", "remote": "remote",
        "설명": "description", "description": "description", "힌트": "hint", "hint": "hint",
    }
    return aliases.get(key, key.replace(" ", "_"))


def _first(values: dict[str, list[str]], key: str) -> str | None:
    found = values.get(key, [])
    return found[0] if found and found[0] else None


def _all(values: dict[str, list[str]], key: str) -> list[str]:
    return [value for value in values.get(key, []) if value]


def _parse_challenge_heading(heading: str) -> tuple[str, str]:
    parts = heading.split("/")
    if len(parts) != 2:
        raise ContestParseError(f"challenge heading must be category/name: {heading!r}")
    category, name = (part.strip() for part in parts)
    for label, value in (("category", category), ("challenge name", name)):
        if not value or value in {".", ".."} or "\\" in value or "\x00" in value:
            raise ContestParseError(f"unsafe {label} in challenge heading: {heading!r}")
        try:
            slugify(value)
        except ValueError as exc:
            raise ContestParseError(f"unsafe {label} in challenge heading: {heading!r}") from exc
    return category, name


def _parse_score(value: str, heading: str) -> int:
    try:
        score = int(value)
    except ValueError as exc:
        raise ContestParseError(f"invalid score for {heading}: {value!r}") from exc
    if score < 0:
        raise ContestParseError(f"score cannot be negative for {heading}")
    return score


def _format_to_pattern(value: str) -> str:
    """Convert common ``SCA{...}`` format notation into a safe regex."""
    escaped = re.escape(value.strip())
    return escaped.replace(re.escape("..."), r"[^}]+")
