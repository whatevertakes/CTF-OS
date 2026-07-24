"""Parse and select one organizer-supplied contest challenge."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import unicodedata
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path

from .categories import canonical_category


class ContestError(ValueError):
    pass


class SelectionError(ValueError):
    def __init__(self, message: str, *, candidates: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.candidates = candidates

    def payload(self) -> dict[str, object]:
        return {"error": str(self), "candidates": list(self.candidates)}


def safe_name(value: str, *, fallback: str = "item") -> str:
    normalized = unicodedata.normalize("NFKC", value).strip()
    ascii_text = unicodedata.normalize("NFKD", normalized).encode("ascii", "ignore").decode()
    slug = re.sub(r"[^A-Za-z0-9]+", "-", ascii_text).strip("-").casefold()
    digest = hashlib.sha256(normalized.casefold().encode()).hexdigest()[:8]
    return f"{slug or fallback}-{digest}"


def initialize_contest(root: str | Path, contest: str, challenge_key: str) -> dict[str, object]:
    """Create the minimal fresh-schema input location for one challenge."""
    contest_name = unicodedata.normalize("NFKC", contest).strip()
    _reject_unsafe_component(contest_name, kind="contest name", raw=contest)
    category, challenge_name = _parse_heading(challenge_key)
    incoming = Path(root).resolve() / "incoming"
    _ensure_directory(incoming)
    contest_root = incoming / contest_name
    _ensure_directory(contest_root)
    category_root = contest_root / category
    _ensure_directory(category_root)
    challenge_root = category_root / challenge_name
    _ensure_directory(challenge_root)

    manifest = contest_root / "contest.md"
    heading = f"### {category}/{challenge_name}"
    if manifest.exists() or manifest.is_symlink():
        if manifest.is_symlink() or not manifest.is_file():
            raise ContestError(f"contest manifest path is unsafe: {manifest}")
        content = manifest.read_text(encoding="utf-8")
        if heading not in {line.strip() for line in content.splitlines()}:
            suffix = "" if content.endswith("\n\n") else "\n" if content.endswith("\n") else "\n\n"
            _atomic_text(manifest, content + suffix + f"{heading}\n- 설명: \n- 원격: \n")
            challenge_added = True
        else:
            challenge_added = False
        manifest_created = False
    else:
        _atomic_text(
            manifest,
            f"# 대회명: {contest_name}\n"
            "<!-- 여기에 대회 플래그 패턴을 추가하세요. -->\n\n"
            f"{heading}\n- 설명: \n- 원격: \n",
        )
        manifest_created = True
        challenge_added = True
    return {
        "contest": contest_name,
        "challenge": f"{category}/{challenge_name}",
        "contest_path": str(contest_root),
        "challenge_path": str(challenge_root),
        "manifest_path": str(manifest),
        "manifest_created": manifest_created,
        "challenge_added": challenge_added,
    }


def _ensure_directory(path: Path) -> None:
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_dir():
            raise ContestError(f"directory path is unsafe: {path}")
        return
    path.mkdir(mode=0o700)


def _atomic_text(path: Path, content: str) -> None:
    if path.is_symlink():
        raise ContestError(f"contest manifest path is unsafe: {path}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


@dataclass(frozen=True, slots=True)
class ManifestWarning:
    line: int
    scope: str
    field: str
    severity: str
    message: str
    suggestion: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "line": self.line, "scope": self.scope, "field": self.field,
            "severity": self.severity, "message": self.message,
            "suggestion": self.suggestion,
        }


@dataclass(frozen=True, slots=True)
class ChallengeSpec:
    number: int
    id: str
    category: str
    name: str
    workspace_name: str
    score: int | None
    description: str | None
    hint: str | None
    remotes: tuple[str, ...]
    flag_format: str | None
    flag_pattern: str | None
    input_profile: str
    warnings: tuple[ManifestWarning, ...] = ()

    @property
    def key(self) -> str:
        return f"{self.category}/{self.name}"

    def to_dict(self) -> dict[str, object]:
        return {
            "number": self.number, "id": self.id, "selector": f"{self.number:02d}",
            "category": self.category, "name": self.name, "key": self.key,
            "workspace_name": self.workspace_name, "score": self.score,
            "description": self.description, "hint": self.hint,
            "remotes": list(self.remotes), "flag_format": self.flag_format,
            "flag_pattern": self.flag_pattern,
            "input_profile": self.input_profile,
            "warnings": [warning.to_dict() for warning in self.warnings],
        }


@dataclass(frozen=True, slots=True)
class ContestManifest:
    name: str
    slug: str
    path: Path
    date: str | None
    flag_format: str | None
    flag_pattern: str | None
    input_profile: str
    challenges: tuple[ChallengeSpec, ...]
    warnings: tuple[ManifestWarning, ...] = ()

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name, "slug": self.slug, "date": self.date,
            "flag_format": self.flag_format, "flag_pattern": self.flag_pattern,
            "input_profile": self.input_profile,
            "manifest_path": str(self.path), "manifest_sha256": self.fingerprint,
            "challenges": [challenge.to_dict() for challenge in self.challenges],
            "warnings": [warning.to_dict() for warning in self.warnings],
        }


_TITLE = re.compile(r"^#\s*(?:(?:대회명|contest(?:\s+name)?)\s*[:：]\s*)?(.+?)\s*$", re.IGNORECASE)
_H3 = re.compile(r"^###\s+(.+?)\s*$")
_FIELD = re.compile(r"^\s*-\s*([^:：]+)\s*[:：]\s*(.*?)\s*$")
_ALIASES = {
    "날짜": "date", "date": "date",
    "플래그 형식": "flag_format", "flag format": "flag_format", "flag_format": "flag_format",
    "플래그 패턴": "flag_pattern", "flag pattern": "flag_pattern", "flag_pattern": "flag_pattern",
    "점수": "score", "score": "score", "points": "score",
    "설명": "description", "description": "description", "desc": "description",
    "힌트": "hint", "hints": "hint", "hint": "hint",
    "원격": "remote", "remote": "remote", "target": "remote",
    "입력 프로필": "input_profile", "input profile": "input_profile", "input_profile": "input_profile",
}
_INPUT_PROFILES = frozenset({"standard", "large", "large-forensic"})
_SUGGESTION_FIELDS = {
    "date": "date", "score": "score", "description": "description", "desc": "description",
    "hint": "hint", "remote": "remote", "target": "remote",
    "flag": "flag_format", "flag format": "flag_format", "flag pattern": "flag_pattern",
    "input profile": "input_profile",
}
_HIGH_VALUE_FIELDS = frozenset({"remote", "description", "flag_format", "flag_pattern"})


def parse_contest(path: str | Path) -> ContestManifest:
    manifest_path = Path(path)
    if manifest_path.name != "contest.md" or not manifest_path.is_file() or manifest_path.is_symlink():
        raise ContestError(f"contest manifest not found or unsafe: {manifest_path}")
    try:
        lines = manifest_path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ContestError("contest.md must be UTF-8") from exc

    name: str | None = None
    metadata: dict[str, list[str]] = {}
    entries: list[tuple[str, dict[str, list[str]], list[ManifestWarning]]] = []
    heading: str | None = None
    fields: dict[str, list[str]] | None = None
    warnings: list[ManifestWarning] = []
    field_warnings: list[ManifestWarning] | None = None
    last_key: str | None = None
    in_html_comment = False
    code_fence: tuple[str, int] | None = None

    for line_number, raw in enumerate(lines, 1):
        stripped = raw.lstrip()
        if in_html_comment:
            if "-->" in raw:
                in_html_comment = False
            continue
        if code_fence:
            fence_character, fence_length = code_fence
            if stripped.startswith(fence_character * fence_length):
                code_fence = None
            continue
        if stripped.startswith("<!--"):
            last_key = None
            if "-->" not in stripped:
                in_html_comment = True
            continue
        fence = re.match(r"^(`{3,}|~{3,})", stripped)
        if fence:
            last_key = None
            marker = fence.group(1)
            code_fence = (marker[0], len(marker))
            continue
        if name is None:
            match = _TITLE.match(raw)
            if match:
                name = match.group(1).strip()
                continue
        h3 = _H3.match(raw)
        if h3 and "/" in h3.group(1):
            if heading is not None and fields is not None:
                entries.append((heading, fields, field_warnings or []))
            heading, fields, field_warnings, last_key = h3.group(1).strip(), {}, [], None
            continue
        field = _FIELD.match(raw)
        if field:
            raw_key = field.group(1).strip()
            normalized_key = _normalize_key(raw_key)
            key = _ALIASES.get(normalized_key)
            if key is None:
                warning = _unknown_field_warning(
                    raw_key, normalized_key, line_number,
                    heading or "contest",
                )
                (field_warnings if field_warnings is not None else warnings).append(warning)
                last_key = None
                continue
            target = fields if fields is not None else metadata
            target.setdefault(key, []).append(field.group(2).strip())
            last_key = key
            continue
        if raw.strip() and raw[:1].isspace() and last_key:
            target = fields if fields is not None else metadata
            target[last_key][-1] = (target[last_key][-1] + "\n" + raw.strip()).strip()
        elif raw.strip():
            last_key = None
    if heading is not None and fields is not None:
        entries.append((heading, fields, field_warnings or []))
    if not name:
        raise ContestError("expected '# 대회명: <name>' or '# Contest: <name>'")
    contest_flag = _first(metadata, "flag_format")
    contest_pattern = _first(metadata, "flag_pattern") or (_format_pattern(contest_flag) if contest_flag else None)
    contest_input_profile = _input_profile(_first(metadata, "input_profile"), "contest")
    challenges: list[ChallengeSpec] = []
    identities: dict[tuple[str, str], str] = {}
    workspaces: dict[tuple[str, str], str] = {}
    for number, (raw_heading, values, entry_warnings) in enumerate(entries, 1):
        category, challenge_name = _parse_heading(raw_heading)
        normalized_name = unicodedata.normalize("NFKC", challenge_name).casefold()
        identity = (category, normalized_name)
        if identity in identities:
            raise ContestError(f"duplicate challenge: {raw_heading!r} conflicts with {identities[identity]!r}")
        identities[identity] = raw_heading
        workspace_name = safe_name(challenge_name, fallback="challenge")
        workspace_key = (category, workspace_name.casefold())
        if workspace_key in workspaces:
            raise ContestError(f"workspace collision: {raw_heading!r} conflicts with {workspaces[workspace_key]!r}")
        workspaces[workspace_key] = raw_heading
        stable_source = json.dumps([unicodedata.normalize("NFKC", name).casefold(), category, normalized_name], ensure_ascii=False)
        challenge_id = hashlib.sha256(stable_source.encode()).hexdigest()[:16]
        score_text = _first(values, "score")
        try:
            score = int(score_text) if score_text not in {None, ""} else None
        except ValueError as exc:
            raise ContestError(f"invalid score for {raw_heading}: {score_text!r}") from exc
        if score is not None and score < 0:
            raise ContestError(f"score cannot be negative for {raw_heading}")
        flag_format = _first(values, "flag_format") or contest_flag
        flag_pattern = _first(values, "flag_pattern") or (_format_pattern(flag_format) if flag_format else contest_pattern)
        input_profile = _input_profile(_first(values, "input_profile"), raw_heading, default=contest_input_profile)
        challenges.append(ChallengeSpec(
            number=number, id=challenge_id, category=category, name=challenge_name,
            workspace_name=workspace_name, score=score,
            description=_first(values, "description"), hint=_first(values, "hint"),
            remotes=tuple(value for value in values.get("remote", []) if value),
            flag_format=flag_format, flag_pattern=flag_pattern,
            input_profile=input_profile, warnings=tuple(entry_warnings),
        ))
    return ContestManifest(
        name=name, slug=safe_name(name, fallback="contest"), path=manifest_path.resolve(),
        date=_first(metadata, "date"), flag_format=contest_flag,
        flag_pattern=contest_pattern, input_profile=contest_input_profile,
        challenges=tuple(challenges), warnings=tuple(warnings),
    )


def discover_contests(root: str | Path) -> tuple[ContestManifest, ...]:
    incoming_raw = Path(root)
    # Reject a symlinked incoming root before resolving it: resolve() would follow
    # the link silently and let an attacker select manifests/input from outside
    # the repository.
    if incoming_raw.is_symlink():
        raise ContestError(f"incoming path must not be a symlink: {incoming_raw}")
    incoming = incoming_raw.resolve()
    if not incoming.is_dir():
        return ()
    manifests: list[ContestManifest] = []
    for child in sorted(incoming.iterdir(), key=lambda p: p.name.casefold()):
        candidate = child / "contest.md"
        if child.is_dir() and not child.is_symlink() and candidate.is_file() and not candidate.is_symlink():
            manifests.append(parse_contest(candidate))
    return tuple(manifests)


def select_contest(contests: tuple[ContestManifest, ...], selector: str | None) -> ContestManifest:
    if selector:
        key = unicodedata.normalize("NFKC", selector).strip().casefold()
        matches = [c for c in contests if key in {c.name.casefold(), c.path.parent.name.casefold(), c.slug.casefold()}]
    else:
        matches = list(contests)
    if len(matches) == 1:
        return matches[0]
    candidates = ", ".join(c.name for c in (matches or contests)) or "none"
    raise ContestError(f"contest selection is ambiguous or missing; candidates: {candidates}")


def resolve_selector(challenges: tuple[ChallengeSpec, ...], selector: str) -> ChallengeSpec:
    if "\n" in selector or "\r" in selector:
        raise SelectionError("challenge selector must be one exact line")
    raw = unicodedata.normalize("NFKC", selector).strip()
    number = re.fullmatch(r"0*([1-9][0-9]*)\s*(?:번(?:\s*문제)?)?", raw)
    if number:
        wanted = int(number.group(1))
        matches = [challenge for challenge in challenges if challenge.number == wanted]
    else:
        folded = raw.casefold()
        exact = [
            challenge for challenge in challenges
            if challenge.key.casefold() == folded or challenge.id.casefold() == folded
        ]
        matches = exact or [challenge for challenge in challenges if challenge.name.casefold() == folded]
    if len(matches) == 1:
        return matches[0]
    candidates = tuple(f"{challenge.number:02d} {challenge.key}" for challenge in (matches or challenges))
    if not matches:
        raise SelectionError(f"challenge selector did not match: {selector!r}", candidates=candidates)
    raise SelectionError(f"ambiguous challenge selector: {selector!r}", candidates=candidates)


def _normalize_key(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().casefold())


def _first(values: dict[str, list[str]], key: str) -> str | None:
    for value in values.get(key, []):
        if value:
            return value
    return None


def _input_profile(value: str | None, scope: str, *, default: str = "standard") -> str:
    if value in {None, ""}:
        return default
    normalized = value.strip().casefold().replace("_", "-")
    if normalized not in _INPUT_PROFILES:
        allowed = ", ".join(sorted(_INPUT_PROFILES))
        raise ContestError(f"invalid input profile for {scope}: {value!r}; allowed: {allowed}")
    return normalized


def _unknown_field_warning(raw: str, normalized: str, line: int, scope: str) -> ManifestWarning:
    ranked = sorted(
        ((SequenceMatcher(None, normalized, candidate).ratio(), candidate, canonical)
         for candidate, canonical in _SUGGESTION_FIELDS.items()),
        reverse=True,
    )
    score, _candidate, canonical = ranked[0]
    suggestion = canonical if score >= 0.68 else None
    severity = "HIGH" if suggestion in _HIGH_VALUE_FIELDS else "WARNING"
    message = f"unknown contest.md field {raw!r}"
    if suggestion:
        message += f"; did you mean {suggestion!r}?"
    return ManifestWarning(
        line=line, scope=scope, field=raw, severity=severity,
        message=message, suggestion=suggestion,
    )


def _reject_unsafe_component(value: str, *, kind: str, raw: str) -> None:
    """Fail closed on any name that is not one safe directory component.

    The value must already be NFKC-normalized so that fullwidth or otherwise
    compatibility-equivalent separators (．． ／ ＼) have folded to their ASCII
    form before this check runs.
    """
    if not value or value in {".", ".."}:
        raise ContestError(f"unsafe {kind}: {raw!r}")
    for character in value:
        # Explicit path separators plus Unicode control (Cc, includes NUL, CR,
        # LF, tab, ESC), format (Cf, includes zero-width joiners), and surrogate
        # (Cs) characters can never appear in a safe single directory name.
        if character in ("/", "\\", "\0") or unicodedata.category(character) in {"Cc", "Cf", "Cs"}:
            raise ContestError(f"unsafe {kind}: {raw!r}")


def _parse_heading(value: str) -> tuple[str, str]:
    # Normalize the whole heading first so compatibility separators fold into
    # ASCII before we split or validate; validating raw text would let ／ and
    # ．． slip past and only become dangerous after a later normalization.
    normalized = unicodedata.normalize("NFKC", value)
    parts = normalized.split("/", 1)
    if len(parts) != 2:
        raise ContestError(f"challenge heading must be category/name: {value!r}")
    category_text, name = (part.strip() for part in parts)
    _reject_unsafe_component(name, kind="challenge name", raw=value)
    try:
        category = canonical_category(category_text)
    except ValueError as exc:
        raise ContestError(str(exc)) from exc
    return category, name


def _format_pattern(value: str) -> str:
    escaped = re.escape(value.strip()).replace(re.escape("..."), r"[^}\r\n]+")
    return rf"\A{escaped}\Z"
