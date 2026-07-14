"""Plain-text problem intake and internal ``contest.md`` manifest generation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import unicodedata

from .categories import canonical_category
from .contest import ContestError, ContestManifest, parse_contest
from .workspace import atomic_text


class ProblemsError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ProblemInput:
    category: str
    name: str
    values: dict[str, tuple[str, ...]]


@dataclass(frozen=True, slots=True)
class ProblemsDocument:
    name: str | None
    metadata: dict[str, tuple[str, ...]]
    problems: tuple[ProblemInput, ...]


_GLOBAL_FIELDS = {
    "대회명": "name", "contest": "name", "contest name": "name",
    "날짜": "date", "date": "date",
    "플래그 형식": "flag_format", "flag format": "flag_format", "flag_format": "flag_format",
    "플래그 패턴": "flag_pattern", "flag pattern": "flag_pattern", "flag_pattern": "flag_pattern",
    "입력 프로필": "input_profile", "input profile": "input_profile", "input_profile": "input_profile",
}
_PROBLEM_FIELDS = {
    "점수": "score", "score": "score", "points": "score",
    "설명": "description", "description": "description", "desc": "description",
    "힌트": "hint", "hint": "hint", "hints": "hint",
    "원격": "remote", "remote": "remote", "target": "remote",
    "플래그 형식": "flag_format", "flag format": "flag_format", "flag_format": "flag_format",
    "플래그 패턴": "flag_pattern", "flag pattern": "flag_pattern", "flag_pattern": "flag_pattern",
    "입력 프로필": "input_profile", "input profile": "input_profile", "input_profile": "input_profile",
}


def problems_template(contest_name: str) -> str:
    return (
        "# 이 파일만 편집하세요. 문제는 빈 줄로 구분합니다.\n"
        f"대회명: {contest_name}\n"
        "날짜: 2026-01-01\n"
        "플래그 형식: CTF{...}\n"
        "입력 프로필: standard\n"
        "\n"
        "# 아래 예시를 복사해 #을 지운 뒤 문제 정보를 붙여 넣으세요.\n"
        "# pwn/문제명\n"
        "# 설명: 문제 원문 설명\n"
        "# 원격: nc host.example 31337\n"
        "# 원격: {\"host\":\"10.10.20.15\",\"port\":31337,\"protocol\":\"tcp\",\"organizer_declared\":true}\n"
    )


def parse_problems(path: str | Path) -> ProblemsDocument:
    source = Path(path)
    if source.name != "problems.txt" or not source.is_file() or source.is_symlink():
        raise ProblemsError(f"problems.txt not found or unsafe: {source}")
    try:
        lines = source.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ProblemsError("problems.txt must be UTF-8") from exc

    name: str | None = None
    metadata: dict[str, list[str]] = {}
    entries: list[ProblemInput] = []
    current_category: str | None = None
    current_name: str | None = None
    current_values: dict[str, list[str]] = {}

    def finish_current() -> None:
        nonlocal current_category, current_name, current_values
        if current_category is not None and current_name is not None:
            entries.append(ProblemInput(
                category=current_category, name=current_name,
                values={key: tuple(value) for key, value in current_values.items()},
            ))
        current_category, current_name, current_values = None, None, {}

    for line_number, raw in enumerate(lines, 1):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        header = _problem_header(text)
        if header is not None:
            finish_current()
            current_category, current_name = header
            continue
        key, value = _field(text)
        normalized = _normalize_key(key) if key is not None else None
        if current_category is None:
            if normalized not in _GLOBAL_FIELDS:
                raise ProblemsError(f"line {line_number}: expected contest field or category/problem name")
            field_name = _GLOBAL_FIELDS[normalized]
            if field_name == "name":
                name = value or None
            elif value:
                metadata.setdefault(field_name, []).append(value)
            continue
        if normalized in _PROBLEM_FIELDS:
            field_name = _PROBLEM_FIELDS[normalized]
            if value:
                current_values.setdefault(field_name, []).append(value)
            continue
        description = text if key is None else f"{key}: {value}".rstrip()
        _append_description(current_values, description)
    finish_current()
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        identity = (entry.category, entry.name.casefold())
        if identity in seen:
            raise ProblemsError(f"duplicate problem entry: {entry.category}/{entry.name}")
        seen.add(identity)
    return ProblemsDocument(
        name=name,
        metadata={key: tuple(value) for key, value in metadata.items()},
        problems=tuple(entries),
    )


def sync_contest_manifest(root: str | Path, selector: str | None = None) -> Path | None:
    repository = Path(root).resolve()
    incoming = repository / "incoming"
    if not incoming.is_dir() or incoming.is_symlink():
        return None
    contest_dir = _select_problem_directory(incoming, selector)
    if contest_dir is None:
        return None
    problems_path = contest_dir / "problems.txt"
    if not problems_path.is_file() or problems_path.is_symlink():
        return None

    existing = _existing_manifest(contest_dir / "contest.md")
    document = parse_problems(problems_path)
    content = render_contest_manifest(document, contest_dir.name, existing)
    manifest_path = contest_dir / "contest.md"
    if manifest_path.is_symlink():
        raise ProblemsError(f"contest.md path is unsafe: {manifest_path}")
    atomic_text(manifest_path, content)
    parse_contest(manifest_path)
    return manifest_path


def render_contest_manifest(document: ProblemsDocument, fallback_name: str, existing: ContestManifest | None = None) -> str:
    name = document.name or (existing.name if existing else fallback_name)
    if not name.strip():
        raise ProblemsError("contest name cannot be empty")
    metadata = dict(document.metadata)
    lines = [f"# 대회명: {name.strip()}", ""]
    for key, label in (
        ("date", "날짜"), ("flag_format", "플래그 형식"),
        ("flag_pattern", "플래그 패턴"), ("input_profile", "입력 프로필"),
    ):
        for value in metadata.get(key, ()):
            if value:
                lines.append(f"- {label}: {value}")
    if len(lines) > 2:
        lines.append("")
    for problem in document.problems:
        lines.append(f"### {problem.category}/{problem.name}")
        for key, label in (
            ("score", "점수"), ("description", "설명"), ("hint", "힌트"),
            ("remote", "원격"), ("flag_format", "플래그 형식"),
            ("flag_pattern", "플래그 패턴"), ("input_profile", "입력 프로필"),
        ):
            for value in problem.values.get(key, ()):
                lines.extend(_manifest_field(label, value))
        lines.append("")
    return "\n".join(lines)


def _select_problem_directory(incoming: Path, selector: str | None) -> Path | None:
    candidates = [path for path in incoming.iterdir() if path.is_dir() and not path.is_symlink()]
    with_problems = [path for path in candidates if (path / "problems.txt").is_file() and not (path / "problems.txt").is_symlink()]
    if selector is None:
        if len(with_problems) == 1:
            return with_problems[0]
        if len(with_problems) > 1:
            names = ", ".join(path.name for path in with_problems)
            raise ContestError(f"contest selection is ambiguous or missing; candidates: {names}")
        return None
    key = _normalize_key(selector)
    matches = [path for path in candidates if _normalize_key(path.name) == key]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise ContestError(f"contest selection is ambiguous or missing; candidates: {', '.join(path.name for path in matches)}")
    return None


def _existing_manifest(path: Path) -> ContestManifest | None:
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise ProblemsError(f"contest.md path is unsafe: {path}")
    try:
        return parse_contest(path)
    except ContestError:
        return None


def _problem_header(value: str) -> tuple[str, str] | None:
    if ":" in value or "：" in value or value.count("/") != 1:
        return None
    category_text, name = (part.strip() for part in value.split("/", 1))
    if not category_text or not name:
        return None
    try:
        category = canonical_category(category_text)
    except ValueError as exc:
        raise ProblemsError(str(exc)) from exc
    if name in {".", ".."} or any(character in name for character in ("/", "\\", "\0")):
        raise ProblemsError(f"unsafe problem name: {value!r}")
    return category, unicodedata.normalize("NFKC", name)


def _field(value: str) -> tuple[str | None, str]:
    match = re.match(r"^([^:：]+)\s*[:：]\s*(.*)$", value)
    return (match.group(1).strip(), match.group(2).strip()) if match else (None, value)


def _normalize_key(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().casefold())


def _manifest_field(label: str, value: str) -> list[str]:
    parts = value.splitlines() or [""]
    return [f"- {label}: {parts[0]}", *(f"  {part}" for part in parts[1:])]


def _append_description(values: dict[str, list[str]], value: str) -> None:
    descriptions = values.setdefault("description", [])
    if descriptions:
        descriptions[-1] = f"{descriptions[-1]}\n{value}"
    else:
        descriptions.append(value)
