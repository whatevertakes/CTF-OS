"""Create a safe, minimal contest workspace below ``incoming/``."""

from __future__ import annotations

import unicodedata
from pathlib import Path


DEFAULT_CATEGORIES = ("pwn", "rev", "web", "forensic", "misc", "crypto")
_SLOT_COUNT = 4


def initialize_contest(root: Path, name: str) -> dict[str, object]:
    contest_name = unicodedata.normalize("NFKC", name).strip()
    if (
        not contest_name
        or contest_name in {".", ".."}
        or any(character in contest_name for character in ("/", "\\", "\0"))
    ):
        raise ValueError("contest name must be a single safe directory name")

    incoming = root / "incoming"
    _ensure_directory(incoming)
    contest_root = incoming / contest_name
    _ensure_directory(contest_root)

    category_paths: list[str] = []
    for category in DEFAULT_CATEGORIES:
        category_path = contest_root / category
        _ensure_directory(category_path)
        category_paths.append(str(category_path))

    manifest = contest_root / "contest.md"
    created_manifest = False
    if manifest.exists() or manifest.is_symlink():
        if manifest.is_symlink() or not manifest.is_file():
            raise ValueError(f"contest manifest path is unsafe: {manifest}")
    else:
        template = _contest_template(contest_name)
        try:
            with manifest.open("x", encoding="utf-8") as handle:
                handle.write(template)
        except FileExistsError:
            if manifest.is_symlink() or not manifest.is_file():
                raise ValueError(f"contest manifest path is unsafe: {manifest}")
        else:
            created_manifest = True

    return {
        "contest": contest_name,
        "contest_path": str(contest_root),
        "manifest_path": str(manifest),
        "manifest_created": created_manifest,
        "categories": list(DEFAULT_CATEGORIES),
        "category_paths": category_paths,
    }


def _ensure_directory(path: Path) -> None:
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_dir():
            raise ValueError(f"directory path is unsafe: {path}")
        return
    path.mkdir()


def _contest_template(contest_name: str) -> str:
    lines = [
        f"# 대회명: {contest_name}",
        "",
        "- 날짜: 2026-01-01",
        "- 플래그 형식: CTF{...}",
        "- 입력 프로필: standard",
        "",
        "## 문제 등록 카드",
        "",
        "날짜와 플래그 형식은 실제 값으로 바꾸세요. 아래 카드를 복사해 이 문서의 원하는 위치에 붙여 넣으면 됩니다.",
        "문제 파일은 incoming/<대회명>/<카테고리>/<문제명>/ 아래에 둡니다.",
        "원격이 없는 문제는 '- 원격:' 줄을 삭제하세요.",
        "",
    ]
    for category in DEFAULT_CATEGORIES:
        lines.extend([f"### {category} 등록 카드", "", "```markdown"])
        for number in range(1, _SLOT_COUNT + 1):
            lines.extend([
                f"### {category}/문제명-{number}",
                "- 설명: 문제 원문 설명",
                "- 원격: nc host.example 31337",
                "",
            ])
        lines.extend(["```", ""])
    lines.extend([
        "### 추가 문제 복사용 카드",
        "",
        "```markdown",
        "### 카테고리/문제명",
        "- 설명: 문제 원문 설명",
        "- 원격: nc host.example 31337",
        "```",
        "",
    ])
    return "\n".join(lines)
