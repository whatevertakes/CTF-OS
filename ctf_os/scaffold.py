"""Create a safe, minimal contest workspace below ``incoming/``."""

from __future__ import annotations

import unicodedata
from pathlib import Path


DEFAULT_CATEGORIES = ("pwn", "rev", "web", "forensic", "misc", "crypto")


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
        template = (
            f"# 대회명: {contest_name}\n"
            "- 날짜:\n"
            "- 플래그 형식:\n"
            "- 입력 프로필: standard\n"
            "\n"
            "<!-- 문제를 추가할 때 아래 형식을 복사하세요.\n"
            "### pwn/문제명\n"
            "- 설명: 문제 설명\n"
            "- 원격: nc example.com 31337\n"
            "-->\n"
        )
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
