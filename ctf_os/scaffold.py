"""Create a safe, minimal contest workspace below ``incoming/``."""

from __future__ import annotations

import unicodedata
from pathlib import Path

from .problems import problems_template


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

    problems = contest_root / "problems.txt"
    created_problems = False
    if problems.exists() or problems.is_symlink():
        if problems.is_symlink() or not problems.is_file():
            raise ValueError(f"problems.txt path is unsafe: {problems}")
    else:
        try:
            with problems.open("x", encoding="utf-8") as handle:
                handle.write(problems_template(contest_name))
        except FileExistsError:
            if problems.is_symlink() or not problems.is_file():
                raise ValueError(f"problems.txt path is unsafe: {problems}")
        else:
            created_problems = True

    return {
        "contest": contest_name,
        "contest_path": str(contest_root),
        "problems_path": str(problems),
        "problems_created": created_problems,
        "categories": list(DEFAULT_CATEGORIES),
        "category_paths": category_paths,
    }


def _ensure_directory(path: Path) -> None:
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_dir():
            raise ValueError(f"directory path is unsafe: {path}")
        return
    path.mkdir()
