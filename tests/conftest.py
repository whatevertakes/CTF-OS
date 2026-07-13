from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "incoming").mkdir()
    (tmp_path / "output").mkdir()
    return tmp_path


def write_contest(repo: Path, text: str, name: str = "Demo CTF") -> Path:
    root = repo / "incoming" / name
    root.mkdir(parents=True)
    path = root / "contest.md"
    path.write_text(text, encoding="utf-8")
    return path
