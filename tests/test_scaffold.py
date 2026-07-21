from pathlib import Path

import pytest

from ctf_os.contest import parse_contest
from ctf_os.problems import parse_problems, sync_contest_manifest
from ctf_os.scaffold import DEFAULT_CATEGORIES, initialize_contest


def test_initialize_contest_creates_template_and_category_directories(repo: Path) -> None:
    result = initialize_contest(repo, " My CTF 2026 ")
    contest_root = repo / "incoming" / "My CTF 2026"

    assert result["problems_created"] is True
    assert result["contest"] == "My CTF 2026"
    assert result["categories"] == list(DEFAULT_CATEGORIES)
    assert all((contest_root / category).is_dir() for category in DEFAULT_CATEGORIES)
    problems = contest_root / "problems.txt"
    document = parse_problems(problems)
    assert document.name == "My CTF 2026"
    assert document.problems == ()
    assert "# pwn/문제명" in problems.read_text(encoding="utf-8")
    manifest = sync_contest_manifest(repo, "My CTF 2026")
    assert manifest == contest_root / "contest.md"
    assert parse_contest(manifest).challenges == ()


def test_initialize_contest_creates_a_missing_incoming_directory(tmp_path: Path) -> None:
    result = initialize_contest(tmp_path, "Fresh Contest")

    assert result["contest_path"] == str(tmp_path / "incoming" / "Fresh Contest")
    assert (tmp_path / "incoming" / "Fresh Contest" / "problems.txt").is_file()


def test_initialize_contest_is_idempotent_and_does_not_overwrite_manifest(repo: Path) -> None:
    initialize_contest(repo, "Demo Contest")
    problems = repo / "incoming" / "Demo Contest" / "problems.txt"
    problems.write_text("user content\n", encoding="utf-8")

    result = initialize_contest(repo, "Demo Contest")

    assert result["problems_created"] is False
    assert problems.read_text(encoding="utf-8") == "user content\n"


@pytest.mark.parametrize("name", ["", ".", "..", "../escape", "nested/name", "nested\\name"])
def test_initialize_contest_rejects_unsafe_names(repo: Path, name: str) -> None:
    with pytest.raises(ValueError, match="safe directory name"):
        initialize_contest(repo, name)
