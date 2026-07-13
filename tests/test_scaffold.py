from pathlib import Path

import pytest

from ctf_os.contest import parse_contest
from ctf_os.scaffold import DEFAULT_CATEGORIES, initialize_contest


def test_initialize_contest_creates_template_and_category_directories(repo: Path) -> None:
    result = initialize_contest(repo, " My CTF 2026 ")
    contest_root = repo / "incoming" / "My CTF 2026"

    assert result["manifest_created"] is True
    assert result["contest"] == "My CTF 2026"
    assert result["categories"] == list(DEFAULT_CATEGORIES)
    assert all((contest_root / category).is_dir() for category in DEFAULT_CATEGORIES)
    manifest = parse_contest(contest_root / "contest.md")
    assert manifest.name == "My CTF 2026"
    assert manifest.challenges == ()


def test_initialize_contest_is_idempotent_and_does_not_overwrite_manifest(repo: Path) -> None:
    initialize_contest(repo, "Demo Contest")
    manifest = repo / "incoming" / "Demo Contest" / "contest.md"
    manifest.write_text("user content\n", encoding="utf-8")

    result = initialize_contest(repo, "Demo Contest")

    assert result["manifest_created"] is False
    assert manifest.read_text(encoding="utf-8") == "user content\n"


@pytest.mark.parametrize("name", ["", ".", "..", "../escape", "nested/name", "nested\\name"])
def test_initialize_contest_rejects_unsafe_names(repo: Path, name: str) -> None:
    with pytest.raises(ValueError, match="safe directory name"):
        initialize_contest(repo, name)
