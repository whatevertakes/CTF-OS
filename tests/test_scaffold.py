from pathlib import Path

import pytest

from ctf_os.scaffold import DEFAULT_CATEGORIES, initialize_contest


def test_initialize_contest_creates_template_and_category_directories(repo: Path) -> None:
    result = initialize_contest(repo, " SCA ")
    contest_root = repo / "incoming" / "SCA"

    assert result["manifest_created"] is True
    assert result["categories"] == list(DEFAULT_CATEGORIES)
    assert all((contest_root / category).is_dir() for category in DEFAULT_CATEGORIES)
    assert (contest_root / "contest.md").read_text(encoding="utf-8").startswith("# 대회명: SCA\n")


def test_initialize_contest_is_idempotent_and_does_not_overwrite_manifest(repo: Path) -> None:
    initialize_contest(repo, "SCA")
    manifest = repo / "incoming" / "SCA" / "contest.md"
    manifest.write_text("user content\n", encoding="utf-8")

    result = initialize_contest(repo, "SCA")

    assert result["manifest_created"] is False
    assert manifest.read_text(encoding="utf-8") == "user content\n"


@pytest.mark.parametrize("name", ["", ".", "..", "../escape", "nested/name", "nested\\name"])
def test_initialize_contest_rejects_unsafe_names(repo: Path, name: str) -> None:
    with pytest.raises(ValueError, match="safe directory name"):
        initialize_contest(repo, name)
