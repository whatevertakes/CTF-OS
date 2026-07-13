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
    template = (contest_root / "contest.md").read_text(encoding="utf-8")
    assert "# 대회명: My CTF 2026\n\n- 날짜: 2026-01-01" in template
    assert "- 플래그 형식: CTF{...}" in template
    assert "```markdown" in template
    for category in DEFAULT_CATEGORIES:
        for number in range(1, 5):
            assert f"### {category}/문제명-{number}" in template
    assert "### 카테고리/문제명" in template


def test_initialize_contest_creates_a_missing_incoming_directory(tmp_path: Path) -> None:
    result = initialize_contest(tmp_path, "Fresh Contest")

    assert result["contest_path"] == str(tmp_path / "incoming" / "Fresh Contest")
    assert (tmp_path / "incoming" / "Fresh Contest" / "contest.md").is_file()


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
