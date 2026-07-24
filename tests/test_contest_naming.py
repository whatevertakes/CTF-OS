"""L1 regression: challenge/contest names are NFKC-normalized before validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from ctf_os.contest import (
    ContestError,
    _parse_heading,
    initialize_contest,
    parse_contest,
)

# Fullwidth / control payloads that only become dangerous after NFKC folding or
# that smuggle path separators and control characters past a naive check.
UNSAFE_NAMES = [
    "web/．．",  # fullwidth ".." -> ".."
    "web/a／b",  # fullwidth "/" -> "/"
    "web/a＼b",  # fullwidth "\" -> "\"
    "web/．．／etc",  # fullwidth "../etc"
    "web/a\rb",  # carriage return
    "web/a\nb",  # newline
    "web/a\tb",  # tab
    "web/a\x1bb",  # ESC
    "web/a\x00b",  # NUL
    "web/\u200bhidden",  # zero-width space (format char, NFKC keeps it)
    "web/.",
    "web/..",
    "web/",
]


@pytest.mark.parametrize("heading", UNSAFE_NAMES)
def test_parse_heading_rejects_unsafe(heading: str) -> None:
    with pytest.raises(ContestError):
        _parse_heading(heading)


def test_parse_heading_allows_normal_unicode() -> None:
    category, name = _parse_heading("web/Example Challenge")
    assert category == "web"
    assert name == "Example Challenge"
    # Korean and internal spaces are preserved.
    category, name = _parse_heading("crypto/한글 문제 이름")
    assert category == "crypto"
    assert name == "한글 문제 이름"


def test_parse_heading_normalizes_before_returning() -> None:
    # Fullwidth latin normalizes to a safe ASCII directory name.
    category, name = _parse_heading("web/ＡＢＣ")  # ABC fullwidth
    assert category == "web"
    assert name == "ABC"


@pytest.mark.parametrize(
    "challenge",
    ["web/．．", "web/a／b", "web/a\nb", "web/a\x00b"],
)
def test_initialize_contest_rejects_unsafe(tmp_path: Path, challenge: str) -> None:
    with pytest.raises(ContestError):
        initialize_contest(tmp_path, "Demo CTF", challenge)


def test_initialize_contest_no_traversal_directory(tmp_path: Path) -> None:
    # A fullwidth traversal must never create a directory outside the contest root.
    with pytest.raises(ContestError):
        initialize_contest(tmp_path, "Demo CTF", "web/．．／escape")
    assert not (tmp_path / "escape").exists()


def test_manifest_parse_rejects_unsafe_heading(tmp_path: Path) -> None:
    root = tmp_path / "incoming" / "Demo CTF"
    root.mkdir(parents=True)
    (root / "contest.md").write_text(
        "# Contest: Demo CTF\n- flag_pattern: \\ACTF\\{[^}\\r\\n]+\\}\\Z\n\n"
        "### web/a／..／etc\n- description: evil\n",
        encoding="utf-8",
    )
    with pytest.raises(ContestError):
        parse_contest(root / "contest.md")
