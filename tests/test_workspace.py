from pathlib import Path

import pytest

from ctf_os.workspace import safe_under


def test_safe_under_rejects_escape_and_absolute(repo: Path) -> None:
    assert safe_under(repo / "output", Path("contest/challenge")).is_relative_to(repo / "output")
    with pytest.raises(ValueError):
        safe_under(repo / "output", Path("../secret"))
    with pytest.raises(ValueError):
        safe_under(repo / "output", Path("/tmp/secret"))
    linked = repo / "linked-output"
    linked.symlink_to(repo / "output", target_is_directory=True)
    with pytest.raises(ValueError):
        safe_under(linked, Path("contest/challenge"))
