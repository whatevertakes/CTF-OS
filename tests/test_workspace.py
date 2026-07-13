from pathlib import Path
import json
from types import SimpleNamespace

import pytest

from ctf_os.workspace import bind_input_fingerprint, safe_under


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


def test_fingerprint_change_clears_split_replay_verdict(tmp_path: Path) -> None:
    root = tmp_path / "output" / "demo" / "web" / "challenge"
    root.mkdir(parents=True)
    (root / "STATE.json").write_text(json.dumps({
        "challenge_id": "abc", "status": "VERIFICATION_REQUIRED",
        "input_fingerprint": "old", "flag_candidate": "DEMO{remote}",
        "verification": {"verdict": "REMOTE_FLAG_OBTAINED"},
        "replay_verdict": "REMOTE_FLAG_OBTAINED", "branches": [],
    }))
    challenge = SimpleNamespace(id="abc", key="web/challenge")

    bind_input_fingerprint(root, challenge, "new")

    state = json.loads((root / "STATE.json").read_text())
    assert state["status"] == "PREPARED"
    assert state["verification"] == {} and state["replay_verdict"] is None
