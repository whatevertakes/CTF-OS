import json
import os
from pathlib import Path

import pytest

from ctf_os.challenge import resolve_selector
from ctf_os.contest import discover_contests
from ctf_os.intake import run_intake
from ctf_os.replay import run_replay
from conftest import write_contest


pytestmark = pytest.mark.skipif(os.environ.get("CTF_OS_LIVE_DOCKER") != "1", reason="live Docker opt-in")


def test_live_offline_replay_is_clean_independent_and_ready(repo: Path) -> None:
    write_contest(repo, "# Replay CTF\n- Flag Format: LIVE{...}\n### misc/Toy\n", "Replay CTF")
    source = repo / "incoming" / "Replay CTF" / "misc" / "Toy"
    source.mkdir(parents=True)
    (source / "input.txt").write_text("fixture")
    intake = run_intake(repo, "Replay CTF")
    record = intake["challenges"][0]
    root = Path(record["workspace_path"])
    (root / "exploit").mkdir()
    (root / "exploit" / "solve.py").write_text("print('LIVE{sandbox-replay}')\n")
    (root / "REPRODUCE.json").write_text(json.dumps({
        "schema_version": 1, "image_profile": "base", "resource_profile": "light",
        "service_required": False, "argv": ["python3", "/artifacts/exploit/solve.py"],
        "expected_flag_pattern": record["flag_pattern"], "input_fingerprint": record["source_fingerprint"],
    }))
    manifest = discover_contests(repo / "incoming")[0]
    challenge = resolve_selector(manifest.challenges, "1")

    result = run_replay(repo, manifest, challenge, record)

    assert result["flag_candidate"] == "LIVE{sandbox-replay}"
    assert result["verification"]["status"] == "READY_FOR_HUMAN_SUBMISSION"
    assert len({receipt["receipt_id"] for receipt in result["receipts"]}) == 2
    assert all(item["removed"] for item in result["cleanup"])
