"""M4 (winner native-stop gating) and RM1 (idle lease interrupt) regressions."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from conftest import fake_sandbox, make_race
from test_blackboard_race import _receipt, _spec

import ctf_os.agent_tools.__main__ as cli
from ctf_os.flag import record_candidate
from ctf_os.race import (
    attach_lane_sandbox,
    confirm_native_spawn,
    finish_lane_cleanup,
    load_race,
    note_command_receipt,
    reserve_lanes,
    status,
    stop_confirmed,
)


def _spawned_child(run: Path, challenge, family: str, native_session: str) -> dict:
    child = reserve_lanes(run, [_spec(family)])[0]
    attach_lane_sandbox(
        run, lane_id=child["lane_id"], sandbox=fake_sandbox(run, challenge, child["lane_id"])
    )
    confirm_native_spawn(run, lane_id=child["lane_id"], native_session=native_session)
    return child


def test_child_winner_blocks_cleanup_until_native_stop(repo: Path, monkeypatch) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    note_command_receipt(
        run, _receipt(run, challenge, "root", "root attack", receipt_id="root-first")
    )
    child = _spawned_child(run, challenge, "winner-family", "thread-win")

    winning_receipt = _receipt(
        run, challenge, child["lane_id"], "CTF{child_win}", receipt_id="child-flag"
    )
    result = record_candidate(
        run, lane_id=child["lane_id"], attack_family=child["attack_family"],
        candidate="CTF{child_win}", receipt=winning_receipt,
    )
    assert result["first"] is True

    race = load_race(run)
    winner_lane = next(row for row in race["lanes"] if row["lane_id"] == child["lane_id"])
    # The winning child is still a live native thread: CANCEL_REQUIRED, not WON.
    assert winner_lane["status"] == "CANCEL_REQUIRED"
    assert winner_lane.get("native_stopped_at") is None
    assert race["winner"]["candidate"] == "CTF{child_win}"

    monkeypatch.setattr(cli, "cleanup", lambda metadata, docker="docker": {"removed": True})

    # Cleanup must refuse the winning child until its native stop is confirmed.
    with pytest.raises(ValueError, match="native"):
        cli._race_cleanup(repo, argparse.Namespace(run_id=run.name, docker="docker"))
    assert cli.resolve_run(repo, run.name) == run

    # After interrupt + reconcile the child reaches STOPPED and cleanup proceeds.
    stop_confirmed(run, lane_id=child["lane_id"], native_session="thread-win")
    finish_lane_cleanup(run, lane_id=child["lane_id"])
    stopped = next(
        row for row in load_race(run)["lanes"] if row["lane_id"] == child["lane_id"]
    )
    assert stopped["status"] == "STOPPED"
    assert stopped["native_stopped_at"]
    cleaned = cli._race_cleanup(repo, argparse.Namespace(run_id=run.name, docker="docker"))
    assert cleaned["active_cleared"] is True


def test_root_winner_path_is_preserved(repo: Path, monkeypatch) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    winning_receipt = _receipt(
        run, challenge, "root", "CTF{root_win}", receipt_id="root-flag"
    )
    record_candidate(
        run, lane_id="root", attack_family="root-primary",
        candidate="CTF{root_win}", receipt=winning_receipt,
    )
    race = load_race(run)
    root_lane = next(row for row in race["lanes"] if row["lane_id"] == "root")
    assert root_lane["status"] == "WON"
    assert race["status"] == "WON"

    monkeypatch.setattr(cli, "cleanup", lambda metadata, docker="docker": {"removed": True})
    cleaned = cli._race_cleanup(repo, argparse.Namespace(run_id=run.name, docker="docker"))
    assert cleaned["active_cleared"] is True


def test_idle_lane_after_one_command_becomes_stagnant_and_interruptible(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    note_command_receipt(
        run, _receipt(run, challenge, "root", "root attack", receipt_id="root-first")
    )
    child = _spawned_child(run, challenge, "idle-family", "thread-idle")
    _receipt(run, challenge, child["lane_id"], "single command output", receipt_id="only-one")

    lease = int(load_race(run)["lease_seconds"])
    future = datetime.now(UTC) + timedelta(seconds=lease + 60)
    report = status(run, now=future)

    lane_row = next(row for row in report["lanes"] if row["lane_id"] == child["lane_id"])
    assert "no-new-output-hash" in lane_row["stagnation_signals"]
    assert lane_row["status"] == "STAGNANT"
    interrupts = [
        action for action in report["native_actions"]
        if action["action"] == "INTERRUPT" and action["lane_id"] == child["lane_id"]
    ]
    assert interrupts == [
        {"action": "INTERRUPT", "lane_id": child["lane_id"], "native_session": "thread-idle"}
    ]
