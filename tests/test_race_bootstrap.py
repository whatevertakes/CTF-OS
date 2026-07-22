from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

import ctf_os.agent_tools.__main__ as cli
from ctf_os.blackboard import append_verified_event
from ctf_os.race import (
    RaceError, confirm_native_spawn, load_race, reserve_lanes, reserve_max_endgame,
    stop_confirmed,
)

from conftest import fake_sandbox, make_race


def _spec(family: str, profile: str = "sol-xhigh", mode: str = "fresh") -> dict[str, str]:
    return {
        "model_profile": profile,
        "role": "independent attacker",
        "task": f"execute {family}",
        "context_mode": mode,
        "attack_family": family,
    }


def test_bootstrap_returns_three_private_ready_sandboxes_and_exact_native_args(repo: Path, monkeypatch) -> None:
    manifest, challenge, run, _race = make_race(repo)
    specifications = [_spec("source-dataflow"), _spec("protocol-state"), _spec("parser-confusion", "terra-high", "directed")]

    def fake_create(spec, docker="docker"):
        return fake_sandbox(run, challenge, spec.lane_id, spec.image)

    monkeypatch.setattr(cli, "create", fake_create)
    args = argparse.Namespace(
        selector="1", contest="Demo CTF", lanes_json=json.dumps(specifications),
        lanes_file=None, docker="docker",
    )
    result = cli._race_bootstrap(repo, args)
    assert len(result["packets"]) == 3
    assert result["failures"] == []
    metadata_paths = {packet["worker_paths"]["metadata_path"] for packet in result["packets"]}
    assert len(metadata_paths) == 3
    for packet in result["packets"]:
        args = packet["spawn_agent_args"]
        assert set(args) == {"task_name", "agent_type", "fork_turns", "message"}
        assert args["fork_turns"] == "none"
        assert "sandbox-exec" in args["message"]
    fresh = result["packets"][0]["challenge_context"]
    directed = result["packets"][2]["challenge_context"]
    assert "verified_blackboard_delta" not in fresh
    assert directed["verified_blackboard_delta"] == []
    assert "root history" not in json.dumps(fresh).casefold()


def test_root_plus_three_is_hard_limit_and_families_must_be_distinct(repo: Path) -> None:
    _manifest, _challenge, run, _race = make_race(repo)
    with pytest.raises(RaceError, match="distinct"):
        reserve_lanes(run, [_spec("injection"), _spec("injection")])
    reserve_lanes(run, [_spec("a-family"), _spec("b-family"), _spec("c-family")])
    with pytest.raises(RaceError, match="concurrency four"):
        reserve_lanes(run, [_spec("d-family")])


def test_native_lane_is_not_running_until_root_confirms_real_thread(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    lane = reserve_lanes(run, [_spec("behavioral-differential")])[0]
    from ctf_os.race import attach_lane_sandbox
    attach_lane_sandbox(run, lane_id=lane["lane_id"], sandbox=fake_sandbox(run, challenge, lane["lane_id"]))
    assert load_race(run)["lanes"][1]["status"] == "PREPARED"
    confirmed = confirm_native_spawn(run, lane_id=lane["lane_id"], native_session="thread-123")
    assert confirmed["status"] == "RUNNING"
    assert confirmed["native_session"] == "thread-123"


def test_native_stop_confirmation_cleans_private_sandbox_before_replacement(
    repo: Path, monkeypatch
) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    lane = reserve_lanes(run, [_spec("bounded-old-family")])[0]
    from ctf_os.race import attach_lane_sandbox
    attach_lane_sandbox(
        run, lane_id=lane["lane_id"],
        sandbox=fake_sandbox(run, challenge, lane["lane_id"]),
    )
    confirm_native_spawn(run, lane_id=lane["lane_id"], native_session="thread-stop")
    cleaned: list[str] = []

    def fake_cleanup(metadata, docker="docker"):
        cleaned.append(str(metadata["lane_id"]))
        return {"container": metadata["name"], "removed": True, "already_absent": False}

    monkeypatch.setattr(cli, "cleanup", fake_cleanup)
    result = cli.dispatch(
        argparse.Namespace(
            command="race-stop-confirm", run_id=run.name, lane=lane["lane_id"],
            native_session="thread-stop", docker="docker",
        ),
        repo,
    )
    assert result["lane"]["status"] == "STOPPED"
    assert result["sandbox_cleanup"]["removed"] is True
    assert cleaned == [lane["lane_id"]]


def test_sol_max_is_one_bounded_qualified_post_minute_60_replacement(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    old = reserve_lanes(run, [_spec("initial-mechanism")])[0]
    from ctf_os.race import attach_lane_sandbox
    attach_lane_sandbox(run, lane_id=old["lane_id"], sandbox=fake_sandbox(run, challenge, old["lane_id"]))
    confirm_native_spawn(run, lane_id=old["lane_id"], native_session="thread-old")
    stop_confirmed(run, lane_id=old["lane_id"], native_session="thread-old")
    from test_blackboard_race import _receipt
    artifact = run / "workers" / "root" / "artifacts" / "partial.py"
    artifact.write_text("print('partial')\n", encoding="utf-8")
    for event_type, output, identifier, artifact_name in (
        ("WORKING_POC", "partial exploit controls state", "max-poc", "partial.py"),
        ("REMOTE_RESULT", "remote rejected stage two", "max-remote", None),
        ("EXACT_BLOCKER", "equation branch ambiguity at bit 17", "max-blocker", None),
    ):
        append_verified_event(
            run, event_type=event_type, lane_id="root", attack_family="root-primary",
            receipt=_receipt(run, challenge, "root", output, receipt_id=identifier),
            artifact=artifact_name,
        )
    with pytest.raises(RaceError, match="before minute 60"):
        reserve_max_endgame(
            run, replaced_lane_id=old["lane_id"], task="solve the bit-17 branch",
            attack_family="symbolic-endgame",
        )
    after_sixty = datetime.fromisoformat(load_race(run)["started_at"]) + timedelta(minutes=61)
    lane = reserve_max_endgame(
        run, replaced_lane_id=old["lane_id"], task="solve the bit-17 branch",
        attack_family="symbolic-endgame", now=after_sixty,
    )
    assert lane["model_profile"] == "sol-max"
    assert lane["lease_seconds"] == 600
    assert lane["max_actual_attacks"] == 2
