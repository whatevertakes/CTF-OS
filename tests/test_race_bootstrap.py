from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from conftest import fake_sandbox, make_race
from test_blackboard_race import _receipt

import ctf_os.agent_tools.__main__ as cli
from ctf_os.blackboard import append_verified_event
from ctf_os.race import (
    RaceError,
    confirm_native_spawn,
    finish_lane_cleanup,
    load_race,
    note_command_receipt,
    reserve_lanes,
    reserve_max_endgame,
    stop_confirmed,
)


def _spec(family: str, profile: str = "sol-xhigh", mode: str = "fresh") -> dict[str, str]:
    return {
        "model_profile": profile,
        "role": "independent attacker",
        "task": f"execute {family}",
        "context_mode": mode,
        "attack_family": family,
    }


def _record_root_attack(run: Path, challenge) -> dict:
    receipt = _receipt(
        run, challenge, "root", "root attack completed",
        receipt_id="root-first-attack",
    )
    note_command_receipt(run, receipt)
    return receipt


def test_bootstrap_returns_three_private_ready_sandboxes_and_exact_native_args(repo: Path, monkeypatch) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    _record_root_attack(run, challenge)
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
    _manifest, challenge, run, _race = make_race(repo)
    with pytest.raises(RaceError, match="distinct"):
        reserve_lanes(run, [_spec("injection"), _spec("injection")])
    _record_root_attack(run, challenge)
    reserve_lanes(run, [_spec("a-family"), _spec("b-family"), _spec("c-family")])
    with pytest.raises(RaceError, match="concurrency four"):
        reserve_lanes(run, [_spec("d-family")])


def test_native_lane_is_not_running_until_root_confirms_real_thread(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    _record_root_attack(run, challenge)
    lane = reserve_lanes(run, [_spec("behavioral-differential")])[0]
    from ctf_os.race import attach_lane_sandbox
    attach_lane_sandbox(run, lane_id=lane["lane_id"], sandbox=fake_sandbox(run, challenge, lane["lane_id"]))
    assert load_race(run)["lanes"][1]["status"] == "PREPARED"
    confirmed = confirm_native_spawn(run, lane_id=lane["lane_id"], native_session="thread-123")
    assert confirmed["status"] == "RUNNING"
    assert confirmed["native_session"] == "thread-123"


def test_native_spawn_confirmation_accepts_canonical_path_after_fast_receipt(
    repo: Path,
) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    _record_root_attack(run, challenge)
    lane = reserve_lanes(run, [_spec("fast-first-command")])[0]
    from ctf_os.race import attach_lane_sandbox
    attach_lane_sandbox(
        run,
        lane_id=lane["lane_id"],
        sandbox=fake_sandbox(run, challenge, lane["lane_id"]),
    )
    note_command_receipt(
        run,
        _receipt(
            run,
            challenge,
            lane["lane_id"],
            "fast child completed",
            receipt_id="fast-child-first",
        ),
    )
    assert load_race(run)["lanes"][1]["status"] == "EXECUTING"

    confirmed = confirm_native_spawn(
        run,
        lane_id=lane["lane_id"],
        native_session="/root/lane_1",
    )
    assert confirmed["native_session"] == "/root/lane_1"
    assert confirmed["status"] == "EXECUTING"
    assert confirm_native_spawn(
        run,
        lane_id=lane["lane_id"],
        native_session="/root/lane_1",
    ) == confirmed


@pytest.mark.parametrize(
    "native_session",
    ("/root//lane_1", "/root/../lane_1", "/root/./lane_1", "/root/lane_1/"),
)
def test_native_spawn_confirmation_rejects_unsafe_canonical_paths(
    repo: Path,
    native_session: str,
) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    _record_root_attack(run, challenge)
    lane = reserve_lanes(run, [_spec("unsafe-session-path")])[0]
    from ctf_os.race import attach_lane_sandbox
    attach_lane_sandbox(
        run,
        lane_id=lane["lane_id"],
        sandbox=fake_sandbox(run, challenge, lane["lane_id"]),
    )
    with pytest.raises(RaceError, match="native session identity"):
        confirm_native_spawn(
            run,
            lane_id=lane["lane_id"],
            native_session=native_session,
        )


def test_native_stop_confirmation_cleans_private_sandbox_before_replacement(
    repo: Path, monkeypatch
) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    _record_root_attack(run, challenge)
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
    # Native interrupt results are applied only through the reconcile path's
    # internal stop+cleanup routine (no legacy race-stop-confirm subcommand).
    result = cli._stop_and_cleanup_lane(
        run, lane_id=lane["lane_id"], native_session="thread-stop", docker="docker",
    )
    assert result["lane"]["status"] == "STOPPED"
    assert result["sandbox_cleanup"]["removed"] is True
    assert cleaned == [lane["lane_id"]]


def test_native_task_name_is_unique_to_the_attempt(repo: Path, monkeypatch) -> None:
    _manifest, challenge, run, race = make_race(repo)
    _record_root_attack(run, challenge)

    def fake_create(spec, docker="docker"):
        return fake_sandbox(run, challenge, spec.lane_id, spec.image)

    monkeypatch.setattr(cli, "create", fake_create)
    result = cli._race_bootstrap(
        repo,
        argparse.Namespace(
            selector="1",
            contest="Demo CTF",
            lanes_json=json.dumps([_spec("attempt-scoped-task")]),
            lanes_file=None,
            docker="docker",
        ),
    )
    task_name = result["packets"][0]["spawn_agent_args"]["task_name"]
    normalized_attempt = race["attempt_id"].replace("-", "_").casefold()[:16]
    assert task_name == f"lane_1_{normalized_attempt}"


def test_cleanup_failure_keeps_slot_until_retry_succeeds(
    repo: Path, monkeypatch
) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    _record_root_attack(run, challenge)
    lanes = reserve_lanes(
        run,
        [_spec("old-family"), _spec("peer-family"), _spec("third-family")],
    )
    old = lanes[0]
    from ctf_os.race import attach_lane_sandbox
    attach_lane_sandbox(
        run, lane_id=old["lane_id"],
        sandbox=fake_sandbox(run, challenge, old["lane_id"]),
    )
    confirm_native_spawn(
        run, lane_id=old["lane_id"], native_session="thread-cleanup-retry"
    )
    attempts = 0

    def flaky_cleanup(metadata, docker="docker"):
        nonlocal attempts
        attempts += 1
        assert next(
            row for row in load_race(run)["lanes"]
            if row["lane_id"] == old["lane_id"]
        )["status"] == "STOPPING"
        if attempts == 1:
            raise RuntimeError("docker rm failed")
        return {
            "container": metadata["name"],
            "removed": False,
            "already_absent": True,
        }

    monkeypatch.setattr(cli, "cleanup", flaky_cleanup)

    def _stop():
        return cli._stop_and_cleanup_lane(
            run, lane_id=old["lane_id"],
            native_session="thread-cleanup-retry", docker="docker",
        )

    with pytest.raises(RuntimeError, match="docker rm failed"):
        _stop()
    failed = next(
        row for row in load_race(run)["lanes"]
        if row["lane_id"] == old["lane_id"]
    )
    assert failed["status"] == "CLEANUP_FAILED"
    assert failed["cleanup_error"] == "docker rm failed"
    with pytest.raises(RaceError, match="concurrency four"):
        reserve_lanes(run, [_spec("replacement-blocked")])

    retried = _stop()
    assert retried["lane"]["status"] == "STOPPED"
    assert retried["lane"]["cleanup_attempts"] == 2
    assert attempts == 2
    replacement = reserve_lanes(run, [_spec("replacement-allowed")])
    assert replacement[0]["status"] == "PREPARED"


def test_bootstrap_requires_durable_root_receipt_and_recovers_metric(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    with pytest.raises(RaceError, match="actual sandbox attack command"):
        reserve_lanes(run, [_spec("too-early")])

    race_path = run / "RACE.json"
    state = json.loads(race_path.read_text(encoding="utf-8"))
    state["timestamps"]["root_first_command_at"] = datetime.now(UTC).isoformat()
    race_path.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(RaceError, match="actual sandbox attack command"):
        reserve_lanes(run, [_spec("timestamp-only")])

    receipt = _receipt(
        run, challenge, "root", "durable despite metric logging failure",
        receipt_id="root-durable-only",
    )
    state = json.loads(race_path.read_text(encoding="utf-8"))
    state["timestamps"]["root_first_command_at"] = None
    race_path.write_text(json.dumps(state), encoding="utf-8")
    lanes = reserve_lanes(run, [_spec("after-real-command")])
    assert lanes[0]["status"] == "PREPARED"
    assert load_race(run)["timestamps"]["root_first_command_at"] == receipt["finished_at"]


def test_sol_max_is_one_bounded_qualified_post_minute_60_replacement(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    _record_root_attack(run, challenge)
    old = reserve_lanes(run, [_spec("initial-mechanism")])[0]
    from ctf_os.race import attach_lane_sandbox
    attach_lane_sandbox(run, lane_id=old["lane_id"], sandbox=fake_sandbox(run, challenge, old["lane_id"]))
    confirm_native_spawn(run, lane_id=old["lane_id"], native_session="thread-old")
    stop_confirmed(run, lane_id=old["lane_id"], native_session="thread-old")
    finish_lane_cleanup(run, lane_id=old["lane_id"])
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
