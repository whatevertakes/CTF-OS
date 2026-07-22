from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from ctf_os.contest import ChallengeSpec
from ctf_os.swarm import (
    SwarmError, confirm_native_spawn, create_worker_packet, flag_found,
    initialize_swarm, record_attack_event, record_command_after_execution,
    record_spawn_failure, replace_worker, start_max_endgame, stop_confirmed,
    submission_result, terminate_for_handoff, worker_status,
)
from ctf_os.workspace import start_fresh_attempt


START = datetime.now(timezone.utc)


def _challenge() -> ChallengeSpec:
    return ChallengeSpec(
        number=1, id="first-to-flag", category="web", name="Fast",
        workspace_name="fast", score=100, description="find the flag",
        hint="try the shortest path", remotes=("nc challenge.example 31337",),
        flag_format="DEMO{...}", flag_pattern=r"\ADEMO\{[^}]+\}\Z",
        input_profile="standard",
    )


def _run(tmp_path: Path, *, now: datetime = START) -> tuple[Path, dict]:
    root = tmp_path / "challenge"
    input_root = root / "input"
    input_root.mkdir(parents=True)
    (input_root / "app.py").write_text("print('ready')\n", encoding="utf-8")
    challenge = _challenge()
    run = start_fresh_attempt(root, challenge, "fingerprint")
    swarm = initialize_swarm(
        run, challenge=challenge,
        record={"prepared_input": str(input_root), "recommended_image": "ctf-os-sandbox:web"},
        root_session="root-thread", now=now,
    )
    return run, swarm


def _packet(run: Path, profile: str, role: str, *, mode: str = "fresh", **kwargs) -> dict:
    return create_worker_packet(
        run, model_profile=profile, role=role,
        task=f"execute {role} task", context_mode=mode, **kwargs,
    )


def _start(run: Path, packet: dict) -> None:
    confirm_native_spawn(
        run, lane_id=packet["lane_id"], native_session=f"thread-{packet['lane_id']}",
        operation_id=f"operation-{packet['lane_id']}",
    )


def test_prepare_starts_root_directly_with_no_mandatory_worker(tmp_path: Path) -> None:
    run, swarm = _run(tmp_path)

    assert swarm["workers"] == []
    assert swarm["status"] == "ACTIVE"
    assert swarm["root_lane"] == {
        "id": "root", "model_profile": "sol-xhigh", "role": "lead-attacker",
        "native_session": "root-thread", "status": "RUNNING", "coordinator_only": False,
    }
    assert swarm["root_direct_attack_required"] is True
    assert swarm["native_children_running"] == 0
    state = json.loads((run / "STATE.json").read_text())
    persisted = json.loads((run / "SWARM.json").read_text())
    assert state["status"] == "SWARM_ACTIVE" and state["active_child_width"] == 0
    assert "planned_child_width" not in state
    assert "spawn_queue" not in persisted


def test_sol_terra_luna_packets_are_easy_and_preserve_minimum_request(tmp_path: Path) -> None:
    run, _ = _run(tmp_path)
    artifact = run / "artifacts" / "probe.py"
    artifact.write_text("print('probe')\n", encoding="utf-8")

    sol = create_worker_packet(
        run, model_profile="sol-xhigh", role="fresh-path", task="find a new mechanism",
        context_mode="fresh", facts=("Root hypothesis must not leak",),
        failure_output="private failure must not leak", exact_blocker="private blocker",
    )
    terra = create_worker_packet(
        run, model_profile="terra-high", role="builder", task="build remote exploit.py",
        context_mode="directed", facts=("printf(user_input) observed", "offset candidate 8"),
        failure_command=("python", "probe.py"), failure_output="leak ended at 0x7f",
        artifact="artifacts/probe.py", exact_blocker="need stable libc base",
    )
    luna = _packet(run, "luna-high", "extractor")

    for packet, profile, role, task, mode in (
        (sol, "sol-xhigh", "fresh-path", "find a new mechanism", "fresh"),
        (terra, "terra-high", "builder", "build remote exploit.py", "directed"),
        (luna, "luna-high", "extractor", "execute extractor task", "fresh"),
    ):
        assert packet["model_profile"] == profile
        assert packet["role"] == role and packet["task"] == task
        assert packet["context_mode"] == mode
        assert packet["spawn_agent_args"]["fork_turns"] == "none"
        assert packet["worker_paths"]["input_read_only"] is True
        assert Path(packet["worker_paths"]["work"]).parent.name == packet["lane_id"]
    assert sol["agent_profile"] == "ctf_sol_xhigh"
    assert terra["agent_profile"] == "ctf_terra_high"
    assert luna["agent_profile"] == "ctf_luna_high"
    assert "directed" not in sol["challenge_context"]
    directed = terra["challenge_context"]["directed"]
    assert directed["facts"] == ["printf(user_input) observed", "offset candidate 8"]
    assert directed["actual_failure"] == {
        "command": ["python", "probe.py"], "output": "leak ended at 0x7f",
    }
    assert directed["artifact"] == "artifacts/probe.py"
    assert directed["exact_blocker"] == "need stable libc base"
    rendered = json.dumps([sol, terra, luna], sort_keys=True).casefold()
    for forbidden in ("evidence_grade", "confidence_score", "primitive_approval", "milestone_graph"):
        assert forbidden not in rendered


def test_only_native_identity_runs_and_spawn_failure_retries_once(tmp_path: Path) -> None:
    run, _ = _run(tmp_path)
    failed = _packet(run, "sol-xhigh", "alternate")
    first = record_spawn_failure(run, lane_id=failed["lane_id"], error="native start failed")
    second = record_spawn_failure(run, lane_id=failed["lane_id"], error="retry failed")
    assert first["retry_allowed"] is True and first["retry_packet"]["lane_id"] == failed["lane_id"]
    assert second["retry_allowed"] is False
    assert first["root_attack_continues"] is True

    packet = _packet(run, "terra-high", "builder")
    before = worker_status(run, now=START + timedelta(seconds=1))
    assert before["native_children_running"] == 0
    started = confirm_native_spawn(
        run, lane_id=packet["lane_id"], native_session="thread-7", operation_id="operation-7",
    )
    assert started["worker"]["status"] == "RUNNING"
    assert worker_status(run, now=START + timedelta(seconds=1))["native_children_running"] == 1


def test_root_plus_three_is_the_native_concurrency_limit(tmp_path: Path) -> None:
    run, _ = _run(tmp_path)
    packets = [
        _packet(run, "sol-xhigh", "path-a"),
        _packet(run, "terra-high", "builder"),
        _packet(run, "luna-high", "extractor"),
    ]
    for packet in packets:
        _start(run, packet)
    assert worker_status(run, now=START)["native_children_running"] == 3
    with pytest.raises(SwarmError, match="at most three"):
        _packet(run, "sol-xhigh", "path-b")


def test_stop_then_replace_with_another_profile_and_role(tmp_path: Path) -> None:
    run, _ = _run(tmp_path)
    original = _packet(run, "terra-high", "builder", mode="directed", facts=("known route",))
    _start(run, original)
    stopped = stop_confirmed(
        run, lane_id=original["lane_id"], native_session=f"thread-{original['lane_id']}",
    )
    assert stopped["status"] == "STOPPED"
    replaced = replace_worker(
        run, lane_id=original["lane_id"], model_profile="luna-high", role="batcher",
        task="repeat the request across the supplied candidates", context_mode="directed",
        reason="builder artifact is complete", facts=("request template is stable",),
        failure_command=("python", "exploit.py"), failure_output="3 of 20 completed",
    )
    assert replaced["spawn_packet"]["model_profile"] == "luna-high"
    assert replaced["spawn_packet"]["role"] == "batcher"
    _start(run, replaced["spawn_packet"])
    status = worker_status(run, now=START + timedelta(minutes=1))
    assert status["native_children_running"] == 1
    assert {row["status"] for row in status["workers"]} == {"STOPPED", "RUNNING"}


def test_compact_status_exposes_actual_output_without_semantic_role_gate(tmp_path: Path) -> None:
    run, _ = _run(tmp_path)
    packet = _packet(run, "luna-high", "mechanical")
    _start(run, packet)
    record_attack_event(
        run, lane_id=packet["lane_id"], event_type="COMMAND_EXECUTED",
        summary="normalized strings", command=["python", "normalize.py"],
        observed_output="12 unique candidates",
    )
    record_attack_event(
        run, lane_id=packet["lane_id"], event_type="USEFUL_FAILURE",
        summary="task requires protocol judgment", command=["python", "normalize.py"],
        observed_output="ambiguous field 7", next_attack="Root chooses field meaning",
    )
    row = worker_status(run, now=START + timedelta(minutes=2))["workers"][0]
    assert row["actual_command_count"] == 1
    assert row["high_value_output_count"] == 2
    assert row["last_event"]["type"] == "USEFUL_FAILURE"
    assert row["last_event"]["observed_output"] == "ambiguous field 7"


def test_attack_and_remote_events_need_no_prior_confirmation(tmp_path: Path) -> None:
    run, _ = _run(tmp_path)
    for event_type, output in (
        ("ATTACK_PATH_FOUND", "HTTP 200 admin"),
        ("EXPLOIT_ATTEMPTED", "admin panel"),
        ("REMOTE_ATTEMPT", "connected"),
    ):
        result = record_attack_event(
            run, lane_id="root", event_type=event_type,
            summary="smallest bypass payload executed", command=["python", "exploit.py"],
            observed_output=output, next_attack="mutate one header",
        )
        assert result["persisted"]
    events = (run / "ATTACK_EVENTS.jsonl").read_text()
    assert "EXPLOIT_ATTEMPTED" in events and "REMOTE_ATTEMPT" in events


def test_post_execution_log_failure_never_blocks_completed_command(tmp_path: Path, monkeypatch) -> None:
    run, _ = _run(tmp_path)

    def fail_append(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("ctf_os.swarm.append_jsonl_fsync", fail_append)
    receipt = record_command_after_execution(
        run, lane_id="root", command=["python", "exploit.py"],
        result={"returncode": 0, "stdout": "payload already ran"},
    )
    assert receipt["persisted"] is False
    assert "disk full" in receipt["record_warning"]
    assert receipt["observed_output"] == "payload already ran"


def test_sol_max_strictly_replaces_a_qualified_worker_and_is_bounded(tmp_path: Path) -> None:
    run, _ = _run(tmp_path)
    packet = _packet(run, "sol-xhigh", "hard-blocker")
    _start(run, packet)
    lane = packet["lane_id"]
    artifact = run / "workers" / lane / "artifacts" / "partial.py"
    artifact.write_text("print('partial')\n", encoding="utf-8")
    record_attack_event(
        run, lane_id=lane, event_type="ATTACK_PATH_FOUND", summary="partial ROP executes",
        command=["python", "partial.py"], artifact=str(artifact), observed_output="controlled RIP",
    )
    for output in ("chain stops at gadget A", "chain reaches gadget B"):
        record_attack_event(
            run, lane_id=lane, event_type="EXPLOIT_ATTEMPTED", summary="actual partial attack",
            command=["python", "partial.py"], observed_output=output,
        )
    record_attack_event(
        run, lane_id=lane, event_type="BLOCKER", summary="stack alignment before syscall",
        command=["python", "partial.py"], observed_output="rsp is eight bytes off",
        next_attack="insert the concrete alignment gadget at offset 5",
    )
    status = worker_status(run, now=START + timedelta(minutes=61))
    assert status["max_endgame_candidates"] == [lane]
    promoted = start_max_endgame(
        run, lane_id=lane, native_stop_session=f"thread-{lane}",
        now=START + timedelta(minutes=61),
    )
    max_packet = promoted["spawn_packet"]
    assert max_packet["model_profile"] == "sol-max"
    assert max_packet["agent_profile"] == "ctf_sol_max"
    assert max_packet["lease"]["maximum_actual_attacks"] == 2
    assert len(max_packet["challenge_context"]["directed"]["actual_attacks"]) == 2
    _start(run, max_packet)
    for count in range(2):
        record_attack_event(
            run, lane_id=max_packet["lane_id"], event_type="EXPLOIT_ATTEMPTED",
            summary="bounded endgame attack", command=["python", "final.py", str(count)],
            observed_output="still blocked",
        )
    max_row = next(
        row for row in worker_status(run, now=START + timedelta(minutes=62))["workers"]
        if row["id"] == max_packet["lane_id"]
    )
    assert max_row["status"] == "CANCEL_REQUIRED" and max_row["endgame_attacks"] == 2


def test_sol_max_rejects_environment_blockers(tmp_path: Path) -> None:
    run, _ = _run(tmp_path)
    packet = _packet(run, "terra-high", "builder")
    _start(run, packet)
    lane = packet["lane_id"]
    record_attack_event(
        run, lane_id=lane, event_type="PRIMITIVE", summary="sendable payload",
        command=["python", "solve.py"], observed_output="local response",
    )
    for _ in range(2):
        record_attack_event(
            run, lane_id=lane, event_type="REMOTE_ATTEMPT", summary="actual remote attack",
            command=["python", "solve.py", "--remote"], observed_output="connection failed",
        )
    record_attack_event(
        run, lane_id=lane, event_type="BLOCKER", summary="target down connection failure",
        observed_output="refused", next_attack="retry target",
    )
    assert worker_status(run, now=START + timedelta(minutes=61))["max_endgame_candidates"] == []
    with pytest.raises(SwarmError, match="executable partial path"):
        start_max_endgame(
            run, lane_id=lane, native_stop_session=f"thread-{lane}",
            now=START + timedelta(minutes=61),
        )


def test_first_valid_target_observed_flag_wins_and_cancels_siblings(tmp_path: Path) -> None:
    run, _ = _run(tmp_path)
    packets = [
        _packet(run, "sol-xhigh", "new-path"),
        _packet(run, "terra-high", "builder"),
        _packet(run, "luna-high", "extractor"),
    ]
    for packet in packets:
        _start(run, packet)
    winner = packets[1]["lane_id"]
    with pytest.raises(SwarmError, match="absent"):
        flag_found(
            run, lane_id=winner, candidate="DEMO{win}",
            flag_pattern=_challenge().flag_pattern, challenge_key=_challenge().key,
            command=["python", "solve.py"], observed_output="no flag", artifact=None,
            source="declared remote",
        )
    result = flag_found(
        run, lane_id=winner, candidate="DEMO{win}",
        flag_pattern=_challenge().flag_pattern, challenge_key=_challenge().key,
        command=["python", "solve.py", "--remote"],
        observed_output="service says DEMO{win}", artifact=None, source="declared remote",
    )
    assert result["display"].startswith("REMOTE FLAG OBTAINED")
    assert result["manual_submission_only"] is True
    assert {row["lane"] for row in result["cancel_queue"]} == {
        packets[0]["lane_id"], packets[2]["lane_id"],
    }
    assert json.loads((run / "STATE.json").read_text())["status"] == "SUBMISSION_RECOMMENDED"
    accepted = submission_result(run, candidate="DEMO{win}", result="accepted")
    assert {row["lane"] for row in accepted["cancel_queue"]} == {
        packet["lane_id"] for packet in packets
    }


def test_wrong_resumes_root_and_allows_a_fresh_worker_without_forcing_one(tmp_path: Path) -> None:
    run, _ = _run(tmp_path)
    packet = _packet(run, "luna-high", "extractor")
    _start(run, packet)
    flag_found(
        run, lane_id="root", candidate="DEMO{wrong}",
        flag_pattern=_challenge().flag_pattern, challenge_key=_challenge().key,
        command=["python", "solve.py"], observed_output="DEMO{wrong}",
        artifact=None, source="declared remote",
    )
    resumed = submission_result(run, candidate="DEMO{wrong}", result="wrong")
    assert resumed["worker_spawn_available"] is True
    assert "spawn_packet" not in resumed
    stop_confirmed(
        run, lane_id=packet["lane_id"], native_session=f"thread-{packet['lane_id']}",
    )
    fresh = _packet(run, "sol-xhigh", "fresh-after-wrong")
    assert fresh["context_mode"] == "fresh"


def test_hard_ninety_minute_cutoff_has_no_extension(tmp_path: Path) -> None:
    run, _ = _run(tmp_path)
    packet = _packet(run, "terra-high", "builder")
    _start(run, packet)
    cutoff = worker_status(run, now=START + timedelta(minutes=90))
    assert cutoff["status"] == "TIMED_OUT"
    assert cutoff["cutoff"]["automatic_extension"] is False
    assert Path(cutoff["cutoff"]["handoff"]).is_file()
    assert cutoff["cutoff"]["cancel_queue"] == [
        {"lane": packet["lane_id"], "native_session": f"thread-{packet['lane_id']}"},
    ]
    with pytest.raises(SwarmError, match="terminal"):
        record_attack_event(run, lane_id="root", event_type="EXPLOIT_ATTEMPTED", summary="late")


def test_manual_handoff_terminates_solve_and_returns_native_cancel_targets(tmp_path: Path) -> None:
    run, _ = _run(tmp_path)
    packet = _packet(run, "luna-high", "extractor")
    _start(run, packet)

    result = terminate_for_handoff(run)

    assert result == {
        "status": "HANDOFF",
        "cancel_queue": [{"lane": packet["lane_id"], "native_session": f"thread-{packet['lane_id']}"}],
        "automatic_continuation": False,
    }
    assert json.loads((run / "STATE.json").read_text())["status"] == "HANDOFF"
    with pytest.raises(SwarmError, match="terminal"):
        _packet(run, "sol-xhigh", "late-worker")
