from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from ctf_os.contest import ChallengeSpec
from ctf_os.swarm import (
    SwarmError, confirm_native_spawn, flag_found, initialize_swarm,
    record_attack_event, record_command_after_execution, record_spawn_failure,
    replace_lane, start_max_endgame, submission_result, swarm_status,
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


def _start_all(run: Path, swarm: dict) -> None:
    for packet in swarm["spawn_queue"]:
        confirm_native_spawn(
            run, lane_id=packet["lane"], native_session=f"thread-{packet['lane']}",
            operation_id=f"operation-{packet['lane']}",
        )


def test_prepare_returns_three_immediate_native_packets_without_gates(tmp_path: Path) -> None:
    run, swarm = _run(tmp_path)
    assert [row["lane"] for row in swarm["spawn_queue"]] == [
        "independent", "exploit-first", "tool-driven",
    ]
    assert swarm["root_lane"] == {
        "id": "root", "role": "lead-attacker", "native_session": "root-thread",
        "status": "RUNNING", "must_continue_after_spawn": True,
    }
    assert swarm["root_direct_attack_required"] is True
    assert swarm["native_children_running"] == 0
    assert json.loads((run / "STATE.json").read_text())["status"] == "SWARM_READY"
    for packet in swarm["spawn_queue"]:
        assert packet["spawn_agent_args"]["fork_turns"] == "none"
        assert packet["model_request"] == {"model": "gpt-5.6-sol", "reasoning_effort": "xhigh"}
        assert packet["context"]["challenge_files"].endswith("/input")
        assert packet["context"]["remote"] == ["nc challenge.example 31337"]
        assert packet["sandbox"]["input_read_only"] is True
        assert "Immediately use tools" in packet["spawn_agent_args"]["message"]
    independent = swarm["spawn_queue"][0]["spawn_agent_args"]["message"]
    assert "Root's analysis or hypotheses" in independent
    rendered = json.dumps(swarm, sort_keys=True).casefold()
    for forbidden in ("triage", "evidence gate", "tier", "authorization receipt"):
        assert forbidden not in rendered


def test_only_actual_native_identity_runs_and_spawn_failure_retries_once(tmp_path: Path) -> None:
    run, _ = _run(tmp_path)
    first = record_spawn_failure(run, lane_id="independent", error="native start failed")
    second = record_spawn_failure(run, lane_id="independent", error="retry failed")
    assert first["retry_allowed"] is True and first["retry_packet"]
    assert second["retry_allowed"] is False
    assert first["root_attack_continues"] is True
    started = confirm_native_spawn(
        run, lane_id="exploit-first", native_session="thread-7", operation_id="operation-7",
    )
    assert started["lane"]["status"] == "RUNNING"
    assert started["lane"]["native_start_operation_id"] == "operation-7"
    assert swarm_status(run, now=START + timedelta(seconds=1))["native_children_running"] == 1


def test_attack_path_and_remote_execute_without_confirmation_or_authorization(tmp_path: Path) -> None:
    run, swarm = _run(tmp_path)
    _start_all(run, swarm)
    path = record_attack_event(
        run, lane_id="root", event_type="ATTACK_PATH_FOUND",
        summary="auth bypass request is constructible", command=["python", "probe.py"],
        observed_output="HTTP 200 admin", next_attack="send remote payload",
    )
    strike = record_attack_event(
        run, lane_id="root", event_type="EXPLOIT_ATTEMPTED",
        summary="smallest bypass payload executed", command=["python", "exploit.py"],
        observed_output="admin panel",
    )
    remote = record_attack_event(
        run, lane_id="root", event_type="REMOTE_ATTEMPT",
        summary="payload sent to declared remote", command=["python", "exploit.py", "--remote"],
        observed_output="connected",
    )
    assert path["persisted"] and strike["persisted"] and remote["persisted"]
    events = (run / "ATTACK_EVENTS.jsonl").read_text()
    assert "ATTACK_PATH_FOUND" in events and "EXPLOIT_ATTEMPTED" in events and "REMOTE_ATTEMPT" in events
    assert "CONFIRMED" not in events and "authorization" not in events.casefold()


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


def test_first_valid_target_observed_flag_wins_and_cancels_siblings(tmp_path: Path) -> None:
    run, swarm = _run(tmp_path)
    _start_all(run, swarm)
    with pytest.raises(SwarmError, match="absent"):
        flag_found(
            run, lane_id="exploit-first", candidate="DEMO{win}",
            flag_pattern=_challenge().flag_pattern, challenge_key=_challenge().key,
            command=["python", "solve.py"], observed_output="no flag", artifact=None,
            source="declared remote",
        )
    result = flag_found(
        run, lane_id="exploit-first", candidate="DEMO{win}",
        flag_pattern=_challenge().flag_pattern, challenge_key=_challenge().key,
        command=["python", "solve.py", "--remote"],
        observed_output="service says DEMO{win}", artifact=None, source="declared remote",
    )
    assert result["display"].startswith("REMOTE FLAG OBTAINED")
    assert "Flag: DEMO{win}" in result["display"]
    assert result["manual_submission_only"] is True
    assert {row["lane"] for row in result["cancel_queue"]} == {"independent", "tool-driven"}
    assert result["stop_additional_analysis"] is True
    state = json.loads((run / "STATE.json").read_text())
    assert state["status"] == "SUBMISSION_RECOMMENDED"
    assert state["submission_recommended"] is True
    accepted = submission_result(run, candidate="DEMO{win}", result="accepted")
    assert accepted["automatic_submission"] is False


def test_wrong_candidate_requires_real_cancel_capacity_before_striker_runs(tmp_path: Path) -> None:
    run, swarm = _run(tmp_path)
    _start_all(run, swarm)
    flag_found(
        run, lane_id="root", candidate="DEMO{wrong}",
        flag_pattern=_challenge().flag_pattern, challenge_key=_challenge().key,
        command=["python", "solve.py"], observed_output="DEMO{wrong}",
        artifact=None, source="declared remote",
    )
    resumed = submission_result(run, candidate="DEMO{wrong}", result="wrong")
    striker = resumed["spawn_packet"]["lane"]
    with pytest.raises(SwarmError, match="concurrency"):
        confirm_native_spawn(run, lane_id=striker, native_session="thread-striker")
    from ctf_os.swarm import stop_confirmed
    stop_confirmed(run, lane_id="independent", native_session="thread-independent")
    started = confirm_native_spawn(run, lane_id=striker, native_session="thread-striker")
    assert started["lane"]["status"] == "RUNNING"


def test_replacement_has_no_lifetime_cap_and_keeps_full_problem_context(tmp_path: Path) -> None:
    run, swarm = _run(tmp_path)
    _start_all(run, swarm)
    first = replace_lane(
        run, lane_id="independent", replacement_role="alternate-family",
        reason="no primitive", native_stop_session="thread-independent",
        actual_failure="python probe.py -> timeout", untried_family="logic bypass",
    )
    packet = first["spawn_packet"]
    assert packet["context"]["name"] == "Fast"
    assert packet["context"]["challenge_files"].endswith("/input")
    confirm_native_spawn(run, lane_id=first["replacement_lane"], native_session="thread-alt")
    second = replace_lane(
        run, lane_id=first["replacement_lane"], replacement_role="failure-analysis",
        reason="different failure", native_stop_session="thread-alt",
        actual_failure="HTTP 403", untried_family="parser confusion",
    )
    assert first["replacement_limit"] is None and second["replacement_limit"] is None
    assert second["spawn_packet"]["context"]["remote"] == ["nc challenge.example 31337"]
    assert swarm_status(run, now=START + timedelta(minutes=1))["native_children_running"] == 2


def test_plateau_endgame_and_hard_ninety_minute_cutoff(tmp_path: Path) -> None:
    run, swarm = _run(tmp_path)
    _start_all(run, swarm)
    for event_type in ("ATTACK_PATH_FOUND", "EXPLOIT_ATTEMPTED", "EXPLOIT_ATTEMPTED", "BLOCKER"):
        record_attack_event(
            run, lane_id="exploit-first", event_type=event_type,
            summary="ROP final link" if event_type == "BLOCKER" else "partial ROP",
            command=["python", "rop.py"], observed_output="chain output",
            next_attack="connect final gadget",
        )
    plateau = swarm_status(run, now=START + timedelta(minutes=31))
    assert plateau["plateau_replacement_candidates"] == ["independent", "exploit-first"]
    endgame = swarm_status(run, now=START + timedelta(minutes=61))
    assert endgame["max_endgame_candidates"] == ["exploit-first"]
    promoted = start_max_endgame(
        run, lane_id="exploit-first", native_stop_session="thread-exploit-first",
        now=START + timedelta(minutes=61),
    )
    assert promoted["spawn_packet"]["model_request"] == {
        "model": "gpt-5.6-sol", "reasoning_effort": "max",
    }
    assert promoted["spawn_packet"]["lease"]["maximum_actual_attacks"] == 2
    max_lane = promoted["max_lane"]
    confirm_native_spawn(run, lane_id=max_lane, native_session="thread-max")
    for _ in range(2):
        record_attack_event(
            run, lane_id=max_lane, event_type="EXPLOIT_ATTEMPTED",
            summary="bounded endgame attack", command=["python", "final.py"],
            observed_output="still blocked",
        )
    max_state = json.loads((run / "SWARM.json").read_text())
    assert next(row for row in max_state["lanes"] if row["id"] == max_lane)["status"] == "CANCEL_REQUIRED"
    cutoff = swarm_status(run, now=START + timedelta(minutes=90))
    assert cutoff["status"] == "TIMED_OUT"
    assert cutoff["automatic_extension"] is False
    assert cutoff["cutoff"]["automatic_extension"] is False
    assert Path(cutoff["cutoff"]["handoff"]).is_file()
    with pytest.raises(SwarmError, match="terminal"):
        record_attack_event(run, lane_id="root", event_type="EXPLOIT_ATTEMPTED", summary="late")
