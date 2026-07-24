from __future__ import annotations

from pathlib import Path

import pytest
from conftest import fake_sandbox, make_race
from test_blackboard_race import _receipt, _spec

from ctf_os.flag import FlagError, StreamingDetector, record_candidate, valid_candidate
from ctf_os.race import (
    RaceError,
    attach_lane_sandbox,
    confirm_native_spawn,
    finish_lane_cleanup,
    load_race,
    note_command_receipt,
    reserve_lanes,
    stop_confirmed,
    terminate,
)


def test_streaming_detector_handles_chunk_boundaries_and_rejects_placeholders() -> None:
    detector = StreamingDetector(r"\ACTF\{[^}\r\n]+\}\Z")
    assert detector.feed("noise CTF{rea") is None
    assert detector.feed("l_flag} trailing") == "CTF{real_flag}"
    assert not valid_candidate("CTF{example_flag}", r"\ACTF\{[^}]+\}\Z")
    assert not valid_candidate("OTHER{x}", r"\ACTF\{[^}]+\}\Z")


def test_placeholder_detection_does_not_reject_words_containing_test() -> None:
    pattern = r"\AACTF\{[^}\r\n]+\}\Z"

    assert valid_candidate("ACTF{contest_winner}", pattern)
    assert valid_candidate("ACTF{latest_solution}", pattern)
    assert not valid_candidate("ACTF{test}", pattern)
    assert not valid_candidate("ACTF{example_flag}", pattern)


def test_streaming_detector_returns_chronologically_first_matching_token() -> None:
    detector = StreamingDetector(r"(?:ABC|CTF\{x\})")
    assert detector.feed("ABC CTF{x}") == "ABC"


def test_adversarial_flag_regex_is_time_bounded() -> None:
    assert valid_candidate("a" * 1023 + "!", r"(a+)+$") is False


def test_first_target_observed_candidate_wins_atomically_and_returns_sibling_cancel_targets(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    note_command_receipt(
        run,
        _receipt(run, challenge, "root", "root attack", receipt_id="root-before-lanes"),
    )
    lanes = reserve_lanes(run, [_spec("source-dataflow"), _spec("protocol-state")])
    for index, lane in enumerate(lanes):
        attach_lane_sandbox(run, lane_id=lane["lane_id"], sandbox=fake_sandbox(run, challenge, lane["lane_id"]))
        confirm_native_spawn(run, lane_id=lane["lane_id"], native_session=f"thread-{index}")
    first_receipt = _receipt(run, challenge, lanes[0]["lane_id"], "target says CTF{first}", receipt_id="flag-one")
    first = record_candidate(
        run, lane_id=lanes[0]["lane_id"], attack_family=lanes[0]["attack_family"],
        candidate="CTF{first}", receipt=first_receipt,
    )
    assert first["first"] is True
    assert first["display"] == "CTF{first}"
    assert first["manual_submission_required"] is True
    # M4: the winning native child is still a live thread and must be interrupted
    # alongside its siblings, so it appears in the returned cancel targets too.
    assert first["cancel_targets"] == [
        {"lane_id": lanes[0]["lane_id"], "native_session": "thread-0"},
        {"lane_id": lanes[1]["lane_id"], "native_session": "thread-1"},
    ]
    winner_lane = next(
        row for row in load_race(run)["lanes"] if row["lane_id"] == lanes[0]["lane_id"]
    )
    assert winner_lane["status"] == "CANCEL_REQUIRED"
    second_receipt = _receipt(run, challenge, lanes[1]["lane_id"], "CTF{second}", receipt_id="flag-two")
    second = record_candidate(
        run, lane_id=lanes[1]["lane_id"], attack_family=lanes[1]["attack_family"],
        candidate="CTF{second}", receipt=second_receipt,
    )
    assert second["first"] is False
    assert second["winner"]["candidate"] == "CTF{first}"
    assert load_race(run)["winner"]["candidate"] == "CTF{first}"


def test_candidate_requires_actual_receipt_output_and_declared_target(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    receipt = _receipt(run, challenge, "root", "no candidate here")
    with pytest.raises(FlagError, match="not present"):
        record_candidate(
            run, lane_id="root", attack_family="root-primary", candidate="CTF{missing}", receipt=receipt
        )
    wrong_target = _receipt(run, challenge, "root", "CTF{real}", target="https://undeclared.invalid", receipt_id="wrong-target")
    with pytest.raises(FlagError, match="declared target"):
        record_candidate(
            run, lane_id="root", attack_family="root-primary", candidate="CTF{real}", receipt=wrong_target
        )


def test_declared_remote_identity_alone_is_not_a_target_observation(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo, remote="nc ctf.example 31337")
    receipt = _receipt(
        run, challenge, "root", "CTF{echoed}", target="nc ctf.example 31337", receipt_id="no-packets"
    )
    receipt["target_observed"] = False
    (run / "workers" / "root" / "logs" / "no-packets.json").write_text(
        __import__("json").dumps(receipt), encoding="utf-8"
    )
    with pytest.raises(FlagError, match="no actual"):
        record_candidate(
            run, lane_id="root", attack_family="root-primary", candidate="CTF{echoed}", receipt=receipt
        )


def test_candidate_receipt_must_match_the_durable_execution(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    receipt = _receipt(run, challenge, "root", "CTF{durable}", receipt_id="tampered-flag")
    durable = dict(receipt)
    durable["observed_output"] = "different output"
    (run / "workers" / "root" / "logs" / "tampered-flag.json").write_text(
        __import__("json").dumps(durable), encoding="utf-8"
    )
    with pytest.raises(FlagError, match="durable execution"):
        record_candidate(
            run, lane_id="root", attack_family="root-primary",
            candidate="CTF{durable}", receipt=receipt,
        )


def test_winner_preserves_sibling_cleanup_failure_state(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    note_command_receipt(
        run,
        _receipt(run, challenge, "root", "root attack", receipt_id="root-before-cleanup"),
    )
    lanes = reserve_lanes(run, [_spec("winner-family"), _spec("cleanup-family")])
    for index, lane in enumerate(lanes):
        attach_lane_sandbox(
            run, lane_id=lane["lane_id"],
            sandbox=fake_sandbox(run, challenge, lane["lane_id"]),
        )
        confirm_native_spawn(
            run, lane_id=lane["lane_id"], native_session=f"thread-{index}"
        )
    cleanup_lane = lanes[1]
    stop_confirmed(
        run, lane_id=cleanup_lane["lane_id"], native_session="thread-1"
    )
    finish_lane_cleanup(
        run, lane_id=cleanup_lane["lane_id"], error="docker rm failed"
    )

    winning_receipt = _receipt(
        run, challenge, lanes[0]["lane_id"], "CTF{winner}",
        receipt_id="winner-with-cleanup-failure",
    )
    record_candidate(
        run, lane_id=lanes[0]["lane_id"],
        attack_family=lanes[0]["attack_family"],
        candidate="CTF{winner}", receipt=winning_receipt,
    )
    persisted = next(
        row for row in load_race(run)["lanes"]
        if row["lane_id"] == cleanup_lane["lane_id"]
    )
    assert persisted["status"] == "CLEANUP_FAILED"
    assert persisted["cleanup_error"] == "docker rm failed"


def test_candidate_cannot_win_after_the_exact_race_terminates(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    terminate(run, reason="TIMED_OUT")
    receipt = _receipt(run, challenge, "root", "CTF{late}", receipt_id="late-flag")
    with pytest.raises(RaceError, match="non-active"):
        record_candidate(
            run, lane_id="root", attack_family="root-primary",
            candidate="CTF{late}", receipt=receipt,
        )
