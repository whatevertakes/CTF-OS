from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from conftest import fake_sandbox, make_race

from ctf_os.blackboard import (
    BlackboardError,
    append_verified_event,
    duplicate_signals,
    events,
    output_hash,
)
from ctf_os.race import (
    RaceError,
    attach_lane_sandbox,
    confirm_native_spawn,
    finish_lane_cleanup,
    load_race,
    note_command_receipt,
    note_event,
    reserve_lanes,
    status,
    stop_confirmed,
)
from ctf_os.workspace import atomic_json, utc_now


def _spec(family: str) -> dict[str, str]:
    return {
        "model_profile": "sol-xhigh", "role": "attacker", "task": family,
        "context_mode": "fresh", "attack_family": family,
    }


def _receipt(run: Path, challenge, lane: str, output: str, *, command: list[str] | None = None, target: str | None = None, receipt_id: str | None = None):
    identifier = receipt_id or f"receipt-{lane}-{len(list((run / 'workers' / lane / 'logs').glob('*.json')))}"
    value = {
        "schema_version": 1,
        "receipt_id": identifier,
        "run_id": run.name,
        "lane_id": lane,
        "argv": command or ["python3", "solver.py"],
        "argv_family": "python3:.py",
        "exit_code": 0,
        "observed_output": output,
        "output_hash": output_hash(output),
        "target_identity": target or f"challenge:{challenge.id}",
        "target_observed": True,
        "finished_at": utc_now(),
    }
    logs = run / "workers" / lane / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    atomic_json(logs / f"{identifier}.json", value)
    return value


def test_blackboard_rejects_claim_without_durable_execution_receipt(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    receipt = _receipt(run, challenge, "root", "observed")
    (run / "workers" / "root" / "logs" / f"{receipt['receipt_id']}.json").unlink()
    with pytest.raises(BlackboardError, match="no durable"):
        append_verified_event(
            run, event_type="OBSERVATION", lane_id="root", attack_family="root-primary", receipt=receipt
        )


def test_blackboard_receipt_id_cannot_escape_lane_logs(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    receipt = _receipt(run, challenge, "root", "observed")
    receipt["receipt_id"] = "../artifacts/forged"
    with pytest.raises(BlackboardError, match="receipt id"):
        append_verified_event(
            run,
            event_type="OBSERVATION",
            lane_id="root",
            attack_family="root-primary",
            receipt=receipt,
        )


def test_output_and_artifact_fingerprints_are_exact_and_append_only(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    artifact = run / "workers" / "root" / "artifacts" / "exploit.py"
    artifact.write_bytes(b"print('poc')\n")
    receipt = _receipt(run, challenge, "root", "controlled response\r\n")
    event = append_verified_event(
        run, event_type="WORKING_POC", lane_id="root", attack_family="root-primary",
        receipt=receipt, artifact="exploit.py",
    )
    assert event["output_hash"] == output_hash("controlled response\r\n")
    assert event["artifact_hash"] == __import__("hashlib").sha256(artifact.read_bytes()).hexdigest()
    assert event["artifact_path"] == "exploit.py"
    assert events(run) == [event]
    with pytest.raises(BlackboardError, match="already recorded"):
        append_verified_event(
            run, event_type="WORKING_POC", lane_id="root", attack_family="root-primary",
            receipt=receipt, artifact="exploit.py",
        )


def test_duplicate_lane_and_stagnation_signals_use_mechanical_fingerprints(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    note_command_receipt(
        run,
        _receipt(run, challenge, "root", "root attack", receipt_id="root-before-lanes"),
    )
    lanes = reserve_lanes(run, [_spec("source-dataflow"), _spec("protocol-state")])
    for index, lane in enumerate(lanes):
        attach_lane_sandbox(run, lane_id=lane["lane_id"], sandbox=fake_sandbox(run, challenge, lane["lane_id"]))
        confirm_native_spawn(run, lane_id=lane["lane_id"], native_session=f"thread-{index}")
        receipt = _receipt(
            run, challenge, lane["lane_id"], "same failed result",
            command=["python3", "probe.py"], receipt_id=f"same-{index}",
        )
        event = append_verified_event(
            run, event_type="COMMAND_RESULT", lane_id=lane["lane_id"],
            attack_family=lane["attack_family"], receipt=receipt,
        )
        note_event(run, event)
    duplicates = duplicate_signals(run)
    assert duplicates and duplicates[0]["reason"] == "same-execution-output"
    later = datetime.now(UTC) + timedelta(minutes=10)
    report = status(run, now=later)
    child_rows = report["lanes"][1:]
    assert any("duplicate-other-lane" in row["stagnation_signals"] for row in child_rows)
    assert all(row["actual_command_count"] == 1 for row in child_rows)
    assert report["metrics"]["duplicate_attack_ratio"] > 0


def test_native_session_identity_cannot_be_reused_across_lanes(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    note_command_receipt(
        run,
        _receipt(run, challenge, "root", "root attack", receipt_id="root-before-lanes"),
    )
    lanes = reserve_lanes(run, [_spec("one"), _spec("two")])
    for lane in lanes:
        attach_lane_sandbox(
            run,
            lane_id=lane["lane_id"],
            sandbox=fake_sandbox(run, challenge, lane["lane_id"]),
        )
    confirm_native_spawn(run, lane_id=lanes[0]["lane_id"], native_session="thread-1")
    with pytest.raises(RaceError, match="already attached"):
        confirm_native_spawn(
            run, lane_id=lanes[1]["lane_id"], native_session="thread-1"
        )


def test_timestamps_and_timeout_are_bound_to_the_exact_run(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    receipt = _receipt(run, challenge, "root", "primitive")
    event = append_verified_event(
        run, event_type="PRIMITIVE", lane_id="root", attack_family="root-primary", receipt=receipt
    )
    note_event(run, event)
    updated = load_race(run)
    assert updated["timestamps"]["root_first_command_at"] is not None
    assert updated["timestamps"]["first_primitive_at"] is not None
    deadline = datetime.fromisoformat(updated["deadline"]) + timedelta(seconds=1)
    report = status(run, now=deadline)
    assert report["status"] == "TIMED_OUT"
    assert report["lanes"][0]["status"] == "CANCEL_REQUIRED"


def test_status_counts_durable_commands_even_without_blackboard_event(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    _receipt(run, challenge, "root", "executed even if logging failed", receipt_id="durable-only")
    report = status(run)
    assert report["lanes"][0]["actual_command_count"] == 1
    assert report["lanes"][0]["new_output_count"] == 1


def test_timeout_preserves_cleanup_failure_state(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    note_command_receipt(
        run,
        _receipt(run, challenge, "root", "root attack", receipt_id="root-before-cleanup"),
    )
    lane = reserve_lanes(run, [_spec("cleanup-failure")])[0]
    attach_lane_sandbox(
        run, lane_id=lane["lane_id"],
        sandbox=fake_sandbox(run, challenge, lane["lane_id"]),
    )
    confirm_native_spawn(
        run, lane_id=lane["lane_id"], native_session="thread-cleanup-failure"
    )
    stop_confirmed(
        run, lane_id=lane["lane_id"], native_session="thread-cleanup-failure"
    )
    finish_lane_cleanup(run, lane_id=lane["lane_id"], error="docker unavailable")

    deadline = datetime.fromisoformat(load_race(run)["deadline"]) + timedelta(seconds=1)
    report = status(run, now=deadline)
    child = next(row for row in report["lanes"] if row["lane_id"] == lane["lane_id"])
    assert child["status"] == "CLEANUP_FAILED"
    assert child["cleanup_error"] == "docker unavailable"
