"""M3 regression: flags spanning two session-read receipts are detected safely."""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import make_race

from ctf_os.blackboard import output_hash
from ctf_os.flag import FlagError, record_candidate
from ctf_os.race import load_race
from ctf_os.workspace import atomic_json, utc_now


def _session_receipt(run: Path, challenge, lane: str, output: str, receipt_id: str) -> dict:
    value = {
        "schema_version": 1,
        "receipt_id": receipt_id,
        "run_id": run.name,
        "lane_id": lane,
        "argv": [f"session:{lane}", "read"],
        "argv_family": "session:debugger:read",
        "exit_code": 0,
        "observed_output": output,
        "output_hash": output_hash(output),
        "target_identity": f"challenge:{challenge.id}",
        "target_observed": True,
        "finished_at": utc_now(),
    }
    atomic_json(run / "workers" / lane / "logs" / f"{receipt_id}.json", value)
    return value


def test_flag_spanning_two_reads_is_recorded(repo: Path) -> None:
    _m, challenge, run, _r = make_race(repo)
    # First read produced the durable prior receipt ending in "CTF{spl".
    _session_receipt(run, challenge, "root", "noise CTF{spl", "prior-read")
    # Second read produced "it}" — neither read alone contains the flag.
    current = _session_receipt(run, challenge, "root", "it} trailing", "current-read")

    result = record_candidate(
        run, lane_id="root", attack_family="root-primary",
        candidate="CTF{split}", receipt=current,
        boundary={"receipt_id": "prior-read", "tail": "noise CTF{spl"},
    )
    assert result["first"] is True
    assert load_race(run)["winner"]["candidate"] == "CTF{split}"


def test_boundary_candidate_with_forged_tail_is_rejected(repo: Path) -> None:
    _m, challenge, run, _r = make_race(repo)
    _session_receipt(run, challenge, "root", "noise CTF{spl", "prior-read")
    current = _session_receipt(run, challenge, "root", "it}", "current-read")
    # A tail that is not a genuine suffix of the durable prior receipt is refused.
    with pytest.raises(FlagError, match="genuine suffix"):
        record_candidate(
            run, lane_id="root", attack_family="root-primary",
            candidate="CTF{split}", receipt=current,
            boundary={"receipt_id": "prior-read", "tail": "FORGED CTF{spl"},
        )


def test_boundary_missing_prior_receipt_is_rejected(repo: Path) -> None:
    _m, challenge, run, _r = make_race(repo)
    current = _session_receipt(run, challenge, "root", "it}", "current-read")
    with pytest.raises(FlagError, match="durable prior receipt"):
        record_candidate(
            run, lane_id="root", attack_family="root-primary",
            candidate="CTF{split}", receipt=current,
            boundary={"receipt_id": "does-not-exist", "tail": "CTF{spl"},
        )


def test_boundary_candidate_must_actually_span(repo: Path) -> None:
    _m, challenge, run, _r = make_race(repo)
    _session_receipt(run, challenge, "root", "prefix", "prior-read")
    # The candidate sits entirely within the current read: not a boundary flag.
    current = _session_receipt(run, challenge, "root", "CTF{whole}", "current-read")
    with pytest.raises(FlagError, match="span two reads"):
        record_candidate(
            run, lane_id="root", attack_family="root-primary",
            candidate="CTF{whole}", receipt=current,
            boundary={"receipt_id": "prior-read", "tail": "prefix"},
        )


def test_boundary_placeholder_is_rejected(repo: Path) -> None:
    _m, challenge, run, _r = make_race(repo)
    _session_receipt(run, challenge, "root", "CTF{examp", "prior-read")
    current = _session_receipt(run, challenge, "root", "le_flag}", "current-read")
    with pytest.raises(FlagError, match="placeholder|flag pattern"):
        record_candidate(
            run, lane_id="root", attack_family="root-primary",
            candidate="CTF{example_flag}", receipt=current,
            boundary={"receipt_id": "prior-read", "tail": "CTF{examp"},
        )


def test_single_read_flag_still_works(repo: Path) -> None:
    _m, challenge, run, _r = make_race(repo)
    current = _session_receipt(run, challenge, "root", "here is CTF{oneshot}", "current-read")
    result = record_candidate(
        run, lane_id="root", attack_family="root-primary",
        candidate="CTF{oneshot}", receipt=current,
    )
    assert result["first"] is True
