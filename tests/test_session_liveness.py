"""M2 regression: only a fresh, identity-matched session heartbeat is live."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from conftest import fake_sandbox, make_race

from ctf_os.race import _running_sessions
from ctf_os.sandbox.session import close_session, session_liveness


def _write_session(
    run: Path, session_id: str, *, status: str = "RUNNING", pid=None, pid_start_time=None
) -> dict:
    lane_root = run / "workers" / "root"
    (lane_root / "sessions").mkdir(parents=True, exist_ok=True)
    state = {
        "schema_version": 1,
        "session_id": session_id,
        "run_id": run.name,
        "lane_id": "root",
        "kind": "debugger",
        "argv": ["gdb"],
        "target_identity": "challenge:x",
        "container_dir": f"/work/.ctf-sessions/{session_id}",
        "heartbeat_relpath": f"work/.ctf-sessions/{session_id}/heartbeat",
        "exit_relpath": f"work/.ctf-sessions/{session_id}/exit",
        "pid": pid,
        "pid_start_time": pid_start_time,
        "cursor": 0,
        "status": status,
        "opened_at": "2000-01-01T00:00:00+00:00",
    }
    (lane_root / "sessions" / f"{session_id}.json").write_text(json.dumps(state), encoding="utf-8")
    return state


def _write_heartbeat(run: Path, session_id: str, content: str) -> None:
    base = run / "workers" / "root" / "work" / ".ctf-sessions" / session_id
    base.mkdir(parents=True, exist_ok=True)
    (base / "heartbeat").write_text(content, encoding="utf-8")


def _write_exit(run: Path, session_id: str) -> None:
    base = run / "workers" / "root" / "work" / ".ctf-sessions" / session_id
    base.mkdir(parents=True, exist_ok=True)
    (base / "exit").write_text("dead", encoding="utf-8")


def _lane_root(run: Path) -> Path:
    return run / "workers" / "root"


def test_running_state_without_heartbeat_is_not_in_flight(repo: Path) -> None:
    _m, _c, run, _r = make_race(repo)
    _write_session(run, "no-hb")
    assert _running_sessions(run, "root", datetime.now(UTC)) == []


def test_stale_heartbeat_is_not_live(repo: Path) -> None:
    _m, _c, run, _r = make_race(repo)
    state = _write_session(run, "stale")
    _write_heartbeat(run, "stale", "1000 1234 55")  # epoch year 1970
    assert session_liveness(_lane_root(run), state, now_epoch=datetime.now(UTC).timestamp())["live"] is False
    assert _running_sessions(run, "root", datetime.now(UTC)) == []


def test_missing_pid_in_heartbeat_is_not_live(repo: Path) -> None:
    _m, _c, run, _r = make_race(repo)
    now = datetime.now(UTC).timestamp()
    state = _write_session(run, "nopid")
    _write_heartbeat(run, "nopid", f"{now:.0f} 0 55")
    assert session_liveness(_lane_root(run), state, now_epoch=now)["live"] is False


def test_pid_mismatch_is_not_live(repo: Path) -> None:
    _m, _c, run, _r = make_race(repo)
    now = datetime.now(UTC).timestamp()
    state = _write_session(run, "mismatch", pid=100, pid_start_time="55")
    _write_heartbeat(run, "mismatch", f"{now:.0f} 200 55")
    result = session_liveness(_lane_root(run), state, now_epoch=now)
    assert result["live"] is False
    assert result["reason"] == "pid-mismatch"


def test_fresh_matching_heartbeat_is_live(repo: Path) -> None:
    _m, _c, run, _r = make_race(repo)
    now = datetime.now(UTC)
    state = _write_session(run, "live-one", pid=4242, pid_start_time="99")
    _write_heartbeat(run, "live-one", f"{now.timestamp():.0f} 4242 99")
    assert session_liveness(_lane_root(run), state, now_epoch=now.timestamp())["live"] is True
    running = _running_sessions(run, "root", now)
    assert [row["session_id"] for row in running] == ["live-one"]
    assert running[0]["pid"] == 4242


def test_exit_marker_makes_session_not_live(repo: Path) -> None:
    _m, _c, run, _r = make_race(repo)
    now = datetime.now(UTC)
    state = _write_session(run, "exited")
    _write_heartbeat(run, "exited", f"{now.timestamp():.0f} 5 55")
    _write_exit(run, "exited")
    assert session_liveness(_lane_root(run), state, now_epoch=now.timestamp())["reason"] == "exited"
    assert _running_sessions(run, "root", now) == []


def test_close_is_idempotent_after_stopped(repo: Path) -> None:
    _m, challenge, run, _r = make_race(repo, category="pwn")
    metadata = fake_sandbox(run, challenge, "root", "ctf-os-sandbox:pwn")
    _write_session(run, "closed", status="STOPPED")

    def runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, "", "")

    # A second close on an already-stopped session succeeds instead of erroring.
    result = close_session(metadata, session_id="closed", runner=runner)
    assert result["stopped"] is True
