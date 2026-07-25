"""M2 regression: only a fresh, identity-matched session heartbeat is live."""

from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from conftest import fake_sandbox, make_race

from ctf_os.race import _running_sessions
from ctf_os.sandbox.runtime import (
    SandboxSpec,
    build_run_argv,
    cleanup,
    user_exec_prefix,
)
from ctf_os.sandbox.session import close_session, open_session, session_liveness


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
        "controller_dir": f"/tmp/.ctf-os-controller-{'a' * 32}",
        "container_name": "ctf-os-test-root",
        "pid": pid,
        "pid_start_time": pid_start_time,
        "cursor": 0,
        "status": status,
        "opened_at": "2000-01-01T00:00:00+00:00",
    }
    (lane_root / "sessions" / f"{session_id}.json").write_text(json.dumps(state), encoding="utf-8")
    return state


def _lane_root(run: Path) -> Path:
    return run / "workers" / "root"


def _probe(output: str, *, returncode: int = 0):
    def runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, returncode, output, "")

    return runner


def test_running_state_without_heartbeat_is_not_in_flight(repo: Path) -> None:
    _m, _c, run, _r = make_race(repo)
    _write_session(run, "no-hb")
    assert _running_sessions(
        run, "root", datetime.now(UTC), runner=_probe("live 1 1 1\n")
    ) == []


def test_stale_heartbeat_is_not_live(repo: Path) -> None:
    _m, _c, run, _r = make_race(repo)
    state = _write_session(run, "stale", pid=1234, pid_start_time="55")
    runner = _probe("live 1000 1234 55\n")  # epoch year 1970
    assert session_liveness(
        _lane_root(run),
        state,
        now_epoch=datetime.now(UTC).timestamp(),
        runner=runner,
    )["live"] is False
    assert _running_sessions(
        run, "root", datetime.now(UTC), runner=runner
    ) == []


def test_missing_pid_in_heartbeat_is_not_live(repo: Path) -> None:
    _m, _c, run, _r = make_race(repo)
    now = datetime.now(UTC).timestamp()
    state = _write_session(run, "nopid")
    result = session_liveness(
        _lane_root(run), state, now_epoch=now, runner=_probe(f"live {now:.0f} 0 55\n")
    )
    assert result["live"] is False
    assert result["reason"] == "unpinned-identity"


def test_pid_mismatch_is_not_live(repo: Path) -> None:
    _m, _c, run, _r = make_race(repo)
    now = datetime.now(UTC).timestamp()
    state = _write_session(run, "mismatch", pid=100, pid_start_time="55")
    result = session_liveness(
        _lane_root(run), state, now_epoch=now, runner=_probe("pid-mismatch\n")
    )
    assert result["live"] is False
    assert result["reason"] == "pid-mismatch"


def test_pid_start_time_mismatch_is_not_live(repo: Path) -> None:
    _m, _c, run, _r = make_race(repo)
    now = datetime.now(UTC).timestamp()
    state = _write_session(run, "reused", pid=100, pid_start_time="55")
    result = session_liveness(
        _lane_root(run), state, now_epoch=now, runner=_probe("pid-reused\n")
    )
    assert result == {"live": False, "reason": "pid-reused"}


def test_fresh_matching_heartbeat_is_live(repo: Path) -> None:
    _m, _c, run, _r = make_race(repo)
    now = datetime.now(UTC)
    state = _write_session(run, "live-one", pid=4242, pid_start_time="99")
    runner = _probe(f"live {now.timestamp():.0f} 4242 99\n")
    assert session_liveness(
        _lane_root(run), state, now_epoch=now.timestamp(), runner=runner
    )["live"] is True
    running = _running_sessions(run, "root", now, runner=runner)
    assert [row["session_id"] for row in running] == ["live-one"]
    assert running[0]["pid"] == 4242


def test_invalid_container_identity_fails_closed(repo: Path) -> None:
    _m, _c, run, _r = make_race(repo)
    now = datetime.now(UTC)
    state = _write_session(run, "bad-container", pid=42, pid_start_time="9")
    state["container_name"] = "../../not-a-container"

    result = session_liveness(
        _lane_root(run), state, now_epoch=now.timestamp()
    )

    assert result == {"live": False, "reason": "probe-failed"}


def test_exit_marker_makes_session_not_live(repo: Path) -> None:
    _m, _c, run, _r = make_race(repo)
    now = datetime.now(UTC)
    state = _write_session(run, "exited", pid=5, pid_start_time="55")
    runner = _probe("exited\n")
    assert session_liveness(
        _lane_root(run), state, now_epoch=now.timestamp(), runner=runner
    )["reason"] == "exited"
    assert _running_sessions(run, "root", now, runner=runner) == []


def test_writable_work_markers_do_not_affect_controller_probe(repo: Path) -> None:
    _m, _c, run, _r = make_race(repo)
    now = datetime.now(UTC)
    state = _write_session(run, "owned", pid=77, pid_start_time="123")
    work = _lane_root(run) / "work" / ".ctf-sessions" / "owned"
    work.mkdir(parents=True)
    (work / "heartbeat").write_text(f"{now.timestamp():.0f} 1 1", encoding="utf-8")
    (work / "exit").write_text("dead", encoding="utf-8")

    result = session_liveness(
        _lane_root(run),
        state,
        now_epoch=now.timestamp(),
        runner=_probe(f"live {now.timestamp():.0f} 77 123\n"),
    )
    assert result["live"] is True


def test_close_is_idempotent_after_stopped(repo: Path) -> None:
    _m, challenge, run, _r = make_race(repo, category="pwn")
    metadata = fake_sandbox(run, challenge, "root", "ctf-os-sandbox:pwn")
    _write_session(run, "closed", status="STOPPED")

    def runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, "", "")

    # A second close on an already-stopped session succeeds instead of erroring.
    result = close_session(metadata, session_id="closed", runner=runner)
    assert result["stopped"] is True


@pytest.mark.live
@pytest.mark.skipif(os.environ.get("CTF_OS_LIVE") != "1", reason="set CTF_OS_LIVE=1")
def test_open_session_pins_real_identity_and_ignores_work_tampering(
    tmp_path: Path,
) -> None:
    source = tmp_path / "input"
    source.mkdir()
    source.chmod(0o555)
    lane_root = tmp_path / "workers" / "root"
    for name in ("work", "evidence", "artifacts", "context"):
        path = lane_root / name
        path.mkdir(parents=True, exist_ok=True)
        if name != "context":
            path.chmod(0o777)
    spec = SandboxSpec(
        run_id="run-session-live",
        contest_slug="demo",
        challenge_id="challenge1",
        category="base",
        lane_id="root",
        source=source,
        lane_root=lane_root,
        input_fingerprint="0" * 64,
        image="ctf-os-sandbox:base",
    )
    started = subprocess.run(
        build_run_argv(spec),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert started.returncode == 0, started.stdout + started.stderr
    metadata = {
        "name": spec.name,
        "run_id": spec.run_id,
        "challenge_id": spec.challenge_id,
        "lane_id": spec.lane_id,
        "category": spec.category,
        "lane_root": str(lane_root),
        "target_identities": [],
    }
    try:
        poisoned = subprocess.run(
            [
                *user_exec_prefix(metadata),
                "sh", "-c",
                "printf '%s\\n' 'raise RuntimeError(\"untrusted cwd import\")' > /work/pathlib.py",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert poisoned.returncode == 0, poisoned.stderr
        state = open_session(
            metadata,
            session_id="real-process",
            kind="shell",
            command=["sh", "-c", "sleep 3"],
        )
        assert isinstance(state["pid"], int) and state["pid"] > 0
        assert str(state["pid_start_time"]).isdigit()
        initial_liveness = session_liveness(
            lane_root, state, now_epoch=datetime.now(UTC).timestamp()
        )
        assert initial_liveness["live"] is True, initial_liveness

        protected = subprocess.run(
            [
                *user_exec_prefix(metadata),
                "sh", "-c",
                "printf 'dead\\n' >\"$1/exit\"",
                "ctf-os-controller-tamper",
                state["controller_dir"],
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert protected.returncode != 0

        tampered = subprocess.run(
            [
                *user_exec_prefix(metadata),
                "sh", "-c",
                (
                    "printf '9999999999 1 1\\n' >\"$1/heartbeat\"; "
                    "printf 'dead\\n' >\"$1/exit\""
                ),
                "ctf-os-work-tamper", state["container_dir"],
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert tampered.returncode == 0, tampered.stderr

        deadline = time.monotonic() + 8
        result = {"live": True}
        while result["live"] and time.monotonic() < deadline:
            time.sleep(0.2)
            result = session_liveness(
                lane_root, state, now_epoch=datetime.now(UTC).timestamp()
            )
        assert result["live"] is False, result
        assert result["reason"] == "exited"

        # Reproduce the original failure: after the real process has exited,
        # the lane user refreshes the old writable /work heartbeat and removes
        # its exit marker. Controller-owned identity still keeps race status
        # from treating the dead session as in flight.
        forged = subprocess.run(
            [
                *user_exec_prefix(metadata),
                "sh", "-c",
                (
                    "rm -f -- \"$1/exit\"; "
                    "printf '%s %s %s\\n' \"$2\" \"$3\" \"$4\" >\"$1/heartbeat\""
                ),
                "ctf-os-dead-session-forge",
                state["container_dir"],
                str(int(time.time())),
                str(state["pid"]),
                str(state["pid_start_time"]),
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert forged.returncode == 0, forged.stderr
        assert _running_sessions(
            tmp_path, "root", datetime.now(UTC)
        ) == []
        close_session(metadata, session_id="real-process")
    finally:
        cleaned = cleanup({"name": spec.name, "labels": spec.labels})
        assert cleaned["removed"] is True
