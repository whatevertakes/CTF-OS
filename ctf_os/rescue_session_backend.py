"""Container-resident persistent session backends for manual Claude rescue."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Any, Mapping, Sequence

from .rescue import RescueError
from .workspace import atomic_json, atomic_text, utc_now


PTY_KINDS = frozenset({"shell", "gdb", "repl"})
SESSION_KINDS = PTY_KINDS | {"tcp"}
MAX_TRANSCRIPT_BYTES = 16 * 1024 * 1024
_TOKEN = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")


class DockerSessionBackend:
    """Low-level tmux PTY and binary-safe socket relay control."""

    def __init__(
        self, rescue_root: Path, metadata: Mapping[str, Any], *, docker: str = "docker",
    ) -> None:
        self.root = rescue_root.resolve(strict=False)
        self.metadata = dict(metadata)
        self.docker = docker
        self.container = str(self.metadata.get("name") or "")
        if not self.container.startswith("ctf-os-"):
            raise RescueError("invalid exact rescue container name")

    def open_pty(
        self, session_id: str, kind: str, argv: Sequence[str], directory: Path,
    ) -> dict[str, Any]:
        if kind not in PTY_KINDS or not argv:
            raise RescueError("PTY session requires shell, gdb, or repl with direct argv")
        token = _tmux_name(session_id)
        self._write_spooler(directory)
        start_file = f"/sessions/{session_id}/control/start"
        result = self._run([
            self.docker, "exec", "--user", "1001:1001", "--workdir", "/work",
            self.container, "tmux", "new-session", "-d", "-s", token,
            "-x", "160", "-y", "48", "--", "/bin/sh", "-c",
            'while [ ! -f "$1" ]; do sleep 0.02; done; shift; exec "$@"',
            "ctf-session", start_file, *argv,
        ])
        if result.returncode:
            raise RescueError("tmux session open failed: " + result.stderr.strip()[:2000])
        pipe_command = f"python3 /sessions/{session_id}/control/spool.py"
        piped = self._run([
            self.docker, "exec", "--user", "1001:1001", self.container,
            "tmux", "pipe-pane", "-O", "-t", token, pipe_command,
        ])
        if piped.returncode:
            self._run([self.docker, "exec", "--user", "1001:1001", self.container, "tmux", "kill-session", "-t", token])
            raise RescueError("tmux transcript pipe failed: " + piped.stderr.strip()[:2000])
        self._run([
            self.docker, "exec", "--user", "1001:1001", self.container,
            "tmux", "set-option", "-t", token, "remain-on-exit", "on",
        ])
        started = self._run([
            self.docker, "exec", "--user", "1001:1001", self.container,
            "touch", start_file,
        ])
        if started.returncode:
            raise RescueError("tmux session start gate failed")
        return {"backend": "tmux", "backend_id": token, "argv": list(argv)}

    def open_tcp(
        self, session_id: str, host: str, port: int, directory: Path,
    ) -> dict[str, Any]:
        self._write_spooler(directory)
        relay = directory / "control" / "tcp_relay.py"
        atomic_text(relay, _TCP_RELAY)
        relay.chmod(0o555)
        result = self._run([
            self.docker, "exec", "--detach", "--user", "1001:1001", "--workdir", "/work",
            self.container, "python3", f"/sessions/{session_id}/control/tcp_relay.py",
            host, str(port), f"/sessions/{session_id}",
        ])
        if result.returncode:
            raise RescueError("TCP session relay failed to start: " + result.stderr.strip()[:2000])
        pid_path = directory / "control" / "pid"
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not pid_path.is_file():
            time.sleep(0.05)
        if not pid_path.is_file() or not pid_path.read_text(encoding="ascii").strip().isdigit():
            raise RescueError("TCP session relay did not publish its PID")
        return {
            "backend": "python-socket-relay", "backend_id": pid_path.read_text().strip(),
            "host": host, "port": port, "argv": ["tcp", host, str(port)],
        }

    def send_pty(self, session_id: str, data: bytes) -> None:
        token = _tmux_name(session_id)
        buffer_name = f"b-{token}"
        loaded = self._run_bytes([
            self.docker, "exec", "--interactive", "--user", "1001:1001",
            self.container, "tmux", "load-buffer", "-b", buffer_name, "-",
        ], data)
        if loaded.returncode:
            raise RescueError("tmux binary input load failed: " + loaded.stderr.decode(errors="replace")[:2000])
        pasted = self._run([
            self.docker, "exec", "--user", "1001:1001", self.container,
            "tmux", "paste-buffer", "-d", "-b", buffer_name, "-t", token,
        ])
        if pasted.returncode:
            raise RescueError("tmux input send failed: " + pasted.stderr.strip()[:2000])

    def send_tcp(self, directory: Path, data: bytes) -> None:
        path = directory / "control" / "input.bin"
        with path.open("ab") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())

    def status(self, state: Mapping[str, Any], directory: Path) -> dict[str, Any]:
        backend = state.get("backend")
        if backend == "tmux":
            result = self._run([
                self.docker, "exec", "--user", "1001:1001", self.container,
                "tmux", "list-panes", "-t", str(state.get("backend_id")),
                "-F", "#{pane_dead}|#{pane_pid}|#{pane_dead_status}",
            ])
            if result.returncode:
                return {"status": "STALE", "backend_detail": result.stderr.strip()[:1000]}
            dead, pid, exit_status = (result.stdout.strip().split("|") + ["", "", ""])[:3]
            return {
                "status": "EXITED" if dead == "1" else "RUNNING",
                "process_id": int(pid) if pid.isdigit() else None,
                "exit_code": int(exit_status) if dead == "1" and exit_status.lstrip("-").isdigit() else None,
            }
        if backend == "python-socket-relay":
            pid = str(state.get("backend_id") or "")
            if not pid.isdigit():
                return {"status": "ERROR", "backend_detail": "missing relay PID"}
            check = self._run([
                self.docker, "exec", "--user", "1001:1001", self.container,
                "/bin/sh", "-c", 'kill -0 "$1" 2>/dev/null', "ctf-session", pid,
            ])
            if check.returncode == 0:
                return {"status": "RUNNING", "process_id": int(pid)}
            error = directory / "control" / "error"
            return {
                "status": "EXITED",
                "backend_detail": error.read_text(encoding="utf-8", errors="replace")[:1000] if error.is_file() else None,
            }
        return {"status": "ERROR", "backend_detail": "unknown session backend"}

    def close(self, state: Mapping[str, Any], directory: Path) -> dict[str, Any]:
        backend = state.get("backend")
        if backend == "tmux":
            token = str(state.get("backend_id") or "")
            pane = self._run([
                self.docker, "exec", "--user", "1001:1001", self.container,
                "tmux", "list-panes", "-t", token, "-F", "#{pane_pid}",
            ])
            pane_pid = pane.stdout.strip().splitlines()[0] if pane.returncode == 0 and pane.stdout.strip() else ""
            result = self._run([
                self.docker, "exec", "--user", "1001:1001", self.container,
                "tmux", "kill-session", "-t", token,
            ])
            if pane_pid.isdigit():
                self._run([
                    self.docker, "exec", "--user", "1001:1001", self.container,
                    "/bin/sh", "-c",
                    'kill -TERM -"$1" 2>/dev/null || true; i=0; '
                    'while ps -o pid=,stat= --sid "$1" 2>/dev/null | awk \'$2 !~ /^Z/ {found=1} END {exit !found}\' && [ "$i" -lt 20 ]; '
                    'do sleep .1; i=$((i+1)); done; kill -KILL -"$1" 2>/dev/null || true',
                    "ctf-session", pane_pid,
                ])
            check = self._run([
                self.docker, "exec", "--user", "1001:1001", self.container,
                "tmux", "has-session", "-t", token,
            ])
            remaining: list[str] = []
            if check.returncode == 0:
                remaining.append(token)
            if pane_pid.isdigit():
                process_check = self._run([
                    self.docker, "exec", "--user", "1001:1001", self.container,
                    "/bin/sh", "-c", 'ps -o pid=,stat= --sid "$1" 2>/dev/null | awk \'$2 !~ /^Z/ {print $1}\'',
                    "ctf-session", pane_pid,
                ])
                remaining.extend(process_check.stdout.split())
            return {
                "termination_exit_code": result.returncode,
                "process_group_id": int(pane_pid) if pane_pid.isdigit() else None,
                "remaining_processes": sorted(set(remaining)),
            }
        if backend == "python-socket-relay":
            (directory / "control" / "close").touch(mode=0o600, exist_ok=True)
            pid = str(state.get("backend_id") or "")
            terminated = self._run([
                self.docker, "exec", "--user", "1001:1001", self.container,
                "/bin/sh", "-c",
                'kill -TERM "$1" 2>/dev/null || true; i=0; while kill -0 "$1" 2>/dev/null && [ "$i" -lt 20 ]; do sleep .1; i=$((i+1)); done; kill -KILL "$1" 2>/dev/null || true',
                "ctf-session", pid,
            ])
            check = self._run([
                self.docker, "exec", "--user", "1001:1001", self.container,
                "/bin/sh", "-c", 'kill -0 "$1" 2>/dev/null', "ctf-session", pid,
            ])
            return {
                "termination_exit_code": terminated.returncode,
                "remaining_processes": [pid] if check.returncode == 0 else [],
            }
        return {"termination_exit_code": 1, "remaining_processes": ["unknown-backend"]}

    def _write_spooler(self, directory: Path) -> None:
        control = directory / "control"
        control.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o777)
        control.chmod(0o777)
        for path in (directory / "stdout.bin", directory / "stderr.bin", control / "input.bin"):
            if not path.exists():
                path.touch(mode=0o600)
            path.chmod(0o666)
        base = control / "cursor_base"
        if not base.exists():
            atomic_text(base, "0\n")
        base.chmod(0o666)
        script = control / "spool.py"
        atomic_text(script, _SPOOLER.replace("__MAX__", str(MAX_TRANSCRIPT_BYTES)))
        script.chmod(0o555)

    def _run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(list(argv), capture_output=True, text=True, timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RescueError(f"session backend command failed: {exc}") from exc

    def _run_bytes(self, argv: Sequence[str], data: bytes) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(list(argv), input=data, capture_output=True, timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RescueError(f"session backend binary command failed: {exc}") from exc


def _tmux_name(session_id: str) -> str:
    token = "r-" + session_id.casefold().replace("_", "-")
    if not _TOKEN.fullmatch(token):
        raise RescueError("session ID cannot be represented safely by tmux")
    return token


_SPOOLER = r'''#!/usr/bin/env python3
import fcntl, os, pathlib, sys, tempfile
root = pathlib.Path(__file__).resolve().parents[1]
out = root / "stdout.bin"
base_path = root / "control" / "cursor_base"
lock_path = root / "control" / "spool.lock"
maximum = __MAX__
with lock_path.open("a+b") as lock:
    while True:
        chunk = os.read(sys.stdin.fileno(), 65536)
        if not chunk:
            break
        fcntl.flock(lock, fcntl.LOCK_EX)
        with out.open("ab") as handle:
            handle.write(chunk); handle.flush(); os.fsync(handle.fileno())
        size = out.stat().st_size
        if size > maximum:
            drop = size - maximum
            data = out.read_bytes()[-maximum:]
            temp = out.with_suffix(".tmp")
            with temp.open("wb") as handle:
                handle.write(data); handle.flush(); os.fsync(handle.fileno())
            os.replace(temp, out)
            try: base = int(base_path.read_text().strip() or "0")
            except Exception: base = 0
            base_path.write_text(str(base + drop) + "\n")
        fcntl.flock(lock, fcntl.LOCK_UN)
'''


_TCP_RELAY = r'''#!/usr/bin/env python3
import fcntl, os, pathlib, select, socket, sys, time
host, port, root_value = sys.argv[1], int(sys.argv[2]), sys.argv[3]
root = pathlib.Path(root_value); control = root / "control"
(control / "pid").write_text(str(os.getpid()) + "\n")
input_path = control / "input.bin"; output_path = root / "stdout.bin"
base_path = control / "cursor_base"; lock_path = control / "spool.lock"
maximum = 16 * 1024 * 1024; offset = 0
def append(data):
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with output_path.open("ab") as out:
            out.write(data); out.flush(); os.fsync(out.fileno())
        size = output_path.stat().st_size
        if size > maximum:
            drop = size - maximum; kept = output_path.read_bytes()[-maximum:]
            temp = output_path.with_suffix(".tmp")
            with temp.open("wb") as out:
                out.write(kept); out.flush(); os.fsync(out.fileno())
            os.replace(temp, output_path)
            try: base = int(base_path.read_text().strip() or "0")
            except Exception: base = 0
            base_path.write_text(str(base + drop) + "\n")
        fcntl.flock(lock, fcntl.LOCK_UN)
try:
    sock = socket.create_connection((host, port), timeout=10); sock.setblocking(False)
    while not (control / "close").exists():
        size = input_path.stat().st_size
        if size > offset:
            with input_path.open("rb") as source:
                source.seek(offset); data = source.read(size - offset)
            if data: sock.sendall(data); offset += len(data)
        readable, _, _ = select.select([sock], [], [], .05)
        if readable:
            data = sock.recv(65536)
            if not data: break
            append(data)
    sock.close()
except Exception as exc:
    (control / "error").write_text(type(exc).__name__ + ": " + str(exc)[:1000] + "\n")
finally:
    (control / "exited").write_text(str(time.time()) + "\n")
'''
