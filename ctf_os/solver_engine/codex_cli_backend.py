from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import queue
import re
import signal
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from threading import Event as ThreadEvent
from typing import Any, TextIO

from ctf_os.model_routing import ModelRouter, ModelSelection


MAX_CODEX_RETAINED_OUTPUT_BYTES = 256 * 1024
MAX_CODEX_STREAM_LINE_CHARS = 8 * 1024
_STREAM_QUEUE_DEPTH = 128
_DANGEROUS_CLI_TOKENS = frozenset({
    "--sandbox", "--dangerously-bypass-approvals-and-sandbox",
    "--danger-full-access", "--full-auto",
})
_BROKER_IPC_DIRECTORY = ".ctf-os-broker"
_RESUME_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")


def _require_broker_socket(socket_path: Path | None, workdir: Path) -> Path:
    if socket_path is None:
        raise ValueError("production Codex requests require an attempt broker endpoint")
    expected = workdir / _BROKER_IPC_DIRECTORY
    candidate = socket_path.absolute()
    if candidate != expected:
        raise ValueError("broker endpoint must be exact attempt-local filesystem IPC")
    try:
        details = candidate.lstat()
    except FileNotFoundError as exc:
        raise ValueError("broker endpoint is unavailable") from exc
    if (stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode)
            or details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) != 0o700):
        raise ValueError("broker endpoint has unsafe ownership or mode")
    return candidate


def _require_sterile_attempt_workdir(workdir: Path) -> Path:
    """Prove that Codex starts below a private, non-project boundary.

    The marker is written by :class:`ArtifactWriter` with mode 0600 in a
    ``mkdtemp`` directory.  Starting the process with that directory as both
    its working directory and ``-C`` root prevents project-config discovery
    from walking into a repository's parent ``.codex`` tree.  Existing auth is
    retained by Codex's ``--ignore-user-config`` behaviour; this check neither
    opens nor copies any auth file.
    """
    root = workdir.parent
    marker = root / ".ctf-os-sterile-attempt"
    try:
        root_info, work_info, marker_info = root.lstat(), workdir.lstat(), marker.lstat()
    except FileNotFoundError as exc:
        raise ValueError("sterile attempt boundary is missing") from exc
    for info, label in ((root_info, "root"), (work_info, "workdir")):
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError(f"sterile attempt {label} is invalid")
    if root_info.st_mode & 0o077:
        raise ValueError("sterile attempt root must be mode 0700")
    if stat.S_ISLNK(marker_info.st_mode) or not stat.S_ISREG(marker_info.st_mode) or marker_info.st_uid != os.getuid():
        raise ValueError("sterile attempt boundary marker is invalid")
    # Parent directories are deliberately not consulted here.  The process is
    # launched with --ignore-user-config, --ignore-rules, and --strict-config;
    # rejecting an unrelated /tmp/.codex would make a legitimate sterile
    # boundary unusable without adding protection.  Only the private root and
    # its marker are part of this capability check.
    return workdir


def _toml_string(value: str) -> str:
    # json's string grammar is a compatible TOML basic-string subset for the
    # path/token-free values placed in a ``-c key=value`` override.
    import json

    return json.dumps(value, ensure_ascii=False)


def _permission_profile_override(
    workdir: Path, socket_path: Path, *, runtime_executable: Path | None = None,
) -> str:
    """One parseable TOML value defining a fail-closed named profile."""
    root = _toml_string(str(workdir))
    # ``socket_path`` is retained in this private API for compatibility with
    # callers while the transport is now regular-file spool IPC.  It grants no
    # Codex permission: the endpoint is already below the sole writable root.
    _ = socket_path
    executable = (
        f",{_toml_string(str(runtime_executable))}=\"read\""
        if runtime_executable is not None else ""
    )
    return (
        "permissions.ctf_os_attempt={"
        'description="CTF-OS attempt-only broker profile",'
        f"workspace_roots={{ {root}=true }},"
        'filesystem={":root"="deny",":minimal"="read",":workspace_roots"={"."="write"}'
        f"{executable}}},"
        # Codex runs on the host, so every network syscall is disabled.  The
        # command broker uses authenticated regular-file spool IPC below the
        # exact writable workdir and needs no Unix/TCP socket exception.
        "network={enabled=false,allow_upstream_proxy=false,enable_socks5=false,enable_socks5_udp=false}"
        "}"
    )


def _runtime_executable(command: str) -> Path | None:
    """Return only the exact Codex binary needed inside its root-deny sandbox."""
    found = shutil.which(command)
    if found is None:
        return None
    try:
        path = Path(found).resolve(strict=True)
    except OSError:
        return None
    if not path.is_file() or not os.access(path, os.X_OK):
        return None
    # The npm launcher is a JavaScript shim.  Codex's Linux sandbox re-execs
    # the platform binary it resolves below this package, so whitelist that
    # one immutable executable instead of widening filesystem access to the
    # user's Node/npm tree.
    if path.name == "codex.js":
        candidates = sorted(path.parent.parent.glob(
            "node_modules/@openai/codex-*/vendor/*/bin/codex"
        ))
        for candidate in candidates:
            try:
                resolved = candidate.resolve(strict=True)
            except OSError:
                continue
            if resolved.is_file() and os.access(resolved, os.X_OK):
                return resolved
    return path


@dataclass(frozen=True)
class CodexExecRequest:
    workdir: Path
    prompt: str
    role: str | None = None
    difficulty: str | None = None
    attempt_kind: str | None = None
    broker_socket: Path | None = None
    selection: ModelSelection | None = None
    json_events: bool = False
    resume_id: str | None = None
    persistent_session: bool = False


@dataclass(frozen=True)
class CodexStreamRecord:
    stream: str
    line: str


@dataclass(frozen=True)
class CodexExecResult:
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    rate_limited: bool = False
    token_usage: int | None = None
    session_id: str | None = None
    unavailable: bool = False
    truncated: bool = False
    # Raw assistant/challenge text is never sufficient to set these.  The
    # backend fills them only from a Codex JSON terminal-error envelope (or a
    # future explicit transport adapter), and orchestration trusts that
    # provenance before a cooldown/fallback can occur.
    failure_provenance: str | None = None
    failure_code: str | None = None
    resume_id: str | None = None

    @property
    def trusted_failure_kind(self) -> str | None:
        if self.failure_provenance not in {"structured", "transport"}:
            return None
        if self.rate_limited:
            return "rate_limited"
        if self.unavailable:
            return "unavailable"
        return None

    @property
    def status(self) -> str:
        if self.timed_out:
            return "timed_out"
        if self.rate_limited:
            return "rate_limited"
        if self.unavailable:
            return "unavailable"
        return "completed" if self.returncode == 0 else "failed"


class CodexCliBackend:
    """Run one Codex CLI child and never signal processes outside that child group."""

    def __init__(
        self,
        *,
        command: str = "codex",
        model_router: ModelRouter,
        process_factory: Callable[..., Any] = subprocess.Popen,
        clock: Callable[[], float] = time.monotonic,
        killpg: Callable[[int, signal.Signals], None] = os.killpg,
        max_retained_output_bytes: int = MAX_CODEX_RETAINED_OUTPUT_BYTES,
    ) -> None:
        if not isinstance(max_retained_output_bytes, int) or not 4 * 1024 <= max_retained_output_bytes <= 4 * 1024 * 1024:
            raise ValueError("Codex retained output budget must be between 4KiB and 4MiB")
        self.command = command
        self.model_router = model_router
        self._process_factory = process_factory
        self._clock = clock
        self._killpg = killpg
        self.max_retained_output_bytes = max_retained_output_bytes

    def build_exec_argv(self, request: CodexExecRequest) -> list[str]:
        selection = request.selection or self.model_router.select(
            role=request.role, difficulty=request.difficulty, attempt_kind=request.attempt_kind,
        )
        return self.build_exec_argv_for_selection(request, selection)

    def build_exec_argv_for_selection(
        self,
        request: CodexExecRequest,
        selection: ModelSelection,
    ) -> list[str]:
        workdir = _require_sterile_attempt_workdir(request.workdir.absolute())
        socket_path = _require_broker_socket(request.broker_socket, workdir)
        permission_override = _permission_profile_override(
            workdir, socket_path, runtime_executable=_runtime_executable(self.command),
        )
        persistent = request.persistent_session or request.resume_id is not None
        if request.resume_id is not None and not _RESUME_ID.fullmatch(request.resume_id):
            raise ValueError("resume_id must be a bounded opaque Codex session identifier")
        argv = [
            self.command,
            "exec",
            "--strict-config",
            "--ignore-user-config",
            "--ignore-rules",
        ]
        if not persistent:
            argv.append("--ephemeral")
        argv.extend([
            "--disable",
            "hooks",
            "--skip-git-repo-check",
            "-C",
            str(workdir),
            "-m",
            selection.model,
            "-c",
            f'model_reasoning_effort="{selection.reasoning_effort}"',
            "-c",
            'approval_policy="never"',
            "-c",
            'mcp_servers={}',
            "-c",
            'default_permissions="ctf_os_attempt"',
            "-c",
            permission_override,
        ])
        if request.json_events:
            argv.append("--json")
        if request.resume_id is not None:
            argv.extend(["resume", request.resume_id])
        argv.append(request.prompt)
        _validate_production_argv(
            argv,
            workdir=workdir,
            socket_path=socket_path,
            runtime_executable=_runtime_executable(self.command),
            require_ephemeral=not persistent,
        )
        return argv

    def run(
        self,
        request: CodexExecRequest,
        *,
        timeout_sec: float | None = None,
        on_output: Callable[[CodexStreamRecord], None] | None = None,
        evidence_sink: TextIO | Callable[[CodexStreamRecord], None] | None = None,
        term_grace_sec: float = 2.0,
        cancel_event: ThreadEvent | None = None,
    ) -> CodexExecResult:
        """Execute and stream a single attempt.

        ``start_new_session=True`` makes the spawned child its own process-group
        leader. Consequently timeout cleanup addresses only ``proc.pid``'s group,
        never an unrelated team member's process group.
        """
        if timeout_sec is not None and timeout_sec <= 0:
            raise ValueError("timeout_sec must be positive when set")
        if term_grace_sec < 0:
            raise ValueError("term_grace_sec must be non-negative")
        argv = self.build_exec_argv(request)
        proc = self._process_factory(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            start_new_session=True,
            cwd=str(request.workdir.absolute()),
        )
        # The readers block on this bounded queue instead of allowing a noisy
        # Codex child to turn callback/evidence backpressure into host memory
        # growth.  The pipe then provides ordinary process backpressure.
        records: queue.Queue[CodexStreamRecord | None] = queue.Queue(maxsize=_STREAM_QUEUE_DEPTH)
        readers = [
            threading.Thread(target=self._read_stream, args=(proc.stdout, "stdout", records), daemon=True),
            threading.Thread(target=self._read_stream, args=(proc.stderr, "stderr", records), daemon=True),
        ]
        for reader in readers:
            reader.start()

        stdout: list[str] = []
        stderr: list[str] = []
        retained_bytes = 0
        truncated = False
        completed_readers = 0
        started = self._clock()
        timed_out = False
        stop_requested = False
        try:
            while completed_readers < len(readers):
                should_stop = (cancel_event is not None and cancel_event.is_set()) or (
                    timeout_sec is not None and self._clock() - started >= timeout_sec
                )
                if should_stop and not stop_requested:
                    timed_out = True
                    stop_requested = True
                    # The event comes only from LocalWorkerPool, which owns
                    # this invocation. The child was created in a private
                    # session, so this can never target another attempt.
                    self._terminate_process_group(proc, term_grace_sec)
                try:
                    record = records.get(timeout=0.05)
                except queue.Empty:
                    if proc.poll() is not None:
                        # Readers normally follow shortly; continue draining
                        # their final records instead of returning early.
                        continue
                    continue
                if record is None:
                    completed_readers += 1
                    continue
                encoded = record.line.encode("utf-8", errors="replace")
                # Reserve one byte per retained record for the join newline,
                # making the returned stdout+stderr bound hard rather than
                # merely approximate.
                cost = len(encoded) + 1
                remaining = self.max_retained_output_bytes - retained_bytes
                if remaining <= 0:
                    truncated = True
                    continue
                if cost > remaining:
                    truncated = True
                    # A partial line is not emitted to parsers/callbacks: it
                    # could manufacture a structured record at a truncation
                    # boundary.  Drain it, but retain no worker-controlled
                    # fragment.
                    continue
                retained_bytes += cost
                if record.stream == "stdout":
                    stdout.append(record.line)
                else:
                    stderr.append(record.line)
                for delivered in self._observable_records(record, json_events=request.json_events):
                    self._deliver(delivered, on_output, evidence_sink)

            returncode, stopped_for_wait = self._wait_until_reaped(
                proc,
                started=started,
                timeout_sec=timeout_sec,
                term_grace_sec=term_grace_sec,
                cancel_event=cancel_event,
                stop_requested=stop_requested,
            )
            timed_out = timed_out or stopped_for_wait
            combined = "\n".join((*stdout, *stderr))
            failure_kind, failure_code = self._structured_failure(
                (*stdout, *stderr), json_events=request.json_events,
            )
            assistant_output = self._assistant_output(tuple(stdout)) if request.json_events else "\n".join(stdout)
            return CodexExecResult(
                argv=tuple(argv),
                returncode=returncode,
                stdout=assistant_output,
                stderr="\n".join(stderr),
                timed_out=timed_out,
                # Never infer service state from arbitrary retained output:
                # assistant/challenge text can legitimately mention HTTP 429
                # or 503.  Only a CLI JSON terminal-error envelope is a
                # trusted service-failure provenance.
                rate_limited=failure_kind == "rate_limited",
                token_usage=self._parse_token_usage(combined),
                session_id=self._parse_session_id(combined, machine_events_only=request.json_events),
                resume_id=self._parse_resume_id(combined, machine_events_only=request.json_events),
                unavailable=failure_kind == "unavailable",
                truncated=truncated,
                failure_provenance="structured" if failure_kind is not None else None,
                failure_code=failure_code,
            )
        finally:
            # Evidence sinks and output callbacks are user-controlled. Their
            # exceptions must not strand a Codex child (or descendants) after
            # this worker unwinds.
            if proc.poll() is None:
                self._terminate_process_group(proc, term_grace_sec)
            self._reap_after_cleanup(proc, cancel_event=cancel_event)

    @staticmethod
    def _read_stream(
        stream: TextIO | None,
        name: str,
        records: queue.Queue[CodexStreamRecord | None],
    ) -> None:
        try:
            if stream is not None:
                for line in iter(lambda: stream.readline(MAX_CODEX_STREAM_LINE_CHARS), ""):
                    records.put(CodexStreamRecord(name, line.rstrip("\r\n")))
        finally:
            records.put(None)

    @staticmethod
    def _deliver(
        record: CodexStreamRecord,
        callback: Callable[[CodexStreamRecord], None] | None,
        sink: TextIO | Callable[[CodexStreamRecord], None] | None,
    ) -> None:
        if callback:
            callback(record)
        if sink is None:
            return
        if callable(sink):
            sink(record)
        else:
            sink.write(f"[{record.stream}] {record.line}\n")
            sink.flush()

    @staticmethod
    def _observable_records(record: CodexStreamRecord, *, json_events: bool) -> tuple[CodexStreamRecord, ...]:
        """Expose assistant text, never raw JSON envelopes, to solver parsers."""
        if not json_events or record.stream != "stdout":
            return (record,)
        try:
            event = json.loads(record.line)
        except json.JSONDecodeError:
            return ()
        if not isinstance(event, dict) or event.get("type") != "item.completed":
            return ()
        item = event.get("item")
        if not isinstance(item, dict) or item.get("type") != "agent_message":
            return ()
        value = item.get("text")
        if not isinstance(value, str):
            return ()
        return tuple(CodexStreamRecord("stdout", line) for line in value.splitlines())

    @classmethod
    def _assistant_output(cls, lines: tuple[str, ...]) -> str:
        return "\n".join(
            record.line
            for line in lines
            for record in cls._observable_records(CodexStreamRecord("stdout", line), json_events=True)
        )

    def _terminate_process_group(self, proc: Any, grace_sec: float) -> None:
        self._kill_process_group(proc, signal.SIGTERM)
        deadline = self._clock() + grace_sec
        while proc.poll() is None and self._clock() < deadline:
            time.sleep(0.01)
        if proc.poll() is None:
            self._kill_process_group(proc, signal.SIGKILL)

    def _wait_until_reaped(
        self,
        proc: Any,
        *,
        started: float,
        timeout_sec: float | None,
        term_grace_sec: float,
        cancel_event: ThreadEvent | None,
        stop_requested: bool,
    ) -> tuple[int | None, bool]:
        """Wait in small intervals so cancellation remains live until reaping."""
        stopped = stop_requested
        while proc.poll() is None:
            should_stop = (cancel_event is not None and cancel_event.is_set()) or (
                timeout_sec is not None and self._clock() - started >= timeout_sec
            )
            if should_stop and not stopped:
                stopped = True
                self._terminate_process_group(proc, term_grace_sec)
                continue
            try:
                return proc.wait(timeout=0.05), stopped
            except subprocess.TimeoutExpired:
                continue
        return proc.poll(), stopped

    @staticmethod
    def _reap_after_cleanup(proc: Any, *, cancel_event: ThreadEvent | None) -> None:
        """Reap after TERM/KILL; keep polling cancellation even during unwind."""
        while proc.poll() is None:
            # There is no broader action cancellation can authorize here. It
            # is still observed so a fake/slow child never hides cancellation.
            _ = cancel_event.is_set() if cancel_event is not None else False
            try:
                proc.wait(timeout=0.05)
            except subprocess.TimeoutExpired:
                continue

    def _kill_process_group(self, proc: Any, sig: signal.Signals) -> None:
        # start_new_session above gives this process a private process group.
        # A process that already exited is not an error and must not cause us to
        # target a replacement PID or any broader process scope.
        if proc.poll() is not None:
            return
        try:
            self._killpg(proc.pid, sig)
        except ProcessLookupError:
            return

    @staticmethod
    def _parse_token_usage(output: str) -> int | None:
        match = re.search(r"(?:total[_ ]?tokens|tokens(?: used)?)[^0-9]{0,16}([0-9][0-9,]*)", output, re.IGNORECASE)
        return int(match.group(1).replace(",", "")) if match else None

    @staticmethod
    def _parse_session_id(output: str, *, machine_events_only: bool = False) -> str | None:
        for line in output.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                for key in ("thread_id", "session_id"):
                    value = event.get(key)
                    if isinstance(value, str) and _RESUME_ID.fullmatch(value):
                        return value
        if machine_events_only:
            return None
        match = re.search(r"session[ _-]?id\s*[:=]\s*\"?([A-Za-z0-9_.-]+)", output, re.IGNORECASE)
        return match.group(1) if match else None

    @staticmethod
    def _parse_resume_id(output: str, *, machine_events_only: bool = False) -> str | None:
        if machine_events_only:
            return CodexCliBackend._parse_session_id(output, machine_events_only=True)
        match = re.search(r"resume[ _-]?id\s*[:=]\s*\"?([A-Za-z0-9_.-]+)", output, re.IGNORECASE)
        if match:
            return match.group(1)
        return CodexCliBackend._parse_session_id(output)

    @staticmethod
    def _structured_failure(
        lines: tuple[str, ...], *, json_events: bool
    ) -> tuple[str | None, str | None]:
        """Classify only a Codex machine-event terminal error.

        ``item.completed`` agent messages and all human-readable stderr are
        deliberately ignored.  They are solver-controlled content and may
        contain phrases such as ``HTTP 429`` without saying anything about the
        Codex transport or selected model.
        """
        if not json_events:
            return None, None
        for line in lines:
            try:
                event = json.loads(line)
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(event, dict) or event.get("type") not in {"error", "turn.failed"}:
                continue
            error = event.get("error")
            if isinstance(error, dict):
                code = error.get("code") or error.get("type")
                if isinstance(code, str):
                    normalized = code.strip().casefold().replace("-", "_")
                    if normalized in {
                        "rate_limited", "rate_limit", "rate_limit_exceeded",
                        "usage_limit_exceeded", "quota_exceeded",
                    }:
                        return "rate_limited", normalized
                    if normalized in {
                        "model_unavailable", "model_not_found",
                        "service_unavailable", "service_overloaded",
                    }:
                        return "unavailable", normalized

            # Codex 0.144.1's localhost-provider transport omits code/type on
            # these terminal envelopes.  Message fallback is permitted only
            # inside the two trusted terminal event shapes above.
            message: object
            if event.get("type") == "error":
                message = event.get("message")
                if not isinstance(message, str) and isinstance(error, dict):
                    message = error.get("message")
            else:
                message = error.get("message") if isinstance(error, dict) else None
            if not isinstance(message, str):
                continue
            normalized_message = message.casefold()
            if "quota" in normalized_message:
                return "rate_limited", "quota_exceeded"
            if any(marker in normalized_message for marker in (
                "usage limit", "credit balance", "insufficient credit",
            )):
                return "rate_limited", "usage_limit_exceeded"
            if (re.search(r"(?:^|\D)429(?:\D|$)", normalized_message)
                    or "rate limit" in normalized_message
                    or "too many requests" in normalized_message):
                return "rate_limited", "rate_limit_exceeded"
            if ("model unavailable" in normalized_message
                    or "model is unavailable" in normalized_message
                    or "selected model" in normalized_message and "unavailable" in normalized_message
                    or "model not found" in normalized_message):
                return "unavailable", "model_unavailable"
            if (re.search(r"(?:^|\D)503(?:\D|$)", normalized_message)
                    or "service unavailable" in normalized_message
                    or "service overloaded" in normalized_message):
                return "unavailable", "service_unavailable"
        return None, None

    @staticmethod
    def strict_isolation_supported(command: str = "codex") -> bool:
        """Fail closed unless the exact strict-profile invocation parses.

        A help-page token check alone is not sufficient: older CLIs accepted
        the legacy ``--sandbox`` flag while silently selecting it over named
        permission profiles.  This probe validates the production argv shape
        first, then gives that exact config construction to ``codex exec
        --help``.  The latter remains local/no-model while catching option or
        strict-config parsing incompatibilities.
        """
        try:
            result = subprocess.run(
                [command, "exec", "--help"], check=False, shell=False,
                text=True, capture_output=True, timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        if result.returncode != 0:
            return False
        text = (result.stdout or "") + (result.stderr or "")
        if not all(option in text for option in (
            "--strict-config", "--ignore-user-config", "--ignore-rules", "--ephemeral", "--disable", "--config",
        )):
            return False
        try:
            with tempfile.TemporaryDirectory(prefix="ctf-os-isolation-probe-") as root_text:
                root = Path(root_text)
                os.chmod(root, 0o700)
                (root / ".ctf-os-sterile-attempt").write_text("probe\n", encoding="utf-8")
                os.chmod(root / ".ctf-os-sterile-attempt", 0o600)
                workdir = root / "work"
                workdir.mkdir(mode=0o700)
                socket_path = workdir / _BROKER_IPC_DIRECTORY
                argv = [
                    command, "exec", "--strict-config", "--ignore-user-config", "--ignore-rules", "--ephemeral",
                    "--disable", "hooks", "--skip-git-repo-check", "-C", str(workdir), "-m", "ctf-os-probe",
                    "-c", 'model_reasoning_effort="low"', "-c", 'approval_policy="never"', "-c", "mcp_servers={}",
                    "-c", 'default_permissions="ctf_os_attempt"',
                    "-c", _permission_profile_override(
                        workdir, socket_path, runtime_executable=_runtime_executable(command),
                    ),
                    "--help",
                ]
                runtime_executable = _runtime_executable(command)
                _validate_production_argv(
                    argv[:-1], workdir=workdir, socket_path=socket_path,
                    runtime_executable=runtime_executable,
                )
                parsed = subprocess.run(argv, check=False, shell=False, text=True, capture_output=True, timeout=5)
                if parsed.returncode != 0:
                    return False
                # ``exec --help`` accepts some nested TOML shapes lazily.
                # Exercise the named profile loader too so the installed CLI
                # must parse the production network-disabled profile.  The
                # standalone sandbox may be unable
                # to execute under a root-deny profile on a host, but a
                # sandbox-launch failure is distinct from a profile parse
                # failure and still proves the nested schema was accepted.
                sandbox_argv = [
                    command, "sandbox", "-C", str(workdir), "-P", "ctf_os_attempt",
                    "-c", 'default_permissions="ctf_os_attempt"',
                    "-c", _permission_profile_override(
                        workdir, socket_path, runtime_executable=runtime_executable,
                    ), "--", "/bin/true",
                ]
                sandbox_parsed = subprocess.run(
                    sandbox_argv, check=False, shell=False, text=True, capture_output=True, timeout=5,
                )
        except (OSError, subprocess.SubprocessError, ValueError):
            return False
        parsed_text = ((parsed.stdout or "") + (parsed.stderr or "")).casefold()
        sandbox_text = ((sandbox_parsed.stdout or "") + (sandbox_parsed.stderr or "")).casefold()
        return not any(marker in parsed_text + sandbox_text for marker in (
            "unknown option", "unknown argument", "unknown configuration", "unknown config", "invalid configuration",
            "invalid type", "expected struct", "in `permissions`",
        ))


def _validate_production_argv(
    argv: list[str], *, workdir: Path, socket_path: Path,
    runtime_executable: Path | None = None, require_ephemeral: bool = True,
) -> None:
    """Assert the non-negotiable named-profile argv construction."""
    if any(item in _DANGEROUS_CLI_TOKENS or "dangerously-bypass" in item or "danger-full-access" in item for item in argv):
        raise ValueError("production Codex argv contains a legacy sandbox or dangerous escape hatch")
    required_flags = {"--strict-config", "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check"}
    if require_ephemeral:
        required_flags.add("--ephemeral")
    if not required_flags.issubset(argv):
        raise ValueError("production Codex argv lacks strict isolation flags")
    configs = [argv[index + 1] for index, item in enumerate(argv[:-1]) if item == "-c"]
    profile = _permission_profile_override(
        workdir, socket_path, runtime_executable=runtime_executable,
    )
    required_configs = {
        'approval_policy="never"', "mcp_servers={}", 'default_permissions="ctf_os_attempt"', profile,
    }
    if not required_configs.issubset(configs):
        raise ValueError("production Codex argv lacks the authoritative named permission profile")
    if any(item.startswith(("sandbox_mode=", "permissions.default=", "default_permissions=\"workspace-write")) for item in configs):
        raise ValueError("production Codex argv contains a conflicting sandbox configuration")
    if ("network={enabled=false" not in profile or "unix_sockets" in profile
            or "enabled=true" in profile):
        raise ValueError("production Codex permission profile must deny host network access")
