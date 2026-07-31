"""Streaming, schema-validating Codex Batch execution."""

from __future__ import annotations

import codecs
import json
import math
import os
import queue
import select
import signal
import stat
import subprocess
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from pathlib import Path
from typing import BinaryIO, Protocol

from ctf_os.process import _popen_with_constructor_cleanup

from .commands import BatchCommandBuilder, BatchInvocation, BuiltCommand
from .contracts import (
    ContractValidation,
    Role,
    role_output_schema,
    validate_role_output,
)
from .events import (
    DEFAULT_EVENT_COUNT_LIMIT,
    DEFAULT_FLAG_CANDIDATE_CHARS_LIMIT,
    DEFAULT_FLAG_CANDIDATE_LIMIT,
    DEFAULT_MALFORMED_LINE_COUNT_LIMIT,
    CodexEvent,
    EventAccumulator,
    ExecutionFailure,
    FlagCandidate,
    FlagDetector,
    FlagNotificationError,
    Usage,
)
from .limiter import (
    ModelCallLimitCancelled,
    ModelCallLimiter,
    ModelCallLimitTimeout,
    ModelCallSlot,
    UnlimitedModelCallLimiter,
)

DEFAULT_RAW_JSONL_LIMIT_BYTES = 16 * 1024 * 1024
DEFAULT_STDERR_LIMIT_BYTES = 1024 * 1024
DEFAULT_STRUCTURED_OUTPUT_LIMIT_BYTES = 2 * 1024 * 1024
DEFAULT_EVENT_LINE_LIMIT_BYTES = 1024 * 1024
DEFAULT_FLAG_SCAN_CHUNK_CHARS = 64 * 1024
DEFAULT_FLAG_SCAN_OVERLAP_CHARS = 1024
DEFAULT_PROCESS_TERMINATE_GRACE_SECONDS = 0.5
DEFAULT_PROCESS_DRAIN_GRACE_SECONDS = 1.0


def _bounded_exception_message(error: BaseException) -> str:
    """Describe a callback failure without invoking user-defined formatting."""

    name = type(error).__name__
    try:
        arguments = BaseException.args.__get__(error, type(error))
        first = arguments[0] if arguments else None
    except BaseException:
        first = None
    if type(first) is not str:
        return name
    detail = first[:4096]
    if len(first) > len(detail):
        detail += "…"
    return f"{name}: {detail}"


def _prioritize_cleanup_error(
    primary: BaseException | None,
    latest: BaseException,
    *,
    context: str,
) -> BaseException:
    """Keep the first control interruption ahead of ordinary retry errors."""

    if primary is None:
        return latest
    if not isinstance(latest, Exception) and isinstance(primary, Exception):
        latest.add_note(
            f"{context}; earlier cleanup failure: "
            f"{_bounded_exception_message(primary)}"
        )
        return latest
    primary.add_note(
        f"{context}: {_bounded_exception_message(latest)}"
    )
    return primary


def _close_stream_bounded(
    stream: BinaryIO,
    *,
    label: str,
) -> tuple[BaseException | None, bool]:
    """Close one exact subprocess stream with one bounded retry."""

    first_error: BaseException | None = None
    for attempt in range(2):
        try:
            stream.close()
        except BaseException as error:
            first_error = _prioritize_cleanup_error(
                first_error,
                error,
                context=f"{label} stream close retry failed",
            )
            if attempt == 0:
                continue
        else:
            return first_error, True
    return first_error, False


@dataclass(frozen=True)
class ProcessOutcome:
    returncode: int
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    stderr_bytes: int | None = None
    stderr_truncated: bool = False
    stderr_raw: bytes | None = None
    stdout_capture_complete: bool = True
    stderr_capture_complete: bool = True
    callback_error: str | None = None


class ProcessExecutor(Protocol):
    def run(
        self,
        command: BuiltCommand,
        *,
        cwd: Path,
        timeout: float | None,
        on_stdout_line: Callable[[str | bytes], None],
    ) -> ProcessOutcome:
        ...


class CommandBuilder(Protocol):
    def build(
        self,
        invocation: BatchInvocation,
        schema_path: Path,
        output_path: Path,
        *,
        resume_thread_id: str | None = None,
        correction: str | None = None,
    ) -> BuiltCommand:
        ...


class _ProcessPumpControl:
    """Coordinate sole stream owners with concurrent process cancellation."""

    def __init__(self) -> None:
        self.output_stop = threading.Event()
        self.stdin_stop = threading.Event()
        self.lifecycle_lock = threading.Lock()
        self.threads: dict[str, threading.Thread] = {}
        self.close_results_lock = threading.Lock()
        self.close_results: dict[
            str,
            tuple[BaseException | None, bool],
        ] = {}

    def record_close(
        self,
        label: str,
        result: tuple[BaseException | None, bool],
    ) -> None:
        with self.close_results_lock:
            self.close_results[label] = result

    def take_close_result(
        self,
        label: str,
    ) -> tuple[BaseException | None, bool] | None:
        with self.close_results_lock:
            result = self.close_results.get(label)
            if (
                result is not None
                and result[0] is not None
                and not isinstance(result[0], Exception)
            ):
                # A stored control interruption is propagated exactly once.
                # Its ownership result remains durable: confirmed retirement
                # becomes clean, while uncertainty becomes an ordinary
                # fail-closed marker that cleanup retries may wait to replace.
                # Re-reading the same object must never be mistaken for a
                # second independent control signal.
                self.close_results[label] = (
                    (
                        None
                        if result[1]
                        else RuntimeError(
                            f"subprocess {label} stream close remains "
                            "unconfirmed after a control interruption"
                        )
                    ),
                    result[1],
                )
            return result


def _thread_definitely_unstarted(thread: threading.Thread) -> bool:
    """Identify the CPython 3.13 state where no native owner was created."""

    try:
        if thread.ident is not None or thread.is_alive():
            return False
        handle = getattr(thread, "_handle", None)
        native_ident = getattr(handle, "ident", None)
    except BaseException:
        return False
    # CPython 3.13 initializes each Thread handle with ident=0 and publishes a
    # nonzero native identity inside _start_joinable_thread(), before
    # Thread._started/ident is set by bootstrap.  Any unknown implementation is
    # conservatively treated as a possibly delayed owner.
    return type(native_ident) is int and native_ident == 0


class SubprocessExecutor:
    """Run without a shell and stream stdout while draining stderr."""

    def __init__(
        self,
        *,
        stderr_limit_bytes: int = DEFAULT_STDERR_LIMIT_BYTES,
        terminate_grace_seconds: float = (
            DEFAULT_PROCESS_TERMINATE_GRACE_SECONDS
        ),
        drain_grace_seconds: float = DEFAULT_PROCESS_DRAIN_GRACE_SECONDS,
    ) -> None:
        if stderr_limit_bytes < 0:
            raise ValueError("stderr_limit_bytes must not be negative")
        for name, value in (
            ("terminate_grace_seconds", terminate_grace_seconds),
            ("drain_grace_seconds", drain_grace_seconds),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or value <= 0
            ):
                raise ValueError(
                    f"{name} must be positive and finite"
                )
        self.stderr_limit_bytes = stderr_limit_bytes
        self.terminate_grace_seconds = float(terminate_grace_seconds)
        self.drain_grace_seconds = float(drain_grace_seconds)
        self._active_lock = threading.Lock()
        self._active_processes: dict[
            int,
            tuple[
                subprocess.Popen[bytes],
                threading.Event | None,
                object,
            ],
        ] = {}
        self._pump_controls: dict[
            int,
            tuple[subprocess.Popen[bytes], _ProcessPumpControl],
        ] = {}

    def cancel_active(
        self,
        *,
        cancel_event: threading.Event | None = None,
    ) -> None:
        """Terminate active process groups, optionally for one logical wave."""

        with self._active_lock:
            processes = tuple(
                process
                for (
                    process,
                    owner_event,
                    _owner_token,
                ) in self._active_processes.values()
                if cancel_event is None or owner_event is cancel_event
            )
        try:
            self._terminate_processes(processes)
        except BaseException as error:
            propagated_error = self._retry_cleanup_until_confirmed(
                lambda: self._terminate_processes(processes),
                active_error=error,
                label="subprocess active cancellation cleanup",
            )
            self._forget_processes(processes)
            if propagated_error is not error:
                raise propagated_error
            raise
        self._forget_processes(processes)

    def _cancel_owner(self, owner_token: object) -> None:
        with self._active_lock:
            processes = tuple(
                process
                for (
                    process,
                    _owner_event,
                    active_owner_token,
                ) in self._active_processes.values()
                if active_owner_token is owner_token
            )
        self._terminate_processes(processes)
        self._forget_processes(processes)

    @staticmethod
    def _retry_cleanup_until_confirmed(
        cleanup: Callable[[], None],
        *,
        active_error: BaseException,
        label: str,
        stop_on_repeated_control: bool = True,
    ) -> BaseException:
        """Hold the caller's scope until exact cleanup is confirmed.

        Ordinary cleanup failures are not role failures: returning through that
        containment boundary would release the challenge session lock while the
        executor still owns a process.  The first control interruption becomes
        (or remains) the primary exception and cleanup continues.  A second
        independent control interruption is the documented crash-only boundary
        unless a caller explicitly owns a broader drain gate and elects to keep
        retrying it.
        """

        primary_error = active_error
        control_seen = not isinstance(active_error, Exception)
        repeated_control_noted = False
        failures = 0

        def record_failure(error: BaseException) -> None:
            nonlocal control_seen, failures
            nonlocal primary_error, repeated_control_noted
            failures += 1
            if not isinstance(error, Exception):
                if control_seen:
                    if not repeated_control_noted:
                        primary_error.add_note(
                            f"{label} retry was interrupted by a second "
                            f"{_bounded_exception_message(error)}"
                        )
                        repeated_control_noted = True
                    if stop_on_repeated_control:
                        raise primary_error
                    return
                error.add_note(
                    f"{label} was interrupted while handling "
                    f"{_bounded_exception_message(active_error)}"
                )
                primary_error = error
                control_seen = True
            if failures == 1:
                primary_error.add_note(
                    f"{label} failed and is being retried: "
                    f"{_bounded_exception_message(error)}"
                )

        while True:
            try:
                cleanup()
            except BaseException as cleanup_error:
                record_failure(cleanup_error)
                try:
                    time.sleep(0.01)
                except BaseException as wait_error:
                    record_failure(wait_error)
                continue
            if failures:
                primary_error.add_note(
                    f"{label} recovered after {failures + 1} attempts"
                )
            return primary_error

    def _register_owner(
        self,
        process: subprocess.Popen[bytes],
        cancel_event: threading.Event | None,
        owner_token: object,
        pump_control: _ProcessPumpControl,
    ) -> None:
        """Register one exact process, preserving a lost lock/STORE interrupt."""

        first_error: BaseException | None = None
        for attempt in range(2):
            try:
                with self._active_lock:
                    existing = self._active_processes.get(process.pid)
                    if (
                        existing is not None
                        and existing[0] is not process
                    ):
                        raise RuntimeError(
                            "subprocess registry PID identity collision"
                        )
                    existing_control = self._pump_controls.get(process.pid)
                    if (
                        existing_control is not None
                        and existing_control[0] is not process
                    ):
                        raise RuntimeError(
                            "subprocess pump-control PID identity collision"
                        )
                    # Publish cancellation coordination before the process is
                    # visible to cancel_active(). If registration is
                    # interrupted between these stores, the caller's exact
                    # cleanup can still stop and serialize with the pump.
                    self._pump_controls[process.pid] = (
                        process,
                        pump_control,
                    )
                    self._active_processes[process.pid] = (
                        process,
                        cancel_event,
                        owner_token,
                    )
            except BaseException as error:
                first_error = _prioritize_cleanup_error(
                    first_error,
                    error,
                    context="subprocess owner registration retry failed",
                )
                if attempt == 0:
                    continue
            else:
                if first_error is not None and not isinstance(
                    first_error, Exception
                ):
                    raise first_error
                return
        assert first_error is not None
        raise first_error

    def _forget_processes(
        self,
        processes: tuple[subprocess.Popen[bytes], ...],
    ) -> None:
        """Forget only registry entries that still name the exact objects."""

        if not processes:
            return
        exact = {process.pid: process for process in processes}
        with self._active_lock:
            for process_id, process in exact.items():
                active = self._active_processes.get(process_id)
                if active is not None and active[0] is process:
                    self._active_processes.pop(process_id, None)
                pump_control = self._pump_controls.get(process_id)
                if (
                    pump_control is not None
                    and pump_control[0] is process
                ):
                    self._pump_controls.pop(process_id, None)

    def _forget_owner(self, owner_token: object) -> None:
        with self._active_lock:
            for process_id, (
                _process,
                _owner_event,
                active_owner_token,
            ) in tuple(self._active_processes.items()):
                if active_owner_token is owner_token:
                    self._active_processes.pop(process_id, None)
                    pump_control = self._pump_controls.get(process_id)
                    if (
                        pump_control is not None
                        and pump_control[0] is _process
                    ):
                        self._pump_controls.pop(process_id, None)

    def _controls_for_processes(
        self,
        processes: tuple[subprocess.Popen[bytes], ...],
    ) -> dict[int, _ProcessPumpControl]:
        controls: dict[int, _ProcessPumpControl] = {}
        with self._active_lock:
            for process in processes:
                owned = self._pump_controls.get(process.pid)
                if owned is not None and owned[0] is process:
                    controls[id(process)] = owned[1]
        return controls

    @staticmethod
    def _process_group_is_live(
        process: subprocess.Popen[bytes],
    ) -> bool:
        """Probe the exact process group, treating uncertainty as live."""

        for attempt in range(2):
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return False
            except OSError:
                if attempt == 0:
                    continue
                # EPERM and persistent probe failures are fail-closed.
                return True
            else:
                return True
        return True

    def _terminate_processes(
        self,
        processes: tuple[subprocess.Popen[bytes], ...],
    ) -> None:
        if not processes:
            return
        pump_controls = self._controls_for_processes(processes)
        signal_errors: list[BaseException] = []
        stream_errors: list[
            tuple[str, BaseException, bool]
        ] = []

        def process_streams(
            process: subprocess.Popen[bytes],
        ) -> tuple[tuple[str, BinaryIO | None], ...]:
            return (
                ("stdin", process.stdin),
                ("stdout", process.stdout),
                ("stderr", process.stderr),
            )

        def record_stream_result(
            label: str,
            result: tuple[BaseException | None, bool],
        ) -> None:
            close_error, closed = result
            if close_error is not None and (
                not closed
                or not isinstance(close_error, Exception)
            ):
                if not isinstance(close_error, Exception):
                    close_error.add_note(
                        f"subprocess {label} stream close was interrupted"
                    )
                    raise close_error
                stream_errors.append((label, close_error, closed))

        for process in processes:
            control = pump_controls.get(id(process))
            if control is None:
                continue
            with control.lifecycle_lock:
                # Publish both stop requests before TERM/KILL/reap. Registered
                # pumps are the sole closers of every stream they claimed, so
                # no peer can retire and reuse a numeric fd under their raw
                # read/write calls.
                control.output_stop.set()
                control.stdin_stop.set()
                # Presence in this map is ownership intent, even while ident
                # is still None: Thread.start() can have created the native
                # thread before its bootstrap publishes ident. Treating that
                # ambiguous state as pre-pump could close and reuse its fd
                # immediately before the pump begins running.
                started_labels = frozenset(control.threads)
                # Registration deliberately precedes ownership publication.
                # Only labels that are not in the map are certainly pre-pump
                # and may be closed here.
                for label, stream in process_streams(process):
                    if stream is None or label in started_labels:
                        continue
                    record_stream_result(
                        label,
                        _close_stream_bounded(stream, label=label),
                    )

        def send_group(
            process: subprocess.Popen[bytes],
            sent_signal: int,
        ) -> None:
            first_error: BaseException | None = None
            for attempt in range(2):
                try:
                    os.killpg(process.pid, sent_signal)
                except ProcessLookupError:
                    if first_error is not None:
                        signal_errors.append(first_error)
                    return
                except BaseException as error:
                    first_error = _prioritize_cleanup_error(
                        first_error,
                        error,
                        context="subprocess signal retry failed",
                    )
                    if not isinstance(first_error, Exception):
                        raise first_error
                    if attempt == 0:
                        continue
                else:
                    break
            if first_error is not None:
                signal_errors.append(first_error)

        def process_is_running(process: subprocess.Popen[bytes]) -> bool:
            try:
                return process.poll() is None
            except OSError:
                # A transient waitpid/poll failure is unknown, not evidence
                # that the exact process group has exited.
                return True

        # Signal the group even if its leader has already been reaped: a
        # same-PGID descendant may still own inherited output pipes.
        for process in processes:
            send_group(process, signal.SIGTERM)
        terminate_deadline = (
            time.monotonic() + self.terminate_grace_seconds
        )
        while (
            any(
                process_is_running(process)
                or self._process_group_is_live(process)
                for process in processes
            )
            and time.monotonic() < terminate_deadline
        ):
            time.sleep(0.01)
        # A group leader may exit on SIGTERM while one of its descendants
        # ignores it, so always signal each exact process group with SIGKILL.
        for process in processes:
            send_group(process, signal.SIGKILL)
        kill_deadline = time.monotonic() + self.terminate_grace_seconds
        live_groups: set[int] = {process.pid for process in processes}
        while time.monotonic() < kill_deadline:
            for process in processes:
                if process.pid not in live_groups:
                    continue
                if not self._process_group_is_live(process):
                    live_groups.discard(process.pid)
            if not live_groups:
                break
            time.sleep(0.01)
        wait_errors: list[BaseException] = []
        pump_join_timeout = max(self.drain_grace_seconds, 0.25)
        for process in processes:
            try:
                process.wait(timeout=self.terminate_grace_seconds)
            except BaseException as error:
                if not isinstance(error, Exception):
                    raise
                wait_errors.append(error)
            control = pump_controls.get(id(process))
            if control is None:
                for label, stream in process_streams(process):
                    if stream is not None:
                        record_stream_result(
                            label,
                            _close_stream_bounded(stream, label=label),
                        )
                continue
            with control.lifecycle_lock:
                registered_threads = tuple(control.threads.items())
            started_threads: list[
                tuple[str, threading.Thread]
            ] = []
            for label, pump_thread in registered_threads:
                try:
                    pump_ident = pump_thread.ident
                except BaseException as error:
                    if not isinstance(error, Exception):
                        raise
                    stream_errors.append((label, error, False))
                    continue
                if pump_ident is None:
                    stream_errors.append(
                        (
                            label,
                            RuntimeError(
                                f"subprocess {label} pump native start "
                                "state is pending"
                            ),
                            False,
                        )
                    )
                    continue
                started_threads.append((label, pump_thread))
            pump_join_deadline = time.monotonic() + pump_join_timeout
            for label, pump_thread in started_threads:
                if pump_thread is not threading.current_thread():
                    try:
                        pump_thread.join(
                            timeout=max(
                                0.0,
                                pump_join_deadline - time.monotonic(),
                            )
                        )
                    except BaseException as error:
                        if not isinstance(error, Exception):
                            raise
                        signal_errors.append(error)
                try:
                    pump_alive = pump_thread.is_alive()
                except BaseException as error:
                    if not isinstance(error, Exception):
                        raise
                    stream_errors.append((label, error, False))
                    continue
                if pump_alive:
                    stream_errors.append(
                        (
                            label,
                            RuntimeError(
                                f"subprocess {label} pump did not stop"
                            ),
                            False,
                        )
                    )
                    continue
                try:
                    close_result = control.take_close_result(label)
                except BaseException as error:
                    if not isinstance(error, Exception):
                        raise
                    stream_errors.append((label, error, False))
                    continue
                if close_result is None:
                    stream_errors.append(
                        (
                            label,
                            RuntimeError(
                                f"subprocess {label} pump did not report close"
                            ),
                            False,
                        )
                    )
                    continue
                record_stream_result(label, close_result)
        # Reaping a leader can remove the last process-group identity. Refresh
        # the pre-wait set so a completed exact cleanup does not report a
        # stale live group.
        for process in processes:
            if (
                process.pid in live_groups
                and not self._process_group_is_live(process)
            ):
                live_groups.discard(process.pid)
        persistent_stream_errors = [
            item for item in stream_errors if not item[2]
        ]
        interruption = next(
            (
                error
                for error in (
                    *signal_errors,
                    *(
                        stream_error
                        for _label, stream_error, _closed in stream_errors
                    ),
                )
                if not isinstance(error, Exception)
            ),
            None,
        )
        if live_groups or wait_errors or persistent_stream_errors:
            error: BaseException = (
                interruption
                if interruption is not None
                else RuntimeError(
                    "subprocess group cleanup did not confirm exit and reap"
                )
            )
            if interruption is not None:
                error.add_note(
                    "subprocess group cleanup did not confirm exit and reap"
                )
            for signal_error in signal_errors:
                if signal_error is error:
                    continue
                error.add_note(
                    "subprocess signal failed: "
                    f"{_bounded_exception_message(signal_error)}"
                )
            for wait_error in wait_errors:
                error.add_note(
                    "subprocess reap failed: "
                    f"{_bounded_exception_message(wait_error)}"
                )
            for label, stream_error, _closed in stream_errors:
                if stream_error is error:
                    continue
                error.add_note(
                    f"subprocess {label} stream cleanup failed: "
                    f"{_bounded_exception_message(stream_error)}"
                )
            raise error
        if interruption is not None:
            raise interruption

    def run(
        self,
        command: BuiltCommand,
        *,
        cwd: Path,
        timeout: float | None,
        on_stdout_line: Callable[[str | bytes], None],
        cancel_event: threading.Event | None = None,
    ) -> ProcessOutcome:
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(float(timeout))
            or timeout <= 0
        ):
            raise ValueError("process timeout must be positive and finite")
        owner_token = object()
        cleanup_confirmed = False
        try:
            outcome = self._run_tracked(
                command,
                cwd=cwd,
                timeout=timeout,
                on_stdout_line=on_stdout_line,
                cancel_event=cancel_event,
                owner_token=owner_token,
            )
            cleanup_confirmed = True
            return outcome
        except BaseException as error:
            propagated_error = self._retry_cleanup_until_confirmed(
                lambda: self._cancel_owner(owner_token),
                active_error=error,
                label="subprocess interruption cleanup",
            )
            cleanup_confirmed = True
            if propagated_error is not error:
                raise propagated_error
            raise
        finally:
            # Retain ownership after a persistent cleanup failure so a caller
            # can retry exact scoped cancellation instead of losing the child.
            if cleanup_confirmed:
                self._forget_owner(owner_token)

    def _run_tracked(
        self,
        command: BuiltCommand,
        *,
        cwd: Path,
        timeout: float | None,
        on_stdout_line: Callable[[str | bytes], None],
        cancel_event: threading.Event | None = None,
        owner_token: object,
    ) -> ProcessOutcome:
        started = time.monotonic()
        pending_handoff: list[subprocess.Popen[bytes]] = []
        process: subprocess.Popen[bytes] | None = None
        pump_control = _ProcessPumpControl()
        try:
            process = _popen_with_constructor_cleanup(
                command.argv,
                pending_handoff=pending_handoff,
                interrupt_cleanup=lambda interrupted: (
                    self._terminate_processes((interrupted,))
                ),
                cleanup_failure_note=(
                    "unregistered subprocess cleanup failed"
                ),
                cwd=cwd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=command.environment,
                text=False,
                bufsize=0,
                start_new_session=True,
            )
            assert process.stdin is not None
            assert process.stdout is not None
            assert process.stderr is not None
            self._register_owner(
                process,
                cancel_event,
                owner_token,
                pump_control,
            )
            pending_handoff.clear()
        except BaseException as registration_error:
            interrupted_process = (
                process
                if process is not None
                else pending_handoff[0]
                if pending_handoff
                else None
            )
            pending_handoff.clear()
            if interrupted_process is not None:
                def cleanup_interrupted_process() -> None:
                    self._terminate_processes((interrupted_process,))
                    self._forget_processes((interrupted_process,))

                propagated_error = self._retry_cleanup_until_confirmed(
                    cleanup_interrupted_process,
                    active_error=registration_error,
                    label="unregistered subprocess cleanup",
                )
                if propagated_error is not registration_error:
                    raise propagated_error
            raise
        assert process is not None
        cancelled_on_start = (
            cancel_event is not None and cancel_event.is_set()
        )
        if cancelled_on_start:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

        stream_queue: queue.Queue[
            tuple[str, bytes | None, bool]
        ] = queue.Queue(maxsize=16)
        pump_stop = pump_control.output_stop
        stdin_stop = pump_control.stdin_stop

        def enqueue(
            item: tuple[str, bytes | None, bool],
        ) -> bool:
            while not pump_stop.is_set():
                try:
                    stream_queue.put(item, timeout=0.1)
                    return True
                except queue.Full:
                    continue
            return False

        def pump(name: str, stream) -> None:
            reached_eof = False
            try:
                if pump_stop.is_set():
                    return
                descriptor = stream.fileno()
                while not pump_stop.is_set():
                    readable, _, _ = select.select(
                        (descriptor,),
                        (),
                        (),
                        0.1,
                    )
                    if not readable:
                        continue
                    chunk = os.read(stream.fileno(), 64 * 1024)
                    if not chunk:
                        reached_eof = True
                        break
                    if not enqueue((name, chunk, False)):
                        return
            except (OSError, ValueError):
                reached_eof = False
            finally:
                pump_control.record_close(
                    name,
                    _close_stream_bounded(stream, label=name),
                )
                enqueue((name, None, reached_eof))

        stdout_thread = threading.Thread(
            target=pump, args=("stdout", process.stdout), daemon=True
        )
        stderr_thread = threading.Thread(
            target=pump, args=("stderr", process.stderr), daemon=True
        )

        def pump_stdin() -> None:
            """Write stdin without blocking output drainage or the deadline."""

            text_offset = 0
            pending = b""
            pending_offset = 0
            try:
                if stdin_stop.is_set():
                    return
                try:
                    descriptor = process.stdin.fileno()
                    os.set_blocking(descriptor, False)
                except (OSError, ValueError):
                    return
                while not stdin_stop.is_set():
                    if pending_offset >= len(pending):
                        if text_offset >= len(command.stdin):
                            break
                        piece = command.stdin[
                            text_offset : text_offset + 16 * 1024
                        ]
                        text_offset += len(piece)
                        try:
                            pending = piece.encode("utf-8")
                        except UnicodeError:
                            break
                        pending_offset = 0
                    try:
                        _, writable, _ = select.select(
                            (),
                            (descriptor,),
                            (),
                            min(0.1, self.drain_grace_seconds),
                        )
                    except (OSError, ValueError):
                        break
                    if not writable:
                        continue
                    if stdin_stop.is_set():
                        break
                    try:
                        written = os.write(
                            descriptor,
                            memoryview(pending)[pending_offset:],
                        )
                    except BlockingIOError:
                        continue
                    except OSError:
                        break
                    if written <= 0:
                        break
                    pending_offset += written
            finally:
                pump_control.record_close(
                    "stdin",
                    _close_stream_bounded(
                        process.stdin,
                        label="stdin",
                    ),
                )

        stdin_thread = threading.Thread(
            target=pump_stdin,
            name=f"ctfos-stdin-{process.pid}",
            daemon=True,
        )
        with pump_control.lifecycle_lock:
            for label, pump_thread in (
                ("stdout", stdout_thread),
                ("stderr", stderr_thread),
                ("stdin", stdin_thread),
            ):
                # Publish the resource-free Thread owner before start(). If
                # start succeeds and its return is interrupted, cancellation
                # already leaves the stream exclusively with that pump. An
                # ident=None owner is also conservatively retained because
                # native-thread creation may already have succeeded; delayed
                # finalization is safer than an ABA close.
                pump_control.threads[label] = pump_thread
                try:
                    pump_thread.start()
                except BaseException:
                    if _thread_definitely_unstarted(pump_thread):
                        pump_control.threads.pop(label, None)
                    raise

        deadline = (
            None
            if cancelled_on_start or timeout is None
            else started + timeout
        )
        closed: set[str] = set()
        stderr_capture = bytearray()
        stderr_bytes = 0
        timed_out = False
        force_kill_at: float | None = (
            time.monotonic() + self.terminate_grace_seconds
            if cancelled_on_start
            else None
        )
        drain_deadline: float | None = None
        callback_error: str | None = None
        callback_interrupt: BaseException | None = None
        flag_notification_failure: FlagNotificationError | None = None
        capture_complete: dict[str, bool] = {
            "stdout": False,
            "stderr": False,
        }
        while len(closed) < 2:
            now = time.monotonic()
            if (
                cancel_event is not None
                and cancel_event.is_set()
                and process.poll() is None
                and force_kill_at is None
            ):
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                force_kill_at = (
                    now + self.terminate_grace_seconds
                )
                deadline = None
            if process.poll() is not None and drain_deadline is None:
                # A detached descendant may inherit the pipe after the direct
                # child exits. Give already-buffered output a bounded drain
                # window instead of holding the provider slot forever.
                deadline = None
                drain_deadline = now + self.drain_grace_seconds
            if drain_deadline is not None and now >= drain_deadline:
                break
            remaining = None if deadline is None else deadline - now
            if remaining is not None and remaining <= 0:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                force_kill_at = now + self.terminate_grace_seconds
                deadline = None
            if force_kill_at is not None and now >= force_kill_at:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                force_kill_at = None
                if drain_deadline is None:
                    drain_deadline = now + self.drain_grace_seconds
            wait_for = 0.1
            for next_deadline in (
                deadline,
                force_kill_at,
                drain_deadline,
            ):
                if next_deadline is not None:
                    wait_for = min(
                        wait_for,
                        max(0.01, next_deadline - time.monotonic()),
                    )
            try:
                name, chunk, reached_eof = stream_queue.get(
                    timeout=wait_for
                )
            except queue.Empty:
                continue
            if chunk is None:
                closed.add(name)
                capture_complete[name] = reached_eof
            elif name == "stdout":
                if callback_error is None:
                    try:
                        on_stdout_line(chunk)
                    except BaseException as exc:
                        callback_error = _bounded_exception_message(exc)
                        if isinstance(exc, FlagNotificationError):
                            flag_notification_failure = exc
                        elif not isinstance(exc, Exception):
                            callback_interrupt = exc
                        deadline = None
                        # Leave the streaming loop immediately and use the
                        # common exact-group TERM/KILL/wait path below. A
                        # direct killpg here could mask the callback's original
                        # BaseException on a transient signal error.
                        break
            else:
                stderr_bytes += len(chunk)
                remaining_capture = self.stderr_limit_bytes - len(stderr_capture)
                if remaining_capture > 0:
                    stderr_capture.extend(chunk[:remaining_capture])

        callback_failure = (
            flag_notification_failure
            if flag_notification_failure is not None
            else callback_interrupt
        )
        pump_stop.set()
        pump_join_timeout = max(self.drain_grace_seconds, 0.25)
        pump_join_deadline = time.monotonic() + pump_join_timeout
        stream_close_errors: list[
            tuple[str, BaseException, bool]
        ] = []

        def output_cleanup_primary() -> BaseException | None:
            primary = callback_failure
            for label, close_error, closed_stream in stream_close_errors:
                if closed_stream and isinstance(close_error, Exception):
                    continue
                if primary is None:
                    primary = close_error
                else:
                    primary = _prioritize_cleanup_error(
                        primary,
                        close_error,
                        context=f"subprocess {label} stream cleanup failed",
                    )
            return primary

        def propagate_output_operation_error(
            error: BaseException,
            *,
            context: str,
        ) -> None:
            primary = output_cleanup_primary()
            if primary is None:
                raise error
            prioritized = _prioritize_cleanup_error(
                primary,
                error,
                context=context,
            )
            raise prioritized

        for label, pump_thread in (
            ("stdout", stdout_thread),
            ("stderr", stderr_thread),
        ):
            try:
                pump_thread.join(
                    timeout=max(
                        0.0,
                        pump_join_deadline - time.monotonic(),
                    )
                )
            except BaseException as error:
                propagate_output_operation_error(
                    error,
                    context=f"subprocess {label} pump join failed",
                )
            try:
                pump_alive = pump_thread.is_alive()
            except BaseException as error:
                propagate_output_operation_error(
                    error,
                    context=f"subprocess {label} pump state check failed",
                )
            if pump_alive:
                stream_close_errors.append(
                    (
                        label,
                        RuntimeError(
                            f"subprocess {label} pump did not stop"
                        ),
                        False,
                    )
                )
                continue
            try:
                close_result = pump_control.take_close_result(label)
            except BaseException as error:
                propagate_output_operation_error(
                    error,
                    context=(
                        f"subprocess {label} pump close result failed"
                    ),
                )
            if close_result is None:
                stream_close_errors.append(
                    (
                        label,
                        RuntimeError(
                            f"subprocess {label} pump did not report close"
                        ),
                        False,
                    )
                )
                continue
            close_error, closed_stream = close_result
            if close_error is not None:
                stream_close_errors.append(
                    (label, close_error, closed_stream)
                )
        persistent_stream_close = any(
            not closed
            for _label, _error, closed in stream_close_errors
        )
        stream_close_interruption = next(
            (
                error
                for _label, error, _closed in stream_close_errors
                if not isinstance(error, Exception)
            ),
            None,
        )
        persistent_close_failure: RuntimeError | None = None
        if persistent_stream_close:
            persistent_close_failure = RuntimeError(
                "subprocess output stream cleanup did not complete"
            )
            for label, close_error, _closed in stream_close_errors:
                persistent_close_failure.add_note(
                    f"{label} stream close failed: "
                    f"{_bounded_exception_message(close_error)}"
                )
        output_failure = callback_failure
        for candidate, context in (
            (
                stream_close_interruption,
                "subprocess output stream cleanup was interrupted",
            ),
            (
                persistent_close_failure,
                "subprocess output stream cleanup failed",
            ),
        ):
            if candidate is None:
                continue
            if output_failure is None:
                output_failure = candidate
            else:
                output_failure = _prioritize_cleanup_error(
                    output_failure,
                    candidate,
                    context=context,
                )

        if (
            not timed_out
            and callback_error is None
            and not persistent_stream_close
            and stream_close_interruption is None
            and process.poll() is None
        ):
            wait_remaining = (
                None
                if deadline is None
                else max(0.0, deadline - time.monotonic())
            )
            try:
                process.wait(timeout=wait_remaining)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        # POSIX exposes no non-reusable process-group identity token. Probe the
        # original PGID immediately after reaping its leader and before
        # releasing registry ownership; this is the narrowest kernel boundary
        # available and also catches descendants that closed or redirected the
        # model output pipes before the leader exited.
        residual_group_live = (
            not timed_out
            and callback_error is None
            and not persistent_stream_close
            and stream_close_interruption is None
            and self._process_group_is_live(process)
        )
        if (
            timed_out
            or callback_error is not None
            or persistent_stream_close
            or stream_close_interruption is not None
            or residual_group_live
        ):
            try:
                self._terminate_processes((process,))
            except BaseException as cleanup_error:
                if output_failure is not None:
                    for label, close_error, closed in stream_close_errors:
                        output_failure.add_note(
                            f"{label} stream close "
                            f"{'recovered' if closed else 'failed'}: "
                            f"{_bounded_exception_message(close_error)}"
                        )
                    prioritized = _prioritize_cleanup_error(
                        output_failure,
                        cleanup_error,
                        context="subprocess process-group cleanup failed",
                    )
                    raise prioritized
                raise

        def propagate_stdin_operation_error(
            error: BaseException,
            *,
            context: str,
        ) -> None:
            if output_failure is None:
                raise error
            prioritized = _prioritize_cleanup_error(
                output_failure,
                error,
                context=context,
            )
            raise prioritized

        try:
            stdin_stop.set()
            stdin_thread.join(timeout=pump_join_timeout)
        except BaseException as error:
            propagate_stdin_operation_error(
                error,
                context="subprocess stdin pump join failed",
            )
        stdin_cleanup_errors: list[
            tuple[BaseException, bool]
        ] = []
        try:
            stdin_alive = stdin_thread.is_alive()
        except BaseException as error:
            propagate_stdin_operation_error(
                error,
                context="subprocess stdin pump state check failed",
            )
        if stdin_alive:
            stdin_cleanup_errors.append(
                (
                    RuntimeError("subprocess stdin pump did not stop"),
                    False,
                )
            )
        else:
            try:
                stdin_close_result = pump_control.take_close_result("stdin")
            except BaseException as error:
                propagate_stdin_operation_error(
                    error,
                    context="subprocess stdin pump close result failed",
                )
            if stdin_close_result is None:
                stdin_cleanup_errors.append(
                    (
                        RuntimeError(
                            "subprocess stdin pump did not report close"
                        ),
                        False,
                    )
                )
            elif stdin_close_result[0] is not None and (
                not stdin_close_result[1]
                or not isinstance(stdin_close_result[0], Exception)
            ):
                stdin_cleanup_errors.append(stdin_close_result)

        def propagate_after_confirmed_cleanup(
            primary_error: BaseException,
        ) -> None:
            try:
                self._forget_processes((process,))
            except BaseException as registry_error:
                prioritized = _prioritize_cleanup_error(
                    primary_error,
                    registry_error,
                    context="subprocess registry cleanup failed",
                )
                raise prioritized
            raise primary_error

        if output_failure is not None:
            for label, close_error, closed in stream_close_errors:
                if close_error is output_failure:
                    continue
                output_failure.add_note(
                    f"{label} stream close "
                    f"{'recovered' if closed else 'failed'}: "
                    f"{_bounded_exception_message(close_error)}"
                )

        stdin_failure: BaseException | None = None
        if stdin_cleanup_errors:
            stdin_failure = RuntimeError(
                "subprocess stdin pump cleanup did not complete"
            )
            for stdin_error, closed in stdin_cleanup_errors:
                stdin_failure = _prioritize_cleanup_error(
                    stdin_failure,
                    stdin_error,
                    context=(
                        "subprocess stdin pump cleanup "
                        f"{'recovered' if closed else 'failed'}"
                    ),
                )

        final_failure = output_failure
        if stdin_failure is not None:
            if final_failure is None:
                final_failure = stdin_failure
            else:
                final_failure = _prioritize_cleanup_error(
                    final_failure,
                    stdin_failure,
                    context="subprocess stdin pump cleanup failed",
                )
        if final_failure is not None:
            if not stdin_cleanup_errors:
                propagate_after_confirmed_cleanup(final_failure)
            raise final_failure

        self._forget_processes((process,))

        returncode = process.poll()
        if returncode is None:
            returncode = -signal.SIGKILL
        if (
            returncode == 0
            and not all(capture_complete.values())
        ):
            returncode = 125
        if returncode == 0 and callback_error is not None:
            returncode = 1
        outcome = ProcessOutcome(
            returncode=returncode,
            stderr=bytes(stderr_capture).decode("utf-8", errors="replace"),
            duration_seconds=time.monotonic() - started,
            timed_out=timed_out,
            stderr_bytes=stderr_bytes,
            stderr_truncated=stderr_bytes > len(stderr_capture),
            stderr_raw=bytes(stderr_capture),
            stdout_capture_complete=(
                capture_complete["stdout"]
                and callback_error is None
            ),
            stderr_capture_complete=capture_complete["stderr"],
            callback_error=callback_error,
        )
        return outcome


@dataclass(frozen=True)
class CallTiming:
    session_created_at: float
    queued_at: float
    started_at: float
    finished_at: float
    provider_wait_seconds: float


@dataclass(frozen=True)
class BatchAttempt:
    number: int
    command: tuple[str, ...]
    returncode: int
    timed_out: bool
    duration_seconds: float
    raw_jsonl_path: Path
    stderr_path: Path
    output_path: Path
    capture_metadata_path: Path
    validation: ContractValidation
    raw_jsonl_bytes: int
    raw_jsonl_stored_bytes: int
    raw_jsonl_truncated: bool
    stderr_bytes: int
    stderr_stored_bytes: int
    stderr_truncated: bool
    output_bytes: int | None
    output_oversized: bool


@dataclass(frozen=True)
class BatchResult:
    invocation: BatchInvocation
    timing: CallTiming
    attempts: tuple[BatchAttempt, ...]
    output: Mapping[str, object] | None
    validation: ContractValidation
    thread_id: str | None
    events: tuple[CodexEvent, ...]
    usage: Usage
    failures: tuple[ExecutionFailure, ...]
    flag_candidates: tuple[FlagCandidate, ...]
    malformed_event_lines: tuple[str, ...]
    deadline_monotonic_seconds: float | None = None

    @property
    def completed(self) -> bool:
        return bool(self.attempts) and self.attempts[-1].returncode == 0

    @property
    def success(self) -> bool:
        return self.completed and self.validation.valid and (
            self.output is not None and self.output.get("status") != "refused"
        )

    @property
    def refused(self) -> bool:
        return self.output is not None and self.output.get("status") == "refused"


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


@dataclass(frozen=True)
class _OutputRead:
    validation: ContractValidation
    payload: str | None
    bytes: int | None
    oversized: bool


def _read_output(
    path: Path,
    role: Role,
    limit_bytes: int,
    *,
    contract_version: int = 1,
) -> _OutputRead:
    try:
        before = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return _OutputRead(
            ContractValidation(False, (f"$: output file was not created: {path}",), None),
            None,
            None,
            False,
        )
    if not stat.S_ISREG(before.st_mode):
        return _OutputRead(
            ContractValidation(False, (f"$: output file is not a regular file: {path}",), None),
            None,
            0,
            False,
        )
    if before.st_size > limit_bytes:
        return _OutputRead(
            ContractValidation(
                False,
                (
                    f"$: structured output exceeds {limit_bytes} byte limit "
                    f"({before.st_size} bytes)",
                ),
                None,
            ),
            None,
            before.st_size,
            True,
        )

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                or opened.st_size != before.st_size
                or opened.st_mtime_ns != before.st_mtime_ns
            ):
                raise OSError("file changed while opening")
            chunks: list[bytes] = []
            remaining = limit_bytes + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        return _OutputRead(
            ContractValidation(False, (f"$: output file is unreadable: {exc}",), None),
            None,
            before.st_size,
            False,
        )

    output_bytes = after.st_size
    if (
        after.st_size != opened.st_size
        or after.st_mtime_ns != opened.st_mtime_ns
    ):
        return _OutputRead(
            ContractValidation(
                False,
                ("$: output file changed while being read",),
                None,
            ),
            None,
            output_bytes,
            False,
        )
    data = b"".join(chunks)
    if len(data) != output_bytes:
        return _OutputRead(
            ContractValidation(
                False,
                ("$: output file could not be read completely",),
                None,
            ),
            None,
            output_bytes,
            False,
        )
    if len(data) > limit_bytes or output_bytes > limit_bytes:
        return _OutputRead(
            ContractValidation(
                False,
                (
                    f"$: structured output exceeds {limit_bytes} byte limit "
                    f"({output_bytes} bytes)",
                ),
                None,
            ),
            None,
            output_bytes,
            True,
        )
    try:
        payload = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        return _OutputRead(
            ContractValidation(False, (f"$: output is not valid UTF-8: {exc}",), None),
            None,
            output_bytes,
            False,
        )
    return _OutputRead(
        validate_role_output(
            payload,
            role,
            contract_version=contract_version,
        ),
        payload,
        output_bytes,
        False,
    )


def _bounded_utf8(value: str, limit_bytes: int) -> tuple[bytes, int, bool]:
    encoded = value.encode("utf-8", errors="replace")
    stored = encoded[:limit_bytes]
    return stored, len(encoded), len(encoded) > len(stored)


class _BatchStdoutCapture:
    """Persist a bounded prefix, parse bounded JSONL, and scan all chunks for flags."""

    def __init__(
        self,
        *,
        raw_handle: BinaryIO,
        accumulator: EventAccumulator,
        raw_limit_bytes: int,
        event_line_limit_bytes: int,
        flag_scan_chunk_chars: int,
        flag_scan_overlap_chars: int,
    ) -> None:
        self.raw_handle = raw_handle
        self.accumulator = accumulator
        self.raw_limit_bytes = raw_limit_bytes
        self.event_line_limit_bytes = event_line_limit_bytes
        self.flag_scan_chunk_chars = flag_scan_chunk_chars
        self.flag_scan_overlap_chars = flag_scan_overlap_chars
        self.bytes = 0
        self.stored_bytes = 0
        self.oversized_event_lines = 0
        self._line = bytearray()
        self._line_oversized = False
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._flag_tail = ""
        self._finished = False
        self._callback_failed = False

    @property
    def truncated(self) -> bool:
        return self.bytes > self.stored_bytes

    def feed(self, chunk: str | bytes) -> None:
        if self._finished:
            raise RuntimeError("stdout capture is already finished")
        data = chunk.encode("utf-8", errors="replace") if isinstance(chunk, str) else chunk
        if not data:
            return
        try:
            self.bytes += len(data)
            remaining = self.raw_limit_bytes - self.stored_bytes
            stored = data[: max(0, remaining)]
            if stored:
                self.raw_handle.write(stored)
                self.raw_handle.flush()
                self.stored_bytes += len(stored)
                self._feed_event_bytes(stored)
            self._scan_text(self._decoder.decode(data, final=False))
        except BaseException:
            self._callback_failed = True
            raise

    def finish(self) -> None:
        if self._finished:
            return
        self._finished = True
        primary_error: BaseException | None = None
        try:
            if self._callback_failed:
                self._decoder.decode(b"", final=True)
                self._line.clear()
                self._line_oversized = False
            else:
                self._scan_text(self._decoder.decode(b"", final=True))
                if not self.truncated and (
                    self._line or self._line_oversized
                ):
                    self._finish_event_line()
        except BaseException as error:
            self._callback_failed = True
            primary_error = error
        try:
            self.raw_handle.flush()
        except BaseException as flush_error:
            self._callback_failed = True
            if primary_error is None:
                raise
            raise _prioritize_cleanup_error(
                primary_error,
                flush_error,
                context="batch stdout capture final flush failed",
            )
        if primary_error is not None:
            raise primary_error

    def _feed_event_bytes(self, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            newline = data.find(b"\n", offset)
            end = len(data) if newline < 0 else newline
            self._append_event_piece(data[offset:end])
            if newline < 0:
                break
            self._finish_event_line()
            offset = newline + 1

    def _append_event_piece(self, piece: bytes) -> None:
        if self._line_oversized:
            return
        available = self.event_line_limit_bytes - len(self._line)
        if len(piece) <= available:
            self._line.extend(piece)
            return
        self._line.clear()
        self._line_oversized = True

    def _finish_event_line(self) -> None:
        line = bytes(self._line)
        oversized = self._line_oversized
        self._line.clear()
        self._line_oversized = False
        if oversized:
            self.oversized_event_lines += 1
            self.accumulator.feed(
                f"<JSONL event exceeded {self.event_line_limit_bytes} byte limit>"
            )
        elif line:
            self.accumulator.feed(line.decode("utf-8", errors="replace"))

    def _scan_text(self, text: str) -> None:
        for offset in range(0, len(text), self.flag_scan_chunk_chars):
            piece = text[offset : offset + self.flag_scan_chunk_chars]
            combined = self._flag_tail + piece
            candidates = self.accumulator.detector.scan(
                combined, "raw.fragment", "raw_jsonl"
            )
            self._flag_tail = combined[-self.flag_scan_overlap_chars :]
            self.accumulator.notify_candidates(candidates)


class _BatchAttemptCaptureOwner:
    """Finalize and close one attempt stream without masking its primary error."""

    def __init__(
        self,
        raw_handle: BinaryIO,
    ) -> None:
        self._raw_handle: BinaryIO | None = raw_handle
        self.capture: _BatchStdoutCapture | None = None
        self.outcome: ProcessOutcome | None = None

    def __enter__(self) -> _BatchAttemptCaptureOwner:
        return self

    def _record_ordinary_failure(
        self,
        error: BaseException,
        *,
        stage: str,
    ) -> None:
        outcome = self.outcome
        if outcome is None:
            raise error
        detail = f"{stage}: {_bounded_exception_message(error)}"
        callback_error = outcome.callback_error
        if callback_error is None:
            callback_error = detail
        elif detail not in callback_error:
            callback_error = f"{callback_error}; {detail}"[:8192]
        self.outcome = replace(
            outcome,
            returncode=(
                outcome.returncode if outcome.returncode != 0 else 1
            ),
            stdout_capture_complete=False,
            callback_error=callback_error,
        )

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        active_error: BaseException | None,
        _traceback: object,
    ) -> None:
        capture = self.capture
        raw_handle = self._raw_handle
        self._raw_handle = None
        finish_error: BaseException | None = None
        close_error: BaseException | None = None
        sequencing_error: BaseException | None = None
        try:
            try:
                if capture is not None:
                    capture.finish()
            except BaseException as error:
                finish_error = error
            finally:
                if raw_handle is not None:
                    try:
                        raw_handle.close()
                    except BaseException as error:
                        close_error = error
        except BaseException as error:
            # The stream has already received its single close attempt. A
            # control interruption in the finish->close handoff is now safe to
            # prioritize without risking a skipped close or an ABA re-close.
            sequencing_error = error

        primary_error = active_error
        for stage, cleanup_error in (
            ("batch stdout capture finalization", finish_error),
            ("batch stdout raw stream close", close_error),
            ("batch stdout cleanup sequencing", sequencing_error),
        ):
            if cleanup_error is None:
                continue
            if primary_error is not None:
                primary_error = _prioritize_cleanup_error(
                    primary_error,
                    cleanup_error,
                    context=f"{stage} failed",
                )
            elif (
                isinstance(cleanup_error, FlagNotificationError)
                or not isinstance(cleanup_error, Exception)
                or self.outcome is None
            ):
                primary_error = cleanup_error
            else:
                self._record_ordinary_failure(
                    cleanup_error,
                    stage=stage,
                )

        if primary_error is None or primary_error is active_error:
            return
        raise primary_error


class BatchRunner:
    """Execute one logical role; provider capacity may delay its actual start."""

    def __init__(
        self,
        *,
        command_builder: BatchCommandBuilder | None = None,
        process_executor: ProcessExecutor | None = None,
        limiter: ModelCallLimiter | None = None,
        limiter_wait_timeout: float | None = None,
        max_schema_retries: int = 1,
        flag_patterns: Sequence[str] | None = None,
        raw_jsonl_limit_bytes: int = DEFAULT_RAW_JSONL_LIMIT_BYTES,
        stderr_limit_bytes: int = DEFAULT_STDERR_LIMIT_BYTES,
        structured_output_limit_bytes: int = DEFAULT_STRUCTURED_OUTPUT_LIMIT_BYTES,
        event_line_limit_bytes: int = DEFAULT_EVENT_LINE_LIMIT_BYTES,
        flag_scan_chunk_chars: int = DEFAULT_FLAG_SCAN_CHUNK_CHARS,
        flag_scan_overlap_chars: int = DEFAULT_FLAG_SCAN_OVERLAP_CHARS,
        flag_candidate_limit: int = DEFAULT_FLAG_CANDIDATE_LIMIT,
        flag_candidate_chars_limit: int = DEFAULT_FLAG_CANDIDATE_CHARS_LIMIT,
        event_count_limit: int = DEFAULT_EVENT_COUNT_LIMIT,
        malformed_line_count_limit: int = DEFAULT_MALFORMED_LINE_COUNT_LIMIT,
    ) -> None:
        if max_schema_retries < 0:
            raise ValueError("max_schema_retries must not be negative")
        if limiter_wait_timeout is not None and (
            isinstance(limiter_wait_timeout, bool)
            or not isinstance(limiter_wait_timeout, (int, float))
            or not math.isfinite(float(limiter_wait_timeout))
            or limiter_wait_timeout <= 0
        ):
            raise ValueError(
                "limiter_wait_timeout must be positive and finite"
            )
        for name, value in (
            ("raw_jsonl_limit_bytes", raw_jsonl_limit_bytes),
            ("stderr_limit_bytes", stderr_limit_bytes),
            ("structured_output_limit_bytes", structured_output_limit_bytes),
            ("flag_candidate_limit", flag_candidate_limit),
            ("flag_candidate_chars_limit", flag_candidate_chars_limit),
            ("event_count_limit", event_count_limit),
            ("malformed_line_count_limit", malformed_line_count_limit),
        ):
            if value < 0:
                raise ValueError(f"{name} must not be negative")
        for name, value in (
            ("event_line_limit_bytes", event_line_limit_bytes),
            ("flag_scan_chunk_chars", flag_scan_chunk_chars),
            ("flag_scan_overlap_chars", flag_scan_overlap_chars),
        ):
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        self.command_builder = command_builder or BatchCommandBuilder()
        self.process_executor = process_executor or SubprocessExecutor(
            stderr_limit_bytes=stderr_limit_bytes
        )
        self.limiter = limiter or UnlimitedModelCallLimiter()
        self.limiter_wait_timeout = (
            None
            if limiter_wait_timeout is None
            else float(limiter_wait_timeout)
        )
        self.max_schema_retries = max_schema_retries
        self.flag_patterns = tuple(flag_patterns) if flag_patterns is not None else None
        self.raw_jsonl_limit_bytes = raw_jsonl_limit_bytes
        self.stderr_limit_bytes = stderr_limit_bytes
        self.structured_output_limit_bytes = structured_output_limit_bytes
        self.event_line_limit_bytes = event_line_limit_bytes
        self.flag_scan_chunk_chars = flag_scan_chunk_chars
        self.flag_scan_overlap_chars = flag_scan_overlap_chars
        self.flag_candidate_limit = flag_candidate_limit
        self.flag_candidate_chars_limit = flag_candidate_chars_limit
        self.event_count_limit = event_count_limit
        self.malformed_line_count_limit = malformed_line_count_limit

    def _model_call_slot(
        self,
        cancel_event: threading.Event | None,
        timeout: float | None = None,
    ) -> ModelCallSlot:
        effective_timeout = self.limiter_wait_timeout
        if timeout is not None:
            effective_timeout = (
                timeout
                if effective_timeout is None
                else min(effective_timeout, timeout)
            )
        return (
            self.limiter.slot(effective_timeout)
            if cancel_event is None
            else self.limiter.slot(
                effective_timeout,
                cancel_event=cancel_event,
            )
        )

    def run(
        self,
        invocation: BatchInvocation,
        *,
        on_event: Callable[[CodexEvent], None] | None = None,
        on_flag: Callable[[FlagCandidate], None] | None = None,
        before_provider_start: Callable[[], None] | None = None,
        session_created_at: float | None = None,
        _cancel_event: threading.Event | None = None,
        command_builder: CommandBuilder | None = None,
    ) -> BatchResult:
        run_started_monotonic = time.monotonic()
        run_started_at = time.time()
        budget_deadline_monotonic = (
            invocation.deadline_monotonic_seconds
            if invocation.deadline_monotonic_seconds is not None
            else None
            if invocation.deadline_epoch_seconds is None
            else (
                run_started_monotonic
                + invocation.deadline_epoch_seconds
                - run_started_at
            )
        )
        created_at = (
            session_created_at
            if session_created_at is not None
            else run_started_at
        )
        output_directory = invocation.output_directory
        raw_directory = output_directory / "raw"
        raw_directory.mkdir(parents=True, exist_ok=True)
        schema_path = output_directory / "output-schema.json"
        _atomic_json(
            schema_path,
            role_output_schema(
                invocation.role,
                contract_version=invocation.contract_version,
            ),
        )

        if self.flag_patterns is not None:
            detector = FlagDetector(
                self.flag_patterns,
                candidate_limit=self.flag_candidate_limit,
                candidate_chars_limit=self.flag_candidate_chars_limit,
                suppress_generic_code_noise=True,
            )
        else:
            detector = FlagDetector(
                candidate_limit=self.flag_candidate_limit,
                candidate_chars_limit=self.flag_candidate_chars_limit,
                suppress_generic_code_noise=True,
            )
        accumulator = EventAccumulator(
            detector=detector,
            on_event=on_event,
            on_flag=on_flag,
            max_events=self.event_count_limit,
            max_malformed_lines=self.malformed_line_count_limit,
        )
        attempts: list[BatchAttempt] = []
        orchestration_failures: list[ExecutionFailure] = []
        validation = ContractValidation(False, ("$: no attempt completed",), None)
        correction: str | None = None
        # Cross-cycle continuity is opt-in per invocation.  Schema repair then
        # remains on that exact lane instead of accidentally starting a fresh
        # conversation when a resumed CLI emits no new thread.started event.
        resume_thread_id = invocation.resume_thread_id
        queued_at = time.time()
        first_started_at: float | None = None
        final_finished_at = queued_at
        total_wait = 0.0

        for attempt_number in range(1, self.max_schema_retries + 2):
            raw_path = raw_directory / f"attempt-{attempt_number}.jsonl"
            stderr_path = raw_directory / f"attempt-{attempt_number}.stderr"
            output_path = output_directory / f"attempt-{attempt_number}-output.json"
            capture_metadata_path = raw_directory / f"attempt-{attempt_number}-capture.json"
            output_path.unlink(missing_ok=True)
            command = (command_builder or self.command_builder).build(
                invocation,
                schema_path,
                output_path,
                resume_thread_id=resume_thread_id,
                correction=correction,
            )

            outcome: ProcessOutcome | None = None
            terminal_failure_kind: str | None = None
            terminal_failure_message = ""
            raw_handle = raw_path.open("wb")
            capture_owner = _BatchAttemptCaptureOwner(raw_handle)
            with capture_owner:
                stdout_capture = _BatchStdoutCapture(
                    raw_handle=raw_handle,
                    accumulator=accumulator,
                    raw_limit_bytes=self.raw_jsonl_limit_bytes,
                    event_line_limit_bytes=self.event_line_limit_bytes,
                    flag_scan_chunk_chars=self.flag_scan_chunk_chars,
                    flag_scan_overlap_chars=self.flag_scan_overlap_chars,
                )
                capture_owner.capture = stdout_capture

                def receive_line(line: str | bytes) -> None:
                    stdout_capture.feed(line)

                lease_wait_started = time.monotonic()
                slot_acquired = False
                try:
                    deadline_remaining = (
                        None
                        if budget_deadline_monotonic is None
                        else (
                            budget_deadline_monotonic
                            - time.monotonic()
                        )
                    )
                    if (
                        deadline_remaining is not None
                        and deadline_remaining <= 0
                    ):
                        raise ModelCallLimitTimeout(
                            "challenge wall-clock budget expired before the "
                            "provider call started"
                        )
                    with self._model_call_slot(
                        _cancel_event,
                        deadline_remaining,
                    ) as model_call_slot:
                        waited = model_call_slot.acquire()
                        total_wait += waited
                        slot_acquired = True
                        if before_provider_start is not None:
                            before_provider_start()
                        deadline_remaining = (
                            None
                            if budget_deadline_monotonic is None
                            else (
                                budget_deadline_monotonic
                                - time.monotonic()
                            )
                        )
                        if (
                            deadline_remaining is not None
                            and deadline_remaining <= 0
                        ):
                            raise ModelCallLimitTimeout(
                                "challenge wall-clock budget expired while "
                                "waiting for the provider"
                            )
                        process_timeout = invocation.timeout_seconds
                        if deadline_remaining is not None:
                            process_timeout = (
                                deadline_remaining
                                if process_timeout is None
                                else min(
                                    process_timeout,
                                    deadline_remaining,
                                )
                            )
                        actual_started_at = time.time()
                        if first_started_at is None:
                            first_started_at = actual_started_at
                        if isinstance(
                            self.process_executor,
                            SubprocessExecutor,
                        ):
                            outcome = self.process_executor.run(
                                command,
                                cwd=invocation.working_directory,
                                timeout=process_timeout,
                                on_stdout_line=receive_line,
                                cancel_event=_cancel_event,
                            )
                        else:
                            outcome = self.process_executor.run(
                                command,
                                cwd=invocation.working_directory,
                                timeout=process_timeout,
                                on_stdout_line=receive_line,
                            )
                        attempt_finished_monotonic = time.monotonic()
                        final_finished_at = time.time()
                        if (
                            budget_deadline_monotonic is not None
                            and attempt_finished_monotonic
                            >= budget_deadline_monotonic
                        ):
                            terminal_failure_kind = (
                                "challenge_budget_expired"
                            )
                            terminal_failure_message = (
                                "challenge wall-clock budget expired during "
                                "the provider call"
                            )
                            outcome = replace(
                                outcome,
                                returncode=124,
                                timed_out=True,
                            )
                        elif (
                            _cancel_event is not None
                            and _cancel_event.is_set()
                        ):
                            terminal_failure_kind = "model_call_cancelled"
                            terminal_failure_message = (
                                "provider model call was cancelled"
                            )
                            outcome = replace(
                                outcome,
                                returncode=(
                                    outcome.returncode
                                    if outcome.returncode != 0
                                    else 130
                                ),
                                timed_out=False,
                            )
                except ModelCallLimitTimeout as exc:
                    wait_elapsed = time.monotonic() - lease_wait_started
                    if not slot_acquired:
                        total_wait += wait_elapsed
                    final_finished_at = time.time()
                    message = str(exc)
                    budget_expired = (
                        budget_deadline_monotonic is not None
                        and time.monotonic()
                        >= budget_deadline_monotonic
                    )
                    terminal_failure_kind = (
                        "challenge_budget_expired"
                        if budget_expired
                        else "model_call_wait_timeout"
                    )
                    terminal_failure_message = message
                    outcome = ProcessOutcome(
                        124,
                        message,
                        wait_elapsed,
                        timed_out=True,
                    )
                except ModelCallLimitCancelled as exc:
                    wait_elapsed = time.monotonic() - lease_wait_started
                    if not slot_acquired:
                        total_wait += wait_elapsed
                    final_finished_at = time.time()
                    terminal_failure_kind = "model_call_cancelled"
                    terminal_failure_message = str(exc)
                    outcome = ProcessOutcome(
                        130,
                        terminal_failure_message,
                        wait_elapsed,
                    )
                except FlagNotificationError:
                    raise
                except OSError as exc:
                    final_finished_at = time.time()
                    message = f"{type(exc).__name__}: {exc}"
                    orchestration_failures.append(
                        ExecutionFailure(
                            "process_launch",
                            message,
                            False,
                            "orchestrator.error",
                        )
                    )
                    outcome = ProcessOutcome(127, message, 0.0)
                except Exception as exc:  # callbacks and injected runners are contained per role
                    final_finished_at = time.time()
                    message = f"{type(exc).__name__}: {exc}"
                    outcome = ProcessOutcome(
                        1,
                        message,
                        0.0,
                        stdout_capture_complete=False,
                        stderr_capture_complete=False,
                        callback_error=message,
                    )
                finally:
                    capture_owner.outcome = outcome

            outcome = capture_owner.outcome
            if outcome is None:
                raise RuntimeError(
                    "batch attempt completed without a process outcome"
                )
            if outcome.stderr_raw is not None:
                encoded_stderr_bytes = len(outcome.stderr_raw)
                stderr_data = outcome.stderr_raw[: self.stderr_limit_bytes]
                encoded_stderr_truncated = (
                    len(outcome.stderr_raw) > len(stderr_data)
                )
            else:
                (
                    stderr_data,
                    encoded_stderr_bytes,
                    encoded_stderr_truncated,
                ) = _bounded_utf8(outcome.stderr, self.stderr_limit_bytes)
            stderr_path.write_bytes(stderr_data)
            stderr_bytes = max(
                encoded_stderr_bytes,
                outcome.stderr_bytes
                if outcome.stderr_bytes is not None
                else 0,
            )
            stderr_truncated = (
                outcome.stderr_truncated
                or encoded_stderr_truncated
                or stderr_bytes > len(stderr_data)
            )
            if terminal_failure_kind is not None:
                orchestration_failures.append(
                    ExecutionFailure(
                        terminal_failure_kind,
                        terminal_failure_message,
                        terminal_failure_kind == "model_call_wait_timeout",
                        "orchestrator.error",
                    )
                )
            if (
                terminal_failure_kind is None
                and outcome.callback_error is not None
            ):
                orchestration_failures.append(
                    ExecutionFailure(
                        "process_error",
                        outcome.callback_error,
                        False,
                        "orchestrator.error",
                    )
                )
            if (
                terminal_failure_kind is None
                and (
                    not outcome.stdout_capture_complete
                    or not outcome.stderr_capture_complete
                )
                and outcome.callback_error is None
            ):
                orchestration_failures.append(
                    ExecutionFailure(
                        "process_output_incomplete",
                        (
                            "a detached descendant kept a model output pipe "
                            "open beyond the bounded drain grace"
                        ),
                        False,
                        "orchestrator.error",
                    )
                )
            if (
                terminal_failure_kind is None
                and outcome.timed_out
            ):
                orchestration_failures.append(
                    ExecutionFailure(
                        "process_timeout",
                        f"role exceeded timeout {invocation.timeout_seconds}",
                        True,
                        "orchestrator.error",
                    )
                )
            if outcome.returncode != 0 and not accumulator.failures and not orchestration_failures:
                orchestration_failures.append(
                    ExecutionFailure(
                        "process_exit",
                        f"codex exited with status {outcome.returncode}",
                        False,
                        "orchestrator.error",
                    )
                )
            output_read = _read_output(
                output_path,
                invocation.role,
                self.structured_output_limit_bytes,
                contract_version=invocation.contract_version,
            )
            validation = output_read.validation
            raw_output = output_read.payload
            if validation.value is not None:
                accumulator.scan_final(validation.value)
            elif raw_output is not None:
                accumulator.scan_final(raw_output)
            _atomic_json(
                capture_metadata_path,
                {
                    "schema_version": 1,
                    "stdout_jsonl": {
                        "limit_bytes": self.raw_jsonl_limit_bytes,
                        "bytes": stdout_capture.bytes,
                        "stored_bytes": stdout_capture.stored_bytes,
                        "truncated": (
                            stdout_capture.truncated
                            if outcome.stdout_capture_complete
                            else None
                        ),
                        "truncation_known": (
                            outcome.stdout_capture_complete
                        ),
                        "capture_complete": (
                            outcome.stdout_capture_complete
                        ),
                        "oversized_event_lines": stdout_capture.oversized_event_lines,
                    },
                    "stderr": {
                        "limit_bytes": self.stderr_limit_bytes,
                        "bytes": stderr_bytes,
                        "stored_bytes": len(stderr_data),
                        "truncated": (
                            stderr_truncated
                            if outcome.stderr_capture_complete
                            else None
                        ),
                        "truncation_known": (
                            outcome.stderr_capture_complete
                        ),
                        "capture_complete": (
                            outcome.stderr_capture_complete
                        ),
                    },
                    "structured_output": {
                        "limit_bytes": self.structured_output_limit_bytes,
                        "bytes": output_read.bytes,
                        "oversized": output_read.oversized,
                    },
                    "event_accumulator": {
                        "event_limit": self.event_count_limit,
                        "events_stored": len(accumulator.events),
                        "events_dropped": accumulator.events_dropped,
                        "malformed_line_limit": self.malformed_line_count_limit,
                        "malformed_lines_stored": len(accumulator.malformed_lines),
                        "malformed_lines_dropped": accumulator.malformed_lines_dropped,
                    },
                    "flag_scan": {
                        "candidate_limit": self.flag_candidate_limit,
                        "candidate_chars_limit": self.flag_candidate_chars_limit,
                        "candidates_stored": len(accumulator.flags),
                        "candidate_chars_stored": detector.accepted_chars,
                        "suppressed_matches": detector.suppressed_matches,
                    },
                },
            )
            if (
                budget_deadline_monotonic is not None
                and time.monotonic() >= budget_deadline_monotonic
                and outcome.returncode == 0
            ):
                terminal_failure_kind = "challenge_budget_expired"
                terminal_failure_message = (
                    "challenge wall-clock budget expired during host result "
                    "processing"
                )
                outcome = replace(
                    outcome,
                    returncode=124,
                    timed_out=True,
                )
                validation = ContractValidation(
                    False,
                    (
                        "$: challenge wall-clock budget expired during host "
                        "result processing",
                    ),
                    None,
                )
                if not any(
                    failure.kind == "challenge_budget_expired"
                    for failure in orchestration_failures
                ):
                    orchestration_failures.append(
                        ExecutionFailure(
                            "challenge_budget_expired",
                            terminal_failure_message,
                            False,
                            "orchestrator.error",
                        )
                    )
            attempts.append(
                BatchAttempt(
                    number=attempt_number,
                    command=command.argv,
                    returncode=outcome.returncode,
                    timed_out=outcome.timed_out,
                    duration_seconds=outcome.duration_seconds,
                    raw_jsonl_path=raw_path,
                    stderr_path=stderr_path,
                    output_path=output_path,
                    capture_metadata_path=capture_metadata_path,
                    validation=validation,
                    raw_jsonl_bytes=stdout_capture.bytes,
                    raw_jsonl_stored_bytes=stdout_capture.stored_bytes,
                    raw_jsonl_truncated=stdout_capture.truncated,
                    stderr_bytes=stderr_bytes,
                    stderr_stored_bytes=len(stderr_data),
                    stderr_truncated=stderr_truncated,
                    output_bytes=output_read.bytes,
                    output_oversized=output_read.oversized,
                )
            )
            if outcome.returncode != 0 or outcome.timed_out or validation.valid:
                break
            if attempt_number > self.max_schema_retries:
                break
            correction = "\n".join(f"- {error}" for error in validation.errors)
            resume_thread_id = accumulator.thread_id or resume_thread_id

        started_at = first_started_at if first_started_at is not None else final_finished_at
        timing = CallTiming(
            session_created_at=created_at,
            queued_at=queued_at,
            started_at=started_at,
            finished_at=final_finished_at,
            provider_wait_seconds=total_wait,
        )
        output = validation.value if validation.valid else None
        return BatchResult(
            invocation=invocation,
            timing=timing,
            attempts=tuple(attempts),
            output=output,
            validation=validation,
            thread_id=accumulator.thread_id or invocation.resume_thread_id,
            events=tuple(accumulator.events),
            usage=accumulator.usage,
            failures=tuple(accumulator.failures) + tuple(orchestration_failures),
            flag_candidates=tuple(accumulator.flags),
            malformed_event_lines=tuple(accumulator.malformed_lines),
            deadline_monotonic_seconds=budget_deadline_monotonic,
        )

    def cancel_active(
        self,
        *,
        cancel_event: threading.Event | None = None,
    ) -> None:
        """Cancel subprocess calls owned by one wave, or all when unscoped."""

        if isinstance(self.process_executor, SubprocessExecutor):
            self.process_executor.cancel_active(
                cancel_event=cancel_event,
            )
            return
        if cancel_event is None:
            cancel = getattr(self.process_executor, "cancel_active", None)
            if callable(cancel):
                cancel()

    @staticmethod
    def failed_result(
        invocation: BatchInvocation,
        error: Exception,
        *,
        session_created_at: float | None = None,
    ) -> BatchResult:
        """Last-resort containment for errors outside the normal attempt path."""

        anchor_monotonic = time.monotonic()
        now = time.time()
        effective_deadline = invocation.deadline_monotonic_seconds
        if (
            effective_deadline is None
            and invocation.deadline_epoch_seconds is not None
        ):
            effective_deadline = (
                anchor_monotonic
                + invocation.deadline_epoch_seconds
                - now
            )
        created_at = session_created_at if session_created_at is not None else now
        message = f"{type(error).__name__}: {error}"
        validation = ContractValidation(False, (f"$: orchestration failure: {message}",), None)
        return BatchResult(
            invocation=invocation,
            timing=CallTiming(created_at, now, now, now, 0.0),
            attempts=(),
            output=None,
            validation=validation,
            thread_id=None,
            events=(),
            usage=Usage(),
            failures=(
                ExecutionFailure(
                    "orchestration_error", message, False, "orchestrator.error"
                ),
            ),
            flag_candidates=(),
            malformed_event_lines=(),
            deadline_monotonic_seconds=effective_deadline,
        )

    @staticmethod
    def expired_result(
        result: BatchResult,
        *,
        message: str = (
            "challenge wall-clock budget expired before the successful "
            "result could be committed"
        ),
    ) -> BatchResult:
        """Invalidate a late success while retaining bounded diagnostic data."""

        validation = ContractValidation(
            False,
            (f"$: {message}",),
            None,
        )
        attempts = result.attempts
        if attempts:
            attempts = (
                *attempts[:-1],
                replace(
                    attempts[-1],
                    returncode=124,
                    timed_out=True,
                    validation=validation,
                ),
            )
        failures = tuple(
            failure
            for failure in result.failures
            if failure.kind != "challenge_budget_expired"
        ) + (
            ExecutionFailure(
                "challenge_budget_expired",
                message,
                False,
                "orchestrator.error",
            ),
        )
        return replace(
            result,
            attempts=attempts,
            output=None,
            validation=validation,
            failures=failures,
        )


@dataclass(frozen=True)
class BatchWave:
    """A logical wave is fixed before any provider-call lease is acquired."""

    wave_id: str
    invocations: tuple[BatchInvocation, ...]
    created_at: float

    @classmethod
    def create(
        cls, wave_id: str, invocations: Sequence[BatchInvocation]
    ) -> "BatchWave":
        if not wave_id:
            raise ValueError("wave_id must not be empty")
        values = tuple(invocations)
        if not values:
            raise ValueError("a wave must contain at least one logical invocation")
        run_ids = [invocation.run_id for invocation in values]
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("wave run_ids must be unique")
        return cls(wave_id, values, time.time())


class _WaveDispatchGate:
    """Track wave-owned callbacks independently of executor bookkeeping."""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._closed = threading.Event()
        self._active: set[object] = set()

    def run(
        self,
        callback: Callable[[], BatchResult],
    ) -> BatchResult | None:
        token = object()
        try:
            if self._closed.is_set():
                return None
            with self._condition:
                if self._closed.is_set():
                    return None
                self._active.add(token)
            return callback()
        finally:
            with self._condition:
                if token in self._active:
                    self._active.remove(token)
                    self._condition.notify_all()

    def close(self) -> None:
        # Event publication prevents a worker delayed before the condition
        # acquisition from entering model work after session cleanup begins.
        self._closed.set()
        with self._condition:
            self._condition.notify_all()

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    def wait_for_idle(self) -> None:
        with self._condition:
            while self._active:
                self._condition.wait()


class BatchWaveRunner:
    """Submit the entire logical wave; each call independently waits for capacity."""

    def __init__(self, runner: BatchRunner) -> None:
        self.runner = runner

    def run(
        self,
        wave: BatchWave,
        *,
        on_event: Callable[[CodexEvent], None] | None = None,
        on_flag: Callable[[FlagCandidate], None] | None = None,
        before_provider_start: Callable[[], None] | None = None,
        before_invocation_provider_start: (
            Callable[[BatchInvocation], None] | None
        ) = None,
        on_invocation_complete: Callable[[BatchResult], None] | None = None,
    ) -> tuple[BatchResult, ...]:
        cancel_event = threading.Event()
        dispatch_gate = _WaveDispatchGate()
        executor = ThreadPoolExecutor(
            max_workers=len(wave.invocations),
            thread_name_prefix=f"ctfos-{wave.wave_id}",
        )
        futures = []

        def dispatch(invocation: BatchInvocation) -> BatchResult | None:
            def before_start() -> None:
                if before_provider_start is not None:
                    before_provider_start()
                if before_invocation_provider_start is not None:
                    before_invocation_provider_start(invocation)

            return dispatch_gate.run(
                lambda: self.runner.run(
                    invocation,
                    on_event=on_event,
                    on_flag=on_flag,
                    before_provider_start=before_start,
                    session_created_at=wave.created_at,
                    _cancel_event=cancel_event,
                )
            )

        try:
            futures = [
                executor.submit(
                    dispatch,
                    invocation,
                )
                for invocation in wave.invocations
            ]
            results: list[BatchResult | None] = [
                None for _ in wave.invocations
            ]
            future_indexes = {
                future: index for index, future in enumerate(futures)
            }
            for future in as_completed(futures):
                index = future_indexes[future]
                invocation = wave.invocations[index]
                try:
                    result = future.result()
                    if result is None:
                        raise RuntimeError(
                            "batch dispatch closed without a wave error"
                        )
                    results[index] = result
                except FlagNotificationError:
                    raise
                except Exception as exc:
                    results[index] = self.runner.failed_result(
                        invocation,
                        exc,
                        session_created_at=wave.created_at,
                    )
                completed_result = results[index]
                if (
                    completed_result is not None
                    and on_invocation_complete is not None
                ):
                    on_invocation_complete(completed_result)
        except BaseException as wave_error:
            def close_dispatch_gate() -> None:
                if not dispatch_gate.closed:
                    dispatch_gate.close()

            wave_error = (
                SubprocessExecutor._retry_cleanup_until_confirmed(
                    close_dispatch_gate,
                    active_error=wave_error,
                    label="batch dispatch closure cleanup",
                    stop_on_repeated_control=False,
                )
            )

            def publish_cancellation() -> None:
                if not cancel_event.is_set():
                    cancel_event.set()

            wave_error = (
                SubprocessExecutor._retry_cleanup_until_confirmed(
                    publish_cancellation,
                    active_error=wave_error,
                    label="batch cancellation publication cleanup",
                    stop_on_repeated_control=False,
                )
            )
            for future in futures:
                try:
                    future.cancel()
                except BaseException as cleanup_error:
                    wave_error = _prioritize_cleanup_error(
                        wave_error,
                        cleanup_error,
                        context="batch future cancellation failed",
                    )
            try:
                self.runner.cancel_active(cancel_event=cancel_event)
            except BaseException as cleanup_error:
                # Preserve the wave owner's exception, but never let a
                # cancellation callback interruption skip executor/gate
                # draining while the caller still owns the session lock.
                wave_error = _prioritize_cleanup_error(
                    wave_error,
                    cleanup_error,
                    context="batch active-process cancellation failed",
                )
            try:
                # The challenge session lock is owned by the caller of this
                # method. Do not let it unwind while a worker callback or
                # post-processing path can still touch that challenge.
                executor.shutdown(wait=True, cancel_futures=True)
            except BaseException as cleanup_error:
                wave_error = _prioritize_cleanup_error(
                    wave_error,
                    cleanup_error,
                    context="batch worker shutdown cleanup failed",
                )
            # CPython 3.13 starts a ThreadPoolExecutor worker before adding it
            # to the executor registry. If Thread.start() is interrupted in
            # that window, shutdown() cannot join it. The wave-owned gate
            # still accounts for every callback that crossed admission.
            wave_error = (
                SubprocessExecutor._retry_cleanup_until_confirmed(
                    dispatch_gate.wait_for_idle,
                    active_error=wave_error,
                    label="batch dispatch drain cleanup",
                    stop_on_repeated_control=False,
                )
            )
            raise wave_error
        else:
            executor.shutdown(wait=True)
            if any(result is None for result in results):
                raise RuntimeError("a batch wave result was not collected")
            return tuple(
                result for result in results if result is not None
            )
