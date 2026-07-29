"""Small process-group supervisor for attached, stdio-inheriting sessions."""

from __future__ import annotations

import math
import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path


_ORIGINAL_POPEN = subprocess.Popen


class _PopenConstructorOwner:
    """Construct one Popen away from main-thread control interruptions.

    CPython's POSIX Popen path stores the result of ``_fork_exec()`` into
    ``self.pid`` in a later bytecode.  A main-thread KeyboardInterrupt or
    SystemExit in that tiny handoff window otherwise leaves a real child whose
    pid is unavailable to the caller.  The constructor thread cannot receive
    Python's process-signal exceptions; this owner keeps its partially
    initialized Popen object reachable until construction is complete.
    """

    def __init__(
        self,
        argv: Sequence[str],
        kwargs: Mapping[str, object],
    ) -> None:
        self._argv = argv
        self._kwargs = dict(kwargs)
        self._lock = threading.Lock()
        self._done = threading.Event()
        self._cancelled = False
        self._phase = "pending"
        self._process: subprocess.Popen[bytes] | None = None
        self._error: BaseException | None = None
        self._thread = threading.Thread(
            target=self._construct,
            name="ctfos-popen-constructor",
            daemon=True,
        )

    @property
    def process(self) -> subprocess.Popen[bytes] | None:
        with self._lock:
            return self._process

    @staticmethod
    def _add_interruption_note(
        active_error: BaseException,
        label: str,
        error: BaseException,
    ) -> None:
        active_error.add_note(
            f"{label}: {type(error).__name__}"
        )

    def _construct(self) -> None:
        with self._lock:
            if self._cancelled:
                self._phase = "done"
                self._done.set()
                return
            self._phase = "constructing"
        try:
            process = _ORIGINAL_POPEN.__new__(_ORIGINAL_POPEN)
            with self._lock:
                self._process = process
            _ORIGINAL_POPEN.__init__(
                process,
                self._argv,
                **self._kwargs,
            )
        except BaseException as error:
            with self._lock:
                self._error = error
        finally:
            with self._lock:
                self._phase = "done"
                self._done.set()

    def _cancel_and_phase(
        self,
        active_error: BaseException,
    ) -> str:
        while True:
            try:
                with self._lock:
                    self._cancelled = True
                    return self._phase
            except BaseException as error:
                self._add_interruption_note(
                    active_error,
                    "Popen constructor cancellation was interrupted",
                    error,
                )

    def _wait_for_done_preserving(
        self,
        active_error: BaseException,
    ) -> None:
        while not self._done.is_set():
            try:
                self._done.wait()
            except BaseException as error:
                self._add_interruption_note(
                    active_error,
                    "Popen constructor cleanup wait was interrupted",
                    error,
                )

    def construct(self) -> subprocess.Popen[bytes]:
        try:
            self._thread.start()
            self._done.wait()
        except BaseException as active_error:
            phase = self._cancel_and_phase(active_error)
            # A pending helper will observe cancellation before it can spawn.
            # Once construction began, do not let the parent session unwind
            # until the exact Popen object (and therefore pid) is published.
            if phase != "pending":
                self._wait_for_done_preserving(active_error)
            raise

        with self._lock:
            process = self._process
            error = self._error
        if error is not None:
            raise error
        if process is None:
            raise RuntimeError("Popen constructor completed without a process")
        return process


def _popen_with_constructor_cleanup(
    argv: Sequence[str],
    *,
    pending_handoff: list[subprocess.Popen[bytes]],
    interrupt_cleanup: Callable[[subprocess.Popen[bytes]], None],
    cleanup_failure_note: str,
    **kwargs: object,
) -> subprocess.Popen[bytes]:
    """Retain a child across constructor and caller handoff interrupts."""

    popen_factory = subprocess.Popen
    process: subprocess.Popen[bytes] | None = None
    constructor_owner: _PopenConstructorOwner | None = None
    try:
        if (
            popen_factory is _ORIGINAL_POPEN
            and threading.current_thread() is threading.main_thread()
        ):
            constructor_owner = _PopenConstructorOwner(argv, kwargs)
            process = constructor_owner.construct()
        elif popen_factory is _ORIGINAL_POPEN:
            process = _ORIGINAL_POPEN.__new__(_ORIGINAL_POPEN)
            _ORIGINAL_POPEN.__init__(process, argv, **kwargs)
        else:
            process = popen_factory(argv, **kwargs)
        pending_handoff.append(process)
        return process
    except BaseException as error:
        if process is None and constructor_owner is not None:
            process = constructor_owner.process
        if process is None and pending_handoff:
            process = pending_handoff[-1]
        pid = (
            getattr(process, "pid", None)
            if process is not None
            else None
        )
        if isinstance(pid, int) and pid > 0:
            if not pending_handoff:
                pending_handoff.append(process)
            try:
                interrupt_cleanup(process)
            except BaseException as cleanup_error:
                error.add_note(
                    f"{cleanup_failure_note}: {cleanup_error}"
                )
            else:
                pending_handoff.clear()
        raise


def _process_group_is_live(
    process: subprocess.Popen[bytes],
) -> bool:
    """Probe one process group, treating persistent uncertainty as live."""

    for attempt in range(2):
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return False
        except OSError:
            if attempt == 0:
                continue
            # EPERM and persistent probe errors are unknown, hence live.
            return True
        else:
            return True
    return True


_PROCESS_GROUP_CLEANUP_CONTEXT = threading.local()


class _ProcessGroupCleanup:
    """Best-effort owner for one numeric process-group cleanup transaction.

    ``_terminate_process_group`` can finish and reap the group before a control
    exception is observed at its return boundary.  Keep that durable success
    receipt outside the call frame so that an interruption observed *after*
    publication makes the immediate retry a no-op.  POSIX numeric PGIDs are
    not generation-pinned handles; reuse before publication remains an
    explicitly documented kernel boundary.
    """

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        *,
        terminate_grace_seconds: float,
    ) -> None:
        self.process = process
        self.terminate_grace_seconds = terminate_grace_seconds
        self.confirmed = False

    def __call__(self) -> None:
        if self.confirmed:
            return
        previous = getattr(
            _PROCESS_GROUP_CLEANUP_CONTEXT,
            "receipt",
            None,
        )
        _PROCESS_GROUP_CLEANUP_CONTEXT.receipt = self
        try:
            # Keep the historical call signature so existing wrappers around
            # the exact cleanup function remain valid. The thread-local owner
            # carries the success receipt through any such wrapper.
            _terminate_process_group(
                self.process,
                terminate_grace_seconds=self.terminate_grace_seconds,
            )
        finally:
            if previous is None:
                try:
                    del _PROCESS_GROUP_CLEANUP_CONTEXT.receipt
                except AttributeError:
                    pass
            else:
                _PROCESS_GROUP_CLEANUP_CONTEXT.receipt = previous


def _terminate_process_group(
    process: subprocess.Popen[bytes],
    *,
    terminate_grace_seconds: float,
) -> None:
    signal_errors: list[BaseException] = []

    def send_group(sent_signal: int) -> None:
        first_error: BaseException | None = None
        for attempt in range(2):
            try:
                os.killpg(process.pid, sent_signal)
            except ProcessLookupError:
                if first_error is not None:
                    signal_errors.append(first_error)
                return
            except BaseException as error:
                if first_error is None:
                    first_error = error
                else:
                    first_error.add_note(
                        f"process-group signal retry failed: {error}"
                    )
                if attempt == 0:
                    continue
            else:
                break
        if first_error is not None:
            signal_errors.append(first_error)

    def process_is_running() -> bool:
        try:
            return process.poll() is None
        except OSError:
            # A transient waitpid/poll error does not prove that the exact
            # group exited. Continue TERM/KILL cleanup conservatively.
            return True

    send_group(signal.SIGTERM)
    deadline = time.monotonic() + terminate_grace_seconds
    while process_is_running() and time.monotonic() < deadline:
        time.sleep(0.01)
    # The group leader can exit on SIGTERM while a descendant ignores it.
    # Signal the exact process group regardless of the leader's state.
    send_group(signal.SIGKILL)
    kill_deadline = time.monotonic() + terminate_grace_seconds
    group_alive = True
    while time.monotonic() < kill_deadline:
        if not _process_group_is_live(process):
            group_alive = False
            break
        time.sleep(0.01)
    try:
        process.wait(timeout=terminate_grace_seconds)
    except subprocess.TimeoutExpired:
        # A kernel-stuck process remains outside our control. Returning would
        # falsely release the session lock.
        raise RuntimeError(
            "interactive process did not exit after SIGKILL"
        ) from None
    # Reaping the leader may be the event that removes the final process-group
    # identity. Never fail from the stale pre-wait probe result.
    group_alive = _process_group_is_live(process)
    if group_alive:
        error = RuntimeError(
            "interactive process group remained after SIGKILL"
        )
        for signal_error in signal_errors:
            error.add_note(f"process-group signal failed: {signal_error}")
        raise error
    cleanup_receipt = getattr(
        _PROCESS_GROUP_CLEANUP_CONTEXT,
        "receipt",
        None,
    )
    if (
        isinstance(cleanup_receipt, _ProcessGroupCleanup)
        and cleanup_receipt.process is process
    ):
        # Publish the success receipt before any saved control interruption is
        # re-raised and before this function's return handoff. Once published,
        # the owner makes later retries resource-free no-ops. This receipt does
        # not turn the POSIX numeric PGID into a generation-pinned handle.
        cleanup_receipt.confirmed = True
    interruption = next(
        (
            error
            for error in signal_errors
            if not isinstance(error, Exception)
        ),
        None,
    )
    if interruption is not None:
        raise interruption


def _retry_process_group_cleanup_until_confirmed(
    cleanup: Callable[[], None],
    *,
    active_error: BaseException,
) -> BaseException:
    """Hold the caller's scope until one exact process group is reaped.

    Ordinary cleanup failures are retried without releasing the surrounding
    challenge-session lock.  The first control interruption remains the
    primary exception and is propagated only after cleanup succeeds.  A second
    independent control interruption is the documented crash-only boundary.
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
                        "interactive process cleanup retry was interrupted "
                        f"by a second {type(error).__name__}: {error}"
                    )
                    repeated_control_noted = True
                raise primary_error
            error.add_note(
                "interactive process cleanup was interrupted while handling "
                f"{type(active_error).__name__}: {active_error}"
            )
            primary_error = error
            control_seen = True
        if failures == 1:
            primary_error.add_note(
                "interactive process cleanup failed and is being retried: "
                f"{type(error).__name__}: {error}"
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
                "interactive process cleanup recovered after "
                f"{failures + 1} attempts"
            )
        return primary_error


def run_bounded_interactive(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: float,
    terminate_grace_seconds: float = 1.0,
    deadline_monotonic_seconds: float | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run an attached command and stop its complete process group at deadline."""

    if not argv:
        raise ValueError("interactive argv cannot be empty")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(float(timeout))
        or timeout <= 0
        or isinstance(terminate_grace_seconds, bool)
        or not isinstance(terminate_grace_seconds, (int, float))
        or not math.isfinite(float(terminate_grace_seconds))
        or terminate_grace_seconds <= 0
    ):
        raise ValueError("interactive process bounds must be positive")
    if deadline_monotonic_seconds is not None and (
        isinstance(deadline_monotonic_seconds, bool)
        or not isinstance(deadline_monotonic_seconds, (int, float))
        or not math.isfinite(float(deadline_monotonic_seconds))
        or deadline_monotonic_seconds <= 0
    ):
        raise ValueError(
            "deadline_monotonic_seconds must be positive and finite"
        )
    issued_at = time.monotonic()
    deadline = min(
        issued_at + float(timeout),
        (
            float(deadline_monotonic_seconds)
            if deadline_monotonic_seconds is not None
            else issued_at + float(timeout)
        ),
    )
    if deadline <= issued_at:
        return subprocess.CompletedProcess(
            list(argv),
            124,
            stdout=None,
            stderr=b"challenge wall-clock budget expired",
        )
    pending_handoff: list[subprocess.Popen[bytes]] = []
    process: subprocess.Popen[bytes] | None = None
    cleanup_owner: _ProcessGroupCleanup | None = None
    timed_out = False
    residual_group_reaped = False

    def cleanup_process_group(
        target: subprocess.Popen[bytes],
    ) -> None:
        nonlocal cleanup_owner
        if cleanup_owner is None:
            cleanup_owner = _ProcessGroupCleanup(
                target,
                terminate_grace_seconds=terminate_grace_seconds,
            )
        elif cleanup_owner.process is not target:
            raise RuntimeError(
                "interactive cleanup owner changed process identity"
            )
        cleanup_owner()

    try:
        process = _popen_with_constructor_cleanup(
            list(argv),
            pending_handoff=pending_handoff,
            interrupt_cleanup=cleanup_process_group,
            cleanup_failure_note="interactive process cleanup failed",
            cwd=cwd,
            env=dict(env),
            start_new_session=True,
        )
        pending_handoff.clear()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            cleanup_process_group(process)
            returncode = 124
        else:
            try:
                returncode = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                timed_out = True
                cleanup_process_group(process)
                returncode = 124
            else:
                # A process can exit at the boundary after wait(2) reports
                # success.  The immutable issued deadline still wins.
                if time.monotonic() >= deadline:
                    timed_out = True
                    cleanup_process_group(process)
                    returncode = 124
                elif _process_group_is_live(process):
                    # A successful group leader must not leave background
                    # descendants alive after the challenge session lock is
                    # released. Reap the exact inherited group and fail closed.
                    cleanup_process_group(process)
                    residual_group_reaped = True
                    returncode = 125
    except BaseException as error:
        interrupted_process = (
            process
            if process is not None
            else pending_handoff[0]
            if pending_handoff
            else None
        )
        pending_handoff.clear()
        if interrupted_process is not None:
            propagated_error = (
                _retry_process_group_cleanup_until_confirmed(
                    lambda: cleanup_process_group(interrupted_process),
                    active_error=error,
                )
            )
            if propagated_error is not error:
                raise propagated_error
        raise
    return subprocess.CompletedProcess(
        list(argv),
        returncode,
        stdout=None,
        stderr=(
            b"challenge wall-clock budget expired"
            if timed_out
            else b"interactive process left a residual process group"
            if residual_group_reaped
            else None
        ),
    )


__all__ = ["run_bounded_interactive"]
