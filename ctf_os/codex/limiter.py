"""Fair model-call limiters, independent from logical session/wave width."""

from __future__ import annotations

import errno
import json
import math
import os
import sys
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Self, TextIO, TypeVar

try:
    import fcntl
except ImportError:  # pragma: no cover - CTF-OS targets Linux/WSL
    fcntl = None  # type: ignore[assignment]


class ModelCallLimitTimeout(TimeoutError):
    pass


class ModelCallLimitCancelled(RuntimeError):
    pass


def _prefer_control_error(
    primary: BaseException,
    latest: BaseException,
    *,
    label: str,
) -> BaseException:
    """Keep the first control-flow exception ahead of ordinary failures."""

    if not isinstance(latest, Exception) and isinstance(primary, Exception):
        latest.add_note(
            f"{label} followed earlier failure: "
            f"{type(primary).__name__}: {primary}"
        )
        return latest
    primary.add_note(f"{label}: {latest}")
    return primary


def _validate_timeout(timeout: float | None) -> float | None:
    if timeout is None:
        return None
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(float(timeout))
        or timeout < 0
    ):
        raise ValueError("timeout must be finite and nonnegative or None")
    return float(timeout)


def _validate_poll_interval(poll_interval: float) -> float:
    if (
        isinstance(poll_interval, bool)
        or not isinstance(poll_interval, (int, float))
        or not math.isfinite(float(poll_interval))
        or poll_interval <= 0
    ):
        raise ValueError("poll_interval must be positive and finite")
    return float(poll_interval)


def _validate_capacity(capacity: int) -> int:
    if (
        isinstance(capacity, bool)
        or not isinstance(capacity, int)
        or capacity < 1
    ):
        raise ValueError("capacity must be a positive integer")
    return capacity


class CancellationEvent(Protocol):
    def is_set(self) -> bool:
        ...

    def wait(self, timeout: float | None = None) -> bool:
        ...


@dataclass(frozen=True)
class LimiterSnapshot:
    capacity: int
    active: int
    waiting: int


class ModelCallSlot(Protocol):
    """A single-use, caller-guarded provider-capacity request."""

    def acquire(self) -> float:
        """Acquire provider capacity and return seconds spent waiting."""

    def __enter__(self) -> Self:
        """Install a resource-free cleanup guard."""

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        exception: BaseException | None,
        _traceback: object,
    ) -> None:
        """Release any queued ticket or held capacity."""


class ModelCallLimiter(Protocol):
    def slot(
        self,
        timeout: float | None = None,
        *,
        cancel_event: CancellationEvent | None = None,
    ) -> ModelCallSlot:
        """Return a resource-free slot owner.

        Callers must enter the owner before calling :meth:`ModelCallSlot.acquire`.
        This separates installation of the cleanup guard from capacity
        acquisition, so an interrupt at an outer ``__enter__`` return cannot
        orphan a ticket or holder.
        """

    def snapshot(self) -> LimiterSnapshot:
        ...


class _ResourceFreeModelCallSlot:
    """Common single-use lifecycle for model-call slot owners."""

    def __init__(self) -> None:
        self._entered = False
        self._acquire_started = False
        self._closed = False

    def __enter__(self) -> Self:
        if self._entered or self._closed:
            raise RuntimeError("model-call slot owner is already used")
        self._entered = True
        # Deliberately acquire no capacity here. The caller's __exit__ guard is
        # installed before acquire() can enqueue or hold a ticket.
        return self

    def _begin_acquire(self) -> None:
        if not self._entered:
            raise RuntimeError(
                "model-call slot acquire requires an active with guard"
            )
        if self._closed or self._acquire_started:
            raise RuntimeError("model-call slot owner is already used")
        self._acquire_started = True

    def _close(self, active_error: BaseException | None) -> None:
        raise NotImplementedError

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        exception: BaseException | None,
        _traceback: object,
    ) -> None:
        self._close(exception)

    def __del__(self) -> None:
        try:
            self._close(None)
        except BaseException:
            pass


class FifoModelCallLimiter:
    """Process-local FIFO limiter suitable for one engine process."""

    def __init__(self, capacity: int) -> None:
        self._capacity = _validate_capacity(capacity)
        self._holders: set[object] = set()
        self._queue: deque[object] = deque()
        self._condition = threading.Condition()

    def _release_condition(
        self,
        active_error: BaseException | None,
    ) -> None:
        cleanup_error: BaseException | None = None
        try:
            self._condition.release()
        except BaseException as error:
            cleanup_error = error
            try:
                still_owned = self._condition._is_owned()
            except BaseException as ownership_error:
                cleanup_error = _prefer_control_error(
                    cleanup_error,
                    ownership_error,
                    label="condition ownership check failed",
                )
                still_owned = True
            if still_owned:
                try:
                    self._condition.release()
                except BaseException as retry_error:
                    cleanup_error = _prefer_control_error(
                        cleanup_error,
                        retry_error,
                        label="condition release retry failed",
                    )
                    # RLock release is identity-safe to retry: unlike an fd
                    # close, it cannot consume and later target a reused
                    # numeric resource. One final attempt prevents two
                    # adjacent cleanup faults from stranding the mutex.
                    try:
                        self._condition.release()
                    except BaseException as final_error:
                        cleanup_error = _prefer_control_error(
                            cleanup_error,
                            final_error,
                            label=(
                                "condition release final retry failed"
                            ),
                        )
            elif isinstance(error, RuntimeError):
                # The corresponding acquire was interrupted before ownership.
                cleanup_error = None
        if cleanup_error is None:
            return
        if active_error is not None and not isinstance(
            active_error,
            Exception,
        ):
            active_error.add_note(
                "condition release cleanup failed: "
                f"{cleanup_error}"
            )
            return
        if not isinstance(cleanup_error, Exception):
            if active_error is not None:
                cleanup_error.add_note(
                    "condition release interrupted while handling: "
                    f"{type(active_error).__name__}: {active_error}"
                )
            raise cleanup_error
        if active_error is not None:
            active_error.add_note(
                "condition release cleanup failed: "
                f"{cleanup_error}"
            )
            return
        if self._condition._is_owned():
            raise cleanup_error

    def _acquire_ticket(
        self,
        ticket: object,
        *,
        deadline: float | None,
        timeout: float | None,
        cancel_event: CancellationEvent | None,
        arm_cleanup: Callable[[], None],
    ) -> None:
        release_maybe_needed = False
        try:
            first_lock_attempt = True
            while True:
                if cancel_event is not None and cancel_event.is_set():
                    raise ModelCallLimitCancelled(
                        "cancelled while waiting for the provider "
                        "model-call limiter lock"
                    )
                now = time.monotonic()
                immediate_attempt = timeout == 0 and first_lock_attempt
                if (
                    deadline is not None
                    and now >= deadline
                    and not immediate_attempt
                ):
                    raise ModelCallLimitTimeout(
                        "timed out waiting for the provider model-call "
                        "limiter lock"
                    )

                # Set ownership intent before every C-level acquire. If an
                # interrupt lands after the RLock is acquired but before the
                # call returns, the finally below still releases that
                # recursion. A failed non-blocking/timed acquire is harmless:
                # _release_condition recognizes that this thread owns no lock.
                release_maybe_needed = True
                if immediate_attempt:
                    acquired = self._condition.acquire(blocking=False)
                elif deadline is None and cancel_event is None:
                    self._condition.acquire()
                    acquired = True
                else:
                    wait_for = (
                        0.1
                        if deadline is None
                        else max(0.0, deadline - now)
                    )
                    if cancel_event is not None:
                        wait_for = min(0.1, wait_for)
                    acquired = self._condition.acquire(timeout=wait_for)
                if acquired:
                    if cancel_event is not None and cancel_event.is_set():
                        raise ModelCallLimitCancelled(
                            "cancelled while waiting for the provider "
                            "model-call limiter lock"
                        )
                    if (
                        deadline is not None
                        and time.monotonic() >= deadline
                        and not immediate_attempt
                    ):
                        raise ModelCallLimitTimeout(
                            "timed out waiting for the provider model-call "
                            "limiter lock"
                        )
                    break
                if timeout == 0:
                    raise ModelCallLimitTimeout(
                        "timed out waiting for the provider model-call "
                        "limiter lock"
                    )
                first_lock_attempt = False

            # Arm exact cleanup immediately before the first mutation. A
            # mutex timeout/cancellation before this point owns no queue or
            # holder state and must not block again merely to clean nothing.
            arm_cleanup()
            self._queue.append(ticket)
            first_check = True
            while True:
                if cancel_event is not None and cancel_event.is_set():
                    raise ModelCallLimitCancelled(
                        "cancelled while waiting for a provider "
                        "model-call slot"
                    )
                now = time.monotonic()
                immediate_check = timeout == 0 and first_check
                if (
                    deadline is not None
                    and now >= deadline
                    and not immediate_check
                ):
                    raise ModelCallLimitTimeout(
                        "timed out waiting for a provider model-call slot"
                    )
                if (
                    self._queue
                    and self._queue[0] is ticket
                    and len(self._holders) < self._capacity
                ):
                    self._queue.popleft()
                    self._holders.add(ticket)
                    return
                if timeout == 0:
                    raise ModelCallLimitTimeout(
                        "timed out waiting for a provider model-call slot"
                    )
                remaining = (
                    None if deadline is None else deadline - now
                )
                wait_for = remaining
                if cancel_event is not None:
                    wait_for = (
                        0.1
                        if remaining is None
                        else min(0.1, remaining)
                    )
                first_check = False
                self._condition.wait(wait_for)
        finally:
            active_error = sys.exception()
            if release_maybe_needed:
                self._release_condition(active_error)

    def _cleanup_ticket_once(self, ticket: object) -> None:
        release_maybe_needed = False
        try:
            release_maybe_needed = True
            self._condition.acquire()
            try:
                self._queue.remove(ticket)
            except ValueError:
                pass
            self._holders.discard(ticket)
            self._condition.notify_all()
        finally:
            active_error = sys.exception()
            if release_maybe_needed:
                self._release_condition(active_error)

    def slot(
        self,
        timeout: float | None = None,
        *,
        cancel_event: CancellationEvent | None = None,
    ) -> ModelCallSlot:
        return _LocalModelCallSlot(
            self,
            timeout=_validate_timeout(timeout),
            cancel_event=cancel_event,
        )

    def _cleanup_ticket(
        self,
        ticket: object,
    ) -> tuple[BaseException | None, bool]:
        cleanup_interruption: BaseException | None = None
        cleanup_succeeded = False
        for cleanup_attempt in range(2):
            try:
                self._cleanup_ticket_once(ticket)
            except BaseException as cleanup_error:
                if cleanup_interruption is None:
                    cleanup_interruption = cleanup_error
                else:
                    cleanup_interruption = _prefer_control_error(
                        cleanup_interruption,
                        cleanup_error,
                        label=(
                            "local model-call limiter cleanup retry failed"
                        ),
                    )
                if cleanup_attempt == 0:
                    continue
            else:
                cleanup_succeeded = True
            break
        effective_error = (
            cleanup_interruption
            if cleanup_interruption is not None
            and (
                not cleanup_succeeded
                or not isinstance(cleanup_interruption, Exception)
            )
            else None
        )
        return effective_error, cleanup_succeeded

    def snapshot(self) -> LimiterSnapshot:
        release_maybe_needed = False
        try:
            release_maybe_needed = True
            self._condition.acquire()
            return LimiterSnapshot(
                self._capacity,
                len(self._holders),
                len(self._queue),
            )
        finally:
            active_error = sys.exception()
            if release_maybe_needed:
                self._release_condition(active_error)


class _LocalModelCallSlot(_ResourceFreeModelCallSlot):
    def __init__(
        self,
        limiter: FifoModelCallLimiter,
        *,
        timeout: float | None,
        cancel_event: CancellationEvent | None,
    ) -> None:
        super().__init__()
        self._limiter = limiter
        self._timeout = timeout
        self._cancel_event = cancel_event
        self._ticket = object()
        self._queued_at: float | None = None
        self._deadline: float | None = None
        self._ticket_may_exist = False

    def _arm_cleanup(self) -> None:
        self._ticket_may_exist = True

    def acquire(self) -> float:
        self._begin_acquire()
        self._queued_at = time.monotonic()
        self._deadline = (
            None
            if self._timeout is None
            else self._queued_at + self._timeout
        )
        try:
            self._limiter._acquire_ticket(
                self._ticket,
                deadline=self._deadline,
                timeout=self._timeout,
                cancel_event=self._cancel_event,
                arm_cleanup=self._arm_cleanup,
            )
            if (
                self._cancel_event is not None
                and self._cancel_event.is_set()
            ):
                raise ModelCallLimitCancelled(
                    "cancelled while waiting for a provider model-call slot"
                )
            if (
                self._deadline is not None
                and self._timeout != 0
                and time.monotonic() >= self._deadline
            ):
                raise ModelCallLimitTimeout(
                    "timed out waiting for a provider model-call slot"
                )
            assert self._queued_at is not None
            return time.monotonic() - self._queued_at
        except BaseException as error:
            self._close(error)
            raise

    def _close(self, active_error: BaseException | None) -> None:
        if self._closed:
            return
        if not self._acquire_started or not self._ticket_may_exist:
            self._closed = True
            return
        cleanup_error, cleanup_succeeded = self._limiter._cleanup_ticket(
            self._ticket
        )
        if cleanup_succeeded:
            self._closed = True
        if cleanup_error is None:
            return
        if active_error is not None and not isinstance(
            active_error,
            Exception,
        ):
            active_error.add_note(
                "local model-call limiter cleanup was interrupted: "
                f"{cleanup_error}"
            )
            return
        if not isinstance(cleanup_error, Exception):
            if active_error is not None:
                cleanup_error.add_note(
                    "local model-call limiter cleanup interrupted while "
                    "handling: "
                    f"{type(active_error).__name__}: {active_error}"
                )
            raise cleanup_error
        if active_error is not None:
            active_error.add_note(
                "local model-call limiter cleanup failed: "
                f"{cleanup_error}"
            )
            return
        raise cleanup_error


class UnlimitedModelCallLimiter:
    def slot(
        self,
        timeout: float | None = None,
        *,
        cancel_event: CancellationEvent | None = None,
    ) -> ModelCallSlot:
        return _UnlimitedModelCallSlot(
            timeout=_validate_timeout(timeout),
            cancel_event=cancel_event,
        )

    def snapshot(self) -> LimiterSnapshot:
        return LimiterSnapshot(2**31 - 1, 0, 0)


class _UnlimitedModelCallSlot(_ResourceFreeModelCallSlot):
    def __init__(
        self,
        *,
        timeout: float | None,
        cancel_event: CancellationEvent | None,
    ) -> None:
        super().__init__()
        del timeout
        self._cancel_event = cancel_event

    def acquire(self) -> float:
        self._begin_acquire()
        if (
            self._cancel_event is not None
            and self._cancel_event.is_set()
        ):
            error = ModelCallLimitCancelled(
                "cancelled while waiting for a provider model-call slot"
            )
            self._close(error)
            raise error
        return 0.0

    def _close(self, active_error: BaseException | None) -> None:
        del active_error
        self._closed = True


def _process_start_ticks(pid: int) -> int | None:
    """Read Linux process start time (field 22), robust to spaces in comm."""

    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        closing_paren = stat.rfind(")")
        if closing_paren < 0:
            return None
        fields_from_state = stat[closing_paren + 2 :].split()
        return int(fields_from_state[19])
    except (FileNotFoundError, PermissionError, ValueError, IndexError):
        return None


def _pid_alive(pid: int, expected_start_ticks: int | None = None) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError as exc:
        if exc.errno != errno.EPERM:
            return False
    if expected_start_ticks is None:
        return True
    return _process_start_ticks(pid) == expected_start_ticks


def _live_entry(entry: object) -> bool:
    if (
        not isinstance(entry, dict)
        or not isinstance(entry.get("pid"), int)
        or isinstance(entry.get("pid"), bool)
    ):
        return False
    ticks = entry.get("process_start_ticks")
    expected_ticks = (
        ticks
        if isinstance(ticks, int) and not isinstance(ticks, bool)
        else None
    )
    return _pid_alive(entry["pid"], expected_ticks)


_StateResult = TypeVar("_StateResult")


def _open_text_file_with_handoff(
    path: Path,
    pending_handoff: list[TextIO],
) -> TextIO:
    """Open one owning stream and expose it before returning to the caller."""

    handle = path.open("a+", encoding="utf-8")
    pending_handoff.append(handle)
    return handle


class FileFifoModelCallLimiter:
    """Cross-process FIFO limiter for CTF-OS-managed Batch model calls.

    Queue entries and holders are keyed by unique tickets, so several threads
    from one process remain distinct. Dead-process entries are removed while
    holding the state lock.
    """

    def __init__(
        self,
        state_path: str | Path,
        capacity: int,
        poll_interval: float = 0.05,
    ) -> None:
        if fcntl is None:
            raise RuntimeError("FileFifoModelCallLimiter requires fcntl")
        self._state_path = Path(state_path)
        self._lock_path = self._state_path.with_suffix(
            self._state_path.suffix + ".lock"
        )
        self._capacity = _validate_capacity(capacity)
        self._poll_interval = _validate_poll_interval(poll_interval)

    def _load_state(self) -> tuple[str | None, dict[str, object]]:
        serialized_before: str | None = None
        try:
            serialized_before = self._state_path.read_text(
                encoding="utf-8"
            )
            value = json.loads(serialized_before)
        except (FileNotFoundError, json.JSONDecodeError):
            value = {
                "version": 1,
                "capacity": self._capacity,
                "queue": [],
                "holders": [],
            }
        if not isinstance(value, dict):
            value = {
                "version": 1,
                "capacity": self._capacity,
                "queue": [],
                "holders": [],
            }
        queue = value.get("queue")
        holders = value.get("holders")
        if not isinstance(queue, list):
            queue = []
        if not isinstance(holders, list):
            holders = []
        stored_capacity = value.get("capacity")
        if (
            isinstance(stored_capacity, bool)
            or not isinstance(stored_capacity, int)
            or stored_capacity < 1
        ):
            stored_capacity = self._capacity
        value["version"] = 1
        value["queue"] = [
            entry for entry in queue if _live_entry(entry)
        ]
        value["holders"] = [
            entry for entry in holders if _live_entry(entry)
        ]
        if value["queue"] or value["holders"]:
            value["capacity"] = min(stored_capacity, self._capacity)
        else:
            value["capacity"] = self._capacity
        return serialized_before, value

    def _commit_state(
        self,
        serialized_before: str | None,
        value: dict[str, object],
    ) -> None:
        serialized_after = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        )
        if serialized_after == serialized_before:
            return
        temporary = self._state_path.with_name(
            f".{self._state_path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
        )
        try:
            with temporary.open("w", encoding="utf-8") as handle:
                handle.write(serialized_after)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self._state_path)
        finally:
            active_error = sys.exception()
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except BaseException as cleanup_error:
                if active_error is None:
                    raise
                if not isinstance(active_error, Exception):
                    active_error.add_note(
                        "shared model-call limiter temporary cleanup "
                        f"failed: {cleanup_error}"
                    )
                elif not isinstance(cleanup_error, Exception):
                    cleanup_error.add_note(
                        "shared model-call limiter temporary cleanup "
                        "interrupted while handling: "
                        f"{type(active_error).__name__}: {active_error}"
                    )
                    raise cleanup_error
                else:
                    active_error.add_note(
                        "shared model-call limiter temporary cleanup "
                        f"failed: {cleanup_error}"
                    )

    def _locked_state(self) -> _FileLimiterLockedState:
        return _FileLimiterLockedState(self)

    def _with_locked_state(
        self,
        operation: Callable[[dict[str, object]], _StateResult],
        *,
        deadline: float | None = None,
        cancel_event: CancellationEvent | None = None,
        allow_immediate: bool = False,
    ) -> _StateResult:
        with self._locked_state() as locked:
            state = locked.acquire(
                deadline=deadline,
                cancel_event=cancel_event,
                allow_immediate=allow_immediate,
            )
            return operation(state)

    def _remove_ticket(
        self,
        ticket: str,
    ) -> tuple[BaseException | None, bool]:
        cleanup_interruption: BaseException | None = None
        for attempt in range(3):
            try:
                def remove(state: dict[str, object]) -> None:
                    state["queue"] = [
                        entry
                        for entry in state["queue"]  # type: ignore[union-attr]
                        if entry.get("ticket") != ticket  # type: ignore[union-attr]
                    ]
                    state["holders"] = [
                        entry
                        for entry in state["holders"]  # type: ignore[union-attr]
                        if entry.get("ticket") != ticket  # type: ignore[union-attr]
                    ]

                self._with_locked_state(remove)
            except BaseException as error:
                if cleanup_interruption is None:
                    cleanup_interruption = error
                else:
                    cleanup_interruption = _prefer_control_error(
                        cleanup_interruption,
                        error,
                        label=(
                            "shared model-call ticket cleanup retry failed"
                        ),
                    )
                if attempt < 2:
                    continue
                return cleanup_interruption, False
            else:
                effective_error = (
                    cleanup_interruption is not None
                    and not isinstance(cleanup_interruption, Exception)
                )
                return (
                    cleanup_interruption if effective_error else None,
                    True,
                )
        raise AssertionError("unreachable model-call ticket cleanup state")

    def slot(
        self,
        timeout: float | None = None,
        *,
        cancel_event: CancellationEvent | None = None,
    ) -> ModelCallSlot:
        return _FileModelCallSlot(
            self,
            timeout=_validate_timeout(timeout),
            cancel_event=cancel_event,
        )

    def snapshot(self) -> LimiterSnapshot:
        def inspect(state: dict[str, object]) -> LimiterSnapshot:
            return LimiterSnapshot(
                state["capacity"],  # type: ignore[arg-type]
                len(state["holders"]),  # type: ignore[arg-type]
                len(state["queue"]),  # type: ignore[arg-type]
            )

        return self._with_locked_state(inspect)


class _FileLimiterLockedState:
    """Resource-free owner for one cross-process limiter state transaction."""

    def __init__(self, limiter: FileFifoModelCallLimiter) -> None:
        self._limiter = limiter
        self._entered = False
        self._acquire_started = False
        self._lock_file: TextIO | None = None
        self._unlock_maybe_needed = False
        self._serialized_before: str | None = None
        self._state: dict[str, object] | None = None
        self._closed = False

    @staticmethod
    def _retry_step(
        label: str,
        operation: Callable[[], None],
    ) -> tuple[BaseException | None, bool]:
        first_error: BaseException | None = None
        for attempt in range(2):
            try:
                operation()
            except BaseException as error:
                if first_error is None:
                    first_error = error
                else:
                    first_error = _prefer_control_error(
                        first_error,
                        error,
                        label=f"{label} retry failed",
                    )
                if attempt == 0:
                    continue
            else:
                return first_error, True
        return first_error, False

    def __enter__(self) -> Self:
        if self._entered or self._closed:
            raise RuntimeError("model-call state lock owner is already used")
        self._entered = True
        return self

    def acquire(
        self,
        *,
        deadline: float | None = None,
        cancel_event: CancellationEvent | None = None,
        allow_immediate: bool = False,
    ) -> dict[str, object]:
        if not self._entered:
            raise RuntimeError(
                "model-call state lock acquire requires an active with guard"
            )
        if self._acquire_started or self._closed:
            raise RuntimeError("model-call state lock owner is already used")
        self._acquire_started = True
        pending_handoff: list[TextIO] = []
        try:
            self._limiter._state_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            self._lock_file = _open_text_file_with_handoff(
                self._limiter._lock_path,
                pending_handoff,
            )
            pending_handoff.clear()
            self._unlock_maybe_needed = True
            assert fcntl is not None
            if deadline is None and cancel_event is None:
                fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX)
            else:
                first_attempt = True
                while True:
                    if cancel_event is not None and cancel_event.is_set():
                        raise ModelCallLimitCancelled(
                            "cancelled while waiting for the shared "
                            "model-call limiter state lock"
                        )
                    now = time.monotonic()
                    immediate_attempt = allow_immediate and first_attempt
                    if (
                        deadline is not None
                        and now >= deadline
                        and not immediate_attempt
                    ):
                        raise ModelCallLimitTimeout(
                            "timed out waiting for the shared model-call "
                            "limiter state lock"
                        )
                    try:
                        fcntl.flock(
                            self._lock_file.fileno(),
                            fcntl.LOCK_EX | fcntl.LOCK_NB,
                        )
                    except OSError as error:
                        if error.errno not in (errno.EACCES, errno.EAGAIN):
                            raise
                    else:
                        if (
                            cancel_event is not None
                            and cancel_event.is_set()
                        ):
                            raise ModelCallLimitCancelled(
                                "cancelled while waiting for the shared "
                                "model-call limiter state lock"
                            )
                        if (
                            deadline is not None
                            and time.monotonic() >= deadline
                            and not immediate_attempt
                        ):
                            raise ModelCallLimitTimeout(
                                "timed out waiting for the shared "
                                "model-call limiter state lock"
                            )
                        break
                    first_attempt = False
                    wait_for = self._limiter._poll_interval
                    if deadline is not None:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise ModelCallLimitTimeout(
                                "timed out waiting for the shared "
                                "model-call limiter state lock"
                            )
                        wait_for = min(wait_for, remaining)
                    if cancel_event is None:
                        time.sleep(wait_for)
                    else:
                        cancel_event.wait(wait_for)
            (
                self._serialized_before,
                self._state,
            ) = self._limiter._load_state()
            return self._state
        except BaseException as error:
            if self._lock_file is None and pending_handoff:
                self._lock_file = pending_handoff[0]
            pending_handoff.clear()
            self._finish(error, commit=False)
            raise

    def _finish(
        self,
        active_error: BaseException | None,
        *,
        commit: bool,
    ) -> None:
        if self._closed:
            return
        primary_error = active_error
        if (
            commit
            and self._state is not None
            and self._lock_file is not None
        ):
            try:
                self._limiter._commit_state(
                    self._serialized_before,
                    self._state,
                )
            except BaseException as error:
                primary_error = error

        unlock_error: BaseException | None = None
        unlock_completed = True
        lock_file = self._lock_file
        if lock_file is not None and self._unlock_maybe_needed:
            assert fcntl is not None
            unlock_error, unlock_completed = self._retry_step(
                "shared model-call limiter unlock",
                lambda: fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN),
            )
            if unlock_completed:
                self._unlock_maybe_needed = False

        close_error: BaseException | None = None
        close_completed = True
        if lock_file is not None:
            close_error, close_completed = self._retry_step(
                "shared model-call limiter lock close",
                lock_file.close,
            )
            if close_completed:
                self._lock_file = None
                self._unlock_maybe_needed = False
                self._closed = True
        else:
            self._closed = True

        cleanup_error = next(
            (
                error
                for error in (unlock_error, close_error)
                if error is not None and not isinstance(error, Exception)
            ),
            None,
        )
        if cleanup_error is None and not close_completed:
            cleanup_error = close_error
        if cleanup_error is None and not unlock_completed and not close_completed:
            cleanup_error = unlock_error
        if cleanup_error is not None:
            other_error = (
                close_error
                if cleanup_error is unlock_error
                else unlock_error
            )
            if other_error is not None:
                cleanup_error.add_note(
                    "shared model-call limiter additional lock cleanup "
                    f"failure: {other_error}"
                )
            if primary_error is None:
                primary_error = cleanup_error
            elif (
                not isinstance(cleanup_error, Exception)
                and isinstance(primary_error, Exception)
            ):
                cleanup_error.add_note(
                    "shared model-call limiter lock cleanup interrupted "
                    "while handling: "
                    f"{type(primary_error).__name__}: {primary_error}"
                )
                primary_error = cleanup_error
            else:
                primary_error.add_note(
                    "shared model-call limiter lock cleanup failed: "
                    f"{cleanup_error}"
                )

        if primary_error is not None and primary_error is not active_error:
            raise primary_error

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        exception: BaseException | None,
        _traceback: object,
    ) -> None:
        self._finish(
            exception,
            commit=exception is None and self._state is not None,
        )

    def __del__(self) -> None:
        try:
            self._finish(None, commit=False)
        except BaseException:
            pass


class _FileModelCallSlot(_ResourceFreeModelCallSlot):
    def __init__(
        self,
        limiter: FileFifoModelCallLimiter,
        *,
        timeout: float | None,
        cancel_event: CancellationEvent | None,
    ) -> None:
        super().__init__()
        self._limiter = limiter
        self._timeout = timeout
        self._cancel_event = cancel_event
        self._ticket = uuid.uuid4().hex
        self._queued_at: float | None = None
        self._deadline: float | None = None
        self._process_start_ticks: int | None = None
        self._entry: dict[str, object] | None = None
        self._ticket_may_exist = False

    def acquire(self) -> float:
        self._begin_acquire()
        self._queued_at = time.monotonic()
        self._deadline = (
            None
            if self._timeout is None
            else self._queued_at + self._timeout
        )
        self._process_start_ticks = _process_start_ticks(os.getpid())
        self._entry = {
            "ticket": self._ticket,
            "pid": os.getpid(),
            "process_start_ticks": self._process_start_ticks,
            "queued_at": time.time(),
        }
        try:
            if (
                self._cancel_event is not None
                and self._cancel_event.is_set()
            ):
                raise ModelCallLimitCancelled(
                    "cancelled while waiting for a shared provider "
                    "model-call slot"
                )

            immediate_enqueue = self._timeout == 0

            def enqueue(state: dict[str, object]) -> None:
                assert self._entry is not None
                if (
                    self._cancel_event is not None
                    and self._cancel_event.is_set()
                ):
                    raise ModelCallLimitCancelled(
                        "cancelled while waiting for a shared provider "
                        "model-call slot"
                    )
                if (
                    self._deadline is not None
                    and time.monotonic() >= self._deadline
                    and not immediate_enqueue
                ):
                    raise ModelCallLimitTimeout(
                        "timed out waiting for a shared provider "
                        "model-call slot"
                    )
                # Publish cleanup intent before mutating durable state. If the
                # commit-return handoff is interrupted, __exit__ still removes
                # this exact ticket.
                self._ticket_may_exist = True
                state["queue"].append(self._entry)  # type: ignore[union-attr]

            self._limiter._with_locked_state(
                enqueue,
                deadline=self._deadline,
                cancel_event=self._cancel_event,
                allow_immediate=immediate_enqueue,
            )
            first_check = True
            while True:
                if (
                    self._cancel_event is not None
                    and self._cancel_event.is_set()
                ):
                    raise ModelCallLimitCancelled(
                        "cancelled while waiting for a shared provider "
                        "model-call slot"
                    )

                def try_acquire(
                    state: dict[str, object],
                    first_check_snapshot: bool = first_check,
                ) -> tuple[bool, bool]:
                    queue = state["queue"]
                    holders = state["holders"]
                    is_head = (
                        bool(queue)
                        and queue[0].get("ticket") == self._ticket  # type: ignore[index,union-attr]
                    )
                    capacity = state["capacity"]
                    cancelled = (
                        self._cancel_event is not None
                        and self._cancel_event.is_set()
                    )
                    now = time.monotonic()
                    immediate_check = (
                        self._timeout == 0 and first_check_snapshot
                    )
                    expired = (
                        self._deadline is not None
                        and now >= self._deadline
                        and not immediate_check
                    )
                    acquired = (
                        not cancelled
                        and not expired
                        and is_head
                        and len(holders) < capacity  # type: ignore[arg-type,operator]
                    )
                    if acquired:
                        queue.pop(0)  # type: ignore[union-attr]
                        holders.append(  # type: ignore[union-attr]
                            {
                                "ticket": self._ticket,
                                "pid": os.getpid(),
                                "process_start_ticks": (
                                    self._process_start_ticks
                                ),
                                "started_at": time.time(),
                            }
                        )
                    return acquired, expired

                acquired, expired = self._limiter._with_locked_state(
                    try_acquire,
                    deadline=self._deadline,
                    cancel_event=self._cancel_event,
                    allow_immediate=(
                        self._timeout == 0 and first_check
                    ),
                )
                if acquired:
                    break
                if expired or self._timeout == 0:
                    raise ModelCallLimitTimeout(
                        "timed out waiting for a shared provider "
                        "model-call slot"
                    )
                wait_for = self._limiter._poll_interval
                if self._deadline is not None:
                    wait_for = min(
                        wait_for,
                        max(0.0, self._deadline - time.monotonic()),
                    )
                first_check = False
                if self._cancel_event is None:
                    time.sleep(wait_for)
                else:
                    self._cancel_event.wait(wait_for)

            if (
                self._cancel_event is not None
                and self._cancel_event.is_set()
            ):
                raise ModelCallLimitCancelled(
                    "cancelled while waiting for a shared provider "
                    "model-call slot"
                )
            if (
                self._deadline is not None
                and self._timeout != 0
                and time.monotonic() >= self._deadline
            ):
                raise ModelCallLimitTimeout(
                    "timed out waiting for a shared provider "
                    "model-call slot"
                )
            assert self._queued_at is not None
            return time.monotonic() - self._queued_at
        except BaseException as error:
            self._close(error)
            raise

    def _close(self, active_error: BaseException | None) -> None:
        if self._closed:
            return
        if not self._acquire_started or not self._ticket_may_exist:
            self._closed = True
            return
        cleanup_error, cleanup_succeeded = self._limiter._remove_ticket(
            self._ticket
        )
        if cleanup_succeeded:
            self._closed = True
        if cleanup_error is None:
            return
        if active_error is not None and not isinstance(
            active_error,
            Exception,
        ):
            active_error.add_note(
                "shared model-call limiter cleanup failed: "
                f"{cleanup_error}"
            )
            return
        if not isinstance(cleanup_error, Exception):
            if active_error is not None:
                cleanup_error.add_note(
                    "shared model-call limiter cleanup interrupted while "
                    "handling: "
                    f"{type(active_error).__name__}: {active_error}"
                )
            raise cleanup_error
        if active_error is not None:
            active_error.add_note(
                "shared model-call limiter cleanup failed: "
                f"{cleanup_error}"
            )
            return
        raise cleanup_error
