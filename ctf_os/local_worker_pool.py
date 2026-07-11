"""Local-only bounded worker scheduler for Codex attempt races."""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Condition, Event as ThreadEvent, Thread
from typing import Any, Callable

from .models import Attempt


class WorkerCapacityError(RuntimeError):
    """Raised when starting an attempt would exceed this node's policy."""


WorkerRunner = Callable[[ThreadEvent], Any]


@dataclass
class WorkerHandle:
    attempt: Attempt
    cancel_event: ThreadEvent = field(default_factory=ThreadEvent)
    done_event: ThreadEvent = field(default_factory=ThreadEvent)
    thread: Thread | None = None
    result: Any = None
    error: BaseException | None = None
    lease_lost: bool = False
    _cancel_callback: Callable[[], None] | None = None

    @property
    def done(self) -> bool:
        return self.done_event.is_set()

    def cancel(self) -> None:
        if self.cancel_event.is_set():
            return
        self.cancel_event.set()
        if self._cancel_callback is not None:
            self._cancel_callback()

    def wait(self, timeout: float | None = None) -> bool:
        return self.done_event.wait(timeout)


class LocalWorkerPool:
    """Schedule only child attempts started by the current local node.

    The pool does not inspect, enumerate, or signal processes outside handles
    it created.  A cancellation signal is scoped to one handle; backends such
    as ``CodexCliBackend`` turn it into termination of their own child process
    group.
    """

    def __init__(self, *, max_workers_total: int, max_workers_per_challenge: int) -> None:
        if max_workers_total < 1 or max_workers_per_challenge < 1:
            raise ValueError("worker limits must be positive")
        self.max_workers_total = max_workers_total
        self.max_workers_per_challenge = max_workers_per_challenge
        self._condition = Condition()
        self._active: dict[str, WorkerHandle] = {}
        self._handles: dict[str, WorkerHandle] = {}

    @property
    def active_count(self) -> int:
        with self._condition:
            return len(self._active)

    def active_count_for(self, challenge_id: str) -> int:
        with self._condition:
            return sum(handle.attempt.challenge_id == challenge_id for handle in self._active.values())

    @property
    def active_attempt_ids(self) -> tuple[str, ...]:
        with self._condition:
            return tuple(sorted(self._active))

    def can_start(self, challenge_id: str) -> bool:
        with self._condition:
            return self._can_start_unlocked(challenge_id)

    def submit(self, attempt: Attempt, runner: WorkerRunner, *, on_cancel: Callable[[], None] | None = None) -> WorkerHandle:
        """Start one local thread that may create one local backend child."""
        with self._condition:
            if attempt.id in self._handles:
                raise ValueError(f"attempt is already owned by this pool: {attempt.id}")
            if not self._can_start_unlocked(attempt.challenge_id):
                raise WorkerCapacityError(
                    f"worker capacity reached for {attempt.challenge_id} "
                    f"(total={self.max_workers_total}, per_challenge={self.max_workers_per_challenge})"
                )
            handle = WorkerHandle(attempt=attempt, _cancel_callback=on_cancel)
            self._active[attempt.id] = handle
            self._handles[attempt.id] = handle
            thread = Thread(target=self._run, args=(handle, runner), name=f"ctf-os-{attempt.id}", daemon=True)
            handle.thread = thread
            thread.start()
            return handle

    def get(self, attempt_id: str) -> WorkerHandle | None:
        with self._condition:
            return self._handles.get(attempt_id)

    def cancel_challenge(self, challenge_id: str, *, except_attempt_id: str | None = None) -> tuple[str, ...]:
        """Cancel active attempts for exactly one challenge on this local node."""
        with self._condition:
            targets = tuple(
                handle for attempt_id, handle in self._active.items()
                if handle.attempt.challenge_id == challenge_id and attempt_id != except_attempt_id
            )
        for handle in targets:
            handle.cancel()
        return tuple(handle.attempt.id for handle in targets)

    def wait_for_change(self, timeout: float | None = None) -> None:
        with self._condition:
            self._condition.wait(timeout)

    def wait_all(self, timeout: float | None = None) -> bool:
        """Wait until no pool-owned local attempt remains active."""
        import time

        deadline = None if timeout is None else time.monotonic() + timeout
        with self._condition:
            while self._active:
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    return False
                self._condition.wait(remaining)
        return True

    def _can_start_unlocked(self, challenge_id: str) -> bool:
        return (
            len(self._active) < self.max_workers_total
            and sum(handle.attempt.challenge_id == challenge_id for handle in self._active.values())
            < self.max_workers_per_challenge
        )

    def _run(self, handle: WorkerHandle, runner: WorkerRunner) -> None:
        try:
            handle.result = runner(handle.cancel_event)
        except BaseException as exc:  # surfaced to coordinator, never silently discarded
            handle.error = exc
        finally:
            handle.done_event.set()
            with self._condition:
                self._active.pop(handle.attempt.id, None)
                self._condition.notify_all()
