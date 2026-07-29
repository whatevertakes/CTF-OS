"""Advisory process locks used by the single-writer state store."""

from __future__ import annotations

import errno
import fcntl
import math
import os
import time
from pathlib import Path
from types import TracebackType


class LockTimeout(TimeoutError):
    """Raised when a lock cannot be acquired within the requested timeout."""


class FileLock:
    """A small ``flock`` context manager.

    Lock files are never unlinked: unlinking a live flock file can create two
    different inodes and therefore two simultaneous "owners".  A process crash
    closes the descriptor and the kernel releases the lock automatically.
    """

    def __init__(
        self,
        path: Path,
        *,
        timeout: float | None = None,
        poll_interval: float = 0.05,
        shared: bool = False,
    ) -> None:
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(float(timeout))
            or timeout < 0
        ):
            raise ValueError(
                "timeout must be a finite non-negative number or None"
            )
        if (
            isinstance(poll_interval, bool)
            or not isinstance(poll_interval, (int, float))
            or not math.isfinite(float(poll_interval))
            or poll_interval <= 0
        ):
            raise ValueError(
                "poll_interval must be a finite positive number"
            )
        self.path = Path(path)
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.shared = shared
        self._descriptor: int | None = None
        self._context_entered = False
        self._context_used = False
        self._context_acquire_started = False

    @property
    def acquired(self) -> bool:
        return self._descriptor is not None

    def acquire(self) -> "FileLock":
        if self.acquired:
            raise RuntimeError(f"lock is already acquired: {self.path}")
        if self._context_used:
            if not self._context_entered:
                raise RuntimeError(
                    f"lock context owner is already used: {self.path}"
                )
            if self._context_acquire_started:
                raise RuntimeError(
                    f"lock context acquire is already attempted: {self.path}"
                )
            self._context_acquire_started = True
        descriptor: int | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(
                self.path,
                os.O_CREAT | os.O_RDWR,
                0o600,
            )
            operation = (
                fcntl.LOCK_SH if self.shared else fcntl.LOCK_EX
            )
            deadline = (
                None
                if self.timeout is None
                else time.monotonic() + self.timeout
            )
            if self.timeout is None:
                fcntl.flock(descriptor, operation)
            else:
                while True:
                    try:
                        fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
                        break
                    except OSError as error:
                        if error.errno not in {errno.EACCES, errno.EAGAIN}:
                            raise
                        assert deadline is not None
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise LockTimeout(
                                f"timed out acquiring lock: {self.path}"
                            ) from error
                        time.sleep(min(self.poll_interval, remaining))
            self._descriptor = descriptor
            return self
        except BaseException as error:
            self._descriptor = None
            if descriptor is not None:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                except BaseException as cleanup_error:
                    error.add_note(
                        "file lock interruption unlock failed: "
                        f"{cleanup_error}"
                    )
                try:
                    # POSIX close errors leave descriptor consumption
                    # ambiguous.  Once attempted, never inspect, restore, or
                    # retry this integer: another thread may already own the
                    # same number for the same lock inode.
                    os.close(descriptor)
                except BaseException as cleanup_error:
                    error.add_note(
                        "file lock interruption close failed: "
                        f"{cleanup_error}"
                    )
            raise

    def release(self) -> None:
        descriptor = self._descriptor
        if descriptor is None:
            return
        primary_error: BaseException | None = None
        def record_error(operation: str, error: BaseException) -> None:
            nonlocal primary_error
            if primary_error is None:
                primary_error = error
                return
            primary_error.add_note(
                f"file lock {operation} cleanup failed: {error}"
            )

        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except BaseException as error:
            record_error("unlock", error)

        # Publish the descriptor as unowned before the one close attempt.
        # A close error is ambiguous: retrying after inspecting only the inode
        # can close a peer's newly reused descriptor for this same lock file.
        self._descriptor = None
        try:
            os.close(descriptor)
        except BaseException as error:
            record_error("descriptor close", error)
        if primary_error is not None:
            raise primary_error

    def __enter__(self) -> "FileLock":
        if self._context_used or self.acquired:
            raise RuntimeError(
                f"lock context owner is already used: {self.path}"
            )
        self._context_used = True
        self._context_entered = True
        # The caller's __exit__ guard is installed before acquire() can own a
        # descriptor or flock. Context-manager callers must acquire explicitly
        # as the first statement in the with body.
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            self.release()
        finally:
            self._context_entered = False

    def __del__(self) -> None:
        try:
            # Reuse the consume-on-attempt release path. A lost acquire return
            # first unlocks the flock, then makes one non-retriable raw close.
            self.release()
        except BaseException:
            pass


# The domain name makes call sites easier to read.
ChallengeLock = FileLock


__all__ = ["ChallengeLock", "FileLock", "LockTimeout"]
