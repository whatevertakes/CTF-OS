"""Cross-process FIFO-ish resource leases backed by ``flock``.

Ordinary live leases own a locked file descriptor and are reclaimed on process
exit. Durable sandbox-job leases retain their reservation after monitor death
until exact runtime recovery explicitly retires the bound record. A short
global mutex protects allocation bookkeeping only.
"""

from __future__ import annotations

import errno
import fcntl
import json
import math
import os
import re
import secrets
import stat
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypeVar

from .resources import ResourceKind, ResourceLimits, ResourceVector

_MutexResult = TypeVar("_MutexResult")


class LeaseError(RuntimeError):
    """Base class for expected lease broker failures."""


class LeaseOwnershipError(LeaseError):
    """Raised when a caller attempts to release a foreign or stale lease."""


class _MutexDeadlineExpired(TimeoutError):
    """Internal signal that a timed broker transaction could not start."""


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


@dataclass(frozen=True, slots=True)
class LeaseRecord:
    lease_id: str
    owner: str
    resources: ResourceVector
    requested: ResourceVector
    acquired_at: str
    pid: int
    durable: bool = False

    @property
    def partial(self) -> bool:
        return self.resources != self.requested


@dataclass(frozen=True, slots=True)
class BrokerStatus:
    capacity: ResourceVector
    used: ResourceVector
    available: ResourceVector
    leases: tuple[LeaseRecord, ...]
    queued: int


class _MutexHandle:
    """Owned broker mutex fd that unlocks on a lost return handoff."""

    __slots__ = ("_fd",)

    def __init__(self) -> None:
        # Construct and publish this resource-free owner before opening an fd.
        # _safe_open() installs ownership directly into this slot.
        self._fd: int | None = None

    def release(self) -> None:
        fd = self._fd
        if fd is None:
            return
        primary_error: BaseException | None = None

        def record_error(operation: str, error: BaseException) -> None:
            nonlocal primary_error
            if primary_error is None:
                primary_error = error
                return
            primary_error = _prefer_control_error(
                primary_error,
                error,
                label=f"resource mutex {operation} cleanup failed",
            )

        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except BaseException as error:
            record_error("unlock", error)

        # A close error does not reveal whether Linux consumed the descriptor.
        # Pre-clear ownership and make exactly one attempt so a same-inode peer
        # that reuses this integer can never be closed by a retry.
        self._fd = None
        try:
            os.close(fd)
        except BaseException as error:
            record_error("descriptor close", error)
        if primary_error is not None:
            raise primary_error

    def __del__(self) -> None:
        try:
            # release() publishes the descriptor as unowned before its one
            # close attempt, so a finalizer call is safely idempotent.
            self.release()
        except BaseException:
            pass


class Lease:
    """A live lease.  Keep this object open for the complete tool lifetime."""

    __slots__ = ("_broker", "_fd", "_fd_identity", "_released", "record")

    def __init__(self) -> None:
        # The resource-free object is stored by _allocate_locked() before any
        # descriptor ownership is activated.  A CALL -> STORE interruption can
        # therefore finalize it without re-entering the broker mutex.
        self._released = True

    def _activate(
        self,
        broker: LeaseBroker,
        fd: int,
        record: LeaseRecord,
    ) -> None:
        self._broker = broker
        self._fd = fd
        opened = os.fstat(fd)
        self._fd_identity = (opened.st_dev, opened.st_ino)
        self.record = record
        # Publish live ownership last.  _allocate_locked() already holds a
        # reference and retires it before its one cleanup close on any later
        # interruption.
        self._released = False

    @property
    def lease_id(self) -> str:
        return self.record.lease_id

    @property
    def resources(self) -> ResourceVector:
        return self.record.resources

    @property
    def partial(self) -> bool:
        return self.record.partial

    @property
    def released(self) -> bool:
        return self._released

    def release(self) -> None:
        self._broker.release(self)

    def __enter__(self) -> Lease:
        if self._released:
            raise LeaseOwnershipError("cannot re-enter a released lease")
        return self

    def __exit__(self, *_: object) -> None:
        self.release()

    def __del__(self) -> None:
        if self._released:
            return
        try:
            # A return value lost before the caller can store it must release
            # both its persisted record and kernel-held capacity immediately.
            self._broker.release(self)
        except BaseException:
            # release() can complete the exact descriptor cleanup and only
            # then propagate an interruption from an earlier cleanup step.
            # In that case the integer may already belong to another thread.
            if self._released:
                return
            fd = self._fd
            try:
                current = os.fstat(fd)
            except OSError as error:
                if error.errno == errno.EBADF:
                    self._released = True
                return
            except BaseException:
                return
            if (current.st_dev, current.st_ino) != self._fd_identity:
                # A stale integer must never be closed by this finalizer.
                self._released = True
                return
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except BaseException:
                pass
            # Finalizer cleanup follows the same consume-on-attempt rule as the
            # primary release path.  A possible unowned fd leak is safer than
            # closing a same-inode descriptor that a peer has already reused.
            self._released = True
            try:
                os.close(fd)
            except BaseException:
                pass


class LeaseBroker:
    """Allocate complete host resource bundles without scheduling sessions."""

    def __init__(
        self,
        root: Path,
        limits: ResourceLimits | ResourceVector | None = None,
        *,
        poll_interval: float = 0.05,
    ) -> None:
        self.root = root.expanduser().resolve()
        self.capacity = (
            limits.as_vector()
            if isinstance(limits, ResourceLimits)
            else limits or ResourceLimits().as_vector()
        )
        if self.capacity.is_empty():
            raise ValueError("at least one resource capacity must be non-zero")
        if (
            isinstance(poll_interval, bool)
            or not isinstance(poll_interval, (int, float))
            or not math.isfinite(float(poll_interval))
            or poll_interval <= 0
        ):
            raise ValueError(
                "poll_interval must be a finite positive number"
            )
        self.poll_interval = poll_interval
        self._leases_dir = self.root / "leases"
        self._queue_dir = self.root / "queue"
        self._mutex_path = self.root / "leases.lock"
        self._capacity_path = self.root / "capacity.json"
        self._prepare_root()

    def _prepare_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.is_symlink():
            raise LeaseError(f"lease root must not be a symlink: {self.root}")
        self._leases_dir.mkdir(mode=0o700, exist_ok=True)
        self._queue_dir.mkdir(mode=0o700, exist_ok=True)
        for directory in (self.root, self._leases_dir, self._queue_dir):
            if directory.is_symlink() or not directory.is_dir():
                raise LeaseError(f"unsafe lease directory: {directory}")
        fd = self._safe_open(
            self._mutex_path,
            os.O_RDWR | os.O_CREAT,
            mode=0o600,
        )
        os.close(fd)

        def initialize_capacity() -> None:
            if self._capacity_path.exists():
                value = self._load_json(self._capacity_path)
                try:
                    recorded = ResourceVector.from_mapping(value["capacity"])
                except (KeyError, TypeError, ValueError) as error:
                    raise LeaseError("invalid persisted resource capacity") from error
                if recorded != self.capacity:
                    raise LeaseError(
                        "resource capacity differs from the broker already "
                        "using this root"
                    )
            else:
                self._atomic_json(
                    self._capacity_path,
                    {
                        "schema_version": 1,
                        "capacity": self.capacity.as_dict(),
                    },
                )

        self._with_mutex(initialize_capacity)

    @staticmethod
    def _safe_open(
        path: Path,
        flags: int,
        *,
        mode: int = 0o600,
        mutex_owner: _MutexHandle | None = None,
    ) -> int:
        flags |= os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            before = path.stat(follow_symlinks=False)
        except FileNotFoundError:
            before = None
        if before is not None and not stat.S_ISREG(before.st_mode):
            raise LeaseError(f"broker file must be regular: {path}")
        fd = os.open(path, flags, mode)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                raise LeaseError(f"broker file must be regular: {path}")
            if before is not None and (
                opened.st_dev,
                opened.st_ino,
            ) != (before.st_dev, before.st_ino):
                raise LeaseError(f"broker file changed while opening: {path}")
            if mutex_owner is not None:
                if mutex_owner._fd is not None:
                    raise RuntimeError("resource mutex owner is already armed")
                # The caller stores mutex_owner before this function is called.
                # If this return is interrupted, its finally path observes the
                # published fd and performs the one authoritative close.
                mutex_owner._fd = fd
            return fd
        except BaseException:
            if mutex_owner is None or mutex_owner._fd != fd:
                os.close(fd)
            raise

    def _lock_mutex(self) -> _MutexHandle:
        # Store a resource-free owner before the open call.  This removes the
        # resource-owning constructor CALL -> STORE handoff window.
        handle = _MutexHandle()
        try:
            self._safe_open(
                self._mutex_path,
                os.O_RDWR,
                mutex_owner=handle,
            )
            fd = handle._fd
            assert fd is not None
            fcntl.flock(fd, fcntl.LOCK_EX)
            return handle
        except BaseException as error:
            try:
                handle.release()
            except BaseException as cleanup_error:
                preferred = _prefer_control_error(
                    error,
                    cleanup_error,
                    label="resource mutex interruption cleanup failed",
                )
                if preferred is not error:
                    raise preferred
            raise

    def _with_mutex(
        self,
        operation: Callable[[], _MutexResult],
        *,
        deadline: float | None = None,
        allow_immediate: bool = False,
    ) -> _MutexResult:
        """Run one broker transaction and close its mutex before returning."""

        # Publish the resource-free handle before _safe_open() can own an fd.
        handle = _MutexHandle()
        try:
            self._safe_open(
                self._mutex_path,
                os.O_RDWR,
                mutex_owner=handle,
            )
            fd = handle._fd
            assert fd is not None
            if deadline is None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            else:
                first_attempt = True
                while True:
                    now = time.monotonic()
                    immediate_attempt = allow_immediate and first_attempt
                    if now >= deadline and not immediate_attempt:
                        raise _MutexDeadlineExpired
                    try:
                        fcntl.flock(
                            fd,
                            fcntl.LOCK_EX | fcntl.LOCK_NB,
                        )
                    except OSError as error:
                        if error.errno not in (errno.EACCES, errno.EAGAIN):
                            raise
                    else:
                        if (
                            time.monotonic() >= deadline
                            and not immediate_attempt
                        ):
                            raise _MutexDeadlineExpired
                        break
                    first_attempt = False
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise _MutexDeadlineExpired
                    time.sleep(min(self.poll_interval, remaining))
            return operation()
        finally:
            active_error = sys.exception()
            try:
                handle.release()
            except BaseException as cleanup_error:
                if (
                    active_error is not None
                    and not isinstance(active_error, Exception)
                ):
                    active_error.add_note(
                        "resource mutex transaction cleanup failed: "
                        f"{cleanup_error}"
                    )
                else:
                    raise

    @staticmethod
    def _unlock_close(handle: _MutexHandle) -> None:
        handle.release()

    @staticmethod
    def _process_identity(pid: int | None = None) -> tuple[int, int | None]:
        actual_pid = pid or os.getpid()
        try:
            text = Path(f"/proc/{actual_pid}/stat").read_text(encoding="ascii")
            fields = text[text.rfind(")") + 2 :].split()
            return actual_pid, int(fields[19])
        except (OSError, ValueError, IndexError):
            return actual_pid, None

    @staticmethod
    def _process_alive(pid: int, start_ticks: int | None) -> bool:
        if pid <= 1:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        if start_ticks is None:
            return True
        current_pid, current_ticks = LeaseBroker._process_identity(pid)
        return current_pid == pid and current_ticks == start_ticks

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _atomic_json(path: Path, value: dict[str, Any]) -> None:
        temporary = path.with_name(
            f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
        )
        fd: int | None = None

        def close_descriptor() -> BaseException | None:
            nonlocal fd
            closing = fd
            if closing is None:
                return None
            fd = None
            try:
                os.close(closing)
            except BaseException as error:
                return error
            return None

        try:
            fd = os.open(
                temporary,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                payload = (
                    json.dumps(
                        value,
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                    + "\n"
                ).encode("utf-8")
                remaining = memoryview(payload)
                while remaining:
                    written = os.write(fd, remaining)
                    if written <= 0:
                        raise OSError(
                            "resource JSON write made no progress"
                        )
                    remaining = remaining[written:]
                os.fsync(fd)
            finally:
                close_error = close_descriptor()
                if close_error is not None:
                    raise close_error
            os.replace(temporary, path)
            directory_fd = os.open(
                path.parent,
                os.O_RDONLY | os.O_CLOEXEC,
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            active_error = sys.exception()
            cleanup_error: BaseException | None = None
            if fd is not None:
                descriptor_error = close_descriptor()
                if descriptor_error is not None:
                    cleanup_error = descriptor_error
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except BaseException as temporary_error:
                if cleanup_error is None:
                    cleanup_error = temporary_error
                else:
                    cleanup_error = _prefer_control_error(
                        cleanup_error,
                        temporary_error,
                        label="resource JSON temporary cleanup failed",
                    )
            if cleanup_error is not None:
                if (
                    active_error is not None
                    and not isinstance(active_error, Exception)
                ):
                    active_error.add_note(
                        "resource JSON cleanup failed: "
                        f"{cleanup_error}"
                    )
                elif not isinstance(cleanup_error, Exception):
                    if active_error is not None:
                        cleanup_error.add_note(
                            "resource JSON cleanup interrupted while "
                            "handling: "
                            f"{type(active_error).__name__}: {active_error}"
                        )
                    raise cleanup_error
                elif active_error is None:
                    raise cleanup_error
                else:
                    active_error.add_note(
                        "resource JSON cleanup failed: "
                        f"{cleanup_error}"
                    )

    @staticmethod
    def _load_json(path: Path, *, maximum_bytes: int = 64 * 1024) -> dict[str, Any]:
        fd = LeaseBroker._safe_open(path, os.O_RDONLY)
        try:
            opened = os.fstat(fd)
            if opened.st_size > maximum_bytes:
                raise LeaseError(f"oversized broker record: {path}")
            data = bytearray()
            while len(data) <= maximum_bytes:
                chunk = os.read(
                    fd,
                    min(64 * 1024, maximum_bytes + 1 - len(data)),
                )
                if not chunk:
                    break
                data.extend(chunk)
        finally:
            os.close(fd)
        if len(data) > maximum_bytes:
            raise LeaseError(f"oversized broker record: {path}")
        try:
            value = json.loads(data.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise LeaseError(f"invalid broker record: {path}") from error
        if not isinstance(value, dict):
            raise LeaseError(f"broker record must be an object: {path}")
        return value

    def _lease_paths(self, lease_id: str) -> tuple[Path, Path]:
        return (
            self._leases_dir / f"{lease_id}.lock",
            self._leases_dir / f"{lease_id}.json",
        )

    def _ticket_path(self, ticket_id: str) -> Path:
        return self._queue_dir / f"{ticket_id}.json"

    def _record_from_json(self, value: dict[str, Any]) -> LeaseRecord:
        try:
            durable = value.get("durable", False)
            if not isinstance(durable, bool):
                raise ValueError("durable must be a boolean")
            return LeaseRecord(
                lease_id=str(value["lease_id"]),
                owner=str(value["owner"]),
                resources=ResourceVector.from_mapping(value["resources"]),
                requested=ResourceVector.from_mapping(value["requested"]),
                acquired_at=str(value["acquired_at"]),
                pid=int(value["pid"]),
                durable=durable,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise LeaseError("invalid persisted lease record") from error

    def _scan_live_locked(self) -> list[LeaseRecord]:
        live: list[LeaseRecord] = []
        for metadata_path in sorted(self._leases_dir.glob("lease-*.json")):
            lease_id = metadata_path.stem
            lock_path, expected_metadata = self._lease_paths(lease_id)
            if expected_metadata != metadata_path:
                continue
            try:
                lock_fd = self._safe_open(lock_path, os.O_RDWR)
            except FileNotFoundError:
                metadata_path.unlink(missing_ok=True)
                continue
            try:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    record = self._record_from_json(self._load_json(metadata_path))
                    if record.lease_id != lease_id:
                        raise LeaseError("lease record identity does not match filename")
                    live.append(record)
                    continue
                record = self._record_from_json(
                    self._load_json(metadata_path)
                )
                if record.lease_id != lease_id:
                    raise LeaseError(
                        "lease record identity does not match filename"
                    )
                if record.durable:
                    # A durable job lease remains a reservation after its host
                    # monitor dies. Recovery must first contain/remove the
                    # exact sandbox runtime, then explicitly retire this
                    # orphan record.
                    live.append(record)
                    continue
                metadata_path.unlink(missing_ok=True)
                lock_path.unlink(missing_ok=True)
            finally:
                os.close(lock_fd)
        for lock_path in sorted(self._leases_dir.glob("lease-*.lock")):
            if lock_path.with_suffix(".json").exists():
                continue
            lock_fd = self._safe_open(lock_path, os.O_RDWR)
            try:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    # Allocation publishes metadata while holding the global
                    # mutex, so a live metadata-free lock is not expected.
                    raise LeaseError("live lease lock has no metadata")
                lock_path.unlink(missing_ok=True)
            finally:
                os.close(lock_fd)
        return live

    def _load_tickets_locked(self) -> list[dict[str, Any]]:
        tickets: list[dict[str, Any]] = []
        for path in sorted(self._queue_dir.glob("ticket-*.json")):
            try:
                value = self._load_json(path)
                pid = int(value["pid"])
                start_ticks_value = value.get("process_start_ticks")
                start_ticks = (
                    int(start_ticks_value)
                    if start_ticks_value is not None
                    else None
                )
                if not self._process_alive(pid, start_ticks):
                    path.unlink(missing_ok=True)
                    continue
                value["request_vector"] = ResourceVector.from_mapping(
                    value["request"]
                )
                value["path"] = path
                tickets.append(value)
            except FileNotFoundError:
                # Ticket retirement is an exact, idempotent unlink that does
                # not need the global allocation mutex.  A concurrent cleanup
                # can therefore remove the globbed name before _load_json()
                # opens it; that is a benign stale snapshot, not broker
                # corruption.
                continue
            except (KeyError, TypeError, ValueError, LeaseError):
                path.unlink(missing_ok=True)
        tickets.sort(
            key=lambda item: (
                int(item.get("created_ns", 0)),
                str(item.get("ticket_id", "")),
            )
        )
        return tickets

    @staticmethod
    def _used(records: list[LeaseRecord]) -> ResourceVector:
        value = ResourceVector()
        for record in records:
            value = value + record.resources
        return value

    def _create_ticket_locked(
        self,
        ticket_id: str,
        request: ResourceVector,
        owner: str,
    ) -> None:
        pid, start_ticks = self._process_identity()
        created_ns = time.monotonic_ns()
        for existing in self._load_tickets_locked():
            previous = existing.get("created_ns")
            if (
                isinstance(previous, int)
                and not isinstance(previous, bool)
                and previous >= 0
            ):
                created_ns = max(created_ns, previous + 1)
        self._atomic_json(
            self._ticket_path(ticket_id),
            {
                "schema_version": 1,
                "ticket_id": ticket_id,
                # Ticket creation is serialized by the broker mutex. Advance
                # past every live ticket as well as the cross-process
                # monotonic clock so wall-clock rollback and equal timestamps
                # cannot reorder waiters.
                "created_ns": created_ns,
                "pid": pid,
                "process_start_ticks": start_ticks,
                "owner": owner,
                "request": request.as_dict(),
            },
        )

    def _allocate_locked(
        self,
        request: ResourceVector,
        granted: ResourceVector,
        owner: str,
        *,
        durable: bool = False,
        pending_handoff: list[Lease] | None = None,
    ) -> Lease:
        lease_id = f"lease-{secrets.token_hex(16)}"
        lock_path, metadata_path = self._lease_paths(lease_id)
        lock_fd = self._safe_open(
            lock_path,
            os.O_RDWR | os.O_CREAT | os.O_EXCL,
        )
        lease: Lease | None = None
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            record = LeaseRecord(
                lease_id=lease_id,
                owner=owner,
                resources=granted,
                requested=request,
                acquired_at=self._now(),
                pid=os.getpid(),
                durable=durable,
            )
            persisted_record: dict[str, object] = {
                "schema_version": 1,
                "lease_id": record.lease_id,
                "owner": record.owner,
                "resources": record.resources.as_dict(),
                "requested": record.requested.as_dict(),
                "acquired_at": record.acquired_at,
                "pid": record.pid,
            }
            # Preserve the historical ordinary-lease document byte shape.
            # Only background-job reservations need the explicit marker.
            if record.durable:
                persisted_record["durable"] = True
            self._atomic_json(metadata_path, persisted_record)
            # Store a resource-free, finalizer-safe owner before activating
            # descriptor ownership.  A constructor CALL -> STORE interruption
            # cannot re-enter release() while this mutex is already held.
            lease = Lease()
            lease._activate(self, lock_fd, record)
            if pending_handoff is not None:
                pending_handoff.append(lease)
            return lease
        except BaseException as error:
            primary_error = error
            if (
                pending_handoff is not None
                and lease is not None
                and pending_handoff
                and pending_handoff[-1] is lease
            ):
                pending_handoff.pop()
            # A constructed Lease is another owner of this exact integer.
            # Retire it before the single close attempt so its finalizer can
            # never reclose a same-inode descriptor reused by a peer.
            if lease is not None:
                lease._released = True
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except BaseException as cleanup_error:
                primary_error = _prefer_control_error(
                    primary_error,
                    cleanup_error,
                    label=(
                        "resource lease allocation unlock cleanup failed"
                    ),
                )
            try:
                os.close(lock_fd)
            except BaseException as cleanup_error:
                primary_error = _prefer_control_error(
                    primary_error,
                    cleanup_error,
                    label=(
                        "resource lease allocation descriptor cleanup failed"
                    ),
                )
            try:
                metadata_path.unlink(missing_ok=True)
            except BaseException as cleanup_error:
                primary_error = _prefer_control_error(
                    primary_error,
                    cleanup_error,
                    label=(
                        "resource lease allocation metadata cleanup failed"
                    ),
                )
            try:
                lock_path.unlink(missing_ok=True)
            except BaseException as cleanup_error:
                primary_error = _prefer_control_error(
                    primary_error,
                    cleanup_error,
                    label=(
                        "resource lease allocation lock cleanup failed"
                    ),
                )
            if primary_error is not error:
                raise primary_error
            raise

    def acquire(
        self,
        kind: ResourceKind | str | ResourceVector,
        count: int = 1,
        timeout: float | None = 60.0,
        *,
        allow_partial: bool = False,
        owner: str | None = None,
        durable: bool = False,
    ) -> Lease | None:
        """Acquire resources, waiting in per-overlap FIFO order.

        ``kind`` can be a single resource name or an atomic ``ResourceVector``.
        Complete bundle requests never receive partial fragments.
        """

        request = (
            kind if isinstance(kind, ResourceVector) else ResourceVector.one(kind, count)
        )
        if request.is_empty():
            raise ValueError("resource request must not be empty")
        if not isinstance(durable, bool):
            raise ValueError("durable must be a boolean")
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(float(timeout))
            or timeout < 0
        ):
            raise ValueError(
                "timeout must be a finite non-negative number or None"
            )
        if not allow_partial and not request.fits_within(self.capacity):
            return None
        if allow_partial and len(request.nonzero()) != 1:
            raise ValueError("partial allocation is supported for one kind only")

        owner_value = owner or f"pid:{os.getpid()}"
        if (
            not isinstance(owner_value, str)
            or not owner_value
            or len(owner_value) > 256
            or any(ord(character) < 0x20 for character in owner_value)
        ):
            raise ValueError("owner must be a non-empty single-line value")
        deadline = None if timeout is None else time.monotonic() + timeout
        ticket_id = f"ticket-{secrets.token_hex(16)}"
        ticket_created = False
        pending_leases: list[Lease] = []
        first_check = True

        try:
            while True:
                immediate_check = timeout == 0 and first_check

                def try_allocate(
                    immediate_check_snapshot: bool = immediate_check,
                ) -> Lease | None:
                    nonlocal ticket_created
                    records = self._scan_live_locked()
                    if (
                        deadline is not None
                        and time.monotonic() >= deadline
                        and not immediate_check_snapshot
                    ):
                        return None
                    if not ticket_created:
                        ticket_created = True
                        self._create_ticket_locked(ticket_id, request, owner_value)
                    tickets = self._load_tickets_locked()
                    if (
                        deadline is not None
                        and time.monotonic() >= deadline
                        and not immediate_check_snapshot
                    ):
                        return None
                    earlier_conflict = False
                    for ticket in tickets:
                        if ticket.get("ticket_id") == ticket_id:
                            break
                        if request.overlaps(ticket["request_vector"]):
                            earlier_conflict = True
                            break

                    if not earlier_conflict:
                        used = self._used(records)
                        available = self.capacity - used
                        granted = request if request.fits_within(available) else None
                        if granted is None and allow_partial:
                            partial = request.partial_for(available)
                            granted = None if partial.is_empty() else partial
                        if granted is not None:
                            if (
                                deadline is not None
                                and time.monotonic() >= deadline
                                and not immediate_check_snapshot
                            ):
                                return None
                            lease = self._allocate_locked(
                                request,
                                granted,
                                owner_value,
                                durable=durable,
                                pending_handoff=pending_leases,
                            )
                            self._ticket_path(ticket_id).unlink(missing_ok=True)
                            return lease
                    return None

                try:
                    lease = self._with_mutex(
                        try_allocate,
                        deadline=deadline,
                        allow_immediate=immediate_check,
                    )
                except _MutexDeadlineExpired:
                    return None
                if lease is not None:
                    if (
                        deadline is not None
                        and timeout != 0
                        and time.monotonic() >= deadline
                    ):
                        # Allocation is already durable and owns a kernel
                        # lock. Roll it back through the normal exact-identity
                        # release path before reporting the timeout.
                        lease.release()
                        return None
                    return lease

                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return None
                    time.sleep(min(self.poll_interval, remaining))
                else:
                    time.sleep(self.poll_interval)
                first_check = False
        finally:
            active_error = sys.exception()
            cleanup_errors: list[BaseException] = []
            try:
                if ticket_created:
                    cleanup_interruption: BaseException | None = None
                    cleanup_succeeded = False
                    for cleanup_attempt in range(2):
                        try:
                            # This ticket id is generated once for this acquire()
                            # call and never reused.  Retire that exact pathname
                            # directly: reacquiring the global allocation mutex
                            # after a durable grant could otherwise block past the
                            # caller's deadline while the lease still holds
                            # capacity.  Concurrent readers tolerate a disappeared
                            # glob entry in _load_tickets_locked().
                            self._ticket_path(ticket_id).unlink(missing_ok=True)
                        except BaseException as cleanup_error:
                            if cleanup_interruption is None:
                                cleanup_interruption = cleanup_error
                            else:
                                cleanup_interruption = _prefer_control_error(
                                    cleanup_interruption,
                                    cleanup_error,
                                    label=(
                                        "resource ticket cleanup retry failed"
                                    ),
                                )
                            if cleanup_attempt == 0:
                                continue
                        else:
                            cleanup_succeeded = True
                        break
                    if cleanup_interruption is not None and (
                        not cleanup_succeeded
                        or not isinstance(cleanup_interruption, Exception)
                    ):
                        cleanup_errors.append(cleanup_interruption)
                if cleanup_errors:
                    if (
                        active_error is not None
                        and not isinstance(active_error, Exception)
                    ):
                        for cleanup_error in cleanup_errors:
                            active_error.add_note(
                                "resource interruption cleanup failed: "
                                f"{cleanup_error}"
                            )
                    else:
                        primary_cleanup = cleanup_errors[0]
                        for cleanup_error in cleanup_errors[1:]:
                            primary_cleanup = _prefer_control_error(
                                primary_cleanup,
                                cleanup_error,
                                label=(
                                    "additional resource cleanup failure"
                                ),
                            )
                        if active_error is not None:
                            primary_cleanup.add_note(
                                "resource cleanup failed while handling: "
                                f"{type(active_error).__name__}: {active_error}"
                            )
                        raise primary_cleanup
            finally:
                pending_error = sys.exception()
                if pending_leases and pending_error is not None:
                    try:
                        pending_leases[-1].release()
                    except BaseException as cleanup_error:
                        if not isinstance(pending_error, Exception):
                            pending_error.add_note(
                                "resource pending lease rollback failed: "
                                f"{cleanup_error}"
                            )
                        else:
                            preferred = _prefer_control_error(
                                pending_error,
                                cleanup_error,
                                label=(
                                    "resource pending lease rollback failed"
                                ),
                            )
                            if preferred is not pending_error:
                                raise preferred

    def release(self, lease: Lease) -> None:
        if not isinstance(lease, Lease) or lease._broker is not self:
            raise LeaseOwnershipError("lease belongs to another broker")
        if lease._released:
            return

        def release_locked() -> None:
            lock_path, metadata_path = self._lease_paths(lease.lease_id)
            try:
                opened = os.fstat(lease._fd)
                current = lock_path.stat(follow_symlinks=False)
            except (OSError, FileNotFoundError) as error:
                raise LeaseOwnershipError("lease record is missing or stale") from error
            if (
                not stat.S_ISREG(current.st_mode)
                or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
                or (opened.st_dev, opened.st_ino) != lease._fd_identity
            ):
                raise LeaseOwnershipError("lease lock identity changed")
            primary_error: BaseException | None = None

            def record_cleanup_error(
                operation: str,
                error: BaseException,
            ) -> None:
                nonlocal primary_error
                if primary_error is None:
                    primary_error = error
                    return
                primary_error = _prefer_control_error(
                    primary_error,
                    error,
                    label=f"resource lease {operation} cleanup failed",
                )

            try:
                metadata_path.unlink(missing_ok=True)
            except BaseException as error:
                record_cleanup_error("metadata", error)
            try:
                fcntl.flock(lease._fd, fcntl.LOCK_UN)
            except BaseException as error:
                record_cleanup_error("unlock", error)

            lease._released = True
            try:
                os.close(lease._fd)
            except BaseException as error:
                record_cleanup_error("descriptor close", error)

            try:
                lock_path.unlink(missing_ok=True)
            except BaseException as error:
                record_cleanup_error("lock file", error)

            if primary_error is not None:
                raise primary_error

        self._with_mutex(release_locked)

    def release_orphaned_durable(
        self,
        lease_id: str,
        *,
        owner: str,
        missing_ok: bool = False,
    ) -> LeaseRecord | None:
        """Retire one dead durable lease after external containment.

        The caller must first stop and remove the exact resource consumer.
        A still-locked record is never retired, and both lease ID and owner
        must match the persisted receipt.
        """

        if (
            not isinstance(lease_id, str)
            or re.fullmatch(r"lease-[0-9a-f]{32}", lease_id) is None
            or not isinstance(owner, str)
            or not owner
            or len(owner) > 256
            or any(ord(character) < 0x20 for character in owner)
            or not isinstance(missing_ok, bool)
        ):
            raise ValueError("invalid durable lease recovery binding")

        def release_locked() -> LeaseRecord | None:
            lock_path, metadata_path = self._lease_paths(lease_id)
            try:
                lock_fd = self._safe_open(lock_path, os.O_RDWR)
            except FileNotFoundError:
                if missing_ok and not metadata_path.exists():
                    return None
                raise LeaseOwnershipError(
                    "durable lease record is missing"
                ) from None
            try:
                try:
                    fcntl.flock(
                        lock_fd,
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
                except BlockingIOError as error:
                    raise LeaseOwnershipError(
                        "durable lease monitor is still live"
                    ) from error
                try:
                    record = self._record_from_json(
                        self._load_json(metadata_path)
                    )
                except FileNotFoundError:
                    if missing_ok:
                        lock_path.unlink(missing_ok=True)
                        return None
                    raise LeaseOwnershipError(
                        "durable lease metadata is missing"
                    ) from None
                if (
                    record.lease_id != lease_id
                    or record.owner != owner
                    or not record.durable
                ):
                    raise LeaseOwnershipError(
                        "durable lease recovery binding changed"
                    )
                metadata_path.unlink()
                lock_path.unlink()
                return record
            finally:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)

        return self._with_mutex(release_locked)

    def status(self) -> BrokerStatus:
        def inspect() -> BrokerStatus:
            records = self._scan_live_locked()
            tickets = self._load_tickets_locked()
            used = self._used(records)
            return BrokerStatus(
                capacity=self.capacity,
                used=used,
                available=self.capacity - used,
                leases=tuple(records),
                queued=len(tickets),
            )

        return self._with_mutex(inspect)


ResourceBroker = LeaseBroker
ResourceLease = Lease
