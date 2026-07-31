"""Cross-process spacing for remote command *start* times.

This module is deliberately not an HTTP request limiter or token bucket.  It
can only space CTF-OS sandbox command starts for the same normalized hostname.
If one command sends several requests, request-level enforcement belongs in an
explicit egress proxy/firewall outside this limiter, including CTF-OS's
challenge-scoped built-in proxy.
"""

from __future__ import annotations

import builtins
import errno
import hashlib
import ipaddress
import json
import math
import os
import re
import stat
import sys
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, TypeVar

from ctf_os.store.atomic import atomic_write_bytes

try:
    import fcntl
except ImportError:  # pragma: no cover - CTF-OS targets Linux/WSL
    fcntl = None  # type: ignore[assignment]


STATE_VERSION = 1
DEFAULT_MIN_INTERVAL_SECONDS = 1.0
MAX_MIN_INTERVAL_SECONDS = 3600.0
DEFAULT_POLL_INTERVAL_SECONDS = 0.05
MAX_STATE_BYTES = 256 * 1024
MAX_WAITERS = 1024
_TICKET = re.compile(r"^[0-9a-f]{32}$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_LockedResult = TypeVar("_LockedResult")


class RemoteCommandStartTimeout(TimeoutError):
    """Raised when a command cannot reach its host start time by deadline."""


class RemoteCommandStartCancelled(RuntimeError):
    """Raised when a queued command start is cancelled."""


class RemoteLimiterStateError(RuntimeError):
    """Raised when shared limiter state is unsafe or malformed."""


class RemoteLimiterQueueFull(RuntimeError):
    """Raised instead of allowing the shared FIFO state to grow unbounded."""


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


class CancellationEvent(Protocol):
    def is_set(self) -> bool:
        ...

    def wait(self, timeout: float | None = None) -> bool:
        ...


@dataclass(frozen=True, slots=True)
class RemoteStartPermit:
    """A command may start immediately when this record is returned."""

    hostname: str
    wait_seconds: float
    started_monotonic: float
    enabled: bool


@dataclass(frozen=True, slots=True)
class RemoteLimiterSnapshot:
    hostname: str
    min_interval_seconds: float
    waiting: int
    last_start_monotonic: float | None
    enabled: bool


def normalize_remote_hostname(hostname: str) -> str:
    """Return one stable DNS/IP hostname key.

    Callers must pass a hostname, not a URL or ``host:port`` target.  IPv6 may
    be bracketed. DNS names are lower-cased, IDNA encoded, and stripped of one
    terminal root dot.
    """

    if not isinstance(hostname, str):
        raise TypeError("remote hostname must be a string")
    value = hostname.strip()
    if (
        not value
        or "\x00" in value
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        or "/" in value
        or "\\" in value
        or "://" in value
    ):
        raise ValueError("remote hostname is empty or contains target syntax")
    if value.startswith("[") or value.endswith("]"):
        if not (value.startswith("[") and value.endswith("]")):
            raise ValueError("remote IPv6 brackets are unbalanced")
        value = value[1:-1]
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if ":" in value:
            raise ValueError(
                "remote hostname must not include a port"
            ) from None
        value = value.removesuffix(".")
        if not value:
            raise ValueError("remote hostname cannot be the DNS root")
        try:
            normalized = value.encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise ValueError("remote hostname is not valid IDNA") from error
        if len(normalized.encode("ascii")) > 253:
            raise ValueError("remote hostname exceeds 253 ASCII bytes")
        labels = normalized.split(".")
        if not all(_DNS_LABEL.fullmatch(label) for label in labels):
            raise ValueError("remote hostname has an invalid DNS label")
        return normalized
    return address.compressed.lower()


def _process_start_ticks(pid: int) -> int | None:
    try:
        payload = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        closing_parenthesis = payload.rfind(")")
        if closing_parenthesis < 0:
            return None
        fields = payload[closing_parenthesis + 2 :].split()
        return int(fields[19])
    except (FileNotFoundError, PermissionError, ValueError, IndexError):
        return None


def _pid_alive(pid: int, expected_start_ticks: int | None) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError as error:
        if error.errno != errno.EPERM:
            return False
    if expected_start_ticks is None:
        return True
    return _process_start_ticks(pid) == expected_start_ticks


def _boot_id() -> str:
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="ascii"
        )
    except (OSError, UnicodeError):
        return "unknown"
    normalized = value.strip().lower()
    if (
        not normalized
        or len(normalized) > 128
        or any(character not in "0123456789abcdef-" for character in normalized)
    ):
        return "unknown"
    return normalized


def _strict_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RemoteLimiterStateError(
                f"duplicate remote limiter state key: {key!r}"
            )
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise RemoteLimiterStateError(
        f"non-finite remote limiter state number: {value}"
    )


def _read_bounded_state(path: Path) -> bytes | None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise RemoteLimiterStateError(
            f"cannot open remote limiter state: {error}"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RemoteLimiterStateError(
                "remote limiter state is not a regular file"
            )
        if metadata.st_size > MAX_STATE_BYTES:
            raise RemoteLimiterStateError(
                f"remote limiter state exceeds {MAX_STATE_BYTES} bytes"
            )
        chunks: list[bytes] = []
        remaining = MAX_STATE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > MAX_STATE_BYTES:
            raise RemoteLimiterStateError(
                f"remote limiter state exceeds {MAX_STATE_BYTES} bytes"
            )
        after = os.fstat(descriptor)
        if (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or len(payload) != after.st_size:
            raise RemoteLimiterStateError(
                "remote limiter state changed while being read"
            )
        return payload
    finally:
        os.close(descriptor)


def _validated_queue_entry(entry: object) -> dict[str, object]:
    if not isinstance(entry, dict) or set(entry) != {
        "ticket",
        "pid",
        "process_start_ticks",
    }:
        raise RemoteLimiterStateError(
            "remote limiter queue entry has an unexpected schema"
        )
    ticket = entry.get("ticket")
    pid = entry.get("pid")
    ticks = entry.get("process_start_ticks")
    if (
        not isinstance(ticket, str)
        or _TICKET.fullmatch(ticket) is None
        or isinstance(pid, bool)
        or not isinstance(pid, int)
        or not 1 <= pid <= 2**31 - 1
        or (
            ticks is not None
            and (
                isinstance(ticks, bool)
                or not isinstance(ticks, int)
                or not 0 <= ticks <= 2**63 - 1
            )
        )
    ):
        raise RemoteLimiterStateError(
            "remote limiter queue entry has invalid values"
        )
    return {
        "ticket": ticket,
        "pid": pid,
        "process_start_ticks": ticks,
    }


class RemoteCommandStartLimiter:
    """Space same-host command starts with a bounded cross-process FIFO.

    Call :meth:`wait_for_start` immediately before starting the sandbox
    command. The returned permit does not reserve a slot for command duration,
    so commands may overlap after their starts have been spaced. This composes
    with independent tool/provider capacity limiters without changing logical
    worker counts.

    It does not inspect or limit requests made inside the command.
    """

    def __init__(
        self,
        runtime_root: Path | str,
        min_interval_seconds: float = DEFAULT_MIN_INTERVAL_SECONDS,
        *,
        poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
        max_waiters: int = MAX_WAITERS,
    ) -> None:
        if fcntl is None:
            raise RuntimeError("RemoteCommandStartLimiter requires fcntl")
        if (
            isinstance(min_interval_seconds, bool)
            or not isinstance(min_interval_seconds, (int, float))
            or not math.isfinite(float(min_interval_seconds))
            or not 0 <= float(min_interval_seconds) <= MAX_MIN_INTERVAL_SECONDS
        ):
            raise ValueError(
                "min_interval_seconds must be finite and between 0 and "
                f"{MAX_MIN_INTERVAL_SECONDS}"
            )
        if (
            isinstance(poll_interval_seconds, bool)
            or not isinstance(poll_interval_seconds, (int, float))
            or not math.isfinite(float(poll_interval_seconds))
            or not 0 < float(poll_interval_seconds) <= 5
        ):
            raise ValueError(
                "poll_interval_seconds must be finite and between 0 and 5"
            )
        if (
            isinstance(max_waiters, bool)
            or not isinstance(max_waiters, int)
            or not 1 <= max_waiters <= MAX_WAITERS
        ):
            raise ValueError(
                f"max_waiters must be between 1 and {MAX_WAITERS}"
            )
        self._runtime_root = Path(runtime_root).expanduser().resolve()
        self._state_root = (
            self._runtime_root / "remote-command-starts"
        )
        self._min_interval = float(min_interval_seconds)
        self._poll_interval = float(poll_interval_seconds)
        self._max_waiters = max_waiters
        self._boot_id = _boot_id()

    @property
    def enabled(self) -> bool:
        return self._min_interval > 0

    def state_path(self, hostname: str) -> Path:
        normalized = normalize_remote_hostname(hostname)
        digest = hashlib.sha256(normalized.encode("ascii")).hexdigest()
        return self._state_root / f"{digest}.json"

    def _lock_path(self, hostname: str) -> Path:
        return self.state_path(hostname).with_suffix(".json.lock")

    def _new_state(self, hostname: str) -> dict[str, object]:
        return {
            "version": STATE_VERSION,
            "hostname": hostname,
            "boot_id": self._boot_id,
            "last_start_monotonic": None,
            "queue": [],
        }

    def _decode_state(
        self,
        payload: bytes | None,
        hostname: str,
    ) -> dict[str, object]:
        if payload is None:
            return self._new_state(hostname)
        try:
            value = json.loads(
                payload.decode("utf-8", errors="strict"),
                object_pairs_hook=_strict_object,
                parse_constant=_invalid_constant,
            )
        except UnicodeDecodeError as error:
            raise RemoteLimiterStateError(
                "remote limiter state is not UTF-8"
            ) from error
        except json.JSONDecodeError as error:
            raise RemoteLimiterStateError(
                f"remote limiter state is invalid JSON: {error.msg}"
            ) from error
        if not isinstance(value, dict) or set(value) != {
            "version",
            "hostname",
            "boot_id",
            "last_start_monotonic",
            "queue",
        }:
            raise RemoteLimiterStateError(
                "remote limiter state has an unexpected schema"
            )
        if value.get("version") != STATE_VERSION:
            raise RemoteLimiterStateError(
                "remote limiter state has an unsupported version"
            )
        if value.get("hostname") != hostname:
            raise RemoteLimiterStateError(
                "remote limiter state hostname does not match its file"
            )
        boot_id = value.get("boot_id")
        if (
            not isinstance(boot_id, str)
            or not boot_id
            or len(boot_id) > 128
        ):
            raise RemoteLimiterStateError(
                "remote limiter state has an invalid boot_id"
            )
        last_start = value.get("last_start_monotonic")
        if last_start is not None and (
            isinstance(last_start, bool)
            or not isinstance(last_start, (int, float))
            or not math.isfinite(float(last_start))
            or float(last_start) < 0
        ):
            raise RemoteLimiterStateError(
                "remote limiter state has an invalid last start"
            )
        queue = value.get("queue")
        if not isinstance(queue, list):
            raise RemoteLimiterStateError(
                "remote limiter queue must be an array"
            )
        if len(queue) > self._max_waiters:
            raise RemoteLimiterStateError(
                "remote limiter queue exceeds its bounded capacity"
            )
        if boot_id != self._boot_id:
            value["boot_id"] = self._boot_id
            value["last_start_monotonic"] = None
            value["queue"] = []
        else:
            live_queue: list[dict[str, object]] = []
            seen_tickets: set[str] = set()
            for raw_entry in queue:
                entry = _validated_queue_entry(raw_entry)
                ticket = str(entry["ticket"])
                if ticket in seen_tickets:
                    raise RemoteLimiterStateError(
                        "remote limiter queue contains a duplicate ticket"
                    )
                seen_tickets.add(ticket)
                pid = int(entry["pid"])
                raw_ticks = entry["process_start_ticks"]
                ticks = int(raw_ticks) if raw_ticks is not None else None
                if _pid_alive(pid, ticks):
                    live_queue.append(entry)
            value["last_start_monotonic"] = (
                float(last_start) if last_start is not None else None
            )
            value["queue"] = live_queue
        return value

    @staticmethod
    def _encode_state(state: dict[str, object]) -> bytes:
        try:
            payload = (
                json.dumps(
                    state,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                + "\n"
            ).encode("utf-8")
        except (TypeError, ValueError) as error:
            raise RemoteLimiterStateError(
                f"cannot encode remote limiter state: {error}"
            ) from error
        if len(payload) > MAX_STATE_BYTES:
            raise RemoteLimiterStateError(
                "remote limiter state would exceed its byte bound"
            )
        return payload

    def _locked_state(
        self,
        hostname: str,
        operation: Callable[[dict[str, object]], _LockedResult],
        *,
        deadline: float | None = None,
        cancel_event: CancellationEvent | None = None,
        allow_immediate: bool = False,
    ) -> _LockedResult:
        """Run one state transaction and release the flock before returning."""

        state_path = self.state_path(hostname)
        lock_path = self._lock_path(hostname)
        self._state_root.mkdir(parents=True, exist_ok=True)

        def private_opener(raw_path: str, flags: int) -> int:
            return os.open(
                raw_path,
                flags
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )

        try:
            stream = builtins.open(
                lock_path,
                "a+b",
                buffering=0,
                opener=private_opener,
            )
        except OSError as error:
            raise RemoteLimiterStateError(
                f"cannot open remote limiter lock: {error}"
            ) from error
        descriptor = stream.fileno()
        try:
            if deadline is None and cancel_event is None:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            else:
                first_attempt = True
                while True:
                    if self._cancelled(cancel_event):
                        raise RemoteCommandStartCancelled(
                            "cancelled while waiting for the remote limiter "
                            "state lock"
                        )
                    now = time.monotonic()
                    immediate_attempt = allow_immediate and first_attempt
                    if (
                        deadline is not None
                        and now >= deadline
                        and not immediate_attempt
                    ):
                        raise RemoteCommandStartTimeout(
                            "timed out waiting for the remote limiter "
                            "state lock"
                        )
                    try:
                        fcntl.flock(
                            descriptor,
                            fcntl.LOCK_EX | fcntl.LOCK_NB,
                        )
                    except OSError as error:
                        if error.errno not in (errno.EACCES, errno.EAGAIN):
                            raise
                    else:
                        if self._cancelled(cancel_event):
                            raise RemoteCommandStartCancelled(
                                "cancelled while waiting for the remote "
                                "limiter state lock"
                            )
                        if (
                            deadline is not None
                            and time.monotonic() >= deadline
                            and not immediate_attempt
                        ):
                            raise RemoteCommandStartTimeout(
                                "timed out waiting for the remote limiter "
                                "state lock"
                            )
                        break
                    first_attempt = False
                    sleep_for = self._poll_interval
                    if deadline is not None:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise RemoteCommandStartTimeout(
                                "timed out waiting for the remote limiter "
                                "state lock"
                            )
                        sleep_for = min(sleep_for, remaining)
                    if cancel_event is None:
                        time.sleep(sleep_for)
                    else:
                        cancel_event.wait(sleep_for)
            original = _read_bounded_state(state_path)
            state = self._decode_state(original, hostname)
            result = operation(state)
            encoded = self._encode_state(state)
            if encoded != original:
                atomic_write_bytes(state_path, encoded, mode=0o600)
            return result
        finally:
            active_error = sys.exception()
            cleanup_error: BaseException | None = None
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except BaseException as error:
                cleanup_error = error

            # A close error does not reveal whether the descriptor was
            # consumed. Retire both owner references before exactly one close
            # attempt; never inspect or retry the numeric descriptor because a
            # peer may already have reused it for this same lock inode.
            owned_stream = stream
            stream = None
            descriptor = -1
            close_error: BaseException | None = None
            try:
                owned_stream.close()
            except BaseException as error:
                close_error = error
            interruption = (
                cleanup_error
                if cleanup_error is not None
                and not isinstance(cleanup_error, Exception)
                else close_error
                if close_error is not None
                and not isinstance(close_error, Exception)
                else None
            )
            effective_error = (
                interruption
                if interruption is not None
                else None
                if close_error is None
                else cleanup_error or close_error
            )
            if effective_error is not None:
                other_error = (
                    close_error
                    if effective_error is cleanup_error
                    else cleanup_error
                )
                if other_error is not None:
                    effective_error.add_note(
                        "remote limiter recovered cleanup error: "
                        f"{other_error}"
                    )
                if active_error is not None and not isinstance(
                    active_error,
                    Exception,
                ):
                    active_error.add_note(
                        "remote limiter lock cleanup failed: "
                        f"{effective_error}"
                    )
                elif (
                    active_error is not None
                    and not isinstance(effective_error, Exception)
                ):
                    effective_error.add_note(
                        "remote limiter lock cleanup interrupted while "
                        "handling: "
                        f"{type(active_error).__name__}: {active_error}"
                    )
                    raise effective_error
                elif active_error is not None:
                    active_error.add_note(
                        "remote limiter lock cleanup failed: "
                        f"{effective_error}"
                    )
                else:
                    raise effective_error

    def _remove_ticket(self, hostname: str, ticket: str) -> None:
        cleanup_interruption: BaseException | None = None
        for attempt in range(3):
            try:
                def remove_from_state(state: dict[str, object]) -> None:
                    queue = state["queue"]
                    if not isinstance(queue, list):
                        raise RemoteLimiterStateError(
                            "remote limiter queue changed type"
                        )
                    state["queue"] = [
                        entry
                        for entry in queue
                        if not (
                            isinstance(entry, dict)
                            and entry.get("ticket") == ticket
                        )
                    ]

                self._locked_state(hostname, remove_from_state)
            except BaseException as error:
                if cleanup_interruption is None:
                    cleanup_interruption = error
                else:
                    cleanup_interruption = _prefer_control_error(
                        cleanup_interruption,
                        error,
                        label=(
                            "remote limiter ticket cleanup retry failed"
                        ),
                    )
                if attempt < 2:
                    continue
                raise cleanup_interruption
            else:
                if (
                    cleanup_interruption is not None
                    and not isinstance(cleanup_interruption, Exception)
                ):
                    raise cleanup_interruption
                return

    @staticmethod
    def _cancelled(cancel_event: CancellationEvent | None) -> bool:
        return cancel_event is not None and cancel_event.is_set()

    def wait_for_start(
        self,
        hostname: str,
        timeout: float | None = None,
        *,
        cancel_event: CancellationEvent | None = None,
    ) -> RemoteStartPermit:
        """Wait in host FIFO, record one start, and return immediately.

        ``timeout`` includes both FIFO and interval waiting. A zero interval is
        an explicit disable and creates no shared state.
        """

        normalized = normalize_remote_hostname(hostname)
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(float(timeout))
            or float(timeout) < 0
        ):
            raise ValueError("timeout must be finite and nonnegative or None")
        if self._cancelled(cancel_event):
            raise RemoteCommandStartCancelled(
                "cancelled before waiting for a remote command start"
            )
        queued_at = time.monotonic()
        if not self.enabled:
            return RemoteStartPermit(
                hostname=normalized,
                wait_seconds=0.0,
                started_monotonic=queued_at,
                enabled=False,
            )

        deadline = (
            None if timeout is None else queued_at + float(timeout)
        )
        ticket = uuid.uuid4().hex
        entry = {
            "ticket": ticket,
            "pid": os.getpid(),
            "process_start_ticks": _process_start_ticks(os.getpid()),
        }
        started = False
        ticket_may_exist = False
        first_check = True
        try:
            def enqueue(state: dict[str, object]) -> None:
                nonlocal ticket_may_exist
                queue = state["queue"]
                if not isinstance(queue, list):
                    raise RemoteLimiterStateError(
                        "remote limiter queue changed type"
                    )
                if len(queue) >= self._max_waiters:
                    raise RemoteLimiterQueueFull(
                        "remote command start FIFO is full"
                    )
                if self._cancelled(cancel_event):
                    raise RemoteCommandStartCancelled(
                        "cancelled while waiting for a remote command start"
                    )
                if (
                    deadline is not None
                    and time.monotonic() >= deadline
                    and timeout != 0
                ):
                    raise RemoteCommandStartTimeout(
                        "timed out waiting for a remote command start"
                    )
                # Arm cleanup before the durable mutation so a commit-return
                # interruption cannot orphan this ticket.
                ticket_may_exist = True
                queue.append(entry)

            self._locked_state(
                normalized,
                enqueue,
                deadline=deadline,
                cancel_event=cancel_event,
                allow_immediate=timeout == 0,
            )
            if self._cancelled(cancel_event):
                raise RemoteCommandStartCancelled(
                    "cancelled while waiting for a remote command start"
                )
            if (
                deadline is not None
                and timeout != 0
                and time.monotonic() >= deadline
            ):
                raise RemoteCommandStartTimeout(
                    "timed out waiting for a remote command start"
                )

            while True:
                if self._cancelled(cancel_event):
                    raise RemoteCommandStartCancelled(
                        "cancelled while waiting for a remote command start"
                    )
                sleep_for = self._poll_interval
                permit: RemoteStartPermit | None = None

                def inspect_head(state: dict[str, object]) -> None:
                    nonlocal sleep_for, permit, expired
                    queue = state["queue"]
                    if not isinstance(queue, list):
                        raise RemoteLimiterStateError(
                            "remote limiter queue changed type"
                        )
                    if not any(
                        isinstance(item, dict)
                        and item.get("ticket") == ticket
                        for item in queue
                    ):
                        raise RemoteLimiterStateError(
                            "remote command start ticket disappeared"
                        )
                    is_head = (
                        bool(queue)
                        and isinstance(queue[0], dict)
                        and queue[0].get("ticket") == ticket
                    )
                    now = time.monotonic()
                    immediate_check = timeout == 0 and first_check
                    expired = (
                        deadline is not None
                        and now >= deadline
                        and not immediate_check
                    )
                    cancelled = self._cancelled(cancel_event)
                    if is_head:
                        raw_last = state.get("last_start_monotonic")
                        last = (
                            float(raw_last)
                            if isinstance(raw_last, (int, float))
                            and not isinstance(raw_last, bool)
                            else None
                        )
                        if last is not None and last > now:
                            # A stale post-reboot value or monotonic rollback is
                            # handled conservatively: wait a full interval.
                            last = now
                            state["last_start_monotonic"] = now
                        ready_at = (
                            now
                            if last is None
                            else last + self._min_interval
                        )
                        if (
                            not expired
                            and not cancelled
                            and now >= ready_at
                        ):
                            queue.pop(0)
                            state["last_start_monotonic"] = now
                            permit = RemoteStartPermit(
                                hostname=normalized,
                                wait_seconds=max(0.0, now - queued_at),
                                started_monotonic=now,
                                enabled=True,
                            )
                        sleep_for = min(
                            sleep_for,
                            max(0.0, ready_at - now),
                        )

                expired = False
                self._locked_state(
                    normalized,
                    inspect_head,
                    deadline=deadline,
                    cancel_event=cancel_event,
                    allow_immediate=timeout == 0 and first_check,
                )
                if permit is not None:
                    if self._cancelled(cancel_event):
                        raise RemoteCommandStartCancelled(
                            "cancelled while waiting for a remote command "
                            "start"
                        )
                    if (
                        deadline is not None
                        and timeout != 0
                        and time.monotonic() >= deadline
                    ):
                        raise RemoteCommandStartTimeout(
                            "timed out waiting for a remote command start"
                        )
                    # The permit is live only after the queue removal and
                    # start timestamp have survived the atomic state commit.
                    # Until then the outer finally must still remove a
                    # persisted live-PID ticket after an interruption.
                    started = True
                    return permit
                if expired or timeout == 0:
                    raise RemoteCommandStartTimeout(
                        "timed out waiting for a remote command start"
                    )
                if deadline is not None:
                    sleep_for = min(
                        sleep_for,
                        max(0.0, deadline - time.monotonic()),
                    )
                first_check = False
                if cancel_event is None:
                    time.sleep(sleep_for)
                else:
                    cancel_event.wait(sleep_for)
        finally:
            if not started and ticket_may_exist:
                active_error = sys.exception()
                try:
                    self._remove_ticket(normalized, ticket)
                except BaseException as cleanup_error:
                    if (
                        active_error is not None
                        and not isinstance(active_error, Exception)
                    ):
                        active_error.add_note(
                            "remote limiter interruption cleanup failed: "
                            f"{cleanup_error}"
                        )
                    else:
                        raise

    def snapshot(self, hostname: str) -> RemoteLimiterSnapshot:
        normalized = normalize_remote_hostname(hostname)
        if not self.enabled:
            return RemoteLimiterSnapshot(
                hostname=normalized,
                min_interval_seconds=0.0,
                waiting=0,
                last_start_monotonic=None,
                enabled=False,
            )

        def build_snapshot(
            state: dict[str, object],
        ) -> RemoteLimiterSnapshot:
            queue = state["queue"]
            last = state.get("last_start_monotonic")
            return RemoteLimiterSnapshot(
                hostname=normalized,
                min_interval_seconds=self._min_interval,
                waiting=len(queue) if isinstance(queue, list) else 0,
                last_start_monotonic=(
                    float(last)
                    if isinstance(last, (int, float))
                    and not isinstance(last, bool)
                    else None
                ),
                enabled=True,
            )

        return self._locked_state(normalized, build_snapshot)


__all__ = [
    "DEFAULT_MIN_INTERVAL_SECONDS",
    "MAX_MIN_INTERVAL_SECONDS",
    "MAX_STATE_BYTES",
    "MAX_WAITERS",
    "RemoteCommandStartCancelled",
    "RemoteCommandStartLimiter",
    "RemoteCommandStartTimeout",
    "RemoteLimiterQueueFull",
    "RemoteLimiterSnapshot",
    "RemoteLimiterStateError",
    "RemoteStartPermit",
    "normalize_remote_hostname",
]
