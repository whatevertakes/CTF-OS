"""Durable append/read JSONL event log for one local node."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Iterator

try:  # ``flock`` is the required cross-process primitive for local TeamSync.
    import fcntl
except ImportError:  # pragma: no cover - exercised through the fail-closed path
    fcntl = None  # type: ignore[assignment]

from .models import Event


class EventLogError(ValueError):
    """The event log cannot be safely read, appended to, or made durable."""


@dataclass(frozen=True, slots=True)
class EventLogDiagnostic:
    """A recoverable final-record issue reported without mutating the log."""

    path: Path
    line: int
    kind: str
    message: str


@dataclass(frozen=True, slots=True)
class EventLogReadReport:
    """Valid events plus any recoverable final-record diagnostic.

    A non-newline tail is treated as crash residue.  A malformed completed
    final record is also recoverable for read-only consumers: callers receive
    all preceding records and a diagnostic, but appends refuse to proceed until
    an operator performs an explicit, separately-authorized recovery.  This
    intentionally keeps normal reads and TeamSync merges non-mutating.
    """

    events: tuple[Event, ...] = ()
    diagnostics: tuple[EventLogDiagnostic, ...] = ()


class LocalEventBus:
    """Append-only, flock-protected JSONL event log.

    ``member`` is optional for a purely local log.  When present, it prevents a
    process configured as one member from accidentally writing another member's
    events.
    """

    def __init__(self, path: str | Path, *, member: str | None = None) -> None:
        self.path = Path(path)
        self.member = member

    def append(self, event: Event) -> Event:
        """Append one durable event while serializing all cooperating writers."""
        return self._append(event, idempotent=False)

    append_event = append

    def append_idempotent(self, event: Event) -> Event:
        """Append ``event`` at most once by event ID across local processes.

        The exclusive advisory lock deliberately spans the duplicate scan,
        append, and file durability barrier.  This is required because an
        outbox retry can otherwise race another process for the same member.
        """
        return self._append(event, idempotent=True)

    def read(self) -> list[Event]:
        return list(self.iter_events())

    read_events = read

    def read_report(self) -> EventLogReadReport:
        """Read valid records and report, without changing, recoverable tails.

        A malformed completed record before the final line is never
        recoverable: it raises :class:`EventLogError` with the exact path and
        line.  The same policy applies to a completed final record followed by
        a later complete line, so valid records after corruption are never
        silently skipped.
        """
        try:
            data = self.path.read_bytes()
        except FileNotFoundError:
            return EventLogReadReport()
        except OSError as exc:
            raise EventLogError(f"cannot read event log {self.path}: {exc}") from exc
        return self._report_from_bytes(data)

    def iter_events(self) -> Iterator[Event]:
        yield from self.read_report().events

    def _append(self, event: Event, *, idempotent: bool) -> Event:
        self._validate_event_member(event, appending=True)
        _require_advisory_locking()
        _ensure_parent_directory(self.path.parent)

        flags = os.O_RDWR | os.O_CREAT | os.O_APPEND
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError as exc:
            raise EventLogError(f"cannot open event log {self.path} for append: {exc}") from exc

        try:
            with _exclusive_file_lock(fd, self.path):
                report = self._report_from_bytes(_read_all(fd, self.path))
                if report.diagnostics:
                    diagnostic = report.diagnostics[0]
                    raise EventLogError(
                        f"cannot append to {self.path}: {diagnostic.kind} at line {diagnostic.line}; "
                        "inspect read_report() and perform explicit recovery first"
                    )
                if idempotent and any(existing.id == event.id for existing in report.events):
                    # This also repairs directory-entry durability if a prior
                    # process wrote the file but returned before its dir fsync.
                    _fsync_directory(self.path.parent)
                    return event

                encoded = (
                    json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
                ).encode("utf-8")
                _write_all(fd, encoded, self.path)
                _fsync_file(fd, self.path)
                # The first file creation (and any parent creation performed
                # above) is not durable until its containing directory entry is
                # synced.  We do this on each successful append so a retry can
                # repair a prior post-write directory-sync failure.
                _fsync_directory(self.path.parent)
                return event
        finally:
            try:
                os.close(fd)
            except OSError as exc:
                raise EventLogError(f"cannot close event log {self.path}: {exc}") from exc

    def _report_from_bytes(self, data: bytes) -> EventLogReadReport:
        if not data:
            return EventLogReadReport()

        complete_lines = data.split(b"\n")
        tail: bytes | None = None
        if data.endswith(b"\n"):
            complete_lines.pop()
        else:
            tail = complete_lines.pop()

        events: list[Event] = []
        complete_line_count = len(complete_lines)
        for line_number, raw_line in enumerate(complete_lines, start=1):
            # JSONL convention permits CRLF, but a lone CR is not a completed
            # record delimiter and remains part of the non-newline tail case.
            if raw_line.endswith(b"\r"):
                raw_line = raw_line[:-1]
            if not raw_line.strip():
                continue
            try:
                decoded = json.loads(raw_line.decode("utf-8"))
                if not isinstance(decoded, dict):
                    raise ValueError("JSONL event must be an object")
                event = Event.from_dict(decoded)
                self._validate_event_member(event)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                if line_number == complete_line_count:
                    diagnostic = EventLogDiagnostic(
                        path=self.path,
                        line=line_number,
                        kind="malformed_final",
                        message=(
                            f"malformed completed final JSONL record in {self.path} at line {line_number}: {exc}; "
                            "ignored for read-only recovery"
                        ),
                    )
                    return EventLogReadReport(tuple(events), (diagnostic,))
                raise EventLogError(f"invalid event in {self.path} at line {line_number}: {exc}") from exc
            events.append(event)

        if tail is not None:
            diagnostic = EventLogDiagnostic(
                path=self.path,
                line=complete_line_count + 1,
                kind="incomplete_tail",
                message=(
                    f"incomplete non-newline tail in {self.path} at line {complete_line_count + 1}; "
                    "ignored as crash residue"
                ),
            )
            return EventLogReadReport(tuple(events), (diagnostic,))
        return EventLogReadReport(tuple(events))

    def _validate_event_member(self, event: Event, *, appending: bool = False) -> None:
        if self.member is not None and event.member != self.member:
            if appending:
                raise PermissionError(
                    f"local node {self.member!r} cannot write events for {event.member!r}"
                )
            raise ValueError(f"event in {self.path} does not belong to member {self.member!r}")


def _require_advisory_locking() -> None:
    if fcntl is None or not hasattr(fcntl, "flock"):
        raise EventLogError("advisory locking unavailable; refusing unsafe JSONL append")


@contextmanager
def _exclusive_file_lock(fd: int, path: Path) -> Iterator[None]:
    _require_advisory_locking()
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)  # type: ignore[union-attr]
    except OSError as exc:
        raise EventLogError(f"cannot acquire advisory lock for {path}: {exc}") from exc
    try:
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)  # type: ignore[union-attr]
        except OSError as exc:
            raise EventLogError(f"cannot release advisory lock for {path}: {exc}") from exc


def _ensure_parent_directory(directory: Path) -> None:
    """Create missing parent components and fsync each new directory entry."""
    missing: list[Path] = []
    existing = directory
    while not existing.exists():
        missing.append(existing)
        parent = existing.parent
        if parent == existing:
            raise EventLogError(f"cannot find an existing ancestor for {directory}")
        existing = parent
    if not existing.is_dir():
        raise EventLogError(f"event log parent is not a directory: {existing}")

    for created in reversed(missing):
        try:
            created.mkdir(mode=0o700)
        except FileExistsError:
            if not created.is_dir():
                raise EventLogError(f"event log parent is not a directory: {created}")
        except OSError as exc:
            raise EventLogError(f"cannot create event log directory {created}: {exc}") from exc
        # This sync is intentionally repeated when a racer created the
        # directory.  It is harmless and ensures this process does not assume
        # another process completed the parent-entry durability barrier.
        _fsync_directory(created.parent)


def _read_all(fd: int, path: Path) -> bytes:
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        while True:
            try:
                chunk = os.read(fd, 1024 * 1024)
            except InterruptedError:
                continue
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    except OSError as exc:
        raise EventLogError(f"cannot scan event log {path}: {exc}") from exc


def _write_all(fd: int, data: bytes, path: Path) -> None:
    view = memoryview(data)
    written_total = 0
    while written_total < len(view):
        try:
            written = os.write(fd, view[written_total:])
        except InterruptedError:
            continue
        except OSError as exc:
            raise EventLogError(f"cannot append event to {path}: {exc}") from exc
        if written <= 0:
            raise EventLogError(f"cannot append event to {path}: write returned {written}")
        if written > len(view) - written_total:
            raise EventLogError(f"cannot append event to {path}: write returned invalid byte count {written}")
        written_total += written


def _fsync_file(fd: int, path: Path) -> None:
    try:
        os.fsync(fd)
    except OSError as exc:
        raise EventLogError(f"cannot fsync event log {path}: {exc}") from exc


def _fsync_directory(directory: Path) -> None:
    """Sync a directory entry, failing closed when the platform cannot do it."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(directory, flags)
    except OSError as exc:
        raise EventLogError(f"cannot open directory for fsync {directory}: {exc}") from exc
    try:
        os.fsync(fd)
    except OSError as exc:
        raise EventLogError(f"cannot fsync directory {directory}: {exc}") from exc
    finally:
        try:
            os.close(fd)
        except OSError as exc:
            raise EventLogError(f"cannot close directory after fsync {directory}: {exc}") from exc
