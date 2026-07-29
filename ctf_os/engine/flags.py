"""Streaming flag-candidate detection and immediate terminal notification."""

from __future__ import annotations

import heapq
import json
import math
import os
import re
import stat
import sys
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from ctf_os.candidates import (
    FlagNotificationError,
    candidate_value_is_valid,
    flag_notification_error,
)
from ctf_os.terminal import terminal_safe

DEFAULT_CANDIDATE_LIMIT = 1024
DEFAULT_CANDIDATE_CHARS_LIMIT = 256 * 1024
DEFAULT_SIDECAR_MAX_BYTES = 1024 * 1024
DEFAULT_SIDECAR_LINE_MAX_BYTES = 32 * 1024
DEFAULT_SIDECAR_CANDIDATE_MAX_CHARS = 1024
DEFAULT_SIDECAR_CANDIDATE_MAX_BYTES = 4 * 1024
FLAG_CANDIDATE_SIDECAR = "flag-candidates.jsonl"
FLAG_PATTERNS_ENV = "CTF_WRAP_FLAG_PATTERNS_JSON"
PROOF_LIVE_DIRECTORY = ".proof-live"
PROOF_FINAL_DIRECTORY = "proof"
_RUN_DIRECTORY = re.compile(r"run-[0-9]{8,}")
_PROOF_LIVE_ATTEMPT_DIRECTORY = re.compile(
    r"clean-[0-9a-f]{12}-[A-Za-z0-9_]{1,64}"
)
_PROOF_FINAL_ATTEMPT_DIRECTORY = re.compile(r"clean-[0-9a-f]{12}")


@dataclass(frozen=True, slots=True)
class DetectedFlag:
    value: str
    source: str
    observed_at: str


def _safe_terminal_text(value: str) -> str:
    return terminal_safe(value)


def print_flag_candidate(
    candidate: DetectedFlag, *, stream: TextIO | None = None
) -> None:
    """Print and flush a candidate immediately.

    This is deliberately not a success or submission message.  The operator
    remains responsible for checking proof and submitting to the CTF.
    """

    actual_stream = sys.stderr if stream is None else stream
    safe_value = _safe_terminal_text(candidate.value)
    safe_source = _safe_terminal_text(candidate.source)
    print(
        f"\n🚩 FLAG CANDIDATE (미제출) [{safe_source}]\n{safe_value}\n",
        file=actual_stream,
        flush=True,
    )


class FlagDetector:
    """Incrementally scan model/tool output without losing split matches."""

    def __init__(
        self,
        patterns: Iterable[str],
        *,
        callback: Callable[[DetectedFlag], None] = print_flag_candidate,
        overlap: int = 1024,
        candidate_limit: int = DEFAULT_CANDIDATE_LIMIT,
        candidate_chars_limit: int = DEFAULT_CANDIDATE_CHARS_LIMIT,
    ) -> None:
        compiled = tuple(re.compile(pattern) for pattern in patterns)
        if not compiled:
            raise ValueError("at least one flag pattern is required")
        if overlap < 1:
            raise ValueError("overlap must be positive")
        if candidate_limit < 0 or candidate_chars_limit < 0:
            raise ValueError("candidate bounds must not be negative")
        self._patterns = compiled
        self._callback = callback
        self._overlap = overlap
        self._candidate_limit = candidate_limit
        self._candidate_chars_limit = candidate_chars_limit
        self._tails: dict[str, str] = {}
        self._seen: set[str] = set()
        self._accepted_chars = 0
        self._suppressed_matches = 0
        self._lock = threading.Lock()

    @property
    def seen(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._seen)

    @property
    def suppressed_matches(self) -> int:
        with self._lock:
            return self._suppressed_matches

    def _accept_locked(
        self, value: str, *, source: str
    ) -> DetectedFlag | None:
        if not candidate_value_is_valid(value):
            return None
        if value in self._seen:
            return None
        if (
            len(self._seen) >= self._candidate_limit
            or self._accepted_chars + len(value)
            > self._candidate_chars_limit
        ):
            self._suppressed_matches += 1
            return None
        self._seen.add(value)
        self._accepted_chars += len(value)
        return DetectedFlag(
            value=value,
            source=source,
            observed_at=datetime.now(UTC).isoformat(),
        )

    def _release_unnotified_locked(
        self,
        candidates: Iterable[DetectedFlag],
    ) -> None:
        for candidate in candidates:
            if candidate.value not in self._seen:
                continue
            self._seen.remove(candidate.value)
            self._accepted_chars -= len(candidate.value)

    def feed(self, text: str, *, source: str) -> tuple[DetectedFlag, ...]:
        """Scan a text chunk and notify once for each distinct candidate."""

        if not text:
            return ()
        with self._lock:
            prefix = self._tails.get(source, "")
            combined = prefix + text
            found: list[DetectedFlag] = []
            for pattern in self._patterns:
                for match in pattern.finditer(combined):
                    candidate = self._accept_locked(
                        match.group(0), source=source
                    )
                    if candidate is not None:
                        found.append(candidate)
            self._tails[source] = combined[-self._overlap :]

        # Never run an arbitrary callback while holding the detector lock.
        for index, candidate in enumerate(found):
            try:
                self._callback(candidate)
            except BaseException as error:
                # `_seen` means the callback accepted the candidate. Release
                # the failing candidate and every callback not yet attempted
                # so a later observation can retry durable notification.
                with self._lock:
                    self._release_unnotified_locked(found[index:])
                if not isinstance(error, Exception):
                    raise
                if isinstance(error, FlagNotificationError):
                    raise
                raise flag_notification_error(error) from error
        return tuple(found)

    def report_candidate(
        self, value: str, *, source: str
    ) -> tuple[DetectedFlag, ...]:
        """Report one sidecar candidate after rechecking it against patterns.

        The sidecar is challenge-writable input. Requiring the exact value to
        satisfy a configured pattern keeps it a candidate signal rather than
        an arbitrary terminal message. Patterns that require context outside
        the matched value should continue to use :meth:`feed`.
        """

        if not value:
            return ()
        with self._lock:
            if not any(pattern.fullmatch(value) for pattern in self._patterns):
                return ()
            candidate = self._accept_locked(value, source=source)
        if candidate is None:
            return ()
        try:
            self._callback(candidate)
        except BaseException as error:
            with self._lock:
                self._release_unnotified_locked((candidate,))
            if not isinstance(error, Exception):
                raise
            if isinstance(error, FlagNotificationError):
                raise
            raise flag_notification_error(error) from error
        return (candidate,)

    def scan_file(
        self,
        path: Path,
        *,
        source: str | None = None,
        max_bytes: int = 16 * 1024 * 1024,
        chunk_size: int = 64 * 1024,
    ) -> tuple[DetectedFlag, ...]:
        """Scan a bounded regular file, returning candidates in encounter order."""

        if max_bytes < 1 or chunk_size < 1:
            raise ValueError("scan bounds must be positive")
        label = source or str(path)
        found: list[DetectedFlag] = []
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise ValueError(
                    f"flag scan target is not a regular file: {path}"
                )
            remaining = min(opened.st_size, max_bytes)
            while remaining:
                chunk = os.read(descriptor, min(chunk_size, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                found.extend(
                    self.feed(
                        chunk.decode("utf-8", errors="replace"), source=label
                    )
                )
        finally:
            os.close(descriptor)
        return tuple(found)


class FlagTailerError(RuntimeError):
    """The live flag-log observer could not stop or drain safely."""


def _raise_descriptor_cleanup_errors(
    active_error: BaseException | None,
    cleanup_errors: list[tuple[str, BaseException]],
) -> None:
    """Raise one cleanup failure without losing a control interruption."""

    if active_error is not None and not isinstance(active_error, Exception):
        primary_error = active_error
    else:
        interruption_entry = next(
            (
                entry
                for entry in cleanup_errors
                if not isinstance(entry[1], Exception)
            ),
            None,
        )
        if interruption_entry is not None:
            primary_error = interruption_entry[1]
        elif cleanup_errors:
            primary_error = cleanup_errors[0][1]
        elif active_error is not None:
            raise active_error
        else:
            return

    for label, error in cleanup_errors:
        if error is primary_error:
            continue
        primary_error.add_note(
            f"flag {label} cleanup also failed: "
            f"{type(error).__name__}: {error}"
        )
    if active_error is not None and active_error is not primary_error:
        primary_error.add_note(
            "flag descriptor cleanup failed while handling "
            f"{type(active_error).__name__}: {active_error}"
        )
    raise primary_error


class FlagLogTailer:
    """Poll newly-created ctfwrap output and candidates while a tool runs.

    The Docker command itself is intentionally blocking, but ``/work`` is a
    host bind mount. Tailing only new regular files under
    ``.ctf/runs/run-*`` lets the operator see a candidate before the command
    exits without exposing an unbounded stream or following solver-created
    symlinks. Raw logs and the bounded full-stream candidate sidecar have
    independent byte budgets, so a truncated raw prefix cannot hide a match.
    """

    def __init__(
        self,
        work_dir: Path,
        detector: FlagDetector,
        *,
        source_prefix: str,
        max_bytes: int,
        proof: bool = False,
        poll_interval: float = 0.05,
        max_run_directories: int = 10_000,
        candidate_sidecar_max_bytes: int = DEFAULT_SIDECAR_MAX_BYTES,
        candidate_sidecar_line_max_bytes: int = (
            DEFAULT_SIDECAR_LINE_MAX_BYTES
        ),
    ) -> None:
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        if (
            isinstance(poll_interval, bool)
            or not isinstance(poll_interval, (int, float))
            or not math.isfinite(float(poll_interval))
            or poll_interval <= 0
        ):
            raise ValueError("poll_interval must be positive and finite")
        if max_run_directories < 1:
            raise ValueError("max_run_directories must be positive")
        if candidate_sidecar_max_bytes < 1:
            raise ValueError("candidate_sidecar_max_bytes must be positive")
        if candidate_sidecar_line_max_bytes < 1:
            raise ValueError(
                "candidate_sidecar_line_max_bytes must be positive"
        )
        self._work_dir = work_dir.expanduser().resolve(strict=True)
        self._work_parent = self._work_dir.parent.resolve(strict=True)
        self._proof = proof
        self._runs_root = self._work_dir / ".ctf" / "runs"
        self._proof_live_root = (
            self._work_parent / PROOF_LIVE_DIRECTORY
        )
        self._proof_final_root = (
            self._work_dir / PROOF_FINAL_DIRECTORY
        )
        self._detector = detector
        self._source_prefix = source_prefix
        self._remaining = max_bytes
        # A clean proof exposes one growing live sidecar and then persists one
        # bounded copy at a different path before the live tree disappears.
        # Reserve one physical-file budget for each.  Otherwise, reading a
        # live prefix can consume the bytes needed to drain the later complete
        # copy and silently hide a candidate near its end.  Ordinary tool runs
        # have only one physical sidecar and retain the original bound.
        candidate_physical_files = 2 if proof else 1
        self._candidate_remaining = (
            candidate_sidecar_max_bytes * candidate_physical_files
        )
        self._candidate_line_max_bytes = candidate_sidecar_line_max_bytes
        self._poll_interval = float(poll_interval)
        self._max_run_directories = max_run_directories
        self._positions: dict[Path, tuple[int, int, int]] = {}
        self._candidate_positions: dict[Path, tuple[int, int, int]] = {}
        self._candidate_buffers: dict[Path, bytearray] = {}
        self._discarding_candidate_line: set[Path] = set()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._thread_error: BaseException | None = None

    def _path_anchor(
        self,
        path: Path,
    ) -> tuple[Path, Path | None] | None:
        if path == self._work_dir or self._work_dir in path.parents:
            private_root = (
                self._proof_final_root
                if (
                    path == self._proof_final_root
                    or self._proof_final_root in path.parents
                )
                else None
            )
            return self._work_dir, private_root
        if self._proof and (
            path == self._proof_live_root
            or self._proof_live_root in path.parents
        ):
            return self._work_parent, self._proof_live_root
        return None

    @staticmethod
    def _directory_metadata_allowed(
        metadata: os.stat_result,
        *,
        private: bool,
    ) -> bool:
        mode = stat.S_IMODE(metadata.st_mode)
        return (
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and not mode & 0o022
            and (not private or not mode & 0o077)
        )

    def _open_directory(self, path: Path) -> int | None:
        """Open one directory from a fixed owner/mode-checked anchor."""

        anchored = self._path_anchor(path)
        if anchored is None:
            return None
        anchor, private_root = anchored
        try:
            relative = path.relative_to(anchor)
        except ValueError:
            return None
        if any(part in {"", ".", ".."} for part in relative.parts):
            return None
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(anchor, flags)
            opened = os.fstat(descriptor)
            if not self._directory_metadata_allowed(
                opened,
                private=(
                    private_root is not None
                    and (
                        anchor == private_root
                        or private_root in anchor.parents
                    )
                ),
            ):
                closing = descriptor
                descriptor = None
                os.close(closing)
                return None
            current = anchor
            for component in relative.parts:
                next_descriptor = os.open(
                    component,
                    flags,
                    dir_fd=descriptor,
                )
                # Publish the new owner before retiring the old directory fd.
                # If close consumes the old fd and then raises, cleanup below
                # closes only this distinct child fd and never a same-number
                # peer that may already have reused the old descriptor.
                closing = descriptor
                descriptor = next_descriptor
                os.close(closing)
                current = current / component
                opened = os.fstat(descriptor)
                if not self._directory_metadata_allowed(
                    opened,
                    private=(
                        private_root is not None
                        and (
                            current == private_root
                            or private_root in current.parents
                        )
                    ),
                ):
                    closing = descriptor
                    descriptor = None
                    os.close(closing)
                    return None
            return descriptor
        except BaseException as error:
            closing = descriptor
            descriptor = None
            cleanup_interruption: BaseException | None = None
            if closing is not None:
                try:
                    # Linux close errors do not say whether the fd was
                    # consumed. Retire ownership first and make one attempt.
                    os.close(closing)
                except BaseException as cleanup_error:
                    error.add_note(
                        "flag directory descriptor cleanup failed: "
                        f"{cleanup_error}"
                    )
                    if not isinstance(cleanup_error, Exception):
                        cleanup_interruption = cleanup_error
            if cleanup_interruption is not None:
                cleanup_interruption.add_note(
                    "flag directory cleanup interrupted while recovering "
                    f"from {type(error).__name__}"
                )
                raise cleanup_interruption
            if isinstance(error, OSError):
                return None
            raise

    def _regular_directory(self, path: Path) -> bool:
        descriptor = self._open_directory(path)
        if descriptor is None:
            return False
        os.close(descriptor)
        return True

    def _child_directories(
        self,
        root: Path,
        pattern: re.Pattern[str],
        *,
        entry_budget: int,
        result_limit: int,
    ) -> tuple[tuple[Path, ...], int]:
        """List bounded non-symlink children beneath one anchored root."""

        if entry_budget <= 0 or result_limit <= 0:
            return (), 0
        descriptor = self._open_directory(root)
        if descriptor is None:
            return (), 0
        scanned = 0
        names: list[str] = []
        try:
            with os.scandir(descriptor) as iterator:
                for entry in iterator:
                    if scanned >= entry_budget:
                        raise FlagTailerError(
                            "flag directory scan exceeded its bounded "
                            "entry limit"
                        )
                    scanned += 1
                    if (
                        pattern.fullmatch(entry.name) is not None
                        and entry.is_dir(follow_symlinks=False)
                    ):
                        names.append(entry.name)
        except OSError:
            return (), scanned
        finally:
            os.close(descriptor)
        selected = heapq.nlargest(
            result_limit,
            names,
            key=lambda name: os.fsencode(name),
        )
        return (
            tuple(root / name for name in reversed(selected)),
            scanned,
        )

    def _proof_run_directories(self) -> tuple[Path, ...]:
        """Find only fixed clean-proof live and final result directories."""

        entry_budget = self._max_run_directories
        result_budget = self._max_run_directories
        values: list[Path] = []

        live_attempts, scanned = self._child_directories(
            self._proof_live_root,
            _PROOF_LIVE_ATTEMPT_DIRECTORY,
            entry_budget=entry_budget,
            result_limit=result_budget,
        )
        entry_budget -= scanned
        for attempt in live_attempts:
            if entry_budget <= 0 or result_budget <= 0:
                break
            run_directories, scanned = self._child_directories(
                attempt / ".ctf" / "runs",
                _RUN_DIRECTORY,
                entry_budget=entry_budget,
                result_limit=result_budget,
            )
            entry_budget -= scanned
            values.extend(run_directories)
            result_budget -= len(run_directories)

        if entry_budget > 0 and result_budget > 0:
            final_attempts, _scanned = self._child_directories(
                self._proof_final_root,
                _PROOF_FINAL_ATTEMPT_DIRECTORY,
                entry_budget=entry_budget,
                result_limit=result_budget,
            )
            values.extend(final_attempts)
        return tuple(values)

    def _run_directories(self) -> tuple[Path, ...]:
        if self._proof:
            return self._proof_run_directories()
        entries, _scanned = self._child_directories(
            self._runs_root,
            _RUN_DIRECTORY,
            entry_budget=self._max_run_directories,
            result_limit=self._max_run_directories,
        )
        return entries

    def _logs(self) -> tuple[Path, ...]:
        return tuple(
            path
            for run_directory in self._run_directories()
            for path in (
                run_directory / "stdout.log",
                run_directory / "stderr.log",
            )
        )

    def _candidate_sidecars(self) -> tuple[Path, ...]:
        return tuple(
            run_directory / FLAG_CANDIDATE_SIDECAR
            for run_directory in self._run_directories()
        )

    def _open_regular(
        self, path: Path
    ) -> tuple[int, os.stat_result] | None:
        anchored = self._path_anchor(path)
        if anchored is None:
            return None
        anchor, private_root = anchored
        try:
            relative = path.relative_to(anchor)
        except ValueError:
            return None
        if (
            not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            return None
        parent = anchor.joinpath(*relative.parts[:-1])
        directory_descriptor = self._open_directory(parent)
        if directory_descriptor is None:
            return None
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        opened: os.stat_result | None = None
        operation_error: BaseException | None = None
        try:
            descriptor = os.open(
                relative.parts[-1],
                flags,
                dir_fd=directory_descriptor,
            )
            opened = os.fstat(descriptor)
        except BaseException as error:
            operation_error = error

        cleanup_errors: list[tuple[str, BaseException]] = []
        closing_directory = directory_descriptor
        directory_descriptor = None
        try:
            os.close(closing_directory)
        except BaseException as error:
            cleanup_errors.append(("directory descriptor", error))

        if operation_error is not None or cleanup_errors:
            closing_descriptor = descriptor
            descriptor = None
            if closing_descriptor is not None:
                try:
                    os.close(closing_descriptor)
                except BaseException as error:
                    cleanup_errors.append(("file descriptor", error))
            if cleanup_errors:
                _raise_descriptor_cleanup_errors(
                    operation_error,
                    cleanup_errors,
                )
            assert operation_error is not None
            if isinstance(operation_error, OSError):
                return None
            raise operation_error

        assert descriptor is not None
        assert opened is not None
        if not stat.S_ISREG(opened.st_mode):
            closing_descriptor = descriptor
            descriptor = None
            try:
                os.close(closing_descriptor)
            except BaseException as error:
                _raise_descriptor_cleanup_errors(
                    None,
                    [("file descriptor", error)],
                )
            return None
        if (
            opened.st_uid != os.geteuid()
            or (
                private_root is not None
                and stat.S_IMODE(opened.st_mode) & 0o077
            )
        ):
            closing_descriptor = descriptor
            descriptor = None
            try:
                os.close(closing_descriptor)
            except BaseException as error:
                _raise_descriptor_cleanup_errors(
                    None,
                    [("file descriptor", error)],
                )
            return None
        transferred_descriptor = descriptor
        descriptor = None
        return transferred_descriptor, opened

    def _baseline(self) -> None:
        for path in self._logs():
            opened = self._open_regular(path)
            if opened is None:
                continue
            descriptor, metadata = opened
            os.close(descriptor)
            self._positions[path] = (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
            )
        for path in self._candidate_sidecars():
            opened = self._open_regular(path)
            if opened is None:
                continue
            descriptor, metadata = opened
            os.close(descriptor)
            self._candidate_positions[path] = (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
            )

    def _poll_logs_once(self) -> None:
        if self._remaining <= 0:
            return
        for path in self._logs():
            if self._remaining <= 0:
                break
            opened = self._open_regular(path)
            if opened is None:
                continue
            descriptor, metadata = opened
            try:
                previous = self._positions.get(path)
                offset = (
                    previous[2]
                    if previous is not None
                    and previous[:2] == (metadata.st_dev, metadata.st_ino)
                    and previous[2] <= metadata.st_size
                    else 0
                )
                os.lseek(descriptor, offset, os.SEEK_SET)
                limit = min(metadata.st_size - offset, self._remaining)
                while limit > 0:
                    chunk = os.read(descriptor, min(64 * 1024, limit))
                    if not chunk:
                        break
                    offset += len(chunk)
                    limit -= len(chunk)
                    self._remaining -= len(chunk)
                    self._detector.feed(
                        chunk.decode("utf-8", errors="replace"),
                        source=(
                            f"{self._source_prefix}:"
                            f"{path.parent.name}:{path.stem}-live"
                        ),
                    )
                self._positions[path] = (
                    metadata.st_dev,
                    metadata.st_ino,
                    offset,
                )
            except OSError:
                continue
            finally:
                os.close(descriptor)

    def _consume_candidate_bytes(self, path: Path, data: bytes) -> None:
        if path in self._discarding_candidate_line:
            separator = data.find(b"\n")
            if separator < 0:
                return
            self._discarding_candidate_line.discard(path)
            data = data[separator + 1 :]

        buffer = self._candidate_buffers.setdefault(path, bytearray())
        buffer.extend(data)
        while True:
            separator = buffer.find(b"\n")
            if separator < 0:
                break
            line = bytes(buffer[:separator])
            del buffer[: separator + 1]
            if len(line) > self._candidate_line_max_bytes:
                continue
            try:
                payload = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            schema_version = payload.get("schema_version")
            stream = payload.get("stream")
            if (
                isinstance(schema_version, bool)
                or schema_version != 1
                or payload.get("kind") != "flag_candidate"
                or not isinstance(stream, str)
                or stream not in {"stdout", "stderr"}
            ):
                continue
            value = payload.get("value")
            if not isinstance(value, str) or not value:
                continue
            try:
                value_bytes = len(value.encode("utf-8"))
            except UnicodeEncodeError:
                continue
            if (
                len(value) > DEFAULT_SIDECAR_CANDIDATE_MAX_CHARS
                or value_bytes > DEFAULT_SIDECAR_CANDIDATE_MAX_BYTES
            ):
                continue
            self._detector.report_candidate(
                value,
                source=(
                    f"{self._source_prefix}:{path.parent.name}:"
                    f"{stream}-stream"
                ),
            )
        if len(buffer) > self._candidate_line_max_bytes:
            buffer.clear()
            self._discarding_candidate_line.add(path)

    def _poll_candidate_sidecars_once(self) -> None:
        if self._candidate_remaining <= 0:
            return
        for path in self._candidate_sidecars():
            if self._candidate_remaining <= 0:
                break
            opened = self._open_regular(path)
            if opened is None:
                continue
            descriptor, metadata = opened
            try:
                previous = self._candidate_positions.get(path)
                same_file = (
                    previous is not None
                    and previous[:2] == (metadata.st_dev, metadata.st_ino)
                    and previous[2] <= metadata.st_size
                )
                offset = previous[2] if same_file else 0
                if not same_file:
                    self._candidate_buffers.pop(path, None)
                    self._discarding_candidate_line.discard(path)
                os.lseek(descriptor, offset, os.SEEK_SET)
                limit = min(
                    metadata.st_size - offset,
                    self._candidate_remaining,
                )
                while limit > 0:
                    chunk = os.read(descriptor, min(64 * 1024, limit))
                    if not chunk:
                        break
                    offset += len(chunk)
                    limit -= len(chunk)
                    self._candidate_remaining -= len(chunk)
                    self._consume_candidate_bytes(path, chunk)
                self._candidate_positions[path] = (
                    metadata.st_dev,
                    metadata.st_ino,
                    offset,
                )
            except OSError:
                continue
            finally:
                os.close(descriptor)

    def _poll_once(self) -> None:
        self._poll_candidate_sidecars_once()
        self._poll_logs_once()

    def _run(self) -> None:
        try:
            while not self._stop.wait(self._poll_interval):
                self._poll_once()
        except BaseException as error:
            self._thread_error = error
            self._stop.set()

    def _publish_stop(self) -> BaseException | None:
        """Publish cancellation before returning any cleanup interruption."""

        first_error: BaseException | None = None
        while True:
            try:
                if self._stop.is_set():
                    return first_error
                self._stop.set()
            except BaseException as error:
                if first_error is None:
                    first_error = error
                else:
                    first_error.add_note(
                        "flag log tailer stop publication retry failed: "
                        f"{error}"
                    )

    def start(self) -> FlagLogTailer:
        if self._thread is not None:
            raise RuntimeError("flag log tailer is already started")
        self._stop.clear()
        self._thread_error = None
        self._baseline()
        self._thread = threading.Thread(
            target=self._run,
            name="ctfos-flag-log-tailer",
            daemon=True,
        )
        try:
            self._thread.start()
            return self
        except BaseException as start_error:
            # ``Thread.start()`` can be interrupted after the native thread
            # was created but before its bootstrap publishes ``ident``.  An
            # unset ident therefore does not prove that no watcher exists.
            # Publish cancellation first and retain the Thread owner until a
            # later bounded join proves that bootstrap/exit completed.
            publication_error = self._publish_stop()
            if publication_error is not None:
                start_error.add_note(
                    "flag log tailer stop publication was interrupted: "
                    f"{publication_error}"
                )
            try:
                self.stop(drain=True)
            except BaseException as cleanup_error:
                start_error.add_note(
                    "flag log tailer startup cleanup failed: "
                    f"{cleanup_error}"
                )
            raise

    def stop(self, *, drain: bool = False) -> None:
        thread = self._thread
        if thread is None:
            return
        join_error = self._publish_stop()
        join_completed = False
        drain_ident: int | None = None
        if drain:
            while True:
                try:
                    drain_ident = thread.ident
                except BaseException as error:
                    if join_error is None:
                        join_error = error
                    else:
                        join_error.add_note(
                            "flag log tailer ident check retry failed: "
                            f"{error}"
                        )
                    continue
                break
        if drain and drain_ident is not None:
            # A context-managed tailer is scoped by the caller's challenge
            # session lock.  Do not let that lock unwind while a callback that
            # crossed into the watcher is still touching state.  Cleanup
            # control interruptions are retained and re-raised only after the
            # owned callback is proved dead.
            while True:
                try:
                    if not thread.is_alive():
                        break
                    thread.join()
                except BaseException as error:
                    if join_error is None:
                        join_error = error
                    else:
                        join_error.add_note(
                            "flag log tailer drain join retry failed: "
                            f"{error}"
                        )
                    continue
            join_completed = True
        for attempt in range(2):
            if join_completed:
                break
            try:
                thread.join(
                    timeout=max(1.0, self._poll_interval * 4)
                )
            except BaseException as error:
                if join_error is None:
                    join_error = error
                else:
                    join_error.add_note(
                        "flag log tailer join retry failed: "
                        f"{error}"
                    )
                if attempt == 0:
                    continue
            else:
                join_completed = True
                break
        if (
            not join_completed
            and thread.ident is None
            and not thread.is_alive()
        ):
            # The native start may merely be delayed.  Clearing this owner
            # would allow a later start() to clear ``_stop`` and revive the
            # unregistered watcher.  Keep the tailer poisoned but safe; a
            # later stop() can finish the join once bootstrap is observable.
            failure = FlagTailerError(
                "flag log tailer startup state is still pending"
            )
            if join_error is not None:
                failure.add_note(
                    "flag log tailer join failed before bootstrap: "
                    f"{join_error}"
            )
            raise failure from join_error
        thread_alive = (
            False
            if drain and join_completed
            else thread.is_alive()
        )
        if thread_alive:
            if join_error is not None and not isinstance(
                join_error, Exception
            ):
                join_error.add_note(
                    "flag log tailer did not stop within its bounded join"
                )
                raise join_error
            raise FlagTailerError(
                "flag log tailer did not stop within its bounded join"
            ) from join_error

        thread_error = self._thread_error
        # The blocking sandbox call has returned, so one final bounded drain
        # observes bytes written between the last poll and process exit.
        drain_error: BaseException | None = None
        try:
            self._poll_once()
        except BaseException as error:
            drain_error = error
        finally:
            self._thread = None

        if (
            join_error is not None
            and not isinstance(join_error, Exception)
        ):
            if join_completed:
                join_error.add_note(
                    "flag log tailer cleanup completed after join retry"
                )
            if thread_error is not None:
                join_error.add_note(
                    "flag log tailer polling also failed: "
                    f"{thread_error}"
                )
            if drain_error is not None:
                join_error.add_note(
                    "flag log tailer final drain also failed: "
                    f"{drain_error}"
                )
            raise join_error
        if join_error is not None and not join_completed:
            failure = FlagTailerError(
                "flag log tailer join failed"
            )
            if thread_error is not None:
                failure.add_note(
                    "flag log tailer polling also failed: "
                    f"{thread_error}"
                )
            if drain_error is not None:
                failure.add_note(
                    "flag log tailer final drain also failed: "
                    f"{drain_error}"
                )
            raise failure from join_error
        if thread_error is not None:
            if drain_error is not None:
                thread_error.add_note(
                    "flag log tailer final drain also failed: "
                    f"{drain_error}"
                )
            if isinstance(thread_error, FlagNotificationError):
                raise thread_error
            raise FlagTailerError(
                "flag log tailer polling failed"
            ) from thread_error
        if drain_error is not None:
            if isinstance(drain_error, FlagNotificationError):
                raise drain_error
            raise FlagTailerError(
                "flag log tailer final drain failed"
            ) from drain_error

    def __enter__(self) -> FlagLogTailer:
        if self._thread is not None:
            raise RuntimeError("flag log tailer is already started")
        # Resource acquisition happens explicitly inside the with body. The
        # caller's __exit__ guard therefore exists before Thread.start(), and
        # this outer return handoff owns no watcher that could be orphaned.
        return self

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        exception: BaseException | None,
        _traceback: object,
    ) -> None:
        try:
            self.stop(drain=True)
        except BaseException as cleanup_error:
            if isinstance(exception, BaseException):
                exception.add_note(
                    "flag log tailer cleanup failed: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
                return
            raise
