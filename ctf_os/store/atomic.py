"""Durable same-directory atomic file operations."""

from __future__ import annotations

import builtins
import json
import os
import secrets
from pathlib import Path
from typing import Any, BinaryIO


_TEMPORARY_NAME_ATTEMPTS = 16


def _retry_close(stream: BinaryIO) -> BaseException | None:
    """Close one exact stream, tolerating one transient ordinary failure."""

    first_error: BaseException | None = None
    for attempt in range(2):
        try:
            stream.close()
        except BaseException as error:
            if first_error is None:
                first_error = error
            else:
                first_error.add_note(f"temporary stream close retry failed: {error}")
            if attempt == 0:
                continue
        else:
            if first_error is not None and not isinstance(
                first_error, Exception
            ):
                return first_error
            return None
    return first_error


def _retry_unlink(path: Path) -> BaseException | None:
    """Remove one exact temporary path, tolerating one transient failure."""

    first_error: BaseException | None = None
    for attempt in range(2):
        try:
            path.unlink(missing_ok=True)
        except BaseException as error:
            if first_error is None:
                first_error = error
            else:
                first_error.add_note(f"temporary unlink retry failed: {error}")
            if attempt == 0:
                continue
        else:
            if first_error is not None and not isinstance(
                first_error, Exception
            ):
                return first_error
            return None
    return first_error


def _open_exclusive_with_handoff(
    path: Path,
    *,
    pending_handoff: list[BinaryIO],
) -> BinaryIO:
    """Create an owning stream and retain it across the caller STORE boundary."""

    # Avoid placing a pre-existing regular file or symlink inside the cleanup
    # region. ``x`` remains the authoritative race-free collision check.
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    else:
        raise FileExistsError(path)

    def private_opener(raw_path: str, flags: int) -> int:
        return os.open(
            raw_path,
            flags
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )

    try:
        stream = builtins.open(
            path,
            "x+b",
            opener=private_opener,
        )
    except FileExistsError:
        raise
    except Exception:
        # A failed ordinary open never transferred ownership to this call.
        raise
    except BaseException as error:
        cleanup_error = _retry_unlink(path)
        if cleanup_error is not None:
            error.add_note(f"temporary allocation cleanup failed: {cleanup_error}")
        raise
    try:
        pending_handoff.append(stream)
        return stream
    except BaseException as error:
        close_error = _retry_close(stream)
        unlink_error = _retry_unlink(path)
        if close_error is not None:
            error.add_note(f"temporary stream cleanup failed: {close_error}")
        if unlink_error is not None:
            error.add_note(f"temporary path cleanup failed: {unlink_error}")
        raise


def _fsync_directory(path: Path) -> None:
    """Persist a directory entry update where the platform supports it."""

    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_bytes(
    path: Path,
    payload: bytes,
    *,
    mode: int = 0o600,
) -> None:
    """Write *payload* and atomically replace *path*.

    The temporary file is created beside the destination, flushed, fsynced, and
    then installed with ``os.replace``.  The parent directory is fsynced too so
    the rename survives a host crash rather than only a process crash.
    """

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    for _attempt in range(_TEMPORARY_NAME_ATTEMPTS):
        temporary_path = path.with_name(
            f".{path.name}.{secrets.token_hex(16)}.tmp"
        )
        pending_handoff: list[BinaryIO] = []
        stream: BinaryIO | None = None
        installed = False
        primary_error: BaseException | None = None
        try:
            try:
                stream = _open_exclusive_with_handoff(
                    temporary_path,
                    pending_handoff=pending_handoff,
                )
            except FileExistsError:
                continue
            pending_handoff.clear()
            os.fchmod(stream.fileno(), mode)
            remaining = memoryview(payload)
            while remaining:
                written = stream.write(remaining)
                if written is None or written <= 0:
                    raise OSError("atomic file write made no progress")
                remaining = remaining[written:]
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(temporary_path, path)
            installed = True
            _fsync_directory(path.parent)
            return
        except BaseException as error:
            primary_error = error
            raise
        finally:
            cleanup_stream = (
                stream
                if stream is not None
                else pending_handoff[0]
                if pending_handoff
                else None
            )
            owns_temporary_path = cleanup_stream is not None
            pending_handoff.clear()
            cleanup_errors: list[BaseException] = []
            if cleanup_stream is not None:
                close_error = _retry_close(cleanup_stream)
                if close_error is not None:
                    cleanup_errors.append(close_error)
            if not installed and owns_temporary_path:
                unlink_error = _retry_unlink(temporary_path)
                if unlink_error is not None:
                    cleanup_errors.append(unlink_error)
            if cleanup_errors:
                if primary_error is not None:
                    for cleanup_error in cleanup_errors:
                        primary_error.add_note(
                            f"atomic temporary cleanup failed: {cleanup_error}"
                        )
                else:
                    cleanup_error = cleanup_errors[0]
                    for additional_error in cleanup_errors[1:]:
                        cleanup_error.add_note(
                            f"additional temporary cleanup failure: "
                            f"{additional_error}"
                        )
                    raise cleanup_error
    raise FileExistsError(
        f"could not allocate a unique temporary file beside {path}"
    )


def atomic_write_text(
    path: Path,
    text: str,
    *,
    mode: int = 0o600,
) -> None:
    atomic_write_bytes(path, text.encode("utf-8"), mode=mode)


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def atomic_write_json(
    path: Path,
    value: Any,
    *,
    mode: int = 0o600,
) -> None:
    atomic_write_bytes(path, canonical_json_bytes(value), mode=mode)


def read_json(path: Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as stream:
        return json.load(stream)


def append_json_line(
    path: Path,
    value: Any,
    *,
    mode: int = 0o600,
) -> None:
    """Durably append one compact JSON object as a single logical record."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    descriptor = os.open(
        path,
        os.O_APPEND | os.O_CREAT | os.O_WRONLY,
        mode,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("JSON line append made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


__all__ = [
    "append_json_line",
    "atomic_write_bytes",
    "atomic_write_json",
    "atomic_write_text",
    "canonical_json_bytes",
    "read_json",
]
