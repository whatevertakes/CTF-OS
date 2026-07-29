"""Immutable, bounded history for exact model context packs."""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path


MAX_ARCHIVED_CONTEXT_BYTES = 256 * 1024


class ContextArchiveError(RuntimeError):
    """An exact context pack could not be installed or verified."""


class ContextArchiveConflict(ContextArchiveError):
    """A run id already names different archived context bytes."""


@dataclass(frozen=True, slots=True)
class ArchivedContext:
    path: Path
    sha256: str
    size_bytes: int


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("context archive write made no progress")
        remaining = remaining[written:]


def _read_existing(
    directory_descriptor: int,
    name: str,
    *,
    expected_size: int,
) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ContextArchiveConflict(
                f"context archive destination is not a regular file: {name}"
            )
        if metadata.st_size != expected_size:
            raise ContextArchiveConflict(
                f"context archive already exists with different bytes: {name}"
            )
        chunks: list[bytes] = []
        remaining = expected_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise ContextArchiveConflict(
                    f"context archive became truncated while reading: {name}"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ContextArchiveConflict(
                f"context archive grew while reading: {name}"
            )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def archive_context_pack(
    history_directory: Path,
    *,
    run_id: str,
    text: str,
    expected_sha256: str,
) -> ArchivedContext:
    """Install one exact context pack without replacing an existing history.

    A byte-identical existing file is accepted to make crash recovery
    idempotent. Any conflicting file, symlink, or non-regular destination is
    rejected without modifying it.
    """

    if (
        not run_id
        or run_id in {".", ".."}
        or Path(run_id).name != run_id
        or "/" in run_id
        or "\x00" in run_id
    ):
        raise ContextArchiveError("invalid context archive run id")
    payload = text.encode("utf-8")
    if len(payload) > MAX_ARCHIVED_CONTEXT_BYTES:
        raise ContextArchiveError(
            "bounded context pack exceeds archive byte limit"
        )
    actual_sha256 = hashlib.sha256(payload).hexdigest()
    if actual_sha256 != expected_sha256.lower():
        raise ContextArchiveError("context pack digest does not match its bytes")

    history_directory = Path(history_directory)
    history_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory_flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    directory_descriptor = os.open(history_directory, directory_flags)
    destination_name = f"{run_id}.jsonl"
    temporary_name = f".{destination_name}.{secrets.token_hex(16)}.tmp"
    temporary_created = False
    try:
        create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            create_flags |= os.O_NOFOLLOW
        temporary_descriptor = os.open(
            temporary_name,
            create_flags,
            0o600,
            dir_fd=directory_descriptor,
        )
        temporary_created = True
        try:
            _write_all(temporary_descriptor, payload)
            os.fsync(temporary_descriptor)
        finally:
            os.close(temporary_descriptor)

        try:
            os.link(
                temporary_name,
                destination_name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            os.fsync(directory_descriptor)
        except FileExistsError as error:
            try:
                existing = _read_existing(
                    directory_descriptor,
                    destination_name,
                    expected_size=len(payload),
                )
            except OSError as read_error:
                raise ContextArchiveConflict(
                    "context archive destination cannot be safely read: "
                    f"{destination_name}"
                ) from read_error
            if existing != payload:
                raise ContextArchiveConflict(
                    "context archive already exists with different bytes: "
                    f"{destination_name}"
                ) from error
    finally:
        if temporary_created:
            try:
                os.unlink(temporary_name, dir_fd=directory_descriptor)
                os.fsync(directory_descriptor)
            except FileNotFoundError:
                pass
        os.close(directory_descriptor)

    return ArchivedContext(
        path=history_directory / destination_name,
        sha256=actual_sha256,
        size_bytes=len(payload),
    )


__all__ = [
    "ArchivedContext",
    "ContextArchiveConflict",
    "ContextArchiveError",
    "MAX_ARCHIVED_CONTEXT_BYTES",
    "archive_context_pack",
]
