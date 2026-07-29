"""Symlink-safe atomic artifact publication for one template category."""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path


def open_output_dir(path: Path) -> int:
    parent_stat = path.parent.lstat()
    if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
        raise OSError(f"unsafe output parent: {path.parent}")
    try:
        path.mkdir(mode=0o755)
    except FileExistsError:
        pass
    path_stat = path.lstat()
    if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISDIR(path_stat.st_mode):
        raise OSError(f"unsafe output directory: {path}")
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise OSError(f"unsafe output directory: {path}")
    return descriptor


def remove_regular_output(descriptor: int, name: str) -> None:
    """Remove one stale regular output without following special files."""

    if not name or "/" in name or name in {".", ".."}:
        raise ValueError("artifact name must be one path component")
    try:
        destination_stat = os.stat(
            name,
            dir_fd=descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    if not stat.S_ISREG(destination_stat.st_mode):
        raise OSError(f"refusing non-regular output artifact: {name}")
    try:
        os.unlink(name, dir_fd=descriptor)
    except FileNotFoundError:
        return
    os.fsync(descriptor)


def atomic_write(descriptor: int, name: str, data: bytes) -> None:
    if not name or "/" in name or name in {".", ".."}:
        raise ValueError("artifact name must be one path component")
    try:
        destination_stat = os.stat(
            name,
            dir_fd=descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISREG(destination_stat.st_mode):
            raise OSError(f"refusing non-regular output artifact: {name}")
    temporary = f".{name}.tmp-{os.getpid()}-{secrets.token_hex(6)}"
    output = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o644,
        dir_fd=descriptor,
    )
    try:
        view = memoryview(data)
        while view:
            written = os.write(output, view)
            view = view[written:]
        os.fsync(output)
    except BaseException:
        os.close(output)
        os.unlink(temporary, dir_fd=descriptor)
        raise
    else:
        os.close(output)
    try:
        os.replace(temporary, name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
    except BaseException:
        os.unlink(temporary, dir_fd=descriptor)
        raise
    os.fsync(descriptor)
