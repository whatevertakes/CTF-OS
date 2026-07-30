"""Deterministic, fail-closed inventory of the executing CTF-OS source.

Promotion evidence is meaningful only when both arms execute the source tree
that was frozen before evaluation.  This module inventories only Git-tracked
runtime source, rejects staged or unstaged changes, and reads every file twice
through descriptor-anchored paths.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ctf_os.store.atomic import canonical_json_bytes


RUNTIME_SOURCE_INVENTORY_SCHEMA_VERSION = 1
RUNTIME_SOURCE_INVENTORY_PROTOCOL = "ctfos.runtime_source.v1"
MAX_RUNTIME_SOURCE_FILES = 2048
MAX_RUNTIME_SOURCE_FILE_BYTES = 16 * 1024 * 1024
MAX_RUNTIME_SOURCE_TOTAL_BYTES = 64 * 1024 * 1024
MAX_GIT_QUERY_BYTES = 4 * 1024 * 1024
_RUNTIME_SOURCE_ROOT = Path(__file__).resolve().parent.parent
_RUNTIME_SOURCE_PATHSPECS = (
    ":(glob)ctf_os/**/*.py",
    "pyproject.toml",
    "ctfos",
    "ctf-container",
)
_REQUIRED_RUNTIME_SOURCE_FILES = frozenset(
    {
        "ctf_os/__main__.py",
        "ctf_os/benchmark.py",
        "ctf_os/cli.py",
        "ctf_os/container_tools.py",
        "ctf_os/promotion_bundles.py",
        "ctf_os/runtime_source.py",
        "pyproject.toml",
    }
)
_GIT_MODE_RE = re.compile(r"100(?:644|755)")
_GIT_OBJECT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_INVENTORY_DOMAIN = b"ctfos-runtime-source-inventory-v1\0"


class RuntimeSourceError(ValueError):
    """The tracked runtime source cannot be inventoried safely."""


@dataclass(frozen=True, slots=True)
class RuntimeSourceFile:
    path: str
    git_mode: str
    size_bytes: int
    sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "git_mode": self.git_mode,
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True, slots=True)
class RuntimeSourceInventory:
    files: tuple[RuntimeSourceFile, ...]
    total_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": RUNTIME_SOURCE_INVENTORY_SCHEMA_VERSION,
            "protocol": RUNTIME_SOURCE_INVENTORY_PROTOCOL,
            "allowlist": list(_RUNTIME_SOURCE_PATHSPECS),
            "required_files": sorted(_REQUIRED_RUNTIME_SOURCE_FILES),
            "file_count": len(self.files),
            "total_bytes": self.total_bytes,
            "files": [item.to_dict() for item in self.files],
        }

    @property
    def sha256(self) -> str:
        return hashlib.sha256(
            _INVENTORY_DOMAIN + canonical_json_bytes(self.to_dict())
        ).hexdigest()


def _git_query(root: Path, *arguments: str, label: str) -> bytes:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "LC_ALL": "C",
        }
    )
    try:
        completed = subprocess.run(
            (
                "git",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.quotepath=false",
                "-C",
                str(root),
                *arguments,
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeSourceError(f"{label} failed") from error
    if (
        completed.returncode != 0
        or len(completed.stdout) > MAX_GIT_QUERY_BYTES
        or len(completed.stderr) > MAX_GIT_QUERY_BYTES
    ):
        raise RuntimeSourceError(f"{label} failed")
    return completed.stdout


def _normalized_path(value: bytes) -> str:
    try:
        text = value.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise RuntimeSourceError(
            "tracked runtime source path is not UTF-8"
        ) from error
    relative = PurePosixPath(text)
    if (
        not text
        or "\\" in text
        or relative.is_absolute()
        or relative.as_posix() != text
        or any(part in {"", ".", ".."} for part in relative.parts)
        or any(
            ord(character) < 0x20 or ord(character) == 0x7F
            for character in text
        )
    ):
        raise RuntimeSourceError(
            "tracked runtime source path is not canonical"
        )
    if not (
        text == "pyproject.toml"
        or text in {"ctfos", "ctf-container"}
        or (
            len(relative.parts) >= 2
            and relative.parts[0] == "ctf_os"
            and relative.suffix == ".py"
        )
    ):
        raise RuntimeSourceError(
            "Git returned a path outside the runtime source allowlist"
        )
    return text


def _tracked_entries(root: Path) -> tuple[tuple[str, str, str], ...]:
    payload = _git_query(
        root,
        "ls-files",
        "--stage",
        "-z",
        "--",
        *_RUNTIME_SOURCE_PATHSPECS,
        label="tracked runtime source query",
    )
    entries: dict[str, tuple[str, str]] = {}
    for raw_entry in payload.split(b"\0"):
        if not raw_entry:
            continue
        metadata, separator, raw_path = raw_entry.partition(b"\t")
        fields = metadata.split(b" ")
        if separator != b"\t" or len(fields) != 3:
            raise RuntimeSourceError(
                "tracked runtime source index entry is malformed"
            )
        try:
            mode = fields[0].decode("ascii")
            object_id = fields[1].decode("ascii")
            stage = fields[2].decode("ascii")
        except UnicodeError as error:
            raise RuntimeSourceError(
                "tracked runtime source index entry is malformed"
            ) from error
        path = _normalized_path(raw_path)
        if (
            _GIT_MODE_RE.fullmatch(mode) is None
            or _GIT_OBJECT_RE.fullmatch(object_id) is None
            or stage != "0"
            or path in entries
        ):
            raise RuntimeSourceError(
                "tracked runtime source index is not canonical"
            )
        entries[path] = (mode, object_id)
    if (
        not _REQUIRED_RUNTIME_SOURCE_FILES.issubset(entries)
        or not 1 <= len(entries) <= MAX_RUNTIME_SOURCE_FILES
    ):
        raise RuntimeSourceError(
            "tracked runtime source inventory is incomplete or oversized"
        )
    return tuple(
        (path, mode, object_id)
        for path, (mode, object_id) in sorted(entries.items())
    )


def _require_clean_tracked_source(root: Path) -> None:
    status = _git_query(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=no",
        "--",
        *_RUNTIME_SOURCE_PATHSPECS,
        label="tracked runtime source status",
    )
    if status:
        raise RuntimeSourceError(
            "tracked runtime source has staged or unstaged changes"
        )


def _open_root(root: Path) -> int:
    if not root.is_absolute():
        raise RuntimeSourceError(
            "runtime source root must be an absolute path"
        )
    try:
        metadata = root.lstat()
    except OSError as error:
        raise RuntimeSourceError(
            "runtime source root is unavailable"
        ) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeSourceError(
            "runtime source root must be a real directory"
        )
    flags = os.O_RDONLY | os.O_CLOEXEC
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(root, flags)
    except OSError as error:
        raise RuntimeSourceError(
            "runtime source root cannot be opened safely"
        ) from error


def _open_relative_regular(root_descriptor: int, path: str) -> int:
    parts = PurePosixPath(path).parts
    parent = os.dup(root_descriptor)
    try:
        directory_flags = os.O_RDONLY | os.O_CLOEXEC
        directory_flags |= getattr(os, "O_DIRECTORY", 0)
        directory_flags |= getattr(os, "O_NOFOLLOW", 0)
        for part in parts[:-1]:
            next_descriptor = os.open(
                part,
                directory_flags,
                dir_fd=parent,
            )
            os.close(parent)
            parent = next_descriptor
        file_flags = os.O_RDONLY | os.O_CLOEXEC
        file_flags |= getattr(os, "O_NOFOLLOW", 0)
        file_flags |= getattr(os, "O_NONBLOCK", 0)
        return os.open(parts[-1], file_flags, dir_fd=parent)
    except OSError as error:
        raise RuntimeSourceError(
            f"runtime source cannot be opened safely: {path}"
        ) from error
    finally:
        os.close(parent)


def _read_source_file(
    root_descriptor: int,
    path: str,
    git_mode: str,
) -> bytes:
    descriptor = _open_relative_regular(root_descriptor, path)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink < 1
            or before.st_size > MAX_RUNTIME_SOURCE_FILE_BYTES
        ):
            raise RuntimeSourceError(
                f"runtime source is not a bounded regular file: {path}"
            )
        expected_executable = git_mode == "100755"
        observed_executable = bool(stat.S_IMODE(before.st_mode) & 0o111)
        if observed_executable != expected_executable:
            raise RuntimeSourceError(
                "runtime source executable mode does not match Git: "
                f"{path}"
            )
        payload = bytearray()
        while len(payload) <= MAX_RUNTIME_SOURCE_FILE_BYTES:
            chunk = os.read(
                descriptor,
                min(
                    1024 * 1024,
                    MAX_RUNTIME_SOURCE_FILE_BYTES + 1 - len(payload),
                ),
            )
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            stat.S_IMODE(before.st_mode),
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            stat.S_IMODE(after.st_mode),
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            identity_before != identity_after
            or len(payload) != after.st_size
            or len(payload) > MAX_RUNTIME_SOURCE_FILE_BYTES
        ):
            raise RuntimeSourceError(
                f"runtime source changed while it was read: {path}"
            )
        return bytes(payload)
    except OSError as error:
        raise RuntimeSourceError(
            f"runtime source cannot be read safely: {path}"
        ) from error
    finally:
        os.close(descriptor)


def _scan(
    root: Path,
    entries: tuple[tuple[str, str, str], ...],
) -> RuntimeSourceInventory:
    root_descriptor = _open_root(root)
    try:
        files: list[RuntimeSourceFile] = []
        total_bytes = 0
        for path, mode, object_id in entries:
            payload = _read_source_file(root_descriptor, path, mode)
            object_algorithm = (
                "sha1" if len(object_id) == 40 else "sha256"
            )
            blob_header = f"blob {len(payload)}\0".encode("ascii")
            if hashlib.new(
                object_algorithm,
                blob_header + payload,
            ).hexdigest() != object_id:
                raise RuntimeSourceError(
                    "runtime source does not match its tracked Git blob: "
                    f"{path}"
                )
            total_bytes += len(payload)
            if total_bytes > MAX_RUNTIME_SOURCE_TOTAL_BYTES:
                raise RuntimeSourceError(
                    "runtime source exceeds the total byte limit"
                )
            files.append(
                RuntimeSourceFile(
                    path=path,
                    git_mode=mode,
                    size_bytes=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                )
            )
        return RuntimeSourceInventory(
            files=tuple(files),
            total_bytes=total_bytes,
        )
    finally:
        os.close(root_descriptor)


def runtime_source_inventory(
    source_root: Path | str | None = None,
) -> RuntimeSourceInventory:
    """Return one stable inventory or reject dirty/ambiguous source."""

    root = (
        _RUNTIME_SOURCE_ROOT
        if source_root is None
        else Path(source_root)
    )
    expected_root = _git_query(
        root,
        "rev-parse",
        "--show-toplevel",
        label="runtime source repository query",
    )
    try:
        git_root = Path(
            expected_root.decode("utf-8", errors="strict").strip()
        )
    except UnicodeError as error:
        raise RuntimeSourceError(
            "runtime source repository root is invalid"
        ) from error
    if not git_root.is_absolute() or git_root.resolve() != root.resolve():
        raise RuntimeSourceError(
            "runtime source root must be the Git worktree root"
        )

    first_entries = _tracked_entries(root)
    _require_clean_tracked_source(root)
    first = _scan(root, first_entries)
    _require_clean_tracked_source(root)
    second_entries = _tracked_entries(root)
    if second_entries != first_entries:
        raise RuntimeSourceError(
            "tracked runtime source index changed during inventory"
        )
    second = _scan(root, second_entries)
    _require_clean_tracked_source(root)
    final_entries = _tracked_entries(root)
    if final_entries != first_entries or second != first:
        raise RuntimeSourceError(
            "runtime source changed during inventory"
        )
    _require_clean_tracked_source(root)
    return first


__all__ = [
    "MAX_RUNTIME_SOURCE_FILES",
    "MAX_RUNTIME_SOURCE_FILE_BYTES",
    "MAX_RUNTIME_SOURCE_TOTAL_BYTES",
    "RUNTIME_SOURCE_INVENTORY_PROTOCOL",
    "RUNTIME_SOURCE_INVENTORY_SCHEMA_VERSION",
    "RuntimeSourceError",
    "RuntimeSourceFile",
    "RuntimeSourceInventory",
    "runtime_source_inventory",
]
