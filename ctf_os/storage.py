"""Bounded challenge storage accounting and recoverable garbage collection.

Storage collection has three deliberately separate steps:

* inventory/plan only inspect files;
* ``quarantine_unreachable`` atomically detaches non-canonical files, but
  remains reversible;
* permanent deletion requires an independently persisted purge preparation
  plus the exact manifest digest and human confirmation returned by it.

The scanner and mutating paths never follow symlinks.  Mutations use
descriptor-relative operations so a manifest path cannot escape the challenge
tree.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from ctf_os.models import ChallengeIdentity, ChallengeState
from ctf_os.store import (
    MAX_CANONICAL_STATE_BYTES,
    ChallengeLock,
    LockTimeout,
    StateStore,
)
from ctf_os.store.atomic import (
    canonical_json_bytes,
    strict_json_loads,
)


DEFAULT_CHALLENGE_STORAGE_QUOTA_BYTES = 64 * 1024 * 1024 * 1024
DEFAULT_STORAGE_SCAN_MAX_BYTES = 256 * 1024 * 1024 * 1024
DEFAULT_STORAGE_SCAN_MAX_ENTRIES = 100_000
DEFAULT_STORAGE_TRANSIENT_SCAN_RETRIES = 2
MAX_QUARANTINE_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_PURGE_STATE_BYTES = 32 * 1024 * 1024
MAX_STORAGE_ISSUES = 64
GC_CONTROL_DIRECTORY = ".storage-gc"
MAX_GC_CONTROL_BYTES = 256 * 1024 * 1024
MAX_GC_CONTROL_ENTRIES = 2_048
_DERIVED_CONTEXT_PATH = "context/current.md"
MAX_DERIVED_CONTEXT_BYTES = MAX_CANONICAL_STATE_BYTES

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_QUARANTINE_ID = re.compile(r"^Q-[0-9a-f]{32}$")
_GC_MANIFEST_TEMP = re.compile(
    r"^\.manifest\.json\.[0-9a-f]{32}\.tmp$"
)
_ALLOWED_STORAGE_ROOTS = frozenset({"artifacts", "proof", "runs"})
_PRESERVED_STORAGE_ROOTS = frozenset(
    {"context", "exports", "knowledge", "runtime"}
)
_ACCOUNTED_STORAGE_ROOTS = (
    "runs",
    "artifacts",
    "proof",
    "runtime",
    "context",
    "knowledge",
    "exports",
)
_TRANSIENT_SCAN_ISSUE_CODES = frozenset(
    {
        "directory_changed_during_scan",
        "entry_changed_during_scan",
        "file_changed_during_scan",
    }
)
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | os.O_CLOEXEC
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_FLAGS = (
    os.O_RDONLY
    | os.O_CLOEXEC
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


class StorageError(RuntimeError):
    pass


class StorageQuotaError(StorageError):
    pass


class _PurgeAttestationError(StorageError):
    """A destructive unlink happened but byte reclamation was not proven."""


def _positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _nonnegative_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _reachable_paths(
    state: ChallengeState,
) -> tuple[set[str], tuple[str, ...]]:
    reachable = {item.path for item in state.artifacts if item.path}
    for run in state.runs:
        for path in (run.request_path, run.result_path, run.validation_path):
            if path:
                reachable.add(path)
    prefixes = [f"runs/{item.id}/" for item in state.runs]
    # The canonical operator workspace is never garbage, even when a file has
    # not been promoted as semantic evidence.
    prefixes.append("artifacts/workspace/")
    if state.closure is not None:
        package_path = state.closure.extra.get("package_path")
        if isinstance(package_path, str) and package_path:
            reachable.add(package_path.rstrip("/"))
            prefixes.append(package_path.rstrip("/") + "/")
    return reachable, tuple(prefixes)


def _safe_relative(value: object) -> Path:
    if not isinstance(value, str) or not value:
        raise StorageError("storage manifest path must be a non-empty string")
    if "\\" in value or "\x00" in value:
        raise StorageError("storage manifest contains an unsafe path")
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
        or pure.as_posix() != value
    ):
        raise StorageError("storage manifest contains an unsafe path")
    return Path(*pure.parts)


def _safe_storage_relative(value: object) -> Path:
    relative = _safe_relative(value)
    if relative.parts[0] not in _ALLOWED_STORAGE_ROOTS:
        raise StorageError("storage manifest path is outside storage roots")
    if relative.parts[:2] == ("artifacts", "quarantine"):
        raise StorageError("nested quarantine paths are forbidden")
    return relative


def _validate_quarantine_id(value: object) -> str:
    if not isinstance(value, str) or _QUARANTINE_ID.fullmatch(value) is None:
        raise StorageError("invalid quarantine id")
    return value


def _signature(metadata: os.stat_result) -> tuple[int, ...]:
    """Fields which must remain stable while one pathname is inspected."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("storage metadata write made no progress")
        view = view[written:]


def _atomic_write_json_at(
    directory_fd: int,
    name: str,
    value: object,
    *,
    maximum_bytes: int = MAX_PURGE_STATE_BYTES,
) -> None:
    """Atomically replace a private JSON file below an already-open directory."""

    if "/" in name or "\\" in name or name in {"", ".", ".."}:
        raise StorageError("unsafe storage metadata name")
    payload = canonical_json_bytes(value)
    if len(payload) > maximum_bytes:
        raise StorageError(
            f"storage metadata exceeds {maximum_bytes} bytes: {name}"
        )
    temporary = f".{name}.{uuid.uuid4().hex}.tmp"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        owned_descriptor = descriptor
        descriptor = None
        os.close(owned_descriptor)
        os.replace(
            temporary,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    except BaseException:
        if descriptor is not None:
            owned_descriptor = descriptor
            descriptor = None
            os.close(owned_descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise


def _read_regular_at(
    directory_fd: int,
    name: str,
    *,
    maximum_bytes: int,
    require_single_link: bool = True,
) -> tuple[bytes, os.stat_result]:
    """Read one bounded, stable regular file without following a symlink."""

    try:
        descriptor = os.open(name, _FILE_FLAGS, dir_fd=directory_fd)
    except OSError as error:
        raise StorageError(
            f"storage metadata is unsafe or missing: {name}"
        ) from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise StorageError(f"storage metadata is not regular: {name}")
        if require_single_link and before.st_nlink != 1:
            raise StorageError(f"storage metadata is hard-linked: {name}")
        if before.st_size > maximum_bytes:
            raise StorageError(
                f"storage metadata exceeds {maximum_bytes} bytes: {name}"
            )
        chunks: list[bytes] = []
        total = 0
        while total <= maximum_bytes:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, maximum_bytes + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > maximum_bytes:
            raise StorageError(
                f"storage metadata exceeds {maximum_bytes} bytes: {name}"
            )
        after = os.fstat(descriptor)
        pathname = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if _signature(before) != _signature(after) or (
            _signature(after) != _signature(pathname)
        ):
            raise StorageError(f"storage metadata changed while reading: {name}")
        return b"".join(chunks), after
    finally:
        os.close(descriptor)


def _read_json_at(
    directory_fd: int,
    name: str,
    *,
    maximum_bytes: int = MAX_QUARANTINE_MANIFEST_BYTES,
) -> tuple[Any, bytes]:
    payload, _metadata = _read_regular_at(
        directory_fd,
        name,
        maximum_bytes=maximum_bytes,
    )
    try:
        return strict_json_loads(payload, max_bytes=maximum_bytes), payload
    except (UnicodeError, ValueError) as error:
        raise StorageError(f"invalid storage JSON: {name}") from error


def _open_directory_at(
    directory_fd: int,
    name: str,
    *,
    create: bool = False,
) -> int:
    if name in {"", ".", ".."} or "/" in name or "\\" in name:
        raise StorageError("unsafe storage directory component")
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=directory_fd)
            os.fsync(directory_fd)
        except FileExistsError:
            pass
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=directory_fd)
    except OSError as error:
        raise StorageError(f"storage directory is unsafe or missing: {name}") from error
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise StorageError(f"storage path is not a directory: {name}")
    return descriptor


def _open_directory_path(
    base_fd: int,
    parts: Iterable[str],
    *,
    create: bool = False,
) -> int:
    current = os.dup(base_fd)
    try:
        for part in parts:
            following = _open_directory_at(current, part, create=create)
            os.close(current)
            current = following
        return current
    except BaseException:
        os.close(current)
        raise


def _open_challenge_root(paths: Any) -> int:
    try:
        descriptor = os.open(paths.root, _DIRECTORY_FLAGS)
    except OSError as error:
        raise StorageError("challenge storage root is unsafe or missing") from error
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise StorageError("challenge storage root is not a directory")
    return descriptor


def _open_quarantine_root(
    paths: Any,
    quarantine_id: str,
    *,
    create: bool = False,
) -> tuple[int, int]:
    challenge_fd = _open_challenge_root(paths)
    try:
        artifacts_fd = _open_directory_at(challenge_fd, "artifacts")
        try:
            quarantine_fd = _open_directory_at(
                artifacts_fd,
                "quarantine",
                create=create,
            )
        finally:
            os.close(artifacts_fd)
        try:
            if create:
                try:
                    os.mkdir(
                        quarantine_id,
                        0o700,
                        dir_fd=quarantine_fd,
                    )
                    os.fsync(quarantine_fd)
                except FileExistsError as error:
                    raise StorageError(
                        "quarantine destination already exists"
                    ) from error
            root_fd = _open_directory_at(
                quarantine_fd,
                quarantine_id,
            )
        finally:
            os.close(quarantine_fd)
        return challenge_fd, root_fd
    except BaseException:
        os.close(challenge_fd)
        raise


def _assert_private_directory_fd(descriptor: int, label: str) -> None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        raise StorageError(
            f"{label} must be a private directory owned by the current user"
        )


def _open_gc_plane(
    paths: Any,
    *,
    create: bool,
) -> tuple[int, int] | None:
    """Open the quota-exempt, hard-bounded GC recovery control plane."""

    challenge_fd = _open_challenge_root(paths)
    try:
        if create:
            plane_fd = _open_directory_at(
                challenge_fd,
                GC_CONTROL_DIRECTORY,
                create=True,
            )
        else:
            try:
                plane_fd = os.open(
                    GC_CONTROL_DIRECTORY,
                    _DIRECTORY_FLAGS,
                    dir_fd=challenge_fd,
                )
            except FileNotFoundError:
                os.close(challenge_fd)
                return None
        try:
            _assert_private_directory_fd(plane_fd, "storage GC control root")
        except BaseException:
            os.close(plane_fd)
            raise
        return challenge_fd, plane_fd
    except BaseException:
        os.close(challenge_fd)
        raise


def _metadata_file_present(directory_fd: int, name: str) -> bool:
    try:
        metadata = os.stat(
            name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise StorageError(f"storage GC metadata is unsafe: {name}")
    return True


def _open_gc_metadata_root(
    paths: Any,
    quarantine_id: str,
    data_root_fd: int,
    *,
    create: bool = False,
) -> tuple[int, bool]:
    """Open new control metadata, or an existing legacy co-located root."""

    legacy_present = _metadata_file_present(data_root_fd, "manifest.json")
    plane = _open_gc_plane(paths, create=create)
    control_fd: int | None = None
    challenge_fd: int | None = None
    plane_fd: int | None = None
    try:
        if plane is not None:
            challenge_fd, plane_fd = plane
            if create:
                control_fd = _open_directory_at(
                    plane_fd,
                    quarantine_id,
                    create=True,
                )
            else:
                try:
                    control_fd = os.open(
                        quarantine_id,
                        _DIRECTORY_FLAGS,
                        dir_fd=plane_fd,
                    )
                except FileNotFoundError:
                    control_fd = None
            if control_fd is not None:
                _assert_private_directory_fd(
                    control_fd,
                    "quarantine GC control directory",
                )
        control_present = (
            control_fd is not None
            and _metadata_file_present(control_fd, "manifest.json")
        )
        if legacy_present and control_present:
            raise StorageError(
                "ambiguous legacy and current quarantine metadata"
            )
        if legacy_present:
            if control_fd is not None:
                os.close(control_fd)
                control_fd = None
            return os.dup(data_root_fd), True
        if control_fd is None:
            raise StorageError("quarantine control metadata is missing")
        if not create and not control_present:
            raise StorageError("quarantine control manifest is missing")
        result = control_fd
        control_fd = None
        return result, False
    finally:
        if control_fd is not None:
            os.close(control_fd)
        if plane_fd is not None:
            os.close(plane_fd)
        if challenge_fd is not None:
            os.close(challenge_fd)


def _atomic_write_gc_json(
    paths: Any,
    metadata_root_fd: int,
    name: str,
    value: object,
    *,
    maximum_bytes: int,
    legacy: bool,
) -> None:
    """Write bounded recovery metadata without consuming artifact quota.

    New metadata lives in a dedicated trusted control plane.  Its aggregate
    hard cap includes the complete atomic temporary generation, preventing
    the exemption from becoming an unbounded storage bypass.  Legacy
    co-located documents remain per-document bounded and update in place.
    """

    payload = canonical_json_bytes(value)
    if len(payload) > maximum_bytes:
        raise StorageError(
            f"storage metadata exceeds {maximum_bytes} bytes: {name}"
        )
    if not legacy:
        try:
            used_bytes, _files, entries = _gc_control_snapshot(paths)
        except StorageError as error:
            raise StorageError(
                "storage GC control aggregate cap or integrity check failed"
            ) from error
        # The temporary generation coexists with the current document until
        # replace(2).  Account for that peak, not merely the final tree.
        if entries + 1 > MAX_GC_CONTROL_ENTRIES:
            raise StorageError("storage GC control entry cap exceeded")
        if used_bytes + len(payload) > MAX_GC_CONTROL_BYTES:
            raise StorageError("storage GC control byte cap exceeded")
    _atomic_write_json_at(
        metadata_root_fd,
        name,
        value,
        maximum_bytes=maximum_bytes,
    )


def _record_issue(
    issues: list[dict[str, str]],
    *,
    code: str,
    path: str,
) -> None:
    if len(issues) < MAX_STORAGE_ISSUES:
        issues.append({"code": code, "path": path})
    elif len(issues) == MAX_STORAGE_ISSUES:
        issues.append(
            {
                "code": "additional_issues_omitted",
                "path": "",
            }
        )


def _storage_class(
    relative: str,
    reachable: set[str],
    reachable_prefixes: tuple[str, ...],
) -> tuple[str, str, bool]:
    root = relative.split("/", 1)[0]
    # These roots contain engine-owned continuity, staging, snapshot, context,
    # and export payloads.  They count toward the challenge quota, but are
    # deliberately preserved: the GC path allowlist remains limited to
    # runs/artifacts/proof and can never move or purge one of these files.
    if root in _PRESERVED_STORAGE_ROOTS:
        return root, "canonical", True
    is_reachable = relative in reachable or relative.startswith(
        reachable_prefixes
    )
    if relative.startswith("artifacts/quarantine/"):
        return (
            "quarantine",
            "canonical" if is_reachable else "quarantine",
            is_reachable,
        )
    return (
        root,
        "canonical" if is_reachable else "noncanonical",
        is_reachable,
    )


def _assert_quarantine_unreferenced(
    store: StateStore,
    identity: ChallengeIdentity,
    quarantine_id: str,
) -> None:
    """Refuse to mutate a quarantine intersecting canonical state reachability.

    A quarantine is initially non-canonical, but an operator may deliberately
    register one of its immutable files later.  Preparation is not authority
    to invalidate that newer canonical reference.  The exclusive state lock
    held by every caller freezes this decision through the mutation.
    """

    state = store.read_snapshot(identity)
    reachable, reachable_prefixes = _reachable_paths(state)
    root = f"artifacts/quarantine/{quarantine_id}"
    prefix = root + "/"
    exact_intersections = sorted(
        path
        for path in reachable
        if path == root or path.startswith(prefix)
    )
    prefix_intersections = sorted(
        path
        for path in reachable_prefixes
        if (
            path.rstrip("/") == root
            or path.startswith(prefix)
            or prefix.startswith(path)
        )
    )
    if exact_intersections or prefix_intersections:
        examples = (exact_intersections + prefix_intersections)[:3]
        suffix = ", ".join(examples)
        raise StorageError(
            "canonical state references quarantine; refusing mutation"
            + (f": {suffix}" if suffix else "")
        )


def _scan_storage(
    paths: Any,
    *,
    reachable: set[str],
    reachable_prefixes: tuple[str, ...],
    max_entries: int,
    max_scan_bytes: int,
) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    issues: list[dict[str, str]] = []
    scanned_entries = 0
    scanned_bytes = 0
    exempt_control_bytes = 0
    exempt_control_files = 0
    halted = False
    directory_observations: dict[str, tuple[int, ...]] = {}
    file_observations: dict[str, tuple[int, ...]] = {}
    missing_roots: set[str] = set()

    for root_name in _ACCOUNTED_STORAGE_ROOTS:
        if halted:
            break
        root_path = paths.root / root_name
        try:
            root_fd = os.open(root_path, _DIRECTORY_FLAGS)
        except FileNotFoundError:
            missing_roots.add(root_name)
            _record_issue(
                issues,
                code="storage_root_missing",
                path=root_name,
            )
            continue
        except OSError:
            _record_issue(
                issues,
                code="storage_root_unsafe",
                path=root_name,
            )
            continue

        frames: list[dict[str, Any]] = []
        try:
            root_metadata = os.fstat(root_fd)
            if not stat.S_ISDIR(root_metadata.st_mode):
                _record_issue(
                    issues,
                    code="storage_root_not_directory",
                    path=root_name,
                )
                os.close(root_fd)
                continue
            frames.append(
                {
                    "fd": root_fd,
                    "iterator": os.scandir(root_fd),
                    "relative": root_name,
                    "before": _signature(root_metadata),
                }
            )
            directory_observations[root_name] = _signature(root_metadata)
            root_fd = -1
            while frames and not halted:
                frame = frames[-1]
                try:
                    entry = next(frame["iterator"])
                except StopIteration:
                    after = os.fstat(frame["fd"])
                    if _signature(after) != frame["before"]:
                        _record_issue(
                            issues,
                            code="directory_changed_during_scan",
                            path=frame["relative"],
                        )
                    frame["iterator"].close()
                    os.close(frame["fd"])
                    frames.pop()
                    continue
                except OSError:
                    _record_issue(
                        issues,
                        code="directory_scan_failed",
                        path=frame["relative"],
                    )
                    halted = True
                    break

                scanned_entries += 1
                relative = f"{frame['relative']}/{entry.name}"
                if scanned_entries > max_entries:
                    _record_issue(
                        issues,
                        code="entry_limit_exceeded",
                        path=relative,
                    )
                    halted = True
                    break
                try:
                    metadata = os.stat(
                        entry.name,
                        dir_fd=frame["fd"],
                        follow_symlinks=False,
                    )
                except OSError:
                    _record_issue(
                        issues,
                        code="entry_changed_during_scan",
                        path=relative,
                    )
                    continue

                if stat.S_ISLNK(metadata.st_mode):
                    _record_issue(
                        issues,
                        code="symlink_forbidden",
                        path=relative,
                    )
                    continue
                if stat.S_ISDIR(metadata.st_mode):
                    try:
                        child_fd = os.open(
                            entry.name,
                            _DIRECTORY_FLAGS,
                            dir_fd=frame["fd"],
                        )
                        opened = os.fstat(child_fd)
                    except OSError:
                        _record_issue(
                            issues,
                            code="directory_changed_during_scan",
                            path=relative,
                        )
                        continue
                    if _signature(metadata) != _signature(opened):
                        os.close(child_fd)
                        _record_issue(
                            issues,
                            code="directory_changed_during_scan",
                            path=relative,
                        )
                        continue
                    try:
                        iterator = os.scandir(child_fd)
                    except OSError:
                        os.close(child_fd)
                        _record_issue(
                            issues,
                            code="directory_scan_failed",
                            path=relative,
                        )
                        continue
                    frames.append(
                        {
                            "fd": child_fd,
                            "iterator": iterator,
                            "relative": relative,
                            "before": _signature(opened),
                        }
                    )
                    directory_observations[relative] = _signature(opened)
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    _record_issue(
                        issues,
                        code="special_file_forbidden",
                        path=relative,
                    )
                    continue

                try:
                    descriptor = os.open(
                        entry.name,
                        _FILE_FLAGS,
                        dir_fd=frame["fd"],
                    )
                    try:
                        opened = os.fstat(descriptor)
                    finally:
                        os.close(descriptor)
                    final = os.stat(
                        entry.name,
                        dir_fd=frame["fd"],
                        follow_symlinks=False,
                    )
                except OSError:
                    _record_issue(
                        issues,
                        code="file_changed_during_scan",
                        path=relative,
                    )
                    continue
                if (
                    _signature(metadata) != _signature(opened)
                    or _signature(opened) != _signature(final)
                ):
                    _record_issue(
                        issues,
                        code="file_changed_during_scan",
                        path=relative,
                    )
                    continue
                if metadata.st_nlink != 1:
                    _record_issue(
                        issues,
                        code="hardlink_forbidden",
                        path=relative,
                    )

                if relative == _DERIVED_CONTEXT_PATH:
                    if metadata.st_size > MAX_DERIVED_CONTEXT_BYTES:
                        _record_issue(
                            issues,
                            code="derived_control_file_exceeds_limit",
                            path=relative,
                        )
                    # current.md is a bounded state-derived control view, not
                    # durable challenge evidence.  It remains fully inspected
                    # and race-rechecked, while immutable context/history
                    # archives below the same root remain quota-accounted.
                    file_observations[relative] = _signature(final)
                    exempt_control_bytes += metadata.st_size
                    exempt_control_files += 1
                    continue

                scope, storage_class, is_reachable = _storage_class(
                    relative,
                    reachable,
                    reachable_prefixes,
                )
                files.append(
                    {
                        "path": relative,
                        "bytes": metadata.st_size,
                        "scope": scope,
                        "storage_class": storage_class,
                        "reachable": is_reachable,
                    }
                )
                file_observations[relative] = _signature(final)
                scanned_bytes += metadata.st_size
                if scanned_bytes > max_scan_bytes:
                    _record_issue(
                        issues,
                        code="byte_limit_exceeded",
                        path=relative,
                    )
                    halted = True
                    break
        finally:
            for frame in reversed(frames):
                try:
                    frame["iterator"].close()
                finally:
                    os.close(frame["fd"])
            if root_fd >= 0:
                os.close(root_fd)

    # Recheck every already-scanned pathname only after all accounted roots
    # have closed. This detects a writer that waits for an early subtree to
    # close and then inserts or replaces bytes while a later root is scanned.
    for relative, expected in (
        *directory_observations.items(),
        *file_observations.items(),
    ):
        try:
            observed = os.stat(
                paths.root / relative,
                follow_symlinks=False,
            )
        except OSError:
            _record_issue(
                issues,
                code="entry_changed_during_scan",
                path=relative,
            )
            continue
        if _signature(observed) != expected:
            _record_issue(
                issues,
                code=(
                    "directory_changed_during_scan"
                    if relative in directory_observations
                    else "file_changed_during_scan"
                ),
                path=relative,
            )
    for root_name in missing_roots:
        if (paths.root / root_name).exists():
            _record_issue(
                issues,
                code="directory_changed_during_scan",
                path=root_name,
            )

    files.sort(key=lambda item: item["path"])
    complete = not issues
    return {
        "files": files,
        "issues": issues,
        "scan_complete": complete,
        "scanned_entries": min(scanned_entries, max_entries),
        "entry_limit": max_entries,
        "total_bytes": scanned_bytes,
        "exempt_control_bytes": exempt_control_bytes,
        "exempt_control_files": exempt_control_files,
        "byte_limit": max_scan_bytes,
    }


def _scan_regular_tree_at(
    base_fd: int,
    *,
    max_entries: int,
    max_bytes: int,
    observed_directories: set[str] | None = None,
    observed_entry_count: list[int] | None = None,
) -> dict[str, int]:
    """Return an exact bounded regular-file map below one trusted directory."""

    root_fd = os.dup(base_fd)
    frames: list[dict[str, Any]] = []
    entries = 0
    total_bytes = 0
    files: dict[str, int] = {}
    directories: set[str] = set()
    try:
        before = os.fstat(root_fd)
        frames.append(
            {
                "fd": root_fd,
                "iterator": os.scandir(root_fd),
                "relative": "",
                "before": _signature(before),
            }
        )
        root_fd = -1
        while frames:
            frame = frames[-1]
            try:
                entry = next(frame["iterator"])
            except StopIteration:
                after = os.fstat(frame["fd"])
                if _signature(after) != frame["before"]:
                    raise StorageError(
                        "quarantine directory changed during verification"
                    )
                frame["iterator"].close()
                os.close(frame["fd"])
                frames.pop()
                continue
            except OSError as error:
                raise StorageError(
                    "quarantine directory scan failed"
                ) from error

            entries += 1
            relative = (
                f"{frame['relative']}/{entry.name}"
                if frame["relative"]
                else entry.name
            )
            if entries > max_entries:
                raise StorageError(
                    "quarantine entry verification limit exceeded"
                )
            try:
                metadata = os.stat(
                    entry.name,
                    dir_fd=frame["fd"],
                    follow_symlinks=False,
                )
            except OSError as error:
                raise StorageError(
                    f"quarantine entry changed during scan: {relative}"
                ) from error
            if stat.S_ISLNK(metadata.st_mode):
                raise StorageError(
                    f"quarantine symlink is forbidden: {relative}"
                )
            if stat.S_ISDIR(metadata.st_mode):
                try:
                    child_fd = os.open(
                        entry.name,
                        _DIRECTORY_FLAGS,
                        dir_fd=frame["fd"],
                    )
                    opened = os.fstat(child_fd)
                except OSError as error:
                    raise StorageError(
                        f"quarantine directory is unsafe: {relative}"
                    ) from error
                if _signature(metadata) != _signature(opened):
                    os.close(child_fd)
                    raise StorageError(
                        f"quarantine directory changed: {relative}"
                    )
                try:
                    iterator = os.scandir(child_fd)
                except BaseException:
                    os.close(child_fd)
                    raise
                frames.append(
                    {
                        "fd": child_fd,
                        "iterator": iterator,
                        "relative": relative,
                        "before": _signature(opened),
                    }
                )
                directories.add(relative)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise StorageError(
                    f"quarantine special file is forbidden: {relative}"
                )
            if metadata.st_nlink != 1:
                raise StorageError(
                    f"quarantine file is hard-linked: {relative}"
                )
            try:
                descriptor = os.open(
                    entry.name,
                    _FILE_FLAGS,
                    dir_fd=frame["fd"],
                )
                try:
                    opened = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
                final = os.stat(
                    entry.name,
                    dir_fd=frame["fd"],
                    follow_symlinks=False,
                )
            except OSError as error:
                raise StorageError(
                    f"quarantine file changed during scan: {relative}"
                ) from error
            if (
                _signature(metadata) != _signature(opened)
                or _signature(opened) != _signature(final)
            ):
                raise StorageError(
                    f"quarantine file changed during scan: {relative}"
                )
            files[relative] = metadata.st_size
            total_bytes += metadata.st_size
            if total_bytes > max_bytes:
                raise StorageError(
                    "quarantine byte verification limit exceeded"
                )
        if observed_directories is not None:
            observed_directories.update(directories)
        if observed_entry_count is not None:
            observed_entry_count.append(entries)
        return files
    finally:
        for frame in reversed(frames):
            try:
                frame["iterator"].close()
            finally:
                os.close(frame["fd"])
        if root_fd >= 0:
            os.close(root_fd)


def _gc_control_snapshot(paths: Any) -> tuple[int, int, int]:
    """Validate and measure the bounded GC recovery control plane."""

    plane = _open_gc_plane(paths, create=False)
    if plane is None:
        return 0, 0, 0
    challenge_fd, plane_fd = plane
    try:
        try:
            directories: set[str] = set()
            entry_count: list[int] = []
            files = _scan_regular_tree_at(
                plane_fd,
                max_entries=MAX_GC_CONTROL_ENTRIES,
                max_bytes=MAX_GC_CONTROL_BYTES,
                observed_directories=directories,
                observed_entry_count=entry_count,
            )
            if any(
                len(PurePosixPath(relative).parts) != 1
                or _QUARANTINE_ID.fullmatch(relative) is None
                for relative in directories
            ):
                raise StorageError(
                    "storage GC control root contains an invalid directory"
                )
            for relative in files:
                parts = PurePosixPath(relative).parts
                if (
                    len(parts) != 2
                    or _QUARANTINE_ID.fullmatch(parts[0]) is None
                    or parts[1] not in {"manifest.json", "purge.json"}
                ):
                    raise StorageError(
                        "storage GC control root contains an invalid document"
                    )
            if len(entry_count) != 1:
                raise StorageError(
                    "storage GC control entry count is unavailable"
                )
            return sum(files.values()), len(files), entry_count[0]
        except OSError as error:
            raise StorageError(
                "storage GC control root cannot be inspected safely"
            ) from error
    finally:
        os.close(plane_fd)
        os.close(challenge_fd)


def _gc_control_usage(paths: Any) -> tuple[int, int]:
    """Return quota-exempt GC bytes and regular control document count."""

    total_bytes, file_count, _entry_count = _gc_control_snapshot(paths)
    return total_bytes, file_count


def _bounded_entry_names_at(
    directory_fd: int,
    *,
    maximum_entries: int,
    label: str,
    shared_budget: list[int] | None = None,
) -> tuple[str, ...]:
    """List one directory exactly once with a hard entry bound."""

    before = os.fstat(directory_fd)
    names: list[str] = []
    try:
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > maximum_entries:
                    raise StorageError(f"{label} entry limit exceeded")
                if shared_budget is not None:
                    shared_budget[0] -= 1
                    if shared_budget[0] < 0:
                        raise StorageError(f"{label} entry limit exceeded")
        after = os.fstat(directory_fd)
    except OSError as error:
        raise StorageError(f"{label} cannot be inspected safely") from error
    if _signature(before) != _signature(after):
        raise StorageError(f"{label} changed during inspection")
    return tuple(sorted(names))


def _assert_unpublished_gc_temp(directory_fd: int, name: str) -> None:
    """Accept only an interrupted initial-manifest atomic generation."""

    if _GC_MANIFEST_TEMP.fullmatch(name) is None:
        raise StorageError(
            "unpublished storage GC transaction contains an unknown entry"
        )
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        descriptor = os.open(name, _FILE_FLAGS, dir_fd=directory_fd)
        try:
            opened = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as error:
        raise StorageError(
            "unpublished storage GC manifest temporary is unsafe"
        ) from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) & 0o077
        or before.st_size > MAX_QUARANTINE_MANIFEST_BYTES
        or _signature(before) != _signature(opened)
        or _signature(opened) != _signature(after)
    ):
        raise StorageError(
            "unpublished storage GC manifest temporary is unsafe"
        )


def _unpublished_control_temps(
    control_fd: int,
    *,
    shared_budget: list[int] | None = None,
) -> tuple[str, ...]:
    if _metadata_file_present(control_fd, "manifest.json"):
        raise StorageError(
            "published storage GC transaction cannot be recovered as abandoned"
        )
    names = _bounded_entry_names_at(
        control_fd,
        maximum_entries=MAX_GC_CONTROL_ENTRIES,
        label="unpublished storage GC control directory",
        shared_budget=shared_budget,
    )
    for name in names:
        _assert_unpublished_gc_temp(control_fd, name)
    return names


def _unpublished_data_shape(
    data_fd: int,
    *,
    maximum_entries: int,
    shared_budget: list[int] | None = None,
) -> tuple[int | None, tuple[str, ...]] | None:
    """Return the exact removable pre-manifest data shape, or legacy marker."""

    if _metadata_file_present(data_fd, "manifest.json"):
        return None
    names = _bounded_entry_names_at(
        data_fd,
        maximum_entries=maximum_entries,
        label="unpublished quarantine data directory",
        shared_budget=shared_budget,
    )
    files_fd: int | None = None
    temporaries: list[str] = []
    try:
        for name in names:
            if name == "files":
                if files_fd is not None:
                    raise StorageError(
                        "unpublished quarantine has duplicate files roots"
                    )
                try:
                    files_fd = os.open(
                        name,
                        _DIRECTORY_FLAGS,
                        dir_fd=data_fd,
                    )
                except OSError as error:
                    raise StorageError(
                        "unpublished quarantine files root is unsafe"
                    ) from error
                _assert_private_directory_fd(
                    files_fd,
                    "unpublished quarantine files root",
                )
                if _bounded_entry_names_at(
                    files_fd,
                    maximum_entries=1,
                    label="unpublished quarantine files root",
                    shared_budget=shared_budget,
                ):
                    raise StorageError(
                        "unpublished quarantine files root is not empty"
                    )
                continue
            _assert_unpublished_gc_temp(data_fd, name)
            temporaries.append(name)
        result = files_fd, tuple(temporaries)
        files_fd = None
        return result
    finally:
        if files_fd is not None:
            os.close(files_fd)


def _open_quarantine_plane(paths: Any) -> tuple[int, int] | None:
    """Open the accounted quarantine parent without creating it."""

    challenge_fd = _open_challenge_root(paths)
    artifacts_fd: int | None = None
    try:
        artifacts_fd = _open_directory_at(challenge_fd, "artifacts")
        try:
            quarantine_fd = os.open(
                "quarantine",
                _DIRECTORY_FLAGS,
                dir_fd=artifacts_fd,
            )
        except FileNotFoundError:
            os.close(challenge_fd)
            os.close(artifacts_fd)
            return None
        try:
            _assert_private_directory_fd(
                quarantine_fd,
                "quarantine data root",
            )
        except BaseException:
            os.close(quarantine_fd)
            raise
        os.close(artifacts_fd)
        artifacts_fd = None
        return challenge_fd, quarantine_fd
    except BaseException:
        if artifacts_fd is not None:
            os.close(artifacts_fd)
        os.close(challenge_fd)
        raise


def _remove_abandoned_gc_transaction(
    paths: Any,
    quarantine_id: str,
    *,
    maximum_entries: int,
) -> None:
    """Remove only an exact empty transaction that never published a manifest."""

    control_plane: tuple[int, int] | None = None
    control_challenge_fd: int | None = None
    control_plane_fd: int | None = None
    control_fd: int | None = None
    control_temporaries: tuple[str, ...] = ()
    data_plane: tuple[int, int] | None = None
    data_challenge_fd: int | None = None
    data_plane_fd: int | None = None
    data_fd: int | None = None
    files_fd: int | None = None
    data_temporaries: tuple[str, ...] = ()
    remove_data = False
    try:
        control_plane = _open_gc_plane(paths, create=False)
        if control_plane is not None:
            control_challenge_fd, control_plane_fd = control_plane
            try:
                control_fd = os.open(
                    quarantine_id,
                    _DIRECTORY_FLAGS,
                    dir_fd=control_plane_fd,
                )
            except FileNotFoundError:
                control_fd = None
            if control_fd is not None:
                _assert_private_directory_fd(
                    control_fd,
                    "unpublished storage GC control directory",
                )
                control_temporaries = _unpublished_control_temps(control_fd)

        data_plane = _open_quarantine_plane(paths)
        if data_plane is not None:
            data_challenge_fd, data_plane_fd = data_plane
            try:
                data_fd = os.open(
                    quarantine_id,
                    _DIRECTORY_FLAGS,
                    dir_fd=data_plane_fd,
                )
            except FileNotFoundError:
                data_fd = None
            if data_fd is not None:
                _assert_private_directory_fd(
                    data_fd,
                    "unpublished quarantine data directory",
                )
                data_shape = _unpublished_data_shape(
                    data_fd,
                    maximum_entries=maximum_entries,
                )
                if data_shape is not None:
                    files_fd, data_temporaries = data_shape
                    remove_data = True

        if control_fd is None and not remove_data:
            return

        # Remove the unpublished control name first. A concurrently published
        # manifest makes rmdir fail closed before any data root is touched.
        if control_fd is not None:
            for name in control_temporaries:
                os.unlink(name, dir_fd=control_fd)
            os.fsync(control_fd)
            os.close(control_fd)
            control_fd = None
            assert control_plane_fd is not None
            os.rmdir(quarantine_id, dir_fd=control_plane_fd)
            os.fsync(control_plane_fd)

        if remove_data:
            assert data_fd is not None
            for name in data_temporaries:
                os.unlink(name, dir_fd=data_fd)
            if files_fd is not None:
                os.close(files_fd)
                files_fd = None
                os.rmdir("files", dir_fd=data_fd)
            os.fsync(data_fd)
            os.close(data_fd)
            data_fd = None
            assert data_plane_fd is not None
            os.rmdir(quarantine_id, dir_fd=data_plane_fd)
            os.fsync(data_plane_fd)
    except OSError as error:
        raise StorageError(
            "abandoned storage GC transaction could not be removed safely"
        ) from error
    finally:
        for descriptor in (
            files_fd,
            data_fd,
            data_plane_fd,
            data_challenge_fd,
            control_fd,
            control_plane_fd,
            control_challenge_fd,
        ):
            if descriptor is not None:
                os.close(descriptor)


def _recover_abandoned_gc_transactions(
    paths: Any,
    *,
    maximum_entries: int,
) -> None:
    """Boundedly recover crash remnants before inventory can reject them."""

    published_control: set[str] = set()
    abandoned: set[str] = set()
    plane = _open_gc_plane(paths, create=False)
    if plane is not None:
        challenge_fd, plane_fd = plane
        control_budget = [MAX_GC_CONTROL_ENTRIES]
        try:
            for name in _bounded_entry_names_at(
                plane_fd,
                maximum_entries=MAX_GC_CONTROL_ENTRIES,
                label="storage GC control root",
                shared_budget=control_budget,
            ):
                if _QUARANTINE_ID.fullmatch(name) is None:
                    raise StorageError(
                        "storage GC control root contains an invalid entry"
                    )
                try:
                    child_fd = os.open(
                        name,
                        _DIRECTORY_FLAGS,
                        dir_fd=plane_fd,
                    )
                except OSError as error:
                    raise StorageError(
                        "storage GC control directory is unsafe"
                    ) from error
                try:
                    _assert_private_directory_fd(
                        child_fd,
                        "storage GC control directory",
                    )
                    if _metadata_file_present(child_fd, "manifest.json"):
                        published_control.add(name)
                    else:
                        _unpublished_control_temps(
                            child_fd,
                            shared_budget=control_budget,
                        )
                        abandoned.add(name)
                finally:
                    os.close(child_fd)
        finally:
            os.close(plane_fd)
            os.close(challenge_fd)

    data_plane = _open_quarantine_plane(paths)
    if data_plane is not None:
        challenge_fd, plane_fd = data_plane
        data_budget = [maximum_entries]
        try:
            for name in _bounded_entry_names_at(
                plane_fd,
                maximum_entries=maximum_entries,
                label="quarantine data root",
                shared_budget=data_budget,
            ):
                if (
                    _QUARANTINE_ID.fullmatch(name) is None
                    or name in published_control
                ):
                    continue
                try:
                    child_fd = os.open(
                        name,
                        _DIRECTORY_FLAGS,
                        dir_fd=plane_fd,
                    )
                except OSError as error:
                    raise StorageError(
                        "unpublished quarantine data directory is unsafe"
                    ) from error
                try:
                    _assert_private_directory_fd(
                        child_fd,
                        "unpublished quarantine data directory",
                    )
                    data_shape = _unpublished_data_shape(
                        child_fd,
                        maximum_entries=maximum_entries,
                        shared_budget=data_budget,
                    )
                    if data_shape is not None:
                        discovered_files_fd, _temporaries = data_shape
                        if discovered_files_fd is not None:
                            os.close(discovered_files_fd)
                        abandoned.add(name)
                finally:
                    os.close(child_fd)
        finally:
            os.close(plane_fd)
            os.close(challenge_fd)

    for quarantine_id in sorted(abandoned):
        _remove_abandoned_gc_transaction(
            paths,
            quarantine_id,
            maximum_entries=maximum_entries,
        )


def _admit_new_gc_control_transaction(paths: Any) -> None:
    """Reserve a directory plus one atomic manifest generation before mkdir."""

    _bytes, _files, entries = _gc_control_snapshot(paths)
    if entries + 2 > MAX_GC_CONTROL_ENTRIES:
        raise StorageError("storage GC control entry cap exceeded")


def _inventory_from_state(
    store: StateStore,
    identity: ChallengeIdentity,
    state: ChallengeState,
    *,
    quota_bytes: int,
    max_entries: int,
    max_scan_bytes: int,
) -> dict[str, Any]:
    paths = store.challenge_paths(identity)
    reachable, reachable_prefixes = _reachable_paths(state)
    scan = _scan_storage(
        paths,
        reachable=reachable,
        reachable_prefixes=reachable_prefixes,
        max_entries=max_entries,
        max_scan_bytes=max_scan_bytes,
    )
    try:
        gc_control_bytes, gc_control_files = _gc_control_usage(paths)
    except StorageError:
        gc_control_bytes = 0
        gc_control_files = 0
        _record_issue(
            scan["issues"],
            code="gc_control_integrity_failed",
            path=GC_CONTROL_DIRECTORY,
        )
        scan["scan_complete"] = False
    active_reservation_bytes = 0
    background_reservation_exact = True
    analysis_reservation_exact = True

    def add_active_reservation(value: object) -> bool:
        nonlocal active_reservation_bytes
        if type(value) is not int or value <= 0:
            return False
        if active_reservation_bytes <= quota_bytes:
            active_reservation_bytes = min(
                quota_bytes + 1,
                active_reservation_bytes + value,
            )
        return True

    background_jobs = state.extra.get("background_jobs", [])
    if type(background_jobs) is not list:
        background_reservation_exact = False
    else:
        for record in background_jobs:
            if type(record) is not dict:
                background_reservation_exact = False
                continue
            status = record.get("status")
            if record.get("schema_version") != 2:
                if status not in {
                    "completed",
                    "failed",
                    "timed_out",
                    "cancelled",
                    "recovered",
                }:
                    background_reservation_exact = False
                continue
            if status in {
                "launching",
                "starting",
                "running",
                "lost",
                "cleanup_pending",
            }:
                if not add_active_reservation(
                    record.get("storage_reservation_bytes")
                ):
                    background_reservation_exact = False
    if not background_reservation_exact:
        _record_issue(
            scan["issues"],
            code="background_reservation_indeterminate",
            path="state.json",
        )
        scan["scan_complete"] = False

    analysis_leases = state.extra.get("analysis_leases", [])
    if type(analysis_leases) is not list:
        analysis_reservation_exact = False
    else:
        for record in analysis_leases:
            if type(record) is not dict:
                analysis_reservation_exact = False
                continue
            status = record.get("status")
            if record.get("schema_version") != 1:
                if status not in {"completed", "failed", "recovered"}:
                    analysis_reservation_exact = False
                continue
            if status in {"running", "cleanup_pending"}:
                if not add_active_reservation(
                    record.get("storage_reservation_bytes")
                ):
                    analysis_reservation_exact = False
            elif status not in {"completed", "failed", "recovered"}:
                analysis_reservation_exact = False
    if not analysis_reservation_exact:
        _record_issue(
            scan["issues"],
            code="analysis_reservation_indeterminate",
            path="state.json",
        )
        scan["scan_complete"] = False
    reservation_exact = (
        background_reservation_exact and analysis_reservation_exact
    )
    files = scan["files"]
    totals = {
        "canonical_bytes": sum(
            item["bytes"]
            for item in files
            if item["storage_class"] == "canonical"
        ),
        "noncanonical_bytes": sum(
            item["bytes"]
            for item in files
            if item["storage_class"] == "noncanonical"
        ),
        "quarantine_bytes": sum(
            item["bytes"]
            for item in files
            if item["storage_class"] == "quarantine"
        ),
    }
    total_bytes = scan["total_bytes"]
    conservative_bytes = total_bytes + active_reservation_bytes
    if conservative_bytes > quota_bytes:
        quota_status = "exceeded"
    elif scan["scan_complete"]:
        quota_status = "within"
    else:
        quota_status = "indeterminate"
    roots: dict[str, dict[str, int]] = {}
    for scope in (
        "runs",
        "artifacts",
        "proof",
        "quarantine",
        "runtime",
        "context",
        "knowledge",
        "exports",
    ):
        scoped = [item for item in files if item["scope"] == scope]
        roots[scope] = {
            "files": len(scoped),
            "bytes": sum(item["bytes"] for item in scoped),
        }
    return {
        "schema_version": 3,
        "identity": identity.key,
        "state_revision": state.revision,
        "scan_complete": scan["scan_complete"],
        "scan": {
            "entries": scan["scanned_entries"],
            "entry_limit": scan["entry_limit"],
            "bytes_lower_bound": total_bytes,
            "physical_bytes_lower_bound": (
                total_bytes
                + scan["exempt_control_bytes"]
                + gc_control_bytes
            ),
            "byte_limit": scan["byte_limit"],
            "issues": scan["issues"],
        },
        "quota": {
            "limit_bytes": quota_bytes,
            "status": quota_status,
            "observed_bytes": total_bytes,
            "observed_physical_bytes": (
                total_bytes
                + scan["exempt_control_bytes"]
                + gc_control_bytes
            ),
            "active_reservation_bytes": active_reservation_bytes,
            "requested_bytes": 0,
            "conservative_projected_bytes": conservative_bytes,
            "accounting_mode": (
                "conservative_upper_bound"
                if active_reservation_bytes
                else "exact_physical"
            ),
            "exact": (
                scan["scan_complete"]
                and reservation_exact
                and active_reservation_bytes == 0
            ),
            "exempt_control_bytes": (
                scan["exempt_control_bytes"] + gc_control_bytes
            ),
            "exempt_control_files": (
                scan["exempt_control_files"] + gc_control_files
            ),
        },
        "control": {
            "quota_exempt_bytes": (
                scan["exempt_control_bytes"] + gc_control_bytes
            ),
            "quota_exempt_files": (
                scan["exempt_control_files"] + gc_control_files
            ),
            "derived_context_bytes": scan["exempt_control_bytes"],
            "derived_context_files": scan["exempt_control_files"],
            "gc_recovery_bytes": gc_control_bytes,
            "gc_recovery_files": gc_control_files,
            "policy": "bounded_derived_and_recovery_control",
        },
        "roots": roots,
        "totals": totals,
        "files": files,
        # Schema-v1 compatibility fields.
        "total_bytes": total_bytes,
        "unreachable_bytes": totals["noncanonical_bytes"],
    }


def storage_inventory(
    store: StateStore,
    identity: ChallengeIdentity,
    *,
    quota_bytes: int = DEFAULT_CHALLENGE_STORAGE_QUOTA_BYTES,
    max_entries: int = DEFAULT_STORAGE_SCAN_MAX_ENTRIES,
    max_scan_bytes: int = DEFAULT_STORAGE_SCAN_MAX_BYTES,
) -> dict[str, Any]:
    quota_bytes = _positive_integer(quota_bytes, "quota_bytes")
    max_entries = _positive_integer(max_entries, "max_entries")
    max_scan_bytes = _positive_integer(max_scan_bytes, "max_scan_bytes")
    paths = store.challenge_paths(identity)
    # A shared state lock freezes canonical reachability while allowing other
    # read-only inspectors.  Artifact writers need not cooperate, so the
    # descriptor scanner still validates every path and parent directory.
    with ChallengeLock(paths.lock, shared=True) as state_lock:
        state_lock.acquire()
        state = store.read_snapshot(identity)
        return _inventory_from_state(
            store,
            identity,
            state,
            quota_bytes=quota_bytes,
            max_entries=max_entries,
            max_scan_bytes=max_scan_bytes,
        )


def enforce_storage_quota(
    store: StateStore,
    identity: ChallengeIdentity,
    *,
    quota_bytes: int = DEFAULT_CHALLENGE_STORAGE_QUOTA_BYTES,
    max_entries: int = DEFAULT_STORAGE_SCAN_MAX_ENTRIES,
    max_scan_bytes: int = DEFAULT_STORAGE_SCAN_MAX_BYTES,
    additional_bytes: int = 0,
    transient_scan_retries: int = DEFAULT_STORAGE_TRANSIENT_SCAN_RETRIES,
) -> dict[str, Any]:
    """Fail closed unless the current and projected totals fit the quota.

    This is an admission check, not a filesystem reservation.  A writer must
    already own the challenge session lock and retain it through its write and
    canonical state commit.  Calling this while holding the exclusive state
    lock would violate the session -> shared-state lock order.
    """

    quota_bytes = _positive_integer(quota_bytes, "quota_bytes")
    max_entries = _positive_integer(max_entries, "max_entries")
    max_scan_bytes = _positive_integer(max_scan_bytes, "max_scan_bytes")
    additional_bytes = _nonnegative_integer(
        additional_bytes,
        "additional_bytes",
    )
    transient_scan_retries = _nonnegative_integer(
        transient_scan_retries,
        "transient_scan_retries",
    )
    if transient_scan_retries > DEFAULT_STORAGE_TRANSIENT_SCAN_RETRIES:
        raise ValueError(
            "transient_scan_retries exceeds the bounded retry limit"
        )

    report: dict[str, Any] | None = None
    retries_used = 0
    for attempt in range(transient_scan_retries + 1):
        report = storage_inventory(
            store,
            identity,
            quota_bytes=quota_bytes,
            max_entries=max_entries,
            max_scan_bytes=max_scan_bytes,
        )
        status = report["quota"]["status"]
        issues = report["scan"]["issues"]
        retryable = (
            status == "indeterminate"
            and bool(issues)
            and all(
                isinstance(issue, dict)
                and issue.get("code") in _TRANSIENT_SCAN_ISSUE_CODES
                for issue in issues
            )
        )
        if not retryable or attempt == transient_scan_retries:
            retries_used = attempt
            break
    if report is None:  # pragma: no cover - loop always runs once.
        raise AssertionError("storage quota inventory did not run")

    status = report["quota"]["status"]
    observed_bytes = report["total_bytes"]
    active_reservation_bytes = report["quota"][
        "active_reservation_bytes"
    ]
    projected_bytes = (
        observed_bytes + active_reservation_bytes + additional_bytes
    )
    report["quota"].update(
        {
            "additional_bytes": additional_bytes,
            "requested_bytes": additional_bytes,
            "projected_bytes": projected_bytes,
            "conservative_projected_bytes": projected_bytes,
            "transient_scan_retries_used": retries_used,
        }
    )
    if status == "exceeded":
        raise StorageQuotaError(
            f"challenge storage quota exceeded: "
            f"{observed_bytes + active_reservation_bytes} > "
            f"{quota_bytes} bytes"
        )
    if projected_bytes > quota_bytes:
        raise StorageQuotaError(
            "challenge storage quota would be exceeded by the requested "
            f"write: {projected_bytes} > {quota_bytes} bytes"
        )
    if status != "within":
        raise StorageQuotaError(
            "challenge storage quota cannot be proven because the bounded "
            "inventory is incomplete"
        )
    return report


def storage_plan(
    store: StateStore,
    identity: ChallengeIdentity,
    *,
    quota_bytes: int = DEFAULT_CHALLENGE_STORAGE_QUOTA_BYTES,
    max_entries: int = DEFAULT_STORAGE_SCAN_MAX_ENTRIES,
    max_scan_bytes: int = DEFAULT_STORAGE_SCAN_MAX_BYTES,
) -> dict[str, Any]:
    inventory = storage_inventory(
        store,
        identity,
        quota_bytes=quota_bytes,
        max_entries=max_entries,
        max_scan_bytes=max_scan_bytes,
    )
    if not inventory["scan_complete"]:
        raise StorageError(
            "storage scan is incomplete; refusing to plan garbage collection"
        )
    candidates = [
        item
        for item in inventory["files"]
        if item["storage_class"] == "noncanonical"
    ]
    return {
        "schema_version": 2,
        "identity": identity.key,
        "state_revision": inventory["state_revision"],
        "action": "quarantine",
        "permanent_delete_enabled": False,
        "quota": inventory["quota"],
        "candidates": candidates,
        "candidate_bytes": sum(item["bytes"] for item in candidates),
    }


def _digest_regular_at(
    directory_fd: int,
    name: str,
    *,
    expected_bytes: int,
    expected_sha256: str,
) -> os.stat_result:
    try:
        descriptor = os.open(name, _FILE_FLAGS, dir_fd=directory_fd)
    except OSError as error:
        raise StorageError(
            f"quarantine file is unsafe or missing: {name}"
        ) from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise StorageError(f"quarantine file is not regular: {name}")
        if before.st_nlink != 1:
            raise StorageError(f"quarantine file is hard-linked: {name}")
        if before.st_size != expected_bytes:
            raise StorageError(f"quarantine file size mismatch: {name}")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        pathname = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            _signature(before) != _signature(after)
            or _signature(after) != _signature(pathname)
        ):
            raise StorageError(f"quarantine file changed while hashing: {name}")
        if digest.hexdigest() != expected_sha256:
            raise StorageError(f"quarantine hash mismatch: {name}")
        return after
    finally:
        os.close(descriptor)


def _validate_manifest(
    value: object,
    *,
    identity: ChallengeIdentity,
    quarantine_id: str,
    allowed_statuses: frozenset[str],
) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
        raise StorageError("invalid quarantine manifest")
    expected_keys = {
        "schema_version",
        "quarantine_id",
        "identity",
        "state_revision",
        "status",
        "permanent_delete_enabled",
        "files",
    }
    if set(value) != expected_keys or value.get("schema_version") != 1:
        raise StorageError("invalid quarantine manifest schema")
    if value.get("quarantine_id") != quarantine_id:
        raise StorageError("invalid quarantine manifest")
    if value.get("identity") != identity.to_dict():
        raise StorageError("quarantine identity does not match challenge")
    if value.get("status") not in allowed_statuses:
        raise StorageError("quarantine status does not allow this operation")
    if value.get("permanent_delete_enabled") is not False:
        raise StorageError("quarantine manifest deletion policy is invalid")
    revision = value.get("state_revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise StorageError("invalid quarantine state revision")
    records = value.get("files")
    if (
        not isinstance(records, list)
        or len(records) > DEFAULT_STORAGE_SCAN_MAX_ENTRIES
    ):
        raise StorageError("invalid quarantine file records")
    validated: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in records:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "bytes"}:
            raise StorageError("invalid quarantine file record")
        relative = _safe_storage_relative(item.get("path")).as_posix()
        digest = item.get("sha256")
        size = item.get("bytes")
        if (
            relative in seen
            or not isinstance(digest, str)
            or _SHA256.fullmatch(digest) is None
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
        ):
            raise StorageError("invalid quarantine file record")
        seen.add(relative)
        validated.append(
            {
                "path": relative,
                "sha256": digest,
                "bytes": size,
            }
        )
    return validated


def _locked_inventory_plan(
    store: StateStore,
    identity: ChallengeIdentity,
    *,
    max_entries: int,
    max_scan_bytes: int,
) -> dict[str, Any]:
    state = store.read_snapshot(identity)
    inventory = _inventory_from_state(
        store,
        identity,
        state,
        quota_bytes=DEFAULT_CHALLENGE_STORAGE_QUOTA_BYTES,
        max_entries=max_entries,
        max_scan_bytes=max_scan_bytes,
    )
    if not inventory["scan_complete"]:
        raise StorageError(
            "storage scan is incomplete; refusing garbage collection"
        )
    candidates = [
        item
        for item in inventory["files"]
        if item["storage_class"] == "noncanonical"
    ]
    return {
        "state_revision": inventory["state_revision"],
        "candidates": candidates,
    }


def _acquire_mutation_locks(
    store: StateStore,
    identity: ChallengeIdentity,
    operation: str,
) -> tuple[Any, ChallengeLock, ChallengeLock]:
    paths = store.challenge_paths(identity)
    store.assert_mutations_allowed()
    session_lock = ChallengeLock(paths.runtime / "session.lock", timeout=0)
    state_lock = ChallengeLock(paths.lock, timeout=0)
    try:
        # Global lock order is session -> state.
        session_lock.acquire()
        state_lock.acquire()
    except BaseException as error:
        try:
            state_lock.release()
        except BaseException as cleanup_error:
            error.add_note(f"state lock cleanup failed: {cleanup_error}")
        try:
            session_lock.release()
        except BaseException as cleanup_error:
            error.add_note(f"session lock cleanup failed: {cleanup_error}")
        if isinstance(error, LockTimeout):
            raise StorageError(
                f"active challenge work blocks storage {operation}"
            ) from error
        raise
    return paths, session_lock, state_lock


def _release_mutation_locks(
    state_lock: ChallengeLock,
    session_lock: ChallengeLock,
) -> None:
    primary_error: BaseException | None = None
    try:
        state_lock.release()
    except BaseException as error:
        primary_error = error
    try:
        session_lock.release()
    except BaseException as error:
        if primary_error is None:
            primary_error = error
        else:
            primary_error.add_note(
                f"session lock cleanup failed: {error}"
            )
    if primary_error is not None:
        raise primary_error


def quarantine_unreachable(
    store: StateStore,
    identity: ChallengeIdentity,
    *,
    max_entries: int = DEFAULT_STORAGE_SCAN_MAX_ENTRIES,
    max_scan_bytes: int = DEFAULT_STORAGE_SCAN_MAX_BYTES,
) -> dict[str, Any]:
    max_entries = _positive_integer(max_entries, "max_entries")
    max_scan_bytes = _positive_integer(max_scan_bytes, "max_scan_bytes")
    paths, session_lock, state_lock = _acquire_mutation_locks(
        store,
        identity,
        "quarantine",
    )
    challenge_fd: int | None = None
    root_fd: int | None = None
    metadata_fd: int | None = None
    legacy_metadata = False
    files_fd: int | None = None
    quarantine_id: str | None = None
    initial_publish_started = False
    manifest_published = False
    try:
        _recover_abandoned_gc_transactions(
            paths,
            maximum_entries=max_entries,
        )
        plan = _locked_inventory_plan(
            store,
            identity,
            max_entries=max_entries,
            max_scan_bytes=max_scan_bytes,
        )
        if not plan["candidates"]:
            # An idempotent GC probe must not allocate an empty recovery
            # transaction. Otherwise harmless repeated probes can consume the
            # hard-bounded control-plane entry budget without moving a byte.
            return {
                "schema_version": 1,
                "quarantine_id": None,
                "identity": identity.to_dict(),
                "state_revision": plan["state_revision"],
                "status": "noop",
                "reason": "no_unreachable_files",
                "permanent_delete_enabled": False,
                "files": [],
            }
        quarantine_id = f"Q-{uuid.uuid4().hex}"
        # Validate every source and the complete recovery document before
        # allocating either half of the transaction.  Each source is checked
        # again immediately before rename below.
        challenge_fd = _open_challenge_root(paths)
        records: list[dict[str, Any]] = []
        for item in plan["candidates"]:
            relative = _safe_storage_relative(item["path"])
            parent_fd = _open_directory_path(
                challenge_fd,
                relative.parent.parts,
            )
            try:
                metadata = os.stat(
                    relative.name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise StorageError(
                        f"quarantine source is not a single-link regular file: "
                        f"{relative}"
                    )
                digest = hashlib.sha256()
                descriptor = os.open(
                    relative.name,
                    _FILE_FLAGS,
                    dir_fd=parent_fd,
                )
                try:
                    opened = os.fstat(descriptor)
                    while chunk := os.read(descriptor, 1024 * 1024):
                        digest.update(chunk)
                    after = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
                final = os.stat(
                    relative.name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                if (
                    _signature(metadata) != _signature(opened)
                    or _signature(opened) != _signature(after)
                    or _signature(after) != _signature(final)
                ):
                    raise StorageError(
                        f"quarantine source changed: {relative}"
                    )
                records.append(
                    {
                        "path": relative.as_posix(),
                        "sha256": digest.hexdigest(),
                        "bytes": metadata.st_size,
                    }
                )
            finally:
                os.close(parent_fd)

        manifest = {
            "schema_version": 1,
            "quarantine_id": quarantine_id,
            "identity": identity.to_dict(),
            "state_revision": plan["state_revision"],
            "status": "moving",
            "permanent_delete_enabled": False,
            "files": records,
        }
        if len(canonical_json_bytes(manifest)) > MAX_QUARANTINE_MANIFEST_BYTES:
            raise StorageError(
                "storage metadata exceeds "
                f"{MAX_QUARANTINE_MANIFEST_BYTES} bytes: manifest.json"
            )
        os.close(challenge_fd)
        challenge_fd = None
        _admit_new_gc_control_transaction(paths)

        # From the first mkdir through the durable initial manifest, any
        # failure must remove only the exact empty pre-publish shape.  This
        # guard starts before the first allocation because a helper may create
        # a directory and then fail before returning its descriptor.
        initial_publish_started = True
        try:
            challenge_fd, root_fd = _open_quarantine_root(
                paths,
                quarantine_id,
                create=True,
            )
            metadata_fd, legacy_metadata = _open_gc_metadata_root(
                paths,
                quarantine_id,
                root_fd,
                create=True,
            )
            files_fd = _open_directory_at(root_fd, "files", create=True)
            _atomic_write_gc_json(
                paths,
                metadata_fd,
                "manifest.json",
                manifest,
                maximum_bytes=MAX_QUARANTINE_MANIFEST_BYTES,
                legacy=legacy_metadata,
            )
            manifest_published = True
        except BaseException as error:
            cleanup_errors: list[BaseException] = []
            if files_fd is not None:
                try:
                    os.close(files_fd)
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
                files_fd = None
            if metadata_fd is not None:
                try:
                    os.close(metadata_fd)
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
                metadata_fd = None
            if root_fd is not None:
                try:
                    os.close(root_fd)
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
                root_fd = None
            if challenge_fd is not None:
                try:
                    os.close(challenge_fd)
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
                challenge_fd = None
            if initial_publish_started and not manifest_published:
                assert quarantine_id is not None
                try:
                    _remove_abandoned_gc_transaction(
                        paths,
                        quarantine_id,
                        maximum_entries=max_entries,
                    )
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
            for cleanup_error in cleanup_errors:
                error.add_note(
                    "unpublished quarantine cleanup failed: "
                    f"{cleanup_error}"
                )
            raise
        moved: list[dict[str, Any]] = []
        try:
            for record in records:
                relative = _safe_storage_relative(record["path"])
                source_parent = _open_directory_path(
                    challenge_fd,
                    relative.parent.parts,
                )
                destination_parent = _open_directory_path(
                    files_fd,
                    relative.parent.parts,
                    create=True,
                )
                try:
                    source = _digest_regular_at(
                        source_parent,
                        relative.name,
                        expected_bytes=record["bytes"],
                        expected_sha256=record["sha256"],
                    )
                    try:
                        os.stat(
                            relative.name,
                            dir_fd=destination_parent,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        pass
                    else:
                        raise StorageError(
                            f"quarantine destination exists: {relative}"
                        )
                    if source.st_dev != os.fstat(destination_parent).st_dev:
                        raise StorageError(
                            "quarantine must remain on one filesystem"
                        )
                    os.rename(
                        relative.name,
                        relative.name,
                        src_dir_fd=source_parent,
                        dst_dir_fd=destination_parent,
                    )
                    # From this point rollback owns the destination even if
                    # the post-rename validation is interrupted.
                    moved.append(record)
                    os.fsync(source_parent)
                    os.fsync(destination_parent)
                    _digest_regular_at(
                        destination_parent,
                        relative.name,
                        expected_bytes=record["bytes"],
                        expected_sha256=record["sha256"],
                    )
                finally:
                    os.close(source_parent)
                    os.close(destination_parent)
            manifest["status"] = "quarantined"
            _atomic_write_gc_json(
                paths,
                metadata_fd,
                "manifest.json",
                manifest,
                maximum_bytes=MAX_QUARANTINE_MANIFEST_BYTES,
                legacy=legacy_metadata,
            )
            return manifest
        except BaseException as error:
            for record in reversed(moved):
                relative = _safe_storage_relative(record["path"])
                source_parent = _open_directory_path(
                    files_fd,
                    relative.parent.parts,
                )
                destination_parent = _open_directory_path(
                    challenge_fd,
                    relative.parent.parts,
                    create=True,
                )
                try:
                    try:
                        os.stat(
                            relative.name,
                            dir_fd=destination_parent,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        os.rename(
                            relative.name,
                            relative.name,
                            src_dir_fd=source_parent,
                            dst_dir_fd=destination_parent,
                        )
                        os.fsync(source_parent)
                        os.fsync(destination_parent)
                finally:
                    os.close(source_parent)
                    os.close(destination_parent)
            try:
                manifest["status"] = "rolled_back"
                _atomic_write_gc_json(
                    paths,
                    metadata_fd,
                    "manifest.json",
                    manifest,
                    maximum_bytes=MAX_QUARANTINE_MANIFEST_BYTES,
                    legacy=legacy_metadata,
                )
            except BaseException as manifest_error:
                error.add_note(
                    f"quarantine rollback manifest failed: {manifest_error}"
                )
            raise
    finally:
        if files_fd is not None:
            os.close(files_fd)
        if metadata_fd is not None:
            os.close(metadata_fd)
        if root_fd is not None:
            os.close(root_fd)
        if challenge_fd is not None:
            os.close(challenge_fd)
        _release_mutation_locks(state_lock, session_lock)


def _load_purge_state(root_fd: int) -> dict[str, Any] | None:
    try:
        value, _payload = _read_json_at(
            root_fd,
            "purge.json",
            maximum_bytes=MAX_PURGE_STATE_BYTES,
        )
    except StorageError as error:
        if isinstance(error.__cause__, FileNotFoundError):
            return None
        raise
    if not isinstance(value, dict):
        raise StorageError("invalid quarantine purge state")
    return value


def _confirmation(
    identity: ChallengeIdentity,
    quarantine_id: str,
    manifest_sha256: str,
) -> str:
    return f"PURGE {identity.key} {quarantine_id} {manifest_sha256}"


def _validated_purge_state(
    value: object,
    *,
    identity: ChallengeIdentity,
    quarantine_id: str,
    manifest_sha256: str,
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StorageError("invalid quarantine purge state")
    expected_keys = {
        "schema_version",
        "identity",
        "quarantine_id",
        "manifest_sha256",
        "confirmation",
        "status",
        "files",
        "completed",
        "active_path",
        "reclaimed_bytes",
    }
    if set(value) != expected_keys or value.get("schema_version") != 1:
        raise StorageError("invalid quarantine purge state schema")
    expected_confirmation = _confirmation(
        identity,
        quarantine_id,
        manifest_sha256,
    )
    if (
        value.get("identity") != identity.to_dict()
        or value.get("quarantine_id") != quarantine_id
        or value.get("manifest_sha256") != manifest_sha256
        or value.get("confirmation") != expected_confirmation
        or value.get("files") != records
        or value.get("status")
        not in {
            "prepared",
            "purging",
            "purged",
            "faulted",
            "cancelled_by_restore",
        }
    ):
        raise StorageError("quarantine purge state binding is invalid")
    completed = value.get("completed")
    paths = [item["path"] for item in records]
    if (
        not isinstance(completed, list)
        or not all(isinstance(item, str) for item in completed)
        or len(completed) != len(set(completed))
        or any(item not in paths for item in completed)
    ):
        raise StorageError("invalid quarantine purge progress")
    active_path = value.get("active_path")
    if active_path is not None and active_path not in paths:
        raise StorageError("invalid active quarantine purge path")
    reclaimed = value.get("reclaimed_bytes")
    expected_reclaimed = sum(
        item["bytes"] for item in records if item["path"] in completed
    )
    if (
        isinstance(reclaimed, bool)
        or not isinstance(reclaimed, int)
        or reclaimed != expected_reclaimed
    ):
        raise StorageError("invalid quarantine reclaimed byte count")
    return dict(value)


def prepare_quarantine_purge(
    store: StateStore,
    identity: ChallengeIdentity,
    quarantine_id: str,
    *,
    max_verify_bytes: int = DEFAULT_STORAGE_SCAN_MAX_BYTES,
) -> dict[str, Any]:
    quarantine_id = _validate_quarantine_id(quarantine_id)
    max_verify_bytes = _positive_integer(max_verify_bytes, "max_verify_bytes")
    paths, session_lock, state_lock = _acquire_mutation_locks(
        store,
        identity,
        "purge preparation",
    )
    challenge_fd: int | None = None
    root_fd: int | None = None
    metadata_fd: int | None = None
    legacy_metadata = False
    files_fd: int | None = None
    try:
        _assert_quarantine_unreferenced(
            store,
            identity,
            quarantine_id,
        )
        challenge_fd, root_fd = _open_quarantine_root(paths, quarantine_id)
        metadata_fd, legacy_metadata = _open_gc_metadata_root(
            paths,
            quarantine_id,
            root_fd,
        )
        manifest, manifest_payload = _read_json_at(
            metadata_fd,
            "manifest.json",
        )
        records = _validate_manifest(
            manifest,
            identity=identity,
            quarantine_id=quarantine_id,
            allowed_statuses=frozenset({"quarantined"}),
        )
        manifest_sha256 = hashlib.sha256(manifest_payload).hexdigest()
        total_bytes = sum(item["bytes"] for item in records)
        if total_bytes > max_verify_bytes:
            raise StorageError(
                "quarantine exceeds the bounded purge verification limit"
            )
        existing = _load_purge_state(metadata_fd)
        if existing is not None:
            prepared = _validated_purge_state(
                existing,
                identity=identity,
                quarantine_id=quarantine_id,
                manifest_sha256=manifest_sha256,
                records=records,
            )
            if prepared["status"] == "cancelled_by_restore":
                raise StorageError("purge preparation was cancelled by restore")
            if prepared["status"] == "faulted":
                raise StorageError(
                    "quarantine purge is faulted and requires operator review"
                )
            # A prepared record is reverified below.  Once deletion has
            # started, prepare is a read-only status operation; only the
            # confirmation-bound purge call may resume it.
            if prepared["status"] in {"purging", "purged"}:
                return {
                    "schema_version": 1,
                    "identity": identity.key,
                    "quarantine_id": quarantine_id,
                    "manifest_sha256": manifest_sha256,
                    "confirmation": prepared["confirmation"],
                    "status": prepared["status"],
                    "file_count": len(records),
                    "bytes": total_bytes,
                    "permanent_delete_performed": (
                        prepared["status"] == "purged"
                    ),
                }
        else:
            prepared = {
                "schema_version": 1,
                "identity": identity.to_dict(),
                "quarantine_id": quarantine_id,
                "manifest_sha256": manifest_sha256,
                "confirmation": _confirmation(
                    identity,
                    quarantine_id,
                    manifest_sha256,
                ),
                "status": "prepared",
                "files": records,
                "completed": [],
                "active_path": None,
                "reclaimed_bytes": 0,
            }

        files_fd = _open_directory_at(root_fd, "files")
        physical_files = _scan_regular_tree_at(
            files_fd,
            max_entries=DEFAULT_STORAGE_SCAN_MAX_ENTRIES,
            max_bytes=max_verify_bytes,
        )
        expected_files = {
            item["path"]: item["bytes"] for item in records
        }
        if physical_files != expected_files:
            raise StorageError(
                "quarantine files do not exactly match the manifest"
            )
        for record in records:
            relative = _safe_storage_relative(record["path"])
            parent_fd = _open_directory_path(
                files_fd,
                relative.parent.parts,
            )
            try:
                _digest_regular_at(
                    parent_fd,
                    relative.name,
                    expected_bytes=record["bytes"],
                    expected_sha256=record["sha256"],
                )
            finally:
                os.close(parent_fd)

        if existing is None:
            _atomic_write_gc_json(
                paths,
                metadata_fd,
                "purge.json",
                prepared,
                maximum_bytes=MAX_PURGE_STATE_BYTES,
                legacy=legacy_metadata,
            )
        return {
            "schema_version": 1,
            "identity": identity.key,
            "quarantine_id": quarantine_id,
            "manifest_sha256": manifest_sha256,
            "confirmation": prepared["confirmation"],
            "status": prepared["status"],
            "file_count": len(records),
            "bytes": total_bytes,
            "permanent_delete_performed": (
                prepared["status"] == "purged"
            ),
        }
    finally:
        if files_fd is not None:
            os.close(files_fd)
        if metadata_fd is not None:
            os.close(metadata_fd)
        if root_fd is not None:
            os.close(root_fd)
        if challenge_fd is not None:
            os.close(challenge_fd)
        _release_mutation_locks(state_lock, session_lock)


def _path_presence(directory_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _unlink_tombstone(
    tombstone_fd: int,
    tombstone_name: str,
    *,
    expected_bytes: int,
    expected_sha256: str,
) -> None:
    try:
        descriptor = os.open(
            tombstone_name,
            _FILE_FLAGS,
            dir_fd=tombstone_fd,
        )
    except OSError as error:
        raise StorageError("purge tombstone is unsafe or missing") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != expected_bytes
        ):
            raise StorageError("purge tombstone is not a safe regular file")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        pathname = os.stat(
            tombstone_name,
            dir_fd=tombstone_fd,
            follow_symlinks=False,
        )
        if (
            _signature(before) != _signature(after)
            or _signature(after) != _signature(pathname)
            or digest.hexdigest() != expected_sha256
        ):
            raise StorageError("purge tombstone binding mismatch")
        os.unlink(tombstone_name, dir_fd=tombstone_fd)
        os.fsync(tombstone_fd)
        unlinked = os.fstat(descriptor)
        if (
            unlinked.st_dev != before.st_dev
            or unlinked.st_ino != before.st_ino
            or unlinked.st_nlink != 0
        ):
            raise _PurgeAttestationError(
                "purge tombstone unlink did not reclaim the bound inode"
            )
    finally:
        os.close(descriptor)


def purge_quarantine(
    store: StateStore,
    identity: ChallengeIdentity,
    quarantine_id: str,
    *,
    manifest_sha256: str,
    confirmation: str,
) -> dict[str, Any]:
    """Permanently delete one prepared quarantine and reclaim its file bytes.

    The quarantine manifest and compact purge state remain as an audit record.
    Calling this function again with the same bindings is idempotent.
    """

    quarantine_id = _validate_quarantine_id(quarantine_id)
    if (
        not isinstance(manifest_sha256, str)
        or _SHA256.fullmatch(manifest_sha256) is None
    ):
        raise StorageError("invalid quarantine manifest digest")
    if not isinstance(confirmation, str) or confirmation != _confirmation(
        identity,
        quarantine_id,
        manifest_sha256,
    ):
        raise StorageError("purge confirmation does not match exact binding")
    paths, session_lock, state_lock = _acquire_mutation_locks(
        store,
        identity,
        "purge",
    )
    challenge_fd: int | None = None
    root_fd: int | None = None
    metadata_fd: int | None = None
    legacy_metadata = False
    files_fd: int | None = None
    tombstone_fd: int | None = None
    try:
        _assert_quarantine_unreferenced(
            store,
            identity,
            quarantine_id,
        )
        challenge_fd, root_fd = _open_quarantine_root(paths, quarantine_id)
        metadata_fd, legacy_metadata = _open_gc_metadata_root(
            paths,
            quarantine_id,
            root_fd,
        )
        manifest, manifest_payload = _read_json_at(
            metadata_fd,
            "manifest.json",
        )
        records = _validate_manifest(
            manifest,
            identity=identity,
            quarantine_id=quarantine_id,
            allowed_statuses=frozenset({"quarantined"}),
        )
        actual_manifest_sha256 = hashlib.sha256(manifest_payload).hexdigest()
        if actual_manifest_sha256 != manifest_sha256:
            raise StorageError("quarantine manifest digest changed")
        raw_purge = _load_purge_state(metadata_fd)
        if raw_purge is None:
            raise StorageError("quarantine purge must be prepared first")
        purge = _validated_purge_state(
            raw_purge,
            identity=identity,
            quarantine_id=quarantine_id,
            manifest_sha256=manifest_sha256,
            records=records,
        )
        if purge["confirmation"] != confirmation:
            raise StorageError("purge confirmation is not the prepared value")
        if purge["status"] == "cancelled_by_restore":
            raise StorageError("purge preparation was cancelled by restore")
        if purge["status"] == "faulted":
            raise StorageError(
                "quarantine purge is faulted and requires operator review"
            )
        if purge["status"] == "purged":
            files_fd = _open_directory_at(root_fd, "files")
            tombstone_fd = _open_directory_at(root_fd, ".purging")
            if _scan_regular_tree_at(
                files_fd,
                max_entries=DEFAULT_STORAGE_SCAN_MAX_ENTRIES,
                max_bytes=DEFAULT_STORAGE_SCAN_MAX_BYTES,
            ) or _scan_regular_tree_at(
                tombstone_fd,
                max_entries=DEFAULT_STORAGE_SCAN_MAX_ENTRIES,
                max_bytes=DEFAULT_STORAGE_SCAN_MAX_BYTES,
            ):
                raise StorageError(
                    "purged quarantine contains recreated file data"
                )
            return {
                "schema_version": 1,
                "identity": identity.key,
                "quarantine_id": quarantine_id,
                "manifest_sha256": manifest_sha256,
                "status": "purged",
                "purged": list(purge["completed"]),
                "reclaimed_bytes": purge["reclaimed_bytes"],
                "permanent_delete_performed": True,
                "already_purged": True,
            }

        files_fd = _open_directory_at(root_fd, "files")
        tombstone_fd = _open_directory_at(
            root_fd,
            ".purging",
            create=True,
        )
        purge["status"] = "purging"
        _atomic_write_gc_json(
            paths,
            metadata_fd,
            "purge.json",
            purge,
            maximum_bytes=MAX_PURGE_STATE_BYTES,
            legacy=legacy_metadata,
        )
        completed = set(purge["completed"])
        for index, record in enumerate(records):
            relative = _safe_storage_relative(record["path"])
            tombstone_name = (
                f"{index:08d}-{record['sha256'][:16]}.pending"
            )
            source_parent = _open_directory_path(
                files_fd,
                relative.parent.parts,
            )
            try:
                source = _path_presence(source_parent, relative.name)
                tombstone = _path_presence(
                    tombstone_fd,
                    tombstone_name,
                )
                if relative.as_posix() in completed:
                    if source is not None or tombstone is not None:
                        raise StorageError(
                            f"completed purge path was recreated: {relative}"
                        )
                    continue

                if purge["active_path"] not in {
                    None,
                    relative.as_posix(),
                }:
                    raise StorageError(
                        "purge progress has an inconsistent active path"
                    )
                resuming_active = (
                    purge["active_path"] == relative.as_posix()
                )
                if (
                    not resuming_active
                    and source is None
                    and tombstone is None
                ):
                    raise StorageError(
                        f"quarantine purge source is missing: {relative}"
                    )
                if purge["active_path"] is None:
                    purge["active_path"] = relative.as_posix()
                    _atomic_write_gc_json(
                        paths,
                        metadata_fd,
                        "purge.json",
                        purge,
                        maximum_bytes=MAX_PURGE_STATE_BYTES,
                        legacy=legacy_metadata,
                    )

                if source is not None and tombstone is not None:
                    raise StorageError(
                        f"ambiguous purge source and tombstone: {relative}"
                    )
                if source is not None:
                    if (
                        not stat.S_ISREG(source.st_mode)
                        or source.st_nlink != 1
                        or source.st_size != record["bytes"]
                    ):
                        raise StorageError(
                            f"unsafe purge source: {relative}"
                        )
                    os.rename(
                        relative.name,
                        tombstone_name,
                        src_dir_fd=source_parent,
                        dst_dir_fd=tombstone_fd,
                    )
                    os.fsync(source_parent)
                    os.fsync(tombstone_fd)
                    tombstone = _path_presence(
                        tombstone_fd,
                        tombstone_name,
                    )
                if tombstone is not None:
                    try:
                        _unlink_tombstone(
                            tombstone_fd,
                            tombstone_name,
                            expected_bytes=record["bytes"],
                            expected_sha256=record["sha256"],
                        )
                    except _PurgeAttestationError as error:
                        purge["status"] = "faulted"
                        try:
                            _atomic_write_gc_json(
                                paths,
                                metadata_fd,
                                "purge.json",
                                purge,
                                maximum_bytes=MAX_PURGE_STATE_BYTES,
                                legacy=legacy_metadata,
                            )
                        except BaseException as persist_error:
                            error.add_note(
                                "purge fault persistence failed: "
                                f"{persist_error}"
                            )
                        raise
                elif not resuming_active:
                    raise StorageError(
                        f"quarantine purge source is missing: {relative}"
                    )
                # Both absent with this exact durable active_path means a
                # previous process died after unlink and before progress commit.
                completed.add(relative.as_posix())
                purge["completed"] = [
                    item["path"]
                    for item in records
                    if item["path"] in completed
                ]
                purge["active_path"] = None
                purge["reclaimed_bytes"] = sum(
                    item["bytes"]
                    for item in records
                    if item["path"] in completed
                )
                _atomic_write_gc_json(
                    paths,
                    metadata_fd,
                    "purge.json",
                    purge,
                    maximum_bytes=MAX_PURGE_STATE_BYTES,
                    legacy=legacy_metadata,
                )
            finally:
                os.close(source_parent)

        if _scan_regular_tree_at(
            files_fd,
            max_entries=DEFAULT_STORAGE_SCAN_MAX_ENTRIES,
            max_bytes=DEFAULT_STORAGE_SCAN_MAX_BYTES,
        ) or _scan_regular_tree_at(
            tombstone_fd,
            max_entries=DEFAULT_STORAGE_SCAN_MAX_ENTRIES,
            max_bytes=DEFAULT_STORAGE_SCAN_MAX_BYTES,
        ):
            raise StorageError(
                "quarantine contains unmanifested file data after purge"
            )
        purge["status"] = "purged"
        purge["active_path"] = None
        _atomic_write_gc_json(
            paths,
            metadata_fd,
            "purge.json",
            purge,
            maximum_bytes=MAX_PURGE_STATE_BYTES,
            legacy=legacy_metadata,
        )
        return {
            "schema_version": 1,
            "identity": identity.key,
            "quarantine_id": quarantine_id,
            "manifest_sha256": manifest_sha256,
            "status": "purged",
            "purged": list(purge["completed"]),
            "reclaimed_bytes": purge["reclaimed_bytes"],
            "permanent_delete_performed": True,
            "already_purged": False,
        }
    finally:
        if tombstone_fd is not None:
            os.close(tombstone_fd)
        if files_fd is not None:
            os.close(files_fd)
        if metadata_fd is not None:
            os.close(metadata_fd)
        if root_fd is not None:
            os.close(root_fd)
        if challenge_fd is not None:
            os.close(challenge_fd)
        _release_mutation_locks(state_lock, session_lock)


def restore_quarantine(
    store: StateStore,
    identity: ChallengeIdentity,
    quarantine_id: str,
) -> dict[str, Any]:
    quarantine_id = _validate_quarantine_id(quarantine_id)
    paths, session_lock, state_lock = _acquire_mutation_locks(
        store,
        identity,
        "restore",
    )
    challenge_fd: int | None = None
    root_fd: int | None = None
    metadata_fd: int | None = None
    legacy_metadata = False
    files_fd: int | None = None
    try:
        _assert_quarantine_unreferenced(
            store,
            identity,
            quarantine_id,
        )
        challenge_fd, root_fd = _open_quarantine_root(paths, quarantine_id)
        metadata_fd, legacy_metadata = _open_gc_metadata_root(
            paths,
            quarantine_id,
            root_fd,
        )
        manifest, manifest_payload = _read_json_at(
            metadata_fd,
            "manifest.json",
        )
        records = _validate_manifest(
            manifest,
            identity=identity,
            quarantine_id=quarantine_id,
            allowed_statuses=frozenset(
                {
                    "moving",
                    "quarantined",
                    "rolled_back",
                    "restored",
                }
            ),
        )
        manifest_sha256 = hashlib.sha256(manifest_payload).hexdigest()
        purge = _load_purge_state(metadata_fd)
        if purge is not None:
            purge_manifest_sha256 = (
                purge.get("manifest_sha256")
                if isinstance(purge, dict)
                else None
            )
            if (
                not isinstance(purge_manifest_sha256, str)
                or _SHA256.fullmatch(purge_manifest_sha256) is None
            ):
                raise StorageError("invalid quarantine purge state digest")
            bound = _validated_purge_state(
                purge,
                identity=identity,
                quarantine_id=quarantine_id,
                manifest_sha256=purge_manifest_sha256,
                records=records,
            )
            if (
                manifest.get("status") == "quarantined"
                and purge_manifest_sha256 != manifest_sha256
            ):
                raise StorageError(
                    "quarantine manifest changed after purge preparation"
                )
            if bound["status"] in {"purging", "purged", "faulted"}:
                raise StorageError(
                    "partially or fully purged quarantine cannot be restored"
                )
            if bound["status"] == "prepared":
                bound["status"] = "cancelled_by_restore"
                _atomic_write_gc_json(
                    paths,
                    metadata_fd,
                    "purge.json",
                    bound,
                    maximum_bytes=MAX_PURGE_STATE_BYTES,
                    legacy=legacy_metadata,
                )

        files_fd = _open_directory_at(root_fd, "files")
        restored: list[str] = []
        for item in records:
            relative = _safe_storage_relative(item["path"])
            source_parent = _open_directory_path(
                files_fd,
                relative.parent.parts,
            )
            destination_parent = _open_directory_path(
                challenge_fd,
                relative.parent.parts,
                create=True,
            )
            try:
                source = _path_presence(source_parent, relative.name)
                destination = _path_presence(
                    destination_parent,
                    relative.name,
                )
                if source is None:
                    if destination is None:
                        raise StorageError(
                            f"quarantine source is missing: {relative}"
                        )
                    _digest_regular_at(
                        destination_parent,
                        relative.name,
                        expected_bytes=item["bytes"],
                        expected_sha256=item["sha256"],
                    )
                    continue
                if destination is not None:
                    raise StorageError(
                        f"restore destination exists: {relative}"
                    )
                _digest_regular_at(
                    source_parent,
                    relative.name,
                    expected_bytes=item["bytes"],
                    expected_sha256=item["sha256"],
                )
                os.rename(
                    relative.name,
                    relative.name,
                    src_dir_fd=source_parent,
                    dst_dir_fd=destination_parent,
                )
                os.fsync(source_parent)
                os.fsync(destination_parent)
                try:
                    _digest_regular_at(
                        destination_parent,
                        relative.name,
                        expected_bytes=item["bytes"],
                        expected_sha256=item["sha256"],
                    )
                except BaseException:
                    if (
                        _path_presence(source_parent, relative.name) is None
                        and _path_presence(
                            destination_parent,
                            relative.name,
                        )
                        is not None
                    ):
                        os.rename(
                            relative.name,
                            relative.name,
                            src_dir_fd=destination_parent,
                            dst_dir_fd=source_parent,
                        )
                        os.fsync(destination_parent)
                        os.fsync(source_parent)
                    raise
                restored.append(relative.as_posix())
            finally:
                os.close(source_parent)
                os.close(destination_parent)
        manifest["status"] = "restored"
        _atomic_write_gc_json(
            paths,
            metadata_fd,
            "manifest.json",
            manifest,
            maximum_bytes=MAX_QUARANTINE_MANIFEST_BYTES,
            legacy=legacy_metadata,
        )
        return {
            "quarantine_id": quarantine_id,
            "restored": restored,
            "permanent_delete_performed": False,
        }
    finally:
        if files_fd is not None:
            os.close(files_fd)
        if metadata_fd is not None:
            os.close(metadata_fd)
        if root_fd is not None:
            os.close(root_fd)
        if challenge_fd is not None:
            os.close(challenge_fd)
        _release_mutation_locks(state_lock, session_lock)


__all__ = [
    "DEFAULT_CHALLENGE_STORAGE_QUOTA_BYTES",
    "DEFAULT_STORAGE_SCAN_MAX_BYTES",
    "DEFAULT_STORAGE_SCAN_MAX_ENTRIES",
    "DEFAULT_STORAGE_TRANSIENT_SCAN_RETRIES",
    "StorageError",
    "StorageQuotaError",
    "enforce_storage_quota",
    "prepare_quarantine_purge",
    "purge_quarantine",
    "quarantine_unreachable",
    "restore_quarantine",
    "storage_inventory",
    "storage_plan",
]
