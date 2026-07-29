"""Bounded, race-aware copies from challenge-writable file trees."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol

DEFAULT_WORK_TREE_MAX_BYTES = 16 * 1024 * 1024 * 1024
DEFAULT_SNAPSHOT_MAX_BYTES = DEFAULT_WORK_TREE_MAX_BYTES
DEFAULT_STREAM_CAPTURE_MAX_BYTES = 16 * 1024 * 1024
MAX_WORK_TREE_ENTRIES = 100_000
MAX_WORK_TREE_DEPTH = 256
_COPY_CHUNK_BYTES = 1024 * 1024
_DescriptorIdentity = tuple[int, int, int, int]
_OwnedDescriptors = dict[int, _DescriptorIdentity]


class SafeFileError(ValueError):
    """A source or destination violated the immutable-copy contract."""


class WorkTreeLimitError(SafeFileError):
    """A conservatively measured work tree exceeded its configured bound."""

    def __init__(
        self,
        *,
        maximum_bytes: int,
        observed_bytes: int,
        locator: str,
    ) -> None:
        self.maximum_bytes = maximum_bytes
        self.observed_bytes = observed_bytes
        self.locator = locator
        super().__init__(
            "work tree exceeds its accounted byte limit: "
            f"at least {observed_bytes} > {maximum_bytes} bytes"
            + (f" at {locator!r}" if locator else "")
        )


@dataclass(frozen=True, slots=True)
class ImmutableFile:
    path: Path
    source_locator: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class WorkTreeUsage:
    """Stable, conservative accounting for one challenge work tree.

    ``accounted_bytes`` uses the larger of logical length and allocated blocks
    for every entry.  Sparse files therefore consume their full logical length,
    hard-linked names are counted separately, and symlinks are counted but
    never followed.  This is a pre/post execution guard, not a live filesystem
    quota: a command may transiently exceed the bound before its container
    exits and the post-check runs.
    """

    accounted_bytes: int
    logical_bytes: int
    allocated_bytes: int
    entries: int


@dataclass(frozen=True, slots=True)
class _WorkTreeSnapshot:
    usage: WorkTreeUsage
    fingerprint: str


class _Digest(Protocol):
    def update(self, data: bytes, /) -> None: ...


def _descriptor_identity(descriptor: int) -> _DescriptorIdentity:
    metadata = os.fstat(descriptor)
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_rdev,
    )


def _track_descriptor(
    owned: _OwnedDescriptors,
    descriptor: int,
) -> int:
    try:
        owned[descriptor] = _descriptor_identity(descriptor)
    except BaseException as error:
        # The caller has transferred the raw descriptor into this helper, but
        # the handoff may have failed immediately before or after publication.
        # Retire either state and consume it exactly once before propagating.
        owned.pop(descriptor, None)
        try:
            os.close(descriptor)
        except BaseException as cleanup_error:
            if (
                isinstance(error, Exception)
                and not isinstance(cleanup_error, Exception)
            ):
                cleanup_error.add_note(
                    "untracked descriptor cleanup interrupted while handling "
                    f"{type(error).__name__}: {error}"
                )
                raise cleanup_error
            error.add_note(
                "untracked descriptor handoff cleanup failed: "
                f"{type(cleanup_error).__name__}: {cleanup_error}"
            )
        raise
    return descriptor


def _close_owned_descriptor(
    owned: _OwnedDescriptors,
    descriptor: int,
) -> None:
    """Consume tracked ownership and attempt exactly one raw-fd close."""

    del owned[descriptor]
    # A post-close identity check cannot distinguish a same-inode descriptor
    # concurrently reopened at this number.  Never restore or retry it.
    os.close(descriptor)
    return None


def _close_owned_descriptors(owned: _OwnedDescriptors) -> None:
    errors: list[BaseException] = []
    for descriptor in tuple(owned):
        try:
            _close_owned_descriptor(owned, descriptor)
        except BaseException as error:
            errors.append(error)
    if not errors:
        return
    primary_error = next(
        (
            error
            for error in errors
            if not isinstance(error, Exception)
        ),
        errors[0],
    )
    for error in errors:
        if error is primary_error:
            continue
        primary_error.add_note(
            "additional tracked descriptor close failed: "
            f"{type(error).__name__}: {error}"
        )
    raise primary_error


def _resolve_cleanup_errors(
    active_error: BaseException | None,
    cleanup_errors: list[tuple[str, BaseException]],
    *,
    context: str,
) -> None:
    """Preserve a control interruption while reporting every cleanup error."""

    if not cleanup_errors:
        return
    if active_error is not None and not isinstance(active_error, Exception):
        for label, error in cleanup_errors:
            active_error.add_note(
                f"{context} {label} cleanup failed: "
                f"{type(error).__name__}: {error}"
            )
        return

    interruption_entry = next(
        (
            entry
            for entry in cleanup_errors
            if not isinstance(entry[1], Exception)
        ),
        None,
    )
    primary_label, primary_error = (
        interruption_entry
        if interruption_entry is not None
        else cleanup_errors[0]
    )
    for label, error in cleanup_errors:
        if error is primary_error:
            continue
        primary_error.add_note(
            f"{context} {label} cleanup also failed: "
            f"{type(error).__name__}: {error}"
        )

    if interruption_entry is not None:
        if active_error is not None:
            primary_error.add_note(
                f"{context} cleanup interrupted while handling "
                f"{type(active_error).__name__}: {active_error}"
            )
        raise primary_error
    if active_error is not None:
        active_error.add_note(
            f"{context} {primary_label} cleanup failed: "
            f"{type(primary_error).__name__}: {primary_error}"
        )
        return
    raise primary_error


def _validate_maximum_bytes(maximum_bytes: int) -> None:
    if (
        isinstance(maximum_bytes, bool)
        or not isinstance(maximum_bytes, int)
        or maximum_bytes <= 0
    ):
        raise ValueError("maximum_bytes must be positive")


def _stable_metadata(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        getattr(metadata, "st_blocks", 0),
    )


def _update_tree_fingerprint(
    digest: _Digest,
    parts: tuple[str, ...],
    metadata: os.stat_result,
) -> None:
    for part in parts:
        encoded = os.fsencode(part)
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    digest.update(b"\0")
    digest.update(repr(_stable_metadata(metadata)).encode("ascii"))
    digest.update(b"\n")


def _scan_work_tree_once(root: Path, maximum_bytes: int) -> _WorkTreeSnapshot:
    """Measure one tree using directory descriptors without following links."""

    directory_flags = os.O_RDONLY | os.O_CLOEXEC
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        root_before = Path(root).stat(follow_symlinks=False)
    except OSError as error:
        raise SafeFileError("work tree cannot be inspected") from error
    if not stat.S_ISDIR(root_before.st_mode):
        raise SafeFileError("work tree root is not a non-symlink directory")
    try:
        root_descriptor = os.open(Path(root), directory_flags)
    except OSError as error:
        raise SafeFileError("work tree cannot be opened safely") from error

    logical_bytes = 0
    allocated_bytes = 0
    accounted_bytes = 0
    entry_count = 0
    digest = hashlib.sha256()

    def visit(
        directory_descriptor: int,
        parts: tuple[str, ...],
        depth: int,
    ) -> None:
        nonlocal accounted_bytes
        nonlocal allocated_bytes
        nonlocal entry_count
        nonlocal logical_bytes

        if depth > MAX_WORK_TREE_DEPTH:
            raise SafeFileError(
                f"work tree nesting exceeds {MAX_WORK_TREE_DEPTH} directories"
            )
        before = os.fstat(directory_descriptor)
        if not stat.S_ISDIR(before.st_mode):
            raise SafeFileError("work tree directory changed while measuring")
        _update_tree_fingerprint(digest, parts, before)
        try:
            with os.scandir(directory_descriptor) as iterator:
                entries: list[os.DirEntry[str]] = []
                for entry in iterator:
                    entry_count += 1
                    if entry_count > MAX_WORK_TREE_ENTRIES:
                        raise SafeFileError(
                            "work tree exceeds "
                            f"{MAX_WORK_TREE_ENTRIES} entries"
                        )
                    entries.append(entry)
                entries.sort(key=lambda entry: os.fsencode(entry.name))
        except OSError as error:
            raise SafeFileError("work tree cannot be enumerated safely") from error

        for entry in entries:
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise SafeFileError(
                    "work tree changed while measuring"
                ) from error
            entry_parts = (*parts, entry.name)
            _update_tree_fingerprint(digest, entry_parts, metadata)
            logical = max(metadata.st_size, 0)
            allocated = max(getattr(metadata, "st_blocks", 0) * 512, 0)
            logical_bytes += logical
            allocated_bytes += allocated
            accounted_bytes += max(logical, allocated)
            if accounted_bytes > maximum_bytes:
                raise WorkTreeLimitError(
                    maximum_bytes=maximum_bytes,
                    observed_bytes=accounted_bytes,
                    locator="/".join(entry_parts),
                )

            if stat.S_ISDIR(metadata.st_mode):
                try:
                    child_descriptor = os.open(
                        entry.name,
                        directory_flags,
                        dir_fd=directory_descriptor,
                    )
                except OSError as error:
                    raise SafeFileError(
                        "work tree directory changed while opening"
                    ) from error
                try:
                    opened = os.fstat(child_descriptor)
                    if (
                        not stat.S_ISDIR(opened.st_mode)
                        or (opened.st_dev, opened.st_ino)
                        != (metadata.st_dev, metadata.st_ino)
                    ):
                        raise SafeFileError(
                            "work tree directory changed while opening"
                        )
                    visit(child_descriptor, entry_parts, depth + 1)
                finally:
                    os.close(child_descriptor)

        after = os.fstat(directory_descriptor)
        if _stable_metadata(after) != _stable_metadata(before):
            raise SafeFileError("work tree changed while measuring")

    try:
        opened_root = os.fstat(root_descriptor)
        if (
            not stat.S_ISDIR(opened_root.st_mode)
            or (opened_root.st_dev, opened_root.st_ino)
            != (root_before.st_dev, root_before.st_ino)
        ):
            raise SafeFileError("work tree root changed while opening")
        visit(root_descriptor, (), 0)
    except OSError as error:
        raise SafeFileError("work tree cannot be measured safely") from error
    finally:
        os.close(root_descriptor)

    return _WorkTreeSnapshot(
        usage=WorkTreeUsage(
            accounted_bytes=accounted_bytes,
            logical_bytes=logical_bytes,
            allocated_bytes=allocated_bytes,
            entries=entry_count,
        ),
        fingerprint=digest.hexdigest(),
    )


def measure_work_tree(
    root: Path,
    *,
    maximum_bytes: int = DEFAULT_WORK_TREE_MAX_BYTES,
) -> WorkTreeUsage:
    """Return stable pre/post-style accounting or fail closed.

    Two complete descriptor-anchored passes must agree.  This catches ordinary
    concurrent mutation without following symlinks.  It cannot provide the
    atomic snapshot or continuous enforcement of a filesystem/project quota.
    """

    _validate_maximum_bytes(maximum_bytes)
    first = _scan_work_tree_once(Path(root), maximum_bytes)
    second = _scan_work_tree_once(Path(root), maximum_bytes)
    if first != second:
        raise SafeFileError("work tree changed between accounting passes")
    return second.usage


def normalize_locator(locator: str) -> str:
    if (
        not isinstance(locator, str)
        or not locator
        or "\x00" in locator
        or "\\" in locator
        or len(locator.encode("utf-8")) > 4096
    ):
        raise SafeFileError("file locator must be a bounded relative path")
    raw_parts = locator.split("/")
    path = PurePosixPath(locator)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in raw_parts)
        or any(len(part.encode("utf-8")) > 255 for part in raw_parts)
    ):
        raise SafeFileError("file locator must be a normalized relative path")
    return path.as_posix()


def ensure_private_directory(path: Path) -> Path:
    """Create and safely reopen one engine-owned directory."""

    destination = Path(path)
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        metadata = destination.stat(follow_symlinks=False)
    except OSError as error:
        raise SafeFileError("snapshot directory cannot be inspected") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise SafeFileError("snapshot directory is not a regular directory")
    flags = os.O_RDONLY | os.O_CLOEXEC
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(destination, flags)
    except OSError as error:
        raise SafeFileError("snapshot directory cannot be opened safely") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino)
            != (metadata.st_dev, metadata.st_ino)
        ):
            raise SafeFileError("snapshot directory changed while opening")
    finally:
        os.close(descriptor)
    return destination


def ensure_relative_directory(
    root: Path,
    locator: str | None = None,
    *,
    mode: int = 0o700,
) -> Path:
    """Create a relative directory tree without following symlink components."""

    base = ensure_private_directory(root)
    if locator in {None, ""}:
        return base
    normalized = normalize_locator(locator)
    directory_flags = os.O_RDONLY | os.O_CLOEXEC
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    owned_descriptors: _OwnedDescriptors = {}
    try:
        directory_descriptor = _track_descriptor(
            owned_descriptors,
            os.open(base, directory_flags),
        )
    except OSError as error:
        raise SafeFileError("relative directory root cannot be opened") from error
    try:
        for component in normalized.split("/"):
            try:
                os.mkdir(component, mode=mode, dir_fd=directory_descriptor)
            except FileExistsError:
                pass
            try:
                next_descriptor = _track_descriptor(
                    owned_descriptors,
                    os.open(
                        component,
                        directory_flags,
                        dir_fd=directory_descriptor,
                    ),
                )
            except OSError as error:
                raise SafeFileError(
                    "relative directory contains an unsafe component"
                ) from error
            _close_owned_descriptor(
                owned_descriptors,
                directory_descriptor,
            )
            directory_descriptor = next_descriptor
        return base / normalized
    finally:
        _close_owned_descriptors(owned_descriptors)


def _open_relative_regular(
    root: Path,
    locator: str,
    *,
    maximum_bytes: int,
    owned_source_descriptors: _OwnedDescriptors | None = None,
) -> tuple[int, os.stat_result, str]:
    normalized = normalize_locator(locator)
    _validate_maximum_bytes(maximum_bytes)

    directory_flags = os.O_RDONLY | os.O_CLOEXEC
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    file_flags |= getattr(os, "O_NOFOLLOW", 0)
    directory_descriptor: int | None = None
    source_descriptor: int | None = None
    opened: os.stat_result | None = None
    owned_directories: _OwnedDescriptors = {}
    source_ownership_is_external = owned_source_descriptors is not None
    owned_sources = (
        owned_source_descriptors
        if owned_source_descriptors is not None
        else {}
    )
    try:
        directory_descriptor = _track_descriptor(
            owned_directories,
            os.open(Path(root), directory_flags),
        )
        parts = normalized.split("/")
        for component in parts[:-1]:
            next_descriptor = _track_descriptor(
                owned_directories,
                os.open(
                    component,
                    directory_flags,
                    dir_fd=directory_descriptor,
                ),
            )
            _close_owned_descriptor(
                owned_directories,
                directory_descriptor,
            )
            directory_descriptor = next_descriptor
        source_descriptor = _track_descriptor(
            owned_sources,
            os.open(
                parts[-1],
                file_flags,
                dir_fd=directory_descriptor,
            ),
        )
        opened = os.fstat(source_descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise SafeFileError("snapshot source is not a regular file")
        if opened.st_size > maximum_bytes:
            raise SafeFileError("snapshot source exceeds its size limit")
    except SafeFileError:
        raise
    except OSError as error:
        raise SafeFileError("snapshot source cannot be opened safely") from error
    finally:
        active_error = sys.exception()
        cleanup_errors: list[tuple[str, BaseException]] = []
        try:
            _close_owned_descriptors(owned_directories)
        except BaseException as error:
            cleanup_errors.append(("directory descriptors", error))
        if (
            not source_ownership_is_external
            and (active_error is not None or cleanup_errors)
        ):
            try:
                _close_owned_descriptors(owned_sources)
            except BaseException as error:
                cleanup_errors.append(("source descriptor", error))
        _resolve_cleanup_errors(
            active_error,
            cleanup_errors,
            context="snapshot source",
        )

    assert source_descriptor is not None
    assert opened is not None
    if not source_ownership_is_external:
        del owned_sources[source_descriptor]
    return source_descriptor, opened, normalized


def copy_bounded_regular(
    source_root: Path,
    source_locator: str,
    destination: Path,
    *,
    maximum_bytes: int = DEFAULT_SNAPSHOT_MAX_BYTES,
    expected_sha256: str | None = None,
    expected_size: int | None = None,
    mode: int = 0o400,
) -> ImmutableFile:
    """Atomically install one immutable copy from a safely opened source.

    The source is opened component-by-component without following symlinks.
    The copy is bounded, hashed while read, checked for concurrent mutation,
    flushed, and linked into place without replacing an existing snapshot.
    """

    _validate_maximum_bytes(maximum_bytes)
    if expected_sha256 is not None and (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(
            character not in "0123456789abcdefABCDEF"
            for character in expected_sha256
        )
    ):
        raise ValueError("expected_sha256 must be a SHA-256 digest")
    if expected_size is not None and (
        isinstance(expected_size, bool)
        or not isinstance(expected_size, int)
        or expected_size < 0
        or expected_size > maximum_bytes
    ):
        raise ValueError("expected_size is outside the copy bound")

    target = Path(destination)
    if target.name in {"", ".", ".."} or target.parent == target:
        raise SafeFileError("snapshot destination is invalid")
    destination_parent = ensure_private_directory(target.parent)
    directory_flags = os.O_RDONLY | os.O_CLOEXEC
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    temporary_name = f".{target.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    source_descriptor: int | None = None
    destination_directory: int | None = None
    temporary_descriptor: int | None = None
    owned_source_descriptors: _OwnedDescriptors = {}
    owned_destination_descriptors: _OwnedDescriptors = {}
    owned_temporary_descriptors: _OwnedDescriptors = {}
    digest = hashlib.sha256()
    total = 0
    try:
        source_descriptor, before, normalized = _open_relative_regular(
            source_root,
            source_locator,
            maximum_bytes=maximum_bytes,
            owned_source_descriptors=owned_source_descriptors,
        )
        destination_directory = _track_descriptor(
            owned_destination_descriptors,
            os.open(destination_parent, directory_flags),
        )
        create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        create_flags |= getattr(os, "O_NOFOLLOW", 0)
        temporary_descriptor = _track_descriptor(
            owned_temporary_descriptors,
            os.open(
                temporary_name,
                create_flags,
                0o600,
                dir_fd=destination_directory,
            ),
        )
        while True:
            block = os.read(source_descriptor, _COPY_CHUNK_BYTES)
            if not block:
                break
            total += len(block)
            if total > maximum_bytes:
                raise SafeFileError("snapshot source grew beyond its size limit")
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(temporary_descriptor, view)
                if written <= 0:
                    raise SafeFileError(
                        "snapshot destination write made no progress"
                    )
                view = view[written:]

        after = os.fstat(source_descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if (
            total != before.st_size
            or any(
                getattr(after, field) != getattr(before, field)
                for field in stable_fields
            )
        ):
            raise SafeFileError("snapshot source changed while copying")
        actual_sha256 = digest.hexdigest()
        if (
            expected_sha256 is not None
            and actual_sha256 != expected_sha256.lower()
        ):
            raise SafeFileError("snapshot source hash changed before copying")
        if expected_size is not None and total != expected_size:
            raise SafeFileError("snapshot source size changed before copying")

        os.fchmod(temporary_descriptor, mode)
        os.fsync(temporary_descriptor)
        _close_owned_descriptor(
            owned_temporary_descriptors,
            temporary_descriptor,
        )
        try:
            os.link(
                temporary_name,
                target.name,
                src_dir_fd=destination_directory,
                dst_dir_fd=destination_directory,
                follow_symlinks=False,
            )
        except FileExistsError as error:
            raise SafeFileError("immutable snapshot already exists") from error
        os.unlink(temporary_name, dir_fd=destination_directory)
        os.fsync(destination_directory)
        return ImmutableFile(
            path=target,
            source_locator=normalized,
            sha256=actual_sha256,
            size_bytes=total,
        )
    except OSError as error:
        raise SafeFileError("snapshot copy failed") from error
    finally:
        active_error = sys.exception()
        cleanup_errors: list[tuple[str, BaseException]] = []

        def cleanup_step(
            label: str,
            operation: Callable[[], None],
        ) -> None:
            try:
                operation()
            except BaseException as error:
                cleanup_errors.append((label, error))

        cleanup_step(
            "source descriptor",
            lambda: _close_owned_descriptors(
                owned_source_descriptors
            ),
        )
        cleanup_step(
            "temporary descriptor",
            lambda: _close_owned_descriptors(
                owned_temporary_descriptors
            ),
        )

        def remove_temporary() -> None:
            if destination_directory is None:
                return
            try:
                os.unlink(
                    temporary_name,
                    dir_fd=destination_directory,
                )
            except FileNotFoundError:
                return

        cleanup_step("temporary file", remove_temporary)
        cleanup_step(
            "destination directory descriptor",
            lambda: _close_owned_descriptors(
                owned_destination_descriptors
            ),
        )
        _resolve_cleanup_errors(
            active_error,
            cleanup_errors,
            context="snapshot copy",
        )
