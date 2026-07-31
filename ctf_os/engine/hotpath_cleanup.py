"""Exact bounded cleanup for hot-path-owned challenge directories.

Hot paths create private attempt and replay trees before those bytes acquire
canonical state authority.  This module removes only a directory whose
device/inode identity was recorded by the engine.  It never follows links,
scans the complete tree against explicit entry/byte bounds before deleting a
single entry, and revalidates every scanned pathname during removal.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from ctf_os.models import ChallengeIdentity

if TYPE_CHECKING:
    from ctf_os.engine.challenge import ChallengeEngine


_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | os.O_CLOEXEC
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


class HotPathCleanupError(RuntimeError):
    """An exact cleanup target could not be safely removed."""


@dataclass(frozen=True, slots=True)
class _Signature:
    device: int
    inode: int
    mode: int
    size: int
    modified_ns: int
    changed_ns: int
    link_count: int
    allocated_bytes: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> _Signature:
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            mode=value.st_mode,
            size=value.st_size,
            modified_ns=value.st_mtime_ns,
            changed_ns=value.st_ctime_ns,
            link_count=value.st_nlink,
            allocated_bytes=max(getattr(value, "st_blocks", 0) * 512, 0),
        )

    def same_identity(self, value: os.stat_result) -> bool:
        return (
            stat.S_ISDIR(value.st_mode)
            and self.device == value.st_dev
            and self.inode == value.st_ino
            and stat.S_ISDIR(self.mode)
        )

    def matches_after_internal_unlinks(
        self,
        value: os.stat_result,
        *,
        removed_links: int,
    ) -> bool:
        """Match one leaf after only our earlier hard-link unlinks changed it."""

        if removed_links < 0 or removed_links >= self.link_count:
            return False
        stable = (
            self.device == value.st_dev
            and self.inode == value.st_ino
            and self.mode == value.st_mode
            and self.size == value.st_size
            and self.modified_ns == value.st_mtime_ns
            and self.allocated_bytes
            == max(getattr(value, "st_blocks", 0) * 512, 0)
            and self.link_count - removed_links == value.st_nlink
        )
        # The kernel updates ctime when link count changes. Before our first
        # unlink it remains a useful concurrent-mutation check.
        return stable and (
            removed_links > 0 or self.changed_ns == value.st_ctime_ns
        )


@dataclass(frozen=True, slots=True)
class _TrackedTree:
    relative: PurePosixPath
    identity: _Signature
    run_id: str | None


@dataclass(frozen=True, slots=True)
class ExactTreeReference:
    """Descriptor-reopenable identity for one engine-owned directory tree.

    The reference deliberately contains only a challenge-root-relative path
    plus the directory device/inode pair.  Contents may grow after capture,
    but cleanup will remove nothing until a complete bounded scan succeeds.
    """

    relative: PurePosixPath
    device: int
    inode: int

    def __post_init__(self) -> None:
        if (
            self.relative.is_absolute()
            or not self.relative.parts
            or any(part in {"", ".", ".."} for part in self.relative.parts)
        ):
            raise ValueError("exact tree reference has an unsafe path")
        if (
            isinstance(self.device, bool)
            or not isinstance(self.device, int)
            or self.device < 0
            or isinstance(self.inode, bool)
            or not isinstance(self.inode, int)
            or self.inode <= 0
        ):
            raise ValueError("exact tree reference has an invalid identity")

    def _tracked(self) -> _TrackedTree:
        return _TrackedTree(
            relative=self.relative,
            identity=_Signature(
                device=self.device,
                inode=self.inode,
                mode=stat.S_IFDIR,
                size=0,
                modified_ns=0,
                changed_ns=0,
                link_count=0,
                allocated_bytes=0,
            ),
            run_id=None,
        )


@dataclass(frozen=True, slots=True)
class _TrackedFile:
    relative: PurePosixPath
    artifact_id: str


@dataclass(frozen=True, slots=True)
class _TreeManifest:
    tracked: _TrackedTree
    entries: dict[tuple[str, ...], _Signature]


@dataclass(frozen=True, slots=True)
class _FileManifest:
    tracked: _TrackedFile
    signature: _Signature


@dataclass(slots=True)
class _ScanBudget:
    maximum_entries: int
    maximum_bytes: int
    maximum_depth: int = 256
    entries: int = 0
    bytes: int = 0

    def add(self, metadata: os.stat_result) -> None:
        self.entries += 1
        if self.entries > self.maximum_entries:
            raise HotPathCleanupError(
                "hot-path cleanup entry bound exceeded before deletion"
            )
        if not stat.S_ISDIR(metadata.st_mode):
            self.bytes += max(
                max(metadata.st_size, 0),
                max(getattr(metadata, "st_blocks", 0) * 512, 0),
            )
            if self.bytes > self.maximum_bytes:
                raise HotPathCleanupError(
                    "hot-path cleanup byte bound exceeded before deletion"
                )


def _safe_relative(root: Path, path: Path) -> PurePosixPath:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise HotPathCleanupError(
            "hot-path cleanup target escapes the challenge root"
        ) from error
    pure = PurePosixPath(relative.as_posix())
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise HotPathCleanupError("unsafe hot-path cleanup target")
    return pure


def _open_tree(
    challenge_root: Path,
    tracked: _TrackedTree,
) -> tuple[list[int], int, int, str]:
    descriptors: list[int] = []
    try:
        current = os.open(challenge_root, _DIRECTORY_FLAGS)
        descriptors.append(current)
        for component in tracked.relative.parts[:-1]:
            current = os.open(
                component,
                _DIRECTORY_FLAGS,
                dir_fd=current,
            )
            descriptors.append(current)
        name = tracked.relative.parts[-1]
        observed = os.stat(name, dir_fd=current, follow_symlinks=False)
        if not tracked.identity.same_identity(observed):
            raise HotPathCleanupError(
                "refused cleanup because the exact directory identity changed"
            )
        tree_descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=current)
        descriptors.append(tree_descriptor)
        if not tracked.identity.same_identity(os.fstat(tree_descriptor)):
            raise HotPathCleanupError(
                "hot-path cleanup directory changed while opening"
            )
        return descriptors, current, tree_descriptor, name
    except BaseException:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _scan_entries(
    directory_descriptor: int,
    prefix: tuple[str, ...],
    entries: dict[tuple[str, ...], _Signature],
    budget: _ScanBudget,
    *,
    root_device: int,
    depth: int,
) -> None:
    if depth > budget.maximum_depth:
        raise HotPathCleanupError(
            "hot-path cleanup depth bound exceeded before deletion"
        )
    for name in sorted(os.listdir(directory_descriptor)):
        if name in {"", ".", ".."} or "/" in name or "\x00" in name:
            raise HotPathCleanupError(
                "hot-path cleanup encountered an unsafe entry name"
            )
        metadata = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if metadata.st_dev != root_device:
            raise HotPathCleanupError(
                "hot-path cleanup encountered a cross-device entry"
            )
        budget.add(metadata)
        relative = (*prefix, name)
        entries[relative] = _Signature.from_stat(metadata)
        if not stat.S_ISDIR(metadata.st_mode):
            continue
        child = os.open(name, _DIRECTORY_FLAGS, dir_fd=directory_descriptor)
        try:
            opened = os.fstat(child)
            if (
                opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
                or not stat.S_ISDIR(opened.st_mode)
            ):
                raise HotPathCleanupError(
                    "hot-path cleanup entry changed while scanning"
                )
            _scan_entries(
                child,
                relative,
                entries,
                budget,
                root_device=root_device,
                depth=depth + 1,
            )
        finally:
            os.close(child)


def _scan_tree(
    challenge_root: Path,
    tracked: _TrackedTree,
    budget: _ScanBudget,
) -> _TreeManifest | None:
    try:
        descriptors, _parent, tree, _name = _open_tree(
            challenge_root,
            tracked,
        )
    except FileNotFoundError:
        return None
    try:
        budget.add(os.fstat(tree))
        entries: dict[tuple[str, ...], _Signature] = {}
        _scan_entries(
            tree,
            (),
            entries,
            budget,
            root_device=tracked.identity.device,
            depth=1,
        )
        regular_inode_paths: dict[tuple[int, int], int] = {}
        for signature in entries.values():
            if stat.S_ISREG(signature.mode):
                key = (signature.device, signature.inode)
                regular_inode_paths[key] = regular_inode_paths.get(key, 0) + 1
        for signature in entries.values():
            if (
                stat.S_ISREG(signature.mode)
                and regular_inode_paths[(signature.device, signature.inode)]
                != signature.link_count
            ):
                raise HotPathCleanupError(
                    "hot-path cleanup regular file has an external hard link"
                )
        return _TreeManifest(tracked=tracked, entries=entries)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _open_parent(
    challenge_root: Path,
    relative: PurePosixPath,
) -> tuple[list[int], int, str]:
    descriptors: list[int] = []
    try:
        current = os.open(challenge_root, _DIRECTORY_FLAGS)
        descriptors.append(current)
        for component in relative.parts[:-1]:
            current = os.open(
                component,
                _DIRECTORY_FLAGS,
                dir_fd=current,
            )
            descriptors.append(current)
        return descriptors, current, relative.parts[-1]
    except BaseException:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _scan_file(
    challenge_root: Path,
    tracked: _TrackedFile,
    budget: _ScanBudget,
) -> _FileManifest | None:
    try:
        descriptors, parent, name = _open_parent(
            challenge_root,
            tracked.relative,
        )
    except FileNotFoundError:
        return None
    try:
        try:
            metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(metadata.st_mode):
            raise HotPathCleanupError(
                "hot-path cleanup file target is not regular"
            )
        budget.add(metadata)
        return _FileManifest(
            tracked=tracked,
            signature=_Signature.from_stat(metadata),
        )
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _immediate_entries(
    entries: dict[tuple[str, ...], _Signature],
    prefix: tuple[str, ...],
) -> dict[str, _Signature]:
    depth = len(prefix) + 1
    return {
        relative[-1]: signature
        for relative, signature in entries.items()
        if len(relative) == depth and relative[:-1] == prefix
    }


def _remove_entries(
    directory_descriptor: int,
    prefix: tuple[str, ...],
    entries: dict[tuple[str, ...], _Signature],
    removed_hardlinks: dict[tuple[int, int], int] | None = None,
) -> None:
    if removed_hardlinks is None:
        removed_hardlinks = {}
    expected = _immediate_entries(entries, prefix)
    if set(os.listdir(directory_descriptor)) != set(expected):
        raise HotPathCleanupError(
            "hot-path cleanup tree changed after its bounded scan"
        )
    for name in sorted(expected):
        signature = expected[name]
        metadata = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        inode_key = (signature.device, signature.inode)
        removed_links = (
            removed_hardlinks.get(inode_key, 0)
            if stat.S_ISREG(signature.mode)
            else 0
        )
        if not signature.matches_after_internal_unlinks(
            metadata,
            removed_links=removed_links,
        ):
            raise HotPathCleanupError(
                "hot-path cleanup entry changed after its bounded scan"
            )
        if stat.S_ISDIR(metadata.st_mode):
            child = os.open(
                name,
                _DIRECTORY_FLAGS,
                dir_fd=directory_descriptor,
            )
            try:
                opened = os.fstat(child)
                if not signature.same_identity(opened):
                    raise HotPathCleanupError(
                        "hot-path cleanup directory changed while removing"
                    )
                _remove_entries(
                    child,
                    (*prefix, name),
                    entries,
                    removed_hardlinks,
                )
                if not signature.same_identity(os.fstat(child)):
                    raise HotPathCleanupError(
                        "hot-path cleanup directory identity changed"
                    )
                os.rmdir(name, dir_fd=directory_descriptor)
            finally:
                os.close(child)
        else:
            os.unlink(name, dir_fd=directory_descriptor)
            if stat.S_ISREG(signature.mode):
                removed_hardlinks[inode_key] = removed_links + 1
    os.fsync(directory_descriptor)


def _remove_tree(
    challenge_root: Path,
    manifest: _TreeManifest,
) -> None:
    descriptors, parent, tree, name = _open_tree(
        challenge_root,
        manifest.tracked,
    )
    try:
        _remove_entries(tree, (), manifest.entries)
        if not manifest.tracked.identity.same_identity(os.fstat(tree)):
            raise HotPathCleanupError(
                "hot-path cleanup root identity changed"
            )
        os.rmdir(name, dir_fd=parent)
        os.fsync(parent)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _remove_file(
    challenge_root: Path,
    manifest: _FileManifest,
) -> None:
    descriptors, parent, name = _open_parent(
        challenge_root,
        manifest.tracked.relative,
    )
    file_descriptor: int | None = None
    try:
        try:
            metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        if _Signature.from_stat(metadata) != manifest.signature:
            raise HotPathCleanupError(
                "hot-path cleanup file changed after its bounded scan"
            )
        file_descriptor = os.open(
            name,
            os.O_RDONLY
            | os.O_CLOEXEC
            | os.O_NONBLOCK
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent,
        )
        if _Signature.from_stat(os.fstat(file_descriptor)) != manifest.signature:
            raise HotPathCleanupError(
                "hot-path cleanup file changed while opening"
            )
        os.unlink(name, dir_fd=parent)
        os.fsync(parent)
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def capture_exact_tree(
    challenge_root: Path,
    path: Path,
) -> ExactTreeReference:
    """Capture one exact owned directory without following its final entry."""

    root = Path(challenge_root)
    target = Path(path)
    relative = _safe_relative(root, target)
    try:
        metadata = target.stat(follow_symlinks=False)
    except OSError as error:
        raise HotPathCleanupError(
            "exact cleanup target cannot be inspected"
        ) from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise HotPathCleanupError(
            "exact cleanup target is not a directory"
        )
    reference = ExactTreeReference(
        relative=relative,
        device=metadata.st_dev,
        inode=metadata.st_ino,
    )
    descriptors: list[int] = []
    try:
        descriptors, _parent, opened, _name = _open_tree(
            root,
            reference._tracked(),
        )
        reopened = os.fstat(opened)
        if (reopened.st_dev, reopened.st_ino) != (
            metadata.st_dev,
            metadata.st_ino,
        ):
            raise HotPathCleanupError(
                "exact cleanup target changed while capturing"
            )
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    return reference


def remove_exact_tree(
    challenge_root: Path,
    reference: ExactTreeReference,
    *,
    maximum_entries: int,
    maximum_bytes: int,
    maximum_depth: int = 256,
) -> bool:
    """Remove one exact tree after a complete bounded descriptor scan.

    Returns ``True`` only when the referenced pathname is absent after the
    parent directory has been fsynced.  Symlinks and special files below the
    owned directory are unlinked as entries and are never followed or opened.
    """

    if not isinstance(reference, ExactTreeReference):
        raise TypeError("reference must be an ExactTreeReference")
    if (
        isinstance(maximum_entries, bool)
        or not isinstance(maximum_entries, int)
        or maximum_entries <= 0
    ):
        raise ValueError("maximum_entries must be a positive integer")
    if (
        isinstance(maximum_bytes, bool)
        or not isinstance(maximum_bytes, int)
        or maximum_bytes < 0
    ):
        raise ValueError("maximum_bytes must be a non-negative integer")
    if (
        isinstance(maximum_depth, bool)
        or not isinstance(maximum_depth, int)
        or maximum_depth <= 0
    ):
        raise ValueError("maximum_depth must be a positive integer")

    root = Path(challenge_root)
    tracked = reference._tracked()
    manifest = _scan_tree(
        root,
        tracked,
        _ScanBudget(
            maximum_entries=maximum_entries,
            maximum_bytes=maximum_bytes,
            maximum_depth=maximum_depth,
        ),
    )
    if manifest is not None:
        _remove_tree(root, manifest)

    try:
        descriptors, parent, name = _open_parent(root, reference.relative)
    except FileNotFoundError:
        return True
    try:
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            os.fsync(parent)
            return True
        raise HotPathCleanupError(
            "exact cleanup target is still present after removal"
        )
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


class HotPathCleanupTracker:
    """Track and exactly remove bounded engine-owned directory trees."""

    def __init__(
        self,
        *,
        maximum_entries: int,
        maximum_bytes: int,
    ) -> None:
        if (
            isinstance(maximum_entries, bool)
            or not isinstance(maximum_entries, int)
            or maximum_entries <= 0
        ):
            raise ValueError("maximum_entries must be a positive integer")
        if (
            isinstance(maximum_bytes, bool)
            or not isinstance(maximum_bytes, int)
            or maximum_bytes < 0
        ):
            raise ValueError("maximum_bytes must be a non-negative integer")
        self.maximum_entries = maximum_entries
        self.maximum_bytes = maximum_bytes
        self.attempt_id: str | None = None
        self._trees: dict[str, _TrackedTree] = {}
        self._files: dict[str, _TrackedFile] = {}

    def set_attempt_id(self, attempt_id: str) -> None:
        if not attempt_id or "/" in attempt_id or "\x00" in attempt_id:
            raise HotPathCleanupError("invalid hot-path cleanup attempt id")
        if self.attempt_id is not None and self.attempt_id != attempt_id:
            raise HotPathCleanupError("hot-path cleanup attempt id changed")
        self.attempt_id = attempt_id

    def track_tree(
        self,
        challenge_root: Path,
        path: Path,
        *,
        run_id: str | None = None,
    ) -> None:
        relative = _safe_relative(challenge_root, path)
        metadata = path.stat(follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode):
            raise HotPathCleanupError(
                "hot-path cleanup target is not an exact directory"
            )
        key = relative.as_posix()
        tracked = _TrackedTree(
            relative=relative,
            identity=_Signature.from_stat(metadata),
            run_id=run_id,
        )
        existing = self._trees.get(key)
        if existing is not None and existing != tracked:
            raise HotPathCleanupError(
                "hot-path cleanup target identity changed while tracking"
            )
        for other_key in self._trees:
            if (
                other_key != key
                and (
                    other_key.startswith(key + "/")
                    or key.startswith(other_key + "/")
                )
            ):
                raise HotPathCleanupError(
                    "overlapping hot-path cleanup targets are forbidden"
                )
        if existing is None and len(self._trees) >= self.maximum_entries:
            raise HotPathCleanupError(
                "hot-path cleanup tracking entry bound exceeded"
            )
        self._trees[key] = tracked

    def track_file(
        self,
        challenge_root: Path,
        path: Path,
        *,
        artifact_id: str,
    ) -> None:
        if not artifact_id or "/" in artifact_id or "\x00" in artifact_id:
            raise HotPathCleanupError(
                "invalid hot-path cleanup artifact id"
            )
        relative = _safe_relative(challenge_root, path)
        key = relative.as_posix()
        for tree_key in self._trees:
            if key == tree_key or key.startswith(tree_key + "/"):
                return
        tracked = _TrackedFile(
            relative=relative,
            artifact_id=artifact_id,
        )
        existing = self._files.get(key)
        if existing is not None and existing != tracked:
            raise HotPathCleanupError(
                "hot-path cleanup file ownership changed"
            )
        if (
            existing is None
            and len(self._trees) + len(self._files)
            >= self.maximum_entries
        ):
            raise HotPathCleanupError(
                "hot-path cleanup tracking entry bound exceeded"
            )
        self._files[key] = tracked

    def cleanup(
        self,
        engine: ChallengeEngine,
        identity: ChallengeIdentity,
        *,
        cause: BaseException | None = None,
    ) -> None:
        if not self._trees and not self._files:
            return
        try:
            canonical = engine.store.load(identity, recover=False)
            canonical_run_ids = {run.id for run in canonical.runs}
            canonical_artifact_ids = {
                artifact.id for artifact in canonical.artifacts
            }
            canonical_artifact_paths = {
                artifact.path for artifact in canonical.artifacts
            }
            challenge_root = engine.store.challenge_paths(identity).root
            selected_trees = tuple(
                tracked
                for tracked in self._trees.values()
                if tracked.run_id is None
                or tracked.run_id not in canonical_run_ids
            )
            selected_files = tuple(
                tracked
                for tracked in self._files.values()
                if tracked.artifact_id not in canonical_artifact_ids
                and tracked.relative.as_posix()
                not in canonical_artifact_paths
            )
            budget = _ScanBudget(
                maximum_entries=self.maximum_entries,
                maximum_bytes=self.maximum_bytes,
            )
            tree_manifests = tuple(
                manifest
                for tracked in selected_trees
                if (
                    manifest := _scan_tree(
                        challenge_root,
                        tracked,
                        budget,
                    )
                )
                is not None
            )
            file_manifests = tuple(
                manifest
                for tracked in selected_files
                if (
                    manifest := _scan_file(
                        challenge_root,
                        tracked,
                        budget,
                    )
                )
                is not None
            )
            for manifest in file_manifests:
                _remove_file(challenge_root, manifest)
            for manifest in tree_manifests:
                _remove_tree(challenge_root, manifest)
            selected_tree_keys = {
                tracked.relative.as_posix() for tracked in selected_trees
            }
            self._trees = {
                key: tracked
                for key, tracked in self._trees.items()
                if key not in selected_tree_keys
            }
            selected_file_keys = {
                tracked.relative.as_posix() for tracked in selected_files
            }
            self._files = {
                key: tracked
                for key, tracked in self._files.items()
                if key not in selected_file_keys
            }
        except BaseException as error:
            if isinstance(error, HotPathCleanupError):
                cleanup_error = error
            else:
                cleanup_error = HotPathCleanupError(
                    "exact hot-path cleanup failed"
                )
                cleanup_error.__cause__ = error
            if cause is not None:
                raise cleanup_error from cause
            raise cleanup_error


__all__ = [
    "ExactTreeReference",
    "HotPathCleanupError",
    "HotPathCleanupTracker",
    "capture_exact_tree",
    "remove_exact_tree",
]
