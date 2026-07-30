"""Descriptor-checked Builder promotion into the canonical workspace."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import uuid
from pathlib import Path, PurePosixPath

from ctf_os.engine.challenge import ChallengeEngine, EngineError
from ctf_os.managed_continuity import (
    THREAD_CONTINUITY_RUN_KEY,
    lane_path_identity_sha256,
    lane_relative_path,
    run_audit_errors,
)
from ctf_os.models import (
    ChallengeIdentity,
    RunOrigin,
    RunStatus,
    WorkspacePublish,
)
from ctf_os.store.atomic import atomic_write_json, read_json
from ctf_os.store.locks import FileLock


MAX_PUBLISH_BYTES = 256 * 1024 * 1024


class WorkspacePublishProposalRejected(EngineError):
    """A Builder-controlled staged source cannot be published safely.

    Only failures attributable to the model's concrete publication proposal
    use this exception.  Canonical workspace conflicts, intent/ledger
    recovery failures, store errors, and unexpected operating-system failures
    retain their original exception types and remain fatal to managed
    execution.
    """

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _safe_relative(value: str) -> Path:
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise EngineError("workspace publish path must be a safe relative path")
    return Path(*pure.parts)


def _hash_descriptor(
    descriptor: int,
    *,
    builder_source: bool = False,
) -> tuple[str, int, os.stat_result]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        if builder_source:
            raise WorkspacePublishProposalRejected(
                "artifact_source_unsafe"
            )
        raise EngineError("workspace publish source must be a regular file")
    if before.st_size > MAX_PUBLISH_BYTES:
        if builder_source:
            raise WorkspacePublishProposalRejected(
                "artifact_size_limit_exceeded"
            )
        raise EngineError("workspace publish source exceeds byte limit")
    digest = hashlib.sha256()
    total = 0
    while total < before.st_size:
        block = os.read(descriptor, min(1024 * 1024, before.st_size - total))
        if not block:
            if builder_source:
                raise WorkspacePublishProposalRejected(
                    "artifact_source_changed"
                )
            raise EngineError("workspace publish source was truncated")
        digest.update(block)
        total += len(block)
    if os.read(descriptor, 1):
        if builder_source:
            raise WorkspacePublishProposalRejected(
                "artifact_source_changed"
            )
        raise EngineError("workspace publish source grew while hashing")
    after = os.fstat(descriptor)
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        if builder_source:
            raise WorkspacePublishProposalRejected(
                "artifact_source_changed"
            )
        raise EngineError("workspace publish source changed while hashing")
    return digest.hexdigest(), total, before


def _hash_file_at(directory_descriptor: int, name: str) -> str | None:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY
            | os.O_CLOEXEC
            | os.O_NONBLOCK
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
    except FileNotFoundError:
        return None
    try:
        digest, _size, _metadata = _hash_descriptor(descriptor)
        return digest
    finally:
        os.close(descriptor)


def _canonical_parent_descriptor(
    root: Path,
    relative_parent: Path,
    *,
    create: bool,
) -> int | None:
    """Open one canonical parent without following mutable symlinks."""

    if create:
        root.mkdir(parents=True, exist_ok=True)
    directory_flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        directory_descriptor = os.open(root, directory_flags)
    except FileNotFoundError:
        if not create:
            return None
        raise
    try:
        for component in relative_parent.parts:
            if component in {"", "."}:
                continue
            if create:
                try:
                    os.mkdir(
                        component,
                        mode=0o700,
                        dir_fd=directory_descriptor,
                    )
                except FileExistsError:
                    pass
            try:
                child_descriptor = os.open(
                    component,
                    directory_flags,
                    dir_fd=directory_descriptor,
                )
            except FileNotFoundError:
                if not create:
                    return None
                raise
            os.close(directory_descriptor)
            directory_descriptor = child_descriptor
        result = directory_descriptor
        directory_descriptor = -1
        return result
    finally:
        if directory_descriptor >= 0:
            os.close(directory_descriptor)


def _raise_builder_stage_open_rejection(error: OSError) -> None:
    """Project only expected model-controlled stage lookup failures."""

    if error.errno == errno.ENOENT:
        raise WorkspacePublishProposalRejected(
            "artifact_source_missing"
        ) from error
    if error.errno in {errno.ELOOP, errno.ENOTDIR}:
        raise WorkspacePublishProposalRejected(
            "artifact_source_unsafe"
        ) from error
    if error.errno in {errno.EACCES, errno.EPERM}:
        raise WorkspacePublishProposalRejected(
            "artifact_source_unopenable"
        ) from error
    raise error


def _open_builder_stage(root: Path, relative: Path) -> int:
    """Open a staged file without following any model-controlled symlink."""

    directory_flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    # The run workspace root is engine-owned.  Failure to open it is an
    # infrastructure/integrity error and therefore remains a raw OSError.
    directory_descriptor = os.open(root, directory_flags)
    try:
        for component in relative.parts[:-1]:
            try:
                child_descriptor = os.open(
                    component,
                    directory_flags,
                    dir_fd=directory_descriptor,
                )
            except OSError as error:
                _raise_builder_stage_open_rejection(error)
                raise AssertionError("unreachable")
            os.close(directory_descriptor)
            directory_descriptor = child_descriptor
        file_flags = (
            os.O_RDONLY
            | os.O_CLOEXEC
            | os.O_NONBLOCK
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            return os.open(
                relative.parts[-1],
                file_flags,
                dir_fd=directory_descriptor,
            )
        except OSError as error:
            _raise_builder_stage_open_rejection(error)
            raise AssertionError("unreachable")
    finally:
        os.close(directory_descriptor)


def canonical_workspace_hash(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    destination: str,
) -> str | None:
    paths = engine.store.challenge_paths(identity)
    destination_relative = _safe_relative(destination)
    parent_descriptor = _canonical_parent_descriptor(
        paths.artifacts / "workspace",
        destination_relative.parent,
        create=False,
    )
    if parent_descriptor is None:
        return None
    try:
        return _hash_file_at(
            parent_descriptor,
            destination_relative.name,
        )
    finally:
        os.close(parent_descriptor)


def _publish_builder_file_locked(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    run_id: str,
    staged_path: str,
    destination: str,
    base_workspace_revision: int,
    base_sha256: str | None,
) -> WorkspacePublish:
    state = engine.store.load(identity)
    run = next((item for item in state.runs if item.id == run_id), None)
    if (
        run is None
        or run.role != "builder"
        or run.status is not RunStatus.COMPLETED
    ):
        raise EngineError("only a canonical Builder run may publish")
    if run.origin is not RunOrigin.MANAGED_MODEL:
        raise EngineError("workspace publish requires a managed Builder run")
    if state.workspace_revision != base_workspace_revision:
        raise EngineError("canonical workspace revision changed")

    paths = engine.store.challenge_paths(identity)
    try:
        source_relative = _safe_relative(staged_path)
    except EngineError as error:
        raise WorkspacePublishProposalRejected(
            "artifact_source_unsafe"
        ) from error
    destination_relative = _safe_relative(destination)
    continuity_audit = run.extra.get(THREAD_CONTINUITY_RUN_KEY)
    continuity_issues = (
        run_audit_errors(continuity_audit)
        if continuity_audit is not None
        else ()
    )
    if continuity_issues:
        raise EngineError("Builder continuity audit is invalid")
    if (
        isinstance(continuity_audit, dict)
        and continuity_audit.get("stable_lane") is True
    ):
        lane_id = continuity_audit.get("lane_identity_sha256")
        if (
            type(lane_id) is not str
            or continuity_audit.get("lane_path_identity_sha256")
            != lane_path_identity_sha256(lane_id)
        ):
            raise EngineError(
                "Builder continuity lane path binding is invalid"
            )
        source_root = paths.root / lane_relative_path(lane_id)
    else:
        source_root = paths.runs / run_id / "workspace"
    source_descriptor = _open_builder_stage(
        source_root,
        source_relative,
    )
    parent_descriptor: int | None = None
    temporary_name: str | None = None
    try:
        # Complete all downgradeable source validation before creating any
        # canonical destination directory or durable publication intent.
        digest, size, source_metadata = _hash_descriptor(
            source_descriptor,
            builder_source=True,
        )
        os.lseek(source_descriptor, 0, os.SEEK_SET)
        canonical_root = paths.artifacts / "workspace"
        parent_descriptor = _canonical_parent_descriptor(
            canonical_root,
            destination_relative.parent,
            create=True,
        )
        assert parent_descriptor is not None
        if (
            _hash_file_at(
                parent_descriptor,
                destination_relative.name,
            )
            != base_sha256
        ):
            raise EngineError("workspace publish base hash changed")
        temporary_name = (
            f".{destination_relative.name}."
            f"{uuid.uuid4().hex}.publish"
        )
        publish_id = f"WP-{uuid.uuid4().hex[:20]}"
        intent = (
            paths.runtime
            / "workspace-publish-intents"
            / f"{publish_id}.json"
        )
        if source_metadata.st_dev != os.fstat(parent_descriptor).st_dev:
            raise EngineError("workspace publish must remain on one filesystem")
        record = WorkspacePublish(
            id=publish_id,
            run_id=run_id,
            staged_path=source_relative.as_posix(),
            destination=destination_relative.as_posix(),
            sha256=digest,
            base_sha256=base_sha256,
            base_workspace_revision=base_workspace_revision,
            status="prepared",
            extra={"size": size},
        )
        atomic_write_json(intent, record.to_dict())
        target_descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
            dir_fd=parent_descriptor,
        )
        try:
            remaining = size
            while remaining:
                block = os.read(source_descriptor, min(1024 * 1024, remaining))
                if not block:
                    # An intent already exists at this point.  Keep this fatal
                    # so the normal reconciliation path, rather than managed
                    # rejection recovery, owns the ambiguous publication.
                    raise EngineError("Builder stage was truncated during copy")
                view = memoryview(block)
                while view:
                    written = os.write(target_descriptor, view)
                    if written <= 0:
                        raise EngineError("workspace publish write made no progress")
                    view = view[written:]
                remaining -= len(block)
            os.fsync(target_descriptor)
        finally:
            os.close(target_descriptor)
        if _hash_file_at(parent_descriptor, temporary_name) != digest:
            raise EngineError("workspace publish temporary hash mismatch")
        after = os.fstat(source_descriptor)
        if (
            after.st_dev != source_metadata.st_dev
            or after.st_ino != source_metadata.st_ino
            or after.st_size != source_metadata.st_size
            or after.st_mtime_ns != source_metadata.st_mtime_ns
        ):
            # The prepared intent is durable.  This cannot be downgraded to a
            # model repair without first proving durable intent cleanup.
            raise EngineError("Builder stage changed during publish")
        os.replace(
            temporary_name,
            destination_relative.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        os.fsync(parent_descriptor)

        current = engine.store.load(identity)
        if current.workspace_revision != base_workspace_revision:
            raise EngineError("workspace revision changed before publish commit")

        def apply(latest: object) -> None:
            if latest.workspace_revision != base_workspace_revision:
                raise EngineError("workspace revision changed before publish commit")
            record.status = "published"
            record.published_workspace_revision = base_workspace_revision + 1
            latest.workspace_publishes.append(record)
            latest.workspace_revision += 1

        engine.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        )
        try:
            intent.unlink()
        except FileNotFoundError:
            pass
        return record
    finally:
        os.close(source_descriptor)
        if parent_descriptor is not None and temporary_name is not None:
            try:
                os.unlink(
                    temporary_name,
                    dir_fd=parent_descriptor,
                )
            except FileNotFoundError:
                pass
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def publish_builder_file(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    run_id: str,
    staged_path: str,
    destination: str,
    base_workspace_revision: int,
    base_sha256: str | None,
) -> WorkspacePublish:
    """Atomically promote one Builder-created file after optimistic checks."""

    paths = engine.store.challenge_paths(identity)
    with FileLock(paths.runtime / "workspace-publish.lock") as publish_lock:
        publish_lock.acquire()
        return _publish_builder_file_locked(
            engine,
            identity,
            run_id=run_id,
            staged_path=staged_path,
            destination=destination,
            base_workspace_revision=base_workspace_revision,
            base_sha256=base_sha256,
        )


def _reconcile_workspace_publishes_locked(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
) -> list[str]:
    paths = engine.store.challenge_paths(identity)
    intent_root = paths.runtime / "workspace-publish-intents"
    if not intent_root.is_dir():
        return []
    reconciled: list[str] = []
    for intent in sorted(intent_root.glob("WP-*.json")):
        raw = read_json(intent)
        if not isinstance(raw, dict):
            raise EngineError(f"invalid workspace publish intent: {intent}")
        record = WorkspacePublish.from_dict(raw)
        state = engine.store.load(identity)
        existing = next(
            (
                item
                for item in state.workspace_publishes
                if item.id == record.id
            ),
            None,
        )
        if existing is not None:
            if (
                existing.sha256 != record.sha256
                or existing.destination != record.destination
            ):
                raise EngineError(
                    f"workspace publish intent conflicts: {record.id}"
                )
            intent.unlink()
            reconciled.append(record.id)
            continue
        if (
            canonical_workspace_hash(
                engine,
                identity,
                record.destination,
            )
            != record.sha256
        ):
            raise EngineError(
                f"workspace publish destination is incomplete: {record.id}"
            )
        if state.workspace_revision != record.base_workspace_revision:
            raise EngineError(
                f"workspace publish revision is ambiguous: {record.id}"
            )

        def apply(latest: object) -> None:
            if latest.workspace_revision != record.base_workspace_revision:
                raise EngineError(
                    f"workspace publish revision changed: {record.id}"
                )
            record.status = "published"
            record.published_workspace_revision = (
                record.base_workspace_revision + 1
            )
            latest.workspace_publishes.append(record)
            latest.workspace_revision += 1

        engine.store.update(
            identity,
            apply,
            expected_revision=state.revision,
        )
        intent.unlink()
        reconciled.append(record.id)
    return reconciled


def reconcile_workspace_publishes(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
) -> list[str]:
    """Finish atomic promotes that crossed the filesystem/state boundary."""

    paths = engine.store.challenge_paths(identity)
    with FileLock(paths.runtime / "workspace-publish.lock") as publish_lock:
        publish_lock.acquire()
        return _reconcile_workspace_publishes_locked(engine, identity)


__all__ = [
    "MAX_PUBLISH_BYTES",
    "WorkspacePublishProposalRejected",
    "canonical_workspace_hash",
    "publish_builder_file",
    "reconcile_workspace_publishes",
]
