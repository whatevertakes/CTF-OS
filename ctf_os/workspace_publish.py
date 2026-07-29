"""Descriptor-checked Builder promotion into the canonical workspace."""

from __future__ import annotations

import hashlib
import os
import stat
import uuid
from pathlib import Path, PurePosixPath

from ctf_os.engine.challenge import ChallengeEngine, EngineError
from ctf_os.models import (
    ChallengeIdentity,
    RunOrigin,
    RunStatus,
    WorkspacePublish,
)
from ctf_os.store.atomic import atomic_write_json, read_json
from ctf_os.store.locks import FileLock


MAX_PUBLISH_BYTES = 256 * 1024 * 1024


def _safe_relative(value: str) -> Path:
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise EngineError("workspace publish path must be a safe relative path")
    return Path(*pure.parts)


def _hash_descriptor(descriptor: int) -> tuple[str, int, os.stat_result]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise EngineError("workspace publish source must be a regular file")
    if before.st_size > MAX_PUBLISH_BYTES:
        raise EngineError("workspace publish source exceeds byte limit")
    digest = hashlib.sha256()
    total = 0
    while total < before.st_size:
        block = os.read(descriptor, min(1024 * 1024, before.st_size - total))
        if not block:
            raise EngineError("workspace publish source was truncated")
        digest.update(block)
        total += len(block)
    if os.read(descriptor, 1):
        raise EngineError("workspace publish source grew while hashing")
    after = os.fstat(descriptor)
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        raise EngineError("workspace publish source changed while hashing")
    return digest.hexdigest(), total, before


def _hash_file(path: Path) -> str | None:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | os.O_CLOEXEC
            | os.O_NONBLOCK
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except FileNotFoundError:
        return None
    try:
        digest, _size, _metadata = _hash_descriptor(descriptor)
        return digest
    finally:
        os.close(descriptor)


def canonical_workspace_hash(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    destination: str,
) -> str | None:
    paths = engine.store.challenge_paths(identity)
    return _hash_file(
        paths.artifacts / "workspace" / _safe_relative(destination)
    )


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
    source_relative = _safe_relative(staged_path)
    destination_relative = _safe_relative(destination)
    source = paths.runs / run_id / "workspace" / source_relative
    canonical_root = paths.artifacts / "workspace"
    canonical_root.mkdir(parents=True, exist_ok=True)
    target = canonical_root / destination_relative
    target.parent.mkdir(parents=True, exist_ok=True)
    if _hash_file(target) != base_sha256:
        raise EngineError("workspace publish base hash changed")

    flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | os.O_NONBLOCK
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        source_descriptor = os.open(source, flags)
    except OSError as error:
        raise EngineError(f"cannot open Builder stage: {error}") from error
    temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.publish")
    publish_id = f"WP-{uuid.uuid4().hex[:20]}"
    intent = paths.runtime / "workspace-publish-intents" / f"{publish_id}.json"
    try:
        digest, size, source_metadata = _hash_descriptor(source_descriptor)
        os.lseek(source_descriptor, 0, os.SEEK_SET)
        if source_metadata.st_dev != target.parent.stat().st_dev:
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
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        try:
            remaining = size
            while remaining:
                block = os.read(source_descriptor, min(1024 * 1024, remaining))
                if not block:
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
        if _hash_file(temporary) != digest:
            raise EngineError("workspace publish temporary hash mismatch")
        after = os.fstat(source_descriptor)
        if (
            after.st_dev != source_metadata.st_dev
            or after.st_ino != source_metadata.st_ino
            or after.st_size != source_metadata.st_size
            or after.st_mtime_ns != source_metadata.st_mtime_ns
        ):
            raise EngineError("Builder stage changed during publish")
        os.replace(temporary, target)
        directory_descriptor = os.open(
            target.parent,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)

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
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


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
        destination = (
            paths.artifacts
            / "workspace"
            / _safe_relative(record.destination)
        )
        if _hash_file(destination) != record.sha256:
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
    "canonical_workspace_hash",
    "publish_builder_file",
    "reconcile_workspace_publishes",
]
