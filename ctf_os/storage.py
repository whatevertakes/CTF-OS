"""Reachability inventory and quarantine-only storage collection."""

from __future__ import annotations

import os
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

from ctf_os.models import ChallengeIdentity
from ctf_os.store import (
    ChallengeLock,
    LockTimeout,
    StateStore,
    sha256_file,
)
from ctf_os.store.atomic import atomic_write_json, read_json


class StorageError(RuntimeError):
    pass


def _reachable_paths(
    store: StateStore,
    identity: ChallengeIdentity,
) -> tuple[set[str], tuple[str, ...]]:
    state = store.load(identity)
    reachable = {
        item.path for item in state.artifacts if item.path
    }
    for run in state.runs:
        for path in (run.request_path, run.result_path, run.validation_path):
            if path:
                reachable.add(path)
    prefixes = [
        f"runs/{item.id}/" for item in state.runs
    ]
    # The canonical operator workspace is never garbage, even when a file has
    # not been promoted as semantic evidence.
    prefixes.append("artifacts/workspace/")
    if state.closure is not None:
        package_path = state.closure.extra.get("package_path")
        if isinstance(package_path, str) and package_path:
            prefixes.append(package_path.rstrip("/") + "/")
    return reachable, tuple(prefixes)


def _safe_relative(value: object) -> Path:
    if not isinstance(value, str):
        raise StorageError("storage manifest path must be a string")
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise StorageError("storage manifest contains an unsafe path")
    return Path(*pure.parts)


def storage_inventory(
    store: StateStore,
    identity: ChallengeIdentity,
) -> dict[str, Any]:
    paths = store.challenge_paths(identity)
    reachable, run_prefixes = _reachable_paths(store, identity)
    files: list[dict[str, Any]] = []
    scan_roots = (paths.artifacts, paths.runs)
    for scan_root in scan_roots:
        if not scan_root.is_dir():
            continue
        for path in sorted(scan_root.rglob("*"), key=lambda item: item.as_posix()):
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(paths.root).as_posix()
            if relative.startswith("artifacts/quarantine/"):
                continue
            files.append(
                {
                    "path": relative,
                    "bytes": path.stat(follow_symlinks=False).st_size,
                    "reachable": (
                        relative in reachable
                        or relative.startswith(run_prefixes)
                    ),
                }
            )
    return {
        "identity": identity.key,
        "state_revision": store.load(identity).revision,
        "files": files,
        "total_bytes": sum(item["bytes"] for item in files),
        "unreachable_bytes": sum(
            item["bytes"] for item in files if not item["reachable"]
        ),
    }


def storage_plan(
    store: StateStore,
    identity: ChallengeIdentity,
) -> dict[str, Any]:
    inventory = storage_inventory(store, identity)
    candidates = [
        item for item in inventory["files"] if not item["reachable"]
    ]
    return {
        "identity": identity.key,
        "state_revision": inventory["state_revision"],
        "action": "quarantine",
        "permanent_delete_enabled": False,
        "candidates": candidates,
        "candidate_bytes": sum(item["bytes"] for item in candidates),
    }


def quarantine_unreachable(
    store: StateStore,
    identity: ChallengeIdentity,
) -> dict[str, Any]:
    paths = store.challenge_paths(identity)
    store.assert_mutations_allowed()
    session_lock = ChallengeLock(paths.runtime / "session.lock", timeout=0)
    state_lock = ChallengeLock(paths.lock, timeout=0)
    try:
        session_lock.acquire()
        state_lock.acquire()
    except LockTimeout as error:
        state_lock.release()
        session_lock.release()
        raise StorageError(
            "active challenge work blocks storage quarantine"
        ) from error
    try:
        plan = storage_plan(store, identity)
        quarantine_id = f"Q-{uuid.uuid4().hex}"
        root = paths.artifacts / "quarantine" / quarantine_id
        records: list[dict[str, Any]] = []
        for item in plan["candidates"]:
            relative = _safe_relative(item["path"])
            source = paths.root / relative
            try:
                metadata = source.stat(follow_symlinks=False)
            except OSError as error:
                raise StorageError(
                    f"cannot inspect quarantine source: {relative}"
                ) from error
            if source.is_symlink() or not source.is_file():
                raise StorageError(
                    f"quarantine source is not regular: {relative}"
                )
            records.append(
                {
                    "path": relative.as_posix(),
                    "sha256": sha256_file(source),
                    "bytes": metadata.st_size,
                }
            )
        manifest = {
            "schema_version": 1,
            "quarantine_id": quarantine_id,
            "identity": identity.to_dict(),
            "state_revision": plan["state_revision"],
            "status": "moving",
            "permanent_delete_enabled": False,
            "files": records,
        }
        atomic_write_json(root / "manifest.json", manifest)
        moved: list[dict[str, Any]] = []
        try:
            for record in records:
                relative = _safe_relative(record["path"])
                source = paths.root / relative
                if sha256_file(source) != record["sha256"]:
                    raise StorageError(
                        f"quarantine source changed: {relative}"
                    )
                destination = root / "files" / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                if source.stat().st_dev != destination.parent.stat().st_dev:
                    raise StorageError(
                        "quarantine must remain on one filesystem"
                    )
                os.replace(source, destination)
                moved.append(record)
            manifest["status"] = "quarantined"
            atomic_write_json(root / "manifest.json", manifest)
            return manifest
        except BaseException as error:
            for record in reversed(moved):
                relative = _safe_relative(record["path"])
                quarantined = root / "files" / relative
                destination = paths.root / relative
                if quarantined.exists() and not destination.exists():
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    os.replace(quarantined, destination)
            try:
                manifest["status"] = "rolled_back"
                atomic_write_json(root / "manifest.json", manifest)
            except BaseException as manifest_error:
                error.add_note(
                    f"quarantine rollback manifest failed: {manifest_error}"
                )
            raise
    finally:
        state_lock.release()
        session_lock.release()


def restore_quarantine(
    store: StateStore,
    identity: ChallengeIdentity,
    quarantine_id: str,
) -> dict[str, Any]:
    if (
        not quarantine_id.startswith("Q-")
        or "/" in quarantine_id
        or "\\" in quarantine_id
    ):
        raise StorageError("invalid quarantine id")
    paths = store.challenge_paths(identity)
    root = paths.artifacts / "quarantine" / quarantine_id
    manifest = read_json(root / "manifest.json")
    if not isinstance(manifest, dict) or manifest.get("quarantine_id") != quarantine_id:
        raise StorageError("invalid quarantine manifest")
    if manifest.get("identity") != identity.to_dict():
        raise StorageError("quarantine identity does not match challenge")
    records = manifest.get("files", [])
    if not isinstance(records, list) or not all(
        isinstance(item, dict) for item in records
    ):
        raise StorageError("invalid quarantine file records")
    store.assert_mutations_allowed()
    session_lock = ChallengeLock(paths.runtime / "session.lock", timeout=0)
    state_lock = ChallengeLock(paths.lock, timeout=0)
    try:
        session_lock.acquire()
        state_lock.acquire()
    except LockTimeout as error:
        state_lock.release()
        session_lock.release()
        raise StorageError(
            "active challenge work blocks storage restore"
        ) from error
    try:
        restored: list[str] = []
        for item in records:
            relative = _safe_relative(item.get("path"))
            source = root / "files" / relative
            destination = paths.root / relative
            if not source.exists():
                if (
                    destination.is_file()
                    and sha256_file(destination) == item.get("sha256")
                ):
                    continue
                raise StorageError(
                    f"quarantine source is missing: {relative}"
                )
            if destination.exists():
                raise StorageError(f"restore destination exists: {relative}")
            if sha256_file(source) != item.get("sha256"):
                raise StorageError(f"quarantine hash mismatch: {relative}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, destination)
            restored.append(relative.as_posix())
        manifest["status"] = "restored"
        atomic_write_json(root / "manifest.json", manifest)
        return {
            "quarantine_id": quarantine_id,
            "restored": restored,
            "permanent_delete_performed": False,
        }
    finally:
        state_lock.release()
        session_lock.release()


__all__ = [
    "StorageError",
    "quarantine_unreachable",
    "restore_quarantine",
    "storage_inventory",
    "storage_plan",
]
