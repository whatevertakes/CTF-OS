"""Fresh race workspaces with atomic, symlink-safe state.

Historical output is deliberately ignored.  The race engine never migrates or
projects an older state schema.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
from typing import Any, Iterator, Mapping

from .contest import ChallengeSpec, ContestManifest


RUN_SCHEMA_VERSION = 1
ACTIVE_SCHEMA_VERSION = 1
_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z")


class WorkspaceError(ValueError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_under(root: Path, relative: Path) -> Path:
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise WorkspaceError(f"unsafe relative path: {relative}")
    base = root.resolve()
    target = (base / relative).resolve(strict=False)
    try:
        target.relative_to(base)
    except ValueError as exc:
        raise WorkspaceError(f"path escapes workspace: {relative}") from exc
    cursor = base
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise WorkspaceError(f"workspace path contains a symlink: {cursor}")
    return target


def challenge_workspace(repo: Path, manifest: ContestManifest, challenge: ChallengeSpec) -> Path:
    return safe_under(
        repo / "output",
        Path(manifest.slug) / "race" / challenge.category / challenge.workspace_name,
    )


def active_pointer(repo: Path) -> Path:
    return safe_under(repo / "output", Path(".active-race.json"))


def create_run(
    repo: Path,
    manifest: ContestManifest,
    challenge: ChallengeSpec,
    *,
    input_fingerprint: str,
    now: str | None = None,
) -> tuple[Path, dict[str, Any]]:
    if not re.fullmatch(r"[0-9a-f]{64}", input_fingerprint):
        raise WorkspaceError("input fingerprint must be a SHA-256 digest")
    root = challenge_workspace(repo, manifest, challenge)
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink():
        raise WorkspaceError("challenge workspace must not be a symlink")
    with state_lock(repo / "output"):
        _assert_no_active_race(repo)
        timestamp = now or utc_now()
        attempt_id = secrets.token_hex(12)
        run_id = f"{challenge.id}-{attempt_id}"
        instance = hashlib.sha256(
            f"{manifest.slug}\0{challenge.id}\0{input_fingerprint}".encode()
        ).hexdigest()[:24]
        run = safe_under(root, Path("runs") / run_id)
        run.mkdir(parents=True, exist_ok=False)
        for relative in ("workers", "receipts", "sessions"):
            path = run / relative
            path.mkdir(mode=0o700)
        manifest_payload: dict[str, Any] = {
            "schema_version": RUN_SCHEMA_VERSION,
            "contest": {"name": manifest.name, "slug": manifest.slug},
            "challenge": challenge.to_dict(),
            "challenge_instance_id": instance,
            "attempt_id": attempt_id,
            "run_id": run_id,
            "input_fingerprint": input_fingerprint,
            "created_at": timestamp,
            "run_root": str(run),
        }
        atomic_json(run / "RUN.json", manifest_payload)
        atomic_json(active_pointer(repo), {
            "schema_version": ACTIVE_SCHEMA_VERSION,
            "run_id": run_id,
            "run_root": str(run),
            "challenge_id": challenge.id,
            "created_at": timestamp,
        })
        return run, manifest_payload


def load_run(run: Path) -> dict[str, Any]:
    payload = read_json(run / "RUN.json", "run manifest")
    if payload.get("schema_version") != RUN_SCHEMA_VERSION:
        raise WorkspaceError("unsupported fresh run schema")
    if Path(str(payload.get("run_root"))).resolve() != run.resolve():
        raise WorkspaceError("run manifest path identity mismatch")
    return payload


def resolve_run(repo: Path, run_id: str | None = None) -> Path:
    pointer = read_json(active_pointer(repo), "active race")
    if pointer.get("schema_version") != ACTIVE_SCHEMA_VERSION:
        raise WorkspaceError("active race schema is unsupported")
    if run_id is not None and pointer.get("run_id") != run_id:
        raise WorkspaceError("requested run is not the exact active race")
    run = Path(str(pointer.get("run_root", ""))).resolve()
    output = (repo / "output").resolve()
    try:
        run.relative_to(output)
    except ValueError as exc:
        raise WorkspaceError("active race path escapes output") from exc
    if run.is_symlink() or not run.is_dir():
        raise WorkspaceError("active race path is missing or unsafe")
    loaded = load_run(run)
    if loaded.get("run_id") != pointer.get("run_id"):
        raise WorkspaceError("active race identity mismatch")
    return run


def clear_active(repo: Path, *, run_id: str) -> None:
    with state_lock(repo / "output"):
        path = active_pointer(repo)
        if not path.exists():
            return
        pointer = read_json(path, "active race")
        if pointer.get("run_id") != run_id:
            raise WorkspaceError("refusing to clear a different active race")
        path.unlink()
        _fsync_dir(path.parent)


def atomic_json(path: Path, payload: object) -> None:
    atomic_text(path, json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def atomic_text(path: Path, content: str) -> None:
    _validate_write_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    descriptor = os.open(
        temporary,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_dir(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def append_jsonl(path: Path, payload: Mapping[str, Any]) -> None:
    _validate_write_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    line = (json.dumps(dict(payload), ensure_ascii=False, sort_keys=True) + "\n").encode()
    with os.fdopen(descriptor, "ab", closefd=True) as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())


def read_json(path: Path, label: str = "state") -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise WorkspaceError(f"{label} is missing or unsafe: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkspaceError(f"{label} is unreadable") from exc
    if not isinstance(payload, dict):
        raise WorkspaceError(f"{label} must be a JSON object")
    return payload


def read_jsonl(path: Path, label: str = "ledger") -> list[dict[str, Any]]:
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file():
        raise WorkspaceError(f"{label} is unsafe")
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise WorkspaceError(f"{label} line {number} is invalid") from exc
        if not isinstance(value, dict):
            raise WorkspaceError(f"{label} line {number} is not an object")
        rows.append(value)
    return rows


@contextmanager
def state_lock(scope: Path) -> Iterator[None]:
    scope.mkdir(parents=True, exist_ok=True)
    if scope.is_symlink():
        raise WorkspaceError("lock scope must not be a symlink")
    lock_path = scope / ".race.lock"
    if lock_path.is_symlink():
        raise WorkspaceError("race lock must not be a symlink")
    descriptor = os.open(
        lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(descriptor, "a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def validate_identifier(value: str, label: str) -> str:
    if not _ID.fullmatch(value):
        raise WorkspaceError(f"invalid {label}: {value!r}")
    return value


def _assert_no_active_race(repo: Path) -> None:
    path = active_pointer(repo)
    if not path.exists():
        return
    pointer = read_json(path, "active race")
    raise WorkspaceError(
        "exactly one challenge may own runtime resources; finish native stops and "
        f"race-cleanup run {pointer.get('run_id')} before preparing another challenge"
    )


def _validate_write_path(path: Path) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise WorkspaceError(f"atomic target is unsafe: {path}")
    cursor = path.parent
    while not cursor.exists() and cursor != cursor.parent:
        cursor = cursor.parent
    if cursor.is_symlink():
        raise WorkspaceError(f"atomic target parent is a symlink: {cursor}")


def _fsync_dir(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
