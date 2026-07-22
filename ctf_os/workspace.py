from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
from typing import Any, Iterator, Mapping, Sequence

from .attempts import (
    ATTEMPT_SCHEMA_VERSION, AttemptError, challenge_instance_id as derive_challenge_instance_id,
    challenge_snapshot_digest as derive_challenge_snapshot_digest,
    legacy_identity as derive_legacy_identity, run_id_for_attempt, safe_attempt_id,
)
from .contest import ChallengeSpec, ContestManifest


RUN_SCHEMA_VERSION = 4
ACTIVE_RUN_SCHEMA_VERSION = 1
RUN_MANIFEST_SCHEMA_VERSION = 2
TARGET_REVISION_SCHEMA_VERSION = 1
CURRENT_FINGERPRINT_SCHEME = "challenge-local-v2"
LEGACY_FINGERPRINT_SCHEME = "challenge-v1"
IMMUTABLE_RUN_STATUSES = frozenset({
    "ACCEPTED", "SEALED", "SOLVED", "SEALED_CLEAN", "HANDOFF", "SUPERSEDED",
})
LEGACY_RUN_FILES = (
    "STATE.json", "RESULT.md", "FINDINGS.md", "evidence.log", "findings.jsonl",
    "ATTACK_EVENTS.jsonl", "SWARM.json", "RESOURCE_STATE.json",
    "RESOURCE_HISTORY.jsonl", "REPRODUCE.json", "reproduce.sh",
    "post-commit-errors.jsonl",
)
LEGACY_RUN_DIRECTORIES = ("flag-receipts", "workers", "exploit", "artifacts", "evidence")


class WorkspaceError(ValueError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def challenge_root(repo: Path, manifest: ContestManifest, challenge: ChallengeSpec) -> Path:
    return safe_under(repo / "output", Path(manifest.slug) / challenge.category / challenge.workspace_name)


def safe_under(root: Path, relative: Path) -> Path:
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError(f"unsafe relative path: {relative}")
    if root.is_symlink():
        raise ValueError(f"workspace root must not be a symlink: {root}")
    base = root.resolve()
    raw_candidate = base / relative
    current = base
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"workspace path contains a symlink: {current}")
    candidate = raw_candidate.resolve(strict=False)
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise ValueError(f"path escapes root: {relative}") from exc
    return candidate


def atomic_json(path: Path, payload: object) -> None:
    atomic_text(path, json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def atomic_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise WorkspaceError(f"atomic write target must not be a symlink: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def challenge_workspace(root: Path) -> Path:
    """Return the challenge workspace for either a workspace or a run path."""

    resolved = root.resolve(strict=False)
    if resolved.parent.name == "runs":
        return resolved.parent.parent
    return resolved


def is_run_root(root: Path) -> bool:
    resolved = root.resolve(strict=False)
    return resolved.parent.name == "runs" and resolved.name not in {"", ".", ".."}


def resolve_active_run(
    root: Path, *, input_fingerprint: str | None = None,
    target_revision: int | None = None, migrate: bool = True,
) -> Path:
    """Resolve the authoritative run while accepting a legacy direct run root.

    A path below ``runs/`` is already authoritative.  A challenge workspace is
    resolved through ``ACTIVE_RUN.json``.  Standalone unit/legacy roots without
    an active pointer remain usable until enough challenge identity exists to
    migrate them safely.
    """

    if is_run_root(root):
        run = root.resolve(strict=False)
        _recover_state_if_needed(run)
        _validate_run_identity(run, input_fingerprint, target_revision)
        return run
    workspace = challenge_workspace(root)
    pointer_path = workspace / "ACTIVE_RUN.json"
    if not pointer_path.exists() and migrate and (workspace / "STATE.json").is_file():
        with state_lock(workspace):
            _migrate_legacy_unlocked(workspace)
    if not pointer_path.exists():
        return workspace
    pointer = _load_json_object(pointer_path, "active run pointer")
    if pointer.get("schema_version") != ACTIVE_RUN_SCHEMA_VERSION:
        raise WorkspaceError("ACTIVE_RUN.json has an unsupported schema_version")
    run_id = _identifier(pointer.get("run_id"), "run_id")
    run = safe_under(workspace / "runs", Path(run_id))
    if not run.is_dir() or run.is_symlink():
        raise WorkspaceError("active run directory is missing or unsafe")
    _recover_state_if_needed(run, pointer=pointer)
    state = _validate_run_identity(run, input_fingerprint, target_revision)
    if pointer.get("input_fingerprint") != state.get("input_fingerprint"):
        raise WorkspaceError("active run pointer fingerprint does not match run state")
    if pointer.get("target_revision") != state.get("target_revision"):
        raise WorkspaceError("active run pointer target revision does not match run state")
    return run


def resolve_run_raw(root: Path, *, run_id: str | None = None) -> Path:
    """Resolve one exact run without consulting its STATE.json projection."""

    if is_run_root(root):
        run = root.resolve(strict=False)
        if run_id is not None and run.name != _identifier(run_id, "run_id"):
            raise WorkspaceError("requested run_id does not match the supplied run path")
        if run.is_symlink() or not run.is_dir():
            raise WorkspaceError("run directory is missing or unsafe")
        return run
    workspace = challenge_workspace(root)
    selected_id = run_id
    if selected_id is None:
        pointer = _load_json_object(workspace / "ACTIVE_RUN.json", "active run pointer")
        if pointer.get("schema_version") != ACTIVE_RUN_SCHEMA_VERSION:
            raise WorkspaceError("ACTIVE_RUN.json has an unsupported schema_version")
        selected_id = _identifier(pointer.get("run_id"), "run_id")
    run = safe_under(workspace / "runs", Path(_identifier(selected_id, "run_id")))
    if run.is_symlink() or not run.is_dir():
        raise WorkspaceError("requested run directory is missing or unsafe")
    return run


def recover_run_state(root: Path, *, run_id: str | None = None, force: bool = True) -> dict[str, Any]:
    """Rebuild STATE.json deterministically from run-local authoritative sources."""

    run = resolve_run_raw(root, run_id=run_id)
    with state_lock(run):
        state = _recover_run_state_unlocked(run, force=force)
    return state


def active_run_id(root: Path) -> str | None:
    run = resolve_active_run(root)
    if run == challenge_workspace(root):
        state_path = run / "STATE.json"
        if not state_path.is_file():
            return None
    state = _load_json_object(run / "STATE.json", "run state")
    value = state.get("run_id")
    return str(value) if value else None


def resolve_exact_run(root: Path, run_id: str) -> Path:
    """Resolve exactly one attempt and never consult ACTIVE_RUN.json as fallback."""

    selected = _identifier(run_id, "run_id")
    if is_run_root(root):
        run = root.resolve(strict=False)
        if run.name != selected:
            raise WorkspaceError("exact run_id does not match supplied run root")
    else:
        run = safe_under(challenge_workspace(root) / "runs", Path(selected))
    if run.is_symlink() or not run.is_dir():
        raise WorkspaceError("exact run_id does not exist in this challenge workspace")
    _recover_state_if_needed(run)
    return run


def resume_attempt(root: Path, *, run_id: str | None = None) -> Path:
    """Resume current compatibility attempt, or an explicitly named attempt."""

    return resolve_exact_run(root, run_id) if run_id is not None else resolve_active_run(root)


def list_attempts(root: Path) -> list[dict[str, Any]]:
    workspace = challenge_workspace(root)
    runs = workspace / "runs"
    if runs.is_symlink():
        raise WorkspaceError("attempt directory must not be a symlink")
    values: list[dict[str, Any]] = []
    if not runs.is_dir():
        return values
    for path in sorted(runs.iterdir(), key=lambda item: item.name):
        if path.is_symlink() or not path.is_dir():
            continue
        try:
            values.append(show_attempt(path, run_id=path.name))
        except WorkspaceError as exc:
            values.append({"run_id": path.name, "readable": False, "error": str(exc)})
    return sorted(values, key=lambda row: (str(row.get("created_at") or ""), str(row["run_id"])))


def show_attempt(root: Path, *, run_id: str) -> dict[str, Any]:
    run = resolve_exact_run(root, run_id)
    state = _load_json_object(run / "STATE.json", "run state")
    manifest = _load_json_object(run / "RUN_MANIFEST.json", "run manifest")
    identity = manifest.get("identity") if isinstance(manifest.get("identity"), Mapping) else {}
    attempt_id = state.get("attempt_id") or identity.get("attempt_id")
    instance_id = state.get("challenge_instance_id") or identity.get("challenge_instance_id")
    legacy = not (attempt_id and instance_id)
    if legacy:
        snapshot = str(
            state.get("challenge_snapshot_digest")
            or hashlib.sha256(json.dumps({
                "challenge_id": state.get("challenge_id"),
                "input_fingerprint": state.get("input_fingerprint"),
                "target_revision": state.get("target_revision"),
            }, sort_keys=True).encode()).hexdigest()
        )
        derived = derive_legacy_identity(
            challenge_id=str(state.get("challenge_id") or "legacy"),
            input_fingerprint=str(state.get("input_fingerprint") or "UNBOUND"),
            target_revision=int(state.get("target_revision") or 1),
            snapshot_digest=snapshot,
        )
        attempt_id, instance_id = derived["attempt_id"], derived["challenge_instance_id"]
    pending = bool(state.get("remote_flag_receipt") and state.get("competition_state") != "ACCEPTED")
    return {
        "schema_version": ATTEMPT_SCHEMA_VERSION,
        "run_id": run.name, "attempt_id": attempt_id,
        "challenge_instance_id": instance_id, "legacy_identity": legacy,
        "status": state.get("status"), "sealed": bool(state.get("sealed")),
        "pending_submission": pending, "created_at": state.get("created_at"),
        "path": str(run), "readable": True,
    }


def start_fresh_attempt(
    root: Path, challenge: ChallengeSpec, fingerprint: str, *,
    target_revision: int | None = None, attempt_id: str | None = None,
    transformation_seed: str | int | None = None,
    requested_model: str = "", requested_reasoning: str = "",
    publish_active: bool = True, local_target_image_digest: str | None = None,
) -> Path:
    return bind_input_fingerprint(
        root, challenge, fingerprint, target_revision=target_revision,
        requested_model=requested_model, requested_reasoning=requested_reasoning,
        fresh_attempt=True, attempt_id=attempt_id,
        transformation_seed=transformation_seed, publish_active=publish_active,
        local_target_image_digest=local_target_image_digest,
    )


def ensure_run_mutable(root: Path) -> Path:
    run = resolve_active_run(root, migrate=False)
    state_path = run / "STATE.json"
    if state_path.is_file():
        state = _load_json_object(state_path, "run state")
        if state.get("sealed") or state.get("status") in IMMUTABLE_RUN_STATUSES:
            raise WorkspaceError("sealed run is immutable")
        if state.get("remote_flag_receipt"):
            raise WorkspaceError("verified remote flag run is immutable pending human submission feedback")
    return run


def initialize_solve_files(
    root: Path, challenge: ChallengeSpec, input_fingerprint: str | None = None,
    *, target_revision: int | None = None, requested_model: str = "",
    requested_reasoning: str = "", fresh_attempt: bool = False,
    attempt_id: str | None = None, transformation_seed: str | int | None = None,
    publish_active: bool = True, local_target_image_digest: str | None = None,
) -> Path:
    """Create or resolve one immutable-generation solve run.

    The returned path is the authoritative run root.  Challenge input remains
    at the challenge workspace and is mounted read-only by sandbox code.
    """

    requested_model = requested_model or os.environ.get("CTF_OS_REQUESTED_MODEL", "")
    requested_reasoning = requested_reasoning or os.environ.get("CTF_OS_REQUESTED_REASONING", "")
    workspace = challenge_workspace(root)
    workspace.mkdir(parents=True, exist_ok=True)
    with state_lock(workspace):
        _migrate_legacy_unlocked(workspace, challenge=challenge)
        pointer = _active_pointer_unlocked(workspace)
        if pointer and not fresh_attempt and attempt_id is None:
            active = workspace / "runs" / str(pointer["run_id"])
            if input_fingerprint in {None, pointer.get("input_fingerprint")} and (
                target_revision is None or target_revision == pointer.get("target_revision")
            ):
                _ensure_run_files(active, challenge)
                return active
        fingerprint = input_fingerprint or "UNBOUND"
        revision = target_revision or _record_target_revision_unlocked(
            workspace, tuple(getattr(challenge, "remotes", ()) or ()), source="contest-manifest",
        )
        return _create_run_unlocked(
            workspace, challenge=challenge, fingerprint=fingerprint,
            target_revision=revision, requested_model=requested_model,
            requested_reasoning=requested_reasoning, fresh_attempt=fresh_attempt,
            attempt_id=attempt_id, transformation_seed=transformation_seed,
            publish_active=publish_active,
            local_target_image_digest=local_target_image_digest,
        )


def bind_input_fingerprint(
    root: Path, challenge: ChallengeSpec, fingerprint: str, *,
    target_revision: int | None = None, requested_model: str = "",
    requested_reasoning: str = "", legacy_fingerprints: Sequence[str] = (),
    fresh_attempt: bool = False, attempt_id: str | None = None,
    transformation_seed: str | int | None = None,
    publish_active: bool = True, local_target_image_digest: str | None = None,
) -> Path:
    """Bind a run without mutating or erasing any previous run generation."""

    requested_model = requested_model or os.environ.get("CTF_OS_REQUESTED_MODEL", "")
    requested_reasoning = requested_reasoning or os.environ.get("CTF_OS_REQUESTED_REASONING", "")
    if not isinstance(fingerprint, str) or not fingerprint.strip():
        raise WorkspaceError("input fingerprint must be a non-empty string")
    workspace = challenge_workspace(root)
    workspace.mkdir(parents=True, exist_ok=True)
    with state_lock(workspace):
        legacy = _migrate_legacy_unlocked(workspace, challenge=challenge)
        revision = target_revision or _record_target_revision_unlocked(
            workspace, tuple(getattr(challenge, "remotes", ()) or ()), source="contest-manifest",
        )
        pointer = _active_pointer_unlocked(workspace)
        if (
            pointer and not fresh_attempt and attempt_id is None
            and pointer.get("input_fingerprint") == fingerprint
            and pointer.get("target_revision") == revision
        ):
            run = workspace / "runs" / str(pointer["run_id"])
            if not (run / "STATE.json").is_file():
                return _create_run_unlocked(
                    workspace, challenge=challenge, fingerprint=fingerprint,
                    target_revision=revision, requested_model=requested_model,
                    requested_reasoning=requested_reasoning,
                    publish_active=publish_active,
                    local_target_image_digest=local_target_image_digest,
                )
            try:
                _validate_run_identity(run, fingerprint, revision)
            except WorkspaceError:
                _recover_run_state_unlocked(run, force=True)
            _validate_run_identity(run, fingerprint, revision)
            _stamp_fingerprint_scheme(run, workspace)
            return run
        if (
            not fresh_attempt and attempt_id is None
            and
            pointer and pointer.get("input_fingerprint") in set(legacy_fingerprints)
            and pointer.get("target_revision") == revision
        ):
            return _migrate_fingerprint_run_unlocked(
                workspace, challenge=challenge, pointer=pointer,
                fingerprint=fingerprint, target_revision=revision,
                requested_model=requested_model,
                requested_reasoning=requested_reasoning,
            )
        run = _create_run_unlocked(
            workspace, challenge=challenge, fingerprint=fingerprint,
            target_revision=revision, requested_model=requested_model,
            requested_reasoning=requested_reasoning, fresh_attempt=fresh_attempt,
            attempt_id=attempt_id, transformation_seed=transformation_seed,
            publish_active=publish_active,
            local_target_image_digest=local_target_image_digest,
        )
        # A legacy STATE.json is retained only as a non-authoritative
        # compatibility projection. Fresh workspaces never create it.
        if legacy or (workspace / "STATE.json").is_file():
            projected = _load_json_object(run / "STATE.json", "run state")
            projected["compatibility_view"] = True
            projected["authoritative_state"] = str((run / "STATE.json").relative_to(workspace))
            atomic_json(workspace / "STATE.json", projected)
        return run


def record_target_revision(
    root: Path, declared_targets: Sequence[str | Mapping[str, Any]], *, source: str,
) -> int:
    workspace = challenge_workspace(root)
    workspace.mkdir(parents=True, exist_ok=True)
    with state_lock(workspace):
        return _record_target_revision_unlocked(workspace, declared_targets, source=source)


def target_revisions(root: Path) -> list[dict[str, Any]]:
    return read_jsonl_strict(challenge_workspace(root) / "target-revisions.jsonl", "target revision ledger")


def append_jsonl_fsync(path: Path, payload: Mapping[str, Any], *, label: str = "ledger") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise WorkspaceError(f"{label} must not be a symlink")
    line = json.dumps(dict(payload), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    descriptor = os.open(
        path, os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600,
    )
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())
    _fsync_directory(path.parent)


def read_jsonl_strict(path: Path, label: str = "ledger") -> list[dict[str, Any]]:
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file():
        raise WorkspaceError(f"{label} is missing or unsafe")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        recovery = path.with_name(f"{path.name}.recovery-{utc_now().replace(':', '')}.txt")
        atomic_text(recovery, f"Unreadable {label}; original ledger preserved.\n")
        raise WorkspaceError(f"{label} is unreadable; recovery note: {recovery}") from exc
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            recovery = path.with_name(f"{path.name}.recovery-{utc_now().replace(':', '')}.txt")
            atomic_text(recovery, f"Malformed {label} line {line_number}; original ledger preserved.\n")
            raise WorkspaceError(f"{label} line {line_number} is malformed; recovery note: {recovery}") from exc
        if not isinstance(row, dict):
            recovery = path.with_name(f"{path.name}.recovery-{utc_now().replace(':', '')}.txt")
            atomic_text(recovery, f"Non-object {label} line {line_number}; original ledger preserved.\n")
            raise WorkspaceError(
                f"{label} line {line_number} is not an object; recovery note: {recovery}"
            )
        rows.append(row)
    return rows


@contextmanager
def state_lock(root: Path) -> Iterator[None]:
    workspace = challenge_workspace(root)
    workspace.mkdir(parents=True, exist_ok=True)
    # One stable challenge-local lock covers migration, pointer changes, and all
    # run ledgers. Changing names during first migration would open a race.
    with _workspace_lock(workspace / ".RUNS.lock", "challenge run state"):
        yield


@contextmanager
def preflight_lock(root: Path) -> Iterator[None]:
    """Serialize preparation only for this exact challenge workspace."""

    workspace = challenge_workspace(root)
    workspace.mkdir(parents=True, exist_ok=True)
    with _workspace_lock(workspace / ".PREFLIGHT.lock", "challenge preflight"):
        yield


@contextmanager
def _workspace_lock(lock_path: Path, label: str) -> Iterator[None]:
    if lock_path.is_symlink():
        raise ValueError(f"{label} lock file must not be a symlink")
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _create_run_unlocked(
    workspace: Path, *, challenge: ChallengeSpec, fingerprint: str,
    target_revision: int, requested_model: str, requested_reasoning: str,
    fresh_attempt: bool = False, attempt_id: str | None = None,
    transformation_seed: str | int | None = None,
    publish_active: bool = True, local_target_image_digest: str | None = None,
) -> Path:
    snapshot_digest = derive_challenge_snapshot_digest(
        workspace, challenge, input_fingerprint=fingerprint,
        target_revision=target_revision, transformation_seed=transformation_seed,
        local_target_image_digest=local_target_image_digest,
    )
    instance_id = derive_challenge_instance_id(
        challenge_id=str(challenge.id), input_fingerprint=fingerprint,
        target_revision=target_revision, challenge_snapshot_digest=snapshot_digest,
        transformation_seed=transformation_seed,
    )
    selected_attempt_id = safe_attempt_id(attempt_id)
    run_id = run_id_for_attempt(instance_id, selected_attempt_id)
    run = safe_under(workspace / "runs", Path(run_id))
    if run.exists() and (run.is_symlink() or not run.is_dir()):
        raise WorkspaceError("run path exists but is not a safe directory")
    if run.exists() and (fresh_attempt or attempt_id is not None):
        raise WorkspaceError(f"duplicate attempt_id is rejected: {selected_attempt_id}")
    run.mkdir(parents=True, exist_ok=True)
    state_path = run / "STATE.json"
    if state_path.exists():
        try:
            state = _validate_run_identity(run, fingerprint, target_revision)
        except WorkspaceError:
            if (run / "RUN_MANIFEST.json").is_file():
                state = _recover_run_state_unlocked(run, force=True)
                if state.get("input_fingerprint") != fingerprint or state.get("target_revision") != target_revision:
                    raise WorkspaceError("recovered run identity conflicts with requested generation")
            else:
                raise
        if state.get("challenge_id") != challenge.id:
            raise WorkspaceError("content-derived run id collides with another challenge")
    elif (run / "RUN_MANIFEST.json").is_file():
        state = _recover_run_state_unlocked(run, force=True)
        if (
            state.get("challenge_id") != challenge.id
            or state.get("input_fingerprint") != fingerprint
            or state.get("target_revision") != target_revision
        ):
            raise WorkspaceError("recovered run identity conflicts with requested generation")
    else:
        now = utc_now()
        atomic_json(state_path, {
            "schema_version": RUN_SCHEMA_VERSION, "run_id": run_id,
            "challenge_instance_id": instance_id, "attempt_id": selected_attempt_id,
            "legacy_identity": False,
            "challenge_id": challenge.id, "status": "PREPARED", "sealed": False,
            "cleanup_state": "NOT_STARTED", "branches": [],
            "flag_candidate": None, "active_candidate_id": None, "candidates": [],
            "verification": {}, "replay_verdict": None, "competition_state": None,
            "remote_flag": None, "submission_recommended": False,
            "remote_flag_receipt": None, "remote_candidate_receipt": None, "flag_history": [],
            "submission_history": [],
            "input_fingerprint": fingerprint, "target_revision": target_revision,
            "challenge_snapshot_digest": snapshot_digest,
            "transformation_seed": "NONE" if transformation_seed is None else str(transformation_seed),
            "solve_engine": "first-to-flag",
            "active_child_width": 0,
            "fingerprint_scheme": CURRENT_FINGERPRINT_SCHEME,
            "created_at": now, "updated_at": now,
        })
        _ensure_run_files(run, challenge)
        atomic_json(run / "RUN_MANIFEST.json", _run_manifest(
            workspace, challenge, run_id, fingerprint, target_revision,
            requested_model=requested_model, requested_reasoning=requested_reasoning,
            challenge_instance_id=instance_id, attempt_id=selected_attempt_id,
            challenge_snapshot_digest=snapshot_digest,
            transformation_seed=transformation_seed,
        ))
    pointer = {
        "schema_version": ACTIVE_RUN_SCHEMA_VERSION, "run_id": run_id,
        "challenge_id": challenge.id, "input_fingerprint": fingerprint,
        "target_revision": target_revision, "updated_at": utc_now(),
        "challenge_instance_id": instance_id, "attempt_id": selected_attempt_id,
        "fingerprint_scheme": CURRENT_FINGERPRINT_SCHEME,
    }
    if publish_active:
        atomic_json(workspace / "ACTIVE_RUN.json", pointer)
    return run


def _ensure_run_files(run: Path, challenge: ChallengeSpec) -> None:
    findings = run / "FINDINGS.md"
    if not findings.exists():
        atomic_text(findings, f"# Findings — {challenge.key}\n\nNo findings recorded yet.\n")
    for name in ("evidence.log", "ATTACK_EVENTS.jsonl"):
        path = run / name
        if path.is_symlink():
            raise WorkspaceError(f"run ledger must not be a symlink: {path}")
        path.touch(exist_ok=True)
    (run / "artifacts").mkdir(exist_ok=True)


def _migrate_legacy_unlocked(workspace: Path, challenge: ChallengeSpec | None = None) -> bool:
    if (workspace / "ACTIVE_RUN.json").exists():
        return False
    legacy_state = workspace / "STATE.json"
    if not legacy_state.is_file() or legacy_state.is_symlink():
        return False
    state = _load_json_object(legacy_state, "legacy challenge state")
    challenge_id = str(state.get("challenge_id") or getattr(challenge, "id", ""))
    if not challenge_id:
        raise WorkspaceError("legacy state has no challenge_id and cannot be migrated safely")
    fingerprint = str(state.get("input_fingerprint") or "UNBOUND")
    revision = int(state.get("target_revision") or 1)
    run_id = "legacy-" + hashlib.sha256(
        f"{challenge_id}\0{fingerprint}\0{revision}".encode(),
    ).hexdigest()[:20]
    run = safe_under(workspace / "runs", Path(run_id))
    run.mkdir(parents=True, exist_ok=True)
    if not (run / "STATE.json").exists():
        migrated = dict(state)
        migrated.update({
            "schema_version": RUN_SCHEMA_VERSION, "run_id": run_id,
            "input_fingerprint": fingerprint,
            "target_revision": revision, "migrated_from_legacy": True,
            "sealed": bool(state.get("sealed") or state.get("status") in IMMUTABLE_RUN_STATUSES),
            "fingerprint_scheme": state.get("fingerprint_scheme") or LEGACY_FINGERPRINT_SCHEME,
        })
        migrated.setdefault("flag_history", [])
        migrated.setdefault("submission_recommended", False)
        migrated.setdefault("remote_flag_receipt", None)
        migrated.setdefault("remote_candidate_receipt", None)
        migrated.setdefault("submission_history", [])
        migrated.setdefault("active_candidate_id", None)
        migrated.setdefault("candidates", [])
        migrated.setdefault("created_at", state.get("updated_at") or utc_now())
        migrated["updated_at"] = utc_now()
        atomic_json(run / "STATE.json", migrated)
    # Every step below is restartable. If the process stopped after STATE.json
    # but before publishing ACTIVE_RUN.json, the next migration fills only the
    # missing compatibility files and then publishes the pointer.
    for name in LEGACY_RUN_FILES:
        source = workspace / name
        target = run / name
        if name == "STATE.json" or not source.is_file() or source.is_symlink() or target.exists():
            continue
        if name.endswith(".json"):
            atomic_json(target, _load_json_object(source, f"legacy {name}"))
        else:
            atomic_text(target, source.read_text(encoding="utf-8"))
    for name in LEGACY_RUN_DIRECTORIES:
        source = workspace / name
        target = run / name
        if source.is_dir() and not source.is_symlink():
            _copy_tree_without_symlinks(source, target)
    if challenge is not None:
        _ensure_run_files(run, challenge)
    else:
        for name in ("evidence.log", "ATTACK_EVENTS.jsonl"):
            (run / name).touch(exist_ok=True)
        (run / "artifacts").mkdir(exist_ok=True)
    if not (run / "RUN_MANIFEST.json").exists():
        placeholder = challenge or _LegacyChallenge(challenge_id)
        atomic_json(run / "RUN_MANIFEST.json", _run_manifest(
            workspace, placeholder, run_id, fingerprint, revision,
            requested_model="", requested_reasoning="",
        ))
    atomic_json(workspace / "ACTIVE_RUN.json", {
        "schema_version": ACTIVE_RUN_SCHEMA_VERSION, "run_id": run_id,
        "challenge_id": challenge_id, "input_fingerprint": fingerprint,
        "target_revision": revision, "legacy_compatibility_view": True,
        "fingerprint_scheme": state.get("fingerprint_scheme") or LEGACY_FINGERPRINT_SCHEME,
        "updated_at": utc_now(),
    })
    return True


class _LegacyChallenge:
    def __init__(self, challenge_id: str) -> None:
        self.id = challenge_id
        self.key = challenge_id


def _record_target_revision_unlocked(
    workspace: Path, declared_targets: Sequence[str | Mapping[str, Any]], *, source: str,
) -> int:
    normalized: list[Any] = []
    for target in declared_targets:
        if isinstance(target, Mapping):
            normalized.append(json.loads(json.dumps(dict(target), sort_keys=True)))
        elif (
            isinstance(target, str) and target
            and target == target.strip() and "\n" not in target and "\r" not in target
        ):
            normalized.append(target)
        else:
            raise WorkspaceError("declared target revisions require strings or objects")
    path = workspace / "target-revisions.jsonl"
    rows = read_jsonl_strict(path, "target revision ledger")
    if rows and rows[-1].get("declared_target") == normalized:
        return int(rows[-1]["target_revision"])
    revision = int(rows[-1]["target_revision"]) + 1 if rows else 1
    record = {
        "schema_version": TARGET_REVISION_SCHEMA_VERSION,
        "target_revision": revision, "declared_target": normalized,
        "source": str(source), "created_at": utc_now(),
        "supersedes": int(rows[-1]["target_revision"]) if rows else None,
    }
    append_jsonl_fsync(path, record, label="target revision ledger")
    return revision


def _run_manifest(
    workspace: Path, challenge: Any, run_id: str, fingerprint: str,
    target_revision: int, *, requested_model: str, requested_reasoning: str,
    challenge_instance_id: str | None = None, attempt_id: str | None = None,
    challenge_snapshot_digest: str | None = None,
    transformation_seed: str | int | None = None,
) -> dict[str, Any]:
    commit, dirty = _repository_identity(workspace)
    started = utc_now()
    return {
        "schema_version": RUN_MANIFEST_SCHEMA_VERSION,
        "challenge_instance_id": challenge_instance_id,
        "attempt_id": attempt_id,
        "run_id": run_id,
        "solve_engine": "first-to-flag",
        "transformation_seed": "NONE" if transformation_seed is None else str(transformation_seed),
        "identity": {
            "challenge_instance_id": challenge_instance_id, "attempt_id": attempt_id,
            "run_id": run_id, "legacy_identity": challenge_instance_id is None,
        },
        "repository": {"commit_sha": commit, "dirty_diff_digest": dirty},
        "runtime": {
            "root_model_request": requested_model or "gpt-5.6-sol",
            "root_reasoning_request": requested_reasoning or "xhigh",
            "model_observation_is_not_an_attack_gate": True,
        },
        "challenge": {
            "challenge_id": challenge.id, "run_id": run_id,
            "input_fingerprint": fingerprint, "target_revision": target_revision,
        },
        "environment": {
            "host_profile": {
                "system": platform.system(), "kernel": platform.release(),
                "machine": platform.machine(), "cpu_count": os.cpu_count(),
            },
            "tool_versions": {"python": platform.python_version()},
            "maximum_model_concurrency": 4,
        },
        "timing": {"started_at": started, "budget_seconds": 90 * 60},
        "challenge_snapshot_digest": challenge_snapshot_digest,
    }


def _repository_identity(start: Path) -> tuple[str, str]:
    repo = next((candidate for candidate in (start, *start.parents) if (candidate / ".git").exists()), None)
    if repo is None:
        return "", ""
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain=v1", "-z"], cwd=repo, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout
        diff = subprocess.run(
            ["git", "diff", "--binary", "HEAD"], cwd=repo, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return "", ""
    return commit, "CLEAN" if not status and not diff else hashlib.sha256(status + b"\0" + diff).hexdigest()


def _active_pointer_unlocked(workspace: Path) -> dict[str, Any] | None:
    path = workspace / "ACTIVE_RUN.json"
    if not path.exists():
        return None
    pointer = _load_json_object(path, "active run pointer")
    if pointer.get("schema_version") != ACTIVE_RUN_SCHEMA_VERSION:
        raise WorkspaceError("ACTIVE_RUN.json has an unsupported schema_version")
    return pointer


def _stamp_fingerprint_scheme(run: Path, workspace: Path) -> None:
    state_path = run / "STATE.json"
    state = _load_json_object(state_path, "run state")
    if state.get("fingerprint_scheme") != CURRENT_FINGERPRINT_SCHEME:
        state["fingerprint_scheme"] = CURRENT_FINGERPRINT_SCHEME
        state["updated_at"] = utc_now()
        atomic_json(state_path, state)
    pointer = _load_json_object(workspace / "ACTIVE_RUN.json", "active run pointer")
    if pointer.get("fingerprint_scheme") != CURRENT_FINGERPRINT_SCHEME:
        pointer["fingerprint_scheme"] = CURRENT_FINGERPRINT_SCHEME
        pointer["updated_at"] = utc_now()
        atomic_json(workspace / "ACTIVE_RUN.json", pointer)


def _migrate_fingerprint_run_unlocked(
    workspace: Path, *, challenge: ChallengeSpec, pointer: Mapping[str, Any],
    fingerprint: str, target_revision: int, requested_model: str,
    requested_reasoning: str,
) -> Path:
    """Clone a byte-equivalent legacy run and atomically publish its v2 identity."""

    source = safe_under(workspace / "runs", Path(_identifier(pointer.get("run_id"), "run_id")))
    legacy_state = _validate_run_identity(source, str(pointer.get("input_fingerprint")), target_revision)
    run_id = _content_run_id(challenge.id, fingerprint, target_revision)
    target = safe_under(workspace / "runs", Path(run_id))
    if target.exists():
        _validate_run_identity(target, fingerprint, target_revision)
    else:
        target.mkdir(parents=True)
        for path in sorted(source.iterdir(), key=lambda item: item.name):
            destination = target / path.name
            if path.is_symlink():
                raise WorkspaceError(f"legacy fingerprint migration contains a symlink: {path}")
            if path.is_dir():
                _copy_tree_without_symlinks(path, destination)
            elif path.name not in {"STATE.json", "RUN_MANIFEST.json"}:
                _atomic_copy_file(path, destination)
        migrated = dict(legacy_state)
        migrated.update({
            "schema_version": RUN_SCHEMA_VERSION, "run_id": run_id,
            "input_fingerprint": fingerprint,
            "fingerprint_scheme": CURRENT_FINGERPRINT_SCHEME,
            "migrated_from_fingerprint": pointer.get("input_fingerprint"),
            "updated_at": utc_now(),
        })
        atomic_json(target / "STATE.json", migrated)
        atomic_json(target / "RUN_MANIFEST.json", _run_manifest(
            workspace, challenge, run_id, fingerprint, target_revision,
            requested_model=requested_model, requested_reasoning=requested_reasoning,
        ))
        _ensure_run_files(target, challenge)
    atomic_json(workspace / "ACTIVE_RUN.json", {
        "schema_version": ACTIVE_RUN_SCHEMA_VERSION, "run_id": run_id,
        "challenge_id": challenge.id, "input_fingerprint": fingerprint,
        "fingerprint_scheme": CURRENT_FINGERPRINT_SCHEME,
        "target_revision": target_revision, "updated_at": utc_now(),
        "migrated_from_run_id": pointer.get("run_id"),
    })
    if (workspace / "STATE.json").is_file():
        projected = _load_json_object(target / "STATE.json", "run state")
        projected["compatibility_view"] = True
        projected["authoritative_state"] = str((target / "STATE.json").relative_to(workspace))
        atomic_json(workspace / "STATE.json", projected)
    return target


def _recover_state_if_needed(
    run: Path, *, pointer: Mapping[str, Any] | None = None,
) -> None:
    path = run / "STATE.json"
    healthy = False
    if path.is_file() and not path.is_symlink():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            healthy = (
                isinstance(payload, dict)
                and payload.get("schema_version") in {1, 2, 3, RUN_SCHEMA_VERSION}
                and payload.get("run_id") == run.name
            )
        except (OSError, json.JSONDecodeError):
            healthy = False
    if healthy:
        return
    with state_lock(run):
        _recover_run_state_unlocked(run, pointer=pointer, force=True)


def _recover_run_state_unlocked(
    run: Path, *, pointer: Mapping[str, Any] | None = None, force: bool,
) -> dict[str, Any]:
    path = run / "STATE.json"
    preserve_corrupt = False
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise WorkspaceError("run state is unsafe")
        try:
            current_state = json.loads(path.read_text(encoding="utf-8"))
            preserve_corrupt = not isinstance(current_state, dict)
        except (OSError, json.JSONDecodeError):
            preserve_corrupt = True
    if not force and path.is_file() and not path.is_symlink():
        return _load_json_object(path, "run state")
    manifest = _load_json_object(run / "RUN_MANIFEST.json", "run manifest")
    challenge = manifest.get("challenge")
    timing = manifest.get("timing")
    if not isinstance(challenge, Mapping) or not isinstance(timing, Mapping):
        raise WorkspaceError("run manifest cannot recover run identity")
    run_id = _identifier(challenge.get("run_id") or run.name, "run_id")
    if run_id != run.name:
        raise WorkspaceError("run manifest run_id does not match its directory")
    challenge_id = _identifier(challenge.get("challenge_id"), "challenge_id")
    fingerprint = str(challenge.get("input_fingerprint") or "").strip()
    revision = challenge.get("target_revision")
    if not fingerprint or not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise WorkspaceError("run manifest identity is incomplete")
    _validate_recovery_target_revision(run, revision)
    recovery_warnings = _recovery_resource_warnings(
        run, run_id, challenge_id, fingerprint, revision,
    )

    started_at = str(timing.get("started_at") or "")
    if not started_at:
        raise WorkspaceError("run manifest has no deterministic start time")
    if manifest.get("solve_engine") == "first-to-flag":
        swarm_path = run / "SWARM.json"
        swarm = (
            _load_json_object(swarm_path, "swarm state")
            if swarm_path.is_file() and not swarm_path.is_symlink() else {}
        )
        if swarm and (
            swarm.get("run_id") != run_id
            or swarm.get("challenge_id") != challenge_id
            or swarm.get("input_fingerprint") != fingerprint
        ):
            raise WorkspaceError("swarm identity does not match its exact attempt")
        events = read_jsonl_strict(run / "ATTACK_EVENTS.jsonl", "attack event ledger")
        _validate_recovery_identities(run_id, challenge_id, fingerprint, revision, events)
        lanes = _recovery_branches(run)
        engine_status = str(swarm.get("status") or "")
        projected_status = {
            "ACTIVE": "SWARM_ACTIVE",
            "FLAG_FOUND": "SUBMISSION_RECOMMENDED",
            "ACCEPTED": "ACCEPTED",
            "TIMED_OUT": "TIMED_OUT",
            "HANDOFF": "HANDOFF",
            "SUPERSEDED": "SUPERSEDED",
        }.get(engine_status, "PREPARED")
        winner = swarm.get("winner") if isinstance(swarm.get("winner"), Mapping) else {}
        submission_history = (
            [dict(row) for row in swarm.get("submission_history", []) if isinstance(row, Mapping)]
            if isinstance(swarm.get("submission_history"), list) else []
        )
        state = {
            "schema_version": RUN_SCHEMA_VERSION, "run_id": run_id,
            "challenge_instance_id": manifest.get("challenge_instance_id"),
            "attempt_id": manifest.get("attempt_id"),
            "legacy_identity": not bool(manifest.get("challenge_instance_id") and manifest.get("attempt_id")),
            "challenge_id": challenge_id, "status": projected_status,
            "sealed": projected_status == "ACCEPTED",
            "cleanup_state": "NOT_STARTED", "branches": lanes,
            "flag_candidate": winner.get("candidate"),
            "competition_state": engine_status or None,
            "submission_recommended": projected_status == "SUBMISSION_RECOMMENDED",
            "submission_history": submission_history,
            "input_fingerprint": fingerprint, "target_revision": revision,
            "challenge_snapshot_digest": manifest.get("challenge_snapshot_digest"),
            "transformation_seed": manifest.get("transformation_seed", "NONE"),
            "solve_engine": "first-to-flag",
            "active_child_width": sum(row.get("status") == "RUNNING" for row in lanes),
            "fingerprint_scheme": CURRENT_FINGERPRINT_SCHEME,
            "created_at": started_at,
            "updated_at": str(swarm.get("updated_at") or started_at),
        }
        if recovery_warnings:
            state["recovery_warnings"] = recovery_warnings
        if preserve_corrupt:
            _preserve_corrupt_state(path)
        atomic_json(path, state)
        return state
    raise WorkspaceError("run manifest does not use the one live first-to-flag engine")


def _validate_recovery_target_revision(run: Path, revision: int) -> None:
    path = challenge_workspace(run) / "target-revisions.jsonl"
    rows = read_jsonl_strict(path, "target revision ledger")
    if not rows:
        return  # Legacy runs may predate the append-only target ledger.
    for row in rows:
        value = row.get("target_revision")
        if (
            row.get("schema_version") != TARGET_REVISION_SCHEMA_VERSION
            or not isinstance(value, int) or isinstance(value, bool) or value < 1
        ):
            raise WorkspaceError("target revision ledger contains an unsupported row")
    if not any(row.get("target_revision") == revision for row in rows):
        raise WorkspaceError("run target revision is absent from the authoritative target ledger")


def _recovery_resource_warnings(
    run: Path, run_id: str, challenge_id: str, fingerprint: str, revision: int,
) -> list[str]:
    path = run / "RESOURCE_STATE.json"
    if not path.exists():
        return []
    try:
        resource = _load_json_object(path, "resource ledger")
    except WorkspaceError as exc:
        return [str(exc)[:2000]]
    warnings: list[str] = []
    for key, value in {
        "run_id": run_id, "challenge_id": challenge_id,
        "input_fingerprint": fingerprint, "target_revision": revision,
    }.items():
        if key in resource and resource.get(key) not in {None, value}:
            warnings.append(f"resource ledger {key} does not match run identity")
    for field in ("requests", "observations"):
        if field in resource and not isinstance(resource.get(field), dict):
            warnings.append(f"resource ledger {field} is malformed")
    return warnings


def _validate_recovery_identities(
    run_id: str, challenge_id: str, fingerprint: str, revision: int,
    rows: Sequence[Mapping[str, Any]],
) -> None:
    for row in rows:
        expected = {
            "run_id": run_id, "challenge_id": challenge_id,
            "input_fingerprint": fingerprint, "target_revision": revision,
        }
        for key, value in expected.items():
            if key in row and row.get(key) != value:
                raise WorkspaceError(f"authoritative receipt {key} does not match run identity")


def _recovery_branches(run: Path) -> list[dict[str, Any]]:
    path = run / "SWARM.json"
    if not path.exists():
        return []
    plan = _load_json_object(path, "swarm state")
    rows = plan.get("lanes")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise WorkspaceError("swarm lanes are malformed")
    return [
        {
            "id": row.get("id"), "session_id": row.get("native_session"),
            "status": row.get("status"), "role": row.get("role"),
            **({"metadata_path": row.get("worker_paths", {}).get("metadata_path")}
               if isinstance(row.get("worker_paths"), Mapping) else {}),
        }
        for row in rows if row.get("id")
    ]


def _preserve_corrupt_state(path: Path) -> Path:
    if path.is_symlink() or not path.is_file():
        raise WorkspaceError("corrupt STATE.json is unsafe and cannot be preserved")
    content = path.read_bytes()
    digest = hashlib.sha256(content).hexdigest()[:12]
    timestamp = utc_now().replace(":", "").replace("-", "")
    destination = path.with_name(f"STATE.corrupt-{timestamp}-{digest}.json")
    os.replace(path, destination)
    _fsync_directory(path.parent)
    return destination


def _validate_run_identity(
    run: Path, fingerprint: str | None, target_revision: int | None,
) -> dict[str, Any]:
    state = _load_json_object(run / "STATE.json", "run state")
    if state.get("schema_version") not in {1, 2, 3, RUN_SCHEMA_VERSION}:
        raise WorkspaceError("run STATE.json has an unsupported schema_version")
    if state.get("run_id") != run.name:
        raise WorkspaceError("run state run_id does not match its directory")
    if fingerprint is not None and state.get("input_fingerprint") != fingerprint:
        raise WorkspaceError("active run input fingerprint mismatch")
    if target_revision is not None and state.get("target_revision") != target_revision:
        raise WorkspaceError("active run target revision mismatch")
    return state


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise WorkspaceError(f"{label} is missing or unsafe")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkspaceError(f"{label} is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise WorkspaceError(f"{label} must be a JSON object")
    return payload


def _content_run_id(challenge_id: str, fingerprint: str, target_revision: int) -> str:
    digest = hashlib.sha256(
        json.dumps(
            {"challenge_id": challenge_id, "input_fingerprint": fingerprint, "target_revision": target_revision},
            sort_keys=True, separators=(",", ":"),
        ).encode(),
    ).hexdigest()[:20]
    return f"run-{target_revision:04d}-{digest}"


def _identifier(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 128 or any(char in text for char in "/\\\0\r\n") or text in {".", ".."}:
        raise WorkspaceError(f"{field} is invalid")
    return text


def _copy_tree_without_symlinks(source: Path, target: Path) -> None:
    for path in source.rglob("*"):
        if path.is_symlink():
            raise WorkspaceError(f"legacy run directory contains a symlink: {path}")
    target.mkdir(parents=True, exist_ok=True)
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        destination = safe_under(target, relative)
        if path.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
        else:
            if destination.is_symlink() or (destination.exists() and not destination.is_file()):
                raise WorkspaceError(f"legacy migration target is unsafe: {destination}")
            if destination.is_file():
                if _same_file_content(path, destination):
                    continue
                raise WorkspaceError(
                    f"legacy migration recovery conflicts with preserved run file: {destination}"
                )
            destination.parent.mkdir(parents=True, exist_ok=True)
            _atomic_copy_file(path, destination)


def _same_file_content(left: Path, right: Path) -> bool:
    if left.stat().st_size != right.stat().st_size:
        return False
    return _file_digest(left) == _file_digest(right)


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_copy_file(source: Path, destination: Path) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with source.open("rb") as input_handle, os.fdopen(descriptor, "wb") as output_handle:
            shutil.copyfileobj(input_handle, output_handle, length=1024 * 1024)
            output_handle.flush()
            os.fsync(output_handle.fileno())
        os.chmod(temporary, source.stat().st_mode & 0o777)
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
