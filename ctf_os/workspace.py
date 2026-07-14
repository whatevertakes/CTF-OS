from __future__ import annotations

from datetime import datetime, timezone
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import tempfile
from typing import Iterator

from .contest import ChallengeSpec, ContestManifest


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
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def atomic_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def initialize_solve_files(root: Path, challenge: ChallengeSpec, input_fingerprint: str | None = None) -> None:
    root.mkdir(parents=True, exist_ok=True)
    state = root / "STATE.json"
    with state_lock(root):
        if not state.exists():
            atomic_json(state, {
                "schema_version": 1, "challenge_id": challenge.id, "status": "PREPARED",
                "branches": [], "flag_candidate": None, "verification": {},
                "replay_verdict": None, "competition_state": None,
                "remote_flag": None, "submission_recommended": False,
                "remote_flag_receipt": None, "flag_history": [],
                "input_fingerprint": input_fingerprint,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            })
    findings = root / "FINDINGS.md"
    if not findings.exists():
        atomic_text(findings, f"# Findings — {challenge.key}\n\nNo findings recorded yet.\n")
    evidence = root / "evidence.log"
    evidence.touch(exist_ok=True)


def bind_input_fingerprint(root: Path, challenge: ChallengeSpec, fingerprint: str) -> None:
    initialize_solve_files(root, challenge, fingerprint)
    state_path = root / "STATE.json"
    with state_lock(root):
        state = json.loads(state_path.read_text(encoding="utf-8"))
        previous = state.get("input_fingerprint")
        stale_result = state.get("flag_candidate") is not None or state.get("status") in {
            "READY_FOR_HUMAN_SUBMISSION", "FLAG_CANDIDATE", "LOCAL_FLAG_OBTAINED",
            "REMOTE_FLAG_OBTAINED", "SUBMISSION_RECOMMENDED", "FULLY_VERIFIED",
            "SUBMITTED_BY_HUMAN",
        }
        if previous not in {None, fingerprint} or (previous is None and stale_result):
            result = root / "RESULT.md"
            if result.is_file():
                archive = root / f"RESULT.stale-{str(previous or 'unknown')[:8]}.md"
                if not archive.exists():
                    atomic_text(archive, result.read_text(encoding="utf-8"))
                atomic_text(result, "# Result invalidated\n\nChallenge input changed. Rerun and reverify the solver.\n")
            state.update({
                "status": "PREPARED", "flag_candidate": None, "verification": {},
                "replay_verdict": None, "branches": [], "competition_state": None,
                "remote_flag": None, "submission_recommended": False,
                "remote_flag_receipt": None, "flag_history": [],
            })
        state["input_fingerprint"] = fingerprint
        atomic_json(state_path, state)


@contextmanager
def state_lock(root: Path) -> Iterator[None]:
    lock_path = root / ".STATE.lock"
    state_path = root / "STATE.json"
    if lock_path.is_symlink() or state_path.is_symlink():
        raise ValueError("challenge state and lock files must not be symlinks")
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
