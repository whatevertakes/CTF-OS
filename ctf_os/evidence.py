from __future__ import annotations

from datetime import datetime, timezone
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
from typing import Any, Iterator


def append_evidence(path: Path, event: str, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {"timestamp": datetime.now(timezone.utc).isoformat(), "event": event, **payload}
    with _append_lock(path.parent / f".{path.name}.lock"):
        _append(path, json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def append_finding(root: Path, branch: str, summary: str, evidence: str, status: str) -> dict[str, object]:
    allowed = {"supported", "rejected", "inconclusive"}
    if status not in allowed:
        raise ValueError(f"finding status must be one of {sorted(allowed)}")
    record: dict[str, object] = {
        "timestamp": datetime.now(timezone.utc).isoformat(), "branch": branch,
        "summary": summary, "evidence": evidence, "status": status,
    }
    root.mkdir(parents=True, exist_ok=True)
    with _append_lock(root / ".findings.lock"):
        _append(root / "findings.jsonl", json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        _append(
            root / "FINDINGS.md",
            f"\n## {summary}\n\n- Branch: `{branch}`\n- Status: **{status}**\n- Evidence: {evidence}\n",
        )
    return record


@contextmanager
def _append_lock(path: Path) -> Iterator[None]:
    if path.is_symlink():
        raise ValueError(f"append lock must not be a symlink: {path}")
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _append(path: Path, content: str) -> None:
    if path.is_symlink():
        raise ValueError(f"append destination must not be a symlink: {path}")
    descriptor = os.open(
        path,
        os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
