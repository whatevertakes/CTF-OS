"""Manual, terminal Claude handoff storage for one exact race."""

from __future__ import annotations

from pathlib import Path
import re
import unicodedata

from .workspace import atomic_text


MAX_HANDOFF_BYTES = 32 * 1024


class HandoffError(ValueError):
    pass


def load_markdown(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise HandoffError("handoff input must be a regular non-symlink file")
    data = path.read_bytes()
    if not data or len(data) > MAX_HANDOFF_BYTES:
        raise HandoffError("handoff markdown must contain 1..32768 bytes")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HandoffError("handoff markdown must be UTF-8") from exc


def save_handoff(repo: Path, *, contest: str, challenge: str, run_id: str, markdown: str) -> Path:
    data = markdown.encode("utf-8")
    if not data or len(data) > MAX_HANDOFF_BYTES:
        raise HandoffError("handoff markdown must contain 1..32768 UTF-8 bytes")
    if run_id not in markdown:
        raise HandoffError("handoff must identify the exact terminated run_id")
    contest_name = safe_component(contest, "contest")
    challenge_name = safe_component(challenge, "challenge")
    rescue = (repo / "rescue").resolve()
    destination = rescue / contest_name / challenge_name / "HANDOFF.md"
    _safe_directories(rescue, destination.parent)
    if destination.is_symlink() or (destination.exists() and not destination.is_file()):
        raise HandoffError("handoff destination is unsafe")
    atomic_text(destination, markdown)
    return destination


def safe_component(value: str, label: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).strip()
    if not normalized or normalized in {".", ".."} or "\x00" in normalized:
        raise HandoffError(f"unsafe {label} component")
    normalized = normalized.replace("/", "_").replace("\\", "_")
    normalized = re.sub(r"[\x00-\x1f\x7f]", "_", normalized).strip(" .")
    if not normalized or normalized in {".", ".."}:
        raise HandoffError(f"unsafe {label} component")
    encoded = normalized.encode("utf-8")
    if len(encoded) > 160:
        raise HandoffError(f"{label} component is too long")
    return normalized


def _safe_directories(root: Path, directory: Path) -> None:
    root.mkdir(mode=0o700, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise HandoffError("rescue root is unsafe")
    try:
        relative = directory.relative_to(root)
    except ValueError as exc:
        raise HandoffError("handoff destination escapes rescue") from exc
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise HandoffError("handoff directory contains a symlink")
        cursor.mkdir(mode=0o700, exist_ok=True)
        if not cursor.is_dir():
            raise HandoffError("handoff directory is unsafe")
