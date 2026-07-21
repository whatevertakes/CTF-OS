"""Safe storage for a single manual Claude handoff document."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unicodedata


MAX_HANDOFF_BYTES = 32 * 1024
HANDOFF_NAME = "HANDOFF.md"


class ClaudeHandoffError(ValueError):
    """Raised when a handoff input or destination is unsafe."""


def safe_handoff_component(value: str, *, label: str) -> str:
    """Return a Unicode-preserving, single-path component."""

    if not isinstance(value, str) or not value.strip():
        raise ClaudeHandoffError(f"{label} must be a non-empty string")
    normalized = unicodedata.normalize("NFKC", value).strip()
    if any(part == ".." for part in normalized.replace("\\", "/").split("/")):
        raise ClaudeHandoffError(f"{label} contains an unsafe path component")
    cleaned = "".join(
        "-" if character in "/\\\0" or unicodedata.category(character) == "Cc" else character
        for character in normalized
    )
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    cleaned = cleaned.strip(" .-")
    if not cleaned or cleaned in {".", ".."} or ".." in cleaned:
        raise ClaudeHandoffError(f"{label} contains an unsafe path component")
    return cleaned


def load_markdown(path: Path) -> bytes:
    """Load one regular, non-symlink UTF-8 Markdown file within the size limit."""

    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise ClaudeHandoffError("markdown input must be a regular non-symlink file")
    data = source.read_bytes()
    if len(data) > MAX_HANDOFF_BYTES:
        raise ClaudeHandoffError(
            f"HANDOFF.md exceeds the {MAX_HANDOFF_BYTES}-byte limit"
        )
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ClaudeHandoffError("HANDOFF.md must be valid UTF-8") from exc
    return data


def handoff_path(repo_root: Path, *, contest: str, challenge: str) -> Path:
    """Resolve the only permitted handoff destination without following symlinks."""

    root = Path(repo_root).absolute()
    if root.is_symlink() or not root.is_dir():
        raise ClaudeHandoffError("repository root must be a real directory, not a symlink")
    components = (
        "rescue",
        safe_handoff_component(contest, label="contest"),
        safe_handoff_component(challenge, label="challenge"),
    )
    current = root
    for component in components:
        current = current / component
        if current.is_symlink():
            raise ClaudeHandoffError(f"handoff path contains a symlink: {current}")
        if current.exists() and not current.is_dir():
            raise ClaudeHandoffError(f"handoff directory path is not a directory: {current}")
    destination = current / HANDOFF_NAME
    if destination.is_symlink() or (destination.exists() and not destination.is_file()):
        raise ClaudeHandoffError("HANDOFF.md destination is unsafe")
    try:
        destination.relative_to(root)
    except ValueError as exc:
        raise ClaudeHandoffError("handoff destination escapes the repository") from exc
    return destination


def save_handoff(
    repo_root: Path, *, contest: str, challenge: str, markdown_file: Path,
) -> Path:
    """Atomically create or replace exactly one challenge handoff file."""

    data = load_markdown(markdown_file)
    destination = handoff_path(repo_root, contest=contest, challenge=challenge)
    directory = destination.parent
    _create_safe_directories(Path(repo_root).absolute(), directory)
    unexpected = [item for item in directory.iterdir() if item.name != HANDOFF_NAME]
    if unexpected:
        raise ClaudeHandoffError(
            "handoff directory may contain only HANDOFF.md"
        )
    if destination.is_symlink():
        raise ClaudeHandoffError("HANDOFF.md destination must not be a symlink")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".HANDOFF.md.", dir=directory
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if destination.is_symlink():
            raise ClaudeHandoffError("HANDOFF.md destination became a symlink")
        os.replace(temporary, destination)
        directory_descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return destination


def _create_safe_directories(root: Path, directory: Path) -> None:
    if root.is_symlink() or not root.is_dir():
        raise ClaudeHandoffError("repository root must be a real directory, not a symlink")
    try:
        relative = directory.relative_to(root)
    except ValueError as exc:
        raise ClaudeHandoffError("handoff directory escapes the repository") from exc
    current = root
    for component in relative.parts:
        current = current / component
        if current.is_symlink():
            raise ClaudeHandoffError(f"handoff path contains a symlink: {current}")
        current.mkdir(exist_ok=True)
        if current.is_symlink() or not current.is_dir():
            raise ClaudeHandoffError(f"handoff path is unsafe: {current}")
