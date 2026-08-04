"""Fail-closed operator staging for an explicitly selected NYU CTF Bench cohort.

This module only copies public challenge inputs and creates fresh CTF-OS
states.  It never starts a challenge service, model session, tool, remote
request, or flag submission.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import shlex
import signal
import stat
import subprocess
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from ctf_os.benchmark import CTF_OS_SYSTEM, THIN_SCAFFOLD
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.models import ChallengeIdentity
from ctf_os.promotion_bundles import (
    PROMOTION_MANIFEST_SCHEMA_VERSION,
    execution_fingerprint_report,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.store.atomic import canonical_json_bytes, strict_json_loads

NYU_STAGE_RESULT_SCHEMA_VERSION = 1
NYU_PARTIAL_MANIFEST_KIND = "nyu_ctf_bench_partial_promotion"
NYU_SOURCE_DATASETS = ("test", "development")
NYU_DATASET_FILES = {
    "test": "test_dataset.json",
    "development": "development_dataset.json",
}
NYU_DATASET_FILE = NYU_DATASET_FILES["test"]
NYU_PUBLIC_METADATA_FILE = "nyu_public_metadata.json"
NYU_CATEGORIES = frozenset({"pwn", "web", "rev", "crypto", "forensics", "misc"})
NYU_PROMOTION_SPLITS = frozenset({"dev", "regression", "blind", "live", "hidden"})
MAX_DATASET_BYTES = 4 * 1024 * 1024
MAX_CHALLENGE_JSON_BYTES = 1024 * 1024
MAX_DATASET_CASES = 4096
MAX_SELECTED_CASES = 256
MAX_CASE_FILES = 1024
MAX_CASE_TOTAL_BYTES = 512 * 1024 * 1024
MAX_CASE_FILE_BYTES = 256 * 1024 * 1024
MAX_PUBLIC_TEXT_BYTES = 256 * 1024
MAX_PUBLIC_METADATA_BYTES = 512 * 1024
MAX_GIT_OUTPUT_BYTES = 4 * 1024 * 1024
# Explicit public-blob reads may use this cap; ordinary Git queries stay smaller.
MAX_PUBLIC_ASSET_BYTES = 32 * 1024 * 1024
GIT_QUERY_TIMEOUT_SECONDS = 30.0
_GIT_READ_CHUNK_BYTES = 64 * 1024
_OBJECT_ID_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_SENSITIVE_BASENAMES = frozenset(
    {
        "answer",
        "answers",
        "flag",
        "flags",
        "reference",
        "solution",
        "solutions",
        "solve",
        "solver",
        "write-up",
        "writeup",
    }
)
_FORBIDDEN_PUBLIC_BASENAMES = frozenset(
    {
        "challenge.json",
        *(name.casefold() for name in NYU_DATASET_FILES.values()),
        NYU_PUBLIC_METADATA_FILE.casefold(),
    }
)
_GIT_OBJECT_FORMAT_LENGTHS = {
    "sha1": 40,
    "sha256": 64,
}
_FINGERPRINT_FIELDS = (
    "tool_manifest_sha256",
    "image_sha256",
    "model_config_sha256",
    "engine_source_sha256",
)


class NYUStageError(ValueError):
    """The selected source or destination cannot be staged safely."""


@dataclass(frozen=True, slots=True)
class _Asset:
    relative_path: str
    source_path: Path
    size: int
    sha256: str
    executable: bool
    identity: tuple[int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class _GitBlob:
    object_id: str
    executable: bool


@dataclass(frozen=True, slots=True)
class _SelectedCase:
    case_id: str
    category: str
    name: str
    description: str
    prompt: str
    source_path: str
    declared_files: tuple[str, ...]
    assets: tuple[_Asset, ...]


@dataclass(frozen=True, slots=True)
class _SessionPlan:
    session_id: str
    arm: str
    attempt: int
    identity: ChallengeIdentity


def _bounded_public_text(value: object, label: str, *, empty: bool) -> str:
    if type(value) is not str or (not empty and not value):
        qualifier = "" if empty else " non-empty"
        raise NYUStageError(f"{label} must be a bounded{qualifier} string")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise NYUStageError(f"{label} must be valid UTF-8 text") from error
    if len(encoded) > MAX_PUBLIC_TEXT_BYTES:
        raise NYUStageError(f"{label} exceeds {MAX_PUBLIC_TEXT_BYTES} UTF-8 bytes")
    if any(
        (ord(character) < 0x20 and character not in "\t\r\n") or ord(character) == 0x7F
        for character in value
    ):
        raise NYUStageError(f"{label} contains control characters")
    return value


def _safe_identifier(value: object, label: str, *, maximum: int = 255) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or Path(value).is_absolute()
        or PureWindowsPath(value).is_absolute()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise NYUStageError(f"{label} must be a safe non-empty identifier")
    try:
        size = len(value.encode("utf-8", errors="strict"))
    except UnicodeError as error:
        raise NYUStageError(f"{label} must be valid UTF-8") from error
    if size > maximum:
        raise NYUStageError(f"{label} exceeds {maximum} UTF-8 bytes")
    return value


def _canonical_public_name(value: str, label: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    canonical = "".join(character for character in normalized if character.isalnum())
    if (
        not canonical
        or len(canonical.encode("utf-8", errors="strict")) > MAX_PUBLIC_TEXT_BYTES
    ):
        raise NYUStageError(
            f"{label} must contain a bounded alphanumeric canonical name"
        )
    return canonical


def _normalized_relative(value: object, label: str) -> str:
    if type(value) is not str or not value or "\\" in value:
        raise NYUStageError(f"{label} must be a normalized relative path")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or PureWindowsPath(value).is_absolute()
        or relative.as_posix() != value
        or any(part in {"", ".", ".."} for part in relative.parts)
        or any(part.casefold() == ".git" for part in relative.parts)
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        or len(value.encode("utf-8", errors="strict")) > 4096
    ):
        raise NYUStageError(f"{label} must be a normalized relative path")
    return value


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_regular(path: Path, *, label: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise NYUStageError(f"{label} cannot be opened safely") from error
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise NYUStageError(f"{label} must be a regular file")
    return descriptor


def _read_regular(path: Path, *, maximum: int, label: str) -> bytes:
    descriptor = _open_regular(path, label=label)
    try:
        before = os.fstat(descriptor)
        if before.st_size > maximum:
            raise NYUStageError(f"{label} exceeds {maximum} bytes")
        payload = bytearray()
        while len(payload) <= maximum:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, maximum + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if (
            len(payload) > maximum
            or len(payload) != after.st_size
            or _file_identity(before) != _file_identity(after)
        ):
            raise NYUStageError(f"{label} changed while it was read")
        return bytes(payload)
    except OSError as error:
        raise NYUStageError(f"{label} cannot be read safely") from error
    finally:
        os.close(descriptor)


def _load_json_payload(payload: bytes, *, maximum: int, label: str) -> object:
    try:
        return strict_json_loads(
            payload,
            max_bytes=maximum,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        if isinstance(error, NYUStageError):
            raise
        raise NYUStageError(f"{label} is not strict bounded JSON") from error


def _real_directory(path: Path, label: str) -> Path:
    absolute = path.expanduser()
    if not absolute.is_absolute():
        absolute = Path.cwd() / absolute
    try:
        metadata = absolute.lstat()
    except OSError as error:
        raise NYUStageError(f"{label} is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise NYUStageError(f"{label} must be a real directory, not a symlink")
    try:
        return absolute.resolve(strict=True)
    except OSError as error:
        raise NYUStageError(f"{label} cannot be resolved safely") from error


def _directory_beneath(root: Path, relative_path: str, label: str) -> Path:
    current = root
    for part in PurePosixPath(relative_path).parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise NYUStageError(f"{label} is unavailable") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise NYUStageError(f"{label} must traverse only real directories")
    try:
        current.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as error:
        raise NYUStageError(f"{label} escapes the source repository") from error
    return current


def _asset_from_path(
    source_root: Path,
    challenge_root: Path,
    relative_path: str,
    *,
    case_id: str,
    repository_path: str,
    release_commit: str,
    object_format: str,
) -> _Asset:
    relative = PurePosixPath(relative_path)
    for component in relative.parts:
        lowered = component.casefold()
        if lowered in _FORBIDDEN_PUBLIC_BASENAMES:
            raise NYUStageError(
                f"{case_id} files[] names verifier metadata: {relative_path}"
            )
        name_candidates = {
            lowered,
            lowered.split(".", maxsplit=1)[0],
            Path(lowered).stem,
        }
        if name_candidates & _SENSITIVE_BASENAMES:
            raise NYUStageError(
                f"{case_id} files[] names a non-public path: {relative_path}"
            )
    parent_relative = PurePosixPath(*relative.parts[:-1]).as_posix()
    parent = (
        challenge_root
        if parent_relative == "."
        else _directory_beneath(
            challenge_root,
            parent_relative,
            f"{case_id} file parent",
        )
    )
    source_path = parent / relative.parts[-1]
    try:
        metadata = source_path.lstat()
    except OSError as error:
        raise NYUStageError(
            f"{case_id} files[] entry is unavailable: {relative_path}"
        ) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise NYUStageError(
            f"{case_id} files[] entries must be regular files: {relative_path}"
        )
    if metadata.st_size > MAX_CASE_FILE_BYTES:
        raise NYUStageError(
            f"{case_id} file exceeds {MAX_CASE_FILE_BYTES} bytes: {relative_path}"
        )
    committed = _committed_blob(
        source_root,
        release_commit=release_commit,
        repository_path=repository_path,
        object_format=object_format,
        label=f"{case_id} committed file {relative_path}",
    )
    descriptor = _open_regular(
        source_path,
        label=f"{case_id} file {relative_path}",
    )
    try:
        opened = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(metadata):
            raise NYUStageError(
                f"{case_id} file changed before hashing: {relative_path}"
            )
        digest = hashlib.sha256()
        git_digest = _git_blob_hasher(object_format, opened.st_size)
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise NYUStageError(f"{case_id} file was truncated: {relative_path}")
            digest.update(chunk)
            git_digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise NYUStageError(f"{case_id} file grew while hashing: {relative_path}")
        after = os.fstat(descriptor)
        if _file_identity(after) != _file_identity(opened):
            raise NYUStageError(
                f"{case_id} file changed while hashing: {relative_path}"
            )
        executable = bool(stat.S_IMODE(opened.st_mode) & 0o111)
        if (
            git_digest.hexdigest() != committed.object_id
            or executable != committed.executable
        ):
            raise NYUStageError(
                f"{case_id} file does not match the release commit blob: "
                f"{relative_path}"
            )
    except OSError as error:
        raise NYUStageError(
            f"{case_id} file cannot be hashed safely: {relative_path}"
        ) from error
    finally:
        os.close(descriptor)
    return _Asset(
        relative_path=relative_path,
        source_path=source_path,
        size=metadata.st_size,
        sha256=digest.hexdigest(),
        executable=committed.executable,
        identity=_file_identity(metadata),
    )


def _git_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_LITERAL_PATHSPECS": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "LC_ALL": "C",
        }
    )
    return environment


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    """Best-effort termination of Git and every child in its process group."""

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
    try:
        process.wait(timeout=1)
    except (OSError, subprocess.TimeoutExpired):
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
        try:
            process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _git_query(
    source_root: Path,
    *arguments: str,
    label: str,
    maximum_stdout_bytes: int | None = None,
) -> bytes:
    stdout_limit = (
        MAX_GIT_OUTPUT_BYTES
        if maximum_stdout_bytes is None
        else maximum_stdout_bytes
    )
    stderr_limit = MAX_GIT_OUTPUT_BYTES
    if (
        type(stdout_limit) is not int
        or not 0 < stdout_limit <= MAX_PUBLIC_ASSET_BYTES
        or type(stderr_limit) is not int
        or not 0 < stderr_limit <= MAX_PUBLIC_ASSET_BYTES
    ):
        raise NYUStageError(f"{label} has an invalid output bound")
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    succeeded = False
    try:
        process = subprocess.Popen(
            (
                "git",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.quotepath=false",
                "-C",
                str(source_root),
                *arguments,
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
            env=_git_environment(),
        )
        if process.stdout is None or process.stderr is None:
            raise NYUStageError(f"{label} failed")
        stdout_payload = bytearray()
        stderr_payload = bytearray()
        selector = selectors.DefaultSelector()
        selector.register(
            process.stdout,
            selectors.EVENT_READ,
            (stdout_payload, stdout_limit),
        )
        selector.register(
            process.stderr,
            selectors.EVENT_READ,
            (stderr_payload, stderr_limit),
        )
        deadline = time.monotonic() + GIT_QUERY_TIMEOUT_SECONDS
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(
                    process.args,
                    GIT_QUERY_TIMEOUT_SECONDS,
                )
            ready = selector.select(remaining)
            if not ready:
                raise subprocess.TimeoutExpired(
                    process.args,
                    GIT_QUERY_TIMEOUT_SECONDS,
            )
            for key, _mask in ready:
                target, output_limit = key.data
                remaining_capacity = output_limit + 1 - len(target)
                chunk = os.read(
                    key.fileobj.fileno(),
                    min(_GIT_READ_CHUNK_BYTES, remaining_capacity),
                )
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target.extend(chunk)
                if len(target) > output_limit:
                    raise NYUStageError(f"{label} failed")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(
                process.args,
                GIT_QUERY_TIMEOUT_SECONDS,
            )
        returncode = process.wait(timeout=remaining)
        if returncode != 0:
            raise NYUStageError(f"{label} failed")
        succeeded = True
        return bytes(stdout_payload)
    except NYUStageError:
        raise
    except (OSError, subprocess.SubprocessError) as error:
        raise NYUStageError(f"{label} failed") from error
    finally:
        if not succeeded and process is not None:
            _terminate_process_group(process)
        if selector is not None:
            selector.close()
        if process is not None:
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()


def _git_ascii_line(payload: bytes, label: str) -> str:
    try:
        value = payload.decode("ascii", errors="strict").strip()
    except UnicodeError as error:
        raise NYUStageError(f"{label} is malformed") from error
    if not value or "\x00" in value or "\n" in value or "\r" in value:
        raise NYUStageError(f"{label} is malformed")
    return value


def _git_blob_hasher(object_format: str, size: int) -> Any:
    if object_format not in _GIT_OBJECT_FORMAT_LENGTHS or size < 0:
        raise NYUStageError("Git object format is unsupported")
    try:
        digest = hashlib.new(object_format)
    except (TypeError, ValueError) as error:
        raise NYUStageError("Git object format is unsupported") from error
    digest.update(f"blob {size}\0".encode("ascii"))
    return digest


def _committed_blob(
    source_root: Path,
    *,
    release_commit: str,
    repository_path: str,
    object_format: str,
    label: str,
) -> _GitBlob:
    repository_path = _normalized_relative(repository_path, label)
    payload = _git_query(
        source_root,
        "ls-tree",
        "-z",
        release_commit,
        "--",
        repository_path,
        label=f"{label} tree query",
    )
    records = payload.split(b"\0")
    if len(records) != 2 or records[-1] != b"":
        raise NYUStageError(f"{label} is not one committed file")
    header, separator, raw_path = records[0].partition(b"\t")
    fields = header.split(b" ")
    try:
        expected_path = repository_path.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise NYUStageError(f"{label} path is not valid UTF-8") from error
    if (
        separator != b"\t"
        or len(fields) != 3
        or raw_path != expected_path
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
    ):
        raise NYUStageError(f"{label} is not a canonical committed blob")
    try:
        object_id = fields[2].decode("ascii", errors="strict")
    except UnicodeError as error:
        raise NYUStageError(f"{label} object ID is malformed") from error
    expected_length = _GIT_OBJECT_FORMAT_LENGTHS.get(object_format)
    if (
        expected_length is None
        or len(object_id) != expected_length
        or re.fullmatch(r"[0-9a-f]+", object_id) is None
    ):
        raise NYUStageError(f"{label} object ID is malformed")
    return _GitBlob(
        object_id=object_id,
        executable=fields[0] == b"100755",
    )


def _read_committed_regular(
    source_root: Path,
    path: Path,
    *,
    repository_path: str,
    release_commit: str,
    object_format: str,
    maximum: int,
    label: str,
) -> bytes:
    committed = _committed_blob(
        source_root,
        release_commit=release_commit,
        repository_path=repository_path,
        object_format=object_format,
        label=label,
    )
    try:
        before = path.lstat()
    except OSError as error:
        raise NYUStageError(f"{label} is unavailable") from error
    payload = _read_regular(path, maximum=maximum, label=label)
    try:
        after = path.lstat()
    except OSError as error:
        raise NYUStageError(f"{label} changed while it was read") from error
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or _file_identity(before) != _file_identity(after)
        or bool(stat.S_IMODE(after.st_mode) & 0o111) != committed.executable
    ):
        raise NYUStageError(f"{label} changed while it was read")
    digest = _git_blob_hasher(object_format, len(payload))
    digest.update(payload)
    if digest.hexdigest() != committed.object_id:
        raise NYUStageError(f"{label} does not match the release commit blob")
    return payload


def _verify_source_revision(source_root: Path, release_commit: str) -> str:
    if _OBJECT_ID_RE.fullmatch(release_commit) is None:
        raise NYUStageError("--release-commit must be a full lowercase Git object ID")
    top_level_payload = _git_query(
        source_root,
        "rev-parse",
        "--show-toplevel",
        label="NYU source repository root query",
    )
    try:
        top_level = Path(
            top_level_payload.decode("utf-8", errors="strict").strip()
        ).resolve(strict=True)
    except (UnicodeError, OSError) as error:
        raise NYUStageError("NYU source repository root is malformed") from error
    if top_level != source_root:
        raise NYUStageError("NYU source must be the exact Git worktree root")
    object_format = _git_ascii_line(
        _git_query(
            source_root,
            "rev-parse",
            "--show-object-format",
            label="NYU source object format query",
        ),
        "NYU source object format",
    )
    expected_length = _GIT_OBJECT_FORMAT_LENGTHS.get(object_format)
    if expected_length is None or len(release_commit) != expected_length:
        raise NYUStageError(
            "--release-commit does not match the repository object format"
        )
    head_payload = _git_query(
        source_root,
        "rev-parse",
        "--verify",
        "HEAD",
        label="NYU source HEAD query",
    )
    head = _git_ascii_line(head_payload, "NYU source HEAD")
    if head != release_commit:
        raise NYUStageError("NYU source HEAD does not exactly match --release-commit")
    object_type = _git_ascii_line(
        _git_query(
            source_root,
            "cat-file",
            "-t",
            release_commit,
            label="NYU release object type query",
        ),
        "NYU release object type",
    )
    if object_type != "commit":
        raise NYUStageError("--release-commit must name a Git commit object")
    local_config = _git_query(
        source_root,
        "config",
        "--local",
        "--null",
        "--list",
        label="NYU source local Git configuration query",
    )
    for raw_record in local_config.split(b"\0"):
        if not raw_record:
            continue
        raw_key = raw_record.split(b"\n", maxsplit=1)[0].lower()
        if raw_key.startswith((b"filter.", b"include.", b"includeif.")):
            raise NYUStageError(
                "NYU source local Git configuration may not define "
                "filters or includes"
            )
    dirty = _git_query(
        source_root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=all",
        label="NYU source cleanliness query",
    )
    if dirty:
        raise NYUStageError(
            "NYU source checkout has staged, unstaged, or untracked changes"
        )
    return object_format


def _selected_cases(
    source_root: Path,
    requested_case_ids: tuple[str, ...],
    *,
    dataset_file: str,
    release_commit: str,
    object_format: str,
) -> tuple[_SelectedCase, ...]:
    dataset = _load_json_payload(
        _read_committed_regular(
            source_root,
            source_root / dataset_file,
            repository_path=dataset_file,
            release_commit=release_commit,
            object_format=object_format,
            maximum=MAX_DATASET_BYTES,
            label=dataset_file,
        ),
        maximum=MAX_DATASET_BYTES,
        label=dataset_file,
    )
    if type(dataset) is not dict or not 1 <= len(dataset) <= MAX_DATASET_CASES:
        raise NYUStageError(f"{dataset_file} must be a bounded non-empty object")
    selected: list[_SelectedCase] = []
    for case_id in sorted(requested_case_ids):
        entry = dataset.get(case_id)
        if type(entry) is not dict:
            raise NYUStageError(
                f"canonical dataset case is missing or malformed: {case_id}"
            )
        category = _safe_identifier(
            entry.get("category"),
            f"{case_id} dataset category",
        )
        if category not in NYU_CATEGORIES:
            raise NYUStageError(f"{case_id} dataset category is not canonical")
        dataset_name = _bounded_public_text(
            entry.get("challenge"),
            f"{case_id} dataset challenge",
            empty=False,
        )
        challenge_relative = _normalized_relative(
            entry.get("path"),
            f"{case_id} dataset path",
        )
        challenge_root = _directory_beneath(
            source_root,
            challenge_relative,
            f"{case_id} challenge directory",
        )
        challenge_repository_path = PurePosixPath(
            challenge_relative,
            "challenge.json",
        ).as_posix()
        document = _load_json_payload(
            _read_committed_regular(
                source_root,
                challenge_root / "challenge.json",
                repository_path=challenge_repository_path,
                release_commit=release_commit,
                object_format=object_format,
                maximum=MAX_CHALLENGE_JSON_BYTES,
                label=f"{case_id} challenge.json",
            ),
            maximum=MAX_CHALLENGE_JSON_BYTES,
            label=f"{case_id} challenge.json",
        )
        if type(document) is not dict:
            raise NYUStageError(f"{case_id} challenge.json must be an object")
        public_category = _safe_identifier(
            document.get("category"),
            f"{case_id} public category",
        )
        name = _bounded_public_text(
            document.get("name"),
            f"{case_id} public name",
            empty=False,
        )
        description = _bounded_public_text(
            document.get("description"),
            f"{case_id} public description",
            empty=True,
        )
        if public_category != category or _canonical_public_name(
            name, f"{case_id} public name"
        ) != _canonical_public_name(
            dataset_name,
            f"{case_id} dataset challenge",
        ):
            raise NYUStageError(f"{case_id} dataset/challenge public metadata mismatch")
        raw_files = document.get("files")
        if type(raw_files) is not list or len(raw_files) > MAX_CASE_FILES:
            raise NYUStageError(f"{case_id} public files must be a bounded list")
        normalized_files = tuple(
            _normalized_relative(value, f"{case_id} files[]") for value in raw_files
        )
        if len(set(normalized_files)) != len(normalized_files):
            raise NYUStageError(f"{case_id} files[] contains duplicates")
        if NYU_PUBLIC_METADATA_FILE in normalized_files:
            raise NYUStageError(
                f"{case_id} files[] collides with reserved staging metadata"
            )
        assets = tuple(
            _asset_from_path(
                source_root,
                challenge_root,
                relative_path,
                case_id=case_id,
                repository_path=PurePosixPath(
                    challenge_relative,
                    relative_path,
                ).as_posix(),
                release_commit=release_commit,
                object_format=object_format,
            )
            for relative_path in sorted(normalized_files)
        )
        total_bytes = sum(asset.size for asset in assets)
        if total_bytes > MAX_CASE_TOTAL_BYTES:
            raise NYUStageError(
                f"{case_id} public files exceed {MAX_CASE_TOTAL_BYTES} bytes"
            )
        prompt = (
            f"NYU CTF Bench challenge: {name}\nCategory: {category}\n\n{description}"
        )
        selected_case = _SelectedCase(
            case_id=case_id,
            category=category,
            name=name,
            description=description,
            prompt=prompt,
            source_path=challenge_relative,
            declared_files=normalized_files,
            assets=assets,
        )
        _public_metadata_payload(
            selected_case,
            release_commit=release_commit,
        )
        selected.append(selected_case)
    observed_categories = {case.category for case in selected}
    if observed_categories != NYU_CATEGORIES:
        missing = ", ".join(sorted(NYU_CATEGORIES - observed_categories))
        raise NYUStageError(
            "explicit --case selection must cover every canonical category; "
            f"missing: {missing or '-'}"
        )
    return tuple(selected)


def _session_plans(
    case: _SelectedCase,
    *,
    contest: str,
    split: str,
) -> tuple[_SessionPlan, ...]:
    plans: list[_SessionPlan] = []
    for arm in (THIN_SCAFFOLD, CTF_OS_SYSTEM):
        for attempt in (1, 2, 3):
            session_id = _safe_identifier(
                f"nyu-{split}-{case.case_id}-{arm}-{attempt}",
                f"{case.case_id} session_id",
            )
            plans.append(
                _SessionPlan(
                    session_id=session_id,
                    arm=arm,
                    attempt=attempt,
                    identity=ChallengeIdentity(
                        contest,
                        case.category,
                        session_id,
                    ),
                )
            )
    return tuple(plans)


def _copy_asset(asset: _Asset, destination_root: Path) -> None:
    destination = destination_root.joinpath(*PurePosixPath(asset.relative_path).parts)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor = _open_regular(
        asset.source_path,
        label=f"source asset {asset.relative_path}",
    )
    destination_descriptor: int | None = None
    try:
        before = os.fstat(descriptor)
        if _file_identity(before) != asset.identity:
            raise NYUStageError(
                f"source asset changed before copy: {asset.relative_path}"
            )
        destination_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        normalized_mode = 0o755 if asset.executable else 0o644
        try:
            destination_descriptor = os.open(
                destination,
                destination_flags,
                normalized_mode,
            )
        except OSError as error:
            raise NYUStageError(
                f"destination asset cannot be created: {asset.relative_path}"
            ) from error
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise NYUStageError(
                    f"source asset was truncated: {asset.relative_path}"
                )
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    raise NYUStageError(
                        f"destination write made no progress: {asset.relative_path}"
                    )
                view = view[written:]
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise NYUStageError(f"source asset grew during copy: {asset.relative_path}")
        after = os.fstat(descriptor)
        if (
            _file_identity(after) != asset.identity
            or digest.hexdigest() != asset.sha256
        ):
            raise NYUStageError(
                f"source asset changed during copy: {asset.relative_path}"
            )
        os.fchmod(destination_descriptor, normalized_mode)
        os.fsync(destination_descriptor)
    except OSError as error:
        raise NYUStageError(f"asset copy failed: {asset.relative_path}") from error
    finally:
        os.close(descriptor)
        if destination_descriptor is not None:
            os.close(destination_descriptor)


def _write_exclusive_regular(
    path: Path,
    payload: bytes,
    *,
    maximum: int,
    label: str,
) -> None:
    if len(payload) > maximum:
        raise NYUStageError(f"{label} exceeds {maximum} bytes")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o644)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise NYUStageError(f"{label} write made no progress")
            view = view[written:]
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
    except FileExistsError as error:
        raise NYUStageError(f"{label} already exists") from error
    except OSError as error:
        raise NYUStageError(f"{label} cannot be created safely") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_public_metadata(
    case: _SelectedCase,
    destination_root: Path,
    *,
    release_commit: str,
) -> None:
    _write_exclusive_regular(
        destination_root / NYU_PUBLIC_METADATA_FILE,
        _public_metadata_payload(
            case,
            release_commit=release_commit,
        ),
        maximum=MAX_PUBLIC_METADATA_BYTES,
        label=f"{case.case_id} generated public metadata",
    )


def _public_metadata_payload(
    case: _SelectedCase,
    *,
    release_commit: str,
) -> bytes:
    public_document = {
        "case_id": case.case_id,
        "category": case.category,
        "description": case.description,
        "files": list(case.declared_files),
        "name": case.name,
        "path": case.source_path,
        "release_commit": release_commit,
    }
    payload = canonical_json_bytes(public_document) + b"\n"
    if len(payload) > MAX_PUBLIC_METADATA_BYTES:
        raise NYUStageError(
            f"{case.case_id} generated public metadata exceeds "
            f"{MAX_PUBLIC_METADATA_BYTES} bytes"
        )
    return payload


def _exclusive_atomic_json(path: Path, value: object) -> None:
    payload = canonical_json_bytes(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{os.urandom(8).hex()}.tmp")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    installed = False
    try:
        descriptor = os.open(temporary, flags, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise NYUStageError("manifest write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as error:
            raise NYUStageError("output manifest already exists") from error
        installed = True
        directory_descriptor = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        raise NYUStageError("output manifest cannot be created atomically") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            if not installed:
                raise


def _fingerprint(
    workspace_root: Path,
) -> tuple[str, dict[str, str]]:
    report = execution_fingerprint_report(workspace_root)
    model_ids = report.get("model_ids")
    raw_fingerprint = report.get("execution_fingerprint")
    if (
        report.get("schema_version") != PROMOTION_MANIFEST_SCHEMA_VERSION
        or report.get("single_model") is not True
        or type(model_ids) is not list
        or len(model_ids) != 1
        or type(model_ids[0]) is not str
        or type(raw_fingerprint) is not dict
    ):
        raise NYUStageError(
            "NYU staging requires one current model across every logical role"
        )
    model_id = _safe_identifier(model_ids[0], "fingerprint model_id")
    fingerprint: dict[str, str] = {}
    for field in _FINGERPRINT_FIELDS:
        value = raw_fingerprint.get(field)
        if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
            raise NYUStageError(f"current execution fingerprint has invalid {field}")
        fingerprint[field] = value
    return model_id, fingerprint


def _refuse_existing(path: Path, label: str) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise NYUStageError(f"{label} cannot be inspected") from error
    raise NYUStageError(f"{label} already exists")


def _command(*values: object) -> str:
    return " ".join(shlex.quote(str(value)) for value in values)


def stage_nyu_ctf_bench(
    workspace_root: Path | str,
    *,
    source: Path | str,
    release_commit: str,
    case_ids: tuple[str, ...],
    output_manifest: Path | str,
    contest: str,
    split: str,
    wall_seconds: int,
    model_call_limit: int,
    total_token_limit: int,
    source_dataset: str = "test",
) -> dict[str, object]:
    """Stage one explicitly selected NYU split without starting any session."""

    workspace = Path(workspace_root).expanduser().resolve()
    if not workspace.is_dir():
        raise NYUStageError("workspace root must be an existing directory")
    contest = _safe_identifier(contest, "--contest")
    if split not in NYU_PROMOTION_SPLITS:
        raise NYUStageError("--split is not a promotion split")
    if type(source_dataset) is not str or source_dataset not in NYU_DATASET_FILES:
        raise NYUStageError(
            "--source-dataset must be one of: " + ", ".join(NYU_SOURCE_DATASETS)
        )
    dataset_file = NYU_DATASET_FILES[source_dataset]
    for value, label in (
        (wall_seconds, "wall_seconds"),
        (model_call_limit, "model_call_limit"),
        (total_token_limit, "total_token_limit"),
    ):
        if type(value) is not int or not 1 <= value <= (1 << 63) - 1:
            raise NYUStageError(f"{label} must be a positive integer")
    if (
        not case_ids
        or len(case_ids) > MAX_SELECTED_CASES
        or len(set(case_ids)) != len(case_ids)
    ):
        raise NYUStageError(
            "--case must explicitly name 1.."
            f"{MAX_SELECTED_CASES} unique canonical dataset IDs"
        )
    requested = tuple(_safe_identifier(case_id, "--case") for case_id in case_ids)
    output = Path(output_manifest).expanduser()
    if not output.is_absolute():
        output = Path.cwd() / output
    _refuse_existing(output, "output manifest")

    source_root = _real_directory(Path(source), "NYU source")
    try:
        output.resolve(strict=False).relative_to(source_root)
    except ValueError:
        pass
    else:
        raise NYUStageError(
            "output manifest must be outside the immutable NYU source checkout"
        )
    object_format = _verify_source_revision(source_root, release_commit)
    selected = _selected_cases(
        source_root,
        requested,
        dataset_file=dataset_file,
        release_commit=release_commit,
        object_format=object_format,
    )
    model_id, fingerprint = _fingerprint(workspace)

    engine = ChallengeEngine(workspace)
    plans_by_case = {
        case.case_id: _session_plans(
            case,
            contest=contest,
            split=split,
        )
        for case in selected
    }
    for plans in plans_by_case.values():
        for plan in plans:
            _refuse_existing(
                engine.challenge_input(plan.identity),
                f"incoming session {plan.session_id}",
            )
            _refuse_existing(
                engine.store.challenge_paths(plan.identity).root,
                f"canonical state session {plan.session_id}",
            )

    manifest_cases: list[dict[str, object]] = []
    all_input_digests: set[str] = set()
    session_next_steps: list[dict[str, str]] = []
    for case in selected:
        case_digests: set[str] = set()
        manifest_sessions: list[dict[str, object]] = []
        for plan in plans_by_case[case.case_id]:
            incoming = engine.challenge_input(plan.identity)
            incoming.mkdir(parents=True, exist_ok=False)
            _write_public_metadata(
                case,
                incoming,
                release_commit=release_commit,
            )
            for asset in case.assets:
                _copy_asset(asset, incoming)
            state = engine.add_challenge(
                plan.identity,
                description=case.description,
                prompt=case.prompt,
                budget_seconds=wall_seconds,
                state_schema_version=STATE_SCHEMA_VERSION,
                exist_ok=False,
            )
            input_digest = state.metadata.get("source_manifest_sha256")
            if (
                type(input_digest) is not str
                or _SHA256_RE.fullmatch(input_digest) is None
                or state.description != case.description
                or state.prompt != case.prompt
                or state.budget.allocated_seconds != wall_seconds
                or state.budget.spent_seconds != 0
                or state.runs
                or state.sessions
                or state.candidates
                or state.submissions
            ):
                raise NYUStageError(
                    f"fresh state verification failed: {plan.session_id}"
                )
            case_digests.add(input_digest)
            manifest_sessions.append(
                {
                    "session_id": plan.session_id,
                    "arm": plan.arm,
                    "attempt": plan.attempt,
                    "contest_id": contest,
                    "category": case.category,
                    "challenge_id": plan.identity.challenge_id,
                }
            )
            solve_mode = "thin" if plan.arm == THIN_SCAFFOLD else "managed"
            session_next_steps.append(
                {
                    "session_id": plan.session_id,
                    "budget_reset": _command(
                        "ctfos",
                        "budget-reset",
                        contest,
                        case.category,
                        plan.identity.challenge_id,
                        "--seconds",
                        wall_seconds,
                    ),
                    "prepare_after_full_freeze": _command(
                        "ctfos",
                        "benchmark",
                        "prepare",
                        "--manifest",
                        "<FULL_FROZEN_MANIFEST>",
                        "--session",
                        plan.session_id,
                    ),
                    "operator_run": _command(
                        "ctfos",
                        "solve",
                        contest,
                        case.category,
                        plan.identity.challenge_id,
                        "--mode",
                        solve_mode,
                    ),
                }
            )
        if len(case_digests) != 1 or len(manifest_sessions) != 6:
            raise NYUStageError(
                f"{case.case_id} sessions do not share one exact input manifest"
            )
        input_digest = next(iter(case_digests))
        if input_digest in all_input_digests:
            raise NYUStageError("selected cases have duplicate input manifest digests")
        all_input_digests.add(input_digest)
        manifest_cases.append(
            {
                "case_id": case.case_id,
                "category": case.category,
                "input_manifest_sha256": input_digest,
                "sessions": manifest_sessions,
            }
        )

    if _verify_source_revision(source_root, release_commit) != object_format:
        raise NYUStageError("NYU source object format changed during staging")
    final_model_id, final_fingerprint = _fingerprint(workspace)
    if final_model_id != model_id or final_fingerprint != fingerprint:
        raise NYUStageError(
            "execution fingerprint changed while NYU sessions were staged"
        )
    manifest = {
        "schema_version": PROMOTION_MANIFEST_SCHEMA_VERSION,
        "benchmark_id": f"nyu-ctf-bench-{release_commit[:12]}",
        "model_id": model_id,
        "budget": {
            "wall_seconds": wall_seconds,
            "model_call_limit": model_call_limit,
            "total_token_limit": total_token_limit,
        },
        "execution_fingerprint": fingerprint,
        "splits": [
            {
                "name": split,
                "trajectory_visible": split == "dev",
                "answers_visible": False,
                # Fresh staging cannot attest historical exposure. A complete
                # regression manifest must replace this only with an
                # operator-verified positive count before freeze.
                "prior_engine_runs": 0,
                "cases": manifest_cases,
            }
        ],
        "metadata": {
            "kind": NYU_PARTIAL_MANIFEST_KIND,
            "partial_manifest": True,
            "promotion_ready": False,
            "source_release_commit": release_commit,
            "source_dataset": dataset_file,
            "selected_split": split,
            "selected_case_ids": [case.case_id for case in selected],
            "automatic_challenge_start": False,
            "automatic_flag_submission": False,
            "model_visible_external_writeup_or_flag_access": False,
            "source_verifier_may_read_hidden_metadata": True,
            "emitted_public_metadata_fields": [
                "case_id",
                "category",
                "description",
                "files",
                "name",
                "path",
                "release_commit",
            ],
        },
    }
    _exclusive_atomic_json(output, manifest)
    return {
        "schema_version": NYU_STAGE_RESULT_SCHEMA_VERSION,
        "benchmark": "NYU CTF Bench",
        "staged": True,
        "source_release_commit": release_commit,
        "split": split,
        "cases": len(selected),
        "sessions": len(session_next_steps),
        "output_manifest": str(output),
        "partial_manifest": True,
        "promotion_ready": False,
        "automatic_challenge_start": False,
        "automatic_flag_submission": False,
        "model_visible_external_writeup_or_flag_access": False,
        "source_verifier_may_read_hidden_metadata": True,
        "network_targets_added": 0,
        "next_steps": [
            (
                "Do not pass this partial manifest to benchmark freeze/compare; "
                "it is intentionally promotion-ineligible, and do not run its "
                "staged states as benchmark evidence before full freeze."
            ),
            (
                "Operator-select and combine explicit dev, regression, blind, "
                "and live split manifests into one complete schema-v2 manifest; "
                "remove partial metadata only after verifying all memberships "
                "and any regression prior_engine_runs count."
            ),
            (
                "Freeze the complete manifest, then for exactly one "
                "human-selected session run budget_reset, "
                "prepare_after_full_freeze, and operator_run in that order."
            ),
            (
                "Record evidence and manual outcomes; never auto-submit a "
                "flag candidate."
            ),
        ],
        "session_next_steps": session_next_steps,
    }
