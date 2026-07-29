"""Immutable challenge input inventory and hashing."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import asdict, dataclass
from pathlib import Path


class IngestError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SourceFile:
    path: str
    size: int
    sha256: str
    mode: int


@dataclass(frozen=True, slots=True)
class SourceInventory:
    root: str
    files: tuple[SourceFile, ...]
    total_bytes: int
    manifest_sha256: str


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb", buffering=0) as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def inventory_challenge(
    challenge_dir: Path,
    *,
    max_files: int = 20_000,
    max_total_bytes: int = 128 * 1024**3,
) -> SourceInventory:
    """Hash regular inputs without following links or opening special files."""

    if max_files < 1 or max_total_bytes < 1:
        raise ValueError("inventory bounds must be positive")
    root = challenge_dir.expanduser().resolve()
    if not root.is_dir():
        raise IngestError(f"challenge input is not a directory: {root}")

    records: list[SourceFile] = []
    total = 0
    for current, directory_names, file_names in os.walk(
        root, topdown=True, followlinks=False
    ):
        current_path = Path(current)
        for name in tuple(directory_names):
            candidate = current_path / name
            try:
                metadata = candidate.lstat()
            except OSError as error:
                raise IngestError(f"cannot inspect {candidate}: {error}") from error
            if stat.S_ISLNK(metadata.st_mode):
                raise IngestError(
                    f"symlink directories are not accepted as input: {candidate}"
                )
            if not stat.S_ISDIR(metadata.st_mode):
                raise IngestError(
                    f"non-directory entry in directory walk: {candidate}"
                )
        for name in file_names:
            candidate = current_path / name
            try:
                metadata_before = candidate.lstat()
            except OSError as error:
                raise IngestError(f"cannot inspect {candidate}: {error}") from error
            if stat.S_ISLNK(metadata_before.st_mode):
                raise IngestError(
                    f"symlink inputs are not accepted: {candidate}"
                )
            if not stat.S_ISREG(metadata_before.st_mode):
                raise IngestError(
                    f"special-file inputs are not accepted: {candidate}"
                )
            relative = candidate.relative_to(root).as_posix()
            total += metadata_before.st_size
            if total > max_total_bytes:
                raise IngestError(
                    f"challenge input exceeds {max_total_bytes} bytes"
                )
            if len(records) >= max_files:
                raise IngestError(
                    f"challenge input exceeds {max_files} regular files"
                )
            digest = _file_hash(candidate)
            metadata_after = candidate.lstat()
            before_identity = (
                metadata_before.st_dev,
                metadata_before.st_ino,
                metadata_before.st_size,
                metadata_before.st_mtime_ns,
            )
            after_identity = (
                metadata_after.st_dev,
                metadata_after.st_ino,
                metadata_after.st_size,
                metadata_after.st_mtime_ns,
            )
            if before_identity != after_identity:
                raise IngestError(
                    f"challenge input changed while hashing: {candidate}"
                )
            records.append(
                SourceFile(
                    path=relative,
                    size=metadata_after.st_size,
                    sha256=digest,
                    mode=stat.S_IMODE(metadata_after.st_mode),
                )
            )
    records.sort(key=lambda record: record.path)
    encoded = json.dumps(
        [asdict(record) for record in records],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return SourceInventory(
        root=str(root),
        files=tuple(records),
        total_bytes=total,
        manifest_sha256=hashlib.sha256(encoded).hexdigest(),
    )

