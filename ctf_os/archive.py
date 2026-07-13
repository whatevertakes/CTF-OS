"""Bounded, link-free archive extraction for untrusted challenge inputs."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import zipfile


class ArchiveError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    max_files: int = 2_000
    max_file_bytes: int = 128 * 1024 * 1024
    max_total_bytes: int = 512 * 1024 * 1024
    max_ratio: int = 200


def extract_archive(archive: Path, destination: Path, limits: ArchiveLimits = ArchiveLimits()) -> list[str]:
    lower = archive.name.casefold()
    if lower.endswith(".zip"):
        return _extract_zip(archive, destination, limits)
    if lower.endswith((".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2")):
        return _extract_tar(archive, destination, limits)
    raise ArchiveError(f"unsupported archive format for safe intake extraction: {archive.name}")


def _safe_relative(name: str) -> Path:
    if not name or "\0" in name or "\\" in name:
        raise ArchiveError(f"unsafe archive member: {name!r}")
    pure = PurePosixPath(name)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ArchiveError(f"archive path traversal rejected: {name!r}")
    if pure.parts and pure.parts[0].endswith(":"):
        raise ArchiveError(f"absolute archive path rejected: {name!r}")
    return Path(*pure.parts)


def _target(root: Path, name: str) -> Path:
    relative = _safe_relative(name)
    target = (root / relative).resolve(strict=False)
    try:
        target.relative_to(root.resolve())
    except ValueError as exc:
        raise ArchiveError(f"archive member escapes destination: {name!r}") from exc
    return target


def _extract_zip(archive: Path, root: Path, limits: ArchiveLimits) -> list[str]:
    try:
        handle = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError) as exc:
        raise ArchiveError(f"damaged ZIP {archive.name}: {exc}") from exc
    names: list[str] = []
    total = 0
    seen: set[str] = set()
    with handle:
        infos = handle.infolist()
        if len(infos) > limits.max_files:
            raise ArchiveError(f"ZIP has too many members: {len(infos)} > {limits.max_files}")
        for info in infos:
            target = _target(root, info.filename)
            key = str(target).casefold()
            if key in seen:
                raise ArchiveError(f"duplicate archive destination: {info.filename!r}")
            seen.add(key)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ArchiveError(f"ZIP symlink rejected: {info.filename!r}")
            if info.flag_bits & 0x1:
                raise ArchiveError(f"encrypted ZIP member rejected: {info.filename!r}")
            if info.file_size > limits.max_file_bytes:
                raise ArchiveError(f"ZIP member exceeds size limit: {info.filename!r}")
            total += info.file_size
            if total > limits.max_total_bytes:
                raise ArchiveError("ZIP expanded size exceeds total limit")
            if info.compress_size and info.file_size / info.compress_size > limits.max_ratio:
                raise ArchiveError(f"ZIP compression ratio rejected: {info.filename!r}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            copied = 0
            with handle.open(info) as source, target.open("xb") as output:
                while chunk := source.read(1024 * 1024):
                    copied += len(chunk)
                    if copied > info.file_size or copied > limits.max_file_bytes:
                        raise ArchiveError(f"ZIP member expanded beyond declared limit: {info.filename!r}")
                    output.write(chunk)
            names.append(info.filename)
    return names


def _extract_tar(archive: Path, root: Path, limits: ArchiveLimits) -> list[str]:
    try:
        handle = tarfile.open(archive, mode="r:*")
    except (tarfile.TarError, OSError) as exc:
        raise ArchiveError(f"damaged tar archive {archive.name}: {exc}") from exc
    names: list[str] = []
    total = 0
    seen: set[str] = set()
    with handle:
        members = handle.getmembers()
        if len(members) > limits.max_files:
            raise ArchiveError(f"tar has too many members: {len(members)} > {limits.max_files}")
        for member in members:
            target = _target(root, member.name)
            key = str(target).casefold()
            if key in seen:
                raise ArchiveError(f"duplicate archive destination: {member.name!r}")
            seen.add(key)
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise ArchiveError(f"tar link/device member rejected: {member.name!r}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise ArchiveError(f"unsupported tar member rejected: {member.name!r}")
            if member.size > limits.max_file_bytes:
                raise ArchiveError(f"tar member exceeds size limit: {member.name!r}")
            total += member.size
            if total > limits.max_total_bytes:
                raise ArchiveError("tar expanded size exceeds total limit")
            target.parent.mkdir(parents=True, exist_ok=True)
            source = handle.extractfile(member)
            if source is None:
                raise ArchiveError(f"cannot read tar member: {member.name!r}")
            copied = 0
            with source, target.open("xb") as output:
                while chunk := source.read(1024 * 1024):
                    copied += len(chunk)
                    if copied > member.size or copied > limits.max_file_bytes:
                        raise ArchiveError(f"tar member expanded beyond declared limit: {member.name!r}")
                    output.write(chunk)
            names.append(member.name)
    return names


def copy_tree_without_links(source: Path, destination: Path, limits: ArchiveLimits = ArchiveLimits()) -> list[str]:
    copied: list[str] = []
    total = 0
    for path in bounded_source_files(source, limits):
        relative = path.relative_to(source)
        size = path.stat().st_size
        if size > limits.max_file_bytes:
            raise ArchiveError(f"source file exceeds size limit: {relative}")
        total += size
        if total > limits.max_total_bytes:
            raise ArchiveError("source directory exceeds total size limit")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise ArchiveError(f"source/archive path collision: {relative}")
        shutil.copyfile(path, target)
        copied.append(relative.as_posix())
    return copied


def bounded_source_files(source: Path, limits: ArchiveLimits = ArchiveLimits()) -> list[Path]:
    stack = [source]
    files: list[Path] = []
    members = 0
    while stack:
        directory = stack.pop()
        children: list[Path] = []
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    members += 1
                    if members > limits.max_files:
                        raise ArchiveError(f"source directory has too many members: {members} > {limits.max_files}")
                    path = Path(entry.path)
                    if entry.is_symlink():
                        raise ArchiveError(f"source symlink rejected: {path}")
                    if entry.is_dir(follow_symlinks=False):
                        children.append(path)
                    elif entry.is_file(follow_symlinks=False):
                        files.append(path)
                    else:
                        raise ArchiveError(f"source special file rejected: {path}")
        except OSError as exc:
            raise ArchiveError(f"cannot inspect source directory {directory}: {exc}") from exc
        stack.extend(sorted(children, reverse=True, key=lambda path: path.name.casefold()))
    return sorted(files, key=lambda path: path.relative_to(source).as_posix())
