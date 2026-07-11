"""Local contest discovery and safe challenge archive extraction."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import PurePosixPath
import secrets
import stat
import tempfile
from pathlib import Path
from zipfile import BadZipFile, ZipFile, ZipInfo

from .config import AppConfig
from .contest_parser import ContestManifest, ContestParseError, parse_contest
from .models import Challenge


class IntakeError(ValueError):
    """Raised for unsafe or malformed local contest intake data."""


@dataclass(frozen=True)
class ZipExtractionLimits:
    """Hard caps applied before and during every archive extraction."""

    max_files: int = 1_000
    max_file_bytes: int = 64 * 1024 * 1024
    max_total_bytes: int = 256 * 1024 * 1024
    max_compression_ratio: int = 100

    def __post_init__(self) -> None:
        if min(self.max_files, self.max_file_bytes, self.max_total_bytes, self.max_compression_ratio) < 1:
            raise ValueError("ZIP extraction limits must be positive")


DEFAULT_ZIP_LIMITS = ZipExtractionLimits()


@dataclass(frozen=True)
class IntakeChallenge:
    manifest: ContestManifest
    challenge: Challenge
    workspace: Path
    archives: tuple[Path, ...]


class IntakeService:
    """Read human-supplied manifests without following archives out of workspace."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def discover_manifests(self) -> tuple[ContestManifest, ...]:
        """Find manifests belonging to this configured contest only.

        The manifest path and the manifest identity must both match the exact
        configured contest. Other incoming directories are deliberately never
        parsed, even if their name or metadata happens to match.
        """
        contest_dir = self.config.incoming_contest_dir()
        path = contest_dir / "contest.md"
        if path.parent != contest_dir or path.name != "contest.md":  # defensive invariant for future config changes
            raise IntakeError("configured manifest path is not incoming/<contest>/contest.md")
        if not path.is_file() or path.is_symlink():
            return ()
        try:
            manifest = parse_contest(path)
        except ContestParseError:
            raise
        if path.parent.name != self.config.contest_name or manifest.name != self.config.contest_name:
            raise IntakeError("contest directory name and contest.md name must both exactly match contest.name")
        return (manifest,)

    def collect(self) -> tuple[IntakeChallenge, ...]:
        result: list[IntakeChallenge] = []
        for manifest in self.discover_manifests():
            for challenge in manifest.owned_by(self.config.owned_categories):
                archives = self.discover_archives(manifest, challenge)
                workspace = self.config.workspace_dir(manifest.name, challenge.slug)
                if archives:
                    extract_zips_safely(archives, workspace)
                workspace.mkdir(parents=True, exist_ok=True)
                result.append(IntakeChallenge(manifest, challenge, workspace, archives))
        return tuple(result)

    @staticmethod
    def discover_archives(manifest: ContestManifest, challenge: Challenge) -> tuple[Path, ...]:
        """Find archives specifically associated with one manifest challenge."""
        contest_root = manifest.path.parent.resolve(strict=False)
        category_root = contest_root / challenge.category
        if not category_root.is_dir() or category_root.is_symlink():
            return ()
        wanted = {challenge.name.casefold(), challenge.slug.casefold()}
        candidates: set[Path] = set()
        for archive in category_root.glob("*.zip"):
            if archive.stem.casefold() in wanted:
                candidates.add(archive)
        named_dir = category_root / challenge.name
        if named_dir.is_dir() and not named_dir.is_symlink():
            candidates.update(path for path in named_dir.rglob("*.zip") if not path.is_symlink())
        safe: list[Path] = []
        for archive in sorted(candidates):
            try:
                archive.resolve(strict=False).relative_to(contest_root)
            except ValueError as exc:
                raise IntakeError(f"archive escapes contest workspace: {archive}") from exc
            if archive.is_file() and not archive.is_symlink():
                safe.append(archive)
        return tuple(safe)


def extract_zip_safely(
    archive: str | Path,
    destination: str | Path,
    *,
    limits: ZipExtractionLimits = DEFAULT_ZIP_LIMITS,
) -> tuple[Path, ...]:
    """Safely extract one archive through a fresh staging directory."""
    return extract_zips_safely((Path(archive),), destination, limits=limits)


def extract_zips_safely(
    archives: tuple[Path, ...] | list[Path],
    destination: str | Path,
    *,
    limits: ZipExtractionLimits = DEFAULT_ZIP_LIMITS,
) -> tuple[Path, ...]:
    """Stream archives into a fresh staging tree, then atomically replace.

    Metadata caps reject obvious ZIP bombs early, but copied-byte counters are
    authoritative because malicious archives can lie about sizes. Existing
    workspaces remain untouched if any member fails validation or streaming.
    """
    if not archives:
        return ()
    archive_paths = tuple(Path(archive) for archive in archives)
    for archive_path in archive_paths:
        if not archive_path.is_file() or archive_path.is_symlink():
            raise IntakeError(f"challenge archive is not a regular file: {archive_path}")
    destination_path = Path(destination)
    if destination_path.exists() and destination_path.is_symlink():
        raise IntakeError(f"workspace must not be a symlink: {destination_path}")
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    if destination_path.parent.is_symlink():
        raise IntakeError(f"workspace parent must not be a symlink: {destination_path.parent}")
    stage: Path | None = Path(tempfile.mkdtemp(prefix=f".{destination_path.name}.extract-", dir=destination_path.parent))
    written_relatives: list[Path] = []
    try:
        _validate_archive_metadata(archive_paths, limits)
        total_written = 0
        for archive_path in archive_paths:
            with ZipFile(archive_path) as bundle:
                for member in bundle.infolist():
                    assert stage is not None
                    target = _zip_target(stage, member)
                    _reject_unsafe_member(member)
                    if member.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    # A duplicate member cannot silently replace a previous
                    # file, which makes multi-archive extraction deterministic.
                    try:
                        output = target.open("xb")
                    except FileExistsError as exc:
                        raise IntakeError(f"duplicate ZIP member target: {member.filename!r}") from exc
                    file_written = 0
                    with bundle.open(member, "r") as source, output:
                        while True:
                            chunk = source.read(64 * 1024)
                            if not chunk:
                                break
                            file_written += len(chunk)
                            total_written += len(chunk)
                            if file_written > limits.max_file_bytes:
                                raise IntakeError(f"ZIP member exceeds per-file limit: {member.filename!r}")
                            if total_written > limits.max_total_bytes:
                                raise IntakeError("ZIP extraction exceeds total expanded-byte limit")
                            output.write(chunk)
                    written_relatives.append(target.relative_to(stage))
        _replace_directory_atomically(stage, destination_path)
        stage = None  # replacement consumed this path; suppress cleanup below
        return tuple(destination_path / relative for relative in written_relatives)
    except BadZipFile as exc:
        raise IntakeError(f"invalid ZIP archive: {archive_paths[0]}") from exc
    finally:
        if stage is not None and stage.exists():
            _remove_tree(stage)


def _zip_target(root: Path, member: ZipInfo) -> Path:
    name = member.filename
    if not name or "\x00" in name:
        raise IntakeError("ZIP member has an empty or NUL path")
    if "\\" in name:
        raise IntakeError(f"unsafe ZIP member path: {name!r}")
    candidate = PurePosixPath(name)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise IntakeError(f"unsafe ZIP member path: {name!r}")
    target = root.joinpath(*candidate.parts)
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise IntakeError(f"ZIP member escapes workspace: {name!r}") from exc
    return target


def _reject_unsafe_member(member: ZipInfo) -> None:
    mode = member.external_attr >> 16
    if stat.S_IFMT(mode) == stat.S_IFLNK:
        raise IntakeError(f"ZIP symlink members are not allowed: {member.filename!r}")


def _ensure_no_symlink_parent(target: Path, root: Path) -> None:
    parent = target.parent
    while parent != root:
        if parent.is_symlink():
            raise IntakeError(f"workspace contains a symlinked archive path: {parent}")
        parent = parent.parent


def _validate_archive_metadata(archives: tuple[Path, ...], limits: ZipExtractionLimits) -> None:
    file_count = 0
    declared_total = 0
    for archive_path in archives:
        try:
            with ZipFile(archive_path) as bundle:
                for member in bundle.infolist():
                    _reject_unsafe_member(member)
                    _zip_target(Path("/safe-root"), member)
                    if member.is_dir():
                        continue
                    file_count += 1
                    if file_count > limits.max_files:
                        raise IntakeError("ZIP archive exceeds file-count limit")
                    if member.file_size > limits.max_file_bytes:
                        raise IntakeError(f"ZIP member exceeds per-file limit: {member.filename!r}")
                    if member.file_size and (member.compress_size <= 0 or member.file_size > member.compress_size * limits.max_compression_ratio):
                        raise IntakeError(f"ZIP member exceeds compression-ratio limit: {member.filename!r}")
                    declared_total += member.file_size
                    if declared_total > limits.max_total_bytes:
                        raise IntakeError("ZIP archive exceeds total expanded-byte limit")
        except BadZipFile as exc:
            raise IntakeError(f"invalid ZIP archive: {archive_path}") from exc


def _replace_directory_atomically(stage: Path, destination: Path) -> None:
    backup: Path | None = None
    if destination.exists():
        if not destination.is_dir() or destination.is_symlink():
            raise IntakeError(f"workspace destination is not a regular directory: {destination}")
        backup = destination.with_name(f".{destination.name}.previous-{secrets.token_hex(8)}")
        os.replace(destination, backup)
    try:
        os.replace(stage, destination)
    except OSError:
        if backup is not None and backup.exists() and not destination.exists():
            os.replace(backup, destination)
        raise
    if backup is not None:
        _remove_tree(backup)


def _remove_tree(path: Path) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)
