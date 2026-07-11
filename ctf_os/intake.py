"""Local contest discovery and safe challenge archive extraction."""

from __future__ import annotations

from dataclasses import dataclass
import os
import hashlib
import shutil
from pathlib import PurePosixPath
import secrets
import stat
import tempfile
from pathlib import Path
from zipfile import BadZipFile, ZipFile, ZipInfo

from .config import AppConfig
from .contest_parser import ContestManifest, ContestParseError, canonical_category, parse_contest
from .models import Challenge
from .sandbox.network_policy import RemotePolicyError, parse_remote_endpoints


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
_TEMPLATE_VALUES = frozenset({"입력 예정", "미정", "todo", "tbd", "placeholder"})


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

    def collect(self, *, materialize: bool = True) -> tuple[IntakeChallenge, ...]:
        """Validate owned challenges and optionally build their workspaces.

        ``materialize=False`` is used by read-only diagnostics so doctor and
        preflight checks exercise the exact queue gate without mutating the
        incoming tree.
        """
        result: list[IntakeChallenge] = []
        manifests = self.discover_manifests()
        if not manifests:
            path = self.config.incoming_contest_dir() / "contest.md"
            raise IntakeError(f"contest manifest not found: {path}")
        for manifest in manifests:
            owned = manifest.owned_by(self.config.owned_categories)
            ready = tuple(challenge for challenge in owned if not _is_template_challenge(challenge))
            if owned and not ready:
                names = ", ".join(f"{challenge.category}/{challenge.name}" for challenge in owned)
                raise IntakeError(
                    "template challenge is not ready to queue: "
                    f"{names} has placeholder field(s): description; edit or remove the template entry"
                )
            for challenge in ready:
                archives = self.discover_archives(manifest, challenge)
                source_dir = self.discover_source_directory(manifest, challenge)
                unsupported = self.discover_unsupported_attachments(manifest, challenge)
                if unsupported:
                    names = ", ".join(path.name for path in unsupported)
                    raise IntakeError(
                        f"unsupported challenge attachment for {challenge.category}/{challenge.name}: {names}; "
                        "use a matching .zip archive or a matching raw directory"
                    )
                try:
                    endpoints = parse_remote_endpoints(challenge.remote)
                except RemotePolicyError as exc:
                    raise IntakeError(
                        f"invalid remote for {challenge.category}/{challenge.name}: {exc}"
                    ) from exc
                if not archives and source_dir is None and not endpoints:
                    raise IntakeError(
                        f"challenge has no matching source or valid remote: {challenge.category}/{challenge.name}; "
                        f"expected {_category_root(manifest.path.parent, challenge.category) / challenge.name}.zip "
                        f"or {_category_root(manifest.path.parent, challenge.category) / challenge.name}/; "
                        "check the contest.md heading and attachment path/name for a mismatch"
                    )
                workspace = self.config.workspace_dir(manifest.name, challenge.slug)
                if materialize:
                    materialize_challenge_sources(archives, source_dir, workspace)
                result.append(IntakeChallenge(manifest, challenge, workspace, archives))
        return tuple(result)

    @staticmethod
    def discover_archives(manifest: ContestManifest, challenge: Challenge) -> tuple[Path, ...]:
        """Find archives specifically associated with one manifest challenge."""
        contest_root = manifest.path.parent.resolve(strict=False)
        category_root = _category_root(contest_root, challenge.category)
        if not category_root.is_dir() or category_root.is_symlink():
            return ()
        wanted = {challenge.name.casefold(), challenge.slug.casefold()}
        candidates = {
            archive for archive in category_root.iterdir()
            if archive.is_file() and archive.suffix.casefold() == ".zip" and archive.stem.casefold() in wanted
        }
        named_dir = category_root / challenge.name
        if named_dir.is_dir() and not named_dir.is_symlink():
            candidates.update(
                path for path in named_dir.rglob("*")
                if path.is_file() and not path.is_symlink() and path.suffix.casefold() == ".zip"
            )
        safe: list[Path] = []
        for archive in sorted(candidates):
            try:
                archive.resolve(strict=False).relative_to(contest_root)
            except ValueError as exc:
                raise IntakeError(f"archive escapes contest workspace: {archive}") from exc
            if archive.is_file() and not archive.is_symlink():
                safe.append(archive)
        return tuple(safe)

    @staticmethod
    def discover_unsupported_attachments(manifest: ContestManifest, challenge: Challenge) -> tuple[Path, ...]:
        """Reject matching archive formats that this safe extractor cannot inspect."""
        contest_root = manifest.path.parent.resolve(strict=False)
        category_root = _category_root(contest_root, challenge.category)
        if not category_root.is_dir() or category_root.is_symlink():
            return ()
        wanted = {challenge.name.casefold(), challenge.slug.casefold()}
        unsupported_suffixes = (".7z", ".rar", ".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz")
        found: list[Path] = []
        for path in category_root.iterdir():
            if not path.is_file() or path.is_symlink():
                continue
            lower = path.name.casefold()
            for suffix in unsupported_suffixes:
                if lower.endswith(suffix) and lower[:-len(suffix)] in wanted:
                    found.append(path)
                    break
        return tuple(sorted(found))

    @staticmethod
    def discover_source_directory(manifest: ContestManifest, challenge: Challenge) -> Path | None:
        contest_root = manifest.path.parent.resolve(strict=False)
        named = _category_root(contest_root, challenge.category) / challenge.name
        if named.is_symlink():
            raise IntakeError(f"challenge source directory must not be a symlink: {named}")
        return named if named.is_dir() else None


def _is_template_challenge(challenge: Challenge) -> bool:
    """Recognize untouched generated entries without rejecting ready siblings."""
    description = (challenge.description or "").strip().casefold()
    return description in _TEMPLATE_VALUES

def _category_root(contest_root: Path, category: str) -> Path:
    direct = contest_root / category
    if direct.is_dir() or canonical_category(category) != "forensics":
        return direct
    for alias in ("forensics", "forensic"):
        candidate = contest_root / alias
        if candidate.is_dir() and not candidate.is_symlink():
            return candidate
    return direct


def materialize_challenge_sources(archives: tuple[Path, ...], source_dir: Path | None, destination: Path) -> None:
    """Build one deterministic workspace from ZIP and/or plain challenge files."""
    fingerprint = _source_fingerprint(archives, source_dir)
    marker = destination.parent / f".{destination.name}.source.sha256"
    if destination.is_dir() and not destination.is_symlink() and marker.is_file():
        if marker.read_text(encoding="ascii", errors="ignore").strip() == fingerprint:
            return
    destination.parent.mkdir(parents=True, exist_ok=True)
    outer = Path(tempfile.mkdtemp(prefix=f".{destination.name}.materialize-", dir=destination.parent))
    payload = outer / "payload"
    try:
        if archives:
            extract_zips_safely(archives, payload)
        else:
            payload.mkdir()
        if source_dir is not None:
            _copy_plain_sources(source_dir, payload)
        _make_workspace_container_readable(payload)
        _replace_directory_atomically(payload, destination)
        marker.write_text(fingerprint + "\n", encoding="ascii")
    finally:
        if outer.exists():
            _remove_tree(outer)


def _copy_plain_sources(source: Path, destination: Path) -> None:
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if path.is_symlink():
            raise IntakeError(f"symlink blocked in challenge source: {relative}")
        target = destination / relative
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif path.is_file() and path.suffix.casefold() != ".zip":
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                raise IntakeError(f"duplicate challenge source target: {relative}")
            shutil.copyfile(path, target, follow_symlinks=False)


def _make_workspace_container_readable(root: Path) -> None:
    """Expose only the read-only challenge copy to the unprivileged container UID."""
    for path in (root, *sorted(root.rglob("*"))):
        if path.is_symlink():
            raise IntakeError(f"symlink blocked in materialized workspace: {path}")
        if path.is_dir():
            path.chmod(0o755)
        elif path.is_file():
            executable = bool(path.stat().st_mode & 0o111)
            path.chmod(0o755 if executable else 0o644)


def _source_fingerprint(archives: tuple[Path, ...], source_dir: Path | None) -> str:
    digest = hashlib.sha256()
    paths = list(archives)
    if source_dir is not None:
        paths.extend(path for path in sorted(source_dir.rglob("*")) if not path.is_dir())
    for path in paths:
        if path.is_symlink():
            raise IntakeError(f"symlink blocked in challenge source: {path}")
        if not path.is_file():
            continue
        digest.update(str(path).encode("utf-8", errors="surrogateescape"))
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(64 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


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
                    if _zip_member_is_executable(member):
                        target.chmod(0o755)
                    written_relatives.append(target.relative_to(stage))
        _replace_directory_atomically(stage, destination_path)
        stage = None  # replacement consumed this path; suppress cleanup below
        return tuple(destination_path / relative for relative in written_relatives)
    except BadZipFile as exc:
        raise IntakeError(f"invalid ZIP archive: {archive_paths[0]}") from exc
    except RuntimeError as exc:
        raise IntakeError(
            f"cannot extract ZIP archive {archive_path}: encrypted member or unsupported compression ({exc})"
        ) from exc
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


def _zip_member_is_executable(member: ZipInfo) -> bool:
    """Honor only Unix executable bits; all other archive permissions are discarded."""
    return member.create_system == 3 and bool((member.external_attr >> 16) & 0o111)


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
                    if member.flag_bits & 0x1:
                        raise IntakeError(f"encrypted ZIP members are unsupported: {member.filename!r}")
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
