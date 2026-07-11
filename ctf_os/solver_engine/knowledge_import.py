"""Safe, deterministic local importer for the pinned ``ctf-skills`` snapshot.

This module deliberately treats an upstream checkout as untrusted input.  It
uses descriptor-relative, no-follow reads; it never invokes a command, opens a
network connection, or follows a link embedded in Markdown.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass, field
from functools import lru_cache
from hashlib import sha256
from importlib import resources
from pathlib import Path
from typing import Iterable, Iterator, Mapping, Sequence


UPSTREAM_REPOSITORY = "https://github.com/ljagiello/ctf-skills"
PINNED_COMMIT = "0a3a9c41bdef1ffb845e71cb53a7a6adbec85956"
POLICY_VERSION = "ctf-os-knowledge-import-v1"
SNAPSHOT_DIRECTORY = "ctf-skills"
MANIFEST_NAME = "manifest.json"
LICENSE_NAME = "LICENSE"
NOTICE_NAME = "NOTICE.md"
MAX_MARKDOWN_BYTES = 256_000
MAX_LICENSE_BYTES = 64_000

# This is an integrity anchor for the reviewed package resource, rather than
# data supplied by a local checkout or snapshot.  Changing the bundled
# manifest without changing this source makes imports and audits fail closed.
# Code/package replacement is outside this runtime trust boundary and must be
# handled by normal package/release integrity controls.
CANONICAL_DEFAULT_MANIFEST_SHA256 = "65c43b3478c4e2499dd7d290701d350a2332b7333401f2a0b4c4a5bc823fbec4"
CANONICAL_NOTICE_SHA256 = "dd7f3a52205e6fdb3e352dceb6efe6e8a7f5175688cce768edcadd118fe42244"

_DEFAULT_FAMILIES = ("pwn", "web", "reverse", "crypto", "forensics", "misc")
_OPTIONAL_FAMILIES = ("malware", "osint", "ai-ml")
_FAMILY_DIRECTORIES = {
    "pwn": "ctf-pwn",
    "web": "ctf-web",
    "reverse": "ctf-reverse",
    "crypto": "ctf-crypto",
    "forensics": "ctf-forensics",
    "misc": "ctf-misc",
    "malware": "ctf-malware",
    "osint": "ctf-osint",
    "ai-ml": "ctf-ai-ml",
}
_DIRECTORY_FAMILIES = {value: key for key, value in _FAMILY_DIRECTORIES.items()}
_EXCLUDED_BASENAMES = frozenset({"skill.md", "readme.md", "contributing.md", "security.md"})
_EXCLUDED_DIRECTORIES = frozenset({".git", ".github", "scripts", "tests", "solve-challenge", "ctf-writeup"})
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_HEADING_RE = re.compile(r"^#{1,3}\s+(.+?)\s*$")
_GENERATED_RE = re.compile(r"(?im)^\s*(?:<!--\s*)?(?:auto[- ]?generated|generated file|do not edit)\b")
_PROMPT_CONTROL_RE = re.compile(
    r"(?is)\b(?:ignore|disregard|forget)\b.{0,120}\b"
    r"(?:previous|prior|system|developer|tool)\s+(?:instructions?|messages?)?\b|"
    r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?instructions?\b|"
    r"\b(?:prompt|instruction|tool)\s+override\b|"
    r"\b(?:system|developer)\s+(?:message|instructions?)\b.{0,120}\b(?:ignore|override)\b"
)
_REVIEW_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("remote-scan", re.compile(r"(?is)\b(?:nmap|masscan|zmap|shodan|port\s+scan|scan\s+(?:each|all|remote|network|hosts?|ip(?:s)?))\b")),
    ("credential", re.compile(r"(?is)\b(?:credential|api[- ]?key|access[- ]?token)\b")),
    ("private-key", re.compile(r"(?is)\bprivate\s+key(?:s)?\b")),
    ("browser", re.compile(r"(?is)\bbrowser(?:s)?\b")),
    ("cloud-metadata", re.compile(r"(?is)\b(?:cloud\s+metadata|metadata\s+service|169\.254\.169\.254)\b")),
    ("privilege", re.compile(r"(?is)\b(?:privilege\s+escalation|privilege|privesc|root\s+shell|sudoers?)\b")),
)


class KnowledgeImportError(ValueError):
    """Raised before an unsafe or non-pinned source can affect a snapshot."""


@dataclass(frozen=True)
class SectionClassification:
    ordinal: int
    heading: str
    content: str
    classification: str
    flags: tuple[str, ...] = ()

    @property
    def sha256(self) -> str:
        return sha256(self.content.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ImportResult:
    destination: Path
    commit: str
    families: tuple[str, ...]
    file_count: int
    total_bytes: int
    reviewed_sections: int
    quarantined_sections: int
    skipped_files: tuple[str, ...] = ()
    dry_run: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "commit": self.commit,
            "destination": str(self.destination),
            "dry_run": self.dry_run,
            "families": list(self.families),
            "file_count": self.file_count,
            "quarantined_sections": self.quarantined_sections,
            "reviewed_sections": self.reviewed_sections,
            "skipped_files": list(self.skipped_files),
            "total_bytes": self.total_bytes,
        }


@dataclass(frozen=True)
class AuditResult:
    destination: Path
    valid: bool
    commit: str | None
    file_count: int
    total_bytes: int
    trust_counts: Mapping[str, int]
    errors: tuple[str, ...] = ()
    # Internal consumers use this only after ``valid`` is true.  It is kept
    # out of CLI JSON so audit output remains a compact report.
    registered_files: Mapping[str, Mapping[str, object]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "commit": self.commit,
            "destination": str(self.destination),
            "errors": list(self.errors),
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "trust_counts": dict(sorted(self.trust_counts.items())),
            "valid": self.valid,
        }


@lru_cache(maxsize=1)
def _canonical_snapshot_manifest() -> Mapping[str, object]:
    """Return the reviewed manifest only when its code-pinned digest matches.

    The package resource is deliberately not trusted on its own: a local
    checkout can alter it just as it can alter an imported snapshot.  The
    digest above is the runtime trust anchor for this reviewed release.
    """
    try:
        raw = resources.files("ctf_os.resources").joinpath(
            "knowledge", "external", SNAPSHOT_DIRECTORY, MANIFEST_NAME,
        ).read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, OSError) as exc:
        raise KnowledgeImportError("packaged canonical knowledge manifest is unavailable") from exc
    if sha256(raw).hexdigest() != CANONICAL_DEFAULT_MANIFEST_SHA256:
        raise KnowledgeImportError("packaged canonical knowledge manifest digest mismatch")
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KnowledgeImportError("packaged canonical knowledge manifest is invalid") from exc
    if not isinstance(manifest, dict):
        raise KnowledgeImportError("packaged canonical knowledge manifest is not an object")
    return manifest


@lru_cache(maxsize=1)
def _canonical_entries() -> Mapping[str, Mapping[str, object]]:
    manifest = _canonical_snapshot_manifest()
    files = manifest.get("files")
    if not isinstance(files, list):
        raise KnowledgeImportError("packaged canonical knowledge manifest has no files")
    records: dict[str, Mapping[str, object]] = {}
    for entry in files:
        if not isinstance(entry, dict):
            raise KnowledgeImportError("packaged canonical knowledge manifest has an invalid file entry")
        relative = entry.get("original_path")
        if not isinstance(relative, str) or not _safe_relative(relative) or _family_for_path(relative) is None:
            raise KnowledgeImportError("packaged canonical knowledge manifest has an unsafe file path")
        if relative in records:
            raise KnowledgeImportError("packaged canonical knowledge manifest has duplicate file paths")
        records[relative] = entry
    if not records:
        raise KnowledgeImportError("packaged canonical knowledge manifest has no reviewed files")
    return records


def _family_for_path(relative: str) -> str | None:
    parts = Path(relative).parts
    if len(parts) < 2:
        return None
    family = _DIRECTORY_FAMILIES.get(parts[0])
    return family if family in _DEFAULT_FAMILIES else None


def _canonical_entries_for_families(families: Sequence[str]) -> dict[str, Mapping[str, object]]:
    unsupported = set(families) - set(_DEFAULT_FAMILIES)
    if unsupported:
        values = ", ".join(sorted(unsupported))
        raise KnowledgeImportError(
            f"optional knowledge families are not canonically reviewed and are rejected: {values}"
        )
    return {
        relative: entry for relative, entry in _canonical_entries().items()
        if _family_for_path(relative) in families
    }


def _canonical_skipped_for_families(families: Sequence[str]) -> list[object]:
    skipped = _canonical_snapshot_manifest().get("skipped_files")
    if not isinstance(skipped, list):
        raise KnowledgeImportError("packaged canonical knowledge manifest has invalid skipped files")
    selected: list[object] = []
    for value in skipped:
        if not isinstance(value, dict) or not isinstance(value.get("original_path"), str):
            raise KnowledgeImportError("packaged canonical knowledge manifest has invalid skipped files")
        if _family_for_path(value["original_path"]) in families:
            selected.append(value)
    return selected


def normalize_families(families: Iterable[str] | None = None) -> tuple[str, ...]:
    """Return sorted known policy family names for later policy enforcement."""
    requested = _DEFAULT_FAMILIES if not families else tuple(families)
    normalized: set[str] = set()
    for family in requested:
        value = family.strip().casefold()
        value = _DIRECTORY_FAMILIES.get(value, value)
        if value not in _FAMILY_DIRECTORIES:
            available = ", ".join((*_DEFAULT_FAMILIES, *_OPTIONAL_FAMILIES))
            raise KnowledgeImportError(f"unknown knowledge family {family!r}; choose one of: {available}")
        normalized.add(value)
    return tuple(sorted(normalized))


def classify_markdown_sections(text: str) -> tuple[SectionClassification, ...]:
    """Classify Markdown by section without interpreting its code or links."""
    sections: list[tuple[str, list[str]]] = []
    heading = "document"
    body: list[str] = []
    for line in text.splitlines():
        match = _HEADING_RE.match(line)
        if match and body:
            sections.append((heading, body))
            heading, body = match.group(1), [line]
        else:
            body.append(line)
    if body:
        sections.append((heading, body))

    classified: list[SectionClassification] = []
    for ordinal, (section_heading, lines) in enumerate(sections, start=1):
        content = "\n".join(lines).strip()
        if not content:
            classified.append(SectionClassification(ordinal, section_heading, content, "skipped", ("empty",)))
            continue
        lower_context = f"{section_heading}\n{content}"
        if _PROMPT_CONTROL_RE.search(lower_context):
            status, flags = "quarantined", ("prompt-control",)
        else:
            flags = tuple(name for name, expression in _REVIEW_RULES if expression.search(lower_context))
            status = "reviewed" if flags else "accepted"
        classified.append(SectionClassification(ordinal, section_heading, content, status, flags))
    return tuple(classified)


def import_snapshot(
    source: str | Path,
    destination: str | Path,
    *,
    commit: str,
    families: Iterable[str] | None = None,
    dry_run: bool = False,
) -> ImportResult:
    """Import the reviewed local checkout into one atomically replaced snapshot.

    ``source`` must be a local checkout of the exact reviewed commit.  The
    importer does not clone, fetch, execute examples, or resolve Markdown URLs.
    """
    _validate_commit(commit)
    selected = normalize_families(families)
    # Optional families do not have a release-reviewed canonical hash set.
    # Do not turn an explicit opt-in into a false provenance claim.
    _canonical_entries_for_families(selected)
    _, root_fd = _open_root(source)
    try:
        actual_commit = _checkout_commit(root_fd)
        if actual_commit != commit:
            raise KnowledgeImportError(
                f"source checkout is {actual_commit or 'unresolved'}, not requested commit {commit}"
            )
        if commit != PINNED_COMMIT:
            raise KnowledgeImportError(f"ctf-skills import is pinned to {PINNED_COMMIT}; received {commit}")
        license_bytes = _read_regular(root_fd, LICENSE_NAME, MAX_LICENSE_BYTES, display=LICENSE_NAME)
        _validate_mit_license(license_bytes)
        expected_license = _canonical_snapshot_manifest().get("license_sha256")
        if not isinstance(expected_license, str) or sha256(license_bytes).hexdigest() != expected_license:
            raise KnowledgeImportError("source LICENSE does not match the canonical pinned snapshot")
        files, skipped = _collect_source_files(root_fd, selected)
        _verify_canonical_source_files(files, skipped, selected)
    finally:
        os.close(root_fd)

    destination_path = Path(destination).expanduser()
    result = _result_for(destination_path, commit, selected, files, skipped, dry_run=dry_run)
    if dry_run:
        return result

    parent = destination_path.parent
    parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink() or not parent.is_dir():
        raise KnowledgeImportError(f"snapshot parent must be a non-symlink directory: {parent}")
    staging = Path(tempfile.mkdtemp(prefix=".ctf-os-knowledge-import-", dir=parent))
    try:
        _write_snapshot(staging, files, license_bytes, commit, selected, skipped)
        _commit_snapshot(staging, destination_path)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return result


def audit_snapshot(destination: str | Path) -> AuditResult:
    """Validate an imported snapshot against the reviewed package anchor.

    The local manifest never authorizes its own content.  It must describe an
    exact, selected subset of the code-anchored default six-family manifest,
    and the on-disk regular-file set must match that description exactly.
    """
    root = Path(destination).expanduser()
    errors: list[str] = []
    try:
        if root.is_symlink() or not root.is_dir():
            raise KnowledgeImportError("snapshot is not a non-symlink directory")
        raw = _read_snapshot_regular(root, MANIFEST_NAME, 2_000_000)
        if b"\x00" in raw:
            raise KnowledgeImportError("snapshot manifest is unsafe")
        manifest = json.loads(raw.decode("utf-8"))
        if not isinstance(manifest, dict):
            raise KnowledgeImportError("snapshot manifest is not an object")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KnowledgeImportError) as exc:
        return AuditResult(root, False, None, 0, 0, {}, (str(exc),))

    upstream = manifest.get("upstream") if isinstance(manifest.get("upstream"), dict) else {}
    commit = upstream.get("commit") if isinstance(upstream.get("commit"), str) else None
    trust_counts: dict[str, int] = {"accepted": 0, "reviewed": 0, "quarantined": 0, "skipped": 0}
    manifest_records: dict[str, Mapping[str, object]] = {}
    total_bytes = 0
    try:
        canonical = _canonical_snapshot_manifest()
        canonical_license = canonical.get("license_sha256")
        if not isinstance(canonical_license, str):
            raise KnowledgeImportError("packaged canonical knowledge manifest has no license hash")
        families = _snapshot_families(manifest)
        expected_records = _canonical_entries_for_families(families)
        expected_skipped = _canonical_skipped_for_families(families)
    except KnowledgeImportError as exc:
        errors.append(str(exc))
        families = ()
        expected_records = {}
        expected_skipped = []
        canonical_license = ""

    if set(manifest) != {
        "file_count", "files", "families", "license_sha256", "policy_version", "schema_version",
        "skipped_files", "total_bytes", "upstream",
    }:
        errors.append("snapshot manifest has unexpected or missing fields")
    if commit != PINNED_COMMIT:
        errors.append(f"unexpected commit: {commit!r}")
    if upstream.get("repository") != UPSTREAM_REPOSITORY:
        errors.append("unexpected upstream repository")
    if upstream.get("license") != "MIT":
        errors.append("unexpected upstream license")
    if manifest.get("policy_version") != POLICY_VERSION or manifest.get("schema_version") != 1:
        errors.append("unexpected snapshot manifest policy or schema")
    if manifest.get("license_sha256") != canonical_license:
        errors.append("snapshot manifest license hash is not canonical")

    files = manifest.get("files")
    if not isinstance(files, list):
        errors.append("snapshot manifest files is not a list")
        files = []
    for entry in files:
        if not isinstance(entry, dict):
            errors.append("manifest contains a non-object file entry")
            continue
        relative = entry.get("original_path")
        if not isinstance(relative, str) or not _safe_relative(relative):
            errors.append("manifest contains an unsafe file path")
            continue
        if relative in manifest_records:
            errors.append(f"manifest contains a duplicate file path: {relative}")
            continue
        manifest_records[relative] = entry

    if set(manifest_records) != set(expected_records):
        for relative in sorted(set(expected_records) - set(manifest_records)):
            errors.append(f"missing canonical manifest entry: {relative}")
        for relative in sorted(set(manifest_records) - set(expected_records)):
            errors.append(f"unreviewed manifest entry: {relative}")

    actual_regular, filesystem_errors = _snapshot_regular_paths(root)
    errors.extend(filesystem_errors)
    expected_regular = {MANIFEST_NAME, LICENSE_NAME, NOTICE_NAME, *expected_records}
    for relative in sorted(expected_regular - actual_regular):
        errors.append(f"missing snapshot file: {relative}")
    for relative in sorted(actual_regular - expected_regular):
        errors.append(f"unregistered snapshot file: {relative}")

    for relative, expected_entry in expected_records.items():
        entry = manifest_records.get(relative)
        if entry != expected_entry:
            errors.append(f"canonical file or section metadata mismatch: {relative}")
        try:
            data = _read_snapshot_regular(root, relative, MAX_MARKDOWN_BYTES)
        except (OSError, KnowledgeImportError):
            continue
        total_bytes += len(data)
        if sha256(data).hexdigest() != expected_entry.get("sha256"):
            errors.append(f"hash mismatch: {relative}")
        sections = expected_entry.get("sections")
        if isinstance(sections, list):
            for section in sections:
                if isinstance(section, dict) and section.get("classification") in trust_counts:
                    trust_counts[str(section["classification"])] += 1

    if manifest.get("file_count") != len(expected_records):
        errors.append("file count does not match canonical manifest")
    if manifest.get("total_bytes") != total_bytes:
        errors.append("total bytes do not match canonical manifest")
    if manifest.get("skipped_files") != expected_skipped:
        errors.append("skipped files do not match canonical manifest")
    try:
        license_bytes = _read_snapshot_regular(root, LICENSE_NAME, MAX_LICENSE_BYTES)
        _validate_mit_license(license_bytes)
        if sha256(license_bytes).hexdigest() != canonical_license:
            errors.append("license hash mismatch")
    except (OSError, KnowledgeImportError):
        errors.append("valid canonical MIT license is missing")
    try:
        notice_bytes = _read_snapshot_regular(root, NOTICE_NAME, MAX_LICENSE_BYTES)
        if sha256(notice_bytes).hexdigest() != CANONICAL_NOTICE_SHA256:
            errors.append("notice hash mismatch")
    except (OSError, KnowledgeImportError):
        errors.append("canonical notice is missing")

    valid = not errors
    return AuditResult(
        root, valid, commit, len(manifest_records), total_bytes, trust_counts, tuple(errors),
        manifest_records if valid else {},
    )


def _validate_commit(commit: str) -> None:
    if not _COMMIT_RE.fullmatch(commit):
        raise KnowledgeImportError("commit must be a lowercase 40-character SHA-1")


def _open_root(source: str | Path) -> tuple[Path, int]:
    path = Path(source).expanduser()
    try:
        source_stat = path.lstat()
    except OSError as exc:
        raise KnowledgeImportError(f"source is unavailable: {path}") from exc
    if stat.S_ISLNK(source_stat.st_mode) or not stat.S_ISDIR(source_stat.st_mode):
        raise KnowledgeImportError(f"source must be a non-symlink directory: {path}")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise KnowledgeImportError(f"cannot open source directory: {path}") from exc
    return path.absolute(), descriptor


def _checkout_commit(root_fd: int) -> str | None:
    """Resolve only ordinary loose/packed git refs using descriptor-safe reads."""
    try:
        git_stat = os.stat(".git", dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(git_stat.st_mode):
        return None
    git_fd = _open_directory(root_fd, ".git")
    try:
        head = _read_regular(git_fd, "HEAD", 4096, display=".git/HEAD").decode("ascii").strip()
        if _COMMIT_RE.fullmatch(head):
            return head
        if not head.startswith("ref: "):
            return None
        reference = head[5:]
        if not _safe_relative(reference) or not reference.startswith("refs/"):
            return None
        try:
            value = _read_nested_regular(git_fd, reference, 4096, display=f".git/{reference}").decode("ascii").strip()
        except FileNotFoundError:
            value = _packed_ref(git_fd, reference)
        return value if _COMMIT_RE.fullmatch(value) else None
    except (OSError, UnicodeDecodeError, KnowledgeImportError):
        return None
    finally:
        os.close(git_fd)


def _packed_ref(git_fd: int, reference: str) -> str:
    try:
        content = _read_regular(git_fd, "packed-refs", 1_000_000, display=".git/packed-refs").decode("ascii")
    except FileNotFoundError:
        return ""
    for line in content.splitlines():
        if not line.startswith(("#", "^")):
            parts = line.split(" ", 1)
            if len(parts) == 2 and parts[1] == reference:
                return parts[0]
    return ""


def _collect_source_files(root_fd: int, families: Sequence[str]) -> tuple[list[tuple[str, str, bytes, tuple[SectionClassification, ...]]], list[str]]:
    files: list[tuple[str, str, bytes, tuple[SectionClassification, ...]]] = []
    skipped: list[str] = []
    for family in families:
        directory = _FAMILY_DIRECTORIES[family]
        try:
            family_fd = _open_directory(root_fd, directory)
        except FileNotFoundError as exc:
            raise KnowledgeImportError(f"source does not contain required family directory: {directory}") from exc
        try:
            for relative, data in _walk_markdown(family_fd, directory):
                basename = relative.rsplit("/", 1)[-1].casefold()
                parts = relative.split("/")
                if basename in _EXCLUDED_BASENAMES or any(part.casefold() in _EXCLUDED_DIRECTORIES for part in parts):
                    continue
                text = data.decode("utf-8")
                if _GENERATED_RE.search(text):
                    skipped.append(relative)
                    continue
                sections = classify_markdown_sections(text)
                files.append((relative, family, data, sections))
        finally:
            os.close(family_fd)
    files.sort(key=lambda item: item[0])
    return files, sorted(skipped)


def _verify_canonical_source_files(
    files: Sequence[tuple[str, str, bytes, tuple[SectionClassification, ...]]],
    skipped: Sequence[str],
    families: Sequence[str],
) -> None:
    """Reject a dirty checkout even when its Git HEAD still names the pin."""
    expected = _canonical_entries_for_families(families)
    actual: dict[str, tuple[str, bytes, tuple[SectionClassification, ...]]] = {}
    for relative, family, data, sections in files:
        if relative in actual:
            raise KnowledgeImportError(f"source contains duplicate knowledge path: {relative}")
        actual[relative] = (family, data, sections)

    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    if missing or unexpected:
        detail = []
        if missing:
            detail.append(f"missing canonical files: {', '.join(missing)}")
        if unexpected:
            detail.append(f"unreviewed source files: {', '.join(unexpected)}")
        raise KnowledgeImportError("source checkout does not match the canonical pinned snapshot (" + "; ".join(detail) + ")")

    for relative, (family, data, sections) in actual.items():
        entry = expected[relative]
        source_entry = _source_manifest_entry(relative, family, data, sections)
        if source_entry != entry:
            raise KnowledgeImportError(f"source file or section metadata does not match the canonical pinned snapshot: {relative}")

    expected_skipped = _canonical_skipped_for_families(families)
    actual_skipped = [{"classification": "skipped", "original_path": value} for value in sorted(skipped)]
    if actual_skipped != expected_skipped:
        raise KnowledgeImportError("source skipped files do not match the canonical pinned snapshot")


def _source_manifest_entry(
    relative: str,
    family: str,
    data: bytes,
    sections: Sequence[SectionClassification],
) -> dict[str, object]:
    return {
        "category": "rev" if family == "reverse" else family,
        "flags": sorted({flag for section in sections for flag in section.flags}),
        "original_path": relative,
        "sections": [
            {
                "classification": section.classification,
                "flags": list(section.flags),
                "heading": section.heading,
                "ordinal": section.ordinal,
                "sha256": section.sha256,
                "truncated": False,
            }
            for section in sections
        ],
        "sha256": sha256(data).hexdigest(),
        "truncated": False,
    }


def _walk_markdown(directory_fd: int, prefix: str) -> Iterator[tuple[str, bytes]]:
    for name in sorted(os.listdir(directory_fd)):
        if name in {".", ".."} or "/" in name or "\\" in name:
            raise KnowledgeImportError("source directory contains an unsafe entry name")
        relative = f"{prefix}/{name}"
        try:
            item_stat = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise KnowledgeImportError(f"cannot inspect source entry: {relative}") from exc
        if stat.S_ISLNK(item_stat.st_mode):
            raise KnowledgeImportError(f"symlink blocked in source: {relative}")
        if stat.S_ISDIR(item_stat.st_mode):
            if name.casefold() in _EXCLUDED_DIRECTORIES:
                continue
            child_fd = _open_directory(directory_fd, name)
            try:
                yield from _walk_markdown(child_fd, relative)
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(item_stat.st_mode) and name.casefold().endswith(".md"):
            if name.casefold() in _EXCLUDED_BASENAMES:
                continue
            yield relative, _read_regular(directory_fd, name, MAX_MARKDOWN_BYTES, display=relative)


def _open_directory(parent_fd: int, name: str) -> int:
    if not _safe_relative(name) or "/" in name:
        raise KnowledgeImportError("unsafe directory name")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    return os.open(name, flags, dir_fd=parent_fd)


def _read_nested_regular(root_fd: int, relative: str, limit: int, *, display: str) -> bytes:
    parts = relative.split("/")
    if not _safe_relative(relative):
        raise KnowledgeImportError(f"unsafe path: {display}")
    current_fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd = _open_directory(current_fd, part)
            os.close(current_fd)
            current_fd = next_fd
        return _read_regular(current_fd, parts[-1], limit, display=display)
    finally:
        os.close(current_fd)


def _read_regular(parent_fd: int, name: str, limit: int, *, display: str) -> bytes:
    if not _safe_relative(name) or "/" in name:
        raise KnowledgeImportError(f"unsafe path: {display}")
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise KnowledgeImportError(f"cannot inspect source file: {display}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise KnowledgeImportError(f"regular file required: {display}")
    if before.st_size > limit:
        raise KnowledgeImportError(f"oversized file blocked: {display}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise KnowledgeImportError(f"cannot open source file: {display}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise KnowledgeImportError(f"source file changed while opening: {display}")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > limit:
            raise KnowledgeImportError(f"oversized file blocked: {display}")
        result = bytes(data)
    finally:
        os.close(descriptor)
    if b"\x00" in result:
        raise KnowledgeImportError(f"NUL byte blocked: {display}")
    try:
        result.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise KnowledgeImportError(f"invalid UTF-8 blocked: {display}") from exc
    return result


def _safe_relative(value: str) -> bool:
    path = Path(value)
    return bool(value) and not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)


def _snapshot_file(root: Path, relative: str) -> Path:
    """Reject a tampered snapshot whose file path crosses a symlink."""
    if not _safe_relative(relative):
        raise OSError("unsafe snapshot path")
    path = root
    for part in Path(relative).parts:
        path = path / part
        if path.is_symlink():
            raise OSError("linked snapshot path")
    return path


def _snapshot_families(manifest: Mapping[str, object]) -> tuple[str, ...]:
    families = manifest.get("families")
    if not isinstance(families, list) or not families or not all(isinstance(value, str) for value in families):
        raise KnowledgeImportError("snapshot manifest has invalid families")
    normalized = tuple(sorted({value.casefold().strip() for value in families}))
    if tuple(families) != normalized:
        raise KnowledgeImportError("snapshot manifest families must be sorted and unique")
    _canonical_entries_for_families(normalized)
    return normalized


def _snapshot_regular_paths(root: Path) -> tuple[set[str], list[str]]:
    """Return every regular file and report every link or non-file node."""
    regular: set[str] = set()
    errors: list[str] = []

    def walk(directory: Path, prefix: Path) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            errors.append(f"cannot inspect snapshot directory: {prefix.as_posix() or '.'} ({exc})")
            return
        for entry in entries:
            relative = prefix / entry.name
            display = relative.as_posix()
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError as exc:
                errors.append(f"cannot inspect snapshot entry: {display} ({exc})")
                continue
            if stat.S_ISLNK(entry_stat.st_mode):
                errors.append(f"symlink blocked in snapshot: {display}")
            elif stat.S_ISDIR(entry_stat.st_mode):
                walk(Path(entry.path), relative)
            elif stat.S_ISREG(entry_stat.st_mode):
                regular.add(display)
            else:
                errors.append(f"non-regular snapshot entry: {display}")

    walk(root, Path())
    return regular, errors


def _read_snapshot_regular(root: Path, relative: str, limit: int) -> bytes:
    """Read one regular snapshot file after rejecting every linked component."""
    path = _snapshot_file(root, relative)
    try:
        before = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise KnowledgeImportError(f"cannot inspect snapshot file: {relative}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise KnowledgeImportError(f"regular snapshot file required: {relative}")
    if before.st_size > limit:
        raise KnowledgeImportError(f"oversized snapshot file blocked: {relative}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise KnowledgeImportError(f"cannot open snapshot file: {relative}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise KnowledgeImportError(f"snapshot file changed while opening: {relative}")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > limit:
            raise KnowledgeImportError(f"oversized snapshot file blocked: {relative}")
        return bytes(data)
    finally:
        os.close(descriptor)


def _validate_mit_license(data: bytes) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise KnowledgeImportError("license must be valid UTF-8") from exc
    required = (
        "MIT License",
        "Permission is hereby granted",
        "without restriction, including without limitation",
        "copies or substantial portions of the Software",
        "THE SOFTWARE IS PROVIDED \"AS IS\"",
        "AUTHORS OR COPYRIGHT HOLDERS",
        "OUT OF OR IN CONNECTION WITH THE SOFTWARE",
    )
    if not all(marker in text for marker in required):
        raise KnowledgeImportError("source LICENSE is not the complete MIT license")


def _result_for(
    destination: Path,
    commit: str,
    families: tuple[str, ...],
    files: Sequence[tuple[str, str, bytes, tuple[SectionClassification, ...]]],
    skipped: Sequence[str],
    *,
    dry_run: bool,
) -> ImportResult:
    classifications = [section.classification for _, _, _, sections in files for section in sections]
    return ImportResult(
        destination=destination,
        commit=commit,
        families=families,
        file_count=len(files),
        total_bytes=sum(len(data) for _, _, data, _ in files),
        reviewed_sections=classifications.count("reviewed"),
        quarantined_sections=classifications.count("quarantined"),
        skipped_files=tuple(skipped),
        dry_run=dry_run,
    )


def _write_snapshot(
    staging: Path,
    files: Sequence[tuple[str, str, bytes, tuple[SectionClassification, ...]]],
    license_bytes: bytes,
    commit: str,
    families: Sequence[str],
    skipped: Sequence[str],
) -> None:
    entries: list[dict[str, object]] = []
    for relative, family, data, sections in files:
        target = staging / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        os.chmod(target, 0o600)
        entries.append({
            "category": "rev" if family == "reverse" else family,
            "flags": sorted({flag for section in sections for flag in section.flags}),
            "original_path": relative,
            "sections": [
                {
                    "classification": section.classification,
                    "flags": list(section.flags),
                    "heading": section.heading,
                    "ordinal": section.ordinal,
                    "sha256": section.sha256,
                    "truncated": False,
                }
                for section in sections
            ],
            "sha256": sha256(data).hexdigest(),
            "truncated": False,
        })
    (staging / LICENSE_NAME).write_bytes(license_bytes)
    os.chmod(staging / LICENSE_NAME, 0o600)
    notice = (
        "# Third-party knowledge attribution\n\n"
        "This snapshot contains selected Markdown reference material from "
        "[ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills), "
        f"commit `{commit}`, Copyright (c) 2026 Lukasz Jagiello.\n\n"
        "It is licensed under the MIT License.  The complete upstream license "
        f"is retained in `{LICENSE_NAME}`.  CTF-OS imports this material locally; "
        "it does not execute fenced commands or fetch linked content.\n"
    )
    (staging / NOTICE_NAME).write_text(notice, encoding="utf-8", newline="\n")
    os.chmod(staging / NOTICE_NAME, 0o600)
    manifest = {
        "file_count": len(entries),
        "files": entries,
        "families": list(families),
        "license_sha256": sha256(license_bytes).hexdigest(),
        "policy_version": POLICY_VERSION,
        "schema_version": 1,
        "skipped_files": [{"classification": "skipped", "original_path": value} for value in sorted(skipped)],
        "total_bytes": sum(len(data) for _, _, data, _ in files),
        "upstream": {
            "commit": commit,
            "license": "MIT",
            "repository": UPSTREAM_REPOSITORY,
        },
    }
    (staging / MANIFEST_NAME).write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    os.chmod(staging / MANIFEST_NAME, 0o600)


def _commit_snapshot(staging: Path, destination: Path) -> None:
    """Swap a complete private directory in, restoring the old snapshot on error."""
    backup = destination.parent / f".{destination.name}.previous"
    if backup.exists() or backup.is_symlink():
        if backup.is_dir() and not backup.is_symlink():
            shutil.rmtree(backup)
        else:
            backup.unlink()
    moved_old = False
    try:
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink() or not destination.is_dir():
                raise KnowledgeImportError(f"snapshot destination must be a directory: {destination}")
            os.replace(destination, backup)
            moved_old = True
        os.replace(staging, destination)
    except BaseException:
        if moved_old and not destination.exists() and backup.exists():
            os.replace(backup, destination)
        raise
    if backup.exists():
        shutil.rmtree(backup)
