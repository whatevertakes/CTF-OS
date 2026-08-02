#!/usr/bin/env python3
"""Emit a bounded, typed index of immutable forensic challenge evidence.

The container entrypoint has already produced a NUL-delimited tree containing
the SHA-256 of every challenge file.  This producer verifies that provenance,
opens source paths component-by-component without following links, reads only
a small prefix for format classification, and emits one canonical JSON
document.  It never executes or parses the evidence with a category tool.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterator


CONTRACT_ID = "ctfos.forensic.evidence_index"
CONTRACT_VERSION = 1
SCHEMA_VERSION = 1
TREE_FORMAT = "ctf-tree-v1-nul"

MAX_METADATA_BYTES = 1024 * 1024
MAX_TREE_BYTES = 32 * 1024 * 1024
MAX_FILES = 20_000
MAX_PREFIX_BYTES = 4096
MAX_EMITTED_RECORDS = 4096
MAX_EMITTED_RECORD_JSON_BYTES = 4 * 1024 * 1024

_HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


class EvidenceIndexError(ValueError):
    """A deterministic, operator-safe evidence-index rejection."""


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _read_bounded_regular(path: Path, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY | _O_CLOEXEC | _O_NONBLOCK | _O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise EvidenceIndexError("provenance_open_failed") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise EvidenceIndexError("provenance_not_regular")
        if before.st_size > maximum_bytes:
            raise EvidenceIndexError("provenance_too_large")
        payload = bytearray()
        while len(payload) <= maximum_bytes:
            block = os.read(
                descriptor,
                min(64 * 1024, maximum_bytes + 1 - len(payload)),
            )
            if not block:
                break
            payload.extend(block)
        if len(payload) > maximum_bytes or os.read(descriptor, 1):
            raise EvidenceIndexError("provenance_grew_beyond_limit")
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_after != identity_before:
            raise EvidenceIndexError("provenance_changed_while_reading")
        return bytes(payload)
    except OSError as error:
        raise EvidenceIndexError("provenance_read_failed") from error
    finally:
        os.close(descriptor)


def _strict_json_object(payload: bytes) -> dict[str, Any]:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise EvidenceIndexError("metadata_duplicate_key")
            value[key] = item
        return value

    try:
        decoded = payload.decode("utf-8")
        value = json.loads(
            decoded,
            object_pairs_hook=reject_duplicate,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                EvidenceIndexError("metadata_nonfinite_number")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceIndexError("metadata_invalid_json") from error
    if not isinstance(value, dict):
        raise EvidenceIndexError("metadata_root_not_object")
    return value


def _validate_relative_path(path: bytes) -> tuple[bytes, ...]:
    if (
        not path
        or path.startswith(b"/")
        or b"\x00" in path
        or any(part in {b"", b".", b".."} for part in path.split(b"/"))
    ):
        raise EvidenceIndexError("tree_path_invalid")
    return tuple(path.split(b"/"))


def _parse_octal_mode(value: bytes) -> int:
    if not value or any(character not in b"01234567" for character in value):
        raise EvidenceIndexError("tree_mode_invalid")
    try:
        parsed = int(value, 8)
    except ValueError as error:
        raise EvidenceIndexError("tree_mode_invalid") from error
    if parsed > 0o7777:
        raise EvidenceIndexError("tree_mode_invalid")
    return parsed


def _tree_files(payload: bytes) -> Iterator[tuple[bytes, int, str]]:
    tokens = payload.split(b"\x00")
    if not tokens or tokens[-1] != b"":
        raise EvidenceIndexError("tree_not_nul_terminated")
    cursor = 0
    previous_path: bytes | None = None
    seen: set[bytes] = set()
    while cursor < len(tokens) - 1:
        entry_kind = tokens[cursor]
        cursor += 1
        if entry_kind in {b"D", b"F"}:
            width = 2 if entry_kind == b"D" else 3
        elif entry_kind == b"L":
            width = 4
        else:
            raise EvidenceIndexError("tree_entry_kind_invalid")
        if cursor + width > len(tokens):
            raise EvidenceIndexError("tree_entry_truncated")
        mode_raw = tokens[cursor]
        path = tokens[cursor + 1]
        cursor += width
        mode = _parse_octal_mode(mode_raw)
        _validate_relative_path(path)
        if path in seen:
            raise EvidenceIndexError("tree_path_duplicate")
        if previous_path is not None and path <= previous_path:
            raise EvidenceIndexError("tree_path_order_invalid")
        previous_path = path
        seen.add(path)
        if entry_kind == b"L":
            raise EvidenceIndexError("tree_symlink_unsupported")
        if entry_kind == b"D":
            continue
        digest = tokens[cursor - 1].decode("ascii", errors="strict")
        if not _HEX_SHA256.fullmatch(digest):
            raise EvidenceIndexError("tree_sha256_invalid")
        yield path, mode, digest


def _open_root(root: Path) -> int:
    flags = os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW
    try:
        descriptor = os.open(root, flags)
    except OSError as error:
        raise EvidenceIndexError("source_root_open_failed") from error
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(opened.st_mode):
        os.close(descriptor)
        raise EvidenceIndexError("source_root_not_directory")
    return descriptor


def _open_relative_regular(root_descriptor: int, path: bytes) -> int:
    components = _validate_relative_path(path)
    current = os.dup(root_descriptor)
    try:
        for component in components[:-1]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
                dir_fd=current,
            )
            os.close(current)
            current = next_descriptor
        descriptor = os.open(
            components[-1],
            os.O_RDONLY | _O_CLOEXEC | _O_NONBLOCK | _O_NOFOLLOW,
            dir_fd=current,
        )
    except OSError as error:
        raise EvidenceIndexError("source_path_open_failed") from error
    finally:
        os.close(current)
    opened = os.fstat(descriptor)
    if not stat.S_ISREG(opened.st_mode):
        os.close(descriptor)
        raise EvidenceIndexError("source_path_not_regular")
    return descriptor


def _probe_file(
    root_descriptor: int,
    path: bytes,
    *,
    expected_mode: int,
    expected_sha256: str,
) -> tuple[os.stat_result, bytes]:
    descriptor = _open_relative_regular(root_descriptor, path)
    try:
        before = os.fstat(descriptor)
        if stat.S_IMODE(before.st_mode) != expected_mode:
            raise EvidenceIndexError("source_mode_mismatch")
        digest = hashlib.sha256()
        prefix = bytearray()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            if len(prefix) < MAX_PREFIX_BYTES:
                prefix.extend(
                    block[: MAX_PREFIX_BYTES - len(prefix)]
                )
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_after != identity_before:
            raise EvidenceIndexError("source_changed_while_probing")
        if digest.hexdigest() != expected_sha256:
            raise EvidenceIndexError("source_hash_mismatch")
        return after, bytes(prefix)
    except OSError as error:
        raise EvidenceIndexError("source_probe_failed") from error
    finally:
        os.close(descriptor)


def _classify(path: str, prefix: bytes) -> tuple[str, str, str]:
    lowered = path.casefold()
    basename = lowered.rsplit("/", 1)[-1]
    suffix = lowered.rsplit(".", 1)[-1] if "." in lowered else ""
    if prefix.startswith(b"SQLite format 3\x00"):
        if basename == "history":
            return "browser_history", "chromium-history-sqlite", "magic+name"
        if basename == "places.sqlite":
            return "browser_history", "firefox-places-sqlite", "magic+name"
    if len(prefix) >= 8 and prefix[4:8] == b"SCCA":
        return "execution_artifact", "windows-prefetch", "magic"
    if prefix.startswith(b"MAM\x04"):
        return "execution_artifact", "windows-prefetch-compressed", "magic"
    if basename in {"$j", "$usnjrnl"} or basename.endswith("$usnjrnl:$j"):
        return "filesystem_artifact", "windows-usn-journal", "name"
    if basename == "$mft":
        return "filesystem_artifact", "windows-mft", "name"
    if basename == "consolehost_history.txt":
        return "shell_history", "powershell-history", "name"
    if basename == ".bash_history":
        return "shell_history", "bash-history", "name"
    magic_rules = (
        (b"\x0a\x0d\x0d\x0a", "network", "pcapng"),
        (b"\xd4\xc3\xb2\xa1", "network", "pcap"),
        (b"\xa1\xb2\xc3\xd4", "network", "pcap"),
        (b"\x4d\x3c\xb2\xa1", "network", "pcap-nanosecond"),
        (b"\xa1\xb2\x3c\x4d", "network", "pcap-nanosecond"),
        (b"ElfFile\x00", "event_log", "windows-evtx"),
        (b"regf", "registry", "windows-registry-hive"),
        (b"EVF\x09\x0d\x0a\xff\x00", "disk", "ewf-e01"),
        (b"%PDF-", "document", "pdf"),
        (b"PK\x03\x04", "archive", "zip"),
        (b"\x1f\x8b", "archive", "gzip"),
        (b"7z\xbc\xaf\x27\x1c", "archive", "7zip"),
        (b"Rar!\x1a\x07", "archive", "rar"),
        (b"\x89PNG\r\n\x1a\n", "image", "png"),
        (b"\xff\xd8\xff", "image", "jpeg"),
        (b"GIF87a", "image", "gif"),
        (b"GIF89a", "image", "gif"),
        (b"SQLite format 3\x00", "database", "sqlite3"),
    )
    for magic, modality, format_name in magic_rules:
        if prefix.startswith(magic):
            return modality, format_name, "magic"
    if prefix.startswith(b"RIFF") and prefix[8:12] == b"WAVE":
        return "audio", "wav", "magic"
    if prefix.startswith(b"RIFF") and prefix[8:12] == b"AVI ":
        return "video", "avi", "magic"
    if len(prefix) >= 12 and prefix[4:8] == b"ftyp":
        return "video", "iso-base-media", "magic"

    extension_rules = {
        "cap": ("network", "packet-capture"),
        "pcap": ("network", "pcap"),
        "pcapng": ("network", "pcapng"),
        "dd": ("disk", "raw-disk-image"),
        "e01": ("disk", "ewf-e01"),
        "ex01": ("disk", "ewf-ex01"),
        "img": ("disk", "disk-image"),
        "qcow2": ("disk", "qcow2"),
        "vhd": ("disk", "vhd"),
        "vhdx": ("disk", "vhdx"),
        "vmdk": ("disk", "vmdk"),
        "dmp": ("memory", "memory-dump"),
        "lime": ("memory", "lime-memory"),
        "mem": ("memory", "memory-dump"),
        "vmem": ("memory", "vmware-memory"),
        "vmsn": ("memory", "vmware-snapshot"),
        "raw": ("memory", "raw-memory-or-disk"),
        "evtx": ("event_log", "windows-evtx"),
        "pf": ("execution_artifact", "windows-prefetch"),
        "eml": ("mail", "rfc822-message"),
        "mbox": ("mail", "mbox"),
        "pst": ("mail", "outlook-pst"),
        "ost": ("mail", "outlook-ost"),
        "jsonl": ("log", "json-lines"),
        "log": ("log", "text-log"),
        "syslog": ("log", "syslog"),
        "bmp": ("image", "bmp"),
        "jpg": ("image", "jpeg"),
        "jpeg": ("image", "jpeg"),
        "png": ("image", "png"),
        "tif": ("image", "tiff"),
        "tiff": ("image", "tiff"),
        "mp3": ("audio", "mp3"),
        "flac": ("audio", "flac"),
        "wav": ("audio", "wav"),
        "avi": ("video", "avi"),
        "mkv": ("video", "matroska"),
        "mov": ("video", "quicktime"),
        "mp4": ("video", "mp4"),
        "doc": ("document", "ole-document"),
        "docx": ("document", "office-open-xml"),
        "hwp": ("document", "hwp"),
        "pdf": ("document", "pdf"),
        "rtf": ("document", "rtf"),
        "xls": ("document", "ole-spreadsheet"),
        "xlsx": ("document", "office-open-xml"),
        "7z": ("archive", "7zip"),
        "bz2": ("archive", "bzip2"),
        "gz": ("archive", "gzip"),
        "rar": ("archive", "rar"),
        "tar": ("archive", "tar"),
        "xz": ("archive", "xz"),
        "zip": ("archive", "zip"),
        "db": ("database", "database"),
        "sqlite": ("database", "sqlite"),
        "sqlite3": ("database", "sqlite3"),
    }
    if suffix in extension_rules:
        modality, format_name = extension_rules[suffix]
        return modality, format_name, "extension"
    return "unknown", "unknown", "none"


def _provenance(
    root: Path,
    tree_path: Path,
    metadata_path: Path,
) -> tuple[dict[str, Any], bytes, str]:
    metadata = _strict_json_object(
        _read_bounded_regular(metadata_path, MAX_METADATA_BYTES)
    )
    tree_payload = _read_bounded_regular(tree_path, MAX_TREE_BYTES)
    tree_digest = hashlib.sha256(tree_payload).hexdigest()
    source = metadata.get("source")
    inventory = metadata.get("inventory")
    tree = metadata.get("tree")
    if (
        metadata.get("schema_version") != 1
        or metadata.get("status") != "initialized"
        or not isinstance(source, dict)
        or source.get("present") is not True
        or source.get("read_only_expected") is not True
        or source.get("mount_read_only") is not True
        or source.get("writable_override_used") is not False
        or not isinstance(source.get("path"), str)
        or os.path.realpath(source["path"]) != os.path.realpath(root)
        or not isinstance(inventory, dict)
        or inventory.get("algorithm") != "sha256"
        or isinstance(inventory.get("file_count"), bool)
        or not isinstance(inventory.get("file_count"), int)
        or inventory["file_count"] < 0
        or inventory["file_count"] > MAX_FILES
        or isinstance(inventory.get("total_bytes"), bool)
        or not isinstance(inventory.get("total_bytes"), int)
        or inventory["total_bytes"] < 0
        or not isinstance(tree, dict)
        or tree.get("format") != TREE_FORMAT
        or tree.get("path") != str(tree_path)
        or tree.get("digest") != tree_digest
    ):
        raise EvidenceIndexError("provenance_binding_invalid")
    return metadata, tree_payload, tree_digest


def build_evidence_index(
    root: Path,
    tree_path: Path,
    metadata_path: Path,
    *,
    max_emitted_records: int = MAX_EMITTED_RECORDS,
    max_emitted_record_json_bytes: int = MAX_EMITTED_RECORD_JSON_BYTES,
) -> dict[str, Any]:
    """Build one bounded evidence graph without executing evidence."""

    if max_emitted_records < 0 or max_emitted_record_json_bytes < 0:
        raise ValueError("output bounds must be non-negative")
    metadata, tree_payload, tree_digest = _provenance(
        root,
        tree_path,
        metadata_path,
    )
    source_path = str(metadata["source"]["path"]).rstrip("/")
    expected_file_count = int(metadata["inventory"]["file_count"])
    expected_total_bytes = int(metadata["inventory"]["total_bytes"])
    root_id = "FE-root-" + tree_digest[:24]
    root_descriptor = _open_root(root)
    records: list[dict[str, Any]] = []
    emitted_record_bytes = 0
    indexed_files = 0
    indexed_bytes = 0
    modality_counts: Counter[str] = Counter()
    format_counts: Counter[str] = Counter()
    chain = hashlib.sha256()
    try:
        for raw_path, expected_mode, source_sha256 in _tree_files(
            tree_payload
        ):
            indexed_files += 1
            if indexed_files > MAX_FILES:
                raise EvidenceIndexError("file_count_limit_exceeded")
            file_stat, prefix = _probe_file(
                root_descriptor,
                raw_path,
                expected_mode=expected_mode,
                expected_sha256=source_sha256,
            )
            indexed_bytes += file_stat.st_size
            display_path = os.fsdecode(raw_path)
            modality, format_name, classification_basis = _classify(
                display_path,
                prefix,
            )
            modality_counts[modality] += 1
            format_counts[format_name] += 1
            evidence_id = (
                "FE-"
                + hashlib.sha256(
                    b"\x00".join(
                        (
                            tree_digest.encode("ascii"),
                            raw_path,
                            source_sha256.encode("ascii"),
                            str(file_stat.st_size).encode("ascii"),
                        )
                    )
                ).hexdigest()[:24]
            )
            record: dict[str, Any] = {
                "classification": {
                    "basis": classification_basis,
                    "format": format_name,
                    "modality": modality,
                },
                "evidence_id": evidence_id,
                "parent_evidence_id": root_id,
                "pointer": {
                    "path": f"{source_path}/{display_path}",
                    "sha256": source_sha256,
                    "size_bytes": file_stat.st_size,
                },
                "prefix_probe": {
                    "bytes": len(prefix),
                    "sha256": hashlib.sha256(prefix).hexdigest(),
                },
                "timestamp": {
                    "kind": "filesystem_mtime",
                    "timezone_status": "unknown",
                    "value_ns": file_stat.st_mtime_ns,
                },
            }
            encoded_record = _canonical_json(record)
            chain.update(encoded_record)
            chain.update(b"\n")
            if (
                len(records) < max_emitted_records
                and emitted_record_bytes + len(encoded_record)
                <= max_emitted_record_json_bytes
            ):
                records.append(record)
                emitted_record_bytes += len(encoded_record)
    finally:
        os.close(root_descriptor)
    if (
        indexed_files != expected_file_count
        or indexed_bytes != expected_total_bytes
    ):
        raise EvidenceIndexError("provenance_inventory_count_mismatch")
    emitted = len(records)
    coverage_ppm = (
        1_000_000
        if indexed_files == 0
        else emitted * 1_000_000 // indexed_files
    )
    return {
        "contract": {
            "id": CONTRACT_ID,
            "version": CONTRACT_VERSION,
        },
        "coverage": {
            "hash_bound_files": indexed_files,
            "indexed_bytes": indexed_bytes,
            "indexed_files": indexed_files,
            "pointer_coverage_ppm": coverage_ppm,
            "pointer_records_emitted": emitted,
            "pointer_records_total": indexed_files,
            "prefix_probed_files": indexed_files,
            "projection": (
                "complete" if emitted == indexed_files else "partial"
            ),
            "records_truncated": emitted != indexed_files,
        },
        "graph": {
            "emitted_edges": emitted,
            "root_evidence_id": root_id,
            "total_edges": indexed_files,
        },
        "index_sha256": chain.hexdigest(),
        "records": records,
        "schema_version": SCHEMA_VERSION,
        "source": {
            "mount_read_only": True,
            "path": source_path,
            "tree_format": TREE_FORMAT,
            "tree_sha256": tree_digest,
        },
        "type_summary": {
            "formats": dict(sorted(format_counts.items())),
            "modalities": dict(sorted(modality_counts.items())),
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build a bounded typed evidence index from entrypoint provenance."
        )
    )
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--tree", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = build_evidence_index(
            arguments.root,
            arguments.tree,
            arguments.metadata,
        )
        encoded = _canonical_json(result)
    except (EvidenceIndexError, OSError, ValueError) as error:
        reason = (
            str(error)
            if isinstance(error, EvidenceIndexError)
            else "unexpected_local_error"
        )
        print(f"forensic-evidence-index: {reason}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(encoded + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
