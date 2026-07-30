"""Engine-side evaluator for the sandbox forensic evidence index.

The image producer is intentionally independent.  This module treats its
stdout as untrusted, validates every emitted pointer against the engine's
immutable source inventory, and returns a bounded commitment-only result.
It does not parse evidence content and cannot satisfy challenge proof.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping

from ctf_os.store.atomic import StrictJSONError, strict_json_loads


FORENSIC_INDEX_PROTOCOL = "forensic_evidence_index_v1"
FORENSIC_INDEX_CONTRACT_ID = "ctfos.forensic.evidence_index"
FORENSIC_INDEX_CONTRACT_VERSION = 1
FORENSIC_INDEX_SCHEMA_VERSION = 1
FORENSIC_INDEX_MAX_BYTES = 8 * 1024 * 1024
FORENSIC_INDEX_MAX_FILES = 20_000
FORENSIC_INDEX_MAX_PREFIX_BYTES = 4096

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_EVIDENCE_ID = re.compile(r"^FE-(?:root-)?[0-9a-f]{24}$")
_ROOT_KEYS = frozenset(
    {
        "contract",
        "coverage",
        "graph",
        "index_sha256",
        "records",
        "schema_version",
        "source",
        "type_summary",
    }
)
_RECORD_KEYS = frozenset(
    {
        "classification",
        "evidence_id",
        "parent_evidence_id",
        "pointer",
        "prefix_probe",
        "timestamp",
    }
)
_FORMAT_MODALITY = {
    "7zip": "archive",
    "avi": "video",
    "bmp": "image",
    "bzip2": "archive",
    "database": "database",
    "disk-image": "disk",
    "ewf-e01": "disk",
    "flac": "audio",
    "gif": "image",
    "gzip": "archive",
    "hwp": "document",
    "iso-base-media": "video",
    "jpeg": "image",
    "json-lines": "log",
    "lime-memory": "memory",
    "matroska": "video",
    "mbox": "mail",
    "memory-dump": "memory",
    "mp3": "audio",
    "mp4": "video",
    "office-open-xml": "document",
    "ole-document": "document",
    "ole-spreadsheet": "document",
    "outlook-ost": "mail",
    "outlook-pst": "mail",
    "packet-capture": "network",
    "pcap": "network",
    "pcap-nanosecond": "network",
    "pcapng": "network",
    "pdf": "document",
    "png": "image",
    "qcow2": "disk",
    "quicktime": "video",
    "rar": "archive",
    "raw-disk-image": "disk",
    "raw-memory-or-disk": "memory",
    "rfc822-message": "mail",
    "rtf": "document",
    "sqlite": "database",
    "sqlite3": "database",
    "syslog": "log",
    "tar": "archive",
    "text-log": "log",
    "tiff": "image",
    "unknown": "unknown",
    "vhd": "disk",
    "vhdx": "disk",
    "vmdk": "disk",
    "wav": "audio",
    "windows-evtx": "event_log",
    "windows-registry-hive": "registry",
    "xz": "archive",
    "zip": "archive",
}


class ForensicIndexVerdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"


@dataclass(frozen=True, slots=True)
class ForensicSourceExpectation:
    """One engine-owned source pointer and its independently read prefix."""

    path: str
    sha256: str
    size_bytes: int
    prefix_sha256: str
    prefix_size_bytes: int

    def __post_init__(self) -> None:
        if (
            type(self.path) is not str
            or not self.path
            or self.path.startswith("/")
            or "\\" in self.path
            or any(part in {"", ".", ".."} for part in self.path.split("/"))
            or _SHA256.fullmatch(self.sha256) is None
            or _SHA256.fullmatch(self.prefix_sha256) is None
            or type(self.size_bytes) is not int
            or self.size_bytes < 0
            or type(self.prefix_size_bytes) is not int
            or self.prefix_size_bytes
            != min(self.size_bytes, FORENSIC_INDEX_MAX_PREFIX_BYTES)
        ):
            raise ValueError("invalid forensic source expectation")

    def commitment(self) -> dict[str, object]:
        return {
            "path": self.path,
            "prefix_sha256": self.prefix_sha256,
            "prefix_size_bytes": self.prefix_size_bytes,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True, slots=True)
class ForensicIndexEvaluation:
    verdict: ForensicIndexVerdict
    reason_code: str
    source_inventory_sha256: str
    tree_sha256: str | None
    index_sha256: str | None
    indexed_files: int
    indexed_bytes: int
    pointer_coverage_ppm: int
    modality_counts: tuple[tuple[str, int], ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "claims": {
                "candidate_ready": False,
                "challenge_proof_satisfied": False,
                "evidence_index_verified": (
                    self.verdict is ForensicIndexVerdict.CONFIRMED
                ),
                "impact_proven": False,
            },
            "index_sha256": self.index_sha256,
            "indexed_bytes": self.indexed_bytes,
            "indexed_files": self.indexed_files,
            "modality_counts": dict(self.modality_counts),
            "pointer_coverage_ppm": self.pointer_coverage_ppm,
            "protocol": FORENSIC_INDEX_PROTOCOL,
            "reason_code": self.reason_code,
            "schema_version": 1,
            "source_inventory_sha256": self.source_inventory_sha256,
            "tree_sha256": self.tree_sha256,
            "verdict": self.verdict.value,
        }

    @property
    def sha256(self) -> str:
        return hashlib.sha256(_canonical_json(self.to_dict())).hexdigest()


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _inventory_sha256(
    sources: tuple[ForensicSourceExpectation, ...],
) -> str:
    return hashlib.sha256(
        _canonical_json([source.commitment() for source in sources])
    ).hexdigest()


def _rejected(
    reason_code: str,
    inventory_sha256: str,
) -> ForensicIndexEvaluation:
    return ForensicIndexEvaluation(
        verdict=ForensicIndexVerdict.REJECTED,
        reason_code=reason_code,
        source_inventory_sha256=inventory_sha256,
        tree_sha256=None,
        index_sha256=None,
        indexed_files=0,
        indexed_bytes=0,
        pointer_coverage_ppm=0,
        modality_counts=(),
    )


def _exact_mapping(
    value: object,
    keys: frozenset[str],
) -> Mapping[str, object] | None:
    return value if type(value) is dict and set(value) == keys else None


def _valid_count(value: object, maximum: int = 2**63 - 1) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _normalize_sources(
    sources: Iterable[ForensicSourceExpectation],
) -> tuple[ForensicSourceExpectation, ...]:
    try:
        bounded = tuple(sources)
    except (TypeError, ValueError) as error:
        raise ValueError("forensic source expectations are not iterable") from error
    if (
        len(bounded) > FORENSIC_INDEX_MAX_FILES
        or any(type(item) is not ForensicSourceExpectation for item in bounded)
    ):
        raise ValueError("invalid forensic source expectations")
    ordered = tuple(sorted(bounded, key=lambda item: item.path.encode("utf-8")))
    if len({item.path for item in ordered}) != len(ordered):
        raise ValueError("duplicate forensic source expectation")
    return ordered


def evaluate_forensic_evidence_index(
    stdout_payload: bytes,
    expected_sources: Iterable[ForensicSourceExpectation],
    *,
    expected_source_root: str = "/challenge",
) -> ForensicIndexEvaluation:
    """Validate one complete producer document against immutable sources."""

    sources = _normalize_sources(expected_sources)
    inventory_sha256 = _inventory_sha256(sources)
    if (
        type(stdout_payload) is not bytes
        or not stdout_payload
        or len(stdout_payload) > FORENSIC_INDEX_MAX_BYTES
    ):
        return _rejected("artifact_size_invalid", inventory_sha256)
    try:
        document = strict_json_loads(
            stdout_payload,
            max_bytes=FORENSIC_INDEX_MAX_BYTES,
            max_depth=12,
        )
    except (StrictJSONError, UnicodeError, ValueError, RecursionError):
        return _rejected("invalid_json", inventory_sha256)
    try:
        canonical = _canonical_json(document)
    except (TypeError, ValueError, UnicodeError):
        return _rejected("invalid_json", inventory_sha256)
    if canonical != stdout_payload:
        return _rejected("noncanonical_json", inventory_sha256)
    root = _exact_mapping(document, _ROOT_KEYS)
    if root is None:
        return _rejected("schema_invalid", inventory_sha256)

    contract = _exact_mapping(
        root["contract"], frozenset({"id", "version"})
    )
    source = _exact_mapping(
        root["source"],
        frozenset(
            {"mount_read_only", "path", "tree_format", "tree_sha256"}
        ),
    )
    coverage = _exact_mapping(
        root["coverage"],
        frozenset(
            {
                "hash_bound_files",
                "indexed_bytes",
                "indexed_files",
                "pointer_coverage_ppm",
                "pointer_records_emitted",
                "pointer_records_total",
                "prefix_probed_files",
                "projection",
                "records_truncated",
            }
        ),
    )
    graph = _exact_mapping(
        root["graph"],
        frozenset({"emitted_edges", "root_evidence_id", "total_edges"}),
    )
    type_summary = _exact_mapping(
        root["type_summary"], frozenset({"formats", "modalities"})
    )
    if (
        contract is None
        or contract
        != {
            "id": FORENSIC_INDEX_CONTRACT_ID,
            "version": FORENSIC_INDEX_CONTRACT_VERSION,
        }
        or root["schema_version"] != FORENSIC_INDEX_SCHEMA_VERSION
        or source is None
        or source["mount_read_only"] is not True
        or source["path"] != expected_source_root.rstrip("/")
        or source["tree_format"] != "ctf-tree-v1-nul"
        or type(source["tree_sha256"]) is not str
        or _SHA256.fullmatch(source["tree_sha256"]) is None
        or coverage is None
        or graph is None
        or type_summary is None
        or type(root["records"]) is not list
        or type(root["index_sha256"]) is not str
        or _SHA256.fullmatch(root["index_sha256"]) is None
    ):
        return _rejected("schema_invalid", inventory_sha256)

    expected_files = len(sources)
    expected_bytes = sum(item.size_bytes for item in sources)
    expected_coverage = 1_000_000
    if (
        coverage
        != {
            "hash_bound_files": expected_files,
            "indexed_bytes": expected_bytes,
            "indexed_files": expected_files,
            "pointer_coverage_ppm": expected_coverage,
            "pointer_records_emitted": expected_files,
            "pointer_records_total": expected_files,
            "prefix_probed_files": expected_files,
            "projection": "complete",
            "records_truncated": False,
        }
        or graph["emitted_edges"] != expected_files
        or graph["total_edges"] != expected_files
        or len(root["records"]) != expected_files
    ):
        return _rejected("coverage_incomplete", inventory_sha256)

    tree_sha256 = str(source["tree_sha256"])
    root_evidence_id = "FE-root-" + tree_sha256[:24]
    if (
        graph["root_evidence_id"] != root_evidence_id
        or _SAFE_EVIDENCE_ID.fullmatch(root_evidence_id) is None
    ):
        return _rejected("graph_binding_invalid", inventory_sha256)

    modality_counts: Counter[str] = Counter()
    format_counts: Counter[str] = Counter()
    chain = hashlib.sha256()
    for expected, value in zip(sources, root["records"], strict=True):
        record = _exact_mapping(value, _RECORD_KEYS)
        if record is None:
            return _rejected("record_schema_invalid", inventory_sha256)
        pointer = _exact_mapping(
            record["pointer"],
            frozenset({"path", "sha256", "size_bytes"}),
        )
        prefix = _exact_mapping(
            record["prefix_probe"], frozenset({"bytes", "sha256"})
        )
        classification = _exact_mapping(
            record["classification"],
            frozenset({"basis", "format", "modality"}),
        )
        timestamp = _exact_mapping(
            record["timestamp"],
            frozenset({"kind", "timezone_status", "value_ns"}),
        )
        expected_pointer_path = (
            expected_source_root.rstrip("/") + "/" + expected.path
        )
        if (
            pointer is None
            or pointer
            != {
                "path": expected_pointer_path,
                "sha256": expected.sha256,
                "size_bytes": expected.size_bytes,
            }
            or prefix is None
            or prefix
            != {
                "bytes": expected.prefix_size_bytes,
                "sha256": expected.prefix_sha256,
            }
            or classification is None
            or type(classification["format"]) is not str
            or type(classification["modality"]) is not str
            or classification["format"] not in _FORMAT_MODALITY
            or _FORMAT_MODALITY[classification["format"]]
            != classification["modality"]
            or classification["basis"] not in {"extension", "magic", "none"}
            or timestamp is None
            or timestamp["kind"] != "filesystem_mtime"
            or timestamp["timezone_status"] != "unknown"
            or not _valid_count(timestamp["value_ns"])
            or record["parent_evidence_id"] != root_evidence_id
        ):
            return _rejected("record_binding_invalid", inventory_sha256)
        evidence_id = (
            "FE-"
            + hashlib.sha256(
                b"\x00".join(
                    (
                        tree_sha256.encode("ascii"),
                        expected.path.encode("utf-8"),
                        expected.sha256.encode("ascii"),
                        str(expected.size_bytes).encode("ascii"),
                    )
                )
            ).hexdigest()[:24]
        )
        if record["evidence_id"] != evidence_id:
            return _rejected("graph_binding_invalid", inventory_sha256)
        encoded_record = _canonical_json(record)[:-1]
        chain.update(encoded_record)
        chain.update(b"\n")
        modality_counts[str(classification["modality"])] += 1
        format_counts[str(classification["format"])] += 1

    expected_summary = {
        "formats": dict(sorted(format_counts.items())),
        "modalities": dict(sorted(modality_counts.items())),
    }
    if (
        type_summary != expected_summary
        or root["index_sha256"] != chain.hexdigest()
    ):
        return _rejected("index_commitment_invalid", inventory_sha256)
    return ForensicIndexEvaluation(
        verdict=ForensicIndexVerdict.CONFIRMED,
        reason_code="complete_hash_bound_index",
        source_inventory_sha256=inventory_sha256,
        tree_sha256=tree_sha256,
        index_sha256=str(root["index_sha256"]),
        indexed_files=expected_files,
        indexed_bytes=expected_bytes,
        pointer_coverage_ppm=expected_coverage,
        modality_counts=tuple(sorted(modality_counts.items())),
    )


__all__ = [
    "FORENSIC_INDEX_MAX_BYTES",
    "FORENSIC_INDEX_PROTOCOL",
    "ForensicIndexEvaluation",
    "ForensicIndexVerdict",
    "ForensicSourceExpectation",
    "evaluate_forensic_evidence_index",
]
