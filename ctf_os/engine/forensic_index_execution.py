"""Transport-bound Forensic evidence-index execution contract.

The sandbox producer and :mod:`ctf_os.engine.forensic_index` parser are only
half of the gate.  A model-authored or partially captured stdout document must
not become an executed fact merely because its JSON is semantically plausible.
This module binds that document to one exact engine-issued adapter-seed
request, terminal run, execution receipt, immutable stdout artifact, freshly
re-inventoried challenge input, and independently re-read file prefixes.

The result is deliberately raw-free.  It can authorize one executed
evidence-index fact and one progress marker, but never a candidate, impact,
challenge proof, status transition, or automatic submission.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from itertools import islice

from ctf_os.engine.forensic_index import (
    FORENSIC_INDEX_MAX_BYTES,
    FORENSIC_INDEX_MAX_FILES,
    FORENSIC_INDEX_MAX_PREFIX_BYTES,
    ForensicIndexEvaluation,
    ForensicIndexVerdict,
    ForensicSourceExpectation,
    evaluate_forensic_evidence_index,
)
from ctf_os.models import (
    MAX_RECEIPT_EXCERPT_JSON_CHARS,
    MAX_RECEIPT_SAMPLE_BYTES,
    MAX_RECEIPT_STREAM_EVIDENCE_BYTES,
    ArtifactReference,
    ChallengeIdentity,
    ExecutionReceipt,
    ReceiptOutcome,
    RunOrigin,
    RunReference,
    RunStatus,
    SourceFile,
)
from ctf_os.sandbox.files import (
    DEFAULT_STREAM_CAPTURE_MAX_BYTES,
    SafeFileError,
    normalize_locator,
)
from ctf_os.schema import RUN_ENVELOPE_SCHEMA_VERSION
from ctf_os.store.atomic import (
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)


FORENSIC_INDEX_EXECUTION_PROTOCOL = (
    "forensic_evidence_index_execution_v1"
)
FORENSIC_INDEX_EXECUTION_SCHEMA_VERSION = 1
FORENSIC_INDEX_REQUEST_MAX_BYTES = 1024 * 1024
FORENSIC_INDEX_MAX_SOURCE_BYTES = 128 * 1024**3
FORENSIC_INDEX_EXPECTED_ARGV = (
    "/usr/bin/python3",
    "/opt/ctf-templates/forensic/evidence_index.py",
    "--root",
    "/challenge",
    "--tree",
    "/work/.ctf/challenge.tree",
    "--metadata",
    "/work/.ctf/challenge.json",
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,511}$")
_REQUEST_KEYS = frozenset(
    {
        "adapter_name",
        "adapter_seed",
        "adapter_seed_contract_version",
        "adapter_seed_order",
        "adapter_spec_id",
        "adapter_spec_sha256",
        "adapter_spec_template_id",
        "argv",
        "base_revision",
        "category",
        "challenge_id",
        "configuration_epoch",
        "contest_id",
        "created_at",
        "experiment_id",
        "image",
        "image_digest",
        "image_reference",
        "kind",
        "lease_id",
        "network_target",
        "network_target_generation",
        "network_target_id",
        "partial_oracle",
        "requires_explicit_execution",
        "resource_class",
        "resource_request",
        "run_id",
        "schema_version",
        "source_binding",
        "source_snapshot",
    }
)
_SOURCE_BINDING_KEYS = frozenset(
    {
        "adapter_plan_sha256",
        "manifest_sha256",
        "path",
        "schema_version",
        "sha256",
        "size_bytes",
    }
)
_RESOURCE_KEYS = frozenset(
    {"cpu", "gpu", "kvm", "memory_mib", "network"}
)
_STREAM_EVIDENCE_KEYS = frozenset(
    {
        "artifact_id",
        "binary_sample_omitted",
        "capture_complete",
        "capture_error_present",
        "coverage",
        "drained_bytes",
        "head",
        "limit_bytes",
        "omitted_stored_bytes",
        "path",
        "redaction_count",
        "sample_policy",
        "schema_version",
        "sha256",
        "stored_bytes",
        "stream",
        "stream_error_present",
        "tail",
        "transport_summary_truncated",
        "truncated",
        "truncation_known",
    }
)
_ALLOWED_RUN_ORIGINS = frozenset(
    {RunOrigin.MANAGED_TOOL, RunOrigin.OPERATOR_TOOL}
)
_NON_AUTHORITIES = {
    "automatic_submission_authorized": False,
    "candidate_authorized": False,
    "challenge_proof_satisfied": False,
    "impact_proven": False,
}


class ForensicIndexExecutionVerdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"


@dataclass(frozen=True, slots=True)
class ForensicIndexExecutionEnvelope:
    """Canonical, raw-free commitment to one sandbox transport."""

    category: str
    contest_id: str
    challenge_id: str
    configuration_epoch: int
    experiment_id: str
    run_id: str
    run_origin: str
    request_path: str
    request_sha256: str
    request_size_bytes: int
    result_path: str
    validation_path: str
    receipt_id: str
    image_name: str
    image_digest: str
    source_manifest_sha256: str
    source_inventory_sha256: str
    source_file_count: int
    source_total_bytes: int
    prefix_coverage_ppm: int
    stdout_artifact_id: str
    stdout_artifact_path: str
    stdout_artifact_sha256: str
    stdout_artifact_size_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "category": self.category,
            "challenge_id": self.challenge_id,
            "configuration_epoch": self.configuration_epoch,
            "contest_id": self.contest_id,
            "experiment_id": self.experiment_id,
            "image": {
                "digest": self.image_digest,
                "name": self.image_name,
            },
            "prefix_coverage_ppm": self.prefix_coverage_ppm,
            "protocol": FORENSIC_INDEX_EXECUTION_PROTOCOL,
            "receipt": {
                "exit_code": 0,
                "id": self.receipt_id,
                "outcome": ReceiptOutcome.SUCCEEDED.value,
            },
            "request": {
                "path": self.request_path,
                "sha256": self.request_sha256,
                "size_bytes": self.request_size_bytes,
            },
            "run": {
                "id": self.run_id,
                "origin": self.run_origin,
                "result_path": self.result_path,
                "status": RunStatus.COMPLETED.value,
                "validation_path": self.validation_path,
            },
            "schema_version": FORENSIC_INDEX_EXECUTION_SCHEMA_VERSION,
            "source": {
                "file_count": self.source_file_count,
                "inventory_sha256": self.source_inventory_sha256,
                "manifest_sha256": self.source_manifest_sha256,
                "total_bytes": self.source_total_bytes,
            },
            "stdout_artifact": {
                "id": self.stdout_artifact_id,
                "path": self.stdout_artifact_path,
                "sha256": self.stdout_artifact_sha256,
                "size_bytes": self.stdout_artifact_size_bytes,
                "source_run_id": self.run_id,
            },
            "transport": {
                "capture_complete": True,
                "coverage": "complete_stream",
                "network": "none",
                "truncated": False,
                "truncation_known": True,
            },
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.to_dict())

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class ForensicIndexExecutionEvaluation:
    """Raw-free execution gate result and its deliberately narrow authority."""

    verdict: ForensicIndexExecutionVerdict
    reason_code: str
    envelope: ForensicIndexExecutionEnvelope | None
    semantic_evaluation: ForensicIndexEvaluation | None

    @property
    def confirmed(self) -> bool:
        return (
            self.verdict is ForensicIndexExecutionVerdict.CONFIRMED
            and self.envelope is not None
            and self.semantic_evaluation is not None
            and self.semantic_evaluation.verdict
            is ForensicIndexVerdict.CONFIRMED
            and self.semantic_evaluation.pointer_coverage_ppm == 1_000_000
            and self.envelope.prefix_coverage_ppm == 1_000_000
            and self.semantic_evaluation.source_inventory_sha256
            == self.envelope.source_inventory_sha256
            and self.semantic_evaluation.indexed_files
            == self.envelope.source_file_count
            and self.semantic_evaluation.indexed_bytes
            == self.envelope.source_total_bytes
        )

    def to_dict(self) -> dict[str, object]:
        authorities = {
            **_NON_AUTHORITIES,
            "executed_evidence_index_fact_authorized": self.confirmed,
            "progress_marker_authorized": self.confirmed,
        }
        return {
            "authorities": authorities,
            "confirmed": self.confirmed,
            "envelope": (
                self.envelope.to_dict()
                if self.envelope is not None
                else None
            ),
            "envelope_sha256": (
                self.envelope.sha256
                if self.envelope is not None
                else None
            ),
            "protocol": FORENSIC_INDEX_EXECUTION_PROTOCOL,
            "reason_code": self.reason_code,
            "schema_version": FORENSIC_INDEX_EXECUTION_SCHEMA_VERSION,
            "semantic_evaluation": (
                self.semantic_evaluation.to_dict()
                if self.semantic_evaluation is not None
                else None
            ),
            "semantic_evaluation_sha256": (
                self.semantic_evaluation.sha256
                if self.semantic_evaluation is not None
                else None
            ),
            "verdict": self.verdict.value,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.to_dict())

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()

    def reduction_projection(self) -> dict[str, object]:
        """Return the only state effects this result may authorize.

        The caller still allocates canonical Fact/ProgressMarker identifiers
        inside ``StateStore.update``.  Returning explicit ``None`` values for
        stronger effects makes accidental authority widening visible in tests
        and review.
        """

        if not self.confirmed:
            return {
                "automatic_submission": False,
                "candidate": None,
                "executed_fact": None,
                "impact": None,
                "progress": None,
                "proof": None,
            }
        assert self.envelope is not None
        assert self.semantic_evaluation is not None
        modalities = dict(self.semantic_evaluation.modality_counts)
        statement = (
            "Engine-verified Forensic evidence index bound "
            f"{self.semantic_evaluation.indexed_files} files and "
            f"{self.semantic_evaluation.indexed_bytes} bytes at "
            "1000000 ppm pointer coverage; "
            f"index_sha256={self.semantic_evaluation.index_sha256}; "
            "modalities="
            + json.dumps(
                modalities,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "."
        )
        binding = {
            "evaluation_sha256": self.sha256,
            "receipt_id": self.envelope.receipt_id,
            "source_inventory_sha256": (
                self.envelope.source_inventory_sha256
            ),
            "source_manifest_sha256": (
                self.envelope.source_manifest_sha256
            ),
        }
        return {
            "automatic_submission": False,
            "candidate": None,
            "executed_fact": {
                "artifact_id": self.envelope.stdout_artifact_id,
                "extra": {
                    "forensic_evidence_index": binding,
                },
                "locator": self.envelope.stdout_artifact_path,
                "provenance": "executed",
                "source_run_id": self.envelope.run_id,
                "statement": statement[:2048],
            },
            "impact": None,
            "progress": {
                "artifact_ids": [self.envelope.stdout_artifact_id],
                "extra": {
                    "forensic_evidence_index": binding,
                },
                "run_id": self.envelope.run_id,
                "statement": (
                    "Complete hash-bound Forensic evidence index verified "
                    "against the current immutable source inventory"
                ),
            },
            "proof": None,
        }


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


def _rejected(
    reason_code: str,
    *,
    envelope: ForensicIndexExecutionEnvelope | None = None,
    semantic: ForensicIndexEvaluation | None = None,
) -> ForensicIndexExecutionEvaluation:
    return ForensicIndexExecutionEvaluation(
        verdict=ForensicIndexExecutionVerdict.REJECTED,
        reason_code=reason_code,
        envelope=envelope,
        semantic_evaluation=semantic,
    )


def _valid_identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _valid_sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _valid_size(value: object, maximum: int) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _bounded_text(value: object, maximum_bytes: int = 512) -> bool:
    if type(value) is not str or not value:
        return False
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        return False
    return (
        len(encoded) <= maximum_bytes
        and all(
            character.isprintable()
            for character in value
        )
    )


def _safe_locator(value: object) -> str | None:
    if type(value) is not str:
        return None
    try:
        return normalize_locator(value)
    except (SafeFileError, UnicodeError):
        return None


def _source_records(
    values: Iterable[SourceFile],
) -> tuple[tuple[str, str, int], ...] | None:
    try:
        bounded = tuple(islice(iter(values), FORENSIC_INDEX_MAX_FILES + 1))
    except Exception:
        return None
    if (
        len(bounded) > FORENSIC_INDEX_MAX_FILES
        or any(type(item) is not SourceFile for item in bounded)
    ):
        return None
    records: list[tuple[str, str, int]] = []
    total = 0
    for item in bounded:
        path = _safe_locator(item.path)
        if (
            path is None
            or path != item.path
            or item.kind != "file"
            or not _valid_sha256(item.sha256)
            or not _valid_size(item.size, FORENSIC_INDEX_MAX_SOURCE_BYTES)
        ):
            return None
        total += item.size
        if total > FORENSIC_INDEX_MAX_SOURCE_BYTES:
            return None
        records.append((path, item.sha256, item.size))
    records.sort(key=lambda item: item[0].encode("utf-8"))
    if len({item[0] for item in records}) != len(records):
        return None
    return tuple(records)


def _source_expectations(
    expected_sources: Iterable[SourceFile],
    current_sources: Iterable[SourceFile],
    prefix_payloads: Mapping[str, bytes],
) -> tuple[ForensicSourceExpectation, ...] | None:
    expected = _source_records(expected_sources)
    current = _source_records(current_sources)
    if expected is None or current is None or expected != current:
        return None
    if type(prefix_payloads) is not dict or set(prefix_payloads) != {
        item[0] for item in current
    }:
        return None
    result: list[ForensicSourceExpectation] = []
    for path, source_sha256, source_size in current:
        prefix = prefix_payloads.get(path)
        expected_prefix_size = min(
            source_size,
            FORENSIC_INDEX_MAX_PREFIX_BYTES,
        )
        if type(prefix) is not bytes or len(prefix) != expected_prefix_size:
            return None
        prefix_sha256 = hashlib.sha256(prefix).hexdigest()
        if (
            source_size <= FORENSIC_INDEX_MAX_PREFIX_BYTES
            and prefix_sha256 != source_sha256
        ):
            return None
        try:
            result.append(
                ForensicSourceExpectation(
                    path=path,
                    sha256=source_sha256,
                    size_bytes=source_size,
                    prefix_sha256=prefix_sha256,
                    prefix_size_bytes=expected_prefix_size,
                )
            )
        except ValueError:
            return None
    return tuple(result)


def _inventory_sha256(
    sources: tuple[ForensicSourceExpectation, ...],
) -> str:
    return hashlib.sha256(
        _canonical_json([item.commitment() for item in sources])
    ).hexdigest()


def _request_document(
    payload: bytes,
    issued: Mapping[str, object],
) -> Mapping[str, object] | None:
    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > FORENSIC_INDEX_REQUEST_MAX_BYTES
        or type(issued) is not dict
    ):
        return None
    try:
        parsed = strict_json_loads(
            payload,
            max_bytes=FORENSIC_INDEX_REQUEST_MAX_BYTES,
            max_depth=16,
        )
        canonical = canonical_json_bytes(parsed)
    except (
        StrictJSONError,
        TypeError,
        UnicodeError,
        ValueError,
        RecursionError,
    ):
        return None
    if (
        type(parsed) is not dict
        or set(parsed) != _REQUEST_KEYS
        or parsed != issued
        or payload != canonical
    ):
        return None
    return parsed


def _request_binding_valid(
    request: Mapping[str, object],
    *,
    identity: ChallengeIdentity,
    configuration_epoch: int,
    expected_image_name: str,
    expected_image_digest: str,
    expected_source_manifest_sha256: str,
    sources: tuple[ForensicSourceExpectation, ...],
    run: RunReference,
    receipt: ExecutionReceipt,
) -> tuple[bool, str]:
    resources = request.get("resource_request")
    source = request.get("source_binding")
    if (
        type(resources) is not dict
        or set(resources) != _RESOURCE_KEYS
        or any(
            type(resources[key]) is not int or resources[key] < 0
            for key in _RESOURCE_KEYS
        )
        or resources["cpu"] < 1
        or resources["memory_mib"] < 256
        or resources["network"] != 0
        or request.get("network_target") is not None
        or request.get("network_target_id") is not None
        or request.get("network_target_generation") is not None
    ):
        return False, "network_or_resource_binding_mismatch"
    if (
        request.get("image_digest") != expected_image_digest
        or request.get("image_reference") != expected_image_digest
        or request.get("image") != expected_image_name
    ):
        return False, "image_digest_mismatch"
    if (
        request.get("schema_version") != RUN_ENVELOPE_SCHEMA_VERSION
        or request.get("contest_id") != identity.contest_id
        or request.get("category") != identity.category
        or request.get("challenge_id") != identity.challenge_id
        or request.get("configuration_epoch") != configuration_epoch
        or request.get("run_id") != run.id
        or request.get("experiment_id") != receipt.experiment_id
        or request.get("base_revision") != run.base_revision
        or request.get("kind") != "tool"
        or request.get("argv") != list(FORENSIC_INDEX_EXPECTED_ARGV)
        or request.get("resource_class") != "light"
        or not _valid_identifier(request.get("lease_id"))
        or type(request.get("created_at")) is not str
        or not request["created_at"]
        or len(request["created_at"].encode("utf-8")) > 128
    ):
        return False, "request_run_binding_mismatch"
    if (
        request.get("adapter_name") != "forensics"
        or request.get("adapter_seed") is not True
        or request.get("adapter_seed_contract_version") != 1
        or request.get("adapter_seed_order") != 0
        or request.get("adapter_spec_template_id") != "file_inventory"
        or request.get("requires_explicit_execution") is not True
        or request.get("partial_oracle") is not None
        or request.get("source_snapshot") is not None
        or not _valid_sha256(request.get("adapter_spec_sha256"))
        or request.get("adapter_spec_id")
        != "file_inventory@" + str(request.get("adapter_spec_sha256"))
    ):
        return False, "adapter_seed_binding_mismatch"
    if type(source) is not dict or set(source) != _SOURCE_BINDING_KEYS:
        return False, "source_binding_mismatch"
    if (
        source.get("schema_version") != 1
        or source.get("manifest_sha256")
        != expected_source_manifest_sha256
        or not _valid_sha256(source.get("adapter_plan_sha256"))
    ):
        return False, "source_manifest_mismatch"
    by_path = {item.path: item for item in sources}
    primary_path = source.get("path")
    if not sources:
        if (
            primary_path is not None
            or source.get("sha256") is not None
            or source.get("size_bytes") is not None
        ):
            return False, "source_binding_mismatch"
    elif (
        type(primary_path) is not str
        or primary_path not in by_path
        or source.get("sha256") != by_path[primary_path].sha256
        or source.get("size_bytes") != by_path[primary_path].size_bytes
    ):
        return False, "source_binding_mismatch"
    seed_keys = (
        "adapter_name",
        "adapter_seed",
        "adapter_seed_contract_version",
        "adapter_seed_order",
        "adapter_spec_id",
        "adapter_spec_sha256",
        "adapter_spec_template_id",
        "partial_oracle",
        "requires_explicit_execution",
        "source_binding",
        "source_snapshot",
    )
    if any(run.extra.get(key) != request.get(key) for key in seed_keys):
        return False, "run_seed_binding_mismatch"
    return True, ""


def _run_binding_valid(
    run: object,
    receipt: object,
    artifact: object,
    *,
    configuration_epoch: int,
) -> str | None:
    if (
        type(run) is not RunReference
        or type(receipt) is not ExecutionReceipt
        or type(artifact) is not ArtifactReference
    ):
        return "transport_type_invalid"
    if (
        not _valid_identifier(run.id)
        or type(run.extra) is not dict
        or run.status is not RunStatus.COMPLETED
        or run.origin not in _ALLOWED_RUN_ORIGINS
        or run.role != "tool"
        or run.configuration_epoch != configuration_epoch
        or not _valid_size(run.base_revision, 2**63 - 1)
        or _safe_locator(run.request_path) != run.request_path
        or _safe_locator(run.result_path) != run.result_path
        or _safe_locator(run.validation_path) != run.validation_path
        or len(
            {run.request_path, run.result_path, run.validation_path}
        )
        != 3
    ):
        return "run_binding_mismatch"
    if (
        not _valid_identifier(receipt.id)
        or not _valid_identifier(receipt.experiment_id)
        or type(receipt.extra) is not dict
        or receipt.run_id != run.id
        or run.extra.get("experiment_id") != receipt.experiment_id
        or receipt.outcome is not ReceiptOutcome.SUCCEEDED
        or receipt.exit_code != 0
    ):
        return "receipt_binding_mismatch"
    if (
        not _valid_identifier(artifact.id)
        or type(artifact.extra) is not dict
        or artifact.source_run_id != run.id
        or artifact.extra.get("stream") != "stdout"
        or _safe_locator(artifact.path) != artifact.path
        or not _valid_sha256(artifact.sha256)
        or not _valid_size(
            artifact.size,
            min(
                FORENSIC_INDEX_MAX_BYTES,
                DEFAULT_STREAM_CAPTURE_MAX_BYTES,
            ),
        )
        or receipt.stdout_artifact_id != artifact.id
        or receipt.stdout_bytes != artifact.size
    ):
        return "stdout_artifact_binding_mismatch"
    return None


def _stdout_capture_valid(
    receipt: ExecutionReceipt,
    artifact: ArtifactReference,
) -> bool:
    if receipt.extra.get("line_count_basis") != "transport_summary_tail":
        return False
    streams = receipt.extra.get("stream_evidence")
    if type(streams) is not dict or "stdout" not in streams:
        return False
    evidence = streams.get("stdout")
    if type(evidence) is not dict or set(evidence) != _STREAM_EVIDENCE_KEYS:
        return False
    try:
        encoded_evidence = json.dumps(
            evidence,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, UnicodeError, ValueError, RecursionError):
        return False
    if len(encoded_evidence) > MAX_RECEIPT_STREAM_EVIDENCE_BYTES:
        return False

    def sample_bounds(
        value: object,
    ) -> tuple[int, int, bool] | None:
        if type(value) is not dict:
            return None
        encoding = value.get("encoding")
        common = {"byte_end", "byte_start", "encoding"}
        if encoding == "utf-8":
            if (
                set(value) != {*common, "text", "text_truncated"}
                or type(value.get("text")) is not str
                or type(value.get("text_truncated")) is not bool
            ):
                return None
            try:
                encoded_text = json.dumps(
                    value["text"],
                    ensure_ascii=True,
                    separators=(",", ":"),
                )
            except (TypeError, UnicodeError, ValueError):
                return None
            if len(encoded_text) > MAX_RECEIPT_EXCERPT_JSON_CHARS:
                return None
            binary = False
        elif encoding == "binary-omitted":
            if (
                set(value) != {*common, "sample_sha256"}
                or not _valid_sha256(value.get("sample_sha256"))
            ):
                return None
            binary = True
        else:
            return None
        start = value.get("byte_start")
        end = value.get("byte_end")
        if (
            type(start) is not int
            or type(end) is not int
            or not 0 <= start <= end <= artifact.size
            or end - start > MAX_RECEIPT_SAMPLE_BYTES
        ):
            return None
        return start, end, binary

    head = sample_bounds(evidence.get("head"))
    tail_value = evidence.get("tail")
    tail = (
        sample_bounds(tail_value)
        if tail_value is not None
        else None
    )
    omitted = evidence.get("omitted_stored_bytes")
    redactions = evidence.get("redaction_count")
    if (
        head is None
        or head[0] != 0
        or (
            tail is not None
            and (
                tail[1] != artifact.size
                or head[1] > tail[0]
            )
        )
        or type(omitted) is not int
        or omitted
        != artifact.size
        - (head[1] - head[0])
        - (0 if tail is None else tail[1] - tail[0])
        or type(redactions) is not int
        or redactions < 0
        or evidence.get("sample_policy")
        != "immutable_snapshot_head_tail"
        or evidence.get("binary_sample_omitted")
        is not (head[2] or (tail is not None and tail[2]))
    ):
        return False
    return (
        evidence.get("schema_version") == 1
        and evidence.get("stream") == "stdout"
        and evidence.get("artifact_id") == artifact.id
        and evidence.get("path") == artifact.path
        and evidence.get("sha256") == artifact.sha256
        and evidence.get("drained_bytes") == artifact.size
        and evidence.get("stored_bytes") == artifact.size
        and type(evidence.get("limit_bytes")) is int
        and evidence["limit_bytes"] >= artifact.size
        and evidence["limit_bytes"] <= DEFAULT_STREAM_CAPTURE_MAX_BYTES
        and evidence.get("capture_complete") is True
        and evidence.get("truncation_known") is True
        and evidence.get("truncated") is False
        and evidence.get("coverage") == "complete_stream"
        and evidence.get("stream_error_present") is False
        and evidence.get("capture_error_present") is False
        and type(evidence.get("transport_summary_truncated")) is bool
    )


def evaluate_forensic_index_execution(
    *,
    identity: ChallengeIdentity,
    configuration_epoch: int,
    expected_source_manifest_sha256: str,
    current_source_manifest_sha256: str,
    expected_source_inventory: Iterable[SourceFile],
    current_source_inventory: Iterable[SourceFile],
    current_prefix_payloads: Mapping[str, bytes],
    expected_image_name: str,
    expected_image_digest: str,
    issued_request: Mapping[str, object],
    request_payload: bytes,
    run: RunReference,
    receipt: ExecutionReceipt,
    stdout_artifact: ArtifactReference,
    stdout_payload: bytes,
) -> ForensicIndexExecutionEvaluation:
    """Evaluate one exact Forensic evidence-index transport.

    ``expected_*`` values come from the canonical state and frozen runtime
    configuration.  ``current_*`` values must come from a fresh immutable
    inventory and independent prefix reads immediately before the attempted
    state replacement.  ``issued_request`` is the engine-owned in-memory copy
    made before sandbox execution; ``request_payload`` is the separately
    re-read durable request file.
    """

    if (
        type(identity) is not ChallengeIdentity
        or identity.category != "forensics"
        or not _bounded_text(identity.contest_id)
        or not _bounded_text(identity.challenge_id)
    ):
        return _rejected("category_mismatch")
    if (
        type(configuration_epoch) is not int
        or not 0 <= configuration_epoch <= 2**63 - 1
    ):
        return _rejected("configuration_epoch_invalid")
    if (
        not _valid_sha256(expected_source_manifest_sha256)
        or not _valid_sha256(current_source_manifest_sha256)
        or expected_source_manifest_sha256
        != current_source_manifest_sha256
    ):
        return _rejected("source_manifest_mismatch")
    if (
        not _bounded_text(expected_image_name)
        or type(expected_image_digest) is not str
        or _IMAGE_DIGEST.fullmatch(expected_image_digest) is None
    ):
        return _rejected("image_digest_invalid")
    sources = _source_expectations(
        expected_source_inventory,
        current_source_inventory,
        current_prefix_payloads,
    )
    if sources is None:
        return _rejected("source_inventory_or_prefix_mismatch")
    transport_error = _run_binding_valid(
        run,
        receipt,
        stdout_artifact,
        configuration_epoch=configuration_epoch,
    )
    if transport_error is not None:
        return _rejected(transport_error)
    assert type(run) is RunReference
    assert type(receipt) is ExecutionReceipt
    assert type(stdout_artifact) is ArtifactReference
    request = _request_document(request_payload, issued_request)
    if request is None:
        return _rejected("request_artifact_mismatch")
    request_valid, request_error = _request_binding_valid(
        request,
        identity=identity,
        configuration_epoch=configuration_epoch,
        expected_image_name=expected_image_name,
        expected_image_digest=expected_image_digest,
        expected_source_manifest_sha256=(
            expected_source_manifest_sha256
        ),
        sources=sources,
        run=run,
        receipt=receipt,
    )
    if not request_valid:
        return _rejected(request_error)
    if not _stdout_capture_valid(receipt, stdout_artifact):
        return _rejected("stdout_capture_incomplete")
    if (
        type(stdout_payload) is not bytes
        or len(stdout_payload) != stdout_artifact.size
        or hashlib.sha256(stdout_payload).hexdigest()
        != stdout_artifact.sha256
    ):
        return _rejected("stdout_artifact_content_mismatch")
    inventory_sha256 = _inventory_sha256(sources)
    envelope = ForensicIndexExecutionEnvelope(
        category=identity.category,
        contest_id=identity.contest_id,
        challenge_id=identity.challenge_id,
        configuration_epoch=configuration_epoch,
        experiment_id=receipt.experiment_id,
        run_id=run.id,
        run_origin=run.origin.value,
        request_path=run.request_path,
        request_sha256=hashlib.sha256(request_payload).hexdigest(),
        request_size_bytes=len(request_payload),
        result_path=run.result_path,
        validation_path=run.validation_path,
        receipt_id=receipt.id,
        image_name=expected_image_name,
        image_digest=expected_image_digest,
        source_manifest_sha256=expected_source_manifest_sha256,
        source_inventory_sha256=inventory_sha256,
        source_file_count=len(sources),
        source_total_bytes=sum(item.size_bytes for item in sources),
        prefix_coverage_ppm=1_000_000,
        stdout_artifact_id=stdout_artifact.id,
        stdout_artifact_path=stdout_artifact.path,
        stdout_artifact_sha256=stdout_artifact.sha256,
        stdout_artifact_size_bytes=stdout_artifact.size,
    )
    semantic = evaluate_forensic_evidence_index(
        stdout_payload,
        sources,
        expected_source_root="/challenge",
    )
    if (
        semantic.source_inventory_sha256 != inventory_sha256
        or semantic.pointer_coverage_ppm != 1_000_000
        or semantic.verdict is not ForensicIndexVerdict.CONFIRMED
    ):
        return _rejected(
            f"semantic_{semantic.reason_code}",
            envelope=envelope,
            semantic=semantic,
        )
    return ForensicIndexExecutionEvaluation(
        verdict=ForensicIndexExecutionVerdict.CONFIRMED,
        reason_code="complete_executed_evidence_index",
        envelope=envelope,
        semantic_evaluation=semantic,
    )


__all__ = [
    "FORENSIC_INDEX_EXECUTION_PROTOCOL",
    "FORENSIC_INDEX_EXPECTED_ARGV",
    "ForensicIndexExecutionEnvelope",
    "ForensicIndexExecutionEvaluation",
    "ForensicIndexExecutionVerdict",
    "evaluate_forensic_index_execution",
]
