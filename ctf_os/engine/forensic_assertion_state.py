"""Exact durable state for transport-verified Forensic assertions.

This module is independent from ``ChallengeEngine``.  It converts one
transport-bound Forensic assertion evaluation into the sole raw-free
Experiment/Run/Receipt/Artifact/Fact/Progress graph that may represent it, and
it validates that graph against a complete :class:`ChallengeState`.

The binding retains the complete value-free operator contract, confirmed
evidence-index root, current readiness registry, typed pointers, every
pre-issued identity and request commitment, canonical observation-document
commitments, raw tool-output commitments, and the effective independent-family
corroboration result.  It never stores raw evidence, tool output, model prose,
credentials, a flag candidate, a proof, a submission, or a challenge-status
transition.  A rejected evaluation creates no Fact or ProgressMarker.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from itertools import islice

from ctf_os.engine.forensic_assertion_execution import (
    FORENSIC_ASSERTION_EXECUTION_MAX_CAPTURE_BYTES,
    FORENSIC_ASSERTION_EXECUTION_PROTOCOL,
    FORENSIC_ASSERTION_OPERATOR_SPEC_MAX_BYTES,
    FORENSIC_ASSERTION_OPERATOR_SPEC_PROTOCOL,
    ForensicAssertionExecutionPreflightError,
    ForensicAssertionExecutionEvaluation,
    ForensicAssertionExecutionPlan,
    ForensicAssertionExecutionRecord,
    ForensicAssertionExecutionVerdict,
    ForensicToolReadiness,
    forensic_assertion_execution_plan_is_canonical,
    forensic_tool_readiness_registry_sha256,
)
from ctf_os.engine.forensic_assertion_graph import (
    FORENSIC_ASSERTION_GRAPH_PROTOCOL,
    FORENSIC_ASSERTION_MAX_ARTIFACT_BYTES,
    FORENSIC_ASSERTION_MAX_OBSERVATIONS,
    FORENSIC_ASSERTION_MIN_COVERAGE_PPM,
    FORENSIC_CLAIM_KINDS,
    FORENSIC_POINTER_KINDS,
    FORENSIC_TIMESTAMP_KINDS,
    ForensicAssertionGraphEvaluation,
    ForensicAssertionState,
    ForensicAssertionVerdict,
    ForensicCorroborationObservation,
    ForensicCorroborationRecord,
    ForensicObservationArtifact,
    evaluate_forensic_assertion_graph,
    forensic_evidence_pointer_sha256,
)
from ctf_os.models import (
    ArtifactReference,
    ChallengeIdentity,
    ChallengeState,
    ExecutionReceipt,
    Experiment,
    ExperimentKind,
    ExperimentStatus,
    Fact,
    FactKind,
    ProgressMarker,
    Provenance,
    ReceiptOutcome,
    RunOrigin,
    RunReference,
    RunStatus,
)
from ctf_os.store.atomic import StrictJSONError, strict_json_loads


FORENSIC_ASSERTION_STATE_PROTOCOL = (
    "ctfos.forensic.assertion.state.v1"
)
FORENSIC_ASSERTION_STATE_SCHEMA_VERSION = 1
FORENSIC_ASSERTION_STATE_EXECUTOR = (
    "forensic_assertion_execution_state_v1"
)
FORENSIC_ASSERTION_STATE_MAX_BINDING_BYTES = 16 * 1024 * 1024
FORENSIC_ASSERTION_STATE_MAX_PROJECTION_BYTES = 32 * 1024 * 1024
FORENSIC_ASSERTION_STATE_MAX_EXISTING_IDS = 100_000
FORENSIC_ASSERTION_STATE_MAX_HYPOTHESES = 64
FORENSIC_ASSERTION_STATE_MAX_TIMEOUT_SECONDS = 24 * 60 * 60

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,255}$")
_REASON_CODE = re.compile(r"^[A-Za-z0-9_:-]{1,256}$")
_ALLOWED_RUN_ORIGINS = frozenset(
    {RunOrigin.MANAGED_TOOL, RunOrigin.OPERATOR_TOOL}
)
_ARTIFACT_ROLES = frozenset(
    {
        "operator_spec",
        "execution_plan",
        "execution_evaluation",
        "preissued_request",
        "observation_document",
        "tool_output",
    }
)
_AUTHORITIES_FALSE = {
    "automatic_submission_authorized": False,
    "candidate_authorized": False,
    "challenge_proof_satisfied": False,
    "flag_proven": False,
    "impact_proven": False,
    "proof_authorized": False,
    "self_report_accepted": False,
    "status_transition_authorized": False,
}

_ROOT_KEYS = frozenset(
    {
        "artifacts",
        "authorities",
        "base_revision",
        "configuration_epoch",
        "corroboration",
        "evaluation",
        "experiment",
        "identity",
        "plan",
        "preissued_requests",
        "protocol",
        "records",
        "reduction",
        "schema_version",
        "state_ids",
    }
)
_IDENTITY_KEYS = frozenset({"category", "challenge_id", "contest_id"})
_EXPERIMENT_KEYS = frozenset(
    {
        "evaluated_at",
        "hypothesis_ids",
        "id",
        "run_origin",
        "timeout_seconds",
    }
)
_EVALUATION_KEYS = frozenset(
    {
        "confirmed",
        "execution_plan_sha256",
        "reason_codes",
        "record_count",
        "semantic_evaluation_sha256",
        "sha256",
        "size_bytes",
        "verdict",
    }
)
_PLAN_KEYS = frozenset(
    {
        "assertion_graph_plan_sha256",
        "execution_plan_sha256",
        "execution_plan_size_bytes",
        "index_root",
        "operator_spec",
        "operator_spec_sha256",
        "operator_spec_size_bytes",
        "pointers",
        "readiness_registry_sha256",
        "source_catalog_sha256",
    }
)
_STATE_IDS_KEYS = frozenset(
    {
        "evaluation_artifact_id",
        "fact_id",
        "operator_spec_artifact_id",
        "plan_artifact_id",
        "progress_id",
    }
)
_ARTIFACT_KEYS = frozenset(
    {
        "artifact_id",
        "context_visibility",
        "media_type",
        "path",
        "role",
        "sha256",
        "size_bytes",
        "source_run_id",
    }
)
_PREISSUED_KEYS = frozenset(
    {
        "artifact",
        "command",
        "execution_nonce_sha256",
        "index_execution_evaluation_sha256",
        "observation",
        "operator_spec_sha256",
        "plan_sha256",
        "pointer",
        "protocol",
        "readiness_registry_sha256",
        "request_id",
        "request_path",
        "request_sha256",
        "request_size_bytes",
        "run_id",
        "schema_version",
        "semantic_execution_contract_sha256",
        "source",
        "tool",
        "transport_contract",
    }
)
_PREISSUED_ARTIFACT_KEYS = frozenset(
    {"artifact_id", "maximum_size_bytes", "path"}
)
_PREISSUED_COMMAND_KEYS = frozenset(
    {"argv", "argv_sha256", "template_sha256"}
)
_PREISSUED_OBSERVATION_KEYS = frozenset(
    {"observation_id", "path", "receipt_id"}
)
_PREISSUED_SOURCE_KEYS = frozenset(
    {
        "evidence_root",
        "evidence_root_access",
        "inventory_sha256",
        "manifest_sha256",
    }
)
_PREISSUED_TOOL_KEYS = frozenset(
    {
        "independence_family",
        "runtime_image_digest",
        "tool_id",
        "tool_version_sha256",
    }
)
_PREISSUED_TRANSPORT_KEYS = frozenset(
    {
        "artifact_capture",
        "evidence_access",
        "network",
        "observation_document",
        "transport_execution_contract_sha256",
        "workspace",
    }
)
_RECORD_KEYS = frozenset(
    {
        "execution_record",
        "observation_document_artifact",
        "result_path",
        "tool_output_artifact",
        "transport_receipt_path",
        "validation_path",
        "wall_seconds",
    }
)
_EXECUTION_RECORD_KEYS = frozenset(
    {
        "artifact",
        "independence_family",
        "observation_document",
        "pointer_id",
        "pointer_sha256",
        "receipt_id",
        "receipt_sha256",
        "request_id",
        "request_path",
        "request_sha256",
        "run_id",
        "tool_id",
    }
)
_EXECUTION_ARTIFACT_KEYS = frozenset(
    {"artifact_id", "path", "sha256", "size_bytes"}
)
_EXECUTION_OBSERVATION_KEYS = frozenset(
    {"observation_id", "path", "sha256", "size_bytes"}
)
_CORROBORATION_KEYS = frozenset(
    {
        "available_families",
        "covered",
        "observed_families",
        "pointer_id",
        "pointer_kind",
        "required_family_count",
    }
)
_REDUCTION_KEYS = frozenset(
    {
        "automatic_submission",
        "candidate",
        "executed_fact",
        "impact",
        "progress",
        "proof",
        "status_transition",
    }
)
_REDUCTION_BINDING_KEYS = frozenset(
    {
        "evaluation_sha256",
        "index_execution_evaluation_sha256",
        "minimum_confirmed_coverage_ppm",
        "plan_sha256",
        "source_inventory_sha256",
        "source_manifest_sha256",
    }
)
_MARKER_KEYS = frozenset(
    {
        "binding_sha256",
        "experiment_id",
        "object_id",
        "object_kind",
        "protocol",
        "record_sha256",
        "schema_version",
    }
)
_OPERATOR_KEYS = frozenset(
    {
        "assertions",
        "coverage_threshold_ppm",
        "index_root",
        "pointers",
        "protocol",
        "readiness_registry_sha256",
        "schema_version",
        "source_catalog_sha256",
        "tools",
    }
)
_ASSERTION_KEYS = frozenset(
    {
        "assertion_id",
        "claim_kind",
        "claim_sha256",
        "depends_on",
        "evidence_pointer_ids",
        "state",
    }
)
_READINESS_KEYS = frozenset(
    {
        "command_template",
        "independence_family",
        "readiness_artifact",
        "readiness_generation",
        "readiness_status",
        "runtime_image_digest",
        "supported_pointer_kinds",
        "tool_id",
        "tool_version_sha256",
    }
)
_READINESS_ARTIFACT_KEYS = frozenset(
    {"artifact_id", "sha256", "size_bytes"}
)
_INDEX_ROOT_KEYS = frozenset(
    {
        "evidence_index_sha256",
        "evidence_tree_sha256",
        "index_artifact",
        "index_execution_envelope_sha256",
        "index_execution_evaluation_sha256",
        "index_receipt_id",
        "index_run_id",
        "source_file_count",
        "source_inventory_sha256",
        "source_manifest_sha256",
        "source_total_bytes",
    }
)
_INDEX_ARTIFACT_KEYS = frozenset(
    {"artifact_id", "sha256", "size_bytes"}
)
_TIMESTAMP_KEYS = frozenset(
    {
        "normalized_timezone",
        "normalized_utc_epoch_ns",
        "precision_ns",
        "source_local_epoch_ns",
        "source_utc_offset_minutes",
        "timestamp_kind",
    }
)
_POINTER_KEYS = {
    "file_range": frozenset(
        {
            "kind",
            "length_bytes",
            "offset_bytes",
            "pointer_id",
            "source_path",
            "source_sha256",
        }
    ),
    "inode": frozenset(
        {
            "inode_number",
            "kind",
            "metadata_length_bytes",
            "metadata_offset_bytes",
            "metadata_sha256",
            "partition_offset_bytes",
            "pointer_id",
            "source_path",
            "source_sha256",
        }
    ),
    "pcap_frame": frozenset(
        {
            "captured_length_bytes",
            "frame_number",
            "kind",
            "original_length_bytes",
            "packet_offset_bytes",
            "packet_sha256",
            "pointer_id",
            "source_path",
            "source_sha256",
            "timestamp",
        }
    ),
    "process": frozenset(
        {
            "kind",
            "object_length_bytes",
            "object_offset_bytes",
            "object_sha256",
            "pid",
            "pointer_id",
            "process_start",
            "source_path",
            "source_sha256",
            "virtual_address",
        }
    ),
    "timestamp": frozenset(
        {
            "field_length_bytes",
            "field_offset_bytes",
            "field_sha256",
            "kind",
            "pointer_id",
            "source_path",
            "source_sha256",
            "timestamp",
        }
    ),
}


class ForensicAssertionStateContractError(ValueError):
    """One durable state projection violated the exact contract."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _canonical_json_bytes(
    value: object,
    *,
    maximum_bytes: int | None = None,
) -> bytes:
    try:
        payload = (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise ForensicAssertionStateContractError(
            "canonical_json_invalid"
        ) from error
    if maximum_bytes is not None and len(payload) > maximum_bytes:
        raise ForensicAssertionStateContractError(
            "canonical_json_size_exceeded"
        )
    return payload


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _valid_sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _valid_image_digest(value: object) -> bool:
    return type(value) is str and _IMAGE_DIGEST.fullmatch(value) is not None


def _safe_id(value: object) -> bool:
    return type(value) is str and _SAFE_ID.fullmatch(value) is not None


def _exact_int(
    value: object,
    *,
    minimum: int = 0,
    maximum: int = 2**63 - 1,
) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _exact_number(
    value: object,
    *,
    minimum: float = 0.0,
    maximum: float = float(
        FORENSIC_ASSERTION_STATE_MAX_TIMEOUT_SECONDS
    ),
) -> bool:
    return (
        type(value) in {int, float}
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and minimum <= float(value) <= maximum
    )


def _exact_dict(
    value: object,
    keys: frozenset[str],
    code: str,
) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise ForensicAssertionStateContractError(code)
    return value


def _safe_path(value: object) -> bool:
    return (
        type(value) is str
        and bool(value)
        and not value.startswith("/")
        and "\\" not in value
        and all(part not in {"", ".", ".."} for part in value.split("/"))
    )


def _bounded_utc(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        if not 1 <= len(value.encode("utf-8", errors="strict")) <= 128:
            return False
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00" if value.endswith("Z") else value
        )
    except (TypeError, UnicodeError, ValueError):
        return False
    return parsed.tzinfo is not None


def _state_artifact_path(artifact_id: str, role: str) -> str:
    return (
        "artifacts/forensic-assertion-state/"
        f"{role}/{artifact_id}.json"
    )


def _run_paths(run_id: str) -> tuple[str, str]:
    root = f"runs/{run_id}/forensic-assertion"
    return f"{root}/result.json", f"{root}/validation.json"


@dataclass(frozen=True, slots=True)
class ForensicAssertionStateIds:
    experiment_id: str
    operator_spec_artifact_id: str
    plan_artifact_id: str
    evaluation_artifact_id: str
    fact_id: str | None
    progress_id: str | None


@dataclass(frozen=True, slots=True)
class ForensicAssertionStateProjection:
    """Complete state delta; deliberately no candidate or status field."""

    binding: dict[str, object]
    experiment: Experiment
    runs: tuple[RunReference, ...]
    receipts: tuple[ExecutionReceipt, ...]
    artifacts: tuple[ArtifactReference, ...]
    fact: Fact | None
    progress: ProgressMarker | None

    @property
    def binding_sha256(self) -> str:
        return _sha256(
            _canonical_json_bytes(
                self.binding,
                maximum_bytes=FORENSIC_ASSERTION_STATE_MAX_BINDING_BYTES,
            )
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "artifacts": [item.to_dict() for item in self.artifacts],
            "binding": copy.deepcopy(self.binding),
            "binding_sha256": self.binding_sha256,
            "experiment": self.experiment.to_dict(v2=True),
            "fact": (
                self.fact.to_dict(v2=True)
                if self.fact is not None
                else None
            ),
            "progress": (
                self.progress.to_dict()
                if self.progress is not None
                else None
            ),
            "protocol": FORENSIC_ASSERTION_STATE_PROTOCOL,
            "receipts": [item.to_dict() for item in self.receipts],
            "runs": [item.to_dict(v2=True) for item in self.runs],
            "schema_version": FORENSIC_ASSERTION_STATE_SCHEMA_VERSION,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(
            self.to_dict(),
            maximum_bytes=(
                FORENSIC_ASSERTION_STATE_MAX_PROJECTION_BYTES
            ),
        )

    @property
    def sha256(self) -> str:
        return _sha256(self.canonical_bytes)

    @property
    def object_ids(self) -> tuple[str, ...]:
        values = [self.experiment.id]
        values.extend(item.id for item in self.runs)
        values.extend(item.id for item in self.receipts)
        values.extend(item.id for item in self.artifacts)
        if self.fact is not None:
            values.append(self.fact.id)
        if self.progress is not None:
            values.append(self.progress.id)
        return tuple(values)

    @property
    def reserved_ids(self) -> tuple[str, ...]:
        values = list(self.object_ids)
        for request in self.binding["preissued_requests"]:
            values.extend(
                (
                    request["run_id"],
                    request["observation"]["observation_id"],
                    request["observation"]["receipt_id"],
                    request["artifact"]["artifact_id"],
                )
            )
        return tuple(values)


def _validate_identity(identity: ChallengeIdentity) -> None:
    if type(identity) is not ChallengeIdentity:
        raise ForensicAssertionStateContractError(
            "challenge_identity_invalid"
        )
    try:
        valid = (
            identity.category == "forensics"
            and all(
                type(value) is str
                and bool(value.strip())
                and len(value.encode("utf-8", errors="strict")) <= 512
                for value in (
                    identity.contest_id,
                    identity.category,
                    identity.challenge_id,
                )
            )
        )
    except UnicodeError as error:
        raise ForensicAssertionStateContractError(
            "challenge_identity_invalid"
        ) from error
    if not valid:
        raise ForensicAssertionStateContractError(
            "challenge_identity_invalid"
        )


def _validate_state_ids(
    ids: ForensicAssertionStateIds,
    *,
    confirmed: bool,
) -> None:
    if type(ids) is not ForensicAssertionStateIds:
        raise ForensicAssertionStateContractError(
            "state_ids_type_invalid"
        )
    required = (
        ids.experiment_id,
        ids.operator_spec_artifact_id,
        ids.plan_artifact_id,
        ids.evaluation_artifact_id,
    )
    if any(not _safe_id(value) for value in required):
        raise ForensicAssertionStateContractError(
            "state_identifier_invalid"
        )
    if confirmed:
        if not _safe_id(ids.fact_id) or not _safe_id(ids.progress_id):
            raise ForensicAssertionStateContractError(
                "confirmed_state_ids_invalid"
            )
    elif ids.fact_id is not None or ids.progress_id is not None:
        raise ForensicAssertionStateContractError(
            "rejected_state_retains_authority_ids"
        )
    present = list(required)
    if ids.fact_id is not None:
        present.append(ids.fact_id)
    if ids.progress_id is not None:
        present.append(ids.progress_id)
    if len(set(present)) != len(present):
        raise ForensicAssertionStateContractError(
            "state_identifier_reused"
        )


def _validate_hypothesis_ids(
    values: Iterable[str],
) -> tuple[str, ...]:
    try:
        selected = tuple(
            islice(
                iter(values),
                FORENSIC_ASSERTION_STATE_MAX_HYPOTHESES + 1,
            )
        )
    except Exception as error:
        raise ForensicAssertionStateContractError(
            "hypothesis_ids_invalid"
        ) from error
    if (
        len(selected) > FORENSIC_ASSERTION_STATE_MAX_HYPOTHESES
        or any(not _safe_id(item) for item in selected)
        or len(set(selected)) != len(selected)
    ):
        raise ForensicAssertionStateContractError(
            "hypothesis_ids_invalid"
        )
    return selected


def _semantic_observations_from_records(
    evaluation: ForensicAssertionGraphEvaluation,
) -> tuple[ForensicCorroborationObservation, ...]:
    if evaluation.plan is None:
        return ()
    plan = evaluation.plan
    tools = {item.tool_id: item for item in plan.tools}
    observations: list[ForensicCorroborationObservation] = []
    for record in evaluation.corroboration_records:
        if type(record) is not ForensicCorroborationRecord:
            raise ForensicAssertionStateContractError(
                "semantic_corroboration_record_invalid"
            )
        tool = tools.get(record.tool_id)
        if tool is None:
            raise ForensicAssertionStateContractError(
                "semantic_tool_orphan"
            )
        observations.append(
            ForensicCorroborationObservation(
                observation_id=record.observation_id,
                pointer_id=record.pointer_id,
                tool_id=record.tool_id,
                run_id=record.run_id,
                receipt_id=record.receipt_id,
                receipt_sha256=record.receipt_sha256,
                execution_nonce_sha256=(
                    record.execution_nonce_sha256
                ),
                execution_contract_sha256=(
                    record.execution_contract_sha256
                ),
                plan_sha256=plan.plan_sha256,
                source_manifest_sha256=(
                    plan.inventory_root.source_manifest_sha256
                ),
                source_inventory_sha256=(
                    plan.inventory_root.source_inventory_sha256
                ),
                runtime_image_digest=tool.runtime_image_digest,
                clean_workspace=True,
                network_disabled=True,
                orchestration_status="completed",
                exit_code=0,
                timed_out=False,
                capture_complete=True,
                truncation_known=True,
                truncated=False,
                capture_error=None,
                observation_artifact=record.observation_artifact,
            )
        )
    return tuple(observations)


def _validate_evaluation_and_plan(
    evaluation: ForensicAssertionExecutionEvaluation,
    execution_plan: ForensicAssertionExecutionPlan,
    operator_spec_payload: bytes,
) -> None:
    if (
        type(evaluation) is not ForensicAssertionExecutionEvaluation
        or type(execution_plan) is not ForensicAssertionExecutionPlan
        or type(operator_spec_payload) is not bytes
        or not operator_spec_payload
        or len(operator_spec_payload)
        > FORENSIC_ASSERTION_OPERATOR_SPEC_MAX_BYTES
    ):
        raise ForensicAssertionStateContractError(
            "evaluation_plan_input_invalid"
        )
    if not forensic_assertion_execution_plan_is_canonical(
        execution_plan
    ):
        raise ForensicAssertionStateContractError(
            "execution_plan_not_canonical"
        )
    specification = execution_plan.specification
    if (
        _sha256(operator_spec_payload)
        != specification.operator_spec_sha256
        or len(operator_spec_payload)
        != specification.operator_spec_size_bytes
        or evaluation.execution_plan_sha256
        != execution_plan.execution_plan_sha256
    ):
        raise ForensicAssertionStateContractError(
            "evaluation_plan_binding_mismatch"
        )
    try:
        evaluation_payload = evaluation.canonical_bytes
        execution_plan.canonical_bytes
    except (AttributeError, TypeError, ValueError) as error:
        raise ForensicAssertionStateContractError(
            "evaluation_or_plan_not_canonical"
        ) from error
    if len(evaluation_payload) > FORENSIC_ASSERTION_STATE_MAX_BINDING_BYTES:
        raise ForensicAssertionStateContractError(
            "evaluation_size_exceeded"
        )
    if (
        type(evaluation.reason_codes) is not tuple
        or len(evaluation.reason_codes) > 16
        or any(
            type(code) is not str
            or _REASON_CODE.fullmatch(code) is None
            for code in evaluation.reason_codes
        )
        or type(evaluation.records) is not tuple
        or len(evaluation.records) > len(execution_plan.requests)
    ):
        raise ForensicAssertionStateContractError(
            "evaluation_shape_invalid"
        )
    if evaluation.confirmed:
        if (
            evaluation.verdict
            is not ForensicAssertionExecutionVerdict.CONFIRMED
            or evaluation.reason_codes
            or evaluation.semantic_evaluation is None
            or not evaluation.semantic_evaluation.passed
            or len(evaluation.records) != len(execution_plan.requests)
        ):
            raise ForensicAssertionStateContractError(
                "confirmed_evaluation_inconsistent"
            )
    elif (
        evaluation.verdict
        is not ForensicAssertionExecutionVerdict.REJECTED
        or not evaluation.reason_codes
    ):
        raise ForensicAssertionStateContractError(
            "rejected_evaluation_inconsistent"
        )
    for position, (record, request) in enumerate(
        zip(
            evaluation.records,
            execution_plan.requests,
            strict=False,
        ),
        start=1,
    ):
        if (
            type(record) is not ForensicAssertionExecutionRecord
            or record.request_id != request.request_id
            or record.request_sha256 != request.request_sha256
            or record.request_path != request.request_path
            or record.run_id != request.run_id
            or record.observation_id != request.observation_id
            or record.observation_path != request.observation_path
            or record.receipt_id != request.receipt_id
            or record.pointer_id != request.pointer_id
            or record.pointer_sha256 != request.pointer_sha256
            or record.tool_id != request.tool_id
            or record.independence_family
            != request.independence_family
            or record.artifact.artifact_id != request.artifact_id
            or record.artifact_path != request.artifact_path
        ):
            raise ForensicAssertionStateContractError(
                f"observation-{position}:evaluation_record_rebound"
            )
    semantic = evaluation.semantic_evaluation
    if semantic is not None:
        if (
            type(semantic) is not ForensicAssertionGraphEvaluation
            or semantic.plan != specification.plan
        ):
            raise ForensicAssertionStateContractError(
                "semantic_evaluation_plan_rebound"
            )
        try:
            rebuilt = evaluate_forensic_assertion_graph(
                specification.plan,
                _semantic_observations_from_records(semantic),
            )
        except (AttributeError, TypeError, ValueError) as error:
            raise ForensicAssertionStateContractError(
                "semantic_evaluation_invalid"
            ) from error
        if rebuilt != semantic:
            raise ForensicAssertionStateContractError(
                "semantic_evaluation_rebound"
            )
        if len(semantic.corroboration_records) != len(evaluation.records):
            raise ForensicAssertionStateContractError(
                "semantic_execution_record_count_rebound"
            )
        for position, (transport, corroboration) in enumerate(
            zip(
                evaluation.records,
                semantic.corroboration_records,
                strict=True,
            ),
            start=1,
        ):
            if (
                corroboration.observation_id
                != transport.observation_id
                or corroboration.pointer_id != transport.pointer_id
                or corroboration.pointer_sha256
                != transport.pointer_sha256
                or corroboration.tool_id != transport.tool_id
                or corroboration.independence_family
                != transport.independence_family
                or corroboration.run_id != transport.run_id
                or corroboration.receipt_id != transport.receipt_id
                or corroboration.receipt_sha256
                != transport.receipt_sha256
                or corroboration.observation_artifact
                != transport.artifact
            ):
                raise ForensicAssertionStateContractError(
                    f"observation-{position}:semantic_record_rebound"
                )
    elif evaluation.confirmed:
        raise ForensicAssertionStateContractError(
            "confirmed_semantic_evaluation_missing"
        )


def _operator_document(payload: bytes) -> dict[str, object]:
    try:
        value = strict_json_loads(
            payload,
            max_bytes=FORENSIC_ASSERTION_OPERATOR_SPEC_MAX_BYTES,
            max_depth=24,
        )
    except (
        StrictJSONError,
        RecursionError,
        UnicodeError,
        ValueError,
    ) as error:
        raise ForensicAssertionStateContractError(
            "operator_spec_json_invalid"
        ) from error
    if (
        type(value) is not dict
        or payload != _canonical_json_bytes(value)
    ):
        raise ForensicAssertionStateContractError(
            "operator_spec_not_canonical"
        )
    return value


def _artifact_document(
    artifact_id: str,
    *,
    role: str,
    path: str,
    sha256: str,
    size_bytes: int,
    source_run_id: str | None,
    media_type: str,
) -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "context_visibility": "engine_private",
        "media_type": media_type,
        "path": path,
        "role": role,
        "sha256": sha256,
        "size_bytes": size_bytes,
        "source_run_id": source_run_id,
    }


def _preissued_document(request: object) -> dict[str, object]:
    document = request.to_dict()
    return {
        **copy.deepcopy(document),
        "request_sha256": request.request_sha256,
        "request_size_bytes": len(request.canonical_bytes),
    }


def _corroboration_bindings(
    evaluation: ForensicAssertionExecutionEvaluation,
    execution_plan: ForensicAssertionExecutionPlan,
) -> list[dict[str, object]]:
    plan = execution_plan.specification.plan
    observed: dict[str, set[str]] = {
        pointer.pointer_id: set() for pointer in plan.pointers
    }
    for record in evaluation.records:
        observed[record.pointer_id].add(record.independence_family)
    result: list[dict[str, object]] = []
    for pointer in plan.pointers:
        available = sorted(
            {
                tool.independence_family
                for tool in plan.tools
                if pointer.kind in tool.supported_pointer_kinds
            }
        )
        required = 2 if len(available) >= 2 else 1
        observed_families = sorted(observed[pointer.pointer_id])
        result.append(
            {
                "available_families": available,
                "covered": len(observed_families) >= required,
                "observed_families": observed_families,
                "pointer_id": pointer.pointer_id,
                "pointer_kind": pointer.kind,
                "required_family_count": required,
            }
        )
    return result


def _validate_reduction_shape(
    evaluation: ForensicAssertionExecutionEvaluation,
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    reduction = evaluation.reduction_projection()
    if (
        type(reduction) is not dict
        or set(reduction)
        != {
            "automatic_submission",
            "candidate",
            "executed_fact",
            "impact",
            "progress",
            "proof",
        }
        or reduction["automatic_submission"] is not False
        or reduction["candidate"] is not None
        or reduction["impact"] is not None
        or reduction["proof"] is not None
    ):
        raise ForensicAssertionStateContractError(
            "evaluation_authority_widened"
        )
    fact = reduction["executed_fact"]
    progress = reduction["progress"]
    if evaluation.confirmed:
        if (
            type(fact) is not dict
            or set(fact)
            != {
                "artifact_id",
                "extra",
                "provenance",
                "source_run_id",
                "statement",
            }
            or fact["provenance"] != "executed"
            or type(progress) is not dict
            or set(progress)
            != {
                "artifact_ids",
                "extra",
                "run_id",
                "statement",
            }
        ):
            raise ForensicAssertionStateContractError(
                "confirmed_reduction_invalid"
            )
        return fact, progress
    if fact is not None or progress is not None:
        raise ForensicAssertionStateContractError(
            "rejected_reduction_retains_authority"
        )
    return None, None


def _build_binding(
    evaluation: ForensicAssertionExecutionEvaluation,
    execution_plan: ForensicAssertionExecutionPlan,
    operator_spec_payload: bytes,
    *,
    identity: ChallengeIdentity,
    configuration_epoch: int,
    base_revision: int,
    ids: ForensicAssertionStateIds,
    hypothesis_ids: Iterable[str],
    evaluated_at: str,
    timeout_seconds: int,
    run_origin: RunOrigin,
    observation_wall_seconds: Mapping[str, float],
) -> dict[str, object]:
    _validate_evaluation_and_plan(
        evaluation,
        execution_plan,
        operator_spec_payload,
    )
    _validate_identity(identity)
    if not _exact_int(configuration_epoch):
        raise ForensicAssertionStateContractError(
            "configuration_epoch_invalid"
        )
    if not _exact_int(base_revision):
        raise ForensicAssertionStateContractError(
            "base_revision_invalid"
        )
    if (
        not _exact_int(
            timeout_seconds,
            minimum=1,
            maximum=FORENSIC_ASSERTION_STATE_MAX_TIMEOUT_SECONDS,
        )
        or not _bounded_utc(evaluated_at)
        or type(run_origin) is not RunOrigin
        or run_origin not in _ALLOWED_RUN_ORIGINS
    ):
        raise ForensicAssertionStateContractError(
            "experiment_execution_metadata_invalid"
        )
    selected_hypotheses = _validate_hypothesis_ids(hypothesis_ids)
    _validate_state_ids(ids, confirmed=evaluation.confirmed)
    if type(observation_wall_seconds) is not dict:
        raise ForensicAssertionStateContractError(
            "observation_wall_seconds_invalid"
        )
    record_run_ids = tuple(item.run_id for item in evaluation.records)
    if (
        set(observation_wall_seconds) != set(record_run_ids)
        or any(
            not _exact_number(value)
            for value in observation_wall_seconds.values()
        )
    ):
        raise ForensicAssertionStateContractError(
            "observation_wall_seconds_invalid"
        )
    fact_payload, progress_payload = _validate_reduction_shape(
        evaluation
    )
    specification = execution_plan.specification
    graph_plan = specification.plan
    operator_document = _operator_document(operator_spec_payload)
    evaluation_payload = evaluation.canonical_bytes
    plan_payload = execution_plan.canonical_bytes
    preissued = [
        _preissued_document(request)
        for request in execution_plan.requests
    ]
    final_run_id = (
        evaluation.records[-1].run_id
        if evaluation.records
        else None
    )
    artifacts: list[dict[str, object]] = [
        _artifact_document(
            ids.operator_spec_artifact_id,
            role="operator_spec",
            path=_state_artifact_path(
                ids.operator_spec_artifact_id,
                "operator_spec",
            ),
            sha256=_sha256(operator_spec_payload),
            size_bytes=len(operator_spec_payload),
            source_run_id=None,
            media_type="application/json",
        ),
        _artifact_document(
            ids.plan_artifact_id,
            role="execution_plan",
            path=_state_artifact_path(
                ids.plan_artifact_id,
                "execution_plan",
            ),
            sha256=_sha256(plan_payload),
            size_bytes=len(plan_payload),
            source_run_id=None,
            media_type="application/json",
        ),
        _artifact_document(
            ids.evaluation_artifact_id,
            role="execution_evaluation",
            path=_state_artifact_path(
                ids.evaluation_artifact_id,
                "execution_evaluation",
            ),
            sha256=_sha256(evaluation_payload),
            size_bytes=len(evaluation_payload),
            source_run_id=final_run_id,
            media_type="application/json",
        ),
    ]
    for request in execution_plan.requests:
        artifacts.append(
            _artifact_document(
                request.request_id,
                role="preissued_request",
                path=request.request_path,
                sha256=request.request_sha256,
                size_bytes=len(request.canonical_bytes),
                source_run_id=None,
                media_type="application/json",
            )
        )
    records: list[dict[str, object]] = []
    for record in evaluation.records:
        observation_artifact = _artifact_document(
            record.observation_id,
            role="observation_document",
            path=record.observation_path,
            sha256=record.observation_document_sha256,
            size_bytes=record.observation_document_size_bytes,
            source_run_id=record.run_id,
            media_type="application/json",
        )
        output_artifact = _artifact_document(
            record.artifact.artifact_id,
            role="tool_output",
            path=record.artifact_path,
            sha256=record.artifact.sha256,
            size_bytes=record.artifact.size_bytes,
            source_run_id=record.run_id,
            media_type="application/octet-stream",
        )
        artifacts.extend((observation_artifact, output_artifact))
        result_path, validation_path = _run_paths(record.run_id)
        records.append(
            {
                "execution_record": record.to_dict(),
                "observation_document_artifact": (
                    copy.deepcopy(observation_artifact)
                ),
                "result_path": result_path,
                "tool_output_artifact": copy.deepcopy(output_artifact),
                "transport_receipt_path": record.observation_path,
                "validation_path": validation_path,
                "wall_seconds": observation_wall_seconds[record.run_id],
            }
        )

    state_identifiers = [
        ids.experiment_id,
        ids.operator_spec_artifact_id,
        ids.plan_artifact_id,
        ids.evaluation_artifact_id,
    ]
    if ids.fact_id is not None:
        state_identifiers.append(ids.fact_id)
    if ids.progress_id is not None:
        state_identifiers.append(ids.progress_id)
    preissued_identifiers: list[str] = []
    for request in execution_plan.requests:
        preissued_identifiers.extend(
            (
                request.request_id,
                request.run_id,
                request.observation_id,
                request.receipt_id,
                request.artifact_id,
            )
        )
    index_root = graph_plan.inventory_root
    forbidden_anchor_ids = {
        index_root.index_run_id,
        index_root.index_receipt_id,
        index_root.index_artifact_id,
        *(
            item.readiness_artifact_id
            for item in specification.readiness
        ),
    }
    all_new = [*state_identifiers, *preissued_identifiers]
    if (
        any(not _safe_id(value) for value in all_new)
        or len(set(all_new)) != len(all_new)
        or set(all_new) & forbidden_anchor_ids
    ):
        raise ForensicAssertionStateContractError(
            "projection_global_identifier_reused"
        )
    artifact_ids = {item["artifact_id"] for item in artifacts}
    if evaluation.confirmed:
        assert isinstance(fact_payload, dict)
        assert isinstance(progress_payload, dict)
        if (
            fact_payload["artifact_id"] not in artifact_ids
            or fact_payload["source_run_id"] not in record_run_ids
            or progress_payload["run_id"] not in record_run_ids
            or type(progress_payload["artifact_ids"]) is not list
            or not progress_payload["artifact_ids"]
            or any(
                artifact_id not in artifact_ids
                for artifact_id in progress_payload["artifact_ids"]
            )
        ):
            raise ForensicAssertionStateContractError(
                "reduction_artifact_or_run_orphan"
            )

    pointers = [
        {
            "pointer": pointer.to_dict(),
            "sha256": forensic_evidence_pointer_sha256(pointer),
        }
        for pointer in graph_plan.pointers
    ]
    confirmed = evaluation.confirmed
    binding: dict[str, object] = {
        "artifacts": artifacts,
        "authorities": {
            **_AUTHORITIES_FALSE,
            "executed_forensic_assertion_fact_authorized": confirmed,
            "forensic_assertion_graph_confirmed": confirmed,
            "forensic_assertion_transport_confirmed": confirmed,
            "progress_marker_authorized": confirmed,
        },
        "base_revision": base_revision,
        "configuration_epoch": configuration_epoch,
        "corroboration": _corroboration_bindings(
            evaluation,
            execution_plan,
        ),
        "evaluation": {
            "confirmed": confirmed,
            "execution_plan_sha256": evaluation.execution_plan_sha256,
            "reason_codes": list(evaluation.reason_codes),
            "record_count": len(evaluation.records),
            "semantic_evaluation_sha256": (
                evaluation.semantic_evaluation.sha256
                if evaluation.semantic_evaluation is not None
                else None
            ),
            "sha256": _sha256(evaluation_payload),
            "size_bytes": len(evaluation_payload),
            "verdict": evaluation.verdict.value,
        },
        "experiment": {
            "evaluated_at": evaluated_at,
            "hypothesis_ids": list(selected_hypotheses),
            "id": ids.experiment_id,
            "run_origin": run_origin.value,
            "timeout_seconds": timeout_seconds,
        },
        "identity": identity.to_dict(),
        "plan": {
            "assertion_graph_plan_sha256": graph_plan.plan_sha256,
            "execution_plan_sha256": (
                execution_plan.execution_plan_sha256
            ),
            "execution_plan_size_bytes": len(plan_payload),
            "index_root": graph_plan.inventory_root.to_dict(),
            "operator_spec": operator_document,
            "operator_spec_sha256": specification.operator_spec_sha256,
            "operator_spec_size_bytes": (
                specification.operator_spec_size_bytes
            ),
            "pointers": pointers,
            "readiness_registry_sha256": (
                specification.readiness_registry_sha256
            ),
            "source_catalog_sha256": graph_plan.source_catalog_sha256,
        },
        "preissued_requests": preissued,
        "protocol": FORENSIC_ASSERTION_STATE_PROTOCOL,
        "records": records,
        "reduction": {
            "automatic_submission": False,
            "candidate": None,
            "executed_fact": copy.deepcopy(fact_payload),
            "impact": None,
            "progress": copy.deepcopy(progress_payload),
            "proof": None,
            "status_transition": None,
        },
        "schema_version": FORENSIC_ASSERTION_STATE_SCHEMA_VERSION,
        "state_ids": {
            "evaluation_artifact_id": ids.evaluation_artifact_id,
            "fact_id": ids.fact_id,
            "operator_spec_artifact_id": (
                ids.operator_spec_artifact_id
            ),
            "plan_artifact_id": ids.plan_artifact_id,
            "progress_id": ids.progress_id,
        },
    }
    _canonical_json_bytes(
        binding,
        maximum_bytes=FORENSIC_ASSERTION_STATE_MAX_BINDING_BYTES,
    )
    return binding


def _marker(
    binding: Mapping[str, object],
    *,
    object_kind: str,
    object_id: str,
    record: object,
) -> dict[str, object]:
    binding_bytes = _canonical_json_bytes(
        binding,
        maximum_bytes=FORENSIC_ASSERTION_STATE_MAX_BINDING_BYTES,
    )
    experiment = binding["experiment"]
    assert isinstance(experiment, Mapping)
    return {
        "binding_sha256": _sha256(binding_bytes),
        "experiment_id": experiment["id"],
        "object_id": object_id,
        "object_kind": object_kind,
        "protocol": FORENSIC_ASSERTION_STATE_PROTOCOL,
        "record_sha256": _sha256(_canonical_json_bytes(record)),
        "schema_version": FORENSIC_ASSERTION_STATE_SCHEMA_VERSION,
    }


def _projection_from_binding(
    binding: dict[str, object],
) -> ForensicAssertionStateProjection:
    _validate_binding_document(binding)
    experiment_binding = binding["experiment"]
    evaluation_binding = binding["evaluation"]
    reduction = binding["reduction"]
    state_ids = binding["state_ids"]
    identity = binding["identity"]
    records = binding["records"]
    artifacts_binding = binding["artifacts"]
    assert isinstance(experiment_binding, dict)
    assert isinstance(evaluation_binding, dict)
    assert isinstance(reduction, dict)
    assert isinstance(state_ids, dict)
    assert isinstance(identity, dict)
    assert isinstance(records, list)
    assert isinstance(artifacts_binding, list)
    binding_sha256 = _sha256(
        _canonical_json_bytes(
            binding,
            maximum_bytes=FORENSIC_ASSERTION_STATE_MAX_BINDING_BYTES,
        )
    )
    confirmed = evaluation_binding["confirmed"] is True
    evaluated_at = experiment_binding["evaluated_at"]
    experiment_id = experiment_binding["id"]

    artifacts: list[ArtifactReference] = []
    for artifact_binding in artifacts_binding:
        assert isinstance(artifact_binding, dict)
        artifact_id = artifact_binding["artifact_id"]
        marker = _marker(
            binding,
            object_kind=str(artifact_binding["role"]) + "_artifact",
            object_id=artifact_id,
            record=artifact_binding,
        )
        artifacts.append(
            ArtifactReference(
                id=artifact_id,
                path=artifact_binding["path"],
                sha256=artifact_binding["sha256"],
                source_run_id=artifact_binding["source_run_id"],
                created_at=evaluated_at,
                media_type=artifact_binding["media_type"],
                size=artifact_binding["size_bytes"],
                extra={
                    "context_visibility": "engine_private",
                    "forensic_assertion_state": marker,
                    "kind": "forensic_assertion_"
                    + str(artifact_binding["role"]),
                    "protocol": FORENSIC_ASSERTION_STATE_PROTOCOL,
                },
            )
        )

    runs: list[RunReference] = []
    receipts: list[ExecutionReceipt] = []
    for record_binding in records:
        assert isinstance(record_binding, dict)
        execution_record = record_binding["execution_record"]
        output = record_binding["tool_output_artifact"]
        observation = record_binding["observation_document_artifact"]
        assert isinstance(execution_record, dict)
        assert isinstance(output, dict)
        assert isinstance(observation, dict)
        run_id = execution_record["run_id"]
        receipt_id = execution_record["receipt_id"]
        run_marker = _marker(
            binding,
            object_kind="tool_observation_run",
            object_id=run_id,
            record=record_binding,
        )
        receipt_marker = _marker(
            binding,
            object_kind="tool_observation_receipt",
            object_id=receipt_id,
            record=record_binding,
        )
        runs.append(
            RunReference(
                id=run_id,
                base_revision=binding["base_revision"],
                status=RunStatus.COMPLETED,
                request_path=execution_record["request_path"],
                result_path=record_binding["result_path"],
                validation_path=record_binding["validation_path"],
                role="forensic-assertion",
                origin=RunOrigin(experiment_binding["run_origin"]),
                configuration_epoch=binding["configuration_epoch"],
                created_at=evaluated_at,
                extra={
                    "experiment_id": experiment_id,
                    "forensic_assertion_state": run_marker,
                    "observation_document_artifact_id": (
                        observation["artifact_id"]
                    ),
                    "request_id": execution_record["request_id"],
                    "request_sha256": execution_record["request_sha256"],
                    "transport_receipt_path": record_binding[
                        "transport_receipt_path"
                    ],
                },
            )
        )
        receipts.append(
            ExecutionReceipt(
                id=receipt_id,
                experiment_id=experiment_id,
                run_id=run_id,
                outcome=ReceiptOutcome.SUCCEEDED,
                exit_code=0,
                wall_seconds=record_binding["wall_seconds"],
                stdout_artifact_id=output["artifact_id"],
                stderr_artifact_id=None,
                stdout_bytes=output["size_bytes"],
                stderr_bytes=0,
                stdout_lines=0,
                stderr_lines=0,
                preview="",
                created_at=evaluated_at,
                extra={
                    "forensic_assertion_state": receipt_marker,
                    "observation_document_path": observation["path"],
                    "observation_document_sha256": observation["sha256"],
                    "observation_document_size_bytes": observation[
                        "size_bytes"
                    ],
                    "transport_receipt_path": record_binding[
                        "transport_receipt_path"
                    ],
                    "transport_receipt_sha256": execution_record[
                        "receipt_sha256"
                    ],
                },
            )
        )

    fact: Fact | None = None
    progress: ProgressMarker | None = None
    fact_payload = reduction["executed_fact"]
    progress_payload = reduction["progress"]
    if confirmed:
        assert isinstance(fact_payload, dict)
        assert isinstance(progress_payload, dict)
        fact_id = state_ids["fact_id"]
        progress_id = state_ids["progress_id"]
        assert isinstance(fact_id, str)
        assert isinstance(progress_id, str)
        fact_extra = copy.deepcopy(fact_payload["extra"])
        progress_extra = copy.deepcopy(progress_payload["extra"])
        assert isinstance(fact_extra, dict)
        assert isinstance(progress_extra, dict)
        fact_extra["forensic_assertion_state"] = _marker(
            binding,
            object_kind="executed_fact",
            object_id=fact_id,
            record=fact_payload,
        )
        progress_extra["forensic_assertion_state"] = _marker(
            binding,
            object_kind="progress_marker",
            object_id=progress_id,
            record=progress_payload,
        )
        fact = Fact(
            id=fact_id,
            statement=fact_payload["statement"],
            provenance=Provenance.EXECUTED,
            kind=FactKind.OBSERVATION,
            challenge_id=identity["challenge_id"],
            source_run_id=fact_payload["source_run_id"],
            artifact_id=fact_payload["artifact_id"],
            locator=None,
            created_at=evaluated_at,
            extra=fact_extra,
        )
        progress = ProgressMarker(
            id=progress_id,
            statement=progress_payload["statement"],
            created_at=evaluated_at,
            run_id=progress_payload["run_id"],
            artifact_ids=list(progress_payload["artifact_ids"]),
            extra=progress_extra,
        )

    evidence_run_ids = [
        record["execution_record"]["run_id"] for record in records
    ]
    evidence_receipt_ids = [
        record["execution_record"]["receipt_id"] for record in records
    ]
    artifact_ids = [
        artifact["artifact_id"] for artifact in artifacts_binding
    ]
    reason_codes = evaluation_binding["reason_codes"]
    assert isinstance(reason_codes, list)
    experiment = Experiment(
        id=experiment_id,
        hypothesis_ids=list(experiment_binding["hypothesis_ids"]),
        command="engine:forensic-assertion-execution:v1",
        expected_observation=(
            "typed indexed evidence pointers corroborated by independent "
            "ready tool families"
        ),
        keep_if=(
            "transport and deterministic Forensic assertion graph confirm"
        ),
        drop_if="any source, readiness, transport, or graph binding rejects",
        timeout_seconds=experiment_binding["timeout_seconds"],
        resource_class="forensics",
        kind=ExperimentKind.PROBE,
        status=(
            ExperimentStatus.COMPLETED
            if confirmed
            else ExperimentStatus.INCONCLUSIVE
        ),
        result={
            "forensic_assertion_state": {
                "binding": copy.deepcopy(binding),
                "binding_sha256": binding_sha256,
                "protocol": FORENSIC_ASSERTION_STATE_PROTOCOL,
            }
        },
        source_run_id=(
            evidence_run_ids[-1] if evidence_run_ids else None
        ),
        artifact_ids=artifact_ids,
        evidence_fact_ids=([fact.id] if fact is not None else []),
        evidence_run_ids=evidence_run_ids,
        evidence_receipt_ids=evidence_receipt_ids,
        evaluation_reason=(
            "forensic_assertion_execution:"
            + str(evaluation_binding["verdict"])
            + (
                ":" + reason_codes[0]
                if reason_codes
                else ":confirmed"
            )
        )[:512],
        evaluated_at=evaluated_at,
        created_at=evaluated_at,
        extra={
            "engine_executor": FORENSIC_ASSERTION_STATE_EXECUTOR,
            "forensic_assertion_state": _marker(
                binding,
                object_kind="experiment",
                object_id=experiment_id,
                record={"binding_sha256": binding_sha256},
            ),
        },
    )
    projection = ForensicAssertionStateProjection(
        binding=copy.deepcopy(binding),
        experiment=experiment,
        runs=tuple(runs),
        receipts=tuple(receipts),
        artifacts=tuple(artifacts),
        fact=fact,
        progress=progress,
    )
    projection.canonical_bytes
    return projection


def _validate_timestamp_document(
    value: object,
    code: str,
    *,
    expected_kind: str | None = None,
) -> dict[str, object]:
    timestamp = _exact_dict(value, _TIMESTAMP_KEYS, code)
    kind = timestamp["timestamp_kind"]
    local = timestamp["source_local_epoch_ns"]
    offset = timestamp["source_utc_offset_minutes"]
    normalized = timestamp["normalized_utc_epoch_ns"]
    precision = timestamp["precision_ns"]
    if (
        type(kind) is not str
        or kind not in FORENSIC_TIMESTAMP_KINDS
        or (expected_kind is not None and kind != expected_kind)
        or not _exact_int(local, minimum=-(2**63))
        or not _exact_int(offset, minimum=-840, maximum=840)
        or not _exact_int(normalized, minimum=-(2**63))
        or not _exact_int(
            precision,
            minimum=1,
            maximum=86_400 * 1_000_000_000,
        )
        or timestamp["normalized_timezone"] != "UTC"
        or normalized != local - offset * 60 * 1_000_000_000
        or normalized % precision != 0
    ):
        raise ForensicAssertionStateContractError(code)
    return timestamp


def _validate_pointer_document(
    value: object,
    code: str,
) -> dict[str, object]:
    if type(value) is not dict or type(value.get("kind")) is not str:
        raise ForensicAssertionStateContractError(code)
    kind = value["kind"]
    keys = _POINTER_KEYS.get(kind)
    if keys is None:
        raise ForensicAssertionStateContractError(code)
    pointer = _exact_dict(value, keys, code)
    if (
        not _safe_id(pointer["pointer_id"])
        or not _safe_path(pointer["source_path"])
        or not _valid_sha256(pointer["source_sha256"])
    ):
        raise ForensicAssertionStateContractError(code)
    if kind == "file_range":
        valid = (
            _exact_int(pointer["offset_bytes"])
            and _exact_int(pointer["length_bytes"], minimum=1)
        )
    elif kind == "inode":
        valid = (
            _exact_int(pointer["partition_offset_bytes"])
            and _exact_int(pointer["inode_number"], minimum=1)
            and _exact_int(
                pointer["metadata_offset_bytes"],
                minimum=pointer["partition_offset_bytes"],
            )
            and _exact_int(pointer["metadata_length_bytes"], minimum=1)
            and _valid_sha256(pointer["metadata_sha256"])
        )
    elif kind == "pcap_frame":
        valid = (
            _exact_int(pointer["frame_number"], minimum=1)
            and _exact_int(pointer["packet_offset_bytes"])
            and _exact_int(pointer["captured_length_bytes"], minimum=1)
            and _exact_int(
                pointer["original_length_bytes"],
                minimum=pointer["captured_length_bytes"],
                maximum=2**32 - 1,
            )
            and _valid_sha256(pointer["packet_sha256"])
        )
        _validate_timestamp_document(
            pointer["timestamp"],
            code,
            expected_kind="packet_capture",
        )
    elif kind == "process":
        valid = (
            _exact_int(
                pointer["pid"],
                minimum=1,
                maximum=2**32 - 1,
            )
            and _exact_int(
                pointer["virtual_address"],
                maximum=2**64 - 1,
            )
            and _exact_int(pointer["object_offset_bytes"])
            and _exact_int(pointer["object_length_bytes"], minimum=1)
            and _valid_sha256(pointer["object_sha256"])
        )
        _validate_timestamp_document(
            pointer["process_start"],
            code,
            expected_kind="process_start",
        )
    else:
        valid = (
            _exact_int(pointer["field_offset_bytes"])
            and _exact_int(pointer["field_length_bytes"], minimum=1)
            and _valid_sha256(pointer["field_sha256"])
        )
        _validate_timestamp_document(pointer["timestamp"], code)
    if not valid:
        raise ForensicAssertionStateContractError(code)
    return pointer


def _validate_index_root(value: object) -> dict[str, object]:
    root = _exact_dict(
        value,
        _INDEX_ROOT_KEYS,
        "state_binding_index_root_invalid",
    )
    artifact = _exact_dict(
        root["index_artifact"],
        _INDEX_ARTIFACT_KEYS,
        "state_binding_index_root_invalid",
    )
    if (
        any(
            not _valid_sha256(root[key])
            for key in (
                "evidence_index_sha256",
                "evidence_tree_sha256",
                "index_execution_envelope_sha256",
                "index_execution_evaluation_sha256",
                "source_inventory_sha256",
                "source_manifest_sha256",
            )
        )
        or not _safe_id(root["index_run_id"])
        or not _safe_id(root["index_receipt_id"])
        or not _safe_id(artifact["artifact_id"])
        or not _valid_sha256(artifact["sha256"])
        or not _exact_int(
            artifact["size_bytes"],
            minimum=1,
            maximum=FORENSIC_ASSERTION_MAX_ARTIFACT_BYTES,
        )
        or not _exact_int(root["source_file_count"], minimum=1)
        or not _exact_int(root["source_total_bytes"])
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_index_root_invalid"
        )
    return root


def _validate_readiness_document(
    value: object,
) -> dict[str, object]:
    tool = _exact_dict(
        value,
        _READINESS_KEYS,
        "state_binding_readiness_invalid",
    )
    artifact = _exact_dict(
        tool["readiness_artifact"],
        _READINESS_ARTIFACT_KEYS,
        "state_binding_readiness_invalid",
    )
    template = tool["command_template"]
    kinds = tool["supported_pointer_kinds"]
    try:
        invalid = (
            not _safe_id(tool["tool_id"])
            or not _safe_id(tool["independence_family"])
            or not _valid_sha256(tool["tool_version_sha256"])
            or not _valid_image_digest(tool["runtime_image_digest"])
            or type(kinds) is not list
            or not kinds
            or kinds != sorted(set(kinds))
            or any(
                type(kind) is not str
                or kind not in FORENSIC_POINTER_KINDS
                for kind in kinds
            )
            or type(template) is not list
            or not 4 <= len(template) <= 32
            or any(
                type(token) is not str
                or not token
                or len(token.encode("utf-8", errors="strict")) > 256
                for token in template
            )
            or tool["readiness_status"] != "ready"
            or not _exact_int(tool["readiness_generation"])
            or not _safe_id(artifact["artifact_id"])
            or not _valid_sha256(artifact["sha256"])
            or not _exact_int(artifact["size_bytes"], minimum=1)
        )
        if not invalid:
            candidate = ForensicToolReadiness(
                tool_id=tool["tool_id"],
                independence_family=tool["independence_family"],
                tool_version_sha256=tool["tool_version_sha256"],
                runtime_image_digest=tool["runtime_image_digest"],
                supported_pointer_kinds=tuple(kinds),
                command_template=tuple(template),
                readiness_generation=tool["readiness_generation"],
                readiness_artifact_id=artifact["artifact_id"],
                readiness_artifact_sha256=artifact["sha256"],
                readiness_artifact_size_bytes=artifact["size_bytes"],
            )
            forensic_tool_readiness_registry_sha256((candidate,))
    except (
        ForensicAssertionExecutionPreflightError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as error:
        raise ForensicAssertionStateContractError(
            "state_binding_readiness_invalid"
        ) from error
    if invalid:
        raise ForensicAssertionStateContractError(
            "state_binding_readiness_invalid"
        )
    return tool


def _validate_operator_document(
    value: object,
) -> dict[str, object]:
    operator = _exact_dict(
        value,
        _OPERATOR_KEYS,
        "state_binding_operator_spec_invalid",
    )
    if (
        operator["protocol"]
        != FORENSIC_ASSERTION_OPERATOR_SPEC_PROTOCOL
        or type(operator["schema_version"]) is not int
        or operator["schema_version"] != 1
        or not _valid_sha256(operator["readiness_registry_sha256"])
        or not _valid_sha256(operator["source_catalog_sha256"])
        or not _exact_int(
            operator["coverage_threshold_ppm"],
            minimum=FORENSIC_ASSERTION_MIN_COVERAGE_PPM,
            maximum=1_000_000,
        )
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_operator_spec_invalid"
        )
    _validate_index_root(operator["index_root"])
    tools_raw = operator["tools"]
    pointers_raw = operator["pointers"]
    assertions_raw = operator["assertions"]
    if (
        type(tools_raw) is not list
        or not tools_raw
        or type(pointers_raw) is not list
        or not pointers_raw
        or type(assertions_raw) is not list
        or not assertions_raw
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_operator_spec_invalid"
        )
    tools = [_validate_readiness_document(item) for item in tools_raw]
    pointers = [
        _validate_pointer_document(
            item,
            "state_binding_pointer_invalid",
        )
        for item in pointers_raw
    ]
    tool_ids = [item["tool_id"] for item in tools]
    pointer_ids = [item["pointer_id"] for item in pointers]
    if (
        tool_ids != sorted(tool_ids)
        or len(set(tool_ids)) != len(tool_ids)
        or len(set(pointer_ids)) != len(pointer_ids)
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_operator_spec_invalid"
        )
    assertion_ids: list[str] = []
    claim_hashes: list[str] = []
    referenced: set[str] = set()
    dependencies: dict[str, list[str]] = {}
    for raw in assertions_raw:
        assertion = _exact_dict(
            raw,
            _ASSERTION_KEYS,
            "state_binding_assertion_invalid",
        )
        depends_on = assertion["depends_on"]
        evidence_ids = assertion["evidence_pointer_ids"]
        if (
            not _safe_id(assertion["assertion_id"])
            or assertion["state"]
            not in {
                ForensicAssertionState.HYPOTHESIS.value,
                ForensicAssertionState.CONFIRMED.value,
            }
            or assertion["claim_kind"] not in FORENSIC_CLAIM_KINDS
            or not _valid_sha256(assertion["claim_sha256"])
            or type(depends_on) is not list
            or depends_on != sorted(set(depends_on))
            or any(not _safe_id(item) for item in depends_on)
            or type(evidence_ids) is not list
            or evidence_ids != sorted(set(evidence_ids))
            or any(item not in pointer_ids for item in evidence_ids)
            or (
                assertion["state"]
                == ForensicAssertionState.CONFIRMED.value
                and not evidence_ids
            )
        ):
            raise ForensicAssertionStateContractError(
                "state_binding_assertion_invalid"
            )
        assertion_ids.append(assertion["assertion_id"])
        claim_hashes.append(assertion["claim_sha256"])
        dependencies[assertion["assertion_id"]] = list(depends_on)
        referenced.update(evidence_ids)
    if (
        len(set(assertion_ids)) != len(assertion_ids)
        or len(set(claim_hashes)) != len(claim_hashes)
        or any(
            dependency not in assertion_ids
            for values in dependencies.values()
            for dependency in values
        )
        or referenced != set(pointer_ids)
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_assertion_invalid"
        )
    states = {
        assertion["assertion_id"]: assertion["state"]
        for assertion in assertions_raw
    }
    if any(
        states[assertion_id]
        == ForensicAssertionState.CONFIRMED.value
        and any(
            states[dependency]
            != ForensicAssertionState.CONFIRMED.value
            for dependency in dependencies[assertion_id]
        )
        for assertion_id in assertion_ids
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_assertion_invalid"
        )
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(assertion_id: str) -> None:
        if assertion_id in visited:
            return
        if assertion_id in visiting:
            raise ForensicAssertionStateContractError(
                "state_binding_assertion_invalid"
            )
        visiting.add(assertion_id)
        for dependency in dependencies[assertion_id]:
            visit(dependency)
        visiting.remove(assertion_id)
        visited.add(assertion_id)

    for assertion_id in assertion_ids:
        visit(assertion_id)
    return operator


def _validate_plan_document(
    value: object,
) -> dict[str, object]:
    plan = _exact_dict(
        value,
        _PLAN_KEYS,
        "state_binding_plan_invalid",
    )
    operator = _validate_operator_document(plan["operator_spec"])
    index_root = _validate_index_root(plan["index_root"])
    if (
        any(
            not _valid_sha256(plan[key])
            for key in (
                "assertion_graph_plan_sha256",
                "execution_plan_sha256",
                "operator_spec_sha256",
                "readiness_registry_sha256",
                "source_catalog_sha256",
            )
        )
        or not _exact_int(
            plan["execution_plan_size_bytes"],
            minimum=1,
            maximum=32 * 1024 * 1024,
        )
        or not _exact_int(
            plan["operator_spec_size_bytes"],
            minimum=1,
            maximum=FORENSIC_ASSERTION_OPERATOR_SPEC_MAX_BYTES,
        )
        or plan["index_root"] != operator["index_root"]
        or plan["readiness_registry_sha256"]
        != operator["readiness_registry_sha256"]
        or plan["source_catalog_sha256"]
        != operator["source_catalog_sha256"]
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_plan_invalid"
        )
    pointers_raw = plan["pointers"]
    if (
        type(pointers_raw) is not list
        or len(pointers_raw) != len(operator["pointers"])
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_plan_pointers_invalid"
        )
    operator_by_id = {
        item["pointer_id"]: item for item in operator["pointers"]
    }
    pointer_ids: list[str] = []
    for raw in pointers_raw:
        entry = _exact_dict(
            raw,
            frozenset({"pointer", "sha256"}),
            "state_binding_plan_pointers_invalid",
        )
        pointer = _validate_pointer_document(
            entry["pointer"],
            "state_binding_plan_pointers_invalid",
        )
        pointer_id = pointer["pointer_id"]
        if (
            pointer != operator_by_id.get(pointer_id)
            or not _valid_sha256(entry["sha256"])
            or entry["sha256"]
            != _sha256(_canonical_json_bytes(pointer))
        ):
            raise ForensicAssertionStateContractError(
                "state_binding_plan_pointers_invalid"
            )
        pointer_ids.append(pointer_id)
    if pointer_ids != sorted(pointer_ids):
        raise ForensicAssertionStateContractError(
            "state_binding_plan_pointers_invalid"
        )
    readiness_document = {
        "kind": "complete_current_forensic_tool_readiness_v1",
        "tools": operator["tools"],
    }
    graph_tools = [
        {
            "independence_family": tool["independence_family"],
            "runtime_image_digest": tool["runtime_image_digest"],
            "supported_pointer_kinds": tool[
                "supported_pointer_kinds"
            ],
            "tool_id": tool["tool_id"],
            "tool_version_sha256": tool["tool_version_sha256"],
        }
        for tool in operator["tools"]
    ]
    graph_plan_document = {
        "assertions": sorted(
            operator["assertions"],
            key=lambda item: item["assertion_id"],
        ),
        "coverage_policy": {
            "coverage_basis": "corroborated_pointer_count",
            "corroboration_scope": "per_pointer",
            "independent_tool_families_when_available": 2,
            "minimum_coverage_ppm": operator[
                "coverage_threshold_ppm"
            ],
            "single_family_fallback_only_when_registry_has_one": True,
        },
        "inventory_root": operator["index_root"],
        "pointers": [
            entry["pointer"] for entry in plan["pointers"]
        ],
        "protocol": FORENSIC_ASSERTION_GRAPH_PROTOCOL,
        "schema_version": 1,
        "source_catalog_sha256": operator[
            "source_catalog_sha256"
        ],
        "tools": graph_tools,
    }
    if (
        operator["readiness_registry_sha256"]
        != _sha256(_canonical_json_bytes(readiness_document))
        or plan["assertion_graph_plan_sha256"]
        != _sha256(_canonical_json_bytes(graph_plan_document))
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_plan_commitment_invalid"
        )
    assert isinstance(index_root, dict)
    return plan


def _validate_preissued_document(
    value: object,
    *,
    plan: dict[str, object],
) -> dict[str, object]:
    request = _exact_dict(
        value,
        _PREISSUED_KEYS,
        "state_binding_preissued_request_invalid",
    )
    artifact = _exact_dict(
        request["artifact"],
        _PREISSUED_ARTIFACT_KEYS,
        "state_binding_preissued_request_invalid",
    )
    command = _exact_dict(
        request["command"],
        _PREISSUED_COMMAND_KEYS,
        "state_binding_preissued_request_invalid",
    )
    observation = _exact_dict(
        request["observation"],
        _PREISSUED_OBSERVATION_KEYS,
        "state_binding_preissued_request_invalid",
    )
    source = _exact_dict(
        request["source"],
        _PREISSUED_SOURCE_KEYS,
        "state_binding_preissued_request_invalid",
    )
    tool = _exact_dict(
        request["tool"],
        _PREISSUED_TOOL_KEYS,
        "state_binding_preissued_request_invalid",
    )
    transport = _exact_dict(
        request["transport_contract"],
        _PREISSUED_TRANSPORT_KEYS,
        "state_binding_preissued_request_invalid",
    )
    pointer_raw = request["pointer"]
    if type(pointer_raw) is not dict or "sha256" not in pointer_raw:
        raise ForensicAssertionStateContractError(
            "state_binding_preissued_request_invalid"
        )
    pointer = dict(pointer_raw)
    pointer_sha256 = pointer.pop("sha256")
    pointer = _validate_pointer_document(
        pointer,
        "state_binding_preissued_pointer_invalid",
    )
    operator = plan["operator_spec"]
    index_root = plan["index_root"]
    assert isinstance(operator, dict)
    assert isinstance(index_root, dict)
    readiness_by_id = {
        item["tool_id"]: item for item in operator["tools"]
    }
    pointer_by_id = {
        item["pointer_id"]: item for item in operator["pointers"]
    }
    ready = readiness_by_id.get(tool["tool_id"])
    ids = (
        request["request_id"],
        request["run_id"],
        observation["observation_id"],
        observation["receipt_id"],
        artifact["artifact_id"],
    )
    argv = command["argv"]
    if (
        request["protocol"] != FORENSIC_ASSERTION_EXECUTION_PROTOCOL
        or type(request["schema_version"]) is not int
        or request["schema_version"] != 1
        or any(not _safe_id(item) for item in ids)
        or len(set(ids)) != len(ids)
        or not _safe_path(request["request_path"])
        or not _safe_path(observation["path"])
        or not _safe_path(artifact["path"])
        or request["request_path"]
        != (
            f"runs/{request['run_id']}/"
            "forensic-assertion/request.json"
        )
        or observation["path"]
        != (
            "artifacts/forensic-assertion-observations/"
            f"{observation['observation_id']}.json"
        )
        or artifact["path"]
        != (
            "artifacts/forensic-assertion-tool-output/"
            f"{artifact['artifact_id']}.bin"
        )
        or artifact["maximum_size_bytes"]
        != FORENSIC_ASSERTION_MAX_ARTIFACT_BYTES
        or type(argv) is not list
        or not argv
        or any(type(item) is not str or not item for item in argv)
        or not _valid_sha256(command["argv_sha256"])
        or command["argv_sha256"]
        != _sha256(_canonical_json_bytes(argv))
        or not _valid_sha256(command["template_sha256"])
        or not _valid_sha256(request["execution_nonce_sha256"])
        or not _valid_sha256(
            request["semantic_execution_contract_sha256"]
        )
        or not _valid_sha256(
            transport["transport_execution_contract_sha256"]
        )
        or request["operator_spec_sha256"]
        != plan["operator_spec_sha256"]
        or request["plan_sha256"]
        != plan["assertion_graph_plan_sha256"]
        or request["readiness_registry_sha256"]
        != plan["readiness_registry_sha256"]
        or request["index_execution_evaluation_sha256"]
        != index_root["index_execution_evaluation_sha256"]
        or source
        != {
            "evidence_root": "/challenge",
            "evidence_root_access": "read_only",
            "inventory_sha256": index_root[
                "source_inventory_sha256"
            ],
            "manifest_sha256": index_root["source_manifest_sha256"],
        }
        or transport["artifact_capture"]
        != "complete_exact_bytes"
        or transport["evidence_access"] != "read_only"
        or transport["network"] != "none"
        or transport["observation_document"]
        != "canonical_value_free_json"
        or transport["workspace"] != "fresh"
        or pointer_by_id.get(pointer["pointer_id"]) != pointer
        or not _valid_sha256(pointer_sha256)
        or pointer_sha256 != _sha256(_canonical_json_bytes(pointer))
        or ready is None
        or tool
        != {
            "independence_family": ready["independence_family"],
            "runtime_image_digest": ready["runtime_image_digest"],
            "tool_id": ready["tool_id"],
            "tool_version_sha256": ready["tool_version_sha256"],
        }
        or pointer["kind"] not in ready["supported_pointer_kinds"]
        or command["template_sha256"]
        != _sha256(
            _canonical_json_bytes(ready["command_template"])
        )
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_preissued_request_invalid"
        )
    replacements = {
        "{request_path}": request["request_path"],
        "{observation_path}": observation["path"],
        "{artifact_path}": artifact["path"],
    }
    expected_argv = [
        replacements.get(token, token)
        for token in ready["command_template"]
    ]
    if argv != expected_argv:
        raise ForensicAssertionStateContractError(
            "state_binding_preissued_command_rebound"
        )
    request_body = copy.deepcopy(request)
    request_sha256 = request_body.pop("request_sha256")
    request_size_bytes = request_body.pop("request_size_bytes")
    request_payload = _canonical_json_bytes(request_body)
    if (
        not _valid_sha256(request_sha256)
        or request_sha256 != _sha256(request_payload)
        or not _exact_int(
            request_size_bytes,
            minimum=1,
            maximum=1024 * 1024,
        )
        or request_size_bytes != len(request_payload)
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_preissued_request_commitment_invalid"
        )
    return request


def _validate_artifact_binding(
    value: object,
) -> dict[str, object]:
    artifact = _exact_dict(
        value,
        _ARTIFACT_KEYS,
        "state_binding_artifact_invalid",
    )
    if (
        not _safe_id(artifact["artifact_id"])
        or artifact["role"] not in _ARTIFACT_ROLES
        or artifact["context_visibility"] != "engine_private"
        or artifact["media_type"]
        not in {"application/json", "application/octet-stream"}
        or not _safe_path(artifact["path"])
        or not _valid_sha256(artifact["sha256"])
        or not _exact_int(
            artifact["size_bytes"],
            minimum=1,
            maximum=32 * 1024 * 1024,
        )
        or (
            artifact["source_run_id"] is not None
            and not _safe_id(artifact["source_run_id"])
        )
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_artifact_invalid"
        )
    return artifact


def _validate_binding_document(
    binding: object,
) -> dict[str, object]:
    root = _exact_dict(
        binding,
        _ROOT_KEYS,
        "state_binding_schema_invalid",
    )
    if (
        root["protocol"] != FORENSIC_ASSERTION_STATE_PROTOCOL
        or type(root["schema_version"]) is not int
        or root["schema_version"]
        != FORENSIC_ASSERTION_STATE_SCHEMA_VERSION
        or not _exact_int(root["configuration_epoch"])
        or not _exact_int(root["base_revision"])
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_header_invalid"
        )
    identity = _exact_dict(
        root["identity"],
        _IDENTITY_KEYS,
        "state_binding_identity_invalid",
    )
    if (
        identity["category"] != "forensics"
        or any(
            type(identity[key]) is not str
            or not identity[key].strip()
            for key in _IDENTITY_KEYS
        )
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_identity_invalid"
        )
    experiment = _exact_dict(
        root["experiment"],
        _EXPERIMENT_KEYS,
        "state_binding_experiment_invalid",
    )
    hypothesis_ids = experiment["hypothesis_ids"]
    if (
        not _safe_id(experiment["id"])
        or type(hypothesis_ids) is not list
        or len(hypothesis_ids)
        > FORENSIC_ASSERTION_STATE_MAX_HYPOTHESES
        or any(not _safe_id(item) for item in hypothesis_ids)
        or len(set(hypothesis_ids)) != len(hypothesis_ids)
        or not _bounded_utc(experiment["evaluated_at"])
        or not _exact_int(
            experiment["timeout_seconds"],
            minimum=1,
            maximum=FORENSIC_ASSERTION_STATE_MAX_TIMEOUT_SECONDS,
        )
        or experiment["run_origin"]
        not in {item.value for item in _ALLOWED_RUN_ORIGINS}
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_experiment_invalid"
        )
    evaluation = _exact_dict(
        root["evaluation"],
        _EVALUATION_KEYS,
        "state_binding_evaluation_invalid",
    )
    if (
        type(evaluation["confirmed"]) is not bool
        or evaluation["verdict"]
        not in {
            ForensicAssertionExecutionVerdict.CONFIRMED.value,
            ForensicAssertionExecutionVerdict.REJECTED.value,
        }
        or not _valid_sha256(evaluation["execution_plan_sha256"])
        or not _valid_sha256(evaluation["sha256"])
        or not _exact_int(
            evaluation["size_bytes"],
            minimum=1,
            maximum=FORENSIC_ASSERTION_STATE_MAX_BINDING_BYTES,
        )
        or not _exact_int(
            evaluation["record_count"],
            maximum=FORENSIC_ASSERTION_MAX_OBSERVATIONS,
        )
        or (
            evaluation["semantic_evaluation_sha256"] is not None
            and not _valid_sha256(
                evaluation["semantic_evaluation_sha256"]
            )
        )
        or type(evaluation["reason_codes"]) is not list
        or len(evaluation["reason_codes"]) > 16
        or any(
            type(code) is not str
            or _REASON_CODE.fullmatch(code) is None
            for code in evaluation["reason_codes"]
        )
        or (
            evaluation["confirmed"]
            and (
                evaluation["verdict"]
                != ForensicAssertionExecutionVerdict.CONFIRMED.value
                or evaluation["reason_codes"]
                or evaluation["semantic_evaluation_sha256"] is None
            )
        )
        or (
            not evaluation["confirmed"]
            and (
                evaluation["verdict"]
                != ForensicAssertionExecutionVerdict.REJECTED.value
                or not evaluation["reason_codes"]
            )
        )
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_evaluation_invalid"
        )
    plan = _validate_plan_document(root["plan"])
    operator = plan["operator_spec"]
    index_root = plan["index_root"]
    assert isinstance(operator, dict)
    assert isinstance(index_root, dict)
    if (
        plan["operator_spec_sha256"]
        != _sha256(_canonical_json_bytes(operator))
        or plan["operator_spec_size_bytes"]
        != len(_canonical_json_bytes(operator))
        or plan["execution_plan_sha256"]
        != evaluation["execution_plan_sha256"]
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_plan_commitment_invalid"
        )
    authorities = root["authorities"]
    expected_authorities = {
        **_AUTHORITIES_FALSE,
        "executed_forensic_assertion_fact_authorized": (
            evaluation["confirmed"]
        ),
        "forensic_assertion_graph_confirmed": evaluation["confirmed"],
        "forensic_assertion_transport_confirmed": (
            evaluation["confirmed"]
        ),
        "progress_marker_authorized": evaluation["confirmed"],
    }
    if type(authorities) is not dict or authorities != expected_authorities:
        raise ForensicAssertionStateContractError(
            "state_binding_authority_widened"
        )
    state_ids = _exact_dict(
        root["state_ids"],
        _STATE_IDS_KEYS,
        "state_binding_ids_invalid",
    )
    ids = ForensicAssertionStateIds(
        experiment_id=experiment["id"],
        operator_spec_artifact_id=state_ids[
            "operator_spec_artifact_id"
        ],
        plan_artifact_id=state_ids["plan_artifact_id"],
        evaluation_artifact_id=state_ids[
            "evaluation_artifact_id"
        ],
        fact_id=state_ids["fact_id"],
        progress_id=state_ids["progress_id"],
    )
    _validate_state_ids(ids, confirmed=evaluation["confirmed"])

    preissued_raw = root["preissued_requests"]
    if (
        type(preissued_raw) is not list
        or not preissued_raw
        or len(preissued_raw) > FORENSIC_ASSERTION_MAX_OBSERVATIONS
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_preissued_requests_invalid"
        )
    preissued = [
        _validate_preissued_document(item, plan=plan)
        for item in preissued_raw
    ]
    all_preissued_ids: list[str] = []
    request_hashes: list[str] = []
    nonce_hashes: list[str] = []
    transport_hashes: list[str] = []
    actual_pairs: list[tuple[str, str]] = []
    for request in preissued:
        observation = request["observation"]
        artifact = request["artifact"]
        pointer = request["pointer"]
        tool = request["tool"]
        transport = request["transport_contract"]
        assert isinstance(observation, dict)
        assert isinstance(artifact, dict)
        assert isinstance(pointer, dict)
        assert isinstance(tool, dict)
        assert isinstance(transport, dict)
        all_preissued_ids.extend(
            (
                request["request_id"],
                request["run_id"],
                observation["observation_id"],
                observation["receipt_id"],
                artifact["artifact_id"],
            )
        )
        request_hashes.append(request["request_sha256"])
        nonce_hashes.append(request["execution_nonce_sha256"])
        transport_hashes.append(
            transport["transport_execution_contract_sha256"]
        )
        actual_pairs.append((pointer["pointer_id"], tool["tool_id"]))
    if (
        len(set(all_preissued_ids)) != len(all_preissued_ids)
        or len(set(request_hashes)) != len(request_hashes)
        or len(set(nonce_hashes)) != len(nonce_hashes)
        or len(set(transport_hashes)) != len(transport_hashes)
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_preissued_identifier_reused"
        )
    readiness = operator["tools"]
    expected_pairs: list[tuple[str, str]] = []
    for pointer_entry in plan["pointers"]:
        pointer = pointer_entry["pointer"]
        by_family: dict[str, list[dict[str, object]]] = {}
        for tool in readiness:
            if pointer["kind"] in tool["supported_pointer_kinds"]:
                by_family.setdefault(
                    tool["independence_family"],
                    [],
                ).append(tool)
        for family in sorted(by_family)[:2]:
            selected = min(
                by_family[family],
                key=lambda item: item["tool_id"],
            )
            expected_pairs.append(
                (pointer["pointer_id"], selected["tool_id"])
            )
    if actual_pairs != expected_pairs:
        raise ForensicAssertionStateContractError(
            "state_binding_preissued_family_selection_rebound"
        )
    specification_document = {
        "index_execution_evaluation_sha256": index_root[
            "index_execution_evaluation_sha256"
        ],
        "operator_spec_sha256": plan["operator_spec_sha256"],
        "operator_spec_size_bytes": plan["operator_spec_size_bytes"],
        "plan_sha256": plan["assertion_graph_plan_sha256"],
        "protocol": FORENSIC_ASSERTION_EXECUTION_PROTOCOL,
        "readiness_registry_sha256": plan[
            "readiness_registry_sha256"
        ],
        "schema_version": 1,
        "source_catalog_sha256": plan["source_catalog_sha256"],
        "source_inventory_sha256": index_root[
            "source_inventory_sha256"
        ],
        "source_manifest_sha256": index_root[
            "source_manifest_sha256"
        ],
        "tool_count": len(readiness),
    }
    execution_plan_document = {
        "operator_spec_sha256": plan["operator_spec_sha256"],
        "plan_sha256": plan["assertion_graph_plan_sha256"],
        "protocol": FORENSIC_ASSERTION_EXECUTION_PROTOCOL,
        "readiness_registry_sha256": plan[
            "readiness_registry_sha256"
        ],
        "requests": [
            {
                **{
                    key: copy.deepcopy(value)
                    for key, value in request.items()
                    if key
                    not in {"request_sha256", "request_size_bytes"}
                },
                "request_sha256": request["request_sha256"],
            }
            for request in preissued
        ],
        "schema_version": 1,
        "specification_sha256": _sha256(
            _canonical_json_bytes(specification_document)
        ),
    }
    execution_plan_payload = _canonical_json_bytes(
        execution_plan_document
    )
    if (
        plan["execution_plan_sha256"]
        != _sha256(execution_plan_payload)
        or plan["execution_plan_size_bytes"]
        != len(execution_plan_payload)
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_execution_plan_commitment_invalid"
        )

    declared_state_ids = [
        experiment["id"],
        state_ids["operator_spec_artifact_id"],
        state_ids["plan_artifact_id"],
        state_ids["evaluation_artifact_id"],
    ]
    if state_ids["fact_id"] is not None:
        declared_state_ids.append(state_ids["fact_id"])
    if state_ids["progress_id"] is not None:
        declared_state_ids.append(state_ids["progress_id"])
    anchor_ids = [
        index_root["index_run_id"],
        index_root["index_receipt_id"],
        index_root["index_artifact"]["artifact_id"],
        *[
            item["readiness_artifact"]["artifact_id"]
            for item in readiness
        ],
    ]
    if (
        len(set(declared_state_ids + all_preissued_ids))
        != len(declared_state_ids) + len(all_preissued_ids)
        or len(set(anchor_ids)) != len(anchor_ids)
        or set(anchor_ids)
        & set(declared_state_ids + all_preissued_ids)
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_global_identifier_reused"
        )

    artifacts_raw = root["artifacts"]
    records_raw = root["records"]
    if (
        type(records_raw) is not list
        or len(records_raw) != evaluation["record_count"]
        or len(records_raw) > len(preissued)
        or (
            evaluation["confirmed"]
            and len(records_raw) != len(preissued)
        )
        or type(artifacts_raw) is not list
        or len(artifacts_raw)
        != 3 + len(preissued) + 2 * len(records_raw)
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_record_or_artifact_count_invalid"
        )
    artifacts = [
        _validate_artifact_binding(item) for item in artifacts_raw
    ]
    artifact_ids = [item["artifact_id"] for item in artifacts]
    if (
        len(set(artifact_ids)) != len(artifact_ids)
        or artifact_ids[:3]
        != [
            state_ids["operator_spec_artifact_id"],
            state_ids["plan_artifact_id"],
            state_ids["evaluation_artifact_id"],
        ]
        or [item["role"] for item in artifacts[:3]]
        != [
            "operator_spec",
            "execution_plan",
            "execution_evaluation",
        ]
        or artifacts[0]["sha256"] != plan["operator_spec_sha256"]
        or artifacts[0]["size_bytes"]
        != plan["operator_spec_size_bytes"]
        or artifacts[1]["sha256"]
        != plan["execution_plan_sha256"]
        or artifacts[1]["size_bytes"]
        != plan["execution_plan_size_bytes"]
        or artifacts[2]["sha256"] != evaluation["sha256"]
        or artifacts[2]["size_bytes"] != evaluation["size_bytes"]
        or artifacts[0]["source_run_id"] is not None
        or artifacts[1]["source_run_id"] is not None
        or any(
            item["media_type"] != "application/json"
            for item in artifacts[:3]
        )
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_primary_artifact_invalid"
        )
    request_artifacts = artifacts[3 : 3 + len(preissued)]
    for request, artifact in zip(
        preissued,
        request_artifacts,
        strict=True,
    ):
        if (
            artifact
            != {
                "artifact_id": request["request_id"],
                "context_visibility": "engine_private",
                "media_type": "application/json",
                "path": request["request_path"],
                "role": "preissued_request",
                "sha256": request["request_sha256"],
                "size_bytes": request["request_size_bytes"],
                "source_run_id": None,
            }
        ):
            raise ForensicAssertionStateContractError(
                "state_binding_request_artifact_rebound"
            )

    flattened: list[dict[str, object]] = []
    record_run_ids: list[str] = []
    record_receipt_ids: list[str] = []
    record_families: dict[str, set[str]] = {
        entry["pointer"]["pointer_id"]: set()
        for entry in plan["pointers"]
    }
    total_capture_bytes = 0
    for position, (raw_record, request) in enumerate(
        zip(records_raw, preissued, strict=False),
        start=1,
    ):
        record = _exact_dict(
            raw_record,
            _RECORD_KEYS,
            "state_binding_record_invalid",
        )
        execution_record = _exact_dict(
            record["execution_record"],
            _EXECUTION_RECORD_KEYS,
            "state_binding_execution_record_invalid",
        )
        output = _exact_dict(
            execution_record["artifact"],
            _EXECUTION_ARTIFACT_KEYS,
            "state_binding_execution_record_invalid",
        )
        observation = _exact_dict(
            execution_record["observation_document"],
            _EXECUTION_OBSERVATION_KEYS,
            "state_binding_execution_record_invalid",
        )
        observation_artifact = _validate_artifact_binding(
            record["observation_document_artifact"]
        )
        output_artifact = _validate_artifact_binding(
            record["tool_output_artifact"]
        )
        pre_observation = request["observation"]
        pre_artifact = request["artifact"]
        pre_pointer = request["pointer"]
        pre_tool = request["tool"]
        assert isinstance(pre_observation, dict)
        assert isinstance(pre_artifact, dict)
        assert isinstance(pre_pointer, dict)
        assert isinstance(pre_tool, dict)
        result_path, validation_path = _run_paths(
            execution_record["run_id"]
        )
        if (
            execution_record["request_id"] != request["request_id"]
            or execution_record["request_sha256"]
            != request["request_sha256"]
            or execution_record["request_path"]
            != request["request_path"]
            or execution_record["run_id"] != request["run_id"]
            or execution_record["receipt_id"]
            != pre_observation["receipt_id"]
            or execution_record["observation_document"][
                "observation_id"
            ]
            != pre_observation["observation_id"]
            or execution_record["observation_document"]["path"]
            != pre_observation["path"]
            or execution_record["pointer_id"]
            != pre_pointer["pointer_id"]
            or execution_record["pointer_sha256"]
            != pre_pointer["sha256"]
            or execution_record["tool_id"] != pre_tool["tool_id"]
            or execution_record["independence_family"]
            != pre_tool["independence_family"]
            or output["artifact_id"] != pre_artifact["artifact_id"]
            or output["path"] != pre_artifact["path"]
            or not _valid_sha256(output["sha256"])
            or not _exact_int(
                output["size_bytes"],
                minimum=1,
                maximum=FORENSIC_ASSERTION_MAX_ARTIFACT_BYTES,
            )
            or not _valid_sha256(observation["sha256"])
            or not _exact_int(
                observation["size_bytes"],
                minimum=1,
                maximum=1024 * 1024,
            )
            or execution_record["receipt_sha256"]
            != observation["sha256"]
            or not _exact_number(record["wall_seconds"])
            or record["result_path"] != result_path
            or record["validation_path"] != validation_path
            or record["transport_receipt_path"]
            != observation["path"]
            or observation_artifact
            != {
                "artifact_id": observation["observation_id"],
                "context_visibility": "engine_private",
                "media_type": "application/json",
                "path": observation["path"],
                "role": "observation_document",
                "sha256": observation["sha256"],
                "size_bytes": observation["size_bytes"],
                "source_run_id": execution_record["run_id"],
            }
            or output_artifact
            != {
                "artifact_id": output["artifact_id"],
                "context_visibility": "engine_private",
                "media_type": "application/octet-stream",
                "path": output["path"],
                "role": "tool_output",
                "sha256": output["sha256"],
                "size_bytes": output["size_bytes"],
                "source_run_id": execution_record["run_id"],
            }
        ):
            raise ForensicAssertionStateContractError(
                f"state_binding_record_{position}_rebound"
            )
        flattened.extend((observation_artifact, output_artifact))
        record_run_ids.append(execution_record["run_id"])
        record_receipt_ids.append(execution_record["receipt_id"])
        record_families[execution_record["pointer_id"]].add(
            execution_record["independence_family"]
        )
        total_capture_bytes += (
            observation["size_bytes"] + output["size_bytes"]
        )
    if (
        flattened != artifacts[3 + len(preissued) :]
        or len(set(record_run_ids)) != len(record_run_ids)
        or len(set(record_receipt_ids)) != len(record_receipt_ids)
        or total_capture_bytes
        > FORENSIC_ASSERTION_EXECUTION_MAX_CAPTURE_BYTES
        or artifacts[2]["source_run_id"]
        != (record_run_ids[-1] if record_run_ids else None)
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_record_set_invalid"
        )

    corroboration_raw = root["corroboration"]
    if (
        type(corroboration_raw) is not list
        or len(corroboration_raw) != len(plan["pointers"])
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_corroboration_invalid"
        )
    expected_corroboration: list[dict[str, object]] = []
    for pointer_entry in plan["pointers"]:
        pointer = pointer_entry["pointer"]
        available = sorted(
            {
                tool["independence_family"]
                for tool in readiness
                if pointer["kind"] in tool["supported_pointer_kinds"]
            }
        )
        required = 2 if len(available) >= 2 else 1
        observed = sorted(record_families[pointer["pointer_id"]])
        expected_corroboration.append(
            {
                "available_families": available,
                "covered": len(observed) >= required,
                "observed_families": observed,
                "pointer_id": pointer["pointer_id"],
                "pointer_kind": pointer["kind"],
                "required_family_count": required,
            }
        )
    for item in corroboration_raw:
        _exact_dict(
            item,
            _CORROBORATION_KEYS,
            "state_binding_corroboration_invalid",
        )
    if root["corroboration"] != expected_corroboration:
        raise ForensicAssertionStateContractError(
            "state_binding_corroboration_rebound"
        )

    reduction = _exact_dict(
        root["reduction"],
        _REDUCTION_KEYS,
        "state_binding_reduction_invalid",
    )
    if (
        reduction["automatic_submission"] is not False
        or reduction["candidate"] is not None
        or reduction["impact"] is not None
        or reduction["proof"] is not None
        or reduction["status_transition"] is not None
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_reduction_widened"
        )
    if evaluation["confirmed"]:
        fact = reduction["executed_fact"]
        progress = reduction["progress"]
        confirmed_assertions = [
            assertion
            for assertion in operator["assertions"]
            if assertion["state"]
            == ForensicAssertionState.CONFIRMED.value
        ]
        confirmed_pointer_ids = {
            pointer_id
            for assertion in confirmed_assertions
            for pointer_id in assertion["evidence_pointer_ids"]
        }
        confirmed_records = [
            record
            for record in records_raw
            if record["execution_record"]["pointer_id"]
            in confirmed_pointer_ids
        ]
        if not confirmed_records:
            raise ForensicAssertionStateContractError(
                "state_binding_confirmed_reduction_invalid"
            )
        first_record = confirmed_records[0]["execution_record"]
        expected_progress_artifacts = sorted(
            {
                record["execution_record"]["artifact"]["artifact_id"]
                for record in confirmed_records
            }
        )
        expected_progress_statement = (
            "Typed Forensic evidence pointers and independent "
            "corroboration satisfied the assertion graph gate"
        )
        if (
            type(fact) is not dict
            or set(fact)
            != {
                "artifact_id",
                "extra",
                "provenance",
                "source_run_id",
                "statement",
            }
            or fact["provenance"] != "executed"
            or fact["artifact_id"]
            != first_record["artifact"]["artifact_id"]
            or fact["source_run_id"] != first_record["run_id"]
            or type(fact["statement"]) is not str
            or type(fact["extra"]) is not dict
            or set(fact["extra"]) != {"forensic_assertion_graph"}
            or type(progress) is not dict
            or set(progress)
            != {
                "artifact_ids",
                "extra",
                "run_id",
                "statement",
            }
            or progress["run_id"] != first_record["run_id"]
            or type(progress["artifact_ids"]) is not list
            or progress["artifact_ids"]
            != expected_progress_artifacts
            or progress["statement"] != expected_progress_statement
            or progress["extra"] != fact["extra"]
        ):
            raise ForensicAssertionStateContractError(
                "state_binding_confirmed_reduction_invalid"
            )
        artifact_by_id = {
            artifact["artifact_id"]: artifact
            for artifact in artifacts
        }
        if (
            artifact_by_id[fact["artifact_id"]]["role"]
            != "tool_output"
            or any(
                artifact_by_id[artifact_id]["role"]
                != "tool_output"
                for artifact_id in progress["artifact_ids"]
            )
        ):
            raise ForensicAssertionStateContractError(
                "state_binding_confirmed_reduction_invalid"
            )
        reduction_binding = _exact_dict(
            fact["extra"]["forensic_assertion_graph"],
            _REDUCTION_BINDING_KEYS,
            "state_binding_reduction_evidence_invalid",
        )
        if (
            any(
                not _valid_sha256(reduction_binding[key])
                for key in _REDUCTION_BINDING_KEYS
                if key != "minimum_confirmed_coverage_ppm"
            )
            or not _exact_int(
                reduction_binding[
                    "minimum_confirmed_coverage_ppm"
                ],
                minimum=FORENSIC_ASSERTION_MIN_COVERAGE_PPM,
                maximum=1_000_000,
            )
            or reduction_binding["evaluation_sha256"]
            != evaluation["semantic_evaluation_sha256"]
            or reduction_binding[
                "index_execution_evaluation_sha256"
            ]
            != index_root["index_execution_evaluation_sha256"]
            or reduction_binding["plan_sha256"]
            != plan["assertion_graph_plan_sha256"]
            or reduction_binding["source_inventory_sha256"]
            != index_root["source_inventory_sha256"]
            or reduction_binding["source_manifest_sha256"]
            != index_root["source_manifest_sha256"]
            or fact["statement"]
            != (
                "Engine-validated Forensic assertion graph confirmed "
                f"{len(confirmed_assertions)} claim commitments at minimum "
                f"{reduction_binding['minimum_confirmed_coverage_ppm']} "
                "ppm evidence coverage."
            )
        ):
            raise ForensicAssertionStateContractError(
                "state_binding_reduction_evidence_invalid"
            )
    elif (
        reduction["executed_fact"] is not None
        or reduction["progress"] is not None
    ):
        raise ForensicAssertionStateContractError(
            "state_binding_rejected_reduction_invalid"
        )
    _canonical_json_bytes(
        root,
        maximum_bytes=FORENSIC_ASSERTION_STATE_MAX_BINDING_BYTES,
    )
    return root


def _reserved_ids(values: Iterable[str]) -> set[str]:
    try:
        selected = tuple(
            islice(
                iter(values),
                FORENSIC_ASSERTION_STATE_MAX_EXISTING_IDS + 1,
            )
        )
    except Exception as error:
        raise ForensicAssertionStateContractError(
            "existing_global_ids_invalid"
        ) from error
    if (
        len(selected) > FORENSIC_ASSERTION_STATE_MAX_EXISTING_IDS
        or any(not _safe_id(item) for item in selected)
        or len(set(selected)) != len(selected)
    ):
        raise ForensicAssertionStateContractError(
            "existing_global_ids_invalid"
        )
    return set(selected)


def build_forensic_assertion_state_projection(
    evaluation: ForensicAssertionExecutionEvaluation,
    execution_plan: ForensicAssertionExecutionPlan,
    operator_spec_payload: bytes,
    *,
    identity: ChallengeIdentity,
    configuration_epoch: int,
    base_revision: int,
    ids: ForensicAssertionStateIds,
    hypothesis_ids: Iterable[str],
    evaluated_at: str,
    timeout_seconds: int,
    run_origin: RunOrigin,
    observation_wall_seconds: Mapping[str, float],
    existing_global_ids: Iterable[str] = (),
) -> ForensicAssertionStateProjection:
    """Build the sole raw-free durable delta for one assertion wave."""

    binding = _build_binding(
        evaluation,
        execution_plan,
        operator_spec_payload,
        identity=identity,
        configuration_epoch=configuration_epoch,
        base_revision=base_revision,
        ids=ids,
        hypothesis_ids=hypothesis_ids,
        evaluated_at=evaluated_at,
        timeout_seconds=timeout_seconds,
        run_origin=run_origin,
        observation_wall_seconds=observation_wall_seconds,
    )
    projection = _projection_from_binding(binding)
    validate_forensic_assertion_state_projection(
        projection,
        evaluation=evaluation,
        execution_plan=execution_plan,
        operator_spec_payload=operator_spec_payload,
        existing_global_ids=existing_global_ids,
    )
    return projection


def validate_forensic_assertion_state_projection(
    projection: ForensicAssertionStateProjection,
    *,
    evaluation: ForensicAssertionExecutionEvaluation,
    execution_plan: ForensicAssertionExecutionPlan,
    operator_spec_payload: bytes,
    existing_global_ids: Iterable[str] = (),
) -> None:
    """Rebuild and compare every object before a store transaction."""

    if type(projection) is not ForensicAssertionStateProjection:
        raise ForensicAssertionStateContractError(
            "projection_type_invalid"
        )
    binding = _validate_binding_document(projection.binding)
    expected = _projection_from_binding(copy.deepcopy(binding))
    if projection.to_dict() != expected.to_dict():
        raise ForensicAssertionStateContractError(
            "projection_object_graph_rebound"
        )
    experiment = binding["experiment"]
    state_ids = binding["state_ids"]
    assert isinstance(experiment, dict)
    assert isinstance(state_ids, dict)
    ids = ForensicAssertionStateIds(
        experiment_id=experiment["id"],
        operator_spec_artifact_id=state_ids[
            "operator_spec_artifact_id"
        ],
        plan_artifact_id=state_ids["plan_artifact_id"],
        evaluation_artifact_id=state_ids[
            "evaluation_artifact_id"
        ],
        fact_id=state_ids["fact_id"],
        progress_id=state_ids["progress_id"],
    )
    wall_seconds = {
        record["execution_record"]["run_id"]: record[
            "wall_seconds"
        ]
        for record in binding["records"]
    }
    rebuilt = _build_binding(
        evaluation,
        execution_plan,
        operator_spec_payload,
        identity=ChallengeIdentity(
            contest_id=binding["identity"]["contest_id"],
            category=binding["identity"]["category"],
            challenge_id=binding["identity"]["challenge_id"],
        ),
        configuration_epoch=binding["configuration_epoch"],
        base_revision=binding["base_revision"],
        ids=ids,
        hypothesis_ids=tuple(experiment["hypothesis_ids"]),
        evaluated_at=experiment["evaluated_at"],
        timeout_seconds=experiment["timeout_seconds"],
        run_origin=RunOrigin(experiment["run_origin"]),
        observation_wall_seconds=wall_seconds,
    )
    if binding != rebuilt:
        raise ForensicAssertionStateContractError(
            "projection_evaluation_binding_rebound"
        )
    object_ids = projection.object_ids
    reserved = projection.reserved_ids
    if (
        len(set(object_ids)) != len(object_ids)
        or set(reserved) & _reserved_ids(existing_global_ids)
    ):
        raise ForensicAssertionStateContractError(
            "projection_global_identifier_collision"
        )
    projection.canonical_bytes


def _model_dict(
    value: object,
    *,
    challenge_id: str,
) -> dict[str, object]:
    if isinstance(value, Experiment):
        return value.to_dict(v2=True)
    if isinstance(value, RunReference):
        return value.to_dict(v2=True)
    if isinstance(value, ArtifactReference):
        return value.to_dict()
    if isinstance(value, ExecutionReceipt):
        return value.to_dict()
    if isinstance(value, Fact):
        return value.to_dict(
            default_challenge_id=challenge_id,
            v2=True,
        )
    if isinstance(value, ProgressMarker):
        return value.to_dict()
    raise TypeError("unsupported state object")


def _has_forensic_assertion_marker(value: object) -> bool:
    extra = getattr(value, "extra", None)
    return (
        type(extra) is dict
        and (
            "forensic_assertion_state" in extra
            or extra.get("protocol")
            == FORENSIC_ASSERTION_STATE_PROTOCOL
        )
    )


def _validate_state_anchors(
    state: ChallengeState,
    binding: dict[str, object],
    *,
    lookup: dict[str, dict[str, object]],
    global_owners: dict[str, list[str]],
) -> None:
    plan = binding["plan"]
    assert isinstance(plan, dict)
    operator = plan["operator_spec"]
    index_root = plan["index_root"]
    assert isinstance(operator, dict)
    assert isinstance(index_root, dict)
    index_artifact_binding = index_root["index_artifact"]
    assert isinstance(index_artifact_binding, dict)

    if (
        type(state.metadata) is not dict
        or state.metadata.get("source_manifest_sha256")
        != index_root["source_manifest_sha256"]
        or type(state.source_inventory) is not list
        or len(state.source_inventory)
        != index_root["source_file_count"]
        or sum(item.size for item in state.source_inventory)
        != index_root["source_total_bytes"]
    ):
        raise ForensicAssertionStateContractError(
            "current_source_inventory_rebound"
        )
    sources: dict[str, object] = {}
    for source in state.source_inventory:
        if (
            type(source.path) is not str
            or not _safe_path(source.path)
            or source.path in sources
            or not _valid_sha256(source.sha256)
            or not _exact_int(source.size)
            or source.kind != "file"
        ):
            raise ForensicAssertionStateContractError(
                "current_source_inventory_rebound"
            )
        sources[source.path] = source
    for pointer in operator["pointers"]:
        source = sources.get(pointer["source_path"])
        if source is None or source.sha256 != pointer["source_sha256"]:
            raise ForensicAssertionStateContractError(
                "current_pointer_source_rebound"
            )
        if pointer["kind"] == "file_range":
            end = pointer["offset_bytes"] + pointer["length_bytes"]
        elif pointer["kind"] == "inode":
            end = (
                pointer["metadata_offset_bytes"]
                + pointer["metadata_length_bytes"]
            )
        elif pointer["kind"] == "pcap_frame":
            end = (
                pointer["packet_offset_bytes"]
                + pointer["captured_length_bytes"]
            )
        elif pointer["kind"] == "process":
            end = (
                pointer["object_offset_bytes"]
                + pointer["object_length_bytes"]
            )
        else:
            end = (
                pointer["field_offset_bytes"]
                + pointer["field_length_bytes"]
            )
        if end > source.size:
            raise ForensicAssertionStateContractError(
                "current_pointer_source_rebound"
            )

    index_run = lookup["run"].get(index_root["index_run_id"])
    index_receipt = lookup["receipt"].get(
        index_root["index_receipt_id"]
    )
    index_artifact = lookup["artifact"].get(
        index_artifact_binding["artifact_id"]
    )
    if (
        not isinstance(index_run, RunReference)
        or index_run.status is not RunStatus.COMPLETED
        or index_run.configuration_epoch
        != binding["configuration_epoch"]
        or not isinstance(index_receipt, ExecutionReceipt)
        or index_receipt.run_id != index_run.id
        or index_receipt.outcome is not ReceiptOutcome.SUCCEEDED
        or type(index_receipt.exit_code) is not int
        or index_receipt.exit_code != 0
        or not isinstance(index_artifact, ArtifactReference)
        or index_artifact.sha256
        != index_artifact_binding["sha256"]
        or index_artifact.size
        != index_artifact_binding["size_bytes"]
        or index_artifact.source_run_id != index_run.id
        or any(
            len(global_owners.get(record_id, [])) != 1
            for record_id in (
                index_run.id,
                index_receipt.id,
                index_artifact.id,
            )
        )
    ):
        raise ForensicAssertionStateContractError(
            "confirmed_index_anchor_missing_or_rebound"
        )
    index_evidence = {
        "evaluation_sha256": index_root[
            "index_execution_evaluation_sha256"
        ],
        "receipt_id": index_root["index_receipt_id"],
        "source_inventory_sha256": index_root[
            "source_inventory_sha256"
        ],
        "source_manifest_sha256": index_root[
            "source_manifest_sha256"
        ],
    }
    matching_facts = [
        fact
        for fact in state.facts
        if (
            type(fact.extra) is dict
            and fact.extra.get("forensic_evidence_index")
            == index_evidence
        )
    ]
    matching_progress = [
        marker
        for marker in state.progress_markers
        if (
            type(marker.extra) is dict
            and marker.extra.get("forensic_evidence_index")
            == index_evidence
        )
    ]
    if (
        len(matching_facts) != 1
        or len(matching_progress) != 1
        or matching_facts[0].provenance is not Provenance.EXECUTED
        or matching_facts[0].kind is not FactKind.OBSERVATION
        or matching_facts[0].challenge_id != state.challenge_id
        or matching_facts[0].source_run_id != index_run.id
        or matching_facts[0].artifact_id != index_artifact.id
        or matching_progress[0].run_id != index_run.id
        or matching_progress[0].artifact_ids != [index_artifact.id]
        or len(
            global_owners.get(matching_facts[0].id, [])
        )
        != 1
        or len(
            global_owners.get(matching_progress[0].id, [])
        )
        != 1
    ):
        raise ForensicAssertionStateContractError(
            "confirmed_index_fact_or_progress_missing"
        )

    for readiness in operator["tools"]:
        readiness_binding = readiness["readiness_artifact"]
        artifact = lookup["artifact"].get(
            readiness_binding["artifact_id"]
        )
        if (
            not isinstance(artifact, ArtifactReference)
            or artifact.sha256 != readiness_binding["sha256"]
            or artifact.size != readiness_binding["size_bytes"]
            or len(global_owners.get(artifact.id, [])) != 1
        ):
            raise ForensicAssertionStateContractError(
                "current_readiness_artifact_missing_or_rebound"
            )


def forensic_assertion_state_graph_errors(
    state: ChallengeState,
) -> list[str]:
    """Return exact assertion-state graph errors without mutation."""

    if type(state) is not ChallengeState:
        return [
            "Forensic assertion state must be an exact ChallengeState"
        ]
    errors: list[str] = []
    collections: tuple[tuple[str, Iterable[object]], ...] = (
        ("experiment", state.experiments),
        ("run", state.runs),
        ("receipt", state.receipts),
        ("artifact", state.artifacts),
        ("fact", state.facts),
        ("progress", state.progress_markers),
        ("hypothesis", state.hypotheses),
        ("goal", state.goals),
        ("candidate", state.candidates),
        ("submission", state.submissions),
        ("session", state.sessions),
        ("cycle", state.cycles),
        ("wave", state.waves),
        ("checkpoint", state.checkpoints),
        ("target", state.targets),
        ("workspace_publish", state.workspace_publishes),
    )
    global_owners: dict[str, list[str]] = {}
    lookup: dict[str, dict[str, object]] = {}
    for name, records in collections:
        current: dict[str, object] = {}
        for record in records:
            record_id = getattr(record, "id", None)
            if type(record_id) is str:
                global_owners.setdefault(record_id, []).append(name)
                current[record_id] = record
        lookup[name] = current

    bound: dict[str, set[str]] = {
        name: set()
        for name in (
            "experiment",
            "run",
            "receipt",
            "artifact",
            "fact",
            "progress",
        )
    }
    for experiment in state.experiments:
        result = experiment.result
        has_result = (
            type(result) is dict
            and "forensic_assertion_state" in result
        )
        has_executor = (
            type(experiment.extra) is dict
            and experiment.extra.get("engine_executor")
            == FORENSIC_ASSERTION_STATE_EXECUTOR
        )
        if not has_result and not has_executor:
            continue
        label = f"Forensic assertion experiment {experiment.id}"
        try:
            result_root = _exact_dict(
                result,
                frozenset({"forensic_assertion_state"}),
                "experiment_result_schema_invalid",
            )
            wrapper = _exact_dict(
                result_root["forensic_assertion_state"],
                frozenset(
                    {"binding", "binding_sha256", "protocol"}
                ),
                "experiment_result_wrapper_invalid",
            )
            binding = _validate_binding_document(wrapper["binding"])
            binding_sha256 = _sha256(
                _canonical_json_bytes(
                    binding,
                    maximum_bytes=(
                        FORENSIC_ASSERTION_STATE_MAX_BINDING_BYTES
                    ),
                )
            )
            if (
                wrapper["protocol"]
                != FORENSIC_ASSERTION_STATE_PROTOCOL
                or wrapper["binding_sha256"] != binding_sha256
                or binding["identity"]
                != {
                    "category": state.category,
                    "challenge_id": state.challenge_id,
                    "contest_id": state.contest_id,
                }
                or binding["configuration_epoch"]
                != state.configuration_epoch
                or binding["base_revision"] > state.revision
            ):
                raise ForensicAssertionStateContractError(
                    "experiment_state_binding_mismatch"
                )
            _validate_state_anchors(
                state,
                binding,
                lookup=lookup,
                global_owners=global_owners,
            )
            expected = _projection_from_binding(copy.deepcopy(binding))
            expected_by_kind: dict[str, tuple[object, ...]] = {
                "experiment": (expected.experiment,),
                "run": expected.runs,
                "receipt": expected.receipts,
                "artifact": expected.artifacts,
                "fact": (
                    (expected.fact,)
                    if expected.fact is not None
                    else ()
                ),
                "progress": (
                    (expected.progress,)
                    if expected.progress is not None
                    else ()
                ),
            }
            for kind, expected_records in expected_by_kind.items():
                for expected_record in expected_records:
                    actual = lookup[kind].get(expected_record.id)
                    if actual is None:
                        raise ForensicAssertionStateContractError(
                            f"missing_{kind}_{expected_record.id}"
                        )
                    if _model_dict(
                        actual,
                        challenge_id=state.challenge_id,
                    ) != _model_dict(
                        expected_record,
                        challenge_id=state.challenge_id,
                    ):
                        raise ForensicAssertionStateContractError(
                            f"{kind}_object_rebound"
                        )
                    if len(
                        global_owners.get(expected_record.id, [])
                    ) != 1:
                        raise ForensicAssertionStateContractError(
                            "graph_identifier_duplicated_globally"
                        )
                    bound[kind].add(expected_record.id)
            expected_ids = set(expected.object_ids)
            for reserved_id in set(expected.reserved_ids) - expected_ids:
                if global_owners.get(reserved_id):
                    raise ForensicAssertionStateContractError(
                        "unmaterialized_preissued_identifier_claimed"
                    )
            for hypothesis_id in expected.experiment.hypothesis_ids:
                if hypothesis_id not in lookup["hypothesis"]:
                    raise ForensicAssertionStateContractError(
                        "experiment_hypothesis_orphan"
                    )
        except (
            AttributeError,
            KeyError,
            TypeError,
            UnicodeError,
            ValueError,
            ForensicAssertionStateContractError,
        ) as error:
            errors.append(f"{label} is invalid: {error}")

    for kind, records in (
        ("experiment", state.experiments),
        ("run", state.runs),
        ("receipt", state.receipts),
        ("artifact", state.artifacts),
        ("fact", state.facts),
        ("progress", state.progress_markers),
    ):
        for record in records:
            if (
                _has_forensic_assertion_marker(record)
                and record.id not in bound[kind]
            ):
                errors.append(
                    f"orphan Forensic assertion {kind} {record.id}"
                )
    for candidate in state.candidates:
        if _has_forensic_assertion_marker(candidate):
            errors.append(
                "Forensic assertion candidate authority widening "
                f"{candidate.id}"
            )
    for submission in state.submissions:
        if _has_forensic_assertion_marker(submission):
            errors.append(
                "Forensic assertion submission authority widening "
                f"{submission.id}"
            )
    if (
        type(state.extra) is dict
        and (
            "forensic_assertion_state" in state.extra
            or state.extra.get("protocol")
            == FORENSIC_ASSERTION_STATE_PROTOCOL
        )
    ):
        errors.append(
            "Forensic assertion challenge status/state authority widening"
        )
    return errors


def validate_forensic_assertion_state_graph(
    state: ChallengeState,
) -> None:
    """Raise the first stable error for an orphaned or rebound graph."""

    errors = forensic_assertion_state_graph_errors(state)
    if errors:
        raise ForensicAssertionStateContractError(errors[0])


__all__ = [
    "FORENSIC_ASSERTION_STATE_EXECUTOR",
    "FORENSIC_ASSERTION_STATE_MAX_BINDING_BYTES",
    "FORENSIC_ASSERTION_STATE_MAX_PROJECTION_BYTES",
    "FORENSIC_ASSERTION_STATE_PROTOCOL",
    "FORENSIC_ASSERTION_STATE_SCHEMA_VERSION",
    "ForensicAssertionStateContractError",
    "ForensicAssertionStateIds",
    "ForensicAssertionStateProjection",
    "build_forensic_assertion_state_projection",
    "forensic_assertion_state_graph_errors",
    "validate_forensic_assertion_state_graph",
    "validate_forensic_assertion_state_projection",
]
