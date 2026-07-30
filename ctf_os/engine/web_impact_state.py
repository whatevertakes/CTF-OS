"""Exact durable-state projection for transport-verified Web impact.

This module is intentionally independent from ``ChallengeEngine`` and
``ChallengeState.validate``.  It turns one
:class:`~ctf_os.engine.web_impact_execution.WebImpactExecutionEvaluation`
into the only engine-owned Experiment/Run/Receipt/Artifact/Fact/Progress graph
that may represent that evaluation.  The same binding document can then be
validated either before append or against a complete ``ChallengeState``.

The projection contains no HTTP body, cookie, session token, credential, flag,
or model prose.  Raw capture artifacts are referenced by hash and marked
``engine_private``.  A confirmed projection grants only one executed fact and
one progress marker.  It never creates or authorizes a candidate, proof, flag,
submission, challenge status transition, or automatic submission.
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

from ctf_os.engine.web_impact import (
    WEB_IMPACT_KINDS,
    WEB_IMPACT_MAX_ARTIFACT_BYTES,
    WEB_IMPACT_MAX_TIMELINE_STEPS,
    WEB_IMPACT_MAX_TRACE_BYTES,
    WEB_IMPACT_REPLAY_COUNT,
    WebArtifactCommitment,
    WebImpactEvaluation,
    WebImpactReplayRecord,
    WebImpactReplayObservation,
    evaluate_web_impact,
)
from ctf_os.engine.web_impact_execution import (
    WEB_IMPACT_EXECUTION_MAX_CAPTURE_BYTES,
    WEB_IMPACT_EXECUTION_PROTOCOL,
    WEB_IMPACT_OPERATOR_SPEC_MAX_BYTES,
    WebImpactExecutionEvaluation,
    WebImpactExecutionPlan,
    WebImpactExecutionRecord,
    WebImpactExecutionVerdict,
    web_impact_execution_plan_is_canonical,
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


WEB_IMPACT_STATE_PROTOCOL = "ctfos.web.impact.state.v1"
WEB_IMPACT_STATE_SCHEMA_VERSION = 1
WEB_IMPACT_STATE_EXECUTOR = "web_impact_execution_state_v1"
WEB_IMPACT_STATE_MAX_BINDING_BYTES = 1024 * 1024
WEB_IMPACT_STATE_MAX_PROJECTION_BYTES = 2 * 1024 * 1024
WEB_IMPACT_STATE_MAX_EXISTING_IDS = 100_000
WEB_IMPACT_STATE_MAX_HYPOTHESES = 64
WEB_IMPACT_STATE_MAX_TIMEOUT_SECONDS = 24 * 60 * 60

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,255}$")
_REASON_CODE = re.compile(r"^[A-Za-z0-9_:-]{1,160}$")
_CAPTURE_ROLE = re.compile(
    r"^(?:timeline-(?:[1-9]|[12][0-9]|3[0-2]):"
    r"(?:request|response)|source_sink:runtime_trace)$"
)
_MAX_REPLAY_RECORDS = WEB_IMPACT_REPLAY_COUNT * 2
_MAX_CAPTURE_ARTIFACTS_PER_REPLAY = (
    WEB_IMPACT_MAX_TIMELINE_STEPS * 2 + 1
)
_MAX_STATE_ARTIFACTS = (
    3
    + _MAX_REPLAY_RECORDS
    * _MAX_CAPTURE_ARTIFACTS_PER_REPLAY
)
_ALLOWED_RUN_ORIGINS = frozenset(
    {RunOrigin.MANAGED_TOOL, RunOrigin.OPERATOR_TOOL}
)
_ROOT_KEYS = frozenset(
    {
        "artifacts",
        "authorities",
        "base_revision",
        "configuration_epoch",
        "evaluation",
        "experiment",
        "identity",
        "plan",
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
        "semantic_evaluation_sha256",
        "sha256",
        "size_bytes",
        "verdict",
    }
)
_PLAN_KEYS = frozenset(
    {
        "control_target",
        "impact_kind",
        "operator_spec_sha256",
        "operator_spec_size_bytes",
        "plan_sha256",
        "runtime_image_digest",
        "source_manifest_sha256",
        "vulnerable_target",
    }
)
_REDUCTION_BINDING_KEYS = frozenset(
    {
        "evaluation_sha256",
        "oracle_contract_sha256",
        "plan_sha256",
        "response_artifact_sha256",
    }
)
_TARGET_KEYS = frozenset({"binding_sha256", "generation", "kind"})
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
_STATE_IDS_KEYS = frozenset(
    {
        "evaluation_artifact_id",
        "fact_id",
        "operator_spec_artifact_id",
        "plan_artifact_id",
        "progress_id",
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
_RECORD_KEYS = frozenset(
    {
        "capture_artifacts",
        "execution_record",
        "request_path",
        "result_path",
        "transport_receipt_path",
        "validation_path",
        "wall_seconds",
    }
)
_EXECUTION_RECORD_KEYS = frozenset(
    {
        "artifact_manifest_sha256",
        "observation_commitment_sha256",
        "receipt_id",
        "receipt_sha256",
        "replay_nonce_sha256",
        "replay_ordinal",
        "replay_target_kind",
        "request_id",
        "request_sha256",
        "run_id",
        "semantic_execution_contract_sha256",
        "target",
        "transport_execution_contract_sha256",
    }
)
_AUTHORITIES_FALSE = {
    "automatic_submission_authorized": False,
    "candidate_authorized": False,
    "challenge_proof_satisfied": False,
    "flag_proven": False,
    "proof_authorized": False,
    "self_report_accepted": False,
    "status_transition_authorized": False,
}
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


class WebImpactStateContractError(ValueError):
    """One durable state projection violated the exact Web contract."""

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
        raise WebImpactStateContractError(
            "canonical_json_invalid"
        ) from error
    if maximum_bytes is not None and len(payload) > maximum_bytes:
        raise WebImpactStateContractError(
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
    return (
        type(value) is int
        and minimum <= value <= maximum
    )


def _exact_number(
    value: object,
    *,
    minimum: float = 0.0,
    maximum: float = float(WEB_IMPACT_STATE_MAX_TIMEOUT_SECONDS),
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
        raise WebImpactStateContractError(code)
    return value


def _bounded_utc(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        if not 1 <= len(
            value.encode("utf-8", errors="strict")
        ) <= 128:
            return False
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00" if value.endswith("Z") else value
        )
    except (TypeError, UnicodeError, ValueError):
        return False
    return parsed.tzinfo is not None


def _artifact_path(artifact_id: str, role: str) -> str:
    if role in {
        "operator_spec",
        "execution_plan",
        "execution_evaluation",
    }:
        return f"artifacts/web-impact/{artifact_id}.json"
    return f"artifacts/web-impact/captures/{artifact_id}.bin"


def _run_paths(run_id: str) -> tuple[str, str, str, str]:
    root = f"runs/{run_id}"
    return (
        f"{root}/request.json",
        f"{root}/result.json",
        f"{root}/validation.json",
        f"{root}/web-impact-receipt.json",
    )


@dataclass(frozen=True, slots=True)
class WebImpactStateIds:
    experiment_id: str
    operator_spec_artifact_id: str
    plan_artifact_id: str
    evaluation_artifact_id: str
    fact_id: str | None
    progress_id: str | None


@dataclass(frozen=True, slots=True)
class WebImpactStateProjection:
    """The complete state delta; it contains no candidate or status field."""

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
                maximum_bytes=WEB_IMPACT_STATE_MAX_BINDING_BYTES,
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
            "protocol": WEB_IMPACT_STATE_PROTOCOL,
            "receipts": [item.to_dict() for item in self.receipts],
            "runs": [item.to_dict(v2=True) for item in self.runs],
            "schema_version": WEB_IMPACT_STATE_SCHEMA_VERSION,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(
            self.to_dict(),
            maximum_bytes=WEB_IMPACT_STATE_MAX_PROJECTION_BYTES,
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


def _validate_state_ids(
    ids: WebImpactStateIds,
    *,
    confirmed: bool,
) -> None:
    if type(ids) is not WebImpactStateIds:
        raise WebImpactStateContractError("state_ids_type_invalid")
    required = (
        ids.experiment_id,
        ids.operator_spec_artifact_id,
        ids.plan_artifact_id,
        ids.evaluation_artifact_id,
    )
    if any(not _safe_id(value) for value in required):
        raise WebImpactStateContractError("state_identifier_invalid")
    if confirmed:
        if not _safe_id(ids.fact_id) or not _safe_id(ids.progress_id):
            raise WebImpactStateContractError(
                "confirmed_state_ids_invalid"
            )
    elif ids.fact_id is not None or ids.progress_id is not None:
        raise WebImpactStateContractError(
            "rejected_state_retains_authority_ids"
        )
    present = [*required]
    if ids.fact_id is not None:
        present.append(ids.fact_id)
    if ids.progress_id is not None:
        present.append(ids.progress_id)
    if len(set(present)) != len(present):
        raise WebImpactStateContractError("state_identifier_reused")


def _validate_identity(identity: ChallengeIdentity) -> None:
    if type(identity) is not ChallengeIdentity:
        raise WebImpactStateContractError("challenge_identity_invalid")
    try:
        valid = (
            identity.category == "web"
            and all(
                type(value) is str
                and bool(value.strip())
                and len(
                    value.encode("utf-8", errors="strict")
                )
                <= 512
                for value in (
                    identity.contest_id,
                    identity.category,
                    identity.challenge_id,
                )
            )
        )
    except UnicodeError as error:
        raise WebImpactStateContractError(
            "challenge_identity_invalid"
        ) from error
    if not valid:
        raise WebImpactStateContractError("challenge_identity_invalid")


def _validate_hypothesis_ids(
    values: Iterable[str],
) -> tuple[str, ...]:
    try:
        selected = tuple(
            islice(
                iter(values),
                WEB_IMPACT_STATE_MAX_HYPOTHESES + 1,
            )
        )
    except Exception as error:
        raise WebImpactStateContractError(
            "hypothesis_ids_invalid"
        ) from error
    if (
        len(selected) > WEB_IMPACT_STATE_MAX_HYPOTHESES
        or any(not _safe_id(item) for item in selected)
        or len(set(selected)) != len(selected)
    ):
        raise WebImpactStateContractError("hypothesis_ids_invalid")
    return selected


def _validate_evaluation_and_plan(
    evaluation: WebImpactExecutionEvaluation,
    execution_plan: WebImpactExecutionPlan,
    operator_spec_payload: bytes,
) -> None:
    if (
        type(evaluation) is not WebImpactExecutionEvaluation
        or type(execution_plan) is not WebImpactExecutionPlan
        or type(operator_spec_payload) is not bytes
        or not operator_spec_payload
        or len(operator_spec_payload)
        > WEB_IMPACT_OPERATOR_SPEC_MAX_BYTES
    ):
        raise WebImpactStateContractError(
            "evaluation_plan_input_invalid"
        )
    if not web_impact_execution_plan_is_canonical(execution_plan):
        raise WebImpactStateContractError(
            "execution_plan_not_canonical"
        )
    if (
        evaluation.semantic_evaluation is not None
        and type(evaluation.semantic_evaluation)
        is not WebImpactEvaluation
    ):
        raise WebImpactStateContractError(
            "semantic_evaluation_type_invalid"
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
        raise WebImpactStateContractError(
            "evaluation_plan_binding_mismatch"
        )
    try:
        evaluation_payload = evaluation.canonical_bytes
        execution_plan.canonical_bytes
    except (AttributeError, TypeError, ValueError) as error:
        raise WebImpactStateContractError(
            "evaluation_or_plan_not_canonical"
        ) from error
    if len(evaluation_payload) > WEB_IMPACT_STATE_MAX_BINDING_BYTES:
        raise WebImpactStateContractError("evaluation_size_exceeded")
    if (
        type(evaluation.reason_codes) is not tuple
        or len(evaluation.reason_codes) > 16
        or any(
            type(code) is not str
            or _REASON_CODE.fullmatch(code) is None
            for code in evaluation.reason_codes
        )
    ):
        raise WebImpactStateContractError(
            "evaluation_reason_codes_invalid"
        )
    if evaluation.confirmed:
        if (
            evaluation.verdict
            is not WebImpactExecutionVerdict.CONFIRMED
            or evaluation.reason_codes
            or evaluation.semantic_evaluation is None
            or not evaluation.semantic_evaluation.passed
            or len(evaluation.records) != len(execution_plan.requests)
        ):
            raise WebImpactStateContractError(
                "confirmed_evaluation_inconsistent"
            )
        semantic = evaluation.semantic_evaluation
        if (
            type(semantic.replay_records) is not tuple
            or any(
                type(record) is not WebImpactReplayRecord
                for record in semantic.replay_records
            )
        ):
            raise WebImpactStateContractError(
                "confirmed_semantic_evaluation_invalid"
            )
        observations = tuple(
            WebImpactReplayObservation(
                target_kind=record.target_kind,
                replay_ordinal=record.replay_ordinal,
                run_id=record.run_id,
                receipt_id=record.receipt_id,
                receipt_sha256=record.receipt_sha256,
                replay_nonce_sha256=record.replay_nonce_sha256,
                identity_epoch_sha256=record.identity_epoch_sha256,
                execution_contract_sha256=(
                    record.execution_contract_sha256
                ),
                plan_sha256=record.plan_sha256,
                source_manifest_sha256=(
                    record.source_manifest_sha256
                ),
                runtime_image_digest=record.runtime_image_digest,
                authorized_target_binding_sha256=(
                    record.authorized_target_binding_sha256
                ),
                target_generation=record.target_generation,
                clean_workspace=True,
                fresh_identity_state=True,
                network_target_authorized=True,
                orchestration_status="completed",
                exit_code=0,
                timed_out=False,
                capture_complete=True,
                truncation_known=True,
                truncated=False,
                capture_error=None,
                timeline=record.timeline,
                source_sink=record.source_sink,
            )
            for record in semantic.replay_records
        )
        try:
            rebuilt_semantic = evaluate_web_impact(
                execution_plan.specification.plan,
                observations,
            )
        except (AttributeError, TypeError, ValueError) as error:
            raise WebImpactStateContractError(
                "confirmed_semantic_evaluation_invalid"
            ) from error
        if rebuilt_semantic != semantic:
            raise WebImpactStateContractError(
                "confirmed_semantic_evaluation_rebound"
            )
    elif (
        evaluation.verdict
        is not WebImpactExecutionVerdict.REJECTED
        or not evaluation.reason_codes
    ):
        raise WebImpactStateContractError(
            "rejected_evaluation_inconsistent"
        )
    if (
        type(evaluation.records) is not tuple
        or len(evaluation.records) > len(execution_plan.requests)
    ):
        raise WebImpactStateContractError(
            "evaluation_records_invalid"
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
            type(record) is not WebImpactExecutionRecord
            or record.request_id != request.request_id
            or record.request_sha256 != request.request_sha256
            or record.run_id != request.run_id
            or record.replay_target_kind
            != request.replay_target_kind
            or type(record.replay_ordinal) is not int
            or record.replay_ordinal != request.replay_ordinal
            or record.replay_nonce_sha256
            != request.replay_nonce_sha256
            or record.semantic_execution_contract_sha256
            != request.semantic_execution_contract_sha256
            or record.transport_execution_contract_sha256
            != request.transport_execution_contract_sha256
            or record.target != request.target
        ):
            raise WebImpactStateContractError(
                f"replay-{position}:evaluation_record_rebound"
            )
    if evaluation.confirmed:
        assert evaluation.semantic_evaluation is not None
        for position, (
            execution_record,
            semantic_record,
        ) in enumerate(
            zip(
                evaluation.records,
                evaluation.semantic_evaluation.replay_records,
                strict=True,
            ),
            start=1,
        ):
            if (
                type(semantic_record) is not WebImpactReplayRecord
                or semantic_record.target_kind
                != execution_record.replay_target_kind
                or type(semantic_record.replay_ordinal) is not int
                or semantic_record.replay_ordinal
                != execution_record.replay_ordinal
                or semantic_record.run_id != execution_record.run_id
                or semantic_record.receipt_id
                != execution_record.receipt_id
                or semantic_record.receipt_sha256
                != execution_record.receipt_sha256
                or semantic_record.replay_nonce_sha256
                != execution_record.replay_nonce_sha256
                or semantic_record.execution_contract_sha256
                != execution_record.semantic_execution_contract_sha256
                or semantic_record.plan_sha256
                != execution_plan.specification.plan.plan_sha256
                or semantic_record.source_manifest_sha256
                != execution_plan.specification.plan.source_manifest_sha256
                or semantic_record.runtime_image_digest
                != execution_plan.specification.plan.runtime_image_digest
                or semantic_record.authorized_target_binding_sha256
                != execution_record.target.binding_sha256
                or type(semantic_record.target_generation) is not int
                or semantic_record.target_generation
                != execution_record.target.generation
            ):
                raise WebImpactStateContractError(
                    f"replay-{position}:semantic_record_rebound"
                )


def _capture_bindings(
    evaluation: WebImpactExecutionEvaluation,
) -> dict[str, list[dict[str, object]]]:
    by_run: dict[str, list[dict[str, object]]] = {}
    semantic = evaluation.semantic_evaluation
    if semantic is None:
        return by_run
    if type(semantic.replay_records) is not tuple:
        raise WebImpactStateContractError(
            "semantic_replay_records_invalid"
        )
    for record in semantic.replay_records:
        if type(record) is not WebImpactReplayRecord:
            raise WebImpactStateContractError(
                "semantic_replay_record_type_invalid"
            )
        entries: list[tuple[str, WebArtifactCommitment, int]] = []
        for event in record.timeline:
            entries.extend(
                (
                    (
                        f"timeline-{event.ordinal}:request",
                        event.request_artifact,
                        WEB_IMPACT_MAX_ARTIFACT_BYTES,
                    ),
                    (
                        f"timeline-{event.ordinal}:response",
                        event.response_artifact,
                        WEB_IMPACT_MAX_ARTIFACT_BYTES,
                    ),
                )
            )
        entries.append(
            (
                "source_sink:runtime_trace",
                record.source_sink.trace_artifact,
                WEB_IMPACT_MAX_TRACE_BYTES,
            )
        )
        values: list[dict[str, object]] = []
        for role, artifact, maximum in entries:
            if (
                type(artifact) is not WebArtifactCommitment
                or not _safe_id(artifact.artifact_id)
                or not _valid_sha256(artifact.sha256)
                or not _exact_int(
                    artifact.size_bytes,
                    maximum=maximum,
                )
            ):
                raise WebImpactStateContractError(
                    "semantic_artifact_binding_invalid"
                )
            values.append(
                {
                    "artifact_id": artifact.artifact_id,
                    "context_visibility": "engine_private",
                    "media_type": "application/octet-stream",
                    "path": _artifact_path(
                        artifact.artifact_id,
                        role,
                    ),
                    "role": role,
                    "sha256": artifact.sha256,
                    "size_bytes": artifact.size_bytes,
                    "source_run_id": record.run_id,
                }
            )
        if record.run_id in by_run:
            raise WebImpactStateContractError(
                "semantic_run_binding_reused"
            )
        by_run[record.run_id] = values
    return by_run


def _artifact_document(
    artifact_id: str,
    *,
    role: str,
    sha256: str,
    size_bytes: int,
    source_run_id: str | None,
) -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "context_visibility": "engine_private",
        "media_type": "application/json",
        "path": _artifact_path(artifact_id, role),
        "role": role,
        "sha256": sha256,
        "size_bytes": size_bytes,
        "source_run_id": source_run_id,
    }


def _capture_manifest_sha256(
    captures: list[dict[str, object]],
) -> str:
    return _sha256(
        _canonical_json_bytes(
            {
                "artifacts": [
                    {
                        "artifact_id": capture["artifact_id"],
                        "label": capture["role"],
                        "sha256": capture["sha256"],
                        "size_bytes": capture["size_bytes"],
                    }
                    for capture in captures
                ],
                "kind": "ordered_exact_payload_commitments_v1",
            }
        )
    )


def _build_binding(
    evaluation: WebImpactExecutionEvaluation,
    execution_plan: WebImpactExecutionPlan,
    operator_spec_payload: bytes,
    *,
    identity: ChallengeIdentity,
    configuration_epoch: int,
    base_revision: int,
    ids: WebImpactStateIds,
    hypothesis_ids: Iterable[str],
    evaluated_at: str,
    timeout_seconds: int,
    run_origin: RunOrigin,
    replay_wall_seconds: Mapping[str, float],
) -> dict[str, object]:
    _validate_evaluation_and_plan(
        evaluation,
        execution_plan,
        operator_spec_payload,
    )
    _validate_identity(identity)
    if not _exact_int(configuration_epoch):
        raise WebImpactStateContractError(
            "configuration_epoch_invalid"
        )
    if not _exact_int(base_revision):
        raise WebImpactStateContractError("base_revision_invalid")
    if (
        not _exact_int(
            timeout_seconds,
            minimum=1,
            maximum=WEB_IMPACT_STATE_MAX_TIMEOUT_SECONDS,
        )
        or not _bounded_utc(evaluated_at)
        or type(run_origin) is not RunOrigin
        or run_origin not in _ALLOWED_RUN_ORIGINS
    ):
        raise WebImpactStateContractError(
            "experiment_execution_metadata_invalid"
        )
    selected_hypotheses = _validate_hypothesis_ids(hypothesis_ids)
    confirmed = evaluation.confirmed
    _validate_state_ids(ids, confirmed=confirmed)
    if type(replay_wall_seconds) is not dict:
        raise WebImpactStateContractError(
            "replay_wall_seconds_invalid"
        )
    record_run_ids = tuple(item.run_id for item in evaluation.records)
    if (
        set(replay_wall_seconds) != set(record_run_ids)
        or any(
            not _exact_number(value)
            for value in replay_wall_seconds.values()
        )
    ):
        raise WebImpactStateContractError(
            "replay_wall_seconds_invalid"
        )

    reduction = evaluation.reduction_projection()
    if (
        type(reduction) is not dict
        or reduction.get("automatic_submission") is not False
        or reduction.get("candidate") is not None
        or reduction.get("proof") is not None
        or reduction.get("impact") is not None
    ):
        raise WebImpactStateContractError(
            "evaluation_authority_widened"
        )
    fact_payload = reduction.get("executed_fact")
    progress_payload = reduction.get("progress")
    if confirmed:
        if (
            type(fact_payload) is not dict
            or set(fact_payload)
            != {
                "artifact_id",
                "extra",
                "provenance",
                "source_run_id",
                "statement",
            }
            or fact_payload["provenance"] != "executed"
            or type(progress_payload) is not dict
            or set(progress_payload)
            != {
                "artifact_ids",
                "extra",
                "run_id",
                "statement",
            }
        ):
            raise WebImpactStateContractError(
                "confirmed_reduction_invalid"
            )
    elif fact_payload is not None or progress_payload is not None:
        raise WebImpactStateContractError(
            "rejected_reduction_retains_authority"
        )

    specification = execution_plan.specification
    evaluation_payload = evaluation.canonical_bytes
    plan_payload = execution_plan.canonical_bytes
    capture_by_run = _capture_bindings(evaluation)
    final_run_id = (
        evaluation.records[-1].run_id
        if evaluation.records
        else None
    )
    artifacts: list[dict[str, object]] = [
        _artifact_document(
            ids.operator_spec_artifact_id,
            role="operator_spec",
            sha256=_sha256(operator_spec_payload),
            size_bytes=len(operator_spec_payload),
            source_run_id=None,
        ),
        _artifact_document(
            ids.plan_artifact_id,
            role="execution_plan",
            sha256=_sha256(plan_payload),
            size_bytes=len(plan_payload),
            source_run_id=None,
        ),
        _artifact_document(
            ids.evaluation_artifact_id,
            role="execution_evaluation",
            sha256=_sha256(evaluation_payload),
            size_bytes=len(evaluation_payload),
            source_run_id=final_run_id,
        ),
    ]
    records: list[dict[str, object]] = []
    for record in evaluation.records:
        request_path, result_path, validation_path, receipt_path = (
            _run_paths(record.run_id)
        )
        captures = copy.deepcopy(capture_by_run.get(record.run_id, []))
        artifacts.extend(captures)
        records.append(
            {
                "capture_artifacts": captures,
                "execution_record": record.to_dict(),
                "request_path": request_path,
                "result_path": result_path,
                "transport_receipt_path": receipt_path,
                "validation_path": validation_path,
                "wall_seconds": replay_wall_seconds[record.run_id],
            }
        )

    object_ids = [
        ids.experiment_id,
        *(item.run_id for item in evaluation.records),
        *(item.receipt_id for item in evaluation.records),
        *(item["artifact_id"] for item in artifacts),
    ]
    if ids.fact_id is not None:
        object_ids.append(ids.fact_id)
    if ids.progress_id is not None:
        object_ids.append(ids.progress_id)
    if (
        any(not _safe_id(value) for value in object_ids)
        or len(set(object_ids)) != len(object_ids)
    ):
        raise WebImpactStateContractError(
            "projection_global_identifier_reused"
        )
    artifact_ids = {
        item["artifact_id"] for item in artifacts
    }
    if confirmed:
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
            raise WebImpactStateContractError(
                "reduction_artifact_or_run_orphan"
            )

    authorities = {
        **_AUTHORITIES_FALSE,
        "executed_web_impact_fact_authorized": confirmed,
        "progress_marker_authorized": confirmed,
        "web_impact_oracle_satisfied": confirmed,
    }
    binding: dict[str, object] = {
        "artifacts": artifacts,
        "authorities": authorities,
        "base_revision": base_revision,
        "configuration_epoch": configuration_epoch,
        "evaluation": {
            "confirmed": confirmed,
            "execution_plan_sha256": evaluation.execution_plan_sha256,
            "reason_codes": list(evaluation.reason_codes),
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
            "control_target": (
                specification.control_target.to_dict()
                if specification.control_target is not None
                else None
            ),
            "impact_kind": specification.plan.oracle.impact_kind,
            "operator_spec_sha256": (
                specification.operator_spec_sha256
            ),
            "operator_spec_size_bytes": (
                specification.operator_spec_size_bytes
            ),
            "plan_sha256": specification.plan.plan_sha256,
            "runtime_image_digest": (
                specification.plan.runtime_image_digest
            ),
            "source_manifest_sha256": (
                specification.plan.source_manifest_sha256
            ),
            "vulnerable_target": (
                specification.vulnerable_target.to_dict()
            ),
        },
        "protocol": WEB_IMPACT_STATE_PROTOCOL,
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
        "schema_version": WEB_IMPACT_STATE_SCHEMA_VERSION,
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
        maximum_bytes=WEB_IMPACT_STATE_MAX_BINDING_BYTES,
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
        maximum_bytes=WEB_IMPACT_STATE_MAX_BINDING_BYTES,
    )
    experiment = binding["experiment"]
    assert isinstance(experiment, Mapping)
    return {
        "binding_sha256": _sha256(binding_bytes),
        "experiment_id": experiment["id"],
        "object_id": object_id,
        "object_kind": object_kind,
        "protocol": WEB_IMPACT_STATE_PROTOCOL,
        "record_sha256": _sha256(_canonical_json_bytes(record)),
        "schema_version": WEB_IMPACT_STATE_SCHEMA_VERSION,
    }


def _projection_from_binding(
    binding: dict[str, object],
) -> WebImpactStateProjection:
    _validate_binding_document(binding)
    experiment_binding = binding["experiment"]
    evaluation_binding = binding["evaluation"]
    reduction = binding["reduction"]
    state_ids = binding["state_ids"]
    identity = binding["identity"]
    assert isinstance(experiment_binding, dict)
    assert isinstance(evaluation_binding, dict)
    assert isinstance(reduction, dict)
    assert isinstance(state_ids, dict)
    assert isinstance(identity, dict)
    binding_sha256 = _sha256(
        _canonical_json_bytes(
            binding,
            maximum_bytes=WEB_IMPACT_STATE_MAX_BINDING_BYTES,
        )
    )
    confirmed = evaluation_binding["confirmed"] is True
    evaluated_at = experiment_binding["evaluated_at"]
    experiment_id = experiment_binding["id"]
    records = binding["records"]
    artifacts_binding = binding["artifacts"]
    assert isinstance(records, list)
    assert isinstance(artifacts_binding, list)

    artifacts: list[ArtifactReference] = []
    for artifact_binding in artifacts_binding:
        assert isinstance(artifact_binding, dict)
        artifact_id = artifact_binding["artifact_id"]
        marker = _marker(
            binding,
            object_kind=(
                "capture_artifact"
                if artifact_binding["role"]
                not in {
                    "operator_spec",
                    "execution_plan",
                    "execution_evaluation",
                }
                else str(artifact_binding["role"]) + "_artifact"
            ),
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
                    "kind": "web_impact_" + str(
                        artifact_binding["role"]
                    ),
                    "protocol": WEB_IMPACT_STATE_PROTOCOL,
                    "web_impact_state": marker,
                },
            )
        )

    runs: list[RunReference] = []
    receipts: list[ExecutionReceipt] = []
    for record_binding in records:
        assert isinstance(record_binding, dict)
        execution_record = record_binding["execution_record"]
        assert isinstance(execution_record, dict)
        run_id = execution_record["run_id"]
        receipt_id = execution_record["receipt_id"]
        record_hash_source = copy.deepcopy(record_binding)
        run_marker = _marker(
            binding,
            object_kind="replay_run",
            object_id=run_id,
            record=record_hash_source,
        )
        receipt_marker = _marker(
            binding,
            object_kind="replay_receipt",
            object_id=receipt_id,
            record=record_hash_source,
        )
        runs.append(
            RunReference(
                id=run_id,
                base_revision=binding["base_revision"],
                status=RunStatus.COMPLETED,
                request_path=record_binding["request_path"],
                result_path=record_binding["result_path"],
                validation_path=record_binding["validation_path"],
                role="web-impact",
                origin=RunOrigin(experiment_binding["run_origin"]),
                configuration_epoch=binding["configuration_epoch"],
                created_at=evaluated_at,
                extra={
                    "experiment_id": experiment_id,
                    "request_sha256": execution_record[
                        "request_sha256"
                    ],
                    "transport_receipt_path": record_binding[
                        "transport_receipt_path"
                    ],
                    "web_impact_state": run_marker,
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
                preview="",
                created_at=evaluated_at,
                extra={
                    "transport_receipt_path": record_binding[
                        "transport_receipt_path"
                    ],
                    "transport_receipt_sha256": execution_record[
                        "receipt_sha256"
                    ],
                    "web_impact_state": receipt_marker,
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
        fact_marker = _marker(
            binding,
            object_kind="executed_fact",
            object_id=fact_id,
            record=fact_payload,
        )
        progress_marker = _marker(
            binding,
            object_kind="progress_marker",
            object_id=progress_id,
            record=progress_payload,
        )
        fact_extra = copy.deepcopy(fact_payload["extra"])
        assert isinstance(fact_extra, dict)
        fact_extra["web_impact_state"] = fact_marker
        progress_extra = copy.deepcopy(progress_payload["extra"])
        assert isinstance(progress_extra, dict)
        progress_extra["web_impact_state"] = progress_marker
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
        record["execution_record"]["run_id"]
        for record in records
    ]
    evidence_receipt_ids = [
        record["execution_record"]["receipt_id"]
        for record in records
    ]
    artifact_ids = [
        artifact["artifact_id"]
        for artifact in artifacts_binding
    ]
    experiment_marker = _marker(
        binding,
        object_kind="experiment",
        object_id=experiment_id,
        record={"binding_sha256": binding_sha256},
    )
    reason_codes = evaluation_binding["reason_codes"]
    assert isinstance(reason_codes, list)
    experiment = Experiment(
        id=experiment_id,
        hypothesis_ids=list(experiment_binding["hypothesis_ids"]),
        command="engine:web-impact-execution:v1",
        expected_observation=(
            "exact response and source-to-sink oracle across three "
            "fresh replays"
        ),
        keep_if="transport and semantic Web impact oracle both confirm",
        drop_if="any transport or semantic binding rejects",
        timeout_seconds=experiment_binding["timeout_seconds"],
        resource_class="web",
        kind=ExperimentKind.PROBE,
        status=(
            ExperimentStatus.COMPLETED
            if confirmed
            else ExperimentStatus.INCONCLUSIVE
        ),
        result={
            "web_impact_state": {
                "binding": copy.deepcopy(binding),
                "binding_sha256": binding_sha256,
                "protocol": WEB_IMPACT_STATE_PROTOCOL,
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
            "web_impact_execution:"
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
            "engine_executor": WEB_IMPACT_STATE_EXECUTOR,
            "web_impact_state": experiment_marker,
        },
    )
    projection = WebImpactStateProjection(
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


def _validate_target(value: object, code: str) -> None:
    target = _exact_dict(value, _TARGET_KEYS, code)
    if (
        target["kind"] != "allowlisted_http_origin_v1"
        or not _valid_sha256(target["binding_sha256"])
        or not _exact_int(target["generation"])
    ):
        raise WebImpactStateContractError(code)


def _validate_artifact_binding(
    value: object,
) -> dict[str, object]:
    artifact = _exact_dict(
        value,
        _ARTIFACT_KEYS,
        "artifact_binding_schema_invalid",
    )
    if (
        not _safe_id(artifact["artifact_id"])
        or artifact["context_visibility"] != "engine_private"
        or artifact["media_type"]
        not in {"application/json", "application/octet-stream"}
        or type(artifact["path"]) is not str
        or type(artifact["role"]) is not str
        or not 1 <= len(artifact["role"]) <= 64
        or artifact["path"]
        != _artifact_path(
            artifact["artifact_id"],
            artifact["role"],
        )
        or not _valid_sha256(artifact["sha256"])
        or not _exact_int(
            artifact["size_bytes"],
            maximum=WEB_IMPACT_MAX_ARTIFACT_BYTES,
        )
        or (
            artifact["source_run_id"] is not None
            and not _safe_id(artifact["source_run_id"])
        )
    ):
        raise WebImpactStateContractError(
            "artifact_binding_fields_invalid"
        )
    return artifact


def _validate_binding_document(binding: object) -> dict[str, object]:
    root = _exact_dict(
        binding,
        _ROOT_KEYS,
        "state_binding_schema_invalid",
    )
    if (
        root["protocol"] != WEB_IMPACT_STATE_PROTOCOL
        or type(root["schema_version"]) is not int
        or root["schema_version"] != WEB_IMPACT_STATE_SCHEMA_VERSION
        or not _exact_int(root["configuration_epoch"])
        or not _exact_int(root["base_revision"])
    ):
        raise WebImpactStateContractError(
            "state_binding_header_invalid"
        )
    identity = _exact_dict(
        root["identity"],
        _IDENTITY_KEYS,
        "state_binding_identity_invalid",
    )
    try:
        valid_identity = (
            identity["category"] == "web"
            and all(
                type(identity[key]) is str
                and bool(identity[key].strip())
                and len(
                    identity[key].encode(
                        "utf-8",
                        errors="strict",
                    )
                )
                <= 512
                for key in _IDENTITY_KEYS
            )
        )
    except UnicodeError as error:
        raise WebImpactStateContractError(
            "state_binding_identity_invalid"
        ) from error
    if not valid_identity:
        raise WebImpactStateContractError(
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
        or len(hypothesis_ids) > WEB_IMPACT_STATE_MAX_HYPOTHESES
        or any(not _safe_id(item) for item in hypothesis_ids)
        or len(set(hypothesis_ids)) != len(hypothesis_ids)
        or experiment["run_origin"]
        not in {
            RunOrigin.MANAGED_TOOL.value,
            RunOrigin.OPERATOR_TOOL.value,
        }
        or not _bounded_utc(experiment["evaluated_at"])
        or not _exact_int(
            experiment["timeout_seconds"],
            minimum=1,
            maximum=WEB_IMPACT_STATE_MAX_TIMEOUT_SECONDS,
        )
    ):
        raise WebImpactStateContractError(
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
            WebImpactExecutionVerdict.CONFIRMED.value,
            WebImpactExecutionVerdict.REJECTED.value,
        }
        or not _valid_sha256(evaluation["execution_plan_sha256"])
        or not _valid_sha256(evaluation["sha256"])
        or not _exact_int(
            evaluation["size_bytes"],
            minimum=1,
            maximum=WEB_IMPACT_STATE_MAX_BINDING_BYTES,
        )
        or (
            evaluation["semantic_evaluation_sha256"] is not None
            and not _valid_sha256(
                evaluation["semantic_evaluation_sha256"]
            )
        )
        or (
            evaluation["confirmed"]
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
                != WebImpactExecutionVerdict.CONFIRMED.value
                or evaluation["reason_codes"]
            )
        )
        or (
            not evaluation["confirmed"]
            and (
                evaluation["verdict"]
                != WebImpactExecutionVerdict.REJECTED.value
                or not evaluation["reason_codes"]
            )
        )
    ):
        raise WebImpactStateContractError(
            "state_binding_evaluation_invalid"
        )
    plan = _exact_dict(
        root["plan"],
        _PLAN_KEYS,
        "state_binding_plan_invalid",
    )
    _validate_target(
        plan["vulnerable_target"],
        "state_binding_vulnerable_target_invalid",
    )
    if plan["control_target"] is not None:
        _validate_target(
            plan["control_target"],
            "state_binding_control_target_invalid",
        )
    if (
        not _valid_sha256(plan["operator_spec_sha256"])
        or not _exact_int(
            plan["operator_spec_size_bytes"],
            minimum=1,
            maximum=WEB_IMPACT_OPERATOR_SPEC_MAX_BYTES,
        )
        or not _valid_sha256(plan["plan_sha256"])
        or not _valid_sha256(plan["source_manifest_sha256"])
        or not _valid_image_digest(plan["runtime_image_digest"])
        or plan["impact_kind"] not in WEB_IMPACT_KINDS
    ):
        raise WebImpactStateContractError(
            "state_binding_plan_invalid"
        )
    authorities = root["authorities"]
    expected_authorities = {
        **_AUTHORITIES_FALSE,
        "executed_web_impact_fact_authorized": evaluation["confirmed"],
        "progress_marker_authorized": evaluation["confirmed"],
        "web_impact_oracle_satisfied": evaluation["confirmed"],
    }
    if type(authorities) is not dict or authorities != expected_authorities:
        raise WebImpactStateContractError(
            "state_binding_authority_widened"
        )
    state_ids = _exact_dict(
        root["state_ids"],
        _STATE_IDS_KEYS,
        "state_binding_ids_invalid",
    )
    ids = WebImpactStateIds(
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

    artifacts_raw = root["artifacts"]
    if (
        type(artifacts_raw) is not list
        or not 3 <= len(artifacts_raw) <= _MAX_STATE_ARTIFACTS
    ):
        raise WebImpactStateContractError(
            "state_binding_artifacts_invalid"
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
        or artifacts[0]["sha256"]
        != plan["operator_spec_sha256"]
        or artifacts[0]["size_bytes"]
        != plan["operator_spec_size_bytes"]
        or artifacts[1]["sha256"]
        != evaluation["execution_plan_sha256"]
        or artifacts[2]["sha256"] != evaluation["sha256"]
        or artifacts[2]["size_bytes"] != evaluation["size_bytes"]
        or any(
            item["media_type"] != "application/json"
            for item in artifacts[:3]
        )
        or artifacts[0]["source_run_id"] is not None
        or artifacts[1]["source_run_id"] is not None
    ):
        raise WebImpactStateContractError(
            "state_binding_artifacts_invalid"
        )

    records = root["records"]
    expected_count = WEB_IMPACT_REPLAY_COUNT * (
        2 if plan["control_target"] is not None else 1
    )
    if (
        type(records) is not list
        or len(records) > expected_count
        or (evaluation["confirmed"] and len(records) != expected_count)
    ):
        raise WebImpactStateContractError(
            "state_binding_records_invalid"
        )
    record_run_ids: list[str] = []
    record_receipt_ids: list[str] = []
    record_request_ids: list[str] = []
    record_request_hashes: list[str] = []
    record_receipt_hashes: list[str] = []
    record_nonce_hashes: list[str] = []
    record_transport_hashes: list[str] = []
    flattened_captures: list[dict[str, object]] = []
    expected_capture_roles: list[str] | None = None
    total_capture_bytes = 0
    for position, raw_record in enumerate(records, start=1):
        record = _exact_dict(
            raw_record,
            _RECORD_KEYS,
            "state_binding_record_schema_invalid",
        )
        execution_record = _exact_dict(
            record["execution_record"],
            _EXECUTION_RECORD_KEYS,
            "state_binding_execution_record_invalid",
        )
        control = position > WEB_IMPACT_REPLAY_COUNT
        expected_kind = "control" if control else "vulnerable"
        expected_ordinal = (
            position - WEB_IMPACT_REPLAY_COUNT
            if control
            else position
        )
        _validate_target(
            execution_record["target"],
            "state_binding_record_target_invalid",
        )
        expected_target = (
            plan["control_target"]
            if control
            else plan["vulnerable_target"]
        )
        if (
            execution_record["replay_target_kind"] != expected_kind
            or type(execution_record["replay_ordinal"]) is not int
            or execution_record["replay_ordinal"] != expected_ordinal
            or any(
                not _safe_id(execution_record[key])
                for key in ("request_id", "run_id", "receipt_id")
            )
            or any(
                not _valid_sha256(execution_record[key])
                for key in (
                    "artifact_manifest_sha256",
                    "observation_commitment_sha256",
                    "receipt_sha256",
                    "replay_nonce_sha256",
                    "request_sha256",
                    "semantic_execution_contract_sha256",
                    "transport_execution_contract_sha256",
                )
            )
            or not _exact_number(record["wall_seconds"])
            or execution_record["target"] != expected_target
        ):
            raise WebImpactStateContractError(
                "state_binding_execution_record_invalid"
            )
        paths = _run_paths(execution_record["run_id"])
        if (
            (
                record["request_path"],
                record["result_path"],
                record["validation_path"],
                record["transport_receipt_path"],
            )
            != paths
        ):
            raise WebImpactStateContractError(
                "state_binding_run_paths_invalid"
            )
        captures = record["capture_artifacts"]
        if (
            type(captures) is not list
            or not 5
            <= len(captures)
            <= _MAX_CAPTURE_ARTIFACTS_PER_REPLAY
            or len(captures) % 2 != 1
        ):
            raise WebImpactStateContractError(
                "state_binding_capture_list_invalid"
            )
        timeline_steps = (len(captures) - 1) // 2
        capture_roles = [
            role
            for ordinal in range(1, timeline_steps + 1)
            for role in (
                f"timeline-{ordinal}:request",
                f"timeline-{ordinal}:response",
            )
        ]
        capture_roles.append("source_sink:runtime_trace")
        if (
            expected_capture_roles is None
            or capture_roles == expected_capture_roles
        ):
            expected_capture_roles = capture_roles
        else:
            raise WebImpactStateContractError(
                "state_binding_capture_timeline_rebound"
            )
        for capture in captures:
            artifact = _validate_artifact_binding(capture)
            expected_role = capture_roles[
                len(flattened_captures)
                % len(capture_roles)
            ]
            if (
                artifact["source_run_id"]
                != execution_record["run_id"]
                or artifact["media_type"]
                != "application/octet-stream"
                or _CAPTURE_ROLE.fullmatch(artifact["role"]) is None
                or artifact["role"] != expected_role
                or (
                    artifact["role"]
                    == "source_sink:runtime_trace"
                    and artifact["size_bytes"]
                    > WEB_IMPACT_MAX_TRACE_BYTES
                )
            ):
                raise WebImpactStateContractError(
                    "state_binding_capture_run_rebound"
                )
            total_capture_bytes += artifact["size_bytes"]
            flattened_captures.append(artifact)
        if (
            _capture_manifest_sha256(captures)
            != execution_record["artifact_manifest_sha256"]
        ):
            raise WebImpactStateContractError(
                "state_binding_capture_manifest_rebound"
            )
        record_run_ids.append(execution_record["run_id"])
        record_receipt_ids.append(execution_record["receipt_id"])
        record_request_ids.append(execution_record["request_id"])
        record_request_hashes.append(execution_record["request_sha256"])
        record_receipt_hashes.append(
            execution_record["receipt_sha256"]
        )
        record_nonce_hashes.append(
            execution_record["replay_nonce_sha256"]
        )
        record_transport_hashes.append(
            execution_record[
                "transport_execution_contract_sha256"
            ]
        )
    if (
        len(set(record_run_ids)) != len(record_run_ids)
        or len(set(record_receipt_ids)) != len(record_receipt_ids)
        or len(set(record_request_ids)) != len(record_request_ids)
        or len(set(record_request_hashes))
        != len(record_request_hashes)
        or len(set(record_receipt_hashes))
        != len(record_receipt_hashes)
        or len(set(record_nonce_hashes)) != len(record_nonce_hashes)
        or len(set(record_transport_hashes))
        != len(record_transport_hashes)
        or flattened_captures != artifacts[3:]
        or total_capture_bytes
        > WEB_IMPACT_EXECUTION_MAX_CAPTURE_BYTES
        or artifacts[2]["source_run_id"]
        != (record_run_ids[-1] if record_run_ids else None)
    ):
        raise WebImpactStateContractError(
            "state_binding_record_identifiers_reused"
        )

    reduction = _exact_dict(
        root["reduction"],
        _REDUCTION_KEYS,
        "state_binding_reduction_invalid",
    )
    if (
        reduction["automatic_submission"] is not False
        or reduction["candidate"] is not None
        or reduction["proof"] is not None
        or reduction["impact"] is not None
        or reduction["status_transition"] is not None
    ):
        raise WebImpactStateContractError(
            "state_binding_reduction_widened"
        )
    if evaluation["confirmed"]:
        fact = reduction["executed_fact"]
        progress = reduction["progress"]
        expected_source_run_id = record_run_ids[
            WEB_IMPACT_REPLAY_COUNT - 1
        ]
        expected_fact_statement = (
            "Three fresh sandbox replays satisfied the explicit "
            f"{plan['impact_kind']} Web impact oracle"
            + (
                " and three patched/non-vulnerable controls "
                "produced the declared differential."
                if plan["control_target"] is not None
                else "."
            )
        )
        expected_progress_statement = (
            "Deterministic Web impact oracle reproduced in three "
            "fresh identity-isolated executions"
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
            or fact["artifact_id"] not in artifact_ids
            or fact["source_run_id"] != expected_source_run_id
            or fact["statement"] != expected_fact_statement
            or type(fact["extra"]) is not dict
            or set(fact["extra"]) != {"web_impact"}
            or type(progress) is not dict
            or set(progress)
            != {
                "artifact_ids",
                "extra",
                "run_id",
                "statement",
            }
            or progress["run_id"] != expected_source_run_id
            or type(progress["artifact_ids"]) is not list
            or len(progress["artifact_ids"]) != 2
            or len(set(progress["artifact_ids"])) != 2
            or progress["artifact_ids"][0] != fact["artifact_id"]
            or any(
                artifact_id not in artifact_ids
                for artifact_id in progress["artifact_ids"]
            )
            or progress["statement"]
            != expected_progress_statement
            or type(progress["extra"]) is not dict
            or set(progress["extra"]) != {"web_impact"}
            or progress["extra"] != fact["extra"]
        ):
            raise WebImpactStateContractError(
                "state_binding_confirmed_reduction_invalid"
            )
        reduction_binding = _exact_dict(
            fact["extra"]["web_impact"],
            _REDUCTION_BINDING_KEYS,
            "state_binding_reduction_evidence_invalid",
        )
        artifact_by_id = {
            artifact["artifact_id"]: artifact
            for artifact in artifacts
        }
        response_artifact = artifact_by_id[fact["artifact_id"]]
        trace_artifact = artifact_by_id[
            progress["artifact_ids"][1]
        ]
        if (
            any(
                not _valid_sha256(reduction_binding[key])
                for key in _REDUCTION_BINDING_KEYS
            )
            or reduction_binding["evaluation_sha256"]
            != evaluation["semantic_evaluation_sha256"]
            or reduction_binding["plan_sha256"]
            != plan["plan_sha256"]
            or reduction_binding["response_artifact_sha256"]
            != response_artifact["sha256"]
            or response_artifact["source_run_id"]
            != expected_source_run_id
            or not response_artifact["role"].endswith(":response")
            or trace_artifact["source_run_id"]
            != expected_source_run_id
            or trace_artifact["role"]
            != "source_sink:runtime_trace"
        ):
            raise WebImpactStateContractError(
                "state_binding_reduction_evidence_invalid"
            )
    elif (
        reduction["executed_fact"] is not None
        or reduction["progress"] is not None
    ):
        raise WebImpactStateContractError(
            "state_binding_rejected_reduction_invalid"
        )
    _canonical_json_bytes(
        root,
        maximum_bytes=WEB_IMPACT_STATE_MAX_BINDING_BYTES,
    )
    return root


def _reserved_ids(
    values: Iterable[str],
) -> set[str]:
    try:
        selected = tuple(
            islice(
                iter(values),
                WEB_IMPACT_STATE_MAX_EXISTING_IDS + 1,
            )
        )
    except Exception as error:
        raise WebImpactStateContractError(
            "existing_global_ids_invalid"
        ) from error
    if (
        len(selected) > WEB_IMPACT_STATE_MAX_EXISTING_IDS
        or any(not _safe_id(item) for item in selected)
        or len(set(selected)) != len(selected)
    ):
        raise WebImpactStateContractError(
            "existing_global_ids_invalid"
        )
    return set(selected)


def build_web_impact_state_projection(
    evaluation: WebImpactExecutionEvaluation,
    execution_plan: WebImpactExecutionPlan,
    operator_spec_payload: bytes,
    *,
    identity: ChallengeIdentity,
    configuration_epoch: int,
    base_revision: int,
    ids: WebImpactStateIds,
    hypothesis_ids: Iterable[str],
    evaluated_at: str,
    timeout_seconds: int,
    run_origin: RunOrigin,
    replay_wall_seconds: Mapping[str, float],
    existing_global_ids: Iterable[str] = (),
) -> WebImpactStateProjection:
    """Build the only durable graph allowed for one Web evaluation."""

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
        replay_wall_seconds=replay_wall_seconds,
    )
    projection = _projection_from_binding(binding)
    validate_web_impact_state_projection(
        projection,
        evaluation=evaluation,
        execution_plan=execution_plan,
        operator_spec_payload=operator_spec_payload,
        existing_global_ids=existing_global_ids,
    )
    return projection


def validate_web_impact_state_projection(
    projection: WebImpactStateProjection,
    *,
    evaluation: WebImpactExecutionEvaluation,
    execution_plan: WebImpactExecutionPlan,
    operator_spec_payload: bytes,
    existing_global_ids: Iterable[str] = (),
) -> None:
    """Rebuild and compare every state object before ``StateStore.update``."""

    if type(projection) is not WebImpactStateProjection:
        raise WebImpactStateContractError("projection_type_invalid")
    binding = _validate_binding_document(projection.binding)
    expected = _projection_from_binding(copy.deepcopy(binding))
    if projection.to_dict() != expected.to_dict():
        raise WebImpactStateContractError(
            "projection_object_graph_rebound"
        )
    experiment = binding["experiment"]
    state_ids = binding["state_ids"]
    assert isinstance(experiment, dict)
    assert isinstance(state_ids, dict)
    ids = WebImpactStateIds(
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
    rebuilt_binding = _build_binding(
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
        replay_wall_seconds=wall_seconds,
    )
    if binding != rebuilt_binding:
        raise WebImpactStateContractError(
            "projection_evaluation_binding_rebound"
        )
    object_ids = projection.object_ids
    if (
        len(set(object_ids)) != len(object_ids)
        or set(object_ids) & _reserved_ids(existing_global_ids)
    ):
        raise WebImpactStateContractError(
            "projection_global_identifier_collision"
        )
    projection.canonical_bytes


def _model_dict(value: object, *, challenge_id: str) -> dict[str, object]:
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


def _has_web_marker(value: object) -> bool:
    extra = getattr(value, "extra", None)
    return (
        type(extra) is dict
        and (
            "web_impact_state" in extra
            or extra.get("protocol") == WEB_IMPACT_STATE_PROTOCOL
        )
    )


def web_impact_state_graph_errors(
    state: ChallengeState,
) -> list[str]:
    """Return exact durable Web graph errors without mutating state."""

    if type(state) is not ChallengeState:
        return ["Web impact state must be an exact ChallengeState"]
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
            type(result) is dict and "web_impact_state" in result
        )
        has_executor = (
            experiment.extra.get("engine_executor")
            == WEB_IMPACT_STATE_EXECUTOR
        )
        if not has_result and not has_executor:
            continue
        label = f"Web impact experiment {experiment.id}"
        try:
            result_root = _exact_dict(
                result,
                frozenset({"web_impact_state"}),
                "experiment_result_schema_invalid",
            )
            wrapper = _exact_dict(
                result_root["web_impact_state"],
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
                        WEB_IMPACT_STATE_MAX_BINDING_BYTES
                    ),
                )
            )
            if (
                wrapper["protocol"] != WEB_IMPACT_STATE_PROTOCOL
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
                raise WebImpactStateContractError(
                    "experiment_state_binding_mismatch"
                )
            expected = _projection_from_binding(
                copy.deepcopy(binding)
            )
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
                        raise WebImpactStateContractError(
                            f"missing_{kind}_{expected_record.id}"
                        )
                    if _model_dict(
                        actual,
                        challenge_id=state.challenge_id,
                    ) != _model_dict(
                        expected_record,
                        challenge_id=state.challenge_id,
                    ):
                        raise WebImpactStateContractError(
                            f"{kind}_object_rebound"
                        )
                    if len(
                        global_owners.get(expected_record.id, [])
                    ) != 1:
                        raise WebImpactStateContractError(
                            "graph_identifier_duplicated_globally"
                        )
                    bound[kind].add(expected_record.id)
            for hypothesis_id in expected.experiment.hypothesis_ids:
                if hypothesis_id not in lookup["hypothesis"]:
                    raise WebImpactStateContractError(
                        "experiment_hypothesis_orphan"
                    )
        except (
            AttributeError,
            KeyError,
            TypeError,
            ValueError,
            WebImpactStateContractError,
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
            if _has_web_marker(record) and record.id not in bound[kind]:
                errors.append(
                    f"orphan Web impact {kind} {record.id}"
                )
    for candidate in state.candidates:
        if _has_web_marker(candidate):
            errors.append(
                f"Web impact candidate authority widening {candidate.id}"
            )
    for submission in state.submissions:
        if _has_web_marker(submission):
            errors.append(
                "Web impact submission authority widening "
                f"{submission.id}"
            )
    if (
        "web_impact_state" in state.extra
        or state.extra.get("protocol") == WEB_IMPACT_STATE_PROTOCOL
    ):
        errors.append(
            "Web impact challenge status/state authority widening"
        )
    return errors


def validate_web_impact_state_graph(
    state: ChallengeState,
) -> None:
    """Raise one stable error if any typed Web object is orphaned/rebound."""

    errors = web_impact_state_graph_errors(state)
    if errors:
        raise WebImpactStateContractError(errors[0])


__all__ = [
    "WEB_IMPACT_STATE_EXECUTOR",
    "WEB_IMPACT_STATE_MAX_BINDING_BYTES",
    "WEB_IMPACT_STATE_MAX_PROJECTION_BYTES",
    "WEB_IMPACT_STATE_PROTOCOL",
    "WEB_IMPACT_STATE_SCHEMA_VERSION",
    "WebImpactStateContractError",
    "WebImpactStateIds",
    "WebImpactStateProjection",
    "build_web_impact_state_projection",
    "validate_web_impact_state_graph",
    "validate_web_impact_state_projection",
    "web_impact_state_graph_errors",
]
