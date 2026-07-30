"""Deterministic, pointer-only state digest for resuming long solve sessions.

The capsule is deliberately rendered from canonical state only.  It never
opens artifacts and never copies command text, provider errors, transport
summaries, receipt previews, or checkpoint action text into model context.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from ctf_os.contracts.pwn_crash_v1 import PWN_CRASH_V1_ATTEMPT_COUNT
from ctf_os.engine.failure_capsule import (
    experiment_command_sha256,
    safe_run_diagnostics,
    validate_failure_capsule,
)
from ctf_os.models import (
    ACTIVE_HYPOTHESIS_STATUSES,
    ArtifactReference,
    ChallengeState,
    ExecutionReceipt,
    Experiment,
    ExperimentKind,
    ExperimentStatus,
    Fact,
    ModelValidationError,
    Provenance,
    PwnRuntimeSnapshotDisclosureEnvelope,
    ReceiptOutcome,
    RunReference,
    RunStatus,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.store.atomic import canonical_json_record


RESUME_CAPSULE_SCHEMA_VERSION = 1
MAX_RESUME_CAPSULE_BYTES = 12 * 1024
MIN_RESUME_CAPSULE_BYTES = 1536
MAX_FAILURE_HISTORY_CHECKPOINTS = 64

_PENDING_STATUSES = frozenset(
    {
        ExperimentStatus.REGISTERED,
        ExperimentStatus.RUNNING,
        ExperimentStatus.AWAITING_EVALUATION,
    }
)
_NEGATIVE_STATUSES = frozenset(
    {
        ExperimentStatus.DROPPED,
        ExperimentStatus.INCONCLUSIVE,
        ExperimentStatus.FAILED,
        ExperimentStatus.CANCELLED,
    }
)
_TERMINAL_RUN_STATUSES = frozenset(
    {
        RunStatus.COMPLETED,
        RunStatus.INVALID,
        RunStatus.FAILED,
        RunStatus.TIMED_OUT,
        RunStatus.CANCELLED,
        RunStatus.INTERRUPTED,
    }
)
_RUN_STATUS_FOR_OUTCOME = {
    ReceiptOutcome.SUCCEEDED: RunStatus.COMPLETED,
    ReceiptOutcome.FAILED: RunStatus.FAILED,
    ReceiptOutcome.TIMED_OUT: RunStatus.TIMED_OUT,
    ReceiptOutcome.CANCELLED: RunStatus.CANCELLED,
    ReceiptOutcome.INTERRUPTED: RunStatus.INTERRUPTED,
}
_ENGINE_EVALUATION_REASON = re.compile(
    r"(?:"
    r"rev_inventory:(?:evaluated|rejected):"
    r"|rev_proof:(?:semantic_falsification|structural_failure):"
    r")"
    r"[a-z0-9_/,.-]{1,384}"
)
_PWN_CRASH_ENGINE_EXECUTOR = "pwn_crash_differential_v1"
_PWN_CRASH_RESULT_KEY = "pwn_crash_evidence"
_PWN_CRASH_TERMINAL_STATUSES = frozenset(
    {
        ExperimentStatus.KEPT,
        ExperimentStatus.INCONCLUSIVE,
        ExperimentStatus.FAILED,
    }
)
_PWN_RUNTIME_SNAPSHOT_ENGINE_EXECUTOR = "pwn_runtime_snapshot_v1"
_PWN_RUNTIME_SNAPSHOT_RESULT_KEY = "pwn_runtime_snapshot_evidence"


@dataclass(frozen=True, slots=True)
class ResumeCapsulePolicy:
    """Selection and byte limits that are part of capsule determinism."""

    max_bytes: int = MAX_RESUME_CAPSULE_BYTES
    pending_limit: int = 6
    negative_limit: int = 12
    confirmed_limit: int = 6

    def validate(self) -> None:
        if (
            isinstance(self.max_bytes, bool)
            or not isinstance(self.max_bytes, int)
            or not MIN_RESUME_CAPSULE_BYTES
            <= self.max_bytes
            <= MAX_RESUME_CAPSULE_BYTES
        ):
            raise ValueError(
                "resume capsule max_bytes must be between "
                f"{MIN_RESUME_CAPSULE_BYTES} and "
                f"{MAX_RESUME_CAPSULE_BYTES}"
            )
        for name, value, minimum, maximum in (
            ("pending_limit", self.pending_limit, 0, 6),
            ("negative_limit", self.negative_limit, 0, 12),
            ("confirmed_limit", self.confirmed_limit, 1, 6),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise ValueError(
                    f"resume capsule {name} must be between "
                    f"{minimum} and {maximum}"
                )


@dataclass(frozen=True, slots=True)
class ResumeCapsule:
    """One canonical JSONL record plus its exact content digest."""

    text: str
    sha256: str
    total_counts: dict[str, int]
    included_counts: dict[str, int]
    omitted_counts: dict[str, int]


def _bounded(value: str | None, maximum: int = 160) -> str | None:
    if value is None:
        return None
    if len(value) <= maximum:
        return value
    return value[: maximum - 1] + "…"


def _bounded_canonical_text(
    value: str | None,
    *,
    maximum_bytes: int,
) -> str | None:
    """Bound text by its exact canonical-JSON token size."""

    if value is None:
        return None
    if len(canonical_json_record(value).encode("ascii")) <= maximum_bytes:
        return value
    suffix = "…"
    low = 0
    high = len(value)
    while low < high:
        middle = (low + high + 1) // 2
        candidate = value[:middle] + suffix
        if (
            len(canonical_json_record(candidate).encode("ascii"))
            <= maximum_bytes
        ):
            low = middle
        else:
            high = middle - 1
    return value[:low] + suffix


def _bounded_ids(
    values: list[str],
    *,
    maximum: int = 12,
) -> tuple[list[str], int]:
    unique = list(dict.fromkeys(values))
    return unique[:maximum], max(0, len(unique) - maximum)


def _bounded_id_digest(
    values: list[str],
    *,
    maximum: int,
    source_omitted: int = 0,
) -> dict[str, object]:
    included, omitted = _bounded_ids(values, maximum=maximum)
    result: dict[str, object] = {
        "ids": included,
        "total": len(list(dict.fromkeys(values))) + source_omitted,
    }
    total_omitted = omitted + source_omitted
    if total_omitted:
        result["omitted"] = total_omitted
    return result


def _exact_run_pointer(
    value: str | None,
    *,
    run_id: str,
    label: str,
) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ModelValidationError(
            f"failure capsule run {label} is not a canonical path"
        )
    pure = PurePosixPath(value)
    expected = (
        PurePosixPath("runs")
        / run_id
        / (
            "result.json"
            if label == "result_path"
            else "validation.json"
        )
    )
    if (
        pure.is_absolute()
        or value != pure.as_posix()
        or any(part in {"", ".", ".."} for part in pure.parts)
        or pure != expected
        or len(canonical_json_record(value).encode("ascii")) > 512
    ):
        raise ModelValidationError(
            f"failure capsule run {label} is not a bounded canonical path"
        )
    return value


def _recent_key(record: Any) -> tuple[str, str]:
    return str(getattr(record, "created_at", "")), str(
        getattr(record, "id", "")
    )


def _command_sha256(experiment: Experiment) -> str:
    try:
        payload = experiment.command.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise ModelValidationError(
            f"experiment {experiment.id} command is not valid UTF-8"
        ) from error
    return hashlib.sha256(payload).hexdigest()


def _experiment_contract_sha256(experiment: Experiment) -> str:
    """Hash model-authored conditions without replaying their free text."""

    return hashlib.sha256(
        canonical_json_record(
            {
                "drop_if": experiment.drop_if,
                "expected_observation": experiment.expected_observation,
                "keep_if": experiment.keep_if,
            }
        ).encode("ascii")
    ).hexdigest()


def _safe_engine_evaluation_reason(
    experiment: Experiment,
) -> str | None:
    """Expose only reasons from a structurally engine-owned oracle path."""

    reason = experiment.evaluation_reason
    if not isinstance(reason, str) or not _ENGINE_EVALUATION_REASON.fullmatch(
        reason
    ):
        return None
    if reason.startswith("rev_inventory:"):
        if not experiment.id.startswith(
            "E-adapter-reversing-inventory_observation-"
        ):
            return None
    elif (
        experiment.kind is not ExperimentKind.PROOF
        or experiment.proof_recipe is None
    ):
        return None
    return reason


def _receipt_maps(
    state: ChallengeState,
) -> tuple[
    dict[str, ExecutionReceipt],
    dict[str, tuple[ExecutionReceipt, ...]],
]:
    by_id = {item.id: item for item in state.receipts}
    experiments = {item.id: item for item in state.experiments}
    grouped: dict[str, list[ExecutionReceipt]] = {}
    for receipt in state.receipts:
        grouped.setdefault(receipt.experiment_id, []).append(receipt)

    by_experiment: dict[str, tuple[ExecutionReceipt, ...]] = {}
    for experiment_id, receipts in grouped.items():
        if len(receipts) == 1:
            by_experiment[experiment_id] = (receipts[0],)
            continue
        experiment = experiments.get(experiment_id)
        attempt_links = _pwn_crash_attempt_links(experiment)
        if (
            attempt_links is None
            or len(receipts) != PWN_CRASH_V1_ATTEMPT_COUNT
        ):
            raise ModelValidationError(
                f"experiment {experiment_id} has more than one receipt"
            )
        receipt_ids = [
            item.get("receipt_id")
            if isinstance(item, Mapping)
            else None
            for item in attempt_links
        ]
        if (
            any(not isinstance(item, str) for item in receipt_ids)
            or len(set(receipt_ids)) != PWN_CRASH_V1_ATTEMPT_COUNT
            or set(receipt_ids) != {item.id for item in receipts}
            or any(
                receipt_id not in by_id
                or by_id[receipt_id].experiment_id != experiment_id
                for receipt_id in receipt_ids
            )
        ):
            raise ModelValidationError(
                f"Pwn crash experiment {experiment_id} receipts do not "
                "match its canonical attempt order"
            )
        by_experiment[experiment_id] = tuple(
            by_id[receipt_id]
            for receipt_id in receipt_ids
            if isinstance(receipt_id, str)
        )
    return by_id, by_experiment


def _pwn_crash_attempt_links(
    experiment: Experiment | None,
) -> list[object] | None:
    """Return only a state-validated terminal typed Pwn attempt sequence."""

    if (
        experiment is None
        or experiment.status not in _PWN_CRASH_TERMINAL_STATUSES
        or experiment.extra.get("engine_executor")
        != _PWN_CRASH_ENGINE_EXECUTOR
        or type(experiment.result) is not dict
        or set(experiment.result) != {_PWN_CRASH_RESULT_KEY}
    ):
        return None
    evidence = experiment.result[_PWN_CRASH_RESULT_KEY]
    attempts = (
        evidence.get("attempts")
        if type(evidence) is dict
        else None
    )
    if (
        type(attempts) is not list
        or len(attempts) != PWN_CRASH_V1_ATTEMPT_COUNT
    ):
        return None
    return attempts


def _pwn_disclosure_projection(
    state: ChallengeState,
    *,
    artifacts: Mapping[str, ArtifactReference],
    compact: bool,
) -> dict[str, object] | None:
    """Project the latest v2 diagnostic without raw addresses or maps."""

    eligible = sorted(
        (
            item
            for item in state.experiments
            if (
                item.status is ExperimentStatus.COMPLETED
                and item.extra.get("engine_executor")
                == _PWN_RUNTIME_SNAPSHOT_ENGINE_EXECUTOR
                and item.extra.get("managed_contract_version") == 2
                and type(item.result) is dict
                and set(item.result)
                == {_PWN_RUNTIME_SNAPSHOT_RESULT_KEY}
            )
        ),
        key=_recent_key,
        reverse=True,
    )
    if not eligible:
        return None
    experiment = eligible[0]
    evidence = experiment.result[_PWN_RUNTIME_SNAPSHOT_RESULT_KEY]
    if type(evidence) is not dict:
        raise ModelValidationError(
            "Pwn disclosure resume evidence is not canonical"
        )
    evaluation = evidence.get("evaluation")
    if type(evaluation) is not dict:
        raise ModelValidationError(
            "Pwn disclosure resume evaluation is not canonical"
        )
    envelope = PwnRuntimeSnapshotDisclosureEnvelope.from_dict(
        experiment.extra.get("pwn_disclosure")
    )
    result = envelope.result
    pointers: list[dict[str, object]] = []
    for label, key in (
        ("stderr", "stderr_artifact_id"),
        ("stdout", "stdout_artifact_id"),
        ("capability", "capability_attestation_artifact_id"),
    ):
        artifact_id = evidence.get(key)
        artifact = (
            artifacts.get(artifact_id)
            if isinstance(artifact_id, str)
            else None
        )
        if (
            artifact is None
            or type(artifact.sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", artifact.sha256) is None
            or type(artifact.size) is not int
            or artifact.size < 0
        ):
            raise ModelValidationError(
                "Pwn disclosure resume artifact pointer is invalid"
            )
        pointers.append(
            {
                "artifact_id": artifact.id,
                "label": label,
                "path": artifact.path,
                "sha256": artifact.sha256,
                "size": artifact.size,
            }
        )
    if compact:
        projection: dict[str, object] = {
            "artifact_pointer": pointers[0],
            "diagnostic_only": True,
        }
        if result is None:
            projection["phase"] = envelope.phase.value
        return projection
    projection: dict[str, object] = {
        "artifact_pointers": pointers,
        "candidate_count": (
            len(result.candidates) if result is not None else 0
        ),
        "diagnostic_only": True,
        "evaluation_source_state_revision": (
            envelope.evaluation_source_state_revision
        ),
        "expectation_source_state_revision": (
            envelope.expectation_source_state_revision
        ),
        "experiment_id": experiment.id,
        "parent_experiment_id": experiment.extra.get(
            "parent_experiment_id"
        ),
        "phase": envelope.phase.value,
        "result_reason_code": (
            result.reason_code if result is not None else None
        ),
        "result_sha256": envelope.result_sha256,
        "result_status": (
            result.status.value if result is not None else None
        ),
        "snapshot_reason_code": evaluation.get("reason_code"),
        "snapshot_status": evaluation.get("status"),
        "trusted_receipt_expectation_sha256": (
            envelope.trusted_receipt_expectation_sha256
        ),
    }
    return projection


def _pwn_crash_artifact_pointer(
    artifact: ArtifactReference | None,
    *,
    experiment_id: str,
    recipe_sha256: str,
    run_id: str,
    ordinal: int,
    phase: str,
    stream: str,
) -> dict[str, object]:
    """Project one exact engine-owned stream artifact, never free-form text."""

    expected_id = f"A-{run_id}-{stream}"
    expected_path = (
        "artifacts/snapshots/"
        f"pwn-crash-{recipe_sha256}/"
        f"{ordinal:02d}-{run_id}-{stream}.log"
    )
    if (
        artifact is None
        or artifact.id != expected_id
        or artifact.path != expected_path
        or artifact.source_run_id != run_id
        or type(artifact.sha256) is not str
        or not re.fullmatch(r"[0-9a-f]{64}", artifact.sha256)
        or type(artifact.size) is not int
        or artifact.size < 0
        or artifact.extra
        != {
            "stream": stream,
            "engine_executor": _PWN_CRASH_ENGINE_EXECUTOR,
            "recipe_sha256": recipe_sha256,
            "ordinal": ordinal,
            "phase": phase,
            "capture_placeholder": artifact.extra.get(
                "capture_placeholder"
            ),
        }
        or type(artifact.extra.get("capture_placeholder")) is not bool
    ):
        raise ModelValidationError(
            f"Pwn crash experiment {experiment_id} has an invalid "
            f"{stream} artifact pointer"
        )
    return {
        "capture_placeholder": artifact.extra["capture_placeholder"],
        "id": artifact.id,
        "path": artifact.path,
        "sha256": artifact.sha256,
        "size": artifact.size,
    }


def _pwn_crash_run_pointer(
    run: RunReference | None,
    *,
    experiment_id: str,
    compact: bool,
) -> dict[str, object]:
    """Project one exact durable run pointer after the state graph validates."""

    if (
        run is None
        or run.role != "pwn_crash_gate"
        or run.status not in _TERMINAL_RUN_STATUSES
        or run.extra.get("experiment_id") != experiment_id
    ):
        raise ModelValidationError(
            f"Pwn crash experiment {experiment_id} has an invalid run pointer"
        )
    expected_paths = {
        "request_path": f"runs/{run.id}/request.json",
        "result_path": f"runs/{run.id}/result.json",
        "validation_path": f"runs/{run.id}/validation.json",
    }
    if any(
        getattr(run, label) != expected
        for label, expected in expected_paths.items()
    ):
        raise ModelValidationError(
            f"Pwn crash experiment {experiment_id} has a non-canonical "
            "durable run path"
        )
    pointer: dict[str, object] = {
        "id": run.id,
        "status": run.status.value,
    }
    if compact:
        pointer["result_path"] = expected_paths["result_path"]
    else:
        pointer.update(expected_paths)
    return pointer


def _pwn_crash_projection(
    experiment: Experiment,
    *,
    receipts: tuple[ExecutionReceipt, ...],
    runs: Mapping[str, RunReference],
    artifacts: Mapping[str, ArtifactReference],
    compact: bool,
    include_experiment_id: bool,
) -> dict[str, object]:
    """Render the latest typed D→V verdict with exact durable pointers."""

    attempt_links = _pwn_crash_attempt_links(experiment)
    if (
        attempt_links is None
        or len(receipts) != PWN_CRASH_V1_ATTEMPT_COUNT
    ):
        raise ModelValidationError(
            f"Pwn crash experiment {experiment.id} has no canonical "
            "six-receipt terminal result"
        )
    assert isinstance(experiment.result, dict)
    evidence = experiment.result[_PWN_CRASH_RESULT_KEY]
    if type(evidence) is not dict:
        raise ModelValidationError(
            f"Pwn crash experiment {experiment.id} evidence is not an object"
        )
    evaluation = evidence.get("evaluation")
    verdict = (
        evaluation.get("verdict")
        if type(evaluation) is dict
        else None
    )
    reason_code = (
        evaluation.get("reason_code")
        if type(evaluation) is dict
        else None
    )
    evaluation_sha256 = evidence.get("evaluation_sha256")
    recipe_sha256 = evidence.get("recipe_sha256")
    if (
        type(verdict) is not str
        or not re.fullmatch(r"[A-Z_]{1,64}", verdict)
        or type(reason_code) is not str
        or not re.fullmatch(r"[a-z0-9_]{1,160}", reason_code)
        or type(evaluation_sha256) is not str
        or not re.fullmatch(r"[0-9a-f]{64}", evaluation_sha256)
        or type(recipe_sha256) is not str
        or not re.fullmatch(r"[0-9a-f]{64}", recipe_sha256)
    ):
        raise ModelValidationError(
            f"Pwn crash experiment {experiment.id} verdict projection is "
            "invalid"
        )

    compact_ordinal = 1
    compact_stream = "stdout"
    if compact:
        failure_records = evaluation.get("failures")
        if isinstance(failure_records, list):
            causal_failure = next(
                (
                    item
                    for item in failure_records
                    if (
                        type(item) is dict
                        and type(item.get("attempt_ordinal")) is int
                        and 1
                        <= item["attempt_ordinal"]
                        <= PWN_CRASH_V1_ATTEMPT_COUNT
                    )
                ),
                None,
            )
            if causal_failure is not None:
                compact_ordinal = int(
                    causal_failure["attempt_ordinal"]
                )
                failure_code = causal_failure.get("code")
                if (
                    isinstance(failure_code, str)
                    and failure_code.startswith("stderr_")
                ):
                    compact_stream = "stderr"

    attempt_records: list[dict[str, object]] = []
    for expected_ordinal, (link, receipt) in enumerate(
        zip(attempt_links, receipts, strict=True),
        start=1,
    ):
        if type(link) is not dict:
            raise ModelValidationError(
                f"Pwn crash experiment {experiment.id} attempt link is "
                "not canonical"
            )
        run_id = link.get("run_id")
        receipt_id = link.get("receipt_id")
        stdout_id = link.get("stdout_artifact_id")
        run = runs.get(run_id) if isinstance(run_id, str) else None
        pwn_record = (
            run.extra.get("pwn_crash")
            if run is not None
            else None
        )
        phase = (
            pwn_record.get("phase")
            if type(pwn_record) is dict
            else None
        )
        expected_phase = (
            "positive" if expected_ordinal <= 3 else "control"
        )
        if (
            link.get("ordinal") != expected_ordinal
            or receipt.id != receipt_id
            or receipt.run_id != run_id
            or receipt.experiment_id != experiment.id
            or receipt.stdout_artifact_id != stdout_id
            or not isinstance(receipt.stderr_artifact_id, str)
            or phase != expected_phase
        ):
            raise ModelValidationError(
                f"Pwn crash experiment {experiment.id} attempt "
                f"{expected_ordinal} receipt order changed"
            )
        stdout = (
            artifacts.get(stdout_id)
            if isinstance(stdout_id, str)
            else None
        )
        stderr = artifacts.get(receipt.stderr_artifact_id)
        run_pointer = _pwn_crash_run_pointer(
            run,
            experiment_id=experiment.id,
            compact=compact,
        )
        stdout_pointer = _pwn_crash_artifact_pointer(
            stdout,
            experiment_id=experiment.id,
            recipe_sha256=recipe_sha256,
            run_id=run_id,
            ordinal=expected_ordinal,
            phase=expected_phase,
            stream="stdout",
        )
        stderr_pointer = _pwn_crash_artifact_pointer(
            stderr,
            experiment_id=experiment.id,
            recipe_sha256=recipe_sha256,
            run_id=run_id,
            ordinal=expected_ordinal,
            phase=expected_phase,
            stream="stderr",
        )
        record: dict[str, object]
        if compact:
            record = {
                "artifact": (
                    stderr_pointer
                    if compact_stream == "stderr"
                    else stdout_pointer
                ),
                "ordinal": expected_ordinal,
                "run_id": run_pointer["id"],
            }
        else:
            record = {
                "artifacts": {
                    "stderr": stderr_pointer,
                    "stdout": stdout_pointer,
                },
                "ordinal": expected_ordinal,
                "phase": expected_phase,
                "receipt_id": receipt.id,
                "run": run_pointer,
            }
        attempt_records.append(record)

    if compact:
        # One exact run/artifact chain is the minimum durable handoff.  The
        # canonical state pointer remains authoritative for the other five.
        attempt_records = [attempt_records[compact_ordinal - 1]]
    projection = {
        "attempt_count": PWN_CRASH_V1_ATTEMPT_COUNT,
        "attempts": attempt_records,
        "reason_code": reason_code,
        "verdict": verdict,
    }
    if not compact:
        projection["evaluation_sha256"] = evaluation_sha256
        projection["recipe_sha256"] = recipe_sha256
    if include_experiment_id:
        projection["experiment_id"] = experiment.id
    return projection


def _verified_stream_pointers(
    receipt: ExecutionReceipt,
    *,
    artifacts: Mapping[str, ArtifactReference],
) -> list[dict[str, object]]:
    """Return metadata only after the receipt/artifact links agree exactly."""

    raw = receipt.extra.get("stream_evidence")
    if raw is None:
        return []
    if not isinstance(raw, Mapping):
        raise ModelValidationError(
            f"receipt {receipt.id} stream_evidence must be an object"
        )
    pointers: list[dict[str, object]] = []
    for stream in ("stdout", "stderr"):
        expected_id = (
            receipt.stdout_artifact_id
            if stream == "stdout"
            else receipt.stderr_artifact_id
        )
        evidence = raw.get(stream)
        if expected_id is None:
            if evidence is not None:
                raise ModelValidationError(
                    f"receipt {receipt.id} has unexpected {stream} evidence"
                )
            continue
        if not isinstance(evidence, Mapping):
            raise ModelValidationError(
                f"receipt {receipt.id} lacks {stream} evidence"
            )
        artifact = artifacts.get(expected_id)
        if artifact is None:
            raise ModelValidationError(
                f"receipt {receipt.id} references unknown artifact "
                f"{expected_id}"
            )
        stored_bytes = evidence.get("stored_bytes")
        coverage = evidence.get("coverage")
        if (
            evidence.get("artifact_id") != artifact.id
            or evidence.get("path") != artifact.path
            or evidence.get("sha256") != artifact.sha256
            or stored_bytes != artifact.size
            or artifact.source_run_id != receipt.run_id
            or coverage
            not in {
                "complete_stream",
                "retained_prefix_only",
                "incomplete_capture",
                "unknown",
            }
        ):
            raise ModelValidationError(
                f"receipt {receipt.id} has an invalid {stream} "
                "artifact evidence chain"
            )
        pointers.append(
            {
                "artifact_id": artifact.id,
                "coverage": coverage,
                "path": artifact.path,
                "sha256": artifact.sha256,
                "size": artifact.size,
                "stream": stream,
            }
        )
    if set(raw) != {
        item["stream"]
        for item in pointers
    }:
        raise ModelValidationError(
            f"receipt {receipt.id} stream evidence keys do not match "
            "its artifacts"
        )
    return pointers


def _receipt_digest(
    receipt: ExecutionReceipt,
    *,
    runs: Mapping[str, RunReference],
    artifacts: Mapping[str, ArtifactReference],
) -> dict[str, object]:
    run = runs.get(receipt.run_id)
    if (
        run is None
        or run.status not in _TERMINAL_RUN_STATUSES
        or run.status is not _RUN_STATUS_FOR_OUTCOME[receipt.outcome]
    ):
        raise ModelValidationError(
            f"receipt {receipt.id} has an invalid terminal run chain"
        )
    pointers = _verified_stream_pointers(
        receipt,
        artifacts=artifacts,
    )
    return {
        "artifacts": pointers,
        "exit_code": receipt.exit_code,
        "id": receipt.id,
        "outcome": receipt.outcome.value,
        "run_id": run.id,
        "run_status": run.status.value,
        "summary_available": any(
            isinstance(item.get("size"), int) and int(item["size"]) > 0
            for item in pointers
        ),
    }


def _experiment_digest(
    experiment: Experiment,
    *,
    selection_reason: str,
    receipts_by_id: Mapping[str, ExecutionReceipt],
    receipts_by_experiment: Mapping[
        str,
        tuple[ExecutionReceipt, ...],
    ],
    runs: Mapping[str, RunReference],
    artifacts: Mapping[str, ArtifactReference],
) -> dict[str, object]:
    hypothesis_ids, hypothesis_ids_omitted = _bounded_ids(
        experiment.hypothesis_ids
    )
    fact_ids, fact_ids_omitted = _bounded_ids(
        experiment.evidence_fact_ids
    )
    result_run_id: str | None = None
    result_receipt_id: str | None = None
    if isinstance(experiment.result, Mapping):
        raw_run_id = experiment.result.get("run_id")
        raw_receipt_id = experiment.result.get("receipt_id")
        if raw_run_id is not None:
            if not isinstance(raw_run_id, str) or raw_run_id not in runs:
                raise ModelValidationError(
                    f"experiment {experiment.id} result has an invalid run"
                )
            result_run_id = raw_run_id
        if raw_receipt_id is not None:
            if (
                not isinstance(raw_receipt_id, str)
                or raw_receipt_id not in receipts_by_id
            ):
                raise ModelValidationError(
                    f"experiment {experiment.id} result has an invalid "
                    "receipt"
                )
            result_receipt_id = raw_receipt_id

    receipt_sequence = receipts_by_experiment.get(experiment.id, ())
    if len(receipt_sequence) > 1 and _pwn_crash_attempt_links(
        experiment
    ) is None:
        raise ModelValidationError(
            f"experiment {experiment.id} has more than one receipt"
        )
    receipt = receipt_sequence[0] if len(receipt_sequence) == 1 else None
    if (
        result_receipt_id is not None
        and (
            receipt is None
            or receipt.id != result_receipt_id
            or receipt.experiment_id != experiment.id
        )
    ):
        raise ModelValidationError(
            f"experiment {experiment.id} result receipt chain is mismatched"
        )
    if (
        receipt is not None
        and result_run_id is not None
        and receipt.run_id != result_run_id
    ):
        raise ModelValidationError(
            f"experiment {experiment.id} result run chain is mismatched"
        )

    receipt_record = (
        _receipt_digest(
            receipt,
            runs=runs,
            artifacts=artifacts,
        )
        if receipt is not None
        else None
    )
    safe_evaluation_reason = _safe_engine_evaluation_reason(experiment)
    return {
        "command_sha256": _command_sha256(experiment),
        "contract_sha256": _experiment_contract_sha256(experiment),
        "evaluated_at": _bounded(experiment.evaluated_at, 64),
        "evaluation_reason": safe_evaluation_reason,
        "evaluation_reason_available": bool(
            (experiment.evaluation_reason or "").strip()
        ),
        "fact_ids": fact_ids,
        "fact_ids_omitted": fact_ids_omitted,
        "hypothesis_ids": hypothesis_ids,
        "hypothesis_ids_omitted": hypothesis_ids_omitted,
        "id": experiment.id,
        "kind": experiment.kind.value,
        "receipt": receipt_record,
        # Existence alone is not a causal experiment/run binding.  A run is
        # exposed only inside the independently validated receipt above.
        "run": None,
        "selection_reason": selection_reason,
        "status": experiment.status.value,
        "summary_available": bool(
            fact_ids
            or (
                receipt_record is not None
                and receipt_record["summary_available"] is True
            )
        ),
    }


def _fact_digest(
    fact: Fact,
    *,
    runs: Mapping[str, RunReference],
    artifacts: Mapping[str, ArtifactReference],
    receipts_by_run: Mapping[str, ExecutionReceipt],
    pointer_only: bool = False,
) -> dict[str, object]:
    run = runs.get(fact.source_run_id or "")
    artifact = artifacts.get(fact.artifact_id or "")
    if (
        fact.provenance is not Provenance.EXECUTED
        or run is None
        or run.status not in _TERMINAL_RUN_STATUSES
        or artifact is None
        or artifact.source_run_id != run.id
    ):
        raise ModelValidationError(
            f"confirmed fact {fact.id} has an invalid run/artifact chain"
        )
    coverage: str | None = None
    receipt = receipts_by_run.get(run.id)
    if receipt is not None:
        pointers = _verified_stream_pointers(
            receipt,
            artifacts=artifacts,
        )
        matching = next(
            (
                item
                for item in pointers
                if item["artifact_id"] == artifact.id
            ),
            None,
        )
        if matching is not None:
            coverage = str(matching["coverage"])
    digest: dict[str, object] = {
        "artifact": {
            "coverage": coverage,
            "id": artifact.id,
            "path": artifact.path,
            "sha256": artifact.sha256,
            "size": artifact.size,
        },
        "fact_ids": [fact.id],
        "run_id": run.id,
        "run_status": run.status.value,
    }
    if pointer_only:
        return digest
    hypothesis_ids, hypothesis_ids_omitted = _bounded_ids(
        [*fact.supports, *fact.contradicts]
    )
    digest.update(
        {
            "hypothesis_ids": hypothesis_ids,
            "hypothesis_ids_omitted": hypothesis_ids_omitted,
            "kind": fact.kind.value,
            "locator": _bounded_canonical_text(
                fact.locator,
                maximum_bytes=192,
            ),
            "provenance": fact.provenance.value,
            "summary": _bounded_canonical_text(
                fact.statement,
                maximum_bytes=240,
            ),
            "summary_available": bool(fact.statement.strip()),
        }
    )
    return digest


def _failure_run_priority(run: RunReference) -> tuple[int, str, str]:
    return (
        0
        if run.status
        in {
            RunStatus.INVALID,
            RunStatus.FAILED,
            RunStatus.TIMED_OUT,
            RunStatus.CANCELLED,
            RunStatus.INTERRUPTED,
        }
        else 1
        if run.role == "captain"
        else 2,
        run.created_at,
        run.id,
    )


def _pwn_failure_run_priority(
    run: RunReference,
    *,
    selected_pwn_experiment_ids: frozenset[str],
) -> tuple[int, str, str]:
    """Keep negative evidence first, then the typed gate ahead of Captain."""

    selected_pwn = (
        run.role == "pwn_crash_gate"
        and run.extra.get("experiment_id")
        in selected_pwn_experiment_ids
    )
    if run.extra.get("managed_rejection_v1") is not None:
        priority = 0
    elif run.role == "pwn_crash_gate" and not selected_pwn:
        priority = 4
    elif run.status in {
        RunStatus.INVALID,
        RunStatus.FAILED,
        RunStatus.TIMED_OUT,
        RunStatus.CANCELLED,
        RunStatus.INTERRUPTED,
    }:
        priority = 0
    elif selected_pwn:
        priority = 1
    elif run.role == "captain":
        priority = 2
    else:
        priority = 3
    return priority, run.created_at, run.id


def _failure_pointer_run(
    runs: tuple[RunReference, ...],
    *,
    selected_pwn_experiment_ids: frozenset[str],
) -> tuple[RunReference, bool]:
    contains_typed_pwn_failure = bool(selected_pwn_experiment_ids)
    priority = lambda run: _pwn_failure_run_priority(
        run,
        selected_pwn_experiment_ids=selected_pwn_experiment_ids,
    )
    pointer_runs = [
        run
        for run in sorted(runs, key=priority)
        if (
            (
                run.role != "pwn_crash_gate"
                or run.extra.get("experiment_id")
                in selected_pwn_experiment_ids
            )
            and (
                run.result_path is not None
                or run.validation_path is not None
            )
        )
    ][:1]
    if not pointer_runs:
        raise ModelValidationError(
            "failure capsule has no exact run result or validation pointer"
        )
    return pointer_runs[0], contains_typed_pwn_failure


def _selected_pwn_failure_experiments(
    state: ChallengeState,
    *,
    cycle_id: str,
    failed_experiments: tuple[Experiment, ...],
) -> tuple[Experiment, ...]:
    """Return only cycle-selected typed Pwn non-pass evidence."""

    cycle = next(
        (item for item in state.cycles if item.id == cycle_id),
        None,
    )
    if cycle is None:
        raise ModelValidationError(
            "failure capsule Pwn projection references a missing cycle"
        )
    selected_ids = set(cycle.selected_action_ids)
    return tuple(
        experiment
        for experiment in failed_experiments
        if (
            experiment.id in selected_ids
            and experiment.status
            in {
                ExperimentStatus.INCONCLUSIVE,
                ExperimentStatus.FAILED,
            }
            and _pwn_crash_attempt_links(experiment) is not None
        )
    )


def _checkpoint_pwn_pointer_experiment(
    state: ChallengeState,
) -> Experiment | None:
    """Resolve a checkpoint Pwn pointer to its exact failed experiment."""

    if not state.checkpoints:
        return None
    checkpoint = state.checkpoints[-1]
    if (
        checkpoint.failure_capsule is None
        or checkpoint.session_id is None
        or checkpoint.cycle_id is None
    ):
        return None
    _runs, failed_experiments, _next_experiments = (
        validate_failure_capsule(
            state,
            checkpoint.failure_capsule,
            session_id=checkpoint.session_id,
            cycle_id=checkpoint.cycle_id,
        )
    )
    matches = _selected_pwn_failure_experiments(
        state,
        cycle_id=checkpoint.cycle_id,
        failed_experiments=failed_experiments,
    )
    if not matches:
        return None
    return matches[0]


def _failure_occurrence_summary(
    state: ChallengeState,
    checkpoint: Any,
) -> tuple[int, int]:
    capsule = checkpoint.failure_capsule
    window = state.checkpoints[-MAX_FAILURE_HISTORY_CHECKPOINTS:]
    cycle_bindings: set[tuple[str, str]] = set()
    for item in window:
        prior = getattr(item, "failure_capsule", None)
        if (
            prior is None
            or prior.fingerprint_sha256 != capsule.fingerprint_sha256
        ):
            continue
        if item.session_id is None or item.cycle_id is None:
            raise ModelValidationError(
                "historical failure capsule requires a session and cycle"
            )
        if item is not checkpoint:
            validate_failure_capsule(
                state,
                prior,
                session_id=item.session_id,
                cycle_id=item.cycle_id,
            )
        cycle_bindings.add((item.session_id, item.cycle_id))
    return (
        len(cycle_bindings),
        max(0, len(state.checkpoints) - len(window)),
    )


def _failure_capsule_digest(
    state: ChallengeState,
    checkpoint: Any,
    *,
    compact: bool = False,
) -> dict[str, object] | None:
    capsule = getattr(checkpoint, "failure_capsule", None)
    if capsule is None:
        return None
    if checkpoint.session_id is None or checkpoint.cycle_id is None:
        raise ModelValidationError(
            "checkpoint failure capsule requires a session and cycle"
        )
    runs, failed_experiments, next_experiments = (
        validate_failure_capsule(
            state,
            capsule,
            session_id=checkpoint.session_id,
            cycle_id=checkpoint.cycle_id,
        )
    )
    occurrence_count, occurrence_history_omitted = (
        _failure_occurrence_summary(
            state,
            checkpoint,
        )
    )
    next_experiments_stale = (
        len(capsule.next_experiment_ids) - len(next_experiments)
    )
    active_hypothesis_ids = {
        item.id
        for item in state.hypotheses
        if item.status in ACTIVE_HYPOTHESIS_STATUSES
    }
    active_unresolved_hypothesis_ids = [
        item_id
        for item_id in capsule.unresolved_hypothesis_ids
        if item_id in active_hypothesis_ids
    ]
    unresolved_hypotheses_stale = (
        len(capsule.unresolved_hypothesis_ids)
        - len(active_unresolved_hypothesis_ids)
    )

    # One exact result/validation pointer keeps the failure digest inside the
    # mandatory 1536-byte resume floor. Prefer a negative run; a Captain-only
    # frontier rejection naturally selects its completed Captain run. The
    # fingerprint and run_count still cover the complete cycle slice.
    selected_pwn_failures = _selected_pwn_failure_experiments(
        state,
        cycle_id=checkpoint.cycle_id,
        failed_experiments=failed_experiments,
    )
    selected_pwn_experiment_ids = frozenset(
        experiment.id for experiment in selected_pwn_failures
    )
    pointer_run, contains_typed_pwn_failure = _failure_pointer_run(
        runs,
        selected_pwn_experiment_ids=selected_pwn_experiment_ids,
    )
    pointer_runs = [pointer_run]
    run_records = []
    for run in pointer_runs:
        diagnostics = safe_run_diagnostics(run)
        if compact:
            managed_rejection = diagnostics.get("managed_rejection")
            machine_kinds = diagnostics["machine_failure_kinds"]
            machine_failure_retryable_count = diagnostics[
                "machine_failure_retryable_count"
            ]
            machine_failure_kinds_omitted = diagnostics[
                "machine_failure_kinds_omitted"
            ]
            compact_kind_limit = 2
            if isinstance(managed_rejection, Mapping):
                rejection_issues = managed_rejection.get("issues", [])
                if not isinstance(rejection_issues, list):
                    raise ModelValidationError(
                        "managed rejection issues are not an array"
                    )
                compact_issue_limit = 2
                compact_rejections = [
                    {
                        key: issue[key]
                        for key in (
                            "code",
                            "pointer",
                            "proposal_ordinal",
                        )
                        if key in issue
                    }
                    for issue in rejection_issues[:compact_issue_limit]
                    if isinstance(issue, Mapping)
                ]
                diagnostics = {
                    "managed_rejection": compact_rejections,
                }
                rejection_issues_omitted = (
                    int(managed_rejection["issues_omitted"])
                    + max(
                        0,
                        len(rejection_issues) - compact_issue_limit,
                    )
                )
                if rejection_issues_omitted:
                    diagnostics["managed_rejection_issues_omitted"] = (
                        rejection_issues_omitted
                    )
                if machine_kinds:
                    diagnostics["failure_kinds"] = [
                        item["kind"]
                        for item in machine_kinds[:compact_kind_limit]
                    ]
                    omitted_failure_kinds = (
                        int(machine_failure_kinds_omitted)
                        + max(
                            0,
                            len(machine_kinds) - compact_kind_limit,
                        )
                    )
                    if omitted_failure_kinds:
                        diagnostics["failure_kinds_omitted"] = (
                            omitted_failure_kinds
                        )
                if machine_failure_retryable_count:
                    diagnostics["retryable_count"] = (
                        machine_failure_retryable_count
                    )
            else:
                diagnostics = {
                    "contract_errors": diagnostics[
                        "contract_error_count"
                    ],
                    "failure_kinds": [
                        item["kind"]
                        for item in machine_kinds[:compact_kind_limit]
                    ],
                    "failure_kinds_omitted": (
                        int(diagnostics["machine_failure_kinds_omitted"])
                        + max(
                            0,
                            len(machine_kinds) - compact_kind_limit,
                        )
                    ),
                    "failure_records_over_soft_limit": diagnostics[
                        "machine_failure_records_over_soft_limit"
                    ],
                    "malformed_fields": diagnostics[
                        "malformed_failure_field_count"
                    ],
                    "normalization_error": diagnostics[
                        "normalization_error_present"
                    ],
                    "retryable_count": diagnostics[
                        "machine_failure_retryable_count"
                    ],
                }
        result_path = _exact_run_pointer(
            run.result_path,
            run_id=run.id,
            label="result_path",
        )
        validation_path = _exact_run_pointer(
            run.validation_path,
            run_id=run.id,
            label="validation_path",
        )
        run_record = {
            "diagnostics": diagnostics,
            "id": run.id,
            "role": run.role,
            "status": run.status.value,
        }
        if result_path is not None and (
            not compact or validation_path is None
        ):
            run_record["result_path"] = result_path
        if validation_path is not None:
            run_record["validation_path"] = validation_path
        run_records.append(run_record)
    failed_records = [
        {
            "command_sha256": experiment_command_sha256(experiment),
            "id": experiment.id,
            "kind": experiment.kind.value,
        }
        for experiment in failed_experiments[:1]
    ]
    next_records = [
        (
            {"id": experiment.id}
            if compact
            else {
                "command_sha256": experiment_command_sha256(experiment),
                "id": experiment.id,
                "kind": experiment.kind.value,
            }
        )
        for experiment in next_experiments
    ]
    if compact:
        run_count = (
            len(capsule.run_ids)
            + capsule.omitted_counts["run_ids"]
        )
        if contains_typed_pwn_failure:
            if pointer_run.role == "pwn_crash_gate":
                compact_digest: dict[str, object] = {
                    "fingerprint_sha256": capsule.fingerprint_sha256,
                    "occurrence_count": occurrence_count,
                    "reason_code": capsule.reason_code,
                    "stage": capsule.stage,
                }
                experiment_id = pointer_run.extra.get("experiment_id")
                if (
                    type(experiment_id) is not str
                    or experiment_id not in selected_pwn_experiment_ids
                ):
                    raise ModelValidationError(
                        "failure capsule Pwn pointer is not causally bound"
                    )
                # The exact run/artifact pointer is emitted by the top-level
                # projection selected from this same experiment.
                compact_digest["pwn_crash_pointer"] = experiment_id
            else:
                # A negative non-Pwn run remains more diagnostic than a
                # completed Pwn gate.  Preserve that selected pointer even
                # when the same cycle also contains typed Pwn evidence.
                run_record = run_records[0]
                compact_digest = {
                    "fingerprint_sha256": capsule.fingerprint_sha256,
                    "reason_code": capsule.reason_code,
                }
                compact_run = {
                    key: run_record[key]
                    for key in ("id", "status")
                }
                if "validation_path" in run_record:
                    compact_run["validation_path"] = run_record[
                        "validation_path"
                    ]
                elif "result_path" in run_record:
                    compact_run["result_path"] = run_record["result_path"]
                compact_digest["runs"] = [compact_run]
            return compact_digest
        failed_experiment_count = (
            len(capsule.failed_experiment_ids)
            + capsule.omitted_counts["failed_experiment_ids"]
        )
        digest = {
            "evidence_counts": {
                "artifacts": len(capsule.artifact_ids)
                + capsule.omitted_counts["artifact_ids"],
                "facts": len(capsule.fact_ids)
                + capsule.omitted_counts["fact_ids"],
                "receipts": len(capsule.receipt_ids)
                + capsule.omitted_counts["receipt_ids"],
            },
            "failed_experiment_ids": list(
                capsule.failed_experiment_ids[:1]
            ),
            "failed_experiments_omitted": max(
                0, failed_experiment_count - len(failed_records)
            ),
            "fingerprint_sha256": capsule.fingerprint_sha256,
            "next_experiments": next_records,
            "occurrence_count": occurrence_count,
            "reason_code": capsule.reason_code,
            "revisions": [
                capsule.state_revision_before,
                capsule.state_revision_after,
            ],
            "run_count": run_count,
            "runs": run_records,
            "runs_omitted": run_count - len(run_records),
            "schema_version": capsule.schema_version,
            "stage": capsule.stage,
            "unresolved_hypothesis_ids": list(
                active_unresolved_hypothesis_ids[:2]
            ),
            "unresolved_hypotheses_omitted": max(
                0,
                len(active_unresolved_hypothesis_ids)
                - 2
                + capsule.omitted_counts[
                    "unresolved_hypothesis_ids"
                ],
            ),
        }
        if next_experiments_stale:
            digest["next_experiments_stale"] = next_experiments_stale
        if capsule.omitted_counts["next_experiment_ids"]:
            digest["next_experiments_omitted"] = (
                capsule.omitted_counts["next_experiment_ids"]
            )
        if unresolved_hypotheses_stale:
            digest["unresolved_hypotheses_stale"] = (
                unresolved_hypotheses_stale
            )
        if occurrence_history_omitted:
            digest["occurrence_history_omitted"] = (
                occurrence_history_omitted
            )
        return digest
    digest = {
        "evidence_id_deltas": {
            "artifacts": _bounded_id_digest(
                list(capsule.artifact_ids),
                maximum=2,
                source_omitted=capsule.omitted_counts["artifact_ids"],
            ),
            "facts": _bounded_id_digest(
                list(capsule.fact_ids),
                maximum=2,
                source_omitted=capsule.omitted_counts["fact_ids"],
            ),
            "receipts": _bounded_id_digest(
                list(capsule.receipt_ids),
                maximum=2,
                source_omitted=capsule.omitted_counts["receipt_ids"],
            ),
        },
        "failed_experiment_count": (
            len(capsule.failed_experiment_ids)
            + capsule.omitted_counts["failed_experiment_ids"]
        ),
        "failed_experiments": failed_records,
        "failed_experiments_omitted": (
            len(capsule.failed_experiment_ids)
            + capsule.omitted_counts["failed_experiment_ids"]
            - len(failed_records)
        ),
        "fingerprint_sha256": capsule.fingerprint_sha256,
        "next_experiments": next_records,
        "occurrence_count": occurrence_count,
        "reason_code": capsule.reason_code,
        "run_count": (
            len(capsule.run_ids)
            + capsule.omitted_counts["run_ids"]
        ),
        "runs": run_records,
        "runs_omitted": (
            len(capsule.run_ids)
            + capsule.omitted_counts["run_ids"]
            - len(run_records)
        ),
        "schema_version": capsule.schema_version,
        "stage": capsule.stage,
        "state_revision_after": capsule.state_revision_after,
        "state_revision_before": capsule.state_revision_before,
        "unresolved_hypotheses": _bounded_id_digest(
            active_unresolved_hypothesis_ids,
            maximum=3,
            source_omitted=capsule.omitted_counts[
                "unresolved_hypothesis_ids"
            ],
        ),
    }
    if next_experiments_stale:
        digest["next_experiments_stale"] = next_experiments_stale
    if capsule.omitted_counts["next_experiment_ids"]:
        digest["next_experiments_omitted"] = (
            capsule.omitted_counts["next_experiment_ids"]
        )
    if unresolved_hypotheses_stale:
        digest["unresolved_hypotheses_stale"] = (
            unresolved_hypotheses_stale
        )
    if occurrence_history_omitted:
        digest["occurrence_history_omitted"] = occurrence_history_omitted
    return digest


def _checkpoint_digest(
    state: ChallengeState,
    *,
    compact_failure: bool = False,
) -> dict[str, object] | None:
    if not state.checkpoints:
        return None
    checkpoint = state.checkpoints[-1]
    failure_capsule = _failure_capsule_digest(
        state,
        checkpoint,
        compact=compact_failure,
    )
    if compact_failure and failure_capsule is not None:
        # The active goal and evidence indexes are already represented by
        # mandatory top-level/context records.  Under byte pressure retain
        # only the checkpoint binding and the failure evidence itself.
        return {
            "cycle_id": checkpoint.cycle_id,
            "failure_capsule": failure_capsule,
            "id": checkpoint.id,
        }
    digest = {
        "active_goal_id": checkpoint.active_goal_id,
        "artifact_count": len(checkpoint.artifact_ids),
        "cycle_id": checkpoint.cycle_id,
        "do_not_repeat_count": len(checkpoint.do_not_repeat),
        "fact_count": len(checkpoint.observation_fact_ids),
        "hypothesis_ids": list(checkpoint.open_hypothesis_ids[:12]),
        "hypothesis_ids_omitted": max(
            0, len(checkpoint.open_hypothesis_ids) - 12
        ),
        "id": checkpoint.id,
        "next_action_count": len(checkpoint.next_actions),
        "note_available": bool((checkpoint.note or "").strip()),
        "receipt_count": len(checkpoint.receipt_ids),
    }
    if failure_capsule is not None:
        digest["failure_capsule"] = failure_capsule
    return digest


def _pending_priority(
    state: ChallengeState,
) -> tuple[list[Experiment], dict[str, str]]:
    pending = [
        item for item in state.experiments if item.status in _PENDING_STATUSES
    ]
    pending_ids = {item.id for item in pending}
    checkpoint_cycle_ids: set[str] = set()
    checkpoint_receipt_ids: set[str] = set()
    if state.checkpoints:
        checkpoint = state.checkpoints[-1]
        checkpoint_receipt_ids.update(checkpoint.receipt_ids)
        if checkpoint.cycle_id is not None:
            cycle = next(
                (
                    item
                    for item in state.cycles
                    if item.id == checkpoint.cycle_id
                ),
                None,
            )
            if cycle is not None:
                checkpoint_cycle_ids.update(cycle.selected_action_ids)
    receipt_experiment_ids = {
        item.experiment_id
        for item in state.receipts
        if item.id in checkpoint_receipt_ids
    }
    checkpoint_linked = pending_ids.intersection(
        checkpoint_cycle_ids | receipt_experiment_ids
    )
    active_hypothesis_ids = {
        item.id
        for item in state.hypotheses
        if item.status in ACTIVE_HYPOTHESIS_STATUSES
    }
    active_linked = {
        item.id
        for item in pending
        if active_hypothesis_ids.intersection(item.hypothesis_ids)
    } - checkpoint_linked
    recent = pending_ids - checkpoint_linked - active_linked
    by_id = {item.id: item for item in pending}

    def newest(ids: set[str]) -> list[Experiment]:
        return sorted(
            (by_id[item_id] for item_id in ids),
            key=_recent_key,
            reverse=True,
        )

    ordered = [
        *newest(checkpoint_linked),
        *newest(active_linked),
        *newest(recent),
    ]
    reasons = {
        **{item_id: "checkpoint_or_cycle" for item_id in checkpoint_linked},
        **{item_id: "active_hypothesis" for item_id in active_linked},
        **{item_id: "recent" for item_id in recent},
    }
    return ordered, reasons


def render_resume_capsule(
    state: ChallengeState,
    *,
    state_path: Path,
    policy: ResumeCapsulePolicy = ResumeCapsulePolicy(),
) -> ResumeCapsule:
    """Render a bounded capsule without reading files or mutating state."""

    policy.validate()
    state.validate()
    if (
        state.schema_version != STATE_SCHEMA_VERSION
        and any(
            _pwn_crash_attempt_links(item) is not None
            for item in state.experiments
        )
    ):
        raise ModelValidationError(
            "typed Pwn crash resume projection requires the current "
            "state schema"
        )
    runs = {item.id: item for item in state.runs}
    artifacts = {item.id: item for item in state.artifacts}
    receipts_by_id, receipts_by_experiment = _receipt_maps(state)
    receipts_by_run = {item.run_id: item for item in state.receipts}
    experiment_ids = {item.id for item in state.experiments}
    for receipt in state.receipts:
        if receipt.experiment_id not in experiment_ids:
            raise ModelValidationError(
                f"receipt {receipt.id} references an unknown experiment"
            )
        _receipt_digest(
            receipt,
            runs=runs,
            artifacts=artifacts,
        )

    pending, pending_reasons = _pending_priority(state)
    negative = sorted(
        (
            item
            for item in state.experiments
            if item.status in _NEGATIVE_STATUSES
        ),
        key=_recent_key,
        reverse=True,
    )
    confirmed = sorted(
        (
            item
            for item in state.facts
            if item.provenance is Provenance.EXECUTED
        ),
        key=_recent_key,
        reverse=True,
    )
    totals = {
        "confirmed": len(confirmed),
        "negative": len(negative),
        "pending": len(pending),
    }

    selected_pending = [
        _experiment_digest(
            item,
            selection_reason=pending_reasons[item.id],
            receipts_by_id=receipts_by_id,
            receipts_by_experiment=receipts_by_experiment,
            runs=runs,
            artifacts=artifacts,
        )
        for item in pending[: policy.pending_limit]
    ]
    selected_negative = [
        _experiment_digest(
            item,
            selection_reason="recent",
            receipts_by_id=receipts_by_id,
            receipts_by_experiment=receipts_by_experiment,
            runs=runs,
            artifacts=artifacts,
        )
        for item in negative[: policy.negative_limit]
    ]
    selected_confirmed_facts = confirmed[: policy.confirmed_limit]
    selected_confirmed = [
        _fact_digest(
            item,
            runs=runs,
            artifacts=artifacts,
            receipts_by_run=receipts_by_run,
        )
        for item in selected_confirmed_facts
    ]
    compact_confirmed = [
        _fact_digest(
            item,
            runs=runs,
            artifacts=artifacts,
            receipts_by_run=receipts_by_run,
            pointer_only=True,
        )
        for item in selected_confirmed_facts
    ]
    confirmed_is_compact = [False] * len(selected_confirmed)
    compact_failure = False
    terminal_pwn_experiments = sorted(
        (
            item
            for item in state.experiments
            if _pwn_crash_attempt_links(item) is not None
        ),
        key=_recent_key,
        reverse=True,
    )
    selected_pwn_crash: dict[str, object] | None = None
    compact_pwn_crash: dict[str, object] | None = None
    pwn_crash_is_compact = False
    pwn_crash_is_checkpoint_pointer = False
    selected_pwn_disclosure = _pwn_disclosure_projection(
        state,
        artifacts=artifacts,
        compact=False,
    )
    compact_pwn_disclosure = _pwn_disclosure_projection(
        state,
        artifacts=artifacts,
        compact=True,
    )
    pwn_disclosure_parent_id = (
        selected_pwn_disclosure.get("parent_experiment_id")
        if selected_pwn_disclosure is not None
        else None
    )
    from ctf_os.engine.pwn_dependency_state import (
        project_pwn_dependency_context,
    )

    selected_pwn_dependency = project_pwn_dependency_context(
        state,
        compact=True,
    )
    pwn_disclosure_is_compact = False
    if terminal_pwn_experiments:
        checkpoint_pwn = _checkpoint_pwn_pointer_experiment(state)
        pwn_crash_is_checkpoint_pointer = checkpoint_pwn is not None
        latest_pwn = (
            checkpoint_pwn
            if checkpoint_pwn is not None
            else terminal_pwn_experiments[0]
        )
        pwn_receipts = receipts_by_experiment.get(latest_pwn.id, ())
        selected_pwn_crash = _pwn_crash_projection(
            latest_pwn,
            receipts=pwn_receipts,
            runs=runs,
            artifacts=artifacts,
            compact=False,
            include_experiment_id=True,
        )
        compact_pwn_crash = _pwn_crash_projection(
            latest_pwn,
            receipts=pwn_receipts,
            runs=runs,
            artifacts=artifacts,
            compact=True,
            include_experiment_id=True,
        )

    def payload() -> dict[str, object]:
        included = {
            "confirmed": len(selected_confirmed),
            "negative": len(selected_negative),
            "pending": len(selected_pending),
        }
        counts = {
            name: {
                "included": included[name],
                "omitted": totals[name] - included[name],
                "total": totals[name],
            }
            for name in ("pending", "negative", "confirmed")
        }
        result: dict[str, object] = {
            "canonical_state": str(state_path),
            "challenge_id": state.challenge_id,
            "checkpoint": _checkpoint_digest(
                state,
                compact_failure=compact_failure,
            ),
            "confirmed": selected_confirmed,
            "counts": counts,
            "kind": "resume_capsule",
            "negative": selected_negative,
            "pending": selected_pending,
            "policy": {
                "confirmed_limit": policy.confirmed_limit,
                "max_bytes": policy.max_bytes,
                "negative_limit": policy.negative_limit,
                "pending_limit": policy.pending_limit,
            },
            "revision": state.revision,
            "schema_version": RESUME_CAPSULE_SCHEMA_VERSION,
            "trust": "evidence",
        }
        if selected_pwn_crash is not None:
            result["pwn_crash"] = selected_pwn_crash
        if selected_pwn_disclosure is not None:
            result["pwn_disclosure"] = selected_pwn_disclosure
        if selected_pwn_dependency is not None:
            result["pwn_dependency"] = selected_pwn_dependency
        return result

    def render() -> str:
        return canonical_json_record(payload()) + "\n"

    text = render()
    # Keep at least one independently chained fact ahead of ordinary backlog.
    # A mandatory failure capsule may finally displace that fact after both
    # records have been compacted; the exact canonical state remains pointed
    # to by this record.
    while len(text.encode("ascii")) > policy.max_bytes:
        if selected_pwn_dependency is not None:
            # The exact graph remains canonical in state.json.  This summary
            # is useful continuity context, but never displaces the capsule's
            # mandatory index, failure record, or confirmed-fact pointer.
            selected_pwn_dependency = None
        elif selected_negative:
            selected_negative.pop()
        elif len(selected_pending) > 1:
            selected_pending.pop()
        elif any(not item for item in confirmed_is_compact):
            compact_index = next(
                index
                for index in range(len(confirmed_is_compact) - 1, -1, -1)
                if not confirmed_is_compact[index]
            )
            selected_confirmed[compact_index] = compact_confirmed[
                compact_index
            ]
            confirmed_is_compact[compact_index] = True
        elif (
            selected_pwn_crash is not None
            and compact_pwn_crash is not None
            and not pwn_crash_is_compact
        ):
            selected_pwn_crash = compact_pwn_crash
            pwn_crash_is_compact = True
        elif (
            selected_pwn_disclosure is not None
            and compact_pwn_disclosure is not None
            and not pwn_disclosure_is_compact
        ):
            selected_pwn_disclosure = compact_pwn_disclosure
            pwn_disclosure_is_compact = True
        elif (
            selected_pwn_disclosure is not None
            and selected_pwn_crash is not None
            and pwn_disclosure_is_compact
            and pwn_crash_is_compact
        ):
            selected_pwn_crash_id = selected_pwn_crash.get(
                "experiment_id"
            )
            if (
                not pwn_crash_is_checkpoint_pointer
                and type(pwn_disclosure_parent_id) is str
                and pwn_disclosure_parent_id == selected_pwn_crash_id
            ):
                selected_pwn_crash = None
                compact_pwn_crash = None
                selected_pwn_disclosure = {
                    **selected_pwn_disclosure,
                    "parent_crash_omitted": True,
                }
            else:
                selected_pwn_disclosure = None
                compact_pwn_disclosure = None
                selected_pwn_crash = {
                    **selected_pwn_crash,
                    "disclosure_omitted": True,
                }
        elif len(selected_confirmed) > 1:
            selected_confirmed.pop()
            compact_confirmed.pop()
            confirmed_is_compact.pop()
        elif selected_pending:
            selected_pending.pop()
        elif (
            state.checkpoints
            and state.checkpoints[-1].failure_capsule is not None
            and not compact_failure
        ):
            compact_failure = True
        elif (
            state.checkpoints
            and state.checkpoints[-1].failure_capsule is not None
            and selected_confirmed
        ):
            selected_confirmed.pop()
            compact_confirmed.pop()
            confirmed_is_compact.pop()
        elif selected_pwn_crash is not None and selected_confirmed:
            selected_confirmed.pop()
            compact_confirmed.pop()
            confirmed_is_compact.pop()
        else:
            raise ValueError(
                "resume capsule policy is too small for its mandatory "
                "index and confirmed fact pointer"
            )
        text = render()

    digest = hashlib.sha256(text.encode("ascii")).hexdigest()
    included_counts = {
        "confirmed": len(selected_confirmed),
        "negative": len(selected_negative),
        "pending": len(selected_pending),
    }
    omitted_counts = {
        name: totals[name] - included_counts[name]
        for name in totals
    }
    return ResumeCapsule(
        text=text,
        sha256=digest,
        total_counts=totals,
        included_counts=included_counts,
        omitted_counts=omitted_counts,
    )


__all__ = [
    "MAX_RESUME_CAPSULE_BYTES",
    "MIN_RESUME_CAPSULE_BYTES",
    "RESUME_CAPSULE_SCHEMA_VERSION",
    "ResumeCapsule",
    "ResumeCapsulePolicy",
    "render_resume_capsule",
]
