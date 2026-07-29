"""Deterministic, pointer-only state digest for resuming long solve sessions.

The capsule is deliberately rendered from canonical state only.  It never
opens artifacts and never copies command text, provider errors, transport
summaries, receipt previews, or checkpoint action text into model context.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ctf_os.models import (
    ACTIVE_HYPOTHESIS_STATUSES,
    ArtifactReference,
    ChallengeState,
    ExecutionReceipt,
    Experiment,
    ExperimentStatus,
    Fact,
    ModelValidationError,
    Provenance,
    ReceiptOutcome,
    RunReference,
    RunStatus,
)
from ctf_os.store.atomic import canonical_json_record


RESUME_CAPSULE_SCHEMA_VERSION = 1
MAX_RESUME_CAPSULE_BYTES = 12 * 1024
MIN_RESUME_CAPSULE_BYTES = 1536

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


def _receipt_maps(
    state: ChallengeState,
) -> tuple[dict[str, ExecutionReceipt], dict[str, ExecutionReceipt]]:
    by_id = {item.id: item for item in state.receipts}
    by_experiment: dict[str, ExecutionReceipt] = {}
    for receipt in state.receipts:
        prior = by_experiment.get(receipt.experiment_id)
        if prior is not None and prior.id != receipt.id:
            raise ModelValidationError(
                f"experiment {receipt.experiment_id} has more than one receipt"
            )
        by_experiment[receipt.experiment_id] = receipt
    return by_id, by_experiment


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
    receipts_by_experiment: Mapping[str, ExecutionReceipt],
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

    receipt = receipts_by_experiment.get(experiment.id)
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
    return {
        "command_sha256": _command_sha256(experiment),
        "drop_if": _bounded(experiment.drop_if),
        "evaluated_at": _bounded(experiment.evaluated_at, 64),
        "evaluation_reason": _bounded(experiment.evaluation_reason),
        "expected": _bounded(experiment.expected_observation),
        "fact_ids": fact_ids,
        "fact_ids_omitted": fact_ids_omitted,
        "hypothesis_ids": hypothesis_ids,
        "hypothesis_ids_omitted": hypothesis_ids_omitted,
        "id": experiment.id,
        "keep_if": _bounded(experiment.keep_if),
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


def _checkpoint_digest(state: ChallengeState) -> dict[str, object] | None:
    if not state.checkpoints:
        return None
    checkpoint = state.checkpoints[-1]
    return {
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
        return {
            "canonical_state": str(state_path),
            "challenge_id": state.challenge_id,
            "checkpoint": _checkpoint_digest(state),
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

    def render() -> str:
        return canonical_json_record(payload()) + "\n"

    text = render()
    # Keep at least one independently chained fact ahead of backlog under
    # byte pressure.  Facts first lose optional prose and relationship
    # annotations; only then may older fact pointers be omitted.
    while len(text.encode("ascii")) > policy.max_bytes:
        if selected_negative:
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
        elif len(selected_confirmed) > 1:
            selected_confirmed.pop()
            compact_confirmed.pop()
            confirmed_is_compact.pop()
        elif selected_pending:
            selected_pending.pop()
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
