"""Safe, deterministic failure evidence for one managed cycle.

The durable :class:`~ctf_os.models.FailureCapsule` stores only canonical
identifiers and a fingerprint.  This module derives those identifiers from
state and computes the fingerprint from a deliberately small machine-only
view.  Provider messages, commands, notes, paths, revisions, identifiers, and
other free-form text never enter the fingerprint.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from ctf_os.contracts.managed_rejection_v1 import (
    ManagedRejectionV1ContractError,
    managed_rejection_v1_canonical_json_bytes,
    validate_managed_rejection_v1_mapping,
)
from ctf_os.models import (
    ACTIVE_HYPOTHESIS_STATUSES,
    ChallengeState,
    Experiment,
    ExperimentStatus,
    FailureCapsule,
    ModelValidationError,
    RunReference,
    RunStatus,
)
from ctf_os.store.atomic import canonical_json_record


FAILURE_CAPSULE_SCHEMA_VERSION = 1
MAX_FAILURE_RUNS = 16
MAX_FAILED_EXPERIMENTS = 16
MAX_EVIDENCE_IDS = 32
MAX_UNRESOLVED_HYPOTHESES = 32
MAX_NEXT_EXPERIMENTS = 3
MAX_MACHINE_FAILURE_RECORDS = 128
MAX_MACHINE_FAILURE_KINDS = 32
MAX_MACHINE_IDENTIFIER_BYTES = 64
MAX_MANAGED_REJECTION_CONTEXT_ISSUES = 4
# Engine-generated Pwn run, receipt, and stream-artifact identifiers can
# exceed 64 canonical JSON bytes.  The collection cardinality limits below
# remain the primary capsule bound; 128 retains those exact evidence pointers
# without admitting the model-wide 256-byte identifier maximum.
MAX_CAPTURE_ID_CANONICAL_BYTES = 128

_MACHINE_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,63}")
_PWN_CRASH_ENGINE_COMMAND = "ctfos-engine:pwn-crash-v1"
_PWN_CRASH_ENGINE_EXECUTOR = "pwn_crash_differential_v1"
_PWN_CRASH_RESULT_KEY = "pwn_crash_evidence"
_PWN_CRASH_SETUP_FAILED_REASON = "pwn_crash_setup_failed"
_SAFE_FAILURE_KINDS = frozenset(
    {
        "challenge_budget_expired",
        "contract_invalid",
        "model_call_cancelled",
        "model_call_wait_timeout",
        "orchestration_error",
        "overloaded",
        "process_error",
        "process_exit",
        "process_launch",
        "process_output_incomplete",
        "process_timeout",
        "rate_limit",
        "rate_limit_exceeded",
        "server_error",
        "synthetic_failure",
        "timeout",
    }
)


def _machine_identifier(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not _MACHINE_IDENTIFIER.fullmatch(value)
        or len(value.encode("ascii")) > MAX_MACHINE_IDENTIFIER_BYTES
    ):
        raise ModelValidationError(
            f"failure capsule {label} must be a bounded machine identifier"
        )
    return value


def _canonical_id(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or "\x00" in value
        or len(value.encode("utf-8", errors="strict")) > 256
    ):
        raise ModelValidationError(
            f"failure capsule {label} must be a bounded canonical id"
        )
    return value


def _bounded_unique_projection(
    values: Sequence[str],
    *,
    maximum: int,
) -> tuple[tuple[str, ...], int]:
    unique = tuple(dict.fromkeys(values))
    safe = tuple(
        value
        for value in unique
        if (
            isinstance(value, str)
            and value.strip()
            and "\x00" not in value
            and len(canonical_json_record(value).encode("ascii"))
            <= MAX_CAPTURE_ID_CANONICAL_BYTES
        )
    )
    selected = safe[:maximum]
    return selected, max(0, len(unique) - len(selected))


def _safe_failure_kind(value: object) -> tuple[str, bool]:
    """Return a bounded token without exposing provider-controlled text."""

    if (
        isinstance(value, str)
        and value in _SAFE_FAILURE_KINDS
        and _MACHINE_IDENTIFIER.fullmatch(value)
        and len(value.encode("ascii")) <= MAX_MACHINE_IDENTIFIER_BYTES
    ):
        return value, False
    if isinstance(value, str):
        digest = hashlib.sha256(
            value.encode("utf-8", errors="replace")
        ).hexdigest()[:16]
        return f"external_{digest}", True
    return "malformed_kind", True


def _command_sha256(experiment: Experiment) -> str:
    try:
        payload = experiment.command.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise ModelValidationError(
            f"experiment {experiment.id} command is not valid UTF-8"
        ) from error
    return hashlib.sha256(payload).hexdigest()


def _pwn_crash_experiment_marker(experiment: Experiment) -> bool:
    return (
        experiment.command == _PWN_CRASH_ENGINE_COMMAND
        and experiment.extra.get("engine_executor")
        == _PWN_CRASH_ENGINE_EXECUTOR
    )


def bounded_pwn_crash_failure_reason(
    verdict: str,
    reason_code: str,
) -> str:
    """Project one typed Pwn verdict into a capsule-safe identifier."""

    if (
        not isinstance(verdict, str)
        or re.fullmatch(r"[A-Z_]{1,64}", verdict) is None
        or not isinstance(reason_code, str)
        or re.fullmatch(r"[a-z0-9_]{1,160}", reason_code) is None
    ):
        raise ModelValidationError(
            "typed Pwn failure verdict/reason is not canonical"
        )
    normalized_verdict = verdict.casefold()
    projected = f"pwn_crash_{reason_code}"
    if (
        len(projected.encode("ascii", errors="strict")) <= 64
        and projected.replace("_", "").isalnum()
        and projected[0].isalpha()
        and projected == projected.casefold()
    ):
        return projected
    digest = hashlib.sha256(
        f"{verdict}\0{reason_code}".encode("ascii", errors="strict")
    ).hexdigest()[:16]
    return f"pwn_crash_{normalized_verdict}_{digest}"


def selected_pwn_crash_failure_reason(
    state: ChallengeState,
    selected_action_ids: Sequence[str],
) -> str | None:
    """Derive the only valid Pwn failure reason for selected actions."""

    selected = set(selected_action_ids)
    reasons: list[str] = []
    for experiment in sorted(
        (
            item
            for item in state.experiments
            if (
                item.id in selected
                and _pwn_crash_experiment_marker(item)
                and item.status
                in {
                    ExperimentStatus.INCONCLUSIVE,
                    ExperimentStatus.FAILED,
                }
            )
        ),
        key=lambda item: item.id,
    ):
        result = experiment.result
        evidence = (
            result.get(_PWN_CRASH_RESULT_KEY)
            if isinstance(result, Mapping)
            else None
        )
        evaluation = (
            evidence.get("evaluation")
            if isinstance(evidence, Mapping)
            else None
        )
        verdict = (
            evaluation.get("verdict")
            if isinstance(evaluation, Mapping)
            else None
        )
        reason_code = (
            evaluation.get("reason_code")
            if isinstance(evaluation, Mapping)
            else None
        )
        expected_verdict = (
            "INCONCLUSIVE"
            if experiment.status is ExperimentStatus.INCONCLUSIVE
            else "ERROR"
        )
        if (
            isinstance(verdict, str)
            and verdict == expected_verdict
            and isinstance(reason_code, str)
            and reason_code
        ):
            reasons.append(
                bounded_pwn_crash_failure_reason(
                    verdict,
                    reason_code,
                )
            )
        else:
            reasons.append(_PWN_CRASH_SETUP_FAILED_REASON)
    if not reasons:
        return None
    distinct = tuple(sorted(set(reasons)))
    if len(distinct) == 1:
        return distinct[0]
    digest = hashlib.sha256(
        "\0".join(distinct).encode("ascii", errors="strict")
    ).hexdigest()[:16]
    return f"pwn_crash_nonpass_{digest}"


def validate_pwn_failure_capsule_binding(
    state: ChallengeState,
    capsule: FailureCapsule,
    *,
    cycle: Any,
) -> None:
    """Bind a typed Pwn checkpoint to its selected non-pass verdict."""

    selected_ids = tuple(cycle.selected_action_ids)
    selected_id_set = set(selected_ids)
    selected_pwn = tuple(
        experiment
        for experiment in state.experiments
        if (
            experiment.id in selected_id_set
            and _pwn_crash_experiment_marker(experiment)
        )
    )
    if not selected_pwn:
        if capsule.reason_code.startswith("pwn_crash_"):
            raise ModelValidationError(
                "failure capsule Pwn reason requires a selected typed "
                "Pwn non-pass"
            )
        return
    if any(
        experiment.status
        not in {
            ExperimentStatus.KEPT,
            ExperimentStatus.INCONCLUSIVE,
            ExperimentStatus.FAILED,
        }
        for experiment in selected_pwn
    ):
        raise ModelValidationError(
            "failure capsule cannot bind an active typed Pwn experiment"
        )
    expected_reason = selected_pwn_crash_failure_reason(
        state,
        selected_ids,
    )
    if expected_reason is None:
        if capsule.reason_code.startswith("pwn_crash_"):
            raise ModelValidationError(
                "failure capsule Pwn reason cannot bind only successful "
                "typed Pwn experiments"
            )
        selected_negative_non_pwn = any(
            experiment.id in selected_id_set
            and not _pwn_crash_experiment_marker(experiment)
            and experiment.status
            in {
                ExperimentStatus.DROPPED,
                ExperimentStatus.INCONCLUSIVE,
                ExperimentStatus.FAILED,
                ExperimentStatus.CANCELLED,
            }
            for experiment in state.experiments
        )
        if not selected_negative_non_pwn:
            raise ModelValidationError(
                "failure capsule cannot bind only successful typed Pwn "
                "experiments without a selected non-Pwn failure"
            )
        return
    if (
        capsule.reason_code != expected_reason
        or capsule.stage != "attack"
    ):
        raise ModelValidationError(
            "failure capsule reason/stage does not match its selected "
            "typed Pwn verdict"
        )


def _safe_failure_counts(run: RunReference) -> dict[str, object]:
    """Summarize typed diagnostics without retaining their messages."""

    raw_contract_errors = run.extra.get("contract_errors", ())
    if raw_contract_errors is None:
        raw_contract_errors = ()
    if not isinstance(raw_contract_errors, (list, tuple)):
        raise ModelValidationError(
            f"failure run {run.id} contract_errors must be an array"
        )

    raw_failures = run.extra.get("failures", ())
    if raw_failures is None:
        raw_failures = ()
    if not isinstance(raw_failures, (list, tuple)):
        raise ModelValidationError(
            f"failure run {run.id} failures must be an array"
        )
    counts: Counter[tuple[str, bool]] = Counter()
    malformed_count = 0
    for failure in raw_failures:
        if not isinstance(failure, Mapping):
            counts[("malformed_record", False)] += 1
            malformed_count += 1
            continue
        kind, malformed_kind = _safe_failure_kind(failure.get("kind"))
        malformed_count += int(malformed_kind)
        retryable = failure.get("retryable")
        if not isinstance(retryable, bool):
            retryable = False
            malformed_count += 1
        counts[(kind, retryable)] += 1
    distinct_kinds = sorted(
        {kind for kind, _retryable in counts},
        key=lambda kind: (
            -counts[(kind, True)] - counts[(kind, False)],
            kind,
        ),
    )
    included_kinds = sorted(
        distinct_kinds[:MAX_MACHINE_FAILURE_KINDS]
    )

    by_kind: list[dict[str, object]] = []
    for kind in included_kinds:
        retryable_count = counts[(kind, True)]
        non_retryable_count = counts[(kind, False)]
        by_kind.append(
            {
                "kind": kind,
                "non_retryable_count": non_retryable_count,
                "retryable_count": retryable_count,
                "total_count": retryable_count + non_retryable_count,
            }
        )
    diagnostics: dict[str, object] = {
        "contract_error_count": len(raw_contract_errors),
        "machine_failure_count": len(raw_failures),
        "machine_failure_non_retryable_count": sum(
            count
            for (_kind, retryable), count in counts.items()
            if not retryable
        ),
        "machine_failure_retryable_count": sum(
            count
            for (_kind, retryable), count in counts.items()
            if retryable
        ),
        "machine_failure_kinds": by_kind,
        "machine_failure_kinds_omitted": max(
            0,
            len(distinct_kinds) - len(included_kinds),
        ),
        "machine_failure_records_over_soft_limit": max(
            0,
            len(raw_failures) - MAX_MACHINE_FAILURE_RECORDS,
        ),
        "malformed_failure_field_count": malformed_count,
        "normalization_error_present": (
            run.extra.get("normalization_error") is not None
        ),
    }
    raw_managed_rejection = run.extra.get("managed_rejection_v1")
    if raw_managed_rejection is not None:
        try:
            managed_rejection = validate_managed_rejection_v1_mapping(
                raw_managed_rejection
            )
            encoded_rejection = (
                managed_rejection_v1_canonical_json_bytes(
                    managed_rejection
                )
            )
        except ManagedRejectionV1ContractError as error:
            raise ModelValidationError(
                f"failure run {run.id} has an invalid managed rejection"
            ) from error
        if managed_rejection["role"] != run.role:
            raise ModelValidationError(
                f"failure run {run.id} managed rejection role mismatch"
            )
        issues = managed_rejection["issues"]
        assert isinstance(issues, list)
        diagnostics["managed_rejection"] = {
            "attempt": managed_rejection["attempt"],
            "issues": issues[:MAX_MANAGED_REJECTION_CONTEXT_ISSUES],
            "issues_omitted": (
                int(managed_rejection["omitted_count"])
                + max(
                    0,
                    len(issues) - MAX_MANAGED_REJECTION_CONTEXT_ISSUES,
                )
            ),
            "sha256": hashlib.sha256(encoded_rejection).hexdigest(),
        }
    return diagnostics


def _run_fingerprint_digest(run: RunReference) -> dict[str, object]:
    role = _machine_identifier(run.role, "run role")
    return {
        **_safe_failure_counts(run),
        "role": role,
        "status": run.status.value,
    }


def _experiment_fingerprint_digest(
    experiment: Experiment,
) -> dict[str, object]:
    digest = {
        "command_sha256": _command_sha256(experiment),
        "kind": experiment.kind.value,
    }
    if experiment.proof_recipe is not None:
        recipe_sha256 = experiment.proof_recipe.recipe_sha256
        if not re.fullmatch(r"[0-9a-f]{64}", recipe_sha256):
            raise ModelValidationError(
                f"proof experiment {experiment.id} has an invalid recipe hash"
            )
        digest["proof_recipe_sha256"] = recipe_sha256
    return digest


def _fingerprint_payload(
    *,
    reason_code: str,
    stage: str,
    runs: Sequence[RunReference],
    failed_experiments: Sequence[Experiment],
) -> dict[str, object]:
    safe_reason = _machine_identifier(reason_code, "reason_code")
    safe_stage = _machine_identifier(stage, "stage")
    run_digests = sorted(
        (_run_fingerprint_digest(run) for run in runs),
        key=canonical_json_record,
    )
    experiment_digests = sorted(
        (
            _experiment_fingerprint_digest(experiment)
            for experiment in failed_experiments
        ),
        key=canonical_json_record,
    )
    return {
        "failed_experiments": experiment_digests,
        "reason_code": safe_reason,
        "runs": run_digests,
        "schema_version": FAILURE_CAPSULE_SCHEMA_VERSION,
        "stage": safe_stage,
    }


def _fingerprint(
    *,
    reason_code: str,
    stage: str,
    runs: Sequence[RunReference],
    failed_experiments: Sequence[Experiment],
) -> str:
    payload = _fingerprint_payload(
        reason_code=reason_code,
        stage=stage,
        runs=runs,
        failed_experiments=failed_experiments,
    )
    return hashlib.sha256(
        canonical_json_record(payload).encode("ascii")
    ).hexdigest()


def _cycle(state: ChallengeState, session_id: str, cycle_id: str) -> Any:
    matches = [
        cycle
        for cycle in state.cycles
        if cycle.id == cycle_id and cycle.session_id == session_id
    ]
    if len(matches) != 1:
        raise ModelValidationError(
            "failure capsule requires one canonical session/cycle binding"
        )
    return matches[0]


def _all_cycle_runs(
    state: ChallengeState,
    *,
    session_id: str,
    cycle_id: str,
) -> tuple[RunReference, ...]:
    values = tuple(
        sorted(
            (
                run
                for run in state.runs
                if run.session_id == session_id
                and run.cycle_id == cycle_id
            ),
            key=lambda run: (run.created_at, run.id),
        )
    )
    if not values:
        raise ModelValidationError(
            "failure capsule requires at least one cycle-bound run"
        )
    return values


def _all_failed_cycle_experiments(
    state: ChallengeState,
    *,
    selected_action_ids: Sequence[str],
    failed_runs: Sequence[RunReference],
) -> tuple[Experiment, ...]:
    selected = set(selected_action_ids)
    cycle_run_ids = {run.id for run in failed_runs}
    run_experiment_ids = {
        value
        for run in failed_runs
        if isinstance(
            value := run.extra.get("experiment_id"),
            str,
        )
    }

    values = tuple(
        sorted(
            (
                experiment
                for experiment in state.experiments
                if (
                    experiment.source_run_id in cycle_run_ids
                    or experiment.id in run_experiment_ids
                    or experiment.id in selected
                    or bool(
                        cycle_run_ids.intersection(
                            experiment.evidence_run_ids
                        )
                    )
                )
            ),
            key=lambda experiment: (
                experiment.created_at,
                experiment.id,
            ),
        )
    )
    return values


def _bounded_failed_experiment_projection(
    experiments: Sequence[Experiment],
    *,
    selected_action_ids: Sequence[str],
) -> tuple[tuple[str, ...], int]:
    """Pin selected typed Pwn evidence without reordering generic history."""

    selected = set(selected_action_ids)
    pinned = [
        experiment.id
        for experiment in experiments
        if (
            experiment.id in selected
            and _pwn_crash_experiment_marker(experiment)
        )
    ]
    pinned_set = set(pinned)
    ordered = [
        *pinned,
        *(
            experiment.id
            for experiment in experiments
            if experiment.id not in pinned_set
        ),
    ]
    return _bounded_unique_projection(
        ordered,
        maximum=MAX_FAILED_EXPERIMENTS,
    )


def _evidence_ids(
    state: ChallengeState,
    *,
    failed_runs: Sequence[RunReference],
    failed_experiments: Sequence[Experiment],
) -> tuple[
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    dict[str, int],
]:
    failed_run_ids = {run.id for run in failed_runs}
    failed_experiment_ids = {
        experiment.id for experiment in failed_experiments
    }

    receipt_ids: list[str] = []
    artifact_ids: list[str] = []
    fact_ids: list[str] = []
    for experiment in failed_experiments:
        receipt_ids.extend(experiment.evidence_receipt_ids)
        artifact_ids.extend(experiment.artifact_ids)
        fact_ids.extend(experiment.evidence_fact_ids)
    for receipt in state.receipts:
        if (
            receipt.run_id in failed_run_ids
            or receipt.experiment_id in failed_experiment_ids
            or receipt.id in receipt_ids
        ):
            receipt_ids.append(receipt.id)
            if receipt.stdout_artifact_id is not None:
                artifact_ids.append(receipt.stdout_artifact_id)
            if receipt.stderr_artifact_id is not None:
                artifact_ids.append(receipt.stderr_artifact_id)
    for artifact in state.artifacts:
        if artifact.source_run_id in failed_run_ids:
            artifact_ids.append(artifact.id)
    artifact_id_set = set(artifact_ids)
    for fact in state.facts:
        if (
            fact.source_run_id in failed_run_ids
            or fact.artifact_id in artifact_id_set
        ):
            fact_ids.append(fact.id)

    bounded_facts, omitted_facts = _bounded_unique_projection(
        fact_ids,
        maximum=MAX_EVIDENCE_IDS,
    )
    bounded_artifacts, omitted_artifacts = _bounded_unique_projection(
        artifact_ids,
        maximum=MAX_EVIDENCE_IDS,
    )
    bounded_receipts, omitted_receipts = _bounded_unique_projection(
        receipt_ids,
        maximum=MAX_EVIDENCE_IDS,
    )
    return (
        bounded_facts,
        bounded_artifacts,
        bounded_receipts,
        {
            "fact_ids": omitted_facts,
            "artifact_ids": omitted_artifacts,
            "receipt_ids": omitted_receipts,
        },
    )


def _all_next_experiments(
    state: ChallengeState,
    *,
    unresolved_hypothesis_ids: Sequence[str],
    excluded_experiment_ids: Sequence[str] = (),
) -> tuple[Experiment, ...]:
    active = set(unresolved_hypothesis_ids)
    excluded = set(excluded_experiment_ids)
    registered = [
        experiment
        for experiment in state.experiments
        if experiment.status is ExperimentStatus.REGISTERED
        and experiment.id not in excluded
    ]
    registered.sort(
        key=lambda experiment: (
            not bool(active.intersection(experiment.hypothesis_ids)),
            experiment.created_at,
            experiment.id,
        )
    )
    return tuple(registered)


def _content_sha256(capsule: FailureCapsule) -> str:
    return capsule.computed_content_sha256()


def build_failure_capsule(
    state: ChallengeState,
    session_id: str,
    cycle_id: str,
    reason_code: str,
    stage: str,
    state_revision_after: int,
) -> FailureCapsule:
    """Derive one bounded capsule from canonical managed-cycle state."""

    state.validate()
    _canonical_id(session_id, "session_id")
    _canonical_id(cycle_id, "cycle_id")
    _machine_identifier(reason_code, "reason_code")
    _machine_identifier(stage, "stage")
    if (
        isinstance(state_revision_after, bool)
        or not isinstance(state_revision_after, int)
        or state_revision_after != state.revision + 1
    ):
        raise ModelValidationError(
            "failure capsule state_revision_after must be the next revision"
        )

    cycle = _cycle(state, session_id, cycle_id)
    all_runs = _all_cycle_runs(
        state,
        session_id=session_id,
        cycle_id=cycle_id,
    )
    runs, omitted_runs = _bounded_unique_projection(
        [run.id for run in all_runs],
        maximum=MAX_FAILURE_RUNS,
    )
    all_failed_experiments = _all_failed_cycle_experiments(
        state,
        selected_action_ids=cycle.selected_action_ids,
        failed_runs=all_runs,
    )
    failed_experiment_ids, omitted_failed_experiments = (
        _bounded_failed_experiment_projection(
            all_failed_experiments,
            selected_action_ids=cycle.selected_action_ids,
        )
    )
    fact_ids, artifact_ids, receipt_ids, evidence_omitted = _evidence_ids(
        state,
        failed_runs=all_runs,
        failed_experiments=all_failed_experiments,
    )
    unresolved_hypothesis_ids, omitted_hypotheses = (
        _bounded_unique_projection(
            [
                hypothesis.id
                for hypothesis in state.hypotheses
                if hypothesis.status in ACTIVE_HYPOTHESIS_STATUSES
            ],
            maximum=MAX_UNRESOLVED_HYPOTHESES,
        )
    )
    all_next_experiments = _all_next_experiments(
        state,
        unresolved_hypothesis_ids=unresolved_hypothesis_ids,
        excluded_experiment_ids=[
            experiment.id for experiment in all_failed_experiments
        ],
    )
    next_experiment_ids, omitted_next_experiments = (
        _bounded_unique_projection(
            [
                experiment.id
                for experiment in all_next_experiments
            ],
            maximum=MAX_NEXT_EXPERIMENTS,
        )
    )
    capsule = FailureCapsule(
        schema_version=FAILURE_CAPSULE_SCHEMA_VERSION,
        reason_code=reason_code,
        stage=stage,
        state_revision_before=min(run.base_revision for run in all_runs),
        state_revision_after=state_revision_after,
        fingerprint_sha256=_fingerprint(
            reason_code=reason_code,
            stage=stage,
            runs=all_runs,
            failed_experiments=all_failed_experiments,
        ),
        content_sha256="0" * 64,
        run_ids=list(runs),
        failed_experiment_ids=list(failed_experiment_ids),
        fact_ids=list(fact_ids),
        artifact_ids=list(artifact_ids),
        receipt_ids=list(receipt_ids),
        unresolved_hypothesis_ids=list(unresolved_hypothesis_ids),
        next_experiment_ids=list(next_experiment_ids),
        omitted_counts={
            "run_ids": omitted_runs,
            "failed_experiment_ids": omitted_failed_experiments,
            **evidence_omitted,
            "unresolved_hypothesis_ids": omitted_hypotheses,
            "next_experiment_ids": omitted_next_experiments,
        },
    )
    capsule.content_sha256 = _content_sha256(capsule)
    validate_pwn_failure_capsule_binding(
        state,
        capsule,
        cycle=cycle,
    )
    return capsule


def validate_failure_capsule(
    state: ChallengeState,
    capsule: FailureCapsule,
    *,
    session_id: str,
    cycle_id: str,
) -> tuple[
    tuple[RunReference, ...],
    tuple[Experiment, ...],
    tuple[Experiment, ...],
]:
    """Recompute all derived bindings and the safe fingerprint."""

    if capsule.schema_version != FAILURE_CAPSULE_SCHEMA_VERSION:
        raise ModelValidationError(
            "failure capsule has an unsupported schema_version"
        )
    _machine_identifier(capsule.reason_code, "reason_code")
    _machine_identifier(capsule.stage, "stage")
    if capsule.content_sha256 != _content_sha256(capsule):
        raise ModelValidationError(
            "failure capsule content hash does not match its capture"
        )
    if (
        isinstance(capsule.state_revision_before, bool)
        or not isinstance(capsule.state_revision_before, int)
        or isinstance(capsule.state_revision_after, bool)
        or not isinstance(capsule.state_revision_after, int)
        or capsule.state_revision_before < 0
        or capsule.state_revision_after < capsule.state_revision_before
        or capsule.state_revision_after > state.revision
    ):
        raise ModelValidationError(
            "failure capsule has an invalid revision interval"
        )

    cycle = _cycle(state, session_id, cycle_id)
    validate_pwn_failure_capsule_binding(
        state,
        capsule,
        cycle=cycle,
    )
    runs_by_id = {run.id: run for run in state.runs}
    experiments_by_id = {
        experiment.id: experiment for experiment in state.experiments
    }
    facts_by_id = {fact.id: fact for fact in state.facts}
    artifacts_by_id = {
        artifact.id: artifact for artifact in state.artifacts
    }
    receipts_by_id = {
        receipt.id: receipt for receipt in state.receipts
    }
    hypotheses_by_id = {
        hypothesis.id: hypothesis for hypothesis in state.hypotheses
    }

    try:
        runs = tuple(runs_by_id[run_id] for run_id in capsule.run_ids)
        failed_experiments = tuple(
            experiments_by_id[experiment_id]
            for experiment_id in capsule.failed_experiment_ids
        )
        next_experiments = tuple(
            experiments_by_id[experiment_id]
            for experiment_id in capsule.next_experiment_ids
        )
        capsule_facts = tuple(
            facts_by_id[fact_id] for fact_id in capsule.fact_ids
        )
        capsule_artifacts = tuple(
            artifacts_by_id[artifact_id]
            for artifact_id in capsule.artifact_ids
        )
        capsule_receipts = tuple(
            receipts_by_id[receipt_id]
            for receipt_id in capsule.receipt_ids
        )
        tuple(
            hypotheses_by_id[hypothesis_id]
            for hypothesis_id in capsule.unresolved_hypothesis_ids
        )
    except KeyError as error:
        raise ModelValidationError(
            "failure capsule references a missing canonical record"
        ) from error

    all_cycle_runs = _all_cycle_runs(
        state,
        session_id=session_id,
        cycle_id=cycle_id,
    )
    expected_run_ids, expected_runs_omitted = (
        _bounded_unique_projection(
            [run.id for run in all_cycle_runs],
            maximum=MAX_FAILURE_RUNS,
        )
    )
    if (
        tuple(run.id for run in runs) != expected_run_ids
        or capsule.omitted_counts["run_ids"]
        != expected_runs_omitted
        or len(runs) > MAX_FAILURE_RUNS
        or any(
            run.session_id != session_id or run.cycle_id != cycle_id
            for run in runs
        )
    ):
        raise ModelValidationError(
            "failure capsule run_ids are not a canonical cycle binding"
        )
    if capsule.state_revision_before != min(
        run.base_revision for run in all_cycle_runs
    ):
        raise ModelValidationError(
            "failure capsule state_revision_before does not match its "
            "cycle runs"
        )
    cycle_run_ids = {run.id for run in all_cycle_runs}
    all_failed_experiments = _all_failed_cycle_experiments(
        state,
        selected_action_ids=cycle.selected_action_ids,
        failed_runs=all_cycle_runs,
    )
    expected_failed_ids, expected_failed_omitted = (
        _bounded_failed_experiment_projection(
            all_failed_experiments,
            selected_action_ids=cycle.selected_action_ids,
        )
    )
    if (
        len(failed_experiments) > MAX_FAILED_EXPERIMENTS
        or len({item.id for item in failed_experiments})
        != len(failed_experiments)
        or tuple(
            experiment.id for experiment in failed_experiments
        )
        != expected_failed_ids
        or capsule.omitted_counts["failed_experiment_ids"]
        != expected_failed_omitted
    ):
        raise ModelValidationError(
            "failure capsule failed experiments are not the canonical "
            "cycle-bound set"
        )
    if (
        len(capsule_facts) > MAX_EVIDENCE_IDS
        or len(capsule_artifacts) > MAX_EVIDENCE_IDS
        or len(capsule_receipts) > MAX_EVIDENCE_IDS
        or len(capsule.unresolved_hypothesis_ids)
        > MAX_UNRESOLVED_HYPOTHESES
        or len(next_experiments) > MAX_NEXT_EXPERIMENTS
        or any(
            experiment.id in set(capsule.failed_experiment_ids)
            for experiment in next_experiments
        )
    ):
        raise ModelValidationError(
            "failure capsule contains an invalid bounded record set"
        )
    next_experiments = tuple(
        experiment
        for experiment in next_experiments
        if experiment.status is ExperimentStatus.REGISTERED
    )

    # At the checkpoint revision the complete source projection is still
    # reconstructable, so require exact evidence/frontier capture.  On later
    # revisions records may legitimately become resolved or gain evidence;
    # content_sha256 still makes the historical capture tamper-evident.
    if state.revision == capsule.state_revision_after:
        (
            expected_fact_ids,
            expected_artifact_ids,
            expected_receipt_ids,
            expected_evidence_omitted,
        ) = _evidence_ids(
            state,
            failed_runs=all_cycle_runs,
            failed_experiments=all_failed_experiments,
        )
        expected_unresolved_ids, expected_unresolved_omitted = (
            _bounded_unique_projection(
                [
                    hypothesis.id
                    for hypothesis in state.hypotheses
                    if hypothesis.status in ACTIVE_HYPOTHESIS_STATUSES
                ],
                maximum=MAX_UNRESOLVED_HYPOTHESES,
            )
        )
        all_expected_next_experiments = _all_next_experiments(
            state,
            unresolved_hypothesis_ids=expected_unresolved_ids,
            excluded_experiment_ids=[
                experiment.id
                for experiment in all_failed_experiments
            ],
        )
        expected_next_ids, expected_next_omitted = (
            _bounded_unique_projection(
                [
                    experiment.id
                    for experiment in all_expected_next_experiments
                ],
                maximum=MAX_NEXT_EXPERIMENTS,
            )
        )
        if (
            tuple(capsule.fact_ids) != expected_fact_ids
            or tuple(capsule.artifact_ids) != expected_artifact_ids
            or tuple(capsule.receipt_ids) != expected_receipt_ids
            or {
                key: capsule.omitted_counts[key]
                for key in (
                    "fact_ids",
                    "artifact_ids",
                    "receipt_ids",
                )
            }
            != expected_evidence_omitted
            or tuple(capsule.unresolved_hypothesis_ids)
            != expected_unresolved_ids
            or capsule.omitted_counts["unresolved_hypothesis_ids"]
            != expected_unresolved_omitted
            or tuple(capsule.next_experiment_ids) != expected_next_ids
            or capsule.omitted_counts["next_experiment_ids"]
            != expected_next_omitted
        ):
            raise ModelValidationError(
                "failure capsule capture is not the canonical checkpoint "
                "projection"
            )

    associated_artifact_ids = {
        artifact.id
        for artifact in state.artifacts
        if artifact.source_run_id in cycle_run_ids
    }
    associated_receipt_ids = {
        receipt.id
        for receipt in state.receipts
        if receipt.run_id in cycle_run_ids
        or receipt.experiment_id
        in {item.id for item in all_failed_experiments}
    }
    associated_receipt_ids.update(
        receipt_id
        for experiment in all_failed_experiments
        for receipt_id in experiment.evidence_receipt_ids
    )
    associated_artifact_ids.update(
        artifact_id
        for experiment in all_failed_experiments
        for artifact_id in experiment.artifact_ids
    )
    for receipt in capsule_receipts:
        if receipt.stdout_artifact_id is not None:
            associated_artifact_ids.add(receipt.stdout_artifact_id)
        if receipt.stderr_artifact_id is not None:
            associated_artifact_ids.add(receipt.stderr_artifact_id)
    associated_fact_ids = {
        fact.id
        for fact in state.facts
        if fact.source_run_id in cycle_run_ids
        or fact.artifact_id in associated_artifact_ids
    }
    associated_fact_ids.update(
        fact_id
        for experiment in all_failed_experiments
        for fact_id in experiment.evidence_fact_ids
    )
    if (
        any(
            receipt.id not in associated_receipt_ids
            for receipt in capsule_receipts
        )
        or any(
            artifact.id not in associated_artifact_ids
            for artifact in capsule_artifacts
        )
        or any(
            fact.id not in associated_fact_ids
            for fact in capsule_facts
        )
    ):
        raise ModelValidationError(
            "failure capsule evidence lacks a causal cycle binding"
        )
    expected_fingerprint = _fingerprint(
        reason_code=capsule.reason_code,
        stage=capsule.stage,
        runs=all_cycle_runs,
        failed_experiments=all_failed_experiments,
    )
    if capsule.fingerprint_sha256 != expected_fingerprint:
        raise ModelValidationError(
            "failure capsule fingerprint does not match canonical state"
        )
    return runs, failed_experiments, next_experiments


def safe_run_diagnostics(run: RunReference) -> dict[str, object]:
    """Public renderer helper; returns no free-form diagnostic text."""

    return _safe_failure_counts(run)


def experiment_command_sha256(experiment: Experiment) -> str:
    """Public renderer helper for a command-free experiment digest."""

    return _command_sha256(experiment)


__all__ = [
    "FAILURE_CAPSULE_SCHEMA_VERSION",
    "MAX_NEXT_EXPERIMENTS",
    "bounded_pwn_crash_failure_reason",
    "build_failure_capsule",
    "experiment_command_sha256",
    "safe_run_diagnostics",
    "selected_pwn_crash_failure_reason",
    "validate_failure_capsule",
    "validate_pwn_failure_capsule_binding",
]
