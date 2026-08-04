"""Exact remaining-budget contract for a fixed-width managed wave.

The guard deliberately models provider admission separately from logical wave
width.  A provider limit changes only the number of serial call batches; it
never removes a role from the three-role wave.
"""

from __future__ import annotations

import math
from collections.abc import Mapping


MANAGED_WAVE_BUDGET_GUARD_KEY = "managed_wave_budget_guard_v1"
MANAGED_WAVE_BUDGET_SCHEMA_VERSION = 1
MANAGED_WAVE_BUDGET_PROTOCOL = "ctfos.managed_wave_budget.v1"
MANAGED_WAVE_BUDGET_GUARD_V2_KEY = "managed_wave_budget_guard_v2"
MANAGED_WAVE_BUDGET_V2_SCHEMA_VERSION = 2
MANAGED_WAVE_BUDGET_V2_PROTOCOL = "ctfos.managed_wave_budget.v2"
MANAGED_WAVE_LOGICAL_ROLE_COUNT = 3

_WAVE_KINDS = frozenset({"discovery", "attack", "proof"})
_BUDGET_MODES = frozenset({"bounded", "operator_unbounded"})
_DECISIONS = frozenset({"allow", "pause"})
_REASONS = frozenset(
    {
        "sufficient_remaining_budget",
        "operator_unbounded",
        "insufficient_budget_for_wave",
    }
)
_KEYS = frozenset(
    {
        "schema_version",
        "protocol",
        "decision",
        "reason_code",
        "wave_kind",
        "logical_role_count",
        "provider_max_concurrent_calls",
        "provider_parallel_capacity",
        "serial_provider_batches",
        "queue_reserve_ms",
        "role_call_reserve_ms",
        "action_commit_reserve_ms",
        "minimum_required_ms",
        "remaining_budget_ms",
        "checked_state_revision",
        "configuration_epoch",
        "budget_mode",
    }
)
_V2_KEYS = frozenset(
    {
        "schema_version",
        "protocol",
        "decision",
        "reason_code",
        "wave_kind",
        "logical_role_count",
        "provider_max_concurrent_calls",
        "provider_snapshot_capacity",
        "provider_snapshot_active",
        "provider_snapshot_waiting",
        "effective_provider_capacity",
        "provider_parallel_capacity",
        "serial_provider_batches",
        "occupied_provider_batches",
        "backlog_provider_batches",
        "queue_reserve_ms",
        "role_call_reserve_ms",
        "action_commit_reserve_ms",
        "minimum_required_ms",
        "remaining_budget_ms",
        "checked_state_revision",
        "configuration_epoch",
        "budget_mode",
    }
)


class ManagedWaveBudgetContractError(ValueError):
    """Raised when a managed wave budget decision cannot be canonicalized."""


def _positive_seconds_to_ms(value: object, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise ManagedWaveBudgetContractError(
            f"{label} must be finite and positive"
        )
    scaled = float(value) * 1000.0
    if not math.isfinite(scaled):
        raise ManagedWaveBudgetContractError(
            f"{label} is outside the supported millisecond range"
        )
    milliseconds = math.ceil(scaled)
    if milliseconds < 1:
        raise ManagedWaveBudgetContractError(
            f"{label} is below one millisecond"
        )
    return milliseconds


def _remaining_seconds_to_ms(value: object) -> int | None:
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0
    ):
        raise ManagedWaveBudgetContractError(
            "remaining_seconds must be finite and non-negative"
        )
    # The available side is rounded down while every required component is
    # rounded up.  A sub-millisecond boundary can therefore never over-admit.
    scaled = float(value) * 1000.0
    if not math.isfinite(scaled):
        raise ManagedWaveBudgetContractError(
            "remaining_seconds is outside the supported millisecond range"
        )
    return math.floor(scaled)


def _build_managed_wave_budget_guard_ms(
    *,
    wave_kind: str,
    provider_max_concurrent_calls: int,
    queue_reserve_ms: int,
    role_call_reserve_ms: int,
    action_commit_reserve_ms: int,
    remaining_budget_ms: int | None,
    checked_state_revision: int,
    configuration_epoch: int,
    budget_mode: str,
) -> dict[str, object]:
    """Build from already-canonical integer milliseconds."""

    capacity = min(
        provider_max_concurrent_calls,
        MANAGED_WAVE_LOGICAL_ROLE_COUNT,
    )
    serial_batches = (
        MANAGED_WAVE_LOGICAL_ROLE_COUNT + capacity - 1
    ) // capacity
    minimum_required_ms = (
        queue_reserve_ms
        + (serial_batches * role_call_reserve_ms)
        + action_commit_reserve_ms
    )

    if remaining_budget_ms is None:
        if budget_mode != "operator_unbounded":
            raise ManagedWaveBudgetContractError(
                "only operator_unbounded budget may omit remaining_seconds"
            )
        decision = "allow"
        reason_code = "operator_unbounded"
    elif budget_mode != "bounded":
        raise ManagedWaveBudgetContractError(
            "operator_unbounded budget cannot carry a finite remainder"
        )
    elif remaining_budget_ms >= minimum_required_ms:
        decision = "allow"
        reason_code = "sufficient_remaining_budget"
    else:
        decision = "pause"
        reason_code = "insufficient_budget_for_wave"

    return {
        "schema_version": MANAGED_WAVE_BUDGET_SCHEMA_VERSION,
        "protocol": MANAGED_WAVE_BUDGET_PROTOCOL,
        "decision": decision,
        "reason_code": reason_code,
        "wave_kind": wave_kind,
        "logical_role_count": MANAGED_WAVE_LOGICAL_ROLE_COUNT,
        "provider_max_concurrent_calls": provider_max_concurrent_calls,
        "provider_parallel_capacity": capacity,
        "serial_provider_batches": serial_batches,
        "queue_reserve_ms": queue_reserve_ms,
        "role_call_reserve_ms": role_call_reserve_ms,
        "action_commit_reserve_ms": action_commit_reserve_ms,
        "minimum_required_ms": minimum_required_ms,
        "remaining_budget_ms": remaining_budget_ms,
        "checked_state_revision": checked_state_revision,
        "configuration_epoch": configuration_epoch,
        "budget_mode": budget_mode,
    }


def build_managed_wave_budget_guard(
    *,
    wave_kind: str,
    provider_max_concurrent_calls: int,
    queue_reserve_seconds: float,
    role_call_reserve_seconds: float,
    action_commit_reserve_seconds: float,
    remaining_seconds: float | None,
    checked_state_revision: int,
    configuration_epoch: int,
    budget_mode: str,
) -> dict[str, object]:
    """Build one conservative, auditable admission decision."""

    if wave_kind not in _WAVE_KINDS:
        raise ManagedWaveBudgetContractError("wave_kind is unsupported")
    if (
        type(provider_max_concurrent_calls) is not int
        or provider_max_concurrent_calls < 1
    ):
        raise ManagedWaveBudgetContractError(
            "provider_max_concurrent_calls must be a positive integer"
        )
    if (
        type(checked_state_revision) is not int
        or checked_state_revision < 0
    ):
        raise ManagedWaveBudgetContractError(
            "checked_state_revision must be a non-negative integer"
        )
    if type(configuration_epoch) is not int or configuration_epoch < 0:
        raise ManagedWaveBudgetContractError(
            "configuration_epoch must be a non-negative integer"
        )
    if budget_mode not in _BUDGET_MODES:
        raise ManagedWaveBudgetContractError("budget_mode is unsupported")

    queue_ms = _positive_seconds_to_ms(
        queue_reserve_seconds,
        "queue_reserve_seconds",
    )
    role_call_ms = _positive_seconds_to_ms(
        role_call_reserve_seconds,
        "role_call_reserve_seconds",
    )
    action_commit_ms = _positive_seconds_to_ms(
        action_commit_reserve_seconds,
        "action_commit_reserve_seconds",
    )
    remaining_ms = _remaining_seconds_to_ms(remaining_seconds)
    return _build_managed_wave_budget_guard_ms(
        wave_kind=wave_kind,
        provider_max_concurrent_calls=provider_max_concurrent_calls,
        queue_reserve_ms=queue_ms,
        role_call_reserve_ms=role_call_ms,
        action_commit_reserve_ms=action_commit_ms,
        remaining_budget_ms=remaining_ms,
        checked_state_revision=checked_state_revision,
        configuration_epoch=configuration_epoch,
        budget_mode=budget_mode,
    )


def _build_managed_wave_budget_guard_v2_ms(
    *,
    wave_kind: str,
    provider_max_concurrent_calls: int,
    provider_snapshot_capacity: int,
    provider_snapshot_active: int,
    provider_snapshot_waiting: int,
    queue_reserve_ms: int,
    role_call_reserve_ms: int,
    action_commit_reserve_ms: int,
    remaining_budget_ms: int | None,
    checked_state_revision: int,
    configuration_epoch: int,
    budget_mode: str,
) -> dict[str, object]:
    """Build a live-backlog-aware guard from canonical integer values."""

    effective_capacity = min(
        provider_max_concurrent_calls,
        provider_snapshot_capacity,
    )
    parallel_capacity = min(
        effective_capacity,
        MANAGED_WAVE_LOGICAL_ROLE_COUNT,
    )
    serial_batches = (
        MANAGED_WAVE_LOGICAL_ROLE_COUNT + effective_capacity - 1
    ) // effective_capacity
    occupied_batches = (
        provider_snapshot_active
        + provider_snapshot_waiting
        + MANAGED_WAVE_LOGICAL_ROLE_COUNT
        + effective_capacity
        - 1
    ) // effective_capacity
    backlog_batches = occupied_batches - serial_batches
    minimum_required_ms = (
        queue_reserve_ms
        + (occupied_batches * role_call_reserve_ms)
        + action_commit_reserve_ms
    )

    if remaining_budget_ms is None:
        if budget_mode != "operator_unbounded":
            raise ManagedWaveBudgetContractError(
                "only operator_unbounded budget may omit remaining_seconds"
            )
        decision = "allow"
        reason_code = "operator_unbounded"
    elif budget_mode != "bounded":
        raise ManagedWaveBudgetContractError(
            "operator_unbounded budget cannot carry a finite remainder"
        )
    elif remaining_budget_ms >= minimum_required_ms:
        decision = "allow"
        reason_code = "sufficient_remaining_budget"
    else:
        decision = "pause"
        reason_code = "insufficient_budget_for_wave"

    return {
        "schema_version": MANAGED_WAVE_BUDGET_V2_SCHEMA_VERSION,
        "protocol": MANAGED_WAVE_BUDGET_V2_PROTOCOL,
        "decision": decision,
        "reason_code": reason_code,
        "wave_kind": wave_kind,
        "logical_role_count": MANAGED_WAVE_LOGICAL_ROLE_COUNT,
        "provider_max_concurrent_calls": provider_max_concurrent_calls,
        "provider_snapshot_capacity": provider_snapshot_capacity,
        "provider_snapshot_active": provider_snapshot_active,
        "provider_snapshot_waiting": provider_snapshot_waiting,
        "effective_provider_capacity": effective_capacity,
        "provider_parallel_capacity": parallel_capacity,
        "serial_provider_batches": serial_batches,
        "occupied_provider_batches": occupied_batches,
        "backlog_provider_batches": backlog_batches,
        "queue_reserve_ms": queue_reserve_ms,
        "role_call_reserve_ms": role_call_reserve_ms,
        "action_commit_reserve_ms": action_commit_reserve_ms,
        "minimum_required_ms": minimum_required_ms,
        "remaining_budget_ms": remaining_budget_ms,
        "checked_state_revision": checked_state_revision,
        "configuration_epoch": configuration_epoch,
        "budget_mode": budget_mode,
    }


def build_managed_wave_budget_guard_v2(
    *,
    wave_kind: str,
    provider_max_concurrent_calls: int,
    provider_snapshot_capacity: int,
    provider_snapshot_active: int,
    provider_snapshot_waiting: int,
    queue_reserve_seconds: float,
    role_call_reserve_seconds: float,
    action_commit_reserve_seconds: float,
    remaining_seconds: float | None,
    checked_state_revision: int,
    configuration_epoch: int,
    budget_mode: str,
) -> dict[str, object]:
    """Build one conservative admission decision including live backlog."""

    if wave_kind not in _WAVE_KINDS:
        raise ManagedWaveBudgetContractError("wave_kind is unsupported")
    if (
        type(provider_max_concurrent_calls) is not int
        or provider_max_concurrent_calls < 1
    ):
        raise ManagedWaveBudgetContractError(
            "provider_max_concurrent_calls must be a positive integer"
        )
    if (
        type(provider_snapshot_capacity) is not int
        or provider_snapshot_capacity < 1
    ):
        raise ManagedWaveBudgetContractError(
            "provider_snapshot_capacity must be a positive integer"
        )
    for value, label in (
        (provider_snapshot_active, "provider_snapshot_active"),
        (provider_snapshot_waiting, "provider_snapshot_waiting"),
    ):
        if type(value) is not int or value < 0:
            raise ManagedWaveBudgetContractError(
                f"{label} must be a non-negative integer"
            )
    if provider_snapshot_active > provider_snapshot_capacity:
        raise ManagedWaveBudgetContractError(
            "provider_snapshot_active exceeds provider_snapshot_capacity"
        )
    if (
        type(checked_state_revision) is not int
        or checked_state_revision < 0
    ):
        raise ManagedWaveBudgetContractError(
            "checked_state_revision must be a non-negative integer"
        )
    if type(configuration_epoch) is not int or configuration_epoch < 0:
        raise ManagedWaveBudgetContractError(
            "configuration_epoch must be a non-negative integer"
        )
    if budget_mode not in _BUDGET_MODES:
        raise ManagedWaveBudgetContractError("budget_mode is unsupported")

    return _build_managed_wave_budget_guard_v2_ms(
        wave_kind=wave_kind,
        provider_max_concurrent_calls=provider_max_concurrent_calls,
        provider_snapshot_capacity=provider_snapshot_capacity,
        provider_snapshot_active=provider_snapshot_active,
        provider_snapshot_waiting=provider_snapshot_waiting,
        queue_reserve_ms=_positive_seconds_to_ms(
            queue_reserve_seconds,
            "queue_reserve_seconds",
        ),
        role_call_reserve_ms=_positive_seconds_to_ms(
            role_call_reserve_seconds,
            "role_call_reserve_seconds",
        ),
        action_commit_reserve_ms=_positive_seconds_to_ms(
            action_commit_reserve_seconds,
            "action_commit_reserve_seconds",
        ),
        remaining_budget_ms=_remaining_seconds_to_ms(remaining_seconds),
        checked_state_revision=checked_state_revision,
        configuration_epoch=configuration_epoch,
        budget_mode=budget_mode,
    )


def managed_wave_budget_guard_errors(value: object) -> list[str]:
    """Return exact contract errors, including recomputed admission math."""

    if not isinstance(value, Mapping):
        return ["managed wave budget guard must be an object"]
    if set(value) != _KEYS:
        return ["managed wave budget guard has unknown or missing fields"]
    errors: list[str] = []
    for field in (
        "logical_role_count",
        "provider_max_concurrent_calls",
        "provider_parallel_capacity",
        "serial_provider_batches",
        "queue_reserve_ms",
        "role_call_reserve_ms",
        "action_commit_reserve_ms",
        "minimum_required_ms",
        "checked_state_revision",
        "configuration_epoch",
    ):
        item = value.get(field)
        minimum = 0 if field in {
            "checked_state_revision",
            "configuration_epoch",
        } else 1
        if type(item) is not int or item < minimum:
            errors.append(f"{field} is invalid")
    remaining = value.get("remaining_budget_ms")
    if remaining is not None and (
        type(remaining) is not int or remaining < 0
    ):
        errors.append("remaining_budget_ms is invalid")
    if value.get("schema_version") != MANAGED_WAVE_BUDGET_SCHEMA_VERSION:
        errors.append("schema_version is invalid")
    if value.get("protocol") != MANAGED_WAVE_BUDGET_PROTOCOL:
        errors.append("protocol is invalid")
    if value.get("wave_kind") not in _WAVE_KINDS:
        errors.append("wave_kind is invalid")
    if value.get("budget_mode") not in _BUDGET_MODES:
        errors.append("budget_mode is invalid")
    if value.get("decision") not in _DECISIONS:
        errors.append("decision is invalid")
    if value.get("reason_code") not in _REASONS:
        errors.append("reason_code is invalid")
    if errors:
        return errors

    try:
        expected = _build_managed_wave_budget_guard_ms(
            wave_kind=str(value["wave_kind"]),
            provider_max_concurrent_calls=int(
                value["provider_max_concurrent_calls"]
            ),
            queue_reserve_ms=int(value["queue_reserve_ms"]),
            role_call_reserve_ms=int(value["role_call_reserve_ms"]),
            action_commit_reserve_ms=int(
                value["action_commit_reserve_ms"]
            ),
            remaining_budget_ms=(
                None if remaining is None else int(remaining)
            ),
            checked_state_revision=int(value["checked_state_revision"]),
            configuration_epoch=int(value["configuration_epoch"]),
            budget_mode=str(value["budget_mode"]),
        )
    except ManagedWaveBudgetContractError as error:
        return [str(error)]
    if dict(value) != expected:
        return ["managed wave budget guard math or decision is inconsistent"]
    return []


def managed_wave_budget_guard_v2_errors(value: object) -> list[str]:
    """Return exact v2 errors, including the recorded backlog math."""

    if not isinstance(value, Mapping):
        return ["managed wave budget v2 guard must be an object"]
    if set(value) != _V2_KEYS:
        return ["managed wave budget v2 guard has unknown or missing fields"]
    errors: list[str] = []
    for field in (
        "logical_role_count",
        "provider_max_concurrent_calls",
        "provider_snapshot_capacity",
        "effective_provider_capacity",
        "provider_parallel_capacity",
        "serial_provider_batches",
        "occupied_provider_batches",
        "queue_reserve_ms",
        "role_call_reserve_ms",
        "action_commit_reserve_ms",
        "minimum_required_ms",
    ):
        item = value.get(field)
        if type(item) is not int or item < 1:
            errors.append(f"{field} is invalid")
    for field in (
        "provider_snapshot_active",
        "provider_snapshot_waiting",
        "backlog_provider_batches",
        "checked_state_revision",
        "configuration_epoch",
    ):
        item = value.get(field)
        if type(item) is not int or item < 0:
            errors.append(f"{field} is invalid")
    remaining = value.get("remaining_budget_ms")
    if remaining is not None and (
        type(remaining) is not int or remaining < 0
    ):
        errors.append("remaining_budget_ms is invalid")
    if value.get("schema_version") != MANAGED_WAVE_BUDGET_V2_SCHEMA_VERSION:
        errors.append("schema_version is invalid")
    if value.get("protocol") != MANAGED_WAVE_BUDGET_V2_PROTOCOL:
        errors.append("protocol is invalid")
    if value.get("wave_kind") not in _WAVE_KINDS:
        errors.append("wave_kind is invalid")
    if value.get("budget_mode") not in _BUDGET_MODES:
        errors.append("budget_mode is invalid")
    if value.get("decision") not in _DECISIONS:
        errors.append("decision is invalid")
    if value.get("reason_code") not in _REASONS:
        errors.append("reason_code is invalid")
    active = value.get("provider_snapshot_active")
    snapshot_capacity = value.get("provider_snapshot_capacity")
    if (
        type(active) is int
        and type(snapshot_capacity) is int
        and active > snapshot_capacity
    ):
        errors.append(
            "provider_snapshot_active exceeds provider_snapshot_capacity"
        )
    if errors:
        return errors

    try:
        expected = _build_managed_wave_budget_guard_v2_ms(
            wave_kind=str(value["wave_kind"]),
            provider_max_concurrent_calls=int(
                value["provider_max_concurrent_calls"]
            ),
            provider_snapshot_capacity=int(
                value["provider_snapshot_capacity"]
            ),
            provider_snapshot_active=int(
                value["provider_snapshot_active"]
            ),
            provider_snapshot_waiting=int(
                value["provider_snapshot_waiting"]
            ),
            queue_reserve_ms=int(value["queue_reserve_ms"]),
            role_call_reserve_ms=int(value["role_call_reserve_ms"]),
            action_commit_reserve_ms=int(
                value["action_commit_reserve_ms"]
            ),
            remaining_budget_ms=(
                None if remaining is None else int(remaining)
            ),
            checked_state_revision=int(value["checked_state_revision"]),
            configuration_epoch=int(value["configuration_epoch"]),
            budget_mode=str(value["budget_mode"]),
        )
    except ManagedWaveBudgetContractError as error:
        return [str(error)]
    if dict(value) != expected:
        return [
            "managed wave budget v2 guard math or decision is inconsistent"
        ]
    return []


def managed_wave_budget_state_errors(state: object) -> list[str]:
    """Validate durable guard-to-cycle/wave/checkpoint bindings."""

    cycles = getattr(state, "cycles", ())
    waves = {
        getattr(wave, "id", None): wave
        for wave in getattr(state, "waves", ())
    }
    checkpoints = {
        getattr(checkpoint, "id", None): checkpoint
        for checkpoint in getattr(state, "checkpoints", ())
    }
    runs = {
        getattr(run, "id", None): run
        for run in getattr(state, "runs", ())
    }
    hypotheses = {
        getattr(hypothesis, "id", None): hypothesis
        for hypothesis in getattr(state, "hypotheses", ())
    }
    state_revision = getattr(state, "revision", None)
    errors: list[str] = []
    guarded_cycle_ids: set[str] = set()
    for cycle in cycles:
        cycle_id = getattr(cycle, "id", "")
        extra = getattr(cycle, "extra", {})
        v1_audit = None
        v2_audit = None
        if isinstance(extra, Mapping):
            v1_audit = extra.get(MANAGED_WAVE_BUDGET_GUARD_KEY)
            v2_audit = extra.get(MANAGED_WAVE_BUDGET_GUARD_V2_KEY)
        if v1_audit is None and v2_audit is None:
            continue
        guarded_cycle_ids.add(cycle_id)
        if v1_audit is not None and v2_audit is not None:
            errors.append(
                f"cycle {cycle_id} has both v1 and v2 managed wave "
                "budget guards"
            )
            continue
        audit = v2_audit if v2_audit is not None else v1_audit
        issues = (
            managed_wave_budget_guard_v2_errors(audit)
            if v2_audit is not None
            else managed_wave_budget_guard_errors(audit)
        )
        if issues:
            errors.append(
                f"cycle {cycle_id} has invalid managed wave budget guard: "
                + "; ".join(issues)
            )
            continue
        assert isinstance(audit, Mapping)
        checked_revision = audit["checked_state_revision"]
        if (
            type(state_revision) is not int
            or type(checked_revision) is not int
            or checked_revision > state_revision
        ):
            errors.append(
                f"cycle {cycle_id} budget guard has a future state revision"
            )
        if audit["configuration_epoch"] != getattr(
            cycle,
            "configuration_epoch",
            None,
        ):
            errors.append(
                f"cycle {cycle_id} budget guard epoch does not bind its cycle"
            )
        captain = runs.get(getattr(cycle, "captain_run_id", None))
        captain_status = getattr(
            getattr(captain, "status", None),
            "value",
            getattr(captain, "status", None),
        )
        if captain is None or captain_status != "completed":
            errors.append(
                f"cycle {cycle_id} budget guard requires a completed Captain"
            )

        decision = audit["decision"]
        wave_id = getattr(cycle, "wave_id", None)
        wave = waves.get(wave_id)
        if decision == "allow":
            wave_kind = getattr(
                getattr(wave, "kind", None),
                "value",
                getattr(wave, "kind", None),
            )
            role_run_ids = getattr(wave, "role_run_ids", None)
            if (
                wave is None
                or wave_kind != audit["wave_kind"]
                or not isinstance(role_run_ids, Mapping)
                or len(role_run_ids)
                != MANAGED_WAVE_LOGICAL_ROLE_COUNT
            ):
                errors.append(
                    f"cycle {cycle_id} allowed budget guard does not bind "
                    "one complete three-role wave"
                )
            continue

        if wave_id is not None:
            errors.append(
                f"cycle {cycle_id} paused budget guard cannot bind a wave"
            )
        checkpoint_id = getattr(cycle, "checkpoint_id", None)
        if checkpoint_id is None:
            if (
                getattr(cycle, "phase", None)
                not in {
                    "wave_budget_blocked",
                    "no_action_selected",
                }
                or getattr(cycle, "completed_at", None) is not None
            ):
                errors.append(
                    f"cycle {cycle_id} paused budget guard is not in its "
                    "atomic pre-checkpoint phase"
                )
            continue
        checkpoint = checkpoints.get(checkpoint_id)
        capsule = getattr(checkpoint, "failure_capsule", None)
        if (
            checkpoint is None
            or getattr(capsule, "reason_code", None)
            != "insufficient_budget_for_wave"
            or getattr(capsule, "stage", None) != "captain"
            or getattr(checkpoint, "session_id", None)
            != getattr(cycle, "session_id", None)
            or getattr(checkpoint, "cycle_id", None) != cycle_id
        ):
            errors.append(
                f"cycle {cycle_id} paused budget guard lacks its typed "
                "Captain failure capsule"
            )
            continue
        next_experiment_ids = getattr(
            capsule,
            "next_experiment_ids",
            (),
        )
        unresolved_ids = getattr(
            capsule,
            "unresolved_hypothesis_ids",
            (),
        )
        described_hypothesis = any(
            isinstance(
                getattr(hypotheses.get(hypothesis_id), "extra", None),
                Mapping,
            )
            and isinstance(
                hypotheses[hypothesis_id].extra.get("experiment"),
                str,
            )
            and bool(
                hypotheses[hypothesis_id]
                .extra["experiment"]
                .strip()
            )
            for hypothesis_id in unresolved_ids
            if hypothesis_id in hypotheses
        )
        if not next_experiment_ids and not described_hypothesis:
            errors.append(
                f"cycle {cycle_id} paused budget guard lacks a bounded "
                "next-experiment pointer"
            )

    for checkpoint in checkpoints.values():
        capsule = getattr(checkpoint, "failure_capsule", None)
        if (
            getattr(capsule, "reason_code", None)
            == "insufficient_budget_for_wave"
            and getattr(checkpoint, "cycle_id", None)
            not in guarded_cycle_ids
        ):
            errors.append(
                "insufficient_budget_for_wave capsule lacks its managed "
                "wave budget guard"
            )
    return errors


__all__ = [
    "MANAGED_WAVE_BUDGET_GUARD_KEY",
    "MANAGED_WAVE_BUDGET_GUARD_V2_KEY",
    "MANAGED_WAVE_BUDGET_PROTOCOL",
    "MANAGED_WAVE_BUDGET_SCHEMA_VERSION",
    "MANAGED_WAVE_BUDGET_V2_PROTOCOL",
    "MANAGED_WAVE_BUDGET_V2_SCHEMA_VERSION",
    "MANAGED_WAVE_LOGICAL_ROLE_COUNT",
    "ManagedWaveBudgetContractError",
    "build_managed_wave_budget_guard",
    "build_managed_wave_budget_guard_v2",
    "managed_wave_budget_guard_errors",
    "managed_wave_budget_guard_v2_errors",
    "managed_wave_budget_state_errors",
]
