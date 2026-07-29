"""Bounded, deterministic STALLED detection for one challenge.

The governor observes canonical records only.  It never starts a model, tool,
or challenge session; a recovery action is an operator-visible decision, not
an automatic execution request.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from itertools import pairwise

from ctf_os.models import (
    ArtifactReference,
    ChallengeState,
    Experiment,
    ExperimentStatus,
    RunReference,
    RunStatus,
)

GOVERNOR_METADATA_KEY = "stalled_governor"
DEFAULT_HISTORY_WINDOW = 3
DEFAULT_SIGNAL_THRESHOLD = 1
DEFAULT_MAX_RECORDS = 256
MAX_HISTORY_WINDOW = 64
MAX_GOVERNOR_RECORDS = 4096
MAX_COMMAND_BYTES = 4096
MAX_FAILURE_LABEL_BYTES = 256
MAX_LOCATOR_BYTES = 4096


class StallSignal(str, Enum):
    """Canonical bounded signals that may stop one challenge."""

    REPEATED_COMMAND = "repeated_command"
    REPEATED_FAILURE_LABEL = "repeated_failure_label"
    NO_NEW_EVIDENCE = "no_new_fact_artifact_or_progress"
    ARTIFACT_CHURN = "same_locator_artifact_churn"


class RecoveryAction(str, Enum):
    """One operator-directed recovery action for a stalled challenge."""

    CHANGE_OBSERVATION_LAYER = "change_observation_layer"
    INDEPENDENT_FALSIFIER = "independent_falsifier"
    RECLASSIFY = "reclassify"
    PRIMARY_KNOWLEDGE = "primary_knowledge"
    NEEDS_HUMAN = "needs_human"


RECOVERY_LADDER = (
    RecoveryAction.CHANGE_OBSERVATION_LAYER,
    RecoveryAction.INDEPENDENT_FALSIFIER,
    RecoveryAction.RECLASSIFY,
    RecoveryAction.PRIMARY_KNOWLEDGE,
    RecoveryAction.NEEDS_HUMAN,
)


@dataclass(frozen=True, slots=True)
class GovernorPolicy:
    """Bounds and thresholds for one deterministic evaluation."""

    history_window: int = DEFAULT_HISTORY_WINDOW
    signal_threshold: int = DEFAULT_SIGNAL_THRESHOLD
    max_records: int = DEFAULT_MAX_RECORDS

    def __post_init__(self) -> None:
        if (
            isinstance(self.history_window, bool)
            or not isinstance(self.history_window, int)
            or not 2 <= self.history_window <= MAX_HISTORY_WINDOW
        ):
            raise ValueError(
                "history_window must be an integer between 2 and "
                f"{MAX_HISTORY_WINDOW}"
            )
        if (
            isinstance(self.signal_threshold, bool)
            or not isinstance(self.signal_threshold, int)
            or not 1 <= self.signal_threshold <= len(StallSignal)
        ):
            raise ValueError(
                "signal_threshold must be an integer between 1 and "
                f"{len(StallSignal)}"
            )
        if (
            isinstance(self.max_records, bool)
            or not isinstance(self.max_records, int)
            or not self.history_window
            <= self.max_records
            <= MAX_GOVERNOR_RECORDS
        ):
            raise ValueError(
                "max_records must be between history_window and "
                f"{MAX_GOVERNOR_RECORDS}"
            )


@dataclass(frozen=True, slots=True)
class StallDecision:
    """A pure governor result with at most one recovery action."""

    stalled: bool
    signals: tuple[StallSignal, ...]
    recovery_action: RecoveryAction | None
    history_window: int
    signal_threshold: int
    inspected_run_ids: tuple[str, ...] = ()
    repeated_command: str | None = None
    repeated_failure_label: str | None = None
    artifact_locator: str | None = None

    def __post_init__(self) -> None:
        if self.stalled != (self.recovery_action is not None):
            raise ValueError(
                "a stalled decision must have exactly one recovery action"
            )
        if self.stalled and len(self.signals) < self.signal_threshold:
            raise ValueError("stalled decision does not meet its signal threshold")

    def to_metadata(
        self,
        *,
        attempted_actions: Sequence[RecoveryAction | str] = (),
    ) -> dict[str, object]:
        """Return bounded JSON-ready metadata for canonical state."""

        attempted = _normalize_actions(attempted_actions)
        return {
            "schema_version": 1,
            "stalled": self.stalled,
            "history_window": self.history_window,
            "signal_threshold": self.signal_threshold,
            "signals": [signal.value for signal in self.signals],
            "recovery_action": (
                self.recovery_action.value
                if self.recovery_action is not None
                else None
            ),
            "attempted_recovery_actions": [
                action.value for action in attempted
            ],
            "inspected_run_ids": list(self.inspected_run_ids),
            "repeated_command": self.repeated_command,
            "repeated_failure_label": self.repeated_failure_label,
            "artifact_locator": self.artifact_locator,
        }


def _tail[T](values: Sequence[T], maximum: int) -> tuple[T, ...]:
    start = max(0, len(values) - maximum)
    return tuple(values[start:])


def _bounded_text(value: object, *, maximum_bytes: int) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if (
        not normalized
        or "\x00" in normalized
        # Every Unicode character occupies at least one UTF-8 byte.  Reject
        # definitely oversized values before allocating an oversized encoding.
        or len(normalized) > maximum_bytes
        or len(normalized.encode("utf-8")) > maximum_bytes
    ):
        return None
    return normalized


def _terminal_run(run: RunReference) -> bool:
    return run.status not in {RunStatus.CREATED, RunStatus.RUNNING}


def _executed_experiment(experiment: Experiment) -> bool:
    return experiment.status not in {
        ExperimentStatus.REGISTERED,
        ExperimentStatus.RUNNING,
        ExperimentStatus.CANCELLED,
    }


def _experiment_failure_label(
    experiment: Experiment,
    known_labels: frozenset[str],
) -> str | None:
    explicit = _bounded_text(
        experiment.extra.get("failure_label"),
        maximum_bytes=MAX_FAILURE_LABEL_BYTES,
    )
    if explicit is not None:
        return explicit.casefold()
    if isinstance(experiment.result, Mapping):
        result_label = _bounded_text(
            experiment.result.get("failure_label"),
            maximum_bytes=MAX_FAILURE_LABEL_BYTES,
        )
        if result_label is not None:
            return result_label.casefold()
    reason = _bounded_text(
        experiment.evaluation_reason,
        maximum_bytes=MAX_FAILURE_LABEL_BYTES,
    )
    normalized_reason = reason.casefold() if reason is not None else None
    return (
        normalized_reason
        if normalized_reason is not None
        and normalized_reason in known_labels
        else None
    )


def _run_failure_label(
    run: RunReference,
    linked_experiment: Experiment | None,
    known_labels: frozenset[str],
) -> str | None:
    explicit = _bounded_text(
        run.extra.get("failure_label"),
        maximum_bytes=MAX_FAILURE_LABEL_BYTES,
    )
    if explicit is not None:
        return explicit.casefold()
    failures = run.extra.get("failures")
    if isinstance(failures, list) and failures:
        latest = failures[-1]
        if isinstance(latest, Mapping):
            kind = _bounded_text(
                latest.get("kind"),
                maximum_bytes=MAX_FAILURE_LABEL_BYTES,
            )
            if kind is not None:
                return kind.casefold()
    if linked_experiment is not None:
        return _experiment_failure_label(linked_experiment, known_labels)
    return None


def _logical_locator(artifact: ArtifactReference) -> str | None:
    for value in (
        artifact.extra.get("reported_locator"),
        artifact.extra.get("source_locator"),
        artifact.extra.get("locator"),
        artifact.path,
    ):
        locator = _bounded_text(value, maximum_bytes=MAX_LOCATOR_BYTES)
        if locator is not None:
            return locator
    return None


def _normalize_actions(
    values: Sequence[RecoveryAction | str],
) -> tuple[RecoveryAction, ...]:
    normalized: list[RecoveryAction] = []
    for value in _tail(values, len(RECOVERY_LADDER)):
        try:
            action = (
                value
                if isinstance(value, RecoveryAction)
                else RecoveryAction(value)
                if isinstance(value, str)
                else None
            )
        except ValueError:
            continue
        if action is None:
            continue
        if action not in normalized:
            normalized.append(action)
    return tuple(normalized)


def attempted_recovery_actions(
    state: ChallengeState,
) -> tuple[RecoveryAction, ...]:
    """Read only the bounded governor recovery ledger from state metadata."""

    record = state.metadata.get(GOVERNOR_METADATA_KEY)
    if not isinstance(record, Mapping):
        return ()
    if record.get("active_goal_id") != state.active_goal_id:
        return ()
    values = record.get("attempted_recovery_actions")
    if not isinstance(values, list):
        return ()
    return _normalize_actions(values)


def choose_recovery_action(
    attempted_actions: Sequence[RecoveryAction | str] = (),
) -> RecoveryAction:
    """Choose exactly one untried action from the fixed recovery ladder."""

    attempted = set(_normalize_actions(attempted_actions))
    for action in RECOVERY_LADDER:
        if action not in attempted:
            return action
    return RecoveryAction.NEEDS_HUMAN


def evaluate_stall(
    state: ChallengeState,
    *,
    policy: GovernorPolicy | None = None,
) -> StallDecision:
    """Evaluate bounded canonical history without causing any side effect."""

    actual_policy = policy or GovernorPolicy()
    window = actual_policy.history_window
    maximum = actual_policy.max_records

    experiments = tuple(
        experiment
        for experiment in _tail(state.experiments, maximum)
        if _executed_experiment(experiment)
    )
    configured_labels = state.metadata.get("failure_labels")
    known_failure_labels = frozenset(
        label.casefold()
        for value in (
            _tail(configured_labels, maximum)
            if isinstance(configured_labels, list)
            else ()
        )
        if (
            label := _bounded_text(
                value,
                maximum_bytes=MAX_FAILURE_LABEL_BYTES,
            )
        )
        is not None
    )
    commands = tuple(
        (experiment.id, command)
        for experiment in experiments
        if (
            command := _bounded_text(
                experiment.command,
                maximum_bytes=MAX_COMMAND_BYTES,
            )
        )
        is not None
    )
    recent_commands = commands[-window:]
    repeated_command = (
        recent_commands[0][1]
        if len(recent_commands) == window
        and len({command for _record_id, command in recent_commands}) == 1
        else None
    )

    runs = tuple(
        run
        for run in _tail(state.runs, maximum)
        if _terminal_run(run)
    )
    experiment_by_id = {
        experiment.id: experiment
        for experiment in _tail(state.experiments, maximum)
    }
    labeled_runs: list[tuple[str, str]] = []
    for run in runs:
        experiment_id = run.extra.get("experiment_id")
        linked = (
            experiment_by_id.get(str(experiment_id))
            if experiment_id is not None
            else None
        )
        label = _run_failure_label(run, linked, known_failure_labels)
        if label is not None:
            labeled_runs.append((run.id, label))
    recent_labels = tuple(labeled_runs[-window:])
    if len(recent_labels) < window:
        experiment_labels = tuple(
            (experiment.id, label)
            for experiment in experiments
            if (
                label := _experiment_failure_label(
                    experiment,
                    known_failure_labels,
                )
            )
            is not None
        )
        recent_labels = experiment_labels[-window:]
    repeated_failure_label = (
        recent_labels[0][1]
        if len(recent_labels) == window
        and len({label for _record_id, label in recent_labels}) == 1
        else None
    )

    recent_runs = runs[-window:]
    recent_run_ids = tuple(run.id for run in recent_runs)
    fact_run_ids = {
        fact.source_run_id
        for fact in _tail(state.facts, maximum)
        if fact.source_run_id is not None
    }
    artifact_run_ids = {
        artifact.source_run_id
        for artifact in _tail(state.artifacts, maximum)
        if artifact.source_run_id is not None
    }
    progress_run_ids = {
        marker.run_id
        for marker in _tail(state.progress_markers, maximum)
        if marker.run_id is not None
    }
    evidence_run_ids = fact_run_ids | artifact_run_ids | progress_run_ids
    no_new_evidence = (
        len(recent_run_ids) == window
        and all(run_id not in evidence_run_ids for run_id in recent_run_ids)
    )

    run_order = tuple(run.id for run in runs)
    artifacts_by_run: dict[str, dict[str, str]] = {}
    known_run_ids = set(run_order)
    for artifact in _tail(state.artifacts, maximum):
        run_id = artifact.source_run_id
        if run_id is None or run_id not in known_run_ids:
            continue
        locator = _logical_locator(artifact)
        digest = _bounded_text(artifact.sha256, maximum_bytes=128)
        if locator is None or digest is None:
            continue
        artifacts_by_run.setdefault(run_id, {})[locator] = digest.casefold()
    artifact_runs = tuple(
        run_id for run_id in run_order if artifacts_by_run.get(run_id)
    )[-window:]
    churn_locator: str | None = None
    if len(artifact_runs) == window:
        common_locators = set(artifacts_by_run[artifact_runs[0]])
        for run_id in artifact_runs[1:]:
            common_locators.intersection_update(artifacts_by_run[run_id])
        for locator in sorted(common_locators):
            digests = tuple(
                artifacts_by_run[run_id][locator]
                for run_id in artifact_runs
            )
            if all(
                current != following
                for current, following in pairwise(digests)
            ):
                churn_locator = locator
                break

    signals: list[StallSignal] = []
    if repeated_command is not None:
        signals.append(StallSignal.REPEATED_COMMAND)
    if repeated_failure_label is not None:
        signals.append(StallSignal.REPEATED_FAILURE_LABEL)
    if no_new_evidence:
        signals.append(StallSignal.NO_NEW_EVIDENCE)
    if churn_locator is not None:
        signals.append(StallSignal.ARTIFACT_CHURN)

    stalled = len(signals) >= actual_policy.signal_threshold
    action = (
        choose_recovery_action(attempted_recovery_actions(state))
        if stalled
        else None
    )
    return StallDecision(
        stalled=stalled,
        signals=tuple(signals),
        recovery_action=action,
        history_window=window,
        signal_threshold=actual_policy.signal_threshold,
        inspected_run_ids=recent_run_ids,
        repeated_command=repeated_command,
        repeated_failure_label=repeated_failure_label,
        artifact_locator=churn_locator,
    )


__all__ = [
    "DEFAULT_HISTORY_WINDOW",
    "DEFAULT_MAX_RECORDS",
    "DEFAULT_SIGNAL_THRESHOLD",
    "GOVERNOR_METADATA_KEY",
    "RECOVERY_LADDER",
    "GovernorPolicy",
    "RecoveryAction",
    "StallDecision",
    "StallSignal",
    "attempted_recovery_actions",
    "choose_recovery_action",
    "evaluate_stall",
]
