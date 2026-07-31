"""Read-only contest-start and per-challenge operator diagnostics.

The helpers in this module deliberately inspect only canonical snapshots.  They
never recover a state, start a model or sandbox, contact a target, select a
challenge, or apply a suggested recovery action.  The returned commands are
operator-facing suggestions, not work requests.
"""

from __future__ import annotations

import shlex
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime

from ctf_os.budget import BudgetExhausted, require_remaining_seconds
from ctf_os.config import EngineConfig
from ctf_os.governor import GOVERNOR_METADATA_KEY
from ctf_os.models import (
    BudgetMode,
    ChallengeIdentity,
    ChallengeState,
    ChallengeStatus,
    Experiment,
    ExperimentStatus,
    RunStatus,
    TargetStatus,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.store import StateStore, StateStoreError
from ctf_os.terminal import terminal_safe


CONTEST_READINESS_SCHEMA_VERSION = 1
CHALLENGE_DIAGNOSIS_SCHEMA_VERSION = 1
MAX_CONTESTS = 128
# One report must remain well below the broker/terminal response bounds even
# when every challenge contributes a full set of operator pointers.
MAX_CHALLENGES = 128
MAX_ISSUES = 128
MAX_COMMANDS = 64
MAX_TEXT_BYTES = 512
MAX_IDENTIFIERS = 16

_ACTIVE_BACKGROUND_STATUSES = frozenset(
    {
        "launching",
        "starting",
        "running",
        "lost",
        "cleanup_pending",
    }
)
_TERMINAL_EXPERIMENT_STATUSES = frozenset(
    {
        ExperimentStatus.FAILED,
        ExperimentStatus.INCONCLUSIVE,
        ExperimentStatus.CANCELLED,
    }
)


def _safe_text(value: object, *, maximum_bytes: int = MAX_TEXT_BYTES) -> str:
    """Render one untrusted field in a bounded terminal-safe form."""

    rendered = terminal_safe(value)
    encoded = rendered.encode("utf-8", errors="replace")
    if len(encoded) <= maximum_bytes:
        return rendered
    return encoded[:maximum_bytes].decode("utf-8", errors="ignore") + "…"


def _safe_strings(
    values: Iterable[object],
    *,
    maximum: int = MAX_IDENTIFIERS,
) -> list[str]:
    return [_safe_text(value, maximum_bytes=128) for value in list(values)[:maximum]]


def _command(*arguments: object) -> str:
    return " ".join(shlex.quote(str(argument)) for argument in arguments)


def _scoped_command(
    identity: ChallengeIdentity,
    command: tuple[str, ...],
    *arguments: object,
) -> str:
    """Build a CLI command whose identity follows its command path exactly."""

    return _command(
        "ctfos",
        *command,
        identity.contest_id,
        identity.category,
        identity.challenge_id,
        *arguments,
    )


def _append_unique(values: list[str], value: str) -> None:
    if value not in values and len(values) < MAX_COMMANDS:
        values.append(value)


def _issue(
    collection: list[dict[str, str]],
    *,
    code: str,
    detail: str,
) -> None:
    if len(collection) >= MAX_ISSUES:
        return
    collection.append({"code": code, "detail": _safe_text(detail)})


def _target_expired(expires_at: str | None) -> bool:
    if expires_at is None:
        return False
    try:
        parsed = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        # State validation should have rejected this already.  Treat a bad
        # timestamp as unusable in a diagnostic rather than guessing.
        return True
    if parsed.tzinfo is None:
        return True
    return parsed.astimezone(UTC) <= datetime.now(UTC)


def _registered_remote_work(state: ChallengeState) -> list[Experiment]:
    return [
        experiment
        for experiment in state.experiments
        if experiment.status is ExperimentStatus.REGISTERED
        and (
            experiment.extra.get("network_target") is not None
            or (
                experiment.proof_recipe is not None
                and experiment.proof_recipe.network_endpoint is not None
            )
        )
    ]


def _background_summary(state: ChallengeState) -> dict[str, object]:
    raw = state.extra.get("background_jobs", [])
    records = raw if isinstance(raw, list) else []
    active = [
        item
        for item in records
        if isinstance(item, Mapping)
        and item.get("status") in _ACTIVE_BACKGROUND_STATUSES
    ]
    return {
        "recorded_count": len(records),
        "active_count": len(active),
        "active": [
            {
                "job_id": _safe_text(item.get("job_id", ""), maximum_bytes=128),
                "supervisor_id": _safe_text(
                    item.get("supervisor_id", ""), maximum_bytes=128
                ),
                "status": _safe_text(item.get("status", ""), maximum_bytes=64),
                "reason_code": _safe_text(
                    item.get("reason_code", ""), maximum_bytes=128
                ),
            }
            for item in active[:MAX_IDENTIFIERS]
        ],
    }


def _analysis_lease_summary(state: ChallengeState) -> dict[str, object]:
    raw = state.extra.get("analysis_leases", [])
    records = raw if isinstance(raw, list) else []
    active = [
        item
        for item in records
        if isinstance(item, Mapping)
        and item.get("status") in {"running", "cleanup_pending"}
    ]
    return {
        "recorded_count": len(records),
        "active_count": len(active),
        "active": [
            {
                "analysis_id": _safe_text(
                    item.get("analysis_id", ""), maximum_bytes=128
                ),
                "runtime_id": _safe_text(
                    item.get("runtime_id", ""), maximum_bytes=128
                ),
                "status": _safe_text(item.get("status", ""), maximum_bytes=64),
                "reason_code": _safe_text(
                    item.get("reason_code", ""), maximum_bytes=128
                ),
            }
            for item in active[:MAX_IDENTIFIERS]
        ],
    }


def _governor_summary(state: ChallengeState) -> dict[str, object] | None:
    raw = state.metadata.get(GOVERNOR_METADATA_KEY)
    if not isinstance(raw, Mapping):
        return None
    return {
        "recovery_action": _safe_text(
            raw.get("recovery_action", ""), maximum_bytes=128
        ),
        "signals": _safe_strings(
            raw.get("signals", [])
            if isinstance(raw.get("signals"), list)
            else (),
        ),
        "detected_at": _safe_text(raw.get("detected_at", ""), maximum_bytes=64),
    }


def _selected_target_summary(state: ChallengeState) -> dict[str, object] | None:
    if state.primary_target_id is None:
        return None
    target = next(
        (item for item in state.targets if item.id == state.primary_target_id),
        None,
    )
    if target is None:
        return {
            "id": _safe_text(state.primary_target_id, maximum_bytes=128),
            "status": "missing",
        }
    preflight = target.last_preflight
    preflight_summary: dict[str, object] | None = None
    if isinstance(preflight, Mapping):
        preflight_summary = {
            "ok": preflight.get("ok") is True,
            "generation": preflight.get("generation"),
            "remote_request_performed": (
                preflight.get("remote_request_performed") is True
            ),
            "checked_at": _safe_text(
                preflight.get("checked_at", ""), maximum_bytes=64
            ),
        }
    return {
        "id": _safe_text(target.id, maximum_bytes=128),
        "endpoint": _safe_text(target.endpoint),
        "status": target.status.value,
        "enforcement": _safe_text(target.enforcement, maximum_bytes=64),
        "generation": target.generation,
        "expired": _target_expired(target.expires_at),
        "last_preflight": preflight_summary,
    }


def challenge_readiness(state: ChallengeState) -> dict[str, object]:
    """Return a bounded, snapshot-only operational report for one challenge."""

    identity = state.identity
    blockers: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    commands: list[str] = []
    _append_unique(commands, _scoped_command(identity, ("preflight",)))
    _append_unique(
        commands,
        _scoped_command(identity, ("inspect",), "summary"),
    )

    if state.schema_version != STATE_SCHEMA_VERSION:
        _issue(
            blockers,
            code="state_schema_not_current",
            detail=(
                "managed execution requires the current state schema; inspect "
                "the migration before modifying this challenge"
            ),
        )
        _append_unique(commands, _command("ctfos", "migrate", "check"))
    if not state.prompt.strip():
        _issue(
            blockers,
            code="prompt_missing",
            detail="a problem-solving prompt is required before a managed model call",
        )
    if state.budget.mode is BudgetMode.LEGACY_UNARMED:
        _issue(
            blockers,
            code="budget_unarmed",
            detail="select an explicit bounded or operator-unbounded challenge budget",
        )
        _append_unique(commands, _scoped_command(identity, ("budget-reset",)))
    if (
        state.budget.mode is BudgetMode.OPERATOR_UNBOUNDED
        and not (state.budget.unbounded_reason or "").strip()
    ):
        _issue(
            blockers,
            code="unbounded_budget_reason_missing",
            detail="operator-unbounded budgets require a recorded reason",
        )
    try:
        require_remaining_seconds(state.budget)
    except (BudgetExhausted, ValueError):
        _issue(
            blockers,
            code="budget_exhausted_or_invalid",
            detail="the challenge budget has no usable remaining wall-clock time",
        )
        _append_unique(commands, _scoped_command(identity, ("budget-reset",)))

    if state.active_managed_session_id is not None:
        _issue(
            blockers,
            code="managed_session_active",
            detail=(
                "an existing managed session owns this challenge; resume or "
                "cancel it deliberately before a new start"
            ),
        )
        _append_unique(
            commands,
            _scoped_command(identity, ("inspect",), "state"),
        )

    governor = _governor_summary(state)
    if state.status is ChallengeStatus.STALLED:
        _issue(
            blockers,
            code="challenge_stalled",
            detail=(
                "the governor recorded one operator-directed recovery action; "
                "do not reactivate before performing a discriminating action"
            ),
        )
        _append_unique(
            commands,
            _scoped_command(identity, ("inspect",), "state"),
        )
    elif state.status in {
        ChallengeStatus.NEEDS_HUMAN,
        ChallengeStatus.PAUSED,
    }:
        _issue(
            warnings,
            code="challenge_not_active",
            detail=(
                f"challenge is {state.status.value}; an operator must decide "
                "whether to resume it"
            ),
        )

    remote_experiments = _registered_remote_work(state)
    remote_pending = bool(remote_experiments)
    selected_target = _selected_target_summary(state)
    if remote_pending:
        if selected_target is None:
            _issue(
                blockers,
                code="remote_target_unselected",
                detail=(
                    "registered remote work requires a human-selected active "
                    "target with an enforcing boundary"
                ),
            )
            _append_unique(
                commands,
                _scoped_command(identity, ("target", "list")),
            )
        elif selected_target.get("status") != TargetStatus.ACTIVE.value or bool(
            selected_target.get("expired")
        ):
            _issue(
                blockers,
                code="selected_remote_target_unavailable",
                detail="the selected target is revoked, expired, or unavailable",
            )
            _append_unique(
                commands,
                _scoped_command(identity, ("target", "list")),
            )
        elif selected_target.get("enforcement") not in {"builtin", "proxy"}:
            _issue(
                blockers,
                code="selected_remote_target_not_enforced",
                detail=(
                    "remote work requires builtin or operator-provided proxy "
                    "enforcement; declared-only targets are insufficient"
                ),
            )
            _append_unique(
                commands,
                _scoped_command(identity, ("target", "list")),
            )
        else:
            for experiment in remote_experiments:
                recipe = experiment.proof_recipe
                if recipe is not None and recipe.network_endpoint is not None:
                    target_id = recipe.network_target_id
                    target_generation = recipe.network_target_generation
                    configuration_epoch = recipe.configuration_epoch
                    endpoint = recipe.network_endpoint
                else:
                    target_id = experiment.extra.get("network_target_id")
                    target_generation = experiment.extra.get(
                        "network_target_generation"
                    )
                    configuration_epoch = experiment.extra.get(
                        "configuration_epoch"
                    )
                    endpoint = experiment.extra.get("network_target")
                if (
                    target_id != selected_target.get("id")
                    or target_generation != selected_target.get("generation")
                    or configuration_epoch != state.configuration_epoch
                    or endpoint != selected_target.get("endpoint")
                ):
                    _issue(
                        blockers,
                        code="remote_experiment_binding_stale",
                        detail=(
                            f"registered remote experiment {experiment.id} does "
                            "not match the selected target generation/configuration"
                        ),
                    )
            preflight = selected_target.get("last_preflight")
            generation_matches = (
                isinstance(preflight, Mapping)
                and preflight.get("generation") == selected_target.get("generation")
                and preflight.get("ok") is True
            )
            if not generation_matches:
                _issue(
                    blockers,
                    code="selected_remote_target_preflight_stale",
                    detail=(
                        "the selected target has no successful current-generation "
                        "preflight record"
                    ),
                )
                target_id = selected_target.get("id")
                if isinstance(target_id, str):
                    _append_unique(
                        commands,
                        _scoped_command(
                            identity,
                            ("target", "check"),
                            target_id,
                        ),
                    )
            if selected_target.get("enforcement") == "builtin":
                smoke_current = (
                    isinstance(preflight, Mapping)
                    and preflight.get("generation")
                    == selected_target.get("generation")
                    and preflight.get("ok") is True
                    and preflight.get("remote_request_performed") is True
                )
                if not smoke_current:
                    _issue(
                        blockers,
                        code="builtin_remote_smoke_missing",
                        detail=(
                            "the builtin target has not recorded a successful "
                            "current-generation remote smoke; run it only with "
                            "operator approval"
                        ),
                    )
                    target_id = selected_target.get("id")
                    if isinstance(target_id, str):
                        _append_unique(
                            commands,
                            _scoped_command(
                                identity,
                                ("target", "smoke"),
                                target_id,
                                "--mode",
                                "dns",
                                "--mode",
                                "tcp",
                            ),
                        )
            else:
                _issue(
                    blockers,
                    code="external_proxy_verification_required",
                    detail=(
                        "proxy enforcement needs an operator-verified external "
                        "egress boundary; contest-check never sends a remote probe"
                    ),
                )

    background = _background_summary(state)
    if background["active_count"]:
        _issue(
            blockers,
            code="background_job_active_or_unreconciled",
            detail=(
                "recorded background jobs need an explicit supervisor recovery "
                "or status decision before a clean contest start"
            ),
        )
        _append_unique(
            commands,
            _scoped_command(identity, ("jobs",), "--recover"),
        )

    analysis_leases = _analysis_lease_summary(state)
    if analysis_leases["active_count"]:
        _issue(
            blockers,
            code="analysis_lease_active_or_unreconciled",
            detail=(
                "durable isolated-analysis leases need an operator decision "
                "before a clean contest start"
            ),
        )
        _append_unique(commands, _scoped_command(identity, ("inspect",), "state"))

    if any(
        experiment.status is ExperimentStatus.RUNNING
        for experiment in state.experiments
    ):
        _issue(
            blockers,
            code="unreconciled_running_experiment",
            detail="a canonical experiment is still running and needs inspection",
        )
        _append_unique(
            commands,
            _scoped_command(identity, ("inspect",), "experiments"),
        )
    if any(run.status is RunStatus.RUNNING for run in state.runs):
        _issue(
            blockers,
            code="unreconciled_running_run",
            detail="a canonical run is still running and needs inspection",
        )
        _append_unique(commands, _scoped_command(identity, ("inspect",), "runs"))

    return {
        "identity": {
            "contest": _safe_text(identity.contest_id, maximum_bytes=128),
            "category": _safe_text(identity.category, maximum_bytes=128),
            "challenge": _safe_text(identity.challenge_id, maximum_bytes=128),
        },
        "state_revision": state.revision,
        "state_schema_version": state.schema_version,
        "status": state.status.value,
        "ok": not blockers,
        "managed_session_active": state.active_managed_session_id is not None,
        "remote_work_registered": remote_pending,
        "selected_target": selected_target,
        "background": background,
        "analysis_leases": analysis_leases,
        "governor": governor,
        "blockers": blockers,
        "warnings": warnings,
        "next_commands": commands,
    }


def _iter_contest_ids(
    store: StateStore,
    contest_id: str | None,
) -> tuple[list[str], list[dict[str, str]], bool]:
    errors: list[dict[str, str]] = []
    if contest_id is not None:
        root = store.contest_paths(contest_id).root
        if root.is_symlink() or not root.is_dir():
            _issue(
                errors,
                code="contest_not_found",
                detail=f"no canonical contest exists for {contest_id!r}",
            )
            return [], errors, False
        return [contest_id], errors, False
    root = store.contests_root
    if not root.is_dir():
        return [], errors, False
    values: list[str] = []
    try:
        entries = sorted(root.iterdir(), key=lambda item: item.name)
    except OSError as error:
        _issue(
            errors,
            code="contest_directory_unreadable",
            detail=str(error),
        )
        return [], errors, False
    for path in entries:
        if path.is_symlink() or not path.is_dir():
            _issue(
                errors,
                code="invalid_contest_entry",
                detail=f"unexpected non-directory or symlink: {path.name}",
            )
            continue
        try:
            store.contest_paths(path.name)
        except (StateStoreError, ValueError):
            _issue(
                errors,
                code="invalid_contest_identity",
                detail=f"invalid contest directory: {path.name}",
            )
            continue
        if len(values) >= MAX_CONTESTS:
            return values, errors, True
        values.append(path.name)
    return values, errors, False


def _iter_challenge_identities(
    store: StateStore,
    contest_id: str,
) -> tuple[list[ChallengeIdentity], list[dict[str, str]], bool]:
    errors: list[dict[str, str]] = []
    root = store.contest_paths(contest_id).challenges
    if not root.is_dir():
        return [], errors, False
    identities: list[ChallengeIdentity] = []
    try:
        categories = sorted(root.iterdir(), key=lambda item: item.name)
    except OSError as error:
        _issue(
            errors,
            code="challenge_directory_unreadable",
            detail=str(error),
        )
        return [], errors, False
    for category in categories:
        if category.is_symlink() or not category.is_dir():
            _issue(
                errors,
                code="invalid_category_entry",
                detail=f"unexpected non-directory or symlink: {category.name}",
            )
            continue
        try:
            challenges = sorted(category.iterdir(), key=lambda item: item.name)
        except OSError as error:
            _issue(
                errors,
                code="category_directory_unreadable",
                detail=str(error),
            )
            continue
        for challenge in challenges:
            if challenge.is_symlink() or not challenge.is_dir():
                _issue(
                    errors,
                    code="invalid_challenge_entry",
                    detail=(
                        "unexpected non-directory or symlink: "
                        f"{category.name}/{challenge.name}"
                    ),
                )
                continue
            identity = ChallengeIdentity(
                contest_id,
                category.name,
                challenge.name,
            )
            try:
                store.challenge_paths(identity)
            except (StateStoreError, ValueError):
                _issue(
                    errors,
                    code="challenge_identity_invalid",
                    detail=(
                        "invalid challenge directory "
                        f"{category.name}/{challenge.name}"
                    ),
                )
                continue
            if len(identities) >= MAX_CHALLENGES:
                return identities, errors, True
            identities.append(identity)
    return identities, errors, False


def _doctor_summary(report: Mapping[str, object]) -> dict[str, object]:
    warnings = report.get("warnings")
    raw_warnings = warnings if isinstance(warnings, list) else []
    image = report.get("image")
    capabilities = report.get("managed_capabilities")
    return {
        "ok": report.get("ok") is True,
        "warnings": _safe_strings(raw_warnings, maximum=MAX_IDENTIFIERS),
        "image_pin_status": (
            _safe_text(image.get("pin_status", ""), maximum_bytes=64)
            if isinstance(image, Mapping)
            else "unavailable"
        ),
        "managed_capabilities_status": (
            _safe_text(capabilities.get("status", ""), maximum_bytes=64)
            if isinstance(capabilities, Mapping)
            else "unavailable"
        ),
    }


def contest_readiness(
    store: StateStore,
    config: EngineConfig,
    doctor_report: Mapping[str, object],
    *,
    contest_id: str | None = None,
) -> dict[str, object]:
    """Aggregate snapshot-only operational readiness without a release claim."""

    del config  # The doctor report is the only host/config probe authority here.
    blockers: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    commands: list[str] = []
    doctor = _doctor_summary(doctor_report)
    if doctor["ok"] is not True:
        _issue(
            blockers,
            code="doctor_not_ready",
            detail=(
                "host, exact image pin, or managed capability diagnostics "
                "are not ready"
            ),
        )
        _append_unique(commands, _command("ctfos", "doctor"))

    contests, contest_errors, contest_scan_truncated = _iter_contest_ids(
        store,
        contest_id,
    )
    for error in contest_errors:
        _issue(blockers, code=error["code"], detail=error["detail"])
    if contest_scan_truncated:
        _issue(
            blockers,
            code="contest_scan_limit_reached",
            detail="contest readiness refused to omit contests beyond its bound",
        )
    challenge_reports: list[dict[str, object]] = []
    challenge_scan_truncated = False
    for contest in contests:
        identities, discovery_errors, identities_truncated = (
            _iter_challenge_identities(store, contest)
        )
        challenge_scan_truncated = challenge_scan_truncated or identities_truncated
        for error in discovery_errors:
            _issue(
                blockers,
                code=error["code"],
                detail=error["detail"],
            )
        for identity in identities:
            if len(challenge_reports) >= MAX_CHALLENGES:
                challenge_scan_truncated = True
                break
            try:
                state = store.read_snapshot(identity)
            except (StateStoreError, OSError, ValueError) as error:
                _issue(
                    blockers,
                    code="state_snapshot_unreadable",
                    detail=f"{identity.key}: {error}",
                )
                _append_unique(
                    commands,
                    _scoped_command(identity, ("inspect",), "state"),
                )
                continue
            report = challenge_readiness(state)
            challenge_reports.append(report)
            for item in report["blockers"]:
                if isinstance(item, Mapping):
                    _issue(
                        blockers,
                        code=f"{identity.key}:{item.get('code', 'unknown')}",
                        detail=str(item.get("detail", "")),
                    )
            for item in report["warnings"]:
                if isinstance(item, Mapping):
                    _issue(
                        warnings,
                        code=f"{identity.key}:{item.get('code', 'unknown')}",
                        detail=str(item.get("detail", "")),
                    )
            for command in report["next_commands"]:
                if isinstance(command, str):
                    _append_unique(commands, command)
        if challenge_scan_truncated:
            break

    if contest_id is not None and not challenge_reports:
        _issue(
            blockers,
            code="contest_has_no_challenges",
            detail="no canonical challenge state was found for this contest",
        )
    if challenge_scan_truncated:
        _issue(
            blockers,
            code="challenge_scan_limit_reached",
            detail="contest readiness refused to silently omit additional challenges",
        )

    return {
        "schema_version": CONTEST_READINESS_SCHEMA_VERSION,
        "kind": "ctfos.contest_readiness.v1",
        "ok": not blockers,
        "release": {
            "status": "not_checked",
            "detail": (
                "contest-check is an operational snapshot and never proves "
                "formal release acceptance"
            ),
        },
        "doctor": doctor,
        "contests": [_safe_text(value, maximum_bytes=128) for value in contests],
        "challenges": challenge_reports,
        "blockers": blockers,
        "warnings": warnings,
        "next_commands": commands,
        "authorities": {
            "automatic_challenge_selection": False,
            "automatic_model_request": False,
            "automatic_challenge_tool_execution": False,
            "automatic_remote_request": False,
            "automatic_canonical_state_mutation": False,
            "automatic_submission": False,
            "local_host_diagnostic_processes_performed": True,
        },
    }


def challenge_diagnosis(
    store: StateStore,
    identity: ChallengeIdentity,
) -> dict[str, object]:
    """Return the bounded recovery context for one snapshot without recovery."""

    state = store.read_snapshot(identity)
    readiness = challenge_readiness(state)
    latest_capsule: dict[str, object] | None = None
    for checkpoint in reversed(state.checkpoints):
        capsule = checkpoint.failure_capsule
        if capsule is None:
            continue
        latest_capsule = {
            "checkpoint_id": _safe_text(checkpoint.id, maximum_bytes=128),
            "reason_code": _safe_text(capsule.reason_code, maximum_bytes=128),
            "stage": _safe_text(capsule.stage, maximum_bytes=128),
            "state_revision_before": capsule.state_revision_before,
            "state_revision_after": capsule.state_revision_after,
            "run_ids": _safe_strings(capsule.run_ids),
            "failed_experiment_ids": _safe_strings(capsule.failed_experiment_ids),
            "artifact_ids": _safe_strings(capsule.artifact_ids),
            "receipt_ids": _safe_strings(capsule.receipt_ids),
            "next_experiment_ids": _safe_strings(capsule.next_experiment_ids),
        }
        break

    latest_experiment: dict[str, object] | None = None
    for experiment in reversed(state.experiments):
        if experiment.status not in _TERMINAL_EXPERIMENT_STATUSES:
            continue
        error = (
            experiment.result.get("error")
            if isinstance(experiment.result, Mapping)
            else None
        )
        latest_experiment = {
            "id": _safe_text(experiment.id, maximum_bytes=128),
            "status": experiment.status.value,
            "error": _safe_text(error, maximum_bytes=MAX_TEXT_BYTES)
            if isinstance(error, str)
            else None,
            "run_ids": _safe_strings(experiment.evidence_run_ids),
            "artifact_ids": _safe_strings(experiment.artifact_ids),
        }
        break

    latest_run: dict[str, object] | None = None
    for run in reversed(state.runs):
        if run.status.value not in {"failed", "timed_out", "cancelled", "interrupted"}:
            continue
        latest_run = {
            "id": _safe_text(run.id, maximum_bytes=128),
            "status": run.status.value,
            "result_path": _safe_text(run.result_path, maximum_bytes=256)
            if run.result_path is not None
            else None,
            "validation_path": _safe_text(run.validation_path, maximum_bytes=256)
            if run.validation_path is not None
            else None,
        }
        break

    commands = list(readiness["next_commands"])
    _append_unique(
        commands,
        _scoped_command(identity, ("inspect",), "experiments"),
    )
    _append_unique(commands, _scoped_command(identity, ("inspect",), "runs"))
    return {
        "schema_version": CHALLENGE_DIAGNOSIS_SCHEMA_VERSION,
        "kind": "ctfos.challenge_diagnosis.v1",
        "ok": readiness["ok"],
        "readiness": readiness,
        "latest_failure_capsule": latest_capsule,
        "latest_terminal_experiment": latest_experiment,
        "latest_failed_run": latest_run,
        "next_commands": commands,
        "authorities": {
            "automatic_recovery": False,
            "automatic_canonical_state_mutation": False,
            "automatic_model_request": False,
            "automatic_challenge_tool_execution": False,
            "automatic_remote_request": False,
            "automatic_submission": False,
            "local_host_diagnostic_processes_performed": False,
        },
    }


__all__ = [
    "CHALLENGE_DIAGNOSIS_SCHEMA_VERSION",
    "CONTEST_READINESS_SCHEMA_VERSION",
    "challenge_diagnosis",
    "challenge_readiness",
    "contest_readiness",
]
