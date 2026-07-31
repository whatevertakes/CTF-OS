"""Explicit, crash-recoverable state protocol migration.

The normal state writer never changes a state's schema version.  This module is
the sole v1 -> v2 authority and keeps exact pre-migration bytes for rollback
until a later operational v2 commit is observed.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ctf_os.models import (
    BudgetMode,
    CandidateTier,
    ChallengeState,
    ChallengeStatus,
    ClosureBundle,
    ClosureCompleteness,
    ExecutionReceipt,
    ExperimentKind,
    ExperimentStatus,
    FactKind,
    GoalStatus,
    ReceiptOutcome,
    RunOrigin,
    RunReference,
    RunStatus,
    SubmissionOverride,
    SubmissionStatus,
    TargetRecord,
    TargetStatus,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.store.atomic import (
    atomic_write_bytes,
    atomic_write_json,
    canonical_json_bytes,
    read_json,
    strict_json_loads,
)
from ctf_os.store.locks import FileLock, LockTimeout
from ctf_os.store.upgrades import upgrade_state, validate_state_protocol_shape


class MigrationError(RuntimeError):
    """The explicit migration cannot proceed safely."""


_EXIT_CODE = re.compile(r"\bexited (-?[0-9]+)\b")
_TERMINAL_CHALLENGE = {
    ChallengeStatus.SOLVED,
    ChallengeStatus.ABANDONED,
}


@dataclass(frozen=True)
class StateMigrationResult:
    source_version: int
    target_version: int
    payload: bytes
    stats: dict[str, int]


def _receipt_outcome(status: RunStatus) -> ReceiptOutcome:
    return {
        RunStatus.COMPLETED: ReceiptOutcome.SUCCEEDED,
        RunStatus.FAILED: ReceiptOutcome.FAILED,
        RunStatus.INVALID: ReceiptOutcome.FAILED,
        RunStatus.TIMED_OUT: ReceiptOutcome.TIMED_OUT,
        RunStatus.CANCELLED: ReceiptOutcome.CANCELLED,
        RunStatus.INTERRUPTED: ReceiptOutcome.INTERRUPTED,
    }.get(status, ReceiptOutcome.INTERRUPTED)


def _receipt_fact(
    statement: str,
    *,
    source_run_id: str | None,
    experiment_ids: set[str],
    runs: Mapping[str, RunReference],
) -> str | None:
    if (
        source_run_id is None
        or source_run_id not in runs
        or not statement.startswith("Experiment ")
        or " exited " not in statement
    ):
        return None
    run = runs[source_run_id]
    experiment_id = run.extra.get("experiment_id")
    if not isinstance(experiment_id, str) or experiment_id not in experiment_ids:
        return None
    expected_prefix = f"Experiment {experiment_id} exited "
    return experiment_id if statement.startswith(expected_prefix) else None


def _legacy_target_id(endpoint: str, generation: int) -> str:
    digest = hashlib.sha256(
        f"{endpoint}\0{generation}".encode("utf-8")
    ).hexdigest()[:16]
    return f"T-legacy-{digest}"


def _missing_run_records(
    state: ChallengeState,
    state_path: Path | None,
) -> list[RunReference]:
    if state_path is None:
        return []
    runs_root = state_path.parent / "runs"
    if not runs_root.is_dir():
        return []
    known = {run.id for run in state.runs}
    records: list[RunReference] = []
    for directory in sorted(runs_root.iterdir(), key=lambda item: item.name):
        if not directory.is_dir() or directory.is_symlink() or directory.name in known:
            continue
        request_path = directory / "request.json"
        if not request_path.is_file() or request_path.is_symlink():
            continue
        try:
            request = read_json(request_path)
        except (OSError, ValueError):
            request = {}
        if not isinstance(request, Mapping) or request.get("kind") != "model":
            continue
        relative = request_path.relative_to(state_path.parent).as_posix()
        records.append(
            RunReference(
                id=directory.name,
                base_revision=int(request.get("base_revision", state.revision)),
                status=RunStatus.INTERRUPTED,
                request_path=relative,
                role=str(request.get("role", "unknown")),
                model=(
                    str(request["model"])
                    if request.get("model") is not None
                    else None
                ),
                origin=RunOrigin.COMPATIBILITY,
                configuration_epoch=0,
                extra={
                    "migration_recovery": "orphan_model_run_directory",
                },
            )
        )
    return records


def migrate_state_document(
    raw: Mapping[str, Any],
    *,
    state_path: Path | None = None,
    migration_id: str = "state-v2",
) -> StateMigrationResult:
    """Return deterministic v2 bytes without mutating the workspace."""

    source_version = validate_state_protocol_shape(raw)
    if source_version == STATE_SCHEMA_VERSION:
        state = ChallengeState.from_dict(raw)
        state.validate()
        return StateMigrationResult(
            source_version=source_version,
            target_version=source_version,
            payload=canonical_json_bytes(state.to_dict()),
            stats={"changed": 0},
        )

    upgraded = upgrade_state(raw)
    state = ChallengeState.from_dict(upgraded)
    state.validate()
    state.schema_version = STATE_SCHEMA_VERSION
    state.configuration_epoch = 0
    state.workspace_revision = 0
    state.receipts = []
    state.sessions = []
    state.cycles = []
    state.waves = []
    state.checkpoints = []
    state.targets = []
    state.primary_target_id = None
    state.workspace_publishes = []
    state.active_managed_session_id = None

    for run in state.runs:
        run.origin = (
            RunOrigin.PROOF
            if run.role == "proof"
            else RunOrigin.COMPATIBILITY
        )
        run.configuration_epoch = 0
    missing_runs = _missing_run_records(state, state_path)
    state.runs.extend(missing_runs)

    runs = {run.id: run for run in state.runs}
    experiments = {experiment.id: experiment for experiment in state.experiments}
    artifacts = {artifact.id: artifact for artifact in state.artifacts}
    artifacts_by_run: dict[str, list[Any]] = {}
    for artifact in state.artifacts:
        if artifact.source_run_id:
            artifacts_by_run.setdefault(artifact.source_run_id, []).append(
                artifact
            )

    fact_to_receipt: dict[str, str] = {}
    semantic_facts = []
    for fact in state.facts:
        experiment_id = _receipt_fact(
            fact.statement,
            source_run_id=fact.source_run_id,
            experiment_ids=set(experiments),
            runs=runs,
        )
        if experiment_id is None:
            fact.kind = FactKind.OBSERVATION
            semantic_facts.append(fact)
            continue
        assert fact.source_run_id is not None
        run = runs[fact.source_run_id]
        stderr = next(
            (
                artifact
                for artifact in artifacts_by_run.get(run.id, [])
                if artifact.extra.get("stream") == "stderr"
            ),
            None,
        )
        stdout = artifacts.get(fact.artifact_id or "")
        exit_match = _EXIT_CODE.search(fact.statement)
        receipt_id = f"RCPT-{fact.id}"
        preview = fact.statement.split("; stdout:", 1)[0][:160]
        state.receipts.append(
            ExecutionReceipt(
                id=receipt_id,
                experiment_id=experiment_id,
                run_id=run.id,
                outcome=_receipt_outcome(run.status),
                exit_code=(
                    int(exit_match.group(1)) if exit_match is not None else None
                ),
                wall_seconds=float(run.extra.get("wall_seconds", 0.0)),
                stdout_artifact_id=stdout.id if stdout is not None else None,
                stderr_artifact_id=stderr.id if stderr is not None else None,
                stdout_bytes=(
                    int(stdout.size) if stdout is not None and stdout.size else 0
                ),
                stderr_bytes=(
                    int(stderr.size) if stderr is not None and stderr.size else 0
                ),
                preview=preview,
                created_at=fact.created_at,
                extra={"legacy_fact_id": fact.id},
            )
        )
        fact_to_receipt[fact.id] = receipt_id
    state.facts = semantic_facts

    for hypothesis in state.hypotheses:
        retained: list[str] = []
        for fact_id in hypothesis.evidence_fact_ids:
            receipt_id = fact_to_receipt.get(fact_id)
            if receipt_id is not None:
                hypothesis.evidence_receipt_ids.append(receipt_id)
            else:
                retained.append(fact_id)
        hypothesis.evidence_fact_ids = retained

    probe_count = strategic_count = legacy_count = 0
    for experiment in state.experiments:
        retained = []
        for fact_id in experiment.evidence_fact_ids:
            receipt_id = fact_to_receipt.get(fact_id)
            if receipt_id is not None:
                experiment.evidence_receipt_ids.append(receipt_id)
            else:
                retained.append(fact_id)
        experiment.evidence_fact_ids = retained
        if isinstance(experiment.result, dict):
            fact_id = experiment.result.pop("fact_id", None)
            if isinstance(fact_id, str) and fact_id in fact_to_receipt:
                experiment.result["receipt_id"] = fact_to_receipt[fact_id]
            experiment.result.pop("stdout_summary", None)
            experiment.result.pop("stderr_summary", None)
        if (
            experiment.status is ExperimentStatus.REGISTERED
            and not experiment.hypothesis_ids
        ):
            experiment.kind = ExperimentKind.PROBE
            probe_count += 1
        elif experiment.hypothesis_ids:
            experiment.kind = ExperimentKind.STRATEGIC
            strategic_count += 1
        else:
            experiment.kind = ExperimentKind.LEGACY
            legacy_count += 1

    for candidate in state.candidates:
        candidate.tier = CandidateTier.LEGACY_UNKNOWN
        candidate.format_epoch = 0

    state.budget.mode = (
        BudgetMode.BOUNDED
        if state.budget.allocated_seconds is not None
        else BudgetMode.LEGACY_UNARMED
    )

    legacy_targets = state.metadata.get("network_targets", [])
    if isinstance(legacy_targets, list):
        legacy_enforcement = str(
            state.metadata.get("network_enforcement", "declared")
        )
        for endpoint in legacy_targets:
            if not isinstance(endpoint, str):
                continue
            state.targets.append(
                TargetRecord(
                    id=_legacy_target_id(endpoint, 1),
                    endpoint=endpoint,
                    status=TargetStatus.ACTIVE,
                    enforcement=legacy_enforcement,
                    docker_network=str(
                        state.metadata.get("docker_network", "bridge")
                    ),
                    purpose="legacy allowlist migration",
                    generation=1,
                    provenance="v1 metadata",
                    created_at=state.created_at,
                    extra=(
                        {
                            "builtin_egress": {
                                "http_burst": state.metadata.get(
                                    "network_http_burst",
                                    4,
                                ),
                                "http_requests_per_second": (
                                    state.metadata.get(
                                        "network_http_requests_per_second",
                                        2.0,
                                    )
                                ),
                                "schema_version": 1,
                            }
                        }
                        if legacy_enforcement == "builtin"
                        else {}
                    ),
                )
            )

    override_count = 0
    for submission in state.submissions:
        if (
            submission.status
            in {SubmissionStatus.ACCEPTED, SubmissionStatus.REJECTED}
            and not submission.proof_passed
            and submission.override is None
        ):
            submission.override = SubmissionOverride(
                kind="legacy_unproved",
                actor="migration",
                reason="v1 recorded a terminal outcome without proof",
                timestamp=submission.submitted_at or state.updated_at,
            )
            override_count += 1

    if state.status in _TERMINAL_CHALLENGE:
        active = state.active_goal
        if active is not None:
            active.status = GoalStatus.CANCELLED
            active.blocked_reason = None
        state.active_goal_id = None
        state.closure = ClosureBundle(
            id=f"CL-legacy-{hashlib.sha256(state.identity.key.encode()).hexdigest()[:12]}",
            completeness=ClosureCompleteness.LEGACY_PARTIAL,
            portability="referential",
            proof_run_ids=[
                run.id for run in state.runs if run.origin is RunOrigin.PROOF
            ],
            submission_ids=[item.id for item in state.submissions],
            target_ids=[item.id for item in state.targets],
            created_at=state.updated_at,
        )
    else:
        state.closure = None

    state.metadata["state_v2_migration"] = {
        "id": migration_id,
        "source_schema": source_version,
    }
    state.validate()
    payload = canonical_json_bytes(state.to_dict())
    return StateMigrationResult(
        source_version=source_version,
        target_version=STATE_SCHEMA_VERSION,
        payload=payload,
        stats={
            "changed": 1,
            "receipts": len(state.receipts),
            "semantic_facts": len(state.facts),
            "probe_experiments": probe_count,
            "strategic_experiments": strategic_count,
            "legacy_experiments": legacy_count,
            "legacy_unknown_candidates": len(state.candidates),
            "targets": len(state.targets),
            "unproved_overrides": override_count,
            "terminal_active_goals": int(
                state.status in _TERMINAL_CHALLENGE
                and state.active_goal_id is not None
            ),
            "legacy_spent_seconds": state.budget.spent_seconds,
            "recovered_model_runs": len(missing_runs),
        },
    )


def _state_paths(workspace_root: Path) -> list[Path]:
    contests = workspace_root / ".ctfos" / "contests"
    if not contests.is_dir():
        return []
    return sorted(
        (
            path
            for path in contests.glob("*/challenges/*/*/state.json")
            if path.is_file() and not path.is_symlink()
        ),
        key=lambda path: path.as_posix(),
    )


def plan_migration(
    workspace_root: Path,
    *,
    migration_id: str = "state-v2",
) -> dict[str, Any]:
    root = workspace_root.expanduser().resolve()
    totals: dict[str, int] = {}
    states: list[dict[str, Any]] = []
    for path in _state_paths(root):
        raw = strict_json_loads(path.read_bytes())
        if not isinstance(raw, Mapping):
            raise MigrationError(f"state root is not an object: {path}")
        result = migrate_state_document(
            raw,
            state_path=path,
            migration_id=migration_id,
        )
        for key, value in result.stats.items():
            totals[key] = totals.get(key, 0) + value
        states.append(
            {
                "path": path.relative_to(root).as_posix(),
                "source_version": result.source_version,
                "target_version": result.target_version,
                "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "target_sha256": hashlib.sha256(result.payload).hexdigest(),
                "changed": result.payload != path.read_bytes(),
                "stats": result.stats,
            }
        )
    source_versions = {
        int(item["source_version"]) for item in states
    }
    if len(source_versions) > 1:
        raise MigrationError(
            "mixed state schemas are forbidden within one workspace"
        )
    return {
        "migration_id": migration_id,
        "state_schema_target": STATE_SCHEMA_VERSION,
        "states": states,
        "totals": totals,
        "zero_diff": not any(item["changed"] for item in states),
    }


def _backup_candidates(root: Path, states: list[Path]) -> list[Path]:
    paths = list(states)
    paths.extend(
        path.with_name("state.prev.json")
        for path in states
        if path.with_name("state.prev.json").is_file()
    )
    paths.extend(
        path
        for path in (
            root / ".ctfos" / "engine.toml",
            *(
                item
                for contest in (root / ".ctfos" / "contests").glob("*")
                for item in (
                    contest / "contest.json",
                    contest / "submissions.jsonl",
                    contest / "runtime" / "submission-intents.json",
                )
            ),
        )
        if path.is_file() and not path.is_symlink()
    )
    return sorted(set(paths), key=lambda path: path.as_posix())


def _manifest_relative(value: object) -> Path:
    relative = Path(str(value))
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise MigrationError("migration manifest contains an unsafe path")
    return relative


def _restore_backups(
    root: Path,
    migration_root: Path,
    backups: list[dict[str, Any]],
    absent_paths: list[str],
) -> int:
    restored = 0
    for record in backups:
        if not isinstance(record, Mapping):
            raise MigrationError("migration backup record is corrupt")
        relative = _manifest_relative(record.get("path"))
        backup = migration_root / "backup" / relative
        payload = backup.read_bytes()
        if (
            hashlib.sha256(payload).hexdigest() != record.get("sha256")
            or len(payload) != record.get("size")
        ):
            raise MigrationError(
                f"migration backup hash mismatch: {relative}"
            )
        atomic_write_bytes(root / relative, payload)
        restored += 1
    for value in absent_paths:
        relative = _manifest_relative(value)
        path = root / relative
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    return restored


def _validate_restored_v1_states(root: Path) -> None:
    for state_path in _state_paths(root):
        raw = strict_json_loads(state_path.read_bytes())
        if not isinstance(raw, Mapping):
            raise MigrationError(
                f"restored state root is not an object: {state_path}"
            )
        if validate_state_protocol_shape(raw) not in {0, 1}:
            raise MigrationError(
                f"rollback did not restore v1 state: {state_path}"
            )
        state = ChallengeState.from_dict(upgrade_state(raw))
        state.validate()


def apply_migration(
    workspace_root: Path,
    *,
    migration_id: str = "state-v2",
) -> dict[str, Any]:
    root = workspace_root.expanduser().resolve()
    ctf_root = root / ".ctfos"
    migration_root = ctf_root / "migrations" / migration_id
    backup_root = migration_root / "backup"
    lock = FileLock(ctf_root / "runtime" / "migration.lock", timeout=0)
    held_locks: list[FileLock] = []
    backups: list[dict[str, Any]] = []
    absent_paths: list[str] = []
    installed: list[dict[str, Any]] = []
    marker_installed = False
    plan: dict[str, Any] | None = None
    try:
        lock.acquire()
    except LockTimeout as error:
        raise MigrationError("another migration is active") from error
    try:
        if (migration_root / "manifest.json").exists():
            existing = read_json(migration_root / "manifest.json")
            if isinstance(existing, Mapping) and existing.get("status") == "applied":
                plan = plan_migration(root, migration_id=migration_id)
                if plan["zero_diff"]:
                    return {**plan, "status": "already_applied"}
            raise MigrationError(
                f"migration directory already exists: {migration_root}"
            )

        plan = plan_migration(root, migration_id=migration_id)
        if plan["zero_diff"]:
            return {**plan, "status": "no_changes"}

        states = _state_paths(root)
        for state_path in states:
            raw = strict_json_loads(state_path.read_bytes())
            if not isinstance(raw, Mapping):
                raise MigrationError(
                    f"state root is not an object: {state_path}"
                )
            if raw.get("active_managed_session_id") is not None:
                raise MigrationError(
                    "an active managed session blocks migration"
                )

        marker = {
            "migration_id": migration_id,
            "status": "migrating",
            "active_schema": 1,
        }
        atomic_write_json(ctf_root / "migration.json", marker)
        marker_installed = True

        contest_roots = sorted(
            (
                path
                for path in (ctf_root / "contests").glob("*")
                if path.is_dir() and not path.is_symlink()
            ),
            key=lambda path: path.as_posix(),
        )
        lock_paths = [
            *[
                contest_root / "runtime" / "submissions.lock"
                for contest_root in contest_roots
            ],
            *[
                state_path.parent / "runtime" / "session.lock"
                for state_path in states
            ],
            *[state_path.parent / ".lock" for state_path in states],
            *[
                contest_root / "runtime" / "board.lock"
                for contest_root in contest_roots
            ],
        ]
        for lock_path in lock_paths:
            held = FileLock(lock_path, timeout=0)
            try:
                held.acquire()
            except LockTimeout as error:
                raise MigrationError(
                    f"active workspace owner blocks migration: {lock_path}"
                ) from error
            held_locks.append(held)

        for source in _backup_candidates(root, states):
            relative = source.relative_to(root)
            payload = source.read_bytes()
            destination = backup_root / relative
            atomic_write_bytes(destination, payload)
            backups.append(
                {
                    "path": relative.as_posix(),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                }
            )
        absent_paths = [
            state_path.with_name("state.prev.json")
            .relative_to(root)
            .as_posix()
            for state_path in states
            if not state_path.with_name("state.prev.json").exists()
        ]
        atomic_write_json(
            migration_root / "manifest.json",
            {
                "migration_id": migration_id,
                "status": "prepared",
                "source_schema": 1,
                "target_schema": STATE_SCHEMA_VERSION,
                "backups": backups,
                "absent_paths": absent_paths,
                "installed": [],
                "plan_totals": plan["totals"],
            },
        )

        installed = []
        for state_path in states:
            raw = strict_json_loads(state_path.read_bytes())
            if not isinstance(raw, Mapping):
                raise MigrationError(f"state root is not an object: {state_path}")
            result = migrate_state_document(
                raw,
                state_path=state_path,
                migration_id=migration_id,
            )
            previous = state_path.with_name("state.prev.json")
            previous_payload = result.payload
            if previous.is_file() and not previous.is_symlink():
                previous_raw = strict_json_loads(previous.read_bytes())
                if not isinstance(previous_raw, Mapping):
                    raise MigrationError(
                        f"previous state root is not an object: {previous}"
                    )
                previous_payload = migrate_state_document(
                    previous_raw,
                    state_path=previous,
                    migration_id=migration_id,
                ).payload
            atomic_write_bytes(previous, previous_payload)
            atomic_write_bytes(state_path, result.payload)
            installed.append(
                {
                    "path": state_path.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(result.payload).hexdigest(),
                    "revision": int(
                        strict_json_loads(result.payload).get("revision", 0)
                    ),
                }
            )

        second = plan_migration(root, migration_id=migration_id)
        if not second["zero_diff"]:
            raise MigrationError(
                "second migration dry-run was not byte-stable"
            )
        manifest = {
            "migration_id": migration_id,
            "status": "applied",
            "source_schema": 1,
            "target_schema": STATE_SCHEMA_VERSION,
            "backups": backups,
            "absent_paths": absent_paths,
            "installed": installed,
            "plan_totals": plan["totals"],
            "second_dry_run_zero_diff": True,
        }
        atomic_write_json(migration_root / "manifest.json", manifest)
        atomic_write_json(
            ctf_root / "migration.json",
            {
                "migration_id": migration_id,
                "status": "applied",
                "active_schema": STATE_SCHEMA_VERSION,
            },
        )
        return {**second, "status": "applied", "totals": plan["totals"]}
    except BaseException as error:
        if marker_installed:
            rollback_status = "failed"
            try:
                if backups:
                    _restore_backups(
                        root,
                        migration_root,
                        backups,
                        absent_paths,
                    )
                    _validate_restored_v1_states(root)
                    rollback_status = "failed_rolled_back"
                atomic_write_json(
                    migration_root / "manifest.json",
                    {
                        "migration_id": migration_id,
                        "status": rollback_status,
                        "source_schema": 1,
                        "target_schema": STATE_SCHEMA_VERSION,
                        "backups": backups,
                        "absent_paths": absent_paths,
                        "installed": installed,
                        "plan_totals": (
                            plan["totals"] if plan is not None else {}
                        ),
                    },
                )
                atomic_write_json(
                    ctf_root / "migration.json",
                    {
                        "migration_id": migration_id,
                        "status": rollback_status,
                        "active_schema": 1,
                    },
                )
            except BaseException as rollback_error:
                error.add_note(
                    "automatic migration rollback failed: "
                    f"{type(rollback_error).__name__}: {rollback_error}"
                )
        raise
    finally:
        for held in reversed(held_locks):
            held.release()
        lock.release()


def rollback_migration(
    workspace_root: Path,
    *,
    migration_id: str = "state-v2",
) -> dict[str, Any]:
    root = workspace_root.expanduser().resolve()
    ctf_root = root / ".ctfos"
    migration_root = ctf_root / "migrations" / migration_id
    migration_lock = FileLock(
        ctf_root / "runtime" / "migration.lock",
        timeout=0,
    )
    held_locks: list[FileLock] = []
    marker_installed = False
    restore_started = False
    try:
        try:
            migration_lock.acquire()
        except LockTimeout as error:
            raise MigrationError("another migration is active") from error

        manifest = read_json(migration_root / "manifest.json")
        if not isinstance(manifest, Mapping):
            raise MigrationError("migration rollback manifest is corrupt")
        if manifest.get("status") == "rolled_back":
            atomic_write_json(
                ctf_root / "migration.json",
                {
                    "migration_id": migration_id,
                    "status": "rolled_back",
                    "active_schema": 1,
                },
            )
            return {"status": "already_rolled_back", "restored_files": 0}
        if manifest.get("status") != "applied":
            raise MigrationError("migration has no applied rollback manifest")

        installed = manifest.get("installed", [])
        if not isinstance(installed, list) or not all(
            isinstance(item, Mapping) for item in installed
        ):
            raise MigrationError("migration installed manifest is corrupt")
        backups = manifest.get("backups", [])
        if not isinstance(backups, list) or not all(
            isinstance(item, Mapping) for item in backups
        ):
            raise MigrationError("migration backup manifest is corrupt")
        absent_paths = manifest.get("absent_paths", [])
        if not isinstance(absent_paths, list) or not all(
            isinstance(item, str) for item in absent_paths
        ):
            raise MigrationError("migration absent-path manifest is corrupt")

        backup_hashes: dict[str, str] = {}
        for record in backups:
            relative = _manifest_relative(record.get("path"))
            backup = migration_root / "backup" / relative
            payload = backup.read_bytes()
            digest = hashlib.sha256(payload).hexdigest()
            if (
                digest != record.get("sha256")
                or len(payload) != record.get("size")
            ):
                raise MigrationError(
                    f"migration backup hash mismatch: {relative}"
                )
            backup_hashes[relative.as_posix()] = digest

        try:
            marker = read_json(ctf_root / "migration.json")
        except FileNotFoundError:
            marker = {}
        resuming = (
            isinstance(marker, Mapping)
            and marker.get("status") == "migrating"
            and marker.get("operation") == "rollback"
            and marker.get("migration_id") == migration_id
        )

        state_paths: list[Path] = []
        for record in installed:
            relative = _manifest_relative(record.get("path"))
            path = root / relative
            state_paths.append(path)
            current_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            allowed = {str(record.get("sha256"))}
            if resuming:
                backup_hash = backup_hashes.get(relative.as_posix())
                if backup_hash is not None:
                    allowed.add(backup_hash)
            if current_hash not in allowed:
                raise MigrationError(
                    "v2 operational commit detected; downgrade is forbidden"
                )
            raw = strict_json_loads(path.read_bytes())
            if (
                isinstance(raw, Mapping)
                and raw.get("active_managed_session_id") is not None
            ):
                raise MigrationError(
                    "an active managed session blocks rollback"
                )

        atomic_write_json(
            ctf_root / "migration.json",
            {
                "migration_id": migration_id,
                "status": "migrating",
                "operation": "rollback",
                "active_schema": STATE_SCHEMA_VERSION,
            },
        )
        marker_installed = True

        contest_roots = sorted(
            (
                path
                for path in (ctf_root / "contests").glob("*")
                if path.is_dir() and not path.is_symlink()
            ),
            key=lambda path: path.as_posix(),
        )
        lock_paths = [
            *[
                contest_root / "runtime" / "submissions.lock"
                for contest_root in contest_roots
            ],
            *[
                state_path.parent / "runtime" / "session.lock"
                for state_path in state_paths
            ],
            *[state_path.parent / ".lock" for state_path in state_paths],
            *[
                contest_root / "runtime" / "board.lock"
                for contest_root in contest_roots
            ],
        ]
        for lock_path in lock_paths:
            held = FileLock(lock_path, timeout=0)
            try:
                held.acquire()
            except LockTimeout as error:
                raise MigrationError(
                    f"active workspace owner blocks rollback: {lock_path}"
                ) from error
            held_locks.append(held)

        # Recheck after all ordinary writers have drained.  A resume may find
        # either the installed v2 bytes or the exact v1 backup at each path.
        for record in installed:
            relative = _manifest_relative(record.get("path"))
            current_hash = hashlib.sha256(
                (root / relative).read_bytes()
            ).hexdigest()
            allowed = {
                str(record.get("sha256")),
                backup_hashes.get(relative.as_posix(), ""),
            }
            if current_hash not in allowed:
                raise MigrationError(
                    "v2 operational commit detected; downgrade is forbidden"
                )

        restore_started = True
        restored = _restore_backups(
            root,
            migration_root,
            list(backups),
            list(absent_paths),
        )
        _validate_restored_v1_states(root)
        rolled_back_manifest = {
            **dict(manifest),
            "status": "rolled_back",
            "restored_files": restored,
        }
        atomic_write_json(
            migration_root / "manifest.json",
            rolled_back_manifest,
        )
        atomic_write_json(
            ctf_root / "migration.json",
            {
                "migration_id": migration_id,
                "status": "rolled_back",
                "active_schema": 1,
            },
        )
        return {"status": "rolled_back", "restored_files": restored}
    except BaseException:
        if marker_installed and not restore_started:
            atomic_write_json(
                ctf_root / "migration.json",
                {
                    "migration_id": migration_id,
                    "status": "applied",
                    "active_schema": STATE_SCHEMA_VERSION,
                },
            )
        # Once exact v1 bytes may have been installed, retain the migrating
        # marker.  A repeated rollback is then the only mutation allowed.
        raise
    finally:
        for held in reversed(held_locks):
            held.release()
        migration_lock.release()


__all__ = [
    "MigrationError",
    "StateMigrationResult",
    "apply_migration",
    "migrate_state_document",
    "plan_migration",
    "rollback_migration",
]
