"""Managed one-challenge orchestration.

This module owns the durable Captain -> fixed three-role wave -> deterministic
action -> checkpoint lifecycle.  It deliberately has no contest scheduler and
never falls back to assisted solving after a managed failure.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

from ctf_os.capabilities import (
    CapabilityError,
    inspect_pinned_capabilities,
)
from ctf_os.codex import Role
from ctf_os.codex.contracts import MANAGED_PWN_CRASH_ACTION_KIND
from ctf_os.contracts.managed_rejection_v1 import (
    MANAGED_REJECTION_V1_MAX_ATTEMPT,
    MANAGED_REJECTION_V1_MAX_ISSUES,
    MANAGED_REJECTION_V1_MAX_OMITTED,
    ManagedRejectionV1ContractError,
    build_managed_rejection_v1,
    validate_managed_rejection_v1_mapping,
)
from ctf_os.contracts.pwn_crash_v1 import (
    PWN_CRASH_V1_CONTRACT_FINGERPRINT,
    PWN_CRASH_V1_CONTRACT_ID,
    PWN_CRASH_V1_CONTRACT_VERSION,
    PWN_CRASH_V1_MAX_INPUT_BYTES,
    PWN_CRASH_V1_PROTOCOL,
)
from ctf_os.engine.challenge import (
    WAVE_ROLES,
    ChallengeEngine,
    EngineError,
    SessionAlreadyRunning,
)
from ctf_os.engine.failure_capsule import (
    bounded_pwn_crash_failure_reason,
    build_failure_capsule,
    selected_pwn_crash_failure_reason,
)
from ctf_os.models import (
    ACTIVE_HYPOTHESIS_STATUSES,
    BudgetMode,
    ChallengeIdentity,
    ChallengeState,
    ChallengeStatus,
    Checkpoint,
    distinct_complete_active_hypotheses,
    Experiment,
    ExperimentKind,
    ExperimentStatus,
    FactKind,
    ManagedCycle,
    ManagedWave,
    RunOrigin,
    RunReference,
    RunStatus,
    SessionMode,
    SessionStatus,
    SolveSession,
    TargetStatus,
    WaveKind,
    utc_now,
)
from ctf_os.schema import RUN_ENVELOPE_SCHEMA_VERSION, STATE_SCHEMA_VERSION
from ctf_os.store import ChallengeLock, LockTimeout
from ctf_os.store.atomic import atomic_write_json, read_json
from ctf_os.workspace_publish import (
    WorkspacePublishProposalRejected,
    canonical_workspace_hash,
    publish_builder_file,
    reconcile_workspace_publishes,
)


CapabilityProbe = Callable[[str], Mapping[str, Any]]
_STOP_STATUSES = frozenset(
    {
        ChallengeStatus.PAUSED,
        ChallengeStatus.NEEDS_HUMAN,
        ChallengeStatus.READY_TO_SUBMIT,
        ChallengeStatus.SOLVED,
        ChallengeStatus.ABANDONED,
        ChallengeStatus.STALLED,
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
_PWN_CRASH_ENGINE_COMMAND = "ctfos-engine:pwn-crash-v1"
_PWN_CRASH_ENGINE_EXECUTOR = "pwn_crash_differential_v1"
_MAX_MANAGED_REJECTED_ACTIONS = 64


class ManagedError(EngineError):
    """Managed execution failed without changing to another solve mode."""


class ManagedPreflightBlocked(ManagedError):
    def __init__(self, issues: Sequence[str]) -> None:
        self.issues = tuple(issues)
        super().__init__("managed preflight blocked: " + "; ".join(self.issues))


@dataclass(frozen=True, slots=True)
class PreflightReport:
    ok: bool
    identity: str
    state_revision: int
    configuration_epoch: int
    checks: Mapping[str, Any]
    issues: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "identity": self.identity,
            "state_revision": self.state_revision,
            "configuration_epoch": self.configuration_epoch,
            "checks": dict(self.checks),
            "issues": list(self.issues),
        }


@dataclass(frozen=True, slots=True)
class BuilderPublishRejection:
    run_id: str
    proposal_ordinal: int
    code: str


@dataclass(frozen=True, slots=True)
class BuilderPublishOutcome:
    published_count: int
    rejection: BuilderPublishRejection | None = None


def _managed_rejection_issue_sort_key(
    issue: Mapping[str, object],
) -> tuple[object, ...]:
    kind = issue.get("kind")
    if kind == "role_output":
        return (0, issue.get("pointer"), issue.get("code"))
    if kind == "reported_artifact":
        return (1, issue.get("pointer"), issue.get("code"))
    return (
        2,
        issue.get("proposal_ordinal"),
        issue.get("code"),
    )


def _merge_builder_publish_rejection(
    existing: object,
    *,
    attempt: int,
    proposal_ordinal: int,
    code: str,
) -> dict[str, object]:
    publication = build_managed_rejection_v1(
        role=Role.BUILDER.value,
        attempt=attempt,
        artifact_publication_rejections=(
            {
                "code": code,
                "kind": "artifact_publication",
                "proposal_ordinal": proposal_ordinal,
            },
        ),
    )
    if existing is None:
        return publication
    current = validate_managed_rejection_v1_mapping(existing)
    if current["role"] != Role.BUILDER.value:
        raise ManagedRejectionV1ContractError(
            "Builder rejection role does not match its run"
        )
    new_issue = publication["issues"][0]
    assert isinstance(new_issue, dict)
    current_issues = current["issues"]
    assert isinstance(current_issues, list)
    combined = [
        issue
        for issue in current_issues
        if not (
            isinstance(issue, Mapping)
            and issue.get("kind") == "artifact_publication"
            and issue.get("proposal_ordinal") == proposal_ordinal
        )
    ]
    combined.append(new_issue)
    unique: dict[tuple[object, ...], dict[str, object]] = {}
    for issue in combined:
        assert isinstance(issue, dict)
        unique.setdefault(
            _managed_rejection_issue_sort_key(issue),
            dict(issue),
        )
    ordered = sorted(
        unique.values(),
        key=_managed_rejection_issue_sort_key,
    )
    selected = ordered[:MANAGED_REJECTION_V1_MAX_ISSUES]
    new_identity = _managed_rejection_issue_sort_key(new_issue)
    if (
        len(ordered) > MANAGED_REJECTION_V1_MAX_ISSUES
        and all(
            _managed_rejection_issue_sort_key(issue) != new_identity
            for issue in selected
        )
    ):
        selected = sorted(
            [
                *selected[: MANAGED_REJECTION_V1_MAX_ISSUES - 1],
                new_issue,
            ],
            key=_managed_rejection_issue_sort_key,
        )
    merged = {
        "attempt": max(int(current["attempt"]), attempt),
        "authority": publication["authority"],
        "issues": selected,
        "omitted_count": min(
            MANAGED_REJECTION_V1_MAX_OMITTED,
            int(current["omitted_count"])
            + max(0, len(ordered) - len(selected)),
        ),
        "role": Role.BUILDER.value,
        "schema_version": publication["schema_version"],
    }
    return validate_managed_rejection_v1_mapping(merged)


def _stable_id(prefix: str, *parts: object) -> str:
    payload = "\0".join(str(part) for part in parts)
    return f"{prefix}-{uuid.uuid5(uuid.NAMESPACE_URL, payload).hex[:24]}"


def _bounded_checkpoint_note(*parts: str | None) -> str:
    text = "\n".join(
        item.strip()
        for item in parts
        if item is not None and item.strip()
    )
    encoded = text.encode("utf-8")
    if len(encoded) <= 4096:
        return text
    suffix = "…".encode("utf-8")
    return (
        encoded[: 4096 - len(suffix)].decode("utf-8", errors="ignore")
        + suffix.decode("utf-8")
    )


def _safe_managed_artifact_locator(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    raw_parts = value.split("/")
    path = PurePosixPath(value)
    if (
        not value
        or value == "."
        or "\x00" in value
        or "\\" in value
        or len(value.encode("utf-8")) > 4096
        or path.is_absolute()
        or ".." in path.parts
        or any(
            part in {"", ".", ".."}
            or len(part.encode("utf-8")) > 255
            for part in raw_parts
        )
    ):
        return None
    return value


class ManagedOrchestrator:
    """Serial durable managed orchestrator for exactly one selected challenge."""

    def __init__(
        self,
        engine: ChallengeEngine,
        *,
        capability_probe: CapabilityProbe = inspect_pinned_capabilities,
    ) -> None:
        self.engine = engine
        self.capability_probe = capability_probe

    def preflight(
        self,
        identity: ChallengeIdentity,
        *,
        session_id: str | None = None,
        probe_image: bool = True,
    ) -> PreflightReport:
        state = self.engine.store.load(identity)
        issues: list[str] = []
        checks: dict[str, Any] = {}

        checks["state_schema"] = state.schema_version
        if state.schema_version != STATE_SCHEMA_VERSION:
            issues.append(
                "managed mode requires state schema v2; run migrate first"
            )
        checks["status"] = state.status.value
        if state.status in _STOP_STATUSES:
            issues.append(
                f"challenge status {state.status.value} blocks managed work"
            )
        checks["prompt_present"] = bool(state.prompt.strip())
        if not state.prompt.strip():
            issues.append("problem-solving prompt is required")

        checks["budget_mode"] = state.budget.mode.value
        if state.budget.mode is BudgetMode.LEGACY_UNARMED:
            issues.append(
                "legacy_unarmed budget requires an explicit bounded or "
                "operator-unbounded choice"
            )
        if (
            state.budget.mode is BudgetMode.OPERATOR_UNBOUNDED
            and not (state.budget.unbounded_reason or "").strip()
        ):
            issues.append("operator-unbounded budget requires a reason")
        try:
            self.engine._remaining_budget_seconds(state)
            checks["budget_available"] = True
        except EngineError as error:
            checks["budget_available"] = False
            issues.append(str(error))

        active = state.active_managed_session_id
        checks["active_managed_session_id"] = active
        if active is not None and session_id not in {None, active}:
            issues.append(
                f"managed session {active} is already active for this challenge"
            )

        remote_experiments = [
            item
            for item in state.experiments
            if (
                item.status is ExperimentStatus.REGISTERED
                and (
                    item.extra.get("network_target") is not None
                    or (
                        item.kind is ExperimentKind.PROOF
                        and item.proof_recipe is not None
                        and item.proof_recipe.network_endpoint is not None
                    )
                )
            )
        ]
        remote_pending = bool(remote_experiments)
        checks["remote_action_pending"] = remote_pending
        if remote_pending:
            primary = next(
                (
                    item
                    for item in state.targets
                    if item.id == state.primary_target_id
                ),
                None,
            )
            if primary is None:
                issues.append(
                    "managed remote work requires an explicitly selected target"
                )
            elif (
                primary.status is not TargetStatus.ACTIVE
                or self.engine._target_is_expired(primary)
            ):
                issues.append(
                    "selected target is revoked, expired, or inactive"
                )
            elif primary.enforcement != "proxy":
                issues.append(
                    "managed remote work requires a destination-enforcing "
                    "proxy target"
                )
            else:
                for experiment in remote_experiments:
                    if (
                        experiment.kind is ExperimentKind.PROOF
                        and experiment.proof_recipe is not None
                    ):
                        recipe = experiment.proof_recipe
                        target_id = recipe.network_target_id
                        target_generation = (
                            recipe.network_target_generation
                        )
                        configuration_epoch = (
                            recipe.configuration_epoch
                        )
                        endpoint = recipe.network_endpoint
                    else:
                        target_id = experiment.extra.get(
                            "network_target_id"
                        )
                        target_generation = experiment.extra.get(
                            "network_target_generation"
                        )
                        configuration_epoch = experiment.extra.get(
                            "configuration_epoch"
                        )
                        endpoint = experiment.extra.get(
                            "network_target"
                        )
                    if (
                        target_id != primary.id
                        or target_generation != primary.generation
                        or configuration_epoch != state.configuration_epoch
                        or endpoint != primary.endpoint
                    ):
                        issues.append(
                            f"remote experiment {experiment.id} has a stale "
                            "target/generation/configuration pin"
                        )

        digest = self.engine.config.runtime.image_digest
        checks["image_digest"] = digest
        if digest is None:
            issues.append("managed mode requires a pinned runtime.image_digest")
        elif probe_image:
            try:
                capability = dict(self.capability_probe(digest))
            except (CapabilityError, EngineError, OSError, ValueError) as error:
                capability = {"ok": False, "error": str(error)}
            checks["capabilities"] = capability
            if capability.get("ok") is not True:
                missing = capability.get("missing")
                suffix = (
                    ": " + ", ".join(str(item) for item in missing)
                    if isinstance(missing, list) and missing
                    else ""
                )
                issues.append("pinned image lacks managed capabilities" + suffix)

        return PreflightReport(
            ok=not issues,
            identity=identity.key,
            state_revision=state.revision,
            configuration_epoch=state.configuration_epoch,
            checks=checks,
            issues=tuple(issues),
        )

    def require_preflight(
        self,
        identity: ChallengeIdentity,
        *,
        session_id: str | None = None,
        probe_image: bool = True,
    ) -> PreflightReport:
        report = self.preflight(
            identity,
            session_id=session_id,
            probe_image=probe_image,
        )
        if not report.ok:
            raise ManagedPreflightBlocked(report.issues)
        return report

    @staticmethod
    def _session(state: ChallengeState, session_id: str) -> SolveSession:
        session = next(
            (item for item in state.sessions if item.id == session_id),
            None,
        )
        if session is None:
            raise ManagedError(f"unknown managed session: {session_id}")
        return session

    def _reserve_session(
        self,
        identity: ChallengeIdentity,
        session_id: str | None,
    ) -> tuple[ChallengeState, str]:
        current = self.engine.store.load(identity)
        selected = (
            session_id
            or current.active_managed_session_id
            or f"S-{uuid.uuid4().hex}"
        )

        def apply(state: ChallengeState) -> None:
            if state.configuration_epoch != current.configuration_epoch:
                raise ManagedError("configuration changed during session reserve")
            if state.active_managed_session_id not in {None, selected}:
                raise ManagedError(
                    "another managed session is active for this challenge"
                )
            session = next(
                (item for item in state.sessions if item.id == selected),
                None,
            )
            if session is None:
                session = SolveSession(
                    id=selected,
                    mode=SessionMode.MANAGED,
                    status=SessionStatus.RUNNING,
                    configuration_epoch=state.configuration_epoch,
                    start_revision=state.revision,
                    budget_snapshot=state.budget.to_dict(v2=True),
                    evaluation_policy="observe",
                    started_at=utc_now(),
                )
                state.sessions.append(session)
            elif (
                session.mode is not SessionMode.MANAGED
                or session.status not in {
                    SessionStatus.CREATED,
                    SessionStatus.RUNNING,
                }
            ):
                raise ManagedError(
                    f"session {selected} cannot be resumed from "
                    f"{session.status.value}"
                )
            elif session.configuration_epoch != state.configuration_epoch:
                raise ManagedError(
                    "session configuration epoch is stale; start a new session"
                )
            session.status = SessionStatus.RUNNING
            session.started_at = session.started_at or utc_now()
            state.active_managed_session_id = selected

        return (
            self.engine.store.update(
                identity,
                apply,
                expected_revision=current.revision,
            ),
            selected,
        )

    def _require_epoch(
        self,
        state: ChallengeState,
        session_id: str,
    ) -> SolveSession:
        session = self._session(state, session_id)
        if state.active_managed_session_id != session_id:
            raise ManagedError("managed session is no longer active")
        if session.configuration_epoch != state.configuration_epoch:
            raise ManagedError(
                "configuration epoch changed during managed execution"
            )
        return session

    def _reserve_cycle(
        self,
        identity: ChallengeIdentity,
        session_id: str,
    ) -> tuple[ChallengeState, ManagedCycle]:
        current = self.engine.store.load(identity)
        self._require_epoch(current, session_id)
        ordinal = 1 + max(
            (
                item.ordinal
                for item in current.cycles
                if item.session_id == session_id
            ),
            default=0,
        )
        cycle_id = _stable_id("MC", identity.key, session_id, ordinal)
        run_id = _stable_id(
            "MR",
            identity.key,
            session_id,
            cycle_id,
            "captain",
            current.configuration_epoch,
        )

        def apply(state: ChallengeState) -> None:
            session = self._require_epoch(state, session_id)
            if any(item.id == cycle_id for item in state.cycles):
                raise ManagedError(f"managed cycle already exists: {cycle_id}")
            anticipated_revision = state.revision + 1
            cycle = ManagedCycle(
                id=cycle_id,
                session_id=session_id,
                ordinal=ordinal,
                phase="captain_reserved",
                configuration_epoch=state.configuration_epoch,
                captain_run_id=run_id,
            )
            state.cycles.append(cycle)
            state.runs.append(
                RunReference(
                    id=run_id,
                    base_revision=anticipated_revision,
                    status=RunStatus.CREATED,
                    role=Role.CAPTAIN.value,
                    model=self.engine._model_for_role(Role.CAPTAIN),
                    origin=RunOrigin.MANAGED_MODEL,
                    idempotency_key=(
                        f"managed:{identity.key}:{session_id}:{ordinal}:"
                        f"captain:{state.configuration_epoch}"
                    ),
                    session_id=session_id,
                    cycle_id=cycle_id,
                    configuration_epoch=state.configuration_epoch,
                )
            )
            session.run_ids.append(run_id)

        committed = self.engine.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        )
        return committed, next(
            item for item in committed.cycles if item.id == cycle_id
        )

    def _rebase_created_run(
        self,
        identity: ChallengeIdentity,
        session_id: str,
        run_id: str,
    ) -> ChallengeState:
        """Move an undispatched reservation to the latest durable snapshot."""

        current = self.engine.store.load(identity)

        def apply(state: ChallengeState) -> None:
            self._require_epoch(state, session_id)
            run = next(
                (item for item in state.runs if item.id == run_id),
                None,
            )
            if run is None or run.status is not RunStatus.CREATED:
                raise ManagedError(
                    f"managed run is not an undispatched reservation: {run_id}"
                )
            run.base_revision = state.revision + 1

        return self.engine.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        )

    def _reserve_wave(
        self,
        identity: ChallengeIdentity,
        session_id: str,
        cycle_id: str,
        wave_name: str,
    ) -> tuple[ChallengeState, ManagedWave, dict[Role, str]]:
        roles = WAVE_ROLES[wave_name]
        kind = WaveKind(wave_name)
        current = self.engine.store.load(identity)
        self._require_epoch(current, session_id)
        wave_id = _stable_id(
            "MW",
            identity.key,
            session_id,
            cycle_id,
            wave_name,
            current.configuration_epoch,
        )
        role_runs = {
            role: _stable_id(
                "MR",
                identity.key,
                session_id,
                cycle_id,
                wave_id,
                role.value,
                current.configuration_epoch,
            )
            for role in roles
        }

        def apply(state: ChallengeState) -> None:
            session = self._require_epoch(state, session_id)
            cycle = next(
                (item for item in state.cycles if item.id == cycle_id),
                None,
            )
            if cycle is None:
                raise ManagedError(f"unknown managed cycle: {cycle_id}")
            if cycle.wave_id is not None:
                raise ManagedError(
                    f"cycle {cycle_id} already has wave {cycle.wave_id}"
                )
            anticipated_revision = state.revision + 1
            wave = ManagedWave(
                id=wave_id,
                session_id=session_id,
                cycle_id=cycle_id,
                kind=kind,
                role_run_ids={
                    role.value: role_runs[role] for role in roles
                },
                snapshot_revision=anticipated_revision,
                configuration_epoch=state.configuration_epoch,
                status="created",
            )
            state.waves.append(wave)
            cycle.wave_id = wave_id
            cycle.phase = "wave_reserved"
            session.wave_ids.append(wave_id)
            for role in roles:
                run_id = role_runs[role]
                state.runs.append(
                    RunReference(
                        id=run_id,
                        base_revision=anticipated_revision,
                        status=RunStatus.CREATED,
                        role=role.value,
                        model=self.engine._model_for_role(role),
                        origin=RunOrigin.MANAGED_MODEL,
                        idempotency_key=(
                            f"managed:{identity.key}:{session_id}:"
                            f"{cycle_id}:{wave_name}:{role.value}:"
                            f"{state.configuration_epoch}"
                        ),
                        session_id=session_id,
                        cycle_id=cycle_id,
                        wave_id=wave_id,
                        configuration_epoch=state.configuration_epoch,
                    )
                )
                session.run_ids.append(run_id)

        committed = self.engine.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        )
        return (
            committed,
            next(item for item in committed.waves if item.id == wave_id),
            role_runs,
        )

    @staticmethod
    def _wave_name(captain_output: Mapping[str, object] | None) -> str:
        decision = (
            captain_output.get("decision")
            if isinstance(captain_output, Mapping)
            else None
        )
        next_stage = (
            str(decision.get("next_stage"))
            if isinstance(decision, Mapping)
            else "discover"
        )
        wave = {
            "discover": "discovery",
            "attack": "attack",
            "proof": "proof",
        }.get(next_stage)
        if wave is None:
            raise ManagedError(
                f"Captain did not select a runnable stage: {next_stage}"
            )
        return wave

    @staticmethod
    def _frontier_routing_issue(
        state: ChallengeState,
        captain_output: Mapping[str, object] | None,
    ) -> str | None:
        decision = (
            captain_output.get("decision")
            if isinstance(captain_output, Mapping)
            else None
        )
        next_stage = (
            str(decision.get("next_stage"))
            if isinstance(decision, Mapping)
            else None
        )
        if next_stage not in {"attack", "proof"}:
            return None
        complete = distinct_complete_active_hypotheses(
            state.hypotheses
        )
        if len(complete) >= 3:
            return None
        return (
            f"Captain selected {next_stage} with only {len(complete)} "
            "distinct complete active hypotheses; at least 3 are required "
            "with evidence, non-empty unknowns, experiment, "
            "success_oracle, and falsifier"
        )

    @staticmethod
    def _select_actions(
        state: ChallengeState,
        wave: ManagedWave,
    ) -> tuple[str, ...]:
        cycle = next(
            (
                item
                for item in state.cycles
                if item.id == wave.cycle_id
            ),
            None,
        )
        role_order = {
            run_id: index + 1
            for index, run_id in enumerate(wave.role_run_ids.values())
        }
        if cycle is not None:
            role_order[cycle.captain_run_id] = 0
        candidates = [
            item
            for item in state.experiments
            if item.status is ExperimentStatus.REGISTERED
            and item.source_run_id in role_order
        ]
        if wave.kind is WaveKind.PROOF:
            reproducer_run_id = wave.role_run_ids.get("reproducer")
            proof_recipes = [
                item
                for item in candidates
                if item.kind is ExperimentKind.PROOF
                and item.proof_recipe is not None
                and item.source_run_id == reproducer_run_id
            ]
            proof_recipes.sort(key=lambda item: item.id)
            if len(proof_recipes) != 1 or len(candidates) != 1:
                raise ManagedError(
                    "proof wave must produce exactly one registered proof "
                    "recipe and no other actions; observed "
                    f"{len(proof_recipes)} recipe(s) and "
                    f"{len(candidates)} total action(s)"
                )
            return (proof_recipes[0].id,)
        open_hypotheses = {
            item.id
            for item in state.hypotheses
            if item.status in ACTIVE_HYPOTHESIS_STATUSES
        }
        strategic = [
            item
            for item in candidates
            if item.kind is ExperimentKind.STRATEGIC
            and item.hypothesis_ids
            and set(item.hypothesis_ids) <= open_hypotheses
            and item.expected_observation.strip()
            and item.keep_if.strip()
            and item.drop_if.strip()
        ]
        if strategic:
            strategic.sort(
                key=lambda item: (
                    -len(set(item.hypothesis_ids) & open_hypotheses),
                    item.timeout_seconds,
                    role_order.get(item.source_run_id or "", 999),
                    item.id,
                )
            )
        probes = [
            item
            for item in candidates
            if item.kind is ExperimentKind.PROBE
            and not item.hypothesis_ids
        ]
        probes.sort(
            key=lambda item: (
                role_order.get(item.source_run_id or "", 999),
                item.id,
            )
        )
        selected: list[str] = []
        approaches: set[tuple[str, str]] = set()
        for item in (*strategic, *probes):
            approach = (item.source_run_id or "", item.command)
            if approach in approaches:
                continue
            selected.append(item.id)
            approaches.add(approach)
            if len(selected) == 3:
                break
        return tuple(selected)

    @staticmethod
    def _initial_cartography_actions(
        state: ChallengeState,
        *,
        maximum: int = 3,
    ) -> tuple[str, ...]:
        return tuple(
            item.id
            for item in state.experiments
            if item.status is ExperimentStatus.REGISTERED
            and item.extra.get("adapter_seed") is True
        )[:maximum]

    def _mark_action_selection(
        self,
        identity: ChallengeIdentity,
        session_id: str,
        cycle_id: str,
        selected: Sequence[str],
        *,
        append: bool = False,
    ) -> ChallengeState:
        current = self.engine.store.load(identity)

        def apply(state: ChallengeState) -> None:
            self._require_epoch(state, session_id)
            cycle = next(item for item in state.cycles if item.id == cycle_id)
            cycle.selected_action_ids = (
                list(
                    dict.fromkeys(
                        (*cycle.selected_action_ids, *selected)
                    )
                )
                if append
                else list(selected)
            )
            cycle.phase = (
                "action_selected"
                if cycle.selected_action_ids
                else "no_action_selected"
            )

        return self.engine.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        )

    def _apply_builder_publishes(
        self,
        identity: ChallengeIdentity,
        wave: ManagedWave,
        results: Sequence[Any],
    ) -> BuilderPublishOutcome:
        """Promote only explicit Builder ``write_artifact`` proposals."""

        proposals: list[tuple[str, str, int, int]] = []
        for result in results:
            if result.invocation.role is not Role.BUILDER:
                continue
            output = result.output
            actions = (
                output.get("actions")
                if isinstance(output, Mapping)
                else None
            )
            if not isinstance(actions, list):
                continue
            proposal_ordinal = 0
            for action in actions:
                if (
                    isinstance(action, Mapping)
                    and action.get("kind") == "write_artifact"
                    and isinstance(action.get("artifact_path"), str)
                ):
                    proposal_ordinal += 1
                    proposals.append(
                        (
                            result.invocation.run_id,
                            action["artifact_path"],
                            proposal_ordinal,
                            max(
                                1,
                                min(
                                    MANAGED_REJECTION_V1_MAX_ATTEMPT,
                                    len(result.attempts),
                                ),
                            ),
                        )
                    )
        if len(proposals) > 8:
            raise ManagedError("Builder proposed too many workspace publishes")
        published_count = 0
        for run_id, relative, proposal_ordinal, attempt in proposals:
            state = self.engine.store.load(identity)
            try:
                publish_builder_file(
                    self.engine,
                    identity,
                    run_id=run_id,
                    staged_path=relative,
                    destination=relative,
                    base_workspace_revision=state.workspace_revision,
                    base_sha256=canonical_workspace_hash(
                        self.engine,
                        identity,
                        relative,
                    ),
                )
            except WorkspacePublishProposalRejected as error:
                rejection = BuilderPublishRejection(
                    run_id=run_id,
                    proposal_ordinal=proposal_ordinal,
                    code=error.code,
                )
                current = self.engine.store.load(identity)

                def record_rejection(latest: ChallengeState) -> None:
                    self._require_epoch(latest, wave.session_id)
                    canonical_wave = next(
                        (
                            item
                            for item in latest.waves
                            if item.id == wave.id
                        ),
                        None,
                    )
                    if (
                        canonical_wave is None
                        or canonical_wave.cycle_id != wave.cycle_id
                        or canonical_wave.role_run_ids
                        != wave.role_run_ids
                        or run_id
                        != canonical_wave.role_run_ids.get(
                            Role.BUILDER.value
                        )
                    ):
                        raise ManagedError(
                            "Builder publication rejection lost its "
                            "canonical wave binding"
                        )
                    builder_run = next(
                        (
                            run
                            for run in latest.runs
                            if run.id == run_id
                        ),
                        None,
                    )
                    if (
                        builder_run is None
                        or builder_run.role != Role.BUILDER.value
                        or builder_run.status is not RunStatus.COMPLETED
                        or builder_run.origin
                        is not RunOrigin.MANAGED_MODEL
                    ):
                        raise ManagedError(
                            "Builder publication rejection lost its "
                            "canonical run binding"
                        )
                    try:
                        builder_run.extra["managed_rejection_v1"] = (
                            _merge_builder_publish_rejection(
                                builder_run.extra.get(
                                    "managed_rejection_v1"
                                ),
                                attempt=attempt,
                                proposal_ordinal=proposal_ordinal,
                                code=error.code,
                            )
                        )
                    except ManagedRejectionV1ContractError as contract_error:
                        raise ManagedError(
                            "Builder publication rejection could not be "
                            "represented safely"
                        ) from contract_error
                    cycle = next(
                        (
                            item
                            for item in latest.cycles
                            if item.id == canonical_wave.cycle_id
                        ),
                        None,
                    )
                    if cycle is None:
                        raise ManagedError(
                            "Builder publication rejection lost its cycle"
                        )
                    cycle.selected_action_ids = []
                    wave_run_ids = set(
                        canonical_wave.role_run_ids.values()
                    )
                    for experiment in latest.experiments:
                        if (
                            experiment.source_run_id in wave_run_ids
                            and experiment.status
                            is ExperimentStatus.REGISTERED
                        ):
                            experiment.status = ExperimentStatus.CANCELLED
                            experiment.extra["cancelled_at"] = utc_now()
                            experiment.extra["cancelled_reason"] = (
                                "builder_publish_rejected"
                            )

                self.engine.store.update(
                    identity,
                    record_rejection,
                    expected_revision=current.revision,
                )
                return BuilderPublishOutcome(
                    published_count=published_count,
                    rejection=rejection,
                )
            published_count += 1
        return BuilderPublishOutcome(published_count=published_count)

    def _register_pwn_crash_actions(
        self,
        identity: ChallengeIdentity,
        wave: ManagedWave,
        results: Sequence[Any],
    ) -> ChallengeState:
        """Turn one v2 Builder request into an engine-owned crash proposal."""

        proposals: list[tuple[Any, int, Mapping[str, Any]]] = []
        for result in results:
            output = result.output
            actions = (
                output.get("actions")
                if isinstance(output, Mapping)
                else None
            )
            if not isinstance(actions, list):
                continue
            for index, action in enumerate(actions, start=1):
                if (
                    isinstance(action, Mapping)
                    and action.get("kind")
                    == MANAGED_PWN_CRASH_ACTION_KIND
                ):
                    proposals.append((result, index, action))
        if not proposals:
            return self.engine.store.load(identity)

        current = self.engine.store.load(identity)

        def apply(state: ChallengeState) -> None:
            self._require_epoch(state, wave.session_id)
            canonical_wave = next(
                (item for item in state.waves if item.id == wave.id),
                None,
            )
            if canonical_wave is None:
                raise ManagedError(
                    f"unknown managed wave for Pwn crash action: {wave.id}"
                )

            for result, index, action in proposals:
                invocation = result.invocation
                run = next(
                    (
                        item
                        for item in state.runs
                        if item.id == invocation.run_id
                    ),
                    None,
                )
                if run is None:
                    raise ManagedError(
                        "Pwn crash action references an unknown managed run: "
                        f"{invocation.run_id}"
                    )

                def reject(reason: str) -> None:
                    bucket = run.extra.setdefault("rejected_actions", [])
                    if isinstance(bucket, list):
                        entry = {
                            "action": str(index),
                            "reason": reason[:1024],
                        }
                        if len(bucket) > _MAX_MANAGED_REJECTED_ACTIONS:
                            del bucket[_MAX_MANAGED_REJECTED_ACTIONS:]
                        if (
                            entry not in bucket
                            and len(bucket) < _MAX_MANAGED_REJECTED_ACTIONS
                        ):
                            bucket.append(entry)

                if state.category.strip().casefold() != "pwn":
                    reject("verify_pwn_crash is restricted to category pwn")
                    continue
                if canonical_wave.kind is not WaveKind.ATTACK:
                    reject(
                        "verify_pwn_crash is restricted to an ATTACK wave"
                    )
                    continue
                if (
                    invocation.role is not Role.BUILDER
                    or canonical_wave.role_run_ids.get("builder")
                    != invocation.run_id
                    or run.role != Role.BUILDER.value
                ):
                    reject(
                        "verify_pwn_crash is restricted to the reserved "
                        "ATTACK Builder"
                    )
                    continue
                if invocation.contract_version != 2:
                    reject("verify_pwn_crash requires the v2 role contract")
                    continue
                if (
                    run.origin is not RunOrigin.MANAGED_MODEL
                    or run.wave_id != canonical_wave.id
                    or run.session_id != canonical_wave.session_id
                    or run.cycle_id != canonical_wave.cycle_id
                    or run.configuration_epoch != state.configuration_epoch
                    or run.status is not RunStatus.COMPLETED
                    or run.extra.get("semantic_merge") is not True
                ):
                    reject(
                        "verify_pwn_crash requires the current semantically "
                        "merged Builder result"
                    )
                    continue

                payload_locator = _safe_managed_artifact_locator(
                    action.get("payload_artifact_path")
                )
                if payload_locator is None:
                    reject(
                        "verify_pwn_crash payload locator is not a safe "
                        "relative path"
                    )
                    continue
                payload_matches = [
                    artifact
                    for artifact in state.artifacts
                    if artifact.source_run_id == invocation.run_id
                    and artifact.extra.get("reported_locator")
                    == payload_locator
                ]
                if len(payload_matches) != 1:
                    reject(
                        "verify_pwn_crash payload locator must resolve to "
                        "exactly one normalized artifact from the current "
                        f"Builder result; observed {len(payload_matches)}"
                    )
                    continue
                payload = payload_matches[0]
                if (
                    type(payload.size) is not int
                    or payload.size <= 0
                    or payload.size > PWN_CRASH_V1_MAX_INPUT_BYTES
                ):
                    reject(
                        "verify_pwn_crash payload artifact must be non-empty "
                        f"and at most {PWN_CRASH_V1_MAX_INPUT_BYTES} bytes"
                    )
                    continue

                requested_hypothesis = action.get("hypothesis_id")
                if not isinstance(requested_hypothesis, str):
                    reject(
                        "verify_pwn_crash hypothesis_id must be a string"
                    )
                    continue
                local_hypothesis_ids = {
                    str(item.get("id"))
                    for item in (
                        result.output.get("hypotheses", [])
                        if isinstance(result.output, Mapping)
                        else []
                    )
                    if isinstance(item, Mapping)
                    and isinstance(item.get("id"), str)
                }
                hypothesis_matches = {
                    hypothesis.id
                    for hypothesis in state.hypotheses
                    if (
                        hypothesis.status in ACTIVE_HYPOTHESIS_STATUSES
                        and (
                            hypothesis.id == requested_hypothesis
                            or (
                                requested_hypothesis
                                in local_hypothesis_ids
                                and hypothesis.id
                                == (
                                    f"H-{invocation.run_id}-"
                                    f"{requested_hypothesis}"
                                )
                                and hypothesis.source_run_id
                                == invocation.run_id
                            )
                        )
                    )
                }
                if len(hypothesis_matches) != 1:
                    reject(
                        "verify_pwn_crash hypothesis_id must resolve to "
                        "exactly one active local or canonical hypothesis"
                    )
                    continue
                hypothesis_id = next(iter(hypothesis_matches))

                experiment_id = _stable_id(
                    "E",
                    identity.key,
                    canonical_wave.id,
                    invocation.run_id,
                    index,
                )
                existing = next(
                    (
                        item
                        for item in state.experiments
                        if item.id == experiment_id
                    ),
                    None,
                )
                request = {
                    "schema_version": 1,
                    "contract_id": PWN_CRASH_V1_CONTRACT_ID,
                    "contract_version": PWN_CRASH_V1_CONTRACT_VERSION,
                    "contract_fingerprint": (
                        PWN_CRASH_V1_CONTRACT_FINGERPRINT
                    ),
                    "protocol": PWN_CRASH_V1_PROTOCOL,
                    "configuration_epoch": state.configuration_epoch,
                    "payload_artifact_id": payload.id,
                    "payload_reported_locator": payload_locator,
                    "payload_sha256": payload.sha256,
                    "payload_size_bytes": payload.size,
                    "hypothesis_id": hypothesis_id,
                    "source_builder_run_id": invocation.run_id,
                }
                if existing is not None:
                    if (
                        existing.command != _PWN_CRASH_ENGINE_COMMAND
                        or existing.hypothesis_ids != [hypothesis_id]
                        or existing.artifact_ids != [payload.id]
                        or existing.extra.get("pwn_crash_request")
                        != request
                    ):
                        raise ManagedError(
                            "Pwn crash action idempotency collision: "
                            f"{experiment_id}"
                        )
                    continue
                state.experiments.append(
                    Experiment(
                        id=experiment_id,
                        hypothesis_ids=[hypothesis_id],
                        command=_PWN_CRASH_ENGINE_COMMAND,
                        expected_observation=(
                            "the same allowlisted target fault signal occurs "
                            "in at least two of three exact-input runs while "
                            "all three empty-input controls exit normally"
                        ),
                        keep_if=(
                            "the engine-owned v1 differential evaluator "
                            "returns CONFIRMED"
                        ),
                        drop_if=(
                            "the v1 contract fails closed or the differential "
                            "positive/control condition is not satisfied"
                        ),
                        timeout_seconds=self.engine._budget_command_timeout(
                            state,
                            60,
                        ),
                        resource_class="standard",
                        kind=ExperimentKind.STRATEGIC,
                        status=ExperimentStatus.REGISTERED,
                        source_run_id=invocation.run_id,
                        artifact_ids=[payload.id],
                        extra={
                            "managed_contract_version": 2,
                            "managed_action_kind": (
                                MANAGED_PWN_CRASH_ACTION_KIND
                            ),
                            "engine_executor": (
                                _PWN_CRASH_ENGINE_EXECUTOR
                            ),
                            "configuration_epoch": (
                                state.configuration_epoch
                            ),
                            "pwn_crash_request": request,
                        },
                    )
                )

        return self.engine.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        )

    def _checkpoint(
        self,
        identity: ChallengeIdentity,
        session_id: str,
        cycle_id: str,
        *,
        note: str | None,
        failure_reason_code: str | None = None,
        failure_stage: str | None = None,
    ) -> ChallengeState:
        current = self.engine.store.load(identity)
        session = self._require_epoch(current, session_id)
        cycle = next(item for item in current.cycles if item.id == cycle_id)
        if (failure_reason_code is None) != (failure_stage is None):
            raise ManagedError(
                "failure checkpoint requires both reason_code and stage"
            )
        failure_capsule = (
            build_failure_capsule(
                current,
                session_id=session_id,
                cycle_id=cycle_id,
                reason_code=failure_reason_code,
                stage=failure_stage,
                state_revision_after=current.revision + 1,
            )
            if failure_reason_code is not None
            and failure_stage is not None
            else None
        )
        if (
            failure_capsule is not None
            and failure_capsule.state_revision_after
            != current.revision + 1
        ):
            raise ManagedError(
                "failure capsule does not bind the pending checkpoint "
                "revision"
            )
        checkpoint_id = _stable_id(
            "CP", identity.key, session_id, cycle_id
        )
        selected = set(cycle.selected_action_ids)
        selected_experiments = [
            item for item in current.experiments if item.id in selected
        ]
        receipt_ids = [
            item.id
            for item in current.receipts
            if item.experiment_id in selected
        ]
        cycle_run_ids = {
            item.id
            for item in current.runs
            if item.session_id == session_id
            and item.cycle_id == cycle_id
        }
        observation_ids = [
            item.id
            for item in current.facts
            if item.kind is FactKind.OBSERVATION
            and item.source_run_id in cycle_run_ids
        ]
        artifact_ids = list(
            dict.fromkeys(
                artifact_id
                for item in selected_experiments
                for artifact_id in item.artifact_ids
            )
        )
        next_actions = [
            item.command
            for item in current.experiments
            if item.status is ExperimentStatus.REGISTERED
        ][:10]
        do_not_repeat = [
            item.command
            for item in selected_experiments
            if item.status
            in {
                ExperimentStatus.COMPLETED,
                ExperimentStatus.AWAITING_EVALUATION,
                ExperimentStatus.FAILED,
            }
        ]
        checkpoint = Checkpoint(
            id=checkpoint_id,
            session_id=session_id,
            cycle_id=cycle_id,
            active_goal_id=current.active_goal_id,
            open_hypothesis_ids=[
                item.id
                for item in current.hypotheses
                if item.status in ACTIVE_HYPOTHESIS_STATUSES
            ],
            observation_fact_ids=observation_ids,
            next_actions=next_actions,
            do_not_repeat=do_not_repeat,
            artifact_ids=artifact_ids,
            receipt_ids=receipt_ids,
            note=note,
            failure_capsule=failure_capsule,
        )

        def apply(state: ChallengeState) -> None:
            active_session = self._require_epoch(state, session_id)
            target_cycle = next(
                item for item in state.cycles if item.id == cycle_id
            )
            if not any(item.id == checkpoint_id for item in state.checkpoints):
                state.checkpoints.append(checkpoint)
            target_cycle.checkpoint_id = checkpoint_id
            target_cycle.phase = "completed"
            target_cycle.completed_at = utc_now()
            if target_cycle.wave_id is not None:
                wave = next(
                    item
                    for item in state.waves
                    if item.id == target_cycle.wave_id
                )
                statuses = {
                    run.status
                    for run in state.runs
                    if run.id in wave.role_run_ids.values()
                }
                wave.status = (
                    "completed"
                    if statuses == {RunStatus.COMPLETED}
                    else "invalid"
                )
                wave.reduced_at = utc_now()
            for run in state.runs:
                if (
                    run.session_id == session_id
                    and run.id not in active_session.run_ids
                ):
                    active_session.run_ids.append(run.id)

        return self.engine.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        )

    def _execute_selected_actions(
        self,
        identity: ChallengeIdentity,
        selected: Sequence[str],
    ) -> ChallengeState:
        """Run different role lanes concurrently while serializing each role."""

        if not selected:
            return self.engine.store.load(identity)
        state = self.engine.store.load(identity)
        experiments = {
            item.id: item
            for item in state.experiments
            if item.id in set(selected)
        }
        if set(experiments) != set(selected):
            missing = sorted(set(selected) - set(experiments))
            raise ManagedError(
                "selected managed experiments disappeared: "
                + ", ".join(missing)
            )
        proof_experiments = [
            item
            for item in experiments.values()
            if item.kind is ExperimentKind.PROOF
        ]
        if proof_experiments:
            if (
                len(selected) != 1
                or len(proof_experiments) != 1
                or proof_experiments[0].proof_recipe is None
            ):
                raise ManagedError(
                    "managed proof dispatch requires exactly one typed recipe"
                )
            self.engine.execute_proof_experiment(
                identity,
                proof_experiments[0].id,
                _session_owned=True,
            )
            return self.engine.store.load(identity)
        run_roles = {item.id: item.role for item in state.runs}
        lanes: dict[str, list[str]] = {}
        for experiment_id in selected:
            experiment = experiments[experiment_id]
            role = run_roles.get(
                experiment.source_run_id or "",
                experiment.source_run_id
                or (
                    f"adapter:{experiment.id}"
                    if experiment.extra.get("adapter_seed") is True
                    else "unknown"
                ),
            )
            lanes.setdefault(str(role), []).append(experiment_id)

        def execute_lane(experiment_ids: Sequence[str]) -> None:
            for experiment_id in experiment_ids:
                self.engine.execute_registered_experiments(
                    identity,
                    maximum=1,
                    experiment_ids=(experiment_id,),
                    _session_owned=True,
                    _automated=True,
                )

        if len(lanes) == 1:
            execute_lane(next(iter(lanes.values())))
            return self.engine.store.load(identity)

        errors: list[BaseException] = []
        with ThreadPoolExecutor(
            max_workers=len(lanes),
            thread_name_prefix="ctfos-managed-tool",
        ) as executor:
            futures = [
                executor.submit(execute_lane, tuple(experiment_ids))
                for experiment_ids in lanes.values()
            ]
            for future in futures:
                try:
                    future.result()
                except BaseException as error:
                    errors.append(error)
        if errors:
            primary = errors[0]
            for additional in errors[1:]:
                primary.add_note(
                    "additional managed tool lane failed: "
                    f"{type(additional).__name__}: {additional}"
                )
            raise primary
        return self.engine.store.load(identity)

    @staticmethod
    def _bounded_pwn_crash_failure_reason(
        verdict: str,
        reason_code: str,
    ) -> str:
        """Project one typed gate verdict into a capsule-safe identifier."""

        return bounded_pwn_crash_failure_reason(verdict, reason_code)

    @classmethod
    def _selected_pwn_crash_failure_reason(
        cls,
        state: ChallengeState,
        selected: Sequence[str],
    ) -> str | None:
        """Return a deterministic capsule reason for selected non-pass gates."""

        return selected_pwn_crash_failure_reason(state, selected)

    def _checkpoint_selected_actions(
        self,
        identity: ChallengeIdentity,
        session_id: str,
        cycle_id: str,
        wave: ManagedWave,
        selected: Sequence[str],
        *,
        note: str | None,
    ) -> ChallengeState:
        """Checkpoint selected results, making typed Pwn non-passes durable."""

        latest = self.engine.store.load(identity)
        failure_reason = self._selected_pwn_crash_failure_reason(
            latest,
            selected,
        )
        return self._checkpoint(
            identity,
            session_id,
            cycle_id,
            note=note,
            failure_reason_code=failure_reason,
            failure_stage=(
                wave.kind.value if failure_reason is not None else None
            ),
        )

    def _finish_session(
        self,
        identity: ChallengeIdentity,
        session_id: str,
        *,
        status: SessionStatus,
        reason: str,
        challenge_target: ChallengeStatus | None = None,
    ) -> ChallengeState:
        current = self.engine.store.load(identity)

        def apply(state: ChallengeState) -> None:
            session = self._session(state, session_id)
            if session.status in {
                SessionStatus.COMPLETED,
                SessionStatus.PAUSED,
                SessionStatus.FAILED,
                SessionStatus.INTERRUPTED,
            }:
                return
            session.status = status
            session.stop_reason = reason
            session.end_revision = state.revision + 1
            session.ended_at = utc_now()
            if state.active_managed_session_id == session_id:
                state.active_managed_session_id = None
            if challenge_target is ChallengeStatus.PAUSED:
                if state.status is not ChallengeStatus.PAUSED:
                    state.resume_status = state.status
                    state.status = ChallengeStatus.PAUSED
            elif challenge_target is not None:
                state.status = challenge_target
                state.resume_status = None

        return self.engine.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        )

    def cancel_session(
        self,
        identity: ChallengeIdentity,
        *,
        reason: str,
        target: ChallengeStatus,
    ) -> ChallengeState:
        if not reason.strip():
            raise ManagedError("session cancel reason is required")
        if target not in {
            ChallengeStatus.PAUSED,
            ChallengeStatus.NEEDS_HUMAN,
        }:
            raise ManagedError("session cancel target must be PAUSED or NEEDS_HUMAN")
        state = self.engine.store.load(identity)
        if state.active_managed_session_id is None:
            raise ManagedError("there is no active managed session")
        return self._finish_session(
            identity,
            state.active_managed_session_id,
            status=SessionStatus.PAUSED,
            reason=reason,
            challenge_target=target,
        )

    def reconcile(self, identity: ChallengeIdentity) -> ChallengeState:
        """Terminalize orphan managed runs conservatively as interrupted."""

        state = self.engine.store.load(identity)
        orphaned = [
            run
            for run in state.runs
            if run.origin is RunOrigin.MANAGED_MODEL
            and run.status not in _TERMINAL_RUN_STATUSES
        ]
        root = self.engine.store.challenge_paths(identity).root
        terminal_paths: dict[
            str,
            tuple[str, str, str, RunStatus, bool],
        ] = {}
        for run in orphaned:
            paths = self.engine.store.run_paths(identity, run_id=run.id)
            if not paths.root.exists():
                paths.root.mkdir(parents=True, mode=0o700)
            paths.raw.mkdir(mode=0o700, exist_ok=True)
            if not paths.request.exists():
                atomic_write_json(
                    paths.request,
                    {
                        "schema_version": RUN_ENVELOPE_SCHEMA_VERSION,
                        **identity.to_dict(),
                        "run_id": run.id,
                        "base_revision": run.base_revision,
                        "kind": "managed-recovery",
                        "role": run.role,
                        "configuration_epoch": run.configuration_epoch,
                        "created_at": run.created_at,
                    },
                )
            recovered_status = RunStatus.INTERRUPTED
            recovered_from_result = False
            if paths.result.exists() and paths.validation.exists():
                try:
                    result_record = read_json(paths.result)
                    validation_record = read_json(paths.validation)
                    if (
                        isinstance(result_record, Mapping)
                        and isinstance(validation_record, Mapping)
                        and result_record.get("run_id") == run.id
                        and validation_record.get("run_id") == run.id
                    ):
                        terminal = result_record.get("managed_terminal")
                        status_value = (
                            terminal.get("status")
                            if isinstance(terminal, Mapping)
                            else result_record.get("status")
                            if result_record.get(
                                "provisional_managed_result"
                            )
                            is True
                            else None
                        )
                        candidate_status = RunStatus(str(status_value))
                        if candidate_status in _TERMINAL_RUN_STATUSES:
                            recovered_status = candidate_status
                            recovered_from_result = True
                        if (
                            recovered_status is RunStatus.COMPLETED
                            and validation_record.get("ok") is not True
                        ):
                            recovered_status = RunStatus.INVALID
                except (OSError, TypeError, ValueError):
                    recovered_status = RunStatus.INTERRUPTED
            if not paths.result.exists():
                self.engine.store.write_run_result(
                    identity,
                    run.id,
                    {
                        "status": "interrupted",
                        "base_revision": run.base_revision,
                        "artifacts": [],
                        "flag_candidates": [],
                        "recovery": "provider completion is unknown",
                    },
                )
            if not paths.validation.exists():
                self.engine.store.write_run_validation(
                    identity,
                    run.id,
                    {
                        "ok": False,
                        "base_revision": run.base_revision,
                        "errors": ["run interrupted before canonical commit"],
                        "error_type": "ManagedRecovery",
                    },
                )
            terminal_paths[run.id] = (
                str(paths.request.relative_to(root)),
                str(paths.result.relative_to(root)),
                str(paths.validation.relative_to(root)),
                recovered_status,
                recovered_from_result,
            )

        if terminal_paths:
            current = self.engine.store.load(identity)

            def apply(recovered: ChallengeState) -> None:
                for run in recovered.runs:
                    paths = terminal_paths.get(run.id)
                    if paths is None or run.status in _TERMINAL_RUN_STATUSES:
                        continue
                    (
                        request_path,
                        result_path,
                        validation_path,
                        recovered_status,
                        recovered_from_result,
                    ) = paths
                    stale = (
                        run.configuration_epoch
                        != recovered.configuration_epoch
                        or run.session_id
                        != recovered.active_managed_session_id
                        or recovered.status in _STOP_STATUSES
                    )
                    run.status = (
                        RunStatus.INTERRUPTED
                        if stale
                        else recovered_status
                    )
                    run.request_path = request_path
                    run.result_path = result_path
                    run.validation_path = validation_path
                    run.extra["reconciled_at"] = utc_now()
                    run.extra["semantic_merge"] = False
                    run.extra["provisional_managed_terminal"] = True
                    run.extra["recovered_from_durable_result"] = (
                        recovered_from_result
                    )

            state = self.engine.store.update(
                identity,
                apply,
                expected_revision=current.revision,
            )

        unfinished_cycle_ids = {
            cycle.id
            for cycle in state.cycles
            if cycle.completed_at is None
        }
        active_session_id = state.active_managed_session_id
        if (
            active_session_id is not None
            and state.status
            in {
                ChallengeStatus.READY_TO_SUBMIT,
                ChallengeStatus.SOLVED,
                ChallengeStatus.ABANDONED,
            }
            and not any(
                cycle.session_id == active_session_id
                and cycle.completed_at is None
                for cycle in state.cycles
            )
        ):
            return self._finish_session(
                identity,
                active_session_id,
                status=SessionStatus.COMPLETED,
                reason=(
                    "managed recovery finalized a terminal challenge after "
                    "its durable checkpoint"
                ),
            )
        if not unfinished_cycle_ids:
            return state
        current = self.engine.store.load(identity)

        def interrupt_unfinished(recovered: ChallengeState) -> None:
            affected_sessions: set[str] = set()
            for cycle in recovered.cycles:
                if (
                    cycle.id not in unfinished_cycle_ids
                    or cycle.completed_at is not None
                ):
                    continue
                cycle.phase = "interrupted"
                cycle.completed_at = utc_now()
                affected_sessions.add(cycle.session_id)
                if cycle.wave_id is not None:
                    wave = next(
                        (
                            item
                            for item in recovered.waves
                            if item.id == cycle.wave_id
                        ),
                        None,
                    )
                    if wave is not None and wave.reduced_at is None:
                        wave.status = "interrupted"
                        wave.reduced_at = utc_now()
            for session in recovered.sessions:
                if (
                    session.id in affected_sessions
                    and session.status
                    in {SessionStatus.CREATED, SessionStatus.RUNNING}
                ):
                    session.status = SessionStatus.INTERRUPTED
                    session.stop_reason = (
                        "managed recovery found an unfinished durable cycle"
                    )
                    session.end_revision = recovered.revision + 1
                    session.ended_at = utc_now()
            if recovered.active_managed_session_id in affected_sessions:
                recovered.active_managed_session_id = None
                if recovered.status not in {
                    ChallengeStatus.READY_TO_SUBMIT,
                    ChallengeStatus.SOLVED,
                    ChallengeStatus.ABANDONED,
                }:
                    if recovered.status is not ChallengeStatus.PAUSED:
                        recovered.resume_status = recovered.status
                    recovered.status = ChallengeStatus.PAUSED

        return self.engine.store.update(
            identity,
            interrupt_unfinished,
            expected_revision=current.revision,
        )

    def _checkpoint_invalid_cycle(
        self,
        identity: ChallengeIdentity,
        session_id: str,
        cycle_id: str,
        *,
        reason_code: str,
        reason: str,
        note: str | None,
    ) -> ChallengeState:
        """Preserve a failed model attempt and let the next cycle repair it."""

        checkpoint_note = _bounded_checkpoint_note(
            f"{reason_code}: {reason}",
            note,
        )
        self._mark_action_selection(
            identity,
            session_id,
            cycle_id,
            (),
        )
        current = self.engine.store.load(identity)
        cycle = next(
            item for item in current.cycles if item.id == cycle_id
        )
        if cycle.wave_id is None:
            stage = "captain"
        else:
            wave = next(
                item
                for item in current.waves
                if item.id == cycle.wave_id
            )
            stage = wave.kind.value
        state = self._checkpoint(
            identity,
            session_id,
            cycle_id,
            note=checkpoint_note,
            failure_reason_code=reason_code,
            failure_stage=stage,
        )
        if state.status in _STOP_STATUSES:
            target = (
                state.status
                if state.status
                in {
                    ChallengeStatus.PAUSED,
                    ChallengeStatus.NEEDS_HUMAN,
                }
                else None
            )
            return self._finish_session(
                identity,
                session_id,
                status=SessionStatus.PAUSED,
                reason=reason,
                challenge_target=target,
            )
        return state

    def _run_cycle_owned(
        self,
        identity: ChallengeIdentity,
        *,
        session_id: str | None,
        note: str | None,
    ) -> ChallengeState:
        self.engine._recover_session_boundary(identity)
        reconcile_workspace_publishes(self.engine, identity)
        self.reconcile(identity)
        self.require_preflight(identity, session_id=session_id)
        state, selected_session = self._reserve_session(identity, session_id)
        try:
            state, cycle = self._reserve_cycle(
                identity,
                selected_session,
            )
            cartography_actions = self._initial_cartography_actions(state)
            if cartography_actions:
                self._mark_action_selection(
                    identity,
                    selected_session,
                    cycle.id,
                    cartography_actions,
                )
                self.require_preflight(
                    identity,
                    session_id=selected_session,
                )
                self._execute_selected_actions(
                    identity,
                    cartography_actions,
                )
                self._rebase_created_run(
                    identity,
                    selected_session,
                    cycle.captain_run_id,
                )
            self.require_preflight(
                identity,
                session_id=selected_session,
            )
            captain = self.engine.run_role(
                identity,
                Role.CAPTAIN,
                prefix=f"managed-{cycle.ordinal}-captain",
                instruction=(
                    "Select exactly one next stage and maintain one active "
                    "goal. Register only discriminating actions. A candidate "
                    "is not proof."
                ),
                _session_owned=True,
                _automated=True,
                _reserved_run_id=cycle.captain_run_id,
                _managed_workspace=True,
            )
            if not captain.completed or not captain.validation.valid:
                return self._checkpoint_invalid_cycle(
                    identity,
                    selected_session,
                    cycle.id,
                    reason_code="captain_contract_invalid",
                    reason="Captain result was not contract-valid",
                    note=note,
                )
            latest = self.engine.store.load(identity)
            self._require_epoch(latest, selected_session)
            if latest.status in _STOP_STATUSES:
                target = (
                    latest.status
                    if latest.status
                    in {
                        ChallengeStatus.PAUSED,
                        ChallengeStatus.NEEDS_HUMAN,
                    }
                    else None
                )
                return self._finish_session(
                    identity,
                    selected_session,
                    status=SessionStatus.PAUSED,
                    reason=f"Captain selected {latest.status.value}",
                    challenge_target=target,
                )
            frontier_issue = self._frontier_routing_issue(
                latest,
                captain.output,
            )
            if frontier_issue is not None:
                return self._checkpoint_invalid_cycle(
                    identity,
                    selected_session,
                    cycle.id,
                    reason_code="frontier_routing_invalid",
                    reason=frontier_issue,
                    note=note,
                )
            wave_name = self._wave_name(captain.output)
            _state, wave, role_runs = self._reserve_wave(
                identity,
                selected_session,
                cycle.id,
                wave_name,
            )
            self.require_preflight(
                identity,
                session_id=selected_session,
            )
            outcome = self.engine.run_wave(
                identity,
                wave_name,
                _session_owned=True,
                _automated=True,
                _reserved_run_ids=role_runs,
                _semantic_barrier=True,
                _managed_workspace=True,
            )
            latest = self.engine.store.load(identity)
            self._require_epoch(latest, selected_session)
            run_statuses = {
                run.id: run.status
                for run in latest.runs
                if run.id in wave.role_run_ids.values()
            }
            if (
                len(run_statuses) != 3
                or any(
                    status is not RunStatus.COMPLETED
                    for status in run_statuses.values()
                )
            ):
                return self._checkpoint_invalid_cycle(
                    identity,
                    selected_session,
                    cycle.id,
                    reason_code="analysis_wave_invalid",
                    reason=(
                        "analysis wave was invalid; provisional results were "
                        "preserved"
                    ),
                    note=note,
                )
            publish_outcome = self._apply_builder_publishes(
                identity,
                wave,
                outcome.results,
            )
            if publish_outcome.rejection is not None:
                return self._checkpoint_invalid_cycle(
                    identity,
                    selected_session,
                    cycle.id,
                    reason_code="builder_publish_rejected",
                    reason=(
                        "Builder artifact publication proposal was rejected"
                    ),
                    note=note,
                )
            self._register_pwn_crash_actions(
                identity,
                wave,
                outcome.results,
            )
            latest = self.engine.store.load(identity)
            self._require_epoch(latest, selected_session)
            try:
                selected = self._select_actions(latest, wave)
            except ManagedError:
                return self._checkpoint_invalid_cycle(
                    identity,
                    selected_session,
                    cycle.id,
                    reason_code="proof_recipe_invalid",
                    reason=(
                        "proof wave did not produce exactly one valid "
                        "engine-bound replay recipe"
                    ),
                    note=note,
                )
            self._mark_action_selection(
                identity,
                selected_session,
                cycle.id,
                selected,
                append=True,
            )
            if selected:
                self.require_preflight(
                    identity,
                    session_id=selected_session,
                )
                try:
                    self._execute_selected_actions(identity, selected)
                except EngineError:
                    if wave.kind is not WaveKind.PROOF:
                        raise
                    return self._checkpoint_invalid_cycle(
                        identity,
                        selected_session,
                        cycle.id,
                        reason_code="managed_proof_execution_invalid",
                        reason=(
                            "managed proof recipe was stale, unsupported, "
                            "or did not complete its replay"
                        ),
                        note=note,
                    )
            state = self._checkpoint_selected_actions(
                identity,
                selected_session,
                cycle.id,
                wave,
                selected,
                note=note,
            )
            if state.status in {
                ChallengeStatus.READY_TO_SUBMIT,
                ChallengeStatus.SOLVED,
                ChallengeStatus.ABANDONED,
            }:
                return self._finish_session(
                    identity,
                    selected_session,
                    status=SessionStatus.COMPLETED,
                    reason=f"challenge reached {state.status.value}",
                )
            return state
        except KeyboardInterrupt:
            self._finish_session(
                identity,
                selected_session,
                status=SessionStatus.INTERRUPTED,
                reason="operator interrupt",
                challenge_target=ChallengeStatus.PAUSED,
            )
            raise
        except BaseException as error:
            try:
                self._finish_session(
                    identity,
                    selected_session,
                    status=SessionStatus.FAILED,
                    reason=f"{type(error).__name__}: {error}",
                    challenge_target=ChallengeStatus.NEEDS_HUMAN,
                )
                self.reconcile(identity)
            except BaseException as finish_error:
                error.add_note(
                    f"managed failure terminalization failed: {finish_error}"
                )
            if isinstance(error, ManagedError):
                raise
            if isinstance(error, Exception):
                raise ManagedError(
                    f"managed cycle failed: {error}"
                ) from error
            raise

    def run_cycle(
        self,
        identity: ChallengeIdentity,
        *,
        session_id: str | None = None,
        note: str | None = None,
    ) -> ChallengeState:
        paths = self.engine.store.challenge_paths(identity)
        lock = ChallengeLock(paths.runtime / "session.lock", timeout=0)
        try:
            lock.acquire()
        except LockTimeout as error:
            raise SessionAlreadyRunning(
                f"another session already owns {identity.key}"
            ) from error
        try:
            self.engine.refresh_ingest(identity)
            return self._run_cycle_owned(
                identity,
                session_id=session_id,
                note=note,
            )
        finally:
            lock.release()

    def run_cycles(
        self,
        identity: ChallengeIdentity,
        *,
        max_cycles: int,
        session_id: str | None = None,
        note: str | None = None,
    ) -> ChallengeState:
        if max_cycles < 1:
            raise ManagedError("max_cycles must be positive")
        paths = self.engine.store.challenge_paths(identity)
        lock = ChallengeLock(paths.runtime / "session.lock", timeout=0)
        try:
            lock.acquire()
        except LockTimeout as error:
            raise SessionAlreadyRunning(
                f"another session already owns {identity.key}"
            ) from error
        selected_session = session_id
        try:
            self.engine.refresh_ingest(identity)
            for _ in range(max_cycles):
                state = self._run_cycle_owned(
                    identity,
                    session_id=selected_session,
                    note=note,
                )
                selected_session = state.active_managed_session_id
                if state.status in _STOP_STATUSES:
                    return state
            state = self.engine.store.load(identity)
            if state.active_managed_session_id is not None:
                state = self._finish_session(
                    identity,
                    state.active_managed_session_id,
                    status=SessionStatus.PAUSED,
                    reason=f"max_cycles={max_cycles} reached",
                    challenge_target=ChallengeStatus.PAUSED,
                )
            return state
        finally:
            lock.release()


__all__ = [
    "ManagedError",
    "ManagedOrchestrator",
    "ManagedPreflightBlocked",
    "PreflightReport",
]
