"""Local-only runtime orchestration with durable leases and streamed evidence."""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, replace
import copy
from datetime import datetime, timezone
import json
from hashlib import sha256
import os
from pathlib import Path
import queue
import re
import secrets
import shutil
import tempfile
import time
from threading import Event as ThreadEvent, Lock
from threading import Thread
from typing import Callable, Iterable
from uuid import uuid4

from .artifact_writer import ArtifactWriter
from .config import AppConfig, ConfigError
from .flag_detector import FlagDetector
from .contest_parser import ContestParseError
from .intake import IntakeChallenge, IntakeError, IntakeService
from .local_state import LocalState, StateTransitionError
from .local_worker_pool import LocalWorkerPool, WorkerHandle
from .local_event_state import LocalEventState
from .model_routing import ModelRouter, ModelRoutingError, ModelSelection
from .models import (
    Attempt, AttemptStatus, Challenge, ChallengeStatus, ContractTask,
    ContractTaskStatus, Event, FlagCandidate, stable_id, utc_now,
)
from .sandbox.broker import BrokerResponse, broker_transport_supported, send_broker_request
from .sandbox.container import SandboxScope, SandboxSpec, build_docker_exec_argv
from .sandbox.docker_cli import DockerCli
from .sandbox.network_policy import parse_remote_endpoints, resolve_remote_endpoints
from .sandbox.pool import DockerSandboxPool
from .solver_engine.codex_cli_backend import CodexCliBackend, CodexExecRequest, CodexExecResult, CodexStreamRecord
from .solver_engine.category_planner import (
    BranchExecutionSpec, CategoryPlanner, ExecutionContract, PlanParseError, SolvePlan, SolvePlanParser,
)
from .solver_engine.context import ChallengeContext, ChallengeContextBuilder
from .solver_engine.knowledge import KnowledgeIndex
from .solver_engine.loop_detector import LoopDetector, ProgressSnapshot
from .solver_engine.mock_backend import MockBackend
from .solver_engine.parser import ActionObservationParser
from .solver_engine.prompt import PromptRenderer, SessionHandoff
from .solver_engine.race_plan import RaceAttempt, RacePlan
from .solver_engine.strategy_reranker import StrategyReranker
from .solver_engine.types import SolverEvent
from .solver_engine.verifier import Verifier
from .solver_engine.immutable_verifier import ParentOwnedVerifier
from .tactical_engine.strategies import CapabilityCheck, StrategyExecutor, default_strategy_registry
from .tactical_engine.profiles import ProblemClassifier
from .tactical_engine.planners import default_planner_registry
from .tactical_engine.rules import LocalSchedulerRuleState, ReplanEngine, RuleParser, RuleValidationError
from .watcher import PathPollingWatcher


MAX_WORKER_RECORDS = 512
MAX_WORKER_STREAM_LINE_CHARS = 8 * 1024
MAX_SUPERVISOR_HINT_CHARS = 1_500
MAX_KNOWLEDGE_PROMPT_CHARS = 700
_MEANINGFUL_PROGRESS_TYPES = frozenset({
    "PLAN", "HYPOTHESIS", "FINDING", "ACTION", "OBSERVATION", "ARTIFACT", "FLAG_CANDIDATE",
})


class PrerequisiteError(RuntimeError):
    """A safe refusal to start a non-mock worker without required local tools."""


class IntakeBlockedError(PrerequisiteError):
    """A transient local manifest/source error that a watcher may recover from."""


@dataclass(frozen=True)
class AttemptExecution:
    output: str
    controller_output: str
    status: str
    synthetic: bool
    token_usage: int = 0
    records: tuple[SolverEvent, ...] = ()
    session_id: str | None = None
    resume_id: str | None = None


@dataclass(frozen=True)
class PlannedAttempt:
    intake: IntakeChallenge
    state: LocalState
    writer: ArtifactWriter
    race_attempt: RaceAttempt
    session_id: str | None = None
    contract_task_id: str | None = None
    is_session_leader: bool = False


@dataclass(frozen=True)
class CandidateSignal:
    task: PlannedAttempt
    attempt: Attempt
    candidate: FlagCandidate
    synthetic: bool
    records: tuple[SolverEvent, ...]


@dataclass(frozen=True)
class SupervisorHintRequest:
    """The small, injectable boundary around one local supervisor review."""

    task: PlannedAttempt
    challenge: Challenge
    attempt: Attempt
    prompt: str
    selection: ModelSelection | None
    timeout_sec: float


@dataclass(frozen=True)
class SupervisorHintResult:
    hint: str | None
    selection: ModelSelection | None
    reason: str = ""


@dataclass
class _SupervisorHandle:
    request: SupervisorHintRequest
    thread: Thread
    result: SupervisorHintResult | None = None
    error: BaseException | None = None
    done: ThreadEvent | None = None


@dataclass(frozen=True)
class RunReport:
    parsed_challenges: int
    started_attempts: int
    solved_challenges: int
    synthetic: bool


@dataclass(frozen=True)
class OperatorActionResult:
    challenge: Challenge
    already_in_target_state: bool = False
    cancelled_attempt_ids: tuple[str, ...] = ()
    released_container_ids: tuple[str, ...] = ()
    reason: str = ""


class LocalApplication:
    """Coordinate one member's own attempts; never a remote worker pool."""

    def __init__(
        self,
        config: AppConfig,
        *,
        docker: DockerCli | None = None,
        codex_backend_factory: Callable[..., CodexCliBackend] | None = None,
        command_exists: Callable[[str], str | None] = shutil.which,
        strict_isolation_probe: Callable[[str], bool] = CodexCliBackend.strict_isolation_supported,
        supervisor_hint_factory: Callable[[SupervisorHintRequest], str | None] | None = None,
        planner_plan_factory: Callable[[ChallengeContext, tuple[str, ...], tuple[str, ...], dict[str, object]], SolvePlan] | None = None,
        parent_verifier: ParentOwnedVerifier | None = None,
        monotonic_clock: Callable[[], float] = time.monotonic,
        _synthetic_namespace: bool = False,
    ) -> None:
        self.config = config
        self.docker = docker or DockerCli(command_timeout_sec=config.sandbox_command_timeout_sec)
        self._codex_backend_factory = codex_backend_factory
        self._command_exists = command_exists
        self._strict_isolation_probe = strict_isolation_probe
        self._supervisor_hint_factory = supervisor_hint_factory
        self._planner_plan_factory = planner_plan_factory
        self._parent_verifier = parent_verifier
        self._monotonic_clock = monotonic_clock
        self._synthetic_namespace = _synthetic_namespace
        self._sandbox_by_attempt: dict[str, DockerSandboxPool] = {}
        self._effective_strategy_by_attempt: dict[str, str] = {}
        self._candidate_signals: queue.SimpleQueue[CandidateSignal] = queue.SimpleQueue()
        self._records_by_attempt: dict[str, deque[SolverEvent]] = {}
        self._loop_by_attempt: dict[str, LoopDetector] = {}
        self._candidate_values: set[tuple[str, str]] = set()
        self._candidate_artifact_retries: set[tuple[str, str]] = set()
        self._registered_artifact_ids: set[str] = set()
        self._stream_lock = Lock()
        self._knowledge_lock = Lock()
        self._status_callback: Callable[[], None] | None = None
        self._active_pool: LocalWorkerPool | None = None
        self._last_supervision_check: dict[str, float] = {}
        self._last_supervisor_review: dict[str, float] = {}
        self._replan_engines: dict[tuple[str, int], ReplanEngine] = {}
        self._rule_created_task_ids: deque[tuple[str, str]] = deque()
        self._scheduled_contract_task_ids: set[str] = set()
        self._owner = f"{config.team_id}:{config.member_name}:{os.getpid()}:{uuid4().hex}"

    # --- intake / coordinator lifecycle ---------------------------------------------

    def parse(self) -> tuple[IntakeChallenge, ...]:
        """Discover exact-manifest owned challenges and queue only this node's work."""
        service = IntakeService(self.config)
        try:
            intake = tuple(
                replace(item, challenge=replace(
                    item.challenge,
                    challenge_key=f"{self.config.team_id}:{item.challenge.challenge_key}",
                ))
                for item in service.collect()
            )
        except (ContestParseError, IntakeError, PermissionError, OSError) as exc:
            raise IntakeBlockedError(f"queue blocked: contest.md intake failed: {exc}") from exc
        for blocked in service.admission_errors:
            state = LocalState.for_config(self.config, contest_name=blocked.manifest.name)
            challenge = state.upsert_challenge(replace(
                blocked.challenge,
                challenge_key=f"{self.config.team_id}:{blocked.challenge.challenge_key}",
            ))
            event = self._event(
                challenge, "INTAKE_BLOCKED", message=blocked.reason,
                payload=blocked.payload,
            )
            if challenge.status in {ChallengeStatus.DISCOVERED, ChallengeStatus.QUEUED}:
                state.transition_challenge_status(challenge.id, ChallengeStatus.INTAKE_BLOCKED, event=event)
            elif challenge.status is ChallengeStatus.INTAKE_BLOCKED:
                state.append_event(event)
        for item in intake:
            state = LocalState.for_config(
                self.config, contest_name=item.manifest.name
            )
            existing = state.get_challenge(item.challenge.id)
            challenge = state.upsert_challenge(item.challenge)
            if existing is None:
                self._emit(state, challenge, "CHALLENGE_SEEN", message="local manifest discovery")
            if challenge.status in {ChallengeStatus.DISCOVERED, ChallengeStatus.INTAKE_BLOCKED}:
                queued_event = self._event(challenge, "QUEUED", message="owned category queued locally")
                challenge = state.transition_challenge_status(challenge.id, ChallengeStatus.QUEUED, event=queued_event)
                self._flush_outbox(state)
        return intake

    def run_once(
        self,
        *,
        mock_worker: bool = False,
        auto_confirm_flags: bool = False,
        on_status: Callable[[], None] | None = None,
    ) -> RunReport:
        """Run a bounded local race under the SQLite coordinator lease."""
        if mock_worker and not self._synthetic_namespace:
            # Mock results are useful fixtures, never production progress.
            # Separate DB/output/sync roots ensure a later real run still sees
            # the challenge as QUEUED and no team event/artifact is polluted.
            synthetic = LocalApplication(
                self._synthetic_config(), docker=self.docker,
                codex_backend_factory=self._codex_backend_factory,
                command_exists=self._command_exists, strict_isolation_probe=self._strict_isolation_probe,
                supervisor_hint_factory=self._supervisor_hint_factory, monotonic_clock=self._monotonic_clock,
                planner_plan_factory=self._planner_plan_factory,
                _synthetic_namespace=True,
            )
            return synthetic.run_once(
                mock_worker=True,
                auto_confirm_flags=auto_confirm_flags,
                on_status=on_status,
            )
        previous_callback = self._status_callback
        self._status_callback = on_status
        coordinator_state = LocalState.for_config(self.config)
        claim = coordinator_state.claim_coordinator(
            contest=self.config.contest_name, owner=self._owner, lease_seconds=self.config.lease_ttl_sec,
        )
        if not claim.granted:
            self._status_callback = previous_callback
            raise PrerequisiteError(f"local run coordinator busy: {claim.reason}")

        active: dict[str, tuple[WorkerHandle, PlannedAttempt]] = {}
        pool = LocalWorkerPool(
            max_workers_total=self.config.max_workers_total,
            max_workers_per_challenge=self.config.max_workers_per_challenge,
        )
        # This reference exists only inside this local process.  It lets a
        # pause requested through the in-process API cancel *only* handles
        # created by this node; it is never a remote control mechanism.
        self._active_pool = pool
        plans: deque[PlannedAttempt] = deque()
        solved: set[str] = set()
        started = 0
        intake: tuple[IntakeChallenge, ...] = ()
        supervisors: dict[str, _SupervisorHandle] = {}
        try:
            # Surface malformed/missing intake before Docker/Codex diagnostics.
            intake = self.parse()
            recovery = coordinator_state.reconcile_stale_attempts(recovery_event_factory=self._recovery_event)
            self._flush_outbox(coordinator_state)
            if recovery.stale_attempt_ids:
                self._emit_operator(
                    coordinator_state,
                    "STALE_RECOVERY",
                    f"recovered stale local attempts: {', '.join(recovery.stale_attempt_ids)}",
                    payload={"attempt_ids": list(recovery.stale_attempt_ids), "requeued": list(recovery.requeued_challenge_ids)},
                )
            if not mock_worker:
                self._assert_non_mock_prerequisites()
                orphaned = self._cleanup_orphan_containers(coordinator_state)
                if orphaned:
                    self._emit_operator(
                        coordinator_state,
                        "ORPHAN_CLEANUP",
                        f"removed stale local sandbox container(s): {', '.join(orphaned)}",
                        payload={"container_ids": orphaned},
                    )

            self._notify_status()
            for item in intake:
                state = LocalState.for_config(
                    self.config, contest_name=item.manifest.name
                )
                challenge = state.get_challenge(item.challenge.id)
                if challenge is None or challenge.status is not ChallengeStatus.QUEUED:
                    continue
                writer = ArtifactWriter(self.config.output_root, item.manifest.name)
                writer.prepare_challenge(challenge)
                plans.extend(self._enqueue_session_generation(
                    item, state, writer, challenge, require_live_leader=not mock_worker,
                ))

            while plans or active or supervisors:
                if not coordinator_state.heartbeat_coordinator(
                    contest=self.config.contest_name, owner=self._owner, lease_seconds=self.config.lease_ttl_sec,
                ):
                    raise PrerequisiteError("lost local coordinator lease; refusing to launch more attempts")
                for handle, task in tuple(active.values()):
                    # A separately invoked local operator can persist PAUSED
                    # while this process owns the handle.  Observe that state
                    # before launching or keeping any more local work.
                    latest = task.state.get_challenge(handle.attempt.challenge_id)
                    if latest is None or latest.status is ChallengeStatus.PAUSED:
                        pool.cancel_challenge(handle.attempt.challenge_id)
                        continue
                    if not task.state.heartbeat_attempt(
                        attempt_id=handle.attempt.id, owner=self._owner,
                        fencing_token=_fence(handle.attempt), lease_seconds=self.config.lease_ttl_sec,
                    ):
                        handle.lease_lost = True
                        handle.cancel()
                made_progress = self._drain_candidate_signals(pool, plans, solved, auto_confirm_flags)
                made_progress = self._drain_rule_spawn_requests(plans, intake) or made_progress
                made_progress = self._monitor_supervision(active, supervisors) or made_progress
                made_progress = self._drain_supervisor_hints(supervisors, pool, plans) or made_progress

                # Look beyond a full challenge: another local challenge can
                # still use a free global lease slot.
                for _ in range(len(plans)):
                    task = plans.popleft()
                    challenge = task.state.get_challenge(task.intake.challenge.id)
                    if challenge is None or challenge.status not in {
                        ChallengeStatus.QUEUED, ChallengeStatus.RUNNING, ChallengeStatus.FLAG_CANDIDATE,
                    }:
                        made_progress = True
                        continue
                    if task.contract_task_id is not None:
                        durable = task.state.get_contract_task(task.contract_task_id)
                        if durable is None or durable.status is not ContractTaskStatus.PENDING:
                            # Another queue copy or scheduler tick already
                            # owns/completed this durable contract. Never
                            # submit the same RaceAttempt to the local pool.
                            made_progress = True
                            continue
                    active_challenges = {handle.attempt.challenge_id for handle, _ in active.values()}
                    other_waiting = any(
                        queued.intake.challenge.id not in active_challenges | {challenge.id}
                        for queued in plans
                    )
                    challenge_admitted = challenge.id in active_challenges or len(active_challenges) < self.config.max_concurrent_challenges
                    fair_slot = not (challenge.id in active_challenges and other_waiting and len(active_challenges) < self.config.max_concurrent_challenges)
                    if (not challenge_admitted or not fair_slot or not pool.can_start(challenge.id)
                            or (not mock_worker and len(self._sandbox_by_attempt) >= self.config.sandbox_max_containers)):
                        plans.append(task)
                        continue
                    handle = self._start_attempt(pool, task, mock_worker=mock_worker)
                    if handle is None:
                        # A second CLI cannot bypass SQLite profile/capacity
                        # claims.  Do not spin indefinitely on that profile.
                        made_progress = True
                        continue
                    active[handle.attempt.id] = (handle, task)
                    if task.contract_task_id is not None:
                        task.state.mark_contract_task_outcome(
                            task.contract_task_id, status=ContractTaskStatus.RUNNING,
                            assigned_attempt_id=handle.attempt.id,
                        )
                    started += 1
                    made_progress = True
                    self._notify_status()

                for attempt_id, (handle, task) in tuple(active.items()):
                    if not handle.done:
                        continue
                    made_progress = True
                    self._finish_attempt(handle, task, pool, plans, solved, auto_confirm_flags=auto_confirm_flags)
                    active.pop(attempt_id, None)
                    self._notify_status()

                made_progress = self._drain_candidate_signals(pool, plans, solved, auto_confirm_flags) or made_progress
                made_progress = self._drain_rule_spawn_requests(plans, intake) or made_progress
                self._replan_exhausted_challenges(plans, active, intake)
                self._flush_outbox(coordinator_state)
                self._notify_status()
                if (plans or active or supervisors) and not made_progress:
                    # This is notification waiting, not a supervisor retry
                    # loop.  Time-based supervisor checks are separately
                    # gated by ``loop_check_sec`` below.
                    pool.wait_for_change(min(0.25, self.config.loop_check_sec))

            self._flush_outbox(coordinator_state)
            return RunReport(len(intake), started, len(solved), mock_worker)
        except BaseException as exc:
            if isinstance(exc, (PrerequisiteError, IntakeBlockedError)):
                self._emit_operator(
                    coordinator_state, "STARTUP_FAILED", str(exc),
                    payload={"error_type": type(exc).__name__, "reason": str(exc)},
                )
            # Cancellation remains local to the handles this run created.  The
            # backend owns its child process group and reaps it in finally.
            for challenge_id in {handle.attempt.challenge_id for handle, _ in active.values()}:
                pool.cancel_challenge(challenge_id)
            pool.wait_all(5)
            for handle, task in active.values():
                try:
                    task.state.finish_attempt(handle.attempt.id, AttemptStatus.STOPPED, cleanup_status="RECOVERY_PENDING",
                                              owner=self._owner, fencing_token=_fence(handle.attempt))
                    challenge = task.state.get_challenge(handle.attempt.challenge_id)
                    if challenge is not None:
                        self._emit(task.state, challenge, "WORKER_STOPPED", attempt=handle.attempt, message="local run interrupted", synthetic=handle.attempt.synthetic,
                                   fenced=False)
                    self._release_attempt(handle.attempt.id, task.state, preserve=False)
                except (KeyError, OSError, RuntimeError, StateTransitionError):
                    pass
            self._flush_outbox(coordinator_state)
            raise
        finally:
            coordinator_state.release_coordinator(contest=self.config.contest_name, owner=self._owner)
            if self._active_pool is pool:
                self._active_pool = None
            self._status_callback = previous_callback

    def run(
        self,
        *,
        once: bool = False,
        mock_worker: bool = False,
        auto_confirm_flags: bool = False,
        stop_event: ThreadEvent | None = None,
        on_status: Callable[[], None] | None = None,
    ) -> RunReport | None:
        if once:
            return self.run_once(mock_worker=mock_worker, auto_confirm_flags=auto_confirm_flags, on_status=on_status)
        # Input and SQLite use separate baselines.  A run writes SQLite itself,
        # so only the state baseline is acknowledged after handling; input
        # files added while a long attempt is running must remain observable.
        contest_root = self.config.incoming_contest_dir()
        workspace_root = contest_root / "workspace"

        def watched_input(path: Path) -> bool:
            try:
                path.relative_to(workspace_root)
            except ValueError:
                return True
            return False

        input_watcher = PathPollingWatcher(
            (self.config.incoming_root,),
            interval_sec=self.config.poll_interval_sec,
            include=watched_input,
        )
        state_watcher = PathPollingWatcher(
            (self.config.state_path(),),
            interval_sec=self.config.poll_interval_sec,
        )
        while stop_event is None or not stop_event.is_set():
            if input_watcher.changed() or state_watcher.changed():
                try:
                    self.run_once(mock_worker=mock_worker, auto_confirm_flags=auto_confirm_flags, on_status=on_status)
                except IntakeBlockedError:
                    # Editors commonly expose a missing/partial manifest for
                    # one poll.  Keep the queue blocked and retry only after a
                    # local manifest/source change instead of killing watch.
                    pass
                finally:
                    state_watcher.acknowledge()
            if not input_watcher.wait(stop_event):
                break
        return None

    def merged_state(self) -> LocalEventState:
        """Return a projection of this node's durable SQLite event history."""
        state = LocalState.for_config(self.config)
        return LocalEventState.from_events(state.list_events())

    def dashboard_config(self, *, mock_worker: bool) -> AppConfig:
        """Return the local-only namespace whose state a run is displaying."""
        return self._synthetic_config() if mock_worker else self.config

    def retry_challenge(self, selector: str) -> Challenge:
        """Explicitly requeue one failed challenge owned by this local node.

        This is an operator action only: it neither claims work nor signals a
        teammate.  The normal coordinator will later acquire a fresh fenced
        attempt lease before any worker can start.
        """
        wanted = selector.strip()
        if not wanted:
            raise ValueError("retry requires a local challenge name, slug, or id")
        state = LocalState.for_config(self.config)
        local = next(
            (
                challenge for challenge in state.list_challenges()
                if wanted in {challenge.id, challenge.name, challenge.slug}
            ),
            None,
        )
        if local is None:
            team_only = next(
                (
                    item for item in self.merged_state().challenges.values()
                    if wanted in {item.key, item.name or ""}
                ),
                None,
            )
            if team_only is not None:
                raise ValueError(f"refusing retry of team-only challenge: {wanted}")
            raise ValueError(f"not a local failed challenge: {wanted}")
        if local.contest != self.config.contest_name:
            raise ValueError(f"refusing retry of foreign contest challenge: {local.name}")
        if local.status is ChallengeStatus.SOLVED:
            raise ValueError(f"refusing retry of SOLVED challenge: {local.name}")
        team = self.merged_state().get(local.id)
        if team is not None and team.status == "SOLVED":
            raise ValueError(f"refusing retry of SOLVED team challenge: {local.name}")
        if local.status is not ChallengeStatus.FAILED:
            raise ValueError(f"not a local failed challenge: {local.name} (status={local.status.value})")
        event = self._event(local, "RETRY_QUEUED", message="operator explicitly requeued failed local challenge")
        queued = state.transition_challenge_status(local.id, ChallengeStatus.QUEUED, event=event)
        self._flush_outbox(state)
        self._notify_status()
        return queued

    def pause_challenge(self, selector: str) -> OperatorActionResult:
        """Pause one locally owned challenge without controlling a teammate.

        The durable PAUSED transition is written before cancellation.  A
        concurrent local runner therefore sees PAUSED on its next heartbeat
        and refuses to launch another attempt.  In-process handles are
        cancelled through their own ``LocalWorkerPool`` only; a separately
        invoked CLI can at most remove Docker containers selected by all exact
        local labels, never discover or signal a remote worker.
        """
        state, challenge = self._operator_local_challenge(selector, action="pause")
        if challenge.status is ChallengeStatus.SOLVED:
            raise ValueError(f"refusing pause of SOLVED challenge: {challenge.name}")
        if challenge.status is ChallengeStatus.PAUSED:
            return OperatorActionResult(challenge, already_in_target_state=True, reason="already paused")

        event = self._event(
            challenge, "PAUSED", message="operator paused locally owned challenge",
            payload={"reason": "manual operator pause"},
        )
        paused = state.transition_challenge_status(challenge.id, ChallengeStatus.PAUSED, event=event)
        self._flush_outbox(state)

        active_attempts = tuple(
            attempt for attempt in state.list_attempts(paused.id)
            if state.get_active_attempt(attempt.id) is not None
        )
        cancelled: tuple[str, ...] = ()
        pool = self._active_pool
        if pool is not None:
            cancelled = pool.cancel_challenge(paused.id)
        locally_owned = set(cancelled)
        released = self._release_externally_paused_sandboxes(state, paused, active_attempts, skip_attempt_ids=locally_owned)
        self._notify_status()
        return OperatorActionResult(
            paused, cancelled_attempt_ids=cancelled, released_container_ids=released,
            reason="manual pause applied locally",
        )

    def resume_challenge(self, selector: str) -> OperatorActionResult:
        """Requeue exactly one manually paused local challenge.

        Resume does not construct a process command or contact peers;
        the next ordinary local watcher/run claim is the only way work starts.
        """
        state, challenge = self._operator_local_challenge(selector, action="resume")
        if challenge.status is ChallengeStatus.SOLVED:
            raise ValueError(f"refusing resume of SOLVED challenge: {challenge.name}")
        if challenge.status is not ChallengeStatus.PAUSED:
            raise ValueError(f"challenge is not PAUSED: {challenge.name} (status={challenge.status.value})")
        event = self._event(
            challenge, "RESUMED", message="operator requeued paused local challenge",
            payload={"status": ChallengeStatus.QUEUED.value},
        )
        queued = state.transition_challenge_status(challenge.id, ChallengeStatus.QUEUED, event=event)
        self._flush_outbox(state)
        self._notify_status()
        return OperatorActionResult(queued, reason="queued for the next local watcher/run")

    def _operator_local_challenge(self, selector: str, *, action: str) -> tuple[LocalState, Challenge]:
        wanted = selector.strip()
        if not wanted:
            raise ValueError(f"{action} requires a local challenge name, slug, or id")
        state = LocalState.for_config(self.config)
        challenge = next(
            (item for item in state.list_challenges() if wanted in {item.id, item.name, item.slug}),
            None,
        )
        if challenge is None:
            team_only = next(
                (item for item in self.merged_state().challenges.values() if wanted in {item.key, item.name or ""}),
                None,
            )
            if team_only is not None:
                raise ValueError(f"refusing {action} of team-only challenge: {wanted}")
            raise ValueError(f"not a local challenge: {wanted}")
        if challenge.contest != self.config.contest_name:
            raise ValueError(f"refusing {action} of foreign contest challenge: {challenge.name}")
        if challenge.category.casefold() not in self.config.owned_categories:
            raise ValueError(f"refusing {action} of non-owned local challenge: {challenge.name}")
        team = self.merged_state().get(challenge.id)
        if team is not None and team.status == "SOLVED":
            raise ValueError(f"refusing {action} of SOLVED team challenge: {challenge.name}")
        return state, challenge

    def _release_externally_paused_sandboxes(
        self,
        state: LocalState,
        challenge: Challenge,
        attempts: Iterable[Attempt],
        *,
        skip_attempt_ids: set[str],
    ) -> tuple[str, ...]:
        """Remove only exact labelled containers after an out-of-process pause.

        A normal run has an in-memory pool and performs the stronger broker
        teardown path itself.  This fallback exists for a second local CLI
        process and deliberately requires the immutable attempt label before
        Docker receives an ID to remove.
        """
        if not self.config.sandbox_enabled:
            return ()
        removed: list[str] = []
        base = (
            "label=ctf-os=true",
            f"label=ctf-os.team_id={self.config.team_id}",
            f"label=ctf-os.member={self.config.member_name}",
            f"label=ctf-os.contest={self.config.contest_name}",
            f"label=ctf-os.challenge={challenge.name}",
        )
        for attempt in attempts:
            if attempt.id in skip_attempt_ids:
                continue
            for container_id in self.docker.list_container_ids((*base, f"label=ctf-os.attempt_id={attempt.id}")):
                result = self.docker.remove(container_id)
                state.record_cleanup(attempt.id, ok=result.ok, detail=result.stderr or "operator pause exact release")
                if result.ok:
                    removed.append(container_id)
        return tuple(removed)

    def _synthetic_config(self) -> AppConfig:
        raw = copy.deepcopy(self.config.raw)
        paths = raw.setdefault("paths", {})
        paths["output"] = str(self.config.output_root / ".synthetic")
        return AppConfig(raw=raw, path=self.config.path)

    # --- prerequisites and sandbox lifecycle -----------------------------------------

    def _assert_non_mock_prerequisites(self) -> None:
        if not self.config.sandbox_enabled:
            raise PrerequisiteError("sandbox is disabled; use --mock-worker or enable the Docker sandbox before a real run")
        try:
            self.config.model_router()
        except ConfigError as exc:
            raise PrerequisiteError(str(exc)) from exc
        if self._codex_backend_factory is None and self._command_exists(self.config.codex_command) is None:
            raise PrerequisiteError(f"Codex command not found: {self.config.codex_command}; use --mock-worker or install Codex")
        if not self._strict_isolation_probe(self.config.codex_command):
            raise PrerequisiteError("installed Codex cannot demonstrate sterile strict isolation; refusing non-mock execution")
        if not broker_transport_supported():
            raise PrerequisiteError("this host cannot create secure attempt-local filesystem broker IPC; refusing non-mock execution")
        try:
            daemon_available = self.docker.daemon_available()
        except OSError as exc:
            raise PrerequisiteError(f"Docker daemon is unavailable: {exc}; use --mock-worker or start Docker") from exc
        if not daemon_available:
            raise PrerequisiteError("Docker daemon is unavailable; use --mock-worker or start Docker")
        if not self.docker.image_exists(self.config.sandbox_image):
            raise PrerequisiteError(
                f"Docker image is unavailable: {self.config.sandbox_image}. Build it with:\n"
                "docker build \\\n  -f sandbox/Dockerfile.sandbox \\\n  -t ctf-os-sandbox:latest \\\n  ."
            )
        image_id = self.docker.image_id(self.config.sandbox_image)
        print(f"Sandbox image resolved: {self.config.sandbox_image} ({image_id or 'image ID unavailable'})")

    def _cleanup_orphan_containers(self, state: LocalState) -> list[str]:
        """Remove only our labels that lack a live local attempt lease."""
        filters = [
            "label=ctf-os=true", f"label=ctf-os.team_id={self.config.team_id}",
            f"label=ctf-os.member={self.config.member_name}", f"label=ctf-os.contest={self.config.contest_name}",
        ]
        # ``docker ps -aq`` returns IDs, while SQLite records container names.
        # Resolve active IDs through the immutable attempt label rather than
        # comparing those unrelated identifiers.
        active_container_ids: set[str] = set()
        for attempt_id in state.active_attempt_ids():
            active_container_ids.update(self.docker.list_container_ids([*filters, f"label=ctf-os.attempt_id={attempt_id}"]))
        removed: list[str] = []
        for container_id in self.docker.list_container_ids(filters):
            if container_id in active_container_ids:
                continue
            if self.docker.remove(container_id).ok:
                removed.append(container_id)
        return removed

    def _start_attempt(self, pool: LocalWorkerPool, task: PlannedAttempt, *, mock_worker: bool) -> WorkerHandle | None:
        challenge = task.state.get_challenge(task.intake.challenge.id)
        if challenge is None or challenge.status not in {
            ChallengeStatus.QUEUED, ChallengeStatus.RUNNING, ChallengeStatus.FLAG_CANDIDATE,
        }:
            return None
        selection: ModelSelection | None = None
        router: ModelRouter | None = None
        if mock_worker:
            model = "mock-synthetic"
        else:
            router = self.config.model_router()
            contract = task.race_attempt.contract
            if contract is not None and contract.execution.backend != "codex":
                raise PrerequisiteError("execution contract backend must be the configured codex backend")
            selection = self._select_model(task.state, challenge, task.race_attempt, router=router)
            if selection is None:
                quota_blocked = self._quota_warning_blocks_new_workers(task.state, router)
                self._emit(
                    task.state,
                    challenge,
                    "MODEL_UNAVAILABLE",
                    message=(
                        "quota warning cooldown suppresses new local workers until expiry"
                        if quota_blocked
                        else "all configured model selections are cooling down"
                    ),
                    payload={"quota_warning": quota_blocked},
                )
                return None
            model = selection.model
        staging = None if mock_worker else task.writer.create_attempt_staging()
        attempt = Attempt(
            id=f"attempt_{task.race_attempt.attempt_id}", challenge_id=challenge.id,
            profile=task.race_attempt.profile.name, role=task.race_attempt.profile.role,
            backend="mock" if mock_worker else "codex_cli", model=model,
            model_profile=selection.profile if selection is not None else None,
            reasoning_effort=selection.reasoning_effort if selection is not None else None,
            workdir=str((task.writer.attempt_dir(challenge, f"attempt_{task.race_attempt.attempt_id}", profile=task.race_attempt.profile.name) / "work") if mock_worker else staging.workdir),
            status=AttemptStatus.QUEUED, synthetic=mock_worker,
        )
        claimed = task.state.claim_attempt(
            attempt, owner=self._owner, lease_seconds=self.config.lease_ttl_sec,
            max_workers_total=self.config.max_workers_total, max_workers_per_challenge=self.config.max_workers_per_challenge,
        )
        if not claimed.granted:
            if staging is not None:
                task.writer.cleanup_attempt_staging(staging.workdir)
            return None
        attempt = replace(attempt, lease_owner=self._owner, fencing_token=claimed.fencing_token)
        try:
            # An operator PAUSED transition may race the SQLite profile claim.
            # Claiming a lease alone never authorizes a start; re-check before
            # any sandbox/Codex side effect and release our fresh lease if the
            # challenge left a launchable local state.
            latest = task.state.get_challenge(challenge.id)
            if (
                latest is None or latest.status not in {
                    ChallengeStatus.QUEUED, ChallengeStatus.RUNNING, ChallengeStatus.FLAG_CANDIDATE,
                }
                or self._operator_pause_active(task.state, challenge.id)
            ):
                task.state.finish_attempt(
                    attempt.id, AttemptStatus.STOPPED, cleanup_status="PAUSED_BEFORE_START",
                    owner=self._owner, fencing_token=_fence(attempt),
                )
                if staging is not None:
                    task.writer.cleanup_attempt_staging(staging.workdir)
                return None
            challenge = latest
            self._emit(
                task.state,
                challenge,
                "CLAIMED",
                attempt=attempt,
                message="synthetic mock attempt claimed locally" if mock_worker else "local Codex attempt claimed",
                payload={"strategy_seed": task.race_attempt.strategy_seed},
                synthetic=mock_worker,
            )
            if not mock_worker:
                if self._operator_pause_active(task.state, challenge.id):
                    task.state.finish_attempt(
                        attempt.id, AttemptStatus.STOPPED, cleanup_status="PAUSED_BEFORE_SANDBOX",
                        owner=self._owner, fencing_token=_fence(attempt),
                    )
                    self._release_attempt(attempt.id, task.state, preserve=False)
                    return None
                attempt = self._precreate_sandbox(task, challenge, attempt)
                task.state.upsert_attempt(attempt, owner=self._owner, fencing_token=_fence(attempt))
                self._emit(
                    task.state,
                    challenge,
                    "SANDBOX_STARTED",
                    attempt=attempt,
                    message="attempt sandbox precreated",
                    payload={"container_name": attempt.container_name},
                )
            attempt = replace(attempt, status=AttemptStatus.RUNNING, started_at=utc_now())
            task.state.upsert_attempt(attempt, owner=self._owner, fencing_token=_fence(attempt))
            running_payload = {"strategy_seed": task.race_attempt.strategy_seed}
            if challenge.status is ChallengeStatus.QUEUED:
                running_event = self._event(
                    challenge, "RUNNING", attempt=attempt,
                    message="synthetic mock attempt running" if mock_worker else "local Codex attempt running",
                    payload=running_payload, synthetic=mock_worker,
                )
                challenge = task.state.transition_challenge_status(
                    challenge.id, ChallengeStatus.RUNNING, event=running_event,
                    attempt_id=attempt.id, owner=self._owner, fencing_token=_fence(attempt),
                )
                self._flush_outbox(task.state)
            else:
                self._emit(task.state, challenge, "RUNNING", attempt=attempt,
                           message="synthetic mock attempt running" if mock_worker else "local Codex attempt running",
                           payload=running_payload, synthetic=mock_worker)
            # Older consumers still recognize WORKER_STARTED.  RUNNING above
            # is the canonical local lifecycle record and is always first.
            self._emit(task.state, challenge, "WORKER_STARTED", attempt=attempt,
                       message="synthetic mock attempt running" if mock_worker else "local Codex attempt running",
                       payload=running_payload, synthetic=mock_worker)
            if selection is not None:
                payload = self._selection_payload(selection)
                payload["promoted_after_failures"] = self._promotion_applies(
                    task.state, challenge, router=router,
                )
                self._emit(task.state, challenge, "MODEL_ROUTED", attempt=attempt, payload=payload)
            if self._operator_pause_active(task.state, challenge.id):
                # PAUSED may have committed between the pre-start read and
                # the fenced RUNNING write.  Preserve the operator intent and
                # release this freshly created local attempt rather than
                # accepting a PAUSED -> RUNNING race.
                current = task.state.get_challenge(challenge.id)
                if current is not None and current.status is not ChallengeStatus.PAUSED:
                    task.state.transition_challenge_status(challenge.id, ChallengeStatus.PAUSED)
                task.state.finish_attempt(
                    attempt.id, AttemptStatus.STOPPED, cleanup_status="PAUSED_RACE",
                    owner=self._owner, fencing_token=_fence(attempt),
                )
                self._release_attempt(attempt.id, task.state, preserve=False)
                return None
            return pool.submit(
                attempt, lambda cancellation: self._execute_attempt(
                    task, challenge, attempt, cancellation, mock_worker=mock_worker, selection=selection,
                ),
                on_cancel=lambda: self._abort_attempt_sandbox(attempt.id, task.state),
            )
        except BaseException as exc:
            task.state.finish_attempt(attempt.id, AttemptStatus.FAILED, cleanup_status="START_FAILED", cleanup_message=str(exc),
                                      owner=self._owner, fencing_token=_fence(attempt))
            self._release_attempt(attempt.id, task.state, preserve=False)
            raise

    def _select_model(
        self,
        state: LocalState,
        challenge: Challenge,
        race_attempt: RaceAttempt,
        *,
        router: ModelRouter | None = None,
    ) -> ModelSelection | None:
        """Choose only from the route's finite, explicit configured sequence."""
        router = router or self.config.model_router()
        if self._quota_warning_blocks_new_workers(state, router):
            return None
        primary = self._primary_selection(state, challenge, race_attempt, router=router)
        return next(
            (
                candidate
                for candidate in router.selection_sequence(primary)
                if not state.model_in_cooldown(
                    candidate.model,
                    selection_key=candidate.cooldown_key,
                )
            ),
            None,
        )

    def _primary_selection(
        self,
        state: LocalState,
        challenge: Challenge,
        race_attempt: RaceAttempt,
        *,
        router: ModelRouter,
    ) -> ModelSelection:
        if race_attempt.profile.name == "session_leader":
            try:
                leader = router.select(role="session_leader")
            except ModelRoutingError:
                # Older node-local routing files predate the dedicated role;
                # their supervisor route is still required to be Sol.
                leader = router.select(role="supervisor")
            if leader.model != "gpt-5.6-sol":
                raise ModelRoutingError("persistent session leader must route to gpt-5.6-sol")
            return leader
        if race_attempt.contract is not None:
            execution = race_attempt.contract.execution
            return router.select_execution_profile(
                execution.model_profile, reasoning_effort=execution.reasoning_effort,
                role=race_attempt.profile.role,
            )
        # Legacy one-shot attempts may still use configured automatic
        # promotion. A Sol-issued child-session contract is authoritative and
        # must never be silently replaced by this compatibility policy.
        if self._promotion_applies(state, challenge, router=router):
            return router.select_promotion(role="supervisor")
        return router.select(
            role=race_attempt.profile.role,
            difficulty=RacePlan.difficulty_for(challenge.score, category=challenge.category),
            attempt_kind=race_attempt.profile.name,
        )

    @staticmethod
    def _failed_local_attempts(state: LocalState, challenge_id: str) -> int:
        return sum(
            attempt.status == AttemptStatus.FAILED and not attempt.synthetic
            for attempt in state.list_attempts(challenge_id)
        )

    def _promotion_applies(
        self,
        state: LocalState,
        challenge: Challenge,
        *,
        router: ModelRouter | None,
    ) -> bool:
        if router is None:
            return False
        threshold = router.promote_to_sol_after_failures
        return bool(threshold and self._failed_local_attempts(state, challenge.id) >= threshold)

    def _quota_warning_blocks_new_workers(self, state: LocalState, router: ModelRouter) -> bool:
        configured = router.stop_new_workers_on_quota_warning or bool(
            self.config.worker_policy.get("stop_new_workers_on_quota_warning", False)
        )
        return configured and state.quota_warning_in_cooldown()

    @staticmethod
    def _operator_pause_active(state: LocalState, challenge_id: str) -> bool:
        """Whether PAUSED is the latest explicit local operator lifecycle.

        This closes the small cross-process window between a profile lease
        claim and RUNNING transition without altering the v4 state schema.
        Only a durable RESUMED event clears an operator pause intent.
        """
        for event in reversed(state.list_events(challenge_id=challenge_id)):
            if event.type == "PAUSED":
                return True
            if event.type == "RESUMED":
                return False
        return False

    def _precreate_sandbox(self, task: PlannedAttempt, challenge: Challenge, attempt: Attempt) -> Attempt:
        if task.session_id is not None:
            task.writer.seed_session_handoff_artifacts(
                challenge, session_id=task.session_id, attempt_workdir=attempt.workdir,
            )
        scope = SandboxScope(self.config.team_id, self.config.member_name, challenge.contest, challenge.name,
                             challenge.id, challenge.challenge_key)
        sandbox_pool = DockerSandboxPool(
            scope=scope, workspace_root=self.config.incoming_contest_dir(challenge.contest),
            output_root=self.config.output_contest_dir(challenge.contest), docker=self.docker,
            max_containers=self.config.sandbox_max_containers,
        )
        memory, cpus = self.config.sandbox_limits
        storage_bytes, storage_inodes = self.config.sandbox_storage_limits
        staging = ArtifactWriter.staging_for_workdir(attempt.workdir)
        strategy_id = (task.race_attempt.contract.execution.tool_strategy
                       if task.race_attempt.contract is not None else "fast_recon")
        strategy = default_strategy_registry().get(strategy_id)
        image = self.config.strategy_image(strategy.profile, strategy.image)
        endpoints = resolve_remote_endpoints(parse_remote_endpoints(challenge.remote), allow_private=self.config.sandbox_allow_private_egress)
        self._emit(task.state, challenge, "STRATEGY_SELECTED", attempt=attempt,
                   message=f"selected executable strategy {strategy.id}@{strategy.version}",
                   payload={"strategy_id": strategy.id, "strategy_version": strategy.version,
                            "profile": strategy.profile, "image": image}, publish=False)
        self._emit(task.state, challenge, "HARNESS_BOOTSTRAP_STARTED", attempt=attempt,
                   payload={"strategy_id": strategy.id, "strategy_version": strategy.version}, publish=False)
        container = sandbox_pool.precreate(SandboxSpec(
            scope=scope, attempt_id=attempt.id, workspace=task.intake.workspace,
            workdir=staging.workdir, artifacts=staging.artifacts,
            image=image, memory=memory, cpus=cpus, pids_limit=strategy.budget.processes,
            storage_limit_bytes=storage_bytes, storage_inode_limit=storage_inodes,
            endpoints=endpoints,
        ))
        self._sandbox_by_attempt[attempt.id] = sandbox_pool
        checks = self._container_capability_checks(container.name, strategy)
        result = StrategyExecutor().bootstrap(strategy.id, staging.workdir, capability_checks=checks)
        for check in checks:
            self._emit(task.state, challenge, "CAPABILITY_CHECKED", attempt=attempt,
                       message=f"{check.capability}: {'available' if check.available else 'missing'}",
                       payload={"strategy_id": strategy.id, "strategy_version": strategy.version,
                                "profile": strategy.profile, **asdict(check)}, publish=False)
        self._emit(task.state, challenge, "HARNESS_BOOTSTRAP_COMPLETED", attempt=attempt,
                   message="strategy harness materialized",
                   payload={"strategy_id": strategy.id, "strategy_version": strategy.version,
                            "profile": strategy.profile, "manifest": result.manifest_path.name,
                            "degraded": result.degraded, "fallback_strategy": result.fallback_strategy}, publish=False)
        effective = strategy
        if result.degraded and result.fallback_strategy:
            fallback = default_strategy_registry().get(result.fallback_strategy)
            fallback_checks = self._container_capability_checks(container.name, fallback)
            fallback_result = StrategyExecutor().bootstrap(
                fallback.id, staging.workdir, capability_checks=fallback_checks,
            )
            if not fallback_result.degraded:
                effective = fallback
                self._emit(task.state, challenge, "STRATEGY_FALLBACK", attempt=attempt,
                           message=f"capability fallback {strategy.id} -> {fallback.id}",
                           payload={"from_strategy": strategy.id, "to_strategy": fallback.id,
                                    "strategy_version": fallback.version, "profile": fallback.profile}, publish=False)
            else:
                self._emit(task.state, challenge, "STRATEGY_ESCALATION", attempt=attempt,
                           message="selected and fallback strategies both lack required capabilities",
                           payload={"strategy_id": strategy.id, "fallback_strategy": fallback.id,
                                    "missing_required": [item.capability for item in fallback_checks if not item.available]},
                           publish=False)
        self._effective_strategy_by_attempt[attempt.id] = effective.id
        return replace(attempt, container_name=container.name)

    def _container_capability_checks(self, container_name: str, strategy) -> tuple[CapabilityCheck, ...]:
        checks: list[CapabilityCheck] = []
        for capability in (*strategy.required_capabilities, *strategy.optional_capabilities):
            selected: CapabilityCheck | None = None
            for executable in capability.executables:
                result = self.docker.exec(build_docker_exec_argv(
                    container_name, (executable, *capability.version_args),
                    docker_command=self.docker.command,
                ), timeout_sec=min(10, self.config.sandbox_command_timeout_sec))
                if result.returncode in {0, 1, 2} and "not found" not in result.stderr.casefold():
                    version = _redact_event_text((result.stdout or result.stderr or "available").splitlines()[0][:240])
                    selected = CapabilityCheck(capability.id, True, executable, version)
                    break
            checks.append(selected or CapabilityCheck(capability.id, False, reason="not found in selected container profile"))
        return tuple(checks)

    # --- streamed solver execution ----------------------------------------------------

    def _execute_attempt(
        self,
        task: PlannedAttempt,
        challenge: Challenge,
        attempt: Attempt,
        cancellation: ThreadEvent,
        *,
        mock_worker: bool,
        selection: object | None,
    ) -> AttemptExecution:
        prompt = self._render_prompt(task, challenge)
        if mock_worker:
            flag = f"SYNTHETIC{{MOCK_{challenge.id.rsplit('_', 1)[-1][:12].upper()}}}"
            backend = MockBackend((
                "[FINDING] synthetic mock-worker fixture; no network, Docker, or Codex was used",
                f"[FLAG_CANDIDATE] {flag}",
                "[TASK_DONE] synthetic fixture completed",
            ), status="stopped" if cancellation.is_set() else "completed")
            lines: list[str] = []
            def mock_output(line: str) -> None:
                lines.append(line)
                task.writer.append_evidence(challenge, f"[synthetic mock] {line}")
                self._stream_line(task, challenge, attempt, line, synthetic=True)
            result = backend.run(prompt, on_output=mock_output)
            rendered = "\n".join(lines)
            return AttemptExecution(rendered, rendered, result.status, True, records=self._records_snapshot(attempt.id))

        if not isinstance(selection, ModelSelection):
            raise PrerequisiteError("production attempt has no explicit model selection")
        router = self.config.model_router()
        backend = self._codex_backend_factory(command=self.config.codex_command, model_router=router) if self._codex_backend_factory else CodexCliBackend(command=self.config.codex_command, model_router=router)
        sandbox_pool = self._sandbox_by_attempt.get(attempt.id)
        broker = sandbox_pool.broker(attempt.id) if sandbox_pool is not None else None
        if broker is None or not broker.running:
            raise RuntimeError("attempt command broker is unavailable; refusing to start Codex")
        leader_session = task.state.get_challenge_session(challenge.id) if task.is_session_leader else None
        leader_resume_id = (
            (leader_session.leader_resume_id or leader_session.leader_session_id)
            if leader_session is not None else None
        )
        request = CodexExecRequest(
            workdir=Path(attempt.workdir), prompt=prompt, role=attempt.role,
            difficulty=("hard" if task.is_session_leader else
                        RacePlan.difficulty_for(challenge.score, category=challenge.category)),
            attempt_kind=attempt.profile,
            broker_socket=broker.socket_path,
            resume_id=leader_resume_id,
            persistent_session=task.is_session_leader and leader_resume_id is None,
            # Structured Codex terminal errors are the only trusted source
            # for model availability state.  Human-readable assistant output
            # is never allowed to drive cooldown/fallback policy.
            json_events=True,
        )
        candidates = list(router.selection_sequence(selection))
        output_parts: list[str] = []
        output_truncated = False
        total_tokens = 0
        session_id: str | None = None
        resume_id: str | None = None
        previous: ModelSelection | None = None
        final_result: CodexExecResult | None = None
        while candidates and not cancellation.is_set():
            candidate = next(
                (
                    item
                    for item in candidates
                    if not task.state.model_in_cooldown(
                        item.model,
                        selection_key=item.cooldown_key,
                    )
                ),
                None,
            )
            if candidate is None:
                break
            candidates = candidates[candidates.index(candidate) + 1 :]
            active_attempt = self._persist_active_model_selection(task.state, attempt, candidate)
            if previous is not None:
                self._emit(
                    task.state,
                    challenge,
                    "MODEL_FALLBACK",
                    attempt=active_attempt,
                    message="configured fallback selected after model failure",
                    payload=self._fallback_payload(previous, candidate),
                    publish=False,
                )
            result: CodexExecResult = backend.run(
                replace(request, selection=candidate, resume_id=resume_id or request.resume_id,
                        persistent_session=request.persistent_session and not (resume_id or request.resume_id)),
                timeout_sec=self._attempt_timeout(task),
                on_output=lambda record: self._stream_line(task, challenge, active_attempt, record.line, synthetic=False),
                # _stream_line captures bounded parent-observed records in the
                # private staging root.  Supplying an aggregate evidence sink here
                # would let a stale callback write outside its attempt lease.
                evidence_sink=None, cancel_event=cancellation,
            )
            final_result = result
            if result.session_id is not None or result.resume_id is not None:
                active_attempt = task.state.record_attempt_session_ids(
                    active_attempt.id,
                    session_id=result.session_id,
                    resume_id=result.resume_id,
                    owner=self._owner,
                    fencing_token=_fence(active_attempt),
                )
            session_id = active_attempt.session_id
            resume_id = active_attempt.resume_id
            output_parts.extend(part for part in (result.stdout, result.stderr) if part)
            output_truncated = output_truncated or bool(result.truncated)
            total_tokens += result.token_usage or 0
            if result.trusted_failure_kind is None:
                break

            reason = self._model_failure_reason(result)
            payload = self._selection_payload(candidate)
            payload["cooldown_key"] = candidate.cooldown_key
            payload["quota_warning"] = self._is_quota_warning(result)
            cooldown_event = self._event(
                challenge,
                "MODEL_COOLDOWN",
                attempt=active_attempt,
                message=reason,
                payload=payload,
            )
            task.state.record_model_cooldown(
                model=candidate.model,
                selection_key=candidate.cooldown_key,
                reason=reason,
                seconds=self.config.cooldown_on_rate_limit_sec,
                event=cooldown_event,
                owner=self._owner,
                fencing_token=_fence(active_attempt),
            )
            previous = candidate
            if self._quota_warning_blocks_new_workers(task.state, router):
                candidates.clear()
                break

        output = "\n".join(output_parts)
        if final_result is None or previous is not None and final_result.trusted_failure_kind is not None:
            unavailable_attempt = task.state.get_attempt(attempt.id) or attempt
            self._emit(
                task.state,
                challenge,
                "MODEL_UNAVAILABLE",
                attempt=unavailable_attempt,
                message=(
                    "quota warning cooldown suppresses new local workers until expiry"
                    if self._quota_warning_blocks_new_workers(task.state, router)
                    else "all configured model selections are cooling down or unavailable"
                ),
                payload={
                    "configured_selections": [self._selection_payload(item) for item in router.selection_sequence(selection)],
                    "quota_warning": self._quota_warning_blocks_new_workers(task.state, router),
                },
                publish=False,
            )
            status = "unavailable"
        else:
            status = final_result.status
        if output_truncated:
            task.writer.append_attempt_capture(attempt.workdir, "[ctf-os Codex stdout/stderr truncated]")
        # A backend double may not invoke on_output. Parse returned text only
        # when no structured stream record arrived; replaying an already
        # streamed transcript would manufacture semantic loops and duplicate
        # progress events even though candidate values themselves are deduped.
        if not self._records_snapshot(attempt.id):
            for line in output.splitlines():
                self._stream_line(task, challenge, attempt, line, synthetic=False)
        return AttemptExecution(
            output, (final_result.stdout if final_result is not None else ""), status, False, token_usage=total_tokens,
            session_id=session_id, resume_id=resume_id,
            records=self._records_snapshot(attempt.id),
        )

    def _attempt_timeout(self, task: PlannedAttempt) -> int:
        contract = task.race_attempt.contract
        requested = contract.execution.timeout_sec if contract is not None else None
        if requested is not None:
            if isinstance(requested, bool) or not isinstance(requested, int) or not 60 <= requested <= 3600:
                raise PrerequisiteError("execution contract timeout_sec must be between 60 and 3600")
            config = getattr(self, "config", None)
            if config is not None and config.tactical_engine_enabled:
                strategy = default_strategy_registry().get(contract.execution.tool_strategy)
                return min(requested, strategy.budget.timeout_sec)
            return requested
        return self.config.attempt_timeout_sec(
            task.race_attempt.profile.name, task.race_attempt.profile.max_runtime_sec,
        )

    @staticmethod
    def _selection_payload(selection: ModelSelection) -> dict[str, object]:
        return {
            "model": selection.model,
            "profile": selection.profile,
            "reasoning_effort": selection.reasoning_effort,
        }

    def _persist_active_model_selection(
        self, state: LocalState, attempt: Attempt, selection: ModelSelection
    ) -> Attempt:
        """Fence the durable selection update before starting its backend process."""
        active = replace(
            attempt,
            model=selection.model,
            model_profile=selection.profile,
            reasoning_effort=selection.reasoning_effort,
        )
        return state.upsert_attempt(active, owner=self._owner, fencing_token=_fence(attempt))

    @classmethod
    def _fallback_payload(cls, previous: ModelSelection, selected: ModelSelection) -> dict[str, object]:
        payload: dict[str, object] = {}
        for prefix, selection in (("from", previous), ("to", selected)):
            payload.update({f"{prefix}_{key}": value for key, value in cls._selection_payload(selection).items()})
        return payload

    @staticmethod
    def _is_quota_warning(result: CodexExecResult) -> bool:
        return result.failure_code in {"usage_limit_exceeded", "quota_exceeded", "credits_exhausted"}

    def _model_failure_reason(self, result: CodexExecResult) -> str:
        if self._is_quota_warning(result):
            return "quota warning"
        return "rate limited" if result.trusted_failure_kind == "rate_limited" else "model unavailable"

    def _stream_line(self, task: PlannedAttempt, challenge: Challenge, attempt: Attempt, line: str, *, synthetic: bool) -> None:
        line = line[:MAX_WORKER_STREAM_LINE_CHARS]
        if not synthetic:
            # This root-level capture is neither /work nor /artifacts, so the
            # solver cannot edit it and late workers cannot reach aggregate
            # notes, evidence, or local state through this callback.
            task.writer.append_attempt_capture(attempt.workdir, f"[solver] {line}")
        parser = ActionObservationParser()
        record = parser.parse_line(line)
        if record is not None:
            with self._stream_lock:
                records = self._records_by_attempt.setdefault(attempt.id, deque(maxlen=MAX_WORKER_RECORDS))
                records.append(record)
                loop = self._loop_by_attempt.setdefault(attempt.id, LoopDetector())
                snapshot = tuple(records)
            progress_kinds = {"plan", "hypothesis", "finding", "fail", "action", "observation", "shift", "artifact"}
            if synthetic:
                task.writer.append_note(challenge, record.kind, record.content)
                if record.kind in progress_kinds:
                    self._emit(task.state, challenge, record.kind.upper(), attempt=attempt, message=record.content,
                               payload={"record_kind": record.kind, "content": record.content}, synthetic=True, publish=False)
            elif record.kind in progress_kinds:
                # Stream records are made visible only through the exact live
                # attempt fence.  A late callback therefore cannot publish a
                # finding after its lease was reassigned, while the operator
                # can still see a current attempt's progress before it exits.
                event = self._event(
                    challenge, record.kind.upper(), attempt=attempt, message=record.content,
                    payload={"record_kind": record.kind, "content": record.content,
                             "contract_id": task.contract_task_id},
                )
                try:
                    task.state.append_fenced_event(
                        event, attempt_id=attempt.id, owner=self._owner, fencing_token=_fence(attempt),
                    )
                    self._evaluate_replanning(task.state, challenge, event)
                except StateTransitionError:
                    return
            if not synthetic and record.kind == "artifact":
                self._register_declared_artifact(task, challenge, attempt, record)
            shift = loop.observe(record.kind, record.content)
            strategy_id = self._effective_strategy_by_attempt.get(attempt.id) or (
                task.race_attempt.contract.execution.tool_strategy
                if task.race_attempt.contract is not None else "fast_recon")
            hypothesis = next((item.content for item in reversed(snapshot) if item.kind == "hypothesis"), "")
            semantic = loop.observe_snapshot(ProgressSnapshot(
                attempt_id=attempt.id,
                command=record.content if record.kind == "action" else "",
                output=record.content if record.kind == "fail" else "",
                failure_class="reported_failure" if record.kind == "fail" else "",
                strategy=strategy_id, hypothesis=hypothesis,
                new_evidence=1 if record.kind in {"finding", "observation"} else 0,
                new_artifacts=1 if record.kind == "artifact" else 0,
                new_primitives=1 if record.kind == "finding" and "primitive" in record.content.casefold() else 0,
                model=attempt.model or "",
            ))
            if shift.shift_required or semantic.loop or semantic.plateau:
                shift_reason = semantic.reason if (semantic.loop or semantic.plateau) else shift.reason
                shift_record = SolverEvent(kind="shift", content=shift_reason)
                with self._stream_lock:
                    self._records_by_attempt.setdefault(attempt.id, deque(maxlen=MAX_WORKER_RECORDS)).append(shift_record)
                    snapshot = tuple(self._records_by_attempt[attempt.id])
                if synthetic and (semantic.loop or semantic.plateau):
                    task.writer.append_note(challenge, "shift", shift_reason)
                    self._emit(task.state, challenge, "SHIFT", attempt=attempt, message=shift_reason,
                               payload={"count": shift.count}, synthetic=True, publish=False)
                elif not synthetic and (semantic.loop or semantic.plateau):
                    try:
                        self._emit(
                            task.state, challenge, "LOOP_DETECTED" if semantic.loop else "PLATEAU_DETECTED",
                            attempt=attempt, message=semantic.reason,
                            payload={"count": shift.count, "confidence": semantic.confidence,
                                     "cluster": semantic.cluster, "progress_delta": semantic.progress_delta,
                                     "recommended_action": semantic.recommended_action,
                                     "strategy_id": strategy_id}, publish=False,
                        )
                    except StateTransitionError:
                        return
            if not synthetic and record.kind == "artifact":
                # Candidate and artifact output can arrive in either order.
                # Requeue an unavailable candidate once its declaring record
                # appears instead of allowing a process-local dedupe set to
                # strand it permanently.
                for existing in task.state.list_flag_candidates(
                    challenge.id, attempt_id=attempt.id,
                    verification_statuses=("RAW_CANDIDATE", "CANDIDATE", "UNAVAILABLE"),
                ):
                    key = (attempt.id, existing.id)
                    with self._stream_lock:
                        if key in self._candidate_artifact_retries:
                            continue
                        self._candidate_artifact_retries.add(key)
                    self._candidate_signals.put(CandidateSignal(task, attempt, existing, False, snapshot))
        else:
            snapshot = self._records_snapshot(attempt.id)

        detector = FlagDetector(task.intake.manifest.flag_patterns or self.config.flag_patterns, ignore_placeholders=self.config.ignore_placeholder_flags)
        candidates = _synthetic_mock_candidates(line, challenge_id=challenge.id, attempt_id=attempt.id) if synthetic else detector.detect_candidates(
            line, challenge_id=challenge.id, challenge_key=challenge.challenge_key,
            attempt_id=attempt.id, source="codex-stream",
        )
        for raw_candidate in candidates:
            candidate = replace(
                raw_candidate, synthetic=synthetic,
                verification_status=("CANDIDATE" if synthetic else "RAW_CANDIDATE"),
            )
            key = (attempt.id, candidate.value)
            with self._stream_lock:
                if key in self._candidate_values:
                    continue
                self._candidate_values.add(key)
            candidate_payload = {"flag": candidate.value}
            if not synthetic and self._parent_verifier is not None:
                candidate_payload = {
                    "candidate_sha256": sha256(candidate.value.encode("utf-8")).hexdigest(),
                    "redacted": True,
                }
            event = self._event(challenge, "FLAG_CANDIDATE" if synthetic else "FLAG_OBSERVED", attempt=attempt,
                                message="synthetic candidate" if synthetic else "streamed flag candidate detected",
                                payload=candidate_payload, synthetic=synthetic)
            try:
                candidate = task.state.record_candidate(
                    candidate, event, owner=self._owner, fencing_token=_fence(attempt),
                    promote_challenge_status=synthetic,
                )
            except StateTransitionError:
                # A stale callback is intentionally a no-op outside its
                # private capture.  In particular it must not enqueue a later
                # aggregate/event action after reassignment.
                continue
            self._candidate_signals.put(CandidateSignal(task, attempt, candidate, synthetic, snapshot))
        self._notify_status()

    def _records_snapshot(self, attempt_id: str) -> tuple[SolverEvent, ...]:
        with self._stream_lock:
            return tuple(self._records_by_attempt.get(attempt_id, ()))

    def _promote_worker_observations(self, task: PlannedAttempt, challenge: Challenge, attempt: Attempt) -> None:
        """Lease-fenced parent promotion of one attempt's bounded captures."""
        records = self._records_snapshot(attempt.id)

        def operation() -> None:
            task.writer.promote_attempt_observations(challenge, attempt_workdir=attempt.workdir, records=records)

        task.state.run_fenced_operation(
            attempt_id=attempt.id, owner=self._owner, fencing_token=_fence(attempt),
            operation=operation,
        )
        strategy_id = self._effective_strategy_by_attempt.get(attempt.id) or (
            task.race_attempt.contract.execution.tool_strategy
            if task.race_attempt.contract is not None else "fast_recon")
        strategy = default_strategy_registry().get(strategy_id)
        staging = ArtifactWriter.staging_for_workdir(attempt.workdir)
        artifact_root = staging.artifacts.resolve(strict=True)
        candidates: list[Path] = []
        seen_paths: set[Path] = set()
        declared = Verifier().declared_artifacts(
            records, attempt_workdir=staging.workdir, challenge_artifacts=staging.artifacts,
        )
        possible = [*declared, *(item for item in staging.artifacts.rglob("*"))]
        for item in possible:
            try:
                if item.is_symlink() or not item.is_file():
                    continue
                resolved = item.resolve(strict=True)
                if not (resolved.is_relative_to(artifact_root)
                        or resolved.is_relative_to(staging.workdir.resolve(strict=True))):
                    continue
            except (OSError, ValueError):
                continue
            if resolved not in seen_paths:
                seen_paths.add(resolved)
                candidates.append(item)
        for path in sorted(candidates)[:128]:
            resolved = path.resolve(strict=True)
            relative = (resolved.relative_to(artifact_root)
                        if resolved.is_relative_to(artifact_root)
                        else Path("work") / resolved.relative_to(staging.workdir.resolve(strict=True)))
            digest = sha256(path.read_bytes()).hexdigest()
            artifact_id = stable_id(challenge.id, attempt.id, str(relative), digest, prefix="artifact_")
            if artifact_id in self._registered_artifact_ids:
                continue
            creation = self._event(
                challenge, "artifact.created", attempt=attempt,
                message=f"captured {relative}",
                payload={"artifact_id": artifact_id, "artifact_type": _artifact_type(relative),
                         "sha256": digest, "strategy_id": strategy.id,
                         "strategy_version": strategy.version},
            )
            try:
                task.state.append_fenced_event(creation, attempt_id=attempt.id,
                                               owner=self._owner, fencing_token=_fence(attempt))
            except StateTransitionError:
                break
            task.state.record_tactical_artifact({
                "id": artifact_id, "challenge_id": challenge.id, "attempt_id": attempt.id,
                "contract_id": task.contract_task_id, "artifact_type": _artifact_type(relative),
                "path": str(relative), "sha256": digest, "strategy_id": strategy.id,
                "strategy_version": strategy.version, "creation_event_id": creation.id,
                "content_metadata": {"size": path.stat().st_size}, "trust_state": "unverified",
                "consumers": [],
            })
            self._registered_artifact_ids.add(artifact_id)

    def _register_declared_artifact(
        self, task: PlannedAttempt, challenge: Challenge, attempt: Attempt, record: SolverEvent,
    ) -> None:
        """Hash a declared regular file before a following finding can fire a rule."""
        staging = ArtifactWriter.staging_for_workdir(attempt.workdir)
        paths = Verifier().declared_artifacts(
            (record,), attempt_workdir=staging.workdir, challenge_artifacts=staging.artifacts,
        )
        for path in paths:
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                resolved = path.resolve(strict=True)
                work_root = staging.workdir.resolve(strict=True)
                artifact_root = staging.artifacts.resolve(strict=True)
                if resolved.is_relative_to(artifact_root):
                    relative = resolved.relative_to(artifact_root)
                elif resolved.is_relative_to(work_root):
                    relative = Path("work") / resolved.relative_to(work_root)
                else:
                    continue
                digest = sha256(path.read_bytes()).hexdigest()
            except (OSError, ValueError):
                continue
            artifact_id = stable_id(challenge.id, attempt.id, str(relative), digest, prefix="artifact_")
            if artifact_id in self._registered_artifact_ids:
                continue
            creation = self._event(
                challenge, "artifact.created", attempt=attempt, message=f"captured {relative}",
                payload={"artifact_id": artifact_id, "artifact_type": _artifact_type(relative),
                         "sha256": digest, "strategy_id": self._effective_strategy_by_attempt.get(attempt.id, "unknown"),
                         "strategy_version": 1},
            )
            try:
                task.state.append_fenced_event(
                    creation, attempt_id=attempt.id, owner=self._owner, fencing_token=_fence(attempt),
                )
            except StateTransitionError:
                return
            task.state.record_tactical_artifact({
                "id": artifact_id, "challenge_id": challenge.id, "attempt_id": attempt.id,
                "contract_id": task.contract_task_id, "artifact_type": _artifact_type(relative),
                "path": str(relative), "sha256": digest,
                "strategy_id": self._effective_strategy_by_attempt.get(attempt.id, "unknown"),
                "strategy_version": 1, "creation_event_id": creation.id,
                "content_metadata": {"size": path.stat().st_size}, "trust_state": "unverified",
                "consumers": [],
            })
            self._registered_artifact_ids.add(artifact_id)

    # --- local supervisor lifecycle -------------------------------------------------

    def _monitor_supervision(
        self,
        active: dict[str, tuple[WorkerHandle, PlannedAttempt]],
        supervisors: dict[str, _SupervisorHandle],
    ) -> bool:
        """Start at most one bounded hint review per locally leased challenge.

        The coordinator only observes handles it owns.  It does not inspect
        another node's state for control purposes and it never turns an
        event into a remote command.
        """
        now = self._monotonic_clock()
        changed = False
        for handle, task in tuple(active.values()):
            challenge = task.state.get_challenge(handle.attempt.challenge_id)
            if challenge is None or challenge.status is not ChallengeStatus.RUNNING:
                continue
            if challenge.id in supervisors:
                continue
            previous_check = self._last_supervision_check.get(challenge.id)
            if previous_check is not None and now - previous_check < self.config.loop_check_sec:
                continue
            self._last_supervision_check[challenge.id] = now
            reason = self._supervision_reason(task.state, challenge, handle.attempt)
            if reason is None:
                continue
            previous_review = self._last_supervisor_review.get(challenge.id)
            if previous_review is not None and now - previous_review < self.config.hint_after_sec:
                continue
            self._last_supervisor_review[challenge.id] = now
            try:
                stuck_event = self._event(
                    challenge, "STUCK", attempt=handle.attempt, message=reason,
                    payload={"reason": reason},
                )
                challenge = task.state.transition_challenge_status(
                    challenge.id, ChallengeStatus.STUCK, event=stuck_event,
                    attempt_id=handle.attempt.id, owner=self._owner, fencing_token=_fence(handle.attempt),
                )
                selection, unavailable_reason = self._select_supervisor_model(task.state)
                if selection is None and self._supervisor_hint_factory is None:
                    unavailable_event = self._event(
                        challenge, "SUPERVISOR_UNAVAILABLE", attempt=handle.attempt,
                        message=unavailable_reason, payload={"reason": unavailable_reason},
                    )
                    task.state.append_fenced_event(
                        unavailable_event, attempt_id=handle.attempt.id,
                        owner=self._owner, fencing_token=_fence(handle.attempt),
                    )
                    self._flush_outbox(task.state)
                    changed = True
                    continue
                hinting_event = self._event(
                    challenge, "HINTING", attempt=handle.attempt,
                    message="bounded local supervisor review started",
                    payload=self._selection_payload(selection) if selection is not None else {"backend": "injected"},
                )
                challenge = task.state.transition_challenge_status(
                    challenge.id, ChallengeStatus.HINTING, event=hinting_event,
                    attempt_id=handle.attempt.id, owner=self._owner, fencing_token=_fence(handle.attempt),
                )
                request = SupervisorHintRequest(
                    task=task, challenge=challenge, attempt=handle.attempt,
                    prompt=self._render_supervisor_prompt(task, challenge, handle.attempt, reason),
                    selection=selection, timeout_sec=self.config.supervisor_hint_timeout_sec,
                )
                supervisors[challenge.id] = self._start_supervisor_hint(request)
                self._flush_outbox(task.state)
                changed = True
            except StateTransitionError:
                # The attempt may have been paused, expired, or fenced after
                # the read.  Leave the later owner as the sole authority.
                continue
        return changed

    def _supervision_reason(self, state: LocalState, challenge: Challenge, attempt: Attempt) -> str | None:
        """Return a visible reason only after a real no-progress threshold."""
        now = datetime.now(timezone.utc)
        history = state.list_events(challenge_id=challenge.id)
        loop_event = next((event for event in reversed(history) if event.type == "LOOP_DETECTED"), None)
        meaningful = [event.timestamp for event in history if event.type in _MEANINGFUL_PROGRESS_TYPES]
        started = attempt.started_at or challenge.updated_at
        last_progress = max((started, *meaningful), default=started)
        elapsed = max(0.0, (now - last_progress).total_seconds())
        if loop_event is not None and loop_event.timestamp >= last_progress:
            return loop_event.message or "repeated local action/failure detected"
        if elapsed >= self.config.hint_after_sec:
            return f"no meaningful local progress for {int(elapsed)}s"
        return None

    def _select_supervisor_model(self, state: LocalState) -> tuple[ModelSelection | None, str]:
        """Select an explicit Sol route and respect all local cooldowns."""
        try:
            router = self.config.model_router()
        except ConfigError as exc:
            return None, f"supervisor routing unavailable: {exc}"
        if self._quota_warning_blocks_new_workers(state, router):
            return None, "quota cooldown is active; supervisor review is deferred"
        try:
            primary = router.select_promotion(role="supervisor")
        except ModelRoutingError:
            try:
                primary = router.select(role="supervisor")
            except ModelRoutingError as exc:
                return None, f"supervisor profile unavailable: {exc}"
        if primary.model != "gpt-5.6-sol":
            return None, "supervisor primary profile must route to gpt-5.6-sol"
        for candidate in router.selection_sequence(primary):
            if not state.model_in_cooldown(candidate.model, selection_key=candidate.cooldown_key):
                return candidate, ""
        return None, "all configured Sol supervisor/fallback profiles are cooling down"

    def _start_supervisor_hint(self, request: SupervisorHintRequest) -> _SupervisorHandle:
        done = ThreadEvent()
        holder: list[_SupervisorHandle] = []

        def runner() -> None:
            try:
                holder[0].result = self._generate_supervisor_hint(request)
            except BaseException as exc:
                holder[0].error = exc
            finally:
                done.set()

        thread = Thread(target=runner, name=f"ctf-os-supervisor-{request.attempt.id}", daemon=True)
        handle = _SupervisorHandle(request=request, thread=thread, done=done)
        holder.append(handle)
        thread.start()
        return handle

    def _drain_supervisor_hints(
        self,
        supervisors: dict[str, _SupervisorHandle],
        pool: LocalWorkerPool,
        pending: deque[PlannedAttempt],
    ) -> bool:
        changed = False
        for challenge_id, handle in tuple(supervisors.items()):
            if handle.done is None or not handle.done.is_set():
                continue
            supervisors.pop(challenge_id, None)
            task, attempt = handle.request.task, handle.request.attempt
            challenge = task.state.get_challenge(challenge_id)
            live = task.state.get_active_attempt(attempt.id)
            if challenge is None or challenge.status is ChallengeStatus.PAUSED:
                continue
            if challenge.status is not ChallengeStatus.HINTING:
                continue
            if live is None or live.lease_owner != self._owner or live.fencing_token != _fence(attempt):
                # The old worker ended or was fenced while its daemon review
                # was running.  Never revive it; leave a durable, actionable
                # local STUCK reason without requiring the vanished lease.
                abandoned = self._event(
                    challenge, "SUPERVISOR_UNAVAILABLE", attempt=attempt,
                    message="supervisor review ended after its local attempt lease was lost",
                )
                task.state.transition_challenge_status(challenge.id, ChallengeStatus.STUCK, event=abandoned)
                self._flush_outbox(task.state)
                changed = True
                continue
            result = handle.result
            if handle.error is not None:
                result = SupervisorHintResult(None, handle.request.selection, f"supervisor review failed: {handle.error}")
            if result is not None and result.hint:
                hint_event = self._event(
                    challenge, "SUPERVISOR_HINT", attempt=attempt, message=result.hint,
                    payload={"hint": result.hint, **(self._selection_payload(result.selection) if result.selection else {})},
                )
                try:
                    # Persist the content before making RUNNING visible, so a
                    # replacement prompt can never race ahead of its hint.
                    task.state.append_fenced_event(
                        hint_event, attempt_id=attempt.id, owner=self._owner, fencing_token=_fence(attempt),
                    )
                    resumed_event = self._event(
                        challenge, "HINT_RESUMED", attempt=attempt,
                        message="supervisor hint persisted; local work requeued",
                    )
                    task.state.transition_challenge_status(
                        challenge.id, ChallengeStatus.RUNNING, event=resumed_event,
                        attempt_id=attempt.id, owner=self._owner, fencing_token=_fence(attempt),
                    )
                except StateTransitionError:
                    continue
                # Cancel only this process's attempt handles.  The normal
                # finalizer releases their exact sandbox and the queued local
                # RacePlan renders the just-persisted hint into its prompt.
                pool.cancel_challenge(challenge.id)
                if not any(item.intake.challenge.id == challenge.id for item in pending):
                    pending.append(task)
            else:
                reason = result.reason if result is not None else "supervisor review returned no usable hint"
                unavailable_event = self._event(
                    challenge, "SUPERVISOR_UNAVAILABLE", attempt=attempt,
                    message=reason, payload={"reason": reason},
                )
                try:
                    task.state.transition_challenge_status(
                        challenge.id, ChallengeStatus.STUCK, event=unavailable_event,
                        attempt_id=attempt.id, owner=self._owner, fencing_token=_fence(attempt),
                    )
                except StateTransitionError:
                    continue
            self._flush_outbox(task.state)
            self._notify_status()
            changed = True
        return changed

    def _generate_supervisor_hint(self, request: SupervisorHintRequest) -> SupervisorHintResult:
        if self._supervisor_hint_factory is not None:
            return SupervisorHintResult(_bounded_hint(self._supervisor_hint_factory(request)), request.selection)
        if request.selection is None:
            return SupervisorHintResult(None, None, "supervisor model selection is unavailable")
        sandbox_pool = self._sandbox_by_attempt.get(request.attempt.id)
        broker = sandbox_pool.broker(request.attempt.id) if sandbox_pool is not None else None
        if broker is None or not broker.running:
            return SupervisorHintResult(None, request.selection, "no live local broker sandbox is available for supervisor review")
        router = self.config.model_router()
        backend = (
            self._codex_backend_factory(command=self.config.codex_command, model_router=router)
            if self._codex_backend_factory else CodexCliBackend(command=self.config.codex_command, model_router=router)
        )
        candidates = router.selection_sequence(request.selection)
        previous: ModelSelection | None = None
        for candidate in candidates:
            if request.task.state.model_in_cooldown(candidate.model, selection_key=candidate.cooldown_key):
                continue
            result: CodexExecResult = backend.run(
                CodexExecRequest(
                    workdir=Path(request.attempt.workdir), prompt=request.prompt, role="supervisor",
                    difficulty=RacePlan.difficulty_for(
                        request.challenge.score, category=request.challenge.category,
                    ),
                    attempt_kind="supervisor_hint", broker_socket=broker.socket_path,
                    selection=candidate, json_events=True,
                ),
                timeout_sec=request.timeout_sec, evidence_sink=None,
            )
            if result.trusted_failure_kind is None:
                return SupervisorHintResult(_bounded_hint(result.stdout), candidate)
            reason = self._model_failure_reason(result)
            cooldown_event = self._event(
                request.challenge, "MODEL_COOLDOWN", attempt=request.attempt, message=reason,
                payload={**self._selection_payload(candidate), "cooldown_key": candidate.cooldown_key,
                         "quota_warning": self._is_quota_warning(result)},
            )
            request.task.state.record_model_cooldown(
                model=candidate.model, selection_key=candidate.cooldown_key, reason=reason,
                seconds=self.config.cooldown_on_rate_limit_sec, event=cooldown_event,
                owner=self._owner, fencing_token=_fence(request.attempt),
            )
            previous = candidate
            if self._quota_warning_blocks_new_workers(request.task.state, router):
                break
        if self._quota_warning_blocks_new_workers(request.task.state, router):
            return SupervisorHintResult(None, previous, "quota cooldown is active; supervisor review is deferred")
        return SupervisorHintResult(None, previous, "all configured Sol supervisor/fallback profiles are cooling down or unavailable")

    def _render_supervisor_prompt(
        self, task: PlannedAttempt, challenge: Challenge, attempt: Attempt, reason: str,
    ) -> str:
        findings, failures, commands = self._local_evidence(task.state, challenge.id)
        records = self._records_snapshot(attempt.id)
        record_text = "\n".join(f"- [{record.kind.upper()}] {record.content}" for record in records[-20:]) or "- (none)"
        return f"""You are the local Sol supervisor for one authorized CTF attempt.
Do not execute commands, access the network, write files, or propose a flag. Give one concise strategy shift grounded only in the supplied local records.

Challenge: {challenge.name} ({challenge.category}, score={challenge.score if challenge.score is not None else 'unknown'})
Description: {challenge.description or '(none)'}
Why review started: {reason}
Findings: {findings[-8:] or ['(none)']}
Failures: {failures[-8:] or ['(none)']}
Commands: {commands[-8:] or ['(none)']}
Recent structured records:
{record_text}

Return the guidance as one [SUPERVISOR_HINT] line. Do not reveal private chain-of-thought."""

    # --- candidate handling, verification, promotion ---------------------------------

    def _drain_candidate_signals(
        self, pool: LocalWorkerPool, pending: deque[PlannedAttempt], solved: set[str], auto_confirm_flags: bool
    ) -> bool:
        handled = False
        while True:
            try:
                signal = self._candidate_signals.get_nowait()
            except queue.Empty:
                return handled
            try:
                self._handle_candidate(signal, pool, pending, solved, auto_confirm_flags=auto_confirm_flags)
            except StateTransitionError:
                # The signal may have been queued immediately before this
                # attempt expired/reassigned.  Its private capture is safely
                # discarded; it must not mutate aggregate lifecycle state.
                pass
            handled = True

    def _handle_candidate(
        self, signal: CandidateSignal, pool: LocalWorkerPool, pending: deque[PlannedAttempt], solved: set[str], *, auto_confirm_flags: bool
    ) -> None:
        task, attempt, candidate = signal.task, signal.attempt, signal.candidate
        challenge = task.state.get_challenge(candidate.challenge_id)
        if challenge is None or challenge.status is ChallengeStatus.SOLVED:
            return
        if not signal.synthetic:
            live = task.state.get_active_attempt(attempt.id)
            if live is None or live.lease_owner != self._owner or live.fencing_token != _fence(attempt):
                return
        if signal.synthetic:
            if not auto_confirm_flags:
                return
            solved_event = self._event(challenge, "SOLVED", attempt=attempt, message="synthetic mock result auto-confirmed",
                                       payload={"flag": candidate.value}, synthetic=True)
            task.state.solve_verified(candidate_id=candidate.id, flag=candidate.value, event=solved_event, synthetic=True,
                                      owner=self._owner, fencing_token=_fence(attempt))
            self._complete_solve(challenge.id, pool, pending, solved, except_attempt_id=attempt.id)
            return

        patterns = task.intake.manifest.flag_patterns or self.config.flag_patterns
        verifier = Verifier()
        if not self.config.require_verifier_before_solved:
            raise PrerequisiteError("production flag solving requires an explicit sandbox verifier")
        if challenge.status is ChallengeStatus.FLAG_CANDIDATE:
            challenge = task.state.transition_challenge_status(
                challenge.id, ChallengeStatus.VERIFYING, attempt_id=attempt.id,
                owner=self._owner, fencing_token=_fence(attempt),
            )
        candidate = task.state.set_candidate_verification(
            candidate.id, status="VERIFYING", reason="running explicit replay verification",
            owner=self._owner, fencing_token=_fence(attempt),
        )
        if self._parent_verifier is not None:
            verification = self._parent_verifier.verify(
                challenge_id=challenge.id, candidate=candidate.value,
            )
            self._emit(
                task.state, challenge, "verification.started", attempt=attempt,
                message="running parent-owned immutable verification",
                payload={"verifier_id": verification.verifier_id,
                         "candidate_sha256": verification.candidate_sha256}, publish=False,
            )
            if not verification.valid:
                task.state.set_candidate_verification(
                    candidate.id, status="REJECTED", reason=verification.reason,
                    owner=self._owner, fencing_token=_fence(attempt),
                )
                if challenge.status is ChallengeStatus.VERIFYING:
                    challenge = task.state.transition_challenge_status(
                        challenge.id, ChallengeStatus.FLAG_CANDIDATE, attempt_id=attempt.id,
                        owner=self._owner, fencing_token=_fence(attempt),
                    )
                self._emit(
                    task.state, challenge, "verification.failed", attempt=attempt,
                    message=verification.reason,
                    payload={"verifier_id": verification.verifier_id,
                             "candidate_sha256": verification.candidate_sha256}, publish=False,
                )
                return
            verified_event = self._event(
                challenge, "flag.verified", attempt=attempt,
                message="parent-owned immutable verifier accepted candidate",
                payload={"verifier_id": verification.verifier_id,
                         "candidate_sha256": verification.candidate_sha256,
                         "redacted": True},
            )
            task.state.solve_verified(
                candidate_id=candidate.id, flag=candidate.value, event=verified_event,
                owner=self._owner, fencing_token=_fence(attempt),
            )
            self._complete_solve(challenge.id, pool, pending, solved, except_attempt_id=attempt.id)
            return
        self._emit(task.state, challenge, "VERIFYING", attempt=attempt, message="running explicit replay verification",
                   payload={"flag": candidate.value}, publish=False)
        staging = ArtifactWriter.staging_for_workdir(attempt.workdir)
        records = self._records_snapshot(attempt.id) or signal.records
        command = verifier.derive_command(
            records, attempt_workdir=attempt.workdir, challenge_artifacts=staging.artifacts,
            candidate=candidate.value, challenge_id=challenge.id, attempt_id=attempt.id,
            nonce=secrets.token_urlsafe(24),
        )
        sandbox_pool = self._sandbox_by_attempt.get(attempt.id)
        broker = sandbox_pool.broker(attempt.id) if sandbox_pool is not None else None
        if command is None or broker is None or not broker.running:
            task.state.set_candidate_verification(candidate.id, status="UNAVAILABLE", reason="no live broker-backed replay artifact",
                                                  owner=self._owner, fencing_token=_fence(attempt))
            if challenge.status is ChallengeStatus.VERIFYING:
                challenge = task.state.transition_challenge_status(
                    challenge.id, ChallengeStatus.FLAG_CANDIDATE, attempt_id=attempt.id,
                    owner=self._owner, fencing_token=_fence(attempt),
                )
            self._emit(task.state, challenge, "VERIFIER_UNAVAILABLE", attempt=attempt,
                       message="no executable replay artifact was available",
                       payload={"flag": candidate.value}, publish=False)
            return
        verification = verifier.verify_sandbox(
            candidate.value, command,
            execute=lambda argv: self._broker_exec(broker, attempt.id, argv), patterns=patterns,
        )
        if verification.state != "solved":
            task.state.set_candidate_verification(candidate.id, status="REJECTED", reason=verification.reason,
                                                  owner=self._owner, fencing_token=_fence(attempt))
            if challenge.status is ChallengeStatus.VERIFYING:
                challenge = task.state.transition_challenge_status(
                    challenge.id, ChallengeStatus.FLAG_CANDIDATE, attempt_id=attempt.id,
                    owner=self._owner, fencing_token=_fence(attempt),
                )
            self._emit(task.state, challenge, "VERIFIER_REJECTED", attempt=attempt,
                       message=verification.reason, payload={"flag": candidate.value}, publish=False)
            return
        promoted = task.writer.promote_verified_artifacts(
            challenge, attempt_workdir=attempt.workdir,
            artifact_paths=verifier.declared_artifacts(
                records, attempt_workdir=attempt.workdir, challenge_artifacts=staging.artifacts,
            ), attempt_artifacts=staging.artifacts,
        )

        for path in promoted:
            self._emit(task.state, challenge, "ARTIFACT_WRITTEN", attempt=attempt, message=str(path), publish=False)
        task.state.set_candidate_verification(
            candidate.id, status="REPLAY_VERIFIED", reason="sandbox replay succeeded; awaiting Sol approval",
            owner=self._owner, fencing_token=_fence(attempt),
        )
        if challenge.status is ChallengeStatus.VERIFYING:
            task.state.transition_challenge_status(
                challenge.id, ChallengeStatus.FLAG_CANDIDATE, attempt_id=attempt.id,
                owner=self._owner, fencing_token=_fence(attempt),
            )
        self._emit(task.state, challenge, "REPLAY_VERIFIED", attempt=attempt,
                   message="sandbox replay succeeded; persistent Sol must approve",
                   payload={"flag": candidate.value}, publish=False)

    @staticmethod
    def _broker_exec(broker, attempt_id: str, argv: tuple[str, ...]) -> BrokerResponse:
        return send_broker_request(broker.socket_path, attempt_id=attempt_id, token=broker.token, argv=argv)

    @staticmethod
    def _complete_solve(
        challenge_id: str, pool: LocalWorkerPool, pending: deque[PlannedAttempt], solved: set[str],
        *, except_attempt_id: str | None = None,
    ) -> None:
        solved.add(challenge_id)
        # This pool owns only current-node handles.  No teammate/container is
        # enumerated or signalled.
        # Let the winning attempt finish its fenced observation/artifact
        # promotion before its sandbox is released. Removing its staging root
        # from an on-cancel callback here races _finish_attempt.
        pool.cancel_challenge(challenge_id, except_attempt_id=except_attempt_id)
        remaining = [item for item in pending if item.intake.challenge.id != challenge_id]
        pending.clear()
        pending.extend(remaining)

    # --- finalization and event publishing -------------------------------------------

    def _finish_attempt(
        self, handle: WorkerHandle, task: PlannedAttempt, pool: LocalWorkerPool,
        pending: deque[PlannedAttempt], solved: set[str], *, auto_confirm_flags: bool,
    ) -> None:
        challenge = task.state.get_challenge(task.intake.challenge.id)
        if challenge is None:
            return
        if handle.lease_lost:
            self._release_attempt(handle.attempt.id, task.state, preserve=False)
            return
        if handle.error is not None:
            status = AttemptStatus.STOPPED if handle.cancel_event.is_set() else AttemptStatus.FAILED
            attempt = task.state.finish_attempt(handle.attempt.id, status, owner=self._owner, fencing_token=_fence(handle.attempt))
            self._emit(task.state, challenge, "WORKER_STOPPED" if status is AttemptStatus.STOPPED else "FAILED",
                       attempt=attempt, message=str(handle.error), synthetic=attempt.synthetic, fenced=False)
            if task.contract_task_id is not None:
                task.state.mark_contract_task_outcome(
                    task.contract_task_id,
                    status=(ContractTaskStatus.CANCELLED if status is AttemptStatus.STOPPED else ContractTaskStatus.FAILED),
                    result_summary=str(handle.error), assigned_attempt_id=attempt.id,
                )
            self._release_attempt(attempt.id, task.state, preserve=status is AttemptStatus.FAILED and self.config.preserve_failed_attempts)
            return

        execution: AttemptExecution = handle.result
        was_cancelled = handle.cancel_event.is_set()
        # A non-streaming backend result still receives the exact same
        # candidate path as a live stdout/stderr record.  This must happen
        # before finish_attempt deletes the lease, otherwise fenced candidate
        # verification would correctly reject the late write.
        if execution.synthetic or not self._records_snapshot(handle.attempt.id):
            for line in execution.output.splitlines():
                self._stream_line(task, challenge, handle.attempt, line, synthetic=execution.synthetic)
        self._drain_candidate_signals(pool, pending, solved, auto_confirm_flags)
        if not execution.synthetic:
            try:
                self._promote_worker_observations(task, challenge, handle.attempt)
            except StateTransitionError:
                # Lease expiry/reassignment between callback and completion is
                # fail-closed: discard private captures and never emit them.
                self._release_attempt(handle.attempt.id, task.state, preserve=False)
                return
        status = AttemptStatus.STOPPED if was_cancelled else (AttemptStatus.SUCCEEDED if execution.status == "completed" else AttemptStatus.FAILED)
        attempt = task.state.finish_attempt(handle.attempt.id, status, token_total=execution.token_usage,
                                            owner=self._owner, fencing_token=_fence(handle.attempt))
        if execution.token_usage:
            self._emit(task.state, challenge, "TOKEN_USAGE", attempt=attempt, message="local token usage",
                       payload={"token_usage": execution.token_usage}, synthetic=execution.synthetic, fenced=False)
        challenge = task.state.get_challenge(challenge.id) or challenge
        self._emit(task.state, challenge, "WORKER_STOPPED", attempt=attempt,
                   message="attempt completed" if status is AttemptStatus.SUCCEEDED else "attempt stopped",
                   payload=self._attempt_session_payload(attempt),
                   synthetic=execution.synthetic, fenced=False)
        if task.is_session_leader:
            if execution.session_id or execution.resume_id:
                task.state.checkpoint_challenge_session(
                    challenge.id, leader_session_id=execution.session_id,
                    leader_resume_id=execution.resume_id,
                )
            try:
                solve_plan = SolvePlanParser().parse(execution.controller_output)
            except PlanParseError as exc:
                session = task.state.get_challenge_session(challenge.id)
                summary_state = dict(session.summary_state) if session is not None else {}
                rejection_count = int(summary_state.get("plan_rejections", 0)) + 1
                summary_state["plan_rejections"] = rejection_count
                task.state.checkpoint_challenge_session(
                    challenge.id, summary_state=summary_state,
                )
                self._emit(
                    task.state, challenge, "SESSION_PLAN_REJECTED", attempt=attempt,
                    message=str(exc), payload={"count": rejection_count}, fenced=False,
                )
                if challenge.status is ChallengeStatus.RUNNING:
                    if rejection_count == 1:
                        pending.extend(self._materialize_solve_plan(
                            task, challenge, self._bootstrap_solve_plan(challenge),
                        ))
                    else:
                        stuck = self._event(
                            challenge, "STUCK", attempt=attempt,
                            message="persistent Sol leader returned malformed plans twice",
                            payload={"plan_rejections": rejection_count},
                        )
                        challenge = task.state.transition_challenge_status(
                            challenge.id, ChallengeStatus.STUCK, event=stuck,
                        )
            else:
                session = task.state.get_challenge_session(challenge.id)
                if session is not None and session.summary_state.get("plan_rejections"):
                    summary_state = dict(session.summary_state)
                    summary_state["plan_rejections"] = 0
                    task.state.checkpoint_challenge_session(challenge.id, summary_state=summary_state)
                approved = solve_plan.approved_candidate
                replay = next((item for item in task.state.list_flag_candidates(challenge.id)
                               if item.value == approved and item.verification_status == "REPLAY_VERIFIED"), None)
                if approved and replay is not None:
                    solved_event = self._event(
                        challenge, "SOLVED", attempt=attempt,
                        message="replay evidence approved by persistent Sol leader",
                        payload={"flag": approved, "session_id": task.session_id},
                    )
                    task.state.solve_replay_approved(
                        candidate_id=replay.id, flag=approved, event=solved_event,
                        leader_attempt_id=attempt.id,
                    )
                    self._complete_solve(challenge.id, pool, pending, solved, except_attempt_id=attempt.id)
                else:
                    pending.extend(self._materialize_solve_plan(task, challenge, solve_plan))
        if task.contract_task_id is not None and not execution.synthetic:
            records = execution.records or self._records_snapshot(attempt.id)
            summary = "\n".join(
                f"[{record.kind.upper()}] {record.content}" for record in records[-20:]
            ) or execution.output[-2_000:]
            staging = ArtifactWriter.staging_for_workdir(attempt.workdir)
            declared = Verifier().declared_artifacts(
                records, attempt_workdir=attempt.workdir,
                challenge_artifacts=staging.artifacts,
            )
            promoted = task.writer.promote_session_handoff_artifacts(
                challenge,
                session_id=task.session_id or "legacy-session",
                contract_id=task.contract_task_id,
                attempt_workdir=attempt.workdir,
                artifact_paths=declared,
                parent_approved=status is AttemptStatus.SUCCEEDED and bool(records),
            )
            consumers = tuple(
                item.id for item in task.state.list_contract_tasks(task.session_id or "")
                if item.id != task.contract_task_id
                and item.status in {ContractTaskStatus.PENDING, ContractTaskStatus.RUNNING}
                and item.tool_strategy in {"exploit_build", "protocol_replay", "independent_validation"}
            ) if task.session_id else ()
            artifact_ids = task.state.handoff_tactical_artifacts(
                challenge_id=challenge.id, producer_contract_id=task.contract_task_id,
                filenames=(str(path) for path in promoted), consumer_contract_ids=consumers,
            )
            for path in promoted:
                task.state.append_event(self._event(
                    challenge, "artifact.handed_off", message=f"contract artifact handed to session {task.session_id}",
                    payload={"producer_attempt_id": attempt.id, "producer_contract_id": task.contract_task_id,
                             "consumer_session_id": task.session_id, "consumer_contract_ids": list(consumers),
                             "artifact_ids": list(artifact_ids), "path": Path(path).name,
                             "success": bool(artifact_ids and consumers)},
                ))
            task.state.mark_contract_task_outcome(
                task.contract_task_id,
                status=(ContractTaskStatus.SUCCEEDED if status is AttemptStatus.SUCCEEDED else
                        ContractTaskStatus.CANCELLED if status is AttemptStatus.STOPPED else ContractTaskStatus.FAILED),
                result_summary=summary, assigned_attempt_id=attempt.id,
                evidence_ids=(attempt.id, *(str(path) for path in promoted)),
            )
        self._release_attempt(attempt.id, task.state, preserve=status is AttemptStatus.FAILED and self.config.preserve_failed_attempts)

    def _replan_exhausted_challenges(
        self, pending: deque[PlannedAttempt], active: dict[str, tuple[WorkerHandle, PlannedAttempt]], intake: tuple[IntakeChallenge, ...]
    ) -> None:
        pending_ids = {item.intake.challenge.id for item in pending}
        active_ids = {task.intake.challenge.id for _, task in active.values()}
        for item in intake:
            state = LocalState.for_config(
                self.config, contest_name=item.manifest.name
            )
            challenge = state.get_challenge(item.challenge.id)
            if challenge and challenge.status in {ChallengeStatus.RUNNING, ChallengeStatus.FLAG_CANDIDATE} and challenge.id not in pending_ids | active_ids:
                session = state.get_challenge_session(challenge.id)
                if session is None:
                    continue
                tasks = state.list_contract_tasks(session.id)
                if not tasks or any(task.status in {
                    ContractTaskStatus.PENDING, ContractTaskStatus.RUNNING,
                } for task in tasks):
                    continue
                writer = ArtifactWriter(self.config.output_root, item.manifest.name)
                next_generation = self._enqueue_session_generation(item, state, writer, challenge)
                pending.extend(next_generation)
                self._emit(
                    state, challenge, "SESSION_REPLANNED",
                    message="Sol replaced terminal branches with a fresh contract generation",
                    payload={"session_id": session.id, "generation": session.generation + 1,
                             "contract_count": len(next_generation)},
                )

    def _release_attempt(self, attempt_id: str, state: LocalState, *, preserve: bool) -> None:
        self._effective_strategy_by_attempt.pop(attempt_id, None)
        sandbox_pool = self._sandbox_by_attempt.pop(attempt_id, None)
        if sandbox_pool is None:
            attempt = state.get_attempt(attempt_id)
            if attempt is not None and not attempt.synthetic and not preserve:
                try:
                    ArtifactWriter.cleanup_attempt_staging(attempt.workdir)
                except ValueError:
                    pass
            self._notify_status()
            return
        if not self.config.sandbox_cleanup and not preserve:
            state.record_cleanup(attempt_id, ok=True, detail="cleanup disabled by policy")
        else:
            result = sandbox_pool.release(attempt_id, remove=not preserve)
            if result is not None:
                state.record_cleanup(attempt_id, ok=result.ok, detail=result.stderr or ("preserved" if preserve else "removed"))
                attempt = state.get_attempt(attempt_id)
                if attempt is not None:
                    challenge = state.get_challenge(attempt.challenge_id)
                    if challenge is not None:
                        self._emit_sandbox_stopped(state, challenge, attempt, result.ok, result.stderr, preserve=preserve)
        self._notify_status()
        # DockerSandboxPool owns scrub + host teardown for non-preserved
        # attempts.  In particular, a preserved failed container keeps its
        # exact staging evidence and is never passed to ArtifactWriter here.

    def _emit_sandbox_stopped(
        self,
        state: LocalState,
        challenge: Challenge,
        attempt: Attempt,
        ok: bool,
        detail: str,
        *,
        preserve: bool,
    ) -> None:
        """Publish one standard sandbox release result, then its legacy alias."""
        message = detail or ("preserved" if preserve else "removed")
        payload = {"ok": ok, "remove_requested": not preserve}
        self._emit(
            state,
            challenge,
            "SANDBOX_STOPPED",
            attempt=attempt,
            message=message,
            payload=payload,
            fenced=False,
        )
        # Keep prior event names for local consumers while the local
        # vocabulary migrates to SANDBOX_STOPPED.
        self._emit(
            state,
            challenge,
            "SANDBOX_CLEANUP" if ok else "SANDBOX_CLEANUP_FAILED",
            attempt=attempt,
            message=message,
            payload=payload,
            fenced=False,
        )

    def _abort_attempt_sandbox(self, attempt_id: str, state: LocalState) -> None:
        self._effective_strategy_by_attempt.pop(attempt_id, None)
        sandbox_pool = self._sandbox_by_attempt.pop(attempt_id, None)
        if sandbox_pool is not None:
            result = sandbox_pool.release(attempt_id, remove=True)
            if result is not None:
                state.record_cleanup(attempt_id, ok=result.ok, detail=result.stderr or "removed")
                attempt = state.get_attempt(attempt_id)
                if attempt is not None:
                    challenge = state.get_challenge(attempt.challenge_id)
                    if challenge is not None:
                        self._emit_sandbox_stopped(state, challenge, attempt, result.ok, result.stderr, preserve=False)

    def _flush_outbox(self, state: LocalState) -> None:
        """Retire locally committed events without publishing a shared ledger.

        SQLite is the sole runtime source of truth.  Keeping the transactional
        outbox rows acknowledged preserves existing migrations and avoids an
        ever-growing pending queue on upgraded nodes.
        """
        for record in state.pending_outbox():
            state.mark_outbox_published(record.event.id)

    # --- prompt/context integration ---------------------------------------------------

    def _initial_solve_plan(
        self,
        context: ChallengeContext,
        challenge: Challenge,
        findings: list[str],
        failures: list[str],
        summary: dict[str, object] | None = None,
    ) -> SolvePlan:
        """Produce the contracts that the scheduler actually executes.

        The injected boundary is intentionally synchronous: a persistent Sol
        session adapter can resume its own backend session and return the next
        strict plan without teaching the scheduler about a particular Codex
        transport.  The built-in plan is a category-aware bootstrap, not the
        old score-zero/easy race.
        """
        if self._planner_plan_factory is not None:
            plan = self._planner_plan_factory(
                context, tuple(findings), tuple(failures), dict(summary or {}),
            )
            if not isinstance(plan, SolvePlan):
                raise PrerequisiteError("planner plan factory must return a SolvePlan")
            return plan
        return self._bootstrap_solve_plan(challenge)

    def _enqueue_session_generation(
        self,
        intake: IntakeChallenge,
        state: LocalState,
        writer: ArtifactWriter,
        challenge: Challenge,
        *,
        require_live_leader: bool = True,
    ) -> tuple[PlannedAttempt, ...]:
        """Ask the persistent Sol controller for one generation of branches."""
        session = state.get_or_create_challenge_session(
            challenge.id, leader_model="gpt-5.6-sol", leader_profile="sol_xhigh",
            reasoning_effort="max",
        )
        findings, failures, commands = self._local_evidence(state, challenge.id)
        context = self._build_challenge_context(
            intake, state, challenge, findings=findings, failures=failures, commands=commands,
        )
        if self._planner_plan_factory is None and require_live_leader:
            leader = RaceAttempt.session_leader(
                session.id, category=context.category,
            )
            return (PlannedAttempt(
                intake, state, writer, leader, session_id=session.id,
                is_session_leader=True,
            ),)
        previous_profile = state.get_problem_profile(challenge.id)
        profile = ProblemClassifier().classify(
            challenge.category,
            ({"kind": "description", "value": challenge.description or ""},
             {"kind": "files", "value": " ".join(context.files)},
             *({"kind": "finding", "value": item} for item in findings[-20:])),
        )
        tactical_plan = default_planner_registry().plan(profile)
        state.upsert_problem_profile(challenge.id, asdict(profile))
        state.append_event(self._event(
            challenge, "classification.updated" if previous_profile else "problem.classified",
            message=f"classified as {profile.category}.{profile.subtype}",
            payload={"profile": asdict(profile), "planner_id": tactical_plan.planner_id,
                     "fallback_used": tactical_plan.fallback_used},
        ))
        # Keep the callback signature transport-independent while exposing the
        # durable session summary to a resumed Sol adapter.
        solve_plan = self._initial_solve_plan(
            context, challenge, findings, failures, dict(session.summary_state),
        )
        state.checkpoint_challenge_session(
            challenge.id,
            execution_contract=asdict(solve_plan),
            summary_state={
                **dict(session.summary_state),
                "findings": findings[-20:], "failures": failures[-20:],
                "reviewed_findings": findings[-20:],
                "commands": commands[-20:], "last_generation": session.generation + 1,
            },
            advance_generation=True,
        )
        contract_race = RacePlan.from_solve_plan(
            solve_plan, category=context.category, session_id=session.id,
        )
        attempts = contract_race.attempts
        ordered = StrategyReranker().rerank(attempts, findings=findings, failures=failures)
        ordered = tuple(sorted(
            ordered, key=lambda item: item.contract.execution.priority if item.contract is not None else 0,
            reverse=True,
        ))
        tasks: list[PlannedAttempt] = []
        for race_attempt in ordered:
            contract = race_attempt.contract
            if contract is None:
                continue
            durable = state.upsert_contract_task(ContractTask(
                id=stable_id(session.id, f"g{session.generation + 1}:{contract.id}", prefix="task_"),
                session_id=session.id, challenge_id=challenge.id,
                branch=f"g{session.generation + 1}:{contract.id}",
                role=self._contract_session_role(contract),
                objective=contract.objective,
                backend=contract.execution.backend,
                model_profile=contract.execution.model_profile,
                reasoning_effort=contract.execution.reasoning_effort,
                prompt_family=contract.execution.prompt_family,
                timeout_sec=contract.execution.timeout_sec,
                tool_strategy=contract.execution.tool_strategy,
                priority=contract.execution.priority,
                success_criteria=(contract.success_condition,),
                deliverables=(contract.handoff,), failure_handoff=contract.stop_condition,
            ))
            tasks.append(PlannedAttempt(
                intake, state, writer, race_attempt,
                session_id=session.id, contract_task_id=durable.id,
            ))
        return tuple(tasks)

    def _materialize_solve_plan(
        self, leader_task: PlannedAttempt, challenge: Challenge, solve_plan: SolvePlan,
    ) -> tuple[PlannedAttempt, ...]:
        """Persist strict Sol output and turn it into schedulable branches."""
        session = leader_task.state.get_challenge_session(challenge.id)
        if session is None:
            raise KeyError(f"missing challenge session: {challenge.id}")
        findings, failures, _ = self._local_evidence(leader_task.state, challenge.id)
        previous_profile = leader_task.state.get_problem_profile(challenge.id)
        evidence = ({"kind": "description", "value": challenge.description or ""},
                    *({"kind": "finding", "value": item} for item in findings[-20:]))
        profile = ProblemClassifier().classify(challenge.category, evidence)
        profile_payload = asdict(profile)
        leader_task.state.upsert_problem_profile(challenge.id, profile_payload)
        tactical_plan = default_planner_registry().plan(profile)
        leader_task.state.append_event(self._event(
            challenge, "classification.updated" if previous_profile else "problem.classified",
            message=f"classified as {profile.category}.{profile.subtype}",
            payload={"profile": profile_payload, "planner_id": tactical_plan.planner_id,
                     "fallback_used": tactical_plan.fallback_used},
        ))
        leader_task.state.checkpoint_challenge_session(
            challenge.id, execution_contract=asdict(solve_plan),
            summary_state={**dict(session.summary_state),
                           "problem_profile": profile_payload,
                           "tactical_planner": tactical_plan.planner_id,
                           "findings": findings[-20:], "failures": failures[-20:],
                           "reviewed_findings": findings[-20:],
                           "branch_handoffs": [
                               item.result_summary for item in
                               leader_task.state.list_contract_tasks(session.id)[-12:]
                               if item.result_summary
                           ],
                           "last_generation": session.generation + 1},
            advance_generation=True,
        )
        race = RacePlan.from_solve_plan(
            solve_plan, category=challenge.category, session_id=session.id,
        )
        attempts = StrategyReranker().rerank(
            race.attempts,
            findings=findings, failures=failures,
        )
        attempts = tuple(sorted(
            attempts, key=lambda item: item.contract.execution.priority if item.contract is not None else 0,
            reverse=True,
        ))
        materialized: list[PlannedAttempt] = []
        for race_attempt in attempts:
            contract = race_attempt.contract
            assert contract is not None
            durable = leader_task.state.upsert_contract_task(ContractTask(
                id=stable_id(session.id, f"g{session.generation + 1}:{contract.id}", prefix="task_"),
                session_id=session.id, challenge_id=challenge.id,
                branch=f"g{session.generation + 1}:{contract.id}",
                role=self._contract_session_role(contract),
                objective=contract.objective, success_criteria=(contract.success_condition,),
                backend=contract.execution.backend,
                model_profile=contract.execution.model_profile,
                reasoning_effort=contract.execution.reasoning_effort,
                prompt_family=contract.execution.prompt_family,
                timeout_sec=contract.execution.timeout_sec,
                tool_strategy=contract.execution.tool_strategy,
                priority=contract.execution.priority,
                deliverables=(contract.handoff,), failure_handoff=contract.stop_condition,
            ))
            materialized.append(replace(
                leader_task, race_attempt=race_attempt,
                contract_task_id=durable.id, is_session_leader=False,
            ))
        return tuple(materialized)

    @staticmethod
    def _contract_session_role(contract: ExecutionContract) -> str:
        role = getattr(contract, "session_role", None)
        if isinstance(role, str) and role:
            return role
        legacy = getattr(contract, "worker", None)
        if isinstance(legacy, str) and legacy:
            return legacy
        raise PrerequisiteError("execution contract has no session role")

    @staticmethod
    def _bootstrap_solve_plan(challenge: Challenge) -> SolvePlan:
        category = challenge.category.casefold()
        missing_score = challenge.score is None
        hard = (challenge.score or 0) >= 500 or (missing_score and category in {"pwn", "rev", "crypto"})
        easy = not missing_score and (challenge.score or 0) <= 200
        worker_order = (
            ("sol_high", "terra_high", "luna_medium") if hard
            else (("luna_medium", "terra_high") if easy else ("terra_high", "luna_medium"))
        )
        objectives = {
            "sol_high": "Own the core solve path, resolve the hardest conceptual fork, and leave a reproducible solver or exploit handoff.",
            "terra_high": "Implement and execute the strongest concrete attack hypothesis; preserve a runnable solver or exploit and exact replay command.",
            "luna_medium": "Answer one narrow branch-selecting question quickly with tool output that eliminates or promotes an attack path.",
        }
        contracts = tuple(
            ExecutionContract(
                id=chr(ord("A") + index), worker=worker,
                exclusive_scope=f"{category} bootstrap branch {index + 1}: {worker}",
                objective=objectives[worker],
                first_decisive_action=(
                    "Inspect the original inputs and execute the cheapest command that distinguishes the leading attack paths."
                ),
                success_condition="Produce a decisive finding or a runnable replay artifact that advances the challenge toward a real flag.",
                stop_condition="Stop only after the assigned hypothesis is disproved with captured evidence or the replay artifact succeeds.",
                handoff="Return findings, failed assumptions, artifact paths, and exact replay commands to the persistent Sol challenge session.",
            )
            for index, worker in enumerate(worker_order)
        )
        return SolvePlan(
            solve_target="Obtain and reproduce the real challenge flag",
            representation={
                "crypto": "algebra", "pwn": "state", "rev": "validation",
                "web": "protocol", "cloud": "protocol", "forensics": "file-flow",
            }.get(category, "file-flow"),
            mode="parallel" if len(contracts) > 1 else "direct",
            contracts=contracts,
            replan_when="new decisive result or two contracts terminate",
            escalate_when="two distinct branches fail or conceptual ambiguity remains",
        )

    def _build_challenge_context(
        self,
        intake: IntakeChallenge,
        state: LocalState,
        challenge: Challenge,
        *,
        findings: list[str],
        failures: list[str],
        commands: list[str],
    ) -> ChallengeContext:
        files: list[str] = []
        if intake.workspace.is_dir():
            for path in sorted(intake.workspace.rglob("*")):
                if path.is_file() and not path.is_symlink():
                    files.append("/workspace/" + str(path.relative_to(intake.workspace)))
                if len(files) >= 100:
                    break
        knowledge = self._retrieve_knowledge(
            challenge, findings=findings, failures=failures, strategy_seed=challenge.id,
        )
        supervisor_hints = self._supervisor_hints(state, challenge.id)
        return ChallengeContextBuilder().build(
            {"id": challenge.id, "name": challenge.name, "category": challenge.category,
             "score": challenge.score, "description": challenge.description or "",
             "remote": challenge.remote or "",
             "hints": tuple(item for item in ((challenge.hint or ""), *supervisor_hints) if item)},
            files=files, findings=tuple(findings[:12]) + tuple(knowledge),
            failed_strategies=failures[:12], failed_commands=commands[:12],
        )

    def _render_prompt(self, task: PlannedAttempt, challenge: Challenge) -> str:
        findings, failures, commands = self._local_evidence(task.state, challenge.id)
        context = self._build_challenge_context(
            task.intake, task.state, challenge,
            findings=findings, failures=failures, commands=commands,
        )
        if task.is_session_leader:
            session = task.state.get_challenge_session(challenge.id)
            prior = task.state.list_contract_tasks(session.id) if session is not None else ()
            contracts = tuple(
                f"{item.branch}:{item.status.value}:{item.result_summary or ''}" for item in prior[-12:]
            )
            return CategoryPlanner().render(
                context,
                session_id=session.id if session is not None else task.session_id or "",
                session_summary=(
                    json.dumps(dict(session.summary_state), ensure_ascii=False, sort_keys=True)
                    if session is not None else ""
                ),
                findings=findings[-20:], failures=failures[-20:], contracts=contracts,
            )
        session = task.state.get_challenge_session(challenge.id)
        session_tasks = task.state.list_contract_tasks(session.id) if session is not None else ()
        summary = dict(session.summary_state) if session is not None else {}
        replay_artifacts = tuple(
            f"/work/handoff/{item.id}/{Path(evidence).name}"
            for item in session_tasks
            for evidence in item.evidence_ids
            if evidence != item.assigned_attempt_id
        )
        handoff = SessionHandoff(
            session_summary=json.dumps(summary, ensure_ascii=False, sort_keys=True),
            validated_findings=tuple(str(item) for item in summary.get("reviewed_findings", ())),
            replay_artifacts=replay_artifacts,
            branch_handoffs=tuple(
                item.result_summary for item in session_tasks[-12:] if item.result_summary
            ),
        )
        rendered = PromptRenderer().render(context, task.race_attempt, handoff=handoff)
        selected = (task.race_attempt.contract.execution.tool_strategy
                    if task.race_attempt.contract is not None else "fast_recon")
        effective = self._effective_strategy_by_attempt.get(task.race_attempt.attempt_id, selected)
        if effective != selected:
            rendered += (f"\n\nRuntime capability override: execute {effective}, not {selected}. "
                         "The fallback harness and authoritative manifest are already materialized in /work.")
        return rendered

    @staticmethod
    def _local_evidence(state: LocalState, challenge_id: str) -> tuple[list[str], list[str], list[str]]:
        findings: list[str] = []
        failures: list[str] = []
        commands: list[str] = []
        for event in state.list_events(challenge_id=challenge_id)[-80:]:
            content = str(event.payload.get("content") or event.message or "").strip()
            if not content:
                continue
            if event.type == "FINDING":
                findings.append(content)
            elif event.type in {"FAIL", "FAILED"}:
                failures.append(content)
            elif event.type == "ACTION":
                commands.append(content)
        return findings, failures, commands

    def _supervisor_hints(self, state: LocalState, challenge_id: str) -> tuple[str, ...]:
        hints = [
            str(event.payload.get("hint") or event.message or "").strip()
            for event in state.list_events(challenge_id=challenge_id)
            if event.type == "SUPERVISOR_HINT"
        ]
        return tuple(dict.fromkeys(item for item in hints if item))[-3:]

    def _retrieve_knowledge(
        self,
        challenge: Challenge,
        *,
        findings: Iterable[str],
        failures: Iterable[str],
        strategy_seed: str,
    ) -> tuple[str, ...]:
        """Query the persistent local index; never build an in-memory RAG copy.

        A tiny source fingerprint adjacent to the index detects additions,
        removals, and mtime/size changes.  ``KnowledgeIndex.refresh`` already
        atomically replaces its SQLite and JSONL artifacts; the metadata is
        written atomically afterwards, so an interrupted metadata write only
        causes one safe future refresh.
        """
        root = self.config.knowledge_root
        try:
            if not root.exists():
                root = KnowledgeIndex.initialize_default_root(root)
            if root.is_symlink() or not root.is_dir():
                return ()
            with self._knowledge_lock:
                fingerprint = _knowledge_source_fingerprint(root)
                indexes = root / "indexes"
                database = indexes / "knowledge.sqlite"
                chunks = indexes / "chunks.jsonl"
                metadata = indexes / ".ctf-os-runtime-sources.json"
                stored = _read_knowledge_metadata(metadata)
                if stored != fingerprint or not database.is_file() or not chunks.is_file():
                    KnowledgeIndex.refresh(root)
                    _write_knowledge_metadata(metadata, _knowledge_source_fingerprint(root))
                index = KnowledgeIndex.open_root(root)
            try:
                profile = ProblemClassifier().classify(
                    challenge.category,
                    ({"kind": "description", "value": challenge.description or ""},
                     *({"kind": "finding", "value": item} for item in tuple(findings)[-12:])),
                )
                routing_metadata = " ".join(filter(None, (
                    strategy_seed, f"subtype:{profile.subtype}",
                    f"platform:{profile.platform}", f"architecture:{profile.architecture}",
                )))
                rows = index.query(
                    category=challenge.category,
                    challenge_name=challenge.name,
                    description=challenge.description or "",
                    findings=tuple(findings)[-12:],
                    failures=tuple(failures)[-12:],
                    strategy_seed=routing_metadata,
                    limit=self.config.knowledge_top_k,
                )
                return tuple(
                    f"[knowledge source={item.source} id={item.id} selected_for="
                    f"{profile.category}/{profile.subtype} strategy={strategy_seed or 'unspecified'}] "
                    f"{item.content[:MAX_KNOWLEDGE_PROMPT_CHARS]}"
                    for item in rows
                )
            finally:
                index.close()
        except (OSError, ValueError, json.JSONDecodeError):
            # Knowledge is strictly local optional context.  A bad or
            # temporarily unavailable index must not make an authorized local
            # sandbox attempt fall back to network retrieval or crash.
            return ()

    # --- event helpers ----------------------------------------------------------------

    def _event(self, challenge: Challenge, event_type: str, *, attempt: Attempt | None = None, message: str | None = None,
               payload: dict[str, object] | None = None, synthetic: bool = False) -> Event:
        event_payload = dict(payload or {})
        if synthetic:
            event_payload["synthetic"] = True
        return Event(team_id=self.config.team_id, member=self.config.member_name, contest=challenge.contest,
                     type=event_type, category=challenge.category, challenge=challenge.name, challenge_id=challenge.id,
                     challenge_key=challenge.challenge_key,
                     attempt_id=attempt.id if attempt else None, message=message, payload=event_payload)

    @staticmethod
    def _attempt_session_payload(attempt: Attempt) -> dict[str, object]:
        return {
            key: value
            for key, value in (("session_id", attempt.session_id), ("resume_id", attempt.resume_id))
            if value is not None
        }

    def _recovery_event(self, event_type: str, attempt_id: str, challenge_id: str, fencing_token: int) -> Event:
        return Event(
            team_id=self.config.team_id, member=self.config.member_name, contest=self.config.contest_name,
            type=event_type, challenge_id=challenge_id, attempt_id=attempt_id,
            message="attempt lease expired; local recovery requeued challenge" if event_type == "QUEUED" else "attempt lease expired; worker stopped",
            payload={"recovery": True, "fencing_token": fencing_token},
        )

    def _emit(self, state: LocalState, challenge: Challenge, event_type: str, *, attempt: Attempt | None = None,
              message: str | None = None, payload: dict[str, object] | None = None, synthetic: bool = False, publish: bool = True,
              fenced: bool | None = None) -> Event:
        event = self._event(challenge, event_type, attempt=attempt, message=message, payload=payload, synthetic=synthetic)
        require_fence = bool(attempt is not None and not synthetic) if fenced is None else fenced
        if require_fence:
            assert attempt is not None
            state.append_fenced_event(event, attempt_id=attempt.id, owner=self._owner, fencing_token=_fence(attempt))
        else:
            state.append_event(event)
        self._evaluate_replanning(state, challenge, event)
        if publish:
            self._flush_outbox(state)
        return event

    def _evaluate_replanning(self, state: LocalState, challenge: Challenge, event: Event) -> None:
        """Apply structured rules synchronously, within the scheduler's current tick."""
        if not self.config.tactical_engine_enabled or event.type.startswith("rule."):
            return
        session = state.get_challenge_session(challenge.id)
        if session is None:
            return
        raw_rules: list[object] = []
        for key in ("replan_when", "escalate_when"):
            value = session.execution_contract.get(key, ())
            if isinstance(value, (list, tuple)):
                raw_rules.extend(value)
            elif value:
                raw_rules.append(value)
        if not raw_rules:
            return
        try:
            rules = RuleParser().parse_many(raw_rules)
        except RuleValidationError as exc:
            state.append_event(self._event(
                challenge, "rule.validation_failed", message=str(exc),
                payload={"safe_fallback": "legacy no-progress escalation"},
            ))
            return
        key = (challenge.id, session.generation)
        engine = self._replan_engines.get(key)
        if engine is None:
            engine = ReplanEngine(rules)
            self._replan_engines[key] = engine
        canonical = {
            "FINDING": "finding.created", "ARTIFACT": "artifact.created",
            "LOOP_DETECTED": "loop.detected", "PLATEAU_DETECTED": "plateau.detected",
            "FLAG_CANDIDATE": "finding.created", "VERIFIER_REJECTED": "verifier.result",
            "FAILED": "contract.failed",
        }.get(event.type, event.type)
        payload = dict(event.payload)
        content = str(payload.get("content") or event.message or "")
        finding_kind = payload.get("finding_kind") or payload.get("kind")
        if finding_kind is None and "libc" in content.casefold() and "leak" in content.casefold():
            finding_kind = "libc_leak"
        if finding_kind is None and "ssrf" in content.casefold() and any(
            marker in content.casefold() for marker in ("confirm", "internal", "endpoint")
        ):
            finding_kind = "ssrf_confirmed"
        semantic_event = {
            **event.to_dict(), **payload, "type": canonical,
            "finding": {"kind": finding_kind, "confidence": payload.get("confidence", 0.8)},
            "contract_id": payload.get("contract_id"),
        }
        scheduler = LocalSchedulerRuleState(state, challenge.id)
        for execution in engine.evaluate(semantic_event, scheduler):
            if not execution.matched:
                continue
            if not state.record_rule_fire(rule_id=execution.rule_id, event_id=event.id,
                                          challenge_id=challenge.id, before=execution.before,
                                          after=execution.after):
                continue
            cancelled_attempts: list[str] = []
            if self._active_pool is not None:
                for contract in execution.after.get("contracts", ()):
                    if not isinstance(contract, dict) or contract.get("status") != "CANCELLED":
                        continue
                    attempt_id = contract.get("assigned_attempt_id")
                    handle = self._active_pool.get(str(attempt_id)) if attempt_id else None
                    if handle is not None and not handle.done:
                        handle.cancel()
                        cancelled_attempts.append(str(attempt_id))
            matched = self._event(challenge, "rule.matched", message=execution.rule_id,
                                  payload={"parent_event": event.id, "rule_id": execution.rule_id})
            state.append_event(matched)
            state.append_event(self._event(
                challenge, "rule.executed", message=execution.rule_id,
                payload={"parent_event": matched.id, "rule_id": execution.rule_id,
                         "actions": list(execution.executed_actions),
                         "before": dict(execution.before), "after": dict(execution.after)},
            ))
            before_ids = {
                str(item.get("id")) for item in execution.before.get("contracts", ())
                if isinstance(item, dict) and item.get("id")
            }
            for item in execution.after.get("contracts", ()):
                if not isinstance(item, dict) or not item.get("id") or str(item["id"]) in before_ids:
                    continue
                self._rule_created_task_ids.append((challenge.id, str(item["id"])))
            if cancelled_attempts:
                state.append_event(self._event(
                    challenge, "contracts.cancelled", message="semantic rule cancelled active local attempts",
                    payload={"rule_id": execution.rule_id, "attempt_ids": cancelled_attempts},
                ))

    def _drain_rule_spawn_requests(
        self, plans: deque[PlannedAttempt], intake: tuple[IntakeChallenge, ...],
    ) -> bool:
        """Turn rule-created durable contracts into real local scheduler work."""
        if not self._rule_created_task_ids:
            return False
        by_challenge = {item.challenge.id: item for item in intake}
        changed = False
        for _ in range(len(self._rule_created_task_ids)):
            challenge_id, task_id = self._rule_created_task_ids.popleft()
            intake_item = by_challenge.get(challenge_id)
            if intake_item is None:
                continue
            state = LocalState.for_config(self.config, contest_name=intake_item.manifest.name)
            durable = state.get_contract_task(task_id)
            if (durable is None or durable.status is not ContractTaskStatus.PENDING
                    or task_id in self._scheduled_contract_task_ids):
                continue
            dependencies = [state.get_contract_task(item) for item in durable.depends_on]
            if dependencies and any(item is None or item.status is not ContractTaskStatus.SUCCEEDED for item in dependencies):
                self._rule_created_task_ids.append((challenge_id, task_id))
                continue
            execution = BranchExecutionSpec(
                backend=durable.backend, model_profile=durable.model_profile or "terra_high",
                reasoning_effort=durable.reasoning_effort or "high",
                prompt_family=durable.prompt_family, timeout_sec=durable.timeout_sec or 1200,
                tool_strategy=durable.tool_strategy, priority=durable.priority,
            )
            contract = ExecutionContract(
                id=durable.branch, worker=execution.model_profile,
                session_role=durable.role, exclusive_scope=f"semantic rule contract {durable.branch}",
                objective=durable.objective, first_decisive_action="consume parent-approved handoff artifacts",
                success_condition="produce a verified candidate and replay evidence",
                stop_condition=durable.failure_handoff or "stop after bounded failure",
                handoff=", ".join(durable.deliverables) or "replay artifact", execution=execution,
            )
            race = RacePlan.from_solve_plan(
                SolvePlan("semantic rule continuation", "state", "direct", (contract,), "new evidence", "bounded failure"),
                category=intake_item.challenge.category, session_id=durable.session_id,
            )
            writer = ArtifactWriter(self.config.output_root, intake_item.manifest.name)
            plans.append(PlannedAttempt(
                intake_item, state, writer, race.attempts[0],
                session_id=durable.session_id, contract_task_id=durable.id,
            ))
            self._scheduled_contract_task_ids.add(task_id)
            changed = True
        return changed

    def _emit_operator(
        self, state: LocalState, event_type: str, message: str, *, payload: dict[str, object] | None = None,
    ) -> Event:
        """Record an operator-visible local recovery result without control semantics."""
        event = Event(
            team_id=self.config.team_id,
            member=self.config.member_name,
            contest=self.config.contest_name,
            type=event_type,
            message=message,
            payload=payload or {},
        )
        state.append_event(event)
        self._flush_outbox(state)
        self._notify_status()
        return event

    def _notify_status(self) -> None:
        """Best-effort observer hook; it has no scheduler or lease authority."""
        callback = self._status_callback
        if callback is None:
            return
        try:
            callback()
        except Exception:
            # A TTY redraw must never turn into a worker/control-plane failure.
            return


def _synthetic_mock_candidates(output: str, *, challenge_id: str, attempt_id: str) -> list[FlagCandidate]:
    import re
    values = re.findall(r"SYNTHETIC\{MOCK_[A-F0-9]+\}", output)
    return [FlagCandidate(challenge_id=challenge_id, attempt_id=attempt_id, value=value, source="synthetic-mock-worker", synthetic=True)
            for value in dict.fromkeys(values)]


def _fence(attempt: Attempt) -> int:
    if attempt.fencing_token is None:
        raise PrerequisiteError(f"attempt {attempt.id} has no active fencing token")
    return attempt.fencing_token


def _bounded_hint(value: str | None) -> str | None:
    """Normalize one supervisor response into bounded prompt-safe guidance."""
    if not isinstance(value, str):
        return None
    lines: list[str] = []
    for line in value.splitlines():
        stripped = line.strip()
        if stripped.startswith("[SUPERVISOR_HINT]"):
            stripped = stripped.removeprefix("[SUPERVISOR_HINT]").strip()
        elif stripped.startswith("[HINT]"):
            stripped = stripped.removeprefix("[HINT]").strip()
        if stripped:
            lines.append(stripped)
    normalized = " ".join(lines).strip()
    return normalized[:MAX_SUPERVISOR_HINT_CHARS] or None


def _artifact_type(path: Path) -> str:
    name = path.name.casefold()
    if name.endswith((".pcap", ".pcapng")):
        return "pcap"
    if name.endswith((".py", ".sh")):
        return "replay_script"
    if "transcript" in name or name.endswith(".jsonl"):
        return "transcript"
    if "crash" in name or name.startswith("core"):
        return "crash_signature"
    if name.endswith(".json"):
        return "structured_result"
    return "file"


def _redact_event_text(value: str) -> str:
    return re.sub(r"(?i)(token|secret|password|api[_-]?key)\s*[:=]\s*\S+", r"\1=<redacted>", value)


def _knowledge_source_fingerprint(root: Path) -> list[dict[str, object]]:
    """List safe Markdown source mtimes without indexing generated output."""
    result: list[dict[str, object]] = []
    for path in sorted(root.rglob("*.md")):
        try:
            relative = path.relative_to(root)
            if "indexes" in relative.parts or path.is_symlink() or not path.is_file():
                continue
            resolved = path.resolve(strict=True)
            resolved.relative_to(root.resolve(strict=True))
            details = path.stat()
        except (OSError, ValueError):
            continue
        result.append({"path": relative.as_posix(), "mtime_ns": details.st_mtime_ns, "size": details.st_size})
    return result


def _read_knowledge_metadata(path: Path) -> list[dict[str, object]] | None:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    if not isinstance(raw, list) or any(not isinstance(item, dict) for item in raw):
        return None
    return [dict(item) for item in raw]


def _write_knowledge_metadata(path: Path, fingerprint: list[dict[str, object]]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".ctf-os-runtime-", suffix=".json", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(fingerprint, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
