"""Local-only runtime orchestration with durable leases and streamed evidence."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import queue
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
from .models import Attempt, AttemptStatus, Challenge, ChallengeStatus, Event, FlagCandidate, utc_now
from .sandbox.broker import BrokerResponse, broker_transport_supported, send_broker_request
from .sandbox.container import SandboxScope, SandboxSpec
from .sandbox.docker_cli import DockerCli
from .sandbox.network_policy import parse_remote_endpoints, resolve_remote_endpoints
from .sandbox.pool import DockerSandboxPool
from .solver_engine.codex_cli_backend import CodexCliBackend, CodexExecRequest, CodexExecResult, CodexStreamRecord
from .solver_engine.context import ChallengeContextBuilder
from .solver_engine.knowledge import KnowledgeIndex
from .solver_engine.loop_detector import LoopDetector
from .solver_engine.mock_backend import MockBackend
from .solver_engine.parser import ActionObservationParser
from .solver_engine.prompt import PromptRenderer
from .solver_engine.race_plan import RaceAttempt, RacePlan
from .solver_engine.strategy_reranker import StrategyReranker
from .solver_engine.types import SolverEvent
from .solver_engine.verifier import Verifier
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
        monotonic_clock: Callable[[], float] = time.monotonic,
        _synthetic_namespace: bool = False,
    ) -> None:
        self.config = config
        self.docker = docker or DockerCli(command_timeout_sec=config.sandbox_command_timeout_sec)
        self._codex_backend_factory = codex_backend_factory
        self._command_exists = command_exists
        self._strict_isolation_probe = strict_isolation_probe
        self._supervisor_hint_factory = supervisor_hint_factory
        self._monotonic_clock = monotonic_clock
        self._synthetic_namespace = _synthetic_namespace
        self._sandbox_by_attempt: dict[str, DockerSandboxPool] = {}
        self._candidate_signals: queue.SimpleQueue[CandidateSignal] = queue.SimpleQueue()
        self._records_by_attempt: dict[str, deque[SolverEvent]] = {}
        self._loop_by_attempt: dict[str, LoopDetector] = {}
        self._candidate_values: set[tuple[str, str]] = set()
        self._candidate_artifact_retries: set[tuple[str, str]] = set()
        self._stream_lock = Lock()
        self._knowledge_lock = Lock()
        self._status_callback: Callable[[], None] | None = None
        self._active_pool: LocalWorkerPool | None = None
        self._last_supervision_check: dict[str, float] = {}
        self._last_supervisor_review: dict[str, float] = {}
        self._owner = f"{config.team_id}:{config.member_name}:{os.getpid()}:{uuid4().hex}"

    # --- intake / coordinator lifecycle ---------------------------------------------

    def parse(self) -> tuple[IntakeChallenge, ...]:
        """Discover exact-manifest owned challenges and queue only this node's work."""
        try:
            intake = tuple(
                replace(item, challenge=replace(
                    item.challenge,
                    challenge_key=f"{self.config.team_id}:{item.challenge.challenge_key}",
                ))
                for item in IntakeService(self.config).collect()
            )
        except (ContestParseError, IntakeError, PermissionError, OSError) as exc:
            raise IntakeBlockedError(f"queue blocked: contest.md intake failed: {exc}") from exc
        for item in intake:
            state = LocalState.for_config(
                self.config, contest_name=item.manifest.name
            )
            existing = state.get_challenge(item.challenge.id)
            challenge = state.upsert_challenge(item.challenge)
            if existing is None:
                self._emit(state, challenge, "CHALLENGE_SEEN", message="local manifest discovery")
            if challenge.status is ChallengeStatus.DISCOVERED:
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
                findings, failures, _commands = self._local_evidence(state, challenge.id)
                race_plan = RacePlan.for_score(challenge.score or 0, category=challenge.category)
                ordered = StrategyReranker().rerank(race_plan.attempts, findings=findings, failures=failures)
                plans.extend(PlannedAttempt(item, state, writer, race_attempt) for race_attempt in ordered)

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
                made_progress = self._monitor_supervision(active, supervisors) or made_progress
                made_progress = self._drain_supervisor_hints(supervisors, pool, plans) or made_progress

                # Look beyond a full challenge: another local challenge can
                # still use a free global lease slot.
                for _ in range(len(plans)):
                    task = plans.popleft()
                    challenge = task.state.get_challenge(task.intake.challenge.id)
                    if challenge is None or challenge.status is not ChallengeStatus.QUEUED:
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
                self._mark_exhausted_challenges_failed(plans, active, intake)
                self._flush_outbox(coordinator_state)
                self._notify_status()
                if (plans or active or supervisors) and not made_progress:
                    # This is notification waiting, not a supervisor retry
                    # loop.  Time-based supervisor checks are separately
                    # gated by ``loop_check_sec`` below.
                    pool.wait_for_change(min(0.25, self.config.loop_check_sec))

            self._flush_outbox(coordinator_state)
            return RunReport(len(intake), started, len(solved), mock_worker)
        except BaseException:
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
        if challenge is None or challenge.status not in {ChallengeStatus.QUEUED, ChallengeStatus.RUNNING}:
            return None
        selection: ModelSelection | None = None
        router: ModelRouter | None = None
        if mock_worker:
            model = "mock-synthetic"
        else:
            router = self.config.model_router()
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
                latest is None or latest.status not in {ChallengeStatus.QUEUED, ChallengeStatus.RUNNING}
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
        if self._promotion_applies(state, challenge, router=router):
            return router.select_promotion(role="supervisor")
        return router.select(
            role=race_attempt.profile.role,
            difficulty=RacePlan.for_score(challenge.score or 0).difficulty,
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
        scope = SandboxScope(self.config.team_id, self.config.member_name, challenge.contest, challenge.name,
                             challenge.id, challenge.challenge_key)
        sandbox_pool = DockerSandboxPool(
            scope=scope, workspace_root=self.config.incoming_contest_dir(challenge.contest),
            output_root=self.config.output_contest_dir(challenge.contest), docker=self.docker,
            max_containers=self.config.sandbox_max_containers,
        )
        memory, cpus = self.config.sandbox_limits
        staging = ArtifactWriter.staging_for_workdir(attempt.workdir)
        endpoints = resolve_remote_endpoints(parse_remote_endpoints(challenge.remote), allow_private=self.config.sandbox_allow_private_egress)
        container = sandbox_pool.precreate(SandboxSpec(
            scope=scope, attempt_id=attempt.id, workspace=task.intake.workspace,
            workdir=staging.workdir, artifacts=staging.artifacts,
            image=self.config.sandbox_image, memory=memory, cpus=cpus, endpoints=endpoints,
        ))
        self._sandbox_by_attempt[attempt.id] = sandbox_pool
        return replace(attempt, container_name=container.name)

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
            return AttemptExecution("\n".join(lines), result.status, True, records=self._records_snapshot(attempt.id))

        if not isinstance(selection, ModelSelection):
            raise PrerequisiteError("production attempt has no explicit model selection")
        router = self.config.model_router()
        backend = self._codex_backend_factory(command=self.config.codex_command, model_router=router) if self._codex_backend_factory else CodexCliBackend(command=self.config.codex_command, model_router=router)
        sandbox_pool = self._sandbox_by_attempt.get(attempt.id)
        broker = sandbox_pool.broker(attempt.id) if sandbox_pool is not None else None
        if broker is None or not broker.running:
            raise RuntimeError("attempt command broker is unavailable; refusing to start Codex")
        request = CodexExecRequest(
            workdir=Path(attempt.workdir), prompt=prompt, role=attempt.role,
            difficulty=RacePlan.for_score(challenge.score or 0).difficulty, attempt_kind=attempt.profile,
            broker_socket=broker.socket_path,
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
                replace(request, selection=candidate),
                timeout_sec=self.config.attempt_timeout_sec(attempt.profile, task.race_attempt.profile.max_runtime_sec),
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
        # A backend double may not invoke on_output.  Parse the returned text
        # too; the candidate dedupe key makes this harmless for real streaming.
        for line in output.splitlines():
            self._stream_line(task, challenge, attempt, line, synthetic=False)
        return AttemptExecution(
            output, status, False, token_usage=total_tokens,
            session_id=session_id, resume_id=resume_id,
            records=self._records_snapshot(attempt.id),
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
                    payload={"record_kind": record.kind, "content": record.content},
                )
                try:
                    task.state.append_fenced_event(
                        event, attempt_id=attempt.id, owner=self._owner, fencing_token=_fence(attempt),
                    )
                except StateTransitionError:
                    return
            shift = loop.observe(record.kind, record.content)
            if shift.shift_required:
                shift_record = SolverEvent(kind="shift", content=shift.reason)
                with self._stream_lock:
                    self._records_by_attempt.setdefault(attempt.id, deque(maxlen=MAX_WORKER_RECORDS)).append(shift_record)
                    snapshot = tuple(self._records_by_attempt[attempt.id])
                if synthetic:
                    task.writer.append_note(challenge, "shift", shift.reason)
                    self._emit(task.state, challenge, "SHIFT", attempt=attempt, message=shift.reason,
                               payload={"count": shift.count}, synthetic=True, publish=False)
                else:
                    try:
                        self._emit(
                            task.state, challenge, "LOOP_DETECTED", attempt=attempt, message=shift.reason,
                            payload={"count": shift.count}, publish=False,
                        )
                    except StateTransitionError:
                        return
            if not synthetic and record.kind == "artifact":
                # Candidate and artifact output can arrive in either order.
                # Requeue an unavailable candidate once its declaring record
                # appears instead of allowing a process-local dedupe set to
                # strand it permanently.
                for existing in task.state.list_flag_candidates(
                    challenge.id, attempt_id=attempt.id, verification_statuses=("CANDIDATE", "UNAVAILABLE"),
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
            candidate = replace(raw_candidate, synthetic=synthetic)
            key = (attempt.id, candidate.value)
            with self._stream_lock:
                if key in self._candidate_values:
                    continue
                self._candidate_values.add(key)
            event = self._event(challenge, "FLAG_CANDIDATE", attempt=attempt,
                                message="synthetic candidate" if synthetic else "streamed flag candidate detected",
                                payload={"flag": candidate.value}, synthetic=synthetic)
            try:
                task.state.record_candidate(candidate, event, owner=self._owner, fencing_token=_fence(attempt))
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
                    difficulty=RacePlan.for_score(request.challenge.score or 0).difficulty,
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

Challenge: {challenge.name} ({challenge.category}, score={challenge.score or 0})
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
            self._complete_solve(challenge.id, pool, pending, solved)
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
        self._emit(task.state, challenge, "VERIFYING", attempt=attempt, message="running explicit replay verification", publish=False)
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
                       message="no executable replay artifact was available", publish=False)
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
                       message=verification.reason, publish=False)
            return
        promoted = task.writer.promote_verified_artifacts(
            challenge, attempt_workdir=attempt.workdir,
            artifact_paths=verifier.declared_artifacts(
                records, attempt_workdir=attempt.workdir, challenge_artifacts=staging.artifacts,
            ), attempt_artifacts=staging.artifacts,
        )

        for path in promoted:
            self._emit(task.state, challenge, "ARTIFACT_WRITTEN", attempt=attempt, message=str(path), publish=False)
        solved_event = self._event(challenge, "SOLVED", attempt=attempt, message="replay verification succeeded",
                                   payload={"flag": candidate.value})
        task.state.solve_verified(candidate_id=candidate.id, flag=candidate.value, event=solved_event,
                                  owner=self._owner, fencing_token=_fence(attempt))
        self._complete_solve(challenge.id, pool, pending, solved)

    @staticmethod
    def _broker_exec(broker, attempt_id: str, argv: tuple[str, ...]) -> BrokerResponse:
        return send_broker_request(broker.socket_path, attempt_id=attempt_id, token=broker.token, argv=argv)

    @staticmethod
    def _complete_solve(challenge_id: str, pool: LocalWorkerPool, pending: deque[PlannedAttempt], solved: set[str]) -> None:
        solved.add(challenge_id)
        # This pool owns only current-node handles.  No teammate/container is
        # enumerated or signalled.
        pool.cancel_challenge(challenge_id)
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
            self._release_attempt(attempt.id, task.state, preserve=status is AttemptStatus.FAILED and self.config.preserve_failed_attempts)
            return

        execution: AttemptExecution = handle.result
        was_cancelled = handle.cancel_event.is_set()
        # A non-streaming backend result still receives the exact same
        # candidate path as a live stdout/stderr record.  This must happen
        # before finish_attempt deletes the lease, otherwise fenced candidate
        # verification would correctly reject the late write.
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
        self._release_attempt(attempt.id, task.state, preserve=status is AttemptStatus.FAILED and self.config.preserve_failed_attempts)

    def _mark_exhausted_challenges_failed(
        self, pending: deque[PlannedAttempt], active: dict[str, tuple[WorkerHandle, PlannedAttempt]], intake: tuple[IntakeChallenge, ...]
    ) -> None:
        pending_ids = {item.intake.challenge.id for item in pending}
        active_ids = {task.intake.challenge.id for _, task in active.values()}
        for item in intake:
            state = LocalState.for_config(
                self.config, contest_name=item.manifest.name
            )
            challenge = state.get_challenge(item.challenge.id)
            if challenge and challenge.status is ChallengeStatus.RUNNING and challenge.id not in pending_ids | active_ids:
                challenge = state.transition_challenge_status(challenge.id, ChallengeStatus.FAILED)
                self._emit(state, challenge, "FAILED", message="all local race attempts completed without a candidate")

    def _release_attempt(self, attempt_id: str, state: LocalState, *, preserve: bool) -> None:
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

    def _render_prompt(self, task: PlannedAttempt, challenge: Challenge) -> str:
        files: list[str] = []
        if task.intake.workspace.is_dir():
            for path in sorted(task.intake.workspace.rglob("*")):
                if path.is_file() and not path.is_symlink():
                    files.append("/workspace/" + str(path.relative_to(task.intake.workspace)))
                if len(files) >= 100:
                    break
        findings, failures, commands = self._local_evidence(task.state, challenge.id)
        knowledge = self._retrieve_knowledge(
            challenge, findings=findings, failures=failures, strategy_seed=task.race_attempt.strategy_seed,
        )
        supervisor_hints = self._supervisor_hints(task.state, challenge.id)
        context = ChallengeContextBuilder().build(
            {"id": challenge.id, "name": challenge.name, "category": challenge.category, "score": challenge.score or 0,
             "description": challenge.description or "", "remote": challenge.remote or "",
             "hints": tuple(item for item in ((challenge.hint or ""), *supervisor_hints) if item)},
            files=files, findings=tuple(findings[:12]) + tuple(knowledge), failed_strategies=failures[:12], failed_commands=commands[:12],
        )
        return PromptRenderer().render(context, task.race_attempt)

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
                rows = index.query(
                    category=challenge.category,
                    challenge_name=challenge.name,
                    description=challenge.description or "",
                    findings=tuple(findings)[-12:],
                    failures=tuple(failures)[-12:],
                    strategy_seed=strategy_seed,
                    limit=self.config.knowledge_top_k,
                )
                return tuple(
                    f"[knowledge source={item.source} id={item.id}] {item.content[:MAX_KNOWLEDGE_PROMPT_CHARS]}"
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
        if publish:
            self._flush_outbox(state)
        return event

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
