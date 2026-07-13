from __future__ import annotations

from collections import deque
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event as ThreadEvent
import time

import pytest
import yaml

from ctf_os.application import LocalApplication, PlannedAttempt
from ctf_os.artifact_writer import ArtifactWriter
from ctf_os.config import AppConfig, default_config_mapping
from ctf_os.contest_parser import ContestManifest
from ctf_os.intake import IntakeChallenge
from ctf_os.local_state import LocalState
from ctf_os.local_worker_pool import LocalWorkerPool, WorkerHandle
from ctf_os.local_event_state import LocalEventState
from ctf_os.models import Attempt, AttemptStatus, Challenge, ChallengeStatus, Event
from ctf_os.sandbox.docker_cli import CommandResult, DockerCli
from ctf_os.solver_engine.knowledge import KnowledgeIndex
from ctf_os.solver_engine.race_plan import RacePlan


def _config(
    tmp_path: Path,
    *,
    owned: list[str] | None = None,
    routing: bool = False,
    hint_after: float = 1,
    loop_check: float = 1,
) -> AppConfig:
    raw = default_config_mapping("Demo")
    raw["member"]["owned_categories"] = owned or ["web"]
    raw["sandbox"]["enabled"] = False
    raw["coordinator"] = {
        "hint_after_sec": hint_after,
        "loop_check_sec": loop_check,
        "hint_timeout_sec": 2,
    }
    if routing:
        raw["model_routing"] = {
            "enabled": True,
            "config_path": str(Path("config/model-routing.yaml").resolve()),
        }
        raw["worker_policy"]["stop_new_workers_on_quota_warning"] = True
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return AppConfig.from_file(path)


def _challenge(state: LocalState, *, contest: str = "Demo", category: str = "web", name: str = "login") -> Challenge:
    return state.upsert_challenge(Challenge(contest=contest, category=category, name=name, score=100, description="template expression"))


def _running_attempt(app: LocalApplication, state: LocalState, challenge: Challenge, *, seconds_old: float = 20) -> Attempt:
    state.transition_challenge_status(challenge.id, ChallengeStatus.QUEUED)
    attempt = Attempt(
        id="attempt-live", challenge_id=challenge.id, profile="recon_fast", role="recon",
        backend="mock", workdir="/work", status=AttemptStatus.RUNNING,
        started_at=datetime.now(timezone.utc) - timedelta(seconds=seconds_old),
    )
    claim = state.claim_attempt(
        attempt, owner=app._owner, lease_seconds=60, max_workers_total=2, max_workers_per_challenge=2,
    )
    assert claim.granted and claim.fencing_token
    attempt = replace(attempt, lease_owner=app._owner, fencing_token=claim.fencing_token)
    state.upsert_attempt(attempt, owner=app._owner, fencing_token=claim.fencing_token)
    state.transition_challenge_status(
        challenge.id, ChallengeStatus.RUNNING, attempt_id=attempt.id,
        owner=app._owner, fencing_token=attempt.fencing_token,
    )
    return attempt


def _task(tmp_path: Path, config: AppConfig, state: LocalState, challenge: Challenge) -> PlannedAttempt:
    manifest_path = tmp_path / "incoming" / "Demo" / "contest.md"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text("# placeholder\n", encoding="utf-8")
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    return PlannedAttempt(
        IntakeChallenge(ContestManifest(name="Demo", path=manifest_path, challenges=(challenge,)), challenge, workspace, ()),
        state, ArtifactWriter(config.output_root, "Demo"), RacePlan.for_score(100).attempts[0],
    )


def test_pause_resume_are_local_fenced_actions_and_pause_is_idempotent(tmp_path: Path) -> None:
    config = _config(tmp_path)
    app = LocalApplication(config)
    state = LocalState(config.state_path())
    challenge = _challenge(state)
    attempt = _running_attempt(app, state, challenge)
    pool = LocalWorkerPool(max_workers_total=1, max_workers_per_challenge=1)
    handle = pool.submit(attempt, lambda cancel: cancel.wait(1))
    app._active_pool = pool

    paused = app.pause_challenge("login")

    assert paused.challenge.status is ChallengeStatus.PAUSED
    assert paused.cancelled_attempt_ids == (attempt.id,)
    assert handle.cancel_event.is_set()
    assert [event.type for event in state.list_events(challenge_id=challenge.id)] == ["PAUSED"]
    ledger = state.list_events(challenge_id=challenge.id)
    assert [(event.member, event.type) for event in ledger] == [(config.member_name, "PAUSED")]
    merged = LocalEventState.from_events(ledger).get(challenge.id)
    assert merged and merged.status == "PAUSED" and not merged.running_members
    assert app.pause_challenge(challenge.slug).already_in_target_state

    resumed = app.resume_challenge(challenge.id)
    assert resumed.challenge.status is ChallengeStatus.QUEUED
    assert [event.type for event in state.list_events(challenge_id=challenge.id)] == ["PAUSED", "RESUMED"]
    pool.wait_all(1)


def test_out_of_process_pause_releases_only_the_exact_local_attempt_container(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.raw["sandbox"]["enabled"] = True
    calls: list[list[str]] = []

    def runner(argv):
        calls.append(list(argv))
        if argv[1:3] == ["ps", "-aq"]:
            return CommandResult(tuple(argv), stdout="exact-local-container\n")
        return CommandResult(tuple(argv))

    app = LocalApplication(config, docker=DockerCli(runner=runner))
    state = LocalState(config.state_path())
    challenge = _challenge(state)
    attempt = _running_attempt(app, state, challenge)

    result = app.pause_challenge(challenge.name)

    assert result.cancelled_attempt_ids == ()
    assert result.released_container_ids == ("exact-local-container",)
    filters = calls[0]
    assert f"label=ctf-os.team_id={config.team_id}" in filters
    assert f"label=ctf-os.member={config.member_name}" in filters
    assert f"label=ctf-os.attempt_id={attempt.id}" in filters
    assert calls[1] == ["docker", "rm", "-f", "exact-local-container"]


def test_pause_resume_reject_foreign_nonowned_team_only_and_solved(tmp_path: Path) -> None:
    config = _config(tmp_path)
    app = LocalApplication(config)
    state = LocalState(config.state_path())
    foreign = _challenge(state, contest="Other", name="foreign")
    nonowned = _challenge(state, category="pwn", name="pwn-only")
    solved = _challenge(state, name="solved")
    state.transition_challenge_status(solved.id, ChallengeStatus.QUEUED)
    attempt = _running_attempt(app, state, solved)
    candidate_event = Event(team_id=config.team_id, member=config.member_name, contest="Demo", type="FLAG_CANDIDATE", challenge_id=solved.id, attempt_id=attempt.id)
    from ctf_os.models import FlagCandidate
    candidate = FlagCandidate(challenge_id=solved.id, attempt_id=attempt.id, value="FLAG{DONE}")
    state.record_candidate(candidate, candidate_event, owner=app._owner, fencing_token=attempt.fencing_token)
    state.solve_verified(
        candidate_id=candidate.id, flag=candidate.value,
        event=Event(team_id=config.team_id, member=config.member_name, contest="Demo", type="SOLVED", challenge_id=solved.id, attempt_id=attempt.id),
        owner=app._owner, fencing_token=attempt.fencing_token,
    )
    for target, message in ((foreign.name, "foreign"), (nonowned.name, "non-owned"), (solved.name, "SOLVED"), ("team-only", "team-only")):
        with pytest.raises(ValueError, match=message):
            app.pause_challenge(target)
    with pytest.raises(ValueError, match="non-owned"):
        app.resume_challenge(nonowned.name)
    queued = _challenge(state, name="queued")
    state.transition_challenge_status(queued.id, ChallengeStatus.QUEUED)
    with pytest.raises(ValueError, match="not PAUSED"):
        app.resume_challenge(queued.name)


def test_supervisor_transitions_persists_hint_and_injects_it_into_next_prompt(tmp_path: Path) -> None:
    config = _config(tmp_path, hint_after=1, loop_check=0.01)
    now = [0.0]
    app = LocalApplication(
        config,
        supervisor_hint_factory=lambda request: "[SUPERVISOR_HINT] Stop template guessing; establish one local escaping baseline.",
        monotonic_clock=lambda: now[0],
    )
    state = LocalState(config.state_path())
    challenge = _challenge(state)
    attempt = _running_attempt(app, state, challenge)
    task = _task(tmp_path, config, state, challenge)
    active = {attempt.id: (WorkerHandle(attempt), task)}
    supervisors = {}

    assert app._monitor_supervision(active, supervisors)
    for _ in range(100):
        if app._drain_supervisor_hints(supervisors, LocalWorkerPool(max_workers_total=1, max_workers_per_challenge=1), deque()):
            break
        time.sleep(0.01)
    else:
        pytest.fail("injected supervisor hint did not finish")

    stored = state.get_challenge(challenge.id)
    assert stored and stored.status is ChallengeStatus.RUNNING
    events = state.list_events(challenge_id=challenge.id)
    assert [event.type for event in events] == ["STUCK", "HINTING", "SUPERVISOR_HINT", "HINT_RESUMED"]
    prompt = app._render_prompt(task, stored)
    assert "Stop template guessing; establish one local escaping baseline." in prompt


def test_supervisor_loop_check_and_quota_cooling_do_not_hot_loop(tmp_path: Path) -> None:
    config = _config(tmp_path, routing=True, hint_after=60, loop_check=10)
    now = [0.0]
    app = LocalApplication(config, monotonic_clock=lambda: now[0])
    state = LocalState(config.state_path())
    challenge = _challenge(state)
    attempt = _running_attempt(app, state, challenge, seconds_old=120)
    task = _task(tmp_path, config, state, challenge)
    state.set_model_cooldown("gpt-5.6-sol", reason="quota exhausted", seconds=300)
    active = {attempt.id: (WorkerHandle(attempt), task)}
    supervisors = {}

    assert app._monitor_supervision(active, supervisors)
    assert not supervisors
    assert state.get_challenge(challenge.id).status is ChallengeStatus.STUCK
    types = [event.type for event in state.list_events(challenge_id=challenge.id)]
    assert types == ["STUCK", "SUPERVISOR_UNAVAILABLE"]
    now[0] = 11.0
    assert not app._monitor_supervision(active, supervisors)
    assert [event.type for event in state.list_events(challenge_id=challenge.id)] == types


def test_application_uses_persistent_rag_only_refreshing_changed_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _config(tmp_path)
    root = tmp_path / "knowledge"
    (root / "playbooks").mkdir(parents=True)
    source = root / "playbooks" / "web.md"
    source.write_text("# Web\n\nTemplate expression baseline and SSTI validation.\n", encoding="utf-8")
    config.raw["knowledge"] = {"root": "knowledge", "top_k": 2}
    app = LocalApplication(config)
    state = LocalState(config.state_path())
    challenge = _challenge(state)
    original = KnowledgeIndex.refresh.__func__
    calls: list[Path] = []

    def tracked(cls, target, **kwargs):
        calls.append(Path(target))
        return original(cls, target, **kwargs)

    monkeypatch.setattr(KnowledgeIndex, "refresh", classmethod(tracked))
    first = app._retrieve_knowledge(challenge, findings=("template expression",), failures=("guessing",), strategy_seed="baseline")
    second = app._retrieve_knowledge(challenge, findings=("template expression",), failures=("guessing",), strategy_seed="baseline")
    assert first and second and "knowledge/playbooks/web.md" in first[0]
    assert len(calls) == 1
    source.write_text("# Web\n\nTemplate expression baseline changed for SSTI validation.\n", encoding="utf-8")
    app._retrieve_knowledge(challenge, findings=("template expression",), failures=(), strategy_seed="baseline")
    assert len(calls) == 2
    assert (root / "indexes" / "knowledge.sqlite").is_file()
    assert (root / "indexes" / ".ctf-os-runtime-sources.json").is_file()


def test_readme_documents_only_the_manual_workbench_operator_flow() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    assert "ctf-os intake" in readme
    assert "ctf-os solve NBB" in readme
    assert "대회 전체 자동 queue/scheduler" in readme
    assert "CTFd polling" in readme
    assert "별도 TUI는 없습니다" in readme
    assert "실제 제출은" in readme
