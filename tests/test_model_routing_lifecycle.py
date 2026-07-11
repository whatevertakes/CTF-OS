from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event as ThreadEvent
from types import SimpleNamespace

import yaml
import pytest

from ctf_os.application import LocalApplication, PlannedAttempt
from ctf_os.artifact_writer import ArtifactWriter
from ctf_os.config import AppConfig, default_config_mapping
from ctf_os.contest_parser import ContestManifest
from ctf_os.intake import IntakeChallenge
from ctf_os.local_state import LocalState
from ctf_os.local_worker_pool import LocalWorkerPool
from ctf_os.models import Attempt, AttemptStatus, Challenge, ChallengeStatus
from ctf_os.sandbox.docker_cli import CommandResult
from ctf_os.solver_engine.codex_cli_backend import CodexExecResult
from ctf_os.solver_engine.race_plan import RacePlan


ROUTING_CONFIG = Path("config/model-routing.yaml").resolve()


class SequencedBackend:
    def __init__(self, results: list[CodexExecResult]) -> None:
        self.results = list(results)
        self.selections = []

    def run(self, request, **_kwargs):
        self.selections.append(request.selection)
        return self.results.pop(0)


def _app(tmp_path: Path, backend: SequencedBackend) -> tuple[AppConfig, LocalApplication]:
    raw = default_config_mapping("Demo")
    raw["model_routing"] = {"enabled": True, "config_path": str(ROUTING_CONFIG)}
    raw["worker_policy"].update({"cooldown_on_rate_limit_sec": 60, "max_workers_total": 1, "max_workers_per_challenge": 1})
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    config = AppConfig.from_file(path)
    return config, LocalApplication(config, codex_backend_factory=lambda **_kwargs: backend)


def _live_task(tmp_path: Path, app: LocalApplication, config: AppConfig):
    state = LocalState(config.state_path())
    challenge = state.upsert_challenge(Challenge(contest="Demo", category="web", name="login", score=1))
    state.transition_challenge_status(challenge.id, ChallengeStatus.QUEUED)
    manifest_path = tmp_path / "incoming" / "Demo" / "contest.md"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text("# placeholder\n", encoding="utf-8")
    manifest = ContestManifest(name="Demo", path=manifest_path, challenges=(challenge,))
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    race_attempt = RacePlan.for_score(1).attempts[0]
    task = PlannedAttempt(
        IntakeChallenge(manifest, challenge, workspace, ()), state,
        ArtifactWriter(config.output_root, "Demo"), race_attempt,
    )
    selection = app._select_model(state, challenge, race_attempt)
    assert selection is not None
    staging = task.writer.create_attempt_staging()
    attempt = Attempt(
        id="attempt-routing", challenge_id=challenge.id, profile=race_attempt.profile.name,
        role=race_attempt.profile.role, backend="codex_cli", workdir=str(staging.workdir),
        model=selection.model, model_profile=selection.profile, reasoning_effort=selection.reasoning_effort,
    )
    claim = state.claim_attempt(attempt, owner=app._owner, lease_seconds=30, max_workers_total=1, max_workers_per_challenge=1)
    assert claim.granted and claim.fencing_token
    attempt = replace(attempt, status=AttemptStatus.RUNNING, lease_owner=app._owner, fencing_token=claim.fencing_token)
    state.upsert_attempt(attempt, owner=app._owner, fencing_token=claim.fencing_token)
    state.transition_challenge_status(challenge.id, ChallengeStatus.RUNNING, attempt_id=attempt.id, owner=app._owner, fencing_token=claim.fencing_token)
    app._sandbox_by_attempt[attempt.id] = SimpleNamespace(
        broker=lambda _attempt_id: SimpleNamespace(running=True, socket_path=tmp_path / "broker.sock")
    )
    return state, challenge, task, attempt, selection


def test_structured_rate_limit_walks_one_bounded_configured_fallback_and_persists_it(tmp_path: Path) -> None:
    backend = SequencedBackend([
        CodexExecResult((), 1, "", "", rate_limited=True, failure_provenance="structured", failure_code="rate_limit_exceeded"),
        CodexExecResult((), 0, "done", "", token_usage=7),
    ])
    config, app = _app(tmp_path, backend)
    state, challenge, task, attempt, primary = _live_task(tmp_path, app, config)

    execution = app._execute_attempt(task, challenge, attempt, ThreadEvent(), mock_worker=False, selection=primary)

    assert execution.status == "completed" and execution.token_usage == 7
    assert [(item.profile, item.model, item.reasoning_effort) for item in backend.selections] == [
        ("luna_medium", "gpt-5.6-luna", "medium"),
        ("gpt55_medium", "gpt-5.5", "medium"),
    ]
    persisted = state.get_attempt(attempt.id)
    assert persisted and (persisted.model, persisted.model_profile, persisted.reasoning_effort) == (
        "gpt-5.5", "gpt55_medium", "medium"
    )
    events = {event.type: event for event in state.list_events(challenge_id=challenge.id)}
    assert events["MODEL_COOLDOWN"].payload["profile"] == "luna_medium"
    fallback = events["MODEL_FALLBACK"].payload
    assert fallback == {
        "from_model": "gpt-5.6-luna", "from_profile": "luna_medium", "from_reasoning_effort": "medium",
        "to_model": "gpt-5.5", "to_profile": "gpt55_medium", "to_reasoning_effort": "medium",
    }
    assert state.model_in_cooldown(primary.model, selection_key=primary.cooldown_key)


def test_solver_observation_http_429_never_creates_a_cooldown_or_fallback(tmp_path: Path) -> None:
    backend = SequencedBackend([
        CodexExecResult((), 0, "[OBSERVATION] target returned HTTP 429", ""),
    ])
    config, app = _app(tmp_path, backend)
    state, challenge, task, attempt, primary = _live_task(tmp_path, app, config)

    execution = app._execute_attempt(task, challenge, attempt, ThreadEvent(), mock_worker=False, selection=primary)

    assert execution.status == "completed"
    assert len(backend.selections) == 1
    assert not state.model_in_cooldown(primary.model, selection_key=primary.cooldown_key)
    assert not {event.type for event in state.list_events(challenge_id=challenge.id)} & {"MODEL_COOLDOWN", "MODEL_FALLBACK"}


def test_codex_result_session_and_resume_ids_are_persisted_while_the_lease_is_live(tmp_path: Path) -> None:
    backend = SequencedBackend([
        CodexExecResult((), 0, "done", "", session_id="session-123", resume_id="resume-456"),
    ])
    config, app = _app(tmp_path, backend)
    state, challenge, task, attempt, primary = _live_task(tmp_path, app, config)

    execution = app._execute_attempt(task, challenge, attempt, ThreadEvent(), mock_worker=False, selection=primary)

    assert (execution.session_id, execution.resume_id) == ("session-123", "resume-456")
    persisted = state.get_attempt(attempt.id)
    assert persisted and (persisted.session_id, persisted.resume_id) == ("session-123", "resume-456")


def test_sandbox_precreate_failure_never_emits_started_or_running_lifecycle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config, app = _app(tmp_path, SequencedBackend([]))
    state = LocalState(config.state_path())
    challenge = state.upsert_challenge(Challenge(contest="Demo", category="web", name="login", score=1))
    state.transition_challenge_status(challenge.id, ChallengeStatus.QUEUED)
    manifest_path = tmp_path / "incoming" / "Demo" / "contest.md"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text("# placeholder\n", encoding="utf-8")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    race_attempt = RacePlan.for_score(1).attempts[0]
    task = PlannedAttempt(
        IntakeChallenge(ContestManifest(name="Demo", path=manifest_path, challenges=(challenge,)), challenge, workspace, ()),
        state, ArtifactWriter(config.output_root, "Demo"), race_attempt,
    )

    def fail_precreate(*_args, **_kwargs):
        raise RuntimeError("sandbox precreate failed")

    monkeypatch.setattr(app, "_precreate_sandbox", fail_precreate)
    with pytest.raises(RuntimeError, match="sandbox precreate failed"):
        app._start_attempt(LocalWorkerPool(max_workers_total=1, max_workers_per_challenge=1), task, mock_worker=False)

    types = [event.type for event in state.list_events(challenge_id=challenge.id)]
    assert "CLAIMED" in types
    assert "SANDBOX_STARTED" not in types
    assert "RUNNING" not in types
    assert "WORKER_STARTED" not in types


def test_sandbox_release_failure_publishes_standard_stop_with_false_ok_payload(tmp_path: Path) -> None:
    config, app = _app(tmp_path, SequencedBackend([]))
    state = LocalState(config.state_path())
    challenge = state.upsert_challenge(Challenge(contest="Demo", category="web", name="login"))
    attempt = state.upsert_attempt(Attempt(
        id="attempt-release", challenge_id=challenge.id, profile="recon", role="recon",
        backend="codex_cli", workdir="/work", container_name="ctf-os-release",
    ))
    app._sandbox_by_attempt[attempt.id] = SimpleNamespace(
        release=lambda _attempt_id, *, remove: CommandResult(("docker", "rm", "ctf-os-release"), returncode=1, stderr="remove failed")
    )

    app._release_attempt(attempt.id, state, preserve=False)

    stopped = [event for event in state.list_events(challenge_id=challenge.id) if event.type == "SANDBOX_STOPPED"]
    assert len(stopped) == 1
    assert stopped[0].payload["ok"] is False
    assert stopped[0].payload["remove_requested"] is True
    assert [event.type for event in app.team_sync.merge()] == ["SANDBOX_STOPPED", "SANDBOX_CLEANUP_FAILED"]


def test_quota_class_cooldown_stops_new_launches_until_expiry(tmp_path: Path) -> None:
    backend = SequencedBackend([
        CodexExecResult((), 1, "", "", rate_limited=True, failure_provenance="structured", failure_code="usage_limit_exceeded"),
    ])
    config, app = _app(tmp_path, backend)
    state, challenge, task, attempt, primary = _live_task(tmp_path, app, config)

    execution = app._execute_attempt(task, challenge, attempt, ThreadEvent(), mock_worker=False, selection=primary)

    assert execution.status == "unavailable"
    assert len(backend.selections) == 1
    assert state.quota_warning_in_cooldown()
    assert app._select_model(state, challenge, task.race_attempt) is None
    unavailable = [event for event in state.list_events(challenge_id=challenge.id) if event.type == "MODEL_UNAVAILABLE"]
    assert unavailable and unavailable[-1].payload["quota_warning"] is True


def test_selection_cooldown_is_profile_aware_and_expiry_restores_primary(tmp_path: Path) -> None:
    now = datetime(2026, 7, 10, tzinfo=timezone.utc)
    state = LocalState(tmp_path / "state.db", clock=lambda: now)
    config, app = _app(tmp_path, SequencedBackend([]))
    router = config.model_router()
    easy = router.select(role="exploit", difficulty="easy", attempt_kind="exploit_fast")
    normal = router.select(role="exploit", difficulty="medium", attempt_kind="exploit_main")
    assert easy.model == normal.model == "gpt-5.6-terra"
    assert easy.cooldown_key != normal.cooldown_key

    state.set_model_cooldown(easy.model, selection_key=easy.cooldown_key, reason="rate limited", seconds=10, now=now)
    assert state.model_in_cooldown(easy.model, selection_key=easy.cooldown_key, now=now)
    assert not state.model_in_cooldown(normal.model, selection_key=normal.cooldown_key, now=now)
    assert not state.model_in_cooldown(easy.model, selection_key=easy.cooldown_key, now=now + timedelta(seconds=11))


def test_failed_local_attempt_threshold_promotes_next_route_to_explicit_sol_review(tmp_path: Path) -> None:
    config, app = _app(tmp_path, SequencedBackend([]))
    state = LocalState(config.state_path())
    challenge = state.upsert_challenge(Challenge(contest="Demo", category="web", name="login", score=1))
    state.transition_challenge_status(challenge.id, ChallengeStatus.QUEUED)
    for ident in ("failed-1", "failed-2"):
        state.upsert_attempt(Attempt(
            id=ident, challenge_id=challenge.id, profile=ident, role="recon", backend="codex_cli",
            workdir="/work", status=AttemptStatus.FAILED,
        ))

    selected = app._select_model(state, challenge, RacePlan.for_score(1).attempts[0])

    assert selected and (selected.profile, selected.model, selected.reasoning_effort) == (
        "sol_review", "gpt-5.6-sol", "xhigh"
    )
