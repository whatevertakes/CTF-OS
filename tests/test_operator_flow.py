from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from threading import Event as ThreadEvent

import yaml

from ctf_os.cli import _render_sync_watch_update, _watch_readonly_tui, main
from ctf_os.config import AppConfig, default_config_mapping
from ctf_os.local_state import LocalState
from ctf_os.merged_team_state import MergedTeamState
from ctf_os.models import Attempt, AttemptStatus, Challenge, ChallengeStatus, Event, FlagCandidate
from ctf_os.team_sync import TeamSync
from ctf_os.tui import render_tui


def _config(tmp_path: Path) -> AppConfig:
    raw = default_config_mapping("Demo")
    raw["sandbox"]["enabled"] = False
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return AppConfig.from_file(path)


def _manifest(config: AppConfig) -> None:
    path = config.incoming_contest_dir() / "contest.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# 대회명: Demo\n\n### web/login\n- 점수: 100\n", encoding="utf-8")


def test_mock_once_renders_the_synthetic_namespace_without_team_sync_publish(tmp_path: Path, capsys) -> None:
    config = _config(tmp_path)
    _manifest(config)

    assert main([
        "run", "--once", "--mock-worker", "--auto-confirm-flags", "--config", str(config.path),
    ]) == 0

    output = capsys.readouterr().out
    assert "SYNTHETIC_SOLVED" in output
    assert "SYNTHETIC SOLVED:" in output
    assert output.count("SYNTHETIC_SOLVED") == 1
    assert not TeamSync(config.sync_root, team_id=config.team_id, member=config.member_name).merge()


def test_mock_run_status_callback_observes_running_attempt_and_streamed_finding(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _manifest(config)
    from ctf_os.application import LocalApplication

    synthetic_config = LocalApplication(config)._synthetic_config()
    app = LocalApplication(synthetic_config, _synthetic_namespace=True)
    snapshots: list[tuple[bool, bool]] = []

    def observe() -> None:
        state = LocalState(synthetic_config.state_path())
        active = any(item.status is AttemptStatus.RUNNING for challenge in state.list_challenges() for item in state.list_attempts(challenge.id))
        finding = any(event.type == "FINDING" for challenge in state.list_challenges() for event in state.list_events(challenge_id=challenge.id))
        snapshots.append((active, finding))

    app.run_once(mock_worker=True, auto_confirm_flags=True, on_status=observe)

    assert any(active for active, _ in snapshots)
    assert any(finding for _, finding in snapshots)


def test_retry_requeues_only_failed_local_challenges_and_emits_event(tmp_path: Path, capsys) -> None:
    config = _config(tmp_path)
    state = LocalState(config.state_path())
    challenge = state.upsert_challenge(Challenge(contest="Demo", category="web", name="login"))
    state.transition_challenge_status(challenge.id, ChallengeStatus.QUEUED)
    state.transition_challenge_status(challenge.id, ChallengeStatus.FAILED)

    assert main(["retry", "login", "--config", str(config.path)]) == 0
    assert "requeued login" in capsys.readouterr().out
    assert state.get_challenge(challenge.id).status is ChallengeStatus.QUEUED
    assert [event.type for event in state.list_events(challenge_id=challenge.id)] == ["RETRY_QUEUED"]
    assert [event.type for event in TeamSync(config.sync_root, team_id=config.team_id, member=config.member_name).merge()] == ["RETRY_QUEUED"]
    assert main(["retry", "missing-team-only", "--config", str(config.path)]) == 2
    assert "not a local failed challenge" in capsys.readouterr().err


def test_retry_rejects_solved_foreign_and_team_only_challenges(tmp_path: Path, capsys) -> None:
    config = _config(tmp_path)
    state = LocalState(config.state_path())
    solved = state.upsert_challenge(Challenge(contest="Demo", category="web", name="solved"))
    state.transition_challenge_status(solved.id, ChallengeStatus.QUEUED)
    attempt = Attempt(id="attempt-solved", challenge_id=solved.id, profile="recon_fast", role="recon", backend="mock", workdir="/work")
    claim = state.claim_attempt(attempt, owner="owner", lease_seconds=30, max_workers_total=1, max_workers_per_challenge=1)
    assert claim.granted and claim.fencing_token
    state.transition_challenge_status(solved.id, ChallengeStatus.RUNNING, attempt_id=attempt.id, owner="owner", fencing_token=claim.fencing_token)
    state.transition_challenge_status(solved.id, ChallengeStatus.FLAG_CANDIDATE, attempt_id=attempt.id, owner="owner", fencing_token=claim.fencing_token)
    state.transition_challenge_status(solved.id, ChallengeStatus.VERIFYING, attempt_id=attempt.id, owner="owner", fencing_token=claim.fencing_token)
    candidate = FlagCandidate(challenge_id=solved.id, attempt_id=attempt.id, value="FLAG{DONE}")
    state.record_candidate(candidate, Event(team_id=config.team_id, member=config.member_name, contest="Demo", type="FLAG_CANDIDATE", challenge_id=solved.id, attempt_id=attempt.id), owner="owner", fencing_token=claim.fencing_token)
    state.solve_verified(candidate_id=candidate.id, flag=candidate.value,
                         event=Event(team_id=config.team_id, member=config.member_name, contest="Demo", type="SOLVED", challenge_id=solved.id, attempt_id=attempt.id),
                         owner="owner", fencing_token=claim.fencing_token)
    foreign = state.upsert_challenge(Challenge(contest="Other", category="web", name="foreign"))
    state.transition_challenge_status(foreign.id, ChallengeStatus.QUEUED)
    state.transition_challenge_status(foreign.id, ChallengeStatus.FAILED)
    TeamSync(config.sync_root, team_id=config.team_id, member="teammate").append(
        Event(team_id=config.team_id, member="teammate", contest="Demo", type="FAILED", category="rev", challenge="team-only", challenge_id="team-only")
    )

    for target, reason in (("solved", "SOLVED"), ("foreign", "foreign"), ("team-only", "team-only")):
        assert main(["retry", target, "--config", str(config.path)]) == 2
        assert reason in capsys.readouterr().err


def test_plain_tui_includes_attempt_node_team_and_operator_details(tmp_path: Path) -> None:
    config = _config(tmp_path)
    state = LocalState(config.state_path())
    challenge = state.upsert_challenge(Challenge(contest="Demo", category="web", name="login"))
    state.transition_challenge_status(challenge.id, ChallengeStatus.QUEUED)
    attempt = Attempt(
        id="attempt-live", challenge_id=challenge.id, profile="exploit_main", role="exploit", backend="codex_cli",
        model="gpt-5.6-terra", model_profile="terra", reasoning_effort="high", workdir="/work",
        container_name="ctf-os-login", status=AttemptStatus.RUNNING,
        started_at=datetime(2026, 7, 10, tzinfo=timezone.utc),
    )
    state.upsert_attempt(attempt)
    for type_, message, payload in (
        ("WORKER_STARTED", "attempt started", {"strategy_seed": "seed-123"}),
        ("FINDING", "libc leak found", {}),
        ("FAIL", "first offset failed", {}),
        ("MODEL_UNAVAILABLE", "all configured model selections are cooling down", {}),
        ("ORPHAN_CLEANUP", "removed stale container orphan-1", {}),
    ):
        state.append_event(Event(team_id=config.team_id, member=config.member_name, contest="Demo", type=type_, challenge_id=challenge.id,
                                 attempt_id=attempt.id, message=message, payload=payload))
    state.add_flag_candidate(FlagCandidate(challenge_id=challenge.id, attempt_id=attempt.id, value="FLAG{CANDIDATE}"))
    events = [
        Event(team_id=config.team_id, member="alice", contest="Demo", type="RUNNING", category="rev", challenge="team-only", challenge_id="team-only", attempt_id="a"),
        Event(team_id=config.team_id, member="bob", contest="Demo", type="RUNNING", category="rev", challenge="team-only", challenge_id="team-only", attempt_id="b"),
    ]

    rendered = render_tui(config, state, team_state=MergedTeamState.from_events(events), show_team=True)

    assert "local Codex active/max: 1/2" in rendered
    assert "sandbox active/max: 1/2" in rendered
    assert "all models cooling: all configured model selections are cooling down" in rendered
    assert "attempt attempt-live" in rendered
    assert "strategy_seed=seed-123" in rendered
    assert "latest_finding=libc leak found" in rendered
    assert "latest_fail=first offset failed" in rendered
    assert "flag_candidate=FLAG{CANDIDATE}" in rendered
    assert "container=RUNNING:ctf-os-login" in rendered
    assert "model=terra/gpt-5.6-terra/high" in rendered
    assert "team-only" in rendered and "| 2 " in rendered
    assert "OPERATOR ORPHAN_CLEANUP: removed stale container orphan-1" in rendered


def test_init_rejects_mismatched_config_contest_even_with_force(tmp_path: Path, capsys) -> None:
    config = _config(tmp_path)

    assert main(["init", "Other", "--force", "--config", str(config.path)]) == 2
    assert "contest.name" in capsys.readouterr().err
    assert not (tmp_path / "incoming" / "Other").exists()


def test_sync_watch_render_reports_merged_changes_and_recoverable_tail(tmp_path: Path) -> None:
    sync = TeamSync(tmp_path / "sync", team_id="team", member="alice")
    sync.append(Event(team_id="team", member="alice", contest="Demo", type="RUNNING", challenge="login", challenge_id="chal", attempt_id="a"))
    path = tmp_path / "sync" / "team" / "bob.events.jsonl"
    path.write_bytes(b'{"id":"interrupted"')

    rendered = _render_sync_watch_update(sync.merge_report())

    assert "MERGED chal: status=RUNNING running=alice" in rendered
    assert "DIAGNOSTIC incomplete_tail" in rendered


def test_readonly_tui_polls_only_local_state_and_stops_without_writes(tmp_path: Path) -> None:
    config = _config(tmp_path)
    stop = ThreadEvent()
    stop.set()
    output: list[str] = []

    assert _watch_readonly_tui(config, show_team=True, stop_event=stop, printer=output.append) == 0
    assert output and "CTF-OS Local Node" in output[0]
    assert not config.state_path().exists()
    assert not (config.sync_root / config.team_id).exists()
