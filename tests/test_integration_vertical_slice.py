from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import yaml
import pytest

from ctf_os.application import LocalApplication
from ctf_os.config import AppConfig, default_config_mapping
from ctf_os.intake import IntakeError, extract_zip_safely
from ctf_os.local_event_bus import LocalEventBus
from ctf_os.local_state import LocalState
from ctf_os.merged_team_state import MergedTeamState
from ctf_os.models import Challenge, ChallengeStatus, Event, FlagCandidate
from ctf_os.sandbox.docker_cli import DockerCli, RecordingCommandRunner
from ctf_os.solver_engine.codex_cli_backend import CodexExecResult
from ctf_os.team_sync import TeamSync
from ctf_os.tui import render_tui


MANIFEST = """# 대회명: Demo

## 문제 목록

### web/login
- 점수: 100
- 설명: authorized local test challenge

### pwn/bof
- 점수: 300
- 설명: unowned
"""


def _config(tmp_path: Path, *, routing: bool = False, sandbox: bool = False) -> AppConfig:
    raw = default_config_mapping("Demo")
    raw["member"]["owned_categories"] = ["web"]
    raw["sandbox"]["enabled"] = sandbox
    raw["model_routing"]["enabled"] = routing
    if routing:
        route = tmp_path / "routing.yaml"
        route.write_text(
            "model_profiles:\n  selected:\n    model: gpt-5.6-terra\n    reasoning_effort: high\n"
            "default_roles:\n  recon: selected\n  exploit: selected\n  source: selected\n  fallback: selected\n"
            "model_policy:\n  easy:\n    recon_fast: selected\n    exploit_fast: selected\n",
            encoding="utf-8",
        )
        raw["model_routing"]["config_path"] = "routing.yaml"
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return AppConfig.from_file(path)


def _manifest(tmp_path: Path) -> Path:
    path = tmp_path / "incoming" / "Demo" / "contest.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(MANIFEST, encoding="utf-8")
    return path


def test_safe_zip_extraction_rejects_zip_slip_and_parse_filters_and_upserts(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _manifest(tmp_path)
    archive = tmp_path / "incoming" / "Demo" / "web" / "login.zip"
    archive.parent.mkdir(parents=True)
    with ZipFile(archive, "w", ZIP_DEFLATED) as bundle:
        bundle.writestr("app.py", "print('safe')\n")

    parsed = LocalApplication(config).parse()
    assert [item.challenge.name for item in parsed] == ["login"]
    assert (tmp_path / "incoming" / "Demo" / "workspace" / "web-login" / "app.py").is_file()
    state = LocalState(config.state_path())
    assert [challenge.name for challenge in state.list_challenges()] == ["login"]
    LocalApplication(config).parse()
    assert len(state.list_challenges()) == 1
    assert [event.type for event in TeamSync(config.sync_root, team_id=config.team_id, member=config.member_name).merge()] == ["CHALLENGE_SEEN", "QUEUED"]

    malicious = tmp_path / "bad.zip"
    with ZipFile(malicious, "w") as bundle:
        bundle.writestr("../escape", "no")
    with pytest.raises(IntakeError, match="unsafe ZIP member|escapes"):
        extract_zip_safely(malicious, tmp_path / "dest")


def test_mock_once_end_to_end_writes_synthetic_candidate_solved_event_and_artifacts(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _manifest(tmp_path)
    app = LocalApplication(config)
    report = app.run_once(mock_worker=True, auto_confirm_flags=True)
    assert report.synthetic and report.solved_challenges == 1
    synthetic_config = app._synthetic_config()
    state = LocalState(synthetic_config.state_path())
    challenge = state.list_challenges()[0]
    assert challenge.status is ChallengeStatus.SOLVED
    assert challenge.flag and challenge.flag.startswith("SYNTHETIC{")
    candidates = state.list_flag_candidates(challenge.id)
    assert candidates and candidates[0].verified
    output = synthetic_config.output_contest_dir() / challenge.slug
    assert "synthetic mock" in (output / "evidence.log").read_text(encoding="utf-8")
    assert "FINDING" in (output / "notes.md").read_text(encoding="utf-8")
    # Synthetic mock fixtures remain in their private SQLite/output namespace
    # and are never appended to any TeamSync member ledger.
    events = TeamSync(synthetic_config.sync_root, team_id=synthetic_config.team_id, member=synthetic_config.member_name).merge()
    assert not events
    assert "SYNTHETIC SOLVED:" in render_tui(synthetic_config, state, show_team=True)

    LocalApplication(config).parse()
    production_state = LocalState(config.state_path())
    production_challenge = production_state.list_challenges()[0]
    assert production_challenge.status is ChallengeStatus.QUEUED
    assert not production_state.list_flag_candidates(production_challenge.id)
    assert not [event for event in TeamSync(config.sync_root, team_id=config.team_id, member=config.member_name).merge() if event.type == "SOLVED"]


def test_nonmock_request_uses_automatic_model_route_and_never_uses_host_commands(tmp_path: Path) -> None:
    config = _config(tmp_path, routing=True, sandbox=True)
    _manifest(tmp_path)
    received = []
    class FakeCodex:
        def run(self, request, **kwargs):
            received.append(request)
            return CodexExecResult(
                tuple(), 0, "[FLAG_CANDIDATE] FLAG{REAL}", "",
                session_id="session-vertical", resume_id="resume-vertical",
            )
    docker = DockerCli(runner=RecordingCommandRunner())
    app = LocalApplication(config, docker=docker, codex_backend_factory=lambda **_: FakeCodex(), command_exists=lambda _: "/fake/codex")
    app.run_once(auto_confirm_flags=True)
    assert received and received[0].difficulty == "easy" and received[0].attempt_kind == "recon_fast"
    assert all("docker" == call[0] for call in docker.calls)
    sync = TeamSync(config.sync_root, team_id=config.team_id, member=config.member_name)
    ledger = LocalEventBus(sync.own_event_path, member=config.member_name).read()
    by_attempt: dict[str, list[str]] = {}
    for event in ledger:
        if event.attempt_id:
            by_attempt.setdefault(event.attempt_id, []).append(event.type)
            assert event.member == config.member_name
    assert by_attempt
    expected = ["CLAIMED", "SANDBOX_STARTED", "RUNNING", "SANDBOX_STOPPED"]
    for types in by_attempt.values():
        assert all(types.count(event_type) == 1 for event_type in expected)
        assert [types.index(event_type) for event_type in expected] == sorted(types.index(event_type) for event_type in expected)
    worker_stopped = [event for event in ledger if event.type == "WORKER_STOPPED"]
    assert worker_stopped
    assert all(
        event.payload.get("session_id") == "session-vertical"
        and event.payload.get("resume_id") == "resume-vertical"
        for event in worker_stopped
    )


def test_team_merged_state_has_solved_precedence_team_isolation_and_duplicate_warning(tmp_path: Path) -> None:
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    root = tmp_path / "sync"
    alpha = TeamSync(root, team_id="alpha", member="alice")
    alpha.append(Event(timestamp=now, team_id="alpha", member="alice", contest="Demo", type="RUNNING", challenge_id="c", challenge="login"))
    bob = TeamSync(root, team_id="alpha", member="bob")
    bob.append(Event(timestamp=now, team_id="alpha", member="bob", contest="Demo", type="RUNNING", challenge_id="c", challenge="login"))
    bob.append(Event(timestamp=now, team_id="alpha", member="bob", contest="Demo", type="SOLVED", challenge_id="c", challenge="login", payload={"flag": "FLAG{DONE}"}))
    TeamSync(root, team_id="beta", member="eve").append(Event(timestamp=now, team_id="beta", member="eve", contest="Demo", type="RUNNING", challenge_id="c", challenge="login"))
    merged = MergedTeamState.from_events(alpha.merge())
    status = merged.get("c")
    assert status and status.status == "SOLVED" and status.solved_flag == "FLAG{DONE}"
    assert status.duplicate_running is False  # bob's latest record is SOLVED
    duplicate = MergedTeamState.from_events([
        Event(timestamp=now, team_id="alpha", member="alice", contest="Demo", type="RUNNING", challenge_id="d"),
        Event(timestamp=now, team_id="alpha", member="bob", contest="Demo", type="RUNNING", challenge_id="d"),
    ])
    assert duplicate.get("d") and duplicate.get("d").duplicate_running


def test_tui_distinguishes_candidate_from_solved(tmp_path: Path, claimed_attempt) -> None:
    config = _config(tmp_path)
    state = LocalState(config.state_path())
    challenge = state.upsert_challenge(Challenge(contest="Demo", category="web", name="login"))
    state.transition_challenge_status(challenge.id, "QUEUED")
    attempt = claimed_attempt(state, challenge, owner="owner-a", attempt_id="attempt-a")
    state.transition_challenge_status(
        challenge.id, "RUNNING", attempt_id=attempt.id,
        owner=attempt.lease_owner, fencing_token=attempt.fencing_token,
    )
    candidate = FlagCandidate(challenge_id=challenge.id, attempt_id=attempt.id, value="FLAG{SOLVED}")
    event = Event(team_id="team", member="member", contest="Demo", type="FLAG_CANDIDATE", challenge_id=challenge.id, attempt_id=attempt.id)
    state.record_candidate(candidate, event, owner=attempt.lease_owner, fencing_token=attempt.fencing_token)
    assert "? FLAG{SOLVED}" in render_tui(config, state)
    state.transition_challenge_status(
        challenge.id, "VERIFYING", attempt_id=attempt.id,
        owner=attempt.lease_owner, fencing_token=attempt.fencing_token,
    )
    solved = Event(team_id="team", member="member", contest="Demo", type="SOLVED", challenge_id=challenge.id, attempt_id=attempt.id)
    state.solve_verified(candidate_id=candidate.id, flag="FLAG{SOLVED}", event=solved,
                         owner=attempt.lease_owner, fencing_token=attempt.fencing_token)
    assert "SOLVED: FLAG{SOLVED}" in render_tui(config, state)
