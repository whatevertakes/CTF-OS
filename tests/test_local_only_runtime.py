from pathlib import Path

import pytest
import yaml

from ctf_os.application import LocalApplication
from ctf_os.cli import _build_parser
from ctf_os.config import AppConfig, default_config_mapping
from ctf_os.doctor import run_doctor
from ctf_os.local_state import LocalState
from ctf_os.models import Challenge, ChallengeStatus


def _config(tmp_path: Path) -> AppConfig:
    raw = default_config_mapping("Demo", team_id="team", member_name="alice")
    raw["paths"]["incoming"] = str(tmp_path / "incoming")
    raw["paths"]["output"] = str(tmp_path / "output" / "team" / "alice")
    path = tmp_path / "config.yaml"
    return AppConfig(raw=raw, path=path)


def test_event_outbox_is_acknowledged_without_creating_sync_files(tmp_path: Path) -> None:
    config = _config(tmp_path)
    state = LocalState.for_config(config)
    challenge = state.upsert_challenge(Challenge(contest="Demo", category="web", name="one"))
    event = LocalApplication(config)._event(challenge, "QUEUED", message="local")
    state.transition_challenge_status(challenge.id, ChallengeStatus.QUEUED, event=event)

    LocalApplication(config)._flush_outbox(state)

    assert not state.pending_outbox()
    assert not (tmp_path / "sync").exists()
    assert [item.id for item in state.list_events()] == [event.id]


def test_sync_command_is_not_part_of_cli() -> None:
    with pytest.raises(SystemExit):
        _build_parser().parse_args(["sync", "merge"])


def test_doctor_does_not_require_or_create_sync_root(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.path.write_text(yaml.safe_dump(config.raw), encoding="utf-8")
    report = run_doctor(config.path)
    assert any(check.name == "config" and check.ok for check in report.checks)
    assert all("sync" not in check.name for check in report.checks)
