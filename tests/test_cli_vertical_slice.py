from __future__ import annotations

from pathlib import Path

import yaml

from ctf_os.cli import _cleanup_local_containers, main
from ctf_os.artifact_writer import ArtifactWriter
from ctf_os.config import AppConfig, default_config_mapping
from ctf_os.doctor import run_doctor
from ctf_os.local_state import CURRENT_SCHEMA_VERSION, LocalState
from ctf_os.models import Attempt, Challenge
from ctf_os.sandbox.docker_cli import CommandResult, DockerCli, RecordingCommandRunner
from ctf_os.sandbox.exec import execute_attempt_command


def _write_config(tmp_path: Path, *, sandbox_enabled: bool = False) -> AppConfig:
    raw = default_config_mapping("Demo")
    raw["sandbox"]["enabled"] = sandbox_enabled
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return AppConfig.from_file(path)


def test_config_paths_are_relative_to_config_and_invalid_mode_is_rejected(tmp_path: Path) -> None:
    config = _write_config(tmp_path)
    assert config.incoming_root == tmp_path / "incoming"
    assert config.output_contest_dir() == tmp_path / "output" / "Demo"

    raw = default_config_mapping("Demo")
    raw["mode"] = "central_executor"
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    try:
        AppConfig.from_file(path)
    except ValueError as exc:
        assert "local_node" in str(exc)
    else:
        raise AssertionError("invalid execution mode was accepted")


def test_init_does_not_overwrite_manifest_without_force(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    assert main(["init", "Demo", "--config", str(config_path)]) == 0
    manifest = tmp_path / "incoming" / "Demo" / "contest.md"
    original = manifest.read_text(encoding="utf-8")

    assert main(["init", "Demo", "--config", str(config_path)]) == 2
    assert manifest.read_text(encoding="utf-8") == original


def test_state_migrate_is_idempotent_and_uses_configured_local_database(tmp_path: Path, capsys) -> None:
    config = _write_config(tmp_path)
    assert main(["state", "migrate", "--config", str(config.path)]) == 0
    assert config.state_path().is_file()
    assert f"schema v{CURRENT_SCHEMA_VERSION}" in capsys.readouterr().out

    assert main(["state", "migrate", "--config", str(config.path)]) == 0
    assert "migrated local state" in capsys.readouterr().out


def test_sandbox_exec_maps_local_attempt_to_docker_argv_and_cleanup_is_scoped(tmp_path: Path) -> None:
    config = _write_config(tmp_path)
    state = LocalState(config.state_path())
    challenge = state.upsert_challenge(Challenge(contest="Demo", category="web", name="login"))
    state.transition_challenge_status(challenge.id, "QUEUED")
    staging = ArtifactWriter(config.output_root, "Demo").create_attempt_staging()
    workdir = staging.workdir
    from ctf_os.sandbox.container import build_container_name
    name = build_container_name(config.team_id, challenge.contest, challenge.name, "attempt-direct")
    attempt = Attempt(id="attempt-direct", challenge_id=challenge.id, profile="recon_fast", role="recon", backend="codex_cli",
                      workdir=str(workdir), container_name=name)
    claim = state.claim_attempt(attempt, owner="owner", lease_seconds=30, max_workers_total=1, max_workers_per_challenge=1)
    assert claim.granted and claim.fencing_token
    from dataclasses import replace
    attempt = replace(attempt, status="RUNNING", lease_owner="owner", fencing_token=claim.fencing_token)
    state.upsert_attempt(attempt, owner="owner", fencing_token=claim.fencing_token)
    state.transition_challenge_status(challenge.id, "RUNNING", attempt_id=attempt.id, owner="owner", fencing_token=claim.fencing_token)
    runner = RecordingCommandRunner()
    result = execute_attempt_command(config, attempt.id, "file /workspace/chall", docker=DockerCli(runner=runner))
    assert result.ok
    assert runner.calls == [["docker", "exec", "--user", "ctf", "-w", "/work", name, "file", "/workspace/chall"]]

    calls: list[list[str]] = []
    def cleanup_runner(argv: list[str]) -> CommandResult:
        calls.append(argv)
        return CommandResult(tuple(argv), stdout="cid\n" if argv[1:3] == ["ps", "-aq"] else "")
    assert _cleanup_local_containers(config, all_containers=False, docker=DockerCli(runner=cleanup_runner)) == ["cid"]
    assert "label=ctf-os.team_id=demo-team" in calls[0]
    assert "label=ctf-os.member=local" in calls[0]
    assert "label=ctf-os.contest=Demo" in calls[0]


def test_doctor_is_mock_safe_when_sandbox_is_disabled(tmp_path: Path) -> None:
    config = _write_config(tmp_path, sandbox_enabled=False)
    report = run_doctor(config.path, which=lambda _: None)
    assert report.exit_code == 0
    assert any(check.name == "docker sandbox" and check.ok for check in report.checks)
