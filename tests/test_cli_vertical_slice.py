from __future__ import annotations

from pathlib import Path
import shutil

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
    assert config.output_contest_dir() == tmp_path / "output" / "demo-team" / "local" / "Demo"

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


def test_init_creates_team_and_member_isolated_local_paths(tmp_path: Path) -> None:
    config_path = tmp_path / "sca_config.yaml"

    assert main([
        "init", "SCA CTF 2026", "--config", str(config_path),
        "--team-id", "sca-jiwoong-team", "--member", "jiwoong",
    ]) == 0

    config = AppConfig.from_file(config_path)
    assert config.team_id == "sca-jiwoong-team"
    assert config.member_name == "jiwoong"
    assert config.output_contest_dir() == tmp_path / "output" / "sca-jiwoong-team" / "jiwoong" / "SCA CTF 2026"
    assert "team_namespace" not in config.get_mapping("sync")
    assert "forensic" in config.owned_categories
    contest_root = tmp_path / "incoming" / "SCA CTF 2026"
    assert {
        path.name for path in contest_root.iterdir() if path.is_dir()
    } == {
        "pwn", "rev", "web", "crypto", "forensic", "forensics", "misc",
        "cloud", "mobile", "windows", "password", "osint", "hardware",
    }
    manifest = contest_root / "contest.md"
    manifest_text = manifest.read_text(encoding="utf-8")
    assert "category/challenge" in manifest_text
    assert "###" not in manifest_text

    assert main([
        "init", "SCA CTF 2026", "--config", str(config_path),
        "--team-id", "other-team", "--force",
    ]) == 2
    assert main([
        "init", "SCA CTF 2026", "--config", str(config_path),
        "--team-id", "sca-jiwoong-team", "--member", "someone-else", "--force",
    ]) == 2


def test_init_for_a_new_member_reuses_an_existing_contest_manifest(tmp_path: Path) -> None:
    first_config = tmp_path / "jiwoong.yaml"
    second_config = tmp_path / "jueon.yaml"
    assert main([
        "init", "SCA CTF 2026", "--config", str(first_config),
        "--team-id", "sca-jiwoong-team", "--member", "jiwoong",
    ]) == 0
    manifest = tmp_path / "incoming" / "SCA CTF 2026" / "contest.md"
    manifest.write_text("# SCA CTF 2026\n\n### web/login\n", encoding="utf-8")

    assert main([
        "init", "SCA CTF 2026", "--config", str(second_config),
        "--team-id", "sca-jiwoong-team", "--member", "jueon",
    ]) == 0

    assert manifest.read_text(encoding="utf-8") == "# SCA CTF 2026\n\n### web/login\n"
    assert all(
        (manifest.parent / category).is_dir()
        for category in (
            "pwn", "rev", "web", "crypto", "forensic", "forensics", "misc",
            "cloud", "mobile", "windows", "password", "osint", "hardware",
        )
    )
    second = AppConfig.from_file(second_config)
    assert second.output_contest_dir() == tmp_path / "output" / "sca-jiwoong-team" / "jueon" / "SCA CTF 2026"


def test_state_migrate_is_idempotent_and_uses_configured_local_database(tmp_path: Path, capsys) -> None:
    config = _write_config(tmp_path)
    assert main(["state", "migrate", "--config", str(config.path)]) == 0
    assert config.state_path().is_file()
    assert f"schema v{CURRENT_SCHEMA_VERSION}" in capsys.readouterr().out

    assert main(["state", "migrate", "--config", str(config.path)]) == 0
    assert "migrated local state" in capsys.readouterr().out


def test_copied_config_requires_member_and_split_team_output_suffix(tmp_path: Path, capsys) -> None:
    config_path = tmp_path / "team.yaml"
    raw = default_config_mapping(
        "Next CTF", team_id="four-person-team", member_name="alice"
    )
    config_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    assert main(["state", "migrate", "--config", str(config_path)]) == 0
    capsys.readouterr()

    # A teammate copied Alice's config and edited only member.name. Because
    # paths.output still names Alice, this would previously open Alice's DB.
    raw["member"]["name"] = "bob"
    raw["member"]["display_name"] = "bob"
    config_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    assert main(["state", "migrate", "--config", str(config_path)]) == 2
    error = capsys.readouterr().err
    assert "paths.output must end with 'four-person-team'/'bob'" in error
    assert "Do not delete or move the existing output" in error

    # The next contest temporarily splits the four-person team into two teams.
    # Updating the team fields but leaving the old output path is also refused.
    raw["member"]["name"] = "alice"
    raw["member"]["display_name"] = "alice"
    raw["contest"]["team_id"] = "split-team-a"
    config_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    assert main(["state", "migrate", "--config", str(config_path)]) == 2
    error = capsys.readouterr().err
    assert "paths.output must end with 'split-team-a'/'alice'" in error
    assert "use a new local config" in error

    # A properly isolated split-team config initializes an independent DB.
    split_path = tmp_path / "split-team-a.yaml"
    split = default_config_mapping(
        "Next CTF", team_id="split-team-a", member_name="alice"
    )
    split_path.write_text(yaml.safe_dump(split, sort_keys=False), encoding="utf-8")
    assert main(["state", "migrate", "--config", str(split_path)]) == 0
    split_config = AppConfig.from_file(split_path)
    assert split_config.state_path().is_file()


def test_doctor_rejects_a_database_copied_from_another_member(tmp_path: Path) -> None:
    alice_path = tmp_path / "local.team.alice.yaml"
    bob_path = tmp_path / "local.team.bob.yaml"
    for path, member in ((alice_path, "alice"), (bob_path, "bob")):
        raw = default_config_mapping("Demo", team_id="team", member_name=member)
        raw["sandbox"]["enabled"] = False
        path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")

    alice = AppConfig.from_file(alice_path)
    bob = AppConfig.from_file(bob_path)
    assert main(["state", "migrate", "--config", str(alice_path)]) == 0
    bob.state_path().parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(alice.state_path(), bob.state_path())

    report = run_doctor(bob.path, which=lambda _: None)
    identity = next(check for check in report.checks if check.name == "local state identity")
    assert not identity.ok and identity.required
    assert "database member.name is 'alice'" in identity.detail
    assert "config member.name is 'bob'" in identity.detail
    assert report.exit_code == 1


def test_doctor_checks_only_the_configured_contest_manifest(tmp_path: Path) -> None:
    config = _write_config(tmp_path, sandbox_enabled=False)
    old = config.incoming_contest_dir("Old CTF") / "contest.md"
    old.parent.mkdir(parents=True, exist_ok=True)
    old.write_text("this unrelated old manifest is invalid\n", encoding="utf-8")
    current = config.incoming_contest_dir() / "contest.md"
    current.parent.mkdir(parents=True, exist_ok=True)
    current.write_text("# 대회명: Demo\n\n### web/login\n- 점수: 1\n", encoding="utf-8")
    (current.parent / "web" / "login").mkdir(parents=True)
    (current.parent / "web" / "login" / "challenge.txt").write_text("ready\n", encoding="utf-8")

    report = run_doctor(config.path, which=lambda _: None)

    manifest_checks = [check for check in report.checks if check.name == "contest intake"]
    assert len(manifest_checks) == 1
    assert manifest_checks[0].ok
    assert str(current) in manifest_checks[0].detail
    assert "1 owned challenge(s) ready" in manifest_checks[0].detail
    assert all(str(old) not in check.detail for check in report.checks)
    assert report.exit_code == 0


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
    manifest = config.incoming_contest_dir() / "contest.md"
    manifest.parent.mkdir(parents=True)
    manifest.write_text("# 대회명: Demo\n\n### web/login\n- 설명: ready\n", encoding="utf-8")
    source = manifest.parent / "web" / "login"
    source.mkdir(parents=True)
    (source / "challenge.txt").write_text("ready\n", encoding="utf-8")
    report = run_doctor(config.path, which=lambda _: None)
    assert report.exit_code == 0
    assert any(check.name == "docker sandbox" and check.ok for check in report.checks)
