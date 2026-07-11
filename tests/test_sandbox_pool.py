from __future__ import annotations

from pathlib import Path

import pytest

from ctf_os.artifact_writer import ArtifactWriter
from ctf_os.sandbox.container import SandboxScope, SandboxSpec
from ctf_os.sandbox.docker_cli import CommandResult, DockerCli, RecordingCommandRunner
from ctf_os.sandbox.pool import (
    DockerSandboxPool,
    PoolCapacityError,
    SandboxPathError,
    build_cleanup_filters,
)


@pytest.fixture
def scope() -> SandboxScope:
    return SandboxScope("team", "member", "contest", "challenge")


def make_spec(root: Path, scope: SandboxScope, staging, attempt_id: str = "a-1") -> SandboxSpec:
    return SandboxSpec(
        scope=scope,
        attempt_id=attempt_id,
        workspace=root / "incoming" / "challenge",
        workdir=staging.workdir,
        artifacts=staging.artifacts,
    )


def test_mock_runner_and_dry_run_never_contact_docker() -> None:
    runner = RecordingCommandRunner()
    docker = DockerCli(runner=runner)

    assert docker.daemon_available()
    assert docker.image_exists("ctf-os-sandbox:latest")
    assert runner.calls == [
        ["docker", "info", "--format", "{{.ServerVersion}}"],
        ["docker", "image", "inspect", "ctf-os-sandbox:latest"],
    ]

    dry = DockerCli(dry_run=True)
    assert dry.image_exists("not-on-this-host")
    assert dry.calls == [["docker", "image", "inspect", "not-on-this-host"]]


def test_pool_precreates_tracks_capacity_and_creates_helper(tmp_path: Path, scope: SandboxScope, sterile_staging_factory) -> None:
    root = tmp_path / "roots"
    spec = make_spec(root, scope, sterile_staging_factory())
    runner = RecordingCommandRunner()
    pool = DockerSandboxPool(
        scope=scope,
        workspace_root=root / "incoming",
        output_root=root / "output",
        docker=DockerCli(runner=runner),
        max_containers=1,
    )

    container = pool.precreate(spec)

    assert pool.active_attempt_ids == ("a-1",)
    assert (spec.workdir / "ctf-exec").is_file()
    assert pool.broker("a-1") is not None
    assert runner.calls[0][:3] == ["docker", "run", "-d"]
    with pytest.raises(PoolCapacityError):
        pool.precreate(make_spec(root, scope, sterile_staging_factory(), "a-2"))
    assert pool.release("a-1") is not None
    assert pool.active_count == 0
    assert runner.calls[-1] == ["docker", "rm", "-f", container.name]


def test_release_stops_then_scrubs_only_exact_mounts_before_removing_container(
    tmp_path: Path, scope: SandboxScope, sterile_staging_factory
) -> None:
    root = tmp_path / "roots"
    staging = sterile_staging_factory()
    spec = make_spec(root, scope, staging)
    runner = RecordingCommandRunner()
    pool = DockerSandboxPool(
        scope=scope,
        workspace_root=root / "incoming",
        output_root=root / "output",
        docker=DockerCli(runner=runner),
    )
    container = pool.precreate(spec)

    result = pool.release(spec.attempt_id)

    assert result is not None and result.ok
    assert not staging.root.exists()
    stop_index = runner.calls.index(["docker", "stop", container.name])
    remove_index = runner.calls.index(["docker", "rm", "-f", container.name])
    scrub = runner.calls[stop_index + 1]
    assert stop_index < remove_index
    assert scrub[:3] == ["docker", "run", "--rm"]
    assert f"{staging.workdir}:/work:rw" in scrub
    assert f"{staging.artifacts}:/artifacts:rw" in scrub
    assert not any("/workspace" in item for item in scrub)
    assert ["--user", "ctf"] == scrub[scrub.index("--user"):scrub.index("--user") + 2]
    assert ["--network", "none"] == scrub[scrub.index("--network"):scrub.index("--network") + 2]


def test_release_records_hostile_spool_cleanup_but_still_removes_exact_container(
    tmp_path: Path, scope: SandboxScope, sterile_staging_factory
) -> None:
    root = tmp_path / "roots"
    staging = sterile_staging_factory()
    spec = make_spec(root, scope, staging)
    runner = RecordingCommandRunner()
    pool = DockerSandboxPool(
        scope=scope,
        workspace_root=root / "incoming",
        output_root=root / "output",
        docker=DockerCli(runner=runner),
    )
    container = pool.precreate(spec)
    outside = tmp_path / "outside"
    outside.write_text("do not follow", encoding="utf-8")
    broker = pool.broker(spec.attempt_id)
    assert broker is not None
    (broker.socket_path / "unexpected-link").symlink_to(outside)

    result = pool.release(spec.attempt_id)

    assert result is not None and result.ok
    assert pool.active_count == 0
    assert spec.attempt_id in pool.broker_cleanup_errors
    assert outside.read_text(encoding="utf-8") == "do not follow"
    assert ["docker", "stop", container.name] in runner.calls
    assert ["docker", "rm", "-f", container.name] in runner.calls
    assert not staging.root.exists()


def test_release_uses_one_shot_scrub_after_exact_remove_when_attempt_is_already_gone(
    tmp_path: Path, scope: SandboxScope, sterile_staging_factory
) -> None:
    root = tmp_path / "roots"
    staging = sterile_staging_factory()
    spec = make_spec(root, scope, staging)

    def runner(argv):
        if argv[:2] == ["docker", "stop"]:
            return CommandResult(tuple(argv), returncode=1, stderr="No such container")
        return CommandResult(tuple(argv))

    docker = DockerCli(runner=runner)
    pool = DockerSandboxPool(
        scope=scope,
        workspace_root=root / "incoming",
        output_root=root / "output",
        docker=docker,
    )
    container = pool.precreate(spec)

    result = pool.release(spec.attempt_id)

    assert result is not None and result.ok
    calls = docker.calls
    stop_index = calls.index(["docker", "stop", container.name])
    remove_index = calls.index(["docker", "rm", "-f", container.name])
    scrub_index = next(index for index, argv in enumerate(calls) if argv[:3] == ["docker", "run", "--rm"])
    assert stop_index < remove_index < scrub_index
    assert not staging.root.exists()


def test_preserved_release_keeps_staging_untouched(tmp_path: Path, scope: SandboxScope, sterile_staging_factory) -> None:
    root = tmp_path / "roots"
    staging = sterile_staging_factory()
    spec = make_spec(root, scope, staging)
    runner = RecordingCommandRunner()
    pool = DockerSandboxPool(
        scope=scope,
        workspace_root=root / "incoming",
        output_root=root / "output",
        docker=DockerCli(runner=runner),
    )
    pool.precreate(spec)

    result = pool.release(spec.attempt_id, remove=False)

    assert result is not None and result.ok
    assert staging.root.exists()
    assert not any(argv[:3] == ["docker", "run", "--rm"] for argv in runner.calls)
    ArtifactWriter.cleanup_attempt_staging(staging.workdir)


def test_pool_rejects_scope_and_mounts_outside_supplied_roots(
    tmp_path: Path, scope: SandboxScope, sterile_staging_factory
) -> None:
    root = tmp_path / "roots"
    pool = DockerSandboxPool(
        scope=scope,
        workspace_root=root / "incoming",
        output_root=root / "output",
        docker=DockerCli(dry_run=True),
    )
    outside = make_spec(root, scope, sterile_staging_factory())
    outside = SandboxSpec(
        scope=outside.scope,
        attempt_id=outside.attempt_id,
        workspace=tmp_path / "other" / "challenge",
        workdir=outside.workdir,
        artifacts=outside.artifacts,
    )
    with pytest.raises(SandboxPathError, match="workspace"):
        pool.precreate(outside)

    wrong_scope = make_spec(root, SandboxScope("other-team", "member", "contest", "challenge"), sterile_staging_factory())
    with pytest.raises(PermissionError, match="scope"):
        pool.precreate(wrong_scope)


def test_cleanup_is_label_scoped_and_all_never_targets_unlabeled(scope: SandboxScope) -> None:
    local_filters = build_cleanup_filters(scope)
    assert local_filters == [
        "label=ctf-os=true",
        "label=ctf-os.team_id=team",
        "label=ctf-os.member=member",
        "label=ctf-os.contest=contest",
        "label=ctf-os.challenge=challenge",
    ]
    assert build_cleanup_filters(scope, all_containers=True) == [
        "label=ctf-os=true", "label=ctf-os.team_id=team", "label=ctf-os.member=member",
    ]

    calls: list[list[str]] = []

    def runner(argv: list[str]) -> CommandResult:
        calls.append(argv)
        if argv[1:3] == ["ps", "-aq"]:
            return CommandResult(tuple(argv), stdout="id-one\nid-two\n")
        return CommandResult(tuple(argv))

    pool = DockerSandboxPool(
        scope=scope,
        workspace_root="/tmp/incoming",
        output_root="/tmp/output",
        docker=DockerCli(runner=runner),
    )
    assert pool.cleanup() == ["id-one", "id-two"]
    assert calls[0] == [
        "docker",
        "ps",
        "-aq",
        "--filter",
        "label=ctf-os=true",
        "--filter",
        "label=ctf-os.team_id=team",
        "--filter",
        "label=ctf-os.member=member",
        "--filter",
        "label=ctf-os.contest=contest",
        "--filter",
        "label=ctf-os.challenge=challenge",
    ]
    pool.cleanup(all_containers=True)
    assert calls[3] == [
        "docker", "ps", "-aq", "--filter", "label=ctf-os=true",
        "--filter", "label=ctf-os.team_id=team", "--filter", "label=ctf-os.member=member",
    ]
