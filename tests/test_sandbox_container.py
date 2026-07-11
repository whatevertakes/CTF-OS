from __future__ import annotations

from pathlib import Path

import pytest

from ctf_os.sandbox.container import (
    SandboxScope,
    SandboxSpec,
    build_container_name,
    build_ctf_exec_argv,
    build_docker_exec_argv,
    build_docker_run_argv,
    build_labels,
    create_ctf_exec_helper,
)
from ctf_os.sandbox.network_policy import AllowedEndpoint


@pytest.fixture
def scope() -> SandboxScope:
    return SandboxScope(
        team_id="sca-team",
        member="jiwoong",
        contest="SCA CTF 2026",
        challenge="BOF / Intro",
    )


@pytest.fixture
def spec(scope: SandboxScope, sterile_staging_factory) -> SandboxSpec:
    staging = sterile_staging_factory()
    return SandboxSpec(
        scope=scope,
        attempt_id="exploit_main-01",
        workspace=Path("/tmp/workspace/bof"),
        workdir=staging.workdir,
        artifacts=staging.artifacts,
    )


def test_container_name_is_deterministic_docker_safe_and_bounded() -> None:
    name = build_container_name("Team Name!", "SCA CTF", "bof/intro", "exploit main")

    assert name == "ctf-os-team-name-sca-ctf-bof-intro-exploit-main"
    assert build_container_name("x" * 100, "y" * 100, "z" * 100, "a" * 100) == build_container_name(
        "x" * 100, "y" * 100, "z" * 100, "a" * 100
    )
    assert len(build_container_name("x" * 100, "y" * 100, "z" * 100, "a" * 100)) <= 128


def test_labels_include_full_local_scope(scope: SandboxScope) -> None:
    assert build_labels(scope, "a-1") == {
        "ctf-os": "true",
        "ctf-os.team_id": "sca-team",
        "ctf-os.member": "jiwoong",
        "ctf-os.contest": "SCA CTF 2026",
        "ctf-os.challenge": "BOF / Intro",
        "ctf-os.challenge_id": "unknown",
        "ctf-os.challenge_key": "unknown",
        "ctf-os.attempt_id": "a-1",
    }


def test_run_argv_has_isolation_mounts_limits_and_no_egress(spec: SandboxSpec) -> None:
    argv = build_docker_run_argv(spec)

    assert argv[:5] == ["docker", "run", "-d", "--name", spec.container_name]
    assert ["--memory", "16g"] == argv[argv.index("--memory") : argv.index("--memory") + 2]
    assert ["--cpus", "2.0"] == argv[argv.index("--cpus") : argv.index("--cpus") + 2]
    assert "--memory-reservation" not in argv
    assert "--cpuset-cpus" not in argv
    assert ["--pids-limit", "128"] == argv[argv.index("--pids-limit") : argv.index("--pids-limit") + 2]
    assert "nofile=1024:1024" in argv
    assert "nproc=128:128" in argv
    assert ["--network", "none"] == argv[argv.index("--network") : argv.index("--network") + 2]
    assert "ctf-os=true" in argv
    assert "/tmp/workspace/bof:/workspace:ro" in argv
    assert f"{spec.workdir}:/work:rw" not in argv
    assert f"{spec.artifacts}:/artifacts:rw" not in argv
    assert argv[-3:] == ["ctf-os-sandbox:latest", "sleep", "infinity"]
    assert "--cap-drop=ALL" in argv
    assert {"--cap-add=NET_ADMIN", "--cap-add=SETUID", "--cap-add=SETGID", "--cap-add=SETPCAP"}.issubset(argv)
    assert "--security-opt=no-new-privileges:true" in argv


def test_run_argv_uses_a_bounded_tmpfs_budget_for_both_worker_roots(spec: SandboxSpec) -> None:
    """The ctf UID must never receive either host staging directory as rw."""
    limited = SandboxSpec(**{
        **spec.__dict__,
        "storage_limit_bytes": 256 * 1024,
        "storage_inode_limit": 64,
    })

    argv = build_docker_run_argv(limited)

    tmpfs_mounts = [argv[index + 1] for index, value in enumerate(argv[:-1]) if value == "--tmpfs"]
    assert len(tmpfs_mounts) == 2
    assert {mount.split(":", 1)[0] for mount in tmpfs_mounts} == {"/work", "/artifacts"}
    assert all("mode=1777" in mount and "exec" in mount for mount in tmpfs_mounts)
    assert all("nr_inodes=" in mount and "size=" in mount for mount in tmpfs_mounts)
    # The other half is the broker-only host mirror.  The ctf UID sees only
    # the tmpfs roots; the mode-0700 staging parent is mounted at a private
    # control path for fixed root import/export programs.
    assert sum(int(item.split("size=", 1)[1].split(",", 1)[0]) for item in tmpfs_mounts) == limited.storage_limit_bytes // 2
    assert sum(int(item.split("nr_inodes=", 1)[1].split(",", 1)[0]) for item in tmpfs_mounts) == limited.storage_inode_limit // 2
    assert "--read-only" in argv
    assert f"{limited.workdir.parent}:/ctf-os-host:rw" in argv
    assert f"{limited.workdir}:/work:rw" not in argv
    assert f"{limited.artifacts}:/artifacts:rw" not in argv


@pytest.mark.parametrize(
    ("field", "value"),
    (("storage_limit_bytes", 0), ("storage_inode_limit", 1)),
)
def test_storage_budget_rejects_unusable_limits(spec: SandboxSpec, field: str, value: int) -> None:
    with pytest.raises(ValueError, match="storage"):
        SandboxSpec(**{**spec.__dict__, field: value})


def test_exec_argv_uses_unprivileged_direct_argv_not_a_shell() -> None:
    command = "file /workspace/chall; touch /work/owned"
    argv = build_docker_exec_argv("ctf-os-team-c-b-a", command)

    assert argv == [
        "docker",
        "exec",
        "--user",
        "ctf",
        "-w",
        "/work",
        "ctf-os-team-c-b-a",
        "file",
        "/workspace/chall;",
        "touch",
        "/work/owned",
    ]
    assert build_ctf_exec_argv("a-1", command) == [
        "ctf-os",
        "sandbox",
        "exec",
        "a-1",
        "--",
        "file",
        "/workspace/chall;",
        "touch",
        "/work/owned",
    ]


def test_legacy_helper_never_uses_a_shell(tmp_path: Path) -> None:
    helper = create_ctf_exec_helper(tmp_path / "ctf-exec", container_name="ctf-os-safe-name")
    contents = helper.read_text(encoding="utf-8")

    assert helper.stat().st_mode & 0o111
    assert '"$@"' in contents
    assert "ctf-os-safe-name" in contents
    assert "eval" not in contents


def test_remote_endpoint_run_argv_has_exact_host_mapping_and_policy(spec: SandboxSpec) -> None:
    endpoint = AllowedEndpoint("pwn.ctf.example", "8.8.8.8", 31337, "tcp", "nc")
    argv = build_docker_run_argv(SandboxSpec(**{**spec.__dict__, "endpoints": (endpoint,)}))
    assert ["--network", "bridge"] == argv[argv.index("--network") : argv.index("--network") + 2]
    assert "pwn.ctf.example:8.8.8.8" in argv
    env_value = argv[argv.index("CTF_OS_ALLOWED_ENDPOINTS_JSON=[{\"host\":\"pwn.ctf.example\",\"ip\":\"8.8.8.8\",\"port\":31337,\"protocol\":\"tcp\",\"source_protocol\":\"nc\"}]")]
    assert "CTF_OS_ALLOWED_ENDPOINTS_JSON" in env_value


def test_mount_path_with_docker_volume_delimiter_is_rejected(scope: SandboxScope) -> None:
    spec = SandboxSpec(
        scope=scope,
        attempt_id="a",
        workspace=Path("/tmp/bad:path"),
        workdir=Path("/tmp/work"),
        artifacts=Path("/tmp/artifacts"),
    )
    with pytest.raises(ValueError, match="mount paths"):
        build_docker_run_argv(spec)
