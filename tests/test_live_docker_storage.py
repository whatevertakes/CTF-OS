"""Live Docker proof for the per-attempt writable-storage boundary."""

from __future__ import annotations

import os
from pathlib import Path
import stat

import pytest

from ctf_os.artifact_writer import ArtifactWriter
from ctf_os.models import Challenge
from ctf_os.sandbox.broker import BrokerError, send_broker_request
from ctf_os.sandbox.container import SandboxScope, SandboxSpec, build_labels, storage_mount_limits
from ctf_os.sandbox.docker_cli import DockerCli
from ctf_os.sandbox.pool import DockerSandboxPool


def _live_docker_or_skip() -> DockerCli:
    docker = DockerCli(command_timeout_sec=20)
    if not docker.daemon_available():
        pytest.skip("Docker daemon is unavailable")
    if not docker.image_exists("ctf-os-sandbox:latest"):
        pytest.skip("ctf-os-sandbox:latest is unavailable")
    return docker


def _remove_interrupted_live_test_container(docker: DockerCli, spec: SandboxSpec) -> None:
    """Reap only this test's exact deterministic name-and-label scope."""
    argv = [docker.command, "ps", "-aq", "--filter", f"name=^/{spec.container_name}$"]
    for key, value in build_labels(spec.scope, spec.attempt_id).items():
        argv.extend(["--filter", f"label={key}={value}"])
    listed = docker.invoke(argv)
    assert listed.ok and not listed.truncated, listed.stderr
    container_ids = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
    assert len(container_ids) <= 1
    for container_id in container_ids:
        removed = docker.remove(container_id)
        assert removed.ok, removed.stderr


def _worker_tree_usage(root: Path, *, controls: set[str] | None = None) -> tuple[int, int]:
    """Logical bytes and materialized-entry count without traversing links."""
    bytes_used = inodes_used = 0
    for entry in root.iterdir():
        if controls is not None and entry.name in controls:
            continue
        details = entry.lstat()
        inodes_used += 1
        if stat.S_ISDIR(details.st_mode):
            child_bytes, child_inodes = _worker_tree_usage(entry)
            bytes_used += child_bytes
            inodes_used += child_inodes
        elif stat.S_ISREG(details.st_mode):
            bytes_used += details.st_size
    return bytes_used, inodes_used


def test_live_brokered_storage_is_bounded_preserved_and_reclaimed(tmp_path: Path) -> None:
    """Exercise byte/inode ENOSPC through ctf-exec, then prove cleanup."""
    docker = _live_docker_or_skip()
    writer = ArtifactWriter(tmp_path / "output", "Demo")
    staging = writer.create_attempt_staging()
    workspace = tmp_path / "incoming" / "challenge"
    workspace.mkdir(parents=True)
    sentinel = tmp_path / "outside-sentinel"
    sentinel.write_text("do not modify", encoding="utf-8")
    scope = SandboxScope("team", "member", "Demo", "storage-live")
    spec = SandboxSpec(
        scope=scope,
        attempt_id="storage-live-regression",
        workspace=workspace,
        workdir=staging.workdir,
        artifacts=staging.artifacts,
        # The ctf-visible tmpfs receives half of this total, so the test
        # remains safely below a megabyte even while syncing host artifacts.
        storage_limit_bytes=384 * 1024,
        storage_inode_limit=96,
    )
    pool = DockerSandboxPool(
        scope=scope,
        workspace_root=tmp_path / "incoming",
        output_root=tmp_path / "output",
        docker=docker,
    )
    created = False
    try:
        _remove_interrupted_live_test_container(docker, spec)
        pool.precreate(spec)
        created = True
        broker = pool.broker(spec.attempt_id)
        assert broker is not None
        normal = send_broker_request(
            broker.socket_path,
            attempt_id=spec.attempt_id,
            token=broker.token,
            argv=[
                "sh", "-c",
                "test \"$(id -u)\" = 1001 "
                "&& printf normal >/work/temporary "
                "&& cat /work/temporary "
                "&& mv /work/temporary /artifacts/replay.sh "
                "&& printf transient >/work/delete-me "
                "&& rm /work/delete-me",
            ],
        )
        assert normal.returncode == 0, normal.stderr
        assert normal.stdout == "normal"
        assert (staging.artifacts / "replay.sh").read_text(encoding="utf-8") == "normal"
        helper = staging.workdir / "ctf-exec"
        assert helper.is_file() and helper.stat().st_uid == os.getuid()
        assert stat.S_IMODE(helper.stat().st_mode) == 0o700

        root_layer_write = send_broker_request(
            broker.socket_path,
            attempt_id=spec.attempt_id,
            token=broker.token,
            argv=["sh", "-c", "printf bypass >/tmp/storage-bypass"],
        )
        assert root_layer_write.returncode != 0

        challenge = Challenge(contest="Demo", category="misc", name="storage-live")
        promoted = writer.promote_verified_artifacts(
            challenge,
            attempt_workdir=staging.workdir,
            artifact_paths=(staging.artifacts / "replay.sh",),
            attempt_artifacts=staging.artifacts,
        )
        assert promoted and promoted[0].read_text(encoding="utf-8") == "normal"

        byte_exhausted = send_broker_request(
            broker.socket_path,
            attempt_id=spec.attempt_id,
            token=broker.token,
            argv=["fallocate", "-l", "1M", "/work/byte-exhaustion"],
        )
        assert byte_exhausted.returncode != 0
        assert "space" in byte_exhausted.stderr.lower()
        (staging.workdir / "byte-exhaustion").unlink()

        inode_exhausted = send_broker_request(
            broker.socket_path,
            attempt_id=spec.attempt_id,
            token=broker.token,
            argv=[
                "sh", "-c",
                "i=0; while [ \"$i\" -lt 64 ]; do : > /artifacts/inode-$i || exit 73; i=$((i + 1)); done; exit 74",
            ],
        )
        assert inode_exhausted.returncode != 0
        assert "space" in inode_exhausted.stderr.lower()
        for path in staging.artifacts.glob("inode-*"):
            path.unlink()

        symlink_result = send_broker_request(
            broker.socket_path,
            attempt_id=spec.attempt_id,
            token=broker.token,
            argv=["ln", "-s", str(sentinel), "/work/outside-link"],
        )
        assert symlink_result.returncode == 0, symlink_result.stderr
        link = staging.workdir / "outside-link"
        assert link.is_symlink() and link.readlink() == sentinel
        assert sentinel.read_text(encoding="utf-8") == "do not modify"
    finally:
        if created:
            result = pool.release(spec.attempt_id)
            assert result is not None and result.ok, result.stderr if result else "missing release result"
        elif staging.root.exists():
            ArtifactWriter.cleanup_attempt_staging(staging.workdir)

    assert not staging.root.exists()
    assert sentinel.read_text(encoding="utf-8") == "do not modify"


def test_live_export_rejects_hardlink_and_sparse_amplification_without_mutating_snapshot(tmp_path: Path) -> None:
    """Bound the host materialization, not merely the tmpfs's physical blocks."""
    docker = _live_docker_or_skip()
    writer = ArtifactWriter(tmp_path / "output", "Demo")
    staging = writer.create_attempt_staging()
    workspace = tmp_path / "incoming" / "challenge"
    workspace.mkdir(parents=True)
    scope = SandboxScope("team", "member", "Demo", "storage-export-live")
    spec = SandboxSpec(
        scope=scope,
        attempt_id="storage-export-amplification",
        workspace=workspace,
        workdir=staging.workdir,
        artifacts=staging.artifacts,
        storage_limit_bytes=768 * 1024,
        storage_inode_limit=128,
    )
    work_bytes, artifact_bytes, work_inodes, artifact_inodes = storage_mount_limits(
        spec.storage_limit_bytes, spec.storage_inode_limit,
    )
    pool = DockerSandboxPool(
        scope=scope,
        workspace_root=tmp_path / "incoming",
        output_root=tmp_path / "output",
        docker=docker,
    )
    created = False
    try:
        _remove_interrupted_live_test_container(docker, spec)
        pool.precreate(spec)
        created = True
        broker = pool.broker(spec.attempt_id)
        assert broker is not None
        baseline = send_broker_request(
            broker.socket_path,
            attempt_id=spec.attempt_id,
            token=broker.token,
            argv=["sh", "-c", "printf preserved >/work/snapshot"],
        )
        assert baseline.returncode == 0, baseline.stderr
        assert (staging.workdir / "snapshot").read_text(encoding="utf-8") == "preserved"

        with pytest.raises(BrokerError):
            send_broker_request(
                broker.socket_path,
                attempt_id=spec.attempt_id,
                token=broker.token,
                argv=[
                    "sh", "-c",
                    "dd if=/dev/zero of=/work/base bs=1024 count=32 status=none "
                    "&& i=0; while [ \"$i\" -lt 20 ]; do ln /work/base /work/link-$i "
                    "|| exit 88; i=$((i + 1)); done",
                ],
            )
        assert (staging.workdir / "snapshot").read_text(encoding="utf-8") == "preserved"
        assert not (staging.workdir / "base").exists()
        assert not list(staging.workdir.glob("link-*"))
        assert _worker_tree_usage(staging.workdir, controls={"ctf-exec", ".ctf-os-broker"}) <= (work_bytes, work_inodes)
        assert _worker_tree_usage(staging.artifacts) <= (artifact_bytes, artifact_inodes)
        assert not [path for path in staging.root.iterdir() if path.name.startswith(".ctf-os-export-")]

        with pytest.raises(BrokerError):
            send_broker_request(
                broker.socket_path,
                attempt_id=spec.attempt_id,
                token=broker.token,
                argv=["truncate", "-s", "1M", "/work/sparse"],
            )
        assert (staging.workdir / "snapshot").read_text(encoding="utf-8") == "preserved"
        assert not (staging.workdir / "sparse").exists()
        assert _worker_tree_usage(staging.workdir, controls={"ctf-exec", ".ctf-os-broker"}) <= (work_bytes, work_inodes)
        assert not [path for path in staging.root.iterdir() if path.name.startswith(".ctf-os-export-")]

        recovered = send_broker_request(
            broker.socket_path,
            attempt_id=spec.attempt_id,
            token=broker.token,
            argv=["sh", "-c", "test ! -e /work/sparse && cat /work/snapshot"],
        )
        assert recovered.returncode == 0, recovered.stderr
        assert recovered.stdout == "preserved"
    finally:
        if created:
            result = pool.release(spec.attempt_id)
            assert result is not None and result.ok, result.stderr if result else "missing release result"
        elif staging.root.exists():
            ArtifactWriter.cleanup_attempt_staging(staging.workdir)

    assert not staging.root.exists()
