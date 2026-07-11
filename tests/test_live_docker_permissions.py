from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

from ctf_os.artifact_writer import ArtifactWriter
from ctf_os.sandbox.container import STAGING_SCRUB_PROGRAM, build_docker_staging_scrub_argv


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def test_staging_root_marker_and_mount_children_have_exact_host_modes(tmp_path: Path) -> None:
    staging = ArtifactWriter(tmp_path / "output", "Demo").create_attempt_staging()

    assert staging.root.lstat().st_uid == os.getuid()
    assert _mode(staging.root) == 0o700
    marker = staging.root / ".ctf-os-sterile-attempt"
    assert marker.lstat().st_uid == os.getuid()
    assert _mode(marker) == 0o600
    for child in (staging.workdir, staging.artifacts):
        assert child.lstat().st_uid == os.getuid()
        assert _mode(child) == 0o1777

    ArtifactWriter.cleanup_attempt_staging(staging.workdir)


def test_staging_fchmod_contract_survives_an_owner_bit_umask(tmp_path: Path) -> None:
    previous_umask = os.umask(0o777)
    try:
        staging = ArtifactWriter(tmp_path / "output", "Demo").create_attempt_staging()
    finally:
        os.umask(previous_umask)
        # The test deliberately gives the newly-created output parent mode
        # 000.  Restore only that fixture-owned parent so pytest can clean its
        # own tmp_path; the staging assertions below still exercise fchmod.
        output = tmp_path / "output"
        if output.exists():
            os.chmod(output, 0o700)

    assert _mode(staging.root) == 0o700
    assert _mode(staging.root / ".ctf-os-sterile-attempt") == 0o600
    assert _mode(staging.workdir) == _mode(staging.artifacts) == 0o1777
    ArtifactWriter.cleanup_attempt_staging(staging.workdir)


@pytest.mark.parametrize("child", ("work", "artifacts"))
def test_staging_validation_rejects_any_altered_mount_child_mode(tmp_path: Path, child: str) -> None:
    staging = ArtifactWriter(tmp_path / "output", "Demo").create_attempt_staging()
    os.chmod(staging.root / child, 0o0777)

    with pytest.raises(ValueError, match="mode 01777"):
        ArtifactWriter.staging_for_workdir(staging.workdir)

    os.chmod(staging.root / child, 0o1777)
    ArtifactWriter.cleanup_attempt_staging(staging.workdir)


def test_sticky_mount_and_host_helper_modes_protect_helper_from_worker_replacement(
    tmp_path: Path, sterile_staging_factory
) -> None:
    """The different-UID unlink check is exercised by live Docker acceptance.

    Locally, assert the two filesystem properties that make that check true:
    the mount root is sticky and the broker helper is host-owned 0700.  Staging
    creation changes only newly opened mount child descriptors; it does not
    chmod a helper.
    """
    from ctf_os.sandbox.broker import AttemptCommandBroker, create_ctf_exec_helper
    from ctf_os.sandbox.docker_cli import DockerCli, RecordingCommandRunner

    staging = sterile_staging_factory()
    broker = AttemptCommandBroker(
        attempt_id="attempt-a", container_name="ctf-os-a", workdir=staging.workdir,
        docker=DockerCli(runner=RecordingCommandRunner()), token="x" * 32,
    ).start()
    try:
        helper = create_ctf_exec_helper(staging.workdir / "ctf-exec", broker=broker)
        assert _mode(staging.workdir) == 0o1777
        assert helper.lstat().st_uid == os.getuid()
        assert _mode(helper) == 0o700
        ArtifactWriter.staging_for_workdir(staging.workdir)
        assert _mode(helper) == 0o700  # Descriptor validation never widens helpers.
    finally:
        broker.stop()


def test_fixed_argv_scrub_has_no_workspace_or_shell_and_uses_ctf_identity(tmp_path: Path) -> None:
    staging = ArtifactWriter(tmp_path / "output", "Demo").create_attempt_staging()
    argv = build_docker_staging_scrub_argv(
        "ctf-os-sandbox:latest", staging.workdir, staging.artifacts,
    )

    assert argv[:3] == ["docker", "run", "--rm"]
    assert ["--network", "none"] == argv[argv.index("--network"):argv.index("--network") + 2]
    assert ["--user", "ctf"] == argv[argv.index("--user"):argv.index("--user") + 2]
    assert "--cap-drop=ALL" in argv
    assert "--security-opt=no-new-privileges:true" in argv
    assert "/workspace" not in " ".join(argv)
    assert "/bin/sh" not in argv and "bash" not in argv
    assert argv[-3:] == ["-I", "-c", STAGING_SCRUB_PROGRAM]
    assert f"{staging.workdir}:/work:rw" in argv
    assert f"{staging.artifacts}:/artifacts:rw" in argv

    ArtifactWriter.cleanup_attempt_staging(staging.workdir)


def test_scrub_program_removes_mode_zero_owned_tree_without_following_symlink(tmp_path: Path) -> None:
    work, artifacts, outside = tmp_path / "work", tmp_path / "artifacts", tmp_path / "outside"
    work.mkdir()
    artifacts.mkdir()
    outside.mkdir()
    sentinel = outside / "keep"
    sentinel.write_text("outside", encoding="utf-8")
    nested = work / "nested" / "deeper"
    nested.mkdir(parents=True)
    (nested / "owned").write_text("x", encoding="utf-8")
    (artifacts / "outside-link").symlink_to(outside, target_is_directory=True)
    os.chmod(nested, 0)
    os.chmod(work / "nested", 0)
    os.chmod(work, 0o1777)
    os.chmod(artifacts, 0o1777)

    # Exercise the exact one-shot program with only its fixed mount constants
    # replaced by local test mount roots; no Docker daemon is needed here.
    program = STAGING_SCRUB_PROGRAM.replace(
        'ROOTS = ("/work", "/artifacts")', f"ROOTS = ({str(work)!r}, {str(artifacts)!r})",
    ).replace("root_info.st_uid == ME", "False")
    try:
        result = subprocess.run([sys.executable, "-I", "-c", program], check=False, text=True, capture_output=True, timeout=5)

        assert result.returncode == 0, result.stderr
        assert list(work.iterdir()) == []
        assert list(artifacts.iterdir()) == []
        assert sentinel.read_text(encoding="utf-8") == "outside"
    finally:
        # Restore private modes even when an assertion fails.  Otherwise a
        # failed security regression leaks a mode-000 fixture that makes
        # pytest's own cleanup noisy and masks the real result.
        if nested.exists():
            os.chmod(nested, 0o700)
        if (work / "nested").exists():
            os.chmod(work / "nested", 0o700)
        os.chmod(work, 0o700)
        os.chmod(artifacts, 0o700)


def test_host_teardown_normalizes_its_own_mode_zero_tree_without_following_links(tmp_path: Path) -> None:
    staging = ArtifactWriter(tmp_path / "output", "Demo").create_attempt_staging()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "keep"
    sentinel.write_text("outside", encoding="utf-8")
    nested = staging.workdir / "host-nested"
    nested.mkdir()
    (nested / "record").write_text("x", encoding="utf-8")
    (staging.artifacts / "outside-link").symlink_to(outside, target_is_directory=True)
    os.chmod(nested, 0)

    ArtifactWriter.cleanup_attempt_staging(staging.workdir)

    assert not staging.root.exists()
    assert sentinel.read_text(encoding="utf-8") == "outside"
