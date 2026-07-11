from __future__ import annotations

import os
from pathlib import Path
import stat

import pytest

from ctf_os.artifact_writer import ArtifactWriter


_CAPTURE = ".ctf-os-parent-capture.log"


def test_cleanup_removes_parent_capture_and_mode_zero_worker_tree_idempotently(tmp_path: Path) -> None:
    staging = ArtifactWriter(tmp_path / "output", "Demo").create_attempt_staging()
    nested = staging.workdir / "host-owned" / "mode-zero"
    nested.mkdir(parents=True)
    (nested / "record").write_text("worker output", encoding="utf-8")

    previous_umask = os.umask(0o777)
    try:
        assert ArtifactWriter.append_attempt_capture(staging.workdir, "[solver] captured")
    finally:
        os.umask(previous_umask)
    capture = staging.root / _CAPTURE
    details = capture.lstat()
    assert stat.S_ISREG(details.st_mode)
    assert details.st_uid == os.getuid()
    assert stat.S_IMODE(details.st_mode) == 0o600
    assert details.st_nlink == 1
    os.chmod(nested, 0)

    ArtifactWriter.cleanup_attempt_staging(staging.workdir)
    ArtifactWriter.cleanup_attempt_staging(staging.workdir)

    assert not staging.root.exists()


@pytest.mark.parametrize("kind", ("symlink", "hardlink", "wrong-mode", "fifo"))
def test_cleanup_retains_unsafe_parent_capture_without_touching_sentinel(tmp_path: Path, kind: str) -> None:
    staging = ArtifactWriter(tmp_path / "output", "Demo").create_attempt_staging()
    capture = staging.root / _CAPTURE
    sentinel = staging.root.with_name(f"{staging.root.name}-sentinel")
    sentinel.write_text("do not modify", encoding="utf-8")
    try:
        if kind == "symlink":
            capture.symlink_to(sentinel)
        elif kind == "hardlink":
            os.link(sentinel, capture)
        elif kind == "wrong-mode":
            capture.write_text("not private", encoding="utf-8")
            os.chmod(capture, 0o640)
        else:
            os.mkfifo(capture, 0o600)

        with pytest.raises(ValueError, match="parent capture retained"):
            ArtifactWriter.cleanup_attempt_staging(staging.workdir)

        assert staging.root.exists()
        assert capture.exists() or capture.is_symlink()
        assert sentinel.read_text(encoding="utf-8") == "do not modify"
    finally:
        capture.unlink(missing_ok=True)
        if staging.root.exists():
            ArtifactWriter.cleanup_attempt_staging(staging.workdir)
        sentinel.unlink(missing_ok=True)


def test_test_teardown_reclaims_hostile_fixture_without_touching_external_sentinel(
    tmp_path: Path, test_staging_cleanup
) -> None:
    """The test-only reaper cleans retained runtime fixtures by exact identity."""
    staging = ArtifactWriter(tmp_path / "output", "Demo").create_attempt_staging()
    sentinel = tmp_path / "external-sentinel"
    sentinel.write_text("do not modify", encoding="utf-8")
    (staging.root / _CAPTURE).symlink_to(sentinel)
    os.link(sentinel, staging.workdir / "external-hardlink")
    (staging.artifacts / "external-link").symlink_to(sentinel)
    locked = staging.workdir / "mode-zero"
    locked.mkdir()
    (locked / "record").write_text("fixture", encoding="utf-8")
    os.chmod(locked, 0)
    os.chmod(staging.root, 0)

    with pytest.raises(ValueError):
        ArtifactWriter.cleanup_attempt_staging(staging.workdir)

    test_staging_cleanup(staging)

    assert not staging.root.exists()
    assert sentinel.read_text(encoding="utf-8") == "do not modify"
