"""RM4 (root symlink safety) and RM6 (tar compression-ratio) regressions."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from ctf_os.archive import ArchiveError, extract_archive
from ctf_os.contest import ContestError, discover_contests
from ctf_os.workspace import WorkspaceError, safe_under


def test_discover_contests_rejects_symlinked_incoming(tmp_path: Path) -> None:
    external = tmp_path / "external"
    (external / "Evil CTF").mkdir(parents=True)
    (external / "Evil CTF" / "contest.md").write_text(
        "# Contest: Evil CTF\n\n### web/x\n- description: y\n", encoding="utf-8"
    )
    incoming = tmp_path / "repo" / "incoming"
    incoming.parent.mkdir(parents=True)
    incoming.symlink_to(external)
    with pytest.raises(ContestError, match="symlink"):
        discover_contests(incoming)


def test_safe_under_rejects_symlinked_base(tmp_path: Path) -> None:
    external = tmp_path / "external"
    external.mkdir()
    output = tmp_path / "repo" / "output"
    output.parent.mkdir(parents=True)
    output.symlink_to(external)
    with pytest.raises(WorkspaceError, match="symlink"):
        safe_under(output, Path("runs") / "x")


def _zero_tar_gz(path: Path, *, member_size: int) -> None:
    buffer = io.BytesIO(b"\x00" * member_size)
    with tarfile.open(path, mode="w:gz") as handle:
        info = tarfile.TarInfo(name="bomb.bin")
        info.size = member_size
        handle.addfile(info, buffer)


def test_tar_compression_ratio_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "bomb.tar.gz"
    # 100 MiB of zeros compresses to a few KiB — ratio well over 200:1.
    _zero_tar_gz(archive, member_size=100 * 1024 * 1024)
    assert archive.stat().st_size * 200 < 100 * 1024 * 1024
    with pytest.raises(ArchiveError, match="compression ratio"):
        extract_archive(archive, tmp_path / "out")


def test_normal_tar_still_extracts(tmp_path: Path) -> None:
    archive = tmp_path / "normal.tar.gz"
    payload = b"real challenge content, not compressible to nothing " * 100
    buffer = io.BytesIO(payload)
    with tarfile.open(archive, mode="w:gz") as handle:
        info = tarfile.TarInfo(name="chal/readme.txt")
        info.size = len(payload)
        handle.addfile(info, buffer)
    names = extract_archive(archive, tmp_path / "out")
    assert names == ["chal/readme.txt"]
    assert (tmp_path / "out" / "chal" / "readme.txt").read_bytes() == payload
