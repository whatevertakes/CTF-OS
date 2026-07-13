from pathlib import Path

from ctf_os.doctor import _available_memory, _write_probe


def test_doctor_safe_local_probes(tmp_path: Path) -> None:
    assert _available_memory() >= 0
    assert _write_probe(tmp_path / "output") is True
    assert not (tmp_path / "output" / ".doctor-write-probe").exists()


def test_doctor_rejects_symlink_output(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "output"
    link.symlink_to(target, target_is_directory=True)
    assert _write_probe(link) is False
