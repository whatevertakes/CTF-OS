from pathlib import Path

from ctf_os.doctor import IMAGES, PROFILE_PROBES, _available_memory, _write_probe


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


def test_doctor_covers_ten_images_and_required_smokes() -> None:
    assert len(IMAGES) == 10
    assert set(PROFILE_PROBES) == {image.rsplit(":", 1)[1] for image in IMAGES}
    expectations = {
        "pwn": ("qemu-aarch64", "qemu-system-x86_64", "angr"),
        "crypto": ("sage -c", "RsaCtfTool", "cado-nfs"),
        "forensic": ("vol", "mmls", "tshark", "stegseek"),
        "misc": ("podman", "torch", "cv2"),
        "osint": ("chromium --headless", "whois", "tesseract"),
        "ai": ("InferenceSession", "torch.tensor", "tokenizers"),
        "cloud": ("aws --version", "gcloud --version", "conftest", "checkov"),
    }
    for profile, required in expectations.items():
        assert all(value in PROFILE_PROBES[profile] for value in required)
