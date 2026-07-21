from pathlib import Path

from ctf_os.doctor import (
    IMAGES, PROFILE_PROBES, _available_memory, _docker_failure_kind,
    _docker_server_supported, _repository_filesystem, _supported_host,
    _write_probe, _wsl_generation,
)
from ctf_os.timeouts import load_timeout_profiles


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
        "rev": ("pyopencl", "r2 -v"),
        "crypto": ("sage -c", "RsaCtfTool", "cado-nfs", "hashcat --version"),
        "forensic": ("vol", "mmls", "tshark", "stegseek"),
        "misc": ("podman", "torch", "cv2"),
        "osint": ("chromium --headless", "whois", "tesseract"),
        "ai": ("InferenceSession", "torch.tensor", "torch.version.cuda", "tokenizers"),
        "cloud": ("aws --version", "gcloud --version", "conftest", "checkov"),
    }
    for profile, required in expectations.items():
        assert all(value in PROFILE_PROBES[profile] for value in required)
    assert load_timeout_profiles() == {
        "quick_probe": 60, "normal_command": 300, "decompile": 900,
        "symbolic_slice": 1800, "fuzz_slice": 1800, "forensic_scan": 1800,
        "crypto_heavy": 1800, "cracking_slice": 1800, "ai_inference": 1800,
    }


def test_wsl2_and_native_ubuntu_x86_64_are_supported() -> None:
    wsl2 = _wsl_generation("5.15.167.4-microsoft-standard-WSL2", True)
    assert wsl2 == 2
    assert _supported_host(
        host_system="Linux", ubuntu=True, architecture="x86_64",
        wsl_generation=wsl2,
    )
    assert _supported_host(
        host_system="Linux", ubuntu=True, architecture="amd64",
        wsl_generation=None,
    )


def test_non_ubuntu_or_arm64_host_is_unsupported() -> None:
    assert not _supported_host(
        host_system="Linux", ubuntu=False, architecture="x86_64",
        wsl_generation=None,
    )
    assert not _supported_host(
        host_system="Linux", ubuntu=True, architecture="aarch64",
        wsl_generation=None,
    )


def test_drvfs_repository_is_detected_as_warning_condition() -> None:
    filesystem = _repository_filesystem(Path("/mnt/c/Users/example/CTF-OS"))
    assert filesystem["windows_mount"] is True


def test_docker_failures_distinguish_cli_socket_and_daemon(monkeypatch) -> None:
    monkeypatch.setattr("ctf_os.doctor.shutil.which", lambda name: None)
    assert _docker_failure_kind("") == "DOCKER_CLI_MISSING"
    assert _docker_failure_kind("permission denied /var/run/docker.sock").startswith(
        "SOCKET_PERMISSION_DENIED:"
    )
    assert _docker_failure_kind("Cannot connect to the Docker daemon").startswith(
        "DAEMON_STOPPED_OR_UNREACHABLE:"
    )


def test_docker_server_must_be_linux_amd64() -> None:
    assert _docker_server_supported("linux", "amd64")
    assert _docker_server_supported("linux", "x86_64")
    assert not _docker_server_supported("linux", "arm64")
    assert not _docker_server_supported("windows", "amd64")
