from pathlib import Path
import subprocess

import ctf_os.doctor as doctor

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
        "pwn": (
            "qemu-aarch64", "qemu-mipsel", "pwninit --version",
            "seccomp-tools --version", "musl-gcc --version",
            "ctf-os-binary-runtime-smoke", "angr", "afl-clang-fast",
            "afl-qemu-trace", "ctf-os-pwn-fuzzing-smoke",
            "ctf-ghidra-headless", "frida", "pyghidra", "capa",
        ),
        "web": (
            "chromium", "chromedriver", "playwright", "ffuf -V",
            "ctf-os-web-runtime-smoke", "nuclei -version", "sqlmap --version",
            "dalfox --version", "semgrep --version", "ctf-os-web-security-smoke",
        ),
        "rev": (
            "pyopencl", "r2 -v", "qemu-arm", "qemu-mipsel",
            "qemu-system-x86_64", "qemu-system-aarch64",
            "qemu-system-riscv64", "qemu-img",
            "aarch64-linux-gnu-gcc", "ctf-os-binary-runtime-smoke",
            "ctf-os-system-qemu-smoke", "ctf-os-binary-analysis-smoke",
            "ctf-ghidra-headless", "frida", "pyghidra", "capa",
        ),
        "crypto": ("sage -c", "RsaCtfTool", "cado-nfs", "hashcat --version"),
        "forensic": ("vol", "mmls", "tshark", "stegseek"),
        "misc": ("podman", "torch", "cv2"),
        "osint": ("chromium --headless", "whois", "tesseract"),
        "ai": (
            "InferenceSession", "torch.tensor", "torch.version.cuda", "tokenizers",
            "modelscan", "fickling", "tensorflow", "ctf-os-ai-serialization-smoke",
        ),
        "cloud": ("aws --version", "gcloud --version", "conftest", "checkov"),
    }
    for profile, required in expectations.items():
        assert all(value in PROFILE_PROBES[profile] for value in required)
    assert load_timeout_profiles() == {
        "quick_probe": 60, "normal_command": 300, "decompile": 900,
        "symbolic_slice": 1800, "fuzz_slice": 1800, "forensic_scan": 1800,
        "crypto_heavy": 1800, "cracking_slice": 1800, "ai_inference": 1800,
    }


def test_pwn_and_rev_doctor_probes_match_existing_ptrace_runtime(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(argv, timeout=30, cwd=None):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(doctor, "_run", fake_run)
    for profile in ("pwn", "rev"):
        doctor._image_probe(profile)
        joined = " ".join(calls[-1])
        assert "/tmp:rw,exec,nosuid,nodev" in joined
        assert "--cap-add SYS_PTRACE" in joined
        assert "--security-opt seccomp=unconfined" in joined
        assert "--ulimit core=-1:-1" in joined

    doctor._image_probe("web")
    assert "seccomp=unconfined" not in " ".join(calls[-1])


def test_wsl2_and_native_ubuntu_or_kali_x86_64_are_supported() -> None:
    wsl2 = _wsl_generation("5.15.167.4-microsoft-standard-WSL2", True)
    assert wsl2 == 2
    assert _supported_host(
        host_system="Linux", distribution="ubuntu", architecture="x86_64",
        wsl_generation=wsl2,
    )
    assert _supported_host(
        host_system="Linux", distribution="kali", architecture="amd64",
        wsl_generation=None,
    )


def test_unsupported_distribution_or_arm64_host_is_unsupported() -> None:
    assert not _supported_host(
        host_system="Linux", distribution="debian", architecture="x86_64",
        wsl_generation=None,
    )
    assert not _supported_host(
        host_system="Linux", distribution="ubuntu", architecture="aarch64",
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
