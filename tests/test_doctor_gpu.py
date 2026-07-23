from __future__ import annotations

import subprocess
from subprocess import TimeoutExpired

from ctf_os.doctor import (
    GPU_AI_ONNX_PROBE,
    GPU_CRYPTO_HASHCAT_PROBE,
    GPU_REV_CUPY_PROBE,
    _gpu_checks,
)


def _images(*profiles: str) -> dict[str, object]:
    return {
        "profiles": [
            {
                "image": f"ctf-os-sandbox:{profile}",
                "available": profile in profiles,
            }
            for profile in ("base", "pwn", "web", "rev", "crypto", "forensic", "misc", "osint", "ai", "cloud")
        ]
    }


def test_gpu_checks_skip_cleanly_when_host_has_no_nvidia_gpu() -> None:
    calls: list[list[str]] = []

    def runner(argv, **kwargs):
        calls.append(list(argv))
        raise FileNotFoundError("nvidia-smi")

    checks = _gpu_checks(
        _images("base", "ai", "crypto", "rev"),
        docker="docker",
        runner=runner,
    )

    assert all(check["ok"] for check in checks)
    assert all(check["status"] == "SKIPPED" for check in checks)
    assert calls == [[
        "nvidia-smi",
        "--query-gpu=index,name,driver_version",
        "--format=csv,noheader,nounits",
    ]]


def test_gpu_probe_timeout_is_a_failure_not_no_gpu_skip() -> None:
    def runner(argv, **kwargs):
        raise TimeoutExpired(argv, kwargs["timeout"])

    checks = _gpu_checks(_images("base"), docker="docker", runner=runner)
    assert checks[0]["name"] == "gpu-host-driver"
    assert checks[0]["status"] == "FAIL"


def test_gpu_checks_run_scoped_real_operation_probes() -> None:
    calls: list[list[str]] = []

    def runner(argv, **kwargs):
        calls.append(list(argv))
        if argv[0] == "nvidia-smi":
            return subprocess.CompletedProcess(argv, 0, "0, RTX Test, 999.1\n", "")
        if argv[:2] == ["docker", "run"]:
            return subprocess.CompletedProcess(argv, 0, "GPU operation passed\n", "")
        raise AssertionError(argv)

    checks = _gpu_checks(
        _images("base", "ai", "crypto", "rev"),
        docker="docker",
        runner=runner,
    )

    assert all(check["ok"] for check in checks)
    assert {check["name"] for check in checks} == {
        "gpu-host-driver",
        "gpu-docker-passthrough",
        "gpu-ai-torch",
        "gpu-ai-onnx",
        "gpu-crypto-hashcat",
        "gpu-rev-cupy",
    }
    docker_runs = [call for call in calls if call[:2] == ["docker", "run"]]
    assert len(docker_runs) == 5
    assert all("--gpus" in call and "all" in call for call in docker_runs)
    assert all("--network" in call and "none" in call for call in docker_runs)
    assert all("--read-only" in call and "--cap-drop" in call for call in docker_runs)
    assert all(
        "/home/ctf/.cache:rw,nosuid,nodev,size=256m,mode=0700,uid=1001,gid=1001"
        in call
        for call in docker_runs
    )


def test_gpu_check_reports_one_failed_image_probe() -> None:
    def runner(argv, **kwargs):
        if argv[0] == "nvidia-smi":
            return subprocess.CompletedProcess(argv, 0, "0, RTX Test, 999.1\n", "")
        if "ctf-os-sandbox:crypto" in argv:
            return subprocess.CompletedProcess(argv, 1, "", "CUDA backend unavailable")
        return subprocess.CompletedProcess(argv, 0, "GPU operation passed\n", "")

    checks = _gpu_checks(
        _images("base", "ai", "crypto", "rev"),
        docker="docker",
        runner=runner,
    )
    by_name = {check["name"]: check for check in checks}

    assert by_name["gpu-crypto-hashcat"]["ok"] is False
    assert by_name["gpu-crypto-hashcat"]["status"] == "FAIL"
    assert "CUDA backend unavailable" in by_name["gpu-crypto-hashcat"]["detail"]
    assert by_name["gpu-rev-cupy"]["ok"] is True


def test_gpu_probe_contracts_use_cuda_without_relaxing_security() -> None:
    assert GPU_AI_ONNX_PROBE.index("import torch") < GPU_AI_ONNX_PROBE.index("import onnxruntime")
    assert "--backend-ignore-opencl" in GPU_CRYPTO_HASHCAT_PROBE
    assert "password" in GPU_CRYPTO_HASHCAT_PROBE
    assert "import cupy as cp" in GPU_REV_CUPY_PROBE
    assert "RawKernel" in GPU_REV_CUPY_PROBE
    assert "pyopencl" not in GPU_REV_CUPY_PROBE
