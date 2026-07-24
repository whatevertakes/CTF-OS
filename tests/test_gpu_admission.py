"""M1 regression: GPU is admitted and attached only after full verification."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from ctf_os.doctor import HOST_GPU_QUERY as DOCTOR_HOST_GPU_QUERY
from ctf_os.sandbox.gpu import (
    HOST_GPU_COMPUTE_QUERY,
    HOST_GPU_QUERY,
    GpuError,
    admit_gpu,
    gpu_run_flags,
)
from ctf_os.sandbox.runtime import SandboxSpec, build_run_argv


def _no_gpu_runner(argv, **kwargs):
    if list(argv) == list(HOST_GPU_QUERY):
        raise FileNotFoundError("nvidia-smi")
    raise AssertionError(f"unexpected: {argv}")


def _full_gpu_runner(argv, **kwargs):
    if list(argv) == list(HOST_GPU_QUERY):
        return subprocess.CompletedProcess(argv, 0, "0, RTX 4060 Ti, 999.1\n", "")
    if list(argv) == list(HOST_GPU_COMPUTE_QUERY):
        return subprocess.CompletedProcess(argv, 0, "0, 8.9\n", "")
    if argv[:2] == ["docker", "run"]:
        return subprocess.CompletedProcess(argv, 0, "0, RTX 4060 Ti\n", "")
    raise AssertionError(f"unexpected: {argv}")


def _blackwell_gpu_runner(argv, **kwargs):
    if list(argv) == list(HOST_GPU_QUERY):
        return subprocess.CompletedProcess(argv, 0, "0, RTX 5060, 999.1\n", "")
    if list(argv) == list(HOST_GPU_COMPUTE_QUERY):
        return subprocess.CompletedProcess(argv, 0, "0, 12.0\n", "")
    if argv[:2] == ["docker", "run"]:
        return subprocess.CompletedProcess(argv, 0, "0, RTX 5060\n", "")
    raise AssertionError(f"unexpected: {argv}")


def test_off_policy_never_requests_gpu() -> None:
    decision = admit_gpu("off", "ai", runner=lambda *a, **k: pytest.fail("no probe"))
    assert decision["requested"] is False and decision["admitted"] is False


def test_cpu_only_category_is_never_gpu() -> None:
    decision = admit_gpu("auto", "web", runner=lambda *a, **k: pytest.fail("no probe"))
    assert decision["requested"] is False and decision["admitted"] is False


def test_auto_falls_back_to_cpu_without_host_gpu() -> None:
    decision = admit_gpu("auto", "ai", runner=_no_gpu_runner)
    assert decision["requested"] is True
    assert decision["admitted"] is False
    assert decision["degraded"] is True


def test_auto_admits_when_host_and_passthrough_verify() -> None:
    decision = admit_gpu("auto", "crypto", runner=_full_gpu_runner)
    assert decision["admitted"] is True
    assert decision["degraded"] is False


def test_auto_falls_back_before_passing_unsupported_blackwell_gpu() -> None:
    decision = admit_gpu("auto", "ai", runner=_blackwell_gpu_runner)
    assert decision["admitted"] is False
    assert decision["degraded"] is True
    assert "12.0" in decision["reason"]
    assert "9.0" in decision["reason"]


def test_required_rejects_unsupported_blackwell_gpu() -> None:
    with pytest.raises(GpuError, match=r"12\.0.*9\.0"):
        admit_gpu("required", "rev", runner=_blackwell_gpu_runner)


def test_required_without_gpu_is_an_exact_blocker() -> None:
    with pytest.raises(GpuError, match="no usable host NVIDIA GPU"):
        admit_gpu("required", "rev", runner=_no_gpu_runner)


def test_required_on_cpu_only_category_is_blocked() -> None:
    with pytest.raises(GpuError, match="never uses a GPU"):
        admit_gpu("required", "web", runner=lambda *a, **k: pytest.fail("no probe"))


def _gpu_spec(tmp_path: Path, category: str = "ai") -> SandboxSpec:
    source = tmp_path / "input"
    source.mkdir()
    source.chmod(0o555)
    lane_root = tmp_path / "workers" / "root"
    return SandboxSpec(
        run_id="run-1", contest_slug="demo", challenge_id="abc", category=category,
        lane_id="root", source=source, lane_root=lane_root,
        input_fingerprint="0" * 64, image=f"ctf-os-sandbox:{category}",
    )


def test_argv_has_no_gpu_without_admission(tmp_path: Path) -> None:
    argv = build_run_argv(_gpu_spec(tmp_path))
    assert "--gpus" not in argv


def test_argv_adds_scoped_gpu_only_when_admitted(tmp_path: Path) -> None:
    argv = build_run_argv(_gpu_spec(tmp_path), gpu={"admitted": True})
    assert "--gpus" in argv and "all" in argv
    assert f"NVIDIA_DRIVER_CAPABILITIES={'compute,utility'}" in argv
    # No host device or Docker socket is ever mounted for a GPU sandbox.
    assert not any("/dev" in token for token in argv)
    assert not any("docker.sock" in token for token in argv)


def test_degraded_admission_still_yields_cpu_argv(tmp_path: Path) -> None:
    decision = admit_gpu("auto", "ai", runner=_no_gpu_runner)
    argv = build_run_argv(_gpu_spec(tmp_path), gpu=decision)
    assert "--gpus" not in argv


def test_doctor_and_runtime_share_the_same_host_probe() -> None:
    # The doctor and the live runtime must probe the host GPU identically.
    assert DOCTOR_HOST_GPU_QUERY == HOST_GPU_QUERY
    assert gpu_run_flags()[:2] == ["--gpus", "all"]
