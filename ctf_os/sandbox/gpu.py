"""Shared GPU admission policy for the doctor probe and the live sandbox runtime.

Both the pre-contest `doctor` checks and the live `create()` path use these
helpers so the diagnostic and execution code can never disagree about whether a
GPU is present, whether Docker NVIDIA passthrough works, or which categories may
receive a scoped GPU device request. CPU-only hosts stay fully supported: the
default `auto` policy silently falls back to CPU when a GPU cannot be admitted.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Mapping
from typing import Any

# Only these categories run GPU-accelerated tooling (PyTorch/ONNX, hashcat CUDA,
# CuPy). Every other category is always CPU-only.
GPU_CATEGORIES = frozenset({"ai", "crypto", "rev"})
GPU_POLICIES = frozenset({"auto", "off", "required"})
# Compute + utility only: never video/graphics/display, and never any extra host
# device or the Docker socket.
NVIDIA_DRIVER_CAPABILITIES = "compute,utility"
# The exact host driver query shared by doctor and any host-side GPU check.
HOST_GPU_QUERY = (
    "nvidia-smi",
    "--query-gpu=index,name,driver_version",
    "--format=csv,noheader,nounits",
)


class GpuError(RuntimeError):
    pass


def gpu_run_flags() -> list[str]:
    """The scoped Docker GPU device request added only to an admitted sandbox."""

    return ["--gpus", "all", "--env", f"NVIDIA_DRIVER_CAPABILITIES={NVIDIA_DRIVER_CAPABILITIES}"]


def _run(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    argv: list[str],
    *,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    try:
        return runner(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(argv, 127, "", str(exc))
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(argv, 124, "", str(exc))
    except OSError as exc:
        return subprocess.CompletedProcess(argv, 126, "", str(exc))


def host_gpu_present(
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[bool, str]:
    """Return (present, detail). A missing driver or no device is not an error."""

    result = _run(runner, list(HOST_GPU_QUERY), timeout=20)
    detail = (result.stdout or result.stderr).strip()
    if result.returncode == 127:
        return False, detail or "nvidia-smi not installed"
    if result.returncode != 0:
        return False, detail or "nvidia-smi failed"
    return bool(result.stdout.strip()), detail or "no NVIDIA GPU detected"


def docker_gpu_passthrough(
    *,
    image: str = "ctf-os-sandbox:base",
    docker: str = "docker",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[bool, str]:
    """Validate that Docker can actually pass a GPU into a hardened container."""

    argv = [
        docker, "run", "--rm", "--pull", "never", *gpu_run_flags(),
        "--network", "none", "--read-only", "--security-opt", "no-new-privileges",
        "--cap-drop", "ALL", "--user", "1001:1001",
        "--entrypoint", "nvidia-smi", image,
        "--query-gpu=index,name", "--format=csv,noheader,nounits",
    ]
    result = _run(runner, argv, timeout=90)
    detail = (result.stdout or result.stderr).strip()
    return (result.returncode == 0 and bool(result.stdout.strip())), detail


def admit_gpu(
    policy: str,
    category: str,
    *,
    image: str = "ctf-os-sandbox:base",
    docker: str = "docker",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Decide whether one sandbox may receive a scoped GPU device request.

    `off` never uses a GPU. `auto` uses one only when the category supports it and
    both the host driver and Docker passthrough verify, otherwise it falls back to
    CPU. `required` raises GpuError with an exact blocker when a GPU cannot be
    admitted.
    """

    if policy not in GPU_POLICIES:
        raise GpuError(f"gpu policy must be one of {sorted(GPU_POLICIES)}")
    decision: dict[str, Any] = {
        "policy": policy,
        "category": category,
        "requested": False,
        "admitted": False,
        "degraded": False,
        "reason": "",
    }
    if policy == "off":
        decision["reason"] = "gpu disabled by policy"
        return decision
    if category not in GPU_CATEGORIES:
        if policy == "required":
            raise GpuError(f"gpu required but category {category!r} never uses a GPU")
        decision["reason"] = f"category {category} is CPU-only"
        return decision
    decision["requested"] = True
    present, host_detail = host_gpu_present(runner)
    if not present:
        if policy == "required":
            raise GpuError(f"gpu required but no usable host NVIDIA GPU: {host_detail}")
        decision["degraded"] = True
        decision["reason"] = f"no host GPU; CPU fallback ({host_detail})"
        return decision
    passthrough_ok, passthrough_detail = docker_gpu_passthrough(
        image=image, docker=docker, runner=runner
    )
    if not passthrough_ok:
        if policy == "required":
            raise GpuError(
                f"gpu required but Docker NVIDIA passthrough failed: {passthrough_detail}"
            )
        decision["degraded"] = True
        decision["reason"] = f"Docker GPU passthrough unavailable; CPU fallback ({passthrough_detail})"
        return decision
    decision["admitted"] = True
    decision["reason"] = f"gpu admitted for {category} ({host_detail})"
    return decision


def gpu_admitted(decision: Mapping[str, Any] | None) -> bool:
    return bool(decision and decision.get("admitted"))
