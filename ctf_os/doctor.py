"""Pre-contest host and image diagnostics, separate from live Solve."""

from __future__ import annotations

import platform
import re
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from .categories import CATEGORIES
from .images import smoke_images
from .sandbox.gpu import (
    HOST_GPU_QUERY,
    MAX_GPU_COMPUTE_CAPABILITY,
    NVIDIA_DRIVER_CAPABILITIES,
    host_gpu_compute_capabilities,
)

PROFILES = CATEGORIES
IMAGES = tuple(f"ctf-os-sandbox:{profile}" for profile in PROFILES)

GPU_AI_TORCH_PROBE = """
import torch
assert torch.version.cuda is not None
assert torch.cuda.is_available()
values = torch.arange(1024, device="cuda", dtype=torch.float32)
assert values.sum().item() == 523776
torch.cuda.synchronize()
print(torch.version.cuda, torch.cuda.get_device_name(0))
"""

GPU_AI_ONNX_PROBE = """
import numpy as np
import torch
import onnxruntime as ort
from onnx import TensorProto, helper
assert "CUDAExecutionProvider" in ort.get_available_providers()
node = helper.make_node("Add", ["x", "x"], ["y"])
graph = helper.make_graph(
    [node], "gpu-smoke",
    [helper.make_tensor_value_info("x", TensorProto.FLOAT, [4])],
    [helper.make_tensor_value_info("y", TensorProto.FLOAT, [4])],
)
model = helper.make_model(
    graph, opset_imports=[helper.make_opsetid("", 17)], ir_version=9,
)
session = ort.InferenceSession(
    model.SerializeToString(),
    providers=["CUDAExecutionProvider", "CPUExecutionProvider"],
)
assert session.get_providers()[0] == "CUDAExecutionProvider"
result = session.run(None, {"x": np.ones(4, dtype=np.float32)})[0]
assert result.tolist() == [2.0, 2.0, 2.0, 2.0]
print(session.get_providers())
"""

GPU_CRYPTO_HASHCAT_PROBE = """
mkdir -p "$HOME/.local/share/hashcat"
printf '%s\n' 5f4dcc3b5aa765d61d8327deb882cf99 > /work/hash
printf '%s\n' password > /work/words
hashcat -m 0 -a 0 --backend-ignore-opencl --potfile-disable --quiet \
  --outfile /work/cracked /work/hash /work/words
grep -qx '5f4dcc3b5aa765d61d8327deb882cf99:password' /work/cracked
hashcat -I --backend-ignore-opencl
"""

GPU_REV_CUPY_PROBE = r"""
import cupy as cp
values = cp.arange(64, dtype=cp.uint32)
output = cp.empty_like(values)
kernel = cp.RawKernel(r'''
extern "C" __global__
void candidate_check(const unsigned int *input, unsigned int *output) {
    unsigned int i = blockDim.x * blockIdx.x + threadIdx.x;
    if (i < 64) output[i] = input[i] * input[i] + 7;
}
''', "candidate_check")
kernel((1,), (64,), (values, output))
cp.cuda.runtime.deviceSynchronize()
assert cp.all(output == values * values + 7).item()
print(cp.cuda.runtime.getDeviceProperties(0)["name"].decode())
"""

GPU_PROBES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("gpu-ai-torch", "ai", ("python3", "-c", GPU_AI_TORCH_PROBE)),
    ("gpu-ai-onnx", "ai", ("python3", "-c", GPU_AI_ONNX_PROBE)),
    ("gpu-crypto-hashcat", "crypto", ("sh", "-ec", GPU_CRYPTO_HASHCAT_PROBE)),
    ("gpu-rev-cupy", "rev", ("python3", "-c", GPU_REV_CUPY_PROBE)),
)


def run_doctor(
    repo: Path,
    *,
    docker: str = "docker",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.append({
        "name": "host-platform",
        "ok": platform.system() == "Linux" and platform.machine().casefold() in {"x86_64", "amd64"},
        "detail": f"{platform.system()} {platform.machine()}",
    })
    checks.append({
        "name": "repository-filesystem",
        "ok": repo.is_dir() and not repo.is_symlink(),
        "detail": str(repo.resolve()),
    })
    try:
        info = runner(
            [docker, "info", "--format", "{{.OSType}} {{.Architecture}}"],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        info = subprocess.CompletedProcess([], 127, "", str(exc))
    checks.append({
        "name": "docker-daemon",
        "ok": info.returncode == 0 and info.stdout.strip() in {"linux x86_64", "linux amd64"},
        "detail": (info.stdout or info.stderr).strip(),
    })
    try:
        compose = runner(
            [docker, "compose", "version", "--short"],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        compose = subprocess.CompletedProcess([], 127, "", str(exc))
    compose_text = compose.stdout.strip().lstrip("v")
    compose_match = re.match(r"^(\d+)\.(\d+)", compose_text)
    compose_version = (
        (int(compose_match.group(1)), int(compose_match.group(2)))
        if compose_match else (0, 0)
    )
    checks.append({
        "name": "docker-compose-v2",
        "ok": compose.returncode == 0 and compose_version >= (2, 24),
        "detail": (compose.stdout or compose.stderr).strip(),
    })
    images = smoke_images(docker=docker, runner=runner)
    checks.append({
        "name": "category-images",
        "ok": images["all_available"],
        "detail": images["profiles"],
    })
    checks.extend(
        _gpu_checks(
            images,
            docker=docker,
            runner=runner,
        )
    )
    return {
        "schema_version": 1,
        "ok": all(check["ok"] for check in checks),
        "checks": checks,
        "images": images,
        "build_command": ["sandbox/build-images.sh"],
        "solve_builds_images": False,
    }


def _gpu_checks(
    images: Mapping[str, Any],
    *,
    docker: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str, *, skipped: bool = False) -> None:
        checks.append({
            "name": name,
            "ok": ok,
            "status": "SKIPPED" if skipped else "PASS" if ok else "FAIL",
            "detail": detail[-8_000:],
        })

    # Shared with the live runtime's admission probe so diagnostics and execution
    # can never disagree about the host GPU.
    host = _run(runner, list(HOST_GPU_QUERY), timeout=20)
    host_detail = (host.stdout or host.stderr).strip()
    no_gpu = (
        host.returncode == 127
        or "no devices were found" in host_detail.casefold()
        or (host.returncode == 0 and not host.stdout.strip())
    )
    if no_gpu:
        add(
            "gpu-host-driver",
            True,
            host_detail or "no NVIDIA GPU detected; CPU profiles remain available",
            skipped=True,
        )
        for name in (
            "gpu-compute-compatibility",
            "gpu-docker-passthrough",
            *(row[0] for row in GPU_PROBES),
        ):
            add(name, True, "no usable host NVIDIA GPU; GPU probe not run", skipped=True)
        return checks
    if host.returncode:
        add("gpu-host-driver", False, host_detail or "nvidia-smi failed")
        for name in (
            "gpu-compute-compatibility",
            "gpu-docker-passthrough",
            *(row[0] for row in GPU_PROBES),
        ):
            add(name, True, "host NVIDIA driver failed; GPU probe not run", skipped=True)
        return checks
    add("gpu-host-driver", True, host_detail)

    capabilities, capability_detail = host_gpu_compute_capabilities(runner)
    maximum = (
        f"{MAX_GPU_COMPUTE_CAPABILITY[0]}.{MAX_GPU_COMPUTE_CAPABILITY[1]}"
    )
    unsupported = (
        []
        if capabilities is None
        else [
            value
            for value in capabilities
            if tuple(int(part) for part in value.split(".", 1))
            > MAX_GPU_COMPUTE_CAPABILITY
        ]
    )
    if capabilities is None or unsupported:
        reason = (
            f"host compute capability {', '.join(unsupported)} exceeds pinned "
            f"CUDA maximum {maximum}; CPU profiles remain available"
            if unsupported
            else (
                "host compute capability could not be verified; CPU profiles "
                f"remain available ({capability_detail})"
            )
        )
        add(
            "gpu-compute-compatibility",
            True,
            reason,
            skipped=True,
        )
        for name in ("gpu-docker-passthrough", *(row[0] for row in GPU_PROBES)):
            add(name, True, "GPU is not admitted; CPU fallback selected", skipped=True)
        return checks
    add(
        "gpu-compute-compatibility",
        True,
        f"compute capabilities {', '.join(capabilities)} are supported through {maximum}",
    )

    present = {
        str(row.get("image", "")).removeprefix("ctf-os-sandbox:"): bool(row.get("available"))
        for row in images.get("profiles", [])
        if isinstance(row, Mapping)
    }
    if not present.get("base", False):
        add(
            "gpu-docker-passthrough",
            False,
            "ctf-os-sandbox:base is absent; cannot validate scoped GPU passthrough",
        )
        for name, _profile, _command in GPU_PROBES:
            add(name, True, "GPU passthrough was not validated", skipped=True)
        return checks

    passthrough = _gpu_image_probe(
        "base",
        (
            "nvidia-smi",
            "--query-gpu=index,name",
            "--format=csv,noheader,nounits",
        ),
        docker=docker,
        runner=runner,
    )
    passthrough_detail = (passthrough.stdout or passthrough.stderr).strip()
    passthrough_ok = passthrough.returncode == 0 and bool(passthrough.stdout.strip())
    add(
        "gpu-docker-passthrough",
        passthrough_ok,
        passthrough_detail or "container nvidia-smi failed",
    )
    if not passthrough_ok:
        for name, _profile, _command in GPU_PROBES:
            add(name, True, "Docker GPU passthrough unavailable; probe not run", skipped=True)
        return checks

    for name, profile, command in GPU_PROBES:
        if not present.get(profile, False):
            add(name, True, f"ctf-os-sandbox:{profile} is absent", skipped=True)
            continue
        result = _gpu_image_probe(
            profile,
            command,
            docker=docker,
            runner=runner,
        )
        detail = "\n".join(
            stream.strip() for stream in (result.stdout, result.stderr) if stream.strip()
        )
        add(name, result.returncode == 0, detail or "real GPU operation passed")
    return checks


def _gpu_image_probe(
    profile: str,
    command: Sequence[str],
    *,
    docker: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> subprocess.CompletedProcess[str]:
    argv = [
        docker,
        "run",
        "--rm",
        "--pull",
        "never",
        "--gpus",
        "all",
        "--network",
        "none",
        "--read-only",
        "--security-opt",
        "no-new-privileges",
        "--cap-drop",
        "ALL",
        "--user",
        "1001:1001",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=256m,mode=1777",
        "--tmpfs",
        "/work:rw,nosuid,nodev,size=256m,mode=1777",
        "--tmpfs",
        "/home/ctf/.cache:rw,nosuid,nodev,size=256m,mode=0700,uid=1001,gid=1001",
        "--env",
        "HOME=/work",
        "--env",
        "XDG_DATA_HOME=/work/.local/share",
        "--env",
        f"NVIDIA_DRIVER_CAPABILITIES={NVIDIA_DRIVER_CAPABILITIES}",
        "--entrypoint",
        command[0],
        f"ctf-os-sandbox:{profile}",
        *command[1:],
    ]
    return _run(runner, argv, timeout=90)


def _run(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    argv: Sequence[str],
    *,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    try:
        return runner(
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(list(argv), 127, "", str(exc))
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(list(argv), 124, "", str(exc))
    except OSError as exc:
        return subprocess.CompletedProcess(list(argv), 126, "", str(exc))
