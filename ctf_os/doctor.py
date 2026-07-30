"""Read-only host diagnostics for the CTF-OS control plane."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from .capabilities import CapabilityError, inspect_pinned_capabilities
from .config import EngineConfig
from .container_tools import detect_gpu_plan, detect_kvm
from .images import (
    effective_image_reference,
    image_status_is_usable,
    inspect_local_image,
)

Runner = Callable[..., subprocess.CompletedProcess[str]]


def _capture(
    command: Sequence[str],
    *,
    runner: Runner,
    timeout: int = 10,
) -> dict[str, Any]:
    try:
        result = runner(
            list(command),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError:
        return {"available": False, "exit_code": 127}
    except subprocess.TimeoutExpired:
        return {"available": True, "exit_code": 124, "error": "timeout"}
    except OSError as error:
        return {"available": False, "exit_code": 126, "error": str(error)}
    output = (result.stdout or result.stderr).strip()
    return {
        "available": True,
        "exit_code": result.returncode,
        "output": output[:4096],
    }


def _memory_gib() -> float | None:
    try:
        fields = (Path("/proc/meminfo")).read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        return None
    for line in fields:
        if line.startswith("MemTotal:"):
            _, kib, *_ = line.split()
            return round(int(kib) / 1024 / 1024, 2)
    return None


def _image_report(
    config: EngineConfig,
    *,
    docker_available: bool,
    runner: Runner,
) -> dict[str, Any]:
    image_name = config.runtime.image
    configured_digest = config.runtime.image_digest
    execution_reference = effective_image_reference(
        image_name, configured_digest
    )
    if not docker_available:
        return {
            "name": image_name,
            "available": False,
            "error": "Docker daemon unavailable",
            "configured_digest": configured_digest,
            "execution_reference": execution_reference,
            "execution_available": False,
            "pin_status": (
                "missing" if configured_digest is not None else "unpinned"
            ),
        }

    tag_status = inspect_local_image(image_name, runner=runner)
    tag_usable = image_status_is_usable(tag_status)
    report = {
        **tag_status,
        "configured_digest": configured_digest,
        "execution_reference": execution_reference,
    }
    if configured_digest is None:
        report.update(
            {
                "execution_available": tag_usable,
                "pin_status": "unpinned",
            }
        )
        return report

    if tag_usable and tag_status.get("id") == configured_digest:
        pinned_status = tag_status
    else:
        pinned_status = inspect_local_image(configured_digest, runner=runner)
    pinned_usable = (
        image_status_is_usable(pinned_status)
        and pinned_status.get("id") == configured_digest
    )
    if not pinned_usable:
        pin_status = "missing"
    elif tag_usable and tag_status.get("id") == configured_digest:
        pin_status = "matched"
    else:
        pin_status = "mismatch"
    report.update(
        {
            "execution_available": pinned_usable,
            "pin_status": pin_status,
            "pinned_image": pinned_status,
        }
    )
    return report


def _managed_capability_report(
    image: dict[str, Any],
    *,
    runner: Runner,
) -> dict[str, Any]:
    """Probe the exact execution image used by managed challenge sessions."""

    digest = image.get("configured_digest")
    if (
        image.get("execution_available") is not True
        or image.get("pin_status") != "matched"
        or not isinstance(digest, str)
    ):
        return {
            "ok": False,
            "status": "blocked",
            "error": (
                "managed readiness requires runtime.image_digest to match "
                "the local tool image"
            ),
        }
    try:
        report = inspect_pinned_capabilities(
            digest,
            runner=runner,
        )
    except CapabilityError as error:
        return {
            "ok": False,
            "status": "probe_failed",
            "image_digest": digest,
            "error": str(error)[:1024],
        }
    return {
        **report,
        "status": "ready" if report.get("ok") is True else "missing",
    }


def collect_diagnostics(
    config: EngineConfig,
    *,
    runner: Runner = subprocess.run,
    which: Callable[[str], str | None] = shutil.which,
    calibrate: bool = False,
) -> dict[str, Any]:
    """Collect bounded diagnostics without changing the host or config."""

    codex = _capture(["codex", "--version"], runner=runner)
    docker = _capture(
        ["docker", "version", "--format", "{{json .Server.Version}}"],
        runner=runner,
    )
    docker_available = docker.get("exit_code") == 0
    image = _image_report(
        config,
        docker_available=docker_available,
        runner=runner,
    )
    managed_capabilities = _managed_capability_report(
        image,
        runner=runner,
    )
    try:
        gpu_plan = detect_gpu_plan(
            policy="auto", runner=runner, which=which
        )
        gpu = {
            "available": gpu_plan is not None,
            "mode": gpu_plan.mode if gpu_plan else None,
        }
    except Exception as error:  # diagnostics must report, not crash
        gpu = {"available": False, "error": str(error)}
    try:
        kvm = {"available": detect_kvm(policy="auto")}
    except Exception as error:
        kvm = {"available": False, "error": str(error)}

    disk = shutil.disk_usage(config.workspace_root)
    cpu_count = os.cpu_count()
    memory_gib = _memory_gib()
    warnings: list[str] = []
    if codex.get("exit_code") != 0:
        warnings.append("Codex CLI is unavailable")
    if not docker_available:
        warnings.append("Docker daemon is unavailable")
    else:
        if not image_status_is_usable(image):
            warnings.append(f"tool image is missing: {config.runtime.image}")
        pin_status = image["pin_status"]
        if pin_status == "unpinned":
            warnings.append("runtime.image_digest is not pinned")
        elif pin_status == "mismatch":
            warnings.append(
                "runtime.image tag does not match configured image_digest: "
                f"{image.get('id', 'unavailable')} != "
                f"{config.runtime.image_digest}"
            )
        elif pin_status == "missing":
            warnings.append(
                "pinned tool image is missing: "
                f"{config.runtime.image_digest}"
            )
        if managed_capabilities.get("status") == "blocked":
            warnings.append(
                "managed capability readiness is blocked until the local "
                "tool image is exactly pinned"
            )
        elif managed_capabilities.get("status") == "probe_failed":
            warnings.append(
                "managed capability readiness probe failed: "
                f"{managed_capabilities.get('error', 'unknown error')}"
            )
        elif managed_capabilities.get("ok") is not True:
            missing = managed_capabilities.get("missing", [])
            detail = (
                ", ".join(str(item) for item in missing)
                if isinstance(missing, list)
                else "unknown"
            )
            warnings.append(
                "managed tool image is missing required capabilities: "
                f"{detail}"
            )

    image_ready = (
        image.get("execution_available") is True
        and image.get("pin_status") == "matched"
    )

    report: dict[str, Any] = {
        "ok": (
            codex.get("exit_code") == 0
            and docker_available
            and image_ready
            and managed_capabilities.get("ok") is True
        ),
        "workspace": str(config.workspace_root),
        "codex": codex,
        "docker": docker,
        "image": image,
        "managed_capabilities": managed_capabilities,
        "gpu": gpu,
        "kvm": kvm,
        "host": {
            "logical_cpu": cpu_count,
            "memory_gib": memory_gib,
            "disk_free_gib": round(disk.free / 1024**3, 2),
        },
        "policy": {
            "network_default": config.runtime.network_default,
            "logical_workers_per_challenge": (
                config.resources.worker_slots_per_challenge
            ),
            "provider_max_concurrent_calls": (
                config.resources.provider_max_concurrent_calls
            ),
            "manual_submission": True,
        },
        "warnings": warnings,
    }
    if calibrate:
        safe_cpu = max(1, (cpu_count or 1) - 4)
        safe_memory = (
            max(2, int(memory_gib) - 8) if memory_gib is not None else None
        )
        report["calibration"] = {
            "write_performed": False,
            "suggested_tool_cpu_budget": min(
                config.resources.tool_cpu_budget, safe_cpu
            ),
            "suggested_tool_memory_gib": (
                min(config.resources.tool_memory_gib, safe_memory)
                if safe_memory is not None
                else config.resources.tool_memory_gib
            ),
            "note": (
                "Suggestions only; CTF-OS never raises budgets or rewrites "
                "engine.toml during doctor."
            ),
        }
    return report
