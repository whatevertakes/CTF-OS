"""Pre-contest host and image diagnostics, separate from live Solve."""

from __future__ import annotations

import platform
from pathlib import Path
import re
import subprocess
from typing import Any, Callable

from .categories import CATEGORIES
from .images import smoke_images


PROFILES = CATEGORIES
IMAGES = tuple(f"ctf-os-sandbox:{profile}" for profile in PROFILES)


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
    return {
        "schema_version": 1,
        "ok": all(check["ok"] for check in checks),
        "checks": checks,
        "images": images,
        "build_command": ["sandbox/build-images.sh"],
        "solve_builds_images": False,
    }
