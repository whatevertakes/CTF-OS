"""Local-only category image selection for a live race."""

from __future__ import annotations

import json
import subprocess
from typing import Any, Callable, Sequence

from .categories import CATEGORIES


class ImageError(RuntimeError):
    pass


Runner = Callable[..., subprocess.CompletedProcess[str]]


def recommended_image(category: str) -> str:
    if category not in CATEGORIES:
        raise ImageError(f"unsupported image category: {category}")
    return f"ctf-os-sandbox:{category}"


def inspect_image(image: str, *, docker: str = "docker", runner: Runner = subprocess.run) -> dict[str, Any]:
    try:
        result = runner(
            [docker, "image", "inspect", image], capture_output=True, text=True,
            timeout=20, check=False,
        )
    except FileNotFoundError:
        return {"image": image, "available": False, "reason": "docker CLI not found"}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"image": image, "available": False, "reason": str(exc)}
    if result.returncode:
        return {
            "image": image,
            "available": False,
            "reason": result.stderr.strip() or "image not present locally",
        }
    try:
        payload = json.loads(result.stdout)
        row = payload[0]
        image_id = str(row["Id"])
        size = int(row.get("Size", 0))
        labels = row.get("Config", {}).get("Labels", {}) or {}
    except (json.JSONDecodeError, IndexError, KeyError, TypeError, ValueError) as exc:
        return {"image": image, "available": False, "reason": f"malformed image inspect: {exc}"}
    if labels.get("org.ctf-os.sandbox") != "true":
        return {"image": image, "available": False, "reason": "image is not labelled as a CTF-OS sandbox"}
    return {"image": image, "available": True, "id": image_id, "size": size, "labels": labels}


def select_image(
    category: str,
    *,
    docker: str = "docker",
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    recommended = recommended_image(category)
    primary = inspect_image(recommended, docker=docker, runner=runner)
    if primary["available"]:
        return {
            "status": "AVAILABLE",
            "recommended_image": recommended,
            "selected_image": recommended,
            "image_available": True,
            "degraded": False,
            "inspections": [primary],
        }
    inspections = [primary]
    if recommended != "ctf-os-sandbox:base":
        fallback = inspect_image("ctf-os-sandbox:base", docker=docker, runner=runner)
        inspections.append(fallback)
        if fallback["available"]:
            return {
                "status": "DEGRADED",
                "recommended_image": recommended,
                "selected_image": "ctf-os-sandbox:base",
                "image_available": True,
                "degraded": True,
                "reason": f"recommended image unavailable: {primary['reason']}",
                "inspections": inspections,
                "recovery_command": ["sandbox/build-images.sh", category],
            }
    return {
        "status": "UNAVAILABLE",
        "recommended_image": recommended,
        "selected_image": None,
        "image_available": False,
        "degraded": False,
        "reason": "; ".join(str(row["reason"]) for row in inspections),
        "inspections": inspections,
        "recovery_command": ["sandbox/build-images.sh", category],
    }


def smoke_images(
    profiles: Sequence[str] = CATEGORIES,
    *,
    docker: str = "docker",
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    rows = [inspect_image(recommended_image(profile), docker=docker, runner=runner) for profile in profiles]
    return {"profiles": rows, "all_available": all(row["available"] for row in rows)}
