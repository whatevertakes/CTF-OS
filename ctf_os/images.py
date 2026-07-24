"""Local-only category image selection for a live race."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from .categories import CATEGORIES


class ImageError(RuntimeError):
    pass


Runner = Callable[..., subprocess.CompletedProcess[str]]


def expected_build_sha256(repo_root: Path | None = None) -> str:
    root = (
        repo_root.resolve()
        if repo_root is not None
        else Path(__file__).resolve().parents[1]
    )
    sandbox = root / "sandbox"
    if sandbox.is_symlink() or not sandbox.is_dir():
        raise ImageError("sandbox build inputs are unavailable or unsafe")
    paths = [sandbox, *sandbox.rglob("*")]
    dockerignore = root / ".dockerignore"
    if dockerignore.exists() or dockerignore.is_symlink():
        paths.append(dockerignore)
    if not paths:
        raise ImageError("sandbox build inputs are empty")
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda value: value.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        try:
            mode = path.lstat().st_mode & 0o7777
            if path.is_symlink():
                kind = b"symlink"
                content = os.readlink(path).encode("utf-8")
            elif path.is_dir():
                kind = b"directory"
                content = b""
            elif path.is_file():
                kind = b"file"
                content = path.read_bytes()
            else:
                raise ImageError(f"unsupported sandbox build input: {path}")
        except OSError as exc:
            raise ImageError(f"sandbox build input is unreadable: {path}: {exc}") from exc
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(kind).to_bytes(8, "big"))
        digest.update(kind)
        digest.update(mode.to_bytes(4, "big"))
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def expected_lock_sha256() -> str:
    lock = Path(__file__).resolve().parents[1] / "sandbox" / "tool-versions.lock"
    try:
        return hashlib.sha256(lock.read_bytes()).hexdigest()
    except OSError as exc:
        raise ImageError(f"tool version lock is unavailable: {exc}") from exc


def recommended_image(category: str) -> str:
    if category not in CATEGORIES:
        raise ImageError(f"unsupported image category: {category}")
    return f"ctf-os-sandbox:{category}"


def inspect_image(
    image: str,
    *,
    expected_profile: str | None = None,
    docker: str = "docker",
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
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
        operating_system = str(row.get("Os", ""))
        architecture = str(row.get("Architecture", ""))
    except (json.JSONDecodeError, IndexError, KeyError, TypeError, ValueError) as exc:
        return {"image": image, "available": False, "reason": f"malformed image inspect: {exc}"}
    if labels.get("org.ctf-os.sandbox") != "true":
        return {"image": image, "available": False, "reason": "image is not labelled as a CTF-OS sandbox"}
    profile = expected_profile
    if profile is None and image.startswith("ctf-os-sandbox:"):
        profile = image.removeprefix("ctf-os-sandbox:")
    if profile and labels.get("org.ctf-os.profile") != profile:
        return {
            "image": image,
            "available": False,
            "reason": f"image profile label does not match {profile}",
        }
    if labels.get("org.ctf-os.build-policy") != "pre-contest-pinned":
        return {
            "image": image,
            "available": False,
            "reason": "image build-policy label is missing or unsupported",
        }
    expected_lock = expected_lock_sha256()
    if labels.get("org.ctf-os.lock-sha256") != expected_lock:
        return {
            "image": image,
            "available": False,
            "reason": "image was not built from the current tool version lock",
        }
    expected_build = expected_build_sha256()
    if labels.get("org.ctf-os.build-sha256") != expected_build:
        return {
            "image": image,
            "available": False,
            "reason": "image was not built from the current sandbox build inputs",
        }
    if operating_system != "linux" or architecture not in {"amd64", "x86_64"}:
        return {
            "image": image,
            "available": False,
            "reason": f"unsupported image platform: {operating_system}/{architecture}",
        }
    return {
        "image": image,
        "available": True,
        "id": image_id,
        "size": size,
        "labels": labels,
        "platform": f"{operating_system}/{architecture}",
    }


def select_image(
    category: str,
    *,
    docker: str = "docker",
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    recommended = recommended_image(category)
    primary = inspect_image(
        recommended, expected_profile=category, docker=docker, runner=runner
    )
    if primary["available"]:
        return {
            "status": "AVAILABLE",
            "recommended_image": recommended,
            "selected_image": primary["id"],
            "image_available": True,
            "degraded": False,
            "inspections": [primary],
        }
    inspections = [primary]
    if recommended != "ctf-os-sandbox:base":
        fallback = inspect_image(
            "ctf-os-sandbox:base", expected_profile="base", docker=docker, runner=runner
        )
        inspections.append(fallback)
        if fallback["available"]:
            return {
                "status": "DEGRADED",
                "recommended_image": recommended,
                "selected_image": fallback["id"],
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
    rows = [
        inspect_image(
            recommended_image(profile),
            expected_profile=profile,
            docker=docker,
            runner=runner,
        )
        for profile in profiles
    ]
    return {"profiles": rows, "all_available": all(row["available"] for row in rows)}
