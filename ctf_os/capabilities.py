"""Pinned image capability contract used by managed preflight.

The generated tool manifest is intentionally non-canonical image metadata.  A
managed session nevertheless needs a deterministic, fail-closed answer before
it spends a model call.  This module accepts the existing v1 tool manifest and
the smaller v2 capability manifest emitted by ``ctf-capabilities``.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from typing import Any

from ctf_os.images import validate_image_digest
from ctf_os.store.atomic import StrictJSONError, strict_json_loads


REQUIRED_MANAGED_CAPABILITIES = frozenset(
    {"convert", "sqlite_readonly", "z3", "ortools", "angr_python"}
)
MAX_CAPABILITY_OUTPUT_BYTES = 256 * 1024
Runner = Callable[..., subprocess.CompletedProcess[bytes]]


class CapabilityError(RuntimeError):
    """A pinned image did not provide a valid capability contract."""


def normalize_capability_manifest(raw: object) -> dict[str, bool]:
    """Normalize capability manifest v1 or v2 into ``name -> available``."""

    if not isinstance(raw, dict):
        raise CapabilityError("capability manifest root must be an object")
    version = raw.get("schema_version")
    if version == 1:
        records = raw.get("tools")
    elif version == 2:
        records = raw.get("capabilities")
    else:
        raise CapabilityError(
            f"unsupported capability manifest schema_version: {version!r}"
        )
    if not isinstance(records, list):
        raise CapabilityError("capability manifest records must be an array")

    normalized: dict[str, bool] = {}
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise CapabilityError(f"capability record {index} must be an object")
        name = record.get("name")
        available = record.get("available")
        if (
            not isinstance(name, str)
            or not name
            or isinstance(available, bool) is False
        ):
            raise CapabilityError(
                f"capability record {index} requires name and boolean available"
            )
        folded = name.casefold()
        if folded in normalized:
            raise CapabilityError(f"duplicate capability name: {name}")
        normalized[folded] = available
    return normalized


def inspect_pinned_capabilities(
    image_digest: str,
    *,
    runner: Runner = subprocess.run,
    docker: str = "docker",
    required: frozenset[str] = REQUIRED_MANAGED_CAPABILITIES,
) -> dict[str, Any]:
    """Probe one exact local image with network and filesystem writes denied."""

    digest = validate_image_digest(image_digest)
    command = [
        docker,
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=64m",
        "--entrypoint",
        "ctf-capabilities",
        digest,
        "--json",
    ]
    try:
        result = runner(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except FileNotFoundError as error:
        raise CapabilityError("Docker executable is unavailable") from error
    except subprocess.TimeoutExpired as error:
        raise CapabilityError("image capability probe timed out") from error
    except OSError as error:
        raise CapabilityError(f"image capability probe failed: {error}") from error

    stdout_value = result.stdout or b""
    stdout = (
        stdout_value.encode("utf-8", errors="strict")
        if isinstance(stdout_value, str)
        else stdout_value
    )
    if len(stdout) > MAX_CAPABILITY_OUTPUT_BYTES:
        raise CapabilityError("image capability output exceeds byte limit")
    if result.returncode != 0:
        stderr_value = result.stderr or b""
        stderr = (
            stderr_value.encode("utf-8", errors="replace")
            if isinstance(stderr_value, str)
            else stderr_value
        )
        detail = stderr[:512].decode("utf-8", errors="replace")
        raise CapabilityError(
            f"image capability probe exited {result.returncode}: {detail.strip()}"
        )
    try:
        raw = strict_json_loads(
            stdout,
            max_bytes=MAX_CAPABILITY_OUTPUT_BYTES,
            max_depth=32,
        )
    except StrictJSONError as error:
        raise CapabilityError(f"invalid image capability output: {error}") from error
    capabilities = normalize_capability_manifest(raw)
    missing = sorted(name for name in required if not capabilities.get(name, False))
    return {
        "schema_version": raw.get("schema_version"),
        "image_digest": digest,
        "required": sorted(required),
        "available": sorted(
            name for name in required if capabilities.get(name, False)
        ),
        "missing": missing,
        "ok": not missing,
    }


__all__ = [
    "CapabilityError",
    "MAX_CAPABILITY_OUTPUT_BYTES",
    "REQUIRED_MANAGED_CAPABILITIES",
    "inspect_pinned_capabilities",
    "normalize_capability_manifest",
]
