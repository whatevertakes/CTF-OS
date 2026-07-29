"""Exact local Docker image identity helpers.

CTF-OS deliberately treats ``runtime.image_digest`` as a local Docker image
ID, not as a registry RepoDigest.  The only accepted shape is Docker's
canonical ``sha256:<64 lowercase hex>`` image ID, which can be passed directly
to ``docker run``.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable, Sequence
from typing import Any

IMAGE_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
Runner = Callable[..., subprocess.CompletedProcess[str]]


class ImageReferenceError(ValueError):
    """Raised when a configured image name or local image ID is invalid."""


def validate_image_name(value: object) -> str:
    """Return a safe, non-empty Docker image name."""

    if not isinstance(value, str) or not value.strip():
        raise ImageReferenceError("image must be a non-empty string")
    if any(
        character.isspace()
        or ord(character) < 0x20
        or ord(character) == 0x7F
        for character in value
    ):
        raise ImageReferenceError("image contains whitespace or control characters")
    return value


def validate_image_digest(value: object) -> str:
    """Return an exact lowercase local Docker image ID."""

    if not isinstance(value, str) or IMAGE_DIGEST_PATTERN.fullmatch(value) is None:
        raise ImageReferenceError(
            "image_digest must be lowercase sha256:<64 hex> local image ID"
        )
    return value


def effective_image_reference(image: object, image_digest: object | None) -> str:
    """Return the exact reference that Docker must execute."""

    name = validate_image_name(image)
    if image_digest is None:
        return name
    return validate_image_digest(image_digest)


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
        return {"available": False, "exit_code": 124, "error": "timeout"}
    except OSError as error:
        return {"available": False, "exit_code": 126, "error": str(error)}
    output = (result.stdout or result.stderr).strip()
    return {
        "available": True,
        "exit_code": result.returncode,
        "output": output[:4096],
    }


def inspect_local_image(
    image: str,
    *,
    runner: Runner = subprocess.run,
    docker: str = "docker",
) -> dict[str, Any]:
    """Return bounded Docker metadata for one local image reference."""

    reference = validate_image_name(image)
    result = _capture(
        [
            docker,
            "image",
            "inspect",
            reference,
            "--format",
            "{{json .Id}}\n{{json .RepoDigests}}",
        ],
        runner=runner,
    )
    if result.get("exit_code") != 0:
        return {
            "name": reference,
            "available": False,
            "error": result.get("output", result.get("error", "not found")),
        }
    fields = str(result.get("output", "")).splitlines()
    try:
        if len(fields) != 2:
            raise ValueError("unexpected field count")
        image_id = json.loads(fields[0])
        repo_digests = json.loads(fields[1])
        validate_image_digest(image_id)
        if not isinstance(repo_digests, list) or not all(
            isinstance(item, str) for item in repo_digests
        ):
            raise ValueError("unexpected digest type")
    except (json.JSONDecodeError, ImageReferenceError, ValueError):
        return {
            "name": reference,
            "available": True,
            "error": "docker returned malformed image metadata",
        }
    return {
        "name": reference,
        "available": True,
        "id": image_id,
        "repo_digests": repo_digests,
    }


def image_status_is_usable(status: dict[str, Any]) -> bool:
    """Return whether an inspect result identifies one exact local image."""

    return (
        status.get("available") is True
        and "error" not in status
        and isinstance(status.get("id"), str)
        and IMAGE_DIGEST_PATTERN.fullmatch(status["id"]) is not None
    )
