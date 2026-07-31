"""Pinned image capability contract used by managed preflight.

The generated tool manifest is intentionally non-canonical image metadata.  A
managed session nevertheless needs a deterministic, fail-closed answer before
it spends a model call.  This module accepts the existing v1 tool manifest and
the smaller v2 capability manifest emitted by ``ctf-capabilities``.
"""

from __future__ import annotations

import math
import re
import secrets
import subprocess
from collections.abc import Callable
from typing import Any

from ctf_os.images import validate_image_digest
from ctf_os.store.atomic import StrictJSONError, strict_json_loads


CORE_MANAGED_CAPABILITIES = frozenset(
    {
        "convert",
        "sqlite_readonly",
    }
)
CATEGORY_MANAGED_CAPABILITIES: dict[str, frozenset[str]] = {
    "web": frozenset(),
    "pwn": frozenset(
        {
            "angr_python",
            "z3",
            "pwn_crash_v1",
            "pwn_runtime_snapshot_v1",
            "pwn_exploit_effect_v1",
            "pwn_interaction_v1",
        }
    ),
    "rev": frozenset(
        {
            "angr_python",
            "z3",
            "rev_inventory_v2",
            "rev_safe_output",
            "rev_stdin_exec",
            "rev_runtime_exec_v1",
        }
    ),
    "crypto": frozenset(
        {
            "z3",
            "ortools",
            "pysat_cadical300",
            "pysat_kissat404",
            "cryptominisat5",
            "data_transcript_v1",
        }
    ),
    "forensic": frozenset(
        {
            "forensic_evidence_index_v1",
            "forensic_assertion_python3",
            "forensic_assertion_perl",
            "forensic_volatility3",
            "forensic_volatility_symbols",
            "forensic_sleuthkit",
            "forensic_ewf",
            "forensic_tshark",
            "forensic_zeek",
            "forensic_tesseract",
            "forensic_ocr_korean",
            "forensic_hwp",
        }
    ),
    "misc": frozenset(
        {
            "z3",
            "ortools",
            "misc_stegseek",
            "misc_zsteg",
            "misc_ffmpeg",
            "misc_sox",
            "misc_zbar",
            "data_transcript_v1",
        }
    ),
}
REQUIRED_MANAGED_CAPABILITIES = frozenset(
    CORE_MANAGED_CAPABILITIES.union(
        *CATEGORY_MANAGED_CAPABILITIES.values()
    )
)
_CATEGORY_ALIASES = {
    "binary": "pwn",
    "binary-exploitation": "pwn",
    "re": "rev",
    "reversing": "rev",
    "reverse": "rev",
    "cryptography": "crypto",
    "forensics": "forensic",
    "dfir": "forensic",
    "web-security": "web",
    "stego": "misc",
    "jail": "misc",
    "ppc": "misc",
    "custom-protocol": "misc",
}
REQUIRED_MANAGED_ATTESTATIONS: dict[str, dict[str, object]] = {
    "pwn_crash_v1": {
        "schema_version": 1,
        "contract_id": "ctfos.pwn.crash",
        "contract_version": 1,
        "path": "/opt/ctf-templates/pwn/crash_oracle.py",
        "sha256": (
            "ea0b580f549fc796dc814b08dc8e035d"
            "702b3fc148109dd8bbfca0250d856e7e"
        ),
    },
    "pwn_runtime_snapshot_v1": {
        "schema_version": 1,
        "contract_id": "ctfos.pwn.runtime_snapshot",
        "contract_version": 1,
        "path": "/opt/ctf-templates/pwn/runtime_snapshot.py",
        "sha256": (
            "e9d0927e42258a589d17b02f94071379"
            "ea015b040051a405cda455ba14879d97"
        ),
    },
    "pwn_exploit_effect_v1": {
        "schema_version": 1,
        "contract_id": "ctfos.pwn.exploit_effect",
        "contract_version": 1,
        "path": "/opt/ctf-templates/pwn/exploit_effect.py",
        "sha256": (
            "ef8827eb7cf5189893302c43560930de1"
            "f1e0a6c66636c9e5d485c0ecb114835"
        ),
    },
    "pwn_interaction_v1": {
        "schema_version": 1,
        "contract_id": "ctfos.pwn.interaction",
        "contract_version": 1,
        "path": "/opt/ctf-templates/pwn/interaction.py",
        "sha256": (
            "d2a5a4370242adb0fae75ac4ddc68ffd"
            "43952e671ba0abc0ad68f1924423b5b9"
        ),
    },
    "rev_inventory_v2": {
        "schema_version": 1,
        "contract_id": "ctfos.rev.inventory",
        "contract_version": 2,
        "path": "/opt/ctf-templates/rev/inventory_v2.py",
        "sha256": (
            "782d41566f3a288b458ae3fdbb04a068"
            "4f281158b14286739ea3cc1ecc39daee"
        ),
    },
    "rev_safe_output": {
        "schema_version": 1,
        "contract_id": "ctfos.rev.safe_output",
        "contract_version": 1,
        "path": "/opt/ctf-templates/rev/safe_output.py",
        "sha256": (
            "24fbff27464dc2ff12a754831ec87a1a"
            "8e9a0ffb4dde790bb738f83d97852951"
        ),
    },
    "rev_stdin_exec": {
        "schema_version": 1,
        "contract_id": "ctfos.rev.stdin_exec",
        "contract_version": 1,
        "path": "/opt/ctf-templates/rev/stdin_exec.py",
        "sha256": (
            "036edb158461aa32c6688a7f33f3d523"
            "f593202409b62377288c8c8e54b45610"
        ),
    },
    "rev_runtime_exec_v1": {
        "schema_version": 1,
        "contract_id": "ctfos.rev.runtime_exec",
        "contract_version": 1,
        "path": "/opt/ctf-templates/rev/runtime_exec.py",
        "sha256": (
            "9b2544102e8fa2ec7930b09f3d8b6500"
            "41bdf782eff6b5bab0454895194d0d79"
        ),
    },
    "data_transcript_v1": {
        "schema_version": 1,
        "contract_id": "ctfos.data_transcript.producer",
        "contract_version": 1,
        "path": "/opt/ctf-templates/common/data_transcript.py",
        "sha256": (
            "a0e5402456ba09f08429b016329900473"
            "66ca2680be5be52c0f308ef73e74788"
        ),
    },
    "forensic_evidence_index_v1": {
        "schema_version": 1,
        "contract_id": "ctfos.forensic.evidence_index",
        "contract_version": 1,
        "path": "/opt/ctf-templates/forensic/evidence_index.py",
        "sha256": (
            "a2d84dc83fb041413b667b1164bbe3f9"
            "3c7ab1b7db5485d9156f1b51f92eddf2"
        ),
    },
}
MAX_CAPABILITY_OUTPUT_BYTES = 256 * 1024
Runner = Callable[..., subprocess.CompletedProcess[bytes]]
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CapabilityError(RuntimeError):
    """A pinned image did not provide a valid capability contract."""


def required_managed_capabilities_for_category(
    category: str,
) -> frozenset[str]:
    """Return the fail-closed capability set for one challenge category."""

    if not isinstance(category, str) or not category.strip():
        raise CapabilityError("managed category must be a non-empty string")
    normalized = category.strip().casefold()
    normalized = _CATEGORY_ALIASES.get(normalized, normalized)
    category_capabilities = CATEGORY_MANAGED_CAPABILITIES.get(normalized)
    if category_capabilities is None:
        raise CapabilityError(f"unsupported managed category: {category!r}")
    return frozenset(CORE_MANAGED_CAPABILITIES | category_capabilities)


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


def _attestation_error(
    record: object,
    expected: dict[str, object],
) -> str | None:
    if not isinstance(record, dict):
        return "capability record is unavailable"
    attestation = record.get("attestation")
    if not isinstance(attestation, dict):
        return "attestation is missing"
    if set(attestation) != set(expected):
        return "attestation schema is not canonical"
    if (
        type(attestation.get("schema_version")) is not int
        or type(attestation.get("contract_version")) is not int
        or not isinstance(attestation.get("contract_id"), str)
        or not isinstance(attestation.get("path"), str)
        or not isinstance(attestation.get("sha256"), str)
        or _SHA256.fullmatch(attestation["sha256"]) is None
    ):
        return "attestation fields have invalid types"
    if attestation != expected:
        return "attestation does not match the required contract fingerprint"
    return None


def _remove_capability_probe_container(
    docker: str,
    container_name: str,
    *,
    runner: Runner,
) -> None:
    """Best-effort cleanup without replacing the original probe failure."""

    try:
        runner(
            [docker, "rm", "-f", container_name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10.0,
        )
    except Exception:
        # A daemon failure can make cleanup impossible.  The caller still
        # receives the original timeout or launch error rather than a cleanup
        # implementation detail.
        pass


def inspect_pinned_capabilities(
    image_digest: str,
    *,
    runner: Runner = subprocess.run,
    cleanup_runner: Runner | None = None,
    docker: str = "docker",
    required: frozenset[str] = REQUIRED_MANAGED_CAPABILITIES,
    timeout_seconds: int | float = 30,
) -> dict[str, Any]:
    """Probe one exact local image with network and filesystem writes denied."""

    digest = validate_image_digest(image_digest)
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or timeout_seconds <= 0
    ):
        raise CapabilityError(
            "image capability timeout must be positive and finite"
        )
    timeout = min(30.0, float(timeout_seconds))
    container_name = f"ctfos-capability-{secrets.token_hex(12)}"
    command = [
        docker,
        "run",
        "--rm",
        "--name",
        container_name,
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
            timeout=timeout,
        )
    except FileNotFoundError as error:
        raise CapabilityError("Docker executable is unavailable") from error
    except subprocess.TimeoutExpired as error:
        _remove_capability_probe_container(
            docker,
            container_name,
            runner=cleanup_runner or runner,
        )
        raise CapabilityError("image capability probe timed out") from error
    except OSError as error:
        _remove_capability_probe_container(
            docker,
            container_name,
            runner=cleanup_runner or runner,
        )
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
    records = (
        raw.get("capabilities")
        if isinstance(raw, dict) and raw.get("schema_version") == 2
        else []
    )
    records_by_name = {
        record["name"].casefold(): record
        for record in records
        if isinstance(record, dict) and isinstance(record.get("name"), str)
    }
    attestation_errors: dict[str, str] = {}
    accepted_attestations: dict[str, dict[str, object]] = {}
    for name, expected in REQUIRED_MANAGED_ATTESTATIONS.items():
        if name not in required or not capabilities.get(name, False):
            continue
        error = _attestation_error(records_by_name.get(name), expected)
        if error is not None:
            attestation_errors[name] = error
        else:
            accepted_attestations[name] = dict(expected)

    available = sorted(
        name
        for name in required
        if capabilities.get(name, False) and name not in attestation_errors
    )
    missing = sorted(set(required) - set(available))
    return {
        "schema_version": raw.get("schema_version"),
        "image_digest": digest,
        "required": sorted(required),
        "available": available,
        "missing": missing,
        "attestations": accepted_attestations,
        "attestation_errors": attestation_errors,
        "ok": not missing,
    }


__all__ = [
    "CATEGORY_MANAGED_CAPABILITIES",
    "CapabilityError",
    "CORE_MANAGED_CAPABILITIES",
    "MAX_CAPABILITY_OUTPUT_BYTES",
    "REQUIRED_MANAGED_ATTESTATIONS",
    "REQUIRED_MANAGED_CAPABILITIES",
    "inspect_pinned_capabilities",
    "normalize_capability_manifest",
    "required_managed_capabilities_for_category",
]
