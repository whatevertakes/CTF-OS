"""Frozen compatibility contract for historical Rev inventory v1 state.

This module is deliberately immutable.  Its descriptor, parser semantics, and
seed identity algorithm are the behavior shipped before the typed Rev
inventory lifecycle was introduced.  New work must use
``ctf_os.contracts.rev_inventory_v2``.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any


REV_INVENTORY_V1_SCHEMA_VERSION = 1
REV_INVENTORY_V1_CONTRACT_ID = "ctfos.rev.inventory"
REV_INVENTORY_V1_CONTRACT_VERSION = 1
REV_INVENTORY_V1_OUTPUT_NAME = "inventory-v1.json"
REV_INVENTORY_V1_DOCUMENT_TRANSPORT = (
    "atomic-work-file-plus-exact-stdout-once-v1"
)
REV_INVENTORY_V1_MAX_SOURCE_BYTES = 1024 * 1024 * 1024
REV_INVENTORY_V1_SOURCE_HASH_TIMEOUT_SECONDS = 30
REV_INVENTORY_V1_RABIN2_TIMEOUT_SECONDS = 30
REV_INVENTORY_V1_RABIN2_STDOUT_MAX_BYTES = 64 * 1024
REV_INVENTORY_V1_RABIN2_STDERR_MAX_BYTES = 16 * 1024
REV_INVENTORY_V1_MAX_BYTES = 16 * 1024
REV_INVENTORY_V1_MAX_JSON_DEPTH = 8

REV_INVENTORY_V1_ADAPTER_SEED_CONTRACT_VERSION = 1
REV_INVENTORY_V1_SEED_TEMPLATE_ID = "inventory_observation"
REV_INVENTORY_V1_SEED_PURPOSE = (
    "collect a bounded source-bound binary inventory"
)
REV_INVENTORY_V1_SEED_COMMAND_TEMPLATE = (
    "python3",
    "/opt/ctf-templates/rev/inventory.py",
    "{primary}",
)
REV_INVENTORY_V1_SEED_EXPECTED_OBSERVATION = (
    "canonical Rev inventory bound to the immutable primary input"
)
REV_INVENTORY_V1_SEED_KEEP_CONDITION = (
    "the inventory contract identifies the binary profile"
)
REV_INVENTORY_V1_SEED_DROP_CONDITION = (
    "the inventory is malformed, stale, or not applicable"
)
REV_INVENTORY_V1_SEED_RESOURCE_CLASS = "light"
REV_INVENTORY_V1_SEED_TIMEOUT_SECONDS = 60
REV_INVENTORY_V1_SEED_REQUIRES_EXPLICIT_EXECUTION = True
REV_INVENTORY_V1_SNAPSHOT_DIRECTORY_MODE = 0o500
REV_INVENTORY_V1_SNAPSHOT_FILE_MODE = 0o500
REV_INVENTORY_V1_SNAPSHOT_MOUNT_REQUIREMENT = "challenge_read_only"
REV_INVENTORY_V1_SNAPSHOT_PUBLISH = "staged-atomic-no-repair-v1"
REV_INVENTORY_V1_SNAPSHOT_TREE_CONTRACT = "exact-single-primary-v1"

_CONTRACT_DESCRIPTOR = {
    "contract_id": REV_INVENTORY_V1_CONTRACT_ID,
    "contract_version": REV_INVENTORY_V1_CONTRACT_VERSION,
    "document_transport": REV_INVENTORY_V1_DOCUMENT_TRANSPORT,
    "document_shape": (
        "contract(fingerprint,id,version);schema_version;status;"
        "source(sha256,size_bytes);"
        "ok:binary(arch,bits,bintype,endian,havecode)|error:error(code)"
    ),
    "inventory_max_bytes": REV_INVENTORY_V1_MAX_BYTES,
    "json": "utf8-canonical-strict-v1",
    "output_name": REV_INVENTORY_V1_OUTPUT_NAME,
    "rabin2_executable": "/usr/bin/rabin2",
    "rabin2_mode": "-Ij",
    "rabin2_stderr_max_bytes": REV_INVENTORY_V1_RABIN2_STDERR_MAX_BYTES,
    "rabin2_stdout_max_bytes": REV_INVENTORY_V1_RABIN2_STDOUT_MAX_BYTES,
    "rabin2_timeout_seconds": REV_INVENTORY_V1_RABIN2_TIMEOUT_SECONDS,
    "source_hash": "sha256",
    "source_hash_timeout_seconds": (
        REV_INVENTORY_V1_SOURCE_HASH_TIMEOUT_SECONDS
    ),
    "source_max_bytes": REV_INVENTORY_V1_MAX_SOURCE_BYTES,
    "stale_output": "remove-regular-before-source-open",
}


def rev_inventory_v1_canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def rev_inventory_v1_contract_descriptor() -> dict[str, object]:
    return dict(_CONTRACT_DESCRIPTOR)


REV_INVENTORY_V1_CONTRACT_FINGERPRINT = hashlib.sha256(
    rev_inventory_v1_canonical_json_bytes(_CONTRACT_DESCRIPTOR)
).hexdigest()

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_TOKEN = re.compile(r"^[a-z0-9_.+-]{1,64}$")
_BINTYPES = frozenset(
    {"dex", "elf", "java", "mach_o", "pe", "unknown", "wasm"}
)
_ENDIANS = frozenset({"big", "little", "mixed", "unknown"})
_BITS = frozenset({8, 16, 32, 64})
_PRODUCER_ERROR_CODES = frozenset(
    {
        "rabin2_failed",
        "rabin2_invalid_json",
        "rabin2_invalid_schema",
        "rabin2_stderr_limit",
        "rabin2_stdout_limit",
        "rabin2_timeout",
    }
)
_SUPPORTED_ARCH_BITS = {
    "6502": frozenset({8, 16}),
    "aarch64": frozenset({64}),
    "arm": frozenset({16, 32, 64}),
    "avr": frozenset({8}),
    "dalvik": frozenset({32, 64}),
    "java": frozenset({8, 16, 32, 64}),
    "m68k": frozenset({16, 32}),
    "mips": frozenset({32, 64}),
    "ppc": frozenset({32, 64}),
    "riscv": frozenset({32, 64}),
    "sh": frozenset({16, 32}),
    "sparc": frozenset({32, 64}),
    "wasm": frozenset({32, 64}),
    "x86": frozenset({16, 32, 64}),
    "xtensa": frozenset({32}),
    "z80": frozenset({8, 16}),
}


class RevInventoryV1Verdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


@dataclass(frozen=True, slots=True)
class RevInventoryV1BinaryProfile:
    bintype: str
    arch: str | None
    bits: int | None
    endian: str
    havecode: bool


@dataclass(frozen=True, slots=True)
class RevInventoryV1Result:
    verdict: RevInventoryV1Verdict
    oracle_id: str
    oracle_version: int
    contract_fingerprint: str
    reason_code: str
    source_sha256: str | None = None
    source_size_bytes: int | None = None
    profile: RevInventoryV1BinaryProfile | None = None


class RevInventoryV1ContractError(ValueError):
    """A trusted legacy seed argument violates the historical shape."""


class _DuplicateKeyError(ValueError):
    pass


class _SchemaError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _json_depth(value: object) -> int:
    if isinstance(value, dict):
        return 1 + max(
            (_json_depth(item) for item in value.values()),
            default=0,
        )
    if isinstance(value, list):
        return 1 + max((_json_depth(item) for item in value), default=0)
    return 1


def _exact_object(
    value: object,
    keys: set[str],
    label: str,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise _SchemaError(f"{label} has missing or unknown fields")
    return value


def _exact_int(value: object, label: str) -> int:
    if type(value) is not int:
        raise _SchemaError(f"{label} must be an integer")
    return value


def _exact_string(value: object, label: str) -> str:
    if type(value) is not str:
        raise _SchemaError(f"{label} must be a string")
    return value


def _result(
    verdict: RevInventoryV1Verdict,
    reason_code: str,
    *,
    source_sha256: str | None = None,
    source_size_bytes: int | None = None,
    profile: RevInventoryV1BinaryProfile | None = None,
) -> RevInventoryV1Result:
    return RevInventoryV1Result(
        verdict=verdict,
        oracle_id=REV_INVENTORY_V1_CONTRACT_ID,
        oracle_version=REV_INVENTORY_V1_CONTRACT_VERSION,
        contract_fingerprint=REV_INVENTORY_V1_CONTRACT_FINGERPRINT,
        reason_code=reason_code,
        source_sha256=source_sha256,
        source_size_bytes=source_size_bytes,
        profile=profile,
    )


def _validate_expected_source(sha256: str, size_bytes: int) -> None:
    if type(sha256) is not str or not _SHA256.fullmatch(sha256):
        raise ValueError(
            "expected_source_sha256 must be 64 lowercase hex digits"
        )
    if (
        type(size_bytes) is not int
        or size_bytes < 0
        or size_bytes > REV_INVENTORY_V1_MAX_SOURCE_BYTES
    ):
        raise ValueError(
            "expected_source_size_bytes is outside the contract"
        )


def evaluate_rev_inventory_v1(
    payload: bytes,
    *,
    expected_source_sha256: str,
    expected_source_size_bytes: int,
) -> RevInventoryV1Result:
    """Run the exact historical v1 artifact parser."""

    _validate_expected_source(
        expected_source_sha256,
        expected_source_size_bytes,
    )
    if type(payload) is not bytes:
        raise TypeError("payload must be bytes")
    if len(payload) > REV_INVENTORY_V1_MAX_BYTES:
        return _result(RevInventoryV1Verdict.ERROR, "artifact_too_large")
    try:
        text = payload.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        if _json_depth(value) > REV_INVENTORY_V1_MAX_JSON_DEPTH:
            raise _SchemaError("artifact exceeds the JSON depth limit")
    except _DuplicateKeyError:
        return _result(RevInventoryV1Verdict.ERROR, "duplicate_json_key")
    except (
        json.JSONDecodeError,
        RecursionError,
        UnicodeDecodeError,
        ValueError,
    ):
        return _result(RevInventoryV1Verdict.ERROR, "invalid_json")

    try:
        if payload != rev_inventory_v1_canonical_json_bytes(value):
            return _result(
                RevInventoryV1Verdict.ERROR,
                "noncanonical_json",
            )
    except (TypeError, ValueError, UnicodeEncodeError):
        return _result(RevInventoryV1Verdict.ERROR, "invalid_json")

    try:
        root = _exact_object(
            value,
            (
                {
                    "binary",
                    "contract",
                    "schema_version",
                    "source",
                    "status",
                }
                if isinstance(value, dict) and value.get("status") == "ok"
                else {
                    "contract",
                    "error",
                    "schema_version",
                    "source",
                    "status",
                }
                if isinstance(value, dict) and value.get("status") == "error"
                else set()
            ),
            "inventory",
        )
        if (
            _exact_int(root["schema_version"], "schema_version")
            != REV_INVENTORY_V1_SCHEMA_VERSION
        ):
            raise _SchemaError("unsupported schema version")
        contract = _exact_object(
            root["contract"],
            {"fingerprint", "id", "version"},
            "contract",
        )
        if (
            _exact_string(contract["id"], "contract.id")
            != REV_INVENTORY_V1_CONTRACT_ID
            or _exact_int(contract["version"], "contract.version")
            != REV_INVENTORY_V1_CONTRACT_VERSION
            or _exact_string(
                contract["fingerprint"],
                "contract.fingerprint",
            )
            != REV_INVENTORY_V1_CONTRACT_FINGERPRINT
        ):
            return _result(
                RevInventoryV1Verdict.ERROR,
                "contract_mismatch",
            )
        source = _exact_object(
            root["source"],
            {"sha256", "size_bytes"},
            "source",
        )
        source_sha256 = _exact_string(
            source["sha256"],
            "source.sha256",
        )
        source_size = _exact_int(
            source["size_bytes"],
            "source.size_bytes",
        )
        if not _SHA256.fullmatch(source_sha256):
            raise _SchemaError("source.sha256 is not lowercase SHA-256")
        if not 0 <= source_size <= REV_INVENTORY_V1_MAX_SOURCE_BYTES:
            raise _SchemaError(
                "source.size_bytes is outside the contract"
            )
        if source_sha256 != expected_source_sha256:
            return _result(
                RevInventoryV1Verdict.ERROR,
                "source_hash_mismatch",
                source_sha256=source_sha256,
                source_size_bytes=source_size,
            )
        if source_size != expected_source_size_bytes:
            return _result(
                RevInventoryV1Verdict.ERROR,
                "source_size_mismatch",
                source_sha256=source_sha256,
                source_size_bytes=source_size,
            )
        status = _exact_string(root["status"], "status")
        if status == "error":
            error = _exact_object(root["error"], {"code"}, "error")
            error_code = _exact_string(error["code"], "error.code")
            if error_code not in _PRODUCER_ERROR_CODES:
                raise _SchemaError("unknown producer error code")
            return _result(
                RevInventoryV1Verdict.ERROR,
                f"producer_{error_code}",
                source_sha256=source_sha256,
                source_size_bytes=source_size,
            )
        if status != "ok":
            raise _SchemaError("unknown producer status")
        binary = _exact_object(
            root["binary"],
            {"arch", "bits", "bintype", "endian", "havecode"},
            "binary",
        )
        bintype = _exact_string(binary["bintype"], "binary.bintype")
        if bintype not in _BINTYPES:
            raise _SchemaError("binary.bintype is invalid")
        arch_value = binary["arch"]
        if arch_value is None:
            arch = None
        else:
            arch = _exact_string(arch_value, "binary.arch")
            if not _SAFE_TOKEN.fullmatch(arch):
                raise _SchemaError("binary.arch is invalid")
        bits_value = binary["bits"]
        if bits_value is None:
            bits = None
        else:
            bits = _exact_int(bits_value, "binary.bits")
            if bits not in _BITS:
                raise _SchemaError("binary.bits is invalid")
        endian = _exact_string(binary["endian"], "binary.endian")
        if endian not in _ENDIANS:
            raise _SchemaError("binary.endian is invalid")
        if type(binary["havecode"]) is not bool:
            raise _SchemaError("binary.havecode must be boolean")
        havecode = binary["havecode"]
        profile = RevInventoryV1BinaryProfile(
            bintype=bintype,
            arch=arch,
            bits=bits,
            endian=endian,
            havecode=havecode,
        )
    except _SchemaError:
        return _result(RevInventoryV1Verdict.ERROR, "invalid_schema")

    if not havecode:
        verdict = RevInventoryV1Verdict.NOT_APPLICABLE
        reason = "no_executable_code"
    elif bintype == "unknown":
        verdict = RevInventoryV1Verdict.NOT_APPLICABLE
        reason = "unsupported_binary_type"
    elif arch is None or bits is None or endian == "unknown":
        verdict = RevInventoryV1Verdict.INCONCLUSIVE
        reason = "incomplete_binary_profile"
    elif arch not in _SUPPORTED_ARCH_BITS:
        verdict = RevInventoryV1Verdict.NOT_APPLICABLE
        reason = "unsupported_architecture"
    elif bits not in _SUPPORTED_ARCH_BITS[arch]:
        verdict = RevInventoryV1Verdict.NOT_APPLICABLE
        reason = "unsupported_architecture_bits"
    elif endian == "mixed":
        verdict = RevInventoryV1Verdict.INCONCLUSIVE
        reason = "mixed_endian_profile"
    else:
        verdict = RevInventoryV1Verdict.CONFIRMED
        reason = "binary_profile_observed"
    return _result(
        verdict,
        reason,
        source_sha256=source_sha256,
        source_size_bytes=source_size,
        profile=profile,
    )


def evaluate_rev_inventory_v1_artifact_size(
    payload_size: int,
    *,
    expected_source_sha256: str,
    expected_source_size_bytes: int,
) -> RevInventoryV1Result | None:
    """Classify only the historical byte cap without reading a payload."""

    _validate_expected_source(
        expected_source_sha256,
        expected_source_size_bytes,
    )
    if type(payload_size) is not int or payload_size < 0:
        raise ValueError("payload_size must be a non-negative integer")
    if payload_size > REV_INVENTORY_V1_MAX_BYTES:
        return _result(RevInventoryV1Verdict.ERROR, "artifact_too_large")
    return None


def rev_inventory_v1_oracle_descriptor() -> dict[str, object]:
    return {
        "contract_fingerprint": REV_INVENTORY_V1_CONTRACT_FINGERPRINT,
        "document_transport": REV_INVENTORY_V1_DOCUMENT_TRANSPORT,
        "oracle_id": REV_INVENTORY_V1_CONTRACT_ID,
        "oracle_version": REV_INVENTORY_V1_CONTRACT_VERSION,
    }


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or not _SHA256.fullmatch(value):
        raise RevInventoryV1ContractError(
            f"{label} must be 64 lowercase hexadecimal characters"
        )
    return value


def _require_legacy_source_size(value: object) -> int:
    if type(value) is not int or value < 0:
        raise RevInventoryV1ContractError(
            "source_size_bytes must be a non-negative integer"
        )
    return value


def build_rev_inventory_v1_source_binding(
    *,
    manifest_generation: int,
    manifest_sha256: str,
    path: str,
    source_sha256: str,
    source_size_bytes: int,
) -> dict[str, object]:
    if type(manifest_generation) is not int or manifest_generation < 1:
        raise RevInventoryV1ContractError(
            "manifest_generation must be a positive integer"
        )
    _require_sha256(manifest_sha256, "manifest_sha256")
    _require_sha256(source_sha256, "source_sha256")
    _require_legacy_source_size(source_size_bytes)
    if (
        type(path) is not str
        or not path
        or path.startswith("/")
        or "\\" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        raise RevInventoryV1ContractError(
            "source path must be a normalized relative locator"
        )
    return {
        "manifest_generation": manifest_generation,
        "manifest_sha256": manifest_sha256,
        "path": path,
        "sha256": source_sha256,
        "size_bytes": source_size_bytes,
    }


def rev_inventory_v1_snapshot_contract() -> dict[str, object]:
    return {
        "directory_mode": REV_INVENTORY_V1_SNAPSHOT_DIRECTORY_MODE,
        "file_mode": REV_INVENTORY_V1_SNAPSHOT_FILE_MODE,
        "mount_requirement": REV_INVENTORY_V1_SNAPSHOT_MOUNT_REQUIREMENT,
        "publish": REV_INVENTORY_V1_SNAPSHOT_PUBLISH,
        "tree_contract": REV_INVENTORY_V1_SNAPSHOT_TREE_CONTRACT,
    }


def build_rev_inventory_v1_source_snapshot(
    source_binding: Mapping[str, object],
) -> dict[str, object]:
    expected_binding = build_rev_inventory_v1_source_binding(
        manifest_generation=source_binding.get("manifest_generation"),  # type: ignore[arg-type]
        manifest_sha256=source_binding.get("manifest_sha256"),  # type: ignore[arg-type]
        path=source_binding.get("path"),  # type: ignore[arg-type]
        source_sha256=source_binding.get("sha256"),  # type: ignore[arg-type]
        source_size_bytes=source_binding.get("size_bytes"),  # type: ignore[arg-type]
    )
    if dict(source_binding) != expected_binding:
        raise RevInventoryV1ContractError(
            "source binding has missing or unknown fields"
        )
    contract = rev_inventory_v1_snapshot_contract()
    payload = json.dumps(
        {
            "source_binding": expected_binding,
            "snapshot_contract": contract,
        },
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    binding_sha256 = hashlib.sha256(payload).hexdigest()
    snapshot_id = f"rev-primary-{binding_sha256}"
    return {
        "binding_sha256": binding_sha256,
        "challenge_dir": (
            f"runtime/source-snapshots/{snapshot_id}/challenge"
        ),
        **contract,
        "id": snapshot_id,
        "sha256": expected_binding["sha256"],
        "size_bytes": expected_binding["size_bytes"],
        "source_locator": expected_binding["path"],
    }


def build_rev_inventory_v1_seed_spec_descriptor(
    source_binding: Mapping[str, object],
    source_snapshot: Mapping[str, object],
) -> dict[str, object]:
    expected_snapshot = build_rev_inventory_v1_source_snapshot(
        source_binding
    )
    if dict(source_snapshot) != expected_snapshot:
        raise RevInventoryV1ContractError(
            "source snapshot does not match its source binding"
        )
    return {
        "adapter": "reversing",
        "adapter_seed": True,
        "adapter_seed_contract_version": (
            REV_INVENTORY_V1_ADAPTER_SEED_CONTRACT_VERSION
        ),
        "adapter_seed_order": 0,
        "command_template": list(
            REV_INVENTORY_V1_SEED_COMMAND_TEMPLATE
        ),
        "drop_condition": REV_INVENTORY_V1_SEED_DROP_CONDITION,
        "expected_observation": (
            REV_INVENTORY_V1_SEED_EXPECTED_OBSERVATION
        ),
        "keep_condition": REV_INVENTORY_V1_SEED_KEEP_CONDITION,
        "oracle": rev_inventory_v1_oracle_descriptor(),
        "purpose": REV_INVENTORY_V1_SEED_PURPOSE,
        "requires_explicit_execution": (
            REV_INVENTORY_V1_SEED_REQUIRES_EXPLICIT_EXECUTION
        ),
        "requires_network": False,
        "resource_class": REV_INVENTORY_V1_SEED_RESOURCE_CLASS,
        "source_binding": dict(source_binding),
        "source_snapshot": dict(source_snapshot),
        "template_spec_id": REV_INVENTORY_V1_SEED_TEMPLATE_ID,
        "timeout_s": REV_INVENTORY_V1_SEED_TIMEOUT_SECONDS,
    }


def rev_inventory_v1_seed_spec_sha256(
    source_binding: Mapping[str, object],
    source_snapshot: Mapping[str, object],
) -> str:
    payload = json.dumps(
        build_rev_inventory_v1_seed_spec_descriptor(
            source_binding,
            source_snapshot,
        ),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def build_rev_inventory_v1_seed_extra(
    source_binding: Mapping[str, object],
    source_snapshot: Mapping[str, object],
) -> dict[str, object]:
    digest = rev_inventory_v1_seed_spec_sha256(
        source_binding,
        source_snapshot,
    )
    return {
        "adapter_name": "reversing",
        "adapter_seed": True,
        "adapter_seed_contract_version": (
            REV_INVENTORY_V1_ADAPTER_SEED_CONTRACT_VERSION
        ),
        "adapter_seed_order": 0,
        "adapter_spec_id": (
            f"{REV_INVENTORY_V1_SEED_TEMPLATE_ID}@{digest}"
        ),
        "adapter_spec_sha256": digest,
        "adapter_spec_template_id": REV_INVENTORY_V1_SEED_TEMPLATE_ID,
        "partial_oracle": rev_inventory_v1_oracle_descriptor(),
        "purpose": REV_INVENTORY_V1_SEED_PURPOSE,
        "requires_explicit_execution": (
            REV_INVENTORY_V1_SEED_REQUIRES_EXPLICIT_EXECUTION
        ),
        "source_binding": dict(source_binding),
        "source_snapshot": dict(source_snapshot),
    }


def rev_inventory_v1_seed_argv(source_path: str) -> tuple[str, ...]:
    build_rev_inventory_v1_source_binding(
        manifest_generation=1,
        manifest_sha256="0" * 64,
        path=source_path,
        source_sha256="0" * 64,
        source_size_bytes=0,
    )
    primary = f"/challenge/{source_path}"
    return tuple(
        item.replace("{primary}", primary)
        for item in REV_INVENTORY_V1_SEED_COMMAND_TEMPLATE
    )


def rev_inventory_v1_seed_command(source_path: str) -> str:
    return shlex.join(rev_inventory_v1_seed_argv(source_path))


__all__ = [
    "REV_INVENTORY_V1_ADAPTER_SEED_CONTRACT_VERSION",
    "REV_INVENTORY_V1_CONTRACT_FINGERPRINT",
    "REV_INVENTORY_V1_CONTRACT_ID",
    "REV_INVENTORY_V1_CONTRACT_VERSION",
    "REV_INVENTORY_V1_DOCUMENT_TRANSPORT",
    "REV_INVENTORY_V1_MAX_BYTES",
    "REV_INVENTORY_V1_MAX_JSON_DEPTH",
    "REV_INVENTORY_V1_MAX_SOURCE_BYTES",
    "REV_INVENTORY_V1_OUTPUT_NAME",
    "REV_INVENTORY_V1_RABIN2_STDERR_MAX_BYTES",
    "REV_INVENTORY_V1_RABIN2_STDOUT_MAX_BYTES",
    "REV_INVENTORY_V1_RABIN2_TIMEOUT_SECONDS",
    "REV_INVENTORY_V1_SCHEMA_VERSION",
    "REV_INVENTORY_V1_SEED_COMMAND_TEMPLATE",
    "REV_INVENTORY_V1_SEED_DROP_CONDITION",
    "REV_INVENTORY_V1_SEED_EXPECTED_OBSERVATION",
    "REV_INVENTORY_V1_SEED_KEEP_CONDITION",
    "REV_INVENTORY_V1_SEED_PURPOSE",
    "REV_INVENTORY_V1_SEED_REQUIRES_EXPLICIT_EXECUTION",
    "REV_INVENTORY_V1_SEED_RESOURCE_CLASS",
    "REV_INVENTORY_V1_SEED_TEMPLATE_ID",
    "REV_INVENTORY_V1_SEED_TIMEOUT_SECONDS",
    "RevInventoryV1BinaryProfile",
    "RevInventoryV1ContractError",
    "RevInventoryV1Result",
    "RevInventoryV1Verdict",
    "build_rev_inventory_v1_seed_extra",
    "build_rev_inventory_v1_seed_spec_descriptor",
    "build_rev_inventory_v1_source_binding",
    "build_rev_inventory_v1_source_snapshot",
    "evaluate_rev_inventory_v1",
    "evaluate_rev_inventory_v1_artifact_size",
    "rev_inventory_v1_canonical_json_bytes",
    "rev_inventory_v1_contract_descriptor",
    "rev_inventory_v1_oracle_descriptor",
    "rev_inventory_v1_seed_argv",
    "rev_inventory_v1_seed_command",
    "rev_inventory_v1_seed_spec_sha256",
]
