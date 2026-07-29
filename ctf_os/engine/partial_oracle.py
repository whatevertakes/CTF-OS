"""Pure, state-independent deterministic partial-oracle parsers."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any


REV_INVENTORY_SCHEMA_VERSION = 1
REV_INVENTORY_CONTRACT_ID = "ctfos.rev.inventory"
REV_INVENTORY_CONTRACT_VERSION = 1
REV_INVENTORY_OUTPUT_NAME = "inventory-v1.json"
REV_INVENTORY_MAX_SOURCE_BYTES = 1024 * 1024 * 1024
REV_INVENTORY_SOURCE_HASH_TIMEOUT_SECONDS = 30
REV_INVENTORY_RABIN2_TIMEOUT_SECONDS = 30
REV_INVENTORY_RABIN2_STDOUT_MAX_BYTES = 64 * 1024
REV_INVENTORY_RABIN2_STDERR_MAX_BYTES = 16 * 1024
REV_INVENTORY_MAX_BYTES = 16 * 1024
REV_INVENTORY_MAX_JSON_DEPTH = 8

_CONTRACT_DESCRIPTOR = {
    "contract_id": REV_INVENTORY_CONTRACT_ID,
    "contract_version": REV_INVENTORY_CONTRACT_VERSION,
    "document_shape": (
        "contract(fingerprint,id,version);schema_version;status;"
        "source(sha256,size_bytes);"
        "ok:binary(arch,bits,bintype,endian,havecode)|error:error(code)"
    ),
    "inventory_max_bytes": REV_INVENTORY_MAX_BYTES,
    "json": "utf8-canonical-strict-v1",
    "output_name": REV_INVENTORY_OUTPUT_NAME,
    "rabin2_executable": "/usr/bin/rabin2",
    "rabin2_mode": "-Ij",
    "rabin2_stderr_max_bytes": REV_INVENTORY_RABIN2_STDERR_MAX_BYTES,
    "rabin2_stdout_max_bytes": REV_INVENTORY_RABIN2_STDOUT_MAX_BYTES,
    "rabin2_timeout_seconds": REV_INVENTORY_RABIN2_TIMEOUT_SECONDS,
    "source_hash": "sha256",
    "source_hash_timeout_seconds": (
        REV_INVENTORY_SOURCE_HASH_TIMEOUT_SECONDS
    ),
    "source_max_bytes": REV_INVENTORY_MAX_SOURCE_BYTES,
    "stale_output": "remove-regular-before-source-open",
}


def _canonical_json_bytes(value: object) -> bytes:
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


REV_INVENTORY_CONTRACT_FINGERPRINT = hashlib.sha256(
    _canonical_json_bytes(_CONTRACT_DESCRIPTOR)
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


class PartialOracleVerdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


@dataclass(frozen=True, slots=True)
class RevBinaryProfile:
    bintype: str
    arch: str | None
    bits: int | None
    endian: str
    havecode: bool


@dataclass(frozen=True, slots=True)
class PartialOracleResult:
    verdict: PartialOracleVerdict
    oracle_id: str
    oracle_version: int
    contract_fingerprint: str
    reason_code: str
    source_sha256: str | None = None
    source_size_bytes: int | None = None
    profile: RevBinaryProfile | None = None


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
        return 1 + max((_json_depth(item) for item in value.values()), default=0)
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
    verdict: PartialOracleVerdict,
    reason_code: str,
    *,
    source_sha256: str | None = None,
    source_size_bytes: int | None = None,
    profile: RevBinaryProfile | None = None,
) -> PartialOracleResult:
    return PartialOracleResult(
        verdict=verdict,
        oracle_id=REV_INVENTORY_CONTRACT_ID,
        oracle_version=REV_INVENTORY_CONTRACT_VERSION,
        contract_fingerprint=REV_INVENTORY_CONTRACT_FINGERPRINT,
        reason_code=reason_code,
        source_sha256=source_sha256,
        source_size_bytes=source_size_bytes,
        profile=profile,
    )


def _validate_expected_source(sha256: str, size_bytes: int) -> None:
    if type(sha256) is not str or not _SHA256.fullmatch(sha256):
        raise ValueError("expected_source_sha256 must be 64 lowercase hex digits")
    if (
        type(size_bytes) is not int
        or size_bytes < 0
        or size_bytes > REV_INVENTORY_MAX_SOURCE_BYTES
    ):
        raise ValueError("expected_source_size_bytes is outside the contract")


def evaluate_rev_inventory(
    payload: bytes,
    *,
    expected_source_sha256: str,
    expected_source_size_bytes: int,
) -> PartialOracleResult:
    """Validate one immutable ``inventory-v1.json`` snapshot.

    The function performs no filesystem access and no state mutation.  Caller
    bugs in trusted expected-source arguments raise ``ValueError``; every
    property of the untrusted artifact is represented as a neutral typed
    result.
    """

    _validate_expected_source(
        expected_source_sha256,
        expected_source_size_bytes,
    )
    if type(payload) is not bytes:
        raise TypeError("payload must be bytes")
    if len(payload) > REV_INVENTORY_MAX_BYTES:
        return _result(
            PartialOracleVerdict.ERROR,
            "artifact_too_large",
        )
    try:
        text = payload.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        if _json_depth(value) > REV_INVENTORY_MAX_JSON_DEPTH:
            raise _SchemaError("artifact exceeds the JSON depth limit")
    except _DuplicateKeyError:
        return _result(
            PartialOracleVerdict.ERROR,
            "duplicate_json_key",
        )
    except (
        json.JSONDecodeError,
        RecursionError,
        UnicodeDecodeError,
        ValueError,
    ):
        return _result(
            PartialOracleVerdict.ERROR,
            "invalid_json",
        )

    try:
        if payload != _canonical_json_bytes(value):
            return _result(
                PartialOracleVerdict.ERROR,
                "noncanonical_json",
            )
    except (TypeError, ValueError, UnicodeEncodeError):
        return _result(
            PartialOracleVerdict.ERROR,
            "invalid_json",
        )

    try:
        root = _exact_object(
            value,
            (
                {"binary", "contract", "schema_version", "source", "status"}
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
        schema_version = _exact_int(root["schema_version"], "schema_version")
        if schema_version != REV_INVENTORY_SCHEMA_VERSION:
            raise _SchemaError("unsupported schema version")

        contract = _exact_object(
            root["contract"],
            {"fingerprint", "id", "version"},
            "contract",
        )
        contract_id = _exact_string(contract["id"], "contract.id")
        contract_version = _exact_int(
            contract["version"],
            "contract.version",
        )
        fingerprint = _exact_string(
            contract["fingerprint"],
            "contract.fingerprint",
        )
        if (
            contract_id != REV_INVENTORY_CONTRACT_ID
            or contract_version != REV_INVENTORY_CONTRACT_VERSION
            or fingerprint != REV_INVENTORY_CONTRACT_FINGERPRINT
        ):
            return _result(
                PartialOracleVerdict.ERROR,
                "contract_mismatch",
            )

        source = _exact_object(
            root["source"],
            {"sha256", "size_bytes"},
            "source",
        )
        source_sha256 = _exact_string(source["sha256"], "source.sha256")
        source_size = _exact_int(source["size_bytes"], "source.size_bytes")
        if not _SHA256.fullmatch(source_sha256):
            raise _SchemaError("source.sha256 is not lowercase SHA-256")
        if not 0 <= source_size <= REV_INVENTORY_MAX_SOURCE_BYTES:
            raise _SchemaError("source.size_bytes is outside the contract")
        if source_sha256 != expected_source_sha256:
            return _result(
                PartialOracleVerdict.ERROR,
                "source_hash_mismatch",
                source_sha256=source_sha256,
                source_size_bytes=source_size,
            )
        if source_size != expected_source_size_bytes:
            return _result(
                PartialOracleVerdict.ERROR,
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
                PartialOracleVerdict.ERROR,
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
        profile = RevBinaryProfile(
            bintype=bintype,
            arch=arch,
            bits=bits,
            endian=endian,
            havecode=havecode,
        )
    except _SchemaError:
        return _result(
            PartialOracleVerdict.ERROR,
            "invalid_schema",
        )

    if not havecode:
        return _result(
            PartialOracleVerdict.NOT_APPLICABLE,
            "no_executable_code",
            source_sha256=source_sha256,
            source_size_bytes=source_size,
            profile=profile,
        )
    if bintype == "unknown":
        return _result(
            PartialOracleVerdict.NOT_APPLICABLE,
            "unsupported_binary_type",
            source_sha256=source_sha256,
            source_size_bytes=source_size,
            profile=profile,
        )
    if arch is None or bits is None or endian == "unknown":
        return _result(
            PartialOracleVerdict.INCONCLUSIVE,
            "incomplete_binary_profile",
            source_sha256=source_sha256,
            source_size_bytes=source_size,
            profile=profile,
        )
    supported_bits = _SUPPORTED_ARCH_BITS.get(arch)
    if supported_bits is None:
        return _result(
            PartialOracleVerdict.NOT_APPLICABLE,
            "unsupported_architecture",
            source_sha256=source_sha256,
            source_size_bytes=source_size,
            profile=profile,
        )
    if bits not in supported_bits:
        return _result(
            PartialOracleVerdict.NOT_APPLICABLE,
            "unsupported_architecture_bits",
            source_sha256=source_sha256,
            source_size_bytes=source_size,
            profile=profile,
        )
    if endian == "mixed":
        return _result(
            PartialOracleVerdict.INCONCLUSIVE,
            "mixed_endian_profile",
            source_sha256=source_sha256,
            source_size_bytes=source_size,
            profile=profile,
        )
    return _result(
        PartialOracleVerdict.CONFIRMED,
        "binary_profile_observed",
        source_sha256=source_sha256,
        source_size_bytes=source_size,
        profile=profile,
    )


__all__ = [
    "PartialOracleResult",
    "PartialOracleVerdict",
    "REV_INVENTORY_CONTRACT_FINGERPRINT",
    "REV_INVENTORY_CONTRACT_ID",
    "REV_INVENTORY_CONTRACT_VERSION",
    "REV_INVENTORY_MAX_BYTES",
    "REV_INVENTORY_MAX_SOURCE_BYTES",
    "REV_INVENTORY_OUTPUT_NAME",
    "REV_INVENTORY_SCHEMA_VERSION",
    "RevBinaryProfile",
    "evaluate_rev_inventory",
]
