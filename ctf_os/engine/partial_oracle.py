"""Compatibility surface for deterministic partial-oracle contracts.

Rev inventory v1 is implemented in a version-specific, dependency-neutral
contract module so canonical state validation and artifact parsing cannot
drift.  Existing callers keep the original public names through aliases here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ctf_os.contracts.rev_inventory_v1 import (
    REV_INVENTORY_V1_CONTRACT_FINGERPRINT,
    REV_INVENTORY_V1_CONTRACT_ID,
    REV_INVENTORY_V1_CONTRACT_VERSION,
    REV_INVENTORY_V1_DOCUMENT_TRANSPORT,
    REV_INVENTORY_V1_MAX_BYTES,
    REV_INVENTORY_V1_MAX_JSON_DEPTH,
    REV_INVENTORY_V1_MAX_SOURCE_BYTES,
    REV_INVENTORY_V1_OUTPUT_NAME,
    REV_INVENTORY_V1_RABIN2_STDERR_MAX_BYTES,
    REV_INVENTORY_V1_RABIN2_STDOUT_MAX_BYTES,
    REV_INVENTORY_V1_RABIN2_TIMEOUT_SECONDS,
    REV_INVENTORY_V1_SCHEMA_VERSION,
    REV_INVENTORY_V1_SOURCE_HASH_TIMEOUT_SECONDS,
    RevInventoryV1BinaryProfile,
    RevInventoryV1Result,
    RevInventoryV1Verdict,
    evaluate_rev_inventory_v1,
    evaluate_rev_inventory_v1_artifact_size,
)


REV_INVENTORY_SCHEMA_VERSION = REV_INVENTORY_V1_SCHEMA_VERSION
REV_INVENTORY_CONTRACT_ID = REV_INVENTORY_V1_CONTRACT_ID
REV_INVENTORY_CONTRACT_VERSION = REV_INVENTORY_V1_CONTRACT_VERSION
REV_INVENTORY_OUTPUT_NAME = REV_INVENTORY_V1_OUTPUT_NAME
REV_INVENTORY_DOCUMENT_TRANSPORT = REV_INVENTORY_V1_DOCUMENT_TRANSPORT
REV_INVENTORY_MAX_SOURCE_BYTES = REV_INVENTORY_V1_MAX_SOURCE_BYTES
REV_INVENTORY_MAX_BYTES = REV_INVENTORY_V1_MAX_BYTES
REV_INVENTORY_MAX_JSON_DEPTH = REV_INVENTORY_V1_MAX_JSON_DEPTH
REV_INVENTORY_SOURCE_HASH_TIMEOUT_SECONDS = (
    REV_INVENTORY_V1_SOURCE_HASH_TIMEOUT_SECONDS
)
REV_INVENTORY_RABIN2_TIMEOUT_SECONDS = (
    REV_INVENTORY_V1_RABIN2_TIMEOUT_SECONDS
)
REV_INVENTORY_RABIN2_STDOUT_MAX_BYTES = (
    REV_INVENTORY_V1_RABIN2_STDOUT_MAX_BYTES
)
REV_INVENTORY_RABIN2_STDERR_MAX_BYTES = (
    REV_INVENTORY_V1_RABIN2_STDERR_MAX_BYTES
)
REV_INVENTORY_CONTRACT_FINGERPRINT = (
    REV_INVENTORY_V1_CONTRACT_FINGERPRINT
)

class PartialOracleVerdict(str, Enum):
    """Backward-compatible public verdict type for the frozen v1 API."""

    CONFIRMED = "CONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


@dataclass(frozen=True, slots=True)
class RevBinaryProfile:
    """Backward-compatible public v1 binary profile."""

    bintype: str
    arch: str | None
    bits: int | None
    endian: str
    havecode: bool


@dataclass(frozen=True, slots=True)
class PartialOracleResult:
    """Backward-compatible public result returned by the v1 facade."""

    verdict: PartialOracleVerdict
    oracle_id: str
    oracle_version: int
    contract_fingerprint: str
    reason_code: str
    source_sha256: str | None = None
    source_size_bytes: int | None = None
    profile: RevBinaryProfile | None = None


def _compat_result(value: RevInventoryV1Result) -> PartialOracleResult:
    profile = (
        RevBinaryProfile(
            bintype=value.profile.bintype,
            arch=value.profile.arch,
            bits=value.profile.bits,
            endian=value.profile.endian,
            havecode=value.profile.havecode,
        )
        if isinstance(value.profile, RevInventoryV1BinaryProfile)
        else None
    )
    return PartialOracleResult(
        verdict=PartialOracleVerdict(value.verdict.value),
        oracle_id=value.oracle_id,
        oracle_version=value.oracle_version,
        contract_fingerprint=value.contract_fingerprint,
        reason_code=value.reason_code,
        source_sha256=value.source_sha256,
        source_size_bytes=value.source_size_bytes,
        profile=profile,
    )


def evaluate_rev_inventory(
    payload: bytes,
    *,
    expected_source_sha256: str,
    expected_source_size_bytes: int,
) -> PartialOracleResult:
    """Evaluate a v1 document while preserving the original public types."""

    return _compat_result(
        evaluate_rev_inventory_v1(
            payload,
            expected_source_sha256=expected_source_sha256,
            expected_source_size_bytes=expected_source_size_bytes,
        )
    )


def evaluate_rev_inventory_artifact_size(
    payload_size: int,
    *,
    expected_source_sha256: str,
    expected_source_size_bytes: int,
) -> PartialOracleResult | None:
    """Classify a v1 size through the backward-compatible result facade."""

    result = evaluate_rev_inventory_v1_artifact_size(
        payload_size,
        expected_source_sha256=expected_source_sha256,
        expected_source_size_bytes=expected_source_size_bytes,
    )
    return _compat_result(result) if result is not None else None


__all__ = [
    "PartialOracleResult",
    "PartialOracleVerdict",
    "REV_INVENTORY_CONTRACT_FINGERPRINT",
    "REV_INVENTORY_CONTRACT_ID",
    "REV_INVENTORY_CONTRACT_VERSION",
    "REV_INVENTORY_DOCUMENT_TRANSPORT",
    "REV_INVENTORY_MAX_BYTES",
    "REV_INVENTORY_MAX_JSON_DEPTH",
    "REV_INVENTORY_MAX_SOURCE_BYTES",
    "REV_INVENTORY_OUTPUT_NAME",
    "REV_INVENTORY_RABIN2_STDERR_MAX_BYTES",
    "REV_INVENTORY_RABIN2_STDOUT_MAX_BYTES",
    "REV_INVENTORY_RABIN2_TIMEOUT_SECONDS",
    "REV_INVENTORY_SCHEMA_VERSION",
    "REV_INVENTORY_SOURCE_HASH_TIMEOUT_SECONDS",
    "RevBinaryProfile",
    "evaluate_rev_inventory",
    "evaluate_rev_inventory_artifact_size",
]
