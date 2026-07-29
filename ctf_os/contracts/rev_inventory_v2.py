"""Immutable v2 contract for the deterministic Rev inventory oracle.

This module deliberately depends only on the Python standard library.  It is
shared by the artifact parser, canonical-state validation, and seed planning.
The image producer vendors the same descriptor because the sandbox image must
remain independently executable.

Once v2 state has been persisted this module is append-only.  Semantic changes
must be implemented in a new versioned module and selected by an explicit
contract-version/fingerprint dispatch.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any


REV_INVENTORY_V2_SCHEMA_VERSION = 2
REV_INVENTORY_V2_CONTRACT_ID = "ctfos.rev.inventory"
REV_INVENTORY_V2_CONTRACT_VERSION = 2
REV_INVENTORY_V2_OUTPUT_NAME = "inventory-v2.json"
REV_INVENTORY_V2_DOCUMENT_TRANSPORT = (
    "atomic-work-file-plus-exact-stdout-once-v2"
)
REV_INVENTORY_V2_MAX_SOURCE_BYTES = 1024 * 1024 * 1024
REV_INVENTORY_V2_SOURCE_HASH_TIMEOUT_SECONDS = 30
REV_INVENTORY_V2_RABIN2_TIMEOUT_SECONDS = 30
REV_INVENTORY_V2_RABIN2_STDOUT_MAX_BYTES = 64 * 1024
REV_INVENTORY_V2_RABIN2_STDERR_MAX_BYTES = 16 * 1024
REV_INVENTORY_V2_MAX_BYTES = 16 * 1024
REV_INVENTORY_V2_MAX_JSON_DEPTH = 8

REV_INVENTORY_V2_PROFILE_BINTYPES = frozenset(
    {"dex", "elf", "java", "mach_o", "pe", "unknown", "wasm"}
)
REV_INVENTORY_V2_PROFILE_ENDIANS = frozenset(
    {"big", "little", "mixed", "unknown"}
)
REV_INVENTORY_V2_PROFILE_BITS = frozenset({8, 16, 32, 64})
REV_INVENTORY_V2_BINTYPE_ALIASES = MappingProxyType(
    {
        "dex": "dex",
        "elf": "elf",
        "java": "java",
        "mach-o": "mach_o",
        "mach0": "mach_o",
        "mach_o": "mach_o",
        "pe": "pe",
        "wasm": "wasm",
    }
)
REV_INVENTORY_V2_SUPPORTED_ARCH_BITS = MappingProxyType(
    {
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
)
REV_INVENTORY_V2_PRODUCER_ERROR_REASON_MAP = MappingProxyType(
    {
        "rabin2_failed": "producer_rabin2_failed",
        "rabin2_invalid_json": "producer_rabin2_invalid_json",
        "rabin2_invalid_schema": "producer_rabin2_invalid_schema",
        "rabin2_stderr_limit": "producer_rabin2_stderr_limit",
        "rabin2_stdout_limit": "producer_rabin2_stdout_limit",
        "rabin2_timeout": "producer_rabin2_timeout",
    }
)
REV_INVENTORY_V2_PRE_SOURCE_ERROR_REASONS = frozenset(
    {
        "artifact_too_large",
        "contract_mismatch",
        "duplicate_json_key",
        "invalid_json",
        "invalid_schema",
        "noncanonical_json",
    }
)
REV_INVENTORY_V2_SOURCE_MISMATCH_REASONS = frozenset(
    {"source_hash_mismatch", "source_size_mismatch"}
)
REV_INVENTORY_V2_SOURCE_BOUND_ERROR_REASONS = frozenset(
    {
        *REV_INVENTORY_V2_SOURCE_MISMATCH_REASONS,
        *REV_INVENTORY_V2_PRODUCER_ERROR_REASON_MAP.values(),
    }
)
REV_INVENTORY_V2_ERROR_REASONS = frozenset(
    {
        *REV_INVENTORY_V2_PRE_SOURCE_ERROR_REASONS,
        *REV_INVENTORY_V2_SOURCE_BOUND_ERROR_REASONS,
    }
)
REV_INVENTORY_V2_ERROR_REASON_RULES = (
    ("payload-size>inventory-max-bytes", "artifact_too_large", "none"),
    ("duplicate-json-key", "duplicate_json_key", "none"),
    (
        "invalid-utf8|invalid-json|nonfinite-number|depth-limit",
        "invalid_json",
        "none",
    ),
    ("noncanonical-json", "noncanonical_json", "none"),
    ("document-schema-invalid", "invalid_schema", "none"),
    ("document-contract-mismatch", "contract_mismatch", "none"),
    ("source-sha256-mismatch", "source_hash_mismatch", "observed"),
    ("source-size-mismatch", "source_size_mismatch", "observed"),
    ("producer-error-code", "producer-error-map", "observed"),
)

# Ordered first-match decision table.  The symbolic conditions are part of the
# fingerprint; ``classify_rev_inventory_v2_profile`` is the executable form.
REV_INVENTORY_V2_VERDICT_REASON_RULES = (
    (
        "havecode=false",
        "NOT_APPLICABLE",
        "no_executable_code",
    ),
    (
        "bintype=unknown",
        "NOT_APPLICABLE",
        "unsupported_binary_type",
    ),
    (
        "arch=null|bits=null|endian=unknown",
        "INCONCLUSIVE",
        "incomplete_binary_profile",
    ),
    (
        "arch-not-supported",
        "NOT_APPLICABLE",
        "unsupported_architecture",
    ),
    (
        "bits-not-supported-for-arch",
        "NOT_APPLICABLE",
        "unsupported_architecture_bits",
    ),
    (
        "endian=mixed",
        "INCONCLUSIVE",
        "mixed_endian_profile",
    ),
    (
        "otherwise",
        "CONFIRMED",
        "binary_profile_observed",
    ),
)

REV_INVENTORY_V2_ADAPTER_SEED_CONTRACT_VERSION = 2
REV_INVENTORY_V2_SEED_TEMPLATE_ID = "inventory_observation"
REV_INVENTORY_V2_SEED_PURPOSE = (
    "collect a bounded source-bound binary inventory"
)
REV_INVENTORY_V2_SEED_COMMAND_TEMPLATE = (
    "python3",
    "/opt/ctf-templates/rev/inventory_v2.py",
    "{primary}",
)
REV_INVENTORY_V2_SEED_EXPECTED_OBSERVATION = (
    "canonical Rev inventory bound to the immutable primary input"
)
REV_INVENTORY_V2_SEED_KEEP_CONDITION = (
    "the inventory contract identifies the binary profile"
)
REV_INVENTORY_V2_SEED_DROP_CONDITION = (
    "the inventory is malformed, stale, or not applicable"
)
REV_INVENTORY_V2_SEED_RESOURCE_CLASS = "light"
REV_INVENTORY_V2_SEED_TIMEOUT_SECONDS = 60
REV_INVENTORY_V2_SEED_REQUIRES_EXPLICIT_EXECUTION = True
REV_INVENTORY_V2_SNAPSHOT_DIRECTORY_MODE = 0o500
REV_INVENTORY_V2_SNAPSHOT_FILE_MODE = 0o500
REV_INVENTORY_V2_SNAPSHOT_MOUNT_REQUIREMENT = "challenge_read_only"
REV_INVENTORY_V2_SNAPSHOT_PUBLISH = "staged-atomic-no-repair-v2"
REV_INVENTORY_V2_SNAPSHOT_TREE_CONTRACT = "exact-single-primary-v2"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_TOKEN = re.compile(r"^[a-z0-9_.+-]{1,64}$")


def rev_inventory_v2_canonical_json_bytes(value: object) -> bytes:
    """Return the one canonical JSON representation used by v2 artifacts."""

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


def rev_inventory_v2_contract_descriptor() -> dict[str, object]:
    """Build a fresh canonical descriptor for the complete v2 behavior."""

    return {
        "contract_id": REV_INVENTORY_V2_CONTRACT_ID,
        "contract_version": REV_INVENTORY_V2_CONTRACT_VERSION,
        "document_transport": REV_INVENTORY_V2_DOCUMENT_TRANSPORT,
        "document_shape": (
            "contract(fingerprint,id,version);schema_version;status;"
            "source(sha256,size_bytes);"
            "ok:binary(arch,bits,bintype,endian,havecode)|error:error(code)"
        ),
        "inventory_max_bytes": REV_INVENTORY_V2_MAX_BYTES,
        "inventory_max_json_depth": REV_INVENTORY_V2_MAX_JSON_DEPTH,
        "json": "utf8-canonical-strict-v2",
        "output_name": REV_INVENTORY_V2_OUTPUT_NAME,
        "producer_normalization": {
            "arch": {
                "empty": None,
                "input_type": "exact-string",
                "normalization": "strip-lower",
                "output_pattern": "[a-z0-9_.+-]{1,64}",
            },
            "binsz": {
                "input_type": "exact-integer",
                "range": "0<=binsz<=source_size_bytes",
            },
            "bintype": {
                "aliases": dict(
                    sorted(REV_INVENTORY_V2_BINTYPE_ALIASES.items())
                ),
                "empty": "unknown",
                "input_type": "exact-string",
                "normalization": "strip-lower",
                "normalized_nonempty_pattern": "[a-z0-9_.+-]{1,64}",
                "unknown": "unknown",
            },
            "bits": {
                "allowed_nonzero": sorted(
                    REV_INVENTORY_V2_PROFILE_BITS
                ),
                "input_type": "exact-integer",
                "zero": None,
            },
            "endian": {
                "allowed": sorted(REV_INVENTORY_V2_PROFILE_ENDIANS),
                "empty": "unknown",
                "input_type": "exact-string",
                "normalization": "strip-lower",
                "normalized_nonempty_pattern": "[a-z0-9_.+-]{1,64}",
                "unknown": "unknown",
            },
            "havecode": {"input_type": "exact-boolean"},
            "normalization_error": "rabin2_invalid_schema",
            "rabin2_info_required_fields": [
                "arch",
                "binsz",
                "bintype",
                "bits",
                "endian",
                "havecode",
            ],
            "rabin2_info_unknown_fields": "allowed",
            "rabin2_root_fields": ["info"],
        },
        "rabin2_executable": "/usr/bin/rabin2",
        "rabin2_mode": "-Ij",
        "rabin2_stderr_max_bytes": (
            REV_INVENTORY_V2_RABIN2_STDERR_MAX_BYTES
        ),
        "rabin2_stdout_max_bytes": (
            REV_INVENTORY_V2_RABIN2_STDOUT_MAX_BYTES
        ),
        "rabin2_timeout_seconds": (
            REV_INVENTORY_V2_RABIN2_TIMEOUT_SECONDS
        ),
        "result_semantics": {
            "arch_token": "lowercase-safe-token-v2",
            "bits": sorted(REV_INVENTORY_V2_PROFILE_BITS),
            "bintypes": sorted(REV_INVENTORY_V2_PROFILE_BINTYPES),
            "endians": sorted(REV_INVENTORY_V2_PROFILE_ENDIANS),
            "error_reason_rules": [
                {
                    "condition": condition,
                    "reason_code": reason_code,
                    "source_binding": source_binding,
                }
                for condition, reason_code, source_binding in (
                    REV_INVENTORY_V2_ERROR_REASON_RULES
                )
            ],
            "pre_source_error_reasons": sorted(
                REV_INVENTORY_V2_PRE_SOURCE_ERROR_REASONS
            ),
            "producer_error_reason_map": dict(
                sorted(
                    REV_INVENTORY_V2_PRODUCER_ERROR_REASON_MAP.items()
                )
            ),
            "result_shape": (
                "contract_fingerprint;oracle_id;oracle_version;profile;"
                "reason_code;source_sha256;source_size_bytes;verdict"
            ),
            "source_mismatch_reasons": sorted(
                REV_INVENTORY_V2_SOURCE_MISMATCH_REASONS
            ),
            "supported_arch_bits": {
                arch: sorted(bits)
                for arch, bits in sorted(
                    REV_INVENTORY_V2_SUPPORTED_ARCH_BITS.items()
                )
            },
            "verdict_reason_rules": [
                {
                    "condition": condition,
                    "reason_code": reason_code,
                    "verdict": verdict,
                }
                for condition, verdict, reason_code in (
                    REV_INVENTORY_V2_VERDICT_REASON_RULES
                )
            ],
        },
        "source_hash": "sha256",
        "source_hash_timeout_seconds": (
            REV_INVENTORY_V2_SOURCE_HASH_TIMEOUT_SECONDS
        ),
        "source_max_bytes": REV_INVENTORY_V2_MAX_SOURCE_BYTES,
        "stale_output": "remove-regular-before-source-open",
    }


REV_INVENTORY_V2_CONTRACT_FINGERPRINT = hashlib.sha256(
    rev_inventory_v2_canonical_json_bytes(
        rev_inventory_v2_contract_descriptor()
    )
).hexdigest()


def rev_inventory_v2_oracle_descriptor() -> dict[str, object]:
    """Return the exact descriptor persisted with a v2 seed and outcome."""

    return {
        "contract_fingerprint": REV_INVENTORY_V2_CONTRACT_FINGERPRINT,
        "document_transport": REV_INVENTORY_V2_DOCUMENT_TRANSPORT,
        "oracle_id": REV_INVENTORY_V2_CONTRACT_ID,
        "oracle_version": REV_INVENTORY_V2_CONTRACT_VERSION,
    }


class RevInventoryV2ContractError(ValueError):
    """A mapping or trusted seed input violates the immutable v2 contract."""


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or not _SHA256.fullmatch(value):
        raise RevInventoryV2ContractError(
            f"{label} must be 64 lowercase hexadecimal characters"
        )
    return value


def _require_source_size(value: object, label: str) -> int:
    if (
        type(value) is not int
        or value < 0
        or value > REV_INVENTORY_V2_MAX_SOURCE_BYTES
    ):
        raise RevInventoryV2ContractError(
            f"{label} is outside the v2 source-size contract"
        )
    return value


def _require_nonnegative_size(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise RevInventoryV2ContractError(
            f"{label} must be a non-negative integer"
        )
    return value


def build_rev_inventory_v2_source_binding(
    *,
    manifest_generation: int,
    manifest_sha256: str,
    path: str,
    source_sha256: str,
    source_size_bytes: int,
) -> dict[str, object]:
    """Build the exact state binding for one inventory seed source."""

    if type(manifest_generation) is not int or manifest_generation < 1:
        raise RevInventoryV2ContractError(
            "manifest_generation must be a positive integer"
        )
    _require_sha256(manifest_sha256, "manifest_sha256")
    _require_sha256(source_sha256, "source_sha256")
    _require_source_size(source_size_bytes, "source_size_bytes")
    if (
        type(path) is not str
        or not path
        or path.startswith("/")
        or "\\" in path
        or any(component in {"", ".", ".."} for component in path.split("/"))
    ):
        raise RevInventoryV2ContractError(
            "source path must be a normalized relative locator"
        )
    return {
        "manifest_generation": manifest_generation,
        "manifest_sha256": manifest_sha256,
        "path": path,
        "sha256": source_sha256,
        "size_bytes": source_size_bytes,
    }


def rev_inventory_v2_snapshot_contract() -> dict[str, object]:
    """Return the exact immutable source-snapshot policy."""

    return {
        "directory_mode": REV_INVENTORY_V2_SNAPSHOT_DIRECTORY_MODE,
        "file_mode": REV_INVENTORY_V2_SNAPSHOT_FILE_MODE,
        "mount_requirement": (
            REV_INVENTORY_V2_SNAPSHOT_MOUNT_REQUIREMENT
        ),
        "publish": REV_INVENTORY_V2_SNAPSHOT_PUBLISH,
        "tree_contract": REV_INVENTORY_V2_SNAPSHOT_TREE_CONTRACT,
    }


def build_rev_inventory_v2_source_snapshot(
    source_binding: Mapping[str, object],
) -> dict[str, object]:
    """Build the content-addressed source snapshot metadata for a seed."""

    expected_binding = build_rev_inventory_v2_source_binding(
        manifest_generation=source_binding.get("manifest_generation"),  # type: ignore[arg-type]
        manifest_sha256=source_binding.get("manifest_sha256"),  # type: ignore[arg-type]
        path=source_binding.get("path"),  # type: ignore[arg-type]
        source_sha256=source_binding.get("sha256"),  # type: ignore[arg-type]
        source_size_bytes=source_binding.get("size_bytes"),  # type: ignore[arg-type]
    )
    if dict(source_binding) != expected_binding:
        raise RevInventoryV2ContractError(
            "source binding has missing or unknown fields"
        )
    snapshot_contract = rev_inventory_v2_snapshot_contract()
    binding_payload = json.dumps(
        {
            "source_binding": expected_binding,
            "snapshot_contract": snapshot_contract,
        },
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    binding_sha256 = hashlib.sha256(binding_payload).hexdigest()
    snapshot_id = f"rev-primary-{binding_sha256}"
    return {
        "binding_sha256": binding_sha256,
        "challenge_dir": (
            f"runtime/source-snapshots/{snapshot_id}/challenge"
        ),
        **snapshot_contract,
        "id": snapshot_id,
        "sha256": expected_binding["sha256"],
        "size_bytes": expected_binding["size_bytes"],
        "source_locator": expected_binding["path"],
    }


def build_rev_inventory_v2_seed_spec_descriptor(
    source_binding: Mapping[str, object],
    source_snapshot: Mapping[str, object],
) -> dict[str, object]:
    """Build the exact descriptor hashed into the deterministic seed id."""

    expected_snapshot = build_rev_inventory_v2_source_snapshot(
        source_binding
    )
    if dict(source_snapshot) != expected_snapshot:
        raise RevInventoryV2ContractError(
            "source snapshot does not match its source binding"
        )
    return {
        "adapter": "reversing",
        "adapter_seed": True,
        "adapter_seed_contract_version": (
            REV_INVENTORY_V2_ADAPTER_SEED_CONTRACT_VERSION
        ),
        "adapter_seed_order": 0,
        "command_template": list(
            REV_INVENTORY_V2_SEED_COMMAND_TEMPLATE
        ),
        "drop_condition": REV_INVENTORY_V2_SEED_DROP_CONDITION,
        "expected_observation": (
            REV_INVENTORY_V2_SEED_EXPECTED_OBSERVATION
        ),
        "keep_condition": REV_INVENTORY_V2_SEED_KEEP_CONDITION,
        "oracle": rev_inventory_v2_oracle_descriptor(),
        "purpose": REV_INVENTORY_V2_SEED_PURPOSE,
        "requires_explicit_execution": (
            REV_INVENTORY_V2_SEED_REQUIRES_EXPLICIT_EXECUTION
        ),
        "requires_network": False,
        "resource_class": REV_INVENTORY_V2_SEED_RESOURCE_CLASS,
        "source_binding": dict(source_binding),
        "source_snapshot": dict(source_snapshot),
        "template_spec_id": REV_INVENTORY_V2_SEED_TEMPLATE_ID,
        "timeout_s": REV_INVENTORY_V2_SEED_TIMEOUT_SECONDS,
    }


def rev_inventory_v2_seed_spec_sha256(
    source_binding: Mapping[str, object],
    source_snapshot: Mapping[str, object],
) -> str:
    """Return the seed descriptor digest used in its bound spec id."""

    descriptor = build_rev_inventory_v2_seed_spec_descriptor(
        source_binding,
        source_snapshot,
    )
    payload = json.dumps(
        descriptor,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def build_rev_inventory_v2_seed_extra(
    source_binding: Mapping[str, object],
    source_snapshot: Mapping[str, object],
) -> dict[str, object]:
    """Return exact canonical Experiment.extra fields for the v2 seed."""

    spec_sha256 = rev_inventory_v2_seed_spec_sha256(
        source_binding,
        source_snapshot,
    )
    return {
        "adapter_name": "reversing",
        "adapter_seed": True,
        "adapter_seed_contract_version": (
            REV_INVENTORY_V2_ADAPTER_SEED_CONTRACT_VERSION
        ),
        "adapter_seed_order": 0,
        "adapter_spec_id": (
            f"{REV_INVENTORY_V2_SEED_TEMPLATE_ID}@{spec_sha256}"
        ),
        "adapter_spec_sha256": spec_sha256,
        "adapter_spec_template_id": REV_INVENTORY_V2_SEED_TEMPLATE_ID,
        "partial_oracle": rev_inventory_v2_oracle_descriptor(),
        "purpose": REV_INVENTORY_V2_SEED_PURPOSE,
        "requires_explicit_execution": (
            REV_INVENTORY_V2_SEED_REQUIRES_EXPLICIT_EXECUTION
        ),
        "source_binding": dict(source_binding),
        "source_snapshot": dict(source_snapshot),
    }


def rev_inventory_v2_seed_argv(source_path: str) -> tuple[str, ...]:
    """Return exact container argv for a normalized source locator."""

    # Reuse source-binding path validation without inventing a second locator
    # grammar.  The digest values are trusted sentinels used only here.
    build_rev_inventory_v2_source_binding(
        manifest_generation=1,
        manifest_sha256="0" * 64,
        path=source_path,
        source_sha256="0" * 64,
        source_size_bytes=0,
    )
    primary = f"/challenge/{source_path}"
    return tuple(
        argument.replace("{primary}", primary)
        for argument in REV_INVENTORY_V2_SEED_COMMAND_TEMPLATE
    )


def rev_inventory_v2_seed_command(source_path: str) -> str:
    """Return shell-safe display command corresponding to exact seed argv."""

    return shlex.join(rev_inventory_v2_seed_argv(source_path))


class RevInventoryV2Verdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


@dataclass(frozen=True, slots=True)
class RevInventoryV2BinaryProfile:
    bintype: str
    arch: str | None
    bits: int | None
    endian: str
    havecode: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "arch": self.arch,
            "bits": self.bits,
            "bintype": self.bintype,
            "endian": self.endian,
            "havecode": self.havecode,
        }


@dataclass(frozen=True, slots=True)
class RevInventoryV2Result:
    verdict: RevInventoryV2Verdict
    oracle_id: str
    oracle_version: int
    contract_fingerprint: str
    reason_code: str
    source_sha256: str | None = None
    source_size_bytes: int | None = None
    profile: RevInventoryV2BinaryProfile | None = None

    def to_dict(self) -> dict[str, object]:
        """Return the stable state/run representation of one verdict."""

        return {
            "contract_fingerprint": self.contract_fingerprint,
            "oracle_id": self.oracle_id,
            "oracle_version": self.oracle_version,
            "profile": (
                self.profile.to_dict()
                if self.profile is not None
                else None
            ),
            "reason_code": self.reason_code,
            "source_sha256": self.source_sha256,
            "source_size_bytes": self.source_size_bytes,
            "verdict": self.verdict.value,
        }


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
    verdict: RevInventoryV2Verdict,
    reason_code: str,
    *,
    source_sha256: str | None = None,
    source_size_bytes: int | None = None,
    profile: RevInventoryV2BinaryProfile | None = None,
) -> RevInventoryV2Result:
    return RevInventoryV2Result(
        verdict=verdict,
        oracle_id=REV_INVENTORY_V2_CONTRACT_ID,
        oracle_version=REV_INVENTORY_V2_CONTRACT_VERSION,
        contract_fingerprint=REV_INVENTORY_V2_CONTRACT_FINGERPRINT,
        reason_code=reason_code,
        source_sha256=source_sha256,
        source_size_bytes=source_size_bytes,
        profile=profile,
    )


def _validate_expected_source(sha256: str, size_bytes: int) -> None:
    try:
        _require_sha256(sha256, "expected_source_sha256")
        _require_source_size(size_bytes, "expected_source_size_bytes")
    except RevInventoryV2ContractError as error:
        raise ValueError(str(error)) from error


def evaluate_rev_inventory_v2_artifact_size(
    payload_size: int,
    *,
    expected_source_sha256: str,
    expected_source_size_bytes: int,
) -> RevInventoryV2Result | None:
    """Classify an oversized complete artifact without copying its bytes."""

    _validate_expected_source(
        expected_source_sha256,
        expected_source_size_bytes,
    )
    if type(payload_size) is not int or payload_size < 0:
        raise ValueError("payload_size must be a non-negative integer")
    if payload_size > REV_INVENTORY_V2_MAX_BYTES:
        return _result(
            RevInventoryV2Verdict.ERROR,
            "artifact_too_large",
        )
    return None


def classify_rev_inventory_v2_profile(
    profile: RevInventoryV2BinaryProfile,
) -> tuple[RevInventoryV2Verdict, str]:
    """Apply the ordered, fingerprinted profile decision table."""

    if not profile.havecode:
        return (
            RevInventoryV2Verdict.NOT_APPLICABLE,
            "no_executable_code",
        )
    if profile.bintype == "unknown":
        return (
            RevInventoryV2Verdict.NOT_APPLICABLE,
            "unsupported_binary_type",
        )
    if (
        profile.arch is None
        or profile.bits is None
        or profile.endian == "unknown"
    ):
        return (
            RevInventoryV2Verdict.INCONCLUSIVE,
            "incomplete_binary_profile",
        )
    supported_bits = REV_INVENTORY_V2_SUPPORTED_ARCH_BITS.get(
        profile.arch
    )
    if supported_bits is None:
        return (
            RevInventoryV2Verdict.NOT_APPLICABLE,
            "unsupported_architecture",
        )
    if profile.bits not in supported_bits:
        return (
            RevInventoryV2Verdict.NOT_APPLICABLE,
            "unsupported_architecture_bits",
        )
    if profile.endian == "mixed":
        return (
            RevInventoryV2Verdict.INCONCLUSIVE,
            "mixed_endian_profile",
        )
    return (
        RevInventoryV2Verdict.CONFIRMED,
        "binary_profile_observed",
    )


def evaluate_rev_inventory_v2(
    payload: bytes,
    *,
    expected_source_sha256: str,
    expected_source_size_bytes: int,
) -> RevInventoryV2Result:
    """Validate one immutable ``inventory-v2.json`` snapshot."""

    _validate_expected_source(
        expected_source_sha256,
        expected_source_size_bytes,
    )
    if type(payload) is not bytes:
        raise TypeError("payload must be bytes")
    size_result = evaluate_rev_inventory_v2_artifact_size(
        len(payload),
        expected_source_sha256=expected_source_sha256,
        expected_source_size_bytes=expected_source_size_bytes,
    )
    if size_result is not None:
        return size_result
    try:
        text = payload.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        if _json_depth(value) > REV_INVENTORY_V2_MAX_JSON_DEPTH:
            raise _SchemaError("artifact exceeds the JSON depth limit")
    except _DuplicateKeyError:
        return _result(
            RevInventoryV2Verdict.ERROR,
            "duplicate_json_key",
        )
    except (
        json.JSONDecodeError,
        RecursionError,
        UnicodeDecodeError,
        ValueError,
    ):
        return _result(RevInventoryV2Verdict.ERROR, "invalid_json")

    try:
        if payload != rev_inventory_v2_canonical_json_bytes(value):
            return _result(
                RevInventoryV2Verdict.ERROR,
                "noncanonical_json",
            )
    except (TypeError, ValueError, UnicodeEncodeError):
        return _result(RevInventoryV2Verdict.ERROR, "invalid_json")

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
        if schema_version != REV_INVENTORY_V2_SCHEMA_VERSION:
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
            contract_id != REV_INVENTORY_V2_CONTRACT_ID
            or contract_version != REV_INVENTORY_V2_CONTRACT_VERSION
            or fingerprint != REV_INVENTORY_V2_CONTRACT_FINGERPRINT
        ):
            return _result(
                RevInventoryV2Verdict.ERROR,
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
        if not 0 <= source_size <= REV_INVENTORY_V2_MAX_SOURCE_BYTES:
            raise _SchemaError("source.size_bytes is outside the contract")
        if source_sha256 != expected_source_sha256:
            return _result(
                RevInventoryV2Verdict.ERROR,
                "source_hash_mismatch",
                source_sha256=source_sha256,
                source_size_bytes=source_size,
            )
        if source_size != expected_source_size_bytes:
            return _result(
                RevInventoryV2Verdict.ERROR,
                "source_size_mismatch",
                source_sha256=source_sha256,
                source_size_bytes=source_size,
            )

        status = _exact_string(root["status"], "status")
        if status == "error":
            error = _exact_object(root["error"], {"code"}, "error")
            error_code = _exact_string(error["code"], "error.code")
            reason_code = (
                REV_INVENTORY_V2_PRODUCER_ERROR_REASON_MAP.get(error_code)
            )
            if reason_code is None:
                raise _SchemaError("unknown producer error code")
            return _result(
                RevInventoryV2Verdict.ERROR,
                reason_code,
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
        if bintype not in REV_INVENTORY_V2_PROFILE_BINTYPES:
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
            if bits not in REV_INVENTORY_V2_PROFILE_BITS:
                raise _SchemaError("binary.bits is invalid")
        endian = _exact_string(binary["endian"], "binary.endian")
        if endian not in REV_INVENTORY_V2_PROFILE_ENDIANS:
            raise _SchemaError("binary.endian is invalid")
        if type(binary["havecode"]) is not bool:
            raise _SchemaError("binary.havecode must be boolean")
        profile = RevInventoryV2BinaryProfile(
            bintype=bintype,
            arch=arch,
            bits=bits,
            endian=endian,
            havecode=binary["havecode"],
        )
    except _SchemaError:
        return _result(RevInventoryV2Verdict.ERROR, "invalid_schema")

    verdict, reason_code = classify_rev_inventory_v2_profile(profile)
    return _result(
        verdict,
        reason_code,
        source_sha256=source_sha256,
        source_size_bytes=source_size,
        profile=profile,
    )


_RESULT_KEYS = {
    "contract_fingerprint",
    "oracle_id",
    "oracle_version",
    "profile",
    "reason_code",
    "source_sha256",
    "source_size_bytes",
    "verdict",
}
_PROFILE_KEYS = {"arch", "bits", "bintype", "endian", "havecode"}


def validate_rev_inventory_v2_result_mapping(
    value: object,
) -> Mapping[str, object]:
    """Validate that a state mapping is exactly one parser-emittable result."""

    if not isinstance(value, Mapping) or set(value) != _RESULT_KEYS:
        raise RevInventoryV2ContractError(
            "semantic result has missing or unknown fields"
        )
    if (
        value["oracle_id"] != REV_INVENTORY_V2_CONTRACT_ID
        or type(value["oracle_version"]) is not int
        or value["oracle_version"] != REV_INVENTORY_V2_CONTRACT_VERSION
        or value["contract_fingerprint"]
        != REV_INVENTORY_V2_CONTRACT_FINGERPRINT
    ):
        raise RevInventoryV2ContractError(
            "semantic result has a mismatched v2 contract"
        )
    try:
        verdict = RevInventoryV2Verdict(value["verdict"])
    except (TypeError, ValueError) as error:
        raise RevInventoryV2ContractError(
            "semantic result has an invalid verdict"
        ) from error
    reason = value["reason_code"]
    if type(reason) is not str or not reason:
        raise RevInventoryV2ContractError(
            "semantic result has an invalid reason code"
        )

    source_sha256 = value["source_sha256"]
    source_size = value["source_size_bytes"]
    if (source_sha256 is None) != (source_size is None):
        raise RevInventoryV2ContractError(
            "semantic result has a partial source binding"
        )
    if source_sha256 is not None:
        _require_sha256(source_sha256, "semantic result source_sha256")
        _require_source_size(
            source_size,
            "semantic result source_size_bytes",
        )

    profile_value = value["profile"]
    if verdict is RevInventoryV2Verdict.ERROR:
        if profile_value is not None:
            raise RevInventoryV2ContractError(
                "ERROR semantic result cannot contain a profile"
            )
        if reason in REV_INVENTORY_V2_SOURCE_BOUND_ERROR_REASONS:
            if source_sha256 is None:
                raise RevInventoryV2ContractError(
                    "source-bound ERROR result lacks its source binding"
                )
        elif reason in REV_INVENTORY_V2_PRE_SOURCE_ERROR_REASONS:
            if source_sha256 is not None:
                raise RevInventoryV2ContractError(
                    "pre-source ERROR result claims a source binding"
                )
        else:
            raise RevInventoryV2ContractError(
                "ERROR semantic result has an unknown reason"
            )
        return value

    if source_sha256 is None:
        raise RevInventoryV2ContractError(
            "non-error semantic result lacks its source binding"
        )
    if (
        not isinstance(profile_value, Mapping)
        or set(profile_value) != _PROFILE_KEYS
    ):
        raise RevInventoryV2ContractError(
            "non-error semantic result requires an exact profile"
        )
    arch = profile_value["arch"]
    bits = profile_value["bits"]
    bintype = profile_value["bintype"]
    endian = profile_value["endian"]
    havecode = profile_value["havecode"]
    if arch is not None and (
        type(arch) is not str or not _SAFE_TOKEN.fullmatch(arch)
    ):
        raise RevInventoryV2ContractError(
            "semantic profile has an invalid architecture"
        )
    if bits is not None and (
        type(bits) is not int
        or bits not in REV_INVENTORY_V2_PROFILE_BITS
    ):
        raise RevInventoryV2ContractError(
            "semantic profile has invalid bits"
        )
    if (
        type(bintype) is not str
        or bintype not in REV_INVENTORY_V2_PROFILE_BINTYPES
    ):
        raise RevInventoryV2ContractError(
            "semantic profile has an invalid binary type"
        )
    if (
        type(endian) is not str
        or endian not in REV_INVENTORY_V2_PROFILE_ENDIANS
    ):
        raise RevInventoryV2ContractError(
            "semantic profile has invalid endianness"
        )
    if type(havecode) is not bool:
        raise RevInventoryV2ContractError(
            "semantic profile havecode must be boolean"
        )
    profile = RevInventoryV2BinaryProfile(
        bintype=bintype,
        arch=arch,
        bits=bits,
        endian=endian,
        havecode=havecode,
    )
    expected_verdict, expected_reason = (
        classify_rev_inventory_v2_profile(profile)
    )
    if verdict is not expected_verdict or reason != expected_reason:
        raise RevInventoryV2ContractError(
            "semantic verdict/reason/profile contract mismatch"
        )
    return value


__all__ = [
    "REV_INVENTORY_V2_ADAPTER_SEED_CONTRACT_VERSION",
    "REV_INVENTORY_V2_BINTYPE_ALIASES",
    "REV_INVENTORY_V2_CONTRACT_FINGERPRINT",
    "REV_INVENTORY_V2_CONTRACT_ID",
    "REV_INVENTORY_V2_CONTRACT_VERSION",
    "REV_INVENTORY_V2_DOCUMENT_TRANSPORT",
    "REV_INVENTORY_V2_ERROR_REASONS",
    "REV_INVENTORY_V2_ERROR_REASON_RULES",
    "REV_INVENTORY_V2_MAX_BYTES",
    "REV_INVENTORY_V2_MAX_JSON_DEPTH",
    "REV_INVENTORY_V2_MAX_SOURCE_BYTES",
    "REV_INVENTORY_V2_OUTPUT_NAME",
    "REV_INVENTORY_V2_PROFILE_BITS",
    "REV_INVENTORY_V2_PROFILE_BINTYPES",
    "REV_INVENTORY_V2_PROFILE_ENDIANS",
    "REV_INVENTORY_V2_PRE_SOURCE_ERROR_REASONS",
    "REV_INVENTORY_V2_PRODUCER_ERROR_REASON_MAP",
    "REV_INVENTORY_V2_RABIN2_STDERR_MAX_BYTES",
    "REV_INVENTORY_V2_RABIN2_STDOUT_MAX_BYTES",
    "REV_INVENTORY_V2_RABIN2_TIMEOUT_SECONDS",
    "REV_INVENTORY_V2_SCHEMA_VERSION",
    "REV_INVENTORY_V2_SEED_COMMAND_TEMPLATE",
    "REV_INVENTORY_V2_SEED_DROP_CONDITION",
    "REV_INVENTORY_V2_SEED_EXPECTED_OBSERVATION",
    "REV_INVENTORY_V2_SEED_KEEP_CONDITION",
    "REV_INVENTORY_V2_SEED_PURPOSE",
    "REV_INVENTORY_V2_SEED_REQUIRES_EXPLICIT_EXECUTION",
    "REV_INVENTORY_V2_SEED_RESOURCE_CLASS",
    "REV_INVENTORY_V2_SEED_TEMPLATE_ID",
    "REV_INVENTORY_V2_SEED_TIMEOUT_SECONDS",
    "REV_INVENTORY_V2_SNAPSHOT_DIRECTORY_MODE",
    "REV_INVENTORY_V2_SNAPSHOT_FILE_MODE",
    "REV_INVENTORY_V2_SNAPSHOT_MOUNT_REQUIREMENT",
    "REV_INVENTORY_V2_SNAPSHOT_PUBLISH",
    "REV_INVENTORY_V2_SNAPSHOT_TREE_CONTRACT",
    "REV_INVENTORY_V2_SOURCE_HASH_TIMEOUT_SECONDS",
    "REV_INVENTORY_V2_SOURCE_BOUND_ERROR_REASONS",
    "REV_INVENTORY_V2_SOURCE_MISMATCH_REASONS",
    "REV_INVENTORY_V2_SUPPORTED_ARCH_BITS",
    "REV_INVENTORY_V2_VERDICT_REASON_RULES",
    "RevInventoryV2BinaryProfile",
    "RevInventoryV2ContractError",
    "RevInventoryV2Result",
    "RevInventoryV2Verdict",
    "build_rev_inventory_v2_seed_extra",
    "build_rev_inventory_v2_seed_spec_descriptor",
    "build_rev_inventory_v2_source_binding",
    "build_rev_inventory_v2_source_snapshot",
    "classify_rev_inventory_v2_profile",
    "evaluate_rev_inventory_v2",
    "evaluate_rev_inventory_v2_artifact_size",
    "rev_inventory_v2_canonical_json_bytes",
    "rev_inventory_v2_contract_descriptor",
    "rev_inventory_v2_oracle_descriptor",
    "rev_inventory_v2_seed_argv",
    "rev_inventory_v2_seed_command",
    "rev_inventory_v2_seed_spec_sha256",
    "rev_inventory_v2_snapshot_contract",
    "validate_rev_inventory_v2_result_mapping",
]
