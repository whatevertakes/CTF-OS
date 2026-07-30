"""Pure v1 advisory for recipe-scoped Pwn address resolution.

This contract classifies one declared address dependency at a time.  Its
scope is the exact tuple ``(canonical strategy SHA-256, dependency id,
source identity, ELF-profile evidence identity)``.
Consequently, ``CONDITIONAL_NOT_APPLICABLE`` means only that the selected
strategy dependency does not itself require runtime address resolution under
the supplied ELF profile.  ``RUNTIME_ADDRESS_RESOLUTION_REQUIRED`` is also an
advisory: it does not prove that an exploit must first create a leak.  A
provided pointer, an already-proven leak, a non-randomized runtime, or another
strategy can satisfy the resolution requirement.  No verdict authorizes a
stage transition, proves that a challenge globally needs no leak, establishes
an exploitation primitive, or satisfies proof.

The strategy artifact is deliberately small and non-executable.  It can name
only address dependencies; it cannot carry commands, payloads, absolute
addresses, or free-form model prose.  ELF profile values are engine-derived
inputs and are not trusted when malformed, unsupported, or ambiguous.

Once persisted, this module is append-only.  Semantic changes belong in a new
versioned contract selected by an exact id/version/fingerprint tuple.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any


PWN_LEAK_REQUIREMENT_V1_SCHEMA_VERSION = 1
PWN_LEAK_REQUIREMENT_V1_CONTRACT_ID = "ctfos.pwn.leak_requirement"
PWN_LEAK_REQUIREMENT_V1_CONTRACT_VERSION = 1
PWN_LEAK_REQUIREMENT_V1_MAX_STRATEGY_BYTES = 16 * 1024
PWN_LEAK_REQUIREMENT_V1_MAX_RESULT_BYTES = 16 * 1024
PWN_LEAK_REQUIREMENT_V1_MAX_JSON_DEPTH = 6
PWN_LEAK_REQUIREMENT_V1_MAX_DEPENDENCIES = 8
PWN_LEAK_REQUIREMENT_V1_MAX_ID_BYTES = 64
PWN_LEAK_REQUIREMENT_V1_MAX_SOURCE_BYTES = 1024 * 1024 * 1024

PWN_LEAK_REQUIREMENT_V1_PURPOSES = frozenset(
    {"allocator", "control_flow", "read", "write"}
)
PWN_LEAK_REQUIREMENT_V1_OBJECT_KINDS = frozenset(
    {"heap", "libc", "primary_elf", "stack"}
)
PWN_LEAK_REQUIREMENT_V1_ADDRESS_MODES = frozenset(
    {"absolute", "relative"}
)
PWN_LEAK_REQUIREMENT_V1_ELF_TYPES = frozenset({"ET_DYN", "ET_EXEC"})
PWN_LEAK_REQUIREMENT_V1_PROFILE_STATUSES = frozenset(
    {"ambiguous", "supported", "unsupported"}
)
PWN_LEAK_REQUIREMENT_V1_FAILURE_CODES = frozenset(
    {
        "artifact_too_large",
        "contract_mismatch",
        "duplicate_dependency_id",
        "dependency_order_mismatch",
        "duplicate_json_key",
        "invalid_json",
        "invalid_schema",
        "noncanonical_json",
        "result_binding_mismatch",
        "strategy_hash_mismatch",
    }
)
PWN_LEAK_REQUIREMENT_V1_REASON_CODES = frozenset(
    {
        "absolute_runtime_address_dependency",
        "elf_profile_ambiguous",
        "elf_profile_unsupported",
        "fixed_primary_elf_address_dependency",
        "malformed_dependency_lookup",
        "relative_address_dependency",
        "static_et_dyn_profile_unsupported",
        "unknown_dependency",
    }
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_STRATEGY_KEYS = frozenset(
    {"contract", "dependencies", "schema_version", "strategy_id"}
)
_CONTRACT_KEYS = frozenset({"fingerprint", "id", "version"})
_DEPENDENCY_KEYS = frozenset(
    {"address_mode", "dependency_id", "object_kind", "purpose"}
)
_RESULT_KEYS = frozenset(
    {
        "binding",
        "claims",
        "contract",
        "dependency",
        "elf_profile",
        "reason_code",
        "schema_version",
        "verdict",
    }
)
_BINDING_KEYS = frozenset(
    {
        "dependency_id",
        "profile_evidence_sha256",
        "source_manifest_sha256",
        "source_sha256",
        "source_size_bytes",
        "strategy_id",
        "strategy_sha256",
    }
)
_CLAIM_KEYS = frozenset(
    {
        "global_leak_not_applicable_proven",
        "global_runtime_address_resolution_not_applicable_proven",
        "leak_proven",
        "leak_required_proven",
        "primitive_proven",
        "proof_satisfied",
        "stage_advance_authorized",
    }
)
_PROFILE_KEYS = frozenset(
    {
        "e_type",
        "has_interp",
        "profile_evidence_sha256",
        "source_manifest_sha256",
        "source_sha256",
        "source_size_bytes",
        "status",
    }
)


def pwn_leak_requirement_v1_canonical_json_bytes(
    value: object,
) -> bytes:
    """Return the only persisted JSON representation accepted by v1."""

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


def pwn_leak_requirement_v1_contract_descriptor() -> dict[str, object]:
    """Build a fresh descriptor covering every semantic v1 rule."""

    return {
        "advisory_name": "runtime-address-resolution-requirement",
        "address_modes": sorted(
            PWN_LEAK_REQUIREMENT_V1_ADDRESS_MODES
        ),
        "canonical_json": "ascii-strict-sorted-compact-newline-v1",
        "classification_authority": "advisory-only",
        "classification_scope": (
            "exact-canonical-strategy-sha256-plus-dependency-id-plus-"
            "source-identity-plus-profile-evidence-identity"
        ),
        "claims": {
            "global_leak_not_applicable_proven": False,
            "global_runtime_address_resolution_not_applicable_proven": False,
            "leak_proven": False,
            "leak_required_proven": False,
            "primitive_proven": False,
            "proof_satisfied": False,
            "stage_advance_authorized": False,
        },
        "contract_id": PWN_LEAK_REQUIREMENT_V1_CONTRACT_ID,
        "contract_version": PWN_LEAK_REQUIREMENT_V1_CONTRACT_VERSION,
        "decision_rules": [
            (
                "malformed-dependency-lookup=>UNRESOLVED:"
                "malformed_dependency_lookup"
            ),
            "unknown-dependency=>UNRESOLVED:unknown_dependency",
            (
                "profile-status=unsupported=>UNRESOLVED:"
                "elf_profile_unsupported"
            ),
            (
                "profile-status=ambiguous=>UNRESOLVED:"
                "elf_profile_ambiguous"
            ),
            (
                "address-mode=relative=>CONDITIONAL_NOT_APPLICABLE:"
                "relative_address_dependency"
            ),
            (
                "address-mode=absolute,object=primary_elf,"
                "e_type=ET_EXEC=>CONDITIONAL_NOT_APPLICABLE:"
                "fixed_primary_elf_address_dependency"
            ),
            (
                "address-mode=absolute,object=primary_elf,"
                "e_type=ET_DYN,has_interp=true=>"
                "RUNTIME_ADDRESS_RESOLUTION_REQUIRED:"
                "absolute_runtime_address_dependency"
            ),
            (
                "address-mode=absolute,object=primary_elf,"
                "e_type=ET_DYN,has_interp=false=>UNRESOLVED:"
                "static_et_dyn_profile_unsupported"
            ),
            (
                "address-mode=absolute,"
                "object=libc|stack|heap=>"
                "RUNTIME_ADDRESS_RESOLUTION_REQUIRED:"
                "absolute_runtime_address_dependency"
            ),
        ],
        "dependency_count": {
            "maximum": PWN_LEAK_REQUIREMENT_V1_MAX_DEPENDENCIES,
            "minimum": 1,
        },
        "dependency_order": "dependency_id-strictly-increasing",
        "dependency_shape": (
            "dependency_id;purpose;object_kind;address_mode"
        ),
        "elf_profile": {
            "e_type": sorted(PWN_LEAK_REQUIREMENT_V1_ELF_TYPES),
            "has_interp": "exact-boolean",
            "profile_evidence_sha256": "lowercase-sha256",
            "source_manifest_sha256": "lowercase-sha256",
            "source_sha256": "lowercase-sha256",
            "source_size_bytes": (
                f"exact-integer-1.."
                f"{PWN_LEAK_REQUIREMENT_V1_MAX_SOURCE_BYTES}"
            ),
            "status": sorted(
                PWN_LEAK_REQUIREMENT_V1_PROFILE_STATUSES
            ),
        },
        "failure_codes": sorted(
            PWN_LEAK_REQUIREMENT_V1_FAILURE_CODES
        ),
        "id_max_bytes": PWN_LEAK_REQUIREMENT_V1_MAX_ID_BYTES,
        "id_pattern": "[a-z0-9][a-z0-9._-]{0,63}",
        "json_max_depth": PWN_LEAK_REQUIREMENT_V1_MAX_JSON_DEPTH,
        "non_authorities": [
            "advisory-does-not-prove-leak-is-required",
            "does-not-prove-dependency-set-complete",
            "does-not-prove-global-leak-not-applicable",
            "does-not-prove-leak",
            "does-not-prove-primitive",
            "does-not-prove-relative-anchor-resolved",
            "does-not-satisfy-proof",
            "does-not-authorize-stage-advance",
        ],
        "object_kinds": sorted(
            PWN_LEAK_REQUIREMENT_V1_OBJECT_KINDS
        ),
        "purposes": sorted(PWN_LEAK_REQUIREMENT_V1_PURPOSES),
        "reason_codes": sorted(PWN_LEAK_REQUIREMENT_V1_REASON_CODES),
        "result_max_bytes": PWN_LEAK_REQUIREMENT_V1_MAX_RESULT_BYTES,
        "schemas": {
            "binding_keys": sorted(_BINDING_KEYS),
            "claims_keys": sorted(_CLAIM_KEYS),
            "container_types": {
                "binding": "exact-dict",
                "claims": "exact-dict",
                "contract": "exact-dict",
                "dependency": "exact-dict-or-null",
                "elf_profile": "exact-dict",
                "result": "exact-dict",
                "strategy": "exact-dict",
                "strategy.dependencies": "exact-list",
            },
            "contract_keys": sorted(_CONTRACT_KEYS),
            "dependency_keys": sorted(_DEPENDENCY_KEYS),
            "profile_keys": sorted(_PROFILE_KEYS),
            "result_keys": sorted(_RESULT_KEYS),
            "scalar_types": {
                "binding.dependency_id": "exact-safe-id-str-or-null",
                "binding.profile_evidence_sha256": (
                    "exact-lowercase-sha256-str"
                ),
                "binding.source_manifest_sha256": (
                    "exact-lowercase-sha256-str"
                ),
                "binding.source_sha256": (
                    "exact-lowercase-sha256-str"
                ),
                "binding.source_size_bytes": (
                    "exact-bounded-positive-int-not-bool"
                ),
                "binding.strategy_id": "exact-safe-id-str",
                "binding.strategy_sha256": (
                    "exact-lowercase-sha256-str"
                ),
                "contract.fingerprint": (
                    "exact-lowercase-sha256-str"
                ),
                "contract.id": "exact-contract-id-str",
                "contract.version": "exact-int-not-bool",
                "dependency.address_mode": "exact-enum-str",
                "dependency.dependency_id": "exact-safe-id-str",
                "dependency.object_kind": "exact-enum-str",
                "dependency.purpose": "exact-enum-str",
                "profile.e_type": "exact-enum-str",
                "profile.has_interp": "exact-bool",
                "profile.profile_evidence_sha256": (
                    "exact-lowercase-sha256-str"
                ),
                "profile.source_manifest_sha256": (
                    "exact-lowercase-sha256-str"
                ),
                "profile.source_sha256": (
                    "exact-lowercase-sha256-str"
                ),
                "profile.source_size_bytes": (
                    "exact-bounded-positive-int-not-bool"
                ),
                "profile.status": "exact-enum-str",
                "result.reason_code": "exact-enum-str",
                "result.schema_version": "exact-int-not-bool",
                "result.verdict": "exact-enum-str",
                "strategy.schema_version": "exact-int-not-bool",
                "strategy.strategy_id": "exact-safe-id-str",
            },
            "strategy_keys": sorted(_STRATEGY_KEYS),
        },
        "schema_version": PWN_LEAK_REQUIREMENT_V1_SCHEMA_VERSION,
        "source_max_bytes": PWN_LEAK_REQUIREMENT_V1_MAX_SOURCE_BYTES,
        "strategy_forbidden_fields": [
            "absolute-address-values",
            "commands",
            "free-form-prose",
            "payloads",
        ],
        "strategy_max_bytes": (
            PWN_LEAK_REQUIREMENT_V1_MAX_STRATEGY_BYTES
        ),
        "validation": {
            "mapping_return": "new-immutable-result",
            "result_bytes": (
                "bounded-duplicate-free-depth-bounded-canonical-only"
            ),
            "trusted_inputs": [
                "expected_strategy",
                "expected_dependency_id",
                "expected_elf_profile",
                "expected_source_manifest_sha256",
                "expected_source_sha256",
                "expected_source_size_bytes",
                "expected_profile_evidence_sha256",
            ],
        },
        "verdicts": [
            "CONDITIONAL_NOT_APPLICABLE",
            "RUNTIME_ADDRESS_RESOLUTION_REQUIRED",
            "UNRESOLVED",
        ],
    }


PWN_LEAK_REQUIREMENT_V1_CONTRACT_FINGERPRINT = hashlib.sha256(
    pwn_leak_requirement_v1_canonical_json_bytes(
        pwn_leak_requirement_v1_contract_descriptor()
    )
).hexdigest()


class PwnLeakRequirementV1Verdict(str, Enum):
    RUNTIME_ADDRESS_RESOLUTION_REQUIRED = (
        "RUNTIME_ADDRESS_RESOLUTION_REQUIRED"
    )
    CONDITIONAL_NOT_APPLICABLE = "CONDITIONAL_NOT_APPLICABLE"
    UNRESOLVED = "UNRESOLVED"


class PwnLeakRequirementV1ContractError(ValueError):
    """Stable parser rejection carrying no artifact-controlled text."""

    def __init__(self, code: str) -> None:
        if (
            type(code) is not str
            or code not in PWN_LEAK_REQUIREMENT_V1_FAILURE_CODES
        ):
            raise ValueError("unknown Pwn leak requirement v1 failure code")
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class PwnLeakRequirementV1Dependency:
    dependency_id: str
    purpose: str
    object_kind: str
    address_mode: str

    def __post_init__(self) -> None:
        if (
            type(self.dependency_id) is not str
            or _SAFE_ID.fullmatch(self.dependency_id) is None
            or type(self.purpose) is not str
            or self.purpose not in PWN_LEAK_REQUIREMENT_V1_PURPOSES
            or type(self.object_kind) is not str
            or self.object_kind
            not in PWN_LEAK_REQUIREMENT_V1_OBJECT_KINDS
            or type(self.address_mode) is not str
            or self.address_mode
            not in PWN_LEAK_REQUIREMENT_V1_ADDRESS_MODES
        ):
            raise ValueError("invalid Pwn leak requirement v1 dependency")

    def to_dict(self) -> dict[str, object]:
        return {
            "address_mode": self.address_mode,
            "dependency_id": self.dependency_id,
            "object_kind": self.object_kind,
            "purpose": self.purpose,
        }


@dataclass(frozen=True, slots=True)
class PwnLeakRequirementV1Strategy:
    strategy_id: str
    dependencies: tuple[PwnLeakRequirementV1Dependency, ...]

    def __post_init__(self) -> None:
        if (
            type(self.strategy_id) is not str
            or _SAFE_ID.fullmatch(self.strategy_id) is None
        ):
            raise ValueError("invalid Pwn leak requirement v1 strategy id")
        if (
            type(self.dependencies) is not tuple
            or not 1
            <= len(self.dependencies)
            <= PWN_LEAK_REQUIREMENT_V1_MAX_DEPENDENCIES
            or any(
                type(item) is not PwnLeakRequirementV1Dependency
                for item in self.dependencies
            )
        ):
            raise ValueError(
                "invalid Pwn leak requirement v1 dependencies"
            )
        dependency_ids = [
            item.dependency_id for item in self.dependencies
        ]
        if len(set(dependency_ids)) != len(dependency_ids):
            raise ValueError(
                "duplicate Pwn leak requirement v1 dependency id"
            )
        if dependency_ids != sorted(dependency_ids):
            raise ValueError(
                "Pwn leak requirement v1 dependencies are not canonical"
            )
        if (
            len(self.canonical_bytes())
            > PWN_LEAK_REQUIREMENT_V1_MAX_STRATEGY_BYTES
        ):
            raise ValueError(
                "Pwn leak requirement v1 strategy exceeds byte limit"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "contract": {
                "fingerprint": (
                    PWN_LEAK_REQUIREMENT_V1_CONTRACT_FINGERPRINT
                ),
                "id": PWN_LEAK_REQUIREMENT_V1_CONTRACT_ID,
                "version": PWN_LEAK_REQUIREMENT_V1_CONTRACT_VERSION,
            },
            "dependencies": [
                item.to_dict() for item in self.dependencies
            ],
            "schema_version": PWN_LEAK_REQUIREMENT_V1_SCHEMA_VERSION,
            "strategy_id": self.strategy_id,
        }

    def canonical_bytes(self) -> bytes:
        return pwn_leak_requirement_v1_canonical_json_bytes(
            self.to_dict()
        )

    @property
    def strategy_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def dependency(
        self,
        dependency_id: str,
    ) -> PwnLeakRequirementV1Dependency | None:
        return next(
            (
                item
                for item in self.dependencies
                if item.dependency_id == dependency_id
            ),
            None,
        )


@dataclass(frozen=True, slots=True)
class PwnLeakRequirementV1ElfProfile:
    e_type: str
    has_interp: bool
    status: str
    source_manifest_sha256: str
    source_sha256: str
    source_size_bytes: int
    profile_evidence_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.e_type) is not str
            or self.e_type not in PWN_LEAK_REQUIREMENT_V1_ELF_TYPES
            or type(self.has_interp) is not bool
            or type(self.status) is not str
            or self.status
            not in PWN_LEAK_REQUIREMENT_V1_PROFILE_STATUSES
            or type(self.source_manifest_sha256) is not str
            or _SHA256.fullmatch(self.source_manifest_sha256) is None
            or type(self.source_sha256) is not str
            or _SHA256.fullmatch(self.source_sha256) is None
            or type(self.source_size_bytes) is not int
            or not 1
            <= self.source_size_bytes
            <= PWN_LEAK_REQUIREMENT_V1_MAX_SOURCE_BYTES
            or type(self.profile_evidence_sha256) is not str
            or _SHA256.fullmatch(self.profile_evidence_sha256) is None
        ):
            raise ValueError("invalid Pwn leak requirement v1 ELF profile")

    def to_dict(self) -> dict[str, object]:
        return {
            "e_type": self.e_type,
            "has_interp": self.has_interp,
            "profile_evidence_sha256": self.profile_evidence_sha256,
            "source_manifest_sha256": self.source_manifest_sha256,
            "source_sha256": self.source_sha256,
            "source_size_bytes": self.source_size_bytes,
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class PwnLeakRequirementV1Result:
    strategy_id: str
    strategy_sha256: str
    dependency_id: str | None
    dependency: PwnLeakRequirementV1Dependency | None
    elf_profile: PwnLeakRequirementV1ElfProfile
    verdict: PwnLeakRequirementV1Verdict
    reason_code: str

    def __post_init__(self) -> None:
        if (
            type(self.strategy_id) is not str
            or _SAFE_ID.fullmatch(self.strategy_id) is None
            or type(self.strategy_sha256) is not str
            or _SHA256.fullmatch(self.strategy_sha256) is None
            or (
                self.dependency_id is not None
                and (
                    type(self.dependency_id) is not str
                    or _SAFE_ID.fullmatch(self.dependency_id) is None
                )
            )
            or (
                self.dependency is not None
                and (
                    type(self.dependency)
                    is not PwnLeakRequirementV1Dependency
                    or self.dependency.dependency_id
                    != self.dependency_id
                )
            )
            or type(self.elf_profile)
            is not PwnLeakRequirementV1ElfProfile
            or type(self.verdict) is not PwnLeakRequirementV1Verdict
            or type(self.reason_code) is not str
            or self.reason_code
            not in PWN_LEAK_REQUIREMENT_V1_REASON_CODES
        ):
            raise ValueError("invalid Pwn leak requirement v1 result")

    def to_dict(self) -> dict[str, object]:
        return {
            "binding": {
                "dependency_id": self.dependency_id,
                "profile_evidence_sha256": (
                    self.elf_profile.profile_evidence_sha256
                ),
                "source_manifest_sha256": (
                    self.elf_profile.source_manifest_sha256
                ),
                "source_sha256": self.elf_profile.source_sha256,
                "source_size_bytes": (
                    self.elf_profile.source_size_bytes
                ),
                "strategy_id": self.strategy_id,
                "strategy_sha256": self.strategy_sha256,
            },
            "claims": {
                "global_leak_not_applicable_proven": False,
                "global_runtime_address_resolution_not_applicable_proven": (
                    False
                ),
                "leak_proven": False,
                "leak_required_proven": False,
                "primitive_proven": False,
                "proof_satisfied": False,
                "stage_advance_authorized": False,
            },
            "contract": {
                "fingerprint": (
                    PWN_LEAK_REQUIREMENT_V1_CONTRACT_FINGERPRINT
                ),
                "id": PWN_LEAK_REQUIREMENT_V1_CONTRACT_ID,
                "version": PWN_LEAK_REQUIREMENT_V1_CONTRACT_VERSION,
            },
            "dependency": (
                self.dependency.to_dict()
                if self.dependency is not None
                else None
            ),
            "elf_profile": self.elf_profile.to_dict(),
            "reason_code": self.reason_code,
            "schema_version": PWN_LEAK_REQUIREMENT_V1_SCHEMA_VERSION,
            "verdict": self.verdict.value,
        }

    def canonical_bytes(self) -> bytes:
        payload = pwn_leak_requirement_v1_canonical_json_bytes(
            self.to_dict()
        )
        if len(payload) > PWN_LEAK_REQUIREMENT_V1_MAX_RESULT_BYTES:
            raise ValueError(
                "Pwn leak requirement v1 result exceeds byte limit"
            )
        return payload

    @property
    def evidence_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


class _DuplicateKeyError(ValueError):
    pass


class _SchemaError(ValueError):
    pass


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError


def _json_depth_exceeds(value: object, maximum: int) -> bool:
    pending: list[tuple[object, int]] = [(value, 1)]
    while pending:
        current, depth = pending.pop()
        if depth > maximum:
            return True
        if type(current) is dict:
            pending.extend(
                (item, depth + 1) for item in current.values()
            )
        elif type(current) is list:
            pending.extend((item, depth + 1) for item in current)
    return False


def _exact_mapping(
    value: object,
    expected_keys: frozenset[str],
) -> Mapping[str, object]:
    if (
        type(value) is not dict
        or len(value) != len(expected_keys)
        or any(key not in value for key in expected_keys)
    ):
        raise _SchemaError
    return value


def _schema_id(value: object) -> str:
    if type(value) is not str or _SAFE_ID.fullmatch(value) is None:
        raise _SchemaError
    return value


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _require_source_size(value: object, label: str) -> int:
    if (
        type(value) is not int
        or not 1 <= value <= PWN_LEAK_REQUIREMENT_V1_MAX_SOURCE_BYTES
    ):
        raise ValueError(
            f"{label} must be an exact bounded positive integer"
        )
    return value


def parse_pwn_leak_requirement_v1_strategy(
    payload: bytes,
    *,
    expected_strategy_sha256: str | None = None,
) -> PwnLeakRequirementV1Strategy:
    """Parse one complete canonical, non-executable strategy artifact."""

    if type(payload) is not bytes:
        raise TypeError("payload must be exact bytes")
    if expected_strategy_sha256 is not None:
        _require_sha256(
            expected_strategy_sha256,
            "expected_strategy_sha256",
        )
    if len(payload) > PWN_LEAK_REQUIREMENT_V1_MAX_STRATEGY_BYTES:
        raise PwnLeakRequirementV1ContractError(
            "artifact_too_large"
        )
    try:
        text = payload.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateKeyError as error:
        raise PwnLeakRequirementV1ContractError(
            "duplicate_json_key"
        ) from error
    except (
        json.JSONDecodeError,
        RecursionError,
        UnicodeDecodeError,
        ValueError,
    ) as error:
        raise PwnLeakRequirementV1ContractError(
            "invalid_json"
        ) from error
    if _json_depth_exceeds(
        value,
        PWN_LEAK_REQUIREMENT_V1_MAX_JSON_DEPTH,
    ):
        raise PwnLeakRequirementV1ContractError(
            "invalid_json"
        )

    try:
        root = _exact_mapping(value, _STRATEGY_KEYS)
        if (
            type(root["schema_version"]) is not int
            or root["schema_version"]
            != PWN_LEAK_REQUIREMENT_V1_SCHEMA_VERSION
        ):
            raise _SchemaError
        contract = _exact_mapping(
            root["contract"],
            _CONTRACT_KEYS,
        )
        if (
            type(contract["id"]) is not str
            or type(contract["version"]) is not int
            or type(contract["fingerprint"]) is not str
        ):
            raise _SchemaError
        if (
            contract["id"] != PWN_LEAK_REQUIREMENT_V1_CONTRACT_ID
            or contract["version"]
            != PWN_LEAK_REQUIREMENT_V1_CONTRACT_VERSION
            or contract["fingerprint"]
            != PWN_LEAK_REQUIREMENT_V1_CONTRACT_FINGERPRINT
        ):
            raise PwnLeakRequirementV1ContractError(
                "contract_mismatch"
            )
        strategy_id = _schema_id(root["strategy_id"])
        dependency_values = root["dependencies"]
        if (
            type(dependency_values) is not list
            or not 1
            <= len(dependency_values)
            <= PWN_LEAK_REQUIREMENT_V1_MAX_DEPENDENCIES
        ):
            raise _SchemaError
        dependencies: list[PwnLeakRequirementV1Dependency] = []
        dependency_ids: set[str] = set()
        ordered_dependency_ids: list[str] = []
        for value_item in dependency_values:
            item = _exact_mapping(value_item, _DEPENDENCY_KEYS)
            dependency_id = _schema_id(item["dependency_id"])
            if dependency_id in dependency_ids:
                raise PwnLeakRequirementV1ContractError(
                    "duplicate_dependency_id"
                )
            dependency_ids.add(dependency_id)
            ordered_dependency_ids.append(dependency_id)
            purpose = item["purpose"]
            object_kind = item["object_kind"]
            address_mode = item["address_mode"]
            if (
                type(purpose) is not str
                or purpose not in PWN_LEAK_REQUIREMENT_V1_PURPOSES
                or type(object_kind) is not str
                or object_kind
                not in PWN_LEAK_REQUIREMENT_V1_OBJECT_KINDS
                or type(address_mode) is not str
                or address_mode
                not in PWN_LEAK_REQUIREMENT_V1_ADDRESS_MODES
            ):
                raise _SchemaError
            dependencies.append(
                PwnLeakRequirementV1Dependency(
                    dependency_id=dependency_id,
                    purpose=purpose,
                    object_kind=object_kind,
                    address_mode=address_mode,
                )
            )
        if ordered_dependency_ids != sorted(ordered_dependency_ids):
            raise PwnLeakRequirementV1ContractError(
                "dependency_order_mismatch"
            )
    except PwnLeakRequirementV1ContractError:
        raise
    except (KeyError, _SchemaError) as error:
        raise PwnLeakRequirementV1ContractError(
            "invalid_schema"
        ) from error

    try:
        canonical = pwn_leak_requirement_v1_canonical_json_bytes(
            value
        )
    except (TypeError, UnicodeEncodeError, ValueError) as error:
        raise PwnLeakRequirementV1ContractError(
            "invalid_json"
        ) from error
    if canonical != payload:
        raise PwnLeakRequirementV1ContractError(
            "noncanonical_json"
        )

    strategy = PwnLeakRequirementV1Strategy(
        strategy_id=strategy_id,
        dependencies=tuple(dependencies),
    )
    if strategy.canonical_bytes() != payload:
        raise PwnLeakRequirementV1ContractError(
            "invalid_schema"
        )
    if (
        expected_strategy_sha256 is not None
        and strategy.strategy_sha256 != expected_strategy_sha256
    ):
        raise PwnLeakRequirementV1ContractError(
            "strategy_hash_mismatch"
        )
    return strategy


def _normalize_elf_profile(
    value: object,
) -> PwnLeakRequirementV1ElfProfile | None:
    if type(value) is PwnLeakRequirementV1ElfProfile:
        return value
    try:
        profile = _exact_mapping(value, _PROFILE_KEYS)
        return PwnLeakRequirementV1ElfProfile(
            e_type=profile["e_type"],
            has_interp=profile["has_interp"],
            status=profile["status"],
            source_manifest_sha256=profile[
                "source_manifest_sha256"
            ],
            source_sha256=profile["source_sha256"],
            source_size_bytes=profile["source_size_bytes"],
            profile_evidence_sha256=profile[
                "profile_evidence_sha256"
            ],
        )
    except (KeyError, TypeError, ValueError, _SchemaError):
        return None


def _require_trusted_elf_profile(
    expected_elf_profile: object,
    *,
    expected_source_manifest_sha256: object,
    expected_source_sha256: object,
    expected_source_size_bytes: object,
    expected_profile_evidence_sha256: object,
) -> PwnLeakRequirementV1ElfProfile:
    if type(expected_elf_profile) is not PwnLeakRequirementV1ElfProfile:
        raise TypeError(
            "expected_elf_profile must be an exact v1 ELF profile"
        )
    manifest_sha256 = _require_sha256(
        expected_source_manifest_sha256,
        "expected_source_manifest_sha256",
    )
    source_sha256 = _require_sha256(
        expected_source_sha256,
        "expected_source_sha256",
    )
    source_size = _require_source_size(
        expected_source_size_bytes,
        "expected_source_size_bytes",
    )
    profile_evidence_sha256 = _require_sha256(
        expected_profile_evidence_sha256,
        "expected_profile_evidence_sha256",
    )
    if (
        expected_elf_profile.source_manifest_sha256
        != manifest_sha256
        or expected_elf_profile.source_sha256 != source_sha256
        or expected_elf_profile.source_size_bytes != source_size
        or expected_elf_profile.profile_evidence_sha256
        != profile_evidence_sha256
    ):
        raise ValueError(
            "trusted ELF profile does not match trusted evidence binding"
        )
    return expected_elf_profile


def classify_pwn_leak_requirement_v1(
    strategy: PwnLeakRequirementV1Strategy,
    *,
    dependency_id: object,
    elf_profile: object,
) -> PwnLeakRequirementV1Result:
    """Return a non-authoritative address-resolution advisory."""

    if type(strategy) is not PwnLeakRequirementV1Strategy:
        raise TypeError("strategy must be a parsed v1 strategy")
    profile = _normalize_elf_profile(elf_profile)
    if profile is None:
        raise ValueError(
            "elf_profile must be an exact source-bound v1 ELF profile"
        )

    normalized_dependency_id: str | None
    if (
        type(dependency_id) is not str
        or _SAFE_ID.fullmatch(dependency_id) is None
    ):
        normalized_dependency_id = None
        dependency = None
        verdict = PwnLeakRequirementV1Verdict.UNRESOLVED
        reason_code = "malformed_dependency_lookup"
    else:
        normalized_dependency_id = dependency_id
        dependency = strategy.dependency(dependency_id)
        if dependency is None:
            verdict = PwnLeakRequirementV1Verdict.UNRESOLVED
            reason_code = "unknown_dependency"
        else:
            verdict = None
            reason_code = None

    if verdict is None:
        if profile.status == "unsupported":
            verdict = PwnLeakRequirementV1Verdict.UNRESOLVED
            reason_code = "elf_profile_unsupported"
        elif profile.status == "ambiguous":
            verdict = PwnLeakRequirementV1Verdict.UNRESOLVED
            reason_code = "elf_profile_ambiguous"
        elif dependency.address_mode == "relative":
            verdict = (
                PwnLeakRequirementV1Verdict.CONDITIONAL_NOT_APPLICABLE
            )
            reason_code = "relative_address_dependency"
        elif (
            dependency.object_kind == "primary_elf"
            and profile.e_type == "ET_EXEC"
        ):
            verdict = (
                PwnLeakRequirementV1Verdict.CONDITIONAL_NOT_APPLICABLE
            )
            reason_code = "fixed_primary_elf_address_dependency"
        elif (
            dependency.object_kind == "primary_elf"
            and profile.e_type == "ET_DYN"
            and not profile.has_interp
        ):
            verdict = PwnLeakRequirementV1Verdict.UNRESOLVED
            reason_code = "static_et_dyn_profile_unsupported"
        else:
            verdict = (
                PwnLeakRequirementV1Verdict
                .RUNTIME_ADDRESS_RESOLUTION_REQUIRED
            )
            reason_code = "absolute_runtime_address_dependency"

    assert verdict is not None
    assert reason_code is not None
    return PwnLeakRequirementV1Result(
        strategy_id=strategy.strategy_id,
        strategy_sha256=strategy.strategy_sha256,
        dependency_id=normalized_dependency_id,
        dependency=dependency,
        elf_profile=profile,
        verdict=verdict,
        reason_code=reason_code,
    )


def _validate_result_mapping_shape(value: object) -> None:
    root = _exact_mapping(value, _RESULT_KEYS)
    if (
        type(root["schema_version"]) is not int
        or root["schema_version"]
        != PWN_LEAK_REQUIREMENT_V1_SCHEMA_VERSION
    ):
        raise _SchemaError
    contract = _exact_mapping(root["contract"], _CONTRACT_KEYS)
    if (
        type(contract["id"]) is not str
        or contract["id"] != PWN_LEAK_REQUIREMENT_V1_CONTRACT_ID
        or type(contract["version"]) is not int
        or contract["version"]
        != PWN_LEAK_REQUIREMENT_V1_CONTRACT_VERSION
        or type(contract["fingerprint"]) is not str
        or contract["fingerprint"]
        != PWN_LEAK_REQUIREMENT_V1_CONTRACT_FINGERPRINT
    ):
        raise _SchemaError

    claims = _exact_mapping(root["claims"], _CLAIM_KEYS)
    if any(claims[key] is not False for key in _CLAIM_KEYS):
        raise _SchemaError

    binding = _exact_mapping(root["binding"], _BINDING_KEYS)
    _schema_id(binding["strategy_id"])
    _require_sha256(binding["strategy_sha256"], "strategy_sha256")
    dependency_id = binding["dependency_id"]
    if dependency_id is not None:
        _schema_id(dependency_id)
    _require_sha256(
        binding["source_manifest_sha256"],
        "source_manifest_sha256",
    )
    _require_sha256(binding["source_sha256"], "source_sha256")
    _require_source_size(
        binding["source_size_bytes"],
        "source_size_bytes",
    )
    _require_sha256(
        binding["profile_evidence_sha256"],
        "profile_evidence_sha256",
    )

    dependency_value = root["dependency"]
    if dependency_value is not None:
        dependency_mapping = _exact_mapping(
            dependency_value,
            _DEPENDENCY_KEYS,
        )
        PwnLeakRequirementV1Dependency(
            dependency_id=_schema_id(
                dependency_mapping["dependency_id"]
            ),
            purpose=dependency_mapping["purpose"],
            object_kind=dependency_mapping["object_kind"],
            address_mode=dependency_mapping["address_mode"],
        )

    profile = _normalize_elf_profile(root["elf_profile"])
    if profile is None:
        raise _SchemaError
    if (
        binding["source_manifest_sha256"]
        != profile.source_manifest_sha256
        or binding["source_sha256"] != profile.source_sha256
        or binding["source_size_bytes"] != profile.source_size_bytes
        or binding["profile_evidence_sha256"]
        != profile.profile_evidence_sha256
    ):
        raise _SchemaError

    if (
        type(root["verdict"]) is not str
        or root["verdict"]
        not in {
            item.value for item in PwnLeakRequirementV1Verdict
        }
        or type(root["reason_code"]) is not str
        or root["reason_code"]
        not in PWN_LEAK_REQUIREMENT_V1_REASON_CODES
    ):
        raise _SchemaError
    canonical = pwn_leak_requirement_v1_canonical_json_bytes(value)
    if len(canonical) > PWN_LEAK_REQUIREMENT_V1_MAX_RESULT_BYTES:
        raise _SchemaError


def validate_pwn_leak_requirement_v1_result_mapping(
    value: object,
    *,
    expected_strategy: PwnLeakRequirementV1Strategy,
    expected_dependency_id: object,
    expected_elf_profile: PwnLeakRequirementV1ElfProfile,
    expected_source_manifest_sha256: str,
    expected_source_sha256: str,
    expected_source_size_bytes: int,
    expected_profile_evidence_sha256: str,
) -> PwnLeakRequirementV1Result:
    """Validate against trusted inputs and return a new immutable result."""

    if type(expected_strategy) is not PwnLeakRequirementV1Strategy:
        raise TypeError("expected_strategy must be a parsed v1 strategy")
    if expected_dependency_id is not None and (
        type(expected_dependency_id) is not str
        or _SAFE_ID.fullmatch(expected_dependency_id) is None
    ):
        raise ValueError(
            "expected_dependency_id must be null or an exact safe id"
        )
    trusted_profile = _require_trusted_elf_profile(
        expected_elf_profile,
        expected_source_manifest_sha256=(
            expected_source_manifest_sha256
        ),
        expected_source_sha256=expected_source_sha256,
        expected_source_size_bytes=expected_source_size_bytes,
        expected_profile_evidence_sha256=(
            expected_profile_evidence_sha256
        ),
    )
    expected = classify_pwn_leak_requirement_v1(
        expected_strategy,
        dependency_id=expected_dependency_id,
        elf_profile=trusted_profile,
    )
    try:
        _validate_result_mapping_shape(value)
    except (
        KeyError,
        TypeError,
        UnicodeEncodeError,
        ValueError,
        _SchemaError,
    ) as error:
        raise PwnLeakRequirementV1ContractError(
            "invalid_schema"
        ) from error
    if value != expected.to_dict():
        raise PwnLeakRequirementV1ContractError(
            "result_binding_mismatch"
        )
    return expected


def parse_pwn_leak_requirement_v1_result(
    payload: bytes,
    *,
    expected_strategy: PwnLeakRequirementV1Strategy,
    expected_dependency_id: object,
    expected_elf_profile: PwnLeakRequirementV1ElfProfile,
    expected_source_manifest_sha256: str,
    expected_source_sha256: str,
    expected_source_size_bytes: int,
    expected_profile_evidence_sha256: str,
) -> PwnLeakRequirementV1Result:
    """Parse one canonical result and bind it only to trusted inputs."""

    if type(payload) is not bytes:
        raise TypeError("payload must be exact bytes")
    if len(payload) > PWN_LEAK_REQUIREMENT_V1_MAX_RESULT_BYTES:
        raise PwnLeakRequirementV1ContractError(
            "artifact_too_large"
        )
    try:
        text = payload.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateKeyError as error:
        raise PwnLeakRequirementV1ContractError(
            "duplicate_json_key"
        ) from error
    except (
        json.JSONDecodeError,
        RecursionError,
        UnicodeDecodeError,
        ValueError,
    ) as error:
        raise PwnLeakRequirementV1ContractError(
            "invalid_json"
        ) from error
    if _json_depth_exceeds(
        value,
        PWN_LEAK_REQUIREMENT_V1_MAX_JSON_DEPTH,
    ):
        raise PwnLeakRequirementV1ContractError(
            "invalid_json"
        )
    try:
        canonical = pwn_leak_requirement_v1_canonical_json_bytes(
            value
        )
    except (TypeError, UnicodeEncodeError, ValueError) as error:
        raise PwnLeakRequirementV1ContractError(
            "invalid_json"
        ) from error
    if canonical != payload:
        raise PwnLeakRequirementV1ContractError(
            "noncanonical_json"
        )
    return validate_pwn_leak_requirement_v1_result_mapping(
        value,
        expected_strategy=expected_strategy,
        expected_dependency_id=expected_dependency_id,
        expected_elf_profile=expected_elf_profile,
        expected_source_manifest_sha256=(
            expected_source_manifest_sha256
        ),
        expected_source_sha256=expected_source_sha256,
        expected_source_size_bytes=expected_source_size_bytes,
        expected_profile_evidence_sha256=(
            expected_profile_evidence_sha256
        ),
    )


__all__ = [
    "PWN_LEAK_REQUIREMENT_V1_ADDRESS_MODES",
    "PWN_LEAK_REQUIREMENT_V1_CONTRACT_FINGERPRINT",
    "PWN_LEAK_REQUIREMENT_V1_CONTRACT_ID",
    "PWN_LEAK_REQUIREMENT_V1_CONTRACT_VERSION",
    "PWN_LEAK_REQUIREMENT_V1_ELF_TYPES",
    "PWN_LEAK_REQUIREMENT_V1_MAX_DEPENDENCIES",
    "PWN_LEAK_REQUIREMENT_V1_MAX_ID_BYTES",
    "PWN_LEAK_REQUIREMENT_V1_MAX_RESULT_BYTES",
    "PWN_LEAK_REQUIREMENT_V1_MAX_SOURCE_BYTES",
    "PWN_LEAK_REQUIREMENT_V1_MAX_STRATEGY_BYTES",
    "PWN_LEAK_REQUIREMENT_V1_OBJECT_KINDS",
    "PWN_LEAK_REQUIREMENT_V1_PROFILE_STATUSES",
    "PWN_LEAK_REQUIREMENT_V1_PURPOSES",
    "PWN_LEAK_REQUIREMENT_V1_SCHEMA_VERSION",
    "PwnLeakRequirementV1ContractError",
    "PwnLeakRequirementV1Dependency",
    "PwnLeakRequirementV1ElfProfile",
    "PwnLeakRequirementV1Result",
    "PwnLeakRequirementV1Strategy",
    "PwnLeakRequirementV1Verdict",
    "classify_pwn_leak_requirement_v1",
    "parse_pwn_leak_requirement_v1_result",
    "parse_pwn_leak_requirement_v1_strategy",
    "pwn_leak_requirement_v1_canonical_json_bytes",
    "pwn_leak_requirement_v1_contract_descriptor",
    "validate_pwn_leak_requirement_v1_result_mapping",
]
