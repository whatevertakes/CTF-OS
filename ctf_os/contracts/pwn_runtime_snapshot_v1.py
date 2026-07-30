"""Pure v1 contract for a bounded Pwn fault-stop runtime snapshot.

This contract records one x86_64 ``PTRACE_GETREGSET`` ``NT_PRSTATUS``
register set and one bounded ``/proc/<tgid>/maps`` snapshot from a clean
replay stopped at the expected fault signal.  The result is diagnostic only.
It does not prove or revalidate the parent crash, establish a leak or
primitive, authorize a stage transition, or satisfy proof.

Every result is bound to trusted source and payload identities, the parent
crash recipe and evaluation, the expected signal, and the snapshot recipe.
Register and maps bytes remain producer observations; their internal hashes
and metadata are integrity checks, not independent proof of their origin.

Once persisted, this module is append-only.  Semantic changes belong in a new
versioned contract selected by an exact id/version/fingerprint tuple.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any


PWN_RUNTIME_SNAPSHOT_V1_SCHEMA_VERSION = 1
PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_ID = "ctfos.pwn.runtime_snapshot"
PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_VERSION = 1
PWN_RUNTIME_SNAPSHOT_V1_PROTOCOL = (
    "pwn_local_stdin_runtime_snapshot_v1"
)
PWN_RUNTIME_SNAPSHOT_V1_DOCUMENT_TRANSPORT = (
    "exact-canonical-stdout-once-v1"
)
PWN_RUNTIME_SNAPSHOT_V1_ARCHITECTURE = "x86_64"
PWN_RUNTIME_SNAPSHOT_V1_REGISTER_SOURCE = (
    "ptrace_getregset_nt_prstatus"
)
PWN_RUNTIME_SNAPSHOT_V1_REGISTER_SET_BYTES = 27 * 8
PWN_RUNTIME_SNAPSHOT_V1_MAX_DOCUMENT_BYTES = 256 * 1024
PWN_RUNTIME_SNAPSHOT_V1_MAX_MAPS_BYTES = 128 * 1024
PWN_RUNTIME_SNAPSHOT_V1_MAX_MAPS_BASE64_BYTES = (
    4 * ((PWN_RUNTIME_SNAPSHOT_V1_MAX_MAPS_BYTES + 2) // 3)
)
PWN_RUNTIME_SNAPSHOT_V1_MAX_SOURCE_BYTES = 1024 * 1024 * 1024
PWN_RUNTIME_SNAPSHOT_V1_MAX_PAYLOAD_BYTES = 1024 * 1024
PWN_RUNTIME_SNAPSHOT_V1_MAX_JSON_DEPTH = 7
PWN_RUNTIME_SNAPSHOT_V1_MAX_TARGET_OUTPUT_BYTES = 64 * 1024
PWN_RUNTIME_SNAPSHOT_V1_MAX_TRACED_TASKS = 64
PWN_RUNTIME_SNAPSHOT_V1_TARGET_TIMEOUT_SECONDS = 5.0
PWN_RUNTIME_SNAPSHOT_V1_FIXED_ENVIRONMENT = (
    ("HOME", "/nonexistent"),
    ("LANG", "C.UTF-8"),
    ("LC_ALL", "C.UTF-8"),
    ("PATH", "/usr/bin:/bin"),
    ("TERM", "dumb"),
)

# Linux x86_64 ``struct user_regs_struct`` field order returned by
# NT_PRSTATUS.  The order is semantic even though canonical JSON sorts keys.
PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES = (
    "r15",
    "r14",
    "r13",
    "r12",
    "rbp",
    "rbx",
    "r11",
    "r10",
    "r9",
    "r8",
    "rax",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "orig_rax",
    "rip",
    "cs",
    "eflags",
    "rsp",
    "ss",
    "fs_base",
    "gs_base",
    "ds",
    "es",
    "fs",
    "gs",
)

PWN_RUNTIME_SNAPSHOT_V1_ALLOWED_SIGNALS = frozenset({4, 6, 7, 8, 11})
PWN_RUNTIME_SNAPSHOT_V1_SUCCESS_REASON = "snapshot_captured"
PWN_RUNTIME_SNAPSHOT_V1_INCONCLUSIVE_REASONS = frozenset(
    {
        "target_exited_before_expected_signal",
        "target_timeout",
        "unexpected_core_signal_observed",
        "unexpected_signal_termination",
    }
)
PWN_RUNTIME_SNAPSHOT_V1_PRODUCER_ERROR_REASONS = frozenset(
    {
        "additional_tracee_snapshot_unsupported",
        "binary_ancestor_not_directory",
        "binary_ancestor_unavailable",
        "binary_architecture_unsupported",
        "binary_changed_during_validation",
        "binary_header_unavailable",
        "binary_leaf_unavailable",
        "binary_not_elf",
        "binary_not_executable",
        "binary_not_regular",
        "binary_privilege_bits_forbidden",
        "binary_root_not_directory",
        "binary_root_unavailable",
        "caught_or_ignored_core_signal_unsupported",
        "core_limit_not_enforced",
        "core_limit_unavailable",
        "maps_empty",
        "maps_open_failed",
        "maps_read_failed",
        "maps_size_limit_exceeded",
        "multithreaded_core_signal_unsupported",
        "non_root_core_signal_unsupported",
        "nofollow_open_unavailable",
        "payload_ancestor_not_directory",
        "payload_ancestor_unavailable",
        "payload_changed_during_read",
        "payload_hash_mismatch",
        "payload_leaf_unavailable",
        "payload_not_regular",
        "payload_read_failed",
        "payload_read_incomplete",
        "payload_root_not_directory",
        "payload_root_unavailable",
        "payload_size_limit_exceeded",
        "payload_size_mismatch",
        "payload_snapshot_changed_during_seal",
        "payload_snapshot_create_failed",
        "payload_snapshot_not_read_only",
        "payload_snapshot_readback_failed",
        "payload_snapshot_readback_mismatch",
        "payload_snapshot_reopen_failed",
        "payload_snapshot_reopen_mismatch",
        "payload_snapshot_rewind_failed",
        "payload_snapshot_seal_failed",
        "payload_snapshot_seals_missing",
        "payload_snapshot_size_mismatch",
        "payload_snapshot_write_failed",
        "producer_process_protection_unavailable",
        "ptrace_protocol_invalid",
        "ptrace_unavailable",
        "register_set_size_mismatch",
        "register_snapshot_unavailable",
        "seccomp_filter_unavailable",
        "signal_disposition_unavailable",
        "snapshot_document_size_limit_exceeded",
        "source_hash_mismatch",
        "source_read_failed",
        "source_size_limit_exceeded",
        "source_size_mismatch",
        "target_exec_failed",
        "target_process_group_cleanup_failed",
        "target_reap_failed",
        "target_reexec_unsupported",
        "target_task_limit_exceeded",
        "unobserved_core_signal_termination",
        "unsupported_architecture",
        "wait_status_invalid",
    }
)
PWN_RUNTIME_SNAPSHOT_V1_FAILURE_REASONS = frozenset(
    PWN_RUNTIME_SNAPSHOT_V1_INCONCLUSIVE_REASONS
    | PWN_RUNTIME_SNAPSHOT_V1_PRODUCER_ERROR_REASONS
)
PWN_RUNTIME_SNAPSHOT_V1_FAILURE_CODES = frozenset(
    {
        "artifact_too_large",
        "contract_mismatch",
        "duplicate_json_key",
        "invalid_json",
        "invalid_schema",
        "noncanonical_json",
        "result_binding_mismatch",
    }
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REGISTER_VALUE = re.compile(r"^[0-9a-f]{16}$")
_TOP_LEVEL_KEYS = frozenset(
    {
        "binding",
        "claims",
        "contract",
        "reason_code",
        "schema_version",
        "snapshot",
        "status",
    }
)
_CONTRACT_KEYS = frozenset({"fingerprint", "id", "version"})
_BINDING_KEYS = frozenset(
    {
        "expected_signal_number",
        "parent_crash_evaluation_sha256",
        "parent_crash_recipe_sha256",
        "payload_sha256",
        "payload_size_bytes",
        "snapshot_recipe_sha256",
        "source_manifest_sha256",
        "source_sha256",
        "source_size_bytes",
    }
)
_CLAIM_KEYS = frozenset(
    {
        "address_resolution_proven",
        "crash_proven",
        "exploit_proven",
        "leak_proven",
        "parent_crash_revalidated",
        "primitive_proven",
        "proof_satisfied",
        "stage_advance_authorized",
    }
)
_SNAPSHOT_KEYS = frozenset(
    {
        "architecture",
        "maps",
        "register_set_size_bytes",
        "register_source",
        "registers",
        "signal_number",
    }
)
_MAPS_KEYS = frozenset(
    {
        "content_base64",
        "encoding",
        "line_count",
        "sha256",
        "size_bytes",
    }
)
_REGISTER_KEYS = frozenset(PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES)


def pwn_runtime_snapshot_v1_canonical_json_bytes(
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


def pwn_runtime_snapshot_v1_contract_descriptor() -> dict[str, object]:
    """Build a fresh descriptor covering every semantic v1 rule."""

    return {
        "architecture": PWN_RUNTIME_SNAPSHOT_V1_ARCHITECTURE,
        "canonical_json": "ascii-strict-sorted-compact-newline-v1",
        "claims": {
            key: False for key in sorted(_CLAIM_KEYS)
        },
        "contract_id": PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_ID,
        "contract_version": PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_VERSION,
        "diagnostic_authority": "advisory-only",
        "document_shape": (
            "contract(fingerprint,id,version);schema_version;status;"
            "reason_code;binding(source,payload,parent-crash,"
            "expected-signal,snapshot-recipe);claims(all-false);"
            "snapshot-or-null"
        ),
        "document_transport": (
            PWN_RUNTIME_SNAPSHOT_V1_DOCUMENT_TRANSPORT
        ),
        "document_max_bytes": (
            PWN_RUNTIME_SNAPSHOT_V1_MAX_DOCUMENT_BYTES
        ),
        "execution_profile": {
            "core_dumps": (
                "rlimit-zero-verified;core-signals-never-delivered;"
                "single-thread-root-default-expected-core-stop-only"
            ),
            "environment": dict(
                PWN_RUNTIME_SNAPSHOT_V1_FIXED_ENVIRONMENT
            ),
            "network": "outer-challenge-sandbox-none",
            "process_containment": (
                "separate-one-shot-clean-sandbox-required;"
                "fork-vfork-clone-observation-fails-closed;"
                "initial-exec-only;later-exec-fails-closed;"
                "session-process-group-and-tracee-reap"
            ),
            "producer_process": "pr-set-dumpable-zero-verified",
            "seccomp_clone_filter": {
                "architecture_mismatch": "errno:ENOSYS",
                "clone3": "errno:ENOSYS",
                "clone_untraced": "errno:EPERM",
                "cross_tgid_clone_sighand": "errno:EPERM",
                "high_syscall_bit": "errno:ENOSYS",
                "pthread_clone": "allow-but-additional-tracee-error",
            },
            "source_execution": "descriptor-bound-procfd",
            "target_arguments": "argv0-only-no-user-arguments",
            "target_output": (
                "stdout-and-stderr-to-producer-stderr;"
                f"bounded-"
                f"{PWN_RUNTIME_SNAPSHOT_V1_MAX_TARGET_OUTPUT_BYTES}"
                "-bytes"
            ),
            "target_shell": False,
            "target_timeout_seconds": (
                PWN_RUNTIME_SNAPSHOT_V1_TARGET_TIMEOUT_SECONDS
            ),
            "trace": (
                "fixed-ptrace-traceme;getregset-nt-prstatus;"
                "all-additional-tracees-rejected;"
                "initial-and-later-exec-events-distinguished;"
                "exitkill-enabled"
            ),
            "traced_task_limit": (
                PWN_RUNTIME_SNAPSHOT_V1_MAX_TRACED_TASKS
            ),
        },
        "failure_codes": sorted(
            PWN_RUNTIME_SNAPSHOT_V1_FAILURE_CODES
        ),
        "json_max_depth": PWN_RUNTIME_SNAPSHOT_V1_MAX_JSON_DEPTH,
        "maps": {
            "content_base64": "strict-canonical-standard-base64",
            "line_count": "exact-lf-byte-count-positive",
            "maximum_decoded_bytes": (
                PWN_RUNTIME_SNAPSHOT_V1_MAX_MAPS_BYTES
            ),
            "maximum_encoded_bytes": (
                PWN_RUNTIME_SNAPSHOT_V1_MAX_MAPS_BASE64_BYTES
            ),
            "minimum_decoded_bytes": 1,
            "sha256": "lowercase-sha256-of-decoded-bytes",
            "termination": "one-final-lf-byte-required",
            "source": "/proc/<root-tgid>/maps-at-supported-stop",
        },
        "non_authorities": [
            "does-not-prove-address-resolution",
            "does-not-prove-crash",
            "does-not-prove-exploit",
            "does-not-prove-leak",
            "does-not-prove-observation-origin",
            "does-not-prove-parent-evaluation-valid",
            "does-not-prove-primitive",
            "does-not-revalidate-parent-crash",
            "does-not-satisfy-proof",
            "does-not-authorize-stage-advance",
        ],
        "payload_max_bytes": (
            PWN_RUNTIME_SNAPSHOT_V1_MAX_PAYLOAD_BYTES
        ),
        "protocol": PWN_RUNTIME_SNAPSHOT_V1_PROTOCOL,
        "failure_reasons": sorted(
            PWN_RUNTIME_SNAPSHOT_V1_FAILURE_REASONS
        ),
        "inconclusive_reasons": sorted(
            PWN_RUNTIME_SNAPSHOT_V1_INCONCLUSIVE_REASONS
        ),
        "producer_error_reasons": sorted(
            PWN_RUNTIME_SNAPSHOT_V1_PRODUCER_ERROR_REASONS
        ),
        "registers": {
            "count": len(PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES),
            "names_in_getregset_order": list(
                PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES
            ),
            "note_type": 1,
            "representation": "exact-16-lowercase-hex-digits",
            "set_size_bytes": (
                PWN_RUNTIME_SNAPSHOT_V1_REGISTER_SET_BYTES
            ),
            "source": PWN_RUNTIME_SNAPSHOT_V1_REGISTER_SOURCE,
        },
        "schemas": {
            "binding_keys": sorted(_BINDING_KEYS),
            "claims_keys": sorted(_CLAIM_KEYS),
            "container_types": {
                "binding": "exact-dict",
                "claims": "exact-dict",
                "contract": "exact-dict",
                "maps": "exact-dict",
                "registers": "exact-dict",
                "result": "exact-dict",
                "snapshot": "exact-dict",
            },
            "contract_keys": sorted(_CONTRACT_KEYS),
            "maps_keys": sorted(_MAPS_KEYS),
            "register_keys": sorted(_REGISTER_KEYS),
            "result_keys": sorted(_TOP_LEVEL_KEYS),
            "snapshot_keys": sorted(_SNAPSHOT_KEYS),
        },
        "schema_version": PWN_RUNTIME_SNAPSHOT_V1_SCHEMA_VERSION,
        "signal_numbers": sorted(
            PWN_RUNTIME_SNAPSHOT_V1_ALLOWED_SIGNALS
        ),
        "source_max_bytes": (
            PWN_RUNTIME_SNAPSHOT_V1_MAX_SOURCE_BYTES
        ),
        "outcomes": {
            "CAPTURED": {
                "reason_code": (
                    PWN_RUNTIME_SNAPSHOT_V1_SUCCESS_REASON
                ),
                "snapshot": "exact-snapshot-object",
            },
            "ERROR": {
                "reason_codes": sorted(
                    PWN_RUNTIME_SNAPSHOT_V1_PRODUCER_ERROR_REASONS
                ),
                "snapshot": None,
            },
            "INCONCLUSIVE": {
                "reason_codes": sorted(
                    PWN_RUNTIME_SNAPSHOT_V1_INCONCLUSIVE_REASONS
                ),
                "snapshot": None,
            },
        },
        "trusted_binding_inputs": [
            "expected_source_manifest_sha256",
            "expected_source_sha256",
            "expected_source_size_bytes",
            "expected_payload_sha256",
            "expected_payload_size_bytes",
            "expected_parent_crash_recipe_sha256",
            "expected_parent_crash_evaluation_sha256",
            "expected_signal_number",
            "expected_snapshot_recipe_sha256",
        ],
        "validation": {
            "mapping_return": "new-immutable-result",
            "producer_observations": [
                "registers",
                "maps_bytes",
            ],
            "result": (
                "bounded-duplicate-free-depth-bounded-canonical-only"
            ),
            "trusted_reconstruction": (
                "all-binding-fields-and-signal-rebuilt-from-caller-input"
            ),
        },
    }


PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_FINGERPRINT = hashlib.sha256(
    pwn_runtime_snapshot_v1_canonical_json_bytes(
        pwn_runtime_snapshot_v1_contract_descriptor()
    )
).hexdigest()


class PwnRuntimeSnapshotV1ContractError(ValueError):
    """Stable parser rejection carrying no producer-controlled text."""

    def __init__(self, code: str) -> None:
        if (
            type(code) is not str
            or code not in PWN_RUNTIME_SNAPSHOT_V1_FAILURE_CODES
        ):
            raise ValueError("unknown Pwn runtime snapshot v1 failure code")
        super().__init__(code)
        self.code = code


class PwnRuntimeSnapshotV1Status(str, Enum):
    CAPTURED = "CAPTURED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"


@dataclass(frozen=True, slots=True)
class PwnRuntimeSnapshotV1Registers:
    """Immutable exact x86_64 NT_PRSTATUS register representation."""

    values: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if (
            type(self.values) is not tuple
            or len(self.values)
            != len(PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES)
        ):
            raise ValueError("invalid Pwn runtime snapshot v1 registers")
        names: list[str] = []
        for item in self.values:
            if (
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or type(item[1]) is not str
                or _REGISTER_VALUE.fullmatch(item[1]) is None
            ):
                raise ValueError(
                    "invalid Pwn runtime snapshot v1 register"
                )
            names.append(item[0])
        if tuple(names) != PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES:
            raise ValueError(
                "invalid Pwn runtime snapshot v1 register order"
            )

    def to_dict(self) -> dict[str, str]:
        return dict(self.values)


@dataclass(frozen=True, slots=True)
class PwnRuntimeSnapshotV1Maps:
    """Immutable decoded bytes from one bounded proc maps snapshot."""

    data: bytes

    def __post_init__(self) -> None:
        if (
            type(self.data) is not bytes
            or not 1
            <= len(self.data)
            <= PWN_RUNTIME_SNAPSHOT_V1_MAX_MAPS_BYTES
            or not self.data.endswith(b"\n")
            or self.data.count(b"\n") < 1
        ):
            raise ValueError("invalid Pwn runtime snapshot v1 maps")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @property
    def line_count(self) -> int:
        return self.data.count(b"\n")

    def to_dict(self) -> dict[str, object]:
        return {
            "content_base64": base64.b64encode(
                self.data
            ).decode("ascii"),
            "encoding": "base64",
            "line_count": self.line_count,
            "sha256": self.sha256,
            "size_bytes": len(self.data),
        }


@dataclass(frozen=True, slots=True)
class PwnRuntimeSnapshotV1Result:
    """One immutable, source-bound, non-authoritative snapshot."""

    source_manifest_sha256: str
    source_sha256: str
    source_size_bytes: int
    payload_sha256: str
    payload_size_bytes: int
    parent_crash_recipe_sha256: str
    parent_crash_evaluation_sha256: str
    expected_signal_number: int
    snapshot_recipe_sha256: str
    status: PwnRuntimeSnapshotV1Status
    reason_code: str
    registers: PwnRuntimeSnapshotV1Registers | None
    maps: PwnRuntimeSnapshotV1Maps | None

    def __post_init__(self) -> None:
        _require_sha256(
            self.source_manifest_sha256,
            "source_manifest_sha256",
        )
        _require_sha256(self.source_sha256, "source_sha256")
        _require_size(
            self.source_size_bytes,
            "source_size_bytes",
            PWN_RUNTIME_SNAPSHOT_V1_MAX_SOURCE_BYTES,
        )
        _require_sha256(self.payload_sha256, "payload_sha256")
        _require_size(
            self.payload_size_bytes,
            "payload_size_bytes",
            PWN_RUNTIME_SNAPSHOT_V1_MAX_PAYLOAD_BYTES,
        )
        _require_sha256(
            self.parent_crash_recipe_sha256,
            "parent_crash_recipe_sha256",
        )
        _require_sha256(
            self.parent_crash_evaluation_sha256,
            "parent_crash_evaluation_sha256",
        )
        _require_signal(
            self.expected_signal_number,
            "expected_signal_number",
        )
        _require_sha256(
            self.snapshot_recipe_sha256,
            "snapshot_recipe_sha256",
        )
        if type(self.status) is not PwnRuntimeSnapshotV1Status:
            raise ValueError("invalid Pwn runtime snapshot v1 status")
        if type(self.reason_code) is not str:
            raise ValueError("invalid Pwn runtime snapshot v1 reason")
        if self.status is PwnRuntimeSnapshotV1Status.CAPTURED:
            valid_outcome = (
                self.reason_code
                == PWN_RUNTIME_SNAPSHOT_V1_SUCCESS_REASON
                and type(self.registers)
                is PwnRuntimeSnapshotV1Registers
                and type(self.maps) is PwnRuntimeSnapshotV1Maps
            )
        elif self.status is PwnRuntimeSnapshotV1Status.INCONCLUSIVE:
            valid_outcome = (
                self.reason_code
                in PWN_RUNTIME_SNAPSHOT_V1_INCONCLUSIVE_REASONS
                and self.registers is None
                and self.maps is None
            )
        else:
            valid_outcome = (
                self.reason_code
                in PWN_RUNTIME_SNAPSHOT_V1_PRODUCER_ERROR_REASONS
                and self.registers is None
                and self.maps is None
            )
        if not valid_outcome:
            raise ValueError(
                "invalid Pwn runtime snapshot v1 outcome"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "binding": {
                "expected_signal_number": self.expected_signal_number,
                "parent_crash_evaluation_sha256": (
                    self.parent_crash_evaluation_sha256
                ),
                "parent_crash_recipe_sha256": (
                    self.parent_crash_recipe_sha256
                ),
                "payload_sha256": self.payload_sha256,
                "payload_size_bytes": self.payload_size_bytes,
                "snapshot_recipe_sha256": (
                    self.snapshot_recipe_sha256
                ),
                "source_manifest_sha256": (
                    self.source_manifest_sha256
                ),
                "source_sha256": self.source_sha256,
                "source_size_bytes": self.source_size_bytes,
            },
            "claims": {key: False for key in sorted(_CLAIM_KEYS)},
            "contract": {
                "fingerprint": (
                    PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_FINGERPRINT
                ),
                "id": PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_ID,
                "version": (
                    PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_VERSION
                ),
            },
            "reason_code": self.reason_code,
            "schema_version": PWN_RUNTIME_SNAPSHOT_V1_SCHEMA_VERSION,
            "snapshot": (
                {
                    "architecture": (
                        PWN_RUNTIME_SNAPSHOT_V1_ARCHITECTURE
                    ),
                    "maps": self.maps.to_dict(),
                    "register_set_size_bytes": (
                        PWN_RUNTIME_SNAPSHOT_V1_REGISTER_SET_BYTES
                    ),
                    "register_source": (
                        PWN_RUNTIME_SNAPSHOT_V1_REGISTER_SOURCE
                    ),
                    "registers": self.registers.to_dict(),
                    "signal_number": self.expected_signal_number,
                }
                if self.status is PwnRuntimeSnapshotV1Status.CAPTURED
                and self.registers is not None
                and self.maps is not None
                else None
            ),
            "status": self.status.value,
        }

    def canonical_bytes(self) -> bytes:
        payload = pwn_runtime_snapshot_v1_canonical_json_bytes(
            self.to_dict()
        )
        if len(payload) > PWN_RUNTIME_SNAPSHOT_V1_MAX_DOCUMENT_BYTES:
            raise ValueError(
                "Pwn runtime snapshot v1 result exceeds byte limit"
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


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _require_size(
    value: object,
    label: str,
    maximum: int,
) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(
            f"{label} must be an exact bounded positive integer"
        )
    return value


def _require_signal(value: object, label: str) -> int:
    if (
        type(value) is not int
        or value not in PWN_RUNTIME_SNAPSHOT_V1_ALLOWED_SIGNALS
    ):
        raise ValueError(f"{label} must be an allowed exact signal")
    return value


def _registers_from_mapping(
    value: object,
) -> PwnRuntimeSnapshotV1Registers:
    mapping = _exact_mapping(value, _REGISTER_KEYS)
    values: list[tuple[str, str]] = []
    for name in PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES:
        register_value = mapping[name]
        if (
            type(register_value) is not str
            or _REGISTER_VALUE.fullmatch(register_value) is None
        ):
            raise _SchemaError
        values.append((name, register_value))
    return PwnRuntimeSnapshotV1Registers(tuple(values))


def _maps_from_mapping(value: object) -> PwnRuntimeSnapshotV1Maps:
    mapping = _exact_mapping(value, _MAPS_KEYS)
    if (
        type(mapping["encoding"]) is not str
        or mapping["encoding"] != "base64"
        or type(mapping["content_base64"]) is not str
        or len(mapping["content_base64"])
        > PWN_RUNTIME_SNAPSHOT_V1_MAX_MAPS_BASE64_BYTES
    ):
        raise _SchemaError
    try:
        encoded = mapping["content_base64"].encode("ascii")
        data = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as error:
        raise _SchemaError from error
    if base64.b64encode(data) != encoded:
        raise _SchemaError
    maps = PwnRuntimeSnapshotV1Maps(data)
    if (
        type(mapping["size_bytes"]) is not int
        or mapping["size_bytes"] != len(data)
        or type(mapping["line_count"]) is not int
        or mapping["line_count"] != maps.line_count
        or type(mapping["sha256"]) is not str
        or mapping["sha256"] != maps.sha256
    ):
        raise _SchemaError
    return maps


def build_pwn_runtime_snapshot_v1_result(
    *,
    registers: PwnRuntimeSnapshotV1Registers,
    maps: PwnRuntimeSnapshotV1Maps,
    expected_source_manifest_sha256: str,
    expected_source_sha256: str,
    expected_source_size_bytes: int,
    expected_payload_sha256: str,
    expected_payload_size_bytes: int,
    expected_parent_crash_recipe_sha256: str,
    expected_parent_crash_evaluation_sha256: str,
    expected_signal_number: int,
    expected_snapshot_recipe_sha256: str,
) -> PwnRuntimeSnapshotV1Result:
    """Build a fresh immutable diagnostic from trusted bindings."""

    if type(registers) is not PwnRuntimeSnapshotV1Registers:
        raise TypeError("registers must be exact v1 registers")
    if type(maps) is not PwnRuntimeSnapshotV1Maps:
        raise TypeError("maps must be exact v1 maps")
    result = PwnRuntimeSnapshotV1Result(
        source_manifest_sha256=_require_sha256(
            expected_source_manifest_sha256,
            "expected_source_manifest_sha256",
        ),
        source_sha256=_require_sha256(
            expected_source_sha256,
            "expected_source_sha256",
        ),
        source_size_bytes=_require_size(
            expected_source_size_bytes,
            "expected_source_size_bytes",
            PWN_RUNTIME_SNAPSHOT_V1_MAX_SOURCE_BYTES,
        ),
        payload_sha256=_require_sha256(
            expected_payload_sha256,
            "expected_payload_sha256",
        ),
        payload_size_bytes=_require_size(
            expected_payload_size_bytes,
            "expected_payload_size_bytes",
            PWN_RUNTIME_SNAPSHOT_V1_MAX_PAYLOAD_BYTES,
        ),
        parent_crash_recipe_sha256=_require_sha256(
            expected_parent_crash_recipe_sha256,
            "expected_parent_crash_recipe_sha256",
        ),
        parent_crash_evaluation_sha256=_require_sha256(
            expected_parent_crash_evaluation_sha256,
            "expected_parent_crash_evaluation_sha256",
        ),
        expected_signal_number=_require_signal(
            expected_signal_number,
            "expected_signal_number",
        ),
        snapshot_recipe_sha256=_require_sha256(
            expected_snapshot_recipe_sha256,
            "expected_snapshot_recipe_sha256",
        ),
        status=PwnRuntimeSnapshotV1Status.CAPTURED,
        reason_code=PWN_RUNTIME_SNAPSHOT_V1_SUCCESS_REASON,
        registers=registers,
        maps=maps,
    )
    result.canonical_bytes()
    return result


def build_pwn_runtime_snapshot_v1_failure(
    *,
    reason_code: str,
    expected_source_manifest_sha256: str,
    expected_source_sha256: str,
    expected_source_size_bytes: int,
    expected_payload_sha256: str,
    expected_payload_size_bytes: int,
    expected_parent_crash_recipe_sha256: str,
    expected_parent_crash_evaluation_sha256: str,
    expected_signal_number: int,
    expected_snapshot_recipe_sha256: str,
) -> PwnRuntimeSnapshotV1Result:
    """Build a finite, source-bound non-captured outcome."""

    if (
        type(reason_code) is not str
        or reason_code
        not in PWN_RUNTIME_SNAPSHOT_V1_FAILURE_REASONS
    ):
        raise ValueError("reason_code must be a finite failure reason")
    status = (
        PwnRuntimeSnapshotV1Status.INCONCLUSIVE
        if reason_code in PWN_RUNTIME_SNAPSHOT_V1_INCONCLUSIVE_REASONS
        else PwnRuntimeSnapshotV1Status.ERROR
    )
    result = PwnRuntimeSnapshotV1Result(
        source_manifest_sha256=_require_sha256(
            expected_source_manifest_sha256,
            "expected_source_manifest_sha256",
        ),
        source_sha256=_require_sha256(
            expected_source_sha256,
            "expected_source_sha256",
        ),
        source_size_bytes=_require_size(
            expected_source_size_bytes,
            "expected_source_size_bytes",
            PWN_RUNTIME_SNAPSHOT_V1_MAX_SOURCE_BYTES,
        ),
        payload_sha256=_require_sha256(
            expected_payload_sha256,
            "expected_payload_sha256",
        ),
        payload_size_bytes=_require_size(
            expected_payload_size_bytes,
            "expected_payload_size_bytes",
            PWN_RUNTIME_SNAPSHOT_V1_MAX_PAYLOAD_BYTES,
        ),
        parent_crash_recipe_sha256=_require_sha256(
            expected_parent_crash_recipe_sha256,
            "expected_parent_crash_recipe_sha256",
        ),
        parent_crash_evaluation_sha256=_require_sha256(
            expected_parent_crash_evaluation_sha256,
            "expected_parent_crash_evaluation_sha256",
        ),
        expected_signal_number=_require_signal(
            expected_signal_number,
            "expected_signal_number",
        ),
        snapshot_recipe_sha256=_require_sha256(
            expected_snapshot_recipe_sha256,
            "expected_snapshot_recipe_sha256",
        ),
        status=status,
        reason_code=reason_code,
        registers=None,
        maps=None,
    )
    result.canonical_bytes()
    return result


def _validate_and_extract_observations(
    value: object,
) -> tuple[
    PwnRuntimeSnapshotV1Status,
    str,
    PwnRuntimeSnapshotV1Registers | None,
    PwnRuntimeSnapshotV1Maps | None,
]:
    root = _exact_mapping(value, _TOP_LEVEL_KEYS)
    if (
        type(root["schema_version"]) is not int
        or root["schema_version"]
        != PWN_RUNTIME_SNAPSHOT_V1_SCHEMA_VERSION
    ):
        raise _SchemaError
    if (
        type(root["status"]) is not str
        or root["status"]
        not in {item.value for item in PwnRuntimeSnapshotV1Status}
        or type(root["reason_code"]) is not str
    ):
        raise _SchemaError
    status = PwnRuntimeSnapshotV1Status(root["status"])
    reason_code = root["reason_code"]

    contract = _exact_mapping(root["contract"], _CONTRACT_KEYS)
    if (
        type(contract["id"]) is not str
        or contract["id"] != PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_ID
        or type(contract["version"]) is not int
        or contract["version"]
        != PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_VERSION
        or type(contract["fingerprint"]) is not str
    ):
        raise _SchemaError
    if (
        contract["fingerprint"]
        != PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_FINGERPRINT
    ):
        raise PwnRuntimeSnapshotV1ContractError(
            "contract_mismatch"
        )

    claims = _exact_mapping(root["claims"], _CLAIM_KEYS)
    if any(claims[key] is not False for key in _CLAIM_KEYS):
        raise _SchemaError

    binding = _exact_mapping(root["binding"], _BINDING_KEYS)
    _require_sha256(
        binding["source_manifest_sha256"],
        "source_manifest_sha256",
    )
    _require_sha256(binding["source_sha256"], "source_sha256")
    _require_size(
        binding["source_size_bytes"],
        "source_size_bytes",
        PWN_RUNTIME_SNAPSHOT_V1_MAX_SOURCE_BYTES,
    )
    _require_sha256(binding["payload_sha256"], "payload_sha256")
    _require_size(
        binding["payload_size_bytes"],
        "payload_size_bytes",
        PWN_RUNTIME_SNAPSHOT_V1_MAX_PAYLOAD_BYTES,
    )
    _require_sha256(
        binding["parent_crash_recipe_sha256"],
        "parent_crash_recipe_sha256",
    )
    _require_sha256(
        binding["parent_crash_evaluation_sha256"],
        "parent_crash_evaluation_sha256",
    )
    binding_signal = _require_signal(
        binding["expected_signal_number"],
        "expected_signal_number",
    )
    _require_sha256(
        binding["snapshot_recipe_sha256"],
        "snapshot_recipe_sha256",
    )

    if status is not PwnRuntimeSnapshotV1Status.CAPTURED:
        expected_reasons = (
            PWN_RUNTIME_SNAPSHOT_V1_INCONCLUSIVE_REASONS
            if status is PwnRuntimeSnapshotV1Status.INCONCLUSIVE
            else PWN_RUNTIME_SNAPSHOT_V1_PRODUCER_ERROR_REASONS
        )
        if (
            reason_code not in expected_reasons
            or root["snapshot"] is not None
        ):
            raise _SchemaError
        canonical = pwn_runtime_snapshot_v1_canonical_json_bytes(value)
        if (
            len(canonical)
            > PWN_RUNTIME_SNAPSHOT_V1_MAX_DOCUMENT_BYTES
        ):
            raise _SchemaError
        return status, reason_code, None, None

    if reason_code != PWN_RUNTIME_SNAPSHOT_V1_SUCCESS_REASON:
        raise _SchemaError
    snapshot = _exact_mapping(root["snapshot"], _SNAPSHOT_KEYS)
    if (
        type(snapshot["architecture"]) is not str
        or snapshot["architecture"]
        != PWN_RUNTIME_SNAPSHOT_V1_ARCHITECTURE
        or type(snapshot["register_source"]) is not str
        or snapshot["register_source"]
        != PWN_RUNTIME_SNAPSHOT_V1_REGISTER_SOURCE
        or type(snapshot["register_set_size_bytes"]) is not int
        or snapshot["register_set_size_bytes"]
        != PWN_RUNTIME_SNAPSHOT_V1_REGISTER_SET_BYTES
        or type(snapshot["signal_number"]) is not int
        or snapshot["signal_number"] != binding_signal
    ):
        raise _SchemaError
    registers = _registers_from_mapping(snapshot["registers"])
    maps = _maps_from_mapping(snapshot["maps"])

    canonical = pwn_runtime_snapshot_v1_canonical_json_bytes(value)
    if len(canonical) > PWN_RUNTIME_SNAPSHOT_V1_MAX_DOCUMENT_BYTES:
        raise _SchemaError
    return status, reason_code, registers, maps


def validate_pwn_runtime_snapshot_v1_result_mapping(
    value: object,
    *,
    expected_source_manifest_sha256: str,
    expected_source_sha256: str,
    expected_source_size_bytes: int,
    expected_payload_sha256: str,
    expected_payload_size_bytes: int,
    expected_parent_crash_recipe_sha256: str,
    expected_parent_crash_evaluation_sha256: str,
    expected_signal_number: int,
    expected_snapshot_recipe_sha256: str,
) -> PwnRuntimeSnapshotV1Result:
    """Validate and reconstruct a result from trusted bindings."""

    try:
        status, reason_code, registers, maps = (
            _validate_and_extract_observations(value)
        )
    except PwnRuntimeSnapshotV1ContractError:
        raise
    except (
        KeyError,
        TypeError,
        UnicodeEncodeError,
        ValueError,
        _SchemaError,
    ) as error:
        raise PwnRuntimeSnapshotV1ContractError(
            "invalid_schema"
        ) from error

    common = {
        "expected_source_manifest_sha256": (
            expected_source_manifest_sha256
        ),
        "expected_source_sha256": expected_source_sha256,
        "expected_source_size_bytes": expected_source_size_bytes,
        "expected_payload_sha256": expected_payload_sha256,
        "expected_payload_size_bytes": expected_payload_size_bytes,
        "expected_parent_crash_recipe_sha256": (
            expected_parent_crash_recipe_sha256
        ),
        "expected_parent_crash_evaluation_sha256": (
            expected_parent_crash_evaluation_sha256
        ),
        "expected_signal_number": expected_signal_number,
        "expected_snapshot_recipe_sha256": (
            expected_snapshot_recipe_sha256
        ),
    }
    if status is PwnRuntimeSnapshotV1Status.CAPTURED:
        assert registers is not None
        assert maps is not None
        expected = build_pwn_runtime_snapshot_v1_result(
            registers=registers,
            maps=maps,
            **common,
        )
    else:
        expected = build_pwn_runtime_snapshot_v1_failure(
            reason_code=reason_code,
            **common,
        )
    if value != expected.to_dict():
        raise PwnRuntimeSnapshotV1ContractError(
            "result_binding_mismatch"
        )
    return expected


def parse_pwn_runtime_snapshot_v1_result(
    payload: bytes,
    *,
    expected_source_manifest_sha256: str,
    expected_source_sha256: str,
    expected_source_size_bytes: int,
    expected_payload_sha256: str,
    expected_payload_size_bytes: int,
    expected_parent_crash_recipe_sha256: str,
    expected_parent_crash_evaluation_sha256: str,
    expected_signal_number: int,
    expected_snapshot_recipe_sha256: str,
) -> PwnRuntimeSnapshotV1Result:
    """Parse one canonical snapshot and bind it to trusted inputs."""

    if type(payload) is not bytes:
        raise TypeError("payload must be exact bytes")
    if len(payload) > PWN_RUNTIME_SNAPSHOT_V1_MAX_DOCUMENT_BYTES:
        raise PwnRuntimeSnapshotV1ContractError(
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
        raise PwnRuntimeSnapshotV1ContractError(
            "duplicate_json_key"
        ) from error
    except (
        json.JSONDecodeError,
        RecursionError,
        UnicodeDecodeError,
        ValueError,
    ) as error:
        raise PwnRuntimeSnapshotV1ContractError(
            "invalid_json"
        ) from error
    if _json_depth_exceeds(
        value,
        PWN_RUNTIME_SNAPSHOT_V1_MAX_JSON_DEPTH,
    ):
        raise PwnRuntimeSnapshotV1ContractError(
            "invalid_json"
        )
    try:
        canonical = pwn_runtime_snapshot_v1_canonical_json_bytes(
            value
        )
    except (TypeError, UnicodeEncodeError, ValueError) as error:
        raise PwnRuntimeSnapshotV1ContractError(
            "invalid_json"
        ) from error
    if canonical != payload:
        raise PwnRuntimeSnapshotV1ContractError(
            "noncanonical_json"
        )
    return validate_pwn_runtime_snapshot_v1_result_mapping(
        value,
        expected_source_manifest_sha256=(
            expected_source_manifest_sha256
        ),
        expected_source_sha256=expected_source_sha256,
        expected_source_size_bytes=expected_source_size_bytes,
        expected_payload_sha256=expected_payload_sha256,
        expected_payload_size_bytes=expected_payload_size_bytes,
        expected_parent_crash_recipe_sha256=(
            expected_parent_crash_recipe_sha256
        ),
        expected_parent_crash_evaluation_sha256=(
            expected_parent_crash_evaluation_sha256
        ),
        expected_signal_number=expected_signal_number,
        expected_snapshot_recipe_sha256=(
            expected_snapshot_recipe_sha256
        ),
    )


__all__ = [
    "PWN_RUNTIME_SNAPSHOT_V1_ALLOWED_SIGNALS",
    "PWN_RUNTIME_SNAPSHOT_V1_ARCHITECTURE",
    "PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_FINGERPRINT",
    "PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_ID",
    "PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_VERSION",
    "PWN_RUNTIME_SNAPSHOT_V1_DOCUMENT_TRANSPORT",
    "PWN_RUNTIME_SNAPSHOT_V1_FAILURE_CODES",
    "PWN_RUNTIME_SNAPSHOT_V1_FAILURE_REASONS",
    "PWN_RUNTIME_SNAPSHOT_V1_FIXED_ENVIRONMENT",
    "PWN_RUNTIME_SNAPSHOT_V1_INCONCLUSIVE_REASONS",
    "PWN_RUNTIME_SNAPSHOT_V1_MAX_DOCUMENT_BYTES",
    "PWN_RUNTIME_SNAPSHOT_V1_MAX_MAPS_BASE64_BYTES",
    "PWN_RUNTIME_SNAPSHOT_V1_MAX_MAPS_BYTES",
    "PWN_RUNTIME_SNAPSHOT_V1_MAX_PAYLOAD_BYTES",
    "PWN_RUNTIME_SNAPSHOT_V1_MAX_SOURCE_BYTES",
    "PWN_RUNTIME_SNAPSHOT_V1_MAX_TARGET_OUTPUT_BYTES",
    "PWN_RUNTIME_SNAPSHOT_V1_MAX_TRACED_TASKS",
    "PWN_RUNTIME_SNAPSHOT_V1_PRODUCER_ERROR_REASONS",
    "PWN_RUNTIME_SNAPSHOT_V1_PROTOCOL",
    "PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES",
    "PWN_RUNTIME_SNAPSHOT_V1_REGISTER_SET_BYTES",
    "PWN_RUNTIME_SNAPSHOT_V1_REGISTER_SOURCE",
    "PWN_RUNTIME_SNAPSHOT_V1_SCHEMA_VERSION",
    "PWN_RUNTIME_SNAPSHOT_V1_SUCCESS_REASON",
    "PWN_RUNTIME_SNAPSHOT_V1_TARGET_TIMEOUT_SECONDS",
    "PwnRuntimeSnapshotV1ContractError",
    "PwnRuntimeSnapshotV1Maps",
    "PwnRuntimeSnapshotV1Registers",
    "PwnRuntimeSnapshotV1Result",
    "PwnRuntimeSnapshotV1Status",
    "build_pwn_runtime_snapshot_v1_failure",
    "build_pwn_runtime_snapshot_v1_result",
    "parse_pwn_runtime_snapshot_v1_result",
    "pwn_runtime_snapshot_v1_canonical_json_bytes",
    "pwn_runtime_snapshot_v1_contract_descriptor",
    "validate_pwn_runtime_snapshot_v1_result_mapping",
]
