"""Pure v1 contract for a local stdin-triggered Pwn crash gate.

The execution layer produces six small canonical observation documents:
three executions with one exact non-empty PoC and three executions with an
empty standard-input control.  This module contains no sandbox or state-store
code.  It validates the complete source/input/recipe bindings and classifies
only the single-thread root target's terminal status or its default
core-generating signal delivery stop.

Exit codes, output strings, sanitizer text, and core-file presence are never
treated as crashes.  A v1 crash is a default fault signal observed before
delivery in a single-thread root target (and suppressed to prevent a piped
host core handler), reproduced with the same signal in at least two of three
positive attempts while every control exits normally.  Core-generating
signals are never delivered: caught/ignored, non-root, and root-multithreaded
stops are finite producer errors.

Once persisted, this module is append-only.  Semantic changes belong in a new
versioned module selected by an exact id/version/fingerprint tuple.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from itertools import islice
from typing import Any


PWN_CRASH_V1_SCHEMA_VERSION = 1
PWN_CRASH_V1_CONTRACT_ID = "ctfos.pwn.crash"
PWN_CRASH_V1_CONTRACT_VERSION = 1
PWN_CRASH_V1_PROTOCOL = "pwn_local_stdin_crash_v1"
PWN_CRASH_V1_DOCUMENT_TRANSPORT = "exact-canonical-stdout-once-v1"
PWN_CRASH_V1_MAX_DOCUMENT_BYTES = 16 * 1024
PWN_CRASH_V1_MAX_EVIDENCE_BYTES = 256 * 1024
PWN_CRASH_V1_MAX_JSON_DEPTH = 8
PWN_CRASH_V1_MAX_SOURCE_BYTES = 1024 * 1024 * 1024
PWN_CRASH_V1_MAX_INPUT_BYTES = 1024 * 1024
PWN_CRASH_V1_ATTEMPT_COUNT = 6
PWN_CRASH_V1_POSITIVE_ATTEMPTS = 3
PWN_CRASH_V1_CONTROL_ATTEMPTS = 3
PWN_CRASH_V1_REQUIRED_POSITIVE_SUCCESSES = 2
PWN_CRASH_V1_TARGET_TIMEOUT_SECONDS = 5.0
PWN_CRASH_V1_MAX_TRACED_TASKS = 64
PWN_CRASH_V1_CLONE_SIGHAND = 0x00000800
PWN_CRASH_V1_CLONE_THREAD = 0x00010000
PWN_CRASH_V1_CLONE_UNTRACED = 0x00800000
PWN_CRASH_V1_HIGH_SYSCALL_BIT = 0x40000000
PWN_CRASH_V1_CLONE3_SYSCALL = 435
PWN_CRASH_V1_SECCOMP_ARCHITECTURES = (
    ("aarch64", 0xC00000B7, 220),
    ("x86_64", 0xC000003E, 56),
)
PWN_CRASH_V1_FIXED_ENVIRONMENT = (
    ("HOME", "/nonexistent"),
    ("LANG", "C.UTF-8"),
    ("LC_ALL", "C.UTF-8"),
    ("PATH", "/usr/bin:/bin"),
    ("TERM", "dumb"),
)

# Linux signal numbers are part of this versioned image/contract boundary.
PWN_CRASH_V1_ALLOWED_SIGNALS = frozenset({4, 6, 7, 8, 11})
PWN_CRASH_V1_ALLOWED_SIGNAL_NAMES = {
    4: "SIGILL",
    6: "SIGABRT",
    7: "SIGBUS",
    8: "SIGFPE",
    11: "SIGSEGV",
}

PWN_CRASH_V1_PRODUCER_ERROR_REASONS = frozenset(
    {
        "binary_ancestor_not_directory",
        "binary_ancestor_unavailable",
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
        "input_ancestor_not_directory",
        "input_ancestor_unavailable",
        "input_changed_during_read",
        "input_hash_mismatch",
        "input_leaf_unavailable",
        "input_not_regular",
        "input_read_failed",
        "input_read_incomplete",
        "input_root_not_directory",
        "input_root_unavailable",
        "input_size_limit_exceeded",
        "input_size_mismatch",
        "input_snapshot_changed_during_seal",
        "input_snapshot_create_failed",
        "input_snapshot_not_read_only",
        "input_snapshot_readback_failed",
        "input_snapshot_readback_mismatch",
        "input_snapshot_reopen_failed",
        "input_snapshot_reopen_mismatch",
        "input_snapshot_rewind_failed",
        "input_snapshot_seal_failed",
        "input_snapshot_seals_missing",
        "input_snapshot_size_mismatch",
        "input_snapshot_write_failed",
        "linux_proc_descriptor_exec_unavailable",
        "multithreaded_core_signal_unsupported",
        "non_root_core_signal_unsupported",
        "nofollow_open_unavailable",
        "ptrace_protocol_invalid",
        "ptrace_unavailable",
        "producer_process_protection_unavailable",
        "seccomp_filter_unavailable",
        "signal_disposition_unavailable",
        "source_hash_mismatch",
        "source_read_failed",
        "source_size_limit_exceeded",
        "source_size_mismatch",
        "target_exec_failed",
        "target_process_group_cleanup_failed",
        "target_reap_failed",
        "target_reexec_unsupported",
        "target_task_limit_exceeded",
        "target_timeout",
        "unobserved_core_signal_termination",
        "wait_status_invalid",
    }
)

PWN_CRASH_V1_FAILURE_CODES = frozenset(
    {
        "artifact_too_large",
        "attempt_count_mismatch",
        "attempt_order_mismatch",
        "contract_mismatch",
        "duplicate_json_key",
        "input_binding_mismatch",
        "invalid_json",
        "invalid_schema",
        "noncanonical_json",
        "observation_iteration_failed",
        "observation_type_invalid",
        "observations_not_iterable",
        "producer_error",
        "recipe_binding_mismatch",
        "source_binding_mismatch",
        "source_manifest_mismatch",
    }
)

PWN_CRASH_V1_SEMANTIC_REASONS = frozenset(
    {
        "control_abnormal_termination_observed",
        "no_positive_fault_observed",
        "positive_fault_signature_not_reproduced",
        "positive_fault_threshold_not_met",
        "reproducible_input_triggered_fault_signal",
    }
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_TOP_LEVEL_KEYS = frozenset(
    {
        "binding",
        "contract",
        "reason_code",
        "schema_version",
        "status",
        "target",
    }
)
_CONTRACT_KEYS = frozenset({"fingerprint", "id", "version"})
_BINDING_KEYS = frozenset(
    {
        "input_sha256",
        "input_size_bytes",
        "ordinal",
        "phase",
        "recipe_sha256",
        "source_manifest_sha256",
        "source_sha256",
        "source_size_bytes",
    }
)
_TARGET_KEYS = frozenset(
    {"exit_code", "signal_number", "termination"}
)


def pwn_crash_v1_canonical_json_bytes(value: object) -> bytes:
    """Return the only persisted JSON encoding accepted by v1."""

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


def pwn_crash_v1_contract_descriptor() -> dict[str, object]:
    """Build a fresh descriptor covering every semantic v1 constant."""

    return {
        "allowed_fault_signals": [
            {
                "name": PWN_CRASH_V1_ALLOWED_SIGNAL_NAMES[number],
                "number": number,
            }
            for number in sorted(PWN_CRASH_V1_ALLOWED_SIGNALS)
        ],
        "canonical_json": "ascii-strict-sorted-compact-newline-v1",
        "contract_id": PWN_CRASH_V1_CONTRACT_ID,
        "contract_version": PWN_CRASH_V1_CONTRACT_VERSION,
        "decision_rules": [
            "any-structural-failure=>ERROR",
            (
                "any-control-termination!=exited=>INCONCLUSIVE:"
                "control_abnormal_termination_observed"
            ),
            (
                "positive-allowed-fault-count=0=>INCONCLUSIVE:"
                "no_positive_fault_observed"
            ),
            (
                "positive-allowed-fault-count<2=>INCONCLUSIVE:"
                "positive_fault_threshold_not_met"
            ),
            (
                "no-identical-allowed-fault-count>=2=>INCONCLUSIVE:"
                "positive_fault_signature_not_reproduced"
            ),
            (
                "otherwise=>CONFIRMED:"
                "reproducible_input_triggered_fault_signal"
            ),
        ],
        "document_shape": (
            "contract(fingerprint,id,version);schema_version;status;"
            "reason_code;binding(ordinal,phase,recipe,manifest,source,input);"
            "target(termination,exit_code,signal_number)"
        ),
        "document_transport": PWN_CRASH_V1_DOCUMENT_TRANSPORT,
        "execution_profile": {
            "core_dumps": (
                "rlimit-zero-verified;"
                "core-generating-signals-never-delivered;"
                "single-thread-root-default-core-stop-recorded;"
                "all-other-core-stops-error;"
                "unobserved-core-terminal-error"
            ),
            "environment": dict(PWN_CRASH_V1_FIXED_ENVIRONMENT),
            "network": "outer-challenge-sandbox-none",
            "process_containment": (
                "one-shot-clean-sandbox-required;"
                "fork-vfork-clone-traced;"
                "initial-exec-only;later-exec-fails-closed;"
                "session-process-group-and-tracee-reap"
            ),
            "producer_process": "pr-set-dumpable-zero-verified",
            "seccomp_clone_filter": {
                "architectures": [
                    {
                        "audit_arch": audit_arch,
                        "clone_syscall": clone_syscall,
                        "machine": machine,
                    }
                    for (
                        machine,
                        audit_arch,
                        clone_syscall,
                    ) in PWN_CRASH_V1_SECCOMP_ARCHITECTURES
                ],
                "architecture_mismatch": "errno:ENOSYS",
                "clone3": {
                    "action": "errno:ENOSYS",
                    "syscall": PWN_CRASH_V1_CLONE3_SYSCALL,
                },
                "high_syscall_bit": {
                    "action": "errno:ENOSYS",
                    "mask": PWN_CRASH_V1_HIGH_SYSCALL_BIT,
                },
                "clone_flags": {
                    "clone_sighand": PWN_CRASH_V1_CLONE_SIGHAND,
                    "clone_thread": PWN_CRASH_V1_CLONE_THREAD,
                    "clone_untraced": PWN_CRASH_V1_CLONE_UNTRACED,
                    "cross_tgid_clone_sighand": "errno:EPERM",
                    "pthread_clone": "allow",
                },
                "install": (
                    "pre-exec-no-new-privs;"
                    "filter-mode-runtime-verified;"
                    "source-sha256-attested"
                ),
            },
            "signal_disposition": (
                "stopped-proc-status-SigCgt-SigIgn;"
                "caught-or-ignored-core-signal-error;"
                "core-signal-never-delivered"
            ),
            "source_execution": "descriptor-bound-procfd",
            "stdin": "sealed-read-only-memfd",
            "target_arguments": "argv0-only-no-user-arguments",
            "target_shell": False,
            "target_stdout_stderr": "inherited-through-producer-stderr",
            "target_timeout_seconds": (
                PWN_CRASH_V1_TARGET_TIMEOUT_SECONDS
            ),
            "trace": (
                "fixed-ptrace-traceme;"
                "initial-and-later-exec-events-distinguished;"
                "later-exec-fails-closed;"
                "exitkill-enabled"
            ),
            "traced_task_limit": PWN_CRASH_V1_MAX_TRACED_TASKS,
            "transport_validation": (
                "receipt-success-complete-nontruncated;"
                "exact-whole-canonical-stdout"
            ),
        },
        "input_max_bytes": PWN_CRASH_V1_MAX_INPUT_BYTES,
        "observation_max_bytes": PWN_CRASH_V1_MAX_DOCUMENT_BYTES,
        "plan": [
            {"ordinals": [1, 2, 3], "phase": "positive"},
            {
                "input_sha256": _EMPTY_SHA256,
                "input_size_bytes": 0,
                "ordinals": [4, 5, 6],
                "phase": "control",
            },
        ],
        "positive_success_threshold": (
            PWN_CRASH_V1_REQUIRED_POSITIVE_SUCCESSES
        ),
        "producer_error_reasons": sorted(
            PWN_CRASH_V1_PRODUCER_ERROR_REASONS
        ),
        "protocol": PWN_CRASH_V1_PROTOCOL,
        "schema_version": PWN_CRASH_V1_SCHEMA_VERSION,
        "source_max_bytes": PWN_CRASH_V1_MAX_SOURCE_BYTES,
        "target_status": (
            "single-thread-root-terminal-wait-status-or-"
            "default-core-signal-stop;"
            "numeric-exit-is-never-a-signal"
        ),
    }


PWN_CRASH_V1_CONTRACT_FINGERPRINT = hashlib.sha256(
    pwn_crash_v1_canonical_json_bytes(
        pwn_crash_v1_contract_descriptor()
    )
).hexdigest()


class PwnCrashV1Verdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"


class PwnCrashV1ContractError(ValueError):
    """Stable parser rejection carrying no producer-controlled text."""

    def __init__(self, code: str) -> None:
        if code not in PWN_CRASH_V1_FAILURE_CODES:
            raise ValueError("unknown Pwn crash v1 failure code")
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class PwnCrashV1PlanInput:
    ordinal: int
    phase: str
    input_sha256: str
    input_size_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "input_sha256": self.input_sha256,
            "input_size_bytes": self.input_size_bytes,
            "ordinal": self.ordinal,
            "phase": self.phase,
        }


@dataclass(frozen=True, slots=True)
class PwnCrashV1TargetStatus:
    termination: str
    exit_code: int | None
    signal_number: int | None

    def to_dict(self) -> dict[str, object]:
        return {
            "exit_code": self.exit_code,
            "signal_number": self.signal_number,
            "termination": self.termination,
        }


@dataclass(frozen=True, slots=True)
class PwnCrashV1Observation:
    ordinal: int
    phase: str
    recipe_sha256: str
    source_manifest_sha256: str
    source_sha256: str
    source_size_bytes: int
    input_sha256: str
    input_size_bytes: int
    status: str
    reason_code: str
    target: PwnCrashV1TargetStatus | None

    def to_dict(self) -> dict[str, object]:
        return {
            "binding": {
                "input_sha256": self.input_sha256,
                "input_size_bytes": self.input_size_bytes,
                "ordinal": self.ordinal,
                "phase": self.phase,
                "recipe_sha256": self.recipe_sha256,
                "source_manifest_sha256": (
                    self.source_manifest_sha256
                ),
                "source_sha256": self.source_sha256,
                "source_size_bytes": self.source_size_bytes,
            },
            "contract": {
                "fingerprint": PWN_CRASH_V1_CONTRACT_FINGERPRINT,
                "id": PWN_CRASH_V1_CONTRACT_ID,
                "version": PWN_CRASH_V1_CONTRACT_VERSION,
            },
            "reason_code": self.reason_code,
            "schema_version": PWN_CRASH_V1_SCHEMA_VERSION,
            "status": self.status,
            "target": (
                self.target.to_dict() if self.target is not None else None
            ),
        }


@dataclass(frozen=True, slots=True)
class PwnCrashV1Failure:
    code: str
    attempt_ordinal: int | None = None
    producer_reason: str | None = None

    def __post_init__(self) -> None:
        if self.code not in PWN_CRASH_V1_FAILURE_CODES:
            raise ValueError("unknown Pwn crash v1 failure code")
        if (
            self.producer_reason is not None
            and self.producer_reason
            not in PWN_CRASH_V1_PRODUCER_ERROR_REASONS
        ):
            raise ValueError("unknown Pwn crash v1 producer reason")

    def to_dict(self) -> dict[str, object]:
        return {
            "attempt_ordinal": self.attempt_ordinal,
            "code": self.code,
            "producer_reason": self.producer_reason,
        }


@dataclass(frozen=True, slots=True)
class PwnCrashV1Evaluation:
    source_manifest_sha256: str
    source_sha256: str
    source_size_bytes: int
    poc_sha256: str
    poc_size_bytes: int
    recipe_sha256: str
    plan: tuple[PwnCrashV1PlanInput, ...]
    observations: tuple[PwnCrashV1Observation, ...]
    failures: tuple[PwnCrashV1Failure, ...]
    verdict: PwnCrashV1Verdict
    reason_code: str
    positive_signal_counts: tuple[tuple[int, int], ...]
    control_abnormal_terminations: int

    @property
    def passed(self) -> bool:
        return self.verdict is PwnCrashV1Verdict.CONFIRMED

    @property
    def failure_codes(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(item.code for item in self.failures))

    def to_dict(self) -> dict[str, object]:
        return {
            "binding": {
                "poc_sha256": self.poc_sha256,
                "poc_size_bytes": self.poc_size_bytes,
                "recipe_sha256": self.recipe_sha256,
                "source_manifest_sha256": (
                    self.source_manifest_sha256
                ),
                "source_sha256": self.source_sha256,
                "source_size_bytes": self.source_size_bytes,
            },
            "contract": {
                "fingerprint": PWN_CRASH_V1_CONTRACT_FINGERPRINT,
                "id": PWN_CRASH_V1_CONTRACT_ID,
                "version": PWN_CRASH_V1_CONTRACT_VERSION,
            },
            "failure_codes": list(self.failure_codes),
            "failures": [item.to_dict() for item in self.failures],
            "observations": [
                item.to_dict() for item in self.observations
            ],
            "passed": self.passed,
            "plan": [item.to_dict() for item in self.plan],
            "protocol": PWN_CRASH_V1_PROTOCOL,
            "reason_code": self.reason_code,
            "schema_version": PWN_CRASH_V1_SCHEMA_VERSION,
            "stats": {
                "control_abnormal_terminations": (
                    self.control_abnormal_terminations
                ),
                "control_attempts": PWN_CRASH_V1_CONTROL_ATTEMPTS,
                "positive_attempts": PWN_CRASH_V1_POSITIVE_ATTEMPTS,
                "positive_signal_counts": [
                    {
                        "count": count,
                        "signal_number": signal_number,
                    }
                    for signal_number, count
                    in self.positive_signal_counts
                ],
                "required_positive_successes": (
                    PWN_CRASH_V1_REQUIRED_POSITIVE_SUCCESSES
                ),
            },
            "verdict": self.verdict.value,
        }

    def canonical_bytes(self) -> bytes:
        payload = pwn_crash_v1_canonical_json_bytes(self.to_dict())
        if len(payload) > PWN_CRASH_V1_MAX_EVIDENCE_BYTES:
            raise ValueError("Pwn crash v1 evidence exceeds its byte limit")
        return payload

    @property
    def evidence_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase sha256")
    return value


def _require_size(value: object, label: str, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"{label} is outside its size contract")
    return value


def build_pwn_crash_v1_plan(
    poc_input: bytes,
) -> tuple[PwnCrashV1PlanInput, ...]:
    """Build the only six-attempt input plan accepted by v1."""

    if type(poc_input) is not bytes:
        raise TypeError("poc_input must be exact bytes")
    if not poc_input:
        raise ValueError("poc_input must be non-empty")
    if len(poc_input) > PWN_CRASH_V1_MAX_INPUT_BYTES:
        raise ValueError("poc_input exceeds the v1 size limit")
    poc_sha256 = hashlib.sha256(poc_input).hexdigest()
    return tuple(
        PwnCrashV1PlanInput(
            ordinal=ordinal,
            phase=("positive" if ordinal <= 3 else "control"),
            input_sha256=(
                poc_sha256 if ordinal <= 3 else _EMPTY_SHA256
            ),
            input_size_bytes=(
                len(poc_input) if ordinal <= 3 else 0
            ),
        )
        for ordinal in range(1, PWN_CRASH_V1_ATTEMPT_COUNT + 1)
    )


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
    """Bound nesting without recursing over attacker-controlled JSON."""

    pending: list[tuple[object, int]] = [(value, 1)]
    while pending:
        current, depth = pending.pop()
        if depth > maximum:
            return True
        if isinstance(current, dict):
            pending.extend(
                (item, depth + 1) for item in current.values()
            )
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)
    return False


def _exact_mapping(
    value: object,
    expected: frozenset[str],
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise _SchemaError
    return value


def _schema_sha256(value: object) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise _SchemaError
    return value


def _schema_size(value: object, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise _SchemaError
    return value


def _parse_observation_document(
    payload: bytes,
) -> PwnCrashV1Observation:
    if len(payload) > PWN_CRASH_V1_MAX_DOCUMENT_BYTES:
        raise PwnCrashV1ContractError("artifact_too_large")
    try:
        decoded = payload.decode("utf-8", errors="strict")
        value = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateKeyError as error:
        raise PwnCrashV1ContractError(
            "duplicate_json_key"
        ) from error
    except (
        RecursionError,
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        raise PwnCrashV1ContractError("invalid_json") from error
    if _json_depth_exceeds(value, PWN_CRASH_V1_MAX_JSON_DEPTH):
        raise PwnCrashV1ContractError("invalid_json")
    try:
        document = _exact_mapping(value, _TOP_LEVEL_KEYS)
        contract = _exact_mapping(
            document["contract"],
            _CONTRACT_KEYS,
        )
        binding = _exact_mapping(
            document["binding"],
            _BINDING_KEYS,
        )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"]
            != PWN_CRASH_V1_SCHEMA_VERSION
        ):
            raise _SchemaError
        if (
            type(contract["id"]) is not str
            or type(contract["version"]) is not int
            or type(contract["fingerprint"]) is not str
        ):
            raise _SchemaError
        if (
            contract["id"] != PWN_CRASH_V1_CONTRACT_ID
            or contract["version"]
            != PWN_CRASH_V1_CONTRACT_VERSION
            or contract["fingerprint"]
            != PWN_CRASH_V1_CONTRACT_FINGERPRINT
        ):
            raise PwnCrashV1ContractError("contract_mismatch")

        status = document["status"]
        reason_code = document["reason_code"]
        phase = binding["phase"]
        ordinal = binding["ordinal"]
        if (
            type(status) is not str
            or status not in {"ok", "error"}
            or type(reason_code) is not str
            or type(phase) is not str
            or phase not in {"positive", "control"}
            or type(ordinal) is not int
            or not 1 <= ordinal <= PWN_CRASH_V1_ATTEMPT_COUNT
        ):
            raise _SchemaError
        recipe_sha256 = _schema_sha256(binding["recipe_sha256"])
        manifest_sha256 = _schema_sha256(
            binding["source_manifest_sha256"]
        )
        source_sha256 = _schema_sha256(binding["source_sha256"])
        source_size = _schema_size(
            binding["source_size_bytes"],
            PWN_CRASH_V1_MAX_SOURCE_BYTES,
        )
        input_sha256 = _schema_sha256(binding["input_sha256"])
        input_size = _schema_size(
            binding["input_size_bytes"],
            PWN_CRASH_V1_MAX_INPUT_BYTES,
        )

        target_value = document["target"]
        target: PwnCrashV1TargetStatus | None
        if status == "error":
            if (
                reason_code
                not in PWN_CRASH_V1_PRODUCER_ERROR_REASONS
                or target_value is not None
            ):
                raise _SchemaError
            target = None
        else:
            if reason_code != "observation_recorded":
                raise _SchemaError
            target_mapping = _exact_mapping(
                target_value,
                _TARGET_KEYS,
            )
            termination = target_mapping["termination"]
            exit_code = target_mapping["exit_code"]
            signal_number = target_mapping["signal_number"]
            if termination == "exited":
                if (
                    type(exit_code) is not int
                    or not 0 <= exit_code <= 255
                    or signal_number is not None
                ):
                    raise _SchemaError
            elif termination == "signaled":
                if (
                    exit_code is not None
                    or type(signal_number) is not int
                    or not 1 <= signal_number <= 64
                ):
                    raise _SchemaError
            else:
                raise _SchemaError
            target = PwnCrashV1TargetStatus(
                termination=termination,
                exit_code=exit_code,
                signal_number=signal_number,
            )
    except PwnCrashV1ContractError:
        raise
    except (KeyError, _SchemaError) as error:
        raise PwnCrashV1ContractError("invalid_schema") from error

    if pwn_crash_v1_canonical_json_bytes(value) != payload:
        raise PwnCrashV1ContractError("noncanonical_json")
    return PwnCrashV1Observation(
        ordinal=ordinal,
        phase=phase,
        recipe_sha256=recipe_sha256,
        source_manifest_sha256=manifest_sha256,
        source_sha256=source_sha256,
        source_size_bytes=source_size,
        input_sha256=input_sha256,
        input_size_bytes=input_size,
        status=status,
        reason_code=reason_code,
        target=target,
    )


def parse_pwn_crash_v1_observation(
    payload: bytes,
) -> PwnCrashV1Observation:
    """Parse one complete canonical producer document."""

    if type(payload) is not bytes:
        raise TypeError("payload must be exact bytes")
    return _parse_observation_document(payload)


def _error_evaluation(
    *,
    source_manifest_sha256: str,
    source_sha256: str,
    source_size_bytes: int,
    poc_sha256: str,
    poc_size_bytes: int,
    recipe_sha256: str,
    plan: tuple[PwnCrashV1PlanInput, ...],
    observations: tuple[PwnCrashV1Observation, ...],
    failures: tuple[PwnCrashV1Failure, ...],
) -> PwnCrashV1Evaluation:
    reason = failures[0].code if failures else "invalid_schema"
    return PwnCrashV1Evaluation(
        source_manifest_sha256=source_manifest_sha256,
        source_sha256=source_sha256,
        source_size_bytes=source_size_bytes,
        poc_sha256=poc_sha256,
        poc_size_bytes=poc_size_bytes,
        recipe_sha256=recipe_sha256,
        plan=plan,
        observations=observations,
        failures=failures,
        verdict=PwnCrashV1Verdict.ERROR,
        reason_code=reason,
        positive_signal_counts=(),
        control_abnormal_terminations=0,
    )


def evaluate_pwn_crash_v1(
    observation_payloads: Iterable[bytes],
    *,
    poc_input: bytes,
    expected_source_manifest_sha256: str,
    expected_source_sha256: str,
    expected_source_size_bytes: int,
    expected_recipe_sha256: str,
) -> PwnCrashV1Evaluation:
    """Validate and deterministically classify one complete v1 run plan."""

    plan = build_pwn_crash_v1_plan(poc_input)
    manifest_sha256 = _require_sha256(
        expected_source_manifest_sha256,
        "expected_source_manifest_sha256",
    )
    source_sha256 = _require_sha256(
        expected_source_sha256,
        "expected_source_sha256",
    )
    source_size = _require_size(
        expected_source_size_bytes,
        "expected_source_size_bytes",
        PWN_CRASH_V1_MAX_SOURCE_BYTES,
    )
    recipe_sha256 = _require_sha256(
        expected_recipe_sha256,
        "expected_recipe_sha256",
    )
    poc_sha256 = hashlib.sha256(poc_input).hexdigest()
    poc_size = len(poc_input)

    failures: list[PwnCrashV1Failure] = []
    observations: list[PwnCrashV1Observation] = []
    try:
        iterator = iter(observation_payloads)
    except Exception:
        failures.append(
            PwnCrashV1Failure("observations_not_iterable")
        )
        return _error_evaluation(
            source_manifest_sha256=manifest_sha256,
            source_sha256=source_sha256,
            source_size_bytes=source_size,
            poc_sha256=poc_sha256,
            poc_size_bytes=poc_size,
            recipe_sha256=recipe_sha256,
            plan=plan,
            observations=(),
            failures=tuple(failures),
        )
    try:
        raw_payloads = tuple(
            islice(iterator, PWN_CRASH_V1_ATTEMPT_COUNT + 1)
        )
    except Exception:
        failures.append(
            PwnCrashV1Failure("observation_iteration_failed")
        )
        return _error_evaluation(
            source_manifest_sha256=manifest_sha256,
            source_sha256=source_sha256,
            source_size_bytes=source_size,
            poc_sha256=poc_sha256,
            poc_size_bytes=poc_size,
            recipe_sha256=recipe_sha256,
            plan=plan,
            observations=(),
            failures=tuple(failures),
        )
    if len(raw_payloads) != PWN_CRASH_V1_ATTEMPT_COUNT:
        failures.append(PwnCrashV1Failure("attempt_count_mismatch"))

    for index, payload in enumerate(
        raw_payloads[:PWN_CRASH_V1_ATTEMPT_COUNT],
        start=1,
    ):
        if type(payload) is not bytes:
            failures.append(
                PwnCrashV1Failure(
                    "observation_type_invalid",
                    attempt_ordinal=index,
                )
            )
            continue
        try:
            observation = _parse_observation_document(payload)
        except PwnCrashV1ContractError as error:
            failures.append(
                PwnCrashV1Failure(
                    error.code,
                    attempt_ordinal=index,
                )
            )
            continue
        observations.append(observation)
        expected = plan[index - 1]
        if (
            observation.ordinal != expected.ordinal
            or observation.phase != expected.phase
        ):
            failures.append(
                PwnCrashV1Failure(
                    "attempt_order_mismatch",
                    attempt_ordinal=index,
                )
            )
        if (
            observation.input_sha256 != expected.input_sha256
            or observation.input_size_bytes
            != expected.input_size_bytes
        ):
            failures.append(
                PwnCrashV1Failure(
                    "input_binding_mismatch",
                    attempt_ordinal=index,
                )
            )
        if (
            observation.source_manifest_sha256
            != manifest_sha256
        ):
            failures.append(
                PwnCrashV1Failure(
                    "source_manifest_mismatch",
                    attempt_ordinal=index,
                )
            )
        if (
            observation.source_sha256 != source_sha256
            or observation.source_size_bytes != source_size
        ):
            failures.append(
                PwnCrashV1Failure(
                    "source_binding_mismatch",
                    attempt_ordinal=index,
                )
            )
        if observation.recipe_sha256 != recipe_sha256:
            failures.append(
                PwnCrashV1Failure(
                    "recipe_binding_mismatch",
                    attempt_ordinal=index,
                )
            )
        if observation.status == "error":
            failures.append(
                PwnCrashV1Failure(
                    "producer_error",
                    attempt_ordinal=index,
                    producer_reason=observation.reason_code,
                )
            )

    if failures:
        return _error_evaluation(
            source_manifest_sha256=manifest_sha256,
            source_sha256=source_sha256,
            source_size_bytes=source_size,
            poc_sha256=poc_sha256,
            poc_size_bytes=poc_size,
            recipe_sha256=recipe_sha256,
            plan=plan,
            observations=tuple(observations),
            failures=tuple(failures),
        )

    positive_counts: dict[int, int] = {}
    control_abnormal = 0
    for observation in observations:
        target = observation.target
        if target is None:
            raise AssertionError("validated ok observation lacks target")
        if observation.phase == "control":
            if target.termination != "exited":
                control_abnormal += 1
            continue
        if (
            target.termination == "signaled"
            and target.signal_number in PWN_CRASH_V1_ALLOWED_SIGNALS
        ):
            signal_number = target.signal_number
            assert signal_number is not None
            positive_counts[signal_number] = (
                positive_counts.get(signal_number, 0) + 1
            )

    ordered_counts = tuple(sorted(positive_counts.items()))
    positive_total = sum(positive_counts.values())
    maximum_same_signal = max(positive_counts.values(), default=0)
    if control_abnormal:
        verdict = PwnCrashV1Verdict.INCONCLUSIVE
        reason = "control_abnormal_termination_observed"
    elif positive_total == 0:
        verdict = PwnCrashV1Verdict.INCONCLUSIVE
        reason = "no_positive_fault_observed"
    elif positive_total < PWN_CRASH_V1_REQUIRED_POSITIVE_SUCCESSES:
        verdict = PwnCrashV1Verdict.INCONCLUSIVE
        reason = "positive_fault_threshold_not_met"
    elif maximum_same_signal < PWN_CRASH_V1_REQUIRED_POSITIVE_SUCCESSES:
        verdict = PwnCrashV1Verdict.INCONCLUSIVE
        reason = "positive_fault_signature_not_reproduced"
    else:
        verdict = PwnCrashV1Verdict.CONFIRMED
        reason = "reproducible_input_triggered_fault_signal"

    return PwnCrashV1Evaluation(
        source_manifest_sha256=manifest_sha256,
        source_sha256=source_sha256,
        source_size_bytes=source_size,
        poc_sha256=poc_sha256,
        poc_size_bytes=poc_size,
        recipe_sha256=recipe_sha256,
        plan=plan,
        observations=tuple(observations),
        failures=(),
        verdict=verdict,
        reason_code=reason,
        positive_signal_counts=ordered_counts,
        control_abnormal_terminations=control_abnormal,
    )


__all__ = [
    "PWN_CRASH_V1_ALLOWED_SIGNALS",
    "PWN_CRASH_V1_ATTEMPT_COUNT",
    "PWN_CRASH_V1_CLONE3_SYSCALL",
    "PWN_CRASH_V1_CLONE_SIGHAND",
    "PWN_CRASH_V1_CLONE_THREAD",
    "PWN_CRASH_V1_CLONE_UNTRACED",
    "PWN_CRASH_V1_CONTRACT_FINGERPRINT",
    "PWN_CRASH_V1_CONTRACT_ID",
    "PWN_CRASH_V1_CONTRACT_VERSION",
    "PWN_CRASH_V1_CONTROL_ATTEMPTS",
    "PWN_CRASH_V1_DOCUMENT_TRANSPORT",
    "PWN_CRASH_V1_FAILURE_CODES",
    "PWN_CRASH_V1_HIGH_SYSCALL_BIT",
    "PWN_CRASH_V1_MAX_DOCUMENT_BYTES",
    "PWN_CRASH_V1_MAX_EVIDENCE_BYTES",
    "PWN_CRASH_V1_MAX_INPUT_BYTES",
    "PWN_CRASH_V1_MAX_TRACED_TASKS",
    "PWN_CRASH_V1_MAX_SOURCE_BYTES",
    "PWN_CRASH_V1_POSITIVE_ATTEMPTS",
    "PWN_CRASH_V1_PRODUCER_ERROR_REASONS",
    "PWN_CRASH_V1_PROTOCOL",
    "PWN_CRASH_V1_REQUIRED_POSITIVE_SUCCESSES",
    "PWN_CRASH_V1_SCHEMA_VERSION",
    "PWN_CRASH_V1_SECCOMP_ARCHITECTURES",
    "PWN_CRASH_V1_TARGET_TIMEOUT_SECONDS",
    "PwnCrashV1ContractError",
    "PwnCrashV1Evaluation",
    "PwnCrashV1Failure",
    "PwnCrashV1Observation",
    "PwnCrashV1PlanInput",
    "PwnCrashV1TargetStatus",
    "PwnCrashV1Verdict",
    "build_pwn_crash_v1_plan",
    "evaluate_pwn_crash_v1",
    "parse_pwn_crash_v1_observation",
    "pwn_crash_v1_canonical_json_bytes",
    "pwn_crash_v1_contract_descriptor",
]
