#!/usr/bin/env python3
"""Observe one direct ELF target's fault status for the Pwn v1 gate.

This deliberately narrow producer executes one descriptor-bound ELF with one
descriptor-bound file copied to a sealed, read-only memfd as standard input.
The target receives no arguments, no network-specific configuration, and a
fixed environment.  Target stdout and stderr are inherited through this
producer's stderr, leaving stdout exclusively for one canonical observation
document.  The outer ``ctfwrap`` therefore preserves bounded target output
without allowing it to forge the oracle document.

The producer never propagates the target status through its own exit code.
Instead, a fixed ptrace loop distinguishes the exec trap from later signal
delivery stops.  Default core-generating signals are recorded and suppressed
before delivery, so a host-configured piped core handler cannot run.  Caught,
ignored, non-root, and multithreaded core-signal stops fail closed without
delivering the signal.  Thus an ordinary ``exit(139)`` remains different from
a supported direct ``SIGSEGV``.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import os
import resource
import signal
import stat
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence


CHALLENGE_ROOT = Path("/challenge")
WORK_ROOT = Path("/work")
MAX_SOURCE_BYTES = 1024 * 1024 * 1024
MAX_INPUT_BYTES = 1024 * 1024
MAX_DOCUMENT_BYTES = 16 * 1024
MAX_ARGUMENT_BYTES = 4096
MAX_COMPONENT_BYTES = 255
TARGET_TIMEOUT_SECONDS = 5.0
READ_CHUNK_BYTES = 64 * 1024
MAX_PROC_STATUS_BYTES = 64 * 1024
MAX_TRACED_TASKS = 64
SCHEMA_VERSION = 1
CONTRACT_ID = "ctfos.pwn.crash"
CONTRACT_VERSION = 1
PROTOCOL = "pwn_local_stdin_crash_v1"
DOCUMENT_TRANSPORT = "exact-canonical-stdout-once-v1"
ALLOWED_SIGNALS = frozenset({4, 6, 7, 8, 11})
ALLOWED_SIGNAL_NAMES = {
    4: "SIGILL",
    6: "SIGABRT",
    7: "SIGBUS",
    8: "SIGFPE",
    11: "SIGSEGV",
}
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
FIXED_ENVIRONMENT = {
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
    "TERM": "dumb",
}
USAGE = (
    "Usage: crash_oracle.py --binary /challenge/ELF "
    "--input /work/FILE --ordinal N --phase positive|control "
    "--source-manifest-sha256 HEX --source-sha256 HEX "
    "--source-size-bytes N --input-sha256 HEX --input-size-bytes N "
    "--recipe-sha256 HEX"
)

PRODUCER_ERROR_REASONS = frozenset(
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

_SHA256_CHARS = frozenset("0123456789abcdef")
_ARGUMENT_ERROR = 2
_RUNNER_ERROR = 125
_F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
_F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
_F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", 0x0001)
_F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
_F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 0x0004)
_F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 0x0008)
_PR_GET_DUMPABLE = 3
_PR_SET_DUMPABLE = 4
_PR_GET_SECCOMP = 21
_PR_SET_SECCOMP = 22
_PR_SET_NO_NEW_PRIVS = 38
_PR_GET_NO_NEW_PRIVS = 39
_SECCOMP_MODE_FILTER = 2
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_RET_ALLOW = 0x7FFF0000
_BPF_LD_W_ABS = 0x20
_BPF_JMP_JEQ_K = 0x15
_BPF_JMP_JSET_K = 0x45
_BPF_RET_K = 0x06
_SECCOMP_DATA_NR_OFFSET = 0
_SECCOMP_DATA_ARCH_OFFSET = 4
_SECCOMP_DATA_ARG0_LOW_OFFSET = 16
_CLONE_SIGHAND = 0x00000800
_CLONE_THREAD = 0x00010000
_CLONE_UNTRACED = 0x00800000
_HIGH_SYSCALL_BIT = 0x40000000
_CLONE3_SYSCALL = 435
_SECCOMP_ARCHITECTURES = {
    "aarch64": {
        "audit_arch": 0xC00000B7,
        "clone_syscall": 220,
    },
    "x86_64": {
        "audit_arch": 0xC000003E,
        "clone_syscall": 56,
    },
}
_PTRACE_TRACEME = 0
_PTRACE_CONT = 7
_PTRACE_SETOPTIONS = 0x4200
_PTRACE_GETEVENTMSG = 0x4201
_PTRACE_EVENT_FORK = 1
_PTRACE_EVENT_VFORK = 2
_PTRACE_EVENT_CLONE = 3
_PTRACE_EVENT_EXEC = 4
_PTRACE_O_TRACEFORK = 1 << 1
_PTRACE_O_TRACEVFORK = 1 << 2
_PTRACE_O_TRACECLONE = 1 << 3
_PTRACE_O_TRACEEXEC = 1 << 4
_PTRACE_O_EXITKILL = 1 << 20
_PTRACE_OPTIONS = (
    _PTRACE_O_TRACEFORK
    | _PTRACE_O_TRACEVFORK
    | _PTRACE_O_TRACECLONE
    | _PTRACE_O_TRACEEXEC
    | _PTRACE_O_EXITKILL
)
_WAIT_ALL_TRACED = 0x40000000
_CHILD_SETUP_PTRACE_FAILED = b"P"
_CHILD_SETUP_EXEC_FAILED = b"E"
_CHILD_SETUP_SECCOMP_FAILED = b"S"
_CORE_DUMP_SIGNALS = frozenset(
    {
        signal.SIGQUIT,
        signal.SIGILL,
        signal.SIGTRAP,
        signal.SIGABRT,
        signal.SIGBUS,
        signal.SIGFPE,
        signal.SIGSEGV,
        signal.SIGSYS,
        signal.SIGXCPU,
        signal.SIGXFSZ,
    }
)


class _SockFilter(ctypes.Structure):
    _fields_ = (
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint),
    )


class _SockFprog(ctypes.Structure):
    _fields_ = (
        ("length", ctypes.c_ushort),
        ("filters", ctypes.POINTER(_SockFilter)),
    )


def canonical_json_bytes(value: object) -> bytes:
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


def contract_descriptor() -> dict[str, object]:
    return {
        "allowed_fault_signals": [
            {
                "name": ALLOWED_SIGNAL_NAMES[number],
                "number": number,
            }
            for number in sorted(ALLOWED_SIGNALS)
        ],
        "canonical_json": "ascii-strict-sorted-compact-newline-v1",
        "contract_id": CONTRACT_ID,
        "contract_version": CONTRACT_VERSION,
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
        "document_transport": DOCUMENT_TRANSPORT,
        "execution_profile": {
            "core_dumps": (
                "rlimit-zero-verified;"
                "core-generating-signals-never-delivered;"
                "single-thread-root-default-core-stop-recorded;"
                "all-other-core-stops-error;"
                "unobserved-core-terminal-error"
            ),
            "environment": dict(FIXED_ENVIRONMENT),
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
                        "audit_arch": profile["audit_arch"],
                        "clone_syscall": profile["clone_syscall"],
                        "machine": machine,
                    }
                    for machine, profile in sorted(
                        _SECCOMP_ARCHITECTURES.items()
                    )
                ],
                "architecture_mismatch": "errno:ENOSYS",
                "clone3": {
                    "action": "errno:ENOSYS",
                    "syscall": _CLONE3_SYSCALL,
                },
                "high_syscall_bit": {
                    "action": "errno:ENOSYS",
                    "mask": _HIGH_SYSCALL_BIT,
                },
                "clone_flags": {
                    "clone_sighand": _CLONE_SIGHAND,
                    "clone_thread": _CLONE_THREAD,
                    "clone_untraced": _CLONE_UNTRACED,
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
            "target_timeout_seconds": TARGET_TIMEOUT_SECONDS,
            "trace": (
                "fixed-ptrace-traceme;"
                "initial-and-later-exec-events-distinguished;"
                "later-exec-fails-closed;"
                "exitkill-enabled"
            ),
            "traced_task_limit": MAX_TRACED_TASKS,
            "transport_validation": (
                "receipt-success-complete-nontruncated;"
                "exact-whole-canonical-stdout"
            ),
        },
        "input_max_bytes": MAX_INPUT_BYTES,
        "observation_max_bytes": MAX_DOCUMENT_BYTES,
        "plan": [
            {"ordinals": [1, 2, 3], "phase": "positive"},
            {
                "input_sha256": EMPTY_SHA256,
                "input_size_bytes": 0,
                "ordinals": [4, 5, 6],
                "phase": "control",
            },
        ],
        "positive_success_threshold": 2,
        "producer_error_reasons": sorted(PRODUCER_ERROR_REASONS),
        "protocol": PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "source_max_bytes": MAX_SOURCE_BYTES,
        "target_status": (
            "single-thread-root-terminal-wait-status-or-"
            "default-core-signal-stop;"
            "numeric-exit-is-never-a-signal"
        ),
    }


CONTRACT_FINGERPRINT = hashlib.sha256(
    canonical_json_bytes(contract_descriptor())
).hexdigest()


class CrashOracleError(RuntimeError):
    """Finite producer error; exception text is never serialized."""

    def __init__(self, code: str) -> None:
        if code not in PRODUCER_ERROR_REASONS:
            raise ValueError("unknown crash oracle error code")
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class RequestBinding:
    ordinal: int
    phase: str
    source_manifest_sha256: str
    source_sha256: str
    source_size_bytes: int
    input_sha256: str
    input_size_bytes: int
    recipe_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.ordinal) is not int
            or not 1 <= self.ordinal <= 6
            or self.phase not in {"positive", "control"}
            or (self.ordinal <= 3) != (self.phase == "positive")
            or not _valid_sha256(self.source_manifest_sha256)
            or not _valid_sha256(self.source_sha256)
            or not _valid_sha256(self.input_sha256)
            or not _valid_sha256(self.recipe_sha256)
            or type(self.source_size_bytes) is not int
            or not 0 <= self.source_size_bytes <= MAX_SOURCE_BYTES
            or type(self.input_size_bytes) is not int
            or not 0 <= self.input_size_bytes <= MAX_INPUT_BYTES
            or (
                self.phase == "positive"
                and self.input_size_bytes == 0
            )
            or (
                self.phase == "control"
                and (
                    self.input_size_bytes != 0
                    or self.input_sha256 != EMPTY_SHA256
                )
            )
        ):
            raise ValueError("invalid request binding")

    def to_dict(self) -> dict[str, object]:
        return {
            "input_sha256": self.input_sha256,
            "input_size_bytes": self.input_size_bytes,
            "ordinal": self.ordinal,
            "phase": self.phase,
            "recipe_sha256": self.recipe_sha256,
            "source_manifest_sha256": self.source_manifest_sha256,
            "source_sha256": self.source_sha256,
            "source_size_bytes": self.source_size_bytes,
        }


def _valid_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and set(value) <= _SHA256_CHARS
    )


def _base_document(binding: RequestBinding) -> dict[str, object]:
    return {
        "binding": binding.to_dict(),
        "contract": {
            "fingerprint": CONTRACT_FINGERPRINT,
            "id": CONTRACT_ID,
            "version": CONTRACT_VERSION,
        },
        "schema_version": SCHEMA_VERSION,
    }


def success_document(
    binding: RequestBinding,
    *,
    termination: str,
    exit_code: int | None,
    signal_number: int | None,
) -> dict[str, object]:
    if termination == "exited":
        valid = (
            type(exit_code) is int
            and 0 <= exit_code <= 255
            and signal_number is None
        )
    elif termination == "signaled":
        valid = (
            exit_code is None
            and type(signal_number) is int
            and 1 <= signal_number <= 64
        )
    else:
        valid = False
    if not valid:
        raise ValueError("invalid target status")
    return {
        **_base_document(binding),
        "reason_code": "observation_recorded",
        "status": "ok",
        "target": {
            "exit_code": exit_code,
            "signal_number": signal_number,
            "termination": termination,
        },
    }


def error_document(
    binding: RequestBinding,
    reason_code: str,
) -> dict[str, object]:
    if reason_code not in PRODUCER_ERROR_REASONS:
        raise ValueError("invalid producer error reason")
    return {
        **_base_document(binding),
        "reason_code": reason_code,
        "status": "error",
        "target": None,
    }


def _relative_components(
    argument: str,
    public_root: str,
) -> tuple[str, ...]:
    if (
        type(argument) is not str
        or not argument
        or "\x00" in argument
        or "\\" in argument
        or len(argument.encode("utf-8")) > MAX_ARGUMENT_BYTES
    ):
        raise ValueError("invalid path")
    prefix = public_root + "/"
    if not argument.startswith(prefix):
        raise ValueError("path outside fixed root")
    components = tuple(argument[len(prefix) :].split("/"))
    if (
        not components
        or any(
            component in {"", ".", ".."}
            or len(component.encode("utf-8"))
            > MAX_COMPONENT_BYTES
            for component in components
        )
    ):
        raise ValueError("unsafe path")
    return components


def _directory_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory or not Path("/proc/self/fd").is_dir():
        raise CrashOracleError(
            "linux_proc_descriptor_exec_unavailable"
        )
    return os.O_RDONLY | os.O_CLOEXEC | nofollow | directory


def _leaf_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise CrashOracleError("nofollow_open_unavailable")
    return os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | nofollow


@contextmanager
def _open_beneath(
    root: Path,
    components: Sequence[str],
    *,
    label: str,
) -> Iterator[tuple[int, os.stat_result]]:
    descriptors: list[int] = []
    try:
        try:
            current = os.open(root, _directory_flags())
        except CrashOracleError:
            raise
        except OSError as error:
            raise CrashOracleError(
                f"{label}_root_unavailable"
            ) from error
        descriptors.append(current)
        if not stat.S_ISDIR(os.fstat(current).st_mode):
            raise CrashOracleError(f"{label}_root_not_directory")
        for component in components[:-1]:
            try:
                child = os.open(
                    component,
                    _directory_flags(),
                    dir_fd=current,
                )
            except CrashOracleError:
                raise
            except OSError as error:
                raise CrashOracleError(
                    f"{label}_ancestor_unavailable"
                ) from error
            descriptors.append(child)
            if not stat.S_ISDIR(os.fstat(child).st_mode):
                raise CrashOracleError(
                    f"{label}_ancestor_not_directory"
                )
            current = child
        try:
            leaf = os.open(
                components[-1],
                _leaf_flags(),
                dir_fd=current,
            )
        except CrashOracleError:
            raise
        except OSError as error:
            raise CrashOracleError(
                f"{label}_leaf_unavailable"
            ) from error
        descriptors.append(leaf)
        yield leaf, os.fstat(leaf)
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _stable_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_stable(
    descriptor: int,
    before: os.stat_result,
    *,
    maximum_bytes: int,
    label: str,
) -> bytes:
    if not stat.S_ISREG(before.st_mode):
        raise CrashOracleError(f"{label}_not_regular")
    if not 0 <= before.st_size <= maximum_bytes:
        raise CrashOracleError(f"{label}_size_limit_exceeded")
    chunks: list[bytes] = []
    offset = 0
    try:
        while offset <= maximum_bytes:
            requested = min(
                READ_CHUNK_BYTES,
                maximum_bytes + 1 - offset,
            )
            chunk = os.pread(descriptor, requested, offset)
            if not isinstance(chunk, bytes) or len(chunk) > requested:
                raise CrashOracleError(f"{label}_read_incomplete")
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
    except CrashOracleError:
        raise
    except OSError as error:
        raise CrashOracleError(f"{label}_read_failed") from error
    if offset > maximum_bytes:
        raise CrashOracleError(f"{label}_size_limit_exceeded")
    if (
        offset != before.st_size
        or _stable_identity(after) != _stable_identity(before)
    ):
        raise CrashOracleError(f"{label}_changed_during_read")
    return b"".join(chunks)


def _hash_stable_source(
    descriptor: int,
    before: os.stat_result,
) -> tuple[str, int]:
    if not stat.S_ISREG(before.st_mode):
        raise CrashOracleError("binary_not_regular")
    if not 0 <= before.st_size <= MAX_SOURCE_BYTES:
        raise CrashOracleError("source_size_limit_exceeded")
    digest = hashlib.sha256()
    offset = 0
    try:
        while offset <= MAX_SOURCE_BYTES:
            requested = min(
                READ_CHUNK_BYTES,
                MAX_SOURCE_BYTES + 1 - offset,
            )
            chunk = os.pread(descriptor, requested, offset)
            if not isinstance(chunk, bytes) or len(chunk) > requested:
                raise CrashOracleError("source_read_failed")
            if not chunk:
                break
            digest.update(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
    except CrashOracleError:
        raise
    except OSError as error:
        raise CrashOracleError("source_read_failed") from error
    if offset > MAX_SOURCE_BYTES:
        raise CrashOracleError("source_size_limit_exceeded")
    if (
        offset != before.st_size
        or _stable_identity(after) != _stable_identity(before)
    ):
        raise CrashOracleError(
            "binary_changed_during_validation"
        )
    return digest.hexdigest(), offset


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    offset = 0
    try:
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if not 0 < written <= len(view) - offset:
                raise CrashOracleError(
                    "input_snapshot_write_failed"
                )
            offset += written
    except CrashOracleError:
        raise
    except OSError as error:
        raise CrashOracleError(
            "input_snapshot_write_failed"
        ) from error


def _read_memfd_exact(descriptor: int, size: int) -> bytes:
    chunks: list[bytes] = []
    offset = 0
    try:
        while offset <= size:
            requested = min(
                READ_CHUNK_BYTES,
                size + 1 - offset,
            )
            chunk = os.pread(descriptor, requested, offset)
            if not isinstance(chunk, bytes) or len(chunk) > requested:
                raise CrashOracleError(
                    "input_snapshot_readback_failed"
                )
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
    except CrashOracleError:
        raise
    except OSError as error:
        raise CrashOracleError(
            "input_snapshot_readback_failed"
        ) from error
    if offset != size:
        raise CrashOracleError("input_snapshot_readback_failed")
    return b"".join(chunks)


def _reopen_memfd_read_only(
    descriptor: int,
    expected: os.stat_result,
    required_seals: int,
) -> int:
    proc_directory = -1
    reopened = -1
    keep = False
    try:
        proc_directory = os.open(
            "/proc/self/fd",
            _directory_flags(),
        )
        reopened = os.open(
            str(descriptor),
            os.O_RDONLY | os.O_CLOEXEC,
            dir_fd=proc_directory,
        )
        metadata = os.fstat(reopened)
        if (
            metadata.st_dev != expected.st_dev
            or metadata.st_ino != expected.st_ino
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size != expected.st_size
        ):
            raise CrashOracleError(
                "input_snapshot_reopen_mismatch"
            )
        if (
            fcntl.fcntl(reopened, fcntl.F_GETFL) & os.O_ACCMODE
            != os.O_RDONLY
        ):
            raise CrashOracleError(
                "input_snapshot_not_read_only"
            )
        if (
            fcntl.fcntl(reopened, _F_GET_SEALS) & required_seals
            != required_seals
        ):
            raise CrashOracleError(
                "input_snapshot_seals_missing"
            )
        if os.lseek(reopened, 0, os.SEEK_SET) != 0:
            raise CrashOracleError(
                "input_snapshot_rewind_failed"
            )
        keep = True
        return reopened
    except CrashOracleError:
        raise
    except OSError as error:
        raise CrashOracleError(
            "input_snapshot_reopen_failed"
        ) from error
    finally:
        if proc_directory >= 0:
            try:
                os.close(proc_directory)
            except OSError:
                pass
        if reopened >= 0 and not keep:
            try:
                os.close(reopened)
            except OSError:
                pass


@contextmanager
def _sealed_stdin(payload: bytes) -> Iterator[int]:
    writable = -1
    read_only = -1
    try:
        try:
            flags = os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
        except AttributeError as error:
            raise CrashOracleError(
                "input_snapshot_create_failed"
            ) from error
        required_seals = (
            _F_SEAL_WRITE
            | _F_SEAL_GROW
            | _F_SEAL_SHRINK
            | _F_SEAL_SEAL
        )
        try:
            writable = os.memfd_create("ctf-pwn-stdin", flags)
        except (AttributeError, OSError) as error:
            raise CrashOracleError(
                "input_snapshot_create_failed"
            ) from error
        _write_all(writable, payload)
        metadata = os.fstat(writable)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size != len(payload)
        ):
            raise CrashOracleError(
                "input_snapshot_size_mismatch"
            )
        if _read_memfd_exact(writable, len(payload)) != payload:
            raise CrashOracleError(
                "input_snapshot_readback_mismatch"
            )
        try:
            fcntl.fcntl(writable, _F_ADD_SEALS, required_seals)
            observed = fcntl.fcntl(writable, _F_GET_SEALS)
        except OSError as error:
            raise CrashOracleError(
                "input_snapshot_seal_failed"
            ) from error
        if observed & required_seals != required_seals:
            raise CrashOracleError(
                "input_snapshot_seals_missing"
            )
        sealed = os.fstat(writable)
        if (
            sealed.st_dev != metadata.st_dev
            or sealed.st_ino != metadata.st_ino
            or sealed.st_size != len(payload)
        ):
            raise CrashOracleError(
                "input_snapshot_changed_during_seal"
            )
        read_only = _reopen_memfd_read_only(
            writable,
            sealed,
            required_seals,
        )
        os.close(writable)
        writable = -1
        yield read_only
    finally:
        for descriptor in (read_only, writable):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _disable_core_dumps() -> None:
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        observed = resource.getrlimit(resource.RLIMIT_CORE)
    except (OSError, ValueError) as error:
        raise CrashOracleError("core_limit_unavailable") from error
    if observed != (0, 0):
        raise CrashOracleError("core_limit_not_enforced")


def _seccomp_profile() -> tuple[int, int]:
    try:
        machine = os.uname().machine
    except (AttributeError, OSError) as error:
        raise CrashOracleError("seccomp_filter_unavailable") from error
    profile = _SECCOMP_ARCHITECTURES.get(machine)
    if (
        sys.byteorder != "little"
        or profile is None
        or type(profile.get("audit_arch")) is not int
        or type(profile.get("clone_syscall")) is not int
    ):
        raise CrashOracleError("seccomp_filter_unavailable")
    return profile["audit_arch"], profile["clone_syscall"]


def _raw_prctl(
    option: int,
    argument_2: int = 0,
    argument_3: int = 0,
    argument_4: int = 0,
    argument_5: int = 0,
) -> tuple[int, int]:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.argtypes = (
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        )
        prctl.restype = ctypes.c_int
        ctypes.set_errno(0)
        result = prctl(
            option,
            argument_2,
            argument_3,
            argument_4,
            argument_5,
        )
        return int(result), ctypes.get_errno()
    except (AttributeError, TypeError, ValueError):
        return -1, errno.ENOSYS


def _clone_seccomp_instructions(
    audit_arch: int,
    clone_syscall: int,
) -> tuple[_SockFilter, ...]:
    return (
        _SockFilter(
            _BPF_LD_W_ABS,
            0,
            0,
            _SECCOMP_DATA_ARCH_OFFSET,
        ),
        _SockFilter(_BPF_JMP_JEQ_K, 1, 0, audit_arch),
        _SockFilter(
            _BPF_RET_K,
            0,
            0,
            _SECCOMP_RET_ERRNO | errno.ENOSYS,
        ),
        _SockFilter(
            _BPF_LD_W_ABS,
            0,
            0,
            _SECCOMP_DATA_NR_OFFSET,
        ),
        _SockFilter(
            _BPF_JMP_JSET_K,
            7,
            0,
            _HIGH_SYSCALL_BIT,
        ),
        _SockFilter(
            _BPF_JMP_JEQ_K,
            6,
            0,
            _CLONE3_SYSCALL,
        ),
        _SockFilter(_BPF_JMP_JEQ_K, 0, 6, clone_syscall),
        _SockFilter(
            _BPF_LD_W_ABS,
            0,
            0,
            _SECCOMP_DATA_ARG0_LOW_OFFSET,
        ),
        _SockFilter(
            _BPF_JMP_JSET_K,
            2,
            0,
            _CLONE_UNTRACED,
        ),
        _SockFilter(
            _BPF_JMP_JSET_K,
            0,
            3,
            _CLONE_SIGHAND,
        ),
        _SockFilter(
            _BPF_JMP_JSET_K,
            2,
            0,
            _CLONE_THREAD,
        ),
        _SockFilter(
            _BPF_RET_K,
            0,
            0,
            _SECCOMP_RET_ERRNO | errno.EPERM,
        ),
        _SockFilter(
            _BPF_RET_K,
            0,
            0,
            _SECCOMP_RET_ERRNO | errno.ENOSYS,
        ),
        _SockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW),
    )


def _install_clone_seccomp_filter(
    audit_arch: int,
    clone_syscall: int,
) -> bool:
    """Install and verify the fixed pre-exec clone safety filter."""

    try:
        instructions = _clone_seccomp_instructions(
            audit_arch,
            clone_syscall,
        )
        filters = (_SockFilter * len(instructions))(*instructions)
        program = _SockFprog(
            len(instructions),
            ctypes.cast(filters, ctypes.POINTER(_SockFilter)),
        )
        no_new_privs, _error_number = _raw_prctl(
            _PR_SET_NO_NEW_PRIVS,
            1,
        )
        if no_new_privs != 0:
            return False
        observed_no_new_privs, _error_number = _raw_prctl(
            _PR_GET_NO_NEW_PRIVS
        )
        if observed_no_new_privs != 1:
            return False
        installed, _error_number = _raw_prctl(
            _PR_SET_SECCOMP,
            _SECCOMP_MODE_FILTER,
            ctypes.addressof(program),
        )
        if installed != 0:
            return False
        observed_mode, _error_number = _raw_prctl(_PR_GET_SECCOMP)
        return observed_mode == _SECCOMP_MODE_FILTER
    except (OverflowError, TypeError, ValueError):
        return False


def _protect_producer_process() -> None:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.argtypes = (
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        )
        prctl.restype = ctypes.c_int
        if prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "PR_SET_DUMPABLE failed")
        if prctl(_PR_GET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise OSError(
                ctypes.get_errno(),
                "PR_SET_DUMPABLE was not retained",
            )
    except (AttributeError, OSError) as error:
        raise CrashOracleError(
            "producer_process_protection_unavailable"
        ) from error


def _raw_ptrace(
    request: int,
    pid: int,
    address: int = 0,
    data: int = 0,
) -> tuple[int, int]:
    """Call Linux ptrace without exposing libc diagnostics."""

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        ptrace = libc.ptrace
        ptrace.argtypes = (
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.c_void_p,
        )
        ptrace.restype = ctypes.c_long
        ctypes.set_errno(0)
        result = ptrace(
            request,
            pid,
            ctypes.c_void_p(address),
            ctypes.c_void_p(data),
        )
        return int(result), ctypes.get_errno()
    except (AttributeError, TypeError, ValueError):
        return -1, errno.ENOSYS


def _ptrace(
    request: int,
    pid: int,
    address: int = 0,
    data: int = 0,
    *,
    unavailable: bool = False,
) -> None:
    result, _error_number = _raw_ptrace(
        request,
        pid,
        address,
        data,
    )
    if result == -1:
        raise CrashOracleError(
            "ptrace_unavailable"
            if unavailable
            else "ptrace_protocol_invalid"
        )


def _ptrace_event_pid(pid: int) -> int:
    message = ctypes.c_ulong(0)
    try:
        address = ctypes.addressof(message)
    except (TypeError, ValueError) as error:
        raise CrashOracleError("ptrace_protocol_invalid") from error
    _ptrace(_PTRACE_GETEVENTMSG, pid, 0, address)
    observed = int(message.value)
    if observed <= 0:
        raise CrashOracleError("ptrace_protocol_invalid")
    return observed


def _read_tracee_status(
    pid: int,
    signal_number: int,
) -> tuple[int, bool, bool]:
    """Read Tgid and signal masks while one known tracee is stopped."""

    if not 1 <= signal_number <= 64:
        raise CrashOracleError("signal_disposition_unavailable")
    descriptor = -1
    chunks: list[bytes] = []
    observed = 0
    try:
        descriptor = os.open(
            f"/proc/{pid}/status",
            os.O_RDONLY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
        )
        while observed <= MAX_PROC_STATUS_BYTES:
            requested = min(
                READ_CHUNK_BYTES,
                MAX_PROC_STATUS_BYTES + 1 - observed,
            )
            chunk = os.read(descriptor, requested)
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
    except OSError as error:
        raise CrashOracleError(
            "signal_disposition_unavailable"
        ) from error
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if observed > MAX_PROC_STATUS_BYTES:
        raise CrashOracleError("signal_disposition_unavailable")
    fields: dict[bytes, int] = {}
    for line in b"".join(chunks).splitlines():
        name, separator, raw_value = line.partition(b":")
        if name not in {b"Tgid", b"SigCgt", b"SigIgn"}:
            continue
        if separator != b":" or name in fields:
            raise CrashOracleError("signal_disposition_unavailable")
        raw_value = raw_value.strip()
        if name == b"Tgid":
            if (
                not raw_value
                or len(raw_value) > 20
                or not raw_value.isdigit()
            ):
                raise CrashOracleError(
                    "signal_disposition_unavailable"
                )
            fields[name] = int(raw_value, 10)
            continue
        if not raw_value or len(raw_value) > 32 or any(
            byte not in b"0123456789abcdefABCDEF"
            for byte in raw_value
        ):
            raise CrashOracleError("signal_disposition_unavailable")
        fields[name] = int(raw_value, 16)
    if (
        set(fields) != {b"Tgid", b"SigCgt", b"SigIgn"}
        or fields[b"Tgid"] <= 0
    ):
        raise CrashOracleError("signal_disposition_unavailable")
    mask = 1 << (signal_number - 1)
    return (
        fields[b"Tgid"],
        bool(fields[b"SigCgt"] & mask),
        bool(fields[b"SigIgn"] & mask),
    )


def _write_child_setup_error(descriptor: int, value: bytes) -> None:
    try:
        os.write(descriptor, value)
    except OSError:
        pass


def _spawn_traced_target(
    binary_argument: str,
    binary_descriptor: int,
    stdin_descriptor: int,
) -> tuple[int, int]:
    """Fork one tracee and return ``(pid, setup_error_read_fd)``."""

    audit_arch, clone_syscall = _seccomp_profile()
    try:
        read_descriptor, write_descriptor = os.pipe2(
            os.O_CLOEXEC | os.O_NONBLOCK
        )
    except (AttributeError, OSError) as error:
        raise CrashOracleError("target_exec_failed") from error
    try:
        pid = os.fork()
    except OSError as error:
        os.close(read_descriptor)
        os.close(write_descriptor)
        raise CrashOracleError("target_exec_failed") from error
    if pid != 0:
        os.close(write_descriptor)
        return pid, read_descriptor

    try:
        os.close(read_descriptor)
        try:
            os.setsid()
            os.dup2(stdin_descriptor, 0, inheritable=True)
            os.dup2(2, 1, inheritable=True)
        except (OSError, TypeError):
            _write_child_setup_error(
                write_descriptor,
                _CHILD_SETUP_EXEC_FAILED,
            )
            os._exit(_RUNNER_ERROR)
        if not _install_clone_seccomp_filter(
            audit_arch,
            clone_syscall,
        ):
            _write_child_setup_error(
                write_descriptor,
                _CHILD_SETUP_SECCOMP_FAILED,
            )
            os._exit(_RUNNER_ERROR)
        result, _error_number = _raw_ptrace(_PTRACE_TRACEME, 0)
        if result == -1:
            _write_child_setup_error(
                write_descriptor,
                _CHILD_SETUP_PTRACE_FAILED,
            )
            os._exit(_RUNNER_ERROR)
        try:
            os.execve(
                f"/proc/self/fd/{binary_descriptor}",
                (binary_argument,),
                dict(FIXED_ENVIRONMENT),
            )
        except OSError:
            _write_child_setup_error(
                write_descriptor,
                _CHILD_SETUP_EXEC_FAILED,
            )
            os._exit(_RUNNER_ERROR)
    finally:
        os._exit(_RUNNER_ERROR)


def _child_setup_failure(descriptor: int) -> str | None:
    try:
        payload = os.read(descriptor, 2)
    except BlockingIOError:
        return None
    except OSError as error:
        raise CrashOracleError("target_exec_failed") from error
    if payload == _CHILD_SETUP_PTRACE_FAILED:
        return "ptrace_unavailable"
    if payload == _CHILD_SETUP_SECCOMP_FAILED:
        return "seccomp_filter_unavailable"
    if payload:
        return "target_exec_failed"
    return None


def _kill_target_process_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError as error:
        if error.errno == errno.ESRCH:
            return
        raise CrashOracleError(
            "target_process_group_cleanup_failed"
        ) from error


def _kill_tracees(tracees: set[int]) -> None:
    for pid in tuple(tracees):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            continue
        except OSError as error:
            if error.errno != errno.ESRCH:
                raise CrashOracleError(
                    "target_process_group_cleanup_failed"
                ) from error


def _reap_tracees(tracees: set[int], *, deadline: float) -> None:
    while tracees and time.monotonic() < deadline:
        try:
            pid, status = os.waitpid(
                -1,
                os.WNOHANG | os.WUNTRACED | _WAIT_ALL_TRACED,
            )
        except ChildProcessError:
            tracees.clear()
            return
        except OSError as error:
            if error.errno == errno.EINTR:
                continue
            raise CrashOracleError("target_reap_failed") from error
        if pid == 0:
            time.sleep(0.002)
            continue
        tracees.add(pid)
        if os.WIFSTOPPED(status):
            try:
                _ptrace(_PTRACE_CONT, pid, 0, signal.SIGKILL)
            except CrashOracleError:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            continue
        tracees.discard(pid)
    if tracees:
        raise CrashOracleError("target_reap_failed")


def _terminal_signal_result(
    signal_number: int,
) -> tuple[str, None, int]:
    if not 1 <= signal_number <= 64:
        raise CrashOracleError("wait_status_invalid")
    if signal_number in _CORE_DUMP_SIGNALS:
        raise CrashOracleError(
            "unobserved_core_signal_termination"
        )
    return "signaled", None, signal_number


def _execute_target(
    binary_argument: str,
    binary_descriptor: int,
    stdin_descriptor: int,
    *,
    timeout_seconds: float,
) -> tuple[str, int | None, int | None]:
    _disable_core_dumps()
    _protect_producer_process()
    process_pid, setup_descriptor = _spawn_traced_target(
        binary_argument,
        binary_descriptor,
        stdin_descriptor,
    )
    tracees = {process_pid}
    initial_stops = {process_pid}
    root_thread_observed = False
    root_result: tuple[str, int | None, int | None] | None = None
    deadline = time.monotonic() + timeout_seconds
    try:
        while root_result is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CrashOracleError("target_timeout")
            try:
                pid, status = os.waitpid(
                    -1,
                    os.WNOHANG | os.WUNTRACED | _WAIT_ALL_TRACED,
                )
            except ChildProcessError as error:
                failure = _child_setup_failure(setup_descriptor)
                raise CrashOracleError(
                    failure or "ptrace_protocol_invalid"
                ) from error
            except OSError as error:
                if error.errno == errno.EINTR:
                    continue
                raise CrashOracleError(
                    "ptrace_protocol_invalid"
                ) from error
            if pid == 0:
                time.sleep(min(0.002, remaining))
                continue
            if pid not in tracees:
                raise CrashOracleError("ptrace_protocol_invalid")
            if os.WIFEXITED(status):
                tracees.discard(pid)
                if pid == process_pid:
                    failure = _child_setup_failure(setup_descriptor)
                    if failure is not None:
                        raise CrashOracleError(failure)
                    root_result = ("exited", os.WEXITSTATUS(status), None)
                continue
            if os.WIFSIGNALED(status):
                tracees.discard(pid)
                signal_number = os.WTERMSIG(status)
                terminal_result = _terminal_signal_result(
                    signal_number
                )
                if pid == process_pid:
                    root_result = terminal_result
                continue
            if not os.WIFSTOPPED(status):
                raise CrashOracleError("wait_status_invalid")

            signal_number = os.WSTOPSIG(status)
            event = status >> 16
            if pid in initial_stops:
                initial_stops.remove(pid)
                if pid == process_pid:
                    if signal_number != signal.SIGTRAP or event != 0:
                        raise CrashOracleError(
                            "ptrace_protocol_invalid"
                        )
                    failure = _child_setup_failure(setup_descriptor)
                    if failure is not None:
                        raise CrashOracleError(failure)
                    _ptrace(
                        _PTRACE_SETOPTIONS,
                        pid,
                        0,
                        _PTRACE_OPTIONS,
                        unavailable=True,
                    )
                elif signal_number not in {
                    signal.SIGSTOP,
                    signal.SIGTRAP,
                }:
                    raise CrashOracleError(
                        "ptrace_protocol_invalid"
                    )
                _ptrace(_PTRACE_CONT, pid)
                continue

            if event in {
                _PTRACE_EVENT_FORK,
                _PTRACE_EVENT_VFORK,
                _PTRACE_EVENT_CLONE,
            }:
                child_pid = _ptrace_event_pid(pid)
                if child_pid in tracees:
                    raise CrashOracleError(
                        "ptrace_protocol_invalid"
                    )
                if len(tracees) >= MAX_TRACED_TASKS:
                    raise CrashOracleError(
                        "target_task_limit_exceeded"
                    )
                child_tgid, _caught, _ignored = _read_tracee_status(
                    child_pid,
                    signal.SIGKILL,
                )
                if child_tgid == process_pid:
                    root_thread_observed = True
                tracees.add(child_pid)
                initial_stops.add(child_pid)
                _ptrace(_PTRACE_CONT, pid)
                continue
            if event == _PTRACE_EVENT_EXEC:
                raise CrashOracleError(
                    "target_reexec_unsupported"
                )
            if event != 0:
                raise CrashOracleError("ptrace_protocol_invalid")

            if signal_number in _CORE_DUMP_SIGNALS:
                tgid, caught, ignored = _read_tracee_status(
                    pid,
                    signal_number,
                )
                if caught or ignored:
                    raise CrashOracleError(
                        "caught_or_ignored_core_signal_unsupported"
                    )
                if tgid != process_pid:
                    raise CrashOracleError(
                        "non_root_core_signal_unsupported"
                    )
                if root_thread_observed:
                    raise CrashOracleError(
                        "multithreaded_core_signal_unsupported"
                    )
                _ptrace(
                    _PTRACE_CONT,
                    pid,
                    0,
                    signal.SIGKILL,
                )
                root_result = (
                    "signaled",
                    None,
                    signal_number,
                )
                continue
            _ptrace(_PTRACE_CONT, pid, 0, signal_number)
    except CrashOracleError:
        try:
            _kill_target_process_group(process_pid)
            _kill_tracees(tracees)
            _reap_tracees(
                tracees,
                deadline=time.monotonic() + 1.0,
            )
        except CrashOracleError:
            pass
        raise
    finally:
        try:
            os.close(setup_descriptor)
        except OSError:
            pass

    _kill_target_process_group(process_pid)
    _kill_tracees(tracees)
    _reap_tracees(tracees, deadline=time.monotonic() + 1.0)
    if root_result is None:
        raise CrashOracleError("wait_status_invalid")
    return root_result


def produce_document(
    binding: RequestBinding,
    binary_argument: str,
    input_argument: str,
    *,
    challenge_root: Path = CHALLENGE_ROOT,
    work_root: Path = WORK_ROOT,
    timeout_seconds: float = TARGET_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Produce one complete observation or one finite error document."""

    try:
        binary_components = _relative_components(
            binary_argument,
            "/challenge",
        )
    except ValueError:
        return error_document(binding, "binary_leaf_unavailable")
    try:
        input_components = _relative_components(
            input_argument,
            "/work",
        )
    except ValueError:
        return error_document(binding, "input_leaf_unavailable")
    try:
        with _open_beneath(
            challenge_root,
            binary_components,
            label="binary",
        ) as (binary_descriptor, binary_metadata):
            if not stat.S_ISREG(binary_metadata.st_mode):
                raise CrashOracleError("binary_not_regular")
            if binary_metadata.st_mode & (stat.S_ISUID | stat.S_ISGID):
                raise CrashOracleError(
                    "binary_privilege_bits_forbidden"
                )
            if not binary_metadata.st_mode & 0o111:
                raise CrashOracleError("binary_not_executable")
            try:
                magic = os.pread(binary_descriptor, 4, 0)
            except OSError as error:
                raise CrashOracleError(
                    "binary_header_unavailable"
                ) from error
            if magic != b"\x7fELF":
                raise CrashOracleError("binary_not_elf")
            source_sha256, source_size = _hash_stable_source(
                binary_descriptor,
                binary_metadata,
            )
            if source_size != binding.source_size_bytes:
                raise CrashOracleError("source_size_mismatch")
            if source_sha256 != binding.source_sha256:
                raise CrashOracleError("source_hash_mismatch")

            with _open_beneath(
                work_root,
                input_components,
                label="input",
            ) as (input_descriptor, input_metadata):
                payload = _read_stable(
                    input_descriptor,
                    input_metadata,
                    maximum_bytes=MAX_INPUT_BYTES,
                    label="input",
                )
            if len(payload) != binding.input_size_bytes:
                raise CrashOracleError("input_size_mismatch")
            if hashlib.sha256(payload).hexdigest() != binding.input_sha256:
                raise CrashOracleError("input_hash_mismatch")

            source_after = os.fstat(binary_descriptor)
            if _stable_identity(source_after) != _stable_identity(
                binary_metadata
            ):
                raise CrashOracleError(
                    "binary_changed_during_validation"
                )
            with _sealed_stdin(payload) as stdin_descriptor:
                termination, exit_code, signal_number = _execute_target(
                    binary_argument,
                    binary_descriptor,
                    stdin_descriptor,
                    timeout_seconds=timeout_seconds,
                )
            if _stable_identity(
                os.fstat(binary_descriptor)
            ) != _stable_identity(binary_metadata):
                raise CrashOracleError(
                    "binary_changed_during_validation"
                )
            return success_document(
                binding,
                termination=termination,
                exit_code=exit_code,
                signal_number=signal_number,
            )
    except CrashOracleError as error:
        return error_document(binding, error.code)


def _parse_nonnegative_int(value: str, maximum: int) -> int:
    if (
        not value
        or len(value) > 20
        or not value.isascii()
        or not value.isdecimal()
    ):
        raise ValueError
    parsed = int(value)
    if not 0 <= parsed <= maximum:
        raise ValueError
    return parsed


def _parse_cli(
    argv: Sequence[str],
) -> tuple[str, str, RequestBinding]:
    option_names = (
        "--binary",
        "--input",
        "--ordinal",
        "--phase",
        "--source-manifest-sha256",
        "--source-sha256",
        "--source-size-bytes",
        "--input-sha256",
        "--input-size-bytes",
        "--recipe-sha256",
    )
    if (
        len(argv) != len(option_names) * 2
        or tuple(argv[::2]) != option_names
        or any(
            not value
            or "\x00" in value
            or len(value.encode("utf-8")) > MAX_ARGUMENT_BYTES
            for value in argv[1::2]
        )
    ):
        raise ValueError
    binary_argument = argv[1]
    input_argument = argv[3]
    binding = RequestBinding(
        ordinal=_parse_nonnegative_int(argv[5], 6),
        phase=argv[7],
        source_manifest_sha256=argv[9],
        source_sha256=argv[11],
        source_size_bytes=_parse_nonnegative_int(
            argv[13],
            MAX_SOURCE_BYTES,
        ),
        input_sha256=argv[15],
        input_size_bytes=_parse_nonnegative_int(
            argv[17],
            MAX_INPUT_BYTES,
        ),
        recipe_sha256=argv[19],
    )
    return binary_argument, input_argument, binding


def _emit_document(document: dict[str, object]) -> None:
    payload = canonical_json_bytes(document)
    if len(payload) > MAX_DOCUMENT_BYTES:
        raise OSError("observation document exceeds its bound")
    written = sys.stdout.buffer.write(payload)
    if written != len(payload):
        raise OSError("observation document write incomplete")
    sys.stdout.buffer.flush()


def main(argv: Sequence[str] | None = None) -> int:
    selected = tuple(sys.argv[1:] if argv is None else argv)
    try:
        binary_argument, input_argument, binding = _parse_cli(selected)
    except (TypeError, ValueError):
        print("crash_oracle: invalid_cli", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return _ARGUMENT_ERROR
    document = produce_document(
        binding,
        binary_argument,
        input_argument,
    )
    try:
        _emit_document(document)
    except OSError:
        print("crash_oracle: document_transport_failed", file=sys.stderr)
        return _RUNNER_ERROR
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
