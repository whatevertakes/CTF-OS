#!/usr/bin/env python3
"""Capture one bounded Pwn runtime snapshot in a separate clean replay.

The producer executes one descriptor-bound x86-64 ELF with one
descriptor-bound payload copied to a sealed, read-only memfd.  It uses a
fixed ptrace TRACEME loop; no debugger command, shell, or model-controlled
argument is accepted.  The first supported stop must be a default-disposition
core signal from the single-threaded root process and must match the signal
bound by the parent crash evaluation.

At that stopped state, GETREGSET/NT_PRSTATUS must return exactly the Linux
x86-64 216-byte register set.  ``/proc/<tgid>/maps`` is read with a strict
128-KiB bound.  The core signal is never delivered.  All tracees are killed
and reaped after capture, and target output is forwarded only through the
producer's stderr with a fixed byte bound.  Stdout is reserved for one
canonical JSON document.
"""

from __future__ import annotations

import base64
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import resource
import signal
import stat
import struct
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence


CHALLENGE_ROOT = Path("/challenge")
WORK_ROOT = Path("/work")
MAX_SOURCE_BYTES = 1024 * 1024 * 1024
MAX_PAYLOAD_BYTES = 1024 * 1024
MAX_MAPS_BYTES = 128 * 1024
MAX_MAPS_BASE64_BYTES = 4 * ((MAX_MAPS_BYTES + 2) // 3)
MAX_DOCUMENT_BYTES = 256 * 1024
MAX_TARGET_OUTPUT_BYTES = 64 * 1024
MAX_ARGUMENT_BYTES = 4096
MAX_COMPONENT_BYTES = 255
MAX_PROC_STATUS_BYTES = 64 * 1024
MAX_TRACED_TASKS = 64
MAX_JSON_DEPTH = 7
READ_CHUNK_BYTES = 64 * 1024
TARGET_TIMEOUT_SECONDS = 5.0
SCHEMA_VERSION = 1
CONTRACT_ID = "ctfos.pwn.runtime_snapshot"
CONTRACT_VERSION = 1
PROTOCOL = "pwn_local_stdin_runtime_snapshot_v1"
DOCUMENT_TRANSPORT = "exact-canonical-stdout-once-v1"
ARCHITECTURE = "x86_64"
REGISTER_SOURCE = "ptrace_getregset_nt_prstatus"
REGISTER_SET_BYTES = 216
REGISTER_NAMES = (
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
ALLOWED_SIGNALS = frozenset({4, 6, 7, 8, 11})
FIXED_ENVIRONMENT = {
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
    "TERM": "dumb",
}
TARGET_OUTPUT_TRUNCATION_MARKER = b"\n[ctfos target output truncated]\n"
USAGE = (
    "Usage: runtime_snapshot.py --binary /challenge/ELF "
    "--payload /work/FILE --source-manifest-sha256 HEX "
    "--source-sha256 HEX --source-size-bytes N "
    "--payload-sha256 HEX --payload-size-bytes N "
    "--parent-crash-recipe-sha256 HEX "
    "--parent-crash-evaluation-sha256 HEX "
    "--expected-signal-number N --snapshot-recipe-sha256 HEX"
)

PRODUCER_ERROR_REASONS = frozenset(
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
        "target_reexec_unsupported",
        "target_reap_failed",
        "target_task_limit_exceeded",
        "unobserved_core_signal_termination",
        "unsupported_architecture",
        "wait_status_invalid",
    }
)
INCONCLUSIVE_REASONS = frozenset(
    {
        "target_exited_before_expected_signal",
        "target_timeout",
        "unexpected_core_signal_observed",
        "unexpected_signal_termination",
    }
)
FAILURE_REASONS = frozenset(
    PRODUCER_ERROR_REASONS | INCONCLUSIVE_REASONS
)
FAILURE_CODES = frozenset(
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
_AUDIT_ARCH_X86_64 = 0xC000003E
_CLONE_SYSCALL_X86_64 = 56
_CLONE3_SYSCALL_X86_64 = 435
_CLONE_SIGHAND = 0x00000800
_CLONE_THREAD = 0x00010000
_CLONE_UNTRACED = 0x00800000
_HIGH_SYSCALL_BIT = 0x40000000
_PTRACE_TRACEME = 0
_PTRACE_CONT = 7
_PTRACE_SETOPTIONS = 0x4200
_PTRACE_GETEVENTMSG = 0x4201
_PTRACE_GETREGSET = 0x4204
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
_NT_PRSTATUS = 1
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


class _Iovec(ctypes.Structure):
    _fields_ = (
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_size_t),
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


def producer_execution_descriptor() -> dict[str, object]:
    return {
        "architecture": ARCHITECTURE,
        "canonical_json": "ascii-strict-sorted-compact-newline-v1",
        "contract_id": CONTRACT_ID,
        "contract_version": CONTRACT_VERSION,
        "document_shape": (
            "contract(fingerprint,id,version);schema_version;status;"
            "reason_code;binding(source,payload,parent-crash,expected-signal,"
            "snapshot-recipe);claims(all-false);snapshot-or-null"
        ),
        "document_transport": DOCUMENT_TRANSPORT,
        "execution_profile": {
            "core_dumps": (
                "rlimit-zero-verified;core-signals-never-delivered;"
                "single-thread-root-default-expected-core-stop-only"
            ),
            "environment": dict(FIXED_ENVIRONMENT),
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
                f"bounded-{MAX_TARGET_OUTPUT_BYTES}-bytes"
            ),
            "target_shell": False,
            "target_timeout_seconds": TARGET_TIMEOUT_SECONDS,
            "trace": (
                "fixed-ptrace-traceme;getregset-nt-prstatus;"
                "all-additional-tracees-rejected;"
                "initial-and-later-exec-events-distinguished;"
                "exitkill-enabled"
            ),
        },
        "maps": {
            "encoding": "base64",
            "max_bytes": MAX_MAPS_BYTES,
            "termination": "one-final-lf-byte-required",
            "source": "/proc/<root-tgid>/maps-at-supported-stop",
        },
        "observation_max_bytes": MAX_DOCUMENT_BYTES,
        "payload_max_bytes": MAX_PAYLOAD_BYTES,
        "producer_error_reasons": sorted(PRODUCER_ERROR_REASONS),
        "failure_reasons": sorted(FAILURE_REASONS),
        "inconclusive_reasons": sorted(INCONCLUSIVE_REASONS),
        "protocol": PROTOCOL,
        "registers": {
            "encoding": "exact-16-lowercase-hex-digits",
            "getregset_bytes": REGISTER_SET_BYTES,
            "names_in_kernel_order": list(REGISTER_NAMES),
            "note_type": _NT_PRSTATUS,
        },
        "schema_version": SCHEMA_VERSION,
        "source_max_bytes": MAX_SOURCE_BYTES,
        "supported_expected_signals": sorted(ALLOWED_SIGNALS),
        "traced_task_limit": MAX_TRACED_TASKS,
        "outcomes": {
            "CAPTURED": {
                "reason_code": "snapshot_captured",
                "snapshot": "exact-snapshot-object",
            },
            "ERROR": {
                "reason_codes": sorted(PRODUCER_ERROR_REASONS),
                "snapshot": None,
            },
            "INCONCLUSIVE": {
                "reason_codes": sorted(INCONCLUSIVE_REASONS),
                "snapshot": None,
            },
        },
    }


# This literal is the fingerprint of the pure host-side v1 contract.  The
# image capability separately attests this producer's source SHA-256.
CONTRACT_FINGERPRINT = (
    "0b008ed31cd7daf240bf2d96f76c5ce1ac3b340bb5425bfd56fe0fe55f956d4a"
)


class RuntimeSnapshotError(RuntimeError):
    """Finite producer error; exception text is never serialized."""

    def __init__(self, code: str) -> None:
        if code not in FAILURE_REASONS:
            raise ValueError("unknown runtime snapshot error code")
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class RequestBinding:
    source_manifest_sha256: str
    source_sha256: str
    source_size_bytes: int
    payload_sha256: str
    payload_size_bytes: int
    parent_crash_recipe_sha256: str
    parent_crash_evaluation_sha256: str
    expected_signal_number: int
    snapshot_recipe_sha256: str

    def __post_init__(self) -> None:
        if (
            not _valid_sha256(self.source_manifest_sha256)
            or not _valid_sha256(self.source_sha256)
            or type(self.source_size_bytes) is not int
            or not 1 <= self.source_size_bytes <= MAX_SOURCE_BYTES
            or not _valid_sha256(self.payload_sha256)
            or type(self.payload_size_bytes) is not int
            or not 1 <= self.payload_size_bytes <= MAX_PAYLOAD_BYTES
            or not _valid_sha256(self.parent_crash_recipe_sha256)
            or not _valid_sha256(self.parent_crash_evaluation_sha256)
            or type(self.expected_signal_number) is not int
            or self.expected_signal_number not in ALLOWED_SIGNALS
            or not _valid_sha256(self.snapshot_recipe_sha256)
        ):
            raise ValueError("invalid request binding")

    def to_dict(self) -> dict[str, object]:
        return {
            "expected_signal_number": self.expected_signal_number,
            "parent_crash_evaluation_sha256": (
                self.parent_crash_evaluation_sha256
            ),
            "parent_crash_recipe_sha256": self.parent_crash_recipe_sha256,
            "payload_sha256": self.payload_sha256,
            "payload_size_bytes": self.payload_size_bytes,
            "snapshot_recipe_sha256": self.snapshot_recipe_sha256,
            "source_manifest_sha256": self.source_manifest_sha256,
            "source_sha256": self.source_sha256,
            "source_size_bytes": self.source_size_bytes,
        }


@dataclass(frozen=True, slots=True)
class RuntimeSnapshot:
    signal_number: int
    registers: tuple[tuple[str, str], ...]
    maps_payload: bytes

    def __post_init__(self) -> None:
        if (
            type(self.signal_number) is not int
            or self.signal_number not in ALLOWED_SIGNALS
            or type(self.registers) is not tuple
            or tuple(name for name, _value in self.registers)
            != REGISTER_NAMES
            or any(
                type(value) is not str
                or len(value) != 16
                or bool(set(value) - _SHA256_CHARS)
                for _name, value in self.registers
            )
            or type(self.maps_payload) is not bytes
            or not 1 <= len(self.maps_payload) <= MAX_MAPS_BYTES
            or not self.maps_payload.endswith(b"\n")
        ):
            raise ValueError("invalid runtime snapshot")

    def to_dict(self) -> dict[str, object]:
        maps_sha256 = hashlib.sha256(self.maps_payload).hexdigest()
        line_count = self.maps_payload.count(b"\n")
        return {
            "architecture": ARCHITECTURE,
            "maps": {
                "content_base64": base64.b64encode(
                    self.maps_payload
                ).decode("ascii"),
                "encoding": "base64",
                "line_count": line_count,
                "sha256": maps_sha256,
                "size_bytes": len(self.maps_payload),
            },
            "registers": dict(self.registers),
            "register_set_size_bytes": REGISTER_SET_BYTES,
            "register_source": REGISTER_SOURCE,
            "signal_number": self.signal_number,
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
        "claims": {
            "address_resolution_proven": False,
            "crash_proven": False,
            "exploit_proven": False,
            "leak_proven": False,
            "parent_crash_revalidated": False,
            "primitive_proven": False,
            "proof_satisfied": False,
            "stage_advance_authorized": False,
        },
        "contract": {
            "fingerprint": CONTRACT_FINGERPRINT,
            "id": CONTRACT_ID,
            "version": CONTRACT_VERSION,
        },
        "schema_version": SCHEMA_VERSION,
    }


def success_document(
    binding: RequestBinding,
    snapshot: RuntimeSnapshot,
) -> dict[str, object]:
    if (
        snapshot.signal_number != binding.expected_signal_number
        or tuple(name for name, _value in snapshot.registers)
        != REGISTER_NAMES
        or len(snapshot.maps_payload) > MAX_MAPS_BYTES
        or not snapshot.maps_payload
    ):
        raise ValueError("invalid runtime snapshot")
    document = {
        **_base_document(binding),
        "reason_code": "snapshot_captured",
        "snapshot": snapshot.to_dict(),
        "status": "CAPTURED",
    }
    if len(canonical_json_bytes(document)) > MAX_DOCUMENT_BYTES:
        raise RuntimeSnapshotError(
            "snapshot_document_size_limit_exceeded"
        )
    return document


def error_document(
    binding: RequestBinding,
    reason_code: str,
) -> dict[str, object]:
    if reason_code not in FAILURE_REASONS:
        raise ValueError("invalid producer error reason")
    return {
        **_base_document(binding),
        "reason_code": reason_code,
        "snapshot": None,
        "status": (
            "INCONCLUSIVE"
            if reason_code in INCONCLUSIVE_REASONS
            else "ERROR"
        ),
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
            or len(component.encode("utf-8")) > MAX_COMPONENT_BYTES
            for component in components
        )
    ):
        raise ValueError("unsafe path")
    return components


def _directory_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory or not Path("/proc/self/fd").is_dir():
        raise RuntimeSnapshotError("nofollow_open_unavailable")
    return os.O_RDONLY | os.O_CLOEXEC | nofollow | directory


def _leaf_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise RuntimeSnapshotError("nofollow_open_unavailable")
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
        except RuntimeSnapshotError:
            raise
        except OSError as error:
            raise RuntimeSnapshotError(
                f"{label}_root_unavailable"
            ) from error
        descriptors.append(current)
        if not stat.S_ISDIR(os.fstat(current).st_mode):
            raise RuntimeSnapshotError(f"{label}_root_not_directory")
        for component in components[:-1]:
            try:
                child = os.open(
                    component,
                    _directory_flags(),
                    dir_fd=current,
                )
            except RuntimeSnapshotError:
                raise
            except OSError as error:
                raise RuntimeSnapshotError(
                    f"{label}_ancestor_unavailable"
                ) from error
            descriptors.append(child)
            if not stat.S_ISDIR(os.fstat(child).st_mode):
                raise RuntimeSnapshotError(
                    f"{label}_ancestor_not_directory"
                )
            current = child
        try:
            leaf = os.open(
                components[-1],
                _leaf_flags(),
                dir_fd=current,
            )
        except RuntimeSnapshotError:
            raise
        except OSError as error:
            raise RuntimeSnapshotError(
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
        raise RuntimeSnapshotError(f"{label}_not_regular")
    if not 0 <= before.st_size <= maximum_bytes:
        raise RuntimeSnapshotError(f"{label}_size_limit_exceeded")
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
                raise RuntimeSnapshotError(f"{label}_read_incomplete")
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
    except RuntimeSnapshotError:
        raise
    except OSError as error:
        raise RuntimeSnapshotError(f"{label}_read_failed") from error
    if offset > maximum_bytes:
        raise RuntimeSnapshotError(f"{label}_size_limit_exceeded")
    if (
        offset != before.st_size
        or _stable_identity(after) != _stable_identity(before)
    ):
        raise RuntimeSnapshotError(f"{label}_changed_during_read")
    return b"".join(chunks)


def _hash_stable_source(
    descriptor: int,
    before: os.stat_result,
) -> tuple[str, int]:
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeSnapshotError("binary_not_regular")
    if not 0 <= before.st_size <= MAX_SOURCE_BYTES:
        raise RuntimeSnapshotError("source_size_limit_exceeded")
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
                raise RuntimeSnapshotError("source_read_failed")
            if not chunk:
                break
            digest.update(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
    except RuntimeSnapshotError:
        raise
    except OSError as error:
        raise RuntimeSnapshotError("source_read_failed") from error
    if offset > MAX_SOURCE_BYTES:
        raise RuntimeSnapshotError("source_size_limit_exceeded")
    if (
        offset != before.st_size
        or _stable_identity(after) != _stable_identity(before)
    ):
        raise RuntimeSnapshotError(
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
                raise RuntimeSnapshotError(
                    "payload_snapshot_write_failed"
                )
            offset += written
    except RuntimeSnapshotError:
        raise
    except OSError as error:
        raise RuntimeSnapshotError(
            "payload_snapshot_write_failed"
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
                raise RuntimeSnapshotError(
                    "payload_snapshot_readback_failed"
                )
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
    except RuntimeSnapshotError:
        raise
    except OSError as error:
        raise RuntimeSnapshotError(
            "payload_snapshot_readback_failed"
        ) from error
    if offset != size:
        raise RuntimeSnapshotError(
            "payload_snapshot_readback_failed"
        )
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
            raise RuntimeSnapshotError(
                "payload_snapshot_reopen_mismatch"
            )
        if (
            fcntl.fcntl(reopened, fcntl.F_GETFL) & os.O_ACCMODE
            != os.O_RDONLY
        ):
            raise RuntimeSnapshotError(
                "payload_snapshot_not_read_only"
            )
        if (
            fcntl.fcntl(reopened, _F_GET_SEALS) & required_seals
            != required_seals
        ):
            raise RuntimeSnapshotError(
                "payload_snapshot_seals_missing"
            )
        if os.lseek(reopened, 0, os.SEEK_SET) != 0:
            raise RuntimeSnapshotError(
                "payload_snapshot_rewind_failed"
            )
        keep = True
        return reopened
    except RuntimeSnapshotError:
        raise
    except OSError as error:
        raise RuntimeSnapshotError(
            "payload_snapshot_reopen_failed"
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
            raise RuntimeSnapshotError(
                "payload_snapshot_create_failed"
            ) from error
        required_seals = (
            _F_SEAL_WRITE
            | _F_SEAL_GROW
            | _F_SEAL_SHRINK
            | _F_SEAL_SEAL
        )
        try:
            writable = os.memfd_create(
                "ctf-pwn-runtime-snapshot-stdin",
                flags,
            )
        except (AttributeError, OSError) as error:
            raise RuntimeSnapshotError(
                "payload_snapshot_create_failed"
            ) from error
        _write_all(writable, payload)
        metadata = os.fstat(writable)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size != len(payload)
        ):
            raise RuntimeSnapshotError(
                "payload_snapshot_size_mismatch"
            )
        if _read_memfd_exact(writable, len(payload)) != payload:
            raise RuntimeSnapshotError(
                "payload_snapshot_readback_mismatch"
            )
        try:
            fcntl.fcntl(writable, _F_ADD_SEALS, required_seals)
            observed = fcntl.fcntl(writable, _F_GET_SEALS)
        except OSError as error:
            raise RuntimeSnapshotError(
                "payload_snapshot_seal_failed"
            ) from error
        if observed & required_seals != required_seals:
            raise RuntimeSnapshotError(
                "payload_snapshot_seals_missing"
            )
        sealed = os.fstat(writable)
        if (
            sealed.st_dev != metadata.st_dev
            or sealed.st_ino != metadata.st_ino
            or sealed.st_size != len(payload)
        ):
            raise RuntimeSnapshotError(
                "payload_snapshot_changed_during_seal"
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
        raise RuntimeSnapshotError("core_limit_unavailable") from error
    if observed != (0, 0):
        raise RuntimeSnapshotError("core_limit_not_enforced")


def _require_x86_64() -> None:
    try:
        machine = os.uname().machine
    except (AttributeError, OSError) as error:
        raise RuntimeSnapshotError("unsupported_architecture") from error
    if (
        machine != ARCHITECTURE
        or sys.byteorder != "little"
        or ctypes.sizeof(ctypes.c_ulong) != 8
        or ctypes.sizeof(ctypes.c_void_p) != 8
    ):
        raise RuntimeSnapshotError("unsupported_architecture")


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


def _clone_seccomp_instructions() -> tuple[_SockFilter, ...]:
    return (
        _SockFilter(
            _BPF_LD_W_ABS,
            0,
            0,
            _SECCOMP_DATA_ARCH_OFFSET,
        ),
        _SockFilter(_BPF_JMP_JEQ_K, 1, 0, _AUDIT_ARCH_X86_64),
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
            _CLONE3_SYSCALL_X86_64,
        ),
        _SockFilter(
            _BPF_JMP_JEQ_K,
            0,
            6,
            _CLONE_SYSCALL_X86_64,
        ),
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


def _install_clone_seccomp_filter() -> bool:
    try:
        instructions = _clone_seccomp_instructions()
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
    result, _error_number = _raw_prctl(_PR_SET_DUMPABLE, 0)
    if result != 0:
        raise RuntimeSnapshotError(
            "producer_process_protection_unavailable"
        )
    observed, _error_number = _raw_prctl(_PR_GET_DUMPABLE)
    if observed != 0:
        raise RuntimeSnapshotError(
            "producer_process_protection_unavailable"
        )


def _raw_ptrace(
    request: int,
    pid: int,
    address: int = 0,
    data: int = 0,
) -> tuple[int, int]:
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
        raise RuntimeSnapshotError(
            "ptrace_unavailable"
            if unavailable
            else "ptrace_protocol_invalid"
        )


def _ptrace_event_pid(pid: int) -> int:
    message = ctypes.c_ulong(0)
    try:
        address = ctypes.addressof(message)
    except (TypeError, ValueError) as error:
        raise RuntimeSnapshotError("ptrace_protocol_invalid") from error
    _ptrace(_PTRACE_GETEVENTMSG, pid, 0, address)
    observed = int(message.value)
    if observed <= 0:
        raise RuntimeSnapshotError("ptrace_protocol_invalid")
    return observed


def _read_tracee_status(
    pid: int,
    signal_number: int,
) -> tuple[int, bool, bool]:
    if not 1 <= signal_number <= 64:
        raise RuntimeSnapshotError("signal_disposition_unavailable")
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
        raise RuntimeSnapshotError(
            "signal_disposition_unavailable"
        ) from error
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if observed > MAX_PROC_STATUS_BYTES:
        raise RuntimeSnapshotError(
            "signal_disposition_unavailable"
        )
    fields: dict[bytes, int] = {}
    for line in b"".join(chunks).splitlines():
        name, separator, raw_value = line.partition(b":")
        if name not in {b"Tgid", b"SigCgt", b"SigIgn"}:
            continue
        if separator != b":" or name in fields:
            raise RuntimeSnapshotError(
                "signal_disposition_unavailable"
            )
        raw_value = raw_value.strip()
        if name == b"Tgid":
            if (
                not raw_value
                or len(raw_value) > 20
                or not raw_value.isdigit()
            ):
                raise RuntimeSnapshotError(
                    "signal_disposition_unavailable"
                )
            fields[name] = int(raw_value, 10)
            continue
        if not raw_value or len(raw_value) > 32 or any(
            byte not in b"0123456789abcdefABCDEF"
            for byte in raw_value
        ):
            raise RuntimeSnapshotError(
                "signal_disposition_unavailable"
            )
        fields[name] = int(raw_value, 16)
    if (
        set(fields) != {b"Tgid", b"SigCgt", b"SigIgn"}
        or fields[b"Tgid"] <= 0
    ):
        raise RuntimeSnapshotError(
            "signal_disposition_unavailable"
        )
    mask = 1 << (signal_number - 1)
    return (
        fields[b"Tgid"],
        bool(fields[b"SigCgt"] & mask),
        bool(fields[b"SigIgn"] & mask),
    )


def _read_registers(pid: int) -> tuple[tuple[str, str], ...]:
    register_buffer = (ctypes.c_ubyte * REGISTER_SET_BYTES)()
    vector = _Iovec(
        ctypes.cast(register_buffer, ctypes.c_void_p),
        REGISTER_SET_BYTES,
    )
    try:
        result, _error_number = _raw_ptrace(
            _PTRACE_GETREGSET,
            pid,
            _NT_PRSTATUS,
            ctypes.addressof(vector),
        )
    except (OverflowError, TypeError, ValueError) as error:
        raise RuntimeSnapshotError(
            "register_snapshot_unavailable"
        ) from error
    if result == -1:
        raise RuntimeSnapshotError(
            "register_snapshot_unavailable"
        )
    if vector.iov_len != REGISTER_SET_BYTES:
        raise RuntimeSnapshotError("register_set_size_mismatch")
    try:
        values = struct.unpack(
            "<27Q",
            bytes(register_buffer),
        )
    except struct.error as error:
        raise RuntimeSnapshotError(
            "register_set_size_mismatch"
        ) from error
    return tuple(
        (name, f"{value:016x}")
        for name, value in zip(REGISTER_NAMES, values, strict=True)
    )


def _read_proc_maps(tgid: int) -> bytes:
    if type(tgid) is not int or tgid <= 0:
        raise RuntimeSnapshotError("maps_open_failed")
    descriptor = -1
    chunks: list[bytes] = []
    observed = 0
    try:
        descriptor = os.open(
            f"/proc/{tgid}/maps",
            os.O_RDONLY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
        )
        while observed <= MAX_MAPS_BYTES:
            requested = min(
                READ_CHUNK_BYTES,
                MAX_MAPS_BYTES + 1 - observed,
            )
            chunk = os.read(descriptor, requested)
            if not isinstance(chunk, bytes) or len(chunk) > requested:
                raise RuntimeSnapshotError("maps_read_failed")
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
    except RuntimeSnapshotError:
        raise
    except OSError as error:
        code = (
            "maps_open_failed"
            if descriptor < 0
            else "maps_read_failed"
        )
        raise RuntimeSnapshotError(code) from error
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if observed > MAX_MAPS_BYTES:
        raise RuntimeSnapshotError("maps_size_limit_exceeded")
    payload = b"".join(chunks)
    if not payload:
        raise RuntimeSnapshotError("maps_empty")
    if not payload.endswith(b"\n"):
        raise RuntimeSnapshotError("maps_read_failed")
    return payload


def _capture_snapshot(
    pid: int,
    tgid: int,
    signal_number: int,
) -> RuntimeSnapshot:
    registers = _read_registers(pid)
    maps_payload = _read_proc_maps(tgid)
    return RuntimeSnapshot(
        signal_number=signal_number,
        registers=registers,
        maps_payload=maps_payload,
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
) -> tuple[int, int, int]:
    try:
        setup_read, setup_write = os.pipe2(
            os.O_CLOEXEC | os.O_NONBLOCK
        )
        output_read, output_write = os.pipe2(os.O_CLOEXEC)
        os.set_blocking(output_read, False)
    except (AttributeError, OSError) as error:
        for descriptor in locals().get("setup_read", -1), locals().get(
            "setup_write", -1
        ), locals().get("output_read", -1), locals().get(
            "output_write", -1
        ):
            if isinstance(descriptor, int) and descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        raise RuntimeSnapshotError("target_exec_failed") from error
    try:
        pid = os.fork()
    except OSError as error:
        for descriptor in (
            setup_read,
            setup_write,
            output_read,
            output_write,
        ):
            os.close(descriptor)
        raise RuntimeSnapshotError("target_exec_failed") from error
    if pid != 0:
        os.close(setup_write)
        os.close(output_write)
        return pid, setup_read, output_read

    try:
        os.close(setup_read)
        os.close(output_read)
        try:
            os.setsid()
            os.dup2(stdin_descriptor, 0, inheritable=True)
            os.dup2(output_write, 1, inheritable=True)
            os.dup2(output_write, 2, inheritable=True)
            os.close(output_write)
        except (OSError, TypeError):
            _write_child_setup_error(
                setup_write,
                _CHILD_SETUP_EXEC_FAILED,
            )
            os._exit(_RUNNER_ERROR)
        if not _install_clone_seccomp_filter():
            _write_child_setup_error(
                setup_write,
                _CHILD_SETUP_SECCOMP_FAILED,
            )
            os._exit(_RUNNER_ERROR)
        result, _error_number = _raw_ptrace(_PTRACE_TRACEME, 0)
        if result == -1:
            _write_child_setup_error(
                setup_write,
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
                setup_write,
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
        raise RuntimeSnapshotError("target_exec_failed") from error
    if payload == _CHILD_SETUP_PTRACE_FAILED:
        return "ptrace_unavailable"
    if payload == _CHILD_SETUP_SECCOMP_FAILED:
        return "seccomp_filter_unavailable"
    if payload:
        return "target_exec_failed"
    return None


def _drain_target_output(
    descriptor: int,
    captured: bytearray,
    truncated: bool,
) -> bool:
    while True:
        try:
            chunk = os.read(descriptor, READ_CHUNK_BYTES)
        except BlockingIOError:
            return truncated
        except OSError as error:
            if error.errno == errno.EINTR:
                continue
            return True
        if not chunk:
            return truncated
        remaining = MAX_TARGET_OUTPUT_BYTES - len(captured)
        if remaining > 0:
            captured.extend(chunk[:remaining])
        if len(chunk) > remaining:
            truncated = True


def _forward_target_output(
    captured: bytes,
    truncated: bool,
) -> None:
    if truncated:
        keep = max(
            0,
            MAX_TARGET_OUTPUT_BYTES
            - len(TARGET_OUTPUT_TRUNCATION_MARKER),
        )
        payload = captured[:keep] + TARGET_OUTPUT_TRUNCATION_MARKER
    else:
        payload = captured[:MAX_TARGET_OUTPUT_BYTES]
    view = memoryview(payload)
    offset = 0
    while offset < len(view):
        try:
            written = os.write(2, view[offset:])
        except OSError:
            return
        if written <= 0:
            return
        offset += written


def _kill_target_process_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError as error:
        if error.errno == errno.ESRCH:
            return
        raise RuntimeSnapshotError(
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
                raise RuntimeSnapshotError(
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
            raise RuntimeSnapshotError("target_reap_failed") from error
        if pid == 0:
            time.sleep(0.002)
            continue
        tracees.add(pid)
        if os.WIFSTOPPED(status):
            try:
                _ptrace(_PTRACE_CONT, pid, 0, signal.SIGKILL)
            except RuntimeSnapshotError:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            continue
        tracees.discard(pid)
    if tracees:
        raise RuntimeSnapshotError("target_reap_failed")


def _terminal_signal_error(signal_number: int) -> str:
    if not 1 <= signal_number <= 64:
        raise RuntimeSnapshotError("wait_status_invalid")
    if signal_number in _CORE_DUMP_SIGNALS:
        return "unobserved_core_signal_termination"
    return "unexpected_signal_termination"


def _execute_target(
    binary_argument: str,
    binary_descriptor: int,
    stdin_descriptor: int,
    *,
    expected_signal_number: int,
    timeout_seconds: float,
) -> RuntimeSnapshot:
    _require_x86_64()
    _disable_core_dumps()
    _protect_producer_process()
    process_pid, setup_descriptor, output_descriptor = (
        _spawn_traced_target(
            binary_argument,
            binary_descriptor,
            stdin_descriptor,
        )
    )
    tracees = {process_pid}
    initial_stops = {process_pid}
    additional_tracee_observed = False
    snapshot: RuntimeSnapshot | None = None
    failure: RuntimeSnapshotError | None = None
    captured = bytearray()
    output_truncated = False
    deadline = time.monotonic() + timeout_seconds
    try:
        while snapshot is None:
            output_truncated = _drain_target_output(
                output_descriptor,
                captured,
                output_truncated,
            )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeSnapshotError("target_timeout")
            try:
                pid, status = os.waitpid(
                    -1,
                    os.WNOHANG | os.WUNTRACED | _WAIT_ALL_TRACED,
                )
            except ChildProcessError as error:
                setup_failure = _child_setup_failure(setup_descriptor)
                raise RuntimeSnapshotError(
                    setup_failure or "ptrace_protocol_invalid"
                ) from error
            except OSError as error:
                if error.errno == errno.EINTR:
                    continue
                raise RuntimeSnapshotError(
                    "ptrace_protocol_invalid"
                ) from error
            if pid == 0:
                time.sleep(min(0.002, remaining))
                continue
            if pid not in tracees:
                raise RuntimeSnapshotError(
                    "ptrace_protocol_invalid"
                )
            if os.WIFEXITED(status):
                tracees.discard(pid)
                if pid == process_pid:
                    setup_failure = _child_setup_failure(
                        setup_descriptor
                    )
                    raise RuntimeSnapshotError(
                        setup_failure
                        or "target_exited_before_expected_signal"
                    )
                continue
            if os.WIFSIGNALED(status):
                tracees.discard(pid)
                if pid == process_pid:
                    raise RuntimeSnapshotError(
                        _terminal_signal_error(os.WTERMSIG(status))
                    )
                continue
            if not os.WIFSTOPPED(status):
                raise RuntimeSnapshotError("wait_status_invalid")

            signal_number = os.WSTOPSIG(status)
            event = status >> 16
            if pid in initial_stops:
                initial_stops.remove(pid)
                if pid == process_pid:
                    if signal_number != signal.SIGTRAP or event != 0:
                        raise RuntimeSnapshotError(
                            "ptrace_protocol_invalid"
                        )
                    setup_failure = _child_setup_failure(
                        setup_descriptor
                    )
                    if setup_failure is not None:
                        raise RuntimeSnapshotError(setup_failure)
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
                    raise RuntimeSnapshotError(
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
                    raise RuntimeSnapshotError(
                        "ptrace_protocol_invalid"
                    )
                if len(tracees) >= MAX_TRACED_TASKS:
                    raise RuntimeSnapshotError(
                        "target_task_limit_exceeded"
                    )
                _child_tgid, _caught, _ignored = _read_tracee_status(
                    child_pid,
                    signal.SIGKILL,
                )
                additional_tracee_observed = True
                tracees.add(child_pid)
                initial_stops.add(child_pid)
                raise RuntimeSnapshotError(
                    "additional_tracee_snapshot_unsupported"
                )
            if event == _PTRACE_EVENT_EXEC:
                raise RuntimeSnapshotError(
                    "target_reexec_unsupported"
                )
            if event != 0:
                raise RuntimeSnapshotError(
                    "ptrace_protocol_invalid"
                )

            if signal_number in _CORE_DUMP_SIGNALS:
                tgid, caught, ignored = _read_tracee_status(
                    pid,
                    signal_number,
                )
                if caught or ignored:
                    raise RuntimeSnapshotError(
                        "caught_or_ignored_core_signal_unsupported"
                    )
                if tgid != process_pid:
                    raise RuntimeSnapshotError(
                        "non_root_core_signal_unsupported"
                    )
                if additional_tracee_observed or pid != process_pid:
                    raise RuntimeSnapshotError(
                        "multithreaded_core_signal_unsupported"
                    )
                if signal_number != expected_signal_number:
                    raise RuntimeSnapshotError(
                        "unexpected_core_signal_observed"
                    )
                snapshot = _capture_snapshot(
                    pid,
                    tgid,
                    signal_number,
                )
                _ptrace(
                    _PTRACE_CONT,
                    pid,
                    0,
                    signal.SIGKILL,
                )
                continue
            _ptrace(_PTRACE_CONT, pid, 0, signal_number)
    except RuntimeSnapshotError as error:
        failure = error

    cleanup_failure: RuntimeSnapshotError | None = None
    try:
        _kill_target_process_group(process_pid)
    except RuntimeSnapshotError as error:
        cleanup_failure = error
    try:
        _kill_tracees(tracees)
    except RuntimeSnapshotError as error:
        if cleanup_failure is None:
            cleanup_failure = error
    try:
        _reap_tracees(
            tracees,
            deadline=time.monotonic() + 1.0,
        )
    except RuntimeSnapshotError as error:
        if cleanup_failure is None:
            cleanup_failure = error
    output_truncated = _drain_target_output(
        output_descriptor,
        captured,
        output_truncated,
    )
    _forward_target_output(bytes(captured), output_truncated)
    for descriptor in (setup_descriptor, output_descriptor):
        try:
            os.close(descriptor)
        except OSError:
            pass
    if cleanup_failure is not None:
        raise cleanup_failure
    if failure is not None:
        raise failure
    if snapshot is None:
        raise RuntimeSnapshotError("wait_status_invalid")
    return snapshot


def produce_document(
    binding: RequestBinding,
    binary_argument: str,
    payload_argument: str,
    *,
    challenge_root: Path = CHALLENGE_ROOT,
    work_root: Path = WORK_ROOT,
    timeout_seconds: float = TARGET_TIMEOUT_SECONDS,
) -> dict[str, object]:
    try:
        binary_components = _relative_components(
            binary_argument,
            "/challenge",
        )
    except ValueError:
        return error_document(binding, "binary_leaf_unavailable")
    try:
        payload_components = _relative_components(
            payload_argument,
            "/work",
        )
    except ValueError:
        return error_document(binding, "payload_leaf_unavailable")
    try:
        with _open_beneath(
            challenge_root,
            binary_components,
            label="binary",
        ) as (binary_descriptor, binary_metadata):
            if not stat.S_ISREG(binary_metadata.st_mode):
                raise RuntimeSnapshotError("binary_not_regular")
            if binary_metadata.st_mode & (stat.S_ISUID | stat.S_ISGID):
                raise RuntimeSnapshotError(
                    "binary_privilege_bits_forbidden"
                )
            if not binary_metadata.st_mode & 0o111:
                raise RuntimeSnapshotError(
                    "binary_not_executable"
                )
            try:
                header = os.pread(binary_descriptor, 20, 0)
            except OSError as error:
                raise RuntimeSnapshotError(
                    "binary_header_unavailable"
                ) from error
            if len(header) < 4 or header[:4] != b"\x7fELF":
                raise RuntimeSnapshotError("binary_not_elf")
            if (
                len(header) < 20
                or header[4] != 2
                or header[5] != 1
                or int.from_bytes(header[18:20], "little") != 62
            ):
                raise RuntimeSnapshotError(
                    "binary_architecture_unsupported"
                )
            source_sha256, source_size = _hash_stable_source(
                binary_descriptor,
                binary_metadata,
            )
            if source_size != binding.source_size_bytes:
                raise RuntimeSnapshotError("source_size_mismatch")
            if source_sha256 != binding.source_sha256:
                raise RuntimeSnapshotError("source_hash_mismatch")

            with _open_beneath(
                work_root,
                payload_components,
                label="payload",
            ) as (payload_descriptor, payload_metadata):
                payload = _read_stable(
                    payload_descriptor,
                    payload_metadata,
                    maximum_bytes=MAX_PAYLOAD_BYTES,
                    label="payload",
                )
            if len(payload) != binding.payload_size_bytes:
                raise RuntimeSnapshotError("payload_size_mismatch")
            if (
                hashlib.sha256(payload).hexdigest()
                != binding.payload_sha256
            ):
                raise RuntimeSnapshotError("payload_hash_mismatch")

            if _stable_identity(
                os.fstat(binary_descriptor)
            ) != _stable_identity(binary_metadata):
                raise RuntimeSnapshotError(
                    "binary_changed_during_validation"
                )
            with _sealed_stdin(payload) as stdin_descriptor:
                snapshot = _execute_target(
                    binary_argument,
                    binary_descriptor,
                    stdin_descriptor,
                    expected_signal_number=(
                        binding.expected_signal_number
                    ),
                    timeout_seconds=timeout_seconds,
                )
            if _stable_identity(
                os.fstat(binary_descriptor)
            ) != _stable_identity(binary_metadata):
                raise RuntimeSnapshotError(
                    "binary_changed_during_validation"
                )
            return success_document(binding, snapshot)
    except RuntimeSnapshotError as error:
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
        "--payload",
        "--source-manifest-sha256",
        "--source-sha256",
        "--source-size-bytes",
        "--payload-sha256",
        "--payload-size-bytes",
        "--parent-crash-recipe-sha256",
        "--parent-crash-evaluation-sha256",
        "--expected-signal-number",
        "--snapshot-recipe-sha256",
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
    payload_argument = argv[3]
    binding = RequestBinding(
        source_manifest_sha256=argv[5],
        source_sha256=argv[7],
        source_size_bytes=_parse_nonnegative_int(
            argv[9],
            MAX_SOURCE_BYTES,
        ),
        payload_sha256=argv[11],
        payload_size_bytes=_parse_nonnegative_int(
            argv[13],
            MAX_PAYLOAD_BYTES,
        ),
        parent_crash_recipe_sha256=argv[15],
        parent_crash_evaluation_sha256=argv[17],
        expected_signal_number=_parse_nonnegative_int(argv[19], 64),
        snapshot_recipe_sha256=argv[21],
    )
    return binary_argument, payload_argument, binding


def _emit_document(document: dict[str, object]) -> None:
    payload = canonical_json_bytes(document)
    if len(payload) > MAX_DOCUMENT_BYTES:
        raise OSError("runtime snapshot document exceeds its bound")
    written = sys.stdout.buffer.write(payload)
    if written != len(payload):
        raise OSError("runtime snapshot document write incomplete")
    sys.stdout.buffer.flush()


def main(argv: Sequence[str] | None = None) -> int:
    selected = tuple(sys.argv[1:] if argv is None else argv)
    try:
        binary_argument, payload_argument, binding = _parse_cli(selected)
    except (TypeError, ValueError):
        print("runtime_snapshot: invalid_cli", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return _ARGUMENT_ERROR
    document = produce_document(
        binding,
        binary_argument,
        payload_argument,
    )
    try:
        _emit_document(document)
    except OSError:
        print(
            "runtime_snapshot: document_transport_failed",
            file=sys.stderr,
        )
        return _RUNNER_ERROR
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
