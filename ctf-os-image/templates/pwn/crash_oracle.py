#!/usr/bin/env python3
"""Observe one direct ELF target's exact wait status for the Pwn v1 gate.

This deliberately narrow producer executes one descriptor-bound ELF with one
descriptor-bound file copied to a sealed, read-only memfd as standard input.
The target receives no arguments, no network-specific configuration, and a
fixed environment.  Target stdout and stderr are inherited through this
producer's stderr, leaving stdout exclusively for one canonical observation
document.  The outer ``ctfwrap`` therefore preserves bounded target output
without allowing it to forge the oracle document.

The producer never propagates the target status through its own exit code.
Instead, it records whether the direct child exited or was signaled.  Thus an
ordinary ``exit(139)`` remains different from a direct ``SIGSEGV``.
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
import subprocess
import sys
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
CORE_PATTERN_PATH = Path("/proc/sys/kernel/core_pattern")
READ_CHUNK_BYTES = 64 * 1024
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
        "core_limit_not_enforced",
        "core_limit_unavailable",
        "core_pattern_unavailable",
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
        "nofollow_open_unavailable",
        "piped_core_handler_forbidden",
        "producer_process_protection_unavailable",
        "source_hash_mismatch",
        "source_read_failed",
        "source_size_limit_exceeded",
        "source_size_mismatch",
        "target_exec_failed",
        "target_process_group_cleanup_failed",
        "target_timeout",
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
                "rlimit-zero-verified-and-piped-handler-rejected"
            ),
            "core_pattern_path": str(CORE_PATTERN_PATH),
            "environment": dict(FIXED_ENVIRONMENT),
            "network": "outer-challenge-sandbox-none",
            "process_containment": (
                "one-shot-clean-sandbox-required;"
                "session-process-group-best-effort-reap"
            ),
            "producer_process": "pr-set-dumpable-zero-verified",
            "source_execution": "descriptor-bound-procfd",
            "stdin": "sealed-read-only-memfd",
            "target_arguments": "argv0-only-no-user-arguments",
            "target_shell": False,
            "target_stdout_stderr": "inherited-through-producer-stderr",
            "target_timeout_seconds": TARGET_TIMEOUT_SECONDS,
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
            "direct-child-wait-status-only;"
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


def _reject_piped_core_handler(
    core_pattern_path: Path = CORE_PATTERN_PATH,
) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            core_pattern_path,
            os.O_RDONLY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
        )
        payload = os.read(descriptor, 4097)
    except OSError as error:
        raise CrashOracleError("core_pattern_unavailable") from error
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if not payload or len(payload) > 4096 or b"\x00" in payload:
        raise CrashOracleError("core_pattern_unavailable")
    if payload.startswith(b"|"):
        raise CrashOracleError("piped_core_handler_forbidden")


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


def _reap_target_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError as error:
        if error.errno == errno.ESRCH:
            return
        raise CrashOracleError(
            "target_process_group_cleanup_failed"
        ) from error


def _execute_target(
    binary_argument: str,
    binary_descriptor: int,
    stdin_descriptor: int,
    *,
    timeout_seconds: float,
    core_pattern_path: Path = CORE_PATTERN_PATH,
) -> tuple[str, int | None, int | None]:
    executable = f"/proc/self/fd/{binary_descriptor}"
    _reject_piped_core_handler(core_pattern_path)
    _disable_core_dumps()
    _protect_producer_process()
    try:
        process = subprocess.Popen(
            (binary_argument,),
            executable=executable,
            stdin=stdin_descriptor,
            stdout=sys.stderr.buffer,
            stderr=sys.stderr.buffer,
            env=dict(FIXED_ENVIRONMENT),
            close_fds=True,
            pass_fds=(binary_descriptor,),
            shell=False,
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CrashOracleError("target_exec_failed") from error
    try:
        returncode = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        try:
            _reap_target_process_group(process)
        except CrashOracleError:
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=1.0)
            except (OSError, subprocess.TimeoutExpired):
                pass
            raise
        try:
            process.wait(timeout=1.0)
        except (OSError, subprocess.TimeoutExpired):
            pass
        raise CrashOracleError("target_timeout") from error
    _reap_target_process_group(process)
    if type(returncode) is not int:
        raise CrashOracleError("wait_status_invalid")
    if returncode < 0:
        signal_number = -returncode
        if not 1 <= signal_number <= 64:
            raise CrashOracleError("wait_status_invalid")
        return "signaled", None, signal_number
    if not 0 <= returncode <= 255:
        raise CrashOracleError("wait_status_invalid")
    return "exited", returncode, None


def produce_document(
    binding: RequestBinding,
    binary_argument: str,
    input_argument: str,
    *,
    challenge_root: Path = CHALLENGE_ROOT,
    work_root: Path = WORK_ROOT,
    timeout_seconds: float = TARGET_TIMEOUT_SECONDS,
    core_pattern_path: Path = CORE_PATTERN_PATH,
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
                    core_pattern_path=core_pattern_path,
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
