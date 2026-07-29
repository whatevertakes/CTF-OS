#!/usr/bin/env python3
"""Execute one exact ELF with one exact file connected to standard input.

This is a deliberately narrow Rev proof primitive.  The public CLI accepts
only paths beneath the fixed ``/challenge`` and ``/work`` roots, passes no
target arguments, does not interpret target output, and has no knowledge of
candidates, models, success markers, or network targets.

Linux and a mounted procfs are required.  Python in the image does not expose
``os.fexecve``, so the already-open ELF descriptor is executed through
``/proc/self/fd/<fd>`` and kept across ``execve`` with ``pass_fds``.  Input is
copied only to a verified, sealed memfd and reopened read-only; there is no
pipe or mutable-file fallback.
"""

from __future__ import annotations

import fcntl
import os
import resource
import signal
import stat
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Sequence


CHALLENGE_ROOT = Path("/challenge")
WORK_ROOT = Path("/work")
MAX_ACCEPTED_INPUT_BYTES = 1024 * 1024
MAX_ARGUMENT_BYTES = 4096
MAX_COMPONENT_BYTES = 255
_READ_CHUNK_BYTES = 64 * 1024
USAGE = (
    "Usage: stdin_exec.py --binary /challenge/RELATIVE_ELF "
    "--input /work/RELATIVE_FILE"
)
FIXED_ENVIRONMENT = {
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
    "TERM": "dumb",
}

_ARGUMENT_ERROR = 2
_RUNNER_ERROR = 125
# Linux UAPI constants are stable, but some standalone CPython builds omit
# their symbolic names from ``fcntl`` even when the running kernel supports
# memfd sealing.  The operations below still verify the kernel's actual result.
_F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
_F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
_F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", 0x0001)
_F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
_F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 0x0004)
_F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 0x0008)


class StdinExecError(RuntimeError):
    """Stable, bounded failure raised before the target is executed."""

    def __init__(self, code: str, *, exit_code: int = _RUNNER_ERROR) -> None:
        super().__init__(code)
        self.code = code
        self.exit_code = exit_code


def _relative_components(argument: str, public_root: str) -> tuple[str, ...]:
    if (
        not isinstance(argument, str)
        or not argument
        or "\x00" in argument
        or "\\" in argument
        or len(argument.encode("utf-8")) > MAX_ARGUMENT_BYTES
    ):
        raise StdinExecError(
            "invalid_path_argument",
            exit_code=_ARGUMENT_ERROR,
        )
    prefix = public_root + "/"
    if not argument.startswith(prefix):
        raise StdinExecError(
            "path_outside_fixed_root",
            exit_code=_ARGUMENT_ERROR,
        )
    relative = argument[len(prefix) :]
    components = tuple(relative.split("/"))
    if (
        not components
        or any(
            component in {"", ".", ".."}
            or len(component.encode("utf-8")) > MAX_COMPONENT_BYTES
            for component in components
        )
    ):
        raise StdinExecError(
            "unsafe_path_components",
            exit_code=_ARGUMENT_ERROR,
        )
    return components


def _directory_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory or not Path("/proc/self/fd").is_dir():
        raise StdinExecError("linux_proc_descriptor_exec_unavailable")
    return os.O_RDONLY | os.O_CLOEXEC | nofollow | directory


def _leaf_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise StdinExecError("nofollow_open_unavailable")
    return os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | nofollow


@contextmanager
def _open_beneath(
    root: Path,
    components: Sequence[str],
    *,
    label: str,
) -> Iterator[tuple[int, os.stat_result]]:
    """Open every component relative to descriptor-anchored directories."""

    descriptors: list[int] = []
    try:
        try:
            current = os.open(root, _directory_flags())
        except OSError as error:
            raise StdinExecError(f"{label}_root_unavailable") from error
        descriptors.append(current)
        if not stat.S_ISDIR(os.fstat(current).st_mode):
            raise StdinExecError(f"{label}_root_not_directory")

        for component in components[:-1]:
            try:
                child = os.open(
                    component,
                    _directory_flags(),
                    dir_fd=current,
                )
            except OSError as error:
                raise StdinExecError(
                    f"{label}_ancestor_unavailable"
                ) from error
            descriptors.append(child)
            metadata = os.fstat(child)
            if not stat.S_ISDIR(metadata.st_mode):
                raise StdinExecError(f"{label}_ancestor_not_directory")
            current = child

        try:
            leaf = os.open(
                components[-1],
                _leaf_flags(),
                dir_fd=current,
            )
        except OSError as error:
            raise StdinExecError(f"{label}_leaf_unavailable") from error
        descriptors.append(leaf)
        metadata = os.fstat(leaf)
        yield leaf, metadata
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_stable_input(
    descriptor: int,
    before: os.stat_result,
) -> bytes:
    """Read one bounded regular file through EOF and reject any mutation."""

    if not stat.S_ISREG(before.st_mode):
        raise StdinExecError("input_not_regular")
    if not 0 <= before.st_size <= MAX_ACCEPTED_INPUT_BYTES:
        raise StdinExecError("input_size_limit_exceeded")

    chunks: list[bytes] = []
    offset = 0
    try:
        while offset <= MAX_ACCEPTED_INPUT_BYTES:
            requested = min(
                _READ_CHUNK_BYTES,
                MAX_ACCEPTED_INPUT_BYTES + 1 - offset,
            )
            chunk = os.pread(descriptor, requested, offset)
            if (
                not isinstance(chunk, bytes)
                or len(chunk) > requested
            ):
                raise StdinExecError("input_read_incomplete")
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
    except StdinExecError:
        raise
    except OSError as error:
        raise StdinExecError("input_read_failed") from error

    if offset > MAX_ACCEPTED_INPUT_BYTES:
        raise StdinExecError("input_size_limit_exceeded")
    if (
        offset != before.st_size
        or _stable_file_identity(after) != _stable_file_identity(before)
    ):
        raise StdinExecError("input_changed_during_read")
    return b"".join(chunks)


def _memfd_contract() -> tuple[int, int]:
    try:
        flags = os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
        seals = (
            _F_SEAL_WRITE
            | _F_SEAL_GROW
            | _F_SEAL_SHRINK
            | _F_SEAL_SEAL
        )
    except AttributeError as error:
        raise StdinExecError("sealed_memfd_unavailable") from error
    if not callable(getattr(os, "memfd_create", None)):
        raise StdinExecError("sealed_memfd_unavailable")
    return flags, seals


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    offset = 0
    try:
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if not 0 < written <= len(view) - offset:
                raise StdinExecError("input_snapshot_write_failed")
            offset += written
    except StdinExecError:
        raise
    except OSError as error:
        raise StdinExecError("input_snapshot_write_failed") from error


def _read_memfd_exact(descriptor: int, expected_size: int) -> bytes:
    chunks: list[bytes] = []
    offset = 0
    try:
        while offset <= expected_size:
            requested = min(
                _READ_CHUNK_BYTES,
                expected_size + 1 - offset,
            )
            chunk = os.pread(descriptor, requested, offset)
            if (
                not isinstance(chunk, bytes)
                or len(chunk) > requested
            ):
                raise StdinExecError("input_snapshot_readback_failed")
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
    except StdinExecError:
        raise
    except OSError as error:
        raise StdinExecError("input_snapshot_readback_failed") from error
    if offset != expected_size:
        raise StdinExecError("input_snapshot_readback_failed")
    return b"".join(chunks)


def _reopen_memfd_read_only(
    descriptor: int,
    expected: os.stat_result,
    required_seals: int,
) -> int:
    """Reopen an internal memfd with read-only access through trusted procfs."""

    proc_directory = -1
    reopened = -1
    keep_reopened = False
    try:
        proc_directory = os.open(
            "/proc/self/fd",
            _directory_flags(),
        )
        # A procfd entry is itself a Linux magic symlink.  O_NOFOLLOW on this
        # final numeric entry would therefore always fail with ELOOP.  The
        # directory is opened descriptor-relative with O_NOFOLLOW, the leaf
        # name is an internally-created integer, and identity is checked below.
        reopened = os.open(
            str(descriptor),
            os.O_RDONLY | os.O_CLOEXEC,
            dir_fd=proc_directory,
        )
        reopened_metadata = os.fstat(reopened)
        if (
            reopened_metadata.st_dev != expected.st_dev
            or reopened_metadata.st_ino != expected.st_ino
            or not stat.S_ISREG(reopened_metadata.st_mode)
            or reopened_metadata.st_size != expected.st_size
        ):
            raise StdinExecError("input_snapshot_reopen_mismatch")
        access_mode = fcntl.fcntl(reopened, fcntl.F_GETFL) & os.O_ACCMODE
        if access_mode != os.O_RDONLY:
            raise StdinExecError("input_snapshot_not_read_only")
        observed_seals = fcntl.fcntl(reopened, _F_GET_SEALS)
        if observed_seals & required_seals != required_seals:
            raise StdinExecError("input_snapshot_seals_missing")
        if os.lseek(reopened, 0, os.SEEK_SET) != 0:
            raise StdinExecError("input_snapshot_rewind_failed")
        keep_reopened = True
        return reopened
    except StdinExecError:
        raise
    except OSError as error:
        raise StdinExecError("input_snapshot_reopen_failed") from error
    finally:
        if proc_directory >= 0:
            try:
                os.close(proc_directory)
            except OSError:
                pass
        if reopened >= 0 and not keep_reopened:
            try:
                os.close(reopened)
            except OSError:
                pass


@contextmanager
def _sealed_stdin_snapshot(payload: bytes) -> Iterator[int]:
    """Yield a sealed read-only memfd containing exactly ``payload``."""

    writable = -1
    read_only = -1
    try:
        flags, required_seals = _memfd_contract()
        try:
            writable = os.memfd_create("ctf-rev-stdin", flags)
        except OSError as error:
            raise StdinExecError("input_snapshot_create_failed") from error

        _write_all(writable, payload)
        metadata = os.fstat(writable)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size != len(payload)
        ):
            raise StdinExecError("input_snapshot_size_mismatch")
        if _read_memfd_exact(writable, len(payload)) != payload:
            raise StdinExecError("input_snapshot_readback_mismatch")

        try:
            fcntl.fcntl(writable, _F_ADD_SEALS, required_seals)
            observed_seals = fcntl.fcntl(writable, _F_GET_SEALS)
        except OSError as error:
            raise StdinExecError("input_snapshot_seal_failed") from error
        if observed_seals & required_seals != required_seals:
            raise StdinExecError("input_snapshot_seals_missing")

        sealed_metadata = os.fstat(writable)
        if (
            sealed_metadata.st_dev != metadata.st_dev
            or sealed_metadata.st_ino != metadata.st_ino
            or sealed_metadata.st_size != len(payload)
        ):
            raise StdinExecError("input_snapshot_changed_during_seal")
        read_only = _reopen_memfd_read_only(
            writable,
            sealed_metadata,
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
    """Permanently disable core dumps in this single-purpose runner."""

    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        observed = resource.getrlimit(resource.RLIMIT_CORE)
    except (OSError, ValueError) as error:
        raise StdinExecError("core_limit_unavailable") from error
    if observed != (0, 0):
        raise StdinExecError("core_limit_not_enforced")


def execute_stdin(
    binary_argument: str,
    input_argument: str,
    *,
    challenge_root: Path = CHALLENGE_ROOT,
    work_root: Path = WORK_ROOT,
) -> int:
    """Run the descriptor-bound target and return its exact process status."""

    binary_components = _relative_components(binary_argument, "/challenge")
    input_components = _relative_components(input_argument, "/work")
    with _open_beneath(
        challenge_root,
        binary_components,
        label="binary",
    ) as (binary_descriptor, binary_metadata):
        if not stat.S_ISREG(binary_metadata.st_mode):
            raise StdinExecError("binary_not_regular")
        if binary_metadata.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise StdinExecError("binary_privilege_bits_forbidden")
        if not (binary_metadata.st_mode & 0o111):
            raise StdinExecError("binary_not_executable")
        try:
            magic = os.pread(binary_descriptor, 4, 0)
            binary_after_read = os.fstat(binary_descriptor)
        except OSError as error:
            raise StdinExecError("binary_header_unavailable") from error
        if magic != b"\x7fELF":
            raise StdinExecError("binary_not_elf")
        if _stable_file_identity(binary_after_read) != _stable_file_identity(
            binary_metadata
        ):
            raise StdinExecError("binary_changed_during_validation")

        with _open_beneath(
            work_root,
            input_components,
            label="input",
        ) as (input_descriptor, input_metadata):
            payload = _read_stable_input(
                input_descriptor,
                input_metadata,
            )

        with _sealed_stdin_snapshot(payload) as stdin_descriptor:
            executable = f"/proc/self/fd/{binary_descriptor}"
            _disable_core_dumps()
            try:
                completed = subprocess.run(
                    (binary_argument,),
                    executable=executable,
                    stdin=stdin_descriptor,
                    stdout=None,
                    stderr=None,
                    env=dict(FIXED_ENVIRONMENT),
                    close_fds=True,
                    pass_fds=(binary_descriptor,),
                    shell=False,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError) as error:
                raise StdinExecError("target_exec_failed") from error
            return completed.returncode


def _parse_cli(argv: Sequence[str]) -> tuple[str, str]:
    if (
        len(argv) != 4
        or argv[0] != "--binary"
        or argv[2] != "--input"
        or not argv[1]
        or not argv[3]
    ):
        raise StdinExecError(
            "invalid_cli",
            exit_code=_ARGUMENT_ERROR,
        )
    return argv[1], argv[3]


def _preserve_target_status(returncode: int) -> int:
    """Return the target exit code or terminate with its exact signal."""

    if returncode >= 0:
        return returncode
    target_signal = -returncode
    try:
        if target_signal not in {signal.SIGKILL, signal.SIGSTOP}:
            signal.signal(target_signal, signal.SIG_DFL)
        os.kill(os.getpid(), target_signal)
    except (OSError, RuntimeError, ValueError):
        return 128 + target_signal
    # ``os.kill`` does not return when the default signal action terminates.
    return 128 + target_signal


def main(argv: Sequence[str] | None = None) -> int:
    selected = tuple(sys.argv[1:] if argv is None else argv)
    try:
        binary_argument, input_argument = _parse_cli(selected)
        return _preserve_target_status(
            execute_stdin(binary_argument, input_argument)
        )
    except StdinExecError as error:
        print(f"stdin_exec: {error.code}", file=sys.stderr)
        if error.exit_code == _ARGUMENT_ERROR:
            print(USAGE, file=sys.stderr)
        return error.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
