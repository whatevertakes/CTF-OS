#!/usr/bin/env python3
"""Execute one exact ELF with one exact file connected to standard input.

This is a deliberately narrow Rev proof primitive.  The public CLI accepts
only paths beneath the fixed ``/challenge`` and ``/work`` roots, passes no
target arguments, does not interpret target output, and has no knowledge of
candidates, models, success markers, or network targets.

Linux and a mounted procfs are required.  Python in the image does not expose
``os.fexecve``, so the already-open ELF descriptor is executed through
``/proc/self/fd/<fd>`` and kept across ``execve`` with ``pass_fds``.
"""

from __future__ import annotations

import os
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
            if not stat.S_ISREG(input_metadata.st_mode):
                raise StdinExecError("input_not_regular")
            if not 0 <= input_metadata.st_size <= MAX_ACCEPTED_INPUT_BYTES:
                raise StdinExecError("input_size_limit_exceeded")

            executable = f"/proc/self/fd/{binary_descriptor}"
            try:
                completed = subprocess.run(
                    (executable,),
                    executable=executable,
                    stdin=input_descriptor,
                    stdout=None,
                    stderr=None,
                    env=dict(FIXED_ENVIRONMENT),
                    close_fds=True,
                    pass_fds=(binary_descriptor,),
                    shell=False,
                    check=False,
                )
            except OSError as error:
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
