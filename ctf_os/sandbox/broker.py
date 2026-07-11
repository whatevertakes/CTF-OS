"""Attempt-local authenticated filesystem-spool command broker.

Codex may invoke ``./ctf-exec`` from its restricted attempt directory.  The
helper can only send an argv array to this broker; the parent CTF-OS process is
the sole holder of Docker access and never evaluates a host shell command.
The transport uses only regular-file syscalls inside the exact sterile
workdir, so the Codex host tool profile can keep all network syscalls disabled.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import errno
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import tempfile
import threading
import time
from typing import Any, Sequence

from ..artifact_writer import ArtifactWriter
from .container import build_docker_exec_argv
from .container import storage_mount_limits
from .docker_cli import CommandResult, DockerCli


MAX_BROKER_MESSAGE_BYTES = 16 * 1024
MAX_BROKER_RESPONSE_BYTES = 64 * 1024
MAX_COMMAND_ARGUMENTS = 128
MAX_COMMAND_ARGUMENT_BYTES = 4096
MAX_PENDING_BROKER_REQUESTS = 16
MAX_BROKER_SPOOL_BYTES = 2 * 1024 * 1024
BROKER_IPC_DIRECTORY = ".ctf-os-broker"
_SESSION_NAME = "session"
_STOP_NAME = "stopped"
_REQUEST_NAME = re.compile(r"^request-([0-9a-f]{32})-([0-9a-f]{32})$")
_CANCEL_NAME = re.compile(r"^cancel-([0-9a-f]{32})-([0-9a-f]{32})$")
_RESPONSE_NAME = re.compile(r"^response-([0-9a-f]{32})-([0-9a-f]{32})$")
_TEMP_NAME = re.compile(r"^\.tmp-([0-9a-f]{32})$")
_POLL_INTERVAL_SEC = 0.01
_RENAME_NOREPLACE = 1

# These are fixed programs passed to Docker as argv data.  They never receive
# worker-controlled pathnames and use dirfds plus O_NOFOLLOW for every tree
# operation.  The ctf program removes only ctf-owned active tmpfs entries;
# the root program handles the parent-owned, read-only import seed.
_CTF_TMPFS_SCRUB_PROGRAM = r'''import os
import stat

ROOTS = ("/work", "/artifacts")
ME = os.geteuid()
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW

def clear(directory_fd):
    with os.scandir(directory_fd) as entries:
        names = [entry.name for entry in entries]
    for name in names:
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if info.st_uid != ME:
            raise RuntimeError("foreign entry in attempt tmpfs")
        if stat.S_ISDIR(info.st_mode):
            os.chmod(name, 0o700, dir_fd=directory_fd, follow_symlinks=False)
            child_fd = os.open(name, DIRECTORY, dir_fd=directory_fd)
            try:
                child_info = os.fstat(child_fd)
                if not stat.S_ISDIR(child_info.st_mode) or child_info.st_uid != ME:
                    raise RuntimeError("attempt tmpfs directory changed during scrub")
                clear(child_fd)
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=directory_fd)
        else:
            os.unlink(name, dir_fd=directory_fd)

for root in ROOTS:
    root_fd = os.open(root, DIRECTORY)
    try:
        root_info = os.fstat(root_fd)
        if not stat.S_ISDIR(root_info.st_mode) or stat.S_IMODE(root_info.st_mode) != 0o1777:
            raise RuntimeError("unexpected attempt tmpfs root")
        clear(root_fd)
    finally:
        os.close(root_fd)
'''

_SEED_RESET_PROGRAM = r'''import os
import stat

ROOT = "/ctf-os-seed"
ME = os.geteuid()
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW

def clear(directory_fd):
    with os.scandir(directory_fd) as entries:
        names = [entry.name for entry in entries]
    for name in names:
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            os.chmod(name, 0o700, dir_fd=directory_fd, follow_symlinks=False)
            child_fd = os.open(name, DIRECTORY, dir_fd=directory_fd)
            try:
                clear(child_fd)
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=directory_fd)
        else:
            os.unlink(name, dir_fd=directory_fd)

try:
    os.mkdir(ROOT, 0o700)
except FileExistsError:
    pass
root_fd = os.open(ROOT, DIRECTORY)
try:
    root_info = os.fstat(root_fd)
    if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != ME:
        raise RuntimeError("unsafe broker seed root")
    clear(root_fd)
    os.fchmod(root_fd, 0o700)
    os.mkdir("work", 0o700, dir_fd=root_fd)
    os.mkdir("artifacts", 0o700, dir_fd=root_fd)
finally:
    os.close(root_fd)
'''

_SEED_NORMALIZE_PROGRAM = r'''import os
import stat

ROOTS = ("/ctf-os-seed/work", "/ctf-os-seed/artifacts")
ME = os.geteuid()
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW

def normalize(directory_fd):
    with os.scandir(directory_fd) as entries:
        names = [entry.name for entry in entries]
    for name in names:
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            os.chown(name, ME, ME, dir_fd=directory_fd, follow_symlinks=False)
            os.chmod(name, 0o755, dir_fd=directory_fd, follow_symlinks=False)
            child_fd = os.open(name, DIRECTORY, dir_fd=directory_fd)
            try:
                normalize(child_fd)
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(info.st_mode):
            os.chown(name, ME, ME, dir_fd=directory_fd, follow_symlinks=False)
            os.chmod(name, 0o644, dir_fd=directory_fd, follow_symlinks=False)
        elif stat.S_ISLNK(info.st_mode):
            os.chown(name, ME, ME, dir_fd=directory_fd, follow_symlinks=False)
        else:
            raise RuntimeError("broker seed contains an unsupported entry")

seed_fd = os.open("/ctf-os-seed", DIRECTORY)
try:
    seed_info = os.fstat(seed_fd)
    if not stat.S_ISDIR(seed_info.st_mode) or seed_info.st_uid != ME:
        raise RuntimeError("unsafe broker seed root")
    os.fchmod(seed_fd, 0o755)
finally:
    os.close(seed_fd)

for root in ROOTS:
    root_fd = os.open(root, DIRECTORY)
    try:
        root_info = os.fstat(root_fd)
        if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != ME:
            raise RuntimeError("unsafe broker seed directory")
        os.fchmod(root_fd, 0o755)
        normalize(root_fd)
    finally:
        os.close(root_fd)
'''

_SEED_EXPORT_PREPARE_PROGRAM = r'''import os
import stat

ROOT = "/ctf-os-seed"
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW

root_fd = os.open(ROOT, DIRECTORY)
try:
    root_info = os.fstat(root_fd)
    if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.geteuid():
        raise RuntimeError("unsafe broker seed root")
    os.fchmod(root_fd, 0o755)
    for name in ("work", "artifacts"):
        child_fd = os.open(name, DIRECTORY, dir_fd=root_fd)
        try:
            child_info = os.fstat(child_fd)
            if not stat.S_ISDIR(child_info.st_mode) or child_info.st_uid != os.geteuid():
                raise RuntimeError("unsafe broker seed export directory")
            os.fchmod(child_fd, 0o777)
        finally:
            os.close(child_fd)
finally:
    os.close(root_fd)
'''

_CTF_SEED_COPY_PROGRAM = r'''import os
import stat

PAIRS = (("/ctf-os-seed/work", "/work"), ("/ctf-os-seed/artifacts", "/artifacts"))
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW

def copy_all(source_fd, destination_fd):
    with os.scandir(source_fd) as entries:
        names = [entry.name for entry in entries]
    for name in names:
        info = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            os.mkdir(name, info.st_mode & 0o777, dir_fd=destination_fd)
            source_child = os.open(name, DIRECTORY, dir_fd=source_fd)
            destination_child = os.open(name, DIRECTORY, dir_fd=destination_fd)
            try:
                copy_all(source_child, destination_child)
            finally:
                os.close(destination_child)
                os.close(source_child)
        elif stat.S_ISREG(info.st_mode):
            source_file = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=source_fd)
            destination_file = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, info.st_mode & 0o777, dir_fd=destination_fd)
            try:
                while True:
                    chunk = os.read(source_file, 64 * 1024)
                    if not chunk:
                        break
                    offset = 0
                    while offset < len(chunk):
                        offset += os.write(destination_file, chunk[offset:])
            finally:
                os.close(destination_file)
                os.close(source_file)
        elif stat.S_ISLNK(info.st_mode):
            os.symlink(os.readlink(name, dir_fd=source_fd), name, dir_fd=destination_fd)
        else:
            raise RuntimeError("broker seed contains an unsupported entry")

for source, destination in PAIRS:
    source_fd = os.open(source, DIRECTORY)
    destination_fd = os.open(destination, DIRECTORY)
    try:
        copy_all(source_fd, destination_fd)
    finally:
        os.close(destination_fd)
        os.close(source_fd)
'''

_CTF_EXPORT_COPY_PROGRAM = _CTF_SEED_COPY_PROGRAM.replace(
    'PAIRS = (("/ctf-os-seed/work", "/work"), ("/ctf-os-seed/artifacts", "/artifacts"))',
    'PAIRS = (("/work", "/ctf-os-seed/work"), ("/artifacts", "/ctf-os-seed/artifacts"))',
)

_ROOT_STAGING_SYNC_PROGRAM = r'''import os
import pwd
import stat

MODE = "IMPORT"
HOST = "/ctf-os-host"
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW

def fail(message):
    raise RuntimeError(message)

def open_dir(parent_fd, name):
    return os.open(name, DIRECTORY, dir_fd=parent_fd)

def clear(directory_fd, preserve=()):
    with os.scandir(directory_fd) as entries:
        names = [entry.name for entry in entries]
    for name in names:
        if name in preserve:
            continue
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            os.chmod(name, 0o700, dir_fd=directory_fd, follow_symlinks=False)
            child_fd = open_dir(directory_fd, name)
            try:
                clear(child_fd)
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=directory_fd)
        else:
            os.unlink(name, dir_fd=directory_fd)

def copy_tree(source_fd, destination_fd, uid, gid, preserve=()):
    with os.scandir(source_fd) as entries:
        names = [entry.name for entry in entries]
    for name in names:
        if name in preserve:
            continue
        info = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        mode = info.st_mode & 0o777
        if stat.S_ISDIR(info.st_mode):
            os.mkdir(name, mode, dir_fd=destination_fd)
            os.chown(name, uid, gid, dir_fd=destination_fd, follow_symlinks=False)
            source_child = open_dir(source_fd, name)
            destination_child = open_dir(destination_fd, name)
            try:
                copy_tree(source_child, destination_child, uid, gid)
            finally:
                os.close(destination_child)
                os.close(source_child)
        elif stat.S_ISREG(info.st_mode):
            source_file = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=source_fd)
            destination_file = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, mode, dir_fd=destination_fd)
            try:
                while True:
                    chunk = os.read(source_file, 64 * 1024)
                    if not chunk:
                        break
                    offset = 0
                    while offset < len(chunk):
                        written = os.write(destination_file, chunk[offset:])
                        if written <= 0:
                            fail("short staging copy")
                        offset += written
                os.fchmod(destination_file, mode)
                os.fchown(destination_file, uid, gid)
            finally:
                os.close(destination_file)
                os.close(source_file)
        elif stat.S_ISLNK(info.st_mode):
            os.symlink(os.readlink(name, dir_fd=source_fd), name, dir_fd=destination_fd)
            os.chown(name, uid, gid, dir_fd=destination_fd, follow_symlinks=False)
        else:
            fail("unsupported staging filesystem entry")

host_fd = os.open(HOST, DIRECTORY)
try:
    host_info = os.fstat(host_fd)
    if not stat.S_ISDIR(host_info.st_mode) or stat.S_IMODE(host_info.st_mode) != 0o700:
        fail("unexpected broker host staging root")
    marker_fd = os.open(".ctf-os-sterile-attempt", os.O_RDONLY | NOFOLLOW, dir_fd=host_fd)
    try:
        marker_info = os.fstat(marker_fd)
        if not stat.S_ISREG(marker_info.st_mode) or marker_info.st_uid != host_info.st_uid or stat.S_IMODE(marker_info.st_mode) != 0o600:
            fail("unsafe broker host staging marker")
    finally:
        os.close(marker_fd)
    host_work_fd = open_dir(host_fd, "work")
    host_artifacts_fd = open_dir(host_fd, "artifacts")
    try:
        for descriptor in (host_work_fd, host_artifacts_fd):
            details = os.fstat(descriptor)
            if not stat.S_ISDIR(details.st_mode) or details.st_uid != host_info.st_uid or stat.S_IMODE(details.st_mode) != 0o1777:
                fail("unsafe broker host staging child")
        active_work_fd = os.open("/work", DIRECTORY)
        active_artifacts_fd = os.open("/artifacts", DIRECTORY)
        try:
            if MODE == "IMPORT":
                identity = pwd.getpwnam("ctf")
                copy_tree(host_work_fd, active_work_fd, identity.pw_uid, identity.pw_gid, preserve=("ctf-exec", ".ctf-os-broker"))
                copy_tree(host_artifacts_fd, active_artifacts_fd, identity.pw_uid, identity.pw_gid)
            elif MODE == "EXPORT":
                clear(host_work_fd, preserve=("ctf-exec", ".ctf-os-broker"))
                clear(host_artifacts_fd)
                copy_tree(active_work_fd, host_work_fd, host_info.st_uid, host_info.st_gid, preserve=("ctf-exec", ".ctf-os-broker"))
                copy_tree(active_artifacts_fd, host_artifacts_fd, host_info.st_uid, host_info.st_gid)
            else:
                fail("invalid fixed staging sync mode")
        finally:
            os.close(active_artifacts_fd)
            os.close(active_work_fd)
    finally:
        os.close(host_artifacts_fd)
        os.close(host_work_fd)
finally:
    os.close(host_fd)
'''

_ROOT_IMPORT_STAGING_PROGRAM = _ROOT_STAGING_SYNC_PROGRAM.replace('MODE = "IMPORT"', 'MODE = "IMPORT"')
_ROOT_EXPORT_STAGING_PROGRAM = _ROOT_STAGING_SYNC_PROGRAM.replace('MODE = "IMPORT"', 'MODE = "EXPORT"')

# Export never writes directly into the live host mirror.  It copies into two
# broker-generated siblings under the private attempt root, charges every
# materialized regular-file byte (including sparse holes and each hardlink
# name), and removes those siblings again on any quota/copy failure.  The host
# process validates and commits the completed snapshots below.
_ROOT_EXPORT_TO_TEMP_PROGRAM = r'''import os
import stat

HOST = "/ctf-os-host"
WORK_TEMP = __WORK_TEMP__
ARTIFACTS_TEMP = __ARTIFACTS_TEMP__
WORK_BYTES = __WORK_BYTES__
ARTIFACTS_BYTES = __ARTIFACTS_BYTES__
WORK_INODES = __WORK_INODES__
ARTIFACTS_INODES = __ARTIFACTS_INODES__
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW

def fail(message):
    raise RuntimeError(message)

def same(left, right):
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)

def remove_entry(parent_fd, name):
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(info.st_mode):
        child_fd = os.open(name, DIRECTORY, dir_fd=parent_fd)
        try:
            with os.scandir(child_fd) as entries:
                names = [entry.name for entry in entries]
            for child in names:
                remove_entry(child_fd, child)
        finally:
            os.close(child_fd)
        os.rmdir(name, dir_fd=parent_fd)
    else:
        os.unlink(name, dir_fd=parent_fd)

def open_host_child(root_fd, name):
    child_fd = os.open(name, DIRECTORY, dir_fd=root_fd)
    info = os.fstat(child_fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != host_info.st_uid
            or stat.S_IMODE(info.st_mode) != 0o1777):
        os.close(child_fd)
        fail("unsafe broker host staging child")
    return child_fd

def create_temp(root_fd, name):
    try:
        os.mkdir(name, 0o700, dir_fd=root_fd)
    except FileExistsError:
        fail("broker export temporary already exists")
    temp_fd = os.open(name, DIRECTORY, dir_fd=root_fd)
    try:
        info = os.fstat(temp_fd)
        if not stat.S_ISDIR(info.st_mode):
            fail("broker export temporary is unsafe")
        os.fchown(temp_fd, host_info.st_uid, host_info.st_gid)
        os.fchmod(temp_fd, 0o1777)
        return temp_fd
    except BaseException:
        os.close(temp_fd)
        raise

def copy_tree(source_fd, destination_fd, maximum_bytes, maximum_inodes, preserve=()):
    bytes_used = 0
    inodes_used = 0

    def reserve_inode():
        nonlocal inodes_used
        if inodes_used >= maximum_inodes:
            fail("attempt export exceeds configured inode quota")
        inodes_used += 1

    def reserve_bytes(amount):
        nonlocal bytes_used
        if amount < 0 or bytes_used + amount > maximum_bytes:
            fail("attempt export exceeds configured byte quota")
        bytes_used += amount

    def copy_directory(source_directory_fd, destination_directory_fd):
        with os.scandir(source_directory_fd) as entries:
            names = [entry.name for entry in entries]
        for name in names:
            if name in preserve:
                continue
            info = os.stat(name, dir_fd=source_directory_fd, follow_symlinks=False)
            mode = info.st_mode & 0o777
            if stat.S_ISDIR(info.st_mode):
                reserve_inode()
                os.mkdir(name, 0o700, dir_fd=destination_directory_fd)
                source_child = os.open(name, DIRECTORY, dir_fd=source_directory_fd)
                destination_child = os.open(name, DIRECTORY, dir_fd=destination_directory_fd)
                try:
                    if not same(info, os.fstat(source_child)):
                        fail("attempt export directory changed before open")
                    copy_directory(source_child, destination_child)
                    os.fchown(destination_child, host_info.st_uid, host_info.st_gid)
                    os.fchmod(destination_child, mode)
                finally:
                    os.close(destination_child)
                    os.close(source_child)
            elif stat.S_ISREG(info.st_mode):
                reserve_inode()
                source_file = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=source_directory_fd)
                destination_file = os.open(
                    name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600,
                    dir_fd=destination_directory_fd,
                )
                try:
                    before = os.fstat(source_file)
                    if not same(info, before):
                        fail("attempt export file changed before open")
                    while True:
                        chunk = os.read(source_file, 64 * 1024)
                        if not chunk:
                            break
                        reserve_bytes(len(chunk))
                        offset = 0
                        while offset < len(chunk):
                            written = os.write(destination_file, chunk[offset:])
                            if written <= 0:
                                fail("short staging export copy")
                            offset += written
                    after = os.fstat(source_file)
                    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns):
                        fail("attempt export file changed during copy")
                    os.fchown(destination_file, host_info.st_uid, host_info.st_gid)
                    os.fchmod(destination_file, mode)
                finally:
                    os.close(destination_file)
                    os.close(source_file)
            elif stat.S_ISLNK(info.st_mode):
                reserve_inode()
                os.symlink(os.readlink(name, dir_fd=source_directory_fd), name, dir_fd=destination_directory_fd)
                os.chown(name, host_info.st_uid, host_info.st_gid, dir_fd=destination_directory_fd, follow_symlinks=False)
            else:
                fail("unsupported attempt storage entry")

    copy_directory(source_fd, destination_fd)
    return bytes_used, inodes_used

host_fd = os.open(HOST, DIRECTORY)
work_temp_fd = artifacts_temp_fd = None
try:
    host_info = os.fstat(host_fd)
    if (not stat.S_ISDIR(host_info.st_mode) or stat.S_IMODE(host_info.st_mode) != 0o700):
        fail("unexpected broker host staging root")
    marker_fd = os.open(".ctf-os-sterile-attempt", os.O_RDONLY | NOFOLLOW, dir_fd=host_fd)
    try:
        marker_info = os.fstat(marker_fd)
        if (not stat.S_ISREG(marker_info.st_mode) or marker_info.st_uid != host_info.st_uid
                or stat.S_IMODE(marker_info.st_mode) != 0o600):
            fail("unsafe broker host staging marker")
    finally:
        os.close(marker_fd)
    work_host_fd = open_host_child(host_fd, "work")
    artifacts_host_fd = open_host_child(host_fd, "artifacts")
    os.close(artifacts_host_fd)
    os.close(work_host_fd)
    try:
        work_temp_fd = create_temp(host_fd, WORK_TEMP)
        artifacts_temp_fd = create_temp(host_fd, ARTIFACTS_TEMP)
        work_source_fd = os.open("/work", DIRECTORY)
        artifacts_source_fd = os.open("/artifacts", DIRECTORY)
        try:
            copy_tree(work_source_fd, work_temp_fd, WORK_BYTES, WORK_INODES, preserve=("ctf-exec", ".ctf-os-broker"))
            copy_tree(artifacts_source_fd, artifacts_temp_fd, ARTIFACTS_BYTES, ARTIFACTS_INODES)
            os.fsync(work_temp_fd)
            os.fsync(artifacts_temp_fd)
        finally:
            os.close(artifacts_source_fd)
            os.close(work_source_fd)
    except BaseException:
        for temporary in (WORK_TEMP, ARTIFACTS_TEMP):
            try:
                remove_entry(host_fd, temporary)
            except BaseException:
                pass
        raise
finally:
    if artifacts_temp_fd is not None:
        os.close(artifacts_temp_fd)
    if work_temp_fd is not None:
        os.close(work_temp_fd)
    os.close(host_fd)
'''


class BrokerError(ValueError):
    """Raised for malformed, unauthenticated, or out-of-scope broker traffic."""


def broker_transport_supported() -> bool:
    """Return whether exact private dirfd-based spool IPC is available."""
    root: Path | None = None
    try:
        root = Path(tempfile.mkdtemp(prefix="ctf-os-broker-probe-"))
        os.chmod(root, 0o700)
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.mkdir(BROKER_IPC_DIRECTORY, 0o700, dir_fd=root_fd)
            endpoint_fd = os.open(
                BROKER_IPC_DIRECTORY,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_fd,
            )
            try:
                _write_spool_payload(endpoint_fd, "probe", b"ok", 16)
                if _consume_spool_frame(endpoint_fd, "probe", 16) != b"ok":
                    return False
            finally:
                os.close(endpoint_fd)
            os.rmdir(BROKER_IPC_DIRECTORY, dir_fd=root_fd)
        finally:
            os.close(root_fd)
        return True
    except (BrokerError, OSError):
        return False
    finally:
        if root is not None:
            try:
                root.rmdir()
            except OSError:
                pass


@dataclass(frozen=True)
class BrokerResponse:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    truncated: bool = False

    @classmethod
    def from_result(cls, result: CommandResult) -> "BrokerResponse":
        stdout, stdout_truncated = _truncate(result.stdout)
        stderr, stderr_truncated = _truncate(result.stderr)
        return cls(result.returncode, stdout, stderr, result.timed_out, result.truncated or stdout_truncated or stderr_truncated)

    def to_dict(self) -> dict[str, object]:
        return {
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "truncated": self.truncated,
        }


class AttemptCommandBroker:
    """One filesystem-spool broker bound to one attempt/container pair."""

    def __init__(
        self,
        *,
        attempt_id: str,
        container_name: str,
        workdir: str | Path,
        docker: DockerCli,
        artifacts: str | Path | None = None,
        storage_limit_bytes: int | None = None,
        storage_inode_limit: int | None = None,
        token: str | None = None,
        socket_path: str | Path | None = None,
        command_timeout_sec: float | None = None,
    ) -> None:
        _validate_identifier("attempt_id", attempt_id)
        _validate_identifier("container_name", container_name)
        self.attempt_id = attempt_id
        self.container_name = container_name
        self.workdir = Path(workdir).resolve(strict=False)
        self.artifacts = Path(artifacts).resolve(strict=False) if artifacts is not None else None
        if (storage_limit_bytes is None) != (storage_inode_limit is None):
            raise BrokerError("storage byte and inode limits must be configured together")
        if self.artifacts is None and storage_limit_bytes is not None:
            raise BrokerError("storage limits require an exact attempt artifacts directory")
        if self.artifacts is not None:
            if storage_limit_bytes is None:
                raise BrokerError("broker storage limits are required for attempt staging")
            try:
                self._storage_limits = storage_mount_limits(storage_limit_bytes, storage_inode_limit)
            except ValueError as exc:
                raise BrokerError(str(exc)) from exc
        else:
            self._storage_limits = None
        # ``socket_path`` remains as a compatibility name for callers.  It is
        # now the exact private spool directory and can never point outside
        # the sterile workdir.
        expected_endpoint = self.workdir / BROKER_IPC_DIRECTORY
        self.socket_path = Path(socket_path) if socket_path is not None else expected_endpoint
        if not self.socket_path.is_absolute() or self.socket_path != expected_endpoint:
            raise BrokerError("broker IPC endpoint must be exact attempt-local workdir storage")
        self.docker = docker
        self.command_timeout_sec = float(command_timeout_sec if command_timeout_sec is not None else docker.command_timeout_sec)
        if not 0 < self.command_timeout_sec <= 60:
            raise BrokerError("broker command timeout must be in 0..60 seconds")
        self.token = token or secrets.token_urlsafe(32)
        if len(self.token) < 32:
            raise BrokerError("broker token is too short")
        # The helper necessarily contains this capability for the duration of
        # an attempt.  Mode 0700 and the sterile workdir keep it out of other
        # UIDs, but a malicious process already running as the same host UID
        # can still read it.  The HMAC protocol prevents token disclosure in
        # spool entries; it does not claim to isolate mutually hostile same-UID
        # host processes.
        self.session_id: str | None = None
        self._workdir_fd: int | None = None
        self._ipc_dir_fd: int | None = None
        self._workdir_identity: tuple[int, int] | None = None
        self._ipc_identity: tuple[int, int] | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._command_active = threading.Event()
        self._active_cancel: threading.Event | None = None
        self._container_terminated = threading.Event()
        self._terminate_lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> "AttemptCommandBroker":
        if self.running:
            raise BrokerError("broker is already running")
        try:
            if not self.workdir.exists():
                self.workdir.mkdir(parents=True, mode=0o700)
                os.chmod(self.workdir, 0o700)
            self._workdir_fd = _open_validated_workdir(self.workdir)
            try:
                os.stat(BROKER_IPC_DIRECTORY, dir_fd=self._workdir_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise BrokerError("refusing to replace an existing broker IPC endpoint")
            os.mkdir(BROKER_IPC_DIRECTORY, 0o700, dir_fd=self._workdir_fd)
            self._ipc_dir_fd = os.open(
                BROKER_IPC_DIRECTORY,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=self._workdir_fd,
            )
            endpoint = os.fstat(self._ipc_dir_fd)
            if (not stat.S_ISDIR(endpoint.st_mode) or endpoint.st_uid != os.getuid()
                    or stat.S_IMODE(endpoint.st_mode) != 0o700):
                raise BrokerError("broker IPC endpoint has unsafe ownership or mode")
            work = os.fstat(self._workdir_fd)
            self._workdir_identity = (work.st_dev, work.st_ino)
            self._ipc_identity = (endpoint.st_dev, endpoint.st_ino)
            self.session_id = secrets.token_hex(16)
            _write_spool_frame(self._ipc_dir_fd, _SESSION_NAME, _signed_message(self.token, {
                "session_id": self.session_id,
                "attempt_id": self.attempt_id,
            }), MAX_BROKER_RESPONSE_BYTES)
        except BaseException:
            self._close_transport(remove_endpoint=True)
            raise
        self._stop.clear()
        self._container_terminated.clear()
        self._thread = threading.Thread(target=self._serve, name=f"ctf-os-broker-{self.attempt_id}", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        """Cancel brokered work, kill this attempt container, and join."""
        self._stop.set()
        active_cancel = self._active_cancel
        if active_cancel is not None:
            active_cancel.set()
        self._publish_stop_marker()
        if self._command_active.is_set():
            self._terminate_container()
        if self._thread is not None:
            self._thread.join()
        self._thread = None
        self._close_transport(remove_endpoint=True)

    def __enter__(self) -> "AttemptCommandBroker":
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.stop()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                self._validate_transport_identity()
                requests = self._request_names()
            except (BrokerError, OSError):
                self._stop.set()
                return
            for name, session_id, request_id in requests:
                if self._stop.is_set():
                    return
                if session_id != self.session_id:
                    # A helper from an earlier broker lifetime cannot receive
                    # or influence the current session.
                    try:
                        _consume_spool_frame(self._require_ipc_fd(), name, MAX_BROKER_MESSAGE_BYTES)
                    except (BrokerError, OSError):
                        pass
                    continue
                try:
                    payload = _consume_spool_frame(
                        self._require_ipc_fd(), name, MAX_BROKER_MESSAGE_BYTES,
                    )
                    command, deadline_ns = self._validate_request(
                        payload, session_id=session_id, request_id=request_id,
                    )
                    if self._stop.is_set():
                        raise BrokerError("broker is stopping")
                    request_cancel = threading.Event()
                    self._active_cancel = request_cancel
                    watcher_done = threading.Event()
                    watcher = threading.Thread(
                        target=self._watch_request,
                        args=(session_id, request_id, deadline_ns, request_cancel, watcher_done),
                        name=f"ctf-os-broker-cancel-{request_id}", daemon=True,
                    )
                    watcher.start()
                    self._command_active.set()
                    try:
                        self._sync_staging_to_container()
                        result = self.docker.exec(
                            build_docker_exec_argv(self.container_name, command, docker_command=self.docker.command),
                            timeout_sec=min(
                                self.command_timeout_sec,
                                max(0.001, (deadline_ns - time.monotonic_ns()) / 1_000_000_000),
                            ),
                            cancel_event=request_cancel,
                        )
                        if not result.timed_out and not request_cancel.is_set() and not self._stop.is_set():
                            self._sync_container_to_staging()
                    finally:
                        self._command_active.clear()
                        watcher_done.set()
                        watcher.join()
                        self._active_cancel = None
                    if result.timed_out or request_cancel.is_set() or self._stop.is_set():
                        self._terminate_container()
                    if self._stop.is_set():
                        raise BrokerError("broker is stopping")
                    response = _signed_message(self.token, {
                        "session_id": session_id,
                        "request_id": request_id,
                        "ok": True,
                        "result": BrokerResponse.from_result(result).to_dict(),
                    })
                except (BrokerError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    response = _signed_message(self.token, {
                        "session_id": session_id,
                        "request_id": request_id,
                        "ok": False,
                        "error": str(exc),
                    })
                try:
                    _write_spool_frame(
                        self._require_ipc_fd(), f"response-{session_id}-{request_id}", response,
                        MAX_BROKER_RESPONSE_BYTES,
                    )
                except (BrokerError, OSError):
                    # A vanished or replaced endpoint means no authenticated
                    # client can receive this result.  Stop this broker rather
                    # than continuing on an ambiguous transport.
                    self._stop.set()
                    return
                if self._stop.is_set():
                    return
            self._stop.wait(_POLL_INTERVAL_SEC)

    def _request_names(self) -> tuple[tuple[str, str, str], ...]:
        with os.scandir(self._require_ipc_fd()) as entries:
            names = sorted(entry.name for entry in entries)
        requests: list[tuple[str, str, str]] = []
        spool_bytes = 0
        for name in names:
            try:
                details = os.stat(name, dir_fd=self._require_ipc_fd(), follow_symlinks=False)
            except FileNotFoundError:
                # A client may atomically publish, consume, or remove an
                # unrelated malformed spool entry after the directory snapshot.
                # Treat this exact name as a benign per-entry race; the
                # descriptor-backed endpoint and all remaining entries still
                # receive their normal validation below.
                continue
            except OSError as exc:
                raise BrokerError("broker spool entry could not be inspected safely") from exc
            if stat.S_ISDIR(details.st_mode):
                raise BrokerError("broker spool contains an unexpected directory")
            spool_bytes += details.st_size
            matched = _REQUEST_NAME.fullmatch(name)
            if matched:
                requests.append((name, matched.group(1), matched.group(2)))
        if spool_bytes > MAX_BROKER_SPOOL_BYTES:
            raise BrokerError("broker spool exceeds its total byte limit")
        current = sum(session_id == self.session_id for _, session_id, _ in requests)
        if current > MAX_PENDING_BROKER_REQUESTS:
            raise BrokerError("broker pending request queue exceeds its limit")
        return tuple(requests)

    def _watch_request(
        self,
        session_id: str,
        request_id: str,
        deadline_ns: int,
        cancel_event: threading.Event,
        done: threading.Event,
    ) -> None:
        cancel_name = f"cancel-{session_id}-{request_id}"
        while not done.wait(_POLL_INTERVAL_SEC):
            if self._stop.is_set() or time.monotonic_ns() >= deadline_ns:
                cancel_event.set()
                return
            try:
                payload = _consume_spool_frame(
                    self._require_ipc_fd(), cancel_name, MAX_BROKER_MESSAGE_BYTES,
                )
            except FileNotFoundError:
                continue
            except (BrokerError, OSError):
                # A malformed cancellation or replaced endpoint is not safe
                # to ignore while a privileged host action is in progress.
                cancel_event.set()
                return
            try:
                cancel = _verify_signed_message(self.token, payload)
                if (cancel.get("session_id") != session_id
                        or cancel.get("request_id") != request_id
                        or cancel.get("attempt_id") != self.attempt_id
                        or cancel.get("cancelled") is not True):
                    raise BrokerError("broker cancellation identity is invalid")
            except BrokerError:
                cancel_event.set()
                return
            cancel_event.set()
            return

    def _publish_stop_marker(self) -> None:
        if self._ipc_dir_fd is None or self.session_id is None:
            return
        marker = _signed_message(self.token, {
            "session_id": self.session_id,
            "attempt_id": self.attempt_id,
            "stopped": True,
        })
        try:
            _write_spool_frame(self._ipc_dir_fd, _STOP_NAME, marker, MAX_BROKER_RESPONSE_BYTES)
        except (BrokerError, OSError):
            # Endpoint disappearance is independently detected by clients.
            pass

    def _require_ipc_fd(self) -> int:
        if self._ipc_dir_fd is None:
            raise BrokerError("broker IPC endpoint is unavailable")
        return self._ipc_dir_fd

    def _validate_transport_identity(self) -> None:
        if self._workdir_fd is None or self._ipc_dir_fd is None:
            raise BrokerError("broker IPC descriptors are unavailable")
        work_path = os.stat(self.workdir, follow_symlinks=False)
        endpoint_path = os.stat(
            BROKER_IPC_DIRECTORY, dir_fd=self._workdir_fd, follow_symlinks=False,
        )
        work_fd = os.fstat(self._workdir_fd)
        endpoint_fd = os.fstat(self._ipc_dir_fd)
        if ((work_path.st_dev, work_path.st_ino) != self._workdir_identity
                or (work_fd.st_dev, work_fd.st_ino) != self._workdir_identity):
            raise BrokerError("attempt workdir changed during broker lifetime")
        if ((endpoint_path.st_dev, endpoint_path.st_ino) != self._ipc_identity
                or (endpoint_fd.st_dev, endpoint_fd.st_ino) != self._ipc_identity
                or not stat.S_ISDIR(endpoint_fd.st_mode)
                or endpoint_fd.st_uid != os.getuid()
                or stat.S_IMODE(endpoint_fd.st_mode) != 0o700):
            raise BrokerError("broker IPC endpoint changed during broker lifetime")

    def _close_transport(self, *, remove_endpoint: bool) -> None:
        cleanup_error: BrokerError | None = None
        ipc_fd, self._ipc_dir_fd = self._ipc_dir_fd, None
        work_fd, self._workdir_fd = self._workdir_fd, None
        if ipc_fd is not None:
            if remove_endpoint:
                try:
                    _clear_spool_directory(ipc_fd)
                except BrokerError as exc:
                    cleanup_error = exc
            os.close(ipc_fd)
        if remove_endpoint and work_fd is not None:
            try:
                details = os.stat(BROKER_IPC_DIRECTORY, dir_fd=work_fd, follow_symlinks=False)
                if self._ipc_identity == (details.st_dev, details.st_ino) and stat.S_ISDIR(details.st_mode):
                    os.rmdir(BROKER_IPC_DIRECTORY, dir_fd=work_fd)
            except OSError as exc:
                if cleanup_error is None:
                    cleanup_error = BrokerError("broker IPC endpoint cleanup was incomplete")
        if work_fd is not None:
            os.close(work_fd)
        self._workdir_identity = None
        self._ipc_identity = None
        if cleanup_error is not None:
            raise cleanup_error

    def _terminate_container(self) -> None:
        with self._terminate_lock:
            if self._container_terminated.is_set():
                return
            self._container_terminated.set()
        try:
            self.docker.remove(self.container_name)
        except (OSError, RuntimeError, ValueError):
            pass

    @property
    def _uses_storage_mirror(self) -> bool:
        return self.artifacts is not None and self._storage_limits is not None

    def _sync_staging_to_container(self) -> None:
        """Import one bounded host snapshot into ctf-owned tmpfs roots."""
        if not self._uses_storage_mirror:
            return
        assert self.artifacts is not None and self._storage_limits is not None
        self._validate_staging()
        work_bytes, artifact_bytes, work_inodes, artifact_inodes = self._storage_limits
        _enforce_host_tree_limit(self.workdir, work_bytes, work_inodes, "work")
        _enforce_host_tree_limit(self.artifacts, artifact_bytes, artifact_inodes, "artifacts")
        self._run_fixed("ctf", _CTF_TMPFS_SCRUB_PROGRAM, "clearing active attempt storage")
        self._run_fixed("root", _ROOT_IMPORT_STAGING_PROGRAM, "importing bounded host staging")

    def _sync_container_to_staging(self) -> None:
        """Export a bounded temp snapshot, validate it, then commit it safely."""
        if not self._uses_storage_mirror:
            return
        assert self.artifacts is not None and self._storage_limits is not None
        self._validate_staging()
        work_bytes, artifact_bytes, work_inodes, artifact_inodes = self._storage_limits
        nonce = secrets.token_hex(16)
        work_temp = f".ctf-os-export-work-{nonce}"
        artifacts_temp = f".ctf-os-export-artifacts-{nonce}"
        program = _build_root_export_program(
            work_temp=work_temp,
            artifacts_temp=artifacts_temp,
            work_bytes=work_bytes,
            artifact_bytes=artifact_bytes,
            work_inodes=work_inodes,
            artifact_inodes=artifact_inodes,
        )
        try:
            self._run_fixed("root", program, "exporting bounded attempt storage")
            _commit_bounded_export(
                self.workdir,
                self.artifacts,
                work_temp=work_temp,
                artifacts_temp=artifacts_temp,
                work_bytes=work_bytes,
                artifact_bytes=artifact_bytes,
                work_inodes=work_inodes,
                artifact_inodes=artifact_inodes,
            )
        finally:
            # The container program also reclaims failed copies, but this
            # parent-side pass covers a Docker interruption after a sibling was
            # created and before the program's own cleanup could run.
            _discard_export_siblings(self.workdir, (work_temp, artifacts_temp))

    def _validate_staging(self) -> None:
        assert self.artifacts is not None
        try:
            staging = ArtifactWriter.staging_for_workdir(self.workdir)
        except ValueError as exc:
            raise BrokerError(f"attempt storage staging is unsafe: {exc}") from exc
        if staging.artifacts != self.artifacts:
            raise BrokerError("attempt storage artifacts are not exact private staging")

    def _run_fixed(self, user: str, program: str, phase: str) -> None:
        cancel_event = self._active_cancel or self._stop
        result = self.docker.exec(
            [self.docker.command, "exec", "--user", user, "-w", "/", self.container_name,
             "/usr/bin/python3", "-I", "-c", program],
            timeout_sec=self.command_timeout_sec, cancel_event=cancel_event,
        )
        if not result.ok:
            raise BrokerError(_storage_error(phase, result))


    def _validate_request(
        self, payload: bytes, *, session_id: str, request_id: str,
    ) -> tuple[tuple[str, ...], int]:
        request = _verify_signed_message(self.token, payload)
        if request.get("session_id") != session_id or request.get("request_id") != request_id:
            raise BrokerError("broker request identity does not match its spool name")
        if request.get("attempt_id") != self.attempt_id:
            raise BrokerError("broker request is for a different attempt")
        deadline_ns = request.get("deadline_ns")
        now_ns = time.monotonic_ns()
        if (not isinstance(deadline_ns, int) or isinstance(deadline_ns, bool)
                or deadline_ns <= now_ns
                or deadline_ns > now_ns + int(61 * 1_000_000_000)):
            raise BrokerError("broker request deadline is expired or unbounded")
        argv = request.get("argv")
        if not isinstance(argv, list) or not argv or len(argv) > MAX_COMMAND_ARGUMENTS:
            raise BrokerError("broker argv must be a non-empty bounded array")
        validated: list[str] = []
        for index, item in enumerate(argv):
            if not isinstance(item, str) or not item or len(item.encode("utf-8")) > MAX_COMMAND_ARGUMENT_BYTES:
                raise BrokerError("broker argv contains an invalid or oversized argument")
            if any(ord(character) < 32 or ord(character) == 127 for character in item):
                raise BrokerError("broker argv contains a control character")
            if index == 0 and item.startswith("-"):
                raise BrokerError("broker command must not start with '-'")
            validated.append(item)
        return tuple(validated), deadline_ns


def create_ctf_exec_helper(path: str | Path, *, broker: AttemptCommandBroker) -> Path:
    """Write the only solver-facing command entry point into its exact cwd."""

    helper_path = Path(path)
    if not broker.running or broker.session_id is None:
        raise BrokerError("ctf-exec requires a running broker session")
    if helper_path.parent.resolve(strict=False) != broker.workdir:
        raise BrokerError("ctf-exec must be placed in the exact Codex workdir")
    source = _helper_source(
        broker.socket_path, broker.attempt_id, broker.session_id,
        broker.token, broker.command_timeout_sec,
    )
    workdir_fd = _open_validated_workdir(broker.workdir)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            "ctf-exec",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o700,
            dir_fd=workdir_fd,
        )
        encoded = source.encode("utf-8")
        _write_all(descriptor, encoded)
        os.fchmod(descriptor, 0o700)
        os.fsync(descriptor)
        details = os.fstat(descriptor)
        if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid()
                or stat.S_IMODE(details.st_mode) != 0o700 or details.st_nlink != 1):
            raise BrokerError("ctf-exec helper has unsafe ownership, mode, or links")
    except FileExistsError as exc:
        raise BrokerError("refusing to replace an existing ctf-exec helper") from exc
    except BaseException:
        try:
            os.unlink("ctf-exec", dir_fd=workdir_fd)
        except OSError:
            pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(workdir_fd)
    return helper_path


def send_broker_request(
    socket_path: str | Path,
    *,
    attempt_id: str,
    token: str,
    argv: Sequence[str],
    timeout_sec: float = 30.0,
) -> BrokerResponse:
    """Filesystem-spool client used by tests and generated ``ctf-exec``."""

    if not 0 < timeout_sec <= 60:
        raise BrokerError("broker timeout must be in 0..60 seconds")
    endpoint_path = Path(socket_path)
    endpoint_fd = _open_validated_endpoint(endpoint_path)
    request_id = secrets.token_hex(16)
    raw: bytes | None = None
    try:
        session = _verify_signed_message(
            token, _read_spool_frame(endpoint_fd, _SESSION_NAME, MAX_BROKER_RESPONSE_BYTES),
        )
        session_id = session.get("session_id")
        if session.get("attempt_id") != attempt_id:
            raise BrokerError("broker session is for a different attempt")
        if not isinstance(session_id, str) or not re.fullmatch(r"[0-9a-f]{32}", session_id):
            raise BrokerError("broker session identity is invalid")
        deadline_ns = time.monotonic_ns() + int(timeout_sec * 1_000_000_000)
        request = _signed_message(token, {
            "session_id": session_id,
            "request_id": request_id,
            "attempt_id": attempt_id,
            "deadline_ns": deadline_ns,
            "argv": list(argv),
        })
        request_payload = _canonical_json(request)
        if len(request_payload) > MAX_BROKER_MESSAGE_BYTES:
            raise BrokerError("broker request exceeds the message limit")
        request_name = f"request-{session_id}-{request_id}"
        response_name = f"response-{session_id}-{request_id}"
        cancel_name = f"cancel-{session_id}-{request_id}"
        _write_spool_payload(endpoint_fd, request_name, request_payload, MAX_BROKER_MESSAGE_BYTES)
        deadline = time.monotonic() + timeout_sec
        while True:
            try:
                raw = _read_spool_frame(endpoint_fd, response_name, MAX_BROKER_RESPONSE_BYTES)
            except FileNotFoundError:
                if _broker_stopped(endpoint_path, endpoint_fd, token, session_id, attempt_id):
                    raise BrokerError("broker stopped before returning a response")
                if time.monotonic() >= deadline:
                    cancel = _signed_message(token, {
                        "session_id": session_id,
                        "request_id": request_id,
                        "attempt_id": attempt_id,
                        "cancelled": True,
                    })
                    try:
                        _write_spool_frame(endpoint_fd, cancel_name, cancel, MAX_BROKER_MESSAGE_BYTES)
                    except (BrokerError, OSError):
                        pass
                    raise BrokerError("broker response timed out")
                time.sleep(_POLL_INTERVAL_SEC)
                continue
            _safe_unlink_spool_entry(endpoint_fd, response_name)
            break
    finally:
        os.close(endpoint_fd)
    assert raw is not None
    response = _verify_signed_message(token, raw)
    if (response.get("session_id") != session_id or response.get("request_id") != request_id
            or response.get("ok") is not True or not isinstance(response.get("result"), dict)):
        raise BrokerError(str(response.get("error", "broker rejected command")))
    result = response["result"]
    return BrokerResponse(
        returncode=int(result.get("returncode", 1)),
        stdout=str(result.get("stdout", "")),
        stderr=str(result.get("stderr", "")),
        timed_out=bool(result.get("timed_out", False)),
        truncated=bool(result.get("truncated", False)),
    )


def _helper_source(
    socket_path: Path, attempt_id: str, session_id: str, token: str, timeout_sec: float,
) -> str:
    # JSON literals make token/path embedding independent of shell quoting.
    return f'''#!/usr/bin/env python3
import ctypes
import errno
import hashlib
import hmac
import json
import os
import secrets
import stat
import struct
import sys
import time

ENDPOINT_PATH = {json.dumps(str(socket_path))}
ATTEMPT_ID = {json.dumps(attempt_id)}
SESSION_ID = {json.dumps(session_id)}
TOKEN = {json.dumps(token)}
MAX_BYTES = {MAX_BROKER_MESSAGE_BYTES}
MAX_RESPONSE_BYTES = {MAX_BROKER_RESPONSE_BYTES}
TIMEOUT_SEC = {timeout_sec!r}
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW
RENAME_NOREPLACE = 1

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

def signed(value):
    result = dict(value)
    result["hmac"] = hmac.new(TOKEN.encode("utf-8"), canonical(value), hashlib.sha256).hexdigest()
    return result

def verified(payload):
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("broker message is not UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeError("broker message is not an object")
    digest = value.pop("hmac", None)
    expected = hmac.new(TOKEN.encode("utf-8"), canonical(value), hashlib.sha256).hexdigest()
    if not isinstance(digest, str) or not hmac.compare_digest(digest, expected):
        raise RuntimeError("broker message authentication failed")
    return value

def write_all(fd, value):
    offset = 0
    while offset < len(value):
        written = os.write(fd, value[offset:])
        if written <= 0:
            raise RuntimeError("short broker spool write")
        offset += written

def validate_file(details, maximum):
    if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid()
            or stat.S_IMODE(details.st_mode) != 0o600 or details.st_nlink != 1
            or details.st_size < 5 or details.st_size > maximum + 4):
        raise RuntimeError("unsafe broker spool file")

def read_frame(directory_fd, name, maximum):
    before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    validate_file(before, maximum)
    fd = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=directory_fd)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError("broker spool file changed before open")
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                raise RuntimeError("partial broker spool frame")
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(fd)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if ((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                or (current.st_dev, current.st_ino, current.st_size) != (before.st_dev, before.st_ino, before.st_size)):
            raise RuntimeError("broker spool file changed during read")
    finally:
        os.close(fd)
    size = struct.unpack("!I", raw[:4])[0]
    if size == 0 or size > maximum or len(raw) != size + 4:
        raise RuntimeError("invalid broker spool frame")
    return raw[4:]

def write_frame(directory_fd, name, payload, maximum):
    if not payload or len(payload) > maximum:
        raise RuntimeError("broker spool payload is invalid")
    temporary = ".tmp-" + secrets.token_hex(16)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600, dir_fd=directory_fd)
    try:
        write_all(fd, struct.pack("!I", len(payload)) + payload)
        os.fchmod(fd, 0o600)
        os.fsync(fd)
        details = os.fstat(fd)
        validate_file(details, maximum)
    finally:
        os.close(fd)
    try:
        try:
            renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
        except AttributeError as exc:
            raise RuntimeError("atomic no-overwrite spool publish is unsupported") from exc
        renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        renameat2.restype = ctypes.c_int
        result = renameat2(
            directory_fd, os.fsencode(temporary), directory_fd, os.fsencode(name), RENAME_NOREPLACE,
        )
        if result != 0:
            error = ctypes.get_errno()
            if error == errno.EEXIST:
                raise FileExistsError(error, os.strerror(error), name)
            raise RuntimeError("atomic broker spool publish failed: " + os.strerror(error))
        os.fsync(directory_fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
            os.fsync(directory_fd)
        except FileNotFoundError:
            pass

def endpoint_current(directory_fd, identity):
    try:
        path = os.stat(ENDPOINT_PATH, follow_symlinks=False)
        opened = os.fstat(directory_fd)
    except FileNotFoundError:
        return False
    return (path.st_dev, path.st_ino) == identity == (opened.st_dev, opened.st_ino)

def stopped(directory_fd):
    try:
        message = verified(read_frame(directory_fd, "stopped", MAX_RESPONSE_BYTES))
    except FileNotFoundError:
        return False
    return (message.get("session_id") == SESSION_ID
            and message.get("attempt_id") == ATTEMPT_ID
            and message.get("stopped") is True)

if len(sys.argv) < 2 or sys.argv[1].startswith("-"):
    print("usage: ctf-exec PROGRAM [ARG ...]", file=sys.stderr)
    raise SystemExit(64)
request_id = secrets.token_hex(16)
deadline_ns = time.monotonic_ns() + int(TIMEOUT_SEC * 1_000_000_000)
request = canonical(signed({{
    "session_id": SESSION_ID,
    "request_id": request_id,
    "attempt_id": ATTEMPT_ID,
    "deadline_ns": deadline_ns,
    "argv": sys.argv[1:],
}}))
if len(request) > MAX_BYTES:
    print("ctf-exec: command is too large", file=sys.stderr)
    raise SystemExit(64)
endpoint_fd = os.open(ENDPOINT_PATH, DIRECTORY)
try:
    endpoint = os.fstat(endpoint_fd)
    if (not stat.S_ISDIR(endpoint.st_mode) or endpoint.st_uid != os.getuid()
            or stat.S_IMODE(endpoint.st_mode) != 0o700):
        raise RuntimeError("unsafe broker IPC endpoint")
    endpoint_identity = (endpoint.st_dev, endpoint.st_ino)
    session = verified(read_frame(endpoint_fd, "session", MAX_RESPONSE_BYTES))
    if session.get("session_id") != SESSION_ID or session.get("attempt_id") != ATTEMPT_ID:
        raise RuntimeError("stale broker helper session")
    request_name = "request-" + SESSION_ID + "-" + request_id
    response_name = "response-" + SESSION_ID + "-" + request_id
    cancel_name = "cancel-" + SESSION_ID + "-" + request_id
    write_frame(endpoint_fd, request_name, request, MAX_BYTES)
    deadline = time.monotonic() + TIMEOUT_SEC
    while True:
        try:
            raw = read_frame(endpoint_fd, response_name, MAX_RESPONSE_BYTES)
        except FileNotFoundError:
            if not endpoint_current(endpoint_fd, endpoint_identity) or stopped(endpoint_fd):
                raise RuntimeError("broker stopped before returning a response")
            if time.monotonic() >= deadline:
                cancel = canonical(signed({{
                    "session_id": SESSION_ID,
                    "request_id": request_id,
                    "attempt_id": ATTEMPT_ID,
                    "cancelled": True,
                }}))
                try:
                    write_frame(endpoint_fd, cancel_name, cancel, MAX_BYTES)
                except (FileExistsError, OSError, RuntimeError):
                    pass
                raise RuntimeError("broker response timed out")
            time.sleep({_POLL_INTERVAL_SEC!r})
            continue
        os.unlink(response_name, dir_fd=endpoint_fd)
        break
finally:
    os.close(endpoint_fd)
response = verified(raw)
if response.get("session_id") != SESSION_ID or response.get("request_id") != request_id:
    raise RuntimeError("broker response identity mismatch")
if not response.get("ok"):
    print("ctf-exec: " + str(response.get("error", "request rejected")), file=sys.stderr)
    raise SystemExit(126)
result = response["result"]
if result.get("stdout"):
    sys.stdout.write(result["stdout"])
if result.get("stderr"):
    sys.stderr.write(result["stderr"])
raise SystemExit(int(result.get("returncode", 1)))
'''


def _open_validated_workdir(path: Path) -> int:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise BrokerError("attempt workdir is unavailable or unsafe") from exc
    details = os.fstat(descriptor)
    if (not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid()
            or stat.S_IMODE(details.st_mode) not in {0o700, 0o1777}):
        os.close(descriptor)
        raise BrokerError("attempt workdir has unsafe ownership or mode")
    return descriptor


def _canonical_json(value: dict[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _signed_message(token: str, value: dict[str, object]) -> dict[str, object]:
    message = dict(value)
    message["hmac"] = hmac.new(
        token.encode("utf-8"), _canonical_json(value), hashlib.sha256,
    ).hexdigest()
    return message


def _verify_signed_message(token: str, payload: bytes) -> dict[str, Any]:
    try:
        message = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrokerError("broker message must be UTF-8 JSON") from exc
    if not isinstance(message, dict):
        raise BrokerError("broker message must be a JSON object")
    digest = message.pop("hmac", None)
    expected = hmac.new(
        token.encode("utf-8"), _canonical_json(message), hashlib.sha256,
    ).hexdigest()
    if not isinstance(digest, str) or not hmac.compare_digest(digest, expected):
        raise BrokerError("broker message authentication failed")
    return message


def _broker_stopped(
    endpoint_path: Path,
    endpoint_fd: int,
    token: str,
    session_id: str,
    attempt_id: str,
) -> bool:
    try:
        path_info = os.stat(endpoint_path, follow_symlinks=False)
        opened = os.fstat(endpoint_fd)
    except OSError:
        return True
    if ((path_info.st_dev, path_info.st_ino) != (opened.st_dev, opened.st_ino)
            or not stat.S_ISDIR(path_info.st_mode)):
        return True
    try:
        payload = _read_spool_frame(endpoint_fd, _STOP_NAME, MAX_BROKER_RESPONSE_BYTES)
    except FileNotFoundError:
        return False
    except (BrokerError, OSError):
        return True
    try:
        marker = _verify_signed_message(token, payload)
    except BrokerError:
        return True
    return (marker.get("session_id") == session_id
            and marker.get("attempt_id") == attempt_id
            and marker.get("stopped") is True)


def _open_validated_endpoint(path: Path) -> int:
    if not path.is_absolute() or path.name != BROKER_IPC_DIRECTORY:
        raise BrokerError("broker IPC endpoint must be exact attempt-local storage")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise BrokerError("broker IPC endpoint is unavailable or unsafe") from exc
    details = os.fstat(descriptor)
    if (not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid()
            or stat.S_IMODE(details.st_mode) != 0o700):
        os.close(descriptor)
        raise BrokerError("broker IPC endpoint has unsafe ownership or mode")
    return descriptor


def _write_spool_frame(directory_fd: int, name: str, value: dict[str, object], maximum: int) -> None:
    payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
    _write_spool_payload(directory_fd, name, payload, maximum)


def _rename_noreplace(directory_fd: int, source: str, destination: str) -> None:
    """Atomically publish one complete inode without an overwrite window."""

    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as exc:
        raise BrokerError("atomic no-overwrite spool publish is unsupported") from exc
    renameat2.argtypes = (
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        directory_fd, os.fsencode(source), directory_fd, os.fsencode(destination),
        _RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise FileExistsError(error, os.strerror(error), destination)
    raise BrokerError(f"atomic broker spool publish failed: {os.strerror(error)}")


def _write_spool_payload(directory_fd: int, name: str, payload: bytes, maximum: int) -> None:
    if not payload or len(payload) > maximum:
        raise BrokerError("broker spool payload is invalid or exceeds the limit")
    temporary = f".tmp-{secrets.token_hex(16)}"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        _write_all(descriptor, struct.pack("!I", len(payload)) + payload)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        _validate_spool_stat(os.fstat(descriptor), maximum)
        _rename_noreplace(directory_fd, temporary, name)
        os.fsync(directory_fd)
    except FileExistsError as exc:
        raise BrokerError("broker spool destination already exists") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
            os.fsync(directory_fd)
        except FileNotFoundError:
            pass


def _consume_spool_frame(directory_fd: int, name: str, maximum: int) -> bytes:
    try:
        return _read_spool_frame(directory_fd, name, maximum)
    finally:
        _safe_unlink_spool_entry(directory_fd, name)


def _read_spool_frame(directory_fd: int, name: str, maximum: int) -> bytes:
    before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    _validate_spool_stat(before, maximum)
    try:
        descriptor = os.open(
            name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd,
        )
    except OSError as exc:
        raise BrokerError("broker spool file could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise BrokerError("broker spool file changed before open")
        raw = _read_exact_file(descriptor, before.st_size)
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if ((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                or (current.st_dev, current.st_ino, current.st_size)
                != (before.st_dev, before.st_ino, before.st_size)):
            raise BrokerError("broker spool file changed during read")
    finally:
        os.close(descriptor)
    length = struct.unpack("!I", raw[:4])[0]
    if length == 0 or length > maximum or len(raw) != length + 4:
        raise BrokerError("broker spool frame is partial, invalid, or oversized")
    return raw[4:]


def _validate_spool_stat(details: os.stat_result, maximum: int) -> None:
    if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid()
            or stat.S_IMODE(details.st_mode) != 0o600 or details.st_nlink != 1
            or details.st_size < 5 or details.st_size > maximum + 4):
        raise BrokerError("broker spool entry has unsafe type, owner, mode, links, or size")


def _read_exact_file(descriptor: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            raise BrokerError("broker spool file ended before its declared size")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _write_all(descriptor: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        written = os.write(descriptor, value[offset:])
        if written <= 0:
            raise BrokerError("broker spool write was incomplete")
        offset += written


def _safe_unlink_spool_entry(directory_fd: int, name: str) -> None:
    try:
        details = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(details.st_mode):
        raise BrokerError("broker spool contains an unexpected directory")
    try:
        os.unlink(name, dir_fd=directory_fd)
    except FileNotFoundError:
        return


def _clear_spool_directory(directory_fd: int) -> None:
    """Reap exact entries without ever traversing an unexpected object.

    Cleanup must not stop at the first hostile entry: a symlink or malformed
    file is unlinked through the already-open private directory, while an
    unexpected non-empty directory is retained as a diagnostic rather than
    descended into.  The caller still receives a visible cleanup error after
    all safe exact removals have been attempted.
    """
    with os.scandir(directory_fd) as entries:
        names = [entry.name for entry in entries]
    diagnostic: str | None = None
    for name in names:
        try:
            details = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        expected = (
            stat.S_ISREG(details.st_mode)
            and details.st_uid == os.getuid()
            and stat.S_IMODE(details.st_mode) == 0o600
            and details.st_nlink == 1
        )
        if stat.S_ISDIR(details.st_mode):
            try:
                # Never recurse into an unexpected directory.  An empty one
                # can be removed exactly; a non-empty one remains visible for
                # diagnosis and causes the endpoint rmdir to fail closed.
                os.rmdir(name, dir_fd=directory_fd)
            except FileNotFoundError:
                continue
            except OSError:
                diagnostic = diagnostic or "broker spool retained an unexpected directory"
            else:
                diagnostic = diagnostic or "broker spool removed an unexpected directory"
            continue
        try:
            # unlinkat removes a symlink itself and never follows its target.
            os.unlink(name, dir_fd=directory_fd)
        except FileNotFoundError:
            continue
        except OSError as exc:
            diagnostic = diagnostic or f"broker spool entry cleanup failed: {exc}"
            continue
        if not expected:
            diagnostic = diagnostic or "broker spool removed an unsafe entry"
    try:
        os.fsync(directory_fd)
    except OSError as exc:
        raise BrokerError("broker spool cleanup could not be synchronized") from exc
    if diagnostic is not None:
        raise BrokerError(diagnostic)


def _validate_identifier(name: str, value: str) -> None:
    if not isinstance(value, str) or not value or value.startswith("-") or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise BrokerError(f"{name} is invalid")


_EXPORT_SIBLING_NAME = re.compile(r"^\.ctf-os-(?:export|backup)-(?:work|artifacts)-[0-9a-f]{32}$")
_RENAME_EXCHANGE = 2
_WORK_CONTROLS = frozenset({"ctf-exec", BROKER_IPC_DIRECTORY})


def _build_root_export_program(
    *,
    work_temp: str,
    artifacts_temp: str,
    work_bytes: int,
    artifact_bytes: int,
    work_inodes: int,
    artifact_inodes: int,
) -> str:
    """Bind broker-only names and limits into the fixed root export program."""
    for name in (work_temp, artifacts_temp):
        if not _EXPORT_SIBLING_NAME.fullmatch(name):
            raise BrokerError("broker export sibling name is invalid")
    values = (work_bytes, artifact_bytes, work_inodes, artifact_inodes)
    if any(not isinstance(value, int) or value < 1 for value in values):
        raise BrokerError("broker export limits are invalid")
    return (
        _ROOT_EXPORT_TO_TEMP_PROGRAM
        .replace("__WORK_TEMP__", repr(work_temp))
        .replace("__ARTIFACTS_TEMP__", repr(artifacts_temp))
        .replace("__WORK_BYTES__", str(work_bytes))
        .replace("__ARTIFACTS_BYTES__", str(artifact_bytes))
        .replace("__WORK_INODES__", str(work_inodes))
        .replace("__ARTIFACTS_INODES__", str(artifact_inodes))
    )


def _open_broker_staging_root(workdir: Path) -> int:
    """Open the exact marker-backed parent without trusting resolved paths."""
    try:
        staging = ArtifactWriter.staging_for_workdir(workdir)
    except ValueError as exc:
        raise BrokerError(f"attempt storage staging is unsafe: {exc}") from exc
    try:
        root_fd = os.open(staging.root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise BrokerError("attempt storage root is unavailable or unsafe") from exc
    try:
        root = os.fstat(root_fd)
        if (not stat.S_ISDIR(root.st_mode) or root.st_uid != os.getuid()
                or stat.S_IMODE(root.st_mode) != 0o700):
            raise BrokerError("attempt storage root has unsafe ownership or mode")
        marker_fd = os.open(
            ".ctf-os-sterile-attempt", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_fd,
        )
        try:
            marker = os.fstat(marker_fd)
            if (not stat.S_ISREG(marker.st_mode) or marker.st_uid != os.getuid()
                    or stat.S_IMODE(marker.st_mode) != 0o600):
                raise BrokerError("attempt storage marker is unsafe")
        finally:
            os.close(marker_fd)
    except BaseException:
        os.close(root_fd)
        raise
    return root_fd


def _open_staging_child(root_fd: int, name: str, label: str) -> int:
    try:
        descriptor = os.open(
            name, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=root_fd,
        )
    except OSError as exc:
        raise BrokerError(f"attempt {label} staging child is unavailable or unsafe") from exc
    try:
        _validate_host_staging_directory(descriptor, label)
        entry = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        opened = os.fstat(descriptor)
        if (entry.st_dev, entry.st_ino) != (opened.st_dev, opened.st_ino):
            raise BrokerError(f"attempt {label} staging child changed during open")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _enforce_host_tree_limit_fd(
    directory_fd: int, maximum_bytes: int, maximum_inodes: int, label: str,
) -> None:
    bytes_used, inodes_used = _tree_usage(directory_fd)
    if bytes_used > maximum_bytes or inodes_used > maximum_inodes:
        raise BrokerError(
            f"attempt {label} storage exceeds its configured quota "
            f"({bytes_used}/{maximum_bytes} bytes, {inodes_used}/{maximum_inodes} inodes)"
        )


def _directory_names(directory_fd: int) -> tuple[str, ...]:
    try:
        with os.scandir(directory_fd) as entries:
            return tuple(sorted(entry.name for entry in entries))
    except OSError as exc:
        raise BrokerError("attempt storage directory could not be enumerated safely") from exc


def _create_export_sibling(root_fd: int, name: str) -> None:
    if not _EXPORT_SIBLING_NAME.fullmatch(name):
        raise BrokerError("broker export sibling name is invalid")
    try:
        os.mkdir(name, 0o700, dir_fd=root_fd)
    except FileExistsError as exc:
        raise BrokerError("broker export sibling unexpectedly already exists") from exc
    try:
        descriptor = os.open(
            name, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=root_fd,
        )
    except OSError as exc:
        raise BrokerError("broker export sibling is unavailable or unsafe") from exc
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid():
            raise BrokerError("broker export sibling has unsafe ownership or type")
        os.fchmod(descriptor, 0o1777)
        _validate_host_staging_directory(descriptor, "export")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_exchange(directory_fd: int, left: str, right: str) -> None:
    """Atomically exchange two exact private staging children."""
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as exc:
        raise BrokerError("atomic staging exchange is unsupported") from exc
    renameat2.argtypes = (
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    if renameat2(
        directory_fd, os.fsencode(left), directory_fd, os.fsencode(right), _RENAME_EXCHANGE,
    ) == 0:
        return
    error = ctypes.get_errno()
    raise BrokerError(f"atomic staging exchange failed: {os.strerror(error)}")


def _remove_export_sibling(root_fd: int, name: str) -> None:
    """Reclaim only an exact broker-created sibling through its parent dirfd."""
    try:
        descriptor = _open_staging_child(root_fd, name, "export")
    except BrokerError:
        try:
            os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise
    try:
        _clear_host_tree(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.rmdir(name, dir_fd=root_fd)
        os.fsync(root_fd)
    except OSError as exc:
        raise BrokerError("broker export sibling cleanup was incomplete") from exc


def _discard_export_siblings(workdir: Path, names: Sequence[str]) -> None:
    root_fd = _open_broker_staging_root(workdir)
    try:
        for name in names:
            if not _EXPORT_SIBLING_NAME.fullmatch(name):
                raise BrokerError("broker export sibling name is invalid")
            _remove_export_sibling(root_fd, name)
    finally:
        os.close(root_fd)


def _commit_work_export(root_fd: int, work_temp: str, backup: str) -> None:
    """Transactionally merge a new work tree while retaining broker controls."""
    _create_export_sibling(root_fd, backup)
    work_fd = _open_staging_child(root_fd, "work", "work")
    temp_fd = _open_staging_child(root_fd, work_temp, "export")
    backup_fd = _open_staging_child(root_fd, backup, "export")
    moved_old: list[str] = []
    moved_new: list[str] = []
    try:
        new_names = _directory_names(temp_fd)
        if _WORK_CONTROLS.intersection(new_names):
            raise BrokerError("worker export attempted to replace broker control data")
        for name in _directory_names(work_fd):
            if name in _WORK_CONTROLS:
                continue
            os.rename(name, name, src_dir_fd=work_fd, dst_dir_fd=backup_fd)
            moved_old.append(name)
        for name in new_names:
            os.rename(name, name, src_dir_fd=temp_fd, dst_dir_fd=work_fd)
            moved_new.append(name)
        os.fsync(work_fd)
        os.fsync(temp_fd)
        os.fsync(backup_fd)
        os.fsync(root_fd)
    except BaseException as original:
        rollback_error: BaseException | None = None
        for name in reversed(moved_new):
            try:
                os.rename(name, name, src_dir_fd=work_fd, dst_dir_fd=temp_fd)
            except OSError as exc:
                rollback_error = exc
                break
        if rollback_error is None:
            for name in reversed(moved_old):
                try:
                    os.rename(name, name, src_dir_fd=backup_fd, dst_dir_fd=work_fd)
                except OSError as exc:
                    rollback_error = exc
                    break
        if rollback_error is not None:
            raise BrokerError("attempt work export commit failed and rollback was incomplete") from rollback_error
        raise original
    finally:
        os.close(backup_fd)
        os.close(temp_fd)
        os.close(work_fd)


def _rollback_work_export(root_fd: int, work_temp: str, backup: str) -> None:
    """Restore the pre-export work snapshot if a later commit step fails."""
    work_fd = _open_staging_child(root_fd, "work", "work")
    temp_fd = _open_staging_child(root_fd, work_temp, "export")
    backup_fd = _open_staging_child(root_fd, backup, "export")
    try:
        for name in _directory_names(work_fd):
            if name in _WORK_CONTROLS:
                continue
            os.rename(name, name, src_dir_fd=work_fd, dst_dir_fd=temp_fd)
        for name in _directory_names(backup_fd):
            os.rename(name, name, src_dir_fd=backup_fd, dst_dir_fd=work_fd)
        os.fsync(work_fd)
        os.fsync(temp_fd)
        os.fsync(backup_fd)
        os.fsync(root_fd)
    except OSError as exc:
        raise BrokerError("attempt work export rollback was incomplete") from exc
    finally:
        os.close(backup_fd)
        os.close(temp_fd)
        os.close(work_fd)


def _commit_bounded_export(
    workdir: Path,
    artifacts: Path,
    *,
    work_temp: str,
    artifacts_temp: str,
    work_bytes: int,
    artifact_bytes: int,
    work_inodes: int,
    artifact_inodes: int,
) -> None:
    """Validate two private export siblings and commit them as one transaction."""
    if not _EXPORT_SIBLING_NAME.fullmatch(work_temp) or not _EXPORT_SIBLING_NAME.fullmatch(artifacts_temp):
        raise BrokerError("broker export sibling name is invalid")
    try:
        staging = ArtifactWriter.staging_for_workdir(workdir)
    except ValueError as exc:
        raise BrokerError(f"attempt storage staging is unsafe: {exc}") from exc
    if staging.artifacts != artifacts:
        raise BrokerError("attempt storage artifacts are not exact private staging")
    root_fd = _open_broker_staging_root(workdir)
    work_backup = f".ctf-os-backup-work-{work_temp.rsplit('-', 1)[1]}"
    artifacts_exchanged = work_committed = False
    try:
        work_fd = _open_staging_child(root_fd, "work", "work")
        artifacts_fd = _open_staging_child(root_fd, "artifacts", "artifacts")
        work_temp_fd = _open_staging_child(root_fd, work_temp, "export")
        artifacts_temp_fd = _open_staging_child(root_fd, artifacts_temp, "export")
        try:
            _enforce_host_tree_limit_fd(work_temp_fd, work_bytes, work_inodes, "work")
            _enforce_host_tree_limit_fd(artifacts_temp_fd, artifact_bytes, artifact_inodes, "artifacts")
            if _WORK_CONTROLS.intersection(_directory_names(work_temp_fd)):
                raise BrokerError("worker export attempted to replace broker control data")
        finally:
            os.close(artifacts_temp_fd)
            os.close(work_temp_fd)
            os.close(artifacts_fd)
            os.close(work_fd)
        _rename_exchange(root_fd, "artifacts", artifacts_temp)
        artifacts_exchanged = True
        _commit_work_export(root_fd, work_temp, work_backup)
        work_committed = True
    except BaseException as original:
        rollback_error: BaseException | None = None
        if work_committed:
            try:
                _rollback_work_export(root_fd, work_temp, work_backup)
            except BaseException as exc:
                rollback_error = exc
        if artifacts_exchanged:
            try:
                _rename_exchange(root_fd, "artifacts", artifacts_temp)
            except BaseException as exc:
                rollback_error = rollback_error or exc
        if rollback_error is not None:
            raise BrokerError("attempt export commit failed and rollback was incomplete") from rollback_error
        raise original
    else:
        _remove_export_sibling(root_fd, artifacts_temp)
        _remove_export_sibling(root_fd, work_temp)
        _remove_export_sibling(root_fd, work_backup)
    finally:
        os.close(root_fd)


def _enforce_host_tree_limit(path: Path, maximum_bytes: int, maximum_inodes: int, label: str) -> None:
    """Reject an over-budget import before Docker can copy a host snapshot."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise BrokerError(f"attempt {label} staging is unsafe") from exc
    try:
        bytes_used, inodes_used = _tree_usage(fd)
    finally:
        os.close(fd)
    if bytes_used > maximum_bytes or inodes_used > maximum_inodes:
        raise BrokerError(
            f"attempt {label} storage exceeds its configured quota "
            f"({bytes_used}/{maximum_bytes} bytes, {inodes_used}/{maximum_inodes} inodes)"
        )


def _tree_usage(directory_fd: int) -> tuple[int, int]:
    """Charge every materialized entry without following links or deduping links.

    Docker's copy path materializes one regular file per directory entry.  A
    hardlink therefore consumes the regular file's logical size once per name
    in the host mirror, and sparse holes are charged by ``st_size`` rather than
    allocated blocks.
    """
    try:
        with os.scandir(directory_fd) as entries:
            names = [entry.name for entry in entries]
        bytes_used = inodes_used = 0
        for name in names:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            inodes_used += 1
            if stat.S_ISDIR(info.st_mode):
                child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
                try:
                    opened = os.fstat(child_fd)
                    if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                        raise BrokerError("attempt storage directory changed while measuring its quota")
                    child_bytes, child_inodes = _tree_usage(child_fd)
                finally:
                    os.close(child_fd)
                bytes_used += child_bytes
                inodes_used += child_inodes
            elif stat.S_ISREG(info.st_mode):
                bytes_used += info.st_size
            elif not stat.S_ISLNK(info.st_mode):
                raise BrokerError("attempt storage contains an unsupported filesystem entry")
        return bytes_used, inodes_used
    except OSError as exc:
        raise BrokerError("attempt storage changed while measuring its quota") from exc


def _validate_host_staging_directory(directory_fd: int, label: str) -> None:
    details = os.fstat(directory_fd)
    if (not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid()
            or stat.S_IMODE(details.st_mode) != 0o1777):
        raise BrokerError(f"attempt {label} staging mount root is unsafe")


def _clear_host_tree(directory_fd: int) -> None:
    """Clear a host-owned mirror without opening worker-selected link targets."""
    try:
        with os.scandir(directory_fd) as entries:
            names = [entry.name for entry in entries]
        for name in names:
            _remove_host_entry(directory_fd, name)
    except OSError as exc:
        raise BrokerError("attempt storage mirror cleanup was incomplete") from exc


def _remove_host_entry(directory_fd: int | None, name: str) -> None:
    if directory_fd is None:
        raise BrokerError("attempt storage mirror descriptor is unavailable")
    try:
        details = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(details.st_mode):
        if details.st_uid != os.getuid():
            raise BrokerError("foreign directory in attempt storage mirror")
        try:
            os.chmod(name, 0o700, dir_fd=directory_fd, follow_symlinks=False)
            child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
        except OSError as exc:
            raise BrokerError("unsafe directory in attempt storage mirror") from exc
        try:
            _clear_host_tree(child_fd)
        finally:
            os.close(child_fd)
        try:
            os.rmdir(name, dir_fd=directory_fd)
        except OSError as exc:
            raise BrokerError("attempt storage mirror directory removal failed") from exc
    else:
        try:
            # unlinkat removes a symlink itself; a hostile target is never
            # opened, chmodded, or otherwise followed.
            os.unlink(name, dir_fd=directory_fd)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise BrokerError("attempt storage mirror entry removal failed") from exc


def _storage_error(phase: str, result: CommandResult) -> str:
    detail = (result.stderr or result.stdout).strip()
    if result.timed_out:
        detail = detail or "Docker operation timed out"
    return f"attempt storage synchronization failed while {phase}" + (f": {detail}" if detail else "")


def _reject_existing_socket_path(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid():
        path.unlink()
        return
    raise BrokerError(f"refusing to replace existing broker path: {path}")


def _unlink_owned_socket(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid():
        path.unlink()


def _truncate(value: str) -> tuple[str, bool]:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= MAX_BROKER_RESPONSE_BYTES // 2:
        return value, False
    truncated = encoded[: MAX_BROKER_RESPONSE_BYTES // 2]
    return truncated.decode("utf-8", errors="ignore") + "\n[ctf-os broker output truncated]\n", True
