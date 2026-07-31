"""Durable admission and cleanup leases for isolated read-only analysis.

The long sandbox command is intentionally outside canonical ``state.json``
transactions.  A shared challenge-session lock excludes workspace writers,
while a short analysis-admission lock makes quota scan plus reservation commit
atomic across concurrent readers.  Each reader owns an external flock and a
PID/start-time receipt so a later process can distinguish a live owner from a
crash orphan without trusting paths from a wire request.
"""

from __future__ import annotations

import errno
import fcntl
import os
import re
import secrets
import stat
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Self

from ctf_os.engine.hotpath_cleanup import (
    ExactTreeReference,
    HotPathCleanupError,
    capture_exact_tree,
    remove_exact_tree,
)
from ctf_os.models import (
    MAX_ANALYSIS_LEASES,
    MAX_STORAGE_RESERVATION_BYTES,
    ChallengeIdentity,
    ChallengeState,
    utc_now,
)
from ctf_os.sandbox.files import SafeFileError, ensure_private_directory
from ctf_os.sandbox.types import AnalysisLeaseRef
from ctf_os.storage import (
    DEFAULT_CHALLENGE_STORAGE_QUOTA_BYTES,
    DEFAULT_STORAGE_SCAN_MAX_BYTES,
    DEFAULT_STORAGE_SCAN_MAX_ENTRIES,
    enforce_storage_quota,
)
from ctf_os.store import ChallengeLock, LockTimeout, StateStore
from ctf_os.store.atomic import atomic_write_json, strict_json_loads


ANALYSIS_ID = re.compile(r"^analysis-[0-9a-f]{32}$")
SCOPE_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
RUNTIME_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
BOOT_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$"
)
OWNER_DOCUMENT = "owner.json"
OWNER_DOCUMENT_MAX_BYTES = 16 * 1024
ANALYSIS_DIRECTORY = "analysis"
ANALYSIS_LOCK_DIRECTORY = "analysis-locks"
ANALYSIS_ADMISSION_LOCK = "analysis-admission.lock"
DEFAULT_ANALYSIS_CLEANUP_MAX_ENTRIES = 100_000
DEFAULT_ANALYSIS_CLEANUP_MAX_DEPTH = 256

_ACTIVE_STATUSES = frozenset({"running", "cleanup_pending"})
_TERMINAL_STATUSES = frozenset({"completed", "failed", "recovered"})
_BACKGROUND_TERMINAL = frozenset(
    {"completed", "failed", "timed_out", "cancelled", "recovered"}
)
_OWNER_KEYS = frozenset(
    {
        "schema_version",
        "analysis_id",
        "scope_fingerprint",
        "owner_pid",
        "owner_start_ticks",
        "owner_boot_id",
        "root_device",
        "root_inode",
        "work_device",
        "work_inode",
        "base_revision",
        "work_tree_limit_bytes",
        "storage_reservation_bytes",
        "created_at",
    }
)

_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | os.O_CLOEXEC
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


class AnalysisLeaseError(RuntimeError):
    """An isolated analysis lease could not be admitted or recovered."""


class AnalysisLeaseBusy(AnalysisLeaseError):
    """A workspace writer or live lease prevents this operation."""


def _merge_cleanup_failure(
    primary: BaseException,
    cleanup: BaseException,
    *,
    label: str,
) -> BaseException:
    """Keep the first control-flow exception across cleanup failures."""

    if isinstance(primary, Exception) and not isinstance(cleanup, Exception):
        cleanup.add_note(
            "an earlier analysis operation also failed: "
            f"{type(primary).__name__}: {primary}"
        )
        return cleanup
    primary.add_note(
        f"{label}: {type(cleanup).__name__}: {cleanup}"
    )
    return primary


class _OwnerLock:
    """One exact non-following flock whose inode is outside cleanup trees."""

    def __init__(self, path: Path) -> None:
        # Publish a resource-free owner before opening the descriptor.  This
        # lets acquire() distinguish raw ownership from object ownership even
        # when a control exception lands on a CALL -> STORE handoff.
        self.path = path
        self._descriptor: int | None = None
        self.device = -1
        self.inode = -1

    def _activate(
        self,
        descriptor: int,
        *,
        device: int,
        inode: int,
    ) -> None:
        if self._descriptor is not None:
            raise RuntimeError("analysis owner lock is already active")
        self.device = device
        self.inode = inode
        # Publish descriptor ownership last.  acquire() retains this object in
        # a local before activation and consumes only one owner on failure.
        self._descriptor = descriptor

    def _acquire_in_place(
        self,
        *,
        blocking: bool,
        exclusive_create: bool = False,
    ) -> None:
        """Acquire into an already-published consume-once owner.

        New lease allocation uses this form so the object that will own the
        descriptor exists before the resource-creating call.  Recovery keeps
        using :meth:`acquire`, which opens an existing logical owner lock.
        """

        if self._descriptor is not None:
            raise RuntimeError("analysis owner lock is already active")
        path = self.path
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NONBLOCK
        flags |= getattr(os, "O_NOFOLLOW", 0)
        if exclusive_create:
            flags |= os.O_EXCL
        before: os.stat_result | None
        try:
            before = path.stat(follow_symlinks=False)
        except FileNotFoundError:
            before = None
        if exclusive_create and before is not None:
            raise FileExistsError(path)
        if before is not None and (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size != 0
        ):
            raise AnalysisLeaseError("analysis owner lock is unsafe")
        descriptor: int | None = None
        try:
            descriptor = os.open(path, flags, 0o600)
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.geteuid()
                or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != 0o600
                or opened.st_size != 0
            ):
                raise AnalysisLeaseError("analysis owner lock is unsafe")
            # Retain the exact inode before flock/activation.  A newly-created
            # lock that is interrupted later can then be unlinked exactly
            # under the admission lock even though no descriptor reaches the
            # normal return path.
            self.device = opened.st_dev
            self.inode = opened.st_ino
            if before is not None and (
                opened.st_dev,
                opened.st_ino,
            ) != (before.st_dev, before.st_ino):
                raise AnalysisLeaseError(
                    "analysis owner lock changed while opening"
                )
            operation = fcntl.LOCK_EX
            if not blocking:
                operation |= fcntl.LOCK_NB
            try:
                fcntl.flock(descriptor, operation)
            except OSError as error:
                if error.errno in {errno.EACCES, errno.EAGAIN}:
                    raise AnalysisLeaseBusy("analysis lease is still live") from error
                raise
            locked = os.fstat(descriptor)
            if (
                locked.st_dev,
                locked.st_ino,
                locked.st_mode,
                locked.st_uid,
                locked.st_nlink,
                locked.st_size,
            ) != (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_uid,
                opened.st_nlink,
                opened.st_size,
            ):
                raise AnalysisLeaseError(
                    "analysis owner lock changed while acquiring"
                )
            self._activate(
                descriptor,
                device=opened.st_dev,
                inode=opened.st_ino,
            )
            descriptor = None
        except BaseException as error:
            selected_error = error
            if self._descriptor is not None:
                # The object already consumed the raw descriptor.  Clear the
                # duplicate integer before its one idempotent release attempt.
                descriptor = None
                try:
                    self.release()
                except BaseException as cleanup_error:
                    selected_error = _merge_cleanup_failure(
                        selected_error,
                        cleanup_error,
                        label=(
                            "analysis owner lock handoff cleanup failed"
                        ),
                    )
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except BaseException as cleanup_error:
                    selected_error = _merge_cleanup_failure(
                        selected_error,
                        cleanup_error,
                        label=(
                            "analysis owner raw descriptor cleanup failed"
                        ),
                    )
            raise selected_error

    @classmethod
    def acquire(cls, path: Path, *, blocking: bool) -> _OwnerLock:
        owner = cls(path)
        owner._acquire_in_place(blocking=blocking)
        return owner

    def release(self) -> None:
        descriptor = self._descriptor
        if descriptor is None:
            return
        self._descriptor = None
        primary: BaseException | None = None
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except BaseException as error:
            primary = error
        try:
            os.close(descriptor)
        except BaseException as error:
            if primary is None:
                primary = error
            else:
                primary = _merge_cleanup_failure(
                    primary,
                    error,
                    label="owner lock close also failed",
                )
        if primary is not None:
            raise primary

    def __del__(self) -> None:
        try:
            # release() consumes ownership before its single close attempt, so
            # a lost public return can never reclose a reused descriptor.
            self.release()
        except BaseException:
            pass


class _PendingAnalysisTree:
    """Descriptor-bound ownership while a lease tree is being allocated.

    The final analysis path is untrusted after any asynchronous interruption:
    another same-UID process can rename and replace it.  Therefore allocation
    publishes an open directory descriptor and its inode into this object
    before the creating helper returns.  Cleanup later still reopens through
    :class:`ExactTreeReference` and refuses a substituted path.

    This object is deliberately resource-free at construction.  Every owned
    descriptor is consumed by an attribute before a reference is built, so an
    exception after reference construction can be reconciled from the held
    descriptor instead of by trusting a fresh pathname stat.
    """

    def __init__(
        self,
        challenge_root: Path,
        analysis_root: Path,
        analysis_id: str,
    ) -> None:
        if ANALYSIS_ID.fullmatch(analysis_id) is None:
            raise AnalysisLeaseError("invalid pending analysis identity")
        try:
            relative = (analysis_root / analysis_id).relative_to(
                challenge_root
            )
        except ValueError as error:
            raise AnalysisLeaseError(
                "pending analysis root escapes the challenge"
            ) from error
        self.analysis_root = analysis_root
        self.analysis_id = analysis_id
        self.root_path = analysis_root / analysis_id
        self.work_path = self.root_path / "work"
        self._root_relative = PurePosixPath(relative.as_posix())
        self._work_relative = self._root_relative / "work"
        self._parent_descriptor: int | None = None
        self._parent_device = -1
        self._parent_inode = -1
        self._root_descriptor: int | None = None
        self._work_descriptor: int | None = None
        self._root_reference: ExactTreeReference | None = None
        self._work_reference: ExactTreeReference | None = None
        self.root_creation_started = False
        self.work_creation_started = False

    @staticmethod
    def _validate_private_directory(
        metadata: os.stat_result,
        *,
        parent_device: int | None = None,
    ) -> None:
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_nlink < 2
            or (
                parent_device is not None
                and metadata.st_dev != parent_device
            )
        ):
            raise AnalysisLeaseError(
                "pending analysis directory is unsafe"
            )

    def open_parent(self) -> None:
        if self._parent_descriptor is not None:
            raise RuntimeError("pending analysis parent is already open")
        descriptor: int | None = None
        primary: BaseException | None = None
        try:
            descriptor = os.open(self.analysis_root, _DIRECTORY_FLAGS)
            metadata = os.fstat(descriptor)
            self._validate_private_directory(metadata)
            self._parent_device = metadata.st_dev
            self._parent_inode = metadata.st_ino
            # Publish descriptor ownership last; the pending object itself was
            # stored by acquire() before this resource-creating operation.
            self._parent_descriptor = descriptor
            descriptor = None
        except BaseException as error:
            primary = error
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException as error:
                if primary is None:
                    primary = error
                else:
                    primary = _merge_cleanup_failure(
                        primary,
                        error,
                        label=(
                            "pending analysis parent close also failed"
                        ),
                    )
        if primary is not None:
            raise primary

    def _publish_entry(
        self,
        *,
        parent_descriptor: int,
        name: str,
        relative: PurePosixPath,
        descriptor_attribute: str,
        reference_attribute: str,
    ) -> None:
        descriptor: int | None = None
        primary: BaseException | None = None
        try:
            descriptor = os.open(
                name,
                _DIRECTORY_FLAGS,
                dir_fd=parent_descriptor,
            )
            opened = os.fstat(descriptor)
            parent = os.fstat(parent_descriptor)
            self._validate_private_directory(
                opened,
                parent_device=parent.st_dev,
            )
            observed = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (
                observed.st_dev,
                observed.st_ino,
                observed.st_mode,
                observed.st_uid,
            ) != (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_uid,
            ):
                raise AnalysisLeaseError(
                    "pending analysis directory changed while opening"
                )

            # Consume the descriptor before constructing/publishing the
            # reference.  reference_for() can recover a lost constructor
            # return from this exact descriptor without a pathname lookup.
            setattr(self, descriptor_attribute, descriptor)
            descriptor = None
            reference = ExactTreeReference(
                relative=relative,
                device=opened.st_dev,
                inode=opened.st_ino,
            )
            setattr(self, reference_attribute, reference)
        except BaseException as error:
            primary = error
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException as error:
                if primary is None:
                    primary = error
                else:
                    primary = _merge_cleanup_failure(
                        primary,
                        error,
                        label=(
                            "pending analysis entry close also failed"
                        ),
                    )
        if primary is not None:
            raise primary

    def _create_entry(
        self,
        *,
        parent_descriptor: int,
        name: str,
        relative: PurePosixPath,
        descriptor_attribute: str,
        reference_attribute: str,
        started_attribute: str,
    ) -> None:
        try:
            os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(name)

        setattr(self, started_attribute, True)
        creation_error: BaseException | None = None
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_descriptor)
        except BaseException as error:
            # A normal OSError means mkdir did not establish ownership (most
            # importantly EEXIST may be an attacker-created entry).  Only a
            # control exception can represent an asynchronous interruption
            # after the kernel successfully created our directory.
            if isinstance(error, Exception):
                raise
            creation_error = error

        try:
            self._publish_entry(
                parent_descriptor=parent_descriptor,
                name=name,
                relative=relative,
                descriptor_attribute=descriptor_attribute,
                reference_attribute=reference_attribute,
            )
        except BaseException as capture_error:
            if creation_error is not None:
                selected_error = _merge_cleanup_failure(
                    creation_error,
                    capture_error,
                    label=(
                        "pending analysis identity capture also failed"
                    ),
                )
                raise selected_error
            raise
        if creation_error is not None:
            raise creation_error

    def create_root(self) -> None:
        parent = self._parent_descriptor
        if parent is None:
            raise RuntimeError("pending analysis parent is not open")
        self._create_entry(
            parent_descriptor=parent,
            name=self.analysis_id,
            relative=self._root_relative,
            descriptor_attribute="_root_descriptor",
            reference_attribute="_root_reference",
            started_attribute="root_creation_started",
        )

    def create_work(self) -> None:
        root = self._root_descriptor
        if root is None:
            raise RuntimeError("pending analysis root is not open")
        self._create_entry(
            parent_descriptor=root,
            name="work",
            relative=self._work_relative,
            descriptor_attribute="_work_descriptor",
            reference_attribute="_work_reference",
            started_attribute="work_creation_started",
        )

    def _reference_for(
        self,
        *,
        descriptor_attribute: str,
        reference_attribute: str,
        relative: PurePosixPath,
    ) -> ExactTreeReference | None:
        reference = getattr(self, reference_attribute)
        if reference is not None:
            return reference
        descriptor = getattr(self, descriptor_attribute)
        if descriptor is None:
            return None
        metadata = os.fstat(descriptor)
        self._validate_private_directory(metadata)
        reference = ExactTreeReference(
            relative=relative,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
        setattr(self, reference_attribute, reference)
        return reference

    @property
    def root_reference(self) -> ExactTreeReference | None:
        return self._reference_for(
            descriptor_attribute="_root_descriptor",
            reference_attribute="_root_reference",
            relative=self._root_relative,
        )

    @property
    def work_reference(self) -> ExactTreeReference | None:
        return self._reference_for(
            descriptor_attribute="_work_descriptor",
            reference_attribute="_work_reference",
            relative=self._work_relative,
        )

    @staticmethod
    def _verify_entry_binding(
        parent_descriptor: int,
        name: str,
        child_descriptor: int,
    ) -> None:
        observed = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        opened = os.fstat(child_descriptor)
        if (
            observed.st_dev,
            observed.st_ino,
            observed.st_mode,
            observed.st_uid,
        ) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_uid,
        ):
            raise AnalysisLeaseError(
                "pending analysis path binding changed"
            )

    def verify_bindings(self) -> None:
        """Prove public root/work paths still name the held descriptors."""

        parent = self._parent_descriptor
        root = self._root_descriptor
        work = self._work_descriptor
        if parent is None or root is None or work is None:
            raise AnalysisLeaseError(
                "pending analysis descriptors are incomplete"
            )
        try:
            public_parent = self.analysis_root.stat(
                follow_symlinks=False
            )
            opened_parent = os.fstat(parent)
            if (
                public_parent.st_dev,
                public_parent.st_ino,
                public_parent.st_mode,
                public_parent.st_uid,
            ) != (
                opened_parent.st_dev,
                opened_parent.st_ino,
                opened_parent.st_mode,
                opened_parent.st_uid,
            ) or (
                opened_parent.st_dev,
                opened_parent.st_ino,
            ) != (self._parent_device, self._parent_inode):
                raise AnalysisLeaseError(
                    "pending analysis parent binding changed"
                )
            self._verify_entry_binding(parent, self.analysis_id, root)
            self._verify_entry_binding(root, "work", work)
        except OSError as error:
            raise AnalysisLeaseError(
                "pending analysis path binding is unavailable"
            ) from error

    def close(self) -> None:
        primary: BaseException | None = None
        for attribute in (
            "_work_descriptor",
            "_root_descriptor",
            "_parent_descriptor",
        ):
            descriptor = getattr(self, attribute)
            if descriptor is None:
                continue
            setattr(self, attribute, None)
            try:
                os.close(descriptor)
            except BaseException as error:
                if primary is None:
                    primary = error
                else:
                    primary = _merge_cleanup_failure(
                        primary,
                        error,
                        label=(
                            "pending analysis descriptor close also failed"
                        ),
                    )
        if primary is not None:
            raise primary

    def __del__(self) -> None:
        try:
            self.close()
        except BaseException:
            pass


def _process_start_ticks(pid: int) -> int | None:
    if type(pid) is not int or pid <= 1:
        return None
    try:
        payload = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        fields = payload[payload.rfind(")") + 2 :].split()
        if fields[0] in {"Z", "X", "x"}:
            return None
        return int(fields[19])
    except (OSError, UnicodeError, ValueError, IndexError):
        return None


def _boot_id() -> str:
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="ascii"
        ).strip().lower()
    except (OSError, UnicodeError) as error:
        raise AnalysisLeaseError("host boot identity is unavailable") from error
    if BOOT_ID.fullmatch(value) is None:
        raise AnalysisLeaseError("host boot identity is invalid")
    return value


def _owner_is_live(record: Mapping[str, object]) -> bool:
    if record.get("owner_boot_id") != _boot_id():
        return False
    pid = record.get("owner_pid")
    ticks = record.get("owner_start_ticks")
    return (
        type(pid) is int
        and type(ticks) is int
        and _process_start_ticks(pid) == ticks
    )


def _private_directory(path: Path) -> Path:
    try:
        directory = ensure_private_directory(path)
        metadata = directory.stat(follow_symlinks=False)
    except (OSError, SafeFileError) as error:
        raise AnalysisLeaseError("analysis directory is unsafe") from error
    if (
        metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise AnalysisLeaseError(
            "analysis directory must be private and owned by the engine"
        )
    return directory


def _read_owner(path: Path) -> dict[str, object]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o400
            or before.st_size <= 0
            or before.st_size > OWNER_DOCUMENT_MAX_BYTES
        ):
            raise AnalysisLeaseError("analysis owner receipt is unsafe")
        chunks = bytearray()
        while len(chunks) <= OWNER_DOCUMENT_MAX_BYTES:
            chunk = os.read(
                descriptor,
                min(65536, OWNER_DOCUMENT_MAX_BYTES + 1 - len(chunks)),
            )
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(descriptor)
        if (
            len(chunks) > OWNER_DOCUMENT_MAX_BYTES
            or (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_uid,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_uid,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
        ):
            raise AnalysisLeaseError("analysis owner receipt changed while reading")
    except OSError as error:
        raise AnalysisLeaseError("analysis owner receipt cannot be read") from error
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError as close_error:
                active = sys.exception()
                if active is not None:
                    active.add_note(
                        f"analysis owner receipt close failed: {close_error}"
                    )
                else:
                    raise AnalysisLeaseError(
                        "analysis owner receipt close failed"
                    ) from close_error
    try:
        value = strict_json_loads(bytes(chunks), max_bytes=OWNER_DOCUMENT_MAX_BYTES)
    except (UnicodeError, ValueError) as error:
        raise AnalysisLeaseError("analysis owner receipt is invalid JSON") from error
    if type(value) is not dict or set(value) != _OWNER_KEYS:
        raise AnalysisLeaseError("analysis owner receipt has an invalid schema")
    return value


def _validate_owner(
    value: Mapping[str, object],
    *,
    expected_ref: AnalysisLeaseRef | None = None,
    expected_tree: ExactTreeReference | None = None,
    expected_work: ExactTreeReference | None = None,
) -> AnalysisLeaseRef:
    try:
        ref = AnalysisLeaseRef(
            analysis_id=value["analysis_id"],  # type: ignore[arg-type]
            scope_fingerprint=value["scope_fingerprint"],  # type: ignore[arg-type]
        )
    except (KeyError, TypeError, ValueError) as error:
        raise AnalysisLeaseError("analysis owner receipt identity is invalid") from error
    if expected_ref is not None and ref != expected_ref:
        raise AnalysisLeaseError("analysis owner receipt scope binding changed")
    for field in (
        "owner_pid",
        "owner_start_ticks",
        "root_inode",
        "work_inode",
        "work_tree_limit_bytes",
        "storage_reservation_bytes",
    ):
        if type(value.get(field)) is not int or value[field] <= 0:  # type: ignore[operator]
            raise AnalysisLeaseError(
                f"analysis owner receipt has invalid {field}"
            )
    for field in ("root_device", "work_device"):
        if type(value.get(field)) is not int or value[field] < 0:  # type: ignore[operator]
            raise AnalysisLeaseError(
                f"analysis owner receipt has invalid {field}"
            )
    if value["work_device"] != value["root_device"]:
        raise AnalysisLeaseError(
            "analysis work tree must share the lease device"
        )
    if (
        type(value.get("base_revision")) is not int
        or value["base_revision"] < 0  # type: ignore[operator]
        or type(value.get("created_at")) is not str
        or not value["created_at"]
    ):
        raise AnalysisLeaseError(
            "analysis owner receipt has invalid allocation metadata"
        )
    if value["storage_reservation_bytes"] < value["work_tree_limit_bytes"]:  # type: ignore[operator]
        raise AnalysisLeaseError(
            "analysis owner reservation does not cover its work tree"
        )
    if (
        type(value.get("owner_boot_id")) is not str
        or BOOT_ID.fullmatch(value["owner_boot_id"]) is None  # type: ignore[arg-type]
    ):
        raise AnalysisLeaseError(
            "analysis owner receipt has invalid owner_boot_id"
        )
    if value.get("schema_version") != 1:
        raise AnalysisLeaseError(
            "analysis owner receipt has unsupported schema_version"
        )
    if expected_tree is not None and (
        value["root_device"],
        value["root_inode"],
    ) != (expected_tree.device, expected_tree.inode):
        raise AnalysisLeaseError("analysis owner directory identity changed")
    if expected_work is not None and (
        value["work_device"],
        value["work_inode"],
    ) != (expected_work.device, expected_work.inode):
        raise AnalysisLeaseError("analysis work directory identity changed")
    return ref


@dataclass(frozen=True, slots=True)
class AnalysisRecoveryReport:
    recovered: tuple[str, ...]
    live: tuple[str, ...]
    cleanup_pending: tuple[str, ...]


@dataclass(slots=True)
class AnalysisLease:
    """One admitted lease; host paths never belong to its wire reference."""

    ref: AnalysisLeaseRef
    root: Path
    work_dir: Path
    reservation_bytes: int
    work_tree_limit_bytes: int
    base_revision: int
    _manager: AnalysisLeaseManager
    _tree: ExactTreeReference
    _work_tree: ExactTreeReference
    _owner_lock: _OwnerLock | None
    _session_lock: ChallengeLock | None
    _released: bool = False

    def bind_runtime(self, runtime_id: str) -> ChallengeState:
        return self._manager.bind_runtime(self, runtime_id)

    def mark_cleanup_pending(
        self,
        reason_code: str = "analysis_cleanup_pending",
    ) -> ChallengeState:
        return self._manager.mark_cleanup_pending(self, reason_code)

    def finalize(
        self,
        *,
        status: str = "completed",
        reason_code: str | None = None,
        runtime_absent: bool | None = None,
    ) -> ChallengeState:
        return self._manager.finalize(
            self,
            status=status,
            reason_code=reason_code,
            runtime_absent=runtime_absent,
        )

    def abandon(
        self,
        reason_code: str = "analysis_interrupted",
    ) -> ChallengeState:
        return self._manager.abandon(self, reason_code=reason_code)

    def _release_locks(self) -> None:
        if self._released:
            return
        self._released = True
        primary: BaseException | None = None
        owner = self._owner_lock
        self._owner_lock = None
        if owner is not None:
            try:
                owner.release()
            except BaseException as error:
                primary = error
        session = self._session_lock
        self._session_lock = None
        if session is not None:
            try:
                session.release()
            except BaseException as error:
                if primary is None:
                    primary = error
                else:
                    primary = _merge_cleanup_failure(
                        primary,
                        error,
                        label="session lock release also failed",
                    )
        if primary is not None:
            raise primary

    def __enter__(self) -> Self:
        if self._released:
            raise AnalysisLeaseError("analysis lease is already released")
        return self

    def __exit__(self, *exc: object) -> None:
        if not self._released:
            self.abandon()

    def __del__(self) -> None:
        if getattr(self, "_released", True):
            return
        try:
            # A return value lost before the caller's STORE has no bound
            # runtime.  Normal finalization therefore proves exact tree
            # absence and releases the reservation.  If a caller instead
            # drops a runtime-bound lease, finalize uses the configured
            # data-plane absence probe and retains cleanup_pending on doubt.
            self.finalize(
                status="failed",
                reason_code="analysis_handoff_lost",
            )
        except BaseException:
            # finalize normally releases both locks on every path.  Its first
            # ownership validation can itself fail, though, so make one
            # consume-once fallback without allowing finalizer exceptions to
            # escape as unraisable warnings.
            if not getattr(self, "_released", True):
                try:
                    self.abandon("analysis_handoff_lost")
                except BaseException:
                    try:
                        self._release_locks()
                    except BaseException:
                        pass


RuntimeAbsenceProbe = Callable[[AnalysisLeaseRef], None]


class AnalysisLeaseManager:
    """Allocate, recover, and terminalize durable analysis reservations."""

    def __init__(
        self,
        store: StateStore,
        identity: ChallengeIdentity,
        *,
        scope_fingerprint: str,
        quota_bytes: int = DEFAULT_CHALLENGE_STORAGE_QUOTA_BYTES,
        max_scan_entries: int = DEFAULT_STORAGE_SCAN_MAX_ENTRIES,
        max_scan_bytes: int = DEFAULT_STORAGE_SCAN_MAX_BYTES,
        cleanup_max_entries: int = DEFAULT_ANALYSIS_CLEANUP_MAX_ENTRIES,
        cleanup_max_bytes: int | None = None,
        cleanup_max_depth: int = DEFAULT_ANALYSIS_CLEANUP_MAX_DEPTH,
        runtime_absence_probe: RuntimeAbsenceProbe | None = None,
    ) -> None:
        if not isinstance(store, StateStore):
            raise TypeError("store must be a StateStore")
        if not isinstance(identity, ChallengeIdentity):
            raise TypeError("identity must be a ChallengeIdentity")
        if SCOPE_FINGERPRINT.fullmatch(scope_fingerprint) is None:
            raise ValueError("invalid analysis scope fingerprint")
        for value, label in (
            (quota_bytes, "quota_bytes"),
            (max_scan_entries, "max_scan_entries"),
            (max_scan_bytes, "max_scan_bytes"),
            (cleanup_max_entries, "cleanup_max_entries"),
            (cleanup_max_depth, "cleanup_max_depth"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{label} must be a positive integer")
        selected_cleanup_bytes = (
            quota_bytes if cleanup_max_bytes is None else cleanup_max_bytes
        )
        if (
            isinstance(selected_cleanup_bytes, bool)
            or not isinstance(selected_cleanup_bytes, int)
            or selected_cleanup_bytes < 0
        ):
            raise ValueError("cleanup_max_bytes must be non-negative")
        self.store = store
        self.identity = identity
        self.scope_fingerprint = scope_fingerprint
        self.quota_bytes = quota_bytes
        self.max_scan_entries = max_scan_entries
        self.max_scan_bytes = max_scan_bytes
        self.cleanup_max_entries = cleanup_max_entries
        self.cleanup_max_bytes = selected_cleanup_bytes
        self.cleanup_max_depth = cleanup_max_depth
        self.runtime_absence_probe = runtime_absence_probe

    def prepare_root(self) -> Path:
        """Create trusted roots only while challenge writers are excluded."""

        session_lock = ChallengeLock(
            self.paths.runtime / "session.lock",
            timeout=0,
            shared=True,
        )
        try:
            session_lock.acquire()
        except LockTimeout as error:
            raise AnalysisLeaseBusy(
                "a workspace writer already owns the challenge session"
            ) from error
        try:
            with ChallengeLock(
                self.paths.runtime / ANALYSIS_ADMISSION_LOCK
            ) as admission_lock:
                admission_lock.acquire()
                self._ensure_roots()
                return self.analysis_root
        finally:
            session_lock.release()

    def set_runtime_absence_probe(
        self,
        probe: RuntimeAbsenceProbe,
    ) -> None:
        """Bind the analysis-enabled client cleanup probe exactly once."""

        if not callable(probe):
            raise TypeError("runtime absence probe must be callable")
        if self.runtime_absence_probe is not None:
            raise AnalysisLeaseError(
                "runtime absence probe is already configured"
            )
        self.runtime_absence_probe = probe

    @property
    def paths(self) -> Any:
        return self.store.challenge_paths(self.identity)

    @property
    def analysis_root(self) -> Path:
        return self.paths.runtime / ANALYSIS_DIRECTORY

    @property
    def lock_root(self) -> Path:
        return self.paths.runtime / ANALYSIS_LOCK_DIRECTORY

    def _lock_path(self, analysis_id: str) -> Path:
        if ANALYSIS_ID.fullmatch(analysis_id) is None:
            raise AnalysisLeaseError("invalid analysis lease identity")
        return self.lock_root / f"{analysis_id}.lock"

    def _lease_root(self, analysis_id: str) -> Path:
        if ANALYSIS_ID.fullmatch(analysis_id) is None:
            raise AnalysisLeaseError("invalid analysis lease identity")
        return self.analysis_root / analysis_id

    def _ensure_roots(self) -> None:
        _private_directory(self.analysis_root)
        _private_directory(self.lock_root)

    def _unlink_released_owner_lock(
        self,
        *,
        analysis_id: str,
        device: int,
        inode: int,
    ) -> None:
        """Unlink one terminal lease lock under the admission lock."""

        name = f"{analysis_id}.lock"
        if ANALYSIS_ID.fullmatch(analysis_id) is None:
            raise AnalysisLeaseError("invalid analysis owner lock identity")
        directory = os.open(self.lock_root, _DIRECTORY_FLAGS)
        descriptor: int | None = None
        try:
            try:
                before = os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                return
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_size != 0
                or (before.st_dev, before.st_ino) != (device, inode)
            ):
                raise AnalysisLeaseError(
                    "terminal analysis owner lock is unsafe"
                )
            flags = os.O_RDWR | os.O_CLOEXEC | os.O_NONBLOCK
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(name, flags, dir_fd=directory)
            opened = os.fstat(descriptor)
            if (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_uid,
                opened.st_nlink,
                opened.st_size,
            ) != (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_uid,
                before.st_nlink,
                before.st_size,
            ):
                raise AnalysisLeaseError(
                    "terminal analysis owner lock changed while opening"
                )
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno in {errno.EACCES, errno.EAGAIN}:
                    raise AnalysisLeaseBusy(
                        "terminal analysis owner lock is unexpectedly live"
                    ) from error
                raise
            os.unlink(name, dir_fd=directory)
            os.fsync(directory)
        except OSError as error:
            raise AnalysisLeaseError(
                "terminal analysis owner lock cleanup failed"
            ) from error
        finally:
            if descriptor is not None:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(descriptor)
            os.close(directory)

    def _retire_owner_lock(
        self,
        owner_lock: _OwnerLock,
        analysis_id: str,
    ) -> None:
        device, inode = owner_lock.device, owner_lock.inode
        owner_lock.release()
        self._unlink_released_owner_lock(
            analysis_id=analysis_id,
            device=device,
            inode=inode,
        )

    @staticmethod
    def _records(state: ChallengeState) -> list[dict[str, object]]:
        raw = state.extra.get("analysis_leases", [])
        if type(raw) is not list or any(type(item) is not dict for item in raw):
            raise AnalysisLeaseError("analysis lease state is malformed")
        return raw

    @staticmethod
    def _assert_no_active_writer(state: ChallengeState) -> None:
        if state.active_managed_session_id is not None:
            raise AnalysisLeaseBusy(
                "active managed session blocks read-only analysis"
            )
        jobs = state.extra.get("background_jobs", [])
        if type(jobs) is not list:
            raise AnalysisLeaseBusy(
                "indeterminate background job state blocks analysis"
            )
        for record in jobs:
            if type(record) is not dict:
                raise AnalysisLeaseBusy(
                    "indeterminate background job state blocks analysis"
                )
            if record.get("status") not in _BACKGROUND_TERMINAL:
                raise AnalysisLeaseBusy(
                    "active background job blocks read-only analysis"
                )

    @staticmethod
    def _find_record(
        state: ChallengeState,
        analysis_id: str,
    ) -> dict[str, object] | None:
        matches = [
            record
            for record in AnalysisLeaseManager._records(state)
            if record.get("analysis_id") == analysis_id
        ]
        if len(matches) > 1:
            raise AnalysisLeaseError("analysis lease identity is duplicated")
        return matches[0] if matches else None

    def _record_from_owner(
        self,
        owner: Mapping[str, object],
        *,
        status: str,
        runtime_id: str | None = None,
        reservation_bytes: int | None = None,
        reason_code: str | None = None,
        finished_at: str | None = None,
    ) -> dict[str, object]:
        now = utc_now()
        selected_reservation = (
            owner["storage_reservation_bytes"]
            if reservation_bytes is None
            else reservation_bytes
        )
        return {
            "schema_version": 1,
            "analysis_id": owner["analysis_id"],
            "scope_fingerprint": owner["scope_fingerprint"],
            "status": status,
            "owner_pid": owner["owner_pid"],
            "owner_start_ticks": owner["owner_start_ticks"],
            "owner_boot_id": owner["owner_boot_id"],
            "root_device": owner["root_device"],
            "root_inode": owner["root_inode"],
            "work_device": owner["work_device"],
            "work_inode": owner["work_inode"],
            "base_revision": owner["base_revision"],
            "work_tree_limit_bytes": owner["work_tree_limit_bytes"],
            "storage_reservation_bytes": selected_reservation,
            "runtime_id": runtime_id,
            "created_at": owner["created_at"],
            "started_at": owner["created_at"],
            "finished_at": finished_at,
            "observed_at": now,
            "reason_code": reason_code,
        }

    @staticmethod
    def _append_bounded_record(
        records: list[dict[str, object]],
        record: dict[str, object],
    ) -> None:
        while len(records) >= MAX_ANALYSIS_LEASES:
            terminal_index = next(
                (
                    index
                    for index, item in enumerate(records)
                    if item.get("status") in _TERMINAL_STATUSES
                ),
                None,
            )
            if terminal_index is None:
                raise AnalysisLeaseBusy(
                    "analysis lease record bound is occupied by active leases"
                )
            records.pop(terminal_index)
        records.append(record)

    def _runtime_absent(
        self,
        ref: AnalysisLeaseRef,
        runtime_id: object,
        explicit: bool | None = None,
    ) -> bool:
        if runtime_id is None:
            # The data-plane contract requires durable binding before launch.
            return True
        if type(runtime_id) is not str or RUNTIME_ID.fullmatch(runtime_id) is None:
            raise AnalysisLeaseError("analysis runtime binding is invalid")
        if explicit is True:
            return True
        probe = self.runtime_absence_probe
        if probe is None:
            return False
        try:
            probe(ref)
            return True
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            return False

    def _tree_from_record(
        self,
        record: Mapping[str, object],
    ) -> ExactTreeReference:
        return ExactTreeReference(
            relative=PurePosixPath(
                "runtime",
                ANALYSIS_DIRECTORY,
                str(record["analysis_id"]),
            ),
            device=record["root_device"],  # type: ignore[arg-type]
            inode=record["root_inode"],  # type: ignore[arg-type]
        )

    def _work_from_record(
        self,
        record: Mapping[str, object],
    ) -> ExactTreeReference:
        return ExactTreeReference(
            relative=PurePosixPath(
                "runtime",
                ANALYSIS_DIRECTORY,
                str(record["analysis_id"]),
                "work",
            ),
            device=record["work_device"],  # type: ignore[arg-type]
            inode=record["work_inode"],  # type: ignore[arg-type]
        )

    def _remove_tree(self, tree: ExactTreeReference) -> None:
        try:
            removed = remove_exact_tree(
                self.paths.root,
                tree,
                maximum_entries=self.cleanup_max_entries,
                maximum_bytes=self.cleanup_max_bytes,
                maximum_depth=self.cleanup_max_depth,
            )
        except HotPathCleanupError as error:
            raise AnalysisLeaseError(
                "analysis workspace cleanup could not be proven"
            ) from error
        if not removed:
            raise AnalysisLeaseError(
                "analysis workspace absence could not be proven"
            )

    def acquire(
        self,
        *,
        reservation_bytes: int,
        work_tree_limit_bytes: int | None = None,
    ) -> AnalysisLease:
        """Atomically admit one reader and retain its shared session lock."""

        selected_limit = (
            reservation_bytes
            if work_tree_limit_bytes is None
            else work_tree_limit_bytes
        )
        for value, label in (
            (reservation_bytes, "reservation_bytes"),
            (selected_limit, "work_tree_limit_bytes"),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1 <= value <= MAX_STORAGE_RESERVATION_BYTES
            ):
                raise ValueError(f"{label} must be a bounded positive integer")
        if reservation_bytes < selected_limit:
            raise ValueError("reservation must cover the work-tree limit")

        session_lock = ChallengeLock(
            self.paths.runtime / "session.lock",
            timeout=0,
            shared=True,
        )
        try:
            session_lock.acquire()
        except LockTimeout as error:
            raise AnalysisLeaseBusy(
                "a workspace writer already owns the challenge session"
            ) from error

        owner_lock: _OwnerLock | None = None
        pending_tree: _PendingAnalysisTree | None = None
        tree: ExactTreeReference | None = None
        work_tree: ExactTreeReference | None = None
        root: Path | None = None
        analysis_id: str | None = None
        try:
            with ChallengeLock(
                self.paths.runtime / ANALYSIS_ADMISSION_LOCK
            ) as admission_lock:
                admission_lock.acquire()
                self._ensure_roots()
                before = self.store.load(self.identity, recover=False)
                self._assert_no_active_writer(before)
                self._recover_locked()
                before = self.store.load(self.identity, recover=False)
                self._assert_no_active_writer(before)

                for _attempt in range(32):
                    candidate = f"analysis-{secrets.token_hex(16)}"
                    candidate_root = self._lease_root(candidate)
                    candidate_owner = _OwnerLock(
                        self._lock_path(candidate)
                    )
                    # Publish all logical ownership before creating either the
                    # lock inode or lease directory.  O_EXCL means an existing
                    # logical owner is a collision, never something allocation
                    # is allowed to reopen and later delete.
                    analysis_id = candidate
                    root = candidate_root
                    owner_lock = candidate_owner
                    try:
                        candidate_owner._acquire_in_place(
                            blocking=False,
                            exclusive_create=True,
                        )
                    except FileExistsError:
                        analysis_id = None
                        root = None
                        owner_lock = None
                        continue
                    break
                if (
                    analysis_id is None
                    or root is None
                    or owner_lock is None
                ):
                    raise AnalysisLeaseError(
                        "could not allocate a unique analysis lease"
                    )

                # Construction is resource-free, so pending_tree itself is
                # visible to the exception path before any mkdir.  Its create
                # helpers retain exact descriptors/references before returning.
                pending_tree = _PendingAnalysisTree(
                    self.paths.root,
                    self.analysis_root,
                    analysis_id,
                )
                pending_tree.open_parent()
                pending_tree.create_root()
                tree = pending_tree.root_reference
                if tree is None:
                    raise AnalysisLeaseError(
                        "analysis root identity was not published"
                    )
                pending_tree.create_work()
                work_tree = pending_tree.work_reference
                if work_tree is None:
                    raise AnalysisLeaseError(
                        "analysis work identity was not published"
                    )
                work_dir = pending_tree.work_path
                if work_tree.device != tree.device:
                    raise AnalysisLeaseError(
                        "analysis work tree crossed a filesystem boundary"
                    )
                ref = AnalysisLeaseRef(analysis_id, self.scope_fingerprint)
                owner_pid = os.getpid()
                owner_ticks = _process_start_ticks(owner_pid)
                if owner_ticks is None:
                    raise AnalysisLeaseError(
                        "analysis owner process identity is unavailable"
                    )
                owner = {
                    "schema_version": 1,
                    "analysis_id": analysis_id,
                    "scope_fingerprint": self.scope_fingerprint,
                    "owner_pid": owner_pid,
                    "owner_start_ticks": owner_ticks,
                    "owner_boot_id": _boot_id(),
                    "root_device": tree.device,
                    "root_inode": tree.inode,
                    "work_device": work_tree.device,
                    "work_inode": work_tree.inode,
                    "base_revision": before.revision,
                    "work_tree_limit_bytes": selected_limit,
                    "storage_reservation_bytes": reservation_bytes,
                    "created_at": utc_now(),
                }
                atomic_write_json(root / OWNER_DOCUMENT, owner, mode=0o400)
                _validate_owner(
                    _read_owner(root / OWNER_DOCUMENT),
                    expected_ref=ref,
                    expected_tree=tree,
                    expected_work=work_tree,
                )
                pending_tree.verify_bindings()
                enforce_storage_quota(
                    self.store,
                    self.identity,
                    quota_bytes=self.quota_bytes,
                    max_entries=self.max_scan_entries,
                    max_scan_bytes=self.max_scan_bytes,
                    additional_bytes=reservation_bytes,
                )
                new_record = self._record_from_owner(owner, status="running")

                def reserve(state: ChallengeState) -> None:
                    self._assert_no_active_writer(state)
                    records = self._records(state)
                    if any(
                        item.get("analysis_id") == analysis_id
                        for item in records
                    ):
                        raise AnalysisLeaseError(
                            "analysis lease identity already exists"
                        )
                    self._append_bounded_record(records, new_record)
                    state.extra["analysis_leases"] = records

                self.store.update(self.identity, reserve)
                # A substitution detected after canonical replacement becomes
                # cleanup_pending through the handoff reconciliation below;
                # it is never handed to the sandbox as a usable lease.
                pending_tree.verify_bindings()
                pending_tree.close()
            return AnalysisLease(
                ref=ref,
                root=root,
                work_dir=work_dir,
                reservation_bytes=reservation_bytes,
                work_tree_limit_bytes=selected_limit,
                base_revision=before.revision,
                _manager=self,
                _tree=tree,
                _work_tree=work_tree,
                _owner_lock=owner_lock,
                _session_lock=session_lock,
            )
        except BaseException as error:
            if pending_tree is not None:
                # A control exception may land after create_root() published
                # its descriptor/reference but before the caller's STORE.
                # Reconstruct only from that held descriptor, never by
                # restatting the possibly substituted public path.
                if tree is None:
                    try:
                        tree = pending_tree.root_reference
                    except BaseException as cleanup_error:
                        error = _merge_cleanup_failure(
                            error,
                            cleanup_error,
                            label=(
                                "pending analysis root reconciliation failed"
                            ),
                        )
                if work_tree is None:
                    try:
                        work_tree = pending_tree.work_reference
                    except BaseException as cleanup_error:
                        error = _merge_cleanup_failure(
                            error,
                            cleanup_error,
                            label=(
                                "pending analysis work reconciliation failed"
                            ),
                        )
            canonical_record_present: bool | None = None
            if analysis_id is not None:
                # Never trust a local "committed" bit across the atomic state
                # replacement's CALL -> STORE boundary.  Reconcile the actual
                # canonical record while the shared session lock and owner flock
                # still exclude writers and recovery.  Only proven absence may
                # authorize uncommitted-tree deletion below.
                try:
                    with ChallengeLock(
                        self.paths.runtime / ANALYSIS_ADMISSION_LOCK
                    ) as handoff_lock:
                        handoff_lock.acquire()

                        observed = self.store.load(
                            self.identity,
                            recover=False,
                        )
                        observed_record = self._find_record(
                            observed,
                            analysis_id,
                        )
                        if observed_record is None:
                            canonical_record_present = False
                        else:
                            if (
                                observed_record.get("scope_fingerprint")
                                != self.scope_fingerprint
                                or tree is None
                                or (
                                    observed_record.get("root_device"),
                                    observed_record.get("root_inode"),
                                )
                                != (tree.device, tree.inode)
                            ):
                                raise AnalysisLeaseError(
                                    "analysis handoff record binding changed"
                                )
                            canonical_record_present = True

                        def mark_handoff_failure(
                            state: ChallengeState,
                        ) -> None:
                            record = self._find_record(state, analysis_id)
                            if record is None:
                                raise AnalysisLeaseError(
                                    "analysis handoff record disappeared"
                                )
                            if (
                                record.get("scope_fingerprint")
                                != self.scope_fingerprint
                                or tree is None
                                or (
                                    record.get("root_device"),
                                    record.get("root_inode"),
                                )
                                != (tree.device, tree.inode)
                            ):
                                raise AnalysisLeaseError(
                                    "analysis handoff record binding changed"
                                )
                            if record.get("status") in _TERMINAL_STATUSES:
                                return
                            if record.get("status") not in _ACTIVE_STATUSES:
                                raise AnalysisLeaseError(
                                    "analysis handoff record is not active"
                                )
                            record["status"] = "cleanup_pending"
                            record["reason_code"] = (
                                "analysis_acquire_handoff_failed"
                            )
                            record["observed_at"] = utc_now()

                        if canonical_record_present:
                            self.store.update(
                                self.identity,
                                mark_handoff_failure,
                            )
                except BaseException as cleanup_error:
                    canonical_record_present = None
                    error = _merge_cleanup_failure(
                        error,
                        cleanup_error,
                        label=(
                            "analysis acquire handoff persistence failed"
                        ),
                    )
            uncommitted_removed = False
            if tree is not None and canonical_record_present is False:
                try:
                    self._remove_tree(tree)
                    uncommitted_removed = True
                except BaseException as cleanup_error:
                    error = _merge_cleanup_failure(
                        error,
                        cleanup_error,
                        label="uncommitted analysis cleanup failed",
                    )
            if pending_tree is not None:
                try:
                    pending_tree.close()
                except BaseException as cleanup_error:
                    error = _merge_cleanup_failure(
                        error,
                        cleanup_error,
                        label=(
                            "pending analysis descriptor cleanup failed"
                        ),
                    )
            if owner_lock is not None:
                lock_device, lock_inode = owner_lock.device, owner_lock.inode
                try:
                    owner_lock.release()
                except BaseException as cleanup_error:
                    error = _merge_cleanup_failure(
                        error,
                        cleanup_error,
                        label="owner lock cleanup failed",
                    )
                else:
                    root_was_never_started = (
                        pending_tree is None
                        or not pending_tree.root_creation_started
                    )
                    if (
                        canonical_record_present is False
                        and root is not None
                        and lock_device >= 0
                        and lock_inode > 0
                        and (
                            uncommitted_removed
                            or root_was_never_started
                        )
                    ):
                        try:
                            with ChallengeLock(
                                self.paths.runtime / ANALYSIS_ADMISSION_LOCK
                            ) as cleanup_lock:
                                cleanup_lock.acquire()
                                self._unlink_released_owner_lock(
                                    analysis_id=root.name,
                                    device=lock_device,
                                    inode=lock_inode,
                                )
                        except BaseException as cleanup_error:
                            error = _merge_cleanup_failure(
                                error,
                                cleanup_error,
                                label=(
                                    "uncommitted owner lock cleanup failed"
                                ),
                            )
            try:
                session_lock.release()
            except BaseException as cleanup_error:
                error = _merge_cleanup_failure(
                    error,
                    cleanup_error,
                    label="session lock cleanup failed",
                )
            raise error

    def _require_owned_lease(
        self,
        lease: AnalysisLease,
    ) -> dict[str, object]:
        if not isinstance(lease, AnalysisLease) or lease._manager is not self:
            raise AnalysisLeaseError("analysis lease belongs to another manager")
        if lease._released:
            raise AnalysisLeaseError("analysis lease is already released")
        if lease.ref.scope_fingerprint != self.scope_fingerprint:
            raise AnalysisLeaseError("analysis lease scope binding changed")
        state = self.store.load(self.identity, recover=False)
        record = self._find_record(state, lease.ref.analysis_id)
        if record is None:
            raise AnalysisLeaseError("analysis lease record disappeared")
        if record.get("scope_fingerprint") != self.scope_fingerprint:
            raise AnalysisLeaseError("analysis lease record changed scope")
        if (
            record.get("root_device"),
            record.get("root_inode"),
        ) != (lease._tree.device, lease._tree.inode):
            raise AnalysisLeaseError("analysis lease root binding changed")
        if (
            record.get("work_device"),
            record.get("work_inode"),
        ) != (lease._work_tree.device, lease._work_tree.inode):
            raise AnalysisLeaseError("analysis lease work binding changed")
        return record

    def bind_runtime(
        self,
        lease: AnalysisLease,
        runtime_id: str,
    ) -> ChallengeState:
        """Durably bind the deterministic runtime before sandbox launch."""

        self._require_owned_lease(lease)
        if type(runtime_id) is not str or RUNTIME_ID.fullmatch(runtime_id) is None:
            raise ValueError("invalid analysis runtime identity")

        def bind(state: ChallengeState) -> None:
            record = self._find_record(state, lease.ref.analysis_id)
            if record is None or record.get("status") != "running":
                raise AnalysisLeaseError(
                    "only a running analysis lease may bind a runtime"
                )
            existing = record.get("runtime_id")
            if existing not in {None, runtime_id}:
                raise AnalysisLeaseError("analysis runtime binding changed")
            record["runtime_id"] = runtime_id
            record["observed_at"] = utc_now()

        return self.store.update(self.identity, bind)

    def mark_cleanup_pending(
        self,
        lease: AnalysisLease,
        reason_code: str = "analysis_cleanup_pending",
    ) -> ChallengeState:
        self._require_owned_lease(lease)
        if (
            type(reason_code) is not str
            or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", reason_code) is None
        ):
            raise ValueError("invalid analysis cleanup reason code")

        def mark(state: ChallengeState) -> None:
            record = self._find_record(state, lease.ref.analysis_id)
            if record is None:
                raise AnalysisLeaseError("analysis lease record disappeared")
            if record.get("status") in _TERMINAL_STATUSES:
                raise AnalysisLeaseError("analysis lease is already terminal")
            if record.get("status") not in _ACTIVE_STATUSES:
                raise AnalysisLeaseError("analysis lease status is invalid")
            record["status"] = "cleanup_pending"
            record["reason_code"] = reason_code
            record["observed_at"] = utc_now()

        return self.store.update(self.identity, mark)

    def _terminalize(
        self,
        analysis_id: str,
        *,
        status: str,
        reason_code: str | None,
    ) -> ChallengeState:
        if status not in _TERMINAL_STATUSES:
            raise ValueError("invalid terminal analysis status")

        def finish(state: ChallengeState) -> None:
            record = self._find_record(state, analysis_id)
            if record is None:
                raise AnalysisLeaseError("analysis lease record disappeared")
            if record.get("status") not in _ACTIVE_STATUSES:
                raise AnalysisLeaseError(
                    "analysis lease is not active during terminalization"
                )
            record["status"] = status
            record["storage_reservation_bytes"] = 0
            record["reason_code"] = reason_code
            record["finished_at"] = utc_now()
            record["observed_at"] = record["finished_at"]

        return self.store.update(self.identity, finish)

    def finalize(
        self,
        lease: AnalysisLease,
        *,
        status: str = "completed",
        reason_code: str | None = None,
        runtime_absent: bool | None = None,
    ) -> ChallengeState:
        """Release reservation only after runtime and tree absence are proven."""

        record = self._require_owned_lease(lease)
        if status not in {"completed", "failed"}:
            raise ValueError("normal finalize status must be completed or failed")
        if reason_code is not None and (
            type(reason_code) is not str
            or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", reason_code) is None
        ):
            raise ValueError("invalid analysis terminal reason code")

        primary: BaseException | None = None
        result: ChallengeState | None = None
        try:
            with ChallengeLock(
                self.paths.runtime / ANALYSIS_ADMISSION_LOCK
            ) as admission_lock:
                admission_lock.acquire()
                record = self._require_owned_lease(lease)
                if record.get("status") != "cleanup_pending":
                    self.mark_cleanup_pending(
                        lease,
                        reason_code or "analysis_cleanup_pending",
                    )
                    record = self._require_owned_lease(lease)
                if not self._runtime_absent(
                    lease.ref,
                    record.get("runtime_id"),
                    runtime_absent,
                ):
                    raise AnalysisLeaseError(
                        "analysis runtime absence could not be proven; "
                        "reservation retained"
                    )
                try:
                    current_work = capture_exact_tree(
                        self.paths.root,
                        lease.work_dir,
                    )
                except HotPathCleanupError as error:
                    raise AnalysisLeaseError(
                        "analysis work directory absence/identity is uncertain; "
                        "reservation retained"
                    ) from error
                if current_work != lease._work_tree:
                    raise AnalysisLeaseError(
                        "analysis work directory identity changed; "
                        "reservation retained"
                    )
                self._remove_tree(lease._tree)
                result = self._terminalize(
                    lease.ref.analysis_id,
                    status=status,
                    reason_code=reason_code,
                )
                owner_lock = lease._owner_lock
                if owner_lock is None:
                    raise AnalysisLeaseError(
                        "analysis owner lock disappeared before terminal cleanup"
                    )
                try:
                    self._retire_owner_lock(
                        owner_lock,
                        lease.ref.analysis_id,
                    )
                finally:
                    lease._owner_lock = None
        except BaseException as error:
            primary = error
        try:
            lease._release_locks()
        except BaseException as error:
            if primary is None:
                primary = error
            else:
                primary = _merge_cleanup_failure(
                    primary,
                    error,
                    label="analysis lease lock release failed",
                )
        if primary is not None:
            raise primary
        assert result is not None
        return result

    def abandon(
        self,
        lease: AnalysisLease,
        *,
        reason_code: str = "analysis_interrupted",
    ) -> ChallengeState:
        """Retain reservation and return locks when cleanup is uncertain."""

        primary: BaseException | None = None
        result: ChallengeState | None = None
        try:
            result = self.mark_cleanup_pending(lease, reason_code)
        except BaseException as error:
            primary = error
        try:
            lease._release_locks()
        except BaseException as error:
            if primary is None:
                primary = error
            else:
                primary = _merge_cleanup_failure(
                    primary,
                    error,
                    label="analysis lease lock release failed",
                )
        if primary is not None:
            raise primary
        assert result is not None
        return result

    def _lease_directories(self) -> dict[str, ExactTreeReference]:
        self._ensure_roots()
        descriptor = os.open(self.analysis_root, _DIRECTORY_FLAGS)
        try:
            names = sorted(os.listdir(descriptor))
            if len(names) > 2 * MAX_ANALYSIS_LEASES:
                raise AnalysisLeaseError(
                    "analysis recovery directory entry bound exceeded"
                )
            result: dict[str, ExactTreeReference] = {}
            for name in names:
                if ANALYSIS_ID.fullmatch(name) is None:
                    raise AnalysisLeaseError(
                        "analysis recovery encountered an unknown entry"
                    )
                metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if not stat.S_ISDIR(metadata.st_mode):
                    raise AnalysisLeaseError(
                        "analysis recovery lease entry is not a directory"
                    )
                result[name] = ExactTreeReference(
                    relative=PurePosixPath(
                        "runtime", ANALYSIS_DIRECTORY, name
                    ),
                    device=metadata.st_dev,
                    inode=metadata.st_ino,
                )
            return result
        except OSError as error:
            raise AnalysisLeaseError(
                "analysis recovery root cannot be scanned"
            ) from error
        finally:
            os.close(descriptor)

    def _mark_recovery_pending(
        self,
        analysis_id: str,
        reason_code: str,
    ) -> ChallengeState:
        def mark(state: ChallengeState) -> None:
            record = self._find_record(state, analysis_id)
            if record is None or record.get("status") not in _ACTIVE_STATUSES:
                raise AnalysisLeaseError(
                    "analysis recovery record is no longer active"
                )
            record["status"] = "cleanup_pending"
            record["reason_code"] = reason_code
            record["observed_at"] = utc_now()

        return self.store.update(self.identity, mark)

    def _recover_locked(self) -> AnalysisRecoveryReport:
        """Recover stale leases while caller owns admission + session locks."""

        state = self.store.load(self.identity, recover=False)
        self._assert_no_active_writer(state)
        records = self._records(state)
        by_id: dict[str, dict[str, object]] = {}
        for record in records:
            analysis_id = record.get("analysis_id")
            if type(analysis_id) is not str or ANALYSIS_ID.fullmatch(analysis_id) is None:
                raise AnalysisLeaseError("analysis recovery record is invalid")
            if record.get("scope_fingerprint") != self.scope_fingerprint:
                raise AnalysisLeaseError(
                    "analysis recovery encountered another scope"
                )
            if analysis_id in by_id:
                raise AnalysisLeaseError(
                    "analysis recovery encountered a duplicate lease"
                )
            by_id[analysis_id] = record

        directories = self._lease_directories()
        recovered: list[str] = []
        live: list[str] = []
        pending: list[str] = []

        # A terminal record is an absence attestation. Reappearance under the
        # same logical name is not treated as engine-owned and fails closed.
        for analysis_id, record in by_id.items():
            if (
                record.get("status") in _TERMINAL_STATUSES
                and analysis_id in directories
            ):
                raise AnalysisLeaseError(
                    "terminal analysis workspace unexpectedly reappeared"
                )

        for analysis_id, record in by_id.items():
            if record.get("status") not in _ACTIVE_STATUSES:
                continue
            ref = AnalysisLeaseRef(analysis_id, self.scope_fingerprint)
            recorded_tree = self._tree_from_record(record)
            recorded_work = self._work_from_record(record)
            observed_tree = directories.get(analysis_id)
            if observed_tree is not None and observed_tree != recorded_tree:
                raise AnalysisLeaseError(
                    "analysis recovery root identity changed"
                )
            if observed_tree is not None:
                try:
                    observed_work = capture_exact_tree(
                        self.paths.root,
                        self._lease_root(analysis_id) / "work",
                    )
                except HotPathCleanupError as error:
                    raise AnalysisLeaseError(
                        "analysis recovery work directory is unavailable"
                    ) from error
                if observed_work != recorded_work:
                    raise AnalysisLeaseError(
                        "analysis recovery work identity changed"
                    )
                owner = _read_owner(
                    self._lease_root(analysis_id) / OWNER_DOCUMENT
                )
                _validate_owner(
                    owner,
                    expected_ref=ref,
                    expected_tree=recorded_tree,
                    expected_work=recorded_work,
                )
                for field in (
                    "owner_pid",
                    "owner_start_ticks",
                    "owner_boot_id",
                    "work_device",
                    "work_inode",
                    "base_revision",
                    "work_tree_limit_bytes",
                    "storage_reservation_bytes",
                    "created_at",
                ):
                    # Reservation is zero only after terminalization, which is
                    # excluded above, so immutable receipt equality is exact.
                    if owner.get(field) != record.get(field):
                        raise AnalysisLeaseError(
                            "analysis owner receipt changed after admission"
                        )
            try:
                owner_lock = _OwnerLock.acquire(
                    self._lock_path(analysis_id),
                    blocking=False,
                )
            except AnalysisLeaseBusy:
                live.append(analysis_id)
                continue
            try:
                if (
                    record.get("status") == "running"
                    and _owner_is_live(record)
                ):
                    # Flock is authoritative; an alive PID with no lock is an
                    # inconsistent handoff, so preserve bytes and reservation.
                    live.append(analysis_id)
                    continue
                if not self._runtime_absent(
                    ref,
                    record.get("runtime_id"),
                ):
                    self._mark_recovery_pending(
                        analysis_id,
                        "analysis_runtime_cleanup_pending",
                    )
                    pending.append(analysis_id)
                    continue
                self._mark_recovery_pending(
                    analysis_id,
                    "analysis_owner_lost",
                )
                if observed_tree is not None:
                    self._remove_tree(recorded_tree)
                self._terminalize(
                    analysis_id,
                    status="recovered",
                    reason_code="analysis_owner_lost",
                )
                self._retire_owner_lock(owner_lock, analysis_id)
                recovered.append(analysis_id)
            finally:
                owner_lock.release()

        # A directory with no canonical record can only be an allocation that
        # crashed before quota reservation commit. Its immutable owner receipt
        # and external flock are required before any cleanup.
        for analysis_id, tree in directories.items():
            if analysis_id in by_id:
                continue
            owner = _read_owner(self._lease_root(analysis_id) / OWNER_DOCUMENT)
            try:
                observed_work = capture_exact_tree(
                    self.paths.root,
                    self._lease_root(analysis_id) / "work",
                )
            except HotPathCleanupError as error:
                raise AnalysisLeaseError(
                    "analysis orphan work directory is unavailable"
                ) from error
            ref = _validate_owner(
                owner,
                expected_ref=AnalysisLeaseRef(
                    analysis_id,
                    self.scope_fingerprint,
                ),
                expected_tree=tree,
                expected_work=observed_work,
            )
            try:
                owner_lock = _OwnerLock.acquire(
                    self._lock_path(analysis_id),
                    blocking=False,
                )
            except AnalysisLeaseBusy:
                live.append(analysis_id)
                continue
            try:
                if _owner_is_live(owner):
                    live.append(analysis_id)
                    continue
                self._remove_tree(tree)
                terminal = self._record_from_owner(
                    owner,
                    status="recovered",
                    reservation_bytes=0,
                    reason_code="analysis_precommit_orphan",
                    finished_at=utc_now(),
                )

                def record_recovery(current: ChallengeState) -> None:
                    self._assert_no_active_writer(current)
                    current_records = self._records(current)
                    if any(
                        item.get("analysis_id") == ref.analysis_id
                        for item in current_records
                    ):
                        raise AnalysisLeaseError(
                            "analysis orphan acquired a conflicting record"
                        )
                    self._append_bounded_record(current_records, terminal)
                    current.extra["analysis_leases"] = current_records

                self.store.update(self.identity, record_recovery)
                self._retire_owner_lock(owner_lock, analysis_id)
                recovered.append(analysis_id)
            finally:
                owner_lock.release()

        self._reconcile_terminal_locks(by_id, directories)

        return AnalysisRecoveryReport(
            recovered=tuple(sorted(recovered)),
            live=tuple(sorted(live)),
            cleanup_pending=tuple(sorted(pending)),
        )

    def _reconcile_terminal_locks(
        self,
        records: Mapping[str, Mapping[str, object]],
        directories: Mapping[str, ExactTreeReference],
    ) -> None:
        descriptor = os.open(self.lock_root, _DIRECTORY_FLAGS)
        try:
            names = sorted(os.listdir(descriptor))
        finally:
            os.close(descriptor)
        if len(names) > 2 * MAX_ANALYSIS_LEASES:
            raise AnalysisLeaseError(
                "analysis owner-lock recovery entry bound exceeded"
            )
        for name in names:
            if not name.endswith(".lock"):
                raise AnalysisLeaseError(
                    "analysis owner-lock recovery encountered an unknown entry"
                )
            analysis_id = name.removesuffix(".lock")
            if ANALYSIS_ID.fullmatch(analysis_id) is None:
                raise AnalysisLeaseError(
                    "analysis owner-lock recovery encountered an invalid name"
                )
            record = records.get(analysis_id)
            if (
                record is None
                or record.get("status") not in _TERMINAL_STATUSES
                or analysis_id in directories
            ):
                # Active and unknown locks are never deleted.
                continue
            try:
                owner_lock = _OwnerLock.acquire(
                    self._lock_path(analysis_id),
                    blocking=False,
                )
            except AnalysisLeaseBusy as error:
                raise AnalysisLeaseError(
                    "terminal analysis owner lock is unexpectedly live"
                ) from error
            try:
                self._retire_owner_lock(owner_lock, analysis_id)
            finally:
                owner_lock.release()

    def recover(self) -> AnalysisRecoveryReport:
        """Recover all bounded crash orphans without disturbing live readers."""

        session_lock = ChallengeLock(
            self.paths.runtime / "session.lock",
            timeout=0,
            shared=True,
        )
        try:
            session_lock.acquire()
        except LockTimeout as error:
            raise AnalysisLeaseBusy(
                "a workspace writer already owns the challenge session"
            ) from error
        try:
            with ChallengeLock(
                self.paths.runtime / ANALYSIS_ADMISSION_LOCK
            ) as admission_lock:
                admission_lock.acquire()
                self._ensure_roots()
                state = self.store.load(self.identity, recover=False)
                self._assert_no_active_writer(state)
                return self._recover_locked()
        finally:
            session_lock.release()


__all__ = [
    "ANALYSIS_ID",
    "AnalysisLease",
    "AnalysisLeaseBusy",
    "AnalysisLeaseError",
    "AnalysisLeaseManager",
    "AnalysisLeaseRef",
    "AnalysisRecoveryReport",
]
