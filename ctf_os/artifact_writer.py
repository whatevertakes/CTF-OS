"""Per-challenge durable artifacts and private per-attempt staging.

Aggregate challenge output is host-owned.  It is never an attempt mount.  An
attempt receives a freshly-created staging directory under the system temp
area, while only this writer promotes verified regular files into aggregate
output through directory file descriptors.
"""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
import errno
import os
from pathlib import Path
import stat
import tempfile
from collections.abc import Iterable

from .models import Attempt, Challenge, timestamp_text


MAX_ARTIFACT_WRITE_BYTES = 1 * 1024 * 1024
MAX_ARTIFACT_IMPORT_BYTES = 8 * 1024 * 1024
MAX_AGGREGATE_LOG_BYTES = 8 * 1024 * 1024
MAX_ATTEMPT_CAPTURE_BYTES = 1 * 1024 * 1024
_STAGING_MARKER = ".ctf-os-sterile-attempt"
_PRIVATE_CAPTURE = ".ctf-os-parent-capture.log"


@dataclass(frozen=True)
class AttemptStaging:
    """Private host paths mounted into one attempt container only."""

    root: Path
    workdir: Path
    artifacts: Path


class ArtifactWriter:
    def __init__(self, output_root: str | Path, contest: str) -> None:
        self.output_root = Path(output_root)
        self.contest = contest
        self.output_root.mkdir(parents=True, exist_ok=True)
        _require_directory(self.output_root, "artifact output root")
        self.contest_root = self.output_root / _safe_name(contest)

    def challenge_dir(self, challenge: Challenge) -> Path:
        path = self.contest_root / _safe_name(challenge.slug)
        _ensure_descendant(path, self.output_root)
        return path

    def prepare_challenge(self, challenge: Challenge) -> Path:
        with self._challenge_fd(challenge) as root_fd:
            final_fd = _open_or_create_dir(root_fd, "final")
            attempts_fd = _open_or_create_dir(root_fd, "attempts")
            os.close(final_fd)
            os.close(attempts_fd)
            _ensure_file_at(root_fd, "notes.md", f"# {challenge.category}/{challenge.name}\n")
            _ensure_file_at(root_fd, "evidence.log", "")
            _ensure_file_at(root_fd, "writeup.md", f"# {challenge.category}/{challenge.name} writeup\n")
        return self.challenge_dir(challenge)

    create_challenge_tree = prepare_challenge

    def attempt_dir(self, challenge: Challenge, attempt: Attempt | str, *, profile: str | None = None) -> Path:
        """Return host metadata location, not a solver-visible mount.

        This compatibility directory may hold host bookkeeping.  New workers
        must call :meth:`create_attempt_staging` and only mount its two private
        children.
        """
        root = self.prepare_challenge(challenge)
        if isinstance(attempt, Attempt):
            attempt_id, attempt_profile = attempt.id, attempt.profile
        else:
            attempt_id, attempt_profile = attempt, profile or "attempt"
        name = f"{_safe_name(attempt_profile)}-{_safe_name(attempt_id)}"
        with self._challenge_fd(challenge) as challenge_fd:
            attempts_fd = _open_or_create_dir(challenge_fd, "attempts")
            try:
                attempt_fd = _open_or_create_dir(attempts_fd, name)
                try:
                    work_fd = _open_or_create_dir(attempt_fd, "work")
                    os.close(work_fd)
                finally:
                    os.close(attempt_fd)
            finally:
                os.close(attempts_fd)
        return root / "attempts" / name

    def create_attempt_staging(self) -> AttemptStaging:
        """Create a mode-0700, marker-backed isolated mount source.

        ``/tmp`` is deliberately outside a project tree, so Codex config
        discovery cannot inherit a repository's ``.codex`` configuration.  No
        credential is copied: the Codex invocation uses its existing auth with
        ``--ignore-user-config``.
        """
        root = Path(tempfile.mkdtemp(prefix="ctf-os-attempt-", dir=tempfile.gettempdir()))
        try:
            # A process may legally have an owner-bit umask (for example
            # 0777).  Reclaim access to this just-created, private root before
            # opening its descriptor; the final contract is still fchmod'd.
            os.chmod(root, 0o700)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                # ``mkdtemp`` starts private, but make every required mode
                # exact through descriptors so a hostile umask cannot weaken
                # the staging contract.
                os.fchmod(root_fd, 0o700)
                _write_new_at(root_fd, _STAGING_MARKER, "ctf-os sterile attempt boundary\n", 0o600)
                _create_staging_child(root_fd, "work")
                _create_staging_child(root_fd, "artifacts")
            finally:
                os.close(root_fd)
            workdir, artifacts = root / "work", root / "artifacts"
            _require_sterile_staging(root, workdir)
            return AttemptStaging(root=root, workdir=workdir, artifacts=artifacts)
        except BaseException:
            _discard_new_staging(root)
            raise

    @staticmethod
    def staging_for_workdir(workdir: str | Path) -> AttemptStaging:
        work = Path(workdir)
        root = work.parent
        artifacts = root / "artifacts"
        # Do not ``resolve()`` this worker-adjacent path.  The descriptor
        # walk below is the authority: each component is opened relative to
        # the private root with O_NOFOLLOW, so a parent swap or intermediate
        # symlink cannot turn a later open into another attempt's source.
        with _open_attempt_staging(work):
            pass
        return AttemptStaging(root=root, workdir=work, artifacts=artifacts)

    @staticmethod
    def cleanup_attempt_staging(workdir: str | Path) -> None:
        """Delete an exact staging tree, or visibly fail closed.

        The host can remove ordinary worker-owned entries from the sticky
        mount roots, but it cannot safely traverse a worker-owned mode-000
        directory.  The pool's unprivileged scrub phase must remove those
        first.  Do not turn that failure into a successful-looking cleanup.
        A successfully removed root is already clean, so retrying cleanup is
        a no-op.  An unsafe root-level parent capture is deliberately retained
        before any staging child is removed, making the residual actionable.
        """
        work = Path(workdir)
        if work.is_absolute() and work.name == "work":
            try:
                os.lstat(work.parent)
            except FileNotFoundError:
                return
        staging = ArtifactWriter.staging_for_workdir(work)
        try:
            with _open_attempt_staging(staging.workdir) as (root_fd, work_fd, artifacts_fd):
                _remove_private_capture(root_fd)
                _remove_host_accessible_tree(work_fd)
                _remove_host_accessible_tree(artifacts_fd)
                os.rmdir("work", dir_fd=root_fd)
                os.rmdir("artifacts", dir_fd=root_fd)
                os.unlink(_STAGING_MARKER, dir_fd=root_fd)
                os.fsync(root_fd)
            os.rmdir(staging.root)
        except OSError as exc:
            raise ValueError("private attempt staging cleanup was incomplete") from exc

    def append_evidence(self, challenge: Challenge, text: str) -> Path:
        self.prepare_challenge(challenge)
        with self._challenge_fd(challenge) as fd:
            _append_at(fd, "evidence.log", text, maximum=MAX_AGGREGATE_LOG_BYTES)
        return self.challenge_dir(challenge) / "evidence.log"

    write_evidence = append_evidence

    def append_note(self, challenge: Challenge, kind: str, text: str) -> Path:
        if not kind.strip():
            raise ValueError("note kind is required")
        self.prepare_challenge(challenge)
        with self._challenge_fd(challenge) as fd:
            _append_at(fd, "notes.md", f"\n## {kind.strip().upper()} — {timestamp_text()}\n{text.rstrip()}\n", maximum=MAX_AGGREGATE_LOG_BYTES)
        return self.challenge_dir(challenge) / "notes.md"

    write_note = append_note

    def write_final_exploit(self, challenge: Challenge, content: str) -> Path:
        return self._write_final(challenge, "exploit.py", content)

    def write_replay(self, challenge: Challenge, content: str) -> Path:
        return self._write_final(challenge, "replay.sh", content)

    def write_writeup(self, challenge: Challenge, content: str) -> Path:
        self.prepare_challenge(challenge)
        with self._challenge_fd(challenge) as fd:
            _replace_at(fd, "writeup.md", content)
        return self.challenge_dir(challenge) / "writeup.md"

    @staticmethod
    def append_attempt_capture(attempt_workdir: str | Path, text: str) -> bool:
        """Capture parent-observed worker output outside both worker mounts.

        Late/stale callbacks may at most alter their own disposable staging
        directory.  They cannot append notes, evidence, or local state events
        until the coordinator promotes this parent-owned capture under the
        current SQLite lease fence.
        """
        try:
            with _open_attempt_staging(Path(attempt_workdir)) as (root_fd, _work_fd, _artifacts_fd):
                return _append_private_capture(root_fd, text)
        except ValueError:
            return False

    def promote_attempt_observations(
        self,
        challenge: Challenge,
        *,
        attempt_workdir: str | Path,
        records: Iterable[object],
    ) -> None:
        """Promote bounded parent captures and parsed records to aggregate output.

        The caller must invoke this inside ``LocalState.run_fenced_operation``
        so lease validation and aggregate writes share one coordinator-held
        critical section.  No worker callback calls this method directly.
        Parsed records, including plan and hypothesis entries, retain their
        arrival order in ``notes.md``.
        """
        staging = self.staging_for_workdir(attempt_workdir)
        with _open_attempt_staging(staging.workdir) as (root_fd, _work_fd, _artifacts_fd):
            captured = _read_regular_at(root_fd, _PRIVATE_CAPTURE, maximum=MAX_ATTEMPT_CAPTURE_BYTES)
        if captured:
            self.append_evidence(challenge, captured.decode("utf-8", errors="replace"))
        for record in records:
            kind = getattr(record, "kind", None)
            content = getattr(record, "content", None)
            if not isinstance(kind, str) or not isinstance(content, str) or not kind.strip():
                continue
            self.append_note(challenge, kind, content[:MAX_ARTIFACT_WRITE_BYTES])

    def _write_final(self, challenge: Challenge, name: str, content: str) -> Path:
        self.prepare_challenge(challenge)
        with self._challenge_fd(challenge) as challenge_fd:
            final_fd = _open_or_create_dir(challenge_fd, "final")
            try:
                _replace_at(final_fd, name, content)
            finally:
                os.close(final_fd)
        return self.challenge_dir(challenge) / "final" / name

    def promote_verified_artifacts(
        self,
        challenge: Challenge,
        *,
        attempt_workdir: str | Path,
        artifact_paths: Iterable[str | Path],
        attempt_artifacts: str | Path | None = None,
    ) -> tuple[Path, ...]:
        """Import bounded regular files from this attempt's private staging.

        Aggregate output is not an eligible input source.  This prevents a
        worker from promoting another attempt's helper, token, evidence, or
        final file simply by naming it in an ``[ARTIFACT]`` record.
        """
        self.prepare_challenge(challenge)
        staging = self.staging_for_workdir(attempt_workdir)
        if attempt_artifacts is not None and not _same_path_lexically(Path(attempt_artifacts), staging.artifacts):
            raise ValueError("attempt artifacts must be the exact private staging artifacts directory")
        approved: list[Path] = []
        # Source descriptors are opened before any destination write.  The
        # descriptor itself is then copied, which snapshots the approved inode
        # and closes the approval/copy TOCTOU window.
        with _open_attempt_staging(staging.workdir) as (_root_fd, work_fd, artifacts_fd):
            for supplied in artifact_paths:
                source = Path(supplied)
                match = _attempt_source_relative(source, staging.workdir, staging.artifacts)
                if match is None:
                    continue
                source_root, components = match
                destination_name = components[-1]
                if destination_name not in {"exploit.py", "replay.sh", "writeup.md"}:
                    continue
                parent_fd = work_fd if source_root == "work" else artifacts_fd
                try:
                    source_fd = _open_regular_at(parent_fd, components)
                except ValueError as exc:
                    # A worker may race its own staging tree.  Refuse the
                    # complete promotion rather than treating an unsafe
                    # declared source as a harmless pathname miss: callers
                    # need a visible failed-closed result and no aggregate
                    # write may follow it.
                    raise ValueError("artifact source has an unsafe intermediate component") from exc
                try:
                    with self._challenge_fd(challenge) as challenge_fd:
                        destination_fd = _open_or_create_dir(challenge_fd, "final") if destination_name in {"exploit.py", "replay.sh"} else challenge_fd
                        try:
                            _copy_fd_atomic_to_fd(source_fd, destination_fd, destination_name)
                        finally:
                            if destination_fd != challenge_fd:
                                os.close(destination_fd)
                finally:
                    os.close(source_fd)
                approved.append(self.challenge_dir(challenge) / ("final" if destination_name in {"exploit.py", "replay.sh"} else "") / destination_name)
        return tuple(approved)

    @contextmanager
    def _challenge_fd(self, challenge: Challenge):
        root_fd = _open_directory(self.output_root)
        try:
            contest_fd = _open_or_create_dir(root_fd, _safe_name(self.contest))
        finally:
            os.close(root_fd)
        try:
            challenge_fd = _open_or_create_dir(contest_fd, _safe_name(challenge.slug))
        finally:
            os.close(contest_fd)
        try:
            yield challenge_fd
        finally:
            os.close(challenge_fd)


def _safe_name(value: str) -> str:
    if not value or value in {".", ".."} or "/" in value or "\\" in value or "\x00" in value:
        raise ValueError(f"unsafe artifact path component: {value!r}")
    return value


def _ensure_descendant(path: Path, root: Path) -> None:
    try:
        path.absolute().relative_to(root.absolute())
    except ValueError as exc:
        raise ValueError(f"artifact path escapes output root: {path}") from exc


def _require_directory(path: Path, label: str) -> None:
    try:
        details = path.lstat()
    except FileNotFoundError as exc:
        raise ValueError(f"{label} does not exist") from exc
    if stat.S_ISLNK(details.st_mode):
        raise ValueError(f"{label} must not be a symlink")
    if not stat.S_ISDIR(details.st_mode):
        raise ValueError(f"{label} must be a directory")


@contextmanager
def _open_attempt_staging(workdir: Path):
    """Open the complete private staging tree without following any child.

    ``/work`` and ``/artifacts`` are worker-writable mount sources.  Never
    authorize them with ``Path.resolve`` and then reopen by pathname: after a
    root descriptor is trusted, every child is opened through that descriptor
    with O_NOFOLLOW and held until the caller is done with it.
    """
    if not workdir.is_absolute() or workdir.name != "work":
        raise ValueError("sterile attempt workdir must be an absolute work directory")
    root = workdir.parent
    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ValueError("sterile attempt root is unsafe") from exc
    work_fd = artifacts_fd = marker_fd = None
    try:
        root_info = os.fstat(root_fd)
        if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.getuid()
                or stat.S_IMODE(root_info.st_mode) != 0o700):
            raise ValueError("sterile attempt root must be owned and mode 0700")
        try:
            marker_fd = os.open(_STAGING_MARKER, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
            marker_info = os.fstat(marker_fd)
        except OSError as exc:
            raise ValueError("sterile attempt boundary marker is missing or unsafe") from exc
        if (not stat.S_ISREG(marker_info.st_mode) or marker_info.st_uid != os.getuid()
                or stat.S_IMODE(marker_info.st_mode) != 0o600):
            raise ValueError("sterile attempt boundary marker must be owned and mode 0600")
        try:
            work_fd = os.open("work", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
            artifacts_fd = os.open("artifacts", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        except OSError as exc:
            raise ValueError("private attempt staging child is missing or unsafe") from exc
        for descriptor, label in ((work_fd, "workdir"), (artifacts_fd, "artifacts")):
            details = os.fstat(descriptor)
            if (not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid()
                    or stat.S_IMODE(details.st_mode) != 0o1777):
                raise ValueError(f"private attempt {label} must be host-owned and mode 01777")
        yield root_fd, work_fd, artifacts_fd
    finally:
        for descriptor in (marker_fd, artifacts_fd, work_fd, root_fd):
            if descriptor is not None:
                os.close(descriptor)


def _require_sterile_staging(root: Path, workdir: Path) -> None:
    if root != workdir.parent:
        raise ValueError("sterile attempt root does not match workdir")
    with _open_attempt_staging(workdir):
        pass


def _open_directory(path: Path) -> int:
    _require_directory(path, "artifact directory")
    try:
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ValueError(f"refusing unsafe artifact directory: {path}") from exc


def _open_or_create_dir(parent_fd: int, name: str) -> int:
    _safe_name(name)
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    try:
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except OSError as exc:
        raise ValueError(f"artifact directory component is unsafe or replaced: {name}") from exc


def _assert_no_symlink_at(parent_fd: int, name: str) -> None:
    try:
        details = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(details.st_mode):
        raise ValueError(f"artifact destination is a symlink: {name}")
    if not stat.S_ISREG(details.st_mode):
        raise ValueError(f"artifact destination is not a regular file: {name}")


def _ensure_file_at(parent_fd: int, name: str, initial: str) -> None:
    try:
        _replace_at(parent_fd, name, initial, exclusive=True)
    except FileExistsError:
        _assert_no_symlink_at(parent_fd, name)


def _bounded_bytes(text: str, *, limit: int = MAX_ARTIFACT_WRITE_BYTES) -> bytes:
    if not isinstance(text, str):
        raise TypeError("artifact content must be text")
    encoded = text.encode("utf-8")
    if len(encoded) > limit:
        raise ValueError(f"artifact write exceeds {limit} byte limit")
    return encoded


def _write_all(fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(fd, payload[offset:])
        if written <= 0:
            raise OSError("short artifact write")
        offset += written


def _append_at(parent_fd: int, name: str, text: str, *, maximum: int = MAX_ARTIFACT_WRITE_BYTES,
               reject_overflow: bool = True) -> bool:
    payload_text = text if not text or text.endswith("\n") else text + "\n"
    payload = _bounded_bytes(payload_text)
    _assert_no_symlink_at(parent_fd, name)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
    except OSError as exc:
        raise ValueError(f"refusing unsafe artifact append target: {name}") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("artifact append target is not a regular file")
        current = os.fstat(fd).st_size
        if current + len(payload) > maximum:
            if reject_overflow:
                raise ValueError(f"artifact aggregate log exceeds {maximum} byte limit")
            return False
        _write_all(fd, payload)
        os.fsync(fd)
        return True
    finally:
        os.close(fd)


def _replace_at(parent_fd: int, name: str, text: str, *, exclusive: bool = False) -> None:
    payload = _bounded_bytes(text)
    _assert_no_symlink_at(parent_fd, name)
    temporary = f".{name}.{os.getpid()}.{next(tempfile._get_candidate_names())}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        fd = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
        try:
            _write_all(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        if exclusive:
            try:
                os.link(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
            except FileExistsError:
                raise
            finally:
                os.unlink(temporary, dir_fd=parent_fd)
        else:
            _assert_no_symlink_at(parent_fd, name)
            os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        raise


def _write_new_at(parent_fd: int, name: str, text: str, mode: int) -> None:
    """Create one private file with a mode unaffected by the caller's umask."""
    _safe_name(name)
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent_fd)
    try:
        os.fchmod(fd, mode)
        _write_all(fd, _bounded_bytes(text))
        os.fsync(fd)
    finally:
        os.close(fd)


def _create_staging_child(root_fd: int, name: str) -> None:
    """Create then expose one worker mount source with its exact sticky mode."""
    _safe_name(name)
    os.mkdir(name, 0o700, dir_fd=root_fd)
    # The parent is private and this name was just created, so this bootstrap
    # cannot touch a worker path.  It handles an owner-bit umask before the
    # required no-follow descriptor open and final fchmod below.
    os.chmod(name, 0o700, dir_fd=root_fd, follow_symlinks=False)
    try:
        child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
    except OSError:
        # The parent was created by this process and is private.  Leave the
        # caller's exceptional cleanup to remove a partial tree.
        raise
    try:
        os.fchmod(child_fd, 0o1777)
    finally:
        os.close(child_fd)


def _remove_host_accessible_tree(directory_fd: int) -> None:
    """Unlink one trusted tree without opening symlink targets.

    A nested foreign-owned directory is deliberately not chmodded or walked:
    only its owning ``ctf`` user may safely normalize it in the separate
    scrubber.  Raising here leaves the staging root intact for diagnosis and
    prevents cleanup from being reported as successful.
    """
    owner = os.getuid()
    try:
        with os.scandir(directory_fd) as entries:
            names = [entry.name for entry in entries]
        for name in names:
            details = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(details.st_mode):
                if details.st_uid != owner:
                    raise ValueError("worker-owned nested directory requires unprivileged staging scrub")
                # We own this directory.  Restore search/write access before
                # opening it by descriptor; no symlink target is chmodded.
                os.chmod(name, 0o700, dir_fd=directory_fd, follow_symlinks=False)
                child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
                try:
                    child_info = os.fstat(child_fd)
                    if not stat.S_ISDIR(child_info.st_mode) or child_info.st_uid != owner:
                        raise ValueError("staging directory changed during cleanup")
                    _remove_host_accessible_tree(child_fd)
                finally:
                    os.close(child_fd)
                os.rmdir(name, dir_fd=directory_fd)
            else:
                # unlinkat removes the directory entry itself; it never
                # follows a symlink placed by a worker.
                os.unlink(name, dir_fd=directory_fd)
    except OSError as exc:
        raise ValueError("private attempt staging cleanup was incomplete") from exc


def _remove_private_capture(root_fd: int) -> None:
    """Remove only the parent-owned capture entry from one trusted root.

    ``work`` and ``artifacts`` are worker mount roots, but the capture is a
    host-created root child.  Do not let a malformed entry turn cleanup into
    an unlink of an arbitrary object: verify the opened inode and the exact
    directory entry before removing it through ``root_fd``.
    """
    try:
        fd = os.open(
            _PRIVATE_CAPTURE,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=root_fd,
        )
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ValueError(
            "private attempt staging retained: parent capture retained; "
            "root-level .ctf-os-parent-capture.log is not a safe private file"
        ) from exc
    try:
        details = os.fstat(fd)
        if not _is_private_capture(details):
            raise ValueError(
                "private attempt staging retained: parent capture retained; "
                "root-level .ctf-os-parent-capture.log must be a host-owned regular "
                "file with mode 0600 and exactly one link"
            )
        try:
            entry = os.stat(_PRIVATE_CAPTURE, dir_fd=root_fd, follow_symlinks=False)
        except OSError as exc:
            raise ValueError(
                "private attempt staging retained: parent capture retained; "
                "root-level .ctf-os-parent-capture.log changed during cleanup"
            ) from exc
        if (entry.st_dev, entry.st_ino) != (details.st_dev, details.st_ino):
            raise ValueError(
                "private attempt staging retained: parent capture retained; "
                "root-level .ctf-os-parent-capture.log changed during cleanup"
            )
        os.unlink(_PRIVATE_CAPTURE, dir_fd=root_fd)
        os.fsync(root_fd)
    finally:
        os.close(fd)


def _is_private_capture(details: os.stat_result) -> bool:
    return (
        stat.S_ISREG(details.st_mode)
        and details.st_uid == os.getuid()
        and stat.S_IMODE(details.st_mode) == 0o600
        and details.st_nlink == 1
    )


def _append_private_capture(root_fd: int, text: str) -> bool:
    """Append a bounded capture while preserving its strict cleanup contract."""
    payload_text = text if not text or text.endswith("\n") else text + "\n"
    payload = _bounded_bytes(payload_text)
    created = False
    try:
        fd = os.open(
            _PRIVATE_CAPTURE,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_NOFOLLOW,
            0o600,
            dir_fd=root_fd,
        )
        created = True
    except FileExistsError:
        try:
            fd = os.open(
                _PRIVATE_CAPTURE,
                os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW,
                dir_fd=root_fd,
            )
        except OSError as exc:
            raise ValueError("private attempt capture is unsafe") from exc
    except OSError as exc:
        raise ValueError("private attempt capture is unsafe") from exc
    try:
        details = os.fstat(fd)
        if created and stat.S_ISREG(details.st_mode) and details.st_uid == os.getuid() and details.st_nlink == 1:
            os.fchmod(fd, 0o600)
            details = os.fstat(fd)
        if not _is_private_capture(details):
            raise ValueError("private attempt capture is unsafe")
        if details.st_size + len(payload) > MAX_ATTEMPT_CAPTURE_BYTES:
            return False
        _write_all(fd, payload)
        os.fsync(fd)
        return True
    finally:
        os.close(fd)


def _discard_new_staging(root: Path) -> None:
    """Best-effort cleanup for a staging tree that never reached a worker."""
    try:
        # This exceptional path executes before a staging value is returned,
        # so no worker can have written into it.  It is intentionally not used
        # for live attempt cleanup.
        for child in root.iterdir():
            if child.is_dir() and not child.is_symlink():
                for nested in child.iterdir():
                    nested.unlink(missing_ok=True)
                child.rmdir()
            else:
                child.unlink(missing_ok=True)
        root.rmdir()
    except OSError:
        pass


def _same_path_lexically(left: Path, right: Path) -> bool:
    return left.is_absolute() and right.is_absolute() and left.parts == right.parts


def _attempt_source_relative(source: Path, workdir: Path, artifacts: Path) -> tuple[str, tuple[str, ...]] | None:
    """Map only a lexical source below this attempt's exact mount roots."""
    if not source.is_absolute() or any(part in {"", ".", ".."} for part in source.parts):
        return None
    for label, root in (("work", workdir), ("artifacts", artifacts)):
        if not _same_path_lexically(root, root.absolute()):
            return None
        root_parts = root.parts
        if source.parts[:len(root_parts)] != root_parts:
            continue
        remainder = source.parts[len(root_parts):]
        if not remainder or any(part in {"", ".", ".."} for part in remainder):
            return None
        try:
            for component in remainder:
                _safe_name(component)
        except ValueError:
            return None
        return label, tuple(remainder)
    return None


def _open_regular_at(root_fd: int, components: tuple[str, ...]) -> int:
    if not components:
        raise ValueError("artifact source has no leaf")
    current_fd = os.dup(root_fd)
    try:
        for component in components[:-1]:
            _safe_name(component)
            try:
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current_fd)
            except OSError as exc:
                raise ValueError("artifact source has an unsafe intermediate component") from exc
            os.close(current_fd)
            current_fd = next_fd
        leaf = components[-1]
        _safe_name(leaf)
        try:
            source_fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=current_fd)
        except OSError as exc:
            raise ValueError("artifact source is unsafe") from exc
        details = os.fstat(source_fd)
        if not stat.S_ISREG(details.st_mode):
            os.close(source_fd)
            raise ValueError("artifact source is not a regular file")
        return source_fd
    finally:
        os.close(current_fd)


def _read_regular_at(parent_fd: int, name: str, *, maximum: int) -> bytes:
    _safe_name(name)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except FileNotFoundError:
        return b""
    except OSError as exc:
        raise ValueError("private attempt capture is unsafe") from exc
    try:
        details = os.fstat(fd)
        if not stat.S_ISREG(details.st_mode) or details.st_size > maximum:
            raise ValueError("private attempt capture is invalid or exceeds its bound")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(64 * 1024, maximum - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ValueError("private attempt capture exceeds its bound")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _copy_fd_atomic_to_fd(source_fd: int, destination_fd: int, name: str) -> None:
    _assert_no_symlink_at(destination_fd, name)
    temporary = f".{name}.{os.getpid()}.{next(tempfile._get_candidate_names())}.tmp"
    try:
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode):
            raise ValueError("artifact source is not a regular file")
        if source_stat.st_size > MAX_ARTIFACT_IMPORT_BYTES:
            raise ValueError("artifact source exceeds import limit")
        target_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=destination_fd)
        try:
            total = 0
            while True:
                chunk = os.read(source_fd, 64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARTIFACT_IMPORT_BYTES:
                    raise ValueError("artifact source exceeds import limit")
                _write_all(target_fd, chunk)
            os.fchmod(target_fd, source_stat.st_mode & 0o777)
            os.fsync(target_fd)
        finally:
            os.close(target_fd)
        _assert_no_symlink_at(destination_fd, name)
        os.replace(temporary, name, src_dir_fd=destination_fd, dst_dir_fd=destination_fd)
        os.fsync(destination_fd)
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=destination_fd)
        except FileNotFoundError:
            pass
        raise
