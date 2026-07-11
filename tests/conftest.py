from __future__ import annotations

from dataclasses import replace
from dataclasses import dataclass
import os
from pathlib import Path
import stat
import tempfile
from typing import Callable

import pytest

from ctf_os.artifact_writer import ArtifactWriter, AttemptStaging
from ctf_os.local_state import LocalState
from ctf_os.models import Attempt, Challenge


_STAGING_PREFIX = "ctf-os-attempt-"
_STAGING_MARKER = ".ctf-os-sterile-attempt"


@dataclass(frozen=True)
class _TrackedStaging:
    root: Path
    root_identity: tuple[int, int]
    marker_identity: tuple[int, int]


class _StagingTracker:
    """Reclaim only staging roots created by the current test.

    Runtime cleanup intentionally retains malformed worker output for
    diagnosis.  Tests need a separate owner-only reaper so a hostile fixture
    cannot leak a global ``/tmp/ctf-os-attempt-*`` directory into later runs.
    Every destructive operation below is descriptor-relative and starts from
    the exact root identity returned by ``create_attempt_staging``.
    """

    def __init__(self) -> None:
        self._created: list[_TrackedStaging] = []

    def track(self, staging: AttemptStaging) -> None:
        record = _record_staging(staging)
        self._created.append(record)

    def cleanup(self, staging: AttemptStaging) -> None:
        for record in self._created:
            if record.root == staging.root:
                _remove_tracked_staging(record)
                self._created.remove(record)
                return
        raise AssertionError(f"staging root was not created by this test: {staging.root}")

    def cleanup_all(self) -> list[BaseException]:
        failures: list[BaseException] = []
        for record in reversed(self._created[:]):
            try:
                _remove_tracked_staging(record)
            except BaseException as exc:
                failures.append(exc)
            else:
                self._created.remove(record)
        return failures


def _owned_directory(details: os.stat_result, *, mode: int) -> bool:
    return (
        stat.S_ISDIR(details.st_mode)
        and details.st_uid == os.getuid()
        and stat.S_IMODE(details.st_mode) == mode
    )


def _private_marker(details: os.stat_result) -> bool:
    return (
        stat.S_ISREG(details.st_mode)
        and details.st_uid == os.getuid()
        and stat.S_IMODE(details.st_mode) == 0o600
        and details.st_nlink == 1
    )


def _identity(details: os.stat_result) -> tuple[int, int]:
    return details.st_dev, details.st_ino


def _open_temp_parent(root: Path) -> int:
    if root.parent != Path(tempfile.gettempdir()) or not root.name.startswith(_STAGING_PREFIX):
        raise AssertionError(f"refusing non-test staging root: {root}")
    return os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def _record_staging(staging: AttemptStaging) -> _TrackedStaging:
    root = staging.root
    if staging.workdir != root / "work" or staging.artifacts != root / "artifacts":
        raise AssertionError(f"unexpected staging layout: {root}")
    parent_fd = _open_temp_parent(root)
    root_fd = marker_fd = None
    try:
        root_details = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
        if not _owned_directory(root_details, mode=0o700):
            raise AssertionError(f"test staging root is not owned mode 0700: {root}")
        root_fd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        if _identity(os.fstat(root_fd)) != _identity(root_details):
            raise AssertionError(f"test staging root changed while being tracked: {root}")
        marker_fd = os.open(_STAGING_MARKER, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
        marker_details = os.fstat(marker_fd)
        if not _private_marker(marker_details):
            raise AssertionError(f"test staging marker is not owned mode 0600: {root}")
        return _TrackedStaging(root, _identity(root_details), _identity(marker_details))
    finally:
        if marker_fd is not None:
            os.close(marker_fd)
        if root_fd is not None:
            os.close(root_fd)
        os.close(parent_fd)


def _remove_tracked_tree(directory_fd: int, *, preserve: frozenset[str] = frozenset()) -> None:
    """Remove test fixture entries, unlinking links rather than their targets."""
    with os.scandir(directory_fd) as entries:
        names = [entry.name for entry in entries]
    for name in names:
        if name in preserve:
            continue
        details = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISDIR(details.st_mode):
            os.unlink(name, dir_fd=directory_fd)
            continue
        if details.st_uid != os.getuid():
            raise AssertionError(f"refusing foreign-owned test fixture directory: {name}")
        # ``follow_symlinks=False`` makes this normalization apply to the
        # directory entry itself.  It lets mode-000 test fixtures be reclaimed
        # without traversing a link target.
        os.chmod(name, 0o700, dir_fd=directory_fd, follow_symlinks=False)
        child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
        try:
            current = os.fstat(child_fd)
            if not _owned_directory(current, mode=0o700) or _identity(current) != _identity(details):
                raise AssertionError(f"test fixture directory changed during cleanup: {name}")
            _remove_tracked_tree(child_fd)
        finally:
            os.close(child_fd)
        os.rmdir(name, dir_fd=directory_fd)


def _remove_tracked_staging(record: _TrackedStaging) -> None:
    """Safely remove one exact, tracked root even after hostile test setup."""
    parent_fd = _open_temp_parent(record.root)
    root_fd = marker_fd = None
    try:
        try:
            root_details = os.stat(record.root.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if _identity(root_details) != record.root_identity or not stat.S_ISDIR(root_details.st_mode):
            raise AssertionError(f"tracked staging root was replaced: {record.root}")
        if root_details.st_uid != os.getuid():
            raise AssertionError(f"tracked staging root is no longer host-owned: {record.root}")
        # A deliberate mode-000 fixture cannot be opened normally.  The name
        # has already been identity-checked under the temp-parent descriptor;
        # do not follow a possible symlink when restoring its private mode.
        if stat.S_IMODE(root_details.st_mode) != 0o700:
            os.chmod(record.root.name, 0o700, dir_fd=parent_fd, follow_symlinks=False)
            root_details = os.stat(record.root.name, dir_fd=parent_fd, follow_symlinks=False)
        if _identity(root_details) != record.root_identity or not _owned_directory(root_details, mode=0o700):
            raise AssertionError(f"tracked staging root is not owned mode 0700: {record.root}")
        root_fd = os.open(record.root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        if _identity(os.fstat(root_fd)) != record.root_identity:
            raise AssertionError(f"tracked staging root changed during cleanup: {record.root}")
        marker_fd = os.open(_STAGING_MARKER, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
        marker_details = os.fstat(marker_fd)
        if _identity(marker_details) != record.marker_identity or not _private_marker(marker_details):
            raise AssertionError(f"tracked staging marker changed or is unsafe: {record.root}")
        _remove_tracked_tree(root_fd, preserve=frozenset({_STAGING_MARKER}))
        current_marker = os.stat(_STAGING_MARKER, dir_fd=root_fd, follow_symlinks=False)
        if _identity(current_marker) != record.marker_identity or not _private_marker(current_marker):
            raise AssertionError(f"tracked staging marker changed during cleanup: {record.root}")
        os.unlink(_STAGING_MARKER, dir_fd=root_fd)
        if _identity(os.stat(record.root.name, dir_fd=parent_fd, follow_symlinks=False)) != record.root_identity:
            raise AssertionError(f"tracked staging root changed before removal: {record.root}")
        os.rmdir(record.root.name, dir_fd=parent_fd)
    finally:
        if marker_fd is not None:
            os.close(marker_fd)
        if root_fd is not None:
            os.close(root_fd)
        os.close(parent_fd)


@pytest.fixture(autouse=True)
def _track_test_attempt_staging(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest):
    """Track both fixture and direct test calls to the global-temp factory."""
    tracker = _StagingTracker()
    original = ArtifactWriter.create_attempt_staging

    def create_and_track(writer: ArtifactWriter) -> AttemptStaging:
        staging = original(writer)
        tracker.track(staging)
        return staging

    monkeypatch.setattr(ArtifactWriter, "create_attempt_staging", create_and_track)
    request.node._ctf_os_staging_tracker = tracker  # type: ignore[attr-defined]
    yield
    failures = tracker.cleanup_all()
    if failures:
        details = "\n".join(f"- {type(exc).__name__}: {exc}" for exc in failures)
        pytest.fail(f"test staging teardown failed; roots were retained for diagnosis:\n{details}")


@pytest.fixture
def test_staging_cleanup(request: pytest.FixtureRequest) -> Callable[[AttemptStaging], None]:
    """Expose the same safe test-only reaper for teardown regression tests."""
    tracker = request.node._ctf_os_staging_tracker  # type: ignore[attr-defined]
    return tracker.cleanup


@pytest.fixture
def claimed_attempt() -> Callable[..., Attempt]:
    def factory(
        state: LocalState,
        challenge: Challenge,
        *,
        owner: str = "test-owner",
        attempt_id: str = "attempt-test",
        profile: str = "recon_fast",
        role: str = "recon",
        backend: str = "mock",
        workdir: str = "/tmp/ctf-os-test-work",
        lease_seconds: float = 30,
        max_workers_total: int = 4,
        max_workers_per_challenge: int = 4,
    ) -> Attempt:
        attempt = Attempt(
            id=attempt_id,
            challenge_id=challenge.id,
            profile=profile,
            role=role,
            backend=backend,
            workdir=workdir,
        )
        claim = state.claim_attempt(
            attempt,
            owner=owner,
            lease_seconds=lease_seconds,
            max_workers_total=max_workers_total,
            max_workers_per_challenge=max_workers_per_challenge,
        )
        assert claim.granted and claim.fencing_token is not None
        return replace(attempt, lease_owner=owner, fencing_token=claim.fencing_token)

    return factory


@pytest.fixture
def sterile_staging_factory(tmp_path: Path) -> Callable[[], AttemptStaging]:
    def factory() -> AttemptStaging:
        return ArtifactWriter(tmp_path / "sterile-output", "Demo").create_attempt_staging()

    return factory
