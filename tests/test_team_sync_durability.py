from __future__ import annotations

import errno
import multiprocessing
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

import pytest

import ctf_os.local_event_bus as local_event_bus
from ctf_os.local_event_bus import EventLogError, LocalEventBus
from ctf_os.models import Event
from ctf_os.team_sync import TeamSync


TIMESTAMP = datetime(2026, 7, 10, 12, tzinfo=timezone.utc)


def _event(*, event_id: str = "event-durable", member: str = "alice") -> Event:
    return Event(
        id=event_id,
        timestamp=TIMESTAMP,
        team_id="team",
        member=member,
        contest="Demo",
        type="FINDING",
    )


def _concurrent_idempotent_append(root: str, start: object, results: object) -> None:
    """Spawn-safe worker used to exercise an actual process boundary."""
    try:
        start.wait(10)  # type: ignore[union-attr]
        TeamSync(root, team_id="team", member="alice").append_idempotent(_event())
        results.put(None)  # type: ignore[union-attr]
    except BaseException as exc:  # pragma: no cover - forwarded to parent
        results.put(f"{type(exc).__name__}: {exc}")  # type: ignore[union-attr]


@pytest.mark.skipif(getattr(local_event_bus, "fcntl", None) is None, reason="requires flock support")
def test_idempotent_append_is_atomic_across_same_member_processes(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    processes = [
        context.Process(target=_concurrent_idempotent_append, args=(str(tmp_path / "sync"), start, results))
        for _ in range(12)
    ]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(15)
        assert process.exitcode == 0
    assert [results.get(timeout=2) for _ in processes] == [None] * len(processes)

    path = tmp_path / "sync" / "team" / "alice.events.jsonl"
    assert [item.id for item in LocalEventBus(path, member="alice").read()] == ["event-durable"]
    assert path.read_bytes().count(b'"id":"event-durable"') == 1


def test_append_retries_partial_writes_and_opens_in_append_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "events.jsonl"
    real_write = os.write
    real_open = os.open
    writes: list[bytes] = []
    file_open_flags: list[int] = []

    def partial_write(fd: int, data: bytes) -> int:
        writes.append(bytes(data))
        return real_write(fd, data[:7])

    def tracking_open(name: str | bytes | os.PathLike[str] | os.PathLike[bytes], flags: int, mode: int = 0o777) -> int:
        if Path(name) == path:
            file_open_flags.append(flags)
        return real_open(name, flags, mode)

    monkeypatch.setattr(local_event_bus.os, "write", partial_write)
    monkeypatch.setattr(local_event_bus.os, "open", tracking_open)
    LocalEventBus(path).append(_event())

    assert len(writes) > 1
    assert file_open_flags and file_open_flags[0] & os.O_APPEND
    assert LocalEventBus(path).read() == [_event()]


def test_first_creation_fsyncs_file_and_directory_entries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "new" / "team" / "events.jsonl"
    real_fsync = os.fsync
    synced_kinds: list[str] = []

    def recording_fsync(fd: int) -> None:
        synced_kinds.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
        real_fsync(fd)

    monkeypatch.setattr(local_event_bus.os, "fsync", recording_fsync)
    LocalEventBus(path).append(_event())

    assert "file" in synced_kinds
    # Parent directory creation requires its containing entries to be synced,
    # and the new file entry requires the final containing directory sync.
    assert synced_kinds.count("directory") >= 3


def test_directory_fsync_failure_is_visible(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "events.jsonl"
    real_fsync = os.fsync

    def fail_directory_fsync(fd: int) -> None:
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EIO, "simulated directory durability failure")
        real_fsync(fd)

    monkeypatch.setattr(local_event_bus.os, "fsync", fail_directory_fsync)
    with pytest.raises(EventLogError, match="fsync directory"):
        LocalEventBus(path).append(_event())


def test_unsupported_advisory_locking_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(local_event_bus, "fcntl", None)
    path = tmp_path / "events.jsonl"

    with pytest.raises(EventLogError, match="advisory locking unavailable"):
        LocalEventBus(path).append(_event())
    assert not path.exists()


def test_incomplete_tail_is_ignored_and_reported_without_mutation(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_bytes(
        (local_event_bus.json.dumps(_event().to_dict(), sort_keys=True, separators=(",", ":")) + "\n").encode()
        + b'{"id":"interrupted"'
    )

    bus = LocalEventBus(path)
    report = bus.read_report()

    assert list(report.events) == [_event()]
    assert len(report.diagnostics) == 1
    diagnostic = report.diagnostics[0]
    assert (diagnostic.kind, diagnostic.line, diagnostic.path) == ("incomplete_tail", 2, path)
    assert path.read_bytes().endswith(b'{"id":"interrupted"')


def test_malformed_final_line_is_reported_and_does_not_block_other_member_merges(tmp_path: Path) -> None:
    root = tmp_path / "sync"
    bob_path = root / "team" / "bob.events.jsonl"
    bob_path.parent.mkdir(parents=True)
    bob_path.write_bytes(
        (local_event_bus.json.dumps(_event(member="bob").to_dict(), sort_keys=True, separators=(",", ":")) + "\n").encode()
        + b'{"not":"an event"}\n'
    )
    TeamSync(root, team_id="team", member="carol").append(_event(event_id="event-carol", member="carol"))

    sync = TeamSync(root, team_id="team", member="alice")
    report = sync.merge_report()

    assert [event.id for event in report.events] == ["event-carol", "event-durable"]
    assert [(item.kind, item.path, item.line) for item in report.diagnostics] == [
        ("malformed_final", bob_path, 2),
    ]
    assert [event.id for event in sync.merge()] == ["event-carol", "event-durable"]
    with pytest.raises(EventLogError, match="malformed_final"):
        LocalEventBus(bob_path, member="bob").append(_event(event_id="event-next", member="bob"))


def test_malformed_middle_line_fails_closed_with_path_and_line(tmp_path: Path) -> None:
    root = tmp_path / "sync"
    path = root / "team" / "bob.events.jsonl"
    path.parent.mkdir(parents=True)
    path.write_bytes(
        (local_event_bus.json.dumps(_event(member="bob").to_dict(), sort_keys=True, separators=(",", ":")) + "\n").encode()
        + b'{"not":"an event"}\n'
        + (local_event_bus.json.dumps(_event(event_id="event-later", member="bob").to_dict(), sort_keys=True, separators=(",", ":")) + "\n").encode()
    )

    with pytest.raises(EventLogError, match=rf"invalid event in {path} at line 2"):
        TeamSync(root, team_id="team", member="alice").merge()
