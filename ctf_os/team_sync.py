"""Read-only TeamSync merge over member-owned append-only JSONL files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .local_event_bus import EventLogDiagnostic, LocalEventBus
from .models import Event


@dataclass(frozen=True, slots=True)
class TeamSyncMergeReport:
    """Merged valid events and non-mutating trailing-record diagnostics."""

    events: tuple[Event, ...] = ()
    diagnostics: tuple[EventLogDiagnostic, ...] = ()


class TeamSync:
    """A filesystem ledger, not a command channel or remote-worker mechanism."""

    def __init__(self, sync_root: str | Path, *, team_id: str, member: str) -> None:
        _safe_component(team_id, "team_id")
        _safe_component(member, "member")
        self.sync_root = Path(sync_root)
        self.team_id = team_id
        self.member = member

    @property
    def team_directory(self) -> Path:
        return self.sync_root / self.team_id

    @property
    def own_event_path(self) -> Path:
        return self.team_directory / f"{self.member}.events.jsonl"

    def append(self, event: Event) -> Event:
        if event.team_id != self.team_id:
            raise PermissionError("cannot append an event outside this TeamSync namespace")
        if event.member != self.member:
            raise PermissionError("each local node may append only its own member file")
        return LocalEventBus(self.own_event_path, member=self.member).append(event)

    append_event = append

    def append_idempotent(self, event: Event) -> Event:
        """Publish a retried local outbox record without duplicating JSONL."""
        if event.team_id != self.team_id:
            raise PermissionError("cannot append an event outside this TeamSync namespace")
        if event.member != self.member:
            raise PermissionError("each local node may append only its own member file")
        return LocalEventBus(self.own_event_path, member=self.member).append_idempotent(event)

    def merge(self) -> list[Event]:
        """Read all valid files under this team without mutating any of them.

        Use :meth:`merge_report` when callers need to display recoverable
        trailing-record diagnostics.  A malformed non-final record remains a
        fail-closed :class:`EventLogError` and is never hidden by this helper.
        """
        return list(self.merge_report().events)

    def merge_report(self) -> TeamSyncMergeReport:
        """Merge valid events and report recoverable final tails deterministically.

        This is deliberately a read-only recovery API.  It ignores only an
        incomplete non-newline tail or a malformed completed final record in a
        member file, preserving all valid preceding records and continuing to
        other member files.  Any malformed middle record raises from
        ``LocalEventBus.read_report`` with its exact path and line.
        """
        candidates: list[tuple[str, int, Event]] = []
        diagnostics: list[EventLogDiagnostic] = []
        if not self.team_directory.exists():
            return TeamSyncMergeReport()
        for path in sorted(self.team_directory.glob("*.events.jsonl")):
            source_member = path.name.removesuffix(".events.jsonl")
            try:
                _safe_component(source_member, "member filename")
            except ValueError:
                continue
            report = LocalEventBus(path, member=source_member).read_report()
            diagnostics.extend(report.diagnostics)
            for index, event in enumerate(report.events):
                if event.team_id == self.team_id:
                    candidates.append((path.name, index, event))
        # First choose duplicate event IDs deterministically, then sort the
        # visible ledger by event time and ID for stable TUI/replay behavior.
        unique: dict[str, tuple[str, int, Event]] = {}
        for candidate in sorted(candidates, key=lambda item: (item[0], item[1])):
            unique.setdefault(candidate[2].id, candidate)
        events = tuple(
            item[2]
            for item in sorted(unique.values(), key=lambda item: (item[2].timestamp, item[2].id, item[0], item[1]))
        )
        return TeamSyncMergeReport(events, tuple(diagnostics))

    merge_events = merge


def merge_team_events(sync_root: str | Path, *, team_id: str, member: str = "reader") -> list[Event]:
    """Convenience read-only merge for dashboards that do not append events."""
    return TeamSync(sync_root, team_id=team_id, member=member).merge()


def _safe_component(value: str, label: str) -> None:
    if not value or value in {".", ".."} or "/" in value or "\\" in value or "\x00" in value:
        raise ValueError(f"unsafe {label}: {value!r}")
