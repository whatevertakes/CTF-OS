"""Small polling watcher for a single local incoming tree."""

from __future__ import annotations

from pathlib import Path
import time
from threading import Event as ThreadEvent
from typing import Callable, Iterable


class PollingWatcher:
    """Detect local manifest/archive changes without a central executor."""

    def __init__(self, root: str | Path, *, interval_sec: float = 2.0) -> None:
        if interval_sec <= 0:
            raise ValueError("poll interval must be positive")
        self.root = Path(root)
        self.interval_sec = interval_sec
        self._previous: tuple[tuple[str, int, int], ...] | None = None

    def changed(self) -> bool:
        snapshot = self._snapshot()
        if self._previous is None:
            self._previous = snapshot
            return True
        changed = snapshot != self._previous
        self._previous = snapshot
        return changed

    def wait(self, stop_event: ThreadEvent | None = None) -> bool:
        if stop_event is None:
            time.sleep(self.interval_sec)
            return True
        return not stop_event.wait(self.interval_sec)

    def _snapshot(self) -> tuple[tuple[str, int, int], ...]:
        if not self.root.is_dir():
            return ()
        rows: list[tuple[str, int, int]] = []
        for path in self.root.rglob("*"):
            if path.is_symlink() or not path.is_file() or (path.name != "contest.md" and path.suffix.casefold() != ".zip"):
                continue
            stat = path.stat()
            rows.append((str(path.relative_to(self.root)), stat.st_mtime_ns, stat.st_size))
        return tuple(sorted(rows))


class PathPollingWatcher:
    """Bounded, read-only polling for a small explicit set of local paths.

    It is used by operator views only.  It neither opens a coordinator lease
    nor writes state, so watching another member's TeamSync ledger remains a
    display operation rather than remote worker control.
    """

    def __init__(
        self,
        paths: Iterable[str | Path],
        *,
        interval_sec: float = 2.0,
        include: Callable[[Path], bool] | None = None,
    ) -> None:
        if interval_sec <= 0:
            raise ValueError("poll interval must be positive")
        self.paths = tuple(Path(path) for path in paths)
        self.interval_sec = interval_sec
        self.include = include or (lambda _path: True)
        self._previous: tuple[tuple[str, int, int], ...] | None = None

    def changed(self) -> bool:
        snapshot = self._snapshot()
        if self._previous is None:
            self._previous = snapshot
            return True
        changed = snapshot != self._previous
        self._previous = snapshot
        return changed

    def wait(self, stop_event: ThreadEvent | None = None) -> bool:
        if stop_event is None:
            time.sleep(self.interval_sec)
            return True
        return not stop_event.wait(self.interval_sec)

    def _snapshot(self) -> tuple[tuple[str, int, int], ...]:
        rows: list[tuple[str, int, int]] = []
        for root in self.paths:
            candidates = (root,) if root.is_file() else root.rglob("*") if root.is_dir() else ()
            for path in candidates:
                try:
                    if path.is_symlink() or not path.is_file() or not self.include(path):
                        continue
                    details = path.stat()
                except OSError:
                    continue
                rows.append((str(path), details.st_mtime_ns, details.st_size))
        return tuple(sorted(rows))
