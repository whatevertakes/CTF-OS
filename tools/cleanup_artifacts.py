#!/usr/bin/env python3
"""Clean temporary artifacts while refusing real challenge work."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ROOT_PROTECTED = {
    ".codex",
    "benchmarks",
    "capabilities",
    "docs",
    "skills",
    "templates",
    "tools",
}
CACHE_DIR_NAMES = {".pytest_cache", ".mypy_cache", ".ruff_cache", "__pycache__"}
TEMP_MARKER_NAMES = {".selftest-artifact", ".level5_selftest", ".level5_benchmark"}
TEMP_CHALLENGE_EVENTS = {
    "_selftest",
    "_level2selftest",
    "_level3blind",
    "_level4selftest",
    "_level5benchmark",
    "_level5badproof",
    "_level5replay",
    "_level5sanitize",
    "_level5selftest",
}


def fail(message: str, code: int = 1) -> None:
    print(f"cleanup_artifacts: {message}", file=sys.stderr)
    raise SystemExit(code)


def resolve_target(value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = ROOT / path
    try:
        resolved = path.resolve()
        resolved.relative_to(ROOT)
    except ValueError:
        fail(f"target must stay under {ROOT}: {value}", code=2)
    return resolved


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def tracked_entries(path: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", relative(path)],
        cwd=ROOT,
        text=False,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        fail("git ls-files failed while checking cleanup safety")
    return [item.decode("utf-8", errors="replace") for item in result.stdout.split(b"\0") if item]


def is_temp_challenge_path(path: Path) -> bool:
    try:
        rel = path.relative_to(ROOT)
    except ValueError:
        return False
    parts = rel.parts
    if len(parts) < 2 or parts[0] != "challenges":
        return False
    event = parts[1]
    return event in TEMP_CHALLENGE_EVENTS or event.startswith("_level5")


def marker_root(path: Path) -> Path | None:
    if not is_temp_challenge_path(path):
        return None
    current = path if path.is_dir() else path.parent
    stop = ROOT / "challenges"
    while current != stop and current != ROOT:
        if any((current / marker).is_file() for marker in TEMP_MARKER_NAMES):
            return current
        current = current.parent
    return None


def is_zone_identifier(path: Path) -> bool:
    return path.name.endswith(":Zone.Identifier")


def allowed_target(path: Path) -> bool:
    rel = path.relative_to(ROOT)
    parts = rel.parts
    if not parts:
        return False
    if is_zone_identifier(path):
        return True
    if parts[0] in ROOT_PROTECTED:
        return path.name in CACHE_DIR_NAMES
    if parts[0] == ".cache":
        return True
    if path.name in CACHE_DIR_NAMES:
        return True
    if parts[0] == "challenges":
        return marker_root(path) is not None
    return False


def prune_empty_temp_challenge_parents(path: Path) -> None:
    try:
        rel = path.relative_to(ROOT)
    except ValueError:
        return
    parts = rel.parts
    if len(parts) < 2 or parts[0] != "challenges":
        return
    if not is_temp_challenge_path(path):
        return

    stop = ROOT / "challenges"
    current = path.parent
    while current != stop and current != ROOT:
        try:
            current.rmdir()
            print(f"DELETE empty {relative(current)}")
        except OSError:
            break
        current = current.parent


def default_targets() -> list[Path]:
    targets: list[Path] = []
    for event in TEMP_CHALLENGE_EVENTS:
        event_root = ROOT / "challenges" / event
        if event_root.exists():
            for marker in TEMP_MARKER_NAMES:
                targets.extend(path.parent for path in event_root.rglob(marker))
    for event_root in (ROOT / "challenges").glob("_level5*"):
        if event_root.is_dir() and event_root.name not in TEMP_CHALLENGE_EVENTS:
            for marker in TEMP_MARKER_NAMES:
                targets.extend(path.parent for path in event_root.rglob(marker))
    for relative_name in (
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
    ):
        candidate = ROOT / relative_name
        if candidate.exists():
            targets.append(candidate)
    for candidate in ROOT.rglob("__pycache__"):
        if ".git" not in candidate.parts:
            targets.append(candidate)
    for candidate in ROOT.rglob("*:Zone.Identifier"):
        if ".git" not in candidate.parts:
            targets.append(candidate)
    return sorted(set(targets), key=lambda item: item.as_posix())


def remove_target(path: Path, *, yes: bool) -> bool:
    if not path.exists():
        print(f"SKIP missing {relative(path)}")
        return False
    if not allowed_target(path):
        fail(f"refusing to clean non-temporary path: {relative(path)}", code=2)
    tracked = tracked_entries(path)
    if tracked:
        fail(f"refusing to remove tracked git files under {relative(path)}: {tracked[:5]}", code=2)
    action = "DELETE" if yes else "DRY-RUN delete"
    print(f"{action} {relative(path)}")
    if not yes:
        return False
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()
    prune_empty_temp_challenge_parents(path)
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", nargs="*", help="explicit paths to clean; defaults to known temp artifacts")
    parser.add_argument("--yes", action="store_true", help="actually delete matched artifacts")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    targets = [resolve_target(value) for value in args.targets] if args.targets else default_targets()
    removed = 0
    for target in targets:
        if remove_target(target, yes=args.yes):
            removed += 1
    print(f"cleanup_artifacts removed={removed} dry_run={not args.yes}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
