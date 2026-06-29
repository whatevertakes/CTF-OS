#!/usr/bin/env python3
"""Run Level 2 workspace acceptance checks without external dependencies."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MARKER = ".level2_selftest"
ACCEPTANCE_SPECS = (
    ("practice-dreamhack", "web", "login-basic"),
    ("2026-codegate-quals", "pwn", "baby-rop"),
    ("_selftest", "misc", "dummy"),
)
REQUIRED_ENTRIES = (
    "state.json",
    "notes.md",
    "replay.sh",
    "evidence",
    "dist",
    "work",
)


def challenge_path(spec: tuple[str, str, str]) -> Path:
    return ROOT / "challenges" / spec[0] / spec[1] / spec[2]


def fail(message: str) -> None:
    print(f"level2_selftest: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(command: list[str], *, expect_ok: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if expect_ok and result.returncode != 0:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        fail(f"command failed: {' '.join(command)}")
    if not expect_ok and result.returncode == 0:
        print(result.stdout, end="")
        fail(f"command unexpectedly succeeded: {' '.join(command)}")
    return result


def load_state(path: Path) -> dict[str, object]:
    with (path / "state.json").open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_state(path: Path, state: dict[str, object]) -> None:
    with (path / "state.json").open("w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
        handle.write("\n")


def ensure_clean(path: Path) -> None:
    if not path.exists():
        return
    if not (path / MARKER).is_file():
        fail(f"refusing to overwrite unmarked challenge directory: {path.relative_to(ROOT)}")
    shutil.rmtree(path)


def mark(path: Path) -> None:
    (path / MARKER).write_text("created by benchmarks/level2_selftest.py\n", encoding="utf-8")


def intake(spec: tuple[str, str, str]) -> Path:
    path = challenge_path(spec)
    ensure_clean(path)
    run(
        [
            "python3",
            "tools/intake_challenge.py",
            "--event",
            spec[0],
            "--category",
            spec[1],
            "--name",
            spec[2],
        ]
    )
    mark(path)
    return path


def assert_contract(path: Path) -> None:
    missing = [entry for entry in REQUIRED_ENTRIES if not (path / entry).exists()]
    if missing:
        fail(f"{path.relative_to(ROOT)} missing required entries: {', '.join(missing)}")

    state = load_state(path)
    for key in ("event", "category", "name", "status", "final_command", "workspace"):
        if key not in state:
            fail(f"{path.relative_to(ROOT)}/state.json missing key: {key}")
    if state["status"] != "new":
        fail(f"{path.relative_to(ROOT)} should start as status=new")


def assert_validation_status(path: Path, expected_status: str) -> None:
    result = run(["python3", "tools/proof_validate.py", str(path.relative_to(ROOT))])
    if f"status={expected_status}" not in result.stdout:
        fail(
            f"proof validation did not report status={expected_status} for "
            f"{path.relative_to(ROOT)}"
        )
    if expected_status != "solved" and "status=solved" in result.stdout:
        fail(f"{path.relative_to(ROOT)} was incorrectly reported as solved")


def cleanup(paths: list[Path]) -> None:
    for path in sorted(paths, key=lambda item: len(item.parts), reverse=True):
        if path.exists() and (path / MARKER).is_file():
            shutil.rmtree(path)

    for dirname in (
        ROOT / "challenges" / "practice-dreamhack" / "web",
        ROOT / "challenges" / "practice-dreamhack",
        ROOT / "challenges" / "2026-codegate-quals" / "pwn",
        ROOT / "challenges" / "2026-codegate-quals",
        ROOT / "challenges" / "_selftest" / "misc",
        ROOT / "challenges" / "_selftest",
    ):
        try:
            dirname.rmdir()
        except OSError:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--keep",
        action="store_true",
        help="leave marked self-test challenge directories in place",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    created: list[Path] = []
    try:
        for spec in ACCEPTANCE_SPECS:
            path = intake(spec)
            created.append(path)
            assert_contract(path)
            assert_validation_status(path, "new")

        dummy = challenge_path(("_selftest", "misc", "dummy"))
        run(["python3", "tools/replay_runner.py", str(dummy.relative_to(ROOT))])
        if not list((dummy / "evidence").glob("replay_*.log")):
            fail("replay runner did not preserve replay evidence")
        assert_validation_status(dummy, "new")

        blocked = intake(("_selftest", "misc", "blocked-no-reason"))
        created.append(blocked)
        blocked_state = load_state(blocked)
        blocked_state["status"] = "blocked"
        write_state(blocked, blocked_state)
        result = run(
            ["python3", "tools/proof_validate.py", str(blocked.relative_to(ROOT))],
            expect_ok=False,
        )
        if "blocked status requires" not in result.stderr:
            fail("blocked challenge without a blocker reason failed for the wrong reason")

        partial = intake(("_selftest", "misc", "partial-progress"))
        created.append(partial)
        partial_state = load_state(partial)
        partial_state["status"] = "partial"
        write_state(partial, partial_state)
        assert_validation_status(partial, "partial")

        solved = intake(("_selftest", "misc", "solved-proof"))
        created.append(solved)
        solved_state = load_state(solved)
        solved_state["status"] = "solved"
        write_state(solved, solved_state)
        result = run(
            ["python3", "tools/proof_validate.py", str(solved.relative_to(ROOT))],
            expect_ok=False,
        )
        if "solved status requires non-empty final_command" not in result.stderr:
            fail("solved challenge without final_command failed for the wrong reason")
        run(["python3", "tools/replay_runner.py", str(solved.relative_to(ROOT))])
        solved_state = load_state(solved)
        solved_state["final_command"] = "bash replay.sh"
        write_state(solved, solved_state)
        assert_validation_status(solved, "solved")
    finally:
        if not args.keep:
            cleanup(created)

    print("level2 selftest ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
