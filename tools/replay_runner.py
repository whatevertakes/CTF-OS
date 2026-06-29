#!/usr/bin/env python3
"""Run a challenge replay script and preserve stdout/stderr as evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import subprocess
import sys
from pathlib import Path


def fail(message: str, code: int = 2) -> None:
    print(f"replay_runner: {message}", file=sys.stderr)
    raise SystemExit(code)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("challenge_dir", help="challenge directory containing replay.sh")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    challenge_dir = Path(args.challenge_dir).expanduser().resolve()
    if not challenge_dir.is_dir():
        fail(f"challenge directory does not exist: {challenge_dir}")

    replay = challenge_dir / "replay.sh"
    if not replay.is_file():
        fail(f"missing replay script: {replay}")

    evidence_dir = challenge_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_path = evidence_dir / f"replay_{timestamp}.log"
    command = ["bash", "replay.sh"]
    result = subprocess.run(
        command,
        cwd=challenge_dir,
        capture_output=True,
        text=True,
        check=False,
    )

    with log_path.open("w", encoding="utf-8") as handle:
        handle.write(f"timestamp_utc: {timestamp}\n")
        handle.write(f"command: {' '.join(command)}\n")
        handle.write(f"cwd: {challenge_dir}\n")
        handle.write(f"exit_code: {result.returncode}\n")
        handle.write("\n[stdout]\n")
        handle.write(result.stdout)
        if result.stdout and not result.stdout.endswith("\n"):
            handle.write("\n")
        handle.write("\n[stderr]\n")
        handle.write(result.stderr)
        if result.stderr and not result.stderr.endswith("\n"):
            handle.write("\n")

    print(log_path)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
