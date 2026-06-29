#!/usr/bin/env python3
"""Validate that a challenge state has enough evidence for its claimed status."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ALLOWED_STATUSES = {
    "new",
    "triaged",
    "analyzing",
    "exploiting",
    "solved",
    "partial",
    "blocked",
}


def fail(message: str, code: int = 1) -> None:
    print(f"proof_validate: {message}", file=sys.stderr)
    raise SystemExit(code)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("challenge_dir", help="challenge directory containing state.json")
    return parser.parse_args()


def text_reason(value: object) -> str:
    if isinstance(value, str):
        return value.strip()
    return ""


def extract_blocker_reason(state: dict[str, object]) -> str:
    blocker = state.get("blocker")
    if isinstance(blocker, dict):
        blocker_reason = text_reason(blocker.get("reason"))
    else:
        blocker_reason = text_reason(blocker)

    return (
        blocker_reason
        or text_reason(state.get("blocked_reason"))
        or text_reason(state.get("blocker_reason"))
    )


def main() -> int:
    args = parse_args()
    challenge_dir = Path(args.challenge_dir).expanduser().resolve()
    if not challenge_dir.is_dir():
        fail(f"challenge directory does not exist: {challenge_dir}", code=2)

    state_path = challenge_dir / "state.json"
    if not state_path.is_file():
        fail(f"missing state file: {state_path}", code=2)

    try:
        with state_path.open("r", encoding="utf-8") as handle:
            state = json.load(handle)
    except json.JSONDecodeError as exc:
        fail(f"state.json is invalid JSON: {exc}", code=2)

    status = state.get("status")
    if status not in ALLOWED_STATUSES:
        fail(f"invalid status {status!r}; allowed: {', '.join(sorted(ALLOWED_STATUSES))}")

    replay_logs = sorted((challenge_dir / "evidence").glob("replay_*.log"))
    final_command = str(state.get("final_command") or "").strip()
    blocker_reason = extract_blocker_reason(state)
    if status == "solved":
        if not final_command:
            fail("solved status requires non-empty final_command")
        if not replay_logs:
            fail("solved status requires at least one evidence/replay_*.log")
    if status == "blocked" and not blocker_reason:
        fail("blocked status requires non-empty blocker, blocked_reason, or blocker_reason")

    print(f"proof ok: status={status} replay_logs={len(replay_logs)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
