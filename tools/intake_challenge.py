#!/usr/bin/env python3
"""Create a local CTF challenge workspace from the Level 2 template."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shutil
import stat
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = ROOT / "templates" / "challenge"
CHALLENGES_DIR = ROOT / "challenges"
SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9._-]+$")
CONTRACT_DIRS = ("evidence", "dist", "work")
BASH_SHEBANG = re.compile(r"^#!.*\bbash(?:\s|$)")


def fail(message: str, code: int = 2) -> None:
    print(f"intake_challenge: {message}", file=sys.stderr)
    raise SystemExit(code)


def validate_component(value: str, label: str) -> str:
    if not value:
        fail(f"{label} must not be empty")
    if value in {".", ".."} or value.startswith("."):
        fail(f"{label} is an unsafe path component: {value!r}")
    if "/" in value or "\\" in value or "\x00" in value:
        fail(f"{label} must be a single path component: {value!r}")
    if not SAFE_COMPONENT.match(value):
        fail(f"{label} may contain only letters, digits, dot, underscore, and dash: {value!r}")
    return value


def copy_template(destination: Path, force: bool) -> None:
    if not TEMPLATE_DIR.is_dir():
        fail(f"template directory is missing: {TEMPLATE_DIR}")
    template_replay = TEMPLATE_DIR / "replay.sh"
    if not template_replay.is_file():
        fail(f"template replay script is missing: {template_replay}")
    first_line = template_replay.read_text(encoding="utf-8", errors="replace").splitlines()[:1]
    if not first_line or not BASH_SHEBANG.match(first_line[0]):
        fail(f"template replay script must start with a bash shebang: {template_replay}")

    for source in TEMPLATE_DIR.rglob("*"):
        relative = source.relative_to(TEMPLATE_DIR)
        target = destination / relative
        if source.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if relative.as_posix() == "state.json":
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and not force:
            fail(f"target file exists; rerun with --force to overwrite: {target}")
        shutil.copy2(source, target)

    replay = destination / "replay.sh"
    if not replay.is_file():
        fail(f"failed to create replay script: {replay}")
    mode = replay.stat().st_mode
    replay.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def write_state(destination: Path, event: str, category: str, name: str, force: bool) -> None:
    state_path = destination / "state.json"
    if state_path.exists() and not force:
        fail(f"state.json exists; rerun with --force to overwrite: {state_path}")

    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    template_state = {}
    template_state_path = TEMPLATE_DIR / "state.json"
    if template_state_path.exists():
        with template_state_path.open("r", encoding="utf-8") as handle:
            template_state = json.load(handle)

    state = {
        **template_state,
        "event": event,
        "category": category,
        "name": name,
        "status": "new",
        "created_at": now,
        "updated_at": now,
        "final_command": "",
        "workspace": str(destination.relative_to(ROOT)),
    }
    state_path.parent.mkdir(parents=True, exist_ok=True)
    with state_path.open("w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
        handle.write("\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", required=True, help="single safe path component")
    parser.add_argument("--category", required=True, help="single safe path component")
    parser.add_argument("--name", required=True, help="single safe path component")
    parser.add_argument("--force", action="store_true", help="overwrite template files and state.json if present")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    event = validate_component(args.event, "event")
    category = validate_component(args.category, "category")
    name = validate_component(args.name, "name")

    destination = CHALLENGES_DIR / event / category / name
    if destination.exists() and not args.force:
        fail(f"challenge directory exists; rerun with --force to update it: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    for dirname in CONTRACT_DIRS:
        (destination / dirname).mkdir(parents=True, exist_ok=True)

    copy_template(destination, args.force)
    write_state(destination, event, category, name, args.force)
    print(destination.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
