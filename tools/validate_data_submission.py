#!/usr/bin/env python3
"""Validate that a runner PR contains only approved blindtest challenge data."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FLAG_PATTERN = re.compile(r"\b(?:FLAG|CTF|DH|SEKAI)\{[^}\r\n]{1,200}\}", re.IGNORECASE)
SECRET_NAME_PATTERN = re.compile(
    r"(^|/)(?:\.env(?:\..*)?|flag(?:\.txt)?|id_rsa|id_ed25519|.*\.(?:pem|key|log|pcap|pcapng|dmp))$",
    re.IGNORECASE,
)
APPROVED_CHALLENGE_RE = re.compile(
    r"^challenges/blindtest/[^/]+/[^/]+/(?:state\.json|notes\.md|replay\.sh|(?:evidence|work)/.+)$"
)
APPROVED_STATUS = {"A", "M", "T"}


def fail(message: str, code: int = 1) -> None:
    print(f"validate_data_submission: {message}", file=sys.stderr)
    raise SystemExit(code)


def run_git(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", help="base ref or SHA; defaults to origin/main when available")
    parser.add_argument("--head", default="HEAD", help="head ref or SHA")
    parser.add_argument("--staged", action="store_true", help="validate staged changes instead of a ref diff")
    return parser.parse_args()


def default_base() -> str:
    for candidate in ("origin/main", "main"):
        result = run_git(["rev-parse", "--verify", "--quiet", candidate])
        if result.returncode == 0:
            return candidate
    fail("cannot find a default base ref; pass --base explicitly", code=2)


def changed_entries(*, base: str | None, head: str, staged: bool) -> list[tuple[str, str]]:
    if staged:
        command = ["diff", "--cached", "--name-status", "--find-renames"]
    else:
        chosen_base = base or default_base()
        command = ["diff", "--name-status", "--find-renames", f"{chosen_base}...{head}"]
    result = run_git(command)
    if result.returncode != 0:
        fail(result.stderr.strip() or "git diff failed", code=2)

    entries: list[tuple[str, str]] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0]
        if status.startswith(("R", "C")):
            entries.append((status[0], parts[-1]))
        elif len(parts) >= 2:
            entries.append((status[0], parts[1]))
        else:
            fail(f"cannot parse git diff line: {line!r}", code=2)
    return entries


def is_approved_path(path: str) -> bool:
    return APPROVED_CHALLENGE_RE.match(path) is not None


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        fail(f"cannot read {path.relative_to(ROOT)}: {exc}", code=2)


def validate_state_json(path: Path) -> None:
    try:
        data = json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        fail(f"{path.relative_to(ROOT)} is invalid JSON: {exc}", code=2)
    if not isinstance(data, dict):
        fail(f"{path.relative_to(ROOT)} root must be a JSON object", code=2)
    status = data.get("status")
    if not isinstance(status, str) or not status.strip():
        fail(f"{path.relative_to(ROOT)} must contain a non-empty status")
    final_command = data.get("final_command")
    if final_command is not None and not isinstance(final_command, str):
        fail(f"{path.relative_to(ROOT)} final_command must be a string when present")
    evidence = data.get("evidence", [])
    if evidence is not None:
        if not isinstance(evidence, list) or not all(isinstance(entry, str) for entry in evidence):
            fail(f"{path.relative_to(ROOT)} evidence must be a list of relative path strings")
        for entry in evidence:
            relative = Path(entry)
            if relative.is_absolute() or ".." in relative.parts:
                fail(f"{path.relative_to(ROOT)} evidence entry escapes challenge directory: {entry!r}")


def validate_json(path: Path) -> None:
    try:
        json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        fail(f"{path.relative_to(ROOT)} is invalid JSON: {exc}", code=2)


def validate_text_sanitized(path: Path) -> None:
    text = read_text(path)
    if FLAG_PATTERN.search(text):
        fail(f"{path.relative_to(ROOT)} contains a flag-like marker; submit a redacted summary")


def validate_file_content(path: str) -> None:
    full_path = ROOT / path
    if not full_path.is_file():
        fail(f"changed file does not exist in worktree: {path}", code=2)
    if path.endswith("state.json"):
        validate_state_json(full_path)
    elif path.endswith(".json"):
        validate_json(full_path)
    if path.endswith((".md", ".sh", ".json")):
        validate_text_sanitized(full_path)


def main() -> int:
    args = parse_args()
    entries = changed_entries(base=args.base, head=args.head, staged=args.staged)
    if not entries:
        print("data submission ok: no changed files")
        return 0

    errors: list[str] = []
    approved_paths: list[str] = []
    for status, path in entries:
        if status not in APPROVED_STATUS:
            errors.append(f"{path}: status {status!r} is not allowed for data submissions")
            continue
        if SECRET_NAME_PATTERN.search(path):
            errors.append(f"{path}: raw secret/log file names are not allowed")
            continue
        if not is_approved_path(path):
            errors.append(f"{path}: not an approved sanitized data path")
            continue
        approved_paths.append(path)

    if errors:
        for error in errors:
            print(f"FAIL {error}", file=sys.stderr)
        fail(f"{len(errors)} rejected path(s)")

    for path in approved_paths:
        validate_file_content(path)
        print(f"PASS {path}")

    print(f"data submission ok: files={len(approved_paths)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
