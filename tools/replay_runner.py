#!/usr/bin/env python3
"""Run or summarize a challenge replay script and preserve evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path


FLAG_PATTERN = re.compile(r"\b(?:FLAG|CTF|DH|SEKAI)\{[^}\r\n]{1,200}\}", re.IGNORECASE)
SECRET_PATTERNS = (
    (
        re.compile(
            r"\b(api[_-]?key|token|secret|password)\b\s*[:=]\s*([^\s'\"`]+)",
            re.IGNORECASE,
        ),
        lambda match: f"{match.group(1)}=<REDACTED_SECRET>",
    ),
    (
        re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
        lambda _match: "Bearer <REDACTED_SECRET>",
    ),
)
SUMMARY_LIMIT = 16_000


def fail(message: str, code: int = 2) -> None:
    print(f"replay_runner: {message}", file=sys.stderr)
    raise SystemExit(code)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("challenge_dir", help="challenge directory containing replay.sh")
    parser.add_argument(
        "--allow-remote-live",
        action="store_true",
        help="allow replay_kind=remote_live or remote_live_exploit to run",
    )
    parser.add_argument(
        "--summarize-existing",
        action="store_true",
        help="redact and summarize existing evidence/replay_*.log files without running replay.sh",
    )
    return parser.parse_args()


def utc_timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def utc_iso(timestamp: str | None = None) -> str:
    if timestamp is None:
        return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        )
    return dt.datetime.strptime(timestamp, "%Y%m%dT%H%M%SZ").replace(
        tzinfo=dt.timezone.utc
    ).isoformat().replace("+00:00", "Z")


def redact_text(text: str) -> tuple[str, str]:
    sensitivity = "no_sensitive_markers"

    def flag_replacement(_match: re.Match[str]) -> str:
        nonlocal sensitivity
        sensitivity = "contains_flag"
        return "<REDACTED_FLAG>"

    redacted = FLAG_PATTERN.sub(flag_replacement, text)
    for pattern, replacement in SECRET_PATTERNS:
        if pattern.search(redacted) and sensitivity == "no_sensitive_markers":
            sensitivity = "contains_secret"
        redacted = pattern.sub(replacement, redacted)

    if len(redacted) > SUMMARY_LIMIT:
        redacted = redacted[:SUMMARY_LIMIT] + "\n[truncated for summary]\n"
    return redacted, sensitivity


def summary_path_for(log_path: Path) -> Path:
    return log_path.with_name(f"{log_path.stem}.summary.md")


def parse_header_value(log_text: str, key: str) -> str:
    match = re.search(rf"^{re.escape(key)}:\s*(.*)$", log_text, re.MULTILINE)
    return match.group(1).strip() if match else ""


def load_state(challenge_dir: Path) -> dict[str, object]:
    state_path = challenge_dir / "state.json"
    if not state_path.is_file():
        return {}
    try:
        return json.loads(state_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def metadata_dict(state: dict[str, object]) -> dict[str, object]:
    metadata = state.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def replay_kind_for(challenge_dir: Path) -> str:
    return str(metadata_dict(load_state(challenge_dir)).get("replay_kind") or "local").strip()


def validate_replay_script(challenge_dir: Path) -> Path:
    replay = challenge_dir / "replay.sh"
    if not replay.exists():
        fail(f"missing replay script: {replay}")
    if not replay.is_file():
        fail(f"replay script is not a regular file: {replay}")
    if not os.access(replay, os.X_OK):
        fail(f"replay script is not executable: {replay}")
    try:
        with replay.open("rb") as handle:
            first_line = handle.readline(256)
    except OSError as exc:
        fail(f"cannot read replay script: {replay}: {exc}")
    if not first_line.startswith(b"#!"):
        fail(f"replay script lacks a shebang: {replay}")
    return replay


def guard_remote_live_replay(challenge_dir: Path, *, allow_remote_live: bool) -> None:
    replay_kind = replay_kind_for(challenge_dir)
    if replay_kind not in {"remote_live", "remote_live_exploit"}:
        return
    if allow_remote_live:
        return
    fail(
        "refusing to run remote live replay without explicit opt-in: "
        f"metadata.replay_kind={replay_kind!r}; rerun with --allow-remote-live "
        "or use --summarize-existing for saved evidence"
    )


def parse_remote_liveness(log_text: str) -> str:
    match = re.search(r"^remote_liveness=([A-Za-z0-9_/-]+)", log_text, re.MULTILINE)
    if not match:
        return ""
    value = match.group(1).strip().lower()
    if value == "live":
        return "live"
    if "expired" in value or "closed" in value:
        return "expired"
    if "partial" in value:
        return "partial"
    return value or ""


def write_summary(challenge_dir: Path, log_path: Path) -> tuple[Path, str, str]:
    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    redacted, sensitivity = redact_text(log_text)
    raw_sha256 = hashlib.sha256(log_path.read_bytes()).hexdigest()
    redacted_sha256 = hashlib.sha256(redacted.encode("utf-8")).hexdigest()
    summary_path = summary_path_for(log_path)
    raw_rel = log_path.relative_to(challenge_dir).as_posix()
    timestamp = parse_header_value(log_text, "timestamp_utc")
    command = parse_header_value(log_text, "command")
    cwd = parse_header_value(log_text, "cwd")
    exit_code = parse_header_value(log_text, "exit_code")

    summary = [
        "# Replay Summary",
        "",
        f"- raw_log: `{raw_rel}`",
        f"- timestamp_utc: `{timestamp or 'unknown'}`",
        f"- command: `{command or 'unknown'}`",
        f"- cwd: `{cwd or 'unknown'}`",
        f"- exit_code: `{exit_code or 'unknown'}`",
        f"- sensitivity: `{sensitivity}`",
        f"- raw_log_sha256: `{raw_sha256}`",
        f"- redacted_transcript_sha256: `{redacted_sha256}`",
        "",
        "## Redacted Transcript",
        "",
        "```text",
        redacted.rstrip(),
        "```",
        "",
    ]
    summary_path.write_text("\n".join(summary), encoding="utf-8")
    return summary_path, sensitivity, timestamp


def append_unique(items: list[object], value: str) -> None:
    if value not in items:
        items.append(value)


def update_state(
    challenge_dir: Path,
    evidence_paths: list[Path],
    *,
    sensitivity: str,
    timestamp: str,
    replay_summary_only: bool,
) -> None:
    state_path = challenge_dir / "state.json"
    if not state_path.is_file():
        print(f"replay_runner: warning: missing state file: {state_path}", file=sys.stderr)
        return

    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"replay_runner: warning: invalid state.json: {exc}", file=sys.stderr)
        return

    evidence = state.get("evidence")
    if not isinstance(evidence, list):
        evidence = []
        state["evidence"] = evidence

    for path in evidence_paths:
        append_unique(evidence, path.relative_to(challenge_dir).as_posix())

    metadata = state.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
        state["metadata"] = metadata

    if sensitivity != "no_sensitive_markers":
        metadata["evidence_sensitivity"] = sensitivity
    else:
        metadata.setdefault("evidence_sensitivity", sensitivity)

    combined_log = ""
    for path in evidence_paths:
        if path.suffix == ".log":
            combined_log += path.read_text(encoding="utf-8", errors="replace")
    remote_liveness = parse_remote_liveness(combined_log)
    if remote_liveness:
        metadata["current_remote_liveness"] = remote_liveness
    else:
        metadata.setdefault("current_remote_liveness", "not_applicable")
    metadata.setdefault("proof_scope", "none")
    metadata.setdefault("remote_status", "not_attempted")
    metadata.setdefault("remote_solve", "not_attempted")
    metadata.setdefault("replay_kind", "local")

    metadata["last_replay"] = {
        "timestamp_utc": timestamp,
        "summary_only": replay_summary_only,
        "sensitivity": sensitivity,
        "replay_kind": metadata.get("replay_kind", "local"),
        "current_remote_liveness": metadata.get("current_remote_liveness", "not_applicable"),
        "artifacts": [path.relative_to(challenge_dir).as_posix() for path in evidence_paths],
    }
    state["updated_at"] = utc_iso(timestamp) if timestamp else utc_iso()

    state_path.write_text(json.dumps(state, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def summarize_existing(challenge_dir: Path) -> int:
    evidence_dir = challenge_dir / "evidence"
    logs = sorted(evidence_dir.glob("replay_*.log"))
    if not logs:
        fail(f"no replay logs found under: {evidence_dir}")

    all_paths: list[Path] = []
    strongest = "no_sensitive_markers"
    last_timestamp = ""
    for log_path in logs:
        summary_path, sensitivity, timestamp = write_summary(challenge_dir, log_path)
        all_paths.extend([log_path, summary_path])
        last_timestamp = timestamp or last_timestamp
        if sensitivity == "contains_flag":
            strongest = sensitivity
        elif sensitivity != "no_sensitive_markers" and strongest == "no_sensitive_markers":
            strongest = sensitivity
        print(summary_path)

    update_state(
        challenge_dir,
        all_paths,
        sensitivity=strongest,
        timestamp=last_timestamp,
        replay_summary_only=True,
    )
    return 0


def run_replay(challenge_dir: Path, *, allow_remote_live: bool) -> int:
    validate_replay_script(challenge_dir)
    guard_remote_live_replay(challenge_dir, allow_remote_live=allow_remote_live)

    evidence_dir = challenge_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    timestamp = utc_timestamp()
    log_path = evidence_dir / f"replay_{timestamp}.log"
    command = ["./replay.sh"]
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

    summary_path, sensitivity, summary_timestamp = write_summary(challenge_dir, log_path)
    update_state(
        challenge_dir,
        [log_path, summary_path],
        sensitivity=sensitivity,
        timestamp=summary_timestamp or timestamp,
        replay_summary_only=False,
    )

    print(log_path)
    print(summary_path)
    return result.returncode


def main() -> int:
    args = parse_args()
    challenge_dir = Path(args.challenge_dir).expanduser().resolve()
    if not challenge_dir.is_dir():
        fail(f"challenge directory does not exist: {challenge_dir}")

    if args.summarize_existing:
        validate_replay_script(challenge_dir)
        return summarize_existing(challenge_dir)
    return run_replay(challenge_dir, allow_remote_live=args.allow_remote_live)


if __name__ == "__main__":
    raise SystemExit(main())
