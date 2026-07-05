#!/usr/bin/env python3
"""Validate that a runner PR contains only sanitized benchmark data."""

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
APPROVED_BENCHMARK_RE = re.compile(
    r"^benchmarks/[^/]+_(?:SANITIZED_BENCHMARK_REPORT\.md|DATA_MANIFEST\.json)$"
)
APPROVED_CHALLENGE_RE = re.compile(
    r"^challenges/[^/]+/[^/]+/[^/]+/(?:state\.json|notes\.md|replay\.sh|evidence/[^/]+\.(?:summary\.md|sanitize_check\.md))$"
)
SHAREABLE_EVIDENCE_RE = re.compile(r"^evidence/[^/]+\.(?:summary\.md|sanitize_check\.md)$")
RAW_REPLAY_LOG_RE = re.compile(r"^evidence/replay_[^/]+\.log$")
APPROVED_STATUS = {"A", "M", "T"}
TERMINAL_STATUSES = {"solved", "blocked", "partial"}
VALID_AGENT_MODES = {
    "none",
    "assisted",
    "autonomous",
    "hermes_readonly",
    "lazycodex_readonly",
    "gajae_bounded",
}
VALID_FAILURE_CLASSES = {
    "none",
    "env_missing",
    "dependency_missing",
    "wrong_hypothesis",
    "primitive_gap",
    "leak_missing",
    "exploit_unstable",
    "remote_env_mismatch",
    "search_explosion",
    "replay_gap",
    "evidence_gap",
    "false_success_risk",
    "timeout",
    "unknown",
}
REQUIRED_STATE_FIELDS = (
    "event",
    "category",
    "name",
    "workspace",
    "status",
    "evidence",
    "metadata",
    "tool_routing",
)
REQUIRED_METADATA_FIELDS = (
    "proof_scope",
    "remote_status",
    "remote_solve",
    "replay_kind",
    "current_remote_liveness",
    "evidence_sensitivity",
    "last_replay",
    "agent_mode",
    "failure_class",
    "replay_quality",
    "shareability",
    "tool_effectiveness",
)
REQUIRED_TOOL_ROUTING_FIELDS = (
    "primary_tools_used",
    "considered",
    "used",
    "skipped",
    "missing",
    "decision_summary",
)
REQUIRED_NOTES_SECTIONS = (
    "## Summary",
    "## Artifacts",
    "## Observations",
    "## Hypotheses",
    "## Attempts",
    "## Tool Routing Decision",
    "## Agent Design Metadata",
    "## Blocker or Solve",
    "## Evidence",
)


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
    return APPROVED_BENCHMARK_RE.match(path) is not None or APPROVED_CHALLENGE_RE.match(path) is not None


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        fail(f"cannot read {path.relative_to(ROOT)}: {exc}", code=2)


def require_mapping(data: dict[str, object], field: str, path: Path) -> dict[str, object]:
    value = data.get(field)
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} {field} must be a JSON object")
    return value


def require_string(data: dict[str, object], field: str, path: Path) -> str:
    value = data.get(field)
    if not isinstance(value, str):
        fail(f"{path.relative_to(ROOT)} {field} must be a string")
    return value


def require_string_list(data: dict[str, object], field: str, path: Path) -> list[str]:
    value = data.get(field)
    if not isinstance(value, list) or not all(isinstance(entry, str) for entry in value):
        fail(f"{path.relative_to(ROOT)} {field} must be a list of strings")
    return value


def require_nonempty(value: str, field: str, path: Path) -> None:
    if not value.strip():
        fail(f"{path.relative_to(ROOT)} {field} must not be empty")


def replay_summary_for(raw_log_entry: Path) -> Path:
    return raw_log_entry.with_name(f"{raw_log_entry.stem}.summary.md")


def validate_evidence_entry(entry: str, challenge_dir: Path, state_path: Path) -> None:
    evidence_path = Path(entry)
    if evidence_path.is_absolute() or ".." in evidence_path.parts:
        fail(f"{state_path.relative_to(ROOT)} evidence entry escapes challenge directory: {entry!r}")
    normalized = evidence_path.as_posix()
    if SHAREABLE_EVIDENCE_RE.match(normalized):
        if not (challenge_dir / evidence_path).is_file():
            fail(f"{state_path.relative_to(ROOT)} evidence entry does not exist: {entry!r}")
        return
    if RAW_REPLAY_LOG_RE.match(normalized):
        summary_entry = replay_summary_for(evidence_path)
        if not (challenge_dir / summary_entry).is_file():
            fail(
                f"{state_path.relative_to(ROOT)} raw replay log evidence requires "
                f"shareable summary: {summary_entry.as_posix()!r}"
            )
        return
    fail(
        f"{state_path.relative_to(ROOT)} evidence entry must be a shareable summary, "
        f"sanitize check, or raw replay log represented by a summary: {entry!r}"
    )


def has_shareable_replay_proof(evidence: list[str], challenge_dir: Path) -> bool:
    for entry in evidence:
        evidence_path = Path(entry)
        normalized = evidence_path.as_posix()
        if RAW_REPLAY_LOG_RE.match(normalized) and (challenge_dir / replay_summary_for(evidence_path)).is_file():
            return True
        if normalized.startswith("evidence/") and re.match(r"^replay_[^/]+\.summary\.md$", evidence_path.name):
            if (challenge_dir / evidence_path).is_file():
                return True
    return False


def validate_state_json(path: Path) -> None:
    try:
        data = json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        fail(f"{path.relative_to(ROOT)} is invalid JSON: {exc}", code=2)
    if not isinstance(data, dict):
        fail(f"{path.relative_to(ROOT)} root must be a JSON object", code=2)
    missing = [field for field in REQUIRED_STATE_FIELDS if field not in data]
    if missing:
        fail(f"{path.relative_to(ROOT)} missing required field(s): {', '.join(missing)}")

    status = require_string(data, "status", path)
    require_nonempty(status, "status", path)
    for field in ("event", "category", "name", "workspace"):
        require_nonempty(require_string(data, field, path), field, path)

    relative = path.relative_to(ROOT)
    if len(relative.parts) >= 5 and relative.parts[0] == "challenges":
        expected_event, expected_category, expected_name = relative.parts[1:4]
        expected_workspace = Path(*relative.parts[:-1]).as_posix()
        if data["event"] != expected_event:
            fail(f"{relative} event must match path component {expected_event!r}")
        if data["category"] != expected_category:
            fail(f"{relative} category must match path component {expected_category!r}")
        if data["name"] != expected_name:
            fail(f"{relative} name must match path component {expected_name!r}")
        if data["workspace"] != expected_workspace:
            fail(f"{relative} workspace must exactly equal {expected_workspace!r}")

    final_command = data.get("final_command")
    if final_command is not None and not isinstance(final_command, str):
        fail(f"{path.relative_to(ROOT)} final_command must be a string when present")
    evidence = require_string_list(data, "evidence", path)
    challenge_dir = path.parent
    for entry in evidence:
        validate_evidence_entry(entry, challenge_dir, path)

    blocker = require_mapping(data, "blocker", path)
    for field in ("reason", "next_action"):
        require_string(blocker, field, path)
    if status == "blocked":
        require_nonempty(str(blocker["reason"]), "blocker.reason", path)
        require_nonempty(str(blocker["next_action"]), "blocker.next_action", path)

    metadata = require_mapping(data, "metadata", path)
    missing_metadata = [field for field in REQUIRED_METADATA_FIELDS if field not in metadata]
    if missing_metadata:
        fail(f"{path.relative_to(ROOT)} metadata missing required field(s): {', '.join(missing_metadata)}")
    for field in REQUIRED_METADATA_FIELDS:
        if field in {"last_replay", "tool_effectiveness"}:
            require_mapping(metadata, field, path)
        else:
            require_string(metadata, field, path)

    agent_mode = str(metadata["agent_mode"])
    if agent_mode not in VALID_AGENT_MODES:
        fail(f"{path.relative_to(ROOT)} metadata.agent_mode must be one of {', '.join(sorted(VALID_AGENT_MODES))}")
    failure_class = str(metadata["failure_class"])
    if failure_class not in VALID_FAILURE_CLASSES:
        fail(
            f"{path.relative_to(ROOT)} metadata.failure_class must be one of "
            f"{', '.join(sorted(VALID_FAILURE_CLASSES))}"
        )

    tool_routing = require_mapping(data, "tool_routing", path)
    missing_tool_routing = [field for field in REQUIRED_TOOL_ROUTING_FIELDS if field not in tool_routing]
    if missing_tool_routing:
        fail(f"{path.relative_to(ROOT)} tool_routing missing required field(s): {', '.join(missing_tool_routing)}")
    for field in ("primary_tools_used", "considered", "used", "skipped", "missing"):
        require_string_list(tool_routing, field, path)
    require_string(tool_routing, "decision_summary", path)

    if status in TERMINAL_STATUSES:
        for field in (
            "proof_scope",
            "remote_status",
            "remote_solve",
            "replay_kind",
            "current_remote_liveness",
            "evidence_sensitivity",
            "replay_quality",
            "shareability",
        ):
            require_nonempty(str(metadata[field]), f"metadata.{field}", path)
        tool_effectiveness = require_mapping(metadata, "tool_effectiveness", path)
        if not tool_effectiveness:
            fail(f"{path.relative_to(ROOT)} metadata.tool_effectiveness must not be empty for {status}")
        if not all(isinstance(key, str) and isinstance(value, str) for key, value in tool_effectiveness.items()):
            fail(f"{path.relative_to(ROOT)} metadata.tool_effectiveness must map strings to strings")
        require_nonempty(str(tool_routing["decision_summary"]), "tool_routing.decision_summary", path)

    if status == "solved":
        if not isinstance(final_command, str) or not final_command.strip():
            fail(f"{path.relative_to(ROOT)} solved state requires non-empty final_command")
        if str(metadata["proof_scope"]).strip().lower() == "none":
            fail(f"{path.relative_to(ROOT)} solved state requires metadata.proof_scope other than none")
        if failure_class != "none":
            fail(f"{path.relative_to(ROOT)} solved state requires metadata.failure_class = none")
        if not evidence:
            fail(f"{path.relative_to(ROOT)} solved state requires replay/proof evidence entries")
        if not has_shareable_replay_proof(evidence, challenge_dir):
            fail(f"{path.relative_to(ROOT)} solved state requires shareable replay proof evidence")
        if not require_mapping(metadata, "last_replay", path):
            fail(f"{path.relative_to(ROOT)} solved state requires metadata.last_replay details")


def validate_notes_md(path: Path) -> None:
    text = read_text(path)
    missing = [section for section in REQUIRED_NOTES_SECTIONS if section not in text]
    if missing:
        fail(f"{path.relative_to(ROOT)} missing required section(s): {', '.join(missing)}")


def validate_json(path: Path) -> None:
    try:
        json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        fail(f"{path.relative_to(ROOT)} is invalid JSON: {exc}", code=2)


def validate_text_sanitized(path: Path) -> None:
    text = read_text(path)
    if FLAG_PATTERN.search(text):
        fail(f"{path.relative_to(ROOT)} contains a flag-like marker; submit a redacted summary")


def validate_proof_contract(path: Path) -> None:
    challenge_dir = path.parent.relative_to(ROOT).as_posix()
    result = subprocess.run(
        ["python3", "tools/proof_validate.py", challenge_dir],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or f"returncode={result.returncode}"
        fail(f"{path.relative_to(ROOT)} proof validation failed: {detail}")


def validate_file_content(path: str) -> None:
    full_path = ROOT / path
    if not full_path.is_file():
        fail(f"changed file does not exist in worktree: {path}", code=2)
    if path.endswith("state.json"):
        validate_state_json(full_path)
        validate_proof_contract(full_path)
    elif path.endswith("notes.md"):
        validate_notes_md(full_path)
    elif path.endswith(".json"):
        validate_json(full_path)
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
