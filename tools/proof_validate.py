#!/usr/bin/env python3
"""Validate that a challenge state has enough evidence for its claimed status."""

from __future__ import annotations

import argparse
import json
import re
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
FLAG_PATTERN = re.compile(r"\b(?:FLAG|CTF|DH|SEKAI)\{[^}\r\n]{1,200}\}", re.IGNORECASE)
REQUIRED_METADATA_FIELDS = (
    "proof_scope",
    "remote_status",
    "remote_solve",
    "replay_kind",
    "current_remote_liveness",
    "evidence_sensitivity",
)
ALLOWED_REPLAY_KINDS = {
    "local",
    "local_proof",
    "remote_liveness",
    "remote_live",
    "remote_live_exploit",
    "remote_saved_evidence",
}
ALLOWED_REMOTE_LIVENESS = {
    "not_applicable",
    "unknown",
    "live",
    "partial",
    "expired",
    "unavailable",
}
ALLOWED_EVIDENCE_SENSITIVITY = {
    "no_sensitive_markers",
    "contains_flag",
    "contains_secret",
    "unknown",
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


def metadata_dict(state: dict[str, object]) -> dict[str, object]:
    metadata = state.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def validate_metadata_contract(metadata: dict[str, object]) -> None:
    missing = [field for field in REQUIRED_METADATA_FIELDS if field not in metadata]
    if missing:
        fail(f"metadata missing required field(s): {', '.join(missing)}")

    replay_kind = text_reason(metadata.get("replay_kind"))
    if replay_kind not in ALLOWED_REPLAY_KINDS:
        fail(
            "metadata.replay_kind must be one of "
            f"{', '.join(sorted(ALLOWED_REPLAY_KINDS))}; got {replay_kind!r}"
        )

    current_remote_liveness = text_reason(metadata.get("current_remote_liveness"))
    if current_remote_liveness not in ALLOWED_REMOTE_LIVENESS:
        fail(
            "metadata.current_remote_liveness must be one of "
            f"{', '.join(sorted(ALLOWED_REMOTE_LIVENESS))}; got {current_remote_liveness!r}"
        )

    evidence_sensitivity = text_reason(metadata.get("evidence_sensitivity"))
    if evidence_sensitivity not in ALLOWED_EVIDENCE_SENSITIVITY:
        fail(
            "metadata.evidence_sensitivity must be one of "
            f"{', '.join(sorted(ALLOWED_EVIDENCE_SENSITIVITY))}; got {evidence_sensitivity!r}"
        )


def validate_evidence_entries(challenge_dir: Path, state: dict[str, object]) -> list[Path]:
    raw_entries = state.get("evidence", [])
    if raw_entries is None:
        return []
    if not isinstance(raw_entries, list):
        fail("evidence must be a list of relative paths")

    paths: list[Path] = []
    for entry in raw_entries:
        if not isinstance(entry, str) or not entry.strip():
            fail("evidence entries must be non-empty strings")
        relative = Path(entry)
        if relative.is_absolute() or ".." in relative.parts:
            fail(f"evidence entry must stay inside the challenge directory: {entry!r}")
        path = challenge_dir / relative
        if not path.exists():
            fail(f"evidence entry does not exist: {entry}")
        paths.append(path)
    return paths


def summary_path_for(log_path: Path) -> Path:
    return log_path.with_name(f"{log_path.stem}.summary.md")


def contains_sensitive_marker(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return FLAG_PATTERN.search(text) is not None


def validate_sensitive_replay_summaries(replay_logs: list[Path]) -> int:
    sensitive_count = 0
    for log_path in replay_logs:
        if not contains_sensitive_marker(log_path):
            continue
        sensitive_count += 1
        summary_path = summary_path_for(log_path)
        if not summary_path.is_file():
            fail(
                "sensitive replay log requires redacted summary: "
                f"{summary_path.relative_to(log_path.parents[1])}"
            )
        if contains_sensitive_marker(summary_path):
            fail(f"redacted replay summary still contains a flag-like marker: {summary_path}")
    return sensitive_count


def remote_status_failed(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith("fail") or "failed" in lowered or "no_flag" in lowered


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

    evidence_paths = validate_evidence_entries(challenge_dir, state)
    replay_logs = sorted((challenge_dir / "evidence").glob("replay_*.log"))
    final_command = str(state.get("final_command") or "").strip()
    blocker_reason = extract_blocker_reason(state)
    metadata = metadata_dict(state)
    validate_metadata_contract(metadata)
    proof_scope = text_reason(metadata.get("proof_scope"))
    remote_status = text_reason(metadata.get("remote_status"))
    remote_solve = text_reason(metadata.get("remote_solve"))
    replay_kind = text_reason(metadata.get("replay_kind"))
    current_remote_liveness = text_reason(metadata.get("current_remote_liveness"))
    sensitive_logs = validate_sensitive_replay_summaries(replay_logs)

    if status == "solved":
        if not final_command:
            fail("solved status requires non-empty final_command")
        if not replay_logs:
            fail("solved status requires at least one evidence/replay_*.log")
        if proof_scope in {"", "none"}:
            fail("solved status requires metadata.proof_scope to describe the proof")
        if remote_status_failed(remote_status or remote_solve) and "local" not in proof_scope.lower():
            fail("solved status with failed remote status requires local proof_scope metadata")
    if status == "blocked" and not blocker_reason:
        fail("blocked status requires non-empty blocker, blocked_reason, or blocker_reason")
    if status == "partial" and not evidence_paths and not blocker_reason:
        fail("partial status requires evidence entries or a blocker reason")

    scope = proof_scope or "unspecified"
    remote = remote_status or remote_solve or "unspecified"
    print(
        "proof ok: "
        f"status={status} "
        f"replay_logs={len(replay_logs)} "
        f"sensitive_logs={sensitive_logs} "
        f"proof_scope={scope} "
        f"remote_status={remote} "
        f"replay_kind={replay_kind} "
        f"current_remote_liveness={current_remote_liveness}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
