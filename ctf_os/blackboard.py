"""Compact append-only ledger of execution-verified race facts."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from .workspace import append_jsonl, read_json, read_jsonl, state_lock


EVENT_TYPES = frozenset({
    "COMMAND_RESULT", "OBSERVATION", "PRIMITIVE", "WORKING_POC", "REMOTE_RESULT",
    "HYPOTHESIS_KILLED", "EXACT_BLOCKER", "FLAG_CANDIDATE",
})
SHAREABLE_TYPES = EVENT_TYPES - {"COMMAND_RESULT", "FLAG_CANDIDATE"}
HIGH_VALUE_TYPES = frozenset({"PRIMITIVE", "WORKING_POC", "REMOTE_RESULT", "FLAG_CANDIDATE"})
MAX_OBSERVED = 16 * 1024


class BlackboardError(ValueError):
    pass


def append_verified_event(
    run_root: Path,
    *,
    event_type: str,
    lane_id: str,
    attack_family: str,
    receipt: Mapping[str, Any],
    artifact: str | None = None,
) -> dict[str, Any]:
    if event_type not in EVENT_TYPES:
        raise BlackboardError(f"unsupported blackboard event: {event_type}")
    race = read_json(run_root / "RACE.json", "race state")
    lane = _lane(race, lane_id)
    if lane.get("attack_family") != attack_family:
        raise BlackboardError("event attack_family does not match its lane")
    _validate_receipt(run_root, lane_id, receipt)
    observed_full = str(receipt.get("observed_output", ""))
    artifact_path, artifact_hash = _artifact(run_root, lane_id, artifact)
    if event_type != "COMMAND_RESULT" and not observed_full and artifact_path is None:
        raise BlackboardError("verified claim requires observed output or an actual artifact")
    target = str(receipt["target_identity"])
    _validate_target_identity(race, target)
    if event_type in {"REMOTE_RESULT", "FLAG_CANDIDATE"} and receipt.get("target_observed") is not True:
        raise BlackboardError("remote/flag event requires an actual target-observation receipt")
    output_hash = str(receipt["output_hash"])
    argv = [str(value) for value in receipt["argv"]]
    event = {
        "schema_version": 1,
        "event_type": event_type,
        "run_id": race["run_id"],
        "lane_id": lane_id,
        "attack_family": attack_family,
        "receipt_id": str(receipt["receipt_id"]),
        "argv": argv,
        "argv_family": str(receipt["argv_family"]),
        "exit_code": int(receipt["exit_code"]),
        "observed_output": redact_output(observed_full[-MAX_OBSERVED:]),
        "output_hash": output_hash,
        "artifact_path": artifact_path,
        "artifact_hash": artifact_hash,
        "target_identity": target,
        "timestamp": str(receipt.get("finished_at") or _now()),
    }
    event["fingerprint"] = hashlib.sha256(json.dumps({
        "attack_family": attack_family,
        "argv_family": event["argv_family"],
        "target_identity": target,
        "exit_code": event["exit_code"],
        "output_hash": output_hash,
        "artifact_hash": artifact_hash,
    }, sort_keys=True).encode()).hexdigest()
    with state_lock(run_root):
        prior = events(run_root)
        if any(row.get("receipt_id") == event["receipt_id"] and row.get("event_type") == event_type for row in prior):
            raise BlackboardError("this receipt and event type were already recorded")
        append_jsonl(run_root / "BLACKBOARD.jsonl", event)
    return event


def events(run_root: Path) -> list[dict[str, Any]]:
    return read_jsonl(run_root / "BLACKBOARD.jsonl", "blackboard")


def verified_delta(run_root: Path, *, since: str | None = None, limit: int = 12) -> list[dict[str, Any]]:
    rows = [row for row in events(run_root) if row.get("event_type") in SHAREABLE_TYPES]
    if since:
        rows = [row for row in rows if str(row.get("timestamp", "")) > since]
    return [_compact(row) for row in rows[-max(1, min(limit, 50)):]]


def duplicate_signals(run_root: Path) -> list[dict[str, Any]]:
    rows = events(run_root)
    signals: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        for other in rows[:index]:
            if row.get("lane_id") == other.get("lane_id"):
                continue
            same_family_output = (
                row.get("attack_family") == other.get("attack_family")
                and row.get("output_hash") == other.get("output_hash")
            )
            same_execution = (
                row.get("argv_family") == other.get("argv_family")
                and row.get("target_identity") == other.get("target_identity")
                and row.get("exit_code") == other.get("exit_code")
                and row.get("output_hash") == other.get("output_hash")
            )
            if same_family_output or same_execution:
                signals.append({
                    "lane_id": row["lane_id"],
                    "duplicates_lane": other["lane_id"],
                    "fingerprint": row["fingerprint"],
                    "reason": "same-family-output" if same_family_output else "same-execution-output",
                })
                break
    return signals


def output_hash(output: str) -> str:
    normalized = output.replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(normalized.encode()).hexdigest()


def redact_output(value: str) -> str:
    patterns = (
        (re.compile(r"AKIA[0-9A-Z]{16}"), "<redacted-aws-key>"),
        (re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s]+"), r"\1<redacted>"),
        (re.compile(r"(?i)((?:password|secret|api[_-]?key)\s*[=:]\s*)[^\s,;]+"), r"\1<redacted>"),
    )
    result = value
    for pattern, replacement in patterns:
        result = pattern.sub(replacement, result)
    return result


def _validate_receipt(run_root: Path, lane_id: str, receipt: Mapping[str, Any]) -> None:
    required = {
        "receipt_id": str,
        "run_id": str,
        "lane_id": str,
        "argv": list,
        "argv_family": str,
        "exit_code": int,
        "observed_output": str,
        "output_hash": str,
        "target_identity": str,
    }
    for field, expected in required.items():
        if not isinstance(receipt.get(field), expected) or isinstance(receipt.get(field), bool):
            raise BlackboardError(f"execution receipt field {field} is missing or invalid")
    if receipt["run_id"] != run_root.name or receipt["lane_id"] != lane_id:
        raise BlackboardError("execution receipt does not belong to this exact run/lane")
    if not receipt["argv"] or any(not isinstance(value, str) or not value for value in receipt["argv"]):
        raise BlackboardError("execution receipt argv is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", str(receipt["output_hash"])):
        raise BlackboardError("execution receipt output hash is invalid")
    receipt_path = run_root / "workers" / lane_id / "logs" / f"{receipt['receipt_id']}.json"
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise BlackboardError("claim has no durable command/session receipt")
    try:
        durable = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BlackboardError("durable execution receipt is unreadable") from exc
    for field in ("receipt_id", "run_id", "lane_id", "argv", "exit_code", "output_hash", "target_identity"):
        if durable.get(field) != receipt.get(field):
            raise BlackboardError(f"execution receipt was changed after execution: {field}")


def _artifact(run_root: Path, lane_id: str, value: str | None) -> tuple[str | None, str | None]:
    if value is None:
        return None, None
    relative = Path(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise BlackboardError("artifact must be a safe lane-artifacts-relative path")
    root = (run_root / "workers" / lane_id / "artifacts").resolve()
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise BlackboardError("artifact escapes its lane") from exc
    if path.is_symlink() or not path.is_file():
        raise BlackboardError("artifact does not exist as a regular lane-private file")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return relative.as_posix(), digest.hexdigest()


def _validate_target_identity(race: Mapping[str, Any], value: str) -> None:
    allowed = {f"challenge:{race['challenge']['id']}"}
    allowed.update(str(row["declared"]) for row in race.get("declared_targets", []) if isinstance(row, Mapping))
    allowed.update(str(endpoint) for endpoint in race.get("service_endpoints", []))
    if value not in allowed:
        raise BlackboardError("receipt target is not the challenge or an organizer-declared target")


def _lane(race: Mapping[str, Any], lane_id: str) -> Mapping[str, Any]:
    for lane in race.get("lanes", []):
        if isinstance(lane, Mapping) and lane.get("lane_id") == lane_id:
            return lane
    raise BlackboardError(f"unknown race lane: {lane_id}")


def _compact(row: Mapping[str, Any]) -> dict[str, Any]:
    return {key: row.get(key) for key in (
        "event_type", "lane_id", "attack_family", "argv", "exit_code", "observed_output",
        "output_hash", "artifact_path", "artifact_hash", "target_identity", "timestamp",
    )}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
