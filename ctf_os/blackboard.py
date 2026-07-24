"""Compact append-only ledger of execution-verified race facts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .workspace import append_jsonl, read_json, read_jsonl, state_lock

EVENT_TYPES = frozenset({
    "COMMAND_RESULT", "OBSERVATION", "PRIMITIVE", "WORKING_POC", "REMOTE_RESULT",
    "HYPOTHESIS_KILLED", "EXACT_BLOCKER", "FLAG_CANDIDATE",
})
SHAREABLE_TYPES = EVENT_TYPES - {"COMMAND_RESULT", "FLAG_CANDIDATE"}
HIGH_VALUE_TYPES = frozenset({"PRIMITIVE", "WORKING_POC", "REMOTE_RESULT", "FLAG_CANDIDATE"})
MAX_OBSERVED = 16 * 1024
MAX_SHARED_ARTIFACT_BYTES = 512 * 1024 * 1024


class BlackboardError(ValueError):
    pass


def human_relay_blocks_promotion(race: Mapping[str, Any]) -> bool:
    """Return whether a receipt cannot exclude human-relay external input.

    Organizer requests are participant-executed in human-relay mode. A local
    command can echo that participant result and can also make an unrelated
    packet to a Root-owned service. Therefore no sandbox receipt in this mode is
    eligible for automatic remote-result/flag promotion. Command receipts and
    ordinary local observations remain available with their explicit provenance.
    """

    return str(race.get("remote_execution", "agent")) == "human-relay"


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
    artifact_path, artifact_hash, artifact_size = _artifact(run_root, lane_id, artifact)
    if event_type != "COMMAND_RESULT" and not observed_full and artifact_path is None:
        raise BlackboardError("verified claim requires observed output or an actual artifact")
    target = str(receipt["target_identity"])
    _validate_target_identity(race, target)
    if event_type in {"REMOTE_RESULT", "FLAG_CANDIDATE"}:
        if human_relay_blocks_promotion(race):
            raise BlackboardError(
                "human-relay participant output cannot become a verified remote/flag event"
            )
        if receipt.get("target_observed") is not True:
            raise BlackboardError(
                "remote/flag event requires an actual target-observation receipt"
            )
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
        "artifact_size": artifact_size,
        "shared_artifact_path": None,
        "target_identity": target,
        "target_observed": receipt.get("target_observed") is True,
        "observation_source": str(receipt.get("observation_source") or "legacy"),
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
        if artifact_path is not None and artifact_hash is not None:
            shared = _publish_artifact(
                run_root,
                lane_id=lane_id,
                relative=artifact_path,
                expected_hash=artifact_hash,
                expected_size=int(artifact_size or 0),
            )
            event["shared_artifact_path"] = shared
        append_jsonl(run_root / "BLACKBOARD.jsonl", event)
        if event["shared_artifact_path"] is not None:
            try:
                _expose_snapshot(
                    run_root,
                    str(event["shared_artifact_path"]),
                )
            except BlackboardError as exc:
                # The append-only event remains authoritative. A later inbox
                # registration backfills this immutable snapshot.
                event["artifact_exchange_warning"] = str(exc)[:2048]
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
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", str(receipt["receipt_id"])):
        raise BlackboardError("execution receipt id is invalid")
    receipt_path = run_root / "workers" / lane_id / "logs" / f"{receipt['receipt_id']}.json"
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise BlackboardError("claim has no durable command/session receipt")
    try:
        durable = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BlackboardError("durable execution receipt is unreadable") from exc
    fields = [
        "receipt_id", "run_id", "lane_id", "argv", "argv_family", "exit_code",
        "observed_output", "output_hash", "target_identity", "target_observed", "finished_at",
    ]
    if "observation_source" in receipt or "observation_source" in durable:
        fields.append("observation_source")
    for field in fields:
        if durable.get(field) != receipt.get(field):
            raise BlackboardError(f"execution receipt was changed after execution: {field}")


def register_artifact_inbox(run_root: Path, lane_id: str) -> Path:
    """Create one lane's read-only-mounted inbox and backfill verified snapshots."""

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", lane_id):
        raise BlackboardError("artifact inbox lane id is invalid")
    exchange = _exchange_root(run_root)
    inbox = exchange / "inbox" / lane_id
    if inbox.is_symlink():
        raise BlackboardError("artifact inbox is a symlink")
    inbox.mkdir(parents=True, mode=0o755, exist_ok=True)
    inbox.chmod(0o755)
    for row in events(run_root):
        shared = row.get("shared_artifact_path")
        if isinstance(shared, str):
            _link_snapshot(exchange, inbox, shared)
    return inbox


def shared_artifacts(run_root: Path) -> list[dict[str, Any]]:
    """Return compact immutable artifact manifests accepted by the blackboard."""

    return [
        {
            "lane_id": row.get("lane_id"),
            "artifact_path": row.get("artifact_path"),
            "artifact_hash": row.get("artifact_hash"),
            "artifact_size": row.get("artifact_size"),
            "shared_artifact_path": row.get("shared_artifact_path"),
            "container_path": (
                f"/shared-artifacts/{row['shared_artifact_path']}"
                if row.get("shared_artifact_path") else None
            ),
            "timestamp": row.get("timestamp"),
        }
        for row in events(run_root)
        if row.get("shared_artifact_path")
    ]


def _artifact(
    run_root: Path, lane_id: str, value: str | None
) -> tuple[str | None, str | None, int | None]:
    if value is None:
        return None, None, None
    relative = Path(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise BlackboardError("artifact must be a safe lane-artifacts-relative path")
    raw_root = run_root / "workers" / lane_id / "artifacts"
    if raw_root.is_symlink() or not raw_root.is_dir():
        raise BlackboardError("lane artifact root is missing or unsafe")
    root = raw_root.resolve()
    cursor = raw_root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise BlackboardError("artifact path contains a symlink")
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise BlackboardError("artifact escapes its lane") from exc
    if path.is_symlink() or not path.is_file():
        raise BlackboardError("artifact does not exist as a regular lane-private file")
    source_fd = _open_artifact_fd(raw_root, relative)
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode):
            raise BlackboardError("artifact is not a regular lane-private file")
        size = before.st_size
        if size > MAX_SHARED_ARTIFACT_BYTES:
            raise BlackboardError(
                f"artifact exceeds the {MAX_SHARED_ARTIFACT_BYTES}-byte verified exchange limit"
            )
        digest = hashlib.sha256()
        while chunk := os.read(source_fd, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(source_fd)
        if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
            raise BlackboardError("artifact changed while hashing")
        return relative.as_posix(), digest.hexdigest(), size
    finally:
        os.close(source_fd)


def _exchange_root(run_root: Path) -> Path:
    exchange = run_root / "exchange"
    if exchange.is_symlink():
        raise BlackboardError("artifact exchange root is a symlink")
    store = exchange / "store"
    inbox = exchange / "inbox"
    for path in (exchange, store, inbox):
        if path.is_symlink():
            raise BlackboardError("artifact exchange contains a symlink")
        path.mkdir(parents=True, mode=0o755, exist_ok=True)
        path.chmod(0o755)
    return exchange


def _publish_artifact(
    run_root: Path,
    *,
    lane_id: str,
    relative: str,
    expected_hash: str,
    expected_size: int,
) -> str:
    source_root = run_root / "workers" / lane_id / "artifacts"
    exchange = _exchange_root(run_root)
    filename = Path(relative).name
    shared_relative = Path(expected_hash) / filename
    destination_dir = exchange / "store" / expected_hash
    destination = destination_dir / filename
    if destination_dir.is_symlink() or destination.is_symlink():
        raise BlackboardError("artifact exchange destination is unsafe")
    destination_dir.mkdir(mode=0o755, exist_ok=True)
    destination_dir.chmod(0o755)
    if not destination.exists():
        temporary = destination.with_name(f".{filename}.{os.getpid()}.tmp")
        source_fd = _open_artifact_fd(source_root, Path(relative))
        destination_fd: int | None = None
        try:
            before = os.fstat(source_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
                raise BlackboardError("artifact changed before immutable snapshot")
            destination_fd = os.open(
                temporary,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                0o444,
            )
            digest = hashlib.sha256()
            copied = 0
            while chunk := os.read(source_fd, 1024 * 1024):
                copied += len(chunk)
                if copied > MAX_SHARED_ARTIFACT_BYTES:
                    raise BlackboardError("artifact exceeded the verified exchange limit while copying")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_fd, view)
                    if written <= 0:
                        raise BlackboardError("artifact snapshot write made no progress")
                    view = view[written:]
            os.fsync(destination_fd)
            after = os.fstat(source_fd)
            if (
                copied != expected_size
                or digest.hexdigest() != expected_hash
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
            ):
                raise BlackboardError("artifact changed while creating immutable snapshot")
            os.close(destination_fd)
            destination_fd = None
            os.replace(temporary, destination)
            destination.chmod(0o444)
        finally:
            os.close(source_fd)
            if destination_fd is not None:
                os.close(destination_fd)
            if temporary.exists():
                temporary.unlink()
    elif _hash_file(destination) != expected_hash or destination.stat().st_size != expected_size:
        raise BlackboardError("content-addressed artifact exchange collision")
    return shared_relative.as_posix()


def _expose_snapshot(run_root: Path, shared_relative: str) -> None:
    exchange = _exchange_root(run_root)
    for inbox in sorted((exchange / "inbox").iterdir()):
        if inbox.is_dir() and not inbox.is_symlink():
            _link_snapshot(exchange, inbox, shared_relative)


def _link_snapshot(exchange: Path, inbox: Path, shared_relative: str) -> None:
    relative = Path(shared_relative)
    if (
        relative.is_absolute()
        or len(relative.parts) != 2
        or not re.fullmatch(r"[0-9a-f]{64}", relative.parts[0])
        or relative.parts[1] in {"", ".", ".."}
    ):
        raise BlackboardError("shared artifact path is invalid")
    source = exchange / "store" / relative
    destination = inbox / relative
    if source.is_symlink() or not source.is_file():
        raise BlackboardError("shared artifact snapshot is missing or unsafe")
    if destination.is_symlink():
        raise BlackboardError("artifact inbox destination is a symlink")
    destination.parent.mkdir(mode=0o755, exist_ok=True)
    destination.parent.chmod(0o755)
    if not destination.exists():
        os.link(source, destination, follow_symlinks=False)
    elif os.stat(source, follow_symlinks=False).st_ino != os.stat(
        destination, follow_symlinks=False
    ).st_ino:
        raise BlackboardError("artifact inbox path collision")


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _open_artifact_fd(root: Path, relative: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    directory_flags = flags | getattr(os, "O_DIRECTORY", 0)
    try:
        directory_fd = os.open(root, directory_flags)
    except OSError as exc:
        raise BlackboardError("lane artifact root cannot be opened safely") from exc
    try:
        for part in relative.parts[:-1]:
            try:
                child_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            except OSError as exc:
                raise BlackboardError("artifact path cannot be traversed safely") from exc
            os.close(directory_fd)
            directory_fd = child_fd
        try:
            return os.open(relative.parts[-1], flags, dir_fd=directory_fd)
        except OSError as exc:
            raise BlackboardError("artifact cannot be opened safely") from exc
    finally:
        os.close(directory_fd)


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
        "output_hash", "artifact_path", "artifact_hash", "artifact_size",
        "shared_artifact_path", "target_identity", "timestamp",
    )}


def _now() -> str:
    return datetime.now(UTC).isoformat()
