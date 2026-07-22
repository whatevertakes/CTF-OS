"""Streaming first-candidate detection and atomic winner selection."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping

from .blackboard import BlackboardError, append_verified_event
from .race import load_race, record_winner


class FlagError(ValueError):
    pass


_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,48}\{[^{}\r\n]{1,512}\}")
_PLACEHOLDERS = re.compile(
    r"(?i)(?:example|sample|placeholder|dummy|fake|test|redacted|your[_ -]?flag|flag[_ -]?here)"
)


class StreamingDetector:
    def __init__(self, pattern: str | None) -> None:
        if not pattern or len(pattern) > 2048:
            raise FlagError("a bounded challenge flag pattern is required")
        try:
            self.pattern = re.compile(pattern)
        except re.error as exc:
            raise FlagError(f"challenge flag pattern is invalid: {exc}") from exc
        self.buffer = ""
        self.seen: set[str] = set()

    def feed(self, chunk: str) -> str | None:
        self.buffer = (self.buffer + chunk)[-8192:]
        candidates = [match.group(0) for match in _TOKEN.finditer(self.buffer)]
        # Non-braced organizer formats remain supported without allowing an
        # unbounded regex search over command output.
        candidates.extend(token for token in re.split(r"[\s'\"`,;]+", self.buffer) if 1 <= len(token) <= 1024)
        for candidate in candidates:
            if candidate in self.seen:
                continue
            self.seen.add(candidate)
            if valid_candidate(candidate, self.pattern):
                return candidate
        return None


def valid_candidate(candidate: str, pattern: re.Pattern[str] | str | None) -> bool:
    if not candidate or len(candidate) > 1024 or _PLACEHOLDERS.search(candidate):
        return False
    compiled = re.compile(pattern) if isinstance(pattern, str) else pattern
    return bool(compiled and compiled.fullmatch(candidate))


def record_candidate(
    run_root: Path,
    *,
    lane_id: str,
    attack_family: str,
    candidate: str,
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    race = load_race(run_root)
    lane = next(
        (row for row in race.get("lanes", []) if row.get("lane_id") == lane_id),
        None,
    )
    if not isinstance(lane, Mapping) or lane.get("attack_family") != attack_family:
        raise FlagError("candidate attack_family does not match its exact lane")
    if not valid_candidate(candidate, str(race.get("flag_pattern") or "")):
        raise FlagError("candidate does not match the challenge flag pattern or is a placeholder")
    if candidate not in str(receipt.get("observed_output", "")):
        raise FlagError("candidate is not present in actual observed target output")
    if receipt.get("run_id") != race["run_id"] or receipt.get("lane_id") != lane_id:
        raise FlagError("candidate receipt does not belong to this exact run/lane")
    target = str(receipt.get("target_identity", ""))
    allowed = {f"challenge:{race['challenge']['id']}"}
    allowed.update(str(row["declared"]) for row in race.get("declared_targets", []))
    allowed.update(str(value) for value in race.get("service_endpoints", []))
    if target not in allowed:
        raise FlagError("candidate was not observed from the challenge or a declared target")
    if receipt.get("target_observed") is not True:
        raise FlagError("candidate has no actual challenge/declared-target observation receipt")
    receipt_id = str(receipt.get("receipt_id", ""))
    durable = run_root / "workers" / lane_id / "logs" / f"{receipt_id}.json"
    if durable.is_symlink() or not durable.is_file():
        raise FlagError("candidate has no durable command/session receipt")
    try:
        durable_receipt = json.loads(durable.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FlagError("candidate durable receipt is unreadable") from exc
    if not isinstance(durable_receipt, dict):
        raise FlagError("candidate durable receipt is invalid")
    for field in (
        "receipt_id", "run_id", "lane_id", "argv", "exit_code", "observed_output",
        "output_hash", "target_identity", "target_observed", "finished_at",
    ):
        if durable_receipt.get(field) != receipt.get(field):
            raise FlagError(f"candidate receipt does not match durable execution: {field}")
    if candidate not in str(durable_receipt.get("observed_output", "")):
        raise FlagError("candidate is absent from durable observed output")
    result = record_winner(
        run_root,
        lane_id=lane_id,
        candidate=candidate,
        receipt_id=receipt_id,
        target_identity=target,
        timestamp=str(receipt.get("finished_at")),
    )
    if result["first"]:
        try:
            event = append_verified_event(
                run_root,
                event_type="FLAG_CANDIDATE",
                lane_id=lane_id,
                attack_family=attack_family,
                receipt=receipt,
            )
        except BlackboardError as exc:
            # The actual execution and atomic winner are authoritative; a log
            # failure may be reported but never delays or invalidates the flag.
            result["blackboard_warning"] = str(exc)
        else:
            result["event"] = event
    result["display"] = candidate
    result["manual_submission_required"] = True
    return result
