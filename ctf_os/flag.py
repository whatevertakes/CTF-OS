"""Streaming first-candidate detection and atomic winner selection."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import regex as safe_regex

from .blackboard import (
    BlackboardError,
    append_verified_event,
    human_relay_blocks_promotion,
)
from .contest import ContestError, compile_flag_pattern
from .race import load_race, record_winner
from .sandbox.session import MAX_FLAG_TAIL


class FlagError(ValueError):
    pass


_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,48}\{[^{}\r\n]{1,512}\}")
_PLACEHOLDERS = re.compile(
    r"(?i)(?:"
    r"(?:example|sample|placeholder|dummy|fake|test|redacted)(?:[_ -]?flag)?"
    r"|your[_ -]?flag"
    r"|flag[_ -]?here"
    r")\Z"
)


class StreamingDetector:
    def __init__(self, pattern: str | None) -> None:
        try:
            self.pattern = compile_flag_pattern(pattern)
        except ContestError as exc:
            raise FlagError(str(exc)) from exc
        self.buffer = ""
        self.seen: set[str] = set()

    def feed(self, chunk: str) -> str | None:
        self.buffer = (self.buffer + chunk)[-8192:]
        candidates = [
            (match.start(), match.group(0)) for match in _TOKEN.finditer(self.buffer)
        ]
        # Preserve chronological order while supporting non-braced organizer
        # formats without applying an organizer regex to the whole output.
        candidates.extend(
            (match.start(), match.group(0))
            for match in re.finditer(r"[^\s'\"`,;]{1,1024}", self.buffer)
        )
        for _offset, candidate in sorted(candidates, key=lambda row: row[0]):
            if candidate in self.seen:
                continue
            self.seen.add(candidate)
            if valid_candidate(candidate, self.pattern):
                return candidate
        return None


def valid_candidate(candidate: str, pattern: Any | str | None) -> bool:
    if (
        not candidate
        or not pattern
        or len(candidate) > 1024
        or _is_placeholder(candidate)
    ):
        return False
    try:
        compiled = safe_regex.compile(pattern) if isinstance(pattern, str) else pattern
        return bool(
            compiled
            and compiled.fullmatch(candidate, timeout=0.02, concurrent=True)
        )
    except (safe_regex.error, TimeoutError):
        return False


def _is_placeholder(candidate: str) -> bool:
    start = candidate.find("{")
    if start >= 0 and candidate.endswith("}"):
        value = candidate[start + 1:-1]
    else:
        value = candidate
    return _PLACEHOLDERS.fullmatch(value.strip()) is not None


def _verify_boundary_tail(
    run_root: Path, lane_id: str, run_id: str, boundary: Mapping[str, Any]
) -> str:
    """Return the durable prior-read tail, proven to be a suffix of a real receipt.

    The tail is never trusted from the caller: it must exactly match the end of a
    durable prior session-read receipt for this run/lane, so a forged tail cannot
    manufacture a flag that never actually appeared in session output.
    """

    prior_id = str(boundary.get("receipt_id") or "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", prior_id):
        raise FlagError("boundary candidate has no valid prior receipt id")
    claimed_tail = str(boundary.get("tail") or "")
    if not claimed_tail or len(claimed_tail) > MAX_FLAG_TAIL:
        raise FlagError("boundary candidate tail is empty or oversized")
    durable = run_root / "workers" / lane_id / "logs" / f"{prior_id}.json"
    if durable.is_symlink() or not durable.is_file():
        raise FlagError("boundary candidate has no durable prior receipt")
    try:
        prior = json.loads(durable.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FlagError("boundary prior receipt is unreadable") from exc
    if not isinstance(prior, dict):
        raise FlagError("boundary prior receipt is invalid")
    if prior.get("run_id") != run_id or prior.get("lane_id") != lane_id:
        raise FlagError("boundary prior receipt does not belong to this exact run/lane")
    prior_output = str(prior.get("observed_output", ""))
    if not prior_output.endswith(claimed_tail):
        raise FlagError("boundary tail is not a genuine suffix of durable prior output")
    return claimed_tail


def record_candidate(
    run_root: Path,
    *,
    lane_id: str,
    attack_family: str,
    candidate: str,
    receipt: Mapping[str, Any],
    boundary: Mapping[str, Any] | None = None,
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
    current_output = str(receipt.get("observed_output", ""))
    # The verified evidence window is the current read plus, for a boundary
    # candidate, the durable tail of the previous read.
    prior_tail = ""
    if boundary is not None:
        prior_tail = _verify_boundary_tail(run_root, lane_id, str(race["run_id"]), boundary)
    evidence = prior_tail + current_output
    if candidate not in evidence:
        raise FlagError("candidate is not present in actual observed target output")
    if boundary is not None and (candidate in current_output or candidate in prior_tail):
        raise FlagError("boundary candidate must span two reads, not sit within one")
    if receipt.get("run_id") != race["run_id"] or receipt.get("lane_id") != lane_id:
        raise FlagError("candidate receipt does not belong to this exact run/lane")
    target = str(receipt.get("target_identity", ""))
    allowed = {f"challenge:{race['challenge']['id']}"}
    allowed.update(str(row["declared"]) for row in race.get("declared_targets", []))
    allowed.update(str(value) for value in race.get("service_endpoints", []))
    if target not in allowed:
        raise FlagError("candidate was not observed from the challenge or a declared target")
    if human_relay_blocks_promotion(race):
        raise FlagError(
            "human-relay participant output cannot become an automatic winner"
        )
    if receipt.get("target_observed") is not True:
        raise FlagError("candidate has no actual challenge/declared-target observation receipt")
    receipt_id = str(receipt.get("receipt_id", ""))
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", receipt_id):
        raise FlagError("candidate receipt id is invalid")
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
    # prior_tail was already verified to be a genuine suffix of the durable prior
    # receipt, so the durable evidence window is that tail plus this durable read.
    if candidate not in (prior_tail + str(durable_receipt.get("observed_output", ""))):
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
