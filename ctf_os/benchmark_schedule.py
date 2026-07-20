"""Deterministic matched A/B/C/D benchmark schedule and serial block guard."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path
import random
from typing import Any

from .attempts import benchmark_attempt_id, canonical_json
from .workspace import append_jsonl_fsync, read_jsonl_strict, state_lock, utc_now


SCHEDULE_SCHEMA_VERSION = 1
ARMS = ("A", "B", "C", "D")
MODES = {"A": "plain-sol", "B": "sol-only", "C": "fixed-race", "D": "adaptive-race"}


class BenchmarkScheduleError(ValueError):
    pass


def generate_schedule(
    challenges: Sequence[Mapping[str, Any]], *,
    randomization_seed: str | int,
    repetitions: int = 3,
) -> dict[str, Any]:
    if repetitions != 3:
        raise BenchmarkScheduleError("the preregistered minimum benchmark requires exactly 3 repetitions")
    if not challenges:
        raise BenchmarkScheduleError("benchmark schedule requires challenge snapshots")
    entries: list[dict[str, Any]] = []
    for challenge in sorted(challenges, key=lambda row: str(row.get("challenge_instance_id"))):
        _validate_challenge(challenge)
        instance = str(challenge["challenge_instance_id"])
        for repetition in range(1, repetitions + 1):
            matched_seed = hashlib.sha256(canonical_json({
                "randomization_seed": str(randomization_seed),
                "challenge_instance_id": instance, "repetition": repetition,
            })).hexdigest()
            block_id = "block-" + hashlib.sha256(canonical_json({
                "challenge_instance_id": instance, "repetition": repetition,
                "matched_seed": matched_seed,
            })).hexdigest()[:32]
            order = list(ARMS)
            random.Random(int(matched_seed[:16], 16)).shuffle(order)
            matched = {
                key: challenge.get(key)
                for key in (
                    "challenge_snapshot_digest", "target_snapshot_digest", "transformation_seed",
                    "random_seed_family", "network_profile", "model_policy", "host_envelope", "stratum",
                )
            }
            for position, arm in enumerate(order, 1):
                attempt_id = benchmark_attempt_id(block_id, arm, repetition, randomization_seed)
                random_seed = hashlib.sha256(canonical_json({
                    "family": challenge["random_seed_family"], "matched_seed": matched_seed,
                })).hexdigest()
                entries.append({
                    "schema_version": SCHEDULE_SCHEMA_VERSION,
                    "schedule_entry_id": f"{block_id}-{arm}",
                    "matched_block_id": block_id, "challenge_instance_id": instance,
                    "attempt_id": attempt_id, "arm": arm, "mode": MODES[arm],
                    "repetition": repetition, "arm_order": position,
                    "matched_seed": matched_seed, "random_seed": random_seed,
                    **matched,
                })
    payload = {
        "schema_version": SCHEDULE_SCHEMA_VERSION,
        "randomization_seed": str(randomization_seed),
        "challenge_count": len(challenges), "arm_count": 4,
        "repetitions": repetitions, "entry_count": len(entries), "entries": entries,
    }
    payload["schedule_digest"] = hashlib.sha256(canonical_json(payload)).hexdigest()
    validate_schedule(payload)
    return payload


def validate_schedule(schedule: Mapping[str, Any]) -> None:
    entries = schedule.get("entries")
    if schedule.get("schema_version") != SCHEDULE_SCHEMA_VERSION or not isinstance(entries, list):
        raise BenchmarkScheduleError("benchmark schedule schema is invalid")
    unsigned = {key: value for key, value in schedule.items() if key != "schedule_digest"}
    expected_digest = hashlib.sha256(canonical_json(unsigned)).hexdigest()
    if schedule.get("schedule_digest") != expected_digest:
        raise BenchmarkScheduleError("benchmark schedule digest is invalid")
    seed = str(schedule.get("randomization_seed") or "")
    if not seed:
        raise BenchmarkScheduleError("benchmark schedule randomization seed is missing")
    blocks: dict[str, list[Mapping[str, Any]]] = {}
    attempt_ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise BenchmarkScheduleError("schedule entries must be objects")
        required = {
            "schedule_entry_id", "matched_block_id", "challenge_instance_id", "attempt_id",
            "arm", "mode", "repetition", "matched_seed", "challenge_snapshot_digest",
            "target_snapshot_digest", "transformation_seed", "random_seed_family",
            "network_profile", "model_policy", "host_envelope", "stratum",
        }
        if required.difference(entry):
            raise BenchmarkScheduleError("schedule entry is missing matched identity")
        if entry["arm"] not in ARMS or entry["mode"] != MODES[entry["arm"]]:
            raise BenchmarkScheduleError("schedule entry arm/mode is invalid")
        expected_matched_seed = hashlib.sha256(canonical_json({
            "randomization_seed": seed,
            "challenge_instance_id": entry["challenge_instance_id"],
            "repetition": entry["repetition"],
        })).hexdigest()
        if entry["matched_seed"] != expected_matched_seed:
            raise BenchmarkScheduleError("schedule entry matched seed is not reproducible")
        expected_block = "block-" + hashlib.sha256(canonical_json({
            "challenge_instance_id": entry["challenge_instance_id"],
            "repetition": entry["repetition"], "matched_seed": expected_matched_seed,
        })).hexdigest()[:32]
        if entry["matched_block_id"] != expected_block:
            raise BenchmarkScheduleError("schedule matched block identity is not reproducible")
        if entry["schedule_entry_id"] != f"{expected_block}-{entry['arm']}":
            raise BenchmarkScheduleError("schedule entry identity is not reproducible")
        if entry["attempt_id"] != benchmark_attempt_id(
            expected_block, str(entry["arm"]), int(entry["repetition"]), seed,
        ):
            raise BenchmarkScheduleError("schedule attempt identity is not reproducible")
        expected_random = hashlib.sha256(canonical_json({
            "family": entry["random_seed_family"], "matched_seed": expected_matched_seed,
        })).hexdigest()
        if entry.get("random_seed") != expected_random:
            raise BenchmarkScheduleError("schedule run seed is not reproducible")
        if entry["attempt_id"] in attempt_ids:
            raise BenchmarkScheduleError("duplicate benchmark attempt_id")
        attempt_ids.add(str(entry["attempt_id"]))
        blocks.setdefault(str(entry["matched_block_id"]), []).append(entry)
    matched_fields = (
        "challenge_instance_id", "repetition", "matched_seed", "challenge_snapshot_digest",
        "target_snapshot_digest", "transformation_seed", "random_seed_family", "random_seed",
        "network_profile", "model_policy", "host_envelope", "stratum",
    )
    for block_id, rows in blocks.items():
        if {row["arm"] for row in rows} != set(ARMS) or len(rows) != 4:
            raise BenchmarkScheduleError(f"matched block {block_id} must contain exactly A/B/C/D")
        for field in matched_fields:
            if len({json.dumps(row.get(field), sort_keys=True) for row in rows}) != 1:
                raise BenchmarkScheduleError(f"matched block {block_id} differs on {field}")
        order = list(ARMS)
        random.Random(int(str(rows[0]["matched_seed"])[:16], 16)).shuffle(order)
        observed_order = [
            row["arm"] for row in sorted(rows, key=lambda row: int(row.get("arm_order") or 0))
        ]
        if observed_order != order or {row.get("arm_order") for row in rows} != {1, 2, 3, 4}:
            raise BenchmarkScheduleError("schedule arm order is not reproducible")
    if schedule.get("entry_count") != len(entries):
        raise BenchmarkScheduleError("schedule entry count is inconsistent")
    if schedule.get("arm_count") != 4 or schedule.get("repetitions") != 3:
        raise BenchmarkScheduleError("schedule treatment dimensions are inconsistent")
    if schedule.get("challenge_count") * 12 != len(entries):
        raise BenchmarkScheduleError("schedule challenge count is inconsistent")


def begin_schedule_entry(
    schedule: Mapping[str, Any], entry_id: str, execution_ledger: Path,
) -> dict[str, Any]:
    validate_schedule(schedule)
    entry = next((row for row in schedule["entries"] if row["schedule_entry_id"] == entry_id), None)
    if entry is None:
        raise BenchmarkScheduleError("unknown schedule entry")
    with state_lock(execution_ledger.parent):
        rows = read_jsonl_strict(execution_ledger, "benchmark execution ledger")
        active = [row for row in rows if row.get("event") == "STARTED" and not any(
            later.get("event") in {"FINISHED", "START_FAILED"}
            and later.get("schedule_entry_id") == row.get("schedule_entry_id")
            for later in rows
        )]
        if any(row.get("matched_block_id") == entry["matched_block_id"] for row in active):
            raise BenchmarkScheduleError("cross-arm simultaneous execution in one matched block is forbidden")
        record = {
            "schema_version": 1, "event": "STARTED", "schedule_entry_id": entry_id,
            "matched_block_id": entry["matched_block_id"], "arm": entry["arm"],
            "attempt_id": entry["attempt_id"], "created_at": utc_now(),
        }
        append_jsonl_fsync(execution_ledger, record, label="benchmark execution ledger")
    return record


def finish_schedule_entry(
    schedule: Mapping[str, Any], entry_id: str, execution_ledger: Path,
    *, completion_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Close one serial schedule entry after exact-run completion validation."""

    validate_schedule(schedule)
    entry = next((row for row in schedule["entries"] if row["schedule_entry_id"] == entry_id), None)
    if entry is None:
        raise BenchmarkScheduleError("unknown schedule entry")
    with state_lock(execution_ledger.parent):
        rows = read_jsonl_strict(execution_ledger, "benchmark execution ledger")
        starts = [row for row in rows if row.get("event") == "STARTED" and row.get("schedule_entry_id") == entry_id]
        finishes = [row for row in rows if row.get("event") == "FINISHED" and row.get("schedule_entry_id") == entry_id]
        if len(starts) != 1 or finishes:
            raise BenchmarkScheduleError("schedule entry is not in exactly one open STARTED state")
        if completion_receipt.get("run_id") in {None, ""} or completion_receipt.get("valid") is not True:
            raise BenchmarkScheduleError("schedule completion requires a validated exact-run receipt")
        record = {
            "schema_version": 1, "event": "FINISHED", "schedule_entry_id": entry_id,
            "matched_block_id": entry["matched_block_id"], "arm": entry["arm"],
            "attempt_id": entry["attempt_id"], "run_id": completion_receipt["run_id"],
            "completion_receipt_digest": hashlib.sha256(canonical_json(completion_receipt)).hexdigest(),
            "created_at": utc_now(),
        }
        append_jsonl_fsync(execution_ledger, record, label="benchmark execution ledger")
    return record


def fail_schedule_entry(
    schedule: Mapping[str, Any], entry_id: str, execution_ledger: Path,
    *, reason: str,
) -> dict[str, Any]:
    """Close a reserved schedule slot without pretending that a run completed."""

    validate_schedule(schedule)
    entry = next((row for row in schedule["entries"] if row["schedule_entry_id"] == entry_id), None)
    if entry is None or not reason.strip():
        raise BenchmarkScheduleError("failed schedule entry requires known identity and reason")
    with state_lock(execution_ledger.parent):
        rows = read_jsonl_strict(execution_ledger, "benchmark execution ledger")
        open_start = any(
            row.get("event") == "STARTED" and row.get("schedule_entry_id") == entry_id
            for row in rows
        ) and not any(
            row.get("event") in {"FINISHED", "START_FAILED"} and row.get("schedule_entry_id") == entry_id
            for row in rows
        )
        if not open_start:
            raise BenchmarkScheduleError("schedule entry has no open STARTED receipt")
        record = {
            "schema_version": 1, "event": "START_FAILED", "schedule_entry_id": entry_id,
            "matched_block_id": entry["matched_block_id"], "arm": entry["arm"],
            "attempt_id": entry["attempt_id"],
            "reason_digest": hashlib.sha256(reason.strip().encode("utf-8")).hexdigest(),
            "created_at": utc_now(),
        }
        append_jsonl_fsync(execution_ledger, record, label="benchmark execution ledger")
    return record


def solver_context_entry(entry: Mapping[str, Any]) -> dict[str, Any]:
    """Hide held-out provenance while retaining the exact snapshot binding."""

    context = {
        "arm": entry["arm"], "mode": entry["mode"],
        "attempt_id": entry["attempt_id"],
        "challenge_snapshot_digest": entry["challenge_snapshot_digest"],
    }
    if entry.get("stratum") != "PRIVATE_HELDOUT":
        context["challenge_instance_id"] = entry["challenge_instance_id"]
        context["stratum"] = entry["stratum"]
    return context


def _validate_challenge(challenge: Mapping[str, Any]) -> None:
    required = {
        "challenge_instance_id", "challenge_snapshot_digest", "target_snapshot_digest",
        "transformation_seed", "random_seed_family", "network_profile", "model_policy",
        "host_envelope", "stratum",
    }
    if required.difference(challenge):
        raise BenchmarkScheduleError("challenge schedule material is incomplete")
    if challenge.get("stratum") not in {
        "PUBLIC_KNOWN", "TRANSFORMED_FAMILY", "PRIVATE_HELDOUT", "LIVE_CONTEST",
    }:
        raise BenchmarkScheduleError("challenge stratum is invalid")
