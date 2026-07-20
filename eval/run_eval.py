#!/usr/bin/env python3
"""Matched A/B/C/D benchmark evaluator; never launches a model or a run."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime
import json
import math
from pathlib import Path
import random
import statistics
import sys
from typing import Any, Iterable, Mapping, Sequence


ARMS = ("A", "B", "C", "D")
STRATA = ("PUBLIC_KNOWN", "TRANSFORMED_FAMILY", "PRIVATE_HELDOUT", "LIVE_CONTEST")
REQUIRED = {
    "schema_version", "arm", "mode", "challenge_instance_id", "attempt_id", "run_id",
    "matched_block_id", "matched_seed", "repetition", "stratum", "lock_digest",
    "schedule_digest", "configuration_digest", "transformation_seed", "outcome", "timestamps",
    "timestamp_missing_reasons", "target_health_intervals", "resource_consumption",
    "runtime", "source_environment", "artifact_provenance",
    "active_run_pointer_used", "lock_signature_valid",
}
REQUIRED_SOURCE_FIELDS = {
    "git_commit", "dirty_diff_digest", "challenge_snapshot_digest",
    "target_image_digest", "tool_image_digest", "cli_build_hash", "host", "docker",
    "network_profile", "time_limit_seconds", "maximum_model_concurrency", "random_seed",
}
REQUIRED_TIMESTAMPS = {
    "attempt_started_at", "first_meaningful_observation_at", "first_viable_hypothesis_at",
    "first_decisive_experiment_at", "first_primitive_confirmed_at", "first_working_poc_at",
    "first_remote_attempt_at", "first_flag_candidate_at", "first_oracle_accepted_flag_at",
    "attempt_finished_at", "submission_result_at",
}
DETERMINISTIC_RESOURCE_FIELDS = {
    "cpu_seconds", "ram_gib_seconds", "ram_peak_bytes", "network_rx_bytes",
    "network_tx_bytes", "container_lifetime_seconds", "child_session_count",
    "maximum_active_width",
}
REQUIRED_RESOURCE_FIELDS = DETERMINISTIC_RESOURCE_FIELDS | {
    "model_queue_seconds", "model_session_minutes",
}
REQUIRED_OUTCOME_FIELDS = {
    "oracle_result", "solved", "censored", "censor_time_seconds",
    "environment_failure", "invalidation_reason", "cleanup_success", "terminal_correctness",
}
LEGACY_REQUIRED = {
    "fixture", "mode", "solved", "verified_flag", "elapsed_seconds",
    "child_agents", "cleanup_success",
}
DEFAULT_CENSOR_SECONDS = 2700.0
DEFAULT_BOOTSTRAP_SEED = 20260720
DEFAULT_BOOTSTRAP_ITERATIONS = 10_000


class EvaluationError(ValueError):
    pass


def load_receipts(paths: list[Path]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path in paths:
        values = json.loads(path.read_text(encoding="utf-8"))
        batch = values if isinstance(values, list) else [values]
        for value in batch:
            if not isinstance(value, dict):
                raise EvaluationError(f"{path}: receipt must be an object")
            rows.append(value)
    return rows


def summarize(
    receipts: list[dict[str, object]], *,
    bootstrap_seed: int = DEFAULT_BOOTSTRAP_SEED,
    bootstrap_iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS,
) -> dict[str, object]:
    """Compatibility entrypoint: legacy pairs remain explicitly non-authoritative."""

    if receipts and all(LEGACY_REQUIRED.issubset(row) and "arm" not in row for row in receipts):
        return _legacy_summary(receipts)
    return evaluate_benchmark(
        receipts, bootstrap_seed=bootstrap_seed,
        bootstrap_iterations=bootstrap_iterations,
    )


def evaluate_benchmark(
    manifests: Sequence[Mapping[str, Any]], *,
    bootstrap_seed: int = DEFAULT_BOOTSTRAP_SEED,
    bootstrap_iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS,
) -> dict[str, Any]:
    if bootstrap_iterations < 100:
        raise EvaluationError("cluster bootstrap requires at least 100 iterations")
    validation = validate_inputs(manifests)
    valid_rows = validation["valid_rows"]
    valid_blocks = set(validation["valid_matched_blocks"])
    analyzed = [row for row in valid_rows if row["matched_block_id"] in valid_blocks]
    missingness = _missingness(manifests)
    outcomes = {
        stratum: {arm: _arm_summary([
            row for row in analyzed if row["stratum"] == stratum and row["arm"] == arm
        ]) for arm in ARMS}
        for stratum in STRATA
    }
    comparisons: dict[str, Any] = {}
    pairs = [("A", arm) for arm in ("B", "C", "D")] + [
        ("B", "C"), ("B", "D"), ("C", "D"),
    ]
    for base, treatment in pairs:
        key = f"{treatment}_vs_{base}"
        comparisons[key] = {
            stratum: _paired_comparison(
                [row for row in analyzed if row["stratum"] == stratum],
                base=base, treatment=treatment,
                bootstrap_seed=bootstrap_seed,
                bootstrap_iterations=bootstrap_iterations,
            )
            for stratum in ("PUBLIC_KNOWN", "TRANSFORMED_FAMILY", "PRIVATE_HELDOUT")
        }
        comparisons[key]["decision"] = _decision(
            comparisons[key]["PRIVATE_HELDOUT"],
            validation=validation, base=base, treatment=treatment,
        )
        comparisons[key]["decision_stratum"] = "PRIVATE_HELDOUT"
    primary = {key: value for key, value in comparisons.items() if key in {"B_vs_A", "C_vs_A", "D_vs_A"}}
    decisions = [value["decision"] for value in primary.values()]
    final = (
        "REGRESSION_INDICATED" if "REGRESSION_INDICATED" in decisions else
        "PROVEN_IMPROVEMENT" if "PROVEN_IMPROVEMENT" in decisions else
        "SUGGESTIVE_ONLY" if "SUGGESTIVE_ONLY" in decisions else
        "INCONCLUSIVE"
    )
    failures = _failure_summary(analyzed)
    result = {
        "schema_version": 2,
        "authoritative_evaluator": "MATCHED_ABCD_V1",
        "data_validation_report": {
            key: value for key, value in validation.items() if key != "valid_rows"
        },
        "valid_matched_blocks": validation["valid_matched_blocks"],
        "invalid_matched_blocks": validation["invalid_matched_blocks"],
        "exclusion_invalidation_reasons": validation["reason_counts"],
        "missingness_table": missingness,
        "arm_stratum_outcomes": outcomes,
        "paired_comparisons": comparisons,
        "tail_latency": {
            stratum: {
                arm: {
                    "p90_resolved_latency_seconds": outcomes[stratum][arm]["p90_resolved_latency_seconds"],
                    "maximum_resolved_latency_seconds": outcomes[stratum][arm]["maximum_resolved_latency_seconds"],
                }
                for arm in ARMS
            }
            for stratum in STRATA
        },
        "resource_metrics": {
            stratum: {arm: outcomes[stratum][arm]["resource_consumption"] for arm in ARMS}
            for stratum in STRATA
        },
        "target_environment_failures": failures,
        "final_decision": final,
        "primary_conclusion_stratum": "PRIVATE_HELDOUT",
        "stratum_policy": {
            "PUBLIC_KNOWN": "DIAGNOSTIC_ONLY",
            "TRANSFORMED_FAMILY": "SECONDARY_GENERALIZATION_EVIDENCE",
            "PRIVATE_HELDOUT": "PRIMARY",
            "LIVE_CONTEST": "EXCLUDED_FROM_CONTROLLED_CONCLUSION",
        },
        "preregistered_criterion_evaluation": {
            key: value["PRIVATE_HELDOUT"].get("criterion_evaluation", {})
            for key, value in primary.items()
        },
        "bootstrap": {
            "unit": "challenge_instance_id",
            "preserves_repetitions": True,
            "seed": bootstrap_seed, "iterations": bootstrap_iterations,
            "confidence_level": 0.95,
        },
        "censor_time_seconds": DEFAULT_CENSOR_SECONDS,
    }
    return result


def validate_inputs(manifests: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    valid_rows: list[dict[str, Any]] = []
    row_errors: list[dict[str, Any]] = []
    blocks: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for index, raw in enumerate(manifests):
        row = dict(raw)
        reasons = _row_errors(row)
        block = str(row.get("matched_block_id") or f"MISSING_BLOCK_{index}")
        if reasons:
            row_errors.append({"index": index, "matched_block_id": block, "reasons": reasons})
        row["_validation_errors"] = reasons
        valid_rows.append(row)
        blocks[block].append(row)
    invalid: dict[str, list[str]] = defaultdict(list)
    for block_id, rows in blocks.items():
        for row in rows:
            invalid[block_id].extend(row["_validation_errors"])
        arms = [row.get("arm") for row in rows]
        if len(rows) != 4 or set(arms) != set(ARMS):
            invalid[block_id].append("INCOMPLETE_MATCHED_BLOCK")
        identities = (
            "challenge_instance_id", "matched_block_id", "repetition", "matched_seed",
            "stratum", "lock_digest", "schedule_digest", "configuration_digest", "transformation_seed",
        )
        for field in identities:
            values = {_canonical(row.get(field)) for row in rows}
            if len(values) > 1:
                invalid[block_id].append(f"UNMATCHED_{field.upper()}")
        for field in REQUIRED_SOURCE_FIELDS:
            values = {
                _canonical((row.get("source_environment") or {}).get(field))
                for row in rows
            }
            if len(values) > 1:
                invalid[block_id].append(f"UNMATCHED_SOURCE_{field.upper()}")
        for field in ("requested_model", "requested_reasoning", "runtime_observation_policy"):
            values = {_canonical((row.get("runtime") or {}).get(field)) for row in rows}
            if len(values) > 1:
                invalid[block_id].append(f"UNMATCHED_RUNTIME_{field.upper()}")
        attempts = [row.get("attempt_id") for row in rows]
        run_ids = [row.get("run_id") for row in rows]
        if len(set(attempts)) != len(attempts) or len(set(run_ids)) != len(run_ids):
            invalid[block_id].append("ATTEMPT_OR_RUN_ID_REUSED_ACROSS_ARMS")
        provenance: dict[str, str] = {}
        for row in rows:
            for artifact in row.get("artifact_provenance", []) or []:
                if not isinstance(artifact, Mapping):
                    invalid[block_id].append("MALFORMED_ARTIFACT_PROVENANCE")
                    continue
                source_attempt = artifact.get("source_attempt_id")
                if source_attempt not in {None, row.get("attempt_id")}:
                    invalid[block_id].append("CROSS_RUN_ARTIFACT_REUSE")
                artifact_id = str(artifact.get("artifact_id") or artifact.get("sha256") or "")
                if artifact_id and artifact_id in provenance and provenance[artifact_id] != row.get("attempt_id"):
                    invalid[block_id].append("CROSS_RUN_ARTIFACT_REUSE")
                elif artifact_id:
                    provenance[artifact_id] = str(row.get("attempt_id"))
        if any(not _healthy_target(row) for row in rows):
            invalid[block_id].append("TARGET_HEALTH_FAILURE")

    attempt_uses: dict[str, set[str]] = defaultdict(set)
    run_uses: dict[str, set[str]] = defaultdict(set)
    artifact_uses: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for block_id, rows in blocks.items():
        for row in rows:
            if row.get("attempt_id"):
                attempt_uses[str(row["attempt_id"])].add(block_id)
            if row.get("run_id"):
                run_uses[str(row["run_id"])].add(block_id)
            for artifact in row.get("artifact_provenance", []) or []:
                if isinstance(artifact, Mapping):
                    artifact_id = str(artifact.get("artifact_id") or artifact.get("sha256") or "")
                    if artifact_id:
                        artifact_uses[artifact_id].append((block_id, str(row.get("attempt_id"))))
    for uses in (attempt_uses, run_uses):
        for affected in uses.values():
            if len(affected) > 1:
                for block_id in affected:
                    invalid[block_id].append("ATTEMPT_OR_RUN_ID_REUSED_ACROSS_BLOCKS")
    for uses in artifact_uses.values():
        if len({attempt for _block, attempt in uses}) > 1:
            for block_id, _attempt in uses:
                invalid[block_id].append("CROSS_RUN_ARTIFACT_REUSE")
    invalid = {key: sorted(set(values)) for key, values in invalid.items() if values}
    valid_blocks = sorted(set(blocks) - set(invalid))
    controlled = [
        row for block_id in valid_blocks for row in blocks[block_id]
        if row.get("stratum") != "LIVE_CONTEST"
    ]
    repetition_sets: dict[str, set[int]] = defaultdict(set)
    for row in controlled:
        if isinstance(row.get("repetition"), int):
            repetition_sets[str(row.get("challenge_instance_id"))].add(int(row["repetition"]))
    completeness_reasons: list[str] = []
    if len(repetition_sets) != 12:
        completeness_reasons.append("EXPECTED_12_CHALLENGE_INSTANCES")
    if any(values != {1, 2, 3} for values in repetition_sets.values()):
        completeness_reasons.append("EXPECTED_THREE_REPETITIONS_PER_CHALLENGE")
    return {
        "input_run_count": len(manifests),
        "valid_run_count": sum(len(blocks[key]) for key in valid_blocks),
        "invalid_run_count": len(manifests) - sum(len(blocks[key]) for key in valid_blocks),
        "valid_matched_blocks": valid_blocks,
        "invalid_matched_blocks": [
            {"matched_block_id": key, "reasons": invalid[key]} for key in sorted(invalid)
        ],
        "row_errors": row_errors,
        "reason_counts": dict(sorted(Counter(reason for values in invalid.values() for reason in values).items())),
        "sample_complete": not invalid and bool(valid_blocks) and not completeness_reasons,
        "sample_completeness_reasons": completeness_reasons,
        "valid_rows": valid_rows,
    }


def _row_errors(row: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = REQUIRED.difference(row)
    if missing:
        errors.extend(f"MISSING_{field.upper()}" for field in sorted(missing))
        return errors
    if row.get("arm") not in ARMS:
        errors.append("INVALID_ARM")
    expected_mode = {"A": "plain-sol", "B": "sol-only", "C": "fixed-race", "D": "adaptive-race"}
    if row.get("arm") in expected_mode and row.get("mode") != expected_mode[row["arm"]]:
        errors.append("ARM_MODE_TREATMENT_MISMATCH")
    if row.get("stratum") not in STRATA:
        errors.append("INVALID_STRATUM")
    if not isinstance(row.get("repetition"), int) or int(row["repetition"]) < 1 or not row.get("matched_seed"):
        errors.append("MATCHED_SEED_REPETITION_IDENTITY_REQUIRED")
    if not all(_is_hex64(row.get(field)) for field in (
        "lock_digest", "schedule_digest", "configuration_digest", "matched_seed",
    )):
        errors.append("INVALID_DIGEST_IDENTITY")
    if row.get("active_run_pointer_used") is not False:
        errors.append("ACTIVE_RUN_POINTER_USED")
    if row.get("lock_signature_valid") is not True:
        errors.append("LOCK_SIGNATURE_NOT_VALIDATED")
    outcome = row.get("outcome")
    if not isinstance(outcome, Mapping) or REQUIRED_OUTCOME_FIELDS.difference(outcome):
        errors.append("INCOMPLETE_OUTCOME")
    if not isinstance(outcome, Mapping) or outcome.get("oracle_result") is None:
        errors.append("MISSING_ORACLE_RESULT")
    timestamps = row.get("timestamps")
    reasons = row.get("timestamp_missing_reasons")
    if (
        not isinstance(timestamps, Mapping) or REQUIRED_TIMESTAMPS.difference(timestamps)
        or not isinstance(reasons, Mapping) or REQUIRED_TIMESTAMPS.difference(reasons)
    ):
        errors.append("INCOMPLETE_TIMESTAMP_SCHEMA")
    elif any(
        (timestamps[field] is None and not reasons.get(field))
        or (timestamps[field] is not None and reasons.get(field) is not None)
        for field in REQUIRED_TIMESTAMPS
    ):
        errors.append("TIMESTAMP_MISSINGNESS_NOT_EXPLICIT")
    if not isinstance(timestamps, Mapping) or not timestamps.get("attempt_started_at") or not timestamps.get("attempt_finished_at"):
        errors.append("MISSING_WALL_CLOCK_START_END")
    if not isinstance(row.get("target_health_intervals"), list) or not row["target_health_intervals"]:
        errors.append("MISSING_TARGET_HEALTH")
    if not isinstance(outcome, Mapping) or outcome.get("terminal_correctness") is None:
        errors.append("MISSING_TERMINAL_CORRECTNESS")
    resources = row.get("resource_consumption")
    if (
        not isinstance(resources, Mapping)
        or REQUIRED_RESOURCE_FIELDS.difference(resources)
        or not ({"model_tokens", "subscription_units"} & set(resources))
    ):
        errors.append("MISSING_RESOURCE_TELEMETRY")
    elif any(
        not isinstance(value, Mapping)
        or "value" not in value or "observation_status" not in value
        or (value.get("value") is None and not value.get("reason"))
        for value in resources.values()
    ):
        errors.append("RESOURCE_MISSINGNESS_NOT_EXPLICIT")
    source = row.get("source_environment")
    if not isinstance(source, Mapping) or REQUIRED_SOURCE_FIELDS.difference(source):
        errors.append("INCOMPLETE_SOURCE_ENVIRONMENT")
    elif (
        not _is_hex40(source.get("git_commit"))
        or source.get("dirty_diff_digest") != "CLEAN"
        or source.get("time_limit_seconds") != 2700
        or source.get("maximum_model_concurrency") != 4
        or not _is_hex64(source.get("challenge_snapshot_digest"))
        or not _is_image_digest(source.get("target_image_digest"))
        or not _is_image_digest(source.get("tool_image_digest"))
        or not _is_hex64(source.get("cli_build_hash"))
    ):
        errors.append("INVALID_SOURCE_ENVIRONMENT_IDENTITY")
    runtime = row.get("runtime")
    if not isinstance(runtime, Mapping) or any(
        field not in runtime for field in (
            "requested_model", "observed_model", "requested_reasoning", "observed_reasoning",
            "runtime_observation_policy", "runtime_observation_evidence",
        )
    ):
        errors.append("INCOMPLETE_RUNTIME_IDENTITY")
    else:
        required_observation = str(runtime.get("runtime_observation_policy") or "").upper() in {"REQUIRED", "MUST_OBSERVE"}
        if required_observation and (
            runtime.get("observed_model") == "NOT_OBSERVABLE"
            or runtime.get("observed_reasoning") == "NOT_OBSERVABLE"
            or not runtime.get("runtime_observation_evidence")
        ):
            errors.append("REQUIRED_RUNTIME_IDENTITY_NOT_OBSERVABLE")
    return errors


def _healthy_target(row: Mapping[str, Any]) -> bool:
    intervals = row.get("target_health_intervals")
    if not isinstance(intervals, list) or not intervals:
        return False
    timestamps = row.get("timestamps")
    if not isinstance(timestamps, Mapping) or not timestamps.get("attempt_started_at") or not timestamps.get("attempt_finished_at"):
        return False
    try:
        attempt_start = _time(str(timestamps["attempt_started_at"]))
        attempt_end = _time(str(timestamps["attempt_finished_at"]))
    except (ValueError, TypeError):
        return False
    observed: list[tuple[datetime, datetime, str | None]] = []
    for interval in intervals:
        if not isinstance(interval, Mapping):
            return False
        if (
            interval.get("attempt_id") != row.get("attempt_id")
            or interval.get("run_id") != row.get("run_id")
            or interval.get("challenge_instance_id") != row.get("challenge_instance_id")
        ):
            return False
        if str(interval.get("status") or "").upper() not in {"HEALTHY", "OK"}:
            return False
        if str(interval.get("semantic_health_result") or "").upper() not in {"HEALTHY", "OK", "PASS"}:
            return False
        if not interval.get("probe_receipt_id") or interval.get("endpoint_revision") is None:
            return False
        try:
            started = _time(str(interval["started_at"])); ended = _time(str(interval["ended_at"]))
        except (KeyError, ValueError, TypeError):
            return False
        if ended < started:
            return False
        observed.append((started, ended, str(interval.get("phase")) if interval.get("phase") else None))
    observed.sort()
    if len(observed) < 2:
        return False
    if (observed[0][0] - attempt_start).total_seconds() > 60 or (attempt_end - observed[-1][1]).total_seconds() > 60:
        return False
    if observed[0][2] not in {None, "RUN_START"} or observed[-1][2] not in {None, "RUN_END"}:
        return False
    return all(
        (current[0] - previous[1]).total_seconds() <= 75
        for previous, current in zip(observed, observed[1:])
    )


def _arm_summary(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    solved = [row for row in rows if _solved(row)]
    flag_times = [value for row in rows if (value := _latency(row, "first_oracle_accepted_flag_at")) is not None]
    poc_times = [value for row in rows if (value := _latency(row, "first_working_poc_at")) is not None]
    rmst_values = [value for row in rows if (value := _censored_latency(row)) is not None]
    return {
        "runs": len(rows), "oracle_accepted_solved": len(solved),
        "solve_rate_at_2700": len(solved) / len(rows) if rows else None,
        "time_to_first_valid_flag": _distribution(flag_times),
        "time_to_first_executed_working_poc": _distribution(poc_times),
        "rmst_seconds": statistics.mean(rmst_values) if rmst_values else None,
        "solved_only_median_seconds": statistics.median(flag_times) if flag_times else None,
        "p90_resolved_latency_seconds": _percentile(flag_times, .90),
        "maximum_resolved_latency_seconds": max(flag_times) if flag_times else None,
        "false_candidate_count": sum(int(_outcome(row).get("false_candidate_count") or 0) for row in rows),
        "scope_violation_count": sum(int(_outcome(row).get("scope_violation_count") or 0) for row in rows),
        "denied_out_of_scope_action_count": sum(int(_outcome(row).get("denied_out_of_scope_action_count") or 0) for row in rows),
        "terminal_correctness_rate": (
            sum(_outcome(row).get("terminal_correctness") is True for row in rows) / len(rows)
            if rows else None
        ),
        "environment_failure_count": sum(_outcome(row).get("environment_failure") is True for row in rows),
        "censored_count": sum(not _solved(row) for row in rows),
        "missing_flag_latency_count": sum(_solved(row) and _latency(row, "first_oracle_accepted_flag_at") is None for row in rows),
        "resource_consumption": _resource_summary(rows),
    }


def _paired_comparison(
    rows: Sequence[Mapping[str, Any]], *, base: str, treatment: str,
    bootstrap_seed: int, bootstrap_iterations: int,
) -> dict[str, Any]:
    blocks: dict[str, dict[str, Mapping[str, Any]]] = defaultdict(dict)
    for row in rows:
        blocks[str(row["matched_block_id"])][str(row["arm"])] = row
    pairs = [values for values in blocks.values() if base in values and treatment in values]
    both_solved = base_only = treatment_only = neither = 0
    poc_differences: list[float] = []
    flag_differences: list[float] = []
    rmst_contributions: list[float] = []
    resource_differences: dict[str, list[float]] = defaultdict(list)
    per_block: list[dict[str, Any]] = []
    clusters: dict[str, list[dict[str, float]]] = defaultdict(list)
    for pair in pairs:
        left, right = pair[base], pair[treatment]
        left_solved, right_solved = _solved(left), _solved(right)
        if left_solved and right_solved: both_solved += 1
        elif left_solved: base_only += 1
        elif right_solved: treatment_only += 1
        else: neither += 1
        poc_left, poc_right = _latency(left, "first_working_poc_at"), _latency(right, "first_working_poc_at")
        flag_left, flag_right = _latency(left, "first_oracle_accepted_flag_at"), _latency(right, "first_oracle_accepted_flag_at")
        censor_left, censor_right = _censored_latency(left), _censored_latency(right)
        if poc_left is not None and poc_right is not None: poc_differences.append(poc_left - poc_right)
        if flag_left is not None and flag_right is not None: flag_differences.append(flag_left - flag_right)
        rmst = censor_left - censor_right if censor_left is not None and censor_right is not None else None
        if rmst is not None: rmst_contributions.append(rmst)
        for field in _resource_fields(left, right):
            lvalue, rvalue = _resource_value(left, field), _resource_value(right, field)
            if lvalue is not None and rvalue is not None:
                resource_differences[field].append(rvalue - lvalue)
        clusters[str(left["challenge_instance_id"])].append({
            "solve_difference": float(right_solved) - float(left_solved),
            "rmst_improvement": rmst if rmst is not None else math.nan,
            "median_improvement": (flag_left - flag_right) if flag_left is not None and flag_right is not None else math.nan,
        })
        per_block.append({
            "matched_block_id": left["matched_block_id"],
            "challenge_instance_id": left["challenge_instance_id"],
            "repetition": left["repetition"],
            "solve_discordance": int(right_solved) - int(left_solved),
            "poc_time_improvement_seconds": (
                poc_left - poc_right if poc_left is not None and poc_right is not None else None
            ),
            "flag_time_improvement_seconds": (
                flag_left - flag_right if flag_left is not None and flag_right is not None else None
            ),
            "rmst_contribution_seconds": rmst,
            "resource_difference": {
                field: (_resource_value(right, field) - _resource_value(left, field))
                for field in _resource_fields(left, right)
                if _resource_value(left, field) is not None and _resource_value(right, field) is not None
            },
        })
    solve_difference = (treatment_only - base_only) / len(pairs) if pairs else None
    solve_ci = _cluster_bootstrap(
        clusters, "solve_difference", seed=bootstrap_seed,
        iterations=bootstrap_iterations, statistic="mean",
    )
    rmst_ci = _cluster_bootstrap(
        clusters, "rmst_improvement", seed=bootstrap_seed + 1,
        iterations=bootstrap_iterations, statistic="mean",
    )
    median_ci = _cluster_bootstrap(
        clusters, "median_improvement", seed=bootstrap_seed + 2,
        iterations=bootstrap_iterations, statistic="median",
    )
    base_rmst = _arm_summary([pair[base] for pair in pairs])["rmst_seconds"] if pairs else None
    rmst_improvement = statistics.mean(rmst_contributions) if rmst_contributions else None
    median_improvement = statistics.median(flag_differences) if flag_differences else None
    rmst_improvement_fraction = (
        rmst_improvement / base_rmst if rmst_improvement is not None and base_rmst else None
    )
    base_median = _arm_summary([pair[base] for pair in pairs])["solved_only_median_seconds"] if pairs else None
    median_improvement_fraction = (
        median_improvement / base_median if median_improvement is not None and base_median else None
    )
    time_improvement_fraction = max(
        value for value in (rmst_improvement_fraction, median_improvement_fraction)
        if value is not None
    ) if any(value is not None for value in (rmst_improvement_fraction, median_improvement_fraction)) else None
    criterion = {
        "solve_rate_ci_lower_at_least_minus_0_05": bool(solve_ci and solve_ci[0] >= -.05),
        "time_improvement_at_least_15_percent": bool(
            time_improvement_fraction is not None and time_improvement_fraction >= .15
        ),
        "paired_time_ci_excludes_zero_favorable": bool(
            (rmst_ci and rmst_ci[0] > 0) or (median_ci and median_ci[0] > 0)
        ),
        "false_flags_not_increased": sum(int(_outcome(pair[treatment]).get("false_candidate_count") or 0) for pair in pairs) <= sum(int(_outcome(pair[base]).get("false_candidate_count") or 0) for pair in pairs),
        "scope_violations_not_increased": sum(int(_outcome(pair[treatment]).get("scope_violation_count") or 0) for pair in pairs) <= sum(int(_outcome(pair[base]).get("scope_violation_count") or 0) for pair in pairs),
        "terminal_correctness_100_percent": bool(pairs) and all(_outcome(pair[treatment]).get("terminal_correctness") is True for pair in pairs),
        "resource_consumption_reported": bool(pairs) and all(_deterministic_resources_observed(pair[treatment]) for pair in pairs),
        "not_explained_only_by_target_or_model_queue": bool(pairs)
        and all(_latency_attribution_observed(pair[base], pair[treatment]) for pair in pairs)
        and not all(
            _outcome(pair[treatment]).get("latency_explained_by_target_or_model_queue") is True
            for pair in pairs
        ),
    }
    return {
        "base_arm": base, "treatment_arm": treatment, "matched_blocks": len(pairs),
        "solve_discordance": {
            "both_solved": both_solved, "base_only": base_only,
            "treatment_only": treatment_only, "neither_solved": neither,
        },
        "solve_rate_difference": solve_difference,
        "solve_rate_difference_clustered_bootstrap_95_ci": solve_ci,
        "mcnemar_exact_two_sided_p": _mcnemar_exact(base_only, treatment_only),
        "paired_poc_time_difference_seconds": _distribution(poc_differences),
        "paired_flag_time_difference_seconds": _distribution(flag_differences),
        "paired_rmst_improvement_seconds": rmst_improvement,
        "paired_rmst_improvement_clustered_bootstrap_95_ci": rmst_ci,
        "paired_median_improvement_seconds": median_improvement,
        "paired_median_improvement_clustered_bootstrap_95_ci": median_ci,
        "rmst_improvement_fraction": rmst_improvement_fraction,
        "median_improvement_fraction": median_improvement_fraction,
        "time_improvement_fraction": time_improvement_fraction,
        "per_block_contributions": per_block,
        "per_block_rmst_contributions": rmst_contributions,
        "resource_differences": {
            field: _distribution(values) for field, values in sorted(resource_differences.items())
        },
        "criterion_evaluation": criterion,
    }


def _decision(
    private: Mapping[str, Any], *, validation: Mapping[str, Any], base: str, treatment: str,
) -> str:
    if not validation.get("sample_complete") or not private.get("matched_blocks"):
        return "INCONCLUSIVE"
    solve_diff = private.get("solve_rate_difference")
    solve_ci = private.get("solve_rate_difference_clustered_bootstrap_95_ci")
    rmst = private.get("paired_rmst_improvement_seconds")
    rmst_ci = private.get("paired_rmst_improvement_clustered_bootstrap_95_ci")
    criterion = private.get("criterion_evaluation") or {}
    if solve_diff is not None and solve_diff < -.05:
        return "REGRESSION_INDICATED"
    if rmst is not None and rmst < 0 and (solve_diff is None or solve_diff <= 0):
        return "REGRESSION_INDICATED"
    if not solve_ci or solve_ci[1] - solve_ci[0] > .50:
        return "INCONCLUSIVE"
    required = (
        "solve_rate_ci_lower_at_least_minus_0_05", "time_improvement_at_least_15_percent",
        "paired_time_ci_excludes_zero_favorable", "false_flags_not_increased",
        "scope_violations_not_increased", "terminal_correctness_100_percent",
        "resource_consumption_reported", "not_explained_only_by_target_or_model_queue",
    )
    if all(criterion.get(key) is True for key in required):
        return "PROVEN_IMPROVEMENT"
    noninferior = criterion.get("solve_rate_ci_lower_at_least_minus_0_05") is True
    favorable_point = bool(private.get("time_improvement_fraction") and private["time_improvement_fraction"] > 0)
    uncertain_time = not (
        (rmst_ci and rmst_ci[0] > 0)
        or ((private.get("paired_median_improvement_clustered_bootstrap_95_ci") or [0])[0] > 0)
    )
    if noninferior and favorable_point and uncertain_time:
        return "SUGGESTIVE_ONLY"
    return "INCONCLUSIVE"


def _cluster_bootstrap(
    clusters: Mapping[str, Sequence[Mapping[str, float]]], field: str, *,
    seed: int, iterations: int, statistic: str,
) -> list[float] | None:
    names = sorted(clusters)
    if not names:
        return None
    rng = random.Random(seed)
    estimates: list[float] = []
    for _ in range(iterations):
        sampled = [rng.choice(names) for _name in names]
        values = [
            float(row[field]) for name in sampled for row in clusters[name]
            if not math.isnan(float(row[field]))
        ]
        if not values:
            continue
        estimates.append(statistics.mean(values) if statistic == "mean" else statistics.median(values))
    if not estimates:
        return None
    return [_percentile(estimates, .025), _percentile(estimates, .975)]


def _mcnemar_exact(base_only: int, treatment_only: int) -> float | None:
    discordant = base_only + treatment_only
    if not discordant:
        return 1.0
    tail = min(base_only, treatment_only)
    probability = sum(math.comb(discordant, value) for value in range(tail + 1)) / (2 ** discordant)
    return min(1.0, 2.0 * probability)


def _censored_latency(row: Mapping[str, Any]) -> float | None:
    if _solved(row):
        return _latency(row, "first_oracle_accepted_flag_at")
    return DEFAULT_CENSOR_SECONDS


def _latency(row: Mapping[str, Any], field: str) -> float | None:
    timestamps = row.get("timestamps")
    if not isinstance(timestamps, Mapping):
        return None
    start, end = timestamps.get("attempt_started_at"), timestamps.get(field)
    if not start or not end:
        return None
    try:
        value = (_time(str(end)) - _time(str(start))).total_seconds()
    except (ValueError, TypeError):
        return None
    return value if 0 <= value <= DEFAULT_CENSOR_SECONDS else None


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _solved(row: Mapping[str, Any]) -> bool:
    outcome = _outcome(row)
    return outcome.get("oracle_result") == "ACCEPTED" and outcome.get("solved") is True


def _outcome(row: Mapping[str, Any]) -> Mapping[str, Any]:
    value = row.get("outcome")
    return value if isinstance(value, Mapping) else {}


def _resource_fields(*rows: Mapping[str, Any]) -> set[str]:
    result: set[str] = set()
    for row in rows:
        values = row.get("resource_consumption")
        if isinstance(values, Mapping): result.update(str(field) for field in values)
    return result


def _resource_value(row: Mapping[str, Any], field: str) -> float | None:
    resources = row.get("resource_consumption")
    metric = resources.get(field) if isinstance(resources, Mapping) else None
    if not isinstance(metric, Mapping) or metric.get("observation_status") != "OBSERVED":
        return None
    value = metric.get("value")
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _deterministic_resources_observed(row: Mapping[str, Any]) -> bool:
    return all(_resource_value(row, field) is not None for field in DETERMINISTIC_RESOURCE_FIELDS)


def _latency_attribution_observed(base: Mapping[str, Any], treatment: Mapping[str, Any]) -> bool:
    if _resource_value(base, "model_queue_seconds") is not None and _resource_value(treatment, "model_queue_seconds") is not None:
        return True
    for row in (base, treatment):
        outcome = _outcome(row)
        if not isinstance(outcome.get("latency_explained_by_target_or_model_queue"), bool):
            return False
        if not outcome.get("latency_explanation_evidence"):
            return False
    return True


def _resource_summary(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        field: {
            **_distribution(values),
            "observed": len(values), "missing": len(rows) - len(values),
        }
        for field in sorted({field for row in rows for field in _resource_fields(row)})
        if (values := [value for row in rows if (value := _resource_value(row, field)) is not None]) or rows
    }


def _distribution(values: Sequence[float]) -> dict[str, float | int | None]:
    return {
        "count": len(values), "median": statistics.median(values) if values else None,
        "mean": statistics.mean(values) if values else None,
        "p90": _percentile(values, .90), "maximum": max(values) if values else None,
    }


def _percentile(values: Sequence[float], quantile: float) -> float | None:
    if not values: return None
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1: return ordered[0]
    point = (len(ordered) - 1) * quantile
    lower = math.floor(point); upper = math.ceil(point)
    if lower == upper: return ordered[lower]
    return ordered[lower] * (upper - point) + ordered[upper] * (point - lower)


def _missingness(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    counters: Counter[str] = Counter()
    for row in rows:
        timestamps = row.get("timestamps") if isinstance(row.get("timestamps"), Mapping) else {}
        for field in (
            "first_working_poc_at", "first_oracle_accepted_flag_at", "attempt_finished_at",
        ):
            if timestamps.get(field) is None: counters[f"timestamp.{field}"] += 1
        resources = row.get("resource_consumption") if isinstance(row.get("resource_consumption"), Mapping) else {}
        for field, value in resources.items():
            if isinstance(value, Mapping) and value.get("value") is None:
                counters[f"resource.{field}:{value.get('observation_status')}"] += 1
    return {"run_count": len(rows), "missing": dict(sorted(counters.items())), "imputation_used": False}


def _failure_summary(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "environment_failure_runs": sum(_outcome(row).get("environment_failure") is True for row in rows),
        "solver_unsolved_runs": sum(not _solved(row) and not _outcome(row).get("environment_failure") for row in rows),
        "target_failure_duration_seconds": sum(float(_outcome(row).get("target_failure_duration_seconds") or 0) for row in rows),
        "model_failure_duration_seconds": sum(float(_outcome(row).get("model_failure_duration_seconds") or 0) for row in rows),
        "environment_failure_duration_seconds": sum(float(_outcome(row).get("environment_failure_duration_seconds") or 0) for row in rows),
    }


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _is_hex40(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 40 and all(character in "0123456789abcdef" for character in text)


def _is_hex64(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _is_image_digest(value: Any) -> bool:
    text = str(value or "")
    return text.startswith("sha256:") and _is_hex64(text.removeprefix("sha256:"))


def _legacy_summary(receipts: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    solo_fixtures = {str(row["fixture"]) for row in receipts if row["mode"] == "solo"}
    adaptive_fixtures = {str(row["fixture"]) for row in receipts if row["mode"] == "adaptive"}
    paired_fixtures = sorted(solo_fixtures & adaptive_fixtures)
    paired = [row for row in receipts if str(row["fixture"]) in paired_fixtures]
    modes: dict[str, Any] = {}
    for mode in ("solo", "adaptive"):
        rows = [row for row in paired if row["mode"] == mode]
        solved = [row for row in rows if row["solved"] and row["verified_flag"]]
        modes[mode] = {
            "runs": len(rows), "verified_solved": len(solved),
            "solve_rate": len(solved) / len(rows) if rows else None,
            "median_elapsed_seconds": statistics.median(float(row["elapsed_seconds"]) for row in solved) if solved else None,
            "mean_child_agents": statistics.mean(int(row["child_agents"]) for row in rows) if rows else None,
            "mean_context_bytes": statistics.mean(int(row.get("context_bytes", 0)) for row in rows) if rows else None,
        }
    comparable = bool(paired_fixtures and modes["solo"]["runs"] and modes["adaptive"]["runs"])
    improvement = bool(
        comparable and modes["adaptive"]["solve_rate"] >= modes["solo"]["solve_rate"]
        and modes["adaptive"]["median_elapsed_seconds"] is not None
        and modes["solo"]["median_elapsed_seconds"] is not None
        and modes["adaptive"]["median_elapsed_seconds"] < modes["solo"]["median_elapsed_seconds"]
    )
    return {
        "schema_version": 1, "compatibility_mode": "LEGACY_NON_AUTHORITATIVE",
        "paired_fixtures": paired_fixtures, "modes": modes,
        "comparable": comparable, "adaptive_improvement_observed": improvement,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate matched A/B/C/D CTF-OS benchmark manifests")
    parser.add_argument("receipts", nargs="+", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--bootstrap-seed", type=int, default=DEFAULT_BOOTSTRAP_SEED)
    parser.add_argument("--bootstrap-iterations", type=int, default=DEFAULT_BOOTSTRAP_ITERATIONS)
    args = parser.parse_args()
    try:
        result = summarize(
            load_receipts(args.receipts), bootstrap_seed=args.bootstrap_seed,
            bootstrap_iterations=args.bootstrap_iterations,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 2
    text = json.dumps({"ok": True, "result": result}, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
