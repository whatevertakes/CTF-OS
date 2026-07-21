"""Complete benchmark-attempt manifest with explicit observation missingness."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import json
from pathlib import Path
from typing import Any

from .modes import SolveMode
from .workspace import atomic_json, resolve_exact_run, utc_now


BENCHMARK_MANIFEST_SCHEMA_VERSION = 3
ARMS = frozenset({"A", "B", "C", "D", "LIVE"})
STRATA = frozenset({"PUBLIC_KNOWN", "TRANSFORMED_FAMILY", "PRIVATE_HELDOUT", "LIVE_CONTEST"})
TIMESTAMP_FIELDS = (
    "attempt_started_at", "first_meaningful_observation_at", "first_viable_hypothesis_at",
    "first_decisive_experiment_at", "first_primitive_confirmed_at", "first_working_poc_at",
    "first_remote_attempt_at", "first_flag_candidate_at", "first_oracle_accepted_flag_at",
    "attempt_finished_at", "submission_result_at",
)
RESOURCE_FIELDS = (
    "model_queue_seconds", "model_tokens", "subscription_units", "model_session_minutes",
    "cpu_seconds", "ram_gib_seconds", "ram_peak_bytes", "network_rx_bytes",
    "network_tx_bytes", "container_lifetime_seconds", "child_session_count",
    "maximum_active_width",
)


class BenchmarkManifestError(ValueError):
    pass


def missing_observation(reason: str, *, status: str = "NOT_OBSERVABLE") -> dict[str, Any]:
    if not reason.strip():
        raise BenchmarkManifestError("missing observations require a reason")
    return {"value": None, "observation_status": status, "reason": reason.strip()}


def observed(value: Any) -> dict[str, Any]:
    if value is None:
        raise BenchmarkManifestError("an observed metric cannot have a null value")
    return {"value": value, "observation_status": "OBSERVED", "reason": None}


def create_benchmark_manifest(
    run: Path,
    *,
    schedule_entry: Mapping[str, Any],
    lock_payload: Mapping[str, Any],
    lock_digest: str,
    source_environment: Mapping[str, Any],
) -> dict[str, Any]:
    state = _json(run / "STATE.json", "attempt state")
    arm = str(schedule_entry.get("arm") or "")
    stratum = str(schedule_entry.get("stratum") or "")
    if arm not in ARMS or arm == "LIVE" or stratum not in STRATA or stratum == "LIVE_CONTEST":
        raise BenchmarkManifestError("controlled benchmark manifest requires arm A/B/C/D and controlled stratum")
    expected_mode = {
        "A": "plain-sol", "B": SolveMode.SOL_ONLY.value,
        "C": SolveMode.FIXED_RACE.value, "D": SolveMode.ADAPTIVE_RACE.value,
    }[arm]
    if schedule_entry.get("mode") != expected_mode:
        raise BenchmarkManifestError("schedule arm and mode are inconsistent")
    for field in ("challenge_instance_id", "attempt_id", "run_id"):
        expected = state.get(field)
        supplied = schedule_entry.get(field) if field != "run_id" else run.name
        if field == "run_id":
            expected = state.get("run_id")
        if supplied is not None and expected != supplied:
            raise BenchmarkManifestError(f"benchmark manifest {field} does not match exact attempt")
    if state.get("challenge_instance_id") != schedule_entry.get("challenge_instance_id"):
        raise BenchmarkManifestError("schedule challenge instance does not match fresh attempt")
    started = str(schedule_entry.get("attempt_started_at") or utc_now())
    timestamps = {field: (started if field == "attempt_started_at" else None) for field in TIMESTAMP_FIELDS}
    timestamp_missing = {
        field: (None if value is not None else "NOT_YET_OBSERVED")
        for field, value in timestamps.items()
    }
    external_missing = "external model telemetry is unavailable through the user-opened session surface"
    resources = {
        field: missing_observation(
            external_missing if field in {
                "model_queue_seconds", "model_tokens", "subscription_units", "model_session_minutes",
            } else "deterministic resource telemetry has not completed",
            status="NOT_OBSERVABLE" if field.startswith("model_") or field == "subscription_units" else "NOT_YET_OBSERVED",
        )
        for field in RESOURCE_FIELDS
    }
    resources["child_session_count"] = observed(0)
    resources["maximum_active_width"] = observed(0)
    runtime_policy = str(lock_payload["runtime_model_observation_policy"])
    observed_model = source_environment.get("observed_model")
    observed_reasoning = source_environment.get("observed_reasoning")
    runtime = {
        "requested_model": lock_payload["requested_model"],
        "observed_model": observed_model or "NOT_OBSERVABLE",
        "observed_model_missing_reason": None if observed_model else "runtime surface did not expose model identity",
        "requested_reasoning": lock_payload["reasoning"],
        "observed_reasoning": observed_reasoning or "NOT_OBSERVABLE",
        "observed_reasoning_missing_reason": None if observed_reasoning else "runtime surface did not expose reasoning identity",
        "runtime_observation_policy": runtime_policy,
        "runtime_observation_evidence": source_environment.get("runtime_observation_evidence"),
        "branch_routing_observations": [],
        "model_routing_diagnostic_layer": "SEPARATE_FROM_ABCD_TREATMENT",
    }
    manifest = {
        "schema_version": BENCHMARK_MANIFEST_SCHEMA_VERSION,
        "challenge_instance_id": state["challenge_instance_id"],
        "attempt_id": state["attempt_id"], "run_id": run.name,
        "arm": arm, "mode": expected_mode,
        "repetition": schedule_entry.get("repetition"),
        "matched_block_id": schedule_entry.get("matched_block_id"),
        "matched_seed": schedule_entry.get("matched_seed"),
        "stratum": stratum, "lock_digest": lock_digest,
        "schedule_digest": lock_payload["schedule_digest"],
        "configuration_digest": lock_payload["configuration_digest"],
        "transformation_seed": schedule_entry.get("transformation_seed"),
        "source_environment": {
            "git_commit": source_environment.get("git_commit"),
            "dirty_diff_digest": source_environment.get("dirty_diff_digest"),
            "challenge_snapshot_digest": state.get("challenge_snapshot_digest"),
            "target_image_digest": source_environment.get("target_image_digest"),
            "tool_image_digest": source_environment.get("tool_image_digest"),
            "cli_build_hash": source_environment.get("cli_build_hash"),
            "host": dict(source_environment.get("host") or {}),
            "docker": dict(source_environment.get("docker") or {}),
            "network_profile": dict(lock_payload["network_profile"]),
            "time_limit_seconds": lock_payload["time_limit_seconds"],
            "maximum_model_concurrency": lock_payload["maximum_model_concurrency"],
            "random_seed": schedule_entry.get("random_seed"),
        },
        "runtime": runtime,
        "timestamps": timestamps,
        "timestamp_missing_reasons": timestamp_missing,
        "outcome": {
            "oracle_result": None, "solved": None, "censored": None,
            "censor_time_seconds": None, "environment_failure": False,
            "invalidation_reason": None, "cleanup_success": None,
            "terminal_correctness": None,
        },
        "resource_consumption": resources,
        "target_health_intervals": [],
        "target_health_probe_contract": {
            "cadence_seconds": 60, "required_at": ["RUN_START", "EVERY_60_SECONDS", "RUN_END"],
            "deterministic_host_process": True, "creates_model_sessions": False,
        },
        "artifact_provenance": [],
        "lock_signature_valid": True,
        "active_run_pointer_used": False,
        "created_at": started,
    }
    validate_manifest(manifest, require_complete=False)
    existing = run / "RUN_MANIFEST.json"
    if existing.is_symlink():
        raise BenchmarkManifestError("attempt manifest must not be a symlink")
    if existing.is_file():
        prior = _json(existing, "existing attempt manifest")
        prior_attempt = prior.get("attempt_id") or (prior.get("identity") or {}).get("attempt_id")
        if prior_attempt not in {None, state["attempt_id"]}:
            raise BenchmarkManifestError("benchmark attempt cannot reuse another attempt manifest")
    atomic_json(existing, manifest)
    return manifest


def record_timestamp(run: Path, field: str, *, observed_at: str | None = None) -> dict[str, Any]:
    if field not in TIMESTAMP_FIELDS:
        raise BenchmarkManifestError("unsupported benchmark timestamp")
    manifest = _json(run / "RUN_MANIFEST.json", "run manifest")
    if manifest["timestamps"].get(field) is None:
        value = observed_at or utc_now()
        _parse_time(value)
        manifest["timestamps"][field] = value
        manifest["timestamp_missing_reasons"][field] = None
        atomic_json(run / "RUN_MANIFEST.json", manifest)
    return manifest


def record_resource_observation(
    run: Path, field: str, *, value: Any = None,
    observation_status: str = "OBSERVED", reason: str | None = None,
) -> dict[str, Any]:
    if field not in RESOURCE_FIELDS:
        raise BenchmarkManifestError("unsupported resource metric")
    if observation_status == "OBSERVED":
        row = observed(value)
    else:
        if value is not None:
            raise BenchmarkManifestError("missing telemetry must not carry a fabricated value")
        row = missing_observation(reason or "telemetry unavailable", status=observation_status)
    manifest = _json(run / "RUN_MANIFEST.json", "run manifest")
    manifest["resource_consumption"][field] = row
    atomic_json(run / "RUN_MANIFEST.json", manifest)
    return row


def record_runtime_observation(
    run: Path, *, observed_model: str, observed_reasoning: str,
    runtime_observation_evidence: str,
) -> dict[str, Any]:
    if not all(str(value).strip() for value in (
        observed_model, observed_reasoning, runtime_observation_evidence,
    )):
        raise BenchmarkManifestError("runtime observation requires model, reasoning, and exact evidence")
    manifest = _json(run / "RUN_MANIFEST.json", "run manifest")
    if manifest.get("run_id") != run.name or manifest.get("active_run_pointer_used") is not False:
        raise BenchmarkManifestError("runtime observation requires an exact benchmark run")
    runtime = manifest["runtime"]
    prior = (
        runtime.get("observed_model"), runtime.get("observed_reasoning"),
        runtime.get("runtime_observation_evidence"),
    )
    submitted = (
        observed_model.strip(), observed_reasoning.strip(), runtime_observation_evidence.strip(),
    )
    if prior[0] not in {None, "NOT_OBSERVABLE"} and prior != submitted:
        raise BenchmarkManifestError("runtime observation conflicts with the prior exact evidence")
    runtime.update({
        "observed_model": submitted[0], "observed_model_missing_reason": None,
        "observed_reasoning": submitted[1], "observed_reasoning_missing_reason": None,
        "runtime_observation_evidence": submitted[2],
    })
    atomic_json(run / "RUN_MANIFEST.json", manifest)
    return runtime


def record_target_health(
    run: Path, *, started_at: str, ended_at: str, status: str,
    probe_receipt_id: str, endpoint_revision: int,
    semantic_health_result: str, phase: str | None = None,
) -> dict[str, Any]:
    manifest = _json(run / "RUN_MANIFEST.json", "run manifest")
    if manifest.get("run_id") != run.name:
        raise BenchmarkManifestError("target health interval belongs to another attempt")
    started_value = _parse_time(started_at); ended_value = _parse_time(ended_at)
    if ended_value < started_value or not probe_receipt_id:
        raise BenchmarkManifestError("target health interval is malformed")
    row = {
        "challenge_instance_id": manifest["challenge_instance_id"],
        "attempt_id": manifest["attempt_id"], "run_id": manifest["run_id"],
        "started_at": started_at, "ended_at": ended_at, "status": status,
        "probe_receipt_id": probe_receipt_id, "endpoint_revision": endpoint_revision,
        "semantic_health_result": semantic_health_result,
    }
    if phase is not None:
        if phase not in {"RUN_START", "PERIODIC", "RUN_END"}:
            raise BenchmarkManifestError("target health phase is invalid")
        row["phase"] = phase
    manifest["target_health_intervals"].append(row)
    atomic_json(run / "RUN_MANIFEST.json", manifest)
    return row


def record_benchmark_outcome(
    run: Path, *, oracle_result: str, cleanup_success: bool,
    terminal_correctness: bool, environment_failure: bool = False,
    invalidation_reason: str | None = None, finished_at: str | None = None,
    false_candidate_count: int = 0, scope_violation_count: int = 0,
    denied_out_of_scope_action_count: int = 0,
    target_failure_duration_seconds: float = 0.0,
    model_failure_duration_seconds: float = 0.0,
    environment_failure_duration_seconds: float = 0.0,
    latency_explained_by_target_or_model_queue: bool | None = None,
    latency_explanation_evidence: str | None = None,
) -> dict[str, Any]:
    """Atomically close an attempt from explicit oracle and terminal evidence."""

    normalized = oracle_result.strip().upper()
    if normalized not in {"ACCEPTED", "TIMEOUT", "UNSOLVED", "ENVIRONMENT_FAILURE"}:
        raise BenchmarkManifestError("benchmark oracle_result is unsupported")
    counters = (false_candidate_count, scope_violation_count, denied_out_of_scope_action_count)
    durations = (
        target_failure_duration_seconds, model_failure_duration_seconds,
        environment_failure_duration_seconds,
    )
    if any(isinstance(value, bool) or value < 0 for value in counters + durations):
        raise BenchmarkManifestError("benchmark outcome counts and durations must be non-negative")
    if (environment_failure or normalized == "ENVIRONMENT_FAILURE") and not invalidation_reason:
        raise BenchmarkManifestError("environment failure requires an invalidation reason")
    if latency_explained_by_target_or_model_queue is not None and not latency_explanation_evidence:
        raise BenchmarkManifestError("latency attribution requires evidence")
    manifest = _json(run / "RUN_MANIFEST.json", "run manifest")
    if manifest.get("run_id") != run.name or manifest.get("active_run_pointer_used") is not False:
        raise BenchmarkManifestError("benchmark outcome requires an exact run, never ACTIVE_RUN")
    timestamp = finished_at or utc_now(); _parse_time(timestamp)
    solved = normalized == "ACCEPTED"
    if solved and manifest["timestamps"].get("first_oracle_accepted_flag_at") is None:
        raise BenchmarkManifestError("ACCEPTED outcome requires an observed accepted-flag timestamp")
    manifest["timestamps"]["attempt_finished_at"] = timestamp
    manifest["timestamp_missing_reasons"]["attempt_finished_at"] = None
    if solved and manifest["timestamps"].get("submission_result_at") is None:
        manifest["timestamps"]["submission_result_at"] = timestamp
        manifest["timestamp_missing_reasons"]["submission_result_at"] = None
    manifest["outcome"] = {
        "oracle_result": normalized, "solved": solved, "censored": not solved,
        "censor_time_seconds": None if solved else int(
            manifest["source_environment"].get("time_limit_seconds") or 2700
        ),
        "environment_failure": bool(environment_failure or normalized == "ENVIRONMENT_FAILURE"),
        "invalidation_reason": invalidation_reason,
        "cleanup_success": cleanup_success, "terminal_correctness": terminal_correctness,
        "false_candidate_count": false_candidate_count,
        "scope_violation_count": scope_violation_count,
        "denied_out_of_scope_action_count": denied_out_of_scope_action_count,
        "target_failure_duration_seconds": target_failure_duration_seconds,
        "model_failure_duration_seconds": model_failure_duration_seconds,
        "environment_failure_duration_seconds": environment_failure_duration_seconds,
        "latency_explained_by_target_or_model_queue": latency_explained_by_target_or_model_queue,
        "latency_explanation_evidence": latency_explanation_evidence,
    }
    atomic_json(run / "RUN_MANIFEST.json", manifest)
    return manifest


def validate_manifest(manifest: Mapping[str, Any], *, require_complete: bool) -> None:
    required = {
        "schema_version", "challenge_instance_id", "attempt_id", "run_id", "arm", "mode",
        "repetition", "matched_block_id", "stratum", "lock_digest", "configuration_digest",
        "schedule_digest", "transformation_seed", "source_environment", "runtime", "timestamps",
        "timestamp_missing_reasons", "outcome", "resource_consumption",
        "target_health_intervals", "active_run_pointer_used",
    }
    missing = required.difference(manifest)
    if missing or manifest.get("schema_version") != BENCHMARK_MANIFEST_SCHEMA_VERSION:
        raise BenchmarkManifestError(f"benchmark manifest is incomplete: {sorted(missing)}")
    if manifest.get("arm") not in {"A", "B", "C", "D"} or manifest.get("stratum") not in STRATA - {"LIVE_CONTEST"}:
        raise BenchmarkManifestError("benchmark arm or stratum is invalid")
    if manifest.get("active_run_pointer_used") is not False:
        raise BenchmarkManifestError("benchmark attempts must never be selected via ACTIVE_RUN")
    timestamps = manifest.get("timestamps")
    reasons = manifest.get("timestamp_missing_reasons")
    if not isinstance(timestamps, Mapping) or set(TIMESTAMP_FIELDS).difference(timestamps):
        raise BenchmarkManifestError("required benchmark timestamps are missing")
    if not isinstance(reasons, Mapping):
        raise BenchmarkManifestError("timestamp missingness map is absent")
    for field in TIMESTAMP_FIELDS:
        if timestamps[field] is None and not reasons.get(field):
            raise BenchmarkManifestError(f"null timestamp lacks missing_reason: {field}")
        if timestamps[field] is not None and reasons.get(field) is not None:
            raise BenchmarkManifestError(f"observed timestamp has a missing_reason: {field}")
    resources = manifest.get("resource_consumption")
    if not isinstance(resources, Mapping) or set(RESOURCE_FIELDS).difference(resources):
        raise BenchmarkManifestError("resource telemetry fields are incomplete")
    for field in RESOURCE_FIELDS:
        row = resources[field]
        if not isinstance(row, Mapping) or "value" not in row or "observation_status" not in row:
            raise BenchmarkManifestError(f"resource telemetry missingness is malformed: {field}")
        if row["value"] is None and not row.get("reason"):
            raise BenchmarkManifestError(f"missing resource telemetry has no reason: {field}")
    if require_complete:
        outcome = manifest.get("outcome")
        outcome_fields = {
            "oracle_result", "solved", "censored", "censor_time_seconds",
            "environment_failure", "invalidation_reason", "cleanup_success",
            "terminal_correctness",
        }
        if (
            not isinstance(outcome, Mapping) or outcome_fields.difference(outcome)
            or outcome.get("oracle_result") is None
        ):
            raise BenchmarkManifestError("completed attempt requires an oracle result")
        if timestamps["attempt_finished_at"] is None:
            raise BenchmarkManifestError("completed attempt requires attempt_finished_at")
        _validate_completed_target_health(manifest)
        deterministic = {
            "cpu_seconds", "ram_gib_seconds", "ram_peak_bytes", "network_rx_bytes",
            "network_tx_bytes", "container_lifetime_seconds", "child_session_count",
            "maximum_active_width",
        }
        if any(resources[field].get("observation_status") != "OBSERVED" for field in deterministic):
            raise BenchmarkManifestError("completed attempt requires observed deterministic resource telemetry")
        runtime = manifest.get("runtime")
        if isinstance(runtime, Mapping) and str(runtime.get("runtime_observation_policy") or "").upper() in {
            "REQUIRED", "MUST_OBSERVE",
        } and (
            runtime.get("observed_model") == "NOT_OBSERVABLE"
            or runtime.get("observed_reasoning") == "NOT_OBSERVABLE"
            or not runtime.get("runtime_observation_evidence")
        ):
            raise BenchmarkManifestError("required runtime identity was not observed")


def _validate_completed_target_health(manifest: Mapping[str, Any]) -> None:
    intervals = manifest.get("target_health_intervals")
    timestamps = manifest["timestamps"]
    if not isinstance(intervals, list) or len(intervals) < 2:
        raise BenchmarkManifestError("completed attempt requires run-start/periodic/run-end target health")
    try:
        start = _parse_time(str(timestamps["attempt_started_at"]))
        end = _parse_time(str(timestamps["attempt_finished_at"]))
        observed = sorted(
            (_parse_time(str(row["started_at"])), _parse_time(str(row["ended_at"])), row)
            for row in intervals if isinstance(row, Mapping)
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise BenchmarkManifestError("completed target health evidence is malformed") from exc
    if len(observed) != len(intervals):
        raise BenchmarkManifestError("completed target health evidence is malformed")
    if (observed[0][0] - start).total_seconds() > 60 or (end - observed[-1][1]).total_seconds() > 60:
        raise BenchmarkManifestError("target health does not cover run start/end")
    if observed[0][2].get("phase") not in {None, "RUN_START"} or observed[-1][2].get("phase") not in {None, "RUN_END"}:
        raise BenchmarkManifestError("target health phase sequence is invalid")
    if any((right[0] - left[1]).total_seconds() > 75 for left, right in zip(observed, observed[1:])):
        raise BenchmarkManifestError("target health cadence exceeds the 60-second contract")
    if any(
        row.get("status") not in {"HEALTHY", "OK"}
        or row.get("semantic_health_result") not in {"PASS", "HEALTHY", "OK"}
        for _started, _ended, row in observed
    ):
        raise BenchmarkManifestError("target health contains an unhealthy interval")


def _parse_time(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BenchmarkManifestError("timestamp must be ISO-8601") from exc


def _json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise BenchmarkManifestError(f"{label} is missing or unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkManifestError(f"{label} is malformed") from exc
    if not isinstance(value, dict):
        raise BenchmarkManifestError(f"{label} must be an object")
    return value
