from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from ctf_os.benchmark_manifest import (
    BenchmarkManifestError, RESOURCE_FIELDS, TIMESTAMP_FIELDS,
    create_benchmark_manifest, record_benchmark_outcome, record_runtime_observation,
    record_target_health, record_timestamp,
)
from ctf_os.attempts import challenge_instance_id, challenge_snapshot_digest
from ctf_os.benchmark_lock import ARM_CONFIGURATION, HOST_REQUIREMENTS, NETWORK_PROFILE, configuration_digest
from ctf_os.benchmark_runtime import start_benchmark_attempt
from ctf_os.benchmark_schedule import (
    BenchmarkScheduleError, begin_schedule_entry, finish_schedule_entry, generate_schedule,
    solver_context_entry,
)
from ctf_os.benchmark_telemetry import (
    finish_resource_telemetry, run_target_health_monitor, sample_resource_telemetry,
    start_resource_telemetry,
)
from ctf_os.modes import SolveMode
from ctf_os.workspace import start_fresh_attempt


def _run(tmp_path: Path):
    workspace = tmp_path / "challenge"; (workspace / "input").mkdir(parents=True)
    (workspace / "input" / "x").write_text("x")
    challenge = SimpleNamespace(id="c", key="misc/c", category="misc", name="c", remotes=(),
                                description="c", hint=None, flag_format="CTF{}", flag_pattern="CTF",
                                input_profile="standard")
    run = start_fresh_attempt(workspace, challenge, "fp", transformation_seed="seed", mode=SolveMode.SOL_ONLY)
    return run


def _lock(state):
    return {
        "configuration_digest": "d" * 64, "requested_model": "model", "reasoning": "high",
        "runtime_model_observation_policy": "OPTIONAL",
        "network_profile": {"profile": "matched"}, "time_limit_seconds": 2700,
        "maximum_model_concurrency": 4,
        "schedule_digest": "f" * 64,
    }


def _entry(state, arm="B"):
    return {
        "arm": arm, "mode": {"A": "plain-sol", "B": "sol-only", "C": "fixed-race", "D": "adaptive-race"}[arm],
        "repetition": 1, "matched_block_id": "block", "matched_seed": "seed",
        "stratum": "PRIVATE_HELDOUT", "transformation_seed": "seed",
        "random_seed": "r", "challenge_instance_id": state["challenge_instance_id"],
        "attempt_id": state["attempt_id"],
    }


def _source():
    return {
        "git_commit": "a" * 40, "dirty_diff_digest": "CLEAN",
        "target_image_digest": "sha256:" + "b" * 64,
        "tool_image_digest": "sha256:" + "c" * 64,
        "cli_build_hash": "d" * 64, "host": {"system": "Linux"}, "docker": {"architecture": "amd64"},
    }


def _manifest(tmp_path: Path):
    run = _run(tmp_path); state = json.loads((run / "STATE.json").read_text())
    return run, create_benchmark_manifest(run, schedule_entry=_entry(state), lock_payload=_lock(state),
                                          lock_digest="e" * 64, source_environment=_source())


def _challenges(count=12):
    return [{
        "challenge_instance_id": f"ci-{i:02d}", "challenge_snapshot_digest": f"{i:064x}",
        "target_snapshot_digest": f"{i + 20:064x}", "transformation_seed": f"t-{i}",
        "random_seed_family": f"family-{i}", "network_profile": {"profile": "matched"},
        "model_policy": {"model": "same"}, "host_envelope": {"vcpu": 16},
        "stratum": "PRIVATE_HELDOUT",
    } for i in range(count)]


def test_run_manifest_records_attempt_and_challenge_instance_identity(tmp_path: Path) -> None:
    _run_path, manifest = _manifest(tmp_path)
    assert manifest["attempt_id"] and manifest["challenge_instance_id"] and manifest["run_id"]


def test_requested_and_observed_runtime_identity_are_never_conflated(tmp_path: Path) -> None:
    _run_path, manifest = _manifest(tmp_path)
    assert manifest["runtime"]["requested_model"] == "model"
    assert manifest["runtime"]["observed_model"] == "NOT_OBSERVABLE"
    assert manifest["runtime"]["observed_model_missing_reason"]


def test_unobservable_model_metrics_have_explicit_missingness(tmp_path: Path) -> None:
    _run_path, manifest = _manifest(tmp_path)
    metric = manifest["resource_consumption"]["model_tokens"]
    assert metric["value"] is None and metric["observation_status"] == "NOT_OBSERVABLE" and metric["reason"]


def test_all_required_timestamps_have_null_reason_semantics(tmp_path: Path) -> None:
    _run_path, manifest = _manifest(tmp_path)
    assert set(TIMESTAMP_FIELDS) == set(manifest["timestamps"])
    assert all(value is not None or manifest["timestamp_missing_reasons"][field]
               for field, value in manifest["timestamps"].items())


def test_resource_fields_never_default_missing_values_to_zero(tmp_path: Path) -> None:
    _run_path, manifest = _manifest(tmp_path)
    assert set(RESOURCE_FIELDS) == set(manifest["resource_consumption"])
    assert manifest["resource_consumption"]["cpu_seconds"]["value"] is None


def test_target_health_interval_identity_matches_attempt(tmp_path: Path) -> None:
    run, manifest = _manifest(tmp_path)
    row = record_target_health(run, started_at="2026-07-20T00:00:00Z", ended_at="2026-07-20T00:00:01Z",
                               status="HEALTHY", probe_receipt_id="probe", endpoint_revision=1,
                               semantic_health_result="PASS")
    assert row["attempt_id"] == manifest["attempt_id"] and row["run_id"] == run.name


def test_benchmark_attempt_cannot_reuse_another_attempt_manifest(tmp_path: Path) -> None:
    run = _run(tmp_path); state = json.loads((run / "STATE.json").read_text())
    manifest = json.loads((run / "RUN_MANIFEST.json").read_text()); manifest["attempt_id"] = "another"
    (run / "RUN_MANIFEST.json").write_text(json.dumps(manifest))
    with pytest.raises(BenchmarkManifestError, match="reuse"):
        create_benchmark_manifest(run, schedule_entry=_entry(state), lock_payload=_lock(state),
                                  lock_digest="e" * 64, source_environment=_source())


def test_schedule_contains_144_entries_for_12x4x3() -> None:
    assert generate_schedule(_challenges(), randomization_seed=7)["entry_count"] == 144


def test_arm_order_is_deterministic_from_preregistered_seed() -> None:
    first = generate_schedule(_challenges(1), randomization_seed="same")
    second = generate_schedule(_challenges(1), randomization_seed="same")
    assert first == second


def test_schedule_mutation_is_rejected_by_canonical_digest() -> None:
    schedule = generate_schedule(_challenges(1), randomization_seed="same")
    schedule["entries"][0]["arm_order"] = 99
    with pytest.raises(BenchmarkScheduleError, match="digest"):
        from ctf_os.benchmark_schedule import validate_schedule
        validate_schedule(schedule)


def test_each_block_contains_exactly_A_B_C_D() -> None:
    schedule = generate_schedule(_challenges(2), randomization_seed=1)
    blocks = {}
    for row in schedule["entries"]: blocks.setdefault(row["matched_block_id"], set()).add(row["arm"])
    assert all(arms == {"A", "B", "C", "D"} for arms in blocks.values())


def test_each_block_uses_matched_snapshot_and_seed() -> None:
    schedule = generate_schedule(_challenges(1), randomization_seed=1)
    for repetition in range(1, 4):
        rows = [row for row in schedule["entries"] if row["repetition"] == repetition]
        assert len({row["challenge_snapshot_digest"] for row in rows}) == 1
        assert len({row["random_seed"] for row in rows}) == 1


def test_cross_arm_parallel_execution_is_rejected(tmp_path: Path) -> None:
    schedule = generate_schedule(_challenges(1), randomization_seed=1)
    rows = sorted(schedule["entries"], key=lambda row: row["arm_order"])
    ledger = tmp_path / "execution.jsonl"
    begin_schedule_entry(schedule, rows[0]["schedule_entry_id"], ledger)
    same_block = next(row for row in rows if row["matched_block_id"] == rows[0]["matched_block_id"] and row != rows[0])
    with pytest.raises(BenchmarkScheduleError, match="simultaneous"):
        begin_schedule_entry(schedule, same_block["schedule_entry_id"], ledger)


def test_private_heldout_identity_is_not_exposed_to_solver_context() -> None:
    entry = generate_schedule(_challenges(1), randomization_seed=1)["entries"][0]
    context = solver_context_entry(entry)
    assert "challenge_instance_id" not in context and "stratum" not in context


def test_target_health_monitor_records_start_and_end_without_model_lifecycle(tmp_path: Path) -> None:
    run, manifest = _manifest(tmp_path)
    result = run_target_health_monitor(
        run, probe_argv=[sys.executable, "-c", "print('READY')"],
        endpoint_revision=1, duration_seconds=0, cadence_seconds=60,
        semantic_success_token="READY",
    )
    saved = json.loads((run / "RUN_MANIFEST.json").read_text())
    assert result["probe_count"] == 2 and result["model_session_launched"] is False
    assert {row["phase"] for row in result["receipts"]} == {"RUN_START", "RUN_END"}
    assert all(row["attempt_id"] == manifest["attempt_id"] for row in saved["target_health_intervals"])


def test_resource_telemetry_preserves_unobservable_missingness(tmp_path: Path) -> None:
    run, _manifest_value = _manifest(tmp_path)
    start_resource_telemetry(run)
    finish_resource_telemetry(run)
    saved = json.loads((run / "RUN_MANIFEST.json").read_text())
    for field in ("cpu_seconds", "ram_peak_bytes", "network_rx_bytes", "container_lifetime_seconds"):
        metric = saved["resource_consumption"][field]
        assert metric["value"] is None and metric["observation_status"] == "NOT_OBSERVABLE"


def test_resource_telemetry_observes_exact_process_and_network_namespace(tmp_path: Path) -> None:
    run, _manifest_value = _manifest(tmp_path)
    start_resource_telemetry(
        run, tracked_pids=[os.getpid()], network_namespace_pid=os.getpid(),
    )
    sample_resource_telemetry(run)
    finish_resource_telemetry(run)
    resources = json.loads((run / "RUN_MANIFEST.json").read_text())["resource_consumption"]
    for field in ("cpu_seconds", "ram_gib_seconds", "ram_peak_bytes", "network_rx_bytes", "network_tx_bytes"):
        assert resources[field]["observation_status"] == "OBSERVED"


def test_schedule_completion_requires_validated_exact_run_receipt(tmp_path: Path) -> None:
    schedule = generate_schedule(_challenges(1), randomization_seed=1)
    entry = schedule["entries"][0]; ledger = tmp_path / "execution.jsonl"
    begin_schedule_entry(schedule, entry["schedule_entry_id"], ledger)
    with pytest.raises(BenchmarkScheduleError, match="validated"):
        finish_schedule_entry(
            schedule, entry["schedule_entry_id"], ledger,
            completion_receipt={"valid": False, "run_id": "run-x"},
        )
    receipt = finish_schedule_entry(
        schedule, entry["schedule_entry_id"], ledger,
        completion_receipt={"valid": True, "run_id": "run-x", "arm": entry["arm"]},
    )
    assert receipt["event"] == "FINISHED" and receipt["run_id"] == "run-x"


def test_benchmark_outcome_is_exact_and_never_fabricates_accepted_time(tmp_path: Path) -> None:
    run, _manifest_value = _manifest(tmp_path)
    with pytest.raises(BenchmarkManifestError, match="accepted-flag timestamp"):
        record_benchmark_outcome(
            run, oracle_result="ACCEPTED", cleanup_success=True, terminal_correctness=True,
        )
    record_timestamp(run, "first_oracle_accepted_flag_at", observed_at="2026-07-20T00:01:00Z")
    completed = record_benchmark_outcome(
        run, oracle_result="ACCEPTED", cleanup_success=True, terminal_correctness=True,
        finished_at="2026-07-20T00:02:00Z",
    )
    assert completed["outcome"]["solved"] is True
    assert completed["timestamps"]["attempt_finished_at"] == "2026-07-20T00:02:00Z"


def test_environment_failure_outcome_requires_invalidation_reason(tmp_path: Path) -> None:
    run, _manifest_value = _manifest(tmp_path)
    with pytest.raises(BenchmarkManifestError, match="invalidation reason"):
        record_benchmark_outcome(
            run, oracle_result="ENVIRONMENT_FAILURE",
            cleanup_success=False, terminal_correctness=False,
        )


def test_runtime_observation_never_replaces_requested_identity(tmp_path: Path) -> None:
    run, _manifest_value = _manifest(tmp_path)
    observed = record_runtime_observation(
        run, observed_model="observed-model", observed_reasoning="observed-high",
        runtime_observation_evidence="native runtime tree receipt abc",
    )
    assert observed["requested_model"] == "model"
    assert observed["observed_model"] == "observed-model"


def test_benchmark_runtime_creates_exact_non_active_attempt_with_target_digest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    import ctf_os.benchmark_runtime as runtime

    workspace = tmp_path / "challenge"; (workspace / "input").mkdir(parents=True)
    (workspace / "input" / "x").write_text("x")
    challenge = SimpleNamespace(
        id="c", key="misc/c", category="misc", name="c", remotes=(), description="c",
        hint=None, flag_format="CTF{}", flag_pattern="CTF", input_profile="standard",
    )
    target_digest = "sha256:" + "a" * 64; tool_digest = "sha256:" + "b" * 64
    snapshot = challenge_snapshot_digest(
        workspace, challenge, input_fingerprint="fp", target_revision=1,
        transformation_seed="seed", local_target_image_digest=target_digest,
    )
    instance = challenge_instance_id(
        challenge_id="c", input_fingerprint="fp", target_revision=1,
        challenge_snapshot_digest=snapshot, transformation_seed="seed",
    )
    model_policy = {
        "requested_model": "model", "runtime_model_observation_policy": "OPTIONAL",
        "surface": "Sol", "reasoning": "high",
    }
    schedule = generate_schedule([{
        "challenge_instance_id": instance, "challenge_snapshot_digest": snapshot,
        "target_snapshot_digest": target_digest, "transformation_seed": "seed",
        "random_seed_family": "family", "network_profile": NETWORK_PROFILE,
        "model_policy": model_policy, "host_envelope": HOST_REQUIREMENTS,
        "stratum": "PRIVATE_HELDOUT",
    }], randomization_seed="registered")
    entry = schedule["entries"][0]
    archive = tmp_path / "challenge.tar"; archive.write_bytes(b"archive")
    lock = {
        "configuration_digest": configuration_digest(ARM_CONFIGURATION),
        "canonical_arm_configuration": ARM_CONFIGURATION,
        "network_profile": NETWORK_PROFILE, "requested_model": "model", "reasoning": "high",
        "runtime_model_observation_policy": "OPTIONAL", "surface": "Sol",
        "host_requirements": HOST_REQUIREMENTS, "randomization_seed": "registered",
        "schedule_digest": schedule["schedule_digest"],
        "challenge_archive_sha256": hashlib.sha256(b"archive").hexdigest(),
        "cli_build_hash": "c" * 64, "time_limit_seconds": 2700,
        "maximum_model_concurrency": 4,
    }
    monkeypatch.setattr(runtime, "verify_benchmark_lock", lambda *_args, **_kwargs: {
        "payload": lock, "lock_digest": "d" * 64, "signature_valid": True,
    })
    monkeypatch.setattr(runtime, "_git_identity", lambda _repo: ("e" * 40, True, "CLEAN"))
    monkeypatch.setattr(runtime, "_cli_build_hash", lambda _repo: "c" * 64)
    monkeypatch.setattr(runtime, "_docker_identity", lambda **_kwargs: {
        "architecture": "amd64", "operating_system": "Linux",
    })
    monkeypatch.setattr(runtime, "_validate_host_requirements", lambda *_args: {
        "cpu_count": 16, "ram_gib": 64, "free_ssd_gib": 200, "machine": "x86_64",
    })
    monkeypatch.setattr(runtime, "_verify_local_image_digest", lambda _digest: None)
    result = start_benchmark_attempt(
        tmp_path, workspace, challenge, input_fingerprint="fp", target_revision=1,
        schedule=schedule, schedule_entry_id=entry["schedule_entry_id"],
        lock_path=tmp_path / "lock", signature_path=tmp_path / "sig",
        public_keys={}, target_image_digest=target_digest, tool_image_digest=tool_digest,
        challenge_archive_path=archive,
    )
    assert result["active_run_pointer_used"] is False
    assert not (workspace / "ACTIVE_RUN.json").exists()
    state = json.loads((Path(result["run_path"]) / "STATE.json").read_text())
    assert state["challenge_instance_id"] == instance and state["attempt_id"] == entry["attempt_id"]
