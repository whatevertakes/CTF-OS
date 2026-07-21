from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path


def _module():
    spec = importlib.util.spec_from_file_location("benchmark_eval", Path("eval/run_eval.py"))
    module = importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(module)
    return module


def _metric(value):
    return {"value": value, "observation_status": "OBSERVED", "reason": None}


def _rows(*, stratum="PRIVATE_HELDOUT", solved=True, treatment_seconds=80.0, base_seconds=100.0):
    values = []
    for arm in "ABCD":
        seconds = base_seconds if arm == "A" else treatment_seconds
        accepted = solved
        attempt = f"attempt-{arm}"
        run = f"run-{arm}"
        resources = {field: _metric(10 if field != "child_session_count" else (0 if arm in "AB" else 3))
                     for field in ("cpu_seconds", "ram_gib_seconds", "ram_peak_bytes", "network_rx_bytes",
                                   "network_tx_bytes", "container_lifetime_seconds", "child_session_count",
                                   "maximum_active_width")}
        resources["model_tokens"] = {"value": None, "observation_status": "NOT_OBSERVABLE", "reason": "external"}
        resources["model_queue_seconds"] = _metric(1)
        resources["model_session_minutes"] = _metric(45)
        started = datetime(2026, 7, 20, tzinfo=timezone.utc)
        health = []
        for offset in range(0, 2701, 60):
            observed = started + timedelta(seconds=offset)
            health.append({
                "attempt_id": attempt, "run_id": run, "status": "HEALTHY",
                "challenge_instance_id": "ci-one",
                "semantic_health_result": "PASS", "probe_receipt_id": f"probe-{arm}-{offset}",
                "endpoint_revision": 1,
                "started_at": observed.isoformat(),
                "ended_at": (observed + timedelta(milliseconds=1)).isoformat(),
                "phase": "RUN_START" if offset == 0 else "RUN_END" if offset == 2700 else "PERIODIC",
            })
        accepted_at = f"2026-07-20T00:01:{int(seconds - 60):02d}Z" if accepted else None
        timestamps = {
            "attempt_started_at": "2026-07-20T00:00:00Z",
            "first_meaningful_observation_at": "2026-07-20T00:00:10Z",
            "first_viable_hypothesis_at": "2026-07-20T00:00:20Z",
            "first_decisive_experiment_at": "2026-07-20T00:00:30Z",
            "first_primitive_confirmed_at": "2026-07-20T00:00:35Z",
            "first_working_poc_at": "2026-07-20T00:00:40Z",
            "first_remote_attempt_at": "2026-07-20T00:00:50Z",
            "first_flag_candidate_at": accepted_at,
            "first_oracle_accepted_flag_at": accepted_at,
            "attempt_finished_at": "2026-07-20T00:45:00Z",
            "submission_result_at": accepted_at,
        }
        timestamp_reasons = {
            field: (None if value is not None else "NOT_OBSERVED")
            for field, value in timestamps.items()
        }
        values.append({
            "schema_version": 3, "arm": arm,
            "mode": {"A": "plain-sol", "B": "sol-only", "C": "fixed-race", "D": "adaptive-race"}[arm],
            "challenge_instance_id": "ci-one", "attempt_id": attempt, "run_id": run,
            "matched_block_id": "block-one", "repetition": 1, "matched_seed": "1" * 64,
            "stratum": stratum, "lock_digest": "2" * 64, "schedule_digest": "3" * 64,
            "configuration_digest": "4" * 64,
            "transformation_seed": "NONE", "active_run_pointer_used": False,
            "lock_signature_valid": True,
            "outcome": {"oracle_result": "ACCEPTED" if accepted else "TIMEOUT", "solved": accepted,
                        "censored": not accepted, "censor_time_seconds": 2700 if not accepted else None,
                        "environment_failure": False, "invalidation_reason": None,
                        "cleanup_success": True, "terminal_correctness": True,
                        "false_candidate_count": 0, "scope_violation_count": 0,
                        "denied_out_of_scope_action_count": 0},
            "timestamps": timestamps, "timestamp_missing_reasons": timestamp_reasons,
            "target_health_intervals": health,
            "resource_consumption": resources,
            "source_environment": {
                "git_commit": "a" * 40, "dirty_diff_digest": "CLEAN",
                "challenge_snapshot_digest": "b" * 64,
                "target_image_digest": "sha256:" + "c" * 64,
                "tool_image_digest": "sha256:" + "d" * 64,
                "cli_build_hash": "e" * 64, "host": {"cpu_count": 16},
                "docker": {"architecture": "amd64"}, "network_profile": {"profile": "matched"},
                "time_limit_seconds": 2700, "maximum_model_concurrency": 4,
                "random_seed": "random",
            },
            "runtime": {
                "requested_model": "model", "observed_model": "NOT_OBSERVABLE",
                "requested_reasoning": "high", "observed_reasoning": "NOT_OBSERVABLE",
                "runtime_observation_policy": "OPTIONAL", "runtime_observation_evidence": None,
            },
            "artifact_provenance": [],
        })
    return values


def _evaluate(rows):
    return _module().evaluate_benchmark(rows, bootstrap_iterations=100, bootstrap_seed=7)


def test_cost_only_reduction_never_yields_proven_improvement() -> None:
    rows = _rows(treatment_seconds=100, base_seconds=100)
    for row in rows[1:]: row["resource_consumption"]["cpu_seconds"] = _metric(1)
    result = _evaluate(rows)
    assert all(result["paired_comparisons"][f"{arm}_vs_A"]["decision"] != "PROVEN_IMPROVEMENT" for arm in "BCD")


def test_child_count_reduction_never_yields_proven_improvement() -> None:
    rows = _rows(treatment_seconds=100, base_seconds=100)
    rows[0]["resource_consumption"]["child_session_count"] = _metric(3)
    assert _evaluate(rows)["paired_comparisons"]["B_vs_A"]["decision"] != "PROVEN_IMPROVEMENT"


def test_matched_seed_repetition_identity_is_required() -> None:
    rows = _rows(); rows[0].pop("matched_seed")
    result = _evaluate(rows)
    assert result["invalid_matched_blocks"]


def test_unsolved_runs_are_censored_not_dropped() -> None:
    result = _evaluate(_rows(solved=False))
    summary = result["arm_stratum_outcomes"]["PRIVATE_HELDOUT"]["A"]
    assert summary["runs"] == 1 and summary["censored_count"] == 1 and summary["rmst_seconds"] == 2700


def test_missing_latency_is_flagged_not_imputed() -> None:
    rows = _rows(); rows[3]["timestamps"]["first_oracle_accepted_flag_at"] = None
    rows[3]["timestamp_missing_reasons"]["first_oracle_accepted_flag_at"] = "RUNTIME_DID_NOT_EXPOSE_TIMESTAMP"
    summary = _evaluate(rows)["arm_stratum_outcomes"]["PRIVATE_HELDOUT"]["D"]
    assert summary["oracle_accepted_solved"] == 1 and summary["missing_flag_latency_count"] == 1
    assert summary["rmst_seconds"] is None


def test_invalid_matched_block_is_excluded_and_reported() -> None:
    result = _evaluate(_rows()[:-1])
    assert not result["valid_matched_blocks"] and result["invalid_matched_blocks"]


def test_environment_failure_is_separate_from_solver_failure() -> None:
    rows = _rows(solved=False); rows[0]["outcome"]["environment_failure"] = True
    failures = _evaluate(rows)["target_environment_failures"]
    assert failures["environment_failure_runs"] == 1 and failures["solver_unsolved_runs"] == 3


def test_target_health_failure_invalidates_whole_matched_block() -> None:
    rows = _rows(); rows[2]["target_health_intervals"][0]["status"] = "FAILED"
    reasons = _evaluate(rows)["invalid_matched_blocks"][0]["reasons"]
    assert "TARGET_HEALTH_FAILURE" in reasons


def test_target_health_cadence_gap_invalidates_whole_matched_block() -> None:
    rows = _rows(); del rows[1]["target_health_intervals"][10]
    reasons = _evaluate(rows)["invalid_matched_blocks"][0]["reasons"]
    assert "TARGET_HEALTH_FAILURE" in reasons


def test_identity_reuse_across_matched_blocks_invalidates_both_blocks() -> None:
    first = _rows(); second = deepcopy(_rows())
    for row in second:
        row["matched_block_id"] = "block-two"; row["challenge_instance_id"] = "ci-two"
        row["repetition"] = 2; row["attempt_id"] += "-two"; row["run_id"] += "-two"
        for interval in row["target_health_intervals"]:
            interval["attempt_id"] = row["attempt_id"]; interval["run_id"] = row["run_id"]
            interval["challenge_instance_id"] = row["challenge_instance_id"]
    second[0]["attempt_id"] = first[0]["attempt_id"]
    for interval in second[0]["target_health_intervals"]:
        interval["attempt_id"] = second[0]["attempt_id"]
    invalid = _evaluate(first + second)["invalid_matched_blocks"]
    assert len(invalid) == 2
    assert all("ATTEMPT_OR_RUN_ID_REUSED_ACROSS_BLOCKS" in block["reasons"] for block in invalid)


def test_public_known_is_diagnostic_only() -> None:
    result = _evaluate(_rows(stratum="PUBLIC_KNOWN"))
    assert result["stratum_policy"]["PUBLIC_KNOWN"] == "DIAGNOSTIC_ONLY"
    assert result["final_decision"] == "INCONCLUSIVE"


def test_private_heldout_is_primary() -> None:
    assert _evaluate(_rows())["primary_conclusion_stratum"] == "PRIVATE_HELDOUT"


def test_mcnemar_exact_uses_paired_discordance() -> None:
    evaluate = _module()
    assert evaluate._mcnemar_exact(0, 3) == .25
    assert evaluate._mcnemar_exact(0, 0) == 1.0


def test_cluster_bootstrap_preserves_challenge_repetitions() -> None:
    result = _evaluate(_rows())
    assert result["bootstrap"]["unit"] == "challenge_instance_id"
    assert result["bootstrap"]["preserves_repetitions"] is True


def test_paired_output_contains_exact_per_block_contributions() -> None:
    comparison = _evaluate(_rows())["paired_comparisons"]["D_vs_A"]["PRIVATE_HELDOUT"]
    assert comparison["per_block_contributions"][0]["matched_block_id"] == "block-one"


def _private(**changes):
    criterion = {
        "solve_rate_ci_lower_at_least_minus_0_05": True,
        "time_improvement_at_least_15_percent": True,
        "paired_time_ci_excludes_zero_favorable": True,
        "false_flags_not_increased": True, "scope_violations_not_increased": True,
        "terminal_correctness_100_percent": True, "resource_consumption_reported": True,
        "not_explained_only_by_target_or_model_queue": True,
    }
    value = {"matched_blocks": 12, "solve_rate_difference": 0.0,
             "solve_rate_difference_clustered_bootstrap_95_ci": [-.04, .10],
             "paired_rmst_improvement_seconds": 20,
             "paired_rmst_improvement_clustered_bootstrap_95_ci": [5, 30],
             "paired_median_improvement_clustered_bootstrap_95_ci": [4, 25],
             "time_improvement_fraction": .2, "criterion_evaluation": criterion}
    value.update(changes); return value


def test_published_decision_matches_preregistered_criteria() -> None:
    evaluate = _module()
    assert evaluate._decision(_private(), validation={"sample_complete": True}, base="A", treatment="D") == "PROVEN_IMPROVEMENT"


def test_incomplete_identity_or_manifest_returns_inconclusive() -> None:
    evaluate = _module()
    assert evaluate._decision(_private(), validation={"sample_complete": False}, base="A", treatment="D") == "INCONCLUSIVE"


def test_wide_confidence_interval_returns_inconclusive() -> None:
    evaluate = _module()
    private = _private(solve_rate_difference_clustered_bootstrap_95_ci=[-.4, .4])
    assert evaluate._decision(private, validation={"sample_complete": True}, base="A", treatment="D") == "INCONCLUSIVE"


def test_noninferior_but_uncertain_time_returns_suggestive_only() -> None:
    evaluate = _module(); private = _private(
        paired_rmst_improvement_clustered_bootstrap_95_ci=[-5, 20],
        paired_median_improvement_clustered_bootstrap_95_ci=[-2, 15],
    )
    private["criterion_evaluation"] = dict(private["criterion_evaluation"])
    private["criterion_evaluation"]["paired_time_ci_excludes_zero_favorable"] = False
    assert evaluate._decision(private, validation={"sample_complete": True}, base="A", treatment="D") == "SUGGESTIVE_ONLY"


def test_solve_regression_over_five_points_returns_regression_indicated() -> None:
    evaluate = _module(); private = _private(solve_rate_difference=-.06)
    assert evaluate._decision(private, validation={"sample_complete": True}, base="A", treatment="D") == "REGRESSION_INDICATED"


def test_routing_success_is_attributed_to_observed_sol_not_requested_terra() -> None:
    rows = _rows()
    rows[3]["runtime"]["branch_routing_observations"] = [{
        "session_id": "implementation-lane",
        "requested_model": "gpt-5.6-terra", "requested_reasoning": "high",
        "observed_model": "gpt-5.6-sol", "observed_reasoning": "xhigh",
        "routing_classification": "FALLBACK_MATCHED", "solver_success": True,
    }]
    diagnostic = _evaluate(rows)["model_routing_diagnostics"]
    assert diagnostic["performance_by_observed_runtime"] == {
        "gpt-5.6-sol:xhigh": {
            "observations": 1, "solver_successes": 1, "solver_failures": 0,
        },
    }
    assert "gpt-5.6-terra:high" not in diagnostic["performance_by_observed_runtime"]
    assert diagnostic["requested_identity_used_for_attribution"] is False


def test_unknown_observed_sol_request_gets_no_sol_routing_credit() -> None:
    rows = _rows()
    observation = {
        "session_id": "deep-lane",
        "requested_model": "gpt-5.6-sol", "requested_reasoning": "xhigh",
        "observed_model": None, "observed_reasoning": None,
        "routing_classification": "RUNTIME_NOT_OBSERVABLE", "solver_success": True,
    }
    rows[3]["runtime"]["branch_routing_observations"] = [observation]
    diagnostic = _evaluate(rows)["model_routing_diagnostics"]
    assert diagnostic["performance_by_observed_runtime"] == {}
    assert diagnostic["missing_runtime_observations"] == [observation]


def test_routing_mismatch_is_separate_from_validly_routed_solver_failure() -> None:
    rows = _rows()
    mismatch = {
        "session_id": "bounded-lane",
        "requested_model": "gpt-5.6-terra", "requested_reasoning": "high",
        "observed_model": "gpt-5.6-luna", "observed_reasoning": "medium",
        "routing_classification": "ROUTING_MISMATCH", "solver_success": False,
    }
    rows[3]["runtime"]["branch_routing_observations"] = [mismatch]
    diagnostic = _evaluate(rows)["model_routing_diagnostics"]
    assert diagnostic["invalid_model_routing_treatments"] == [mismatch]
    assert diagnostic["performance_by_observed_runtime"] == {}
    assert diagnostic["solver_failures_after_valid_routing"] == []


def test_routing_diagnostic_layer_does_not_change_abcd_treatment_result() -> None:
    rows = _rows()
    baseline = _evaluate(deepcopy(rows))
    rows[3]["runtime"]["branch_routing_observations"] = [{
        "requested_model": "gpt-5.6-terra", "requested_reasoning": "high",
        "observed_model": None, "observed_reasoning": None,
        "routing_classification": "ROUTING_UNSUPPORTED", "solver_success": True,
    }]
    routed = _evaluate(rows)
    assert routed["final_decision"] == baseline["final_decision"]
    assert routed["paired_comparisons"] == baseline["paired_comparisons"]
    assert routed["valid_matched_blocks"] == baseline["valid_matched_blocks"]
