from __future__ import annotations

import argparse
from contextlib import nullcontext
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import sys

from ..benchmark_lock import verify_benchmark_lock
from ..benchmark_manifest import (
    RESOURCE_FIELDS as BENCHMARK_RESOURCE_FIELDS,
    record_benchmark_outcome, record_resource_observation, record_runtime_observation,
)
from ..benchmark_runtime import start_benchmark_attempt, validate_benchmark_completion
from ..benchmark_schedule import (
    begin_schedule_entry, fail_schedule_entry, finish_schedule_entry, generate_schedule,
)
from ..benchmark_telemetry import (
    finish_resource_telemetry, run_resource_telemetry_monitor,
    run_target_health_monitor, sample_resource_telemetry, start_resource_telemetry,
)
from ..challenge import SelectionError, resolve_selector
from ..challenge_scope import remove_challenge_secrets
from ..contest import ContestError, discover_contests, select_contest
from ..evidence import append_finding
from ..doctor import run_doctor
from ..delegation import (
    BranchCandidate, add_branch, branch_utility, init_plan, load_plan,
    record_admission, template_recommendation, update_branch,
    prepare_branch_replacement, confirm_branch_start,
    record_branch_sandbox_ready, record_capacity_admission,
)
from ..events import (
    acknowledge_event, insight_packet, operator_hints, publish_event,
    save_operator_hint, show_events,
)
from ..race import parse_branch_spec, race_board, start_race_plan
from ..resources.scheduler import (
    PRIORITIES as RESOURCE_PRIORITIES, ResourceLedger, ResourceRequest, default_request,
    detect_capacity, infer_workload, parse_bytes, sample_docker_stats,
)
from ..oast import create_oast, oast_events, poll_oast
from ..replay import run_replay
from ..problems import sync_contest_manifest
from ..session_input import parse_session_input, resolve_session_challenge
from ..preflight import (
    load_challenge_preflight, prepare_selected_challenge, prepared_input_bytes,
    prepared_tree_fingerprint,
)
from ..scaffold import initialize_contest
from ..sandbox.network import parse_remotes
from ..sandbox.resources import sandbox_gc, sandbox_status
from ..sandbox.preparation import prepare_sandbox_spec
from ..sandbox.runtime import (
    cleanup, create, execute, export_artifacts, probe_service_connectivity, resize,
)
from ..service import (
    ServiceActor, ServiceSpec, service_build, service_cleanup, service_inspect,
    service_attachment, service_logs, service_plan, service_restart, service_start,
    service_reset, service_status, service_stop,
)
from ..solve_launch import build_solve_launch_context, save_solve_launch_context
from ..triage import finalize_triage, prepare_triage
from ..timeouts import timeout_seconds
from ..transitions import control_loop_tick
from ..tui import resource_panel
from ..workspace import (
    atomic_json, challenge_root, challenge_workspace, initialize_solve_files,
    list_attempts, recover_run_state, resolve_run_raw, resume_attempt, safe_under,
    resolve_exact_run, show_attempt, start_fresh_attempt, state_lock, target_revisions,
)
from ..worker import (
    collect_worker_checkpoints, load_worker_result, merge_worker_checkpoints,
    merge_worker_result_files, save_worker_checkpoint, save_worker_result,
)
from ..verification import record_remote_flag
from ..control import apply_control_action, acknowledge_control_action, load_control_actions
from ..milestones import repair_run_projections, save_milestone
from ..modes import SolveMode, resolve_solve_mode
from ..model_routing import (
    ROUTING_PROFILES, build_routing_contract, recommend_routing_profile,
)
from ..progress import heartbeat_long_compute, record_command
from ..terminal import converge_terminal, record_native_stop, record_submission_result, terminal_status
from ..working_poc import commit_working_poc, resolve_unknown_working_poc
from ..rescue import (
    MODES as RESCUE_MODES, PROFILES as RESCUE_PROFILES,
    close_rescue, prepare_rescue, record_rescue_runtime, show_rescue,
    validate_exact_live_mutable_run, validate_rescue_return,
)
from ..rescue_tool import dispatch as dispatch_rescue_tool


def build_parser() -> argparse.ArgumentParser:
    child_surface = os.environ.get("CTF_OS_SESSION_ROLE") == "child"
    parser = argparse.ArgumentParser(prog="python -m ctf_os.agent_tools", description="Internal JSON tools for the active Sol session")
    parser.add_argument("--repo", default=".")
    commands = parser.add_subparsers(dest="command", required=True)
    init_contest = commands.add_parser(
        "init-contest",
        help="create an incoming contest workspace",
        description="Create a contest workspace using the contest name supplied by the user.",
    )
    init_contest.add_argument(
        "name",
        metavar="CONTEST_NAME",
        help="contest directory and manifest name (for example: 'My CTF 2026')",
    )
    inspect = commands.add_parser("inspect-contest")
    inspect.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    inspect.add_argument("--contest")
    intake = commands.add_parser("intake")
    intake.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    intake.add_argument("--contest")
    triage_prepare = commands.add_parser("triage-prepare")
    triage_prepare.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    triage_prepare.add_argument("--contest")
    triage_finalize = commands.add_parser("triage-finalize")
    triage_finalize.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    triage_finalize.add_argument("--contest")
    triage_finalize.add_argument("--assessments-json", required=True)
    prepare = commands.add_parser(
        "prepare-challenge",
        description=(
            "Prepare one challenge and resume its current attempt by default. "
            "Use --fresh-attempt for independent execution; live mode defaults to adaptive-race with zero active children."
        ),
    )
    prepare.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    prepare.add_argument("selector")
    prepare.add_argument("--contest")
    prepare.add_argument("--session-input-json")
    prepare.add_argument("--fresh-attempt", action="store_true")
    prepare.add_argument("--resume-run-id")
    prepare.add_argument("--attempt-id")
    prepare.add_argument("--transformation-seed")
    prepare.add_argument("--mode", choices=tuple(mode.value for mode in SolveMode))
    prepare.add_argument("--tier", type=int, help="legacy resource/maximum-width hint only")
    if not child_surface:
        attempt_start = commands.add_parser("attempt-start", help="start one isolated fresh attempt")
        attempt_start.add_argument("selector"); attempt_start.add_argument("--contest")
        attempt_start.add_argument("--attempt-id"); attempt_start.add_argument("--transformation-seed")
        attempt_start.add_argument("--mode", choices=tuple(mode.value for mode in SolveMode))
        attempt_start.add_argument("--tier", type=int, help="legacy resource/maximum-width hint only")
        _add_session_args(attempt_start)
        attempt_resume = commands.add_parser("attempt-resume", help="resume current or exact prior attempt")
        attempt_resume.add_argument("selector"); attempt_resume.add_argument("--contest")
        attempt_resume.add_argument("--run-id"); _add_session_args(attempt_resume)
        attempt_list = commands.add_parser("attempt-list", help="list prior isolated attempts")
        attempt_list.add_argument("selector"); attempt_list.add_argument("--contest"); _add_session_args(attempt_list)
        attempt_show = commands.add_parser("attempt-show", help="show an exact prior attempt")
        attempt_show.add_argument("selector"); attempt_show.add_argument("--contest")
        attempt_show.add_argument("--run-id", required=True); _add_session_args(attempt_show)
        benchmark_schedule = commands.add_parser("benchmark-schedule-create")
        benchmark_schedule.add_argument("--challenges-json", required=True)
        benchmark_schedule.add_argument("--randomization-seed", required=True)
        benchmark_schedule.add_argument("--output")
        benchmark_lock = commands.add_parser("benchmark-lock-verify")
        benchmark_lock.add_argument("--lock", required=True); benchmark_lock.add_argument("--signature", required=True)
        benchmark_lock.add_argument("--public-key", required=True); benchmark_lock.add_argument("--key-id", required=True)
        benchmark_start = commands.add_parser(
            "benchmark-start",
            description=(
                "Verify the signed lock and deterministic schedule, then create one exact fresh A/B/C/D attempt. "
                "Tier is not a benchmark treatment and this command never launches a model session."
            ),
        )
        benchmark_start.add_argument("selector"); benchmark_start.add_argument("--contest")
        benchmark_start.add_argument("--schedule", required=True); benchmark_start.add_argument("--entry-id", required=True)
        benchmark_start.add_argument("--lock", required=True); benchmark_start.add_argument("--signature", required=True)
        benchmark_start.add_argument("--public-key", required=True); benchmark_start.add_argument("--key-id", required=True)
        benchmark_start.add_argument("--target-image-digest", required=True)
        benchmark_start.add_argument("--tool-image-digest", required=True)
        benchmark_start.add_argument("--challenge-archive", required=True)
        _add_session_args(benchmark_start)
        benchmark_health = commands.add_parser("benchmark-health-monitor")
        benchmark_health.add_argument("selector"); benchmark_health.add_argument("--contest")
        benchmark_health.add_argument("--run-id", required=True)
        benchmark_health.add_argument("--endpoint-revision", type=int, required=True)
        benchmark_health.add_argument("--duration-seconds", type=float, required=True)
        benchmark_health.add_argument("--cadence-seconds", type=float, default=60.0)
        benchmark_health.add_argument("--timeout-seconds", type=float, default=10.0)
        benchmark_health.add_argument("--semantic-success-token")
        benchmark_health.add_argument("argv", nargs=argparse.REMAINDER)
        _add_session_args(benchmark_health)
        telemetry_start = commands.add_parser("benchmark-telemetry-start")
        telemetry_start.add_argument("selector"); telemetry_start.add_argument("--contest")
        telemetry_start.add_argument("--run-id", required=True)
        telemetry_start.add_argument("--tracked-pid", type=int, action="append", default=[])
        telemetry_start.add_argument("--network-namespace-pid", type=int)
        telemetry_start.add_argument("--container-id", action="append", default=[])
        _add_session_args(telemetry_start)
        telemetry_sample = commands.add_parser("benchmark-telemetry-sample")
        telemetry_sample.add_argument("selector"); telemetry_sample.add_argument("--contest")
        telemetry_sample.add_argument("--run-id", required=True); _add_session_args(telemetry_sample)
        telemetry_monitor = commands.add_parser("benchmark-telemetry-monitor")
        telemetry_monitor.add_argument("selector"); telemetry_monitor.add_argument("--contest")
        telemetry_monitor.add_argument("--run-id", required=True)
        telemetry_monitor.add_argument("--duration-seconds", type=float, required=True)
        telemetry_monitor.add_argument("--cadence-seconds", type=float, default=1.0)
        telemetry_monitor.add_argument("--tracked-pid", type=int, action="append", default=[])
        telemetry_monitor.add_argument("--network-namespace-pid", type=int)
        telemetry_monitor.add_argument("--container-id", action="append", default=[])
        _add_session_args(telemetry_monitor)
        telemetry_finish = commands.add_parser("benchmark-telemetry-finish")
        telemetry_finish.add_argument("selector"); telemetry_finish.add_argument("--contest")
        telemetry_finish.add_argument("--run-id", required=True); _add_session_args(telemetry_finish)
        benchmark_complete = commands.add_parser("benchmark-complete")
        benchmark_complete.add_argument("selector"); benchmark_complete.add_argument("--contest")
        benchmark_complete.add_argument("--run-id", required=True)
        benchmark_complete.add_argument("--schedule", required=True)
        benchmark_complete.add_argument("--entry-id", required=True)
        _add_session_args(benchmark_complete)
        benchmark_outcome = commands.add_parser("benchmark-outcome-record")
        benchmark_outcome.add_argument("selector"); benchmark_outcome.add_argument("--contest")
        benchmark_outcome.add_argument("--run-id", required=True)
        benchmark_outcome.add_argument(
            "--oracle-result", required=True,
            choices=("ACCEPTED", "TIMEOUT", "UNSOLVED", "ENVIRONMENT_FAILURE"),
        )
        benchmark_outcome.add_argument(
            "--cleanup-success", action=argparse.BooleanOptionalAction, required=True,
        )
        benchmark_outcome.add_argument(
            "--terminal-correctness", action=argparse.BooleanOptionalAction, required=True,
        )
        benchmark_outcome.add_argument("--environment-failure", action="store_true")
        benchmark_outcome.add_argument("--invalidation-reason")
        benchmark_outcome.add_argument("--false-candidate-count", type=int, default=0)
        benchmark_outcome.add_argument("--scope-violation-count", type=int, default=0)
        benchmark_outcome.add_argument("--denied-out-of-scope-action-count", type=int, default=0)
        benchmark_outcome.add_argument("--target-failure-duration-seconds", type=float, default=0)
        benchmark_outcome.add_argument("--model-failure-duration-seconds", type=float, default=0)
        benchmark_outcome.add_argument("--environment-failure-duration-seconds", type=float, default=0)
        benchmark_outcome.add_argument(
            "--latency-explained-by-target-or-model-queue",
            action=argparse.BooleanOptionalAction,
        )
        benchmark_outcome.add_argument("--latency-explanation-evidence")
        _add_session_args(benchmark_outcome)
        runtime_observation = commands.add_parser("benchmark-runtime-observation-record")
        runtime_observation.add_argument("selector"); runtime_observation.add_argument("--contest")
        runtime_observation.add_argument("--run-id", required=True)
        runtime_observation.add_argument("--observed-model", required=True)
        runtime_observation.add_argument("--observed-reasoning", required=True)
        runtime_observation.add_argument("--evidence", required=True)
        _add_session_args(runtime_observation)
        resource_observation = commands.add_parser("benchmark-resource-record")
        resource_observation.add_argument("selector"); resource_observation.add_argument("--contest")
        resource_observation.add_argument("--run-id", required=True)
        resource_observation.add_argument("--field", choices=BENCHMARK_RESOURCE_FIELDS, required=True)
        resource_observation.add_argument("--value", type=float)
        resource_observation.add_argument(
            "--observation-status", choices=("OBSERVED", "NOT_OBSERVABLE", "UNAVAILABLE"),
            default="OBSERVED",
        )
        resource_observation.add_argument("--reason")
        _add_session_args(resource_observation)
        repair_run_parser = commands.add_parser("repair-run")
        repair_run_parser.add_argument("selector"); repair_run_parser.add_argument("--contest")
        repair_run_parser.add_argument("--run-id"); _add_session_args(repair_run_parser)
        repair_projection_parser = commands.add_parser("repair-projections")
        repair_projection_parser.add_argument("selector"); repair_projection_parser.add_argument("--contest")
        repair_projection_parser.add_argument("--run-id"); _add_session_args(repair_projection_parser)
        rescue_prepare = commands.add_parser(
            "rescue-prepare",
            description=(
                "Prepare an exact LIVE run for a manually started Claude rescue. "
                "This command never launches Claude or another model process."
            ),
        )
        rescue_prepare.add_argument("selector"); rescue_prepare.add_argument("--contest")
        rescue_prepare.add_argument("--run-id", required=True)
        rescue_prepare.add_argument("--mode", required=True, choices=tuple(sorted(RESCUE_MODES)))
        rescue_prepare.add_argument("--profile", choices=tuple(sorted(RESCUE_PROFILES)), default="standard")
        rescue_prepare.add_argument("--objective", required=True)
        rescue_prepare.add_argument("--current-blocker", required=True)
        rescue_prepare.add_argument("--leading-exploit-path")
        rescue_prepare.add_argument(
            "--avoid", "--path-not-to-repeat", dest="path_not_to_repeat",
            action="append", default=[],
        )
        rescue_prepare.add_argument("--operation-id", required=True)
        rescue_prepare.add_argument("--lead-model")
        _add_session_args(rescue_prepare)
        rescue_show = commands.add_parser("rescue-show")
        rescue_show.add_argument("selector"); rescue_show.add_argument("--contest")
        rescue_show.add_argument("--run-id", required=True)
        rescue_show.add_argument("--rescue-id", required=True)
        _add_session_args(rescue_show)
        rescue_runtime = commands.add_parser("rescue-runtime-record")
        rescue_runtime.add_argument("selector"); rescue_runtime.add_argument("--contest")
        rescue_runtime.add_argument("--run-id", required=True)
        rescue_runtime.add_argument("--rescue-id", required=True)
        rescue_runtime.add_argument("--observed-model", required=True)
        rescue_runtime.add_argument("--evidence", required=True)
        rescue_runtime.add_argument(
            "--fallback-observed", action=argparse.BooleanOptionalAction,
            default=None,
        )
        _add_session_args(rescue_runtime)
        rescue_validate = commands.add_parser("rescue-return-validate")
        rescue_validate.add_argument("selector"); rescue_validate.add_argument("--contest")
        rescue_validate.add_argument("--run-id", required=True)
        rescue_validate.add_argument("--rescue-id", required=True)
        _add_session_args(rescue_validate)
        rescue_close = commands.add_parser("rescue-close")
        rescue_close.add_argument("selector"); rescue_close.add_argument("--contest")
        rescue_close.add_argument("--run-id", required=True)
        rescue_close.add_argument("--rescue-id", required=True)
        rescue_close.add_argument(
            "--outcome", required=True,
            choices=("integrated", "refuted", "no-new-path", "flag-obtained", "manual"),
        )
        rescue_close.add_argument("--evidence-receipt-id")
        _add_session_args(rescue_close)
    rescue_tool_status = commands.add_parser("rescue-tool-status", help=argparse.SUPPRESS)
    rescue_exec = commands.add_parser("rescue-exec", help=argparse.SUPPRESS)
    rescue_exec.add_argument("--timeout", type=int)
    rescue_exec.add_argument("--timeout-profile", default="quick_probe")
    rescue_exec.add_argument("argv", nargs=argparse.REMAINDER)
    rescue_import = commands.add_parser("rescue-import-input", help=argparse.SUPPRESS)
    rescue_import.add_argument("path", nargs="?")
    rescue_import.add_argument("--all-bounded", action="store_true")
    resource_status = commands.add_parser("resource-status")
    resource_status.add_argument("--contest")
    if not child_surface:
        resource_plan = commands.add_parser("resource-plan")
        resource_plan.add_argument("selector"); resource_plan.add_argument("--contest"); _add_session_args(resource_plan)
        rebalance = commands.add_parser("scheduler-rebalance")
        rebalance.add_argument("selector", nargs="?"); rebalance.add_argument("--contest")
        rebalance.add_argument("--apply", dest="apply", action="store_true")
        rebalance.add_argument("--dry-run", dest="apply", action="store_false")
        rebalance.set_defaults(apply=True)
        _add_session_args(rebalance)
        sandbox_resize = commands.add_parser("sandbox-resize")
        sandbox_resize.add_argument("metadata"); sandbox_resize.add_argument("--cpus", type=float); sandbox_resize.add_argument("--memory")
        _add_session_args(sandbox_resize)
    resource_request = commands.add_parser("resource-request")
    resource_request.add_argument("selector"); resource_request.add_argument("--contest")
    resource_request.add_argument("--workload-class"); resource_request.add_argument("--priority", choices=RESOURCE_PRIORITIES)
    resource_request.add_argument("--command", dest="workload_commands", action="append", default=[])
    resource_request.add_argument("--min-cpus", type=float); resource_request.add_argument("--preferred-cpus", type=float); resource_request.add_argument("--max-cpus", type=float)
    resource_request.add_argument("--min-memory"); resource_request.add_argument("--preferred-memory"); resource_request.add_argument("--max-memory"); resource_request.add_argument("--storage")
    resource_request.add_argument("--gpu-required", action="store_true"); resource_request.add_argument("--gpu-preferred", action="store_true"); resource_request.add_argument("--gpu-memory")
    resource_request.add_argument("--parallelizable", action=argparse.BooleanOptionalAction, default=None)
    resource_request.add_argument("--elastic", action=argparse.BooleanOptionalAction, default=None)
    resource_request.add_argument("--preemptible", action=argparse.BooleanOptionalAction, default=None)
    _add_session_args(resource_request)
    resource_update = commands.add_parser("resource-update")
    resource_update.add_argument("selector"); resource_update.add_argument("--contest")
    resource_update.add_argument("--priority", choices=RESOURCE_PRIORITIES); resource_update.add_argument("--workload-class")
    resource_update.add_argument("--progress-json"); resource_update.add_argument("--state")
    resource_update.add_argument("--parallelizable", action=argparse.BooleanOptionalAction, default=None)
    _add_session_args(resource_update)
    resource_release = commands.add_parser("resource-release")
    resource_release.add_argument("selector"); resource_release.add_argument("--contest"); resource_release.add_argument("--reason", required=True)
    _add_session_args(resource_release)
    resource_history = commands.add_parser("resource-history")
    resource_history.add_argument("selector"); resource_history.add_argument("--contest"); resource_history.add_argument("--limit", type=int, default=200)
    _add_session_args(resource_history)
    resource_sample = commands.add_parser("resource-sample")
    resource_sample.add_argument("selector"); resource_sample.add_argument("--contest"); resource_sample.add_argument("--sample-json"); resource_sample.add_argument("--metadata")
    _add_session_args(resource_sample)
    if not child_surface:
        race_start = commands.add_parser(
            "race-plan-start",
            description=(
                "Append branch intents for an explicit solve mode. Only lineage RUNNING counts as active width; "
                "legacy tier is a compatibility/resource hint."
            ),
        )
        race_start.add_argument("selector"); race_start.add_argument("--contest")
        race_start.add_argument("--mode", choices=tuple(mode.value for mode in SolveMode))
        race_start.add_argument("--tier", type=int, help="legacy resource/maximum-width hint only")
        race_start.add_argument("--tier-reason", default="competition-first first-to-flag race")
        race_start.add_argument("--branch-spec"); race_start.add_argument("--threshold", type=float, default=.95)
        _add_session_args(race_start)
        race_show = commands.add_parser("race-board")
        race_show.add_argument("selector"); race_show.add_argument("--contest"); _add_session_args(race_show)
        plan_init = commands.add_parser("delegation-plan-init")
        plan_init.add_argument("selector"); plan_init.add_argument("--contest")
        plan_init.add_argument("--tier", required=True, type=int); plan_init.add_argument("--tier-reason", required=True)
        _add_session_args(plan_init)
        plan_show = commands.add_parser("delegation-plan-show")
        plan_show.add_argument("selector"); plan_show.add_argument("--contest"); _add_session_args(plan_show)
        template_show = commands.add_parser("delegation-template-show")
        template_show.add_argument("selector"); template_show.add_argument("--contest"); template_show.add_argument("--tier", required=True, type=int); _add_session_args(template_show)
        admit = commands.add_parser("branch-admit")
        _add_branch_candidate_args(admit); admit.add_argument("--threshold", type=float, default=.95); admit.add_argument("--purpose"); admit.add_argument("--race-override-reason"); _add_delegation_controller_args(admit)
        branch_add = commands.add_parser("delegation-branch-add")
        _add_branch_candidate_args(branch_add)
        branch_add.add_argument("--evidence-contract", action="append", required=True)
        branch_add.add_argument("--success-condition", required=True); branch_add.add_argument("--kill-condition", required=True)
        branch_add.add_argument("--maximum-steps", type=int, required=True); branch_add.add_argument("--budget-seconds", type=int, required=True)
        branch_add.add_argument("--requested-model-role", required=True); branch_add.add_argument("--requested-reasoning", required=True)
        _add_routing_args(branch_add)
        branch_add.add_argument("--purpose"); _add_delegation_controller_args(branch_add)
        branch_update = commands.add_parser("delegation-branch-update")
        branch_update.add_argument("selector"); branch_update.add_argument("--contest"); branch_update.add_argument("--session-id", required=True)
        branch_update.add_argument("--status", required=True); branch_update.add_argument("--observed-runtime-model"); branch_update.add_argument("--observed-reasoning")
        branch_update.add_argument("--runtime-observation-evidence")
        branch_update.add_argument("--pinning-verified", action="store_true", default=None); branch_update.add_argument("--session-role", choices=("sol", "child"), default="sol")
        branch_update.add_argument("--parent-session-id", default=os.environ.get("CTF_OS_PARENT_SESSION_ID", "sol-main")); branch_update.add_argument("--recover-stale", action="store_true")
        utility = commands.add_parser("branch-utility")
        utility.add_argument("selector"); utility.add_argument("--contest"); utility.add_argument("--session-id", required=True)
        utility.add_argument("--session-role", choices=("sol", "child"), default="sol"); utility.add_argument("--parent-session-id", default=os.environ.get("CTF_OS_PARENT_SESSION_ID", "sol-main")); utility.add_argument("--recover-stale", action="store_true")
        replacement = commands.add_parser("branch-replacement-prepare")
        _add_branch_candidate_args(replacement)
        replacement.add_argument("--superseded-branch-id", required=True)
        replacement.add_argument("--kill-reason", required=True); replacement.add_argument("--distinct-mechanism-proof", required=True)
        replacement.add_argument("--triggering-receipt-id", required=True)
        replacement.add_argument("--evidence-contract", action="append", required=True)
        replacement.add_argument("--success-condition", required=True); replacement.add_argument("--kill-condition", required=True)
        replacement.add_argument("--maximum-steps", type=int, required=True); replacement.add_argument("--budget-seconds", type=int, required=True)
        replacement.add_argument("--requested-model-role", required=True); replacement.add_argument("--requested-reasoning", required=True)
        _add_routing_args(replacement)
        _add_delegation_controller_args(replacement)
        start_confirm = commands.add_parser("branch-start-confirm")
        start_confirm.add_argument("selector"); start_confirm.add_argument("--contest")
        start_confirm.add_argument("--replacement-request-id", default="initial-race"); start_confirm.add_argument("--session-id", required=True)
        start_confirm.add_argument("--native-session-observed", required=True); start_confirm.add_argument("--runtime-observation-evidence", required=True)
        start_confirm.add_argument("--native-start-operation-id", required=True)
        start_confirm.add_argument("--observed-model"); start_confirm.add_argument("--observed-reasoning")
        start_confirm.add_argument(
            "--runtime-observation-status", required=True,
            choices=("OBSERVED", "NOT_OBSERVABLE", "UNSUPPORTED", "CONFLICT"),
        )
        start_confirm.add_argument("--sandbox-metadata-path", required=True)
        start_confirm.add_argument("--session-role", choices=("sol",), default="sol"); start_confirm.add_argument("--parent-session-id", default="sol-main"); start_confirm.add_argument("--recover-stale", action="store_true")
    if not child_surface:
        sandbox_create = commands.add_parser("sandbox-create")
        sandbox_create.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
        sandbox_create.add_argument("selector")
        sandbox_create.add_argument("--contest")
        sandbox_create.add_argument("--branch", required=True)
        sandbox_create.add_argument("--image")
        sandbox_create.add_argument("--resource-profile")
        sandbox_create.add_argument(
            "--service", action="store_true",
            help="require attachment to the existing managed service (active services attach automatically)",
        )
        _add_session_args(sandbox_create, default_role="child")
    sandbox_exec = commands.add_parser("sandbox-exec")
    sandbox_exec.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    sandbox_exec.add_argument("--metadata", dest="metadata_option")
    sandbox_exec.add_argument("--timeout", type=int, default=300)
    sandbox_exec.add_argument("--timeout-profile")
    sandbox_exec.add_argument("--retain-on-timeout", action=argparse.BooleanOptionalAction, default=None)
    sandbox_exec.add_argument("argv", nargs=argparse.REMAINDER)
    _add_session_args(sandbox_exec)
    sandbox_cleanup = commands.add_parser("sandbox-cleanup")
    sandbox_cleanup.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    sandbox_cleanup.add_argument("metadata")
    _add_session_args(sandbox_cleanup)
    sandbox_export = commands.add_parser("sandbox-export")
    sandbox_export.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    sandbox_export.add_argument("metadata")
    _add_session_args(sandbox_export)
    sandbox_status_parser = commands.add_parser("sandbox-status")
    _add_session_args(sandbox_status_parser)
    if not child_surface:
        sandbox_gc_parser = commands.add_parser("sandbox-gc")
        _add_session_args(sandbox_gc_parser)
    doctor_parser = commands.add_parser("doctor")
    doctor_parser.add_argument("selector", nargs="?")
    doctor_parser.add_argument("--contest")
    doctor_parser.add_argument("--run-id")
    doctor_parser.add_argument("--repair-run-projections", action="store_true")
    _add_session_args(doctor_parser)
    service_commands = (
        ("service-plan", "service-status", "service-logs", "service-inspect")
        if child_surface else
        ("service-plan", "service-build", "service-start", "service-restart", "service-status",
         "service-logs", "service-inspect", "service-stop", "service-cleanup")
    )
    for name in service_commands:
        service = commands.add_parser(name)
        service.add_argument("selector")
        service.add_argument("--contest")
        _add_session_args(service)
    private_service_commands = (
        "branch-service-plan", "branch-service-build", "branch-service-start",
        "branch-service-restart", "branch-service-status", "branch-service-logs",
        "branch-service-reset", "branch-service-inspect", "branch-service-stop", "branch-service-cleanup",
    )
    for name in private_service_commands:
        service = commands.add_parser(name)
        service.add_argument("selector"); service.add_argument("--contest")
        service.add_argument("--branch", required=True)
        _add_session_args(service, default_role="child")

    event_publish = commands.add_parser("race-event-publish")
    event_publish.add_argument("selector"); event_publish.add_argument("--contest")
    event_publish.add_argument("--type", required=True); event_publish.add_argument("--priority", default="NORMAL")
    event_publish.add_argument("--summary", required=True); event_publish.add_argument("--evidence", action="append", default=[])
    event_publish.add_argument("--artifact", action="append", default=[]); event_publish.add_argument("--useful-for", default="")
    event_publish.add_argument("--recommended-action", default=""); event_publish.add_argument("--event-id")
    event_publish.add_argument("--primitive-json")
    _add_session_args(event_publish)
    milestone = commands.add_parser("milestone-save")
    milestone.add_argument("selector"); milestone.add_argument("--contest"); milestone.add_argument("--type", required=True)
    milestone.add_argument("--summary", required=True); milestone.add_argument("--evidence", action="append", default=[])
    milestone.add_argument("--artifact", action="append", default=[]); milestone.add_argument("--output", default="")
    milestone.add_argument("--exploit-proximity", type=float, default=0.0); milestone.add_argument("--details-json")
    milestone.add_argument("--candidate"); milestone.add_argument("--source-type", default="STATIC_ANALYSIS")
    milestone.add_argument("--validation-method", default="UNVALIDATED"); milestone.add_argument("--confidence", default="LOW")
    milestone.add_argument("--operation-id")
    milestone.add_argument("argv", nargs="*"); _add_session_args(milestone)
    progress_command = commands.add_parser("progress-command")
    progress_command.add_argument("selector"); progress_command.add_argument("--contest"); progress_command.add_argument("argv", nargs="*"); _add_session_args(progress_command)
    heartbeat = commands.add_parser("long-compute-heartbeat")
    heartbeat.add_argument("selector"); heartbeat.add_argument("--contest"); heartbeat.add_argument("--receipt-id", required=True)
    heartbeat.add_argument("--artifact-changed", action="store_true"); heartbeat.add_argument("--completion-signal-observed", action="store_true"); _add_session_args(heartbeat)
    events_show = commands.add_parser("race-events-show")
    events_show.add_argument("selector"); events_show.add_argument("--contest"); events_show.add_argument("--since")
    events_show.add_argument("--priority", action="append", default=[]); events_show.add_argument("--type", action="append", default=[])
    _add_session_args(events_show)
    event_ack = commands.add_parser("race-events-ack")
    event_ack.add_argument("selector"); event_ack.add_argument("--contest"); event_ack.add_argument("--event-id", required=True)
    _add_session_args(event_ack)
    packet = commands.add_parser("race-insight-packet")
    packet.add_argument("selector"); packet.add_argument("--contest"); packet.add_argument("--target-session-id", required=True)
    packet.add_argument("--limit", type=int, default=20); _add_session_args(packet)
    oast_create = commands.add_parser("oast-create")
    oast_create.add_argument("selector"); oast_create.add_argument("--contest")
    oast_create.add_argument("--branch", required=True); oast_create.add_argument("--provider-url", required=True)
    _add_session_args(oast_create)
    oast_poll = commands.add_parser("oast-poll")
    oast_poll.add_argument("selector"); oast_poll.add_argument("--contest"); oast_poll.add_argument("--oast-id", required=True)
    _add_session_args(oast_poll)
    oast_show = commands.add_parser("oast-events")
    oast_show.add_argument("selector"); oast_show.add_argument("--contest"); oast_show.add_argument("--oast-id", required=True)
    _add_session_args(oast_show)
    if not child_surface:
        hint = commands.add_parser("operator-hint-save")
        hint.add_argument("selector"); hint.add_argument("--contest"); hint.add_argument("--summary", required=True)
        hint.add_argument("--target", action="append", default=[]); _add_session_args(hint)
        hints = commands.add_parser("operator-hints-show")
        hints.add_argument("selector"); hints.add_argument("--contest"); _add_session_args(hints)
        receipt = commands.add_parser("flag-receipt-save")
        receipt.add_argument("selector"); receipt.add_argument("--contest"); receipt.add_argument("--branch", required=True)
        receipt.add_argument("--host", required=True); receipt.add_argument("--port", type=int, required=True)
        receipt.add_argument("--protocol", required=True); receipt.add_argument("--network-observed", action="store_true")
        receipt.add_argument("--output", required=True); receipt.add_argument("--candidate", required=True)
        receipt.add_argument("--exploit-artifact", required=True); receipt.add_argument("argv", nargs="*")
        _add_session_args(receipt)
        working_poc = commands.add_parser("working-poc-commit")
        working_poc.add_argument("selector"); working_poc.add_argument("--contest")
        working_poc.add_argument("--run-id", required=True); working_poc.add_argument("--branch", required=True)
        working_poc.add_argument("--metadata", required=True)
        working_poc.add_argument("--local-receipt-id", required=True)
        working_poc.add_argument("--exploit-artifact", required=True)
        working_poc.add_argument("--target-index", required=True, type=int)
        working_poc.add_argument("--success-condition", required=True)
        working_poc.add_argument("--kill-condition", required=True)
        working_poc.add_argument("--operation-id", required=True)
        working_poc.add_argument("--timeout", type=int, default=300)
        working_poc.add_argument("argv", nargs=argparse.REMAINDER); _add_session_args(working_poc)
        resolve_poc = commands.add_parser("working-poc-resolve-unknown")
        resolve_poc.add_argument("selector"); resolve_poc.add_argument("--contest")
        resolve_poc.add_argument("--run-id", required=True)
        resolve_poc.add_argument("--operation-id", required=True)
        resolve_poc.add_argument(
            "--decision", required=True,
            choices=("RECORD_RESULT", "ABANDON", "AUTHORIZE_RETRY"),
        )
        resolve_poc.add_argument("--receipt-json", required=True)
        resolve_poc.add_argument("--new-operation-id")
        _add_session_args(resolve_poc)
        submission = commands.add_parser("submission-result")
        submission.add_argument("selector"); submission.add_argument("--contest")
        submission.add_argument("--run-id", required=True); submission.add_argument("--candidate-id", required=True)
        submission.add_argument("--result", required=True, choices=("accepted", "wrong")); _add_session_args(submission)
        native_stop = commands.add_parser("branch-native-stop")
        native_stop.add_argument("selector"); native_stop.add_argument("--contest"); native_stop.add_argument("--run-id", required=True)
        native_stop.add_argument("--branch", required=True); native_stop.add_argument("--receipt-json", required=True); _add_session_args(native_stop)
        terminal_show = commands.add_parser("terminal-status")
        terminal_show.add_argument("selector"); terminal_show.add_argument("--contest"); terminal_show.add_argument("--run-id"); _add_session_args(terminal_show)
        control_show = commands.add_parser("control-actions-show")
        control_show.add_argument("selector"); control_show.add_argument("--contest"); _add_session_args(control_show)
        control_ack = commands.add_parser("control-action-ack")
        control_ack.add_argument("selector"); control_ack.add_argument("--contest"); control_ack.add_argument("--action-id", required=True)
        control_ack.add_argument("--status", required=True, choices=("declined", "superseded", "expired")); _add_session_args(control_ack)
        control_apply = commands.add_parser("control-action-apply")
        control_apply.add_argument("selector"); control_apply.add_argument("--contest")
        control_apply.add_argument("--action-id", required=True)
        control_apply.add_argument("--receipt-json", required=True); _add_session_args(control_apply)
    if not child_surface:
        replay = commands.add_parser("replay")
        replay.add_argument("selector")
        replay.add_argument("--contest")
        _add_session_args(replay)
        finding = commands.add_parser("record-finding")
        finding.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
        finding.add_argument("selector")
        finding.add_argument("--contest")
        finding.add_argument("--branch", required=True)
        finding.add_argument("--status", required=True, choices=("supported", "rejected", "inconclusive"))
        finding.add_argument("--summary", required=True)
        finding.add_argument("--evidence", required=True)
        _add_session_args(finding)
    worker_result = commands.add_parser("worker-result-save")
    worker_result.add_argument("selector")
    worker_result.add_argument("--contest")
    worker_result.add_argument("--branch", required=True)
    worker_result.add_argument("--result-json", required=True)
    _add_session_args(worker_result, default_role="child")
    checkpoint = commands.add_parser("worker-checkpoint-save")
    checkpoint.add_argument("selector"); checkpoint.add_argument("--contest")
    checkpoint.add_argument("--type", required=True); checkpoint.add_argument("--summary", required=True)
    checkpoint.add_argument("--evidence", action="append", default=[]); checkpoint.add_argument("--artifact", action="append", default=[])
    checkpoint.add_argument("--useful-for", default=""); checkpoint.add_argument("--recommended-action", default=""); checkpoint.add_argument("--confidence", type=float, required=True)
    checkpoint.add_argument("--current-exploit-hypothesis", default="")
    checkpoint.add_argument("--decisive-experiment-performed", default="")
    checkpoint.add_argument("--observed-result", default="")
    checkpoint.add_argument("--exploit-proximity", type=float, default=0.0)
    checkpoint.add_argument("--next-exploit-action", default="")
    checkpoint.add_argument("--decision", choices=("KILL", "CONTINUE", "PROMOTE"), default="CONTINUE")
    checkpoint.add_argument("--working-poc-present", action="store_true")
    checkpoint.add_argument("--remote-ready", action="store_true")
    checkpoint.add_argument("--research-drift-detected", action="store_true")
    checkpoint.add_argument("--repeated-command", action="store_true")
    checkpoint.add_argument("--sibling-insight-applied", action="store_true")
    checkpoint.add_argument("--hypothesis-family-changed", action="store_true")
    checkpoint.add_argument("--primitive-json")
    _add_session_args(checkpoint, default_role="child")
    if not child_surface:
        worker_merge = commands.add_parser("worker-results-merge")
        worker_merge.add_argument("selector")
        worker_merge.add_argument("--contest")
        _add_session_args(worker_merge)
        checkpoint_merge = commands.add_parser("worker-checkpoints-merge")
        checkpoint_merge.add_argument("selector"); checkpoint_merge.add_argument("--contest"); _add_session_args(checkpoint_merge)
        checkpoint_show = commands.add_parser("worker-checkpoints-show")
        checkpoint_show.add_argument("selector"); checkpoint_show.add_argument("--contest"); checkpoint_show.add_argument("--since-sequence", type=int, default=0); _add_session_args(checkpoint_show)
    return parser


def _add_branch_candidate_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("selector"); parser.add_argument("--contest"); parser.add_argument("--session-id", required=True)
    parser.add_argument("--role", required=True); parser.add_argument("--hypothesis-family", required=True); parser.add_argument("--hypothesis", required=True)
    parser.add_argument("--scope", required=True); parser.add_argument("--tool-strategy", required=True); parser.add_argument("--expected-artifact", action="append", required=True)


def _add_routing_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--routing-profile", choices=tuple(sorted(ROUTING_PROFILES)))
    parser.add_argument("--routing-reason")
    parser.add_argument("--routing-evidence", action="append", default=[])
    parser.add_argument("--fallback-profile", choices=tuple(sorted(ROUTING_PROFILES)))
    parser.add_argument("--fallback-reason")
    parser.add_argument("--routing-context-json")


def _add_delegation_controller_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--session-role", choices=("sol", "child"), default=os.environ.get("CTF_OS_SESSION_ROLE", "sol"))
    parser.add_argument("--parent-session-id", default=os.environ.get("CTF_OS_PARENT_SESSION_ID", "sol-main"))
    parser.add_argument("--recover-stale", action="store_true")


def _add_session_args(parser: argparse.ArgumentParser, *, default_role: str = "sol") -> None:
    parser.add_argument("--session-id", default=os.environ.get("CTF_OS_SESSION_ID"))
    parser.add_argument(
        "--session-role", choices=("sol", "child"),
        default=os.environ.get("CTF_OS_SESSION_ROLE", default_role),
    )
    parser.add_argument("--parent-session-id", default=os.environ.get("CTF_OS_PARENT_SESSION_ID", "sol-main"))
    parser.add_argument("--recover-stale", action="store_true")


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    direct_argv_commands = {
        "milestone-save", "progress-command", "flag-receipt-save", "working-poc-commit",
        "rescue-exec",
    }
    separator = raw_argv.index("--") if "--" in raw_argv else -1
    controls = raw_argv[:separator] if separator >= 0 else raw_argv
    direct_command = next((name for name in direct_argv_commands if name in controls), None)
    if separator >= 0 and direct_command is not None:
        command_argv = raw_argv[separator + 1:]
        args = parser.parse_args(controls)
        args.argv = command_argv
    else:
        args = parser.parse_args(raw_argv)
    root = Path(args.repo).resolve()
    try:
        result = dispatch(root, args)
    except Exception as exc:
        payload: dict[str, object] = {"ok": False, "error": str(exc), "error_type": type(exc).__name__}
        if isinstance(exc, SelectionError):
            payload["candidates"] = list(exc.candidates)
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 2
    command_ok = not (
        args.command == "doctor" and isinstance(result, dict) and result.get("ok") is False
    )
    print(json.dumps({"ok": command_ok, "result": result}, ensure_ascii=False, sort_keys=True))
    return 0 if command_ok else 1


def dispatch(root: Path, args: argparse.Namespace) -> object:
    if args.command in {"rescue-tool-status", "rescue-exec", "rescue-import-input"}:
        fixed = {
            "repo": os.environ.get("CTF_OS_RESCUE_REPO"),
            "metadata": os.environ.get("CTF_OS_RESCUE_METADATA"),
            "run_id": os.environ.get("CTF_OS_RESCUE_RUN_ID"),
            "rescue_id": os.environ.get("CTF_OS_RESCUE_ID"),
            "packet_digest": os.environ.get("CTF_OS_RESCUE_PACKET_DIGEST"),
        }
        if not all(fixed.values()) or Path(str(fixed["repo"])).resolve() != root:
            raise ValueError("internal rescue tool command requires fixed wrapper identity")
        command = {
            "rescue-tool-status": "status",
            "rescue-exec": "exec",
            "rescue-import-input": "import-input",
        }[args.command]
        return dispatch_rescue_tool(argparse.Namespace(
            **fixed,
            command=command,
            timeout=getattr(args, "timeout", None),
            timeout_profile=getattr(args, "timeout_profile", "quick_probe"),
            argv=getattr(args, "argv", []),
            path=getattr(args, "path", None),
            all_bounded=getattr(args, "all_bounded", False),
        ))
    if args.command == "init-contest":
        return initialize_contest(root, args.name)
    if args.command == "doctor":
        result = run_doctor(root)
        if args.selector:
            manifest = select_contest(discover_contests(root / "incoming"), args.contest)
            challenge = resolve_session_challenge(root, manifest, args.selector)
            selected = resolve_run_raw(
                challenge_root(root, manifest, challenge), run_id=args.run_id,
            )
            if args.repair_run_projections:
                _require_sol(args, "Only Sol may repair a selected run during doctor.")
                state = recover_run_state(selected, force=True)
                projection = repair_run_projections(
                    selected, declared_remote=bool(challenge.remotes),
                )
                result["selected_run"] = {
                    "run_id": selected.name, "state": state,
                    "projection_repair": projection,
                }
            else:
                result["selected_run"] = _doctor_selected_run(selected)
        elif args.run_id or args.repair_run_projections:
            raise ValueError("doctor run options require an exact challenge selector")
        return result
    if args.command == "sandbox-status":
        return sandbox_status()
    if args.command == "resource-status":
        capacity = detect_capacity(workspace=root)
        payload = capacity.to_dict()
        if args.contest:
            payload["contest"] = args.contest
        return payload
    if args.command == "sandbox-resize":
        _require_sol(args, "Only the parent Sol session may apply sandbox resize operations.")
        metadata = _load_metadata(root, args.metadata)
        session_id, role = _caller(args, metadata=metadata)
        _validate_resize_budget(metadata, args.cpus, args.memory, detect_capacity(workspace=root).to_dict())
        try:
            return resize(metadata, cpus=args.cpus, memory=args.memory, session_id=session_id, session_role=role)
        except Exception as exc:
            resource_ledger = ResourceLedger(Path(str(metadata["branch_root"])).parents[1])
            if resource_ledger.state_path.exists():
                resource_ledger.append_history(
                    "RESIZE_FAILURE", str(metadata.get("session_id") or metadata.get("branch")),
                    {"requested_cpus": args.cpus, "requested_memory": args.memory, "reason": str(exc)},
                )
            raise
    if args.command == "scheduler-rebalance" and args.selector is None:
        _require_sol(args, "Only the parent Sol session may apply a global scheduler rebalance.")
        return _rebalance_contest(root, args.contest, apply=args.apply)
    if args.command == "sandbox-gc":
        _require_sol(args, "Only the parent Sol session may garbage-collect managed sandboxes.")
        expired = _cleanup_expired_timeout_retention(root, args.parent_session_id)
        result = sandbox_gc()
        result["expired_timeout_retention"] = expired
        return result
    if args.command == "inspect-contest":
        sync_contest_manifest(root, args.contest)
        contest = select_contest(discover_contests(root / "incoming"), args.contest)
        return contest.to_dict()
    if args.command == "intake":
        from ..intake import run_intake

        payload = run_intake(root, args.contest)
        contest = payload["contest"]
        return {
            "contest": contest["name"], "summary": payload["summary"],
            "index_path": str(root / "output" / contest["slug"] / "intake.json"),
            "markdown_path": str(root / "output" / contest["slug"] / "INTAKE.md"),
            "challenges": [
                {"number": r["number"], "key": r["key"], "status": r["status"], "blockers": r["blockers"]}
                for r in payload["challenges"]
            ],
        }
    if args.command == "triage-prepare":
        return prepare_triage(root, args.contest)
    if args.command == "triage-finalize":
        try:
            assessments = json.loads(args.assessments_json)
        except json.JSONDecodeError as exc:
            raise ValueError("--assessments-json must be valid JSON") from exc
        return finalize_triage(root, args.contest, assessments)
    if args.command == "benchmark-schedule-create":
        challenges = json.loads(args.challenges_json)
        if not isinstance(challenges, list):
            raise ValueError("--challenges-json must contain an array")
        schedule = generate_schedule(challenges, randomization_seed=args.randomization_seed)
        if args.output:
            output = Path(args.output).resolve()
            if output.is_symlink():
                raise ValueError("benchmark schedule output must not be a symlink")
            atomic_json(output, schedule)
            schedule["output"] = str(output)
        return schedule
    if args.command == "benchmark-lock-verify":
        return verify_benchmark_lock(
            Path(args.lock).resolve(), Path(args.signature).resolve(),
            {args.key_id: Path(args.public_key).resolve()},
        )
    if args.command == "sandbox-exec":
        misplaced = {
            "--timeout", "--timeout-profile", "--session-id", "--session-role",
            "--parent-session-id", "--recover-stale", "--metadata",
            "--retain-on-timeout", "--no-retain-on-timeout",
        }
        if any(token in misplaced for token in args.argv):
            raise ValueError(
                "Invalid sandbox-exec option placement. Place --timeout-profile, --session-id, "
                "and other CTF-OS options before `--`. Everything after `--` is the container command."
            )
        raw_command = list(args.argv)
        metadata_path = args.metadata_option
        if metadata_path is None and raw_command and raw_command[0] != "--":
            metadata_path = raw_command.pop(0)  # backward-compatible positional metadata
        if not metadata_path:
            raise ValueError("sandbox-exec requires --metadata before `--`")
        metadata = _load_metadata(root, metadata_path)
        execution_state = json.loads((Path(str(metadata["branch_root"])).parents[1] / "STATE.json").read_text(encoding="utf-8"))
        if execution_state.get("sealed"):
            raise ValueError("sealed run is immutable; only terminal cleanup is allowed")
        command = raw_command
        if command and command[0] == "--":
            command.pop(0)
        session_id, role = _caller(args, metadata=metadata)
        timeout = timeout_seconds(args.timeout_profile) if args.timeout_profile else args.timeout
        result = execute(
            metadata, command, timeout, session_id=session_id, session_role=role,
            timeout_profile=args.timeout_profile, retain_on_timeout=args.retain_on_timeout,
        )
        result["progress_gate"] = record_command(
            Path(str(metadata["branch_root"])).parents[1], session_id=session_id,
            command_argv=command, category=str(metadata.get("category") or "misc"),
        )
        if result["timed_out"]:
            _update_branch_state(
                Path(str(metadata["branch_root"])).parents[1], str(metadata["branch"]),
                str(result.get("timeout_status") or "TIMED_OUT_CLEANED"), str(metadata["metadata_path"]),
            )
        return result
    if args.command == "sandbox-cleanup":
        metadata = _load_metadata(root, args.metadata)
        session_id, role = _caller(args, metadata=metadata)
        result = cleanup(metadata, session_id=session_id, session_role=role)
        result["challenge_secrets_cleanup"] = remove_challenge_secrets(Path(str(metadata["branch_root"])))
        _update_branch_state(Path(str(metadata["branch_root"])).parents[1], str(metadata["branch"]), "CLEANED", str(metadata["metadata_path"]))
        return result
    if args.command == "sandbox-export":
        metadata = _load_metadata(root, args.metadata)
        session_id, role = _caller(args, metadata=metadata)
        return export_artifacts(metadata, session_id=session_id, session_role=role)

    if args.command == "prepare-challenge":
        if args.resume_run_id and (
            args.fresh_attempt or args.attempt_id or args.transformation_seed
        ):
            raise ValueError("--resume-run-id conflicts with fresh-attempt identity options")
        selected_mode = resolve_solve_mode(args.mode, tier=args.tier)
        manifest, challenge, record = _prepare_challenge_same_session(
            root, args.contest, args.selector, args.session_input_json,
        )
        workspace = challenge_root(root, manifest, challenge)
        solve_root = (
            resume_attempt(workspace, run_id=args.resume_run_id)
            if args.resume_run_id else
            initialize_solve_files(
                workspace, challenge, str(record["source_fingerprint"]),
                fresh_attempt=args.fresh_attempt, attempt_id=args.attempt_id,
                transformation_seed=args.transformation_seed,
                mode=selected_mode, legacy_tier=args.tier,
            )
        )
        repair_run_projections(solve_root, declared_remote=bool(challenge.remotes))
        launch_state = json.loads((solve_root / "STATE.json").read_text(encoding="utf-8"))
        launch_context = build_solve_launch_context(
            challenge, record, mode=str(launch_state.get("solve_mode") or selected_mode.value),
            legacy_tier=launch_state.get("legacy_tier"),
        )
        launch_context["run_id"] = launch_state.get("run_id")
        launch_context["attempt_id"] = launch_state.get("attempt_id")
        launch_context["challenge_instance_id"] = launch_state.get("challenge_instance_id")
        launch_context["target_revision"] = launch_state.get("target_revision")
        launch_path = save_solve_launch_context(solve_root, launch_context)
        compatibility_launch_path = save_solve_launch_context(workspace, launch_context)
        prepared = _compact_prepare(challenge, record, solve_root, launch_context, compatibility_launch_path)
        prepared["authoritative_solve_launch_path"] = str(launch_path)
        prepared["attempt_id"] = launch_state.get("attempt_id")
        prepared["challenge_instance_id"] = launch_state.get("challenge_instance_id")
        prepared["mode"] = launch_state.get("solve_mode")
        return prepared

    if args.command == "attempt-start":
        _require_sol(args, "Only Sol may start a fresh attempt.")
        selected_mode = resolve_solve_mode(args.mode, tier=args.tier)
        manifest, challenge, record = _prepare_challenge_same_session(
            root, args.contest, args.selector, None,
        )
        workspace = challenge_root(root, manifest, challenge)
        run = start_fresh_attempt(
            workspace, challenge, str(record["source_fingerprint"]),
            attempt_id=args.attempt_id, transformation_seed=args.transformation_seed,
            mode=selected_mode, legacy_tier=args.tier,
        )
        return show_attempt(run, run_id=run.name)

    if args.command in {"attempt-resume", "attempt-list", "attempt-show"}:
        _require_sol(args, "Only Sol may resolve prior attempts.")
        manifest, challenge, _record = _load_challenge_strict(root, args.contest, args.selector)
        workspace = challenge_root(root, manifest, challenge)
        if args.command == "attempt-list":
            return {"attempts": list_attempts(workspace)}
        if args.command == "attempt-show":
            return show_attempt(workspace, run_id=args.run_id)
        run = resume_attempt(workspace, run_id=args.run_id)
        return show_attempt(run, run_id=run.name)

    if args.command == "benchmark-start":
        _require_sol(args, "Only Sol may prepare a benchmark attempt.")
        manifest, challenge, record = _load_challenge_strict(root, args.contest, args.selector)
        workspace = challenge_root(root, manifest, challenge)
        schedule_path = Path(args.schedule).resolve()
        schedule = json.loads(schedule_path.read_text(encoding="utf-8"))
        execution_ledger = schedule_path.with_name("BENCHMARK_EXECUTION.jsonl")
        begin_schedule_entry(schedule, args.entry_id, execution_ledger)
        revisions = target_revisions(workspace)
        if not revisions:
            fail_schedule_entry(
                schedule, args.entry_id, execution_ledger,
                reason="benchmark start requires a prepared authoritative target revision ledger",
            )
            raise ValueError("benchmark start requires a prepared authoritative target revision ledger")
        target_revision = int(revisions[-1]["target_revision"])
        try:
            return start_benchmark_attempt(
                root, workspace, challenge,
                input_fingerprint=str(record["source_fingerprint"]),
                target_revision=target_revision, schedule=schedule,
                schedule_entry_id=args.entry_id, lock_path=Path(args.lock).resolve(),
                signature_path=Path(args.signature).resolve(),
                public_keys={args.key_id: Path(args.public_key).resolve()},
                target_image_digest=args.target_image_digest,
                tool_image_digest=args.tool_image_digest,
                challenge_archive_path=Path(args.challenge_archive).resolve(),
            )
        except Exception as exc:
            fail_schedule_entry(schedule, args.entry_id, execution_ledger, reason=str(exc))
            raise

    if args.command in {
        "benchmark-health-monitor", "benchmark-telemetry-start",
        "benchmark-telemetry-sample", "benchmark-telemetry-monitor",
        "benchmark-telemetry-finish", "benchmark-runtime-observation-record",
        "benchmark-resource-record", "benchmark-outcome-record", "benchmark-complete",
    }:
        _require_sol(args, "Only Sol may operate exact benchmark telemetry/completion receipts.")
        manifest, challenge, _record = _load_challenge_strict(root, args.contest, args.selector)
        workspace = challenge_root(root, manifest, challenge)
        run = resolve_exact_run(workspace, args.run_id)
        if args.command == "benchmark-health-monitor":
            return run_target_health_monitor(
                run, probe_argv=args.argv, endpoint_revision=args.endpoint_revision,
                duration_seconds=args.duration_seconds, cadence_seconds=args.cadence_seconds,
                timeout_seconds=args.timeout_seconds,
                semantic_success_token=args.semantic_success_token,
            )
        if args.command == "benchmark-telemetry-start":
            return start_resource_telemetry(
                run, tracked_pids=args.tracked_pid,
                network_namespace_pid=args.network_namespace_pid,
                container_ids=args.container_id,
            )
        if args.command == "benchmark-telemetry-sample":
            return sample_resource_telemetry(run)
        if args.command == "benchmark-telemetry-monitor":
            return run_resource_telemetry_monitor(
                run, duration_seconds=args.duration_seconds,
                cadence_seconds=args.cadence_seconds, tracked_pids=args.tracked_pid,
                network_namespace_pid=args.network_namespace_pid,
                container_ids=args.container_id,
            )
        if args.command == "benchmark-telemetry-finish":
            return finish_resource_telemetry(run)
        if args.command == "benchmark-outcome-record":
            return record_benchmark_outcome(
                run, oracle_result=args.oracle_result,
                cleanup_success=args.cleanup_success,
                terminal_correctness=args.terminal_correctness,
                environment_failure=args.environment_failure,
                invalidation_reason=args.invalidation_reason,
                false_candidate_count=args.false_candidate_count,
                scope_violation_count=args.scope_violation_count,
                denied_out_of_scope_action_count=args.denied_out_of_scope_action_count,
                target_failure_duration_seconds=args.target_failure_duration_seconds,
                model_failure_duration_seconds=args.model_failure_duration_seconds,
                environment_failure_duration_seconds=args.environment_failure_duration_seconds,
                latency_explained_by_target_or_model_queue=(
                    args.latency_explained_by_target_or_model_queue
                ),
                latency_explanation_evidence=args.latency_explanation_evidence,
            )
        if args.command == "benchmark-runtime-observation-record":
            return record_runtime_observation(
                run, observed_model=args.observed_model,
                observed_reasoning=args.observed_reasoning,
                runtime_observation_evidence=args.evidence,
            )
        if args.command == "benchmark-resource-record":
            if args.observation_status == "OBSERVED" and args.value is None:
                raise ValueError("OBSERVED benchmark resource requires --value")
            if args.observation_status != "OBSERVED" and args.value is not None:
                raise ValueError("unobserved benchmark resource must not supply --value")
            return record_resource_observation(
                run, args.field, value=args.value,
                observation_status=args.observation_status, reason=args.reason,
            )
        schedule_path = Path(args.schedule).resolve()
        schedule = json.loads(schedule_path.read_text(encoding="utf-8"))
        receipt = validate_benchmark_completion(run)
        receipt["schedule_completion"] = finish_schedule_entry(
            schedule, args.entry_id, schedule_path.with_name("BENCHMARK_EXECUTION.jsonl"),
            completion_receipt=receipt,
        )
        return receipt

    if args.command in {
        "rescue-prepare", "rescue-show", "rescue-runtime-record",
        "rescue-return-validate", "rescue-close",
    }:
        _require_sol(args, "Only the current parent Sol session may operate a manual Claude rescue.")
        manifest, challenge, record = _load_challenge_strict(
            root, args.contest, args.selector,
        )
        workspace = challenge_root(root, manifest, challenge)
        run = resolve_run_raw(workspace, run_id=args.run_id)
        if run.name != args.run_id:
            raise ValueError(f"wrong exact run ID: requested {args.run_id}, resolved {run.name}")
        if args.command == "rescue-prepare":
            return prepare_rescue(
                root, manifest, challenge, record, run,
                mode=args.mode, profile=args.profile,
                objective=args.objective, current_blocker=args.current_blocker,
                operation_id=args.operation_id,
                leading_exploit_path=args.leading_exploit_path,
                paths_not_to_repeat=args.path_not_to_repeat,
                lead_model=args.lead_model,
                sandbox_factory=create,
                connectivity_probe=probe_service_connectivity,
                service_inspector=service_inspect,
                attachment_factory=service_attachment,
            )
        if args.command == "rescue-show":
            return show_rescue(run, args.rescue_id)
        if args.command == "rescue-runtime-record":
            validate_exact_live_mutable_run(run, challenge, record)
            return record_rescue_runtime(
                run, args.rescue_id,
                observed_model=args.observed_model, evidence=args.evidence,
                fallback_observed=args.fallback_observed,
            )
        if args.command == "rescue-return-validate":
            validate_exact_live_mutable_run(run, challenge, record)
            return validate_rescue_return(run, challenge, args.rescue_id)
        return close_rescue(
            run, args.rescue_id, outcome=args.outcome,
            evidence_receipt_id=args.evidence_receipt_id,
            sandbox_cleanup=cleanup,
        )

    manifest, challenge, record = _load_challenge_strict(root, args.contest, args.selector)
    if os.environ.get("CTF_OS_SESSION_ROLE") == "child":
        if (
            os.environ.get("CTF_OS_CHALLENGE_ID") != challenge.id
            or os.environ.get("CTF_OS_CONTEST_SLUG") != manifest.slug
        ):
            raise ValueError("DENIED_CHALLENGE_SCOPE: child session may access only its assigned challenge")
    current_fingerprint = str(record["source_fingerprint"])
    workspace = challenge_root(root, manifest, challenge)
    solve_root = initialize_solve_files(workspace, challenge, current_fingerprint)
    if args.command in {"repair-run", "repair-projections"}:
        _require_sol(args, "Only Sol may repair authoritative run projections.")
        selected = (
            solve_root if not args.run_id else
            safe_under(challenge_workspace(solve_root) / "runs", Path(args.run_id))
        )
        if selected.is_symlink() or not selected.is_dir():
            raise ValueError("repair run does not exist in this challenge workspace")
        state = recover_run_state(selected, force=True)
        if args.command == "repair-run":
            return {"run_id": selected.name, "state": state}
        return {
            "run_id": selected.name, "state": state,
            "projections": repair_run_projections(
                selected, declared_remote=bool(challenge.remotes),
            ),
        }
    ledger = ResourceLedger(solve_root)
    if args.command == "resource-request":
        session_id, role = _caller(args)
        inferred = infer_workload(
            command=args.workload_commands,
            files=[str(item.get("path", "")) for item in record.get("files", []) if isinstance(item, dict)],
            role=session_id, category=challenge.category, override=args.workload_class,
        )
        overrides = _resource_overrides(args)
        request = default_request(
            contest=manifest.slug, challenge_id=challenge.id, session_id=session_id,
            workload_class=str(inferred["workload_class"]), priority=args.priority,
            input_bytes=prepared_input_bytes(record), gpu_required=args.gpu_required,
            gpu_preferred=True if args.gpu_preferred else None, overrides=overrides,
        )
        return ledger.request(request, actor_session_id=session_id, actor_role=role, inference=inferred)
    if args.command == "resource-update":
        session_id, role = _caller(args)
        progress = None
        if args.progress_json:
            progress = json.loads(args.progress_json)
            if not isinstance(progress, dict):
                raise ValueError("--progress-json must contain an object")
        result = ledger.update(session_id, actor_session_id=session_id, actor_role=role, changes={
            "priority": args.priority, "workload_class": args.workload_class,
            "parallelizable": args.parallelizable, "progress": progress, "state": args.state,
        })
        result["race_transition"] = control_loop_tick(solve_root, input_fingerprint=current_fingerprint, session_id=session_id)
        return result
    if args.command == "resource-release":
        session_id, role = _caller(args)
        if role == "child" and session_id != os.environ.get("CTF_OS_SESSION_ID"):
            raise ValueError("child may release only its own resource request")
        return ledger.release(
            session_id, args.reason, actor_session_id=session_id, actor_role=role,
        )
    if args.command == "resource-history":
        session_id, role = _caller(args)
        rows = ledger.history(args.limit)
        if role == "child":
            rows = [row for row in rows if row.get("session_id") == session_id]
        return {"history": rows}
    if args.command == "resource-sample":
        session_id, role = _caller(args)
        if args.sample_json:
            sample = json.loads(args.sample_json)
            if not isinstance(sample, dict):
                raise ValueError("--sample-json must contain an object")
        else:
            metadata = _load_metadata(root, args.metadata) if args.metadata else None
            if role == "child" and metadata is not None and metadata.get("session_id") != session_id:
                raise ValueError("child may sample only its own sandbox")
            samples = sample_docker_stats()["samples"]
            container = str(metadata.get("name")) if metadata else ""
            sample = next((row for row in samples if row.get("container") == container), None)
            if sample is None:
                raise ValueError("no Docker utilization sample found for the requested sandbox")
        observation = ledger.sample(session_id, sample)
        if observation.get("classification") in {"CPU_STARVED", "MEMORY_STARVED", "GPU_STARVED", "STALLED_COMPUTE"}:
            observation["race_transition"] = control_loop_tick(solve_root, input_fingerprint=current_fingerprint, session_id=session_id)
        return observation
    if args.command in {"resource-plan", "scheduler-rebalance"}:
        _require_sol(args, "Only the parent Sol session may plan or apply global allocations.")
        state = json.loads((solve_root / "STATE.json").read_text(encoding="utf-8"))
        remote = state.get("remote_flag") if isinstance(state.get("remote_flag"), dict) else {}
        remote_session = str(remote.get("branch_id")) if remote else None
        try:
            race_plan = load_plan(solve_root, input_fingerprint=current_fingerprint)
            tier = int(race_plan.get("tier", 0))
        except Exception:
            tier = None
        capacity = detect_capacity(workspace=root)
        plan = (
            ledger.plan(capacity, tier=tier, remote_flag_session=remote_session)
            if args.command == "resource-plan"
            else ledger.rebalance(capacity, tier=tier, remote_flag_session=remote_session)
        )
        if args.command == "scheduler-rebalance" and args.apply:
            plan["applied_resizes"] = _apply_resize_plan(root, solve_root, plan, args)
            ledger.reconcile_apply(plan, plan["applied_resizes"])
        elif args.command == "scheduler-rebalance":
            plan["apply_required"] = True
        plan["race_transition"] = control_loop_tick(solve_root, input_fingerprint=current_fingerprint, session_id=remote_session)
        return plan
    if args.command.startswith("delegation-") or args.command in {
        "branch-admit", "branch-utility", "branch-replacement-prepare", "branch-start-confirm", "race-plan-start", "race-board",
    }:
        _require_delegation_sol(args)
        if args.command == "race-plan-start":
            template_path = Path(__file__).parents[1] / "resources" / "delegation-templates.yaml"
            selected_mode = resolve_solve_mode(args.mode, tier=args.tier)
            specs = parse_branch_spec(
                args.branch_spec, category=challenge.category, tier=args.tier,
                template_path=template_path, mode=selected_mode,
            )
            board = start_race_plan(
                solve_root, challenge_id=challenge.id, input_fingerprint=current_fingerprint,
                parent_session_id=args.parent_session_id, category=challenge.category,
                tier=args.tier, tier_reason=args.tier_reason, branch_specs=specs,
                threshold=args.threshold, mode=selected_mode,
                frozen_template=selected_mode is SolveMode.FIXED_RACE,
            )
            state_path = solve_root / "STATE.json"
            with state_lock(solve_root):
                race_state = json.loads(state_path.read_text(encoding="utf-8"))
                race_state["status"] = "RACE_RUNNING"; race_state["updated_at"] = datetime.now(timezone.utc).isoformat()
                atomic_json(state_path, race_state)
            _seed_race_resources(
                ledger, board, manifest.slug, challenge.id, challenge.category,
                args.parent_session_id, prepared_input_bytes(record),
            )
            capacity = detect_capacity(workspace=root)
            resource_plan = ledger.rebalance(capacity, tier=args.tier)
            capacity_receipt = record_capacity_admission(
                solve_root, input_fingerprint=current_fingerprint,
                admitted_session_ids=list(resource_plan.get("allocations", {}).keys()),
            )
            board = race_board(
                load_plan(solve_root, input_fingerprint=current_fingerprint),
                state=json.loads((solve_root / "STATE.json").read_text(encoding="utf-8")),
                resources=resource_panel(capacity.to_dict(), ledger.load()),
            )
            board["resource_plan"] = resource_plan
            board["capacity_admission"] = capacity_receipt
            board["next_action"] = (
                "Create each capacity-admitted branch sandbox and verify current input access, then use native "
                "delegation and record its start receipt. Sol continues the deep-solve lane throughout startup."
            )
            return board
        if args.command == "race-board":
            repair_run_projections(solve_root, declared_remote=bool(challenge.remotes))
            transition = control_loop_tick(solve_root, input_fingerprint=current_fingerprint)
            plan = load_plan(solve_root, input_fingerprint=current_fingerprint)
            state = json.loads((solve_root / "STATE.json").read_text(encoding="utf-8"))
            events = show_events(solve_root, input_fingerprint=current_fingerprint)
            try:
                capacity = detect_capacity(workspace=root).to_dict()
                resources = resource_panel(capacity, ResourceLedger(solve_root).load())
            except Exception as exc:
                resources = {"available": False, "reason": str(exc)}
            board = race_board(plan, state=state, events=events, resources=resources)
            board["race_transition"] = transition
            return board
        if args.command == "delegation-plan-init":
            return init_plan(solve_root, challenge_id=challenge.id, input_fingerprint=current_fingerprint, parent_session_id=args.parent_session_id, tier=args.tier, tier_reason=args.tier_reason)
        if args.command == "delegation-plan-show":
            return load_plan(solve_root, input_fingerprint=current_fingerprint)
        if args.command == "delegation-template-show":
            return template_recommendation(Path(__file__).parents[1] / "resources" / "delegation-templates.yaml", category=challenge.category, tier=args.tier)
        if args.command == "branch-admit":
            candidate = _candidate_from_args(args)
            return record_admission(
                solve_root, input_fingerprint=current_fingerprint, candidate=candidate,
                threshold=args.threshold, purpose=args.purpose,
                race_override_reason=args.race_override_reason,
            )
        if args.command == "delegation-branch-add":
            candidate = _candidate_from_args(args)
            routing_contract, routing_context = _routing_from_args(
                args, candidate, purpose=args.purpose,
            )
            return add_branch(
                solve_root, input_fingerprint=current_fingerprint, candidate=candidate,
                evidence_contract=args.evidence_contract,
                success_condition=args.success_condition, kill_condition=args.kill_condition,
                maximum_steps=args.maximum_steps, budget_seconds=args.budget_seconds,
                requested_model_role=args.requested_model_role,
                requested_reasoning=args.requested_reasoning, purpose=args.purpose,
                routing_contract=routing_contract,
                routing_evidence_context=routing_context,
            )
        if args.command == "delegation-branch-update":
            result = update_branch(solve_root, input_fingerprint=current_fingerprint, session_id=args.session_id, status=args.status, observed_runtime_model=args.observed_runtime_model, observed_reasoning=args.observed_reasoning, pinning_verified=args.pinning_verified, runtime_observation_evidence=args.runtime_observation_evidence)
            terminal = args.status.upper() in {"SUPPORTED", "REFUTED", "PARTIAL", "INCONCLUSIVE", "TERMINATED", "ERROR", "STALE"}
            metadata_path = solve_root / "workers" / args.session_id / "sandbox.json"
            if terminal and metadata_path.is_file():
                metadata = _load_metadata(root, str(metadata_path))
                result["sandbox_release"] = cleanup(
                    metadata, session_id=args.parent_session_id, session_role="sol",
                )
            resource_state = ledger.load()
            if terminal and args.session_id in resource_state.get("requests", {}) and resource_state.get("observations", {}).get(args.session_id, {}).get("state") != "RELEASED":
                ledger.release(args.session_id, f"branch terminal state {args.status.upper()}")
            return result
        if args.command == "branch-utility":
            plan = load_plan(solve_root, input_fingerprint=current_fingerprint)
            checkpoints = collect_worker_checkpoints(solve_root / "workers", input_fingerprint=current_fingerprint)
            result_path = solve_root / "workers" / args.session_id / "result.json"
            result = load_worker_result(result_path) if result_path.is_file() else None
            advice = branch_utility(plan, session_id=args.session_id, checkpoints=checkpoints, result=result)
            if args.session_id in ledger.load().get("requests", {}):
                classification = str(advice.get("classification", "INSUFFICIENT_DATA"))
                if classification == "DEAD_BRANCH":
                    ledger.release(args.session_id, "branch utility DEAD_BRANCH")
                else:
                    metrics = advice.get("metrics") if isinstance(advice.get("metrics"), dict) else {}
                    progress: dict[str, object] = {
                        "progressing": classification in {"PROGRESSING", "FLAG_PATH"},
                        **{
                            key: metrics[key] for key in (
                                "exploit_proximity", "decisive_experiment_count",
                                "failed_decisive_experiments",
                                "time_or_steps_since_proximity_increase",
                                "working_poc_present", "remote_ready", "research_drift_detected",
                            ) if key in metrics
                        },
                    }
                    changes: dict[str, object] = {
                        "utility_classification": classification,
                        "scheduler_recommendation": advice.get("recommendation"),
                        "progress": progress,
                    }
                    if classification == "FLAG_PATH":
                        changes["priority"] = "CRITICAL"
                        progress["flag_proximity"] = metrics.get("exploit_proximity", 1.0)
                    ledger.update(
                        args.session_id, actor_session_id=args.parent_session_id,
                        actor_role="sol", changes=changes,
                    )
            return advice
        if args.command == "branch-replacement-prepare":
            candidate = _candidate_from_args(args)
            routing_contract, routing_context = _routing_from_args(
                args, candidate, purpose="alternate-attack-family",
            )
            return prepare_branch_replacement(
                solve_root, input_fingerprint=current_fingerprint,
                superseded_branch_id=args.superseded_branch_id, candidate=candidate,
                kill_reason=args.kill_reason, distinct_mechanism_proof=args.distinct_mechanism_proof,
                evidence_contract=args.evidence_contract, success_condition=args.success_condition,
                kill_condition=args.kill_condition, maximum_steps=args.maximum_steps,
                budget_seconds=args.budget_seconds, requested_model_role=args.requested_model_role,
                requested_reasoning=args.requested_reasoning,
                triggering_receipt_id=args.triggering_receipt_id,
                routing_contract=routing_contract,
                routing_evidence_context=routing_context,
            )
        if args.command == "branch-start-confirm":
            return confirm_branch_start(
                solve_root, input_fingerprint=current_fingerprint,
                replacement_request_id=args.replacement_request_id, session_id=args.session_id,
                native_session_observed=args.native_session_observed,
                runtime_observation_evidence=args.runtime_observation_evidence,
                sandbox_metadata_path=args.sandbox_metadata_path,
                native_start_operation_id=args.native_start_operation_id,
                observed_model=args.observed_model,
                observed_reasoning=args.observed_reasoning,
                runtime_observation_status=args.runtime_observation_status,
            )
    if args.command.startswith("service-"):
        spec = _service_spec(manifest, challenge, record, solve_root)
        actor = _service_actor(args)
        operation = {
            "service-plan": service_plan, "service-build": service_build,
            "service-start": service_start, "service-restart": service_restart,
            "service-status": service_status, "service-logs": service_logs,
            "service-inspect": service_inspect, "service-stop": service_stop,
            "service-cleanup": service_cleanup,
        }[args.command]
        return operation(spec) if args.command == "service-plan" else operation(spec, actor=actor)
    if args.command.startswith("branch-service-"):
        session_id, role = _caller(args, branch=args.branch)
        if session_id != args.branch and role == "child":
            raise ValueError("DENIED_SERVICE_LIFECYCLE: child may operate only its own branch-private service")
        spec = _service_spec(manifest, challenge, record, solve_root, branch_id=args.branch)
        actor = ServiceActor(
            session_id=session_id, role=role, parent_session_id=args.parent_session_id,
            recover_stale=bool(args.recover_stale),
        )
        operation = {
            "branch-service-plan": service_plan, "branch-service-build": service_build,
            "branch-service-start": service_start, "branch-service-restart": service_restart,
            "branch-service-reset": service_reset,
            "branch-service-status": service_status, "branch-service-logs": service_logs,
            "branch-service-inspect": service_inspect, "branch-service-stop": service_stop,
            "branch-service-cleanup": service_cleanup,
        }[args.command]
        return operation(spec) if args.command == "branch-service-plan" else operation(spec, actor=actor)
    if args.command == "race-event-publish":
        session_id, _role = _caller(args)
        primitive = json.loads(args.primitive_json) if args.primitive_json else None
        if primitive is not None and not isinstance(primitive, dict):
            raise ValueError("--primitive-json must be a JSON object")
        return publish_event(
            solve_root, challenge_id=challenge.id, input_fingerprint=current_fingerprint,
            session_id=session_id, event_type=args.type, priority=args.priority,
            summary=args.summary, evidence=args.evidence, artifacts=args.artifact,
            useful_for=_csv(args.useful_for), recommended_action=args.recommended_action,
            event_id=args.event_id,
            primitive=primitive,
        )
    if args.command == "milestone-save":
        session_id, _role = _caller(args)
        details = json.loads(args.details_json) if args.details_json else {}
        if not isinstance(details, dict):
            raise ValueError("--details-json must contain an object")
        argv = list(args.argv)
        if argv and argv[0] == "--": argv.pop(0)
        state = json.loads((solve_root / "STATE.json").read_text(encoding="utf-8"))
        receipt = save_milestone(
            solve_root, challenge_id=challenge.id, session_id=session_id,
            input_fingerprint=current_fingerprint, target_revision=int(state.get("target_revision") or 1),
            event_type=args.type, summary=args.summary, evidence=args.evidence,
            artifacts=args.artifact, command_argv=argv, output=args.output,
            exploit_proximity=args.exploit_proximity, details=details,
            declared_remote=bool(challenge.remotes),
            operation_id=args.operation_id, candidate=args.candidate,
            source_type=args.source_type, validation_method=args.validation_method,
            confidence=args.confidence,
        )
        return receipt
    if args.command == "progress-command":
        session_id, _role = _caller(args)
        argv = list(args.argv)
        if argv and argv[0] == "--": argv.pop(0)
        return record_command(solve_root, session_id=session_id, command_argv=argv, category=challenge.category)
    if args.command == "long-compute-heartbeat":
        session_id, _role = _caller(args)
        return heartbeat_long_compute(
            solve_root, session_id=session_id, receipt_id=args.receipt_id,
            artifact_changed=args.artifact_changed,
            completion_signal_observed=args.completion_signal_observed,
        )
    if args.command == "race-events-show":
        return {"events": show_events(
            solve_root, input_fingerprint=current_fingerprint, since=args.since,
            priorities=args.priority, event_types=args.type,
        )}
    if args.command == "race-events-ack":
        session_id, _role = _caller(args)
        return acknowledge_event(
            solve_root, event_id=args.event_id, session_id=session_id,
            input_fingerprint=current_fingerprint,
        )
    if args.command == "race-insight-packet":
        plan = load_plan(solve_root, input_fingerprint=current_fingerprint)
        return insight_packet(
            solve_root, input_fingerprint=current_fingerprint,
            target_session_id=args.target_session_id, plan=plan, limit=args.limit,
        )
    if args.command == "operator-hint-save":
        _require_sol(args, "Only Sol may record and route operator hints.")
        plan = load_plan(solve_root, input_fingerprint=current_fingerprint)
        return save_operator_hint(
            solve_root, challenge_id=challenge.id, input_fingerprint=current_fingerprint,
            summary=args.summary, active_branches=plan.get("branches", []), targets=args.target,
        )
    if args.command == "operator-hints-show":
        _require_sol(args, "Only Sol may list operator hints.")
        return {"hints": operator_hints(solve_root, input_fingerprint=current_fingerprint)}
    if args.command == "oast-create":
        session_id, role = _caller(args, branch=args.branch)
        if role == "child" and session_id != args.branch:
            raise ValueError("DENIED_CHALLENGE_SCOPE: child may create OAST only for its own branch")
        return create_oast(
            solve_root, challenge_id=challenge.id, input_fingerprint=current_fingerprint,
            branch_id=args.branch, provider_base=args.provider_url,
        )
    if args.command == "oast-poll":
        return poll_oast(solve_root, oast_id=args.oast_id, input_fingerprint=current_fingerprint)
    if args.command == "oast-events":
        return {"events": oast_events(solve_root, oast_id=args.oast_id, input_fingerprint=current_fingerprint)}
    if args.command == "flag-receipt-save":
        _require_sol(args, "Only Sol may set the shared submission recommendation.")
        argv = list(args.argv)
        if argv and argv[0] == "--":
            argv.pop(0)
        receipt = record_remote_flag(
            solve_root, challenge_id=challenge.id, input_fingerprint=current_fingerprint,
            branch_id=args.branch, declared_targets=parse_remotes(challenge.remotes),
            observed_host=args.host, observed_port=args.port, observed_protocol=args.protocol,
            network_observed=args.network_observed, output=args.output, candidate=args.candidate,
            flag_pattern=challenge.flag_pattern, command_argv=argv,
            exploit_artifact=args.exploit_artifact,
            target_revision=int(json.loads((solve_root / "STATE.json").read_text(encoding="utf-8")).get("target_revision") or 1),
        )
        if receipt.get("state") == "SUBMISSION_RECOMMENDED":
            resource_state = ledger.load()
            receipt["resource_reclamation"] = _cleanup_released_sandboxes(
                root, solve_root, resource_state.get("last_plan", {}), args.parent_session_id,
            )
        return receipt
    if args.command == "working-poc-commit":
        _require_sol(args, "Only Sol may explicitly commit a working PoC to the declared remote.")
        if args.run_id != solve_root.name:
            raise ValueError("working-poc-commit run ID is not the current exact run")
        argv = list(args.argv)
        if argv and argv[0] == "--":
            argv.pop(0)
        metadata = _load_metadata(root, args.metadata)
        if str(metadata.get("branch")) != args.branch:
            raise ValueError("working-poc-commit branch does not own the sandbox metadata")
        state = json.loads((solve_root / "STATE.json").read_text(encoding="utf-8"))
        return commit_working_poc(
            solve_root, challenge_id=challenge.id,
            input_fingerprint=current_fingerprint,
            target_revision=int(state.get("target_revision") or 1),
            session_id=args.branch, sandbox_metadata=metadata,
            local_receipt_id=args.local_receipt_id,
            exploit_artifact=args.exploit_artifact, remote_argv=argv,
            declared_targets=parse_remotes(challenge.remotes), target_index=args.target_index,
            flag_pattern=challenge.flag_pattern,
            success_condition=args.success_condition, kill_condition=args.kill_condition,
            operation_id=args.operation_id, timeout=args.timeout,
        )
    if args.command == "working-poc-resolve-unknown":
        _require_sol(args, "Only Sol may resolve an unknown working PoC execution outcome.")
        if args.run_id != solve_root.name:
            raise ValueError("working-poc-resolve-unknown run ID is not the current exact run")
        proof = json.loads(args.receipt_json)
        if not isinstance(proof, dict):
            raise ValueError("--receipt-json must contain an object")
        return resolve_unknown_working_poc(
            solve_root, operation_id=args.operation_id, decision=args.decision,
            resolution_receipt=proof, new_operation_id=args.new_operation_id,
            declared_targets=parse_remotes(challenge.remotes),
            flag_pattern=challenge.flag_pattern,
        )
    if args.command == "submission-result":
        _require_sol(args, "Only Sol may record the human submission result.")
        terminal_run = safe_under(challenge_workspace(solve_root) / "runs", Path(args.run_id))
        if terminal_run.is_symlink() or not terminal_run.is_dir():
            raise ValueError("submission run does not exist in this challenge workspace")
        terminal_ledger = ResourceLedger(terminal_run)
        receipt = record_submission_result(
            terminal_run, run_id=args.run_id, candidate_id=args.candidate_id, result=args.result,
        )
        if args.result == "accepted":
            def release_resource(session_id: str):
                resource_state = terminal_ledger.load()
                observation = resource_state.get("observations", {}).get(session_id, {})
                if session_id not in resource_state.get("requests", {}) or observation.get("state") == "RELEASED":
                    return {"session_id": session_id, "released": True, "idempotent": True}
                return terminal_ledger.release(
                    session_id, "accepted run terminal convergence",
                    actor_session_id=args.parent_session_id, actor_role="sol",
                )
            def clean_sandbox(metadata_path: Path, session_id: str):
                metadata = _load_metadata(root, str(metadata_path))
                return cleanup(metadata, session_id=args.parent_session_id, session_role="sol")
            receipt["terminal_convergence"] = converge_terminal(
                terminal_run, run_id=args.run_id,
                sandbox_cleanup=clean_sandbox, resource_release=release_resource,
            )
            resource_state = terminal_ledger.load()
            receipt["remaining_resource_release"] = [
                {
                    "session_id": session_id, "released": False,
                    "reason": "terminal ordering or native termination is still pending",
                }
                for session_id in list(resource_state.get("requests", {}))
                if resource_state.get("observations", {}).get(session_id, {}).get("state") != "RELEASED"
            ]
        return receipt
    if args.command == "branch-native-stop":
        _require_sol(args, "Sol owns native child termination receipts.")
        payload = json.loads(args.receipt_json)
        if not isinstance(payload, dict):
            raise ValueError("--receipt-json must contain an object")
        return record_native_stop(
            solve_root, run_id=args.run_id, session_id=args.branch, native_receipt=payload,
        )
    if args.command == "terminal-status":
        _require_sol(args, "Only Sol may inspect terminal convergence.")
        selected = solve_root if not args.run_id else safe_under(challenge_workspace(solve_root) / "runs", Path(args.run_id))
        recover_run_state(selected, force=True)
        repair_run_projections(selected, declared_remote=bool(challenge.remotes))
        return terminal_status(selected)
    if args.command == "control-actions-show":
        return {"actions": load_control_actions(solve_root)}
    if args.command == "control-action-ack":
        _require_sol(args, "Only Sol may acknowledge lifecycle actions.")
        status = {
            "declined": "ACKED_DECLINED", "superseded": "SUPERSEDED", "expired": "EXPIRED",
        }[args.status]
        return acknowledge_control_action(
            solve_root, action_id=args.action_id, status=status,
        )
    if args.command == "control-action-apply":
        _require_sol(args, "Only Sol may apply lifecycle actions.")
        proof = json.loads(args.receipt_json)
        if not isinstance(proof, dict):
            raise ValueError("--receipt-json must contain an object")
        return apply_control_action(solve_root, action_id=args.action_id, proof_receipt=proof)
    if args.command == "replay":
        _require_sol(args, "Only the parent Sol session may make the final replay judgment.")
        return run_replay(root, manifest, challenge, record, service_actor=_service_actor(args))
    if args.command == "sandbox-create":
        branch_root = solve_root / "workers" / args.branch
        session_id, session_role = _caller(args, branch=args.branch)
        prepared = prepare_sandbox_spec(
            repo_root=root, manifest=manifest, challenge=challenge, record=record,
            workspace=workspace, solve_root=solve_root, branch=args.branch,
            branch_root=branch_root, session_id=session_id,
            parent_session_id=args.parent_session_id, session_role=session_role,
            image_override=args.image, resource_profile_override=args.resource_profile,
            require_service=bool(args.service),
            prepared_fingerprint_reader=prepared_tree_fingerprint,
            service_inspector=service_inspect,
            service_actor=_service_actor(args, child_default=True),
        )
        spec = prepared.spec
        attachment_service = prepared.attachment_service
        service_network = spec.service_network
        guard = (
            service_attachment(
                attachment_service,
                actor=ServiceActor(
                    args.parent_session_id, role="sol", parent_session_id=args.parent_session_id,
                ),
            )
            if attachment_service is not None else nullcontext()
        )
        with guard:
            metadata = create(spec)
            try:
                if service_network:
                    metadata["connectivity_probe"] = probe_service_connectivity(metadata)
                    atomic_json(Path(str(metadata["metadata_path"])), metadata)
                _mirror_legacy_worker_metadata(workspace, solve_root, args.branch, metadata)
                if (solve_root / "DELEGATION_PLAN.json").is_file():
                    record_branch_sandbox_ready(
                        solve_root, input_fingerprint=current_fingerprint,
                        session_id=args.branch, sandbox_metadata_path=str(metadata["metadata_path"]),
                        input_available=True,
                    )
                else:
                    # Legacy compatibility view: a live sandbox is not proof
                    # that a native child was started.
                    _update_branch_state(
                        solve_root, args.branch, "SANDBOX_READY", str(metadata["metadata_path"]),
                    )
            except Exception:
                cleanup(metadata)
                raise
        return metadata
    if args.command == "record-finding":
        _require_sol(args, "Only the parent Sol session may merge shared findings; submit a worker result instead.")
        return append_finding(solve_root, args.branch, args.summary, args.evidence, args.status)
    if args.command == "worker-result-save":
        session_id, role = _caller(args, branch=args.branch)
        if role != "child" or session_id != args.branch:
            raise ValueError("worker result must be submitted by its matching child session")
        try:
            payload = json.loads(args.result_json)
        except json.JSONDecodeError as exc:
            raise ValueError("--result-json must be valid JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("--result-json must contain a JSON object")
        if (
            payload.get("challenge_id") != challenge.id
            or payload.get("parent_session_id") != args.parent_session_id
            or payload.get("input_fingerprint") != record.get("source_fingerprint")
        ):
            raise ValueError("worker result challenge, parent session, or input fingerprint does not match the active solve")
        worker_root = solve_root / "workers" / args.branch
        sandbox_metadata = worker_root / "sandbox.json"
        active_metadata = None
        if sandbox_metadata.is_file():
            active_metadata = _load_metadata(root, str(sandbox_metadata))
            export_artifacts(
                active_metadata,
                session_id=session_id, session_role=role,
            )
            _adopt_legacy_worker_exports(workspace, solve_root, args.branch)
        result = save_worker_result(worker_root, payload)
        terminal = str(payload.get("status", "")).upper() in {"SUPPORTED", "REFUTED", "PARTIAL", "INCONCLUSIVE", "ERROR"}
        if terminal and isinstance(active_metadata, dict) and all(key in active_metadata for key in ("name", "branch_root", "labels")):
            result["sandbox_release"] = cleanup(active_metadata, session_id=session_id, session_role=role)
        resource_state = ledger.load()
        if terminal and args.branch in resource_state.get("requests", {}) and resource_state.get("observations", {}).get(args.branch, {}).get("state") != "RELEASED":
            ledger.release(args.branch, f"worker result {str(payload.get('status')).upper()}")
        return result
    if args.command == "worker-checkpoint-save":
        session_id, role = _caller(args)
        if role != "child":
            raise ValueError("worker checkpoint must be submitted by a child session")
        if os.environ.get("CTF_OS_SESSION_ROLE") == "child" and session_id != os.environ.get("CTF_OS_SESSION_ID"):
            raise ValueError("DENIED_SESSION_IDENTITY: child may write only its own checkpoint")
        worker_root = solve_root / "workers" / session_id
        if worker_root.name != session_id or not worker_root.is_dir():
            raise ValueError("matching worker directory does not exist")
        sandbox_metadata = worker_root / "sandbox.json"
        if sandbox_metadata.is_file():
            metadata = _load_metadata(root, str(sandbox_metadata))
            if metadata.get("session_id") != session_id or metadata.get("input_fingerprint") != current_fingerprint:
                raise ValueError("worker checkpoint sandbox identity or input fingerprint is stale")
        primitive = json.loads(args.primitive_json) if args.primitive_json else None
        if primitive is not None and not isinstance(primitive, dict):
            raise ValueError("--primitive-json must be a JSON object")
        return save_worker_checkpoint(
            worker_root, parent_session_id=args.parent_session_id, challenge_id=challenge.id,
            input_fingerprint=current_fingerprint, checkpoint_type=args.type, summary=args.summary,
            evidence=args.evidence, artifacts=args.artifact, useful_for=_csv(args.useful_for),
            recommended_action=args.recommended_action, confidence=args.confidence,
            current_exploit_hypothesis=args.current_exploit_hypothesis,
            decisive_experiment_performed=args.decisive_experiment_performed,
            observed_result=args.observed_result, exploit_proximity=args.exploit_proximity,
            next_exploit_action=args.next_exploit_action, decision=args.decision,
            working_poc_present=args.working_poc_present, remote_ready=args.remote_ready,
            research_drift_detected=args.research_drift_detected,
            repeated_command=args.repeated_command,
            sibling_insight_applied=args.sibling_insight_applied,
            hypothesis_family_changed=args.hypothesis_family_changed,
            primitive=primitive, declared_remote=bool(challenge.remotes),
        )
    if args.command == "worker-results-merge":
        _require_sol(args, "Only the parent Sol session may merge worker results.")
        paths = sorted((solve_root / "workers").glob("*/result.json"))
        current_fingerprint = str(record["source_fingerprint"])
        merged = merge_worker_result_files(paths, input_fingerprint=current_fingerprint)
        merged_path = solve_root / "workers" / "MERGED_RESULTS.json"
        atomic_json(merged_path, merged)
        return {**merged, "merged_path": str(merged_path)}
    if args.command == "worker-checkpoints-merge":
        _require_sol(args, "Only the parent Sol session may merge worker checkpoints.")
        merged = merge_worker_checkpoints(solve_root / "workers", input_fingerprint=current_fingerprint)
        return {**merged, "merged_path": str(solve_root / "workers" / "MERGED_CHECKPOINTS.json")}
    if args.command == "worker-checkpoints-show":
        _require_sol(args, "Only the parent Sol session may show all worker checkpoints.")
        return {"checkpoints": collect_worker_checkpoints(solve_root / "workers", input_fingerprint=current_fingerprint, since_sequence=args.since_sequence)}
    raise ValueError(f"unsupported internal command: {args.command}")


def _service_spec(
    manifest, challenge, record: dict[str, object], solve_root: Path,
    *, branch_id: str | None = None,
) -> ServiceSpec:
    plan = record.get("service_plan")
    if not isinstance(plan, dict) or not plan.get("kind"):
        raise ValueError("challenge preparation found no Dockerfile/Compose service plan")
    return ServiceSpec(
        contest_slug=manifest.slug, challenge_id=challenge.id,
        source=challenge_workspace(solve_root) / "input", workspace=solve_root, service_plan=plan,
        branch_id=branch_id,
    )


def _resource_overrides(args: argparse.Namespace) -> dict[str, object]:
    mapping = {
        "min_cpus": args.min_cpus, "preferred_cpus": args.preferred_cpus, "max_cpus": args.max_cpus,
        "min_memory_bytes": parse_bytes(args.min_memory) if args.min_memory else None,
        "preferred_memory_bytes": parse_bytes(args.preferred_memory) if args.preferred_memory else None,
        "max_memory_bytes": parse_bytes(args.max_memory) if args.max_memory else None,
        "storage_bytes": parse_bytes(args.storage) if args.storage else None,
        "gpu_memory_bytes": parse_bytes(args.gpu_memory) if args.gpu_memory else None,
        "parallelizable": args.parallelizable, "elastic": args.elastic, "preemptible": args.preemptible,
    }
    return {key: value for key, value in mapping.items() if value is not None}


def _validate_resize_budget(metadata: dict[str, object], cpus: float | None, memory: str | None, capacity: dict[str, object]) -> None:
    resources = metadata.get("resources") if isinstance(metadata.get("resources"), dict) else {}
    current_cpus = float(resources.get("cpus") or 0)
    current_memory = parse_bytes(resources.get("memory") or 0)
    desired_cpus = cpus if cpus is not None else current_cpus
    desired_memory = parse_bytes(memory) if memory is not None else current_memory
    cpu = capacity.get("cpu") if isinstance(capacity.get("cpu"), dict) else {}
    ram = capacity.get("memory") if isinstance(capacity.get("memory"), dict) else {}
    projected_cpu = float(cpu.get("reserved", 0)) - current_cpus + desired_cpus
    projected_memory = int(ram.get("reserved_bytes", 0)) - current_memory + desired_memory
    if projected_cpu > float(cpu.get("usable", 0)) + 1e-9:
        raise ValueError("sandbox resize would invade the host CPU reserve")
    if projected_memory > int(ram.get("usable_bytes", 0)):
        raise ValueError("sandbox resize would invade the host memory reserve")


def _apply_resize_plan(root: Path, solve_root: Path, plan: dict[str, object], args: argparse.Namespace) -> list[dict[str, object]]:
    results = []
    for action in plan.get("resize_actions", []):
        if not isinstance(action, dict) or action.get("action") != "RESIZE":
            continue
        session_id = str(action.get("session_id", ""))
        metadata_path = solve_root / "workers" / session_id / "sandbox.json"
        if not metadata_path.is_file():
            results.append({"session_id": session_id, "applied": False, "reason": "sandbox metadata not found"})
            continue
        try:
            metadata = _load_metadata(root, str(metadata_path))
            target = action.get("to") if isinstance(action.get("to"), dict) else {}
            receipt = resize(
                metadata, cpus=float(target["cpus"]), memory=int(target["memory_bytes"]),
                session_id=str(getattr(args, "parent_session_id", "sol-main")), session_role="sol",
            )
        except Exception as exc:
            results.append({"session_id": session_id, "applied": False, "reason": str(exc)})
        else:
            results.append({"session_id": session_id, "applied": True, "receipt": receipt})
    return results


def _cleanup_released_sandboxes(root: Path, solve_root: Path, plan: dict[str, object], parent_session_id: str) -> list[dict[str, object]]:
    results = []
    for released in plan.get("released", []):
        if not isinstance(released, dict) or not released.get("session_id"):
            continue
        session_id = str(released["session_id"])
        metadata_path = solve_root / "workers" / session_id / "sandbox.json"
        if not metadata_path.is_file():
            results.append({"session_id": session_id, "reclaimed": True, "reason": "no running sandbox metadata"})
            continue
        try:
            metadata = _load_metadata(root, str(metadata_path))
            cleanup_receipt = cleanup(metadata, session_id=parent_session_id, session_role="sol")
        except Exception as exc:
            results.append({"session_id": session_id, "reclaimed": False, "reason": str(exc), "recommendation": "Sol should export and clean this sandbox manually"})
        else:
            results.append({"session_id": session_id, "reclaimed": True, "receipt": cleanup_receipt})
    return results


def _rebalance_contest(root: Path, contest: str | None, *, apply: bool) -> dict[str, object]:
    output = root / "output"
    search_root = output / contest if contest else output
    if search_root.is_symlink() or not search_root.exists():
        raise ValueError("contest resource workspace is missing or unsafe")
    state_paths = sorted(search_root.glob("**/RESOURCE_STATE.json"))
    if not state_paths:
        return {"contest": contest, "plans": [], "reason": "no active resource ledgers"}
    capacity = detect_capacity(workspace=root).to_dict()
    plans = []
    for path in state_paths:
        solve_root = path.parent
        if (solve_root / "ACTIVE_RUN.json").is_file() and solve_root.parent.name != "runs":
            # Legacy compatibility projections are non-authoritative; their
            # resource ledger was migrated under the active run.
            continue
        ledger = ResourceLedger(solve_root)
        state_path = solve_root / "STATE.json"
        state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.is_file() else {}
        remote = state.get("remote_flag") if isinstance(state.get("remote_flag"), dict) else {}
        plan = ledger.rebalance(capacity, remote_flag_session=str(remote.get("branch_id")) if remote else None)
        entry: dict[str, object] = {"solve_root": str(solve_root), "plan": plan}
        if apply:
            dummy = argparse.Namespace(parent_session_id="sol-main")
            entry["applied_resizes"] = _apply_resize_plan(root, solve_root, plan, dummy)
            ledger.reconcile_apply(plan, entry["applied_resizes"])
        plans.append(entry)
        # Multiple simultaneous solves share the same host.  Consume the first
        # plan's assigned totals before planning the next ledger.
        used_cpu = sum(float(row.get("cpus", 0)) for row in plan["allocations"].values())
        used_memory = sum(int(row.get("memory_bytes", 0)) for row in plan["allocations"].values())
        used_storage = sum(int(row.get("storage_bytes", 0)) for row in plan["allocations"].values())
        capacity["cpu"]["usable"] = max(0.0, float(capacity["cpu"]["usable"]) - used_cpu)
        capacity["memory"]["usable_bytes"] = max(0, int(capacity["memory"]["usable_bytes"]) - used_memory)
        capacity["storage"]["usable_bytes"] = max(0, int(capacity["storage"]["usable_bytes"]) - used_storage)
    return {"contest": contest, "plans": plans, "applied": apply, "capacity": detect_capacity(workspace=root).to_dict()}


def _seed_race_resources(
    ledger: ResourceLedger, board: dict[str, object], contest: str, challenge_id: str,
    category: str, sol_session_id: str, input_bytes: int,
) -> None:
    branch_rows = board.get("planned_branches", board.get("active_branches", []))
    branch_ids = [
        str(branch["session_id"]) for branch in branch_rows
        if isinstance(branch, dict) and branch.get("session_id")
    ]
    ledger.begin_race([sol_session_id, *branch_ids])
    sol_request = default_request(
        contest=contest, challenge_id=challenge_id, session_id=sol_session_id,
        workload_class="exploit-development", priority="HIGH", input_bytes=input_bytes,
        overrides={"preferred_cpus": 6.0, "max_cpus": 10.0},
    )
    ledger.request(
        sol_request, actor_session_id=sol_session_id, actor_role="sol",
        inference={"confidence": "ROLE", "evidence": ["Sol direct deep-solve lane"]},
    )
    for branch in branch_rows:
        if not isinstance(branch, dict) or not branch.get("session_id"):
            continue
        packet = branch.get("prompt_packet") if isinstance(branch.get("prompt_packet"), dict) else {}
        tools = packet.get("tool_strategy") if isinstance(packet.get("tool_strategy"), list) else []
        inferred = infer_workload(
            command=[str(item) for item in tools], role=str(branch.get("role", "")), category=category,
        )
        workload = str(inferred["workload_class"])
        priority = "HIGH" if workload in {"exploit-development", "symbolic-execution", "fuzzing", "crypto-heavy"} else "NORMAL"
        request = default_request(
            contest=contest, challenge_id=challenge_id, session_id=str(branch["session_id"]),
            workload_class=workload, priority=priority, input_bytes=input_bytes,
        )
        ledger.request(request, actor_session_id=sol_session_id, actor_role="sol", inference=inferred)


def _caller(
    args: argparse.Namespace, *, metadata: dict[str, object] | None = None, branch: str | None = None,
) -> tuple[str, str]:
    role = str(getattr(args, "session_role", "sol"))
    configured = getattr(args, "session_id", None)
    environment_role = os.environ.get("CTF_OS_SESSION_ROLE")
    if environment_role == "child":
        environment_id = os.environ.get("CTF_OS_SESSION_ID")
        if role != "child" or not environment_id or configured != environment_id:
            raise ValueError("DENIED_SESSION_IDENTITY: child session identity cannot be overridden")
        return environment_id, "child"
    if configured:
        session_id = str(configured)
    elif role == "child":
        if not branch:
            raise ValueError("child session calls require --session-id")
        session_id = branch
    else:
        session_id = str(getattr(args, "parent_session_id", "sol-main"))
    return session_id, role


def _service_actor(args: argparse.Namespace, *, child_default: bool = False) -> ServiceActor:
    role = str(getattr(args, "session_role", "sol"))
    if child_default and getattr(args, "session_id", None) is None and role == "child" and not os.environ.get("CTF_OS_SESSION_ROLE"):
        session_id = "sandbox-bootstrap"
    else:
        session_id, role = _caller(args)
    return ServiceActor(
        session_id=session_id, role=role, parent_session_id=str(args.parent_session_id),
        recover_stale=bool(getattr(args, "recover_stale", False)),
    )


def _require_sol(args: argparse.Namespace, message: str) -> None:
    session_id, role = _caller(args)
    if role != "sol" or session_id != str(args.parent_session_id):
        raise ValueError(f"DENIED_CONTROLLER_ACTION: {message}")


def _require_delegation_sol(args: argparse.Namespace) -> None:
    """Check the controller without confusing a branch --session-id for caller identity."""
    if os.environ.get("CTF_OS_SESSION_ROLE") == "child" or getattr(args, "session_role", "sol") != "sol":
        raise ValueError("DENIED_CONTROLLER_ACTION: Only the parent Sol session may manage delegation plans and recommendations.")


def _compact_prepare(
    challenge,
    record: dict[str, object],
    solve_root: Path,
    launch_context: dict[str, object],
    launch_path: Path,
) -> dict[str, object]:
    workspace = challenge_workspace(solve_root)
    priority = list(launch_context["priority_files"])
    important_metadata = dict(launch_context["important_metadata"])
    return {
        "challenge": challenge.to_dict(),
        "priority_files": priority,
        "important_metadata": important_metadata,
        "problem_information": dict(launch_context["problem_information"]),
        "observation_hints": list(launch_context["observation_hints"]),
        "recommended_environment": dict(launch_context["recommended_environment"]),
        "service_plan": record.get("service_plan", {}),
        "state_summary": _state_summary(solve_root),
        "read_on_demand": [
            str(workspace / "inventory.json"), str(solve_root / "evidence.log"),
            str(solve_root / "findings.jsonl"), str(solve_root / "workers"),
        ],
        "solve_launch_path": str(launch_path),
        "solve_launch_context": launch_context,
        "preflight_record_path": str(workspace / "CHALLENGE-PREFLIGHT.json"),
        "solve_root": str(workspace),
        "run_root": str(solve_root),
        "run_id": launch_context.get("run_id"),
    }


def _state_summary(solve_root: Path) -> dict[str, object]:
    path = solve_root / "STATE.json"
    if not path.is_file():
        return {}
    state = json.loads(path.read_text(encoding="utf-8"))
    return {key: state.get(key) for key in (
        "status", "replay_verdict", "flag_candidate", "branches", "input_fingerprint", "updated_at",
    )}


def _prepare_challenge_same_session(
    root: Path, contest_selector: str | None, selector: str,
    session_input_json: str | None = None,
):
    """Prepare only the selected challenge in the current Sol session."""

    manifest = select_contest(discover_contests(root / "incoming"), contest_selector)
    packet = parse_session_input(session_input_json) if session_input_json else None
    challenge = resolve_session_challenge(root, manifest, selector, packet)
    try:
        record = prepare_selected_challenge(root, manifest, challenge)
    except Exception as exc:
        raise ValueError(f"Same-session challenge-local preflight failed because {exc}") from exc
    if record.get("status") != "READY":
        blockers = [str(value) for value in record.get("blockers", []) if str(value).strip()]
        detail = "; ".join(blockers) or "no blocker detail was recorded"
        raise ValueError(f"The selected challenge remains BLOCKED: {detail}")
    return manifest, challenge, load_challenge_preflight(root, manifest, challenge)


def _load_challenge_strict(root: Path, contest_selector: str | None, selector: str):
    """Load already-prepared selected state without whole-contest repair."""

    manifest = select_contest(discover_contests(root / "incoming"), contest_selector)
    challenge = resolve_session_challenge(root, manifest, selector)
    return manifest, challenge, load_challenge_preflight(root, manifest, challenge)


def _load_metadata(root: Path, value: str) -> dict[str, object]:
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    path = path.resolve()
    output = (root / "output").resolve()
    try:
        path.relative_to(output)
    except ValueError as exc:
        raise ValueError("sandbox metadata must be below repository output/") from exc
    if path.name != "sandbox.json" or not path.is_file() or path.is_symlink():
        raise ValueError("sandbox metadata path is missing or unsafe")
    metadata = json.loads(path.read_text(encoding="utf-8"))
    if Path(str(metadata.get("branch_root", ""))).resolve() != path.parent:
        raise ValueError("sandbox metadata branch root does not match its location")
    if Path(str(metadata.get("metadata_path", ""))).resolve() != path:
        raise ValueError("sandbox metadata self-path does not match its location")
    branch_root = path.parent
    branch = str(metadata.get("branch", ""))
    if branch_root.parent.name != "workers" or branch_root.name != branch:
        raise ValueError("sandbox metadata is not in its declared workers/<branch> directory")
    challenge_state = branch_root.parents[1] / "STATE.json"
    if not challenge_state.is_file():
        raise ValueError("sandbox metadata has no challenge STATE.json")
    state = json.loads(challenge_state.read_text(encoding="utf-8"))
    if state.get("challenge_id") != metadata.get("challenge_id"):
        raise ValueError("sandbox metadata challenge id does not match STATE.json")
    if state.get("input_fingerprint") != metadata.get("input_fingerprint"):
        raise ValueError("sandbox metadata input fingerprint is stale")
    expected_labels = {
        "ctf-os": "true", "ctf-os.contest": str(metadata.get("contest_slug", "")),
        "ctf-os.challenge_id": str(metadata.get("challenge_id", "")), "ctf-os.branch": branch,
    }
    if metadata.get("labels") != expected_labels:
        raise ValueError("sandbox metadata labels are not canonical")
    return metadata


def _update_branch_state(solve_root: Path, branch: str, status: str, metadata_path: str) -> None:
    path = solve_root / "STATE.json"
    with state_lock(solve_root):
        state = json.loads(path.read_text(encoding="utf-8"))
        branches = [item for item in state.get("branches", []) if item.get("id") != branch]
        branches.append({"id": branch, "status": status, "metadata_path": metadata_path})
        state["branches"] = sorted(branches, key=lambda item: item["id"])
        atomic_json(path, state)


def _cleanup_expired_timeout_retention(root: Path, sol_session_id: str) -> list[dict[str, object]]:
    """Clean retained timeout sandboxes whose conservative TTL has expired."""
    cleaned: list[dict[str, object]] = []
    for receipt_path in sorted((root / "output").glob("**/workers/*/timeout-receipt.json")):
        if receipt_path.is_symlink() or not receipt_path.is_file():
            continue
        try:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            recorded = datetime.fromisoformat(str(receipt["recorded_at"]).replace("Z", "+00:00"))
            ttl = int(receipt.get("retention_ttl_seconds", 21600))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            continue
        if receipt.get("status") != "TIMED_OUT_RETAINED" or ttl < 1:
            continue
        if (datetime.now(timezone.utc) - recorded).total_seconds() < ttl:
            continue
        metadata_path = receipt_path.parent / "sandbox.json"
        try:
            metadata = _load_metadata(root, str(metadata_path))
            result = cleanup(metadata, session_id=sol_session_id, session_role="sol")
            cleaned.append({"metadata": str(metadata_path), **result})
        except Exception as exc:
            cleaned.append({"metadata": str(metadata_path), "removed": False, "error": str(exc)})
    return cleaned


def _doctor_selected_run(run: Path) -> dict[str, object]:
    """Read-only projection health for one explicitly selected exact run."""

    state_path = run / "STATE.json"
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state_health = "VALID" if isinstance(state, dict) else "CORRUPT"
    except (OSError, json.JSONDecodeError):
        state = None
        state_health = "MISSING" if not state_path.exists() else "CORRUPT"
    counts = {"PENDING": 0, "APPLIED": 0, "FAILED": 0, "NOT_REQUIRED": 0}
    malformed: list[str] = []
    projection_root = run / "receipt-projections"
    for path in sorted(projection_root.glob("*.json")) if projection_root.is_dir() else []:
        if path.is_symlink() or not path.is_file():
            malformed.append(path.name)
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            rows = payload.get("projections") if isinstance(payload, dict) else None
            if not isinstance(rows, dict):
                raise ValueError("missing projections")
            for row in rows.values():
                status = row.get("status") if isinstance(row, dict) else None
                if status not in counts:
                    raise ValueError("invalid status")
                counts[str(status)] += 1
        except (OSError, json.JSONDecodeError, ValueError):
            malformed.append(path.name)
    return {
        "run_id": run.name, "path": str(run), "state_health": state_health,
        "state_status": state.get("status") if isinstance(state, dict) else None,
        "projection_statuses": counts, "malformed_projection_manifests": malformed,
        "repair_performed": False,
    }


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _candidate_from_args(args: argparse.Namespace) -> BranchCandidate:
    return BranchCandidate.create(session_id=args.session_id, role=args.role, hypothesis_family=args.hypothesis_family, hypothesis=args.hypothesis, scope=_csv(args.scope), tool_strategy=_csv(args.tool_strategy), expected_artifacts=args.expected_artifact)


def _routing_from_args(
    args: argparse.Namespace, candidate: BranchCandidate, *, purpose: str | None,
) -> tuple[dict[str, object] | None, dict[str, object]]:
    context: dict[str, object] = {
        "role": candidate.role, "purpose": purpose,
        "hypothesis": candidate.hypothesis,
        "hypothesis_family": candidate.hypothesis_family,
        "tool_strategy": list(candidate.tool_strategy),
        "expected_artifacts": list(candidate.expected_artifacts),
    }
    raw_context = getattr(args, "routing_context_json", None)
    if raw_context:
        supplied = json.loads(raw_context)
        if not isinstance(supplied, dict):
            raise ValueError("--routing-context-json must be a JSON object")
        context.update(supplied)
    profile = getattr(args, "routing_profile", None)
    if not profile:
        if any((
            getattr(args, "routing_reason", None),
            getattr(args, "routing_evidence", []),
            getattr(args, "fallback_profile", None),
            getattr(args, "fallback_reason", None),
            raw_context,
        )):
            raise ValueError("routing metadata requires --routing-profile")
        return None, context
    reason = getattr(args, "routing_reason", None)
    references = getattr(args, "routing_evidence", [])
    if not reason or not references:
        recommendation = recommend_routing_profile(context)
        raise ValueError(
            "routed branch requires --routing-reason and --routing-evidence; "
            f"evidence recommendation was {recommendation['routing_profile']}"
        )
    kwargs: dict[str, object] = {}
    if getattr(args, "fallback_profile", None):
        kwargs["fallback_profile"] = args.fallback_profile
        kwargs["fallback_reason"] = args.fallback_reason
    contract = build_routing_contract(
        profile, routing_reason=reason, routing_evidence=references,
        branch_evidence=context, requested_reasoning=args.requested_reasoning,
        **kwargs,
    )
    return contract, context


def _legacy_projection_enabled(workspace: Path) -> bool:
    pointer = workspace / "ACTIVE_RUN.json"
    if not pointer.is_file() or pointer.is_symlink() or not (workspace / "STATE.json").is_file():
        return False
    try:
        return json.loads(pointer.read_text(encoding="utf-8")).get("legacy_compatibility_view") is True
    except (OSError, json.JSONDecodeError):
        return False


def _mirror_legacy_worker_metadata(
    workspace: Path, run: Path, branch: str, metadata: dict[str, object],
) -> None:
    if not _legacy_projection_enabled(workspace):
        return
    target = workspace / "workers" / branch / "sandbox.json"
    projected = dict(metadata)
    projected["compatibility_view"] = True
    projected["authoritative_metadata_path"] = str(run / "workers" / branch / "sandbox.json")
    atomic_json(target, projected)


def _adopt_legacy_worker_exports(workspace: Path, run: Path, branch: str) -> None:
    if not _legacy_projection_enabled(workspace):
        return
    source = workspace / "workers" / branch
    target = run / "workers" / branch
    if not source.is_dir() or source.is_symlink():
        return
    for item in source.rglob("*"):
        if item.is_symlink():
            raise ValueError("legacy worker compatibility export contains a symlink")
        if item.is_file() and item.name != "sandbox.json":
            relative = item.relative_to(source)
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if not destination.exists():
                shutil.copy2(item, destination)


if __name__ == "__main__":
    raise SystemExit(main())
