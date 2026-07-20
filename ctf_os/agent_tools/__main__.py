from __future__ import annotations

import argparse
from contextlib import nullcontext
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

from ..challenge import SelectionError, resolve_selector
from ..challenge_scope import remove_challenge_secrets
from ..contest import ContestError, discover_contests, select_contest
from ..evidence import append_finding
from ..doctor import run_doctor
from ..delegation import (
    BranchCandidate, add_branch, branch_utility, init_plan, load_plan,
    record_admission, template_recommendation, update_branch,
    prepare_branch_replacement, confirm_branch_start,
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
from ..preflight import (
    load_challenge_preflight, prepare_selected_challenge, prepared_tree_fingerprint,
)
from ..scaffold import initialize_contest
from ..sandbox.network import parse_remotes, resolve_targets
from ..sandbox.resources import gpu_available, sandbox_gc, sandbox_status
from ..sandbox.runtime import (
    SandboxSpec, cleanup, create, execute, export_artifacts, probe_service_connectivity, resize,
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
from ..workspace import atomic_json, challenge_root, initialize_solve_files, safe_under, state_lock
from ..worker import (
    collect_worker_checkpoints, load_worker_result, merge_worker_checkpoints,
    merge_worker_result_files, save_worker_checkpoint, save_worker_result,
)
from ..verification import record_remote_flag


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
    prepare = commands.add_parser("prepare-challenge")
    prepare.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    prepare.add_argument("selector")
    prepare.add_argument("--contest")
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
        race_start = commands.add_parser("race-plan-start")
        race_start.add_argument("selector"); race_start.add_argument("--contest")
        race_start.add_argument("--tier", required=True, type=int)
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
        replacement.add_argument("--evidence-contract", action="append", required=True)
        replacement.add_argument("--success-condition", required=True); replacement.add_argument("--kill-condition", required=True)
        replacement.add_argument("--maximum-steps", type=int, required=True); replacement.add_argument("--budget-seconds", type=int, required=True)
        replacement.add_argument("--requested-model-role", required=True); replacement.add_argument("--requested-reasoning", required=True)
        _add_delegation_controller_args(replacement)
        start_confirm = commands.add_parser("branch-start-confirm")
        start_confirm.add_argument("selector"); start_confirm.add_argument("--contest")
        start_confirm.add_argument("--replacement-request-id", required=True); start_confirm.add_argument("--session-id", required=True)
        start_confirm.add_argument("--native-session-observed", required=True); start_confirm.add_argument("--runtime-observation-evidence", required=True)
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
    commands.add_parser("doctor")
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
        receipt.add_argument("--exploit-artifact", required=True); receipt.add_argument("argv", nargs=argparse.REMAINDER)
        _add_session_args(receipt)
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
    args = build_parser().parse_args(argv)
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
    if args.command == "init-contest":
        return initialize_contest(root, args.name)
    if args.command == "doctor":
        return run_doctor(root)
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
        command = raw_command
        if command and command[0] == "--":
            command.pop(0)
        session_id, role = _caller(args, metadata=metadata)
        timeout = timeout_seconds(args.timeout_profile) if args.timeout_profile else args.timeout
        result = execute(
            metadata, command, timeout, session_id=session_id, session_role=role,
            timeout_profile=args.timeout_profile, retain_on_timeout=args.retain_on_timeout,
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
        manifest, challenge, record = _prepare_challenge_same_session(root, args.contest, args.selector)
        solve_root = challenge_root(root, manifest, challenge)
        initialize_solve_files(solve_root, challenge)
        launch_context = build_solve_launch_context(challenge, record)
        launch_path = save_solve_launch_context(solve_root, launch_context)
        return _compact_prepare(challenge, record, solve_root, launch_context, launch_path)

    manifest, challenge, record = _load_challenge_strict(root, args.contest, args.selector)
    if os.environ.get("CTF_OS_SESSION_ROLE") == "child":
        if (
            os.environ.get("CTF_OS_CHALLENGE_ID") != challenge.id
            or os.environ.get("CTF_OS_CONTEST_SLUG") != manifest.slug
        ):
            raise ValueError("DENIED_CHALLENGE_SCOPE: child session may access only its assigned challenge")
    solve_root = challenge_root(root, manifest, challenge)
    initialize_solve_files(solve_root, challenge)
    current_fingerprint = str(record["source_fingerprint"])
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
            input_bytes=int(record.get("total_size", 0)), gpu_required=args.gpu_required,
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
            specs = parse_branch_spec(args.branch_spec, category=challenge.category, tier=args.tier, template_path=template_path)
            board = start_race_plan(
                solve_root, challenge_id=challenge.id, input_fingerprint=current_fingerprint,
                parent_session_id=args.parent_session_id, category=challenge.category,
                tier=args.tier, tier_reason=args.tier_reason, branch_specs=specs,
                threshold=args.threshold,
            )
            state_path = solve_root / "STATE.json"
            with state_lock(solve_root):
                race_state = json.loads(state_path.read_text(encoding="utf-8"))
                race_state["status"] = "RACE_RUNNING"; race_state["updated_at"] = datetime.now(timezone.utc).isoformat()
                atomic_json(state_path, race_state)
            _seed_race_resources(
                ledger, board, manifest.slug, challenge.id, challenge.category,
                args.parent_session_id, int(record.get("total_size", 0)),
            )
            capacity = detect_capacity(workspace=root)
            resource_plan = ledger.rebalance(capacity, tier=args.tier)
            board["resource_plan"] = resource_plan
            board["resource_use"] = resource_panel(capacity.to_dict(), ledger.load())
            board["next_action"] = (
                "Sol must immediately create capacity-admitted children with native delegation; "
                "retain unallocated prompt packets as launch recommendations and continue the Sol deep-solve lane."
            )
            return board
        if args.command == "race-board":
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
            return add_branch(solve_root, input_fingerprint=current_fingerprint, candidate=candidate, evidence_contract=args.evidence_contract, success_condition=args.success_condition, kill_condition=args.kill_condition, maximum_steps=args.maximum_steps, budget_seconds=args.budget_seconds, requested_model_role=args.requested_model_role, requested_reasoning=args.requested_reasoning, purpose=args.purpose)
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
            return prepare_branch_replacement(
                solve_root, input_fingerprint=current_fingerprint,
                superseded_branch_id=args.superseded_branch_id, candidate=_candidate_from_args(args),
                kill_reason=args.kill_reason, distinct_mechanism_proof=args.distinct_mechanism_proof,
                evidence_contract=args.evidence_contract, success_condition=args.success_condition,
                kill_condition=args.kill_condition, maximum_steps=args.maximum_steps,
                budget_seconds=args.budget_seconds, requested_model_role=args.requested_model_role,
                requested_reasoning=args.requested_reasoning,
            )
        if args.command == "branch-start-confirm":
            return confirm_branch_start(
                solve_root, input_fingerprint=current_fingerprint,
                replacement_request_id=args.replacement_request_id, session_id=args.session_id,
                native_session_observed=args.native_session_observed,
                runtime_observation_evidence=args.runtime_observation_evidence,
                sandbox_metadata_path=args.sandbox_metadata_path,
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
        )
        if receipt.get("state") == "SUBMISSION_RECOMMENDED":
            resource_state = ledger.load()
            receipt["resource_reclamation"] = _cleanup_released_sandboxes(
                root, solve_root, resource_state.get("last_plan", {}), args.parent_session_id,
            )
        return receipt
    if args.command == "replay":
        _require_sol(args, "Only the parent Sol session may make the final replay judgment.")
        return run_replay(root, manifest, challenge, record, service_actor=_service_actor(args))
    if args.command == "sandbox-create":
        if record["status"] != "READY":
            raise ValueError(f"challenge is not READY: {record.get('blockers')}")
        branch_root = solve_root / "workers" / args.branch
        input_path = solve_root / "input"
        if input_path.is_symlink() or not input_path.is_dir():
            raise ValueError("prepared challenge input is missing or unsafe; run same-session preparation again")
        expected_source = input_path.resolve()
        try:
            expected_source.relative_to(solve_root.resolve())
        except ValueError as exc:
            raise ValueError("prepared challenge input escapes its challenge workspace") from exc
        if Path(str(record.get("prepared_input", ""))).resolve() != expected_source:
            raise ValueError("intake index prepared_input is outside the selected challenge workspace")
        if record.get("prepared_fingerprint") != prepared_tree_fingerprint(input_path):
            raise ValueError("prepared challenge input changed after preparation; run same-session preparation again")
        supported_profiles = {'pwn', 'web', 'rev', 'crypto', 'forensic', 'misc', 'osint', 'ai', 'cloud'}
        image = args.image or str(record.get("recommended_image") or f"ctf-os-sandbox:{challenge.category if challenge.category in supported_profiles else 'base'}")
        profile = args.resource_profile or str(record.get("recommended_resource_profile") or "standard")
        targets = resolve_targets(parse_remotes(challenge.remotes))
        service_network = None
        attachment_service: ServiceSpec | None = None
        endpoints: tuple[str, ...] = ()
        service_context: dict[str, object] = {
            "exists": False, "state": "UNAVAILABLE", "attach_only": True,
            "lifecycle_owner": args.parent_session_id,
        }
        plan = record.get("service_plan")
        if isinstance(plan, dict) and plan.get("kind") in {"dockerfile", "compose"}:
            service = _service_spec(manifest, challenge, record, solve_root)
            inspection = service_inspect(service, actor=_service_actor(args, child_default=True))
            owner = inspection.get("ownership") if isinstance(inspection.get("ownership"), dict) else {}
            containers = inspection.get("containers") if isinstance(inspection.get("containers"), list) else []
            network = inspection.get("network") if isinstance(inspection.get("network"), dict) else {}
            active = (
                owner.get("state") == "RUNNING" and bool(containers)
                and all(item.get("state") == "running" for item in containers if isinstance(item, dict))
                and network.get("owned") is True and network.get("internal") is True
            )
            service_context = {
                "exists": bool(owner), "state": owner.get("state", "UNOWNED"),
                "alias": service.stable_alias, "network": service.network,
                "lifecycle_owner": owner.get("owner_session_id"), "attach_only": True,
            }
            if active:
                if owner.get("owner_session_id") != args.parent_session_id:
                    raise ValueError(
                        f"managed service owner mismatch: expected {args.parent_session_id}, "
                        f"found {owner.get('owner_session_id')}"
                    )
                metadata = inspection.get("metadata") if isinstance(inspection.get("metadata"), dict) else {}
                endpoint_rows = metadata.get("service_endpoints") if isinstance(metadata.get("service_endpoints"), list) else []
                endpoints = tuple(
                    str(item["target"]) for item in endpoint_rows
                    if isinstance(item, dict) and item.get("target")
                )
                if not endpoints:
                    raise ValueError("active managed service has no stable endpoint metadata")
                targets = ()
                service_network = service.network
                attachment_service = service
                service_context["endpoints"] = endpoint_rows
                service_context["service_url"] = endpoints[0]
                service_context["instructions"] = (
                    "Managed service is already running. You may inspect, connect, send requests, "
                    "and run PoCs. Service lifecycle is owned by the parent Sol session; this worker is attach-only."
                )
            elif args.service or owner.get("state") == "RUNNING" or bool(containers):
                reasons = []
                if not owner: reasons.append("owner missing")
                if owner and owner.get("state") != "RUNNING": reasons.append("service not running")
                if owner.get("state") == "RUNNING" and not containers: reasons.append("service container missing")
                if containers and not all(
                    item.get("state") == "running" for item in containers if isinstance(item, dict)
                ):
                    reasons.append("service container not running")
                if network.get("exists") is not True: reasons.append("network missing")
                elif network.get("owned") is not True: reasons.append("network is not owned")
                elif network.get("internal") is not True: reasons.append("network is not internal")
                raise ValueError("managed service attachment failed: " + ", ".join(reasons or ["service unavailable"]))
        elif args.service:
            raise ValueError("managed service attachment failed: intake has no service plan")
        session_id, session_role = _caller(args, branch=args.branch)
        resource_state = ledger.load()
        request_raw = resource_state.get("requests", {}).get(session_id)
        allocation = resource_state.get("allocations", {}).get(session_id)
        if isinstance(request_raw, dict) and not isinstance(allocation, dict):
            scheduler_plan = ledger.rebalance(detect_capacity(workspace=root))
            allocation = scheduler_plan.get("allocations", {}).get(session_id)
            if not isinstance(allocation, dict):
                waiting = next((row for row in scheduler_plan.get("waiting", []) if row.get("session_id") == session_id), {})
                raise ValueError(f"resource scheduler cannot admit sandbox minimum: {waiting.get('reason', 'insufficient budget')}")
        inferred = infer_workload(
            files=[str(item.get("path", "")) for item in record.get("files", []) if isinstance(item, dict)],
            role=args.branch, category=challenge.category,
            override=str(request_raw.get("workload_class")) if isinstance(request_raw, dict) else None,
        )
        spec = SandboxSpec(
            contest_slug=manifest.slug, challenge_id=challenge.id, branch=args.branch,
            source=expected_source, branch_root=branch_root,
            input_fingerprint=str(record["source_fingerprint"]),
            targets=targets, image=image, resource_profile=profile,
            service_network=service_network, local_endpoints=endpoints,
            session_id=session_id, parent_session_id=args.parent_session_id,
            session_role=session_role, service_context=service_context,
            category=challenge.category,
            memory=str(allocation["memory_bytes"]) if isinstance(allocation, dict) else None,
            cpus=float(allocation["cpus"]) if isinstance(allocation, dict) else None,
            storage=str(allocation["storage_bytes"]) if isinstance(allocation, dict) else None,
            workload_class=str(inferred["workload_class"]),
            resource_priority=str(request_raw.get("priority", "NORMAL")) if isinstance(request_raw, dict) else "NORMAL",
            resource_request_override=request_raw if isinstance(request_raw, dict) else None,
            gpu_enabled=(
                isinstance(allocation, dict) and allocation.get("gpu_device") is not None
            ) or (not isinstance(request_raw, dict) and challenge.category == "ai" and gpu_available()),
            gpu_device=int(allocation["gpu_device"]) if isinstance(allocation, dict) and allocation.get("gpu_device") is not None else None,
        )
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
                _update_branch_state(solve_root, args.branch, "RUNNING", str(metadata["metadata_path"]))
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
            primitive=primitive,
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
        raise ValueError("intake found no Dockerfile/Compose challenge service plan")
    return ServiceSpec(
        contest_slug=manifest.slug, challenge_id=challenge.id,
        source=solve_root / "input", workspace=solve_root, service_plan=plan,
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
    branch_ids = [
        str(branch["session_id"]) for branch in board.get("active_branches", [])
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
    for branch in board.get("active_branches", []):
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
            str(solve_root / "inventory.json"), str(solve_root / "evidence.log"),
            str(solve_root / "findings.jsonl"), str(solve_root / "workers"),
        ],
        "solve_launch_path": str(launch_path),
        "solve_launch_context": launch_context,
        "preflight_record_path": str(solve_root / "CHALLENGE-PREFLIGHT.json"),
        "solve_root": str(solve_root),
    }


def _state_summary(solve_root: Path) -> dict[str, object]:
    path = solve_root / "STATE.json"
    if not path.is_file():
        return {}
    state = json.loads(path.read_text(encoding="utf-8"))
    return {key: state.get(key) for key in (
        "status", "replay_verdict", "flag_candidate", "branches", "input_fingerprint", "updated_at",
    )}


def _prepare_challenge_same_session(root: Path, contest_selector: str | None, selector: str):
    """Prepare only the selected challenge in the current Sol session."""

    sync_contest_manifest(root, contest_selector)
    manifest = select_contest(discover_contests(root / "incoming"), contest_selector)
    challenge = resolve_selector(manifest.challenges, selector)
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

    sync_contest_manifest(root, contest_selector)
    manifest = select_contest(discover_contests(root / "incoming"), contest_selector)
    challenge = resolve_selector(manifest.challenges, selector)
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


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _candidate_from_args(args: argparse.Namespace) -> BranchCandidate:
    return BranchCandidate.create(session_id=args.session_id, role=args.role, hypothesis_family=args.hypothesis_family, hypothesis=args.hypothesis, scope=_csv(args.scope), tool_strategy=_csv(args.tool_strategy), expected_artifacts=args.expected_artifact)


if __name__ == "__main__":
    raise SystemExit(main())
