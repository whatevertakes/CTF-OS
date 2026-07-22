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
from ..swarm import (
    confirm_native_spawn, flag_found, high_value_events, initialize_swarm,
    record_attack_event, record_command_after_execution, record_spawn_failure,
    replace_lane, start_max_endgame, stop_confirmed,
    submission_result as record_swarm_submission_result,
    swarm_status,
)
from ..triage import finalize_triage, prepare_triage
from ..timeouts import timeout_seconds
from ..tui import resource_panel
from ..workspace import (
    atomic_json, challenge_root, challenge_workspace, initialize_solve_files,
    list_attempts, recover_run_state, resolve_active_run, resolve_run_raw, resume_attempt, safe_under,
    resolve_exact_run, show_attempt, start_fresh_attempt, state_lock, target_revisions,
)
from ..claude_handoff import save_handoff


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
            "Use --fresh-attempt for independent execution; every Solve uses the first-to-flag swarm."
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
    if not child_surface:
        attempt_start = commands.add_parser("attempt-start", help="start one isolated fresh attempt")
        attempt_start.add_argument("selector"); attempt_start.add_argument("--contest")
        attempt_start.add_argument("--attempt-id"); attempt_start.add_argument("--transformation-seed")
        _add_session_args(attempt_start)
        attempt_resume = commands.add_parser("attempt-resume", help="resume current or exact prior attempt")
        attempt_resume.add_argument("selector"); attempt_resume.add_argument("--contest")
        attempt_resume.add_argument("--run-id"); _add_session_args(attempt_resume)
        attempt_list = commands.add_parser("attempt-list", help="list prior isolated attempts")
        attempt_list.add_argument("selector"); attempt_list.add_argument("--contest"); _add_session_args(attempt_list)
        attempt_show = commands.add_parser("attempt-show", help="show an exact prior attempt")
        attempt_show.add_argument("selector"); attempt_show.add_argument("--contest")
        attempt_show.add_argument("--run-id", required=True); _add_session_args(attempt_show)
        repair_run_parser = commands.add_parser("repair-run")
        repair_run_parser.add_argument("selector"); repair_run_parser.add_argument("--contest")
        repair_run_parser.add_argument("--run-id"); _add_session_args(repair_run_parser)
        handoff_save = commands.add_parser(
            "claude-handoff-save",
            help=argparse.SUPPRESS,
            description="Store the current exact run's manually composed HANDOFF.md.",
        )
        handoff_save.add_argument("selector"); handoff_save.add_argument("--contest", required=True)
        handoff_save.add_argument("--run-id", required=True)
        handoff_save.add_argument("--markdown-file", required=True)
        _add_session_args(handoff_save)
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

    swarm_show = commands.add_parser("swarm-status")
    swarm_show.add_argument("selector"); swarm_show.add_argument("--contest"); _add_session_args(swarm_show)
    attack_event = commands.add_parser("attack-event")
    attack_event.add_argument("selector"); attack_event.add_argument("--contest")
    attack_event.add_argument("--lane", required=True); attack_event.add_argument("--type", required=True)
    attack_event.add_argument("--summary", required=True); attack_event.add_argument("--artifact")
    attack_event.add_argument("--observed-output"); attack_event.add_argument("--next-attack")
    attack_event.add_argument("argv", nargs=argparse.REMAINDER); _add_session_args(attack_event)
    attack_events = commands.add_parser("attack-events-show")
    attack_events.add_argument("selector"); attack_events.add_argument("--contest"); attack_events.add_argument("--since")
    _add_session_args(attack_events)
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
        spawn_confirm = commands.add_parser("swarm-spawn-confirm")
        spawn_confirm.add_argument("selector"); spawn_confirm.add_argument("--contest")
        spawn_confirm.add_argument("--lane", required=True); spawn_confirm.add_argument("--native-session", required=True)
        spawn_confirm.add_argument("--operation-id"); _add_session_args(spawn_confirm)
        spawn_failed = commands.add_parser("swarm-spawn-failed")
        spawn_failed.add_argument("selector"); spawn_failed.add_argument("--contest")
        spawn_failed.add_argument("--lane", required=True); spawn_failed.add_argument("--error", required=True)
        _add_session_args(spawn_failed)
        replacement = commands.add_parser("swarm-replace")
        replacement.add_argument("selector"); replacement.add_argument("--contest")
        replacement.add_argument("--lane", required=True)
        replacement.add_argument("--role", required=True, choices=("alternate-family", "failure-analysis", "striker"))
        replacement.add_argument("--reason", required=True); replacement.add_argument("--native-stop-session")
        replacement.add_argument("--actual-failure", required=True); replacement.add_argument("--untried-family", required=True)
        _add_session_args(replacement)
        endgame = commands.add_parser("swarm-endgame")
        endgame.add_argument("selector"); endgame.add_argument("--contest")
        endgame.add_argument("--lane", required=True); endgame.add_argument("--native-stop-session", required=True)
        _add_session_args(endgame)
        stop = commands.add_parser("swarm-stop-confirm")
        stop.add_argument("selector"); stop.add_argument("--contest")
        stop.add_argument("--lane", required=True); stop.add_argument("--native-session", required=True)
        _add_session_args(stop)
        found = commands.add_parser("flag-found")
        found.add_argument("selector"); found.add_argument("--contest"); found.add_argument("--lane", required=True)
        found.add_argument("--candidate", required=True); found.add_argument("--observed-output", required=True)
        found.add_argument("--artifact"); found.add_argument("--source", required=True)
        found.add_argument("argv", nargs=argparse.REMAINDER); _add_session_args(found)
        submission = commands.add_parser("submission-result")
        submission.add_argument("selector"); submission.add_argument("--contest")
        submission.add_argument("--run-id", required=True); submission.add_argument("--candidate", required=True)
        submission.add_argument("--result", required=True, choices=("accepted", "wrong")); _add_session_args(submission)
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
    return parser


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
    direct_argv_commands = {"attack-event", "flag-found"}
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
            result["selected_run"] = _doctor_selected_run(selected)
        elif args.run_id:
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
        result["attack_event"] = record_command_after_execution(
            Path(str(metadata["branch_root"])).parents[1],
            lane_id=str(metadata.get("branch") or session_id), command=command, result=result,
        )
        return result
    if args.command == "sandbox-cleanup":
        metadata = _load_metadata(root, args.metadata)
        session_id, role = _caller(args, metadata=metadata)
        result = cleanup(metadata, session_id=session_id, session_role=role)
        result["challenge_secrets_cleanup"] = remove_challenge_secrets(Path(str(metadata["branch_root"])))
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
            )
        )
        launch_state = json.loads((solve_root / "STATE.json").read_text(encoding="utf-8"))
        launch_context = build_solve_launch_context(challenge, record)
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
        prepared["solve_engine"] = "first-to-flag"
        swarm = initialize_swarm(
            solve_root, challenge=challenge, record=record,
            root_session=getattr(args, "parent_session_id", "sol-main"),
        )
        prepared["swarm"] = swarm
        prepared["spawn_queue"] = swarm["spawn_queue"]
        return prepared

    if args.command == "attempt-start":
        _require_sol(args, "Only Sol may start a fresh attempt.")
        manifest, challenge, record = _prepare_challenge_same_session(
            root, args.contest, args.selector, None,
        )
        workspace = challenge_root(root, manifest, challenge)
        run = start_fresh_attempt(
            workspace, challenge, str(record["source_fingerprint"]),
            attempt_id=args.attempt_id, transformation_seed=args.transformation_seed,
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

    if args.command == "claude-handoff-save":
        _require_sol(args, "Only the current parent Sol session may save a Claude handoff.")
        manifest = select_contest(discover_contests(root / "incoming"), args.contest)
        challenge = resolve_session_challenge(root, manifest, args.selector)
        workspace = challenge_root(root, manifest, challenge)
        current = resolve_active_run(workspace, migrate=False)
        run = resolve_exact_run(workspace, args.run_id)
        if current != run:
            raise ValueError("requested run_id is not the current exact run")
        run_manifest_path = run / "RUN_MANIFEST.json"
        if run_manifest_path.is_symlink() or not run_manifest_path.is_file():
            raise ValueError("current run manifest is missing or unsafe")
        run_manifest = json.loads(run_manifest_path.read_text(encoding="utf-8"))
        run_challenge = run_manifest.get("challenge")
        if (
            not isinstance(run_challenge, dict)
            or run_manifest.get("run_id") != args.run_id
            or run_challenge.get("challenge_id") != challenge.id
        ):
            raise ValueError("current run manifest does not match the selected challenge/run")
        path = save_handoff(
            root, contest=manifest.slug, challenge=challenge.id,
            markdown_file=Path(args.markdown_file),
        )
        return {
            "contest": manifest.slug, "challenge": challenge.id,
            "run_id": run.name, "path": str(path),
            "relative_path": str(path.relative_to(root)),
        }

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
    if args.command == "repair-run":
        _require_sol(args, "Only Root may repair the exact run state.")
        selected = solve_root if not args.run_id else safe_under(challenge_workspace(solve_root) / "runs", Path(args.run_id))
        if selected.is_symlink() or not selected.is_dir():
            raise ValueError("repair run does not exist in this challenge workspace")
        return {"run_id": selected.name, "state": recover_run_state(selected, force=True)}
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
        return observation
    if args.command in {"resource-plan", "scheduler-rebalance"}:
        _require_sol(args, "Only the parent Sol session may plan or apply global allocations.")
        capacity = detect_capacity(workspace=root)
        plan = (
            ledger.plan(capacity)
            if args.command == "resource-plan"
            else ledger.rebalance(capacity)
        )
        if args.command == "scheduler-rebalance" and args.apply:
            plan["applied_resizes"] = _apply_resize_plan(root, solve_root, plan, args)
            ledger.reconcile_apply(plan, plan["applied_resizes"])
        elif args.command == "scheduler-rebalance":
            plan["apply_required"] = True
        return plan
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
    if args.command == "swarm-status":
        return swarm_status(solve_root)
    if args.command == "attack-events-show":
        return {"events": high_value_events(solve_root, since=args.since)}
    if args.command == "attack-event":
        session_id, role = _caller(args)
        if role == "child" and session_id != args.lane:
            raise ValueError("DENIED_SESSION_IDENTITY: child may write only its own lane")
        argv = list(args.argv)
        if argv and argv[0] == "--":
            argv.pop(0)
        return record_attack_event(
            solve_root, lane_id=args.lane, event_type=args.type, summary=args.summary,
            command=argv, artifact=args.artifact, observed_output=args.observed_output,
            next_attack=args.next_attack,
        )
    if args.command == "swarm-spawn-confirm":
        _require_sol(args, "Only Root may confirm native child start.")
        return confirm_native_spawn(
            solve_root, lane_id=args.lane, native_session=args.native_session,
            operation_id=args.operation_id,
        )
    if args.command == "swarm-spawn-failed":
        _require_sol(args, "Only Root may record native child start failure.")
        return record_spawn_failure(solve_root, lane_id=args.lane, error=args.error)
    if args.command == "swarm-replace":
        _require_sol(args, "Only Root may replace a native lane.")
        return replace_lane(
            solve_root, lane_id=args.lane, replacement_role=args.role,
            reason=args.reason, native_stop_session=args.native_stop_session,
            actual_failure=args.actual_failure, untried_family=args.untried_family,
        )
    if args.command == "swarm-endgame":
        _require_sol(args, "Only Root may promote a bounded Sol max endgame lane.")
        return start_max_endgame(
            solve_root, lane_id=args.lane, native_stop_session=args.native_stop_session,
        )
    if args.command == "swarm-stop-confirm":
        _require_sol(args, "Only Root may confirm native child stop.")
        return stop_confirmed(
            solve_root, lane_id=args.lane, native_session=args.native_session,
        )
    if args.command == "flag-found":
        _require_sol(args, "Only Root may judge and display a flag candidate.")
        argv = list(args.argv)
        if argv and argv[0] == "--":
            argv.pop(0)
        return flag_found(
            solve_root, lane_id=args.lane, candidate=args.candidate,
            flag_pattern=challenge.flag_pattern, challenge_key=challenge.key,
            command=argv, observed_output=args.observed_output,
            artifact=args.artifact, source=args.source,
        )
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
    if args.command == "submission-result":
        _require_sol(args, "Only Root may record the human submission result.")
        terminal_run = safe_under(challenge_workspace(solve_root) / "runs", Path(args.run_id))
        if terminal_run.is_symlink() or not terminal_run.is_dir():
            raise ValueError("submission run does not exist in this challenge workspace")
        return record_swarm_submission_result(
            terminal_run, candidate=args.candidate, result=args.result,
        )
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
            except Exception:
                cleanup(metadata)
                raise
        return metadata
    if args.command == "record-finding":
        _require_sol(args, "Only Root may append shared findings.")
        return append_finding(solve_root, args.branch, args.summary, args.evidence, args.status)
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
        plan = ledger.rebalance(capacity)
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
    """Read-only first-to-flag health for one explicitly selected exact run."""

    state_path = run / "STATE.json"
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state_health = "VALID" if isinstance(state, dict) else "CORRUPT"
    except (OSError, json.JSONDecodeError):
        state = None
        state_health = "MISSING" if not state_path.exists() else "CORRUPT"
    swarm_path = run / "SWARM.json"
    swarm_health = "MISSING"
    if swarm_path.is_file() and not swarm_path.is_symlink():
        try:
            swarm = json.loads(swarm_path.read_text(encoding="utf-8"))
            swarm_health = "VALID" if isinstance(swarm, dict) else "CORRUPT"
        except (OSError, json.JSONDecodeError):
            swarm_health = "CORRUPT"
    return {
        "run_id": run.name, "path": str(run), "state_health": state_health,
        "state_status": state.get("status") if isinstance(state, dict) else None,
        "swarm_health": swarm_health,
        "repair_performed": False,
    }


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


if __name__ == "__main__":
    raise SystemExit(main())
