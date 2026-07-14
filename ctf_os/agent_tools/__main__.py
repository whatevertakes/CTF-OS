from __future__ import annotations

import argparse
from contextlib import nullcontext
import json
import os
from pathlib import Path
import sys

from ..challenge import SelectionError, resolve_selector
from ..challenge_scope import remove_challenge_secrets
from ..contest import ContestError, discover_contests, select_contest
from ..evidence import append_finding
from ..intake import current_source_fingerprint, prepared_tree_fingerprint, run_intake
from ..doctor import run_doctor
from ..delegation import (
    BranchCandidate, add_branch, branch_utility, init_plan, load_plan,
    record_admission, template_recommendation, update_branch,
)
from ..events import (
    acknowledge_event, insight_packet, operator_hints, publish_event,
    save_operator_hint, show_events,
)
from ..race import parse_branch_spec, race_board, start_race_plan
from ..oast import create_oast, oast_events, poll_oast
from ..replay import run_replay
from ..problems import sync_contest_manifest
from ..scaffold import initialize_contest
from ..sandbox.network import parse_remotes, resolve_targets
from ..sandbox.resources import gpu_available, sandbox_gc, sandbox_status
from ..sandbox.runtime import (
    SandboxSpec, cleanup, create, execute, export_artifacts, probe_service_connectivity,
)
from ..service import (
    ServiceActor, ServiceSpec, service_build, service_cleanup, service_inspect,
    service_attachment, service_logs, service_plan, service_restart, service_start,
    service_reset, service_status, service_stop,
)
from ..triage import finalize_triage, prepare_triage, require_final_triage
from ..timeouts import timeout_seconds
from ..workspace import atomic_json, challenge_root, initialize_solve_files, state_lock
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
    sandbox_exec.add_argument("metadata")
    sandbox_exec.add_argument("--timeout", type=int, default=300)
    sandbox_exec.add_argument("--timeout-profile")
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
    if args.command == "sandbox-gc":
        _require_sol(args, "Only the parent Sol session may garbage-collect managed sandboxes.")
        return sandbox_gc()
    if args.command == "inspect-contest":
        sync_contest_manifest(root, args.contest)
        contest = select_contest(discover_contests(root / "incoming"), args.contest)
        return contest.to_dict()
    if args.command == "intake":
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
        metadata = _load_metadata(root, args.metadata)
        command = list(args.argv)
        if command and command[0] == "--":
            command.pop(0)
        session_id, role = _caller(args, metadata=metadata)
        timeout = timeout_seconds(args.timeout_profile) if args.timeout_profile else args.timeout
        result = execute(metadata, command, timeout, session_id=session_id, session_role=role)
        if result["timed_out"]:
            _update_branch_state(Path(str(metadata["branch_root"])).parents[1], str(metadata["branch"]), "TIMED_OUT", str(metadata["metadata_path"]))
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

    manifest, challenge, record = _load_challenge(root, args.contest, args.selector)
    if os.environ.get("CTF_OS_SESSION_ROLE") == "child":
        if (
            os.environ.get("CTF_OS_CHALLENGE_ID") != challenge.id
            or os.environ.get("CTF_OS_CONTEST_SLUG") != manifest.slug
        ):
            raise ValueError("DENIED_CHALLENGE_SCOPE: child session may access only its assigned challenge")
    solve_root = challenge_root(root, manifest, challenge)
    initialize_solve_files(solve_root, challenge)
    if args.command == "prepare-challenge":
        return _compact_prepare(challenge, record, solve_root)
    current_fingerprint = str(record["source_fingerprint"])
    if args.command.startswith("delegation-") or args.command in {
        "branch-admit", "branch-utility", "race-plan-start", "race-board",
    }:
        _require_delegation_sol(args)
        if args.command == "race-plan-start":
            template_path = Path(__file__).parents[1] / "resources" / "delegation-templates.yaml"
            specs = parse_branch_spec(args.branch_spec, category=challenge.category, tier=args.tier, template_path=template_path)
            return start_race_plan(
                solve_root, challenge_id=challenge.id, input_fingerprint=current_fingerprint,
                parent_session_id=args.parent_session_id, category=challenge.category,
                tier=args.tier, tier_reason=args.tier_reason, branch_specs=specs,
                threshold=args.threshold,
            )
        if args.command == "race-board":
            plan = load_plan(solve_root, input_fingerprint=current_fingerprint)
            state = json.loads((solve_root / "STATE.json").read_text(encoding="utf-8"))
            events = show_events(solve_root, input_fingerprint=current_fingerprint)
            try:
                resources = sandbox_status()
            except Exception as exc:
                resources = {"available": False, "reason": str(exc)}
            return race_board(plan, state=state, events=events, resources=resources)
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
            return update_branch(solve_root, input_fingerprint=current_fingerprint, session_id=args.session_id, status=args.status, observed_runtime_model=args.observed_runtime_model, observed_reasoning=args.observed_reasoning, pinning_verified=args.pinning_verified, runtime_observation_evidence=args.runtime_observation_evidence)
        if args.command == "branch-utility":
            plan = load_plan(solve_root, input_fingerprint=current_fingerprint)
            checkpoints = collect_worker_checkpoints(solve_root / "workers", input_fingerprint=current_fingerprint)
            result_path = solve_root / "workers" / args.session_id / "result.json"
            result = load_worker_result(result_path) if result_path.is_file() else None
            return branch_utility(plan, session_id=args.session_id, checkpoints=checkpoints, result=result)
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
        return publish_event(
            solve_root, challenge_id=challenge.id, input_fingerprint=current_fingerprint,
            session_id=session_id, event_type=args.type, priority=args.priority,
            summary=args.summary, evidence=args.evidence, artifacts=args.artifact,
            useful_for=_csv(args.useful_for), recommended_action=args.recommended_action,
            event_id=args.event_id,
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
        return record_remote_flag(
            solve_root, challenge_id=challenge.id, input_fingerprint=current_fingerprint,
            branch_id=args.branch, declared_targets=parse_remotes(challenge.remotes),
            observed_host=args.host, observed_port=args.port, observed_protocol=args.protocol,
            network_observed=args.network_observed, output=args.output, candidate=args.candidate,
            flag_pattern=challenge.flag_pattern, command_argv=argv,
            exploit_artifact=args.exploit_artifact,
        )
    if args.command == "replay":
        _require_sol(args, "Only the parent Sol session may make the final replay judgment.")
        return run_replay(root, manifest, challenge, record, service_actor=_service_actor(args))
    if args.command == "sandbox-create":
        if record["status"] != "READY":
            raise ValueError(f"challenge is not READY: {record.get('blockers')}")
        branch_root = solve_root / "workers" / args.branch
        input_path = solve_root / "input"
        if input_path.is_symlink() or not input_path.is_dir():
            raise ValueError("prepared challenge input is missing or is a symlink; rerun intake")
        expected_source = input_path.resolve()
        try:
            expected_source.relative_to(solve_root.resolve())
        except ValueError as exc:
            raise ValueError("prepared challenge input escapes its challenge workspace") from exc
        if Path(str(record.get("prepared_input", ""))).resolve() != expected_source:
            raise ValueError("intake index prepared_input is outside the selected challenge workspace")
        if record.get("prepared_fingerprint") != prepared_tree_fingerprint(input_path):
            raise ValueError("prepared challenge input changed after intake; rerun intake")
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
        spec = SandboxSpec(
            contest_slug=manifest.slug, challenge_id=challenge.id, branch=args.branch,
            source=expected_source, branch_root=branch_root,
            input_fingerprint=str(record["source_fingerprint"]),
            targets=targets, image=image, resource_profile=profile,
            service_network=service_network, local_endpoints=endpoints,
            session_id=session_id, parent_session_id=args.parent_session_id,
            session_role=session_role, service_context=service_context,
            category=challenge.category,
            gpu_enabled=challenge.category == "ai" and gpu_available(),
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
        if sandbox_metadata.is_file():
            export_artifacts(
                _load_metadata(root, str(sandbox_metadata)),
                session_id=session_id, session_role=role,
            )
        return save_worker_result(worker_root, payload)
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
        return save_worker_checkpoint(worker_root, parent_session_id=args.parent_session_id, challenge_id=challenge.id, input_fingerprint=current_fingerprint, checkpoint_type=args.type, summary=args.summary, evidence=args.evidence, artifacts=args.artifact, useful_for=_csv(args.useful_for), recommended_action=args.recommended_action, confidence=args.confidence)
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


def _compact_prepare(challenge, record: dict[str, object], solve_root: Path) -> dict[str, object]:
    files = list(record.get("files") or [])
    priority_names = set(record.get("priority_files") or [])
    priority = [item for item in files if isinstance(item, dict) and item.get("path") in priority_names]
    if not priority:
        priority = [item for item in files[:20] if isinstance(item, dict)]
    return {
        "challenge": challenge.to_dict(),
        "priority_files": priority,
        "important_metadata": {
            "file_count": record.get("file_count", len(files)),
            "total_size": record.get("total_size", sum(int(item.get("size", 0)) for item in files if isinstance(item, dict))),
            "subtype": record.get("subtype"), "runtime": record.get("runtime", []),
        },
        "initial_attack_surface": record.get("attack_surface", []),
        "recommended_image": record.get("recommended_image", "ctf-os-sandbox:base"),
        "recommended_resource_profile": record.get("recommended_resource_profile", "standard"),
        "triage_recommendation": record.get("triage_recommendation", {}),
        "service_plan": record.get("service_plan", {}),
        "state_summary": _state_summary(solve_root),
        "read_on_demand": [
            str(solve_root / "inventory.json"), str(solve_root / "evidence.log"),
            str(solve_root / "findings.jsonl"), str(solve_root / "workers"),
        ],
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


def _load_challenge(root: Path, contest_selector: str | None, selector: str):
    manifest = select_contest(discover_contests(root / "incoming"), contest_selector)
    index_path = root / "output" / manifest.slug / "intake.json"
    if not index_path.is_file() or index_path.is_symlink():
        raise ValueError(f"intake index not found: {index_path}; run the intake skill in a dedicated Sol session")
    index = json.loads(index_path.read_text(encoding="utf-8"))
    if index.get("contest", {}).get("manifest_sha256") != manifest.fingerprint:
        raise ValueError("contest.md changed after intake; rerun the intake skill before solving")
    challenge = resolve_selector(manifest.challenges, selector)
    records = [record for record in index.get("challenges", []) if record.get("id") == challenge.id]
    if len(records) != 1:
        raise ValueError("intake index does not contain exactly one matching challenge; rerun intake")
    current_fingerprint = current_source_fingerprint(manifest, challenge)
    if records[0].get("source_fingerprint") != current_fingerprint:
        raise ValueError("challenge files changed after intake; rerun the intake skill before solving")
    if records[0].get("status") == "READY":
        prepared = challenge_root(root, manifest, challenge) / "input"
        if prepared.is_symlink() or not prepared.is_dir():
            raise ValueError("prepared challenge input is missing or unsafe; rerun intake")
        if records[0].get("prepared_fingerprint") != prepared_tree_fingerprint(prepared):
            raise ValueError("prepared challenge input changed after intake; rerun intake")
    triage = require_final_triage(root, manifest, challenge)
    record = dict(records[0])
    record["triage_recommendation"] = triage.get("recommendation", {})
    return manifest, challenge, record


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


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _candidate_from_args(args: argparse.Namespace) -> BranchCandidate:
    return BranchCandidate.create(session_id=args.session_id, role=args.role, hypothesis_family=args.hypothesis_family, hypothesis=args.hypothesis, scope=_csv(args.scope), tool_strategy=_csv(args.tool_strategy), expected_artifacts=args.expected_artifact)


if __name__ == "__main__":
    raise SystemExit(main())
