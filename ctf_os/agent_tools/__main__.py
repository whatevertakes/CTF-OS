"""Single-challenge race controller CLI.

This module prepares state and sandboxes.  It never calls a model API, starts
or interrupts a native agent, or submits a flag.
"""

from __future__ import annotations

import argparse
import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..blackboard import (
    append_verified_event,
    human_relay_blocks_promotion,
    register_artifact_inbox,
)
from ..categories import CATEGORIES
from ..contest import (
    discover_contests,
    initialize_contest,
    resolve_selector,
    select_contest,
)
from ..doctor import run_doctor
from ..flag import StreamingDetector, record_candidate
from ..handoff import load_markdown, save_handoff, validate_handoff
from ..images import select_image, smoke_images
from ..preflight import input_fingerprint, prepare_input, validate_prepared_input
from ..race import (
    attach_lane_sandbox,
    begin_lane_cleanup_retry,
    cancel_targets,
    confirm_native_spawn,
    finish_lane_cleanup,
    initialize_race,
    load_race,
    mark_lane_prepare_failed,
    mark_prepare_failed,
    mark_root_ready,
    note_command_receipt,
    note_event,
    reserve_lanes,
    reserve_max_endgame,
    set_lane_service_context,
    set_service_context,
    stop_confirmed,
    terminate,
)
from ..race import (
    status as race_status,
)
from ..sandbox.network import (
    collect_docker_gateways,
    parse_remotes,
    rebuild_targets,
    resolve_targets,
)
from ..sandbox.resources import sandbox_gc
from ..sandbox.runtime import (
    SandboxError,
    SandboxSpec,
    cleanup,
    create,
    execute,
    load_metadata,
    probe_service_connectivity,
)
from ..sandbox.session import (
    close_session,
    list_sessions,
    list_tools,
    open_session,
    tool_help,
    tool_version,
)
from ..sandbox.session import (
    read as session_read,
)
from ..sandbox.session import (
    send as session_send,
)
from ..service import (
    ServiceActor,
    ServiceCleanupError,
    ServiceSpec,
    cleanup_service,
    load_service,
    prepare_service,
)
from ..tool_audit import run_tool_audit
from ..workspace import atomic_json, clear_active, create_run, resolve_run, utc_now


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m ctf_os.agent_tools",
        description="Verified asynchronous portfolio race controller for exact concurrent CTF runs",
        allow_abbrev=False,
    )
    parser.add_argument("--repo", default=".")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init-contest", help="create a fresh contest manifest and one challenge input folder")
    init.add_argument("contest")
    init.add_argument("--challenge", required=True, metavar="CATEGORY/NAME")

    prepare = commands.add_parser("race-prepare", help="select, materialize, and create the Root sandbox")
    _selection_args(prepare)
    prepare.add_argument("--docker", default="docker")
    prepare.add_argument(
        "--root-model-profile",
        choices=("sol-ultra", "sol-max", "sol-xhigh"),
        default=None,
    )
    prepare.add_argument(
        "--service-isolation",
        choices=("per-lane", "shared"),
        default="per-lane",
        help="use a private local challenge-service instance per lane by default",
    )
    prepare.add_argument(
        "--remote-execution",
        choices=("agent", "human-relay"),
        required=True,
        help=(
            "required explicit safety choice: let agents access declared organizer "
            "targets, or require a participant to execute every organizer-remote command"
        ),
    )
    prepare.add_argument("--dry-run", action="store_true", help="prepare fresh state but do not start service/sandbox")

    bootstrap = commands.add_parser("race-bootstrap", help="prepare all requested private native-worker lanes")
    _selection_args(bootstrap)
    bootstrap.add_argument(
        "--run-id",
        help="exact active run; required when more than one race is active",
    )
    group = bootstrap.add_mutually_exclusive_group(required=True)
    group.add_argument("--lanes-json")
    group.add_argument("--lanes-file")
    group.add_argument(
        "--lane",
        dest="lanes",
        action="append",
        metavar="JSON_OBJECT",
        help="one lane JSON object; repeat --lane to request up to three lanes",
    )
    bootstrap.add_argument("--docker", default="docker")

    endgame = commands.add_parser("race-endgame", help="prepare the single qualified post-minute-60 Sol max replacement")
    endgame.add_argument("--run-id")
    endgame.add_argument("--replaces-lane", required=True)
    endgame.add_argument("--task", required=True)
    endgame.add_argument("--attack-family", required=True)
    endgame.add_argument("--docker", default="docker")

    show = commands.add_parser("race-status", help="return mechanical progress, duplicate, and stagnation signals")
    show.add_argument("--run-id")

    reconcile = commands.add_parser(
        "race-reconcile",
        help="batch-record native spawn/interrupt results and perform controller cleanup",
    )
    reconcile.add_argument("--run-id")
    reconcile.add_argument("--events-json", required=True)
    reconcile.add_argument("--docker", default="docker")

    retry_cleanup = commands.add_parser(
        "race-lane-cleanup",
        help="retry a failed child sandbox/private-service cleanup",
    )
    retry_cleanup.add_argument("--run-id")
    retry_cleanup.add_argument("--lane", required=True)
    retry_cleanup.add_argument("--docker", default="docker")

    end = commands.add_parser("race-end", help="mark timeout, handoff, or explicit stop and return cancel targets")
    end.add_argument("--run-id")
    end.add_argument(
        "--reason",
        required=True,
        type=str.upper,
        choices=("TIMED_OUT", "HANDOFF", "STOPPED"),
    )

    handoff = commands.add_parser("race-handoff", help="terminate the exact race and save one manual HANDOFF.md")
    handoff.add_argument("--run-id")
    handoff.add_argument("--markdown-file", required=True)

    clean = commands.add_parser("race-cleanup", help="clean exact-run sandboxes/service after native stops")
    clean.add_argument("--run-id")
    clean.add_argument("--docker", default="docker")

    gc = commands.add_parser("sandbox-gc", help="remove only stopped, label-validated CTF-OS sandboxes")
    gc.add_argument("--docker", default="docker")

    sandbox_exec = commands.add_parser("sandbox-exec", help="execute one argv in an already prepared lane sandbox")
    sandbox_exec.add_argument("--metadata", required=True)
    sandbox_exec.add_argument("--timeout", type=int, default=300)
    sandbox_exec.add_argument("--target-identity")
    sandbox_exec.add_argument("argv", nargs=argparse.REMAINDER)

    board = commands.add_parser("blackboard-add", help="append one claim backed by an existing execution receipt")
    board.add_argument("--receipt", required=True)
    board.add_argument("--type", required=True)
    board.add_argument("--artifact")

    session_open_parser = commands.add_parser("session-open")
    session_open_parser.add_argument("--metadata", required=True)
    session_open_parser.add_argument("--session", required=True)
    session_open_parser.add_argument("--kind", required=True, choices=("shell", "remote", "debugger"))
    session_open_parser.add_argument("--target-identity")
    session_open_parser.add_argument("argv", nargs=argparse.REMAINDER)

    session_send_parser = commands.add_parser("session-send")
    session_send_parser.add_argument("--metadata", required=True)
    session_send_parser.add_argument("--session", required=True)
    session_send_parser.add_argument("--data", required=True)
    session_send_parser.add_argument("--timeout", type=int, default=10)

    session_read_parser = commands.add_parser("session-read")
    session_read_parser.add_argument("--metadata", required=True)
    session_read_parser.add_argument("--session", required=True)
    session_read_parser.add_argument("--limit", type=int, default=65536)
    session_read_parser.add_argument("--timeout", type=int, default=10)

    session_close_parser = commands.add_parser("session-close")
    session_close_parser.add_argument("--metadata", required=True)
    session_close_parser.add_argument("--session", required=True)
    session_close_parser.add_argument("--timeout", type=int, default=10)

    session_list_parser = commands.add_parser("session-list")
    session_list_parser.add_argument("--metadata", required=True)

    tools = commands.add_parser("list-tools")
    tools.add_argument("--metadata", required=True)
    help_parser = commands.add_parser("tool-help")
    help_parser.add_argument("name")
    help_parser.add_argument("--metadata", required=True)
    version = commands.add_parser("tool-version")
    version.add_argument("name")
    version.add_argument("--metadata", required=True)

    doctor = commands.add_parser("doctor", help="pre-contest host/image diagnostics; never part of race-prepare")
    doctor.add_argument("--docker", default="docker")
    doctor.add_argument(
        "--profiles",
        nargs="+",
        choices=CATEGORIES,
        default=list(CATEGORIES),
        help="validate only the profiles built for this machine (default: all ten)",
    )
    tool_audit = commands.add_parser(
        "tool-audit",
        help="validate immutable tool pins and optionally compare official upstream releases",
    )
    tool_audit.add_argument("--check-upstream", action="store_true")
    image_smoke = commands.add_parser("image-smoke", help="inspect selected local category images")
    image_smoke.add_argument("--docker", default="docker")
    image_smoke.add_argument(
        "--profiles",
        nargs="+",
        choices=CATEGORIES,
        default=list(CATEGORIES),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo = Path(args.repo).resolve()
    try:
        result = dispatch(args, repo)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    succeeded = _command_succeeded(args.command, result)
    print(json.dumps(
        {"ok": succeeded, "result": result},
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ))
    return 0 if succeeded else 1


def dispatch(args: argparse.Namespace, repo: Path) -> Any:
    if args.command == "init-contest":
        return initialize_contest(repo, args.contest, args.challenge)
    if args.command == "race-prepare":
        return _race_prepare(repo, args)
    if args.command == "race-bootstrap":
        return _race_bootstrap(repo, args)
    if args.command == "race-endgame":
        return _race_endgame(repo, args)
    if args.command == "race-status":
        return race_status(resolve_run(repo, args.run_id))
    if args.command == "race-reconcile":
        return _race_reconcile(repo, args)
    if args.command == "race-lane-cleanup":
        run = resolve_run(repo, args.run_id)
        begin_lane_cleanup_retry(run, lane_id=args.lane)
        return _finish_controller_lane_cleanup(
            run,
            lane_id=args.lane,
            docker=args.docker,
            require_sandbox=False,
        )
    if args.command == "race-end":
        return terminate(resolve_run(repo, args.run_id), reason=args.reason)
    if args.command == "race-handoff":
        return _race_handoff(repo, args)
    if args.command == "race-cleanup":
        return _race_cleanup(repo, args)
    if args.command == "sandbox-gc":
        return sandbox_gc(docker=args.docker)
    if args.command == "sandbox-exec":
        return _sandbox_exec(repo, Path(args.metadata), args)
    if args.command == "blackboard-add":
        return _blackboard_add(Path(args.receipt), args)
    if args.command == "session-open":
        metadata = _authorized_metadata(repo, Path(args.metadata))
        _attack_timeout(metadata, 30)
        return open_session(
            metadata, session_id=args.session, kind=args.kind,
            command=_optional_remainder(args.argv), target_identity=args.target_identity,
        )
    if args.command == "session-send":
        metadata = _authorized_metadata(repo, Path(args.metadata))
        return session_send(
            metadata, session_id=args.session, data=args.data,
            timeout=_attack_timeout(metadata, args.timeout),
        )
    if args.command == "session-read":
        return _session_read(repo, Path(args.metadata), args)
    if args.command == "session-close":
        return close_session(
            _authorized_metadata(repo, Path(args.metadata)),
            session_id=args.session,
            timeout=args.timeout,
        )
    if args.command == "session-list":
        return list_sessions(_authorized_metadata(repo, Path(args.metadata)))
    if args.command == "list-tools":
        return list_tools(str(_authorized_metadata(repo, Path(args.metadata))["category"]))
    if args.command == "tool-help":
        metadata = _authorized_metadata(repo, Path(args.metadata))
        return tool_help(str(metadata["category"]), args.name)
    if args.command == "tool-version":
        metadata = _authorized_metadata(repo, Path(args.metadata))
        _attack_timeout(metadata, 20)
        return tool_version(metadata, args.name)
    if args.command == "doctor":
        return run_doctor(repo, profiles=args.profiles, docker=args.docker)
    if args.command == "tool-audit":
        return run_tool_audit(repo, check_upstream=args.check_upstream)
    if args.command == "image-smoke":
        return smoke_images(args.profiles, docker=args.docker)
    raise ValueError(f"unsupported command: {args.command}")


def _command_succeeded(command: str, result: Any) -> bool:
    if command in {"doctor", "tool-audit"}:
        return isinstance(result, Mapping) and result.get("ok") is True
    if command == "image-smoke":
        return (
            isinstance(result, Mapping)
            and result.get("all_available") is True
        )
    return True


def _race_prepare(repo: Path, args: argparse.Namespace) -> dict[str, Any]:
    remote_execution = getattr(args, "remote_execution", None)
    if remote_execution not in {"agent", "human-relay"}:
        raise ValueError(
            "race-prepare requires an explicit --remote-execution "
            "choice: agent or human-relay"
        )
    selected_at = utc_now()
    manifest, challenge = _select(repo, args.contest, args.selector)
    fingerprint = input_fingerprint(manifest, challenge)
    run, run_manifest = create_run(
        repo, manifest, challenge, input_fingerprint=fingerprint, now=selected_at
    )
    try:
        input_record = prepare_input(
            manifest, challenge, run, expected_fingerprint=fingerprint
        )
    except Exception:
        clear_active(repo, run_id=run.name)
        raise
    input_ready_at = utc_now()
    image = select_image(challenge.category, docker=args.docker)
    service: dict[str, Any] = {
        "status": "NOT_PREPARED", "network": None, "endpoints": [], "lifecycle_owner": "root",
    }
    requested_root_profile = getattr(args, "root_model_profile", None)
    race = initialize_race(
        run,
        run_manifest=run_manifest,
        input_record=input_record,
        image=image,
        service=service,
        selected_at=selected_at,
        input_ready_at=input_ready_at,
        root_model_profile=requested_root_profile or "sol-ultra",
        root_model_profile_source=(
            "explicit-cli" if requested_root_profile else "policy-default"
        ),
        service_isolation=getattr(args, "service_isolation", "per-lane"),
        remote_execution=remote_execution,
    )
    if args.dry_run:
        mark_prepare_failed(run, "dry-run requested; no service or sandbox was started")
        clear_active(repo, run_id=run.name)
        return _prepare_result(run, input_record, image, service, load_race(run), dry_run=True)
    if not image["image_available"]:
        mark_prepare_failed(run, str(image["reason"]))
        clear_active(repo, run_id=run.name)
        return _prepare_result(run, input_record, image, service, load_race(run))
    root_sandbox: dict[str, Any] | None = None
    try:
        service_spec = ServiceSpec(
            run_id=run.name,
            challenge_id=challenge.id,
            source=run / "input",
            run_root=run,
            plan=input_record["service_plan"],
            instance_id="root",
            resource_scope=repo / "output" / "resources",
        )
        service = prepare_service(
            service_spec, actor=ServiceActor(lane_id="root", role="root"), docker=args.docker
        )
        set_service_context(run, service)
        targets = _agent_targets(
            challenge.remotes,
            service_network=(
                str(service["network"]) if service.get("status") == "READY" else None
            ),
            remote_execution=str(race.get("remote_execution", "agent")),
            docker=args.docker,
        )
        artifact_inbox = register_artifact_inbox(run, "root")
        root_sandbox = _create_sandbox(SandboxSpec(
            run_id=run.name,
            contest_slug=manifest.slug,
            challenge_id=challenge.id,
            category=challenge.category,
            lane_id="root",
            source=run / "input",
            lane_root=run / "workers" / "root",
            input_fingerprint=fingerprint,
            image=str(image["selected_image"]),
            targets=targets,
            service_network=str(service["network"]) if service.get("status") == "READY" else None,
            service_endpoints=tuple(str(value) for value in service.get("endpoints", [])),
            artifact_inbox=artifact_inbox,
            resource_profile=_resource_profile(input_record),
            race_lane_count=0,
            resource_scope=repo / "output" / "resources",
            remote_execution=str(race.get("remote_execution", "agent")),
        ), docker=args.docker)
        if service.get("status") == "READY":
            root_sandbox["service_probe"] = probe_service_connectivity(root_sandbox, docker=args.docker)
        race = mark_root_ready(run, root_sandbox)
    except Exception as exc:  # noqa: BLE001
        if isinstance(exc, ServiceCleanupError):
            service = dict(exc.service)
            service["cleanup_error"] = "; ".join(exc.failures)
            try:
                set_service_context(run, service)
            except Exception as context_exc:  # noqa: BLE001
                service["cleanup_error"] += (
                    f"; service recovery state write failed: {context_exc}"
                )
        elif "cleanup was incomplete" in str(exc):
            service = service | {
                "status": "CLEANUP_FAILED",
                "cleanup_error": str(exc),
            }
        race = mark_prepare_failed(run, str(exc))
        service = service | {"prepare_error": str(exc)}
        if root_sandbox is not None:
            try:
                cleanup(root_sandbox, docker=args.docker)
            except Exception as cleanup_exc:  # noqa: BLE001
                service["cleanup_error"] = str(cleanup_exc)
        if service.get("status") == "READY":
            try:
                service_cleanup = cleanup_service(
                    service, actor=ServiceActor("root", "root"), docker=args.docker
                )
                if not service_cleanup["cleaned"]:
                    service["cleanup_error"] = "; ".join(service_cleanup["failures"])
            except Exception as cleanup_exc:  # noqa: BLE001
                service["cleanup_error"] = str(cleanup_exc)
        if "cleanup_error" not in service:
            clear_active(repo, run_id=run.name)
    return _prepare_result(run, input_record, image, service, race)


def _race_bootstrap(repo: Path, args: argparse.Namespace) -> dict[str, Any]:
    # Resolve the exact active run from the immutable active registry first, then
    # confirm the CLI selector points at that run's fixed challenge identity. The
    # bootstrap payload is built only from RUN/RACE/INPUT state captured at
    # preparation time, never from the mutable contest.md, so a post-preparation
    # manifest edit (e.g. a swapped remote or category) can never reach a child.
    run = resolve_run(repo, getattr(args, "run_id", None))
    race = load_race(run)
    _require_active_race_selector(race, args.contest, args.selector)
    contest_slug = str(race["contest"]["slug"])
    challenge_id = str(race["challenge"]["id"])
    category = str(race["challenge"]["category"])
    specifications = _lane_json(args)
    reserved = reserve_lanes(run, specifications)
    source, input_record = validate_prepared_input(run)
    root_service_network = race.get("service_network")
    root_service_endpoints = tuple(
        str(value) for value in race.get("service_endpoints", [])
    )
    targets = (
        ()
        if (
            root_service_network
            or str(race.get("remote_execution", "agent")) == "human-relay"
        )
        else _resolve_stored_targets(race.get("declared_targets", []), docker=args.docker)
    )
    packets: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for lane in reserved:
        lane_service: dict[str, Any] | None = None
        metadata: dict[str, Any] | None = None
        try:
            service_network = root_service_network
            service_endpoints = root_service_endpoints
            if (
                root_service_network
                and race.get("service_isolation") == "per-lane"
            ):
                lane_service = prepare_service(
                    ServiceSpec(
                        run_id=run.name,
                        challenge_id=challenge_id,
                        source=source,
                        run_root=run,
                        plan=input_record["service_plan"],
                        instance_id=str(lane["lane_id"]),
                        resource_scope=repo / "output" / "resources",
                    ),
                    actor=ServiceActor(lane_id="root", role="root"),
                    docker=args.docker,
                )
                set_lane_service_context(
                    run,
                    lane_id=str(lane["lane_id"]),
                    service=lane_service,
                )
                service_network = lane_service["network"]
                service_endpoints = tuple(
                    str(value) for value in lane_service.get("endpoints", [])
                )
            artifact_inbox = register_artifact_inbox(
                run, str(lane["lane_id"])
            )
            metadata = _create_sandbox(SandboxSpec(
                run_id=run.name,
                contest_slug=contest_slug,
                challenge_id=challenge_id,
                category=category,
                lane_id=str(lane["lane_id"]),
                source=source,
                lane_root=run / "workers" / str(lane["lane_id"]),
                input_fingerprint=str(input_record["input_fingerprint"]),
                image=str(race["selected_image"]),
                targets=targets,
                service_network=str(service_network) if service_network else None,
                service_endpoints=service_endpoints,
                artifact_inbox=artifact_inbox,
                resource_profile=_resource_profile(input_record),
                race_lane_count=1 + len(packets),
                resource_scope=repo / "output" / "resources",
                remote_execution=str(race.get("remote_execution", "agent")),
            ), docker=args.docker)
            if service_network:
                metadata["service_probe"] = probe_service_connectivity(
                    metadata, docker=args.docker
                )
            packets.append(attach_lane_sandbox(run, lane_id=str(lane["lane_id"]), sandbox=metadata))
        except Exception as exc:  # noqa: BLE001
            cleanup_errors: list[str] = []
            # A service that failed to start AND to fully roll back arrives as a
            # ServiceCleanupError carrying a structured recovery record; persist it
            # so the lane stays CLEANUP_FAILED and race-lane-cleanup can reclaim it.
            if isinstance(exc, ServiceCleanupError):
                cleanup_errors.extend(str(value) for value in exc.failures)
                try:
                    _persist_child_service_recovery(
                        run, str(lane["lane_id"]), exc.service
                    )
                except Exception as recovery_exc:  # noqa: BLE001
                    cleanup_errors.append(f"service recovery write: {recovery_exc}")
            if metadata is not None:
                try:
                    cleanup(metadata, docker=args.docker)
                except Exception as cleanup_exc:  # noqa: BLE001
                    cleanup_errors.append(f"sandbox: {cleanup_exc}")
            if lane_service is not None and lane_service.get("status") == "READY":
                try:
                    cleaned_service = cleanup_service(
                        lane_service,
                        actor=ServiceActor("root", "root"),
                        docker=args.docker,
                    )
                    cleanup_errors.extend(
                        str(value) for value in cleaned_service.get("failures", [])
                    )
                except Exception as cleanup_exc:  # noqa: BLE001
                    cleanup_errors.append(str(cleanup_exc))
            reason = str(exc)
            if cleanup_errors:
                reason += "; isolated service cleanup: " + "; ".join(cleanup_errors)
            mark_lane_prepare_failed(
                run,
                lane_id=str(lane["lane_id"]),
                reason=reason,
                cleanup_failed=bool(cleanup_errors),
            )
            failures.append({"lane_id": str(lane["lane_id"]), "error": reason})
    return {
        "run_id": run.name,
        "packets": packets,
        "failures": failures,
        "native_spawn_performed": False,
        "native_actions": [
            {
                "action": "SPAWN",
                "lane_id": packet["lane_id"],
                "spawn_agent_args": packet["spawn_agent_args"],
            }
            for packet in packets
        ],
        "next_action": (
            "Root executes only the returned native SPAWN actions, then records all "
            "native thread ids in one race-reconcile call while continuing its attack."
        ),
    }


def _race_endgame(repo: Path, args: argparse.Namespace) -> dict[str, Any]:
    run = resolve_run(repo, args.run_id)
    race = load_race(run)
    lane = reserve_max_endgame(
        run,
        replaced_lane_id=args.replaces_lane,
        task=args.task,
        attack_family=args.attack_family,
    )
    source, input_record = validate_prepared_input(run)
    service_network = race.get("service_network")
    service_endpoints = tuple(str(value) for value in race.get("service_endpoints", []))
    remotes = race["challenge"].get("remotes", [])
    targets = _agent_targets(
        remotes,
        service_network=str(service_network) if service_network else None,
        remote_execution=str(race.get("remote_execution", "agent")),
        docker=args.docker,
    )
    lane_service: dict[str, Any] | None = None
    metadata: dict[str, Any] | None = None
    try:
        if service_network and race.get("service_isolation") == "per-lane":
            lane_service = prepare_service(
                ServiceSpec(
                    run_id=run.name,
                    challenge_id=str(race["challenge"]["id"]),
                    source=source,
                    run_root=run,
                plan=input_record["service_plan"],
                instance_id=str(lane["lane_id"]),
                resource_scope=repo / "output" / "resources",
                ),
                actor=ServiceActor("root", "root"),
                docker=args.docker,
            )
            set_lane_service_context(
                run,
                lane_id=str(lane["lane_id"]),
                service=lane_service,
            )
            service_network = lane_service["network"]
            service_endpoints = tuple(
                str(value) for value in lane_service.get("endpoints", [])
            )
        artifact_inbox = register_artifact_inbox(run, str(lane["lane_id"]))
        metadata = _create_sandbox(SandboxSpec(
            run_id=run.name,
            contest_slug=str(race["contest"]["slug"]),
            challenge_id=str(race["challenge"]["id"]),
            category=str(race["challenge"]["category"]),
            lane_id=str(lane["lane_id"]),
            source=source,
            lane_root=run / "workers" / str(lane["lane_id"]),
            input_fingerprint=str(input_record["input_fingerprint"]),
            image=str(race["selected_image"]),
            targets=targets,
            service_network=str(service_network) if service_network else None,
            service_endpoints=service_endpoints,
            artifact_inbox=artifact_inbox,
            resource_profile=_resource_profile(input_record),
            race_lane_count=sum(
                row["status"] not in {"STOPPED", "WON"}
                for row in load_race(run)["lanes"] if row["lane_id"] != lane["lane_id"]
            ),
            resource_scope=repo / "output" / "resources",
            remote_execution=str(race.get("remote_execution", "agent")),
        ), docker=args.docker)
        if service_network:
            metadata["service_probe"] = probe_service_connectivity(
                metadata, docker=args.docker
            )
        packet = attach_lane_sandbox(run, lane_id=str(lane["lane_id"]), sandbox=metadata)
    except Exception as exc:
        cleanup_errors: list[str] = []
        if metadata is not None:
            try:
                cleanup(metadata, docker=args.docker)
            except Exception as cleanup_exc:  # noqa: BLE001
                cleanup_errors.append(f"sandbox: {cleanup_exc}")
        if lane_service is not None and lane_service.get("status") == "READY":
            try:
                service_cleanup = cleanup_service(
                    lane_service,
                    actor=ServiceActor("root", "root"),
                    docker=args.docker,
                )
                cleanup_errors.extend(
                    f"service: {value}"
                    for value in service_cleanup.get("failures", [])
                )
            except Exception as cleanup_exc:  # noqa: BLE001
                cleanup_errors.append(f"service: {cleanup_exc}")
        reason = str(exc)
        if cleanup_errors:
            reason += "; cleanup: " + "; ".join(cleanup_errors)
        mark_lane_prepare_failed(
            run,
            lane_id=str(lane["lane_id"]),
            reason=reason,
            cleanup_failed=bool(cleanup_errors),
        )
        raise
    return {
        "run_id": run.name,
        "packet": packet,
        "lease_seconds": 600,
        "max_actual_attacks": 2,
        "native_spawn_performed": False,
    }


def _sandbox_exec(repo: Path, metadata_path: Path, args: argparse.Namespace) -> dict[str, Any]:
    metadata = _authorized_metadata(repo, metadata_path)
    run = Path(str(metadata["lane_root"])).resolve().parents[1]
    race = load_race(run)
    lane = next(row for row in race["lanes"] if row["lane_id"] == metadata["lane_id"])
    detector = StreamingDetector(str(race.get("flag_pattern") or ""))
    receipt = execute(
        metadata,
        _remainder(args.argv),
        timeout=_attack_timeout(metadata, args.timeout),
        target_identity=args.target_identity,
        candidate_probe=detector.feed,
    )
    warnings: list[str] = []
    winner = None
    if receipt.get("flag_candidate"):
        if (
            receipt.get("target_observed") is True
            and not human_relay_blocks_promotion(race)
        ):
            winner = record_candidate(
                run,
                lane_id=str(metadata["lane_id"]),
                attack_family=str(lane["attack_family"]),
                candidate=str(receipt["flag_candidate"]),
                receipt=receipt,
            )
        else:
            warnings.append(
                "candidate detected in unverified human-relay/local output; "
                "it was not promoted to a winner"
            )
    try:
        note_command_receipt(run, receipt)
        event = append_verified_event(
            run,
            event_type="COMMAND_RESULT",
            lane_id=str(metadata["lane_id"]),
            attack_family=str(lane["attack_family"]),
            receipt=receipt,
        )
        note_event(run, event)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"post-execution blackboard write failed: {exc}")
    return {
        "receipt": receipt,
        "winner": winner,
        "warnings": warnings,
        "supervision": _supervision_snapshot(race_status(run)),
    }


def _blackboard_add(receipt_path: Path, args: argparse.Namespace) -> dict[str, Any]:
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise ValueError("receipt path is missing or unsafe")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if not isinstance(receipt, dict):
        raise ValueError("receipt must be a JSON object")  # noqa: TRY004
    lane_root = receipt_path.parent.parent
    run = lane_root.parents[1]
    race = load_race(run)
    lane = next(row for row in race["lanes"] if row["lane_id"] == receipt["lane_id"])
    event = append_verified_event(
        run,
        event_type=args.type,
        lane_id=str(receipt["lane_id"]),
        attack_family=str(lane["attack_family"]),
        receipt=receipt,
        artifact=args.artifact,
    )
    note_event(run, event)
    return event


def _session_read(repo: Path, metadata_path: Path, args: argparse.Namespace) -> dict[str, Any]:
    metadata = _authorized_metadata(repo, metadata_path)
    receipt = session_read(
        metadata, session_id=args.session, limit=args.limit,
        timeout=_attack_timeout(metadata, args.timeout),
    )
    run = Path(str(metadata["lane_root"])).resolve().parents[1]
    race = load_race(run)
    lane = next(row for row in race["lanes"] if row["lane_id"] == metadata["lane_id"])
    detector = StreamingDetector(str(race.get("flag_pattern") or ""))
    # Seed the detector with the previous read's durable tail so a flag split
    # across two receipts (e.g. "CTF{sp" then "lit}") is still detected.
    prior_tail = str(receipt.get("session_prior_tail") or "")
    if prior_tail:
        detector.buffer = prior_tail
    candidate = detector.feed(str(receipt["observed_output"]))
    winner = None
    warnings: list[str] = []
    if candidate:
        if (
            receipt.get("target_observed") is not True
            or human_relay_blocks_promotion(race)
        ):
            warnings.append(
                "candidate detected in unverified human-relay/local output; "
                "it was not promoted to a winner"
            )
        else:
            current_output = str(receipt["observed_output"])
            if candidate in current_output:
                winner = record_candidate(
                    run,
                    lane_id=str(metadata["lane_id"]),
                    attack_family=str(lane["attack_family"]),
                    candidate=candidate,
                    receipt=receipt,
                )
            else:
                winner = record_candidate(
                    run,
                    lane_id=str(metadata["lane_id"]),
                    attack_family=str(lane["attack_family"]),
                    candidate=candidate,
                    receipt=receipt,
                    boundary={
                        "receipt_id": receipt.get("session_prior_receipt_id"),
                        "tail": prior_tail,
                    },
                )
    try:
        note_command_receipt(run, receipt)
        event = append_verified_event(
            run,
            event_type="COMMAND_RESULT",
            lane_id=str(metadata["lane_id"]),
            attack_family=str(lane["attack_family"]),
            receipt=receipt,
        )
        note_event(run, event)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"post-execution blackboard write failed: {exc}")
    return {
        "receipt": receipt,
        "winner": winner,
        "warnings": warnings,
        "supervision": _supervision_snapshot(race_status(run)),
    }


def _authorized_metadata(repo: Path, metadata_path: Path) -> dict[str, Any]:
    if metadata_path.is_symlink() or not metadata_path.is_file():
        raise ValueError("sandbox metadata path is missing or unsafe")
    metadata_path = metadata_path.resolve()
    metadata = load_metadata(metadata_path)
    lane_root = Path(str(metadata["lane_root"]))
    if lane_root.is_symlink():
        raise ValueError("sandbox lane root is unsafe")
    lane_root = lane_root.resolve()
    try:
        run = lane_root.parents[1]
    except IndexError as exc:
        raise ValueError("sandbox lane root is malformed") from exc
    authoritative_run = resolve_run(repo, run.name).resolve()
    if run != authoritative_run:
        raise ValueError("sandbox metadata does not belong to the active repository run")
    lane_id = str(metadata["lane_id"])
    expected_path = (run / "workers" / lane_id / "sandbox.json").resolve()
    if metadata_path != expected_path or lane_root != expected_path.parent:
        raise ValueError("sandbox metadata is not the authoritative lane record")
    race = load_race(run)
    lane = next(
        (row for row in race.get("lanes", []) if row.get("lane_id") == lane_id),
        None,
    )
    sandbox = lane.get("sandbox") if isinstance(lane, Mapping) else None
    if not isinstance(sandbox, Mapping):
        raise ValueError("sandbox lane is not attached to the exact race")  # noqa: TRY004
    for field in ("name", "run_id", "lane_id", "challenge_id", "category"):
        if sandbox.get(field) != metadata.get(field):
            raise ValueError(f"sandbox metadata does not match the race: {field}")
    expected_remote_execution = str(race.get("remote_execution", "agent"))
    if (
        str(metadata.get("remote_execution", "agent")) != expected_remote_execution
        or str(sandbox.get("remote_execution", expected_remote_execution))
        != expected_remote_execution
    ):
        raise ValueError(
            "sandbox metadata does not match the race: remote_execution"
        )
    if sandbox.get("metadata_path") != str(metadata_path):
        raise ValueError("sandbox metadata path does not match the race")
    return metadata


def _supervision_snapshot(report: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": report["status"],
        "deadline": report["deadline"],
        "winner": report.get("winner"),
        "native_actions": report.get("native_actions", []),
        "controller_actions": report.get("controller_actions", []),
        "lanes": [
            {
                "lane_id": row["lane_id"],
                "status": row["status"],
                "in_flight": row.get("in_flight", False),
                "stagnation_signals": row.get("stagnation_signals", []),
            }
            for row in report.get("lanes", [])
        ],
    }


def _race_handoff(repo: Path, args: argparse.Namespace) -> dict[str, Any]:
    run = resolve_run(repo, args.run_id)
    race = load_race(run)
    markdown = load_markdown(Path(args.markdown_file))
    handoff_args = {
        "contest": str(race["contest"]["name"]),
        "challenge": f"{race['challenge']['category']}-{race['challenge']['name']}",
        "run_id": run.name,
        "markdown": markdown,
    }
    validate_handoff(repo, **handoff_args)
    terminated = terminate(run, reason="HANDOFF")
    destination = save_handoff(
        repo,
        **handoff_args,
    )
    return terminated | {
        "handoff_path": str(destination),
        "next_action": "Root interrupts every cancel target, then runs race-cleanup for this exact run.",
    }


def _race_reconcile(repo: Path, args: argparse.Namespace) -> dict[str, Any]:
    """Apply native-only boundary results in one controller transaction batch."""

    run = resolve_run(repo, args.run_id)
    raw = args.events_json
    if len(raw.encode("utf-8")) > 64 * 1024:
        raise ValueError("native reconciliation JSON is too large")
    value = json.loads(raw)
    if not isinstance(value, list) or not value:
        raise ValueError("native reconciliation requires a non-empty event array")
    results: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for index, row in enumerate(value):
        if not isinstance(row, dict) or set(row) != {
            "action", "lane_id", "native_session",
        }:
            raise ValueError(
                "each native event must contain exactly action, lane_id, native_session"
            )
        action = str(row["action"])
        lane_id = str(row["lane_id"])
        native_session = str(row["native_session"])
        try:
            if action == "SPAWNED":
                results.append({
                    "action": action,
                    "lane": confirm_native_spawn(
                        run,
                        lane_id=lane_id,
                        native_session=native_session,
                    ),
                })
            elif action == "INTERRUPTED":
                results.append({
                    "action": action,
                    "cleanup": _stop_and_cleanup_lane(
                        run,
                        lane_id=lane_id,
                        native_session=native_session,
                        docker=args.docker,
                    ),
                })
            else:
                raise ValueError("native event action must be SPAWNED or INTERRUPTED")
        except Exception as exc:  # noqa: BLE001
            failures.append({
                "index": str(index),
                "lane_id": lane_id,
                "action": action,
                "error": str(exc),
            })
    report = race_status(run)
    return {
        "run_id": run.name,
        "results": results,
        "failures": failures,
        "status": report,
        "native_actions": report["native_actions"],
    }


def _stop_and_cleanup_lane(
    run: Path,
    *,
    lane_id: str,
    native_session: str,
    docker: str,
) -> dict[str, Any]:
    stop_confirmed(
        run,
        lane_id=lane_id,
        native_session=native_session,
    )
    return _finish_controller_lane_cleanup(
        run,
        lane_id=lane_id,
        docker=docker,
        require_sandbox=True,
    )


def _finish_controller_lane_cleanup(
    run: Path,
    *,
    lane_id: str,
    docker: str,
    require_sandbox: bool,
) -> dict[str, Any]:
    failures: list[tuple[str, str]] = []
    cleanup_result: dict[str, Any] | None = None
    service_result: dict[str, Any] | None = None
    metadata_path = run / "workers" / lane_id / "sandbox.json"
    if metadata_path.exists() or require_sandbox:
        try:
            if not metadata_path.is_file() or metadata_path.is_symlink():
                raise ValueError("stopped lane has no safe private sandbox metadata to clean")
            cleanup_result = cleanup(load_metadata(metadata_path), docker=docker)
        except Exception as exc:  # noqa: BLE001
            failures.append(("sandbox", str(exc)))
    service_path = (
        run / "service" / "instances" / lane_id / "service.json"
    )
    if service_path.exists():
        try:
            if service_path.is_symlink() or not service_path.is_file():
                raise ValueError("private service metadata is unsafe")
            service_result = cleanup_service(
                load_service(service_path),
                actor=ServiceActor("root", "root"),
                docker=docker,
            )
            failures.extend(
                ("service", str(value))
                for value in service_result.get("failures", [])
            )
        except Exception as exc:  # noqa: BLE001
            failures.append(("service", str(exc)))
    if failures:
        error = (
            failures[0][1]
            if len(failures) == 1
            else "; ".join(f"{scope}: {message}" for scope, message in failures)
        )
        finish_lane_cleanup(
            run,
            lane_id=lane_id,
            error=error,
        )
        raise RuntimeError(error)
    lane = finish_lane_cleanup(run, lane_id=lane_id)
    return {
        "lane": lane,
        "sandbox_cleanup": cleanup_result,
        "service_cleanup": service_result,
        "artifacts_preserved": str(run / "workers" / lane_id / "artifacts"),
        "shared_artifacts_preserved": str(run / "exchange" / "store"),
    }


def _race_cleanup(repo: Path, args: argparse.Namespace) -> dict[str, Any]:
    run = resolve_run(repo, args.run_id)
    race = load_race(run)
    if race["status"] not in {"WON", "TIMED_OUT", "HANDOFF", "STOPPED"}:
        raise ValueError("race cleanup requires a terminal race state")
    # Every native child that was ever spawned — winner or not — must carry a
    # native_stopped_at stop proof and be in a cleanup-terminal lane state before
    # controller cleanup may touch it. The lane status name alone (including a
    # child that found the flag) is never sufficient.
    unresolved_native = [
        {
            "lane_id": str(lane.get("lane_id")),
            "status": str(lane.get("status")),
            "native_session": str(lane.get("native_session")),
        }
        for lane in race.get("lanes", [])
        if isinstance(lane, Mapping)
        and lane.get("lane_id") != "root"
        and lane.get("native_session")
        and not (
            lane.get("native_stopped_at")
            and lane.get("status") in {"STOPPED", "CLEANUP_FAILED"}
        )
    ]
    pending_cancel_targets = cancel_targets(race)
    if unresolved_native or pending_cancel_targets:
        raise ValueError(
            "race cleanup requires every native child to be interrupted and "
            "reconciled first: "
            + json.dumps(
                {
                    "unresolved_native": unresolved_native,
                    "cancel_targets": pending_cancel_targets,
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
    cleaned: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for lane in race["lanes"]:
        metadata_path = run / "workers" / str(lane["lane_id"]) / "sandbox.json"
        if not metadata_path.exists():
            continue
        try:
            cleaned.append(cleanup(load_metadata(metadata_path), docker=args.docker))
        except Exception as exc:  # noqa: BLE001
            failures.append({"scope": str(lane["lane_id"]), "error": str(exc)})
    service_root = run / "service"
    service_paths = (
        sorted(
            (
                path for path in service_root.rglob("service.json")
                if path != service_root / "service.json"
            ),
            key=lambda path: path.as_posix(),
        )
        if service_root.exists() else []
    )
    root_service_path = service_root / "service.json"
    if root_service_path.exists():
        service_paths.append(root_service_path)
    attempted_service_paths: set[str] = set()
    for service_path in service_paths:
        attempted_service_paths.add(str(service_path.resolve()))
        try:
            if service_path.is_symlink() or not service_path.is_file():
                raise ValueError("service metadata path is unsafe")
            service_cleanup = cleanup_service(
                load_service(service_path), actor=ServiceActor("root", "root"), docker=args.docker
            )
            cleaned.append(service_cleanup)
            if not service_cleanup["cleaned"]:
                failures.extend(
                    {"scope": "service", "error": str(error)}
                    for error in service_cleanup["failures"]
                )
        except Exception as exc:  # noqa: BLE001
            failures.append({"scope": "service", "error": str(exc)})
    recovery_service = race.get("service_context")
    if isinstance(recovery_service, Mapping) and recovery_service.get("runtime"):
        recovery_path = str(
            Path(str(recovery_service.get("metadata_path", ""))).resolve()
        )
        if recovery_path not in attempted_service_paths:
            try:
                if recovery_service.get("run_id") != run.name:
                    raise ValueError(
                        "service recovery state does not belong to this exact run"
                    )
                service_cleanup = cleanup_service(
                    recovery_service,
                    actor=ServiceActor("root", "root"),
                    docker=args.docker,
                )
                cleaned.append(service_cleanup)
                if not service_cleanup["cleaned"]:
                    failures.extend(
                        {"scope": "service", "error": str(error)}
                        for error in service_cleanup["failures"]
                    )
            except Exception as exc:  # noqa: BLE001
                failures.append({"scope": "service-recovery", "error": str(exc)})
    result = {
        "run_id": run.name,
        "cleaned": cleaned,
        "failures": failures,
        "active_cleared": False,
    }
    if failures:
        raise RuntimeError(
            "race cleanup incomplete: "
            + json.dumps(result, ensure_ascii=False, separators=(",", ":"))
        )
    clear_active(repo, run_id=run.name)
    return result | {"active_cleared": True}


def _prepare_result(
    run: Path,
    input_record: Mapping[str, Any],
    image: Mapping[str, Any],
    service: Mapping[str, Any],
    race: Mapping[str, Any],
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    root = next(row for row in race["lanes"] if row["lane_id"] == "root")
    sandbox = root.get("sandbox")
    return {
        "contest": race["contest"],
        "challenge": race["challenge"],
        "run_id": race["run_id"],
        "attempt_id": race["attempt_id"],
        "challenge_instance_id": race["challenge_instance_id"],
        "run_root": str(run),
        "prepared_input": {
            "path": input_record["prepared_input"],
            "read_only": True,
            "fingerprint": input_record["prepared_fingerprint"],
        },
        "declared_targets": race["declared_targets"],
        "recommended_image": image["recommended_image"],
        "selected_image": image["selected_image"],
        "image_availability": image,
        "root_sandbox": sandbox or {"status": "UNAVAILABLE", "reason": race.get("prepare_blocker")},
        "service": service,
        "service_endpoints": race["service_endpoints"],
        "flag_pattern": race["flag_pattern"],
        "priority_files": race["priority_files"],
        "deadline": race["deadline"],
        "root_model_profile": root["model_profile"],
        "root_model_profile_source": root.get("model_profile_source"),
        "service_isolation": race.get("service_isolation", "shared"),
        "remote_execution": race.get("remote_execution", "agent"),
        "service_instances": race.get("service_instances", {}),
        "lanes": [{"lane_id": row["lane_id"], "status": row["status"], "attack_family": row["attack_family"]} for row in race["lanes"]],
        "attack_ready": race["attack_ready"],
        "dry_run": dry_run,
        "next_root_action": (
            {
                "exec_command_prefix": sandbox["exec_command_prefix"],
                "instruction": (
                    "append the highest-probability local attack argv and execute now; "
                    "for an organizer remote attempt, emit HUMAN_REMOTE_ACTION with the "
                    "exact participant-run command and analyze the returned HUMAN_REMOTE_RESULT"
                    if race.get("remote_execution", "agent") == "human-relay"
                    else "append the highest-probability attack argv and execute now"
                ),
            }
            if sandbox else
            {"blocked": True, "recovery_command": image.get("recovery_command"), "reason": race.get("prepare_blocker")}
        ),
    }


def _agent_targets(
    remotes: Sequence[str | Mapping[str, Any]],
    *,
    service_network: str | None,
    remote_execution: str,
    docker: str,
):
    if service_network or remote_execution == "human-relay":
        return ()
    return _resolve_declared_targets(remotes, docker=docker)


def _selection_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("selector")
    parser.add_argument("--contest")


def _select(repo: Path, contest_selector: str | None, challenge_selector: str):
    manifest = select_contest(discover_contests(repo / "incoming"), contest_selector)
    return manifest, resolve_selector(manifest.challenges, challenge_selector)


def _lane_json(args: argparse.Namespace) -> list[Mapping[str, Any]]:
    inline_lanes = getattr(args, "lanes", None)
    if inline_lanes:
        if sum(len(raw) for raw in inline_lanes) > 64 * 1024:
            raise ValueError("inline lane JSON is too large")
        values = [json.loads(raw) for raw in inline_lanes]
        if any(not isinstance(row, dict) for row in values):
            raise ValueError("each --lane value must be one JSON object")
        return values
    if args.lanes_file:
        path = Path(args.lanes_file)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
            raise ValueError("lanes file is missing, unsafe, or too large")
        raw = path.read_text(encoding="utf-8")
    else:
        raw = args.lanes_json
    value = json.loads(raw)
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError("lanes JSON must be an array of objects")
    return value


def _remainder(values: Sequence[str]) -> list[str]:
    result = list(values)
    if result[:1] == ["--"]:
        result = result[1:]
    if not result:
        raise ValueError("an argv is required after --")
    return result


def _optional_remainder(values: Sequence[str]) -> list[str] | None:
    result = list(values)
    if result[:1] == ["--"]:
        result = result[1:]
    return result or None


def _resolve_declared_targets(remotes: Sequence[Any], *, docker: str):
    """Resolve declared remotes against the live Docker gateway set (fail closed)."""

    if not remotes:
        return ()
    blocked = collect_docker_gateways(docker=docker)
    return resolve_targets(
        parse_remotes(remotes, blocked_gateways=blocked), blocked_gateways=blocked
    )


def _resolve_stored_targets(declared_targets: Sequence[Any], *, docker: str):
    """Resolve immutable stored target records against the live Docker gateways."""

    if not declared_targets:
        return ()
    blocked = collect_docker_gateways(docker=docker)
    return resolve_targets(
        rebuild_targets(declared_targets, blocked_gateways=blocked),
        blocked_gateways=blocked,
    )


def _persist_child_service_recovery(
    run: Path, lane_id: str, recovery: Mapping[str, Any]
) -> None:
    """Write a child lane's CLEANUP_FAILED service recovery record for later retry."""

    expected = (run / "service" / "instances" / lane_id / "service.json").resolve()
    if Path(str(recovery.get("metadata_path", ""))).resolve() != expected:
        raise ValueError("service recovery record does not belong to this lane")
    atomic_json(expected, dict(recovery))


def _require_active_race_selector(
    race: Mapping[str, Any], contest_selector: str | None, challenge_selector: str
) -> None:
    """Confirm the CLI selector names the active run without reading the manifest."""

    contest = race.get("contest", {})
    if contest_selector:
        key = unicodedata.normalize("NFKC", contest_selector).strip().casefold()
        if key not in {
            str(contest.get("name", "")).casefold(),
            str(contest.get("slug", "")).casefold(),
        }:
            raise ValueError("selector contest does not match the exact active race")
    challenge = race.get("challenge", {})
    raw = unicodedata.normalize("NFKC", challenge_selector).strip()
    number = re.fullmatch(r"0*([1-9][0-9]*)\s*(?:번(?:\s*문제)?)?", raw)
    if number:
        matched = str(challenge.get("number")) == number.group(1)
    else:
        folded = raw.casefold()
        matched = folded in {
            str(challenge.get("key", "")).casefold(),
            str(challenge.get("id", "")).casefold(),
            str(challenge.get("name", "")).casefold(),
        }
    if not matched:
        raise ValueError("selector does not match the exact active race")


def _resource_profile(input_record: Mapping[str, Any]) -> str:
    total = int(input_record.get("total_bytes", 0))
    if total > 2 * 1024**3:
        return "large-forensic"
    if total > 256 * 1024**2:
        return "heavy"
    return "standard"


def _create_sandbox(spec: SandboxSpec, *, docker: str) -> dict[str, Any]:
    """Admit the strongest feasible profile without oversubscribing the host."""

    order = {
        "large-forensic": ("large-forensic", "heavy", "standard", "light"),
        "heavy": ("heavy", "standard", "light"),
        "standard": ("standard", "light"),
        "light": ("light",),
    }[spec.resource_profile]
    failures: list[str] = []
    for profile in order:
        candidate = replace(spec, resource_profile=profile)
        try:
            metadata = create(candidate, docker=docker)
            if profile != spec.resource_profile:
                metadata["resource_degraded_from"] = spec.resource_profile
                metadata["resource_degraded_reason"] = failures[-1]
            return metadata
        except SandboxError as exc:
            message = str(exc)
            if "aggregate managed-container" not in message and "reserved host budget" not in message:
                raise
            failures.append(message)
    raise SandboxError(
        "no sandbox resource profile fits the aggregate host budget: "
        + "; ".join(failures)
    )


def _attack_timeout(metadata: Mapping[str, Any], requested: int) -> int:
    if requested < 1:
        raise ValueError("attack timeout must be positive")
    run = Path(str(metadata["lane_root"])).resolve().parents[1]
    race = load_race(run)
    if race.get("status") != "ACTIVE":
        raise ValueError(f"race is not attack-active: {race.get('status')}")
    remaining = (datetime.fromisoformat(str(race["deadline"])) - datetime.now(UTC)).total_seconds()
    if remaining <= 0:
        terminal = terminate(run, reason="TIMED_OUT")
        raise ValueError(
            "90-minute race deadline has passed; native cancel targets: "
            + json.dumps(terminal["cancel_targets"], sort_keys=True)
        )
    return max(1, min(requested, int(remaining) or 1))


if __name__ == "__main__":
    raise SystemExit(main())
