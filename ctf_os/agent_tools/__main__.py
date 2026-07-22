"""Single-challenge race controller CLI.

This module prepares state and sandboxes.  It never calls a model API, starts
or interrupts a native agent, or submits a flag.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence

from ..blackboard import append_verified_event
from ..contest import discover_contests, initialize_contest, resolve_selector, select_contest
from ..doctor import run_doctor
from ..flag import StreamingDetector, record_candidate
from ..handoff import load_markdown, save_handoff
from ..images import select_image, smoke_images
from ..preflight import input_fingerprint, prepare_input, validate_prepared_input
from ..race import (
    attach_lane_sandbox,
    confirm_native_spawn,
    initialize_race,
    load_race,
    mark_lane_prepare_failed,
    mark_prepare_failed,
    mark_root_ready,
    note_command_receipt,
    note_event,
    reserve_lanes,
    reserve_max_endgame,
    set_service_context,
    status as race_status,
    stop_confirmed,
    terminate,
)
from ..sandbox.network import parse_remotes, resolve_targets
from ..sandbox.runtime import (
    SandboxSpec, cleanup, create, execute, load_metadata, probe_service_connectivity,
)
from ..sandbox.session import (
    close_session,
    list_sessions,
    list_tools,
    open_session,
    read as session_read,
    send as session_send,
    tool_help,
    tool_version,
)
from ..service import ServiceActor, ServiceSpec, cleanup_service, load_service, prepare_service
from ..workspace import clear_active, create_run, resolve_run, utc_now


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m ctf_os.agent_tools",
        description="Verified asynchronous portfolio race controller for one authorized CTF challenge",
    )
    parser.add_argument("--repo", default=".")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init-contest", help="create a fresh contest manifest and one challenge input folder")
    init.add_argument("contest")
    init.add_argument("--challenge", required=True, metavar="CATEGORY/NAME")

    prepare = commands.add_parser("race-prepare", help="select, materialize, and create the Root sandbox")
    _selection_args(prepare)
    prepare.add_argument("--docker", default="docker")
    prepare.add_argument("--dry-run", action="store_true", help="prepare fresh state but do not start service/sandbox")

    bootstrap = commands.add_parser("race-bootstrap", help="prepare all requested private native-worker lanes")
    _selection_args(bootstrap)
    group = bootstrap.add_mutually_exclusive_group(required=True)
    group.add_argument("--lanes-json")
    group.add_argument("--lanes-file")
    bootstrap.add_argument("--docker", default="docker")

    confirm = commands.add_parser("race-spawn-confirm", help="record the native thread identity returned by Root")
    confirm.add_argument("--run-id")
    confirm.add_argument("--lane", required=True)
    confirm.add_argument("--native-session", required=True)

    endgame = commands.add_parser("race-endgame", help="prepare the single qualified post-minute-60 Sol max replacement")
    endgame.add_argument("--run-id")
    endgame.add_argument("--replaces-lane", required=True)
    endgame.add_argument("--task", required=True)
    endgame.add_argument("--attack-family", required=True)
    endgame.add_argument("--docker", default="docker")

    show = commands.add_parser("race-status", help="return mechanical progress, duplicate, and stagnation signals")
    show.add_argument("--run-id")

    stop = commands.add_parser("race-stop-confirm", help="confirm that Root interrupted one native child")
    stop.add_argument("--run-id")
    stop.add_argument("--lane", required=True)
    stop.add_argument("--native-session", required=True)
    stop.add_argument("--docker", default="docker")

    end = commands.add_parser("race-end", help="mark timeout, handoff, or explicit stop and return cancel targets")
    end.add_argument("--run-id")
    end.add_argument("--reason", required=True, choices=("TIMED_OUT", "HANDOFF", "STOPPED"))

    handoff = commands.add_parser("race-handoff", help="terminate the exact race and save one manual HANDOFF.md")
    handoff.add_argument("--run-id")
    handoff.add_argument("--markdown-file", required=True)

    clean = commands.add_parser("race-cleanup", help="clean exact-run sandboxes/service after native stops")
    clean.add_argument("--run-id")
    clean.add_argument("--docker", default="docker")

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
    image_smoke = commands.add_parser("image-smoke", help="inspect all ten local category images")
    image_smoke.add_argument("--docker", default="docker")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo = Path(args.repo).resolve()
    try:
        result = dispatch(args, repo)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps({"ok": True, "result": result}, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def dispatch(args: argparse.Namespace, repo: Path) -> Any:
    if args.command == "init-contest":
        return initialize_contest(repo, args.contest, args.challenge)
    if args.command == "race-prepare":
        return _race_prepare(repo, args)
    if args.command == "race-bootstrap":
        return _race_bootstrap(repo, args)
    if args.command == "race-spawn-confirm":
        run = resolve_run(repo, args.run_id)
        return confirm_native_spawn(run, lane_id=args.lane, native_session=args.native_session)
    if args.command == "race-endgame":
        return _race_endgame(repo, args)
    if args.command == "race-status":
        return race_status(resolve_run(repo, args.run_id))
    if args.command == "race-stop-confirm":
        run = resolve_run(repo, args.run_id)
        lane = stop_confirmed(run, lane_id=args.lane, native_session=args.native_session)
        metadata_path = run / "workers" / str(args.lane) / "sandbox.json"
        if not metadata_path.is_file() or metadata_path.is_symlink():
            raise ValueError("stopped lane has no safe private sandbox metadata to clean")
        return {
            "lane": lane,
            "sandbox_cleanup": cleanup(load_metadata(metadata_path), docker=args.docker),
            "artifacts_preserved": str(run / "workers" / str(args.lane) / "artifacts"),
        }
    if args.command == "race-end":
        return terminate(resolve_run(repo, args.run_id), reason=args.reason)
    if args.command == "race-handoff":
        return _race_handoff(repo, args)
    if args.command == "race-cleanup":
        return _race_cleanup(repo, args)
    if args.command == "sandbox-exec":
        return _sandbox_exec(Path(args.metadata), args)
    if args.command == "blackboard-add":
        return _blackboard_add(Path(args.receipt), args)
    if args.command == "session-open":
        metadata = load_metadata(Path(args.metadata))
        _attack_timeout(metadata, 30)
        return open_session(
            metadata, session_id=args.session, kind=args.kind,
            command=_optional_remainder(args.argv), target_identity=args.target_identity,
        )
    if args.command == "session-send":
        metadata = load_metadata(Path(args.metadata))
        return session_send(
            metadata, session_id=args.session, data=args.data,
            timeout=_attack_timeout(metadata, args.timeout),
        )
    if args.command == "session-read":
        return _session_read(Path(args.metadata), args)
    if args.command == "session-close":
        return close_session(
            load_metadata(Path(args.metadata)), session_id=args.session, timeout=args.timeout,
        )
    if args.command == "session-list":
        return list_sessions(load_metadata(Path(args.metadata)))
    if args.command == "list-tools":
        return list_tools(str(load_metadata(Path(args.metadata))["category"]))
    if args.command == "tool-help":
        metadata = load_metadata(Path(args.metadata))
        return tool_help(str(metadata["category"]), args.name)
    if args.command == "tool-version":
        metadata = load_metadata(Path(args.metadata))
        _attack_timeout(metadata, 20)
        return tool_version(metadata, args.name)
    if args.command == "doctor":
        return run_doctor(repo, docker=args.docker)
    if args.command == "image-smoke":
        return smoke_images(docker=args.docker)
    raise ValueError(f"unsupported command: {args.command}")


def _race_prepare(repo: Path, args: argparse.Namespace) -> dict[str, Any]:
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
    race = initialize_race(
        run,
        run_manifest=run_manifest,
        input_record=input_record,
        image=image,
        service=service,
        selected_at=selected_at,
        input_ready_at=input_ready_at,
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
        )
        service = prepare_service(
            service_spec, actor=ServiceActor(lane_id="root", role="root"), docker=args.docker
        )
        set_service_context(run, service)
        targets = () if service.get("status") == "READY" else resolve_targets(parse_remotes(challenge.remotes))
        root_sandbox = create(SandboxSpec(
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
            resource_profile=_resource_profile(input_record),
            race_lane_count=0,
        ), docker=args.docker)
        if service.get("status") == "READY":
            root_sandbox["service_probe"] = probe_service_connectivity(root_sandbox, docker=args.docker)
        race = mark_root_ready(run, root_sandbox)
    except Exception as exc:
        race = mark_prepare_failed(run, str(exc))
        service = service | {"prepare_error": str(exc)}
        if root_sandbox is not None:
            try:
                cleanup(root_sandbox, docker=args.docker)
            except Exception as cleanup_exc:
                service["cleanup_error"] = str(cleanup_exc)
        if service.get("status") == "READY":
            try:
                service_cleanup = cleanup_service(
                    service, actor=ServiceActor("root", "root"), docker=args.docker
                )
                if not service_cleanup["cleaned"]:
                    service["cleanup_error"] = "; ".join(service_cleanup["failures"])
            except Exception as cleanup_exc:
                service["cleanup_error"] = str(cleanup_exc)
        if "cleanup_error" not in service:
            clear_active(repo, run_id=run.name)
    return _prepare_result(run, input_record, image, service, race)


def _race_bootstrap(repo: Path, args: argparse.Namespace) -> dict[str, Any]:
    manifest, challenge = _select(repo, args.contest, args.selector)
    run = resolve_run(repo)
    race = load_race(run)
    if race["challenge"]["id"] != challenge.id or race["contest"]["slug"] != manifest.slug:
        raise ValueError("selector does not match the exact active race")
    specifications = _lane_json(args)
    reserved = reserve_lanes(run, specifications)
    source, input_record = validate_prepared_input(run)
    service_network = race.get("service_network")
    service_endpoints = tuple(str(value) for value in race.get("service_endpoints", []))
    targets = () if service_network else resolve_targets(parse_remotes(challenge.remotes))
    packets: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for lane in reserved:
        try:
            metadata = create(SandboxSpec(
                run_id=run.name,
                contest_slug=manifest.slug,
                challenge_id=challenge.id,
                category=challenge.category,
                lane_id=str(lane["lane_id"]),
                source=source,
                lane_root=run / "workers" / str(lane["lane_id"]),
                input_fingerprint=str(input_record["input_fingerprint"]),
                image=str(race["selected_image"]),
                targets=targets,
                service_network=str(service_network) if service_network else None,
                service_endpoints=service_endpoints,
                resource_profile=_resource_profile(input_record),
                race_lane_count=1 + len(packets),
            ), docker=args.docker)
            packets.append(attach_lane_sandbox(run, lane_id=str(lane["lane_id"]), sandbox=metadata))
        except Exception as exc:
            mark_lane_prepare_failed(run, lane_id=str(lane["lane_id"]), reason=str(exc))
            failures.append({"lane_id": str(lane["lane_id"]), "error": str(exc)})
    return {
        "run_id": run.name,
        "packets": packets,
        "failures": failures,
        "native_spawn_performed": False,
        "next_action": "Root passes each spawn_agent_args to native spawn_agent immediately while continuing its own attack.",
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
    targets = () if service_network else resolve_targets(parse_remotes(remotes))
    try:
        metadata = create(SandboxSpec(
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
            resource_profile=_resource_profile(input_record),
            race_lane_count=sum(
                row["status"] not in {"STOPPED", "WON"}
                for row in load_race(run)["lanes"] if row["lane_id"] != lane["lane_id"]
            ),
        ), docker=args.docker)
        packet = attach_lane_sandbox(run, lane_id=str(lane["lane_id"]), sandbox=metadata)
    except Exception as exc:
        mark_lane_prepare_failed(run, lane_id=str(lane["lane_id"]), reason=str(exc))
        raise
    return {
        "run_id": run.name,
        "packet": packet,
        "lease_seconds": 600,
        "max_actual_attacks": 2,
        "native_spawn_performed": False,
    }


def _sandbox_exec(metadata_path: Path, args: argparse.Namespace) -> dict[str, Any]:
    metadata = load_metadata(metadata_path)
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
        winner = record_candidate(
            run,
            lane_id=str(metadata["lane_id"]),
            attack_family=str(lane["attack_family"]),
            candidate=str(receipt["flag_candidate"]),
            receipt=receipt,
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
    except Exception as exc:
        warnings.append(f"post-execution blackboard write failed: {exc}")
    return {"receipt": receipt, "winner": winner, "warnings": warnings}


def _blackboard_add(receipt_path: Path, args: argparse.Namespace) -> dict[str, Any]:
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise ValueError("receipt path is missing or unsafe")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if not isinstance(receipt, dict):
        raise ValueError("receipt must be a JSON object")
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


def _session_read(metadata_path: Path, args: argparse.Namespace) -> dict[str, Any]:
    metadata = load_metadata(metadata_path)
    receipt = session_read(
        metadata, session_id=args.session, limit=args.limit,
        timeout=_attack_timeout(metadata, args.timeout),
    )
    run = Path(str(metadata["lane_root"])).resolve().parents[1]
    race = load_race(run)
    lane = next(row for row in race["lanes"] if row["lane_id"] == metadata["lane_id"])
    detector = StreamingDetector(str(race.get("flag_pattern") or ""))
    candidate = detector.feed(str(receipt["observed_output"]))
    winner = None
    if candidate:
        winner = record_candidate(
            run,
            lane_id=str(metadata["lane_id"]),
            attack_family=str(lane["attack_family"]),
            candidate=candidate,
            receipt=receipt,
        )
    warnings: list[str] = []
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
    except Exception as exc:
        warnings.append(f"post-execution blackboard write failed: {exc}")
    return {"receipt": receipt, "winner": winner, "warnings": warnings}


def _race_handoff(repo: Path, args: argparse.Namespace) -> dict[str, Any]:
    run = resolve_run(repo, args.run_id)
    race = load_race(run)
    terminated = terminate(run, reason="HANDOFF")
    markdown = load_markdown(Path(args.markdown_file))
    destination = save_handoff(
        repo,
        contest=str(race["contest"]["name"]),
        challenge=f"{race['challenge']['category']}-{race['challenge']['name']}",
        run_id=run.name,
        markdown=markdown,
    )
    return terminated | {
        "handoff_path": str(destination),
        "next_action": "Root interrupts every cancel target, then runs race-cleanup for this exact run.",
    }


def _race_cleanup(repo: Path, args: argparse.Namespace) -> dict[str, Any]:
    run = resolve_run(repo, args.run_id)
    race = load_race(run)
    if race["status"] not in {"WON", "TIMED_OUT", "HANDOFF", "STOPPED"}:
        raise ValueError("race cleanup requires a terminal race state")
    cleaned: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for lane in race["lanes"]:
        metadata_path = run / "workers" / str(lane["lane_id"]) / "sandbox.json"
        if not metadata_path.exists():
            continue
        try:
            cleaned.append(cleanup(load_metadata(metadata_path), docker=args.docker))
        except Exception as exc:
            failures.append({"scope": str(lane["lane_id"]), "error": str(exc)})
    service_path = run / "service" / "service.json"
    if service_path.exists():
        try:
            service_cleanup = cleanup_service(
                load_service(service_path), actor=ServiceActor("root", "root"), docker=args.docker
            )
            cleaned.append(service_cleanup)
            if not service_cleanup["cleaned"]:
                failures.extend(
                    {"scope": "service", "error": str(error)}
                    for error in service_cleanup["failures"]
                )
        except Exception as exc:
            failures.append({"scope": "service", "error": str(exc)})
    if not failures:
        clear_active(repo, run_id=run.name)
    return {"run_id": run.name, "cleaned": cleaned, "failures": failures, "active_cleared": not failures}


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
        "lanes": [{"lane_id": row["lane_id"], "status": row["status"], "attack_family": row["attack_family"]} for row in race["lanes"]],
        "attack_ready": race["attack_ready"],
        "dry_run": dry_run,
        "next_root_action": (
            {"exec_command_prefix": sandbox["exec_command_prefix"], "instruction": "append the highest-probability attack argv and execute now"}
            if sandbox else
            {"blocked": True, "recovery_command": image.get("recovery_command"), "reason": race.get("prepare_blocker")}
        ),
    }


def _selection_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("selector")
    parser.add_argument("--contest")


def _select(repo: Path, contest_selector: str | None, challenge_selector: str):
    manifest = select_contest(discover_contests(repo / "incoming"), contest_selector)
    return manifest, resolve_selector(manifest.challenges, challenge_selector)


def _lane_json(args: argparse.Namespace) -> list[Mapping[str, Any]]:
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


def _resource_profile(input_record: Mapping[str, Any]) -> str:
    total = int(input_record.get("total_bytes", 0))
    if total > 2 * 1024**3:
        return "large-forensic"
    if total > 256 * 1024**2:
        return "heavy"
    return "standard"


def _attack_timeout(metadata: Mapping[str, Any], requested: int) -> int:
    if requested < 1:
        raise ValueError("attack timeout must be positive")
    run = Path(str(metadata["lane_root"])).resolve().parents[1]
    race = load_race(run)
    if race.get("status") != "ACTIVE":
        raise ValueError(f"race is not attack-active: {race.get('status')}")
    remaining = (datetime.fromisoformat(str(race["deadline"])) - datetime.now(timezone.utc)).total_seconds()
    if remaining <= 0:
        terminal = terminate(run, reason="TIMED_OUT")
        raise ValueError(
            "90-minute race deadline has passed; native cancel targets: "
            + json.dumps(terminal["cancel_targets"], sort_keys=True)
        )
    return max(1, min(requested, int(remaining) or 1))


if __name__ == "__main__":
    raise SystemExit(main())
