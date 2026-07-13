from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from ..challenge import SelectionError, resolve_selector
from ..contest import ContestError, discover_contests, select_contest
from ..evidence import append_finding
from ..intake import current_source_fingerprint, prepared_tree_fingerprint, run_intake
from ..doctor import run_doctor
from ..replay import run_replay
from ..sandbox.network import parse_remotes, resolve_targets
from ..sandbox.resources import sandbox_gc, sandbox_status
from ..sandbox.runtime import SandboxSpec, cleanup, create, execute, export_artifacts
from ..service import (
    ServiceSpec, service_build, service_cleanup, service_plan,
    service_start, service_status, service_stop,
)
from ..workspace import atomic_json, challenge_root, initialize_solve_files, state_lock


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m ctf_os.agent_tools", description="Internal JSON tools for the active Sol session")
    parser.add_argument("--repo", default=".")
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect-contest")
    inspect.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    inspect.add_argument("--contest")
    intake = commands.add_parser("intake")
    intake.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    intake.add_argument("--contest")
    prepare = commands.add_parser("prepare-challenge")
    prepare.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    prepare.add_argument("selector")
    prepare.add_argument("--contest")
    sandbox_create = commands.add_parser("sandbox-create")
    sandbox_create.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    sandbox_create.add_argument("selector")
    sandbox_create.add_argument("--contest")
    sandbox_create.add_argument("--branch", required=True)
    sandbox_create.add_argument("--image")
    sandbox_create.add_argument("--resource-profile")
    sandbox_create.add_argument("--service", action="store_true", help=argparse.SUPPRESS)
    sandbox_exec = commands.add_parser("sandbox-exec")
    sandbox_exec.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    sandbox_exec.add_argument("metadata")
    sandbox_exec.add_argument("--timeout", type=int, default=120)
    sandbox_exec.add_argument("argv", nargs=argparse.REMAINDER)
    sandbox_cleanup = commands.add_parser("sandbox-cleanup")
    sandbox_cleanup.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    sandbox_cleanup.add_argument("metadata")
    sandbox_export = commands.add_parser("sandbox-export")
    sandbox_export.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    sandbox_export.add_argument("metadata")
    commands.add_parser("sandbox-status")
    commands.add_parser("sandbox-gc")
    commands.add_parser("doctor")
    for name in ("service-plan", "service-build", "service-start", "service-status", "service-stop", "service-cleanup"):
        service = commands.add_parser(name)
        service.add_argument("selector")
        service.add_argument("--contest")
    replay = commands.add_parser("replay")
    replay.add_argument("selector")
    replay.add_argument("--contest")
    finding = commands.add_parser("record-finding")
    finding.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    finding.add_argument("selector")
    finding.add_argument("--contest")
    finding.add_argument("--branch", required=True)
    finding.add_argument("--status", required=True, choices=("supported", "rejected", "inconclusive"))
    finding.add_argument("--summary", required=True)
    finding.add_argument("--evidence", required=True)
    return parser


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
    print(json.dumps({"ok": True, "result": result}, ensure_ascii=False, sort_keys=True))
    return 0


def dispatch(root: Path, args: argparse.Namespace) -> object:
    if args.command == "doctor":
        return run_doctor(root)
    if args.command == "sandbox-status":
        return sandbox_status()
    if args.command == "sandbox-gc":
        return sandbox_gc()
    if args.command == "inspect-contest":
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
    if args.command == "sandbox-exec":
        metadata = _load_metadata(root, args.metadata)
        command = list(args.argv)
        if command and command[0] == "--":
            command.pop(0)
        result = execute(metadata, command, args.timeout)
        if result["timed_out"]:
            _update_branch_state(Path(str(metadata["branch_root"])).parents[1], str(metadata["branch"]), "TIMED_OUT", str(metadata["metadata_path"]))
        return result
    if args.command == "sandbox-cleanup":
        metadata = _load_metadata(root, args.metadata)
        result = cleanup(metadata)
        _update_branch_state(Path(str(metadata["branch_root"])).parents[1], str(metadata["branch"]), "CLEANED", str(metadata["metadata_path"]))
        return result
    if args.command == "sandbox-export":
        return export_artifacts(_load_metadata(root, args.metadata))

    manifest, challenge, record = _load_challenge(root, args.contest, args.selector)
    solve_root = challenge_root(root, manifest, challenge)
    initialize_solve_files(solve_root, challenge)
    if args.command == "prepare-challenge":
        return _compact_prepare(challenge, record, solve_root)
    if args.command.startswith("service-"):
        spec = _service_spec(manifest, challenge, record, solve_root)
        operation = {
            "service-plan": service_plan, "service-build": service_build,
            "service-start": service_start, "service-status": service_status,
            "service-stop": service_stop, "service-cleanup": service_cleanup,
        }[args.command]
        return operation(spec)
    if args.command == "replay":
        return run_replay(root, manifest, challenge, record)
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
        image = args.image or str(record.get("recommended_image") or f"ctf-os-sandbox:{challenge.category if challenge.category in {'pwn', 'web', 'rev', 'crypto', 'forensic'} else 'base'}")
        profile = args.resource_profile or str(record.get("recommended_resource_profile") or "standard")
        targets = resolve_targets(parse_remotes(challenge.remotes))
        service_network = None
        endpoints: tuple[str, ...] = ()
        if args.service:
            service = _service_spec(manifest, challenge, record, solve_root)
            status = service_status(service)
            if not status.get("running"):
                raise ValueError("challenge service is not running; call service-start first")
            targets = ()
            service_network = service.network
            endpoints = tuple(
                str(item["internal_target"]) for item in dict(record.get("service_plan") or {}).get("services", [])
                if isinstance(item, dict) and item.get("internal_target")
            )
        spec = SandboxSpec(
            contest_slug=manifest.slug, challenge_id=challenge.id, branch=args.branch,
            source=expected_source, branch_root=branch_root,
            input_fingerprint=str(record["source_fingerprint"]),
            targets=targets, image=image, resource_profile=profile,
            service_network=service_network, local_endpoints=endpoints,
        )
        metadata = create(spec)
        try:
            _update_branch_state(solve_root, args.branch, "RUNNING", str(metadata["metadata_path"]))
        except Exception:
            cleanup(metadata)
            raise
        return metadata
    if args.command == "record-finding":
        return append_finding(solve_root, args.branch, args.summary, args.evidence, args.status)
    raise ValueError(f"unsupported internal command: {args.command}")


def _service_spec(manifest, challenge, record: dict[str, object], solve_root: Path) -> ServiceSpec:
    plan = record.get("service_plan")
    if not isinstance(plan, dict) or not plan.get("kind"):
        raise ValueError("intake found no Dockerfile/Compose challenge service plan")
    return ServiceSpec(
        contest_slug=manifest.slug, challenge_id=challenge.id,
        source=solve_root / "input", workspace=solve_root, service_plan=plan,
    )


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
    return {key: state.get(key) for key in ("status", "flag_candidate", "branches", "input_fingerprint", "updated_at")}


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
    return manifest, challenge, records[0]


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


if __name__ == "__main__":
    raise SystemExit(main())
