from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from ..challenge import SelectionError, resolve_selector
from ..contest import ContestError, discover_contests, select_contest
from ..evidence import append_finding
from ..flags import verify_and_record
from ..intake import current_source_fingerprint, prepared_tree_fingerprint, run_intake
from ..sandbox.network import parse_remotes, resolve_targets
from ..sandbox.runtime import SandboxSpec, cleanup, create, execute
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
    sandbox_create.add_argument("--image", default="ctf-os-sandbox:latest")
    sandbox_exec = commands.add_parser("sandbox-exec")
    sandbox_exec.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    sandbox_exec.add_argument("metadata")
    sandbox_exec.add_argument("--timeout", type=int, default=120)
    sandbox_exec.add_argument("argv", nargs=argparse.REMAINDER)
    sandbox_cleanup = commands.add_parser("sandbox-cleanup")
    sandbox_cleanup.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    sandbox_cleanup.add_argument("metadata")
    finding = commands.add_parser("record-finding")
    finding.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    finding.add_argument("selector")
    finding.add_argument("--contest")
    finding.add_argument("--branch", required=True)
    finding.add_argument("--status", required=True, choices=("supported", "rejected", "inconclusive"))
    finding.add_argument("--summary", required=True)
    finding.add_argument("--evidence", required=True)
    verify = commands.add_parser("verify-result")
    verify.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    verify.add_argument("selector")
    verify.add_argument("--contest")
    verify.add_argument("--flag", required=True)
    verify.add_argument("--local", action="store_true")
    verify.add_argument("--remote", action="store_true")
    verify.add_argument("--independent", action="store_true")
    verify.add_argument("--reproduce-command", required=True)
    verify.add_argument("--local-evidence", required=True, help="unique substring identifying a successful sandbox receipt")
    verify.add_argument("--independent-evidence", required=True, help="unique substring identifying a different successful sandbox receipt")
    verify.add_argument("--remote-evidence", help="unique substring identifying remote reproduction")
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

    manifest, challenge, record = _load_challenge(root, args.contest, args.selector)
    solve_root = challenge_root(root, manifest, challenge)
    initialize_solve_files(solve_root, challenge)
    if args.command == "prepare-challenge":
        return {"challenge": challenge.to_dict(), "context": record, "solve_root": str(solve_root)}
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
        spec = SandboxSpec(
            contest_slug=manifest.slug, challenge_id=challenge.id, branch=args.branch,
            source=expected_source, branch_root=branch_root,
            input_fingerprint=str(record["source_fingerprint"]),
            targets=resolve_targets(parse_remotes(challenge.remotes)), image=args.image,
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
    if args.command == "verify-result":
        (solve_root / "exploit").mkdir(exist_ok=True)
        state = json.loads((solve_root / "STATE.json").read_text(encoding="utf-8"))
        if state.get("input_fingerprint") != record.get("source_fingerprint"):
            raise ValueError("STATE.json is not bound to the current intake fingerprint; rerun intake")
        evidence_refs = {"local": args.local_evidence, "independent": args.independent_evidence}
        if challenge.remotes:
            if not args.remote_evidence:
                raise ValueError("remote challenge verification requires --remote-evidence")
            evidence_refs["remote"] = args.remote_evidence
        return verify_and_record(
            solve_root, flag=args.flag, pattern=challenge.flag_pattern,
            has_remote=bool(challenge.remotes), local_reproduced=args.local,
            remote_reproduced=args.remote, independent_rerun=args.independent,
            reproduce_command=args.reproduce_command,
            evidence_refs=evidence_refs, require_recorded_evidence=True,
            remote_hosts=tuple(target.host for target in parse_remotes(challenge.remotes)),
            input_fingerprint=str(record["source_fingerprint"]),
        )
    raise ValueError(f"unsupported internal command: {args.command}")


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
