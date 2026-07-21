"""Fixed-identity command wrapper used inside a manual Claude rescue directory."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Mapping, Sequence

from .rescue import (
    RescueError, _direct_argv, _load_json, _load_packet, _validate_rescue_metadata,
    canonical_json,
)
from .sandbox.runtime import execute
from .preflight import prepared_tree_fingerprint
from .timeouts import timeout_seconds
from .workspace import append_jsonl_fsync, challenge_workspace, read_jsonl_strict, utc_now


MAX_IMPORT_FILES = 200
MAX_IMPORT_BYTES = 256 * 1024 * 1024


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ctf-tool")
    parser.add_argument("--repo", required=True, help=argparse.SUPPRESS)
    parser.add_argument("--metadata", required=True, help=argparse.SUPPRESS)
    parser.add_argument("--run-id", required=True, help=argparse.SUPPRESS)
    parser.add_argument("--rescue-id", required=True, help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    execute_parser = commands.add_parser("exec")
    execute_parser.add_argument("--timeout", type=int)
    execute_parser.add_argument("--timeout-profile", default="quick_probe")
    execute_parser.add_argument("argv", nargs=argparse.REMAINDER)
    import_parser = commands.add_parser("import-input")
    import_parser.add_argument("path", nargs="?")
    import_parser.add_argument("--all-bounded", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        result = dispatch(args)
    except Exception as exc:
        print(json.dumps({
            "ok": False, "error": str(exc), "error_type": type(exc).__name__,
        }, ensure_ascii=False, sort_keys=True))
        return 2
    print(json.dumps({"ok": True, "result": result}, ensure_ascii=False, sort_keys=True))
    return 0


def dispatch(args: argparse.Namespace) -> dict[str, Any]:
    run, rescue_root, metadata, packet = _context(args)
    if args.command == "status":
        runtime = _inspect_runtime(str(metadata["name"]))
        labels = runtime.get("Config", {}).get("Labels", {})
        expected_labels = metadata.get("runtime_labels")
        if not isinstance(expected_labels, Mapping) or any(
            labels.get(key) != value for key, value in expected_labels.items()
        ):
            raise RescueError("rescue container labels do not match sandbox metadata")
        state = runtime.get("State") if isinstance(runtime.get("State"), Mapping) else {}
        if state.get("Running") is not True:
            raise RescueError("exact rescue sandbox container is not running")
        return {
            "run_id": run.name, "rescue_attempt_id": args.rescue_id,
            "container": metadata["name"], "container_state": "RUNNING",
            "input_fingerprint": packet["identity"]["input_fingerprint"],
            "target_revision": packet["identity"]["target_revision"],
            "prepared_fingerprint": _validate_prepared(metadata, run),
            "authorized_targets": metadata.get("authorized_targets", []),
            "local_managed_endpoints": metadata.get("local_endpoints", []),
            "service_context": metadata.get("service_context", {}),
        }
    if args.command == "exec":
        command = list(args.argv)
        if command and command[0] == "--":
            command.pop(0)
        direct = _direct_argv(command)
        _reject_model_command(direct)
        profile_timeout = timeout_seconds(args.timeout_profile)
        timeout = args.timeout if args.timeout is not None else profile_timeout
        if timeout < 1 or timeout > 1800:
            raise RescueError("ctf-tool exec timeout must be between 1 and 1800 seconds")
        result = execute(
            metadata, direct, timeout,
            session_id=args.rescue_id, session_role="external",
            timeout_profile=args.timeout_profile,
        )
        result["command_count"] = _command_count(rescue_root / "logs" / "commands.jsonl")
        result["run_id"] = run.name
        result["rescue_attempt_id"] = args.rescue_id
        return result
    if args.command == "import-input":
        if args.all_bounded and args.path:
            raise RescueError("import-input accepts a path or --all-bounded, not both")
        if not args.all_bounded and not args.path:
            raise RescueError("import-input requires one safe relative path or --all-bounded")
        return _import_input(
            run, rescue_root, metadata,
            relative=args.path, all_bounded=bool(args.all_bounded),
        )
    raise RescueError(f"unsupported ctf-tool command: {args.command}")


def _context(args: argparse.Namespace) -> tuple[Path, Path, dict[str, Any], dict[str, Any]]:
    metadata_path = Path(args.metadata).resolve(strict=False)
    if metadata_path.is_symlink() or not metadata_path.is_file() or metadata_path.name != "sandbox.json":
        raise RescueError("fixed rescue sandbox metadata is missing or unsafe")
    rescue_root = metadata_path.parent
    if rescue_root.name != args.rescue_id or rescue_root.parent.name != "rescue":
        raise RescueError("fixed rescue ID does not match metadata path")
    run = rescue_root.parents[1]
    if run.name != args.run_id or run.parent.name != "runs":
        raise RescueError("fixed run ID does not match rescue metadata path")
    metadata = _load_json(metadata_path, "rescue sandbox metadata")
    packet = _load_packet(rescue_root)
    _validate_rescue_metadata(metadata, packet, rescue_root)
    state = _load_json(run / "STATE.json", "run state")
    identity = packet["identity"]
    for field in ("run_id", "challenge_instance_id", "input_fingerprint", "target_revision"):
        if state.get(field) != identity.get(field):
            raise RescueError(f"current exact run {field} changed")
    revisions = read_jsonl_strict(
        challenge_workspace(run) / "target-revisions.jsonl", "target revision ledger",
    )
    if revisions and revisions[-1].get("target_revision") != identity.get("target_revision"):
        raise RescueError("current target revision changed after rescue preparation")
    _validate_prepared(metadata, run)
    return run, rescue_root, metadata, packet


def _validate_prepared(metadata: Mapping[str, Any], run: Path) -> str:
    source = Path(str(metadata.get("source") or ""))
    workspace = challenge_workspace(run)
    expected = workspace / "input"
    if source.resolve(strict=False) != expected.resolve(strict=False):
        raise RescueError("rescue prepared input path no longer matches this challenge")
    if source.is_symlink() or not source.is_dir():
        raise RescueError("rescue prepared input is missing or unsafe")
    preflight = _load_json(workspace / "CHALLENGE-PREFLIGHT.json", "challenge preflight")
    digest = prepared_tree_fingerprint(source)
    if preflight.get("prepared_fingerprint") != digest:
        raise RescueError("rescue prepared input fingerprint changed")
    if preflight.get("source_fingerprint") != metadata.get("input_fingerprint"):
        raise RescueError("rescue source fingerprint changed")
    return digest


def _inspect_runtime(name: str, docker: str = "docker") -> dict[str, Any]:
    if not name.startswith("ctf-os-"):
        raise RescueError("invalid rescue container name")
    result = _run([docker, "inspect", name], 30)
    if result.returncode:
        raise RescueError(f"cannot inspect exact rescue sandbox: {result.stderr.strip()}")
    try:
        payload = json.loads(result.stdout)
        runtime = payload[0]
    except (json.JSONDecodeError, IndexError, TypeError) as exc:
        raise RescueError("Docker returned malformed rescue sandbox metadata") from exc
    if not isinstance(runtime, dict):
        raise RescueError("Docker returned malformed rescue sandbox metadata")
    return runtime


def _import_input(
    run: Path,
    rescue_root: Path,
    metadata: Mapping[str, Any],
    *,
    relative: str | None,
    all_bounded: bool,
) -> dict[str, Any]:
    source_root = Path(str(metadata["source"]))
    profile = str(metadata.get("resource_profile") or "standard")
    if all_bounded and profile == "large-forensic":
        raise RescueError(
            "--all-bounded is disabled for large-forensic input; import individual safe paths"
        )
    files = _input_files(source_root, relative=relative, all_bounded=all_bounded)
    total = sum(path.stat().st_size for _name, path in files)
    if len(files) > MAX_IMPORT_FILES or total > MAX_IMPORT_BYTES:
        message = (
            "--all-bounded exceeds the standard import limit; import individual safe paths"
            if all_bounded else "selected input exceeds the bounded import limit"
        )
        raise RescueError(message)
    manifest = [
        {
            "path": name,
            "size": path.stat().st_size,
            "sha256": _sha256(path),
        }
        for name, path in files
    ]
    script = """\
import hashlib
import json
import pathlib
import shutil
import sys

rows = json.loads(sys.argv[1])
base = pathlib.Path('/challenge')
out = pathlib.Path('/work/input-view')
copied = []
for row in rows:
    source = base / row['path']
    destination = out / row['path']
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    hasher = hashlib.sha256()
    with destination.open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            hasher.update(block)
    digest = hasher.hexdigest()
    copied.append({'path': row['path'], 'size': destination.stat().st_size, 'sha256': digest})
print(json.dumps(copied, sort_keys=True, separators=(',', ':')))
"""
    receipt = execute(
        dict(metadata), ["python3", "-c", script, json.dumps(manifest, separators=(",", ":"))],
        300, session_id=str(metadata["rescue_attempt_id"]), session_role="external",
        timeout_profile="quick_probe",
    )
    if receipt.get("exit_code") != 0:
        raise RescueError("sandbox input import failed: " + str(receipt.get("stderr") or ""))
    try:
        copy_results = json.loads(str(receipt.get("stdout") or "").strip())
    except json.JSONDecodeError as exc:
        raise RescueError("sandbox input import did not return its copy hash receipt") from exc
    if copy_results != manifest:
        raise RescueError("sandbox input import copy hashes do not match prepared input")
    material = {
        "schema_version": 1, "event": "RESCUE_INPUT_IMPORTED",
        "run_id": run.name, "rescue_attempt_id": metadata["rescue_attempt_id"],
        "all_bounded": all_bounded, "files": manifest,
        "copy_results": copy_results, "bytes": total,
    }
    material["receipt_id"] = hashlib.sha256(canonical_json(material)).hexdigest()[:24]
    material["created_at"] = utc_now()
    append_jsonl_fsync(
        rescue_root / "logs" / "input-imports.jsonl", material,
        label="rescue input import ledger",
    )
    return {
        "run_id": run.name, "rescue_attempt_id": metadata["rescue_attempt_id"],
        "files": len(files), "bytes": total, "manifest": manifest,
        "destination": "/work/input-view", "receipt_id": material["receipt_id"],
        "command_count": _command_count(rescue_root / "logs" / "commands.jsonl"),
    }


def _input_files(
    source_root: Path,
    *,
    relative: str | None,
    all_bounded: bool,
) -> list[tuple[str, Path]]:
    if all_bounded:
        selected_root = source_root
    else:
        assert relative is not None
        rel = _safe_relative(relative)
        selected_root = source_root / rel
        try:
            selected_root.resolve(strict=False).relative_to(source_root.resolve())
        except ValueError as exc:
            raise RescueError("input path escapes prepared challenge input") from exc
        if not selected_root.exists():
            raise RescueError("selected input path does not exist")
    candidates = [selected_root] if selected_root.is_file() else sorted(selected_root.rglob("*"))
    rows: list[tuple[str, Path]] = []
    for path in candidates:
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise RescueError(f"input import rejects symlink: {path}")
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise RescueError(f"input import rejects special file: {path}")
        rel = path.relative_to(source_root).as_posix()
        rows.append((rel, path))
        if len(rows) > MAX_IMPORT_FILES:
            break
    return rows


def _safe_relative(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise RescueError("input import path must be a safe relative path")
    return path


def _reject_model_command(argv: Sequence[str]) -> None:
    programs = {
        "claude", "codex", "aider", "gemini", "copilot", "ollama", "llm",
    }
    executable = Path(argv[0]).name.casefold()
    if executable in programs:
        raise RescueError("ctf-tool cannot launch a model process")
    python_names = {"python", "python3", "python3.11", "python3.12", "uv"}
    if executable in python_names:
        lowered = [item.casefold() for item in argv[1:]]
        if "-m" in lowered:
            index = lowered.index("-m")
            module = lowered[index + 1] if index + 1 < len(lowered) else ""
            if module.split(".", 1)[0] in programs | {"anthropic", "openai"}:
                raise RescueError("ctf-tool cannot launch a model process or model API client")
    if executable in {"sh", "bash", "zsh", "dash"} and any(
        re.search(r"(?:^|[/\s])(?:claude|codex|aider|gemini|copilot|ollama)(?:\s|$)", item, re.I)
        for item in argv[1:]
    ):
        raise RescueError("ctf-tool cannot launch a model process through a shell")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _command_count(path: Path) -> int:
    return sum(
        row.get("event") == "sandbox_exec"
        for row in read_jsonl_strict(path, "rescue command receipt ledger")
    )


def _run(argv: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(argv), capture_output=True, text=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return subprocess.CompletedProcess(
            list(argv), 124, stdout, stderr + "\ncommand timed out",
        )
    except FileNotFoundError as exc:
        raise RescueError(f"required executable not found: {argv[0]}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
