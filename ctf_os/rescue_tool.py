"""Fixed-identity command wrapper used inside a manual Claude rescue directory."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any, Mapping, Sequence

from .rescue import (
    RescueError, _direct_argv, _load_json, _load_packet, _validate_rescue_metadata,
    canonical_json, record_rescue_command,
)
from .sandbox.runtime import execute
from .preflight import prepared_tree_fingerprint
from .timeouts import timeout_seconds
from .workspace import (
    append_jsonl_fsync, atomic_text, challenge_workspace, read_jsonl_strict, utc_now,
)


MAX_IMPORT_FILES = 200
MAX_IMPORT_BYTES = 256 * 1024 * 1024


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ctf-tool")
    parser.add_argument("--repo", required=True, help=argparse.SUPPRESS)
    parser.add_argument("--metadata", required=True, help=argparse.SUPPRESS)
    parser.add_argument("--run-id", required=True, help=argparse.SUPPRESS)
    parser.add_argument("--rescue-id", required=True, help=argparse.SUPPRESS)
    parser.add_argument("--packet-digest", required=True, help=argparse.SUPPRESS)
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
        commands = read_jsonl_strict(
            rescue_root / "RESCUE_COMMANDS.jsonl", "rescue command receipt ledger",
        )
        return {
            "run_id": run.name, "rescue_attempt_id": args.rescue_id,
            "container": metadata["name"], "container_state": "RUNNING",
            "input_fingerprint": packet["identity"]["input_fingerprint"],
            "target_revision": packet["identity"]["target_revision"],
            "prepared_fingerprint": _validate_prepared(metadata, run),
            "authorized_targets": metadata.get("authorized_targets", []),
            "local_managed_endpoints": metadata.get("local_endpoints", []),
            "service_context": metadata.get("service_context", {}),
            "packet_digest": packet["packet_digest"],
            "recent_command_receipts": commands[-10:],
            "repeated_command_warnings": sum(
                bool(row.get("repeated_command_warning")) for row in commands
            ),
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
        before_artifacts = _artifact_snapshot(rescue_root)
        result = execute(
            metadata, direct, timeout,
            session_id=args.rescue_id, session_role="external-rescue",
            timeout_profile=args.timeout_profile,
        )
        receipt = _record_command_receipt(
            run, rescue_root, packet, direct, result,
            before_artifacts=before_artifacts,
        )
        result["command_receipt"] = receipt
        result["command_count"] = _command_count(
            rescue_root / "RESCUE_COMMANDS.jsonl"
        )
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
    raw_repo_root = Path(args.repo)
    if raw_repo_root.is_symlink():
        raise RescueError("fixed rescue repository root is missing or unsafe")
    repo_root = raw_repo_root.resolve(strict=False)
    if not repo_root.is_dir():
        raise RescueError("fixed rescue repository root is missing or unsafe")
    raw_metadata_path = Path(args.metadata)
    if raw_metadata_path.is_symlink():
        raise RescueError("fixed rescue sandbox metadata is missing or unsafe")
    metadata_path = raw_metadata_path.resolve(strict=False)
    if not metadata_path.is_file() or metadata_path.name != "sandbox.json":
        raise RescueError("fixed rescue sandbox metadata is missing or unsafe")
    try:
        metadata_path.relative_to((repo_root / "output").resolve())
    except ValueError as exc:
        raise RescueError("fixed rescue metadata is outside repository output") from exc
    rescue_root = metadata_path.parent
    if rescue_root.name != args.rescue_id or rescue_root.parent.name != "rescue":
        raise RescueError("fixed rescue ID does not match metadata path")
    run = rescue_root.parents[1]
    if run.name != args.run_id or run.parent.name != "runs":
        raise RescueError("fixed run ID does not match rescue metadata path")
    metadata = _load_json(metadata_path, "rescue sandbox metadata")
    packet = _load_packet(rescue_root)
    if packet.get("packet_digest") != args.packet_digest:
        raise RescueError("fixed packet digest does not match rescue packet")
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
        300, session_id=str(metadata["rescue_attempt_id"]), session_role="external-rescue",
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
        "command_count": _command_count(rescue_root / "RESCUE_COMMANDS.jsonl"),
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
    if executable in {"sh", "bash", "zsh", "dash"} and any(
        item in {"-c", "-lc", "-ic"} for item in argv[1:]
    ):
        raise RescueError("ctf-tool exec requires direct argv and rejects shell strings")
    python_names = {"python", "python3", "python3.11", "python3.12", "uv"}
    if executable in python_names:
        lowered = [item.casefold() for item in argv[1:]]
        if "-m" in lowered:
            index = lowered.index("-m")
            module = lowered[index + 1] if index + 1 < len(lowered) else ""
            if module.split(".", 1)[0] in programs | {"anthropic", "openai"}:
                raise RescueError("ctf-tool cannot launch a model process or model API client")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _record_command_receipt(
    run: Path,
    rescue_root: Path,
    packet: Mapping[str, Any],
    argv: Sequence[str],
    execution: Mapping[str, Any],
    *,
    before_artifacts: Mapping[str, Any],
) -> dict[str, Any]:
    created_at = utc_now()
    stdout = str(execution.get("stdout") or "")
    stderr = str(execution.get("stderr") or "")
    command_digest = hashlib.sha256(canonical_json(list(argv))).hexdigest()
    command_family = _command_family(argv)
    command_family_digest = hashlib.sha256(
        canonical_json(command_family)
    ).hexdigest()
    stdout_digest = hashlib.sha256(stdout.encode("utf-8")).hexdigest()
    stderr_digest = hashlib.sha256(stderr.encode("utf-8")).hexdigest()
    after_artifacts = _artifact_snapshot(rescue_root)
    target_indices = list(execution.get("authorized_network_target_indices") or [])
    material = {
        "run_id": run.name,
        "rescue_attempt_id": rescue_root.name,
        "packet_digest": packet["packet_digest"],
        "command_digest": command_digest,
        "stdout_digest": stdout_digest,
        "stderr_digest": stderr_digest,
        "exit_code": execution.get("exit_code"),
        "timed_out": execution.get("timed_out") is True,
        "artifact_snapshot": {"before": before_artifacts, "after": after_artifacts},
        "authorized_network_target_indices": target_indices,
        "created_at": created_at,
    }
    receipt_id = hashlib.sha256(canonical_json(material)).hexdigest()[:24]
    evidence_path = rescue_root / "evidence" / "commands" / f"{receipt_id}.txt"
    if evidence_path.is_symlink():
        raise RescueError("command output evidence path must not be a symlink")
    evidence_text = (
        "CTF-OS rescue command receipt\n"
        f"receipt_id: {receipt_id}\n"
        f"argv_json: {json.dumps(list(argv), ensure_ascii=False, separators=(',', ':'))}\n"
        f"exit_code: {execution.get('exit_code')}\n"
        f"timed_out: {execution.get('timed_out') is True}\n"
        "\n[stdout]\n" + stdout + "\n[stderr]\n" + stderr
    )
    atomic_text(evidence_path, evidence_text)
    evidence_path.chmod(0o600)
    prior = read_jsonl_strict(
        rescue_root / "RESCUE_COMMANDS.jsonl", "rescue command receipt ledger",
    )
    repeated = any(
        row.get("command_family_digest") == command_family_digest
        and row.get("stdout_digest") == stdout_digest
        and row.get("stderr_digest") == stderr_digest
        and row.get("artifact_snapshot", {}).get("after") == after_artifacts
        for row in prior
        if isinstance(row.get("artifact_snapshot"), Mapping)
    )
    receipt = {
        "schema_version": 1,
        "command_receipt_id": receipt_id,
        "run_id": run.name,
        "rescue_attempt_id": rescue_root.name,
        "packet_digest": packet["packet_digest"],
        "argv": list(argv),
        "command_digest": command_digest,
        "command_family": command_family,
        "command_family_digest": command_family_digest,
        "exit_code": execution.get("exit_code"),
        "timed_out": execution.get("timed_out") is True,
        "stdout_digest": stdout_digest,
        "stderr_digest": stderr_digest,
        "output_excerpt": _bounded_excerpt(stdout, stderr),
        "authorized_network_observed": execution.get("authorized_network_observed") is True,
        "authorized_network_target_indices": target_indices,
        "authorized_targets": list(execution.get("authorized_targets") or []),
        "artifact_snapshot": {"before": before_artifacts, "after": after_artifacts},
        "evidence_path": evidence_path.relative_to(rescue_root).as_posix(),
        "evidence_digest": _sha256(evidence_path),
        "repeated_command_warning": repeated,
        "created_at": created_at,
    }
    append_jsonl_fsync(
        rescue_root / "RESCUE_COMMANDS.jsonl", receipt,
        label="rescue command receipt ledger",
    )
    record_rescue_command(run, rescue_root.name, receipt)
    return receipt


def _artifact_snapshot(rescue_root: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    total = 0
    unsafe = 0
    for base_name in ("work", "artifacts"):
        base = rescue_root / base_name
        for path in sorted(base.rglob("*")):
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                continue
            if not stat.S_ISREG(mode) or stat.S_ISLNK(mode):
                unsafe += 1
                continue
            size = path.stat().st_size
            total += size
            if len(rows) < 200:
                rows.append({
                    "path": path.relative_to(rescue_root).as_posix(),
                    "size": size, "sha256": _sha256(path),
                })
    digest = hashlib.sha256(canonical_json(rows)).hexdigest()
    return {
        "file_count": len(rows), "total_bytes": total,
        "manifest_digest": digest, "unsafe_entry_count": unsafe,
    }


def _command_family(argv: Sequence[str]) -> list[str]:
    executable = Path(argv[0]).name.casefold()
    family = [executable]
    if executable in {"python", "python3", "python3.11", "python3.12", "pypy3"}:
        if len(argv) > 2 and argv[1] == "-m":
            family.extend(["-m", argv[2]])
        elif len(argv) > 1 and not argv[1].startswith("-"):
            family.append(Path(argv[1]).as_posix())
    elif executable in {"bash", "sh", "zsh", "dash", "node", "ruby", "perl"}:
        if len(argv) > 1 and not argv[1].startswith("-"):
            family.append(Path(argv[1]).as_posix())
    return family


def _bounded_excerpt(stdout: str, stderr: str, maximum: int = 8000) -> str:
    combined = ("stdout:\n" + stdout + "\nstderr:\n" + stderr).replace("\x00", "\\0")
    data = combined.encode("utf-8")
    if len(data) <= maximum:
        return combined
    return data[: maximum - 3].decode("utf-8", errors="ignore") + "..."


def _command_count(path: Path) -> int:
    return len(read_jsonl_strict(path, "rescue command receipt ledger"))


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
