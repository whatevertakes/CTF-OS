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
    RescueError, _append_event_unlocked, _direct_argv, _load_json, _load_packet,
    _validate_rescue_metadata, canonical_json, record_rescue_command, rescue_lock,
)
from .rescue_backend import (
    RescueBackend, artifact_snapshot as backend_artifact_snapshot, record_telemetry,
)
from .rescue_hooks import handle_hook
from .rescue_mcp import StdioMCPServer, _session_data
from .rescue_sessions import RescueSessionManager
from .sandbox.network import ResolvedTarget, Target
from .sandbox.runtime import SandboxSpec, create as create_sandbox, execute
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
    inventory = commands.add_parser("inventory")
    inventory.add_argument("--refresh", action="store_true")
    session = commands.add_parser("session")
    session_commands = session.add_subparsers(dest="session_command", required=True)
    session_commands.add_parser("list")
    session_open = session_commands.add_parser("open")
    session_open.add_argument("--kind", choices=("shell", "gdb", "repl", "tcp"), required=True)
    session_open.add_argument("--name", required=True)
    session_open.add_argument("--target-index", type=int)
    session_open.add_argument("argv", nargs=argparse.REMAINDER)
    session_send = session_commands.add_parser("send")
    session_send.add_argument("--session-id", required=True)
    send_group = session_send.add_mutually_exclusive_group(required=True)
    send_group.add_argument("--text")
    send_group.add_argument("--hex")
    send_group.add_argument("--base64")
    send_group.add_argument("--file")
    session_read = session_commands.add_parser("read")
    session_read.add_argument("--session-id", required=True)
    session_read.add_argument("--cursor", type=int, required=True)
    session_read.add_argument("--max-bytes", type=int, default=32768)
    session_read.add_argument("--wait-seconds", type=float, default=0)
    for name in ("status", "close"):
        child = session_commands.add_parser(name)
        child.add_argument("--session-id", required=True)
    progress = commands.add_parser("progress")
    progress_commands = progress.add_subparsers(dest="progress_command", required=True)
    for name in ("record", "checkpoint"):
        child = progress_commands.add_parser(name)
        child.add_argument("--json", required=True, dest="payload_json")
    progress_commands.add_parser("show")
    task = commands.add_parser("task")
    task_commands = task.add_subparsers(dest="task_command", required=True)
    for name in ("create", "result"):
        child = task_commands.add_parser(name)
        child.add_argument("--json", required=True, dest="payload_json")
    task_show = task_commands.add_parser("show")
    task_show.add_argument("--task-id")
    knowledge = commands.add_parser("knowledge")
    knowledge_commands = knowledge.add_subparsers(dest="knowledge_command", required=True)
    hint = knowledge_commands.add_parser("hint-record")
    hint.add_argument("--json", required=True, dest="payload_json")
    knowledge_commands.add_parser("show")
    sandbox = commands.add_parser("sandbox")
    sandbox_commands = sandbox.add_subparsers(dest="sandbox_command", required=True)
    sandbox_commands.add_parser("status")
    sandbox_commands.add_parser("recover")
    hook = commands.add_parser("hook")
    hook.add_argument("hook_name")
    hook.add_argument("--json", dest="payload_json")
    commands.add_parser("mcp-serve")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "mcp-serve":
            run, rescue_root, metadata, packet = _context(args)
            backend = RescueBackend(run, rescue_root, metadata, packet)
            return StdioMCPServer(
                backend,
                lambda command, timeout, profile: _execute_rescue_command(
                    run, rescue_root, metadata, packet, command,
                    timeout=timeout, timeout_profile=profile,
                ),
            ).serve()
        result = dispatch(args)
    except Exception as exc:
        print(json.dumps({
            "ok": False, "error": str(exc), "error_type": type(exc).__name__,
        }, ensure_ascii=False, sort_keys=True))
        return 2
    if args.command == "hook":
        # Claude Code hook protocol consumes the hook decision at the top level.
        # CLI/MCP commands keep the ordinary typed envelope.
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
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
        return _execute_rescue_command(
            run, rescue_root, metadata, packet, command,
            timeout=args.timeout, timeout_profile=args.timeout_profile,
        )
    if args.command == "import-input":
        if args.all_bounded and args.path:
            raise RescueError("import-input accepts a path or --all-bounded, not both")
        if not args.all_bounded and not args.path:
            raise RescueError("import-input requires one safe relative path or --all-bounded")
        return _import_input(
            run, rescue_root, metadata,
            relative=args.path, all_bounded=bool(args.all_bounded),
        )
    backend = RescueBackend(run, rescue_root, metadata, packet)
    sessions = RescueSessionManager(run, rescue_root, metadata, packet)
    if args.command == "inventory":
        return backend.inventory(refresh=bool(args.refresh))
    if args.command == "session":
        if args.session_command == "list":
            return sessions.list()
        if args.session_command == "open":
            argv = list(args.argv)
            if argv and argv[0] == "--":
                argv.pop(0)
            if argv:
                _reject_model_command(_direct_argv(argv))
            return sessions.open(
                kind=args.kind, name=args.name, argv=argv,
                target_index=args.target_index,
            )
        if args.session_command == "send":
            values = {
                key: getattr(args, key) for key in ("text", "hex", "base64", "file")
            }
            data, encoding = _session_data(rescue_root, values)
            return sessions.send(args.session_id, data, encoding=encoding)
        if args.session_command == "read":
            return sessions.read(
                args.session_id, cursor=args.cursor, max_bytes=args.max_bytes,
                wait_seconds=args.wait_seconds,
            )
        if args.session_command == "status":
            return sessions.status(args.session_id)
        return sessions.close(args.session_id)
    if args.command == "progress":
        if args.progress_command == "show":
            return backend.progress_show()
        payload = _json_argument(args.payload_json, "progress payload")
        if args.progress_command == "checkpoint":
            payload.setdefault("event", "COMPACTION_CHECKPOINT")
        return backend.progress_record(
            payload, checkpoint=args.progress_command == "checkpoint",
        )
    if args.command == "task":
        if args.task_command == "show":
            return backend.task_show(args.task_id)
        payload = _json_argument(args.payload_json, "task payload")
        return (
            backend.task_create(payload) if args.task_command == "create"
            else backend.task_result(payload)
        )
    if args.command == "knowledge":
        if args.knowledge_command == "show":
            return backend.knowledge_show()
        return backend.knowledge_hint_record(
            _json_argument(args.payload_json, "knowledge hint payload")
        )
    if args.command == "hook":
        if args.payload_json is not None:
            payload = _json_argument(args.payload_json, "hook payload")
        else:
            try:
                payload = json.loads(sys.stdin.read())
            except json.JSONDecodeError as exc:
                raise RescueError("hook stdin is malformed JSON") from exc
            if not isinstance(payload, dict):
                raise RescueError("hook payload must be an object")
        return handle_hook(backend, args.hook_name, payload)
    if args.command == "sandbox":
        return _sandbox_control(backend, args.sandbox_command)
    raise RescueError(f"unsupported ctf-tool command: {args.command}")


def _execute_rescue_command(
    run: Path, rescue_root: Path, metadata: Mapping[str, Any],
    packet: Mapping[str, Any], command: Sequence[str], *, timeout: int | None,
    timeout_profile: str,
) -> dict[str, Any]:
    direct = _direct_argv(list(command))
    _reject_model_command(direct)
    selected_timeout = timeout if timeout is not None else timeout_seconds(timeout_profile)
    if not 1 <= selected_timeout <= 1800:
        raise RescueError("ctf-tool exec timeout must be between 1 and 1800 seconds")
    before_artifacts = _artifact_snapshot(rescue_root)
    result = execute(
        dict(metadata), direct, selected_timeout,
        session_id=rescue_root.name, session_role="external-rescue",
        timeout_profile=timeout_profile, retain_on_timeout=True,
    )
    result["container"] = metadata.get("name")
    result["sandbox_image_id"] = metadata.get("actual_image_id")
    result["sandbox_image_digests"] = list(metadata.get("image_repo_digests") or [])
    receipt = _record_command_receipt(
        run, rescue_root, packet, direct, result,
        before_artifacts=before_artifacts,
    )
    result["command_receipt"] = receipt
    record_telemetry(rescue_root, "command_executed", details={
        "command_receipt_id": receipt["command_receipt_id"],
        "repeated_command_warning": receipt["repeated_command_warning"],
        "authorized_network_observed": receipt["authorized_network_observed"],
    })
    if receipt["authorized_network_observed"]:
        telemetry = read_jsonl_strict(
            rescue_root / "RESCUE_TELEMETRY.jsonl", "rescue telemetry ledger",
        )
        if not any(row.get("event") == "first_remote_interaction" for row in telemetry):
            record_telemetry(rescue_root, "first_remote_interaction", details={
                "execution_receipt_id": receipt["command_receipt_id"], "source": "one-shot-command",
            })
    result["command_count"] = _command_count(rescue_root / "RESCUE_COMMANDS.jsonl")
    result["run_id"] = run.name
    result["rescue_attempt_id"] = rescue_root.name
    return result


def _json_argument(value: str, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise RescueError(f"{label} is malformed JSON") from exc
    if not isinstance(payload, dict):
        raise RescueError(f"{label} must be a JSON object")
    return payload


def _sandbox_control(backend: RescueBackend, command: str) -> dict[str, Any]:
    name = str(backend.metadata.get("name") or "")
    inspected = _run([backend.docker, "inspect", name], 30)
    if inspected.returncode:
        status = "MISSING"
        runtime = None
    else:
        try:
            runtime = json.loads(inspected.stdout)[0]
        except (json.JSONDecodeError, IndexError, TypeError) as exc:
            raise RescueError("Docker returned malformed rescue sandbox metadata") from exc
        running = runtime.get("State", {}).get("Running") is True
        status = "RUNNING" if running else "STOPPED"
    if command == "status":
        recoverable, reason = _recovery_check(backend)
        projected = status if status == "RUNNING" else ("RECOVERABLE" if recoverable else "RECOVERY_REQUIRED")
        if status == "MISSING":
            with rescue_lock(backend.run):
                _append_event_unlocked(
                    backend.run, backend.packet, "RESCUE_SANDBOX_MISSING",
                    details={"container": name, "recoverable": recoverable, "reason": reason},
                )
        return {**backend.identity, "container": name, "runtime_state": status, "status": projected, "reason": reason}
    recoverable, reason = _recovery_check(backend)
    if not recoverable:
        with rescue_lock(backend.run):
            _append_event_unlocked(
                backend.run, backend.packet, "RESCUE_SANDBOX_RECOVERY_FAILED",
                details={"container": name, "reason": reason},
            )
        raise RescueError("rescue sandbox recovery requires operator action: " + reason)
    with rescue_lock(backend.run):
        _append_event_unlocked(
            backend.run, backend.packet, "RESCUE_SANDBOX_CREATING",
            details={"container": name, "prior_runtime_state": status},
        )
    if status == "RUNNING":
        return {**backend.identity, "container": name, "status": "RUNNING", "idempotent": True}
    if status == "STOPPED":
        started = _run([backend.docker, "start", name], 60)
        if started.returncode:
            raise RescueError("stopped rescue sandbox could not restart: " + started.stderr.strip())
        metadata = backend.metadata
    else:
        spec = _spec_from_metadata(backend)
        metadata = create_sandbox(spec, docker=backend.docker)
    stale = RescueSessionManager(
        backend.run, backend.rescue_root, metadata, backend.packet, docker=backend.docker,
    ).mark_all_stale("sandbox recovered; interactive process identity no longer exists")
    with rescue_lock(backend.run):
        _append_event_unlocked(
            backend.run, backend.packet, "RESCUE_SANDBOX_RECOVERED",
            details={"container": name, "stale_persistent_sessions": stale},
        )
    return {**backend.identity, "container": name, "status": "RUNNING", "stale_persistent_sessions": stale, "idempotent": False}


def _recovery_check(backend: RescueBackend) -> tuple[bool, str]:
    identity = backend.packet["identity"]
    metadata = backend.metadata
    checks = {
        "run_id": metadata.get("run_id") == identity.get("run_id"),
        "rescue_id": metadata.get("rescue_attempt_id") == identity.get("rescue_attempt_id"),
        "input_fingerprint": metadata.get("input_fingerprint") == identity.get("input_fingerprint"),
        "target_revision": metadata.get("target_revision") == identity.get("target_revision"),
    }
    image = str(metadata.get("image") or "")
    image_result = _run([backend.docker, "image", "inspect", image, "--format", "{{.Id}}"], 30)
    expected_image = str(metadata.get("actual_image_id") or "")
    checks["image_identity"] = image_result.returncode == 0 and (
        not expected_image or image_result.stdout.strip() == expected_image
    )
    service_network = metadata.get("service_network")
    if service_network:
        network = _run([backend.docker, "network", "inspect", str(service_network)], 30)
        checks["managed_service_state"] = network.returncode == 0
    failed = [key for key, passed in checks.items() if not passed]
    return (not failed, "all immutable recovery checks match" if not failed else "mismatch: " + ", ".join(failed))


def _spec_from_metadata(backend: RescueBackend) -> SandboxSpec:
    metadata = backend.metadata
    targets: list[ResolvedTarget] = []
    for raw in list(metadata.get("authorized_targets") or []):
        if not isinstance(raw, Mapping):
            raise RescueError("recovery target metadata is malformed")
        target = Target(
            str(raw.get("declared") or f"{raw.get('protocol', 'tcp')}://{raw.get('host')}:{raw.get('port')}"),
            str(raw.get("host") or ""), int(raw.get("port") or 0),
            str(raw.get("protocol") or raw.get("transport") or "tcp"),
            organizer_declared=raw.get("organizer_declared") is True,
            callback=raw.get("callback") is True,
            transport_override=str(raw.get("transport")) if raw.get("transport") else None,
        )
        targets.append(ResolvedTarget(target, str(raw.get("ip") or raw.get("host") or "")))
    resources = metadata.get("resources") if isinstance(metadata.get("resources"), Mapping) else {}
    return SandboxSpec(
        contest_slug=str(metadata.get("contest_slug") or backend.packet["identity"]["contest"]),
        challenge_id=str(metadata.get("challenge_id") or backend.packet["identity"]["challenge_id"]),
        branch=backend.rescue_root.name,
        source=Path(str(metadata["source"])), branch_root=backend.rescue_root,
        input_fingerprint=str(metadata["input_fingerprint"]),
        target_revision=int(metadata["target_revision"]), targets=tuple(targets),
        image=str(metadata.get("image") or "ctf-os-sandbox:base"),
        resource_profile=str(metadata.get("resource_profile") or "standard"),
        memory=str(resources.get("memory")) if resources.get("memory") else None,
        cpus=float(resources.get("cpus")) if resources.get("cpus") else None,
        pids=int(resources.get("pids")) if resources.get("pids") else None,
        storage=str(resources.get("storage")) if resources.get("storage") else None,
        service_network=str(metadata.get("service_network")) if metadata.get("service_network") else None,
        local_endpoints=tuple(str(item) for item in metadata.get("local_endpoints") or []),
        session_id=backend.rescue_root.name, parent_session_id="sol-main",
        session_role="external-rescue", service_context=metadata.get("service_context") or {},
        category=str(metadata.get("category") or backend.packet["identity"].get("category") or "misc"),
        workspace_mode="bind", run_id=backend.run.name,
        rescue_attempt_id=backend.rescue_root.name, external_solver=True,
        solver_family="claude", session_kind="external-rescue",
        requested_lead_model=str(backend.packet["request"]["requested_lead_model"]),
    )


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
    rescue_root = metadata_path.parent
    if rescue_root.name != args.rescue_id:
        raise RescueError("fixed rescue ID does not match metadata path")
    metadata = _load_json(metadata_path, "rescue sandbox metadata")
    run = Path(str(metadata.get("source_run_path") or "")).resolve(strict=False)
    if run.name != args.run_id or run.parent.name != "runs":
        raise RescueError("fixed run ID does not match rescue metadata path")
    try:
        run.relative_to((repo_root / "output").resolve())
    except ValueError as exc:
        raise RescueError("fixed source run is outside repository output") from exc
    if Path(str(metadata.get("source_repo_path") or "")).resolve(strict=False) != repo_root:
        raise RescueError("fixed rescue source repository mismatch")
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
        "target_revision": packet["identity"]["target_revision"],
        "input_fingerprint": packet["identity"]["input_fingerprint"],
        "container_name": execution.get("container") or None,
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
        "target_revision": packet["identity"]["target_revision"],
        "input_fingerprint": packet["identity"]["input_fingerprint"],
        "container_name": execution.get("container") or None,
        "sandbox_image_id": execution.get("sandbox_image_id"),
        "sandbox_image_digests": list(execution.get("sandbox_image_digests") or []),
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
        "network_observation": list(execution.get("network_observation") or []),
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
    return backend_artifact_snapshot(rescue_root)


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
