"""Shared typed backend for Claude rescue CLI and MCP surfaces.

The backend is deliberately model-agnostic.  It validates one immutable rescue
identity, writes append-only receipts, and never launches a model or submits a
flag.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
from typing import Any

import yaml

from .rescue import RescueError, canonical_json
from .workspace import append_jsonl_fsync, atomic_json, read_jsonl_strict, utc_now


PROGRESS_EVENTS = frozenset({
    "HYPOTHESIS_OPENED", "HYPOTHESIS_KILLED", "HYPOTHESIS_PROMOTED",
    "BLOCKER_UPDATED", "EXPERIMENT_PLANNED", "EXPERIMENT_OBSERVED",
    "EXPERIMENT_DECIDED", "WORKING_ARTIFACT_READY", "REMOTE_ATTEMPTED",
    "FLAG_OBSERVED", "COMPACTION_CHECKPOINT", "NEXT_ACTION_SET",
})
TASK_EVENTS = frozenset({
    "TASK_CREATED", "TASK_STARTED", "TASK_RESULT_RECORDED", "TASK_ADOPTED",
    "TASK_REFUTED", "TASK_CLOSED",
})
TASK_ROLES = frozenset({"recon", "evidence", "exploit-builder", "alternate-solver"})
TASK_RESULTS = frozenset({"SUPPORTED", "REFUTED", "PARTIAL", "INCONCLUSIVE", "ERROR"})
TOOL_CLASSES = frozenset({"REQUIRED", "RECOMMENDED", "OPTIONAL", "UNAVAILABLE"})
MAX_LEDGER_BYTES = 8 * 1024 * 1024
MAX_TEXT = 16_000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def artifact_snapshot(rescue_root: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    total = 0
    unsafe = 0
    for base_name in ("work", "artifacts"):
        base = rescue_root / base_name
        if not base.is_dir() or base.is_symlink():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_dir():
                continue
            if path.is_symlink() or not path.is_file():
                unsafe += 1
                continue
            size = path.stat().st_size
            total += size
            if len(rows) < 200:
                rows.append({
                    "path": path.relative_to(rescue_root).as_posix(),
                    "size": size, "sha256": sha256_file(path),
                })
    return {
        "file_count": len(rows), "total_bytes": total,
        "manifest_digest": hashlib.sha256(canonical_json(rows)).hexdigest(),
        "unsafe_entry_count": unsafe, "files": rows,
    }


def record_telemetry(
    rescue_root: Path, event: str, *, details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    packet = _packet(rescue_root)
    row = {
        "schema_version": 1, "event": _short_text(event, "telemetry event", 120),
        **_identity(rescue_root, packet), "details": _bounded_mapping(details or {}),
        "recorded_at": utc_now(),
    }
    row["telemetry_id"] = hashlib.sha256(canonical_json(row)).hexdigest()[:24]
    append_jsonl_fsync(
        rescue_root / "RESCUE_TELEMETRY.jsonl", row,
        label="rescue telemetry ledger",
    )
    return row


class RescueBackend:
    """One fixed-identity backend shared by CLI, hooks, and MCP."""

    def __init__(
        self, run: Path, rescue_root: Path, metadata: Mapping[str, Any],
        packet: Mapping[str, Any], *, docker: str = "docker",
    ) -> None:
        self.run = run.resolve(strict=False)
        self.rescue_root = rescue_root.resolve(strict=False)
        self.metadata = dict(metadata)
        self.packet = dict(packet)
        self.docker = docker
        identity = self.packet.get("identity")
        if not isinstance(identity, Mapping):
            raise RescueError("rescue packet identity is malformed")
        if (
            identity.get("run_id") != self.run.name
            or identity.get("rescue_attempt_id") != self.rescue_root.name
            or self.packet.get("packet_digest") != self.metadata.get("packet_digest", self.packet.get("packet_digest"))
        ):
            raise RescueError("rescue backend fixed identity mismatch")

    @property
    def identity(self) -> dict[str, Any]:
        return _identity(self.rescue_root, self.packet, self.metadata)

    def progress_record(self, payload: Mapping[str, Any], *, checkpoint: bool = False) -> dict[str, Any]:
        material = dict(payload)
        event = str(material.get("event") or ("COMPACTION_CHECKPOINT" if checkpoint else ""))
        if event not in PROGRESS_EVENTS:
            raise RescueError("progress event is unsupported")
        material["event"] = event
        self._validate_progress(event, material)
        current = self.progress_show(write_projection=False)
        active = {row["hypothesis_id"]: row for row in current["active_hypotheses"]}
        hypothesis_id = str(material.get("hypothesis_id") or "")
        if event == "HYPOTHESIS_OPENED":
            if not _ID.fullmatch(hypothesis_id):
                raise RescueError("HYPOTHESIS_OPENED requires a valid hypothesis_id")
            if hypothesis_id not in active and len(active) >= 2:
                raise RescueError("active hypothesis limit is 2")
        row = self._append("RESCUE_PROGRESS.jsonl", event, material, "progress")
        state = self.progress_show()
        self._telemetry_for_progress(event, row)
        return {"receipt": row, "live_state": state}

    def progress_show(self, *, write_projection: bool = True) -> dict[str, Any]:
        rows = self._read("RESCUE_PROGRESS.jsonl", "rescue progress ledger")
        active: dict[str, dict[str, Any]] = {}
        state: dict[str, Any] = {
            "schema_version": 1, **self.identity, "current_blocker": None,
            "active_hypotheses": [], "last_decisive_experiment": None,
            "latest_working_artifact": None, "next_action": None,
            "last_progress_receipt_id": None, "event_count": len(rows),
        }
        for row in rows:
            event = row.get("event")
            payload = row.get("payload") if isinstance(row.get("payload"), Mapping) else {}
            hypothesis_id = str(payload.get("hypothesis_id") or "")
            if event == "HYPOTHESIS_OPENED":
                active[hypothesis_id] = dict(payload)
            elif event == "HYPOTHESIS_KILLED":
                active.pop(hypothesis_id, None)
            elif event == "HYPOTHESIS_PROMOTED" and hypothesis_id in active:
                active[hypothesis_id]["status"] = "PROMOTED"
            elif event == "BLOCKER_UPDATED":
                state["current_blocker"] = payload.get("blocker")
            elif event in {"EXPERIMENT_OBSERVED", "EXPERIMENT_DECIDED"}:
                state["last_decisive_experiment"] = dict(payload)
            elif event == "WORKING_ARTIFACT_READY":
                state["latest_working_artifact"] = dict(payload)
            elif event == "NEXT_ACTION_SET":
                state["next_action"] = payload.get("next_action")
            state["last_progress_receipt_id"] = row.get("receipt_id")
        state["active_hypotheses"] = list(active.values())[:2]
        state["updated_at"] = rows[-1].get("created_at") if rows else None
        if write_projection:
            atomic_json(self.rescue_root / "RESCUE_LIVE_STATE.json", state)
        return state

    def task_create(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        required = {
            "task_id", "role", "objective", "success_condition", "kill_condition",
            "maximum_turns", "expected_artifacts", "allowed_hypothesis_family",
            "forbidden_repeated_paths",
        }
        if set(payload) != required:
            raise RescueError("task schema fields do not match the typed contract")
        task_id = str(payload.get("task_id") or "")
        if not _ID.fullmatch(task_id) or payload.get("role") not in TASK_ROLES:
            raise RescueError("task ID or role is invalid")
        turns = payload.get("maximum_turns")
        if not isinstance(turns, int) or isinstance(turns, bool) or not 1 <= turns <= 20:
            raise RescueError("task maximum_turns must be 1 through 20")
        if not all(_nonempty(payload.get(name)) for name in ("objective", "success_condition", "kill_condition")):
            raise RescueError("task objective and success/kill conditions are required")
        existing = self._task_rows(task_id)
        if any(row.get("event") == "TASK_CREATED" for row in existing):
            raise RescueError("task_id already exists")
        return self._append("RESCUE_TASKS.jsonl", "TASK_CREATED", dict(payload), "task")

    def task_result(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        required = {
            "task_id", "status", "summary", "command_receipt_ids",
            "session_observation_receipt_ids", "artifacts", "evidence",
            "recommended_next_action",
        }
        if set(payload) != required:
            raise RescueError("task result fields do not match the typed contract")
        task_id = str(payload.get("task_id") or "")
        if payload.get("status") not in TASK_RESULTS or not any(
            row.get("event") == "TASK_CREATED" for row in self._task_rows(task_id)
        ):
            raise RescueError("task result references an unknown task or status")
        command_ids = _string_list(payload.get("command_receipt_ids"), "command receipt IDs")
        session_ids = _string_list(payload.get("session_observation_receipt_ids"), "session observation receipt IDs")
        artifacts = payload.get("artifacts")
        if not isinstance(artifacts, list):
            raise RescueError("task result artifacts must be an array")
        for receipt_id in command_ids:
            self.execution_receipt(receipt_id, expected="command")
        for receipt_id in session_ids:
            self.execution_receipt(receipt_id, expected="session")
        for artifact in artifacts:
            if not isinstance(artifact, Mapping):
                raise RescueError("task result artifact rows must be objects")
            path = self._safe_file(str(artifact.get("path") or ""), {"work", "artifacts"})
            digest = str(artifact.get("sha256") or "")
            if not _SHA256.fullmatch(digest) or sha256_file(path) != digest:
                raise RescueError("task result artifact digest mismatch")
        if payload.get("status") == "SUPPORTED" and not (command_ids or session_ids or artifacts):
            raise RescueError("SUPPORTED task result requires a receipt or hashed artifact")
        return self._append("RESCUE_TASKS.jsonl", "TASK_RESULT_RECORDED", dict(payload), "task")

    def task_show(self, task_id: str | None = None) -> dict[str, Any]:
        rows = self._read("RESCUE_TASKS.jsonl", "rescue task ledger")
        if task_id is not None:
            if not _ID.fullmatch(task_id):
                raise RescueError("task ID is invalid")
            rows = [row for row in rows if row.get("payload", {}).get("task_id") == task_id]
        return {**self.identity, "tasks": rows[-100:], "truncated": len(rows) > 100}

    def knowledge_hint_record(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        required = {
            "query", "source_receipt_ids", "atomic_attack_facts",
            "applicability_conditions", "current_challenge_matches",
            "proposed_attack_path", "decisive_experiment", "status",
        }
        if set(payload) != required or payload.get("status") != "CANDIDATE":
            raise RescueError("knowledge hints must use the exact CANDIDATE schema")
        sources = _string_list(payload.get("source_receipt_ids"), "knowledge source receipt IDs")
        known = {row.get("receipt_id") for row in self._read("KNOWLEDGE_SOURCES.jsonl", "knowledge source ledger")}
        if not sources or any(source not in known for source in sources):
            raise RescueError("knowledge hint requires existing source receipt IDs")
        experiment = payload.get("decisive_experiment")
        if not isinstance(experiment, Mapping) or not _nonempty(experiment.get("success_condition")) or not _nonempty(experiment.get("kill_condition")):
            raise RescueError("knowledge hint requires a decisive experiment with success and kill conditions")
        return self._append("KNOWLEDGE_HINTS.jsonl", "KNOWLEDGE_HINT_RECORDED", dict(payload), "knowledge_hint")

    def knowledge_show(self) -> dict[str, Any]:
        sources = self._read("KNOWLEDGE_SOURCES.jsonl", "knowledge source ledger")
        hints = self._read("KNOWLEDGE_HINTS.jsonl", "knowledge hint ledger")
        return {
            **self.identity, "sources": sources[-50:], "hints": hints[-50:],
            "sources_truncated": len(sources) > 50, "hints_truncated": len(hints) > 50,
        }

    def knowledge_source_record(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        bounded = {
            "query": _bounded_text(payload.get("query")),
            "tool": _bounded_text(payload.get("tool"), 256),
            "source_title": _bounded_text(payload.get("source_title"), 1000),
            "source_url_or_resource_id": _bounded_text(payload.get("source_url_or_resource_id"), 4000),
            "retrieved_at": str(payload.get("retrieved_at") or utc_now()),
            "bounded_excerpt": _bounded_text(payload.get("bounded_excerpt"), 8000),
            "content_digest": str(payload.get("content_digest") or ""),
            "session_id": _bounded_text(payload.get("session_id"), 256),
            "subagent_id": _bounded_text(payload.get("subagent_id"), 256),
        }
        if not _SHA256.fullmatch(bounded["content_digest"]):
            bounded["content_digest"] = hashlib.sha256(
                bounded["bounded_excerpt"].encode("utf-8")
            ).hexdigest()
        return self._append("KNOWLEDGE_SOURCES.jsonl", "KNOWLEDGE_SOURCE_RETRIEVED", bounded, "knowledge_source")

    def inventory(self, *, refresh: bool = False) -> dict[str, Any]:
        receipt_path = self.rescue_root / "TOOLCHAIN_RECEIPT.json"
        if receipt_path.is_file() and not refresh:
            return json.loads(receipt_path.read_text(encoding="utf-8"))
        category = str(self.packet.get("identity", {}).get("category") or "misc").casefold()
        contract = _toolchain_contract(category)
        runtime = self._docker_inspect()
        image_id = str(runtime.get("Image") or self.metadata.get("actual_image_id") or "")
        image_name = str(self.metadata.get("image") or runtime.get("Config", {}).get("Image") or "")
        script = _inventory_script(sorted(contract["tools"]))
        result = subprocess.run(
            [self.docker, "exec", "--user", "1001:1001", str(self.metadata["name"]), "python3", "-c", script],
            capture_output=True, text=True, timeout=120, check=False,
        )
        if result.returncode:
            raise RescueError("toolchain inventory failed: " + result.stderr.strip()[:2000])
        try:
            observed = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RescueError("toolchain inventory returned malformed JSON") from exc
        tools: list[dict[str, Any]] = []
        missing: list[str] = []
        for name, classification in contract["tools"].items():
            item = observed.get("tools", {}).get(name, {})
            available = bool(item.get("path"))
            tools.append({
                "name": name, "classification": classification,
                "available": available, "path": item.get("path"),
                "version": _bounded_text(item.get("version"), 1000),
            })
            if classification == "REQUIRED" and not available:
                missing.append(name)
        receipt = {
            "schema_version": 1, **self.identity, "selected_image_tag": image_name,
            "actual_image_id": image_id,
            "repo_digests": list(self.metadata.get("image_repo_digests") or []),
            "os": observed.get("os"), "architecture": observed.get("architecture"),
            "cpu_features": observed.get("cpu_features"),
            "gpu_availability": observed.get("gpu_availability"),
            "python_version": observed.get("python_version"),
            "important_python_packages": observed.get("python_packages"),
            "installed_tools": tools,
            "service_endpoints": list(self.metadata.get("local_endpoints") or self.metadata.get("authorized_targets") or []),
            "persistent_session_backend": {
                "pty": "tmux" if any(row["name"] == "tmux" and row["available"] for row in tools) else "UNAVAILABLE",
                "tcp": "python-socket-relay", "websocket": "UNAVAILABLE",
            },
            "required_missing": missing, "contract": category,
            "refreshed_at": utc_now(),
        }
        atomic_json(receipt_path, receipt)
        if missing:
            raise RescueError(
                f"{category} rescue image is missing REQUIRED tools: {', '.join(missing)}; rebuild the category image"
            )
        return receipt

    def execution_receipt(self, receipt_id: str, *, expected: str | None = None) -> dict[str, Any]:
        if not _ID.fullmatch(receipt_id):
            raise RescueError("execution receipt ID is invalid")
        sources = []
        if expected in {None, "command"}:
            sources.append(("RESCUE_COMMANDS.jsonl", "command_receipt_id", "command"))
        if expected in {None, "session"}:
            sources.append(("RESCUE_SESSIONS.jsonl", "observation_receipt_id", "session"))
        matches: list[dict[str, Any]] = []
        for filename, field, kind in sources:
            for row in self._read(filename, f"{kind} receipt ledger"):
                if row.get(field) == receipt_id:
                    matches.append({**row, "execution_receipt_type": kind})
        if len(matches) != 1:
            raise RescueError("execution receipt is missing or ambiguous")
        return matches[0]

    def _append(
        self, filename: str, event: str, payload: Mapping[str, Any], namespace: str,
    ) -> dict[str, Any]:
        path = self.rescue_root / filename
        if path.exists() and path.stat().st_size > MAX_LEDGER_BYTES:
            raise RescueError(f"{filename} reached its bounded ledger limit")
        row = {
            "schema_version": 1, "event": event, **self.identity,
            "payload": _bounded_mapping(payload), "created_at": utc_now(),
        }
        row["receipt_id"] = hashlib.sha256(
            namespace.encode() + b"\0" + canonical_json(row)
        ).hexdigest()[:24]
        append_jsonl_fsync(path, row, label=filename)
        return row

    def _read(self, filename: str, label: str) -> list[dict[str, Any]]:
        path = self.rescue_root / filename
        if not path.exists():
            return []
        if path.is_symlink() or path.stat().st_size > MAX_LEDGER_BYTES:
            raise RescueError(f"{label} is unsafe or exceeds its bounded size")
        rows = read_jsonl_strict(path, label)
        required_identity = {
            key: self.identity[key]
            for key in ("run_id", "rescue_attempt_id", "packet_digest")
        }
        for row in rows:
            if any(row.get(key) != value for key, value in required_identity.items()):
                raise RescueError(f"{label} contains another rescue identity")
        return rows

    def _validate_progress(self, event: str, payload: Mapping[str, Any]) -> None:
        if event == "EXPERIMENT_PLANNED" and not all(
            _nonempty(payload.get(name)) for name in ("success_condition", "kill_condition")
        ):
            raise RescueError("planned experiment requires success and kill conditions")
        if event in {"EXPERIMENT_OBSERVED", "FLAG_OBSERVED"}:
            receipt_id = str(payload.get("execution_receipt_id") or payload.get("command_receipt_id") or payload.get("session_observation_receipt_id") or "")
            if not receipt_id:
                raise RescueError(f"{event} requires a command or session observation receipt ID")
            self.execution_receipt(receipt_id)
        if event == "WORKING_ARTIFACT_READY":
            path = self._safe_file(str(payload.get("artifact") or ""), {"work", "artifacts"})
            digest = str(payload.get("artifact_sha256") or "")
            if not _SHA256.fullmatch(digest) or sha256_file(path) != digest:
                raise RescueError("WORKING_ARTIFACT_READY artifact digest mismatch")

    def _safe_file(self, value: str, allowed: set[str]) -> Path:
        relative = Path(value)
        if relative.is_absolute() or not relative.parts or relative.parts[0] not in allowed or any(part in {"", ".", ".."} for part in relative.parts):
            raise RescueError("rescue file path is unsafe")
        path = self.rescue_root.joinpath(relative)
        if path.is_symlink() or not path.is_file():
            raise RescueError("rescue file is missing or unsafe")
        try:
            path.resolve().relative_to(self.rescue_root)
        except ValueError as exc:
            raise RescueError("rescue file escapes the exact workspace") from exc
        return path

    def _task_rows(self, task_id: str) -> list[dict[str, Any]]:
        return [
            row for row in self._read("RESCUE_TASKS.jsonl", "rescue task ledger")
            if row.get("payload", {}).get("task_id") == task_id
        ]

    def _docker_inspect(self) -> dict[str, Any]:
        result = subprocess.run(
            [self.docker, "inspect", str(self.metadata.get("name") or "")],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if result.returncode:
            raise RescueError("exact rescue sandbox is missing: " + result.stderr.strip()[:1000])
        try:
            value = json.loads(result.stdout)[0]
        except (json.JSONDecodeError, IndexError, TypeError) as exc:
            raise RescueError("Docker returned malformed rescue sandbox metadata") from exc
        labels = value.get("Config", {}).get("Labels", {})
        expected = self.metadata.get("runtime_labels") or self.metadata.get("labels") or {}
        if any(labels.get(key) != val for key, val in expected.items()):
            raise RescueError("runtime container labels do not match the exact rescue")
        if not value.get("State", {}).get("Running"):
            raise RescueError("exact rescue sandbox is not running")
        return value

    def _telemetry_for_progress(self, event: str, row: Mapping[str, Any]) -> None:
        mapping = {
            "EXPERIMENT_DECIDED": "first_decisive_experiment",
            "WORKING_ARTIFACT_READY": "first_working_artifact",
            "REMOTE_ATTEMPTED": "first_remote_interaction",
            "FLAG_OBSERVED": "flag_observed",
        }
        if event in mapping:
            prior = read_jsonl_strict(self.rescue_root / "RESCUE_TELEMETRY.jsonl", "rescue telemetry ledger") if (self.rescue_root / "RESCUE_TELEMETRY.jsonl").exists() else []
            if not any(item.get("event") == mapping[event] for item in prior):
                record_telemetry(self.rescue_root, mapping[event], details={"progress_receipt_id": row.get("receipt_id")})


def _identity(
    rescue_root: Path, packet: Mapping[str, Any], metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    identity = packet.get("identity")
    if not isinstance(identity, Mapping):
        raise RescueError("rescue packet identity is malformed")
    meta = metadata or {}
    return {
        "run_id": identity.get("run_id"),
        "rescue_attempt_id": identity.get("rescue_attempt_id"),
        "packet_digest": packet.get("packet_digest"),
        "target_revision": identity.get("target_revision"),
        "input_fingerprint": identity.get("input_fingerprint"),
        "container_name": meta.get("name"),
        "sandbox_image_id": meta.get("actual_image_id"),
        "sandbox_image_digests": list(meta.get("image_repo_digests") or []),
    }


def _packet(rescue_root: Path) -> dict[str, Any]:
    path = rescue_root / "RESCUE_PACKET.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RescueError("rescue packet is missing or malformed") from exc
    if not isinstance(value, dict):
        raise RescueError("rescue packet must be an object")
    return value


def _toolchain_contract(category: str) -> dict[str, Any]:
    resources = Path(__file__).resolve().parent / "resources" / "claude-rescue" / "toolchains"
    path = resources / f"{category}.yaml"
    if not path.is_file():
        path = resources / "misc.yaml"
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RescueError("toolchain contract is missing or malformed") from exc
    tools = value.get("tools") if isinstance(value, Mapping) else None
    if not isinstance(tools, Mapping) or any(v not in TOOL_CLASSES for v in tools.values()):
        raise RescueError("toolchain contract classifications are malformed")
    return {"tools": dict(tools)}


def _inventory_script(tools: Sequence[str]) -> str:
    return """
import json, os, platform, shutil, subprocess, sys
tools = json.loads(sys.argv[1]) if len(sys.argv) > 1 else %s
def version(path):
    for args in ([path, '--version'], [path, '-version'], [path, '-V']):
        try:
            p = subprocess.run(args, capture_output=True, text=True, timeout=5)
            text = (p.stdout or p.stderr).strip()
            if text: return text[:1000]
        except Exception: pass
    return None
rows = {}
for name in tools:
    path = shutil.which(name)
    rows[name] = {'path': path, 'version': version(path) if path else None}
packages = {}
for name in ['requests','pwntools','pwn','z3','Crypto','sympy','numpy','scapy']:
    try:
        mod = __import__(name)
        packages[name] = str(getattr(mod, '__version__', 'installed'))
    except Exception: packages[name] = None
os_release = {}
try:
    for line in open('/etc/os-release'):
        if '=' in line:
            k,v=line.rstrip().split('=',1); os_release[k]=v.strip('"')
except OSError: pass
cpu_features = []
try:
    for line in open('/proc/cpuinfo'):
        if line.startswith(('flags', 'Features')):
            cpu_features = line.split(':',1)[1].split(); break
except OSError: pass
print(json.dumps({'os': os_release, 'architecture': platform.machine(),
 'cpu_features': cpu_features[:256], 'gpu_availability': os.environ.get('CTF_OS_GPU_AVAILABLE') == '1',
 'python_version': sys.version, 'python_packages': packages, 'tools': rows}, sort_keys=True))
""" % json.dumps(list(tools))


def _bounded_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    encoded = canonical_json(dict(value))
    if len(encoded) > 64 * 1024:
        raise RescueError("typed rescue payload exceeds 64 KiB")
    return json.loads(encoded)


def _bounded_text(value: object, maximum: int = MAX_TEXT) -> str:
    text = str(value or "").replace("\x00", "\\0")
    data = text.encode("utf-8")
    if len(data) <= maximum:
        return text
    return data[: maximum - 3].decode("utf-8", errors="ignore") + "..."


def _short_text(value: object, field: str, maximum: int) -> str:
    text = str(value or "").strip()
    if not text or any(char in text for char in "\x00\r\n") or len(text.encode()) > maximum:
        raise RescueError(f"{field} is invalid")
    return text


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 100 or any(not isinstance(item, str) for item in value):
        raise RescueError(f"{label} must be a bounded string array")
    return list(value)
