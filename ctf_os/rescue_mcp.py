"""Project-local stdio MCP server for one exact Claude rescue."""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping, Sequence
import json
from pathlib import Path
import sys
from typing import Any

from .rescue import RescueError
from .rescue_backend import RescueBackend
from .rescue_sessions import RescueSessionManager


MCP_PROTOCOL_VERSION = "2025-06-18"
MAX_MCP_RESPONSE_BYTES = 256 * 1024


TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "ctf_inventory": {"type": "object", "properties": {"refresh": {"type": "boolean"}}},
    "ctf_exec": {"type": "object", "required": ["argv"], "properties": {"argv": {"type": "array", "items": {"type": "string"}}, "timeout": {"type": "integer"}, "timeout_profile": {"type": "string"}}},
    "ctf_session_list": {"type": "object", "properties": {}},
    "ctf_session_open": {"type": "object", "required": ["kind", "name"], "properties": {"kind": {"enum": ["shell", "gdb", "repl", "tcp"]}, "name": {"type": "string"}, "argv": {"type": "array", "items": {"type": "string"}}, "target_index": {"type": "integer"}}},
    "ctf_session_send": {"type": "object", "required": ["session_id"], "properties": {"session_id": {"type": "string"}, "text": {"type": "string"}, "hex": {"type": "string"}, "base64": {"type": "string"}, "file": {"type": "string"}}},
    "ctf_session_read": {"type": "object", "required": ["session_id", "cursor"], "properties": {"session_id": {"type": "string"}, "cursor": {"type": "integer"}, "max_bytes": {"type": "integer"}, "wait_seconds": {"type": "number"}}},
    "ctf_session_status": {"type": "object", "required": ["session_id"], "properties": {"session_id": {"type": "string"}}},
    "ctf_session_close": {"type": "object", "required": ["session_id"], "properties": {"session_id": {"type": "string"}}},
    "ctf_progress_record": {"type": "object", "required": ["payload"], "properties": {"payload": {"type": "object"}}},
    "ctf_progress_show": {"type": "object", "properties": {}},
    "ctf_progress_checkpoint": {"type": "object", "required": ["payload"], "properties": {"payload": {"type": "object"}}},
    "ctf_task_create": {"type": "object", "required": ["payload"], "properties": {"payload": {"type": "object"}}},
    "ctf_task_result": {"type": "object", "required": ["payload"], "properties": {"payload": {"type": "object"}}},
    "ctf_task_show": {"type": "object", "properties": {"task_id": {"type": "string"}}},
    "ctf_knowledge_hint_record": {"type": "object", "required": ["payload"], "properties": {"payload": {"type": "object"}}},
    "ctf_knowledge_show": {"type": "object", "properties": {}},
}


def call_tool(
    backend: RescueBackend, name: str, arguments: Mapping[str, Any],
    *, command_executor: Callable[[Sequence[str], int | None, str], dict[str, Any]],
) -> dict[str, Any]:
    if name not in TOOL_SCHEMAS:
        raise RescueError(f"unknown rescue MCP tool: {name}")
    sessions = RescueSessionManager(
        backend.run, backend.rescue_root, backend.metadata, backend.packet, docker=backend.docker,
    )
    if name == "ctf_inventory":
        return backend.inventory(refresh=arguments.get("refresh") is True)
    if name == "ctf_exec":
        argv = arguments.get("argv")
        if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
            raise RescueError("ctf_exec argv must be a string array")
        return command_executor(
            argv, int(arguments["timeout"]) if arguments.get("timeout") is not None else None,
            str(arguments.get("timeout_profile") or "quick_probe"),
        )
    if name == "ctf_session_list":
        return sessions.list()
    if name == "ctf_session_open":
        return sessions.open(
            kind=str(arguments.get("kind") or ""), name=str(arguments.get("name") or ""),
            argv=list(arguments.get("argv") or []), target_index=arguments.get("target_index"),
        )
    if name == "ctf_session_send":
        data, encoding = _session_data(backend.rescue_root, arguments)
        return sessions.send(str(arguments.get("session_id") or ""), data, encoding=encoding)
    if name == "ctf_session_read":
        return sessions.read(
            str(arguments.get("session_id") or ""), cursor=int(arguments.get("cursor", 0)),
            max_bytes=int(arguments.get("max_bytes", 32768)),
            wait_seconds=float(arguments.get("wait_seconds", 0)),
        )
    if name == "ctf_session_status":
        return sessions.status(str(arguments.get("session_id") or ""))
    if name == "ctf_session_close":
        return sessions.close(str(arguments.get("session_id") or ""))
    if name == "ctf_progress_record":
        return backend.progress_record(_mapping(arguments.get("payload"), "progress payload"))
    if name == "ctf_progress_show":
        return backend.progress_show()
    if name == "ctf_progress_checkpoint":
        payload = dict(_mapping(arguments.get("payload"), "checkpoint payload"))
        payload.setdefault("event", "COMPACTION_CHECKPOINT")
        return backend.progress_record(payload, checkpoint=True)
    if name == "ctf_task_create":
        return backend.task_create(_mapping(arguments.get("payload"), "task payload"))
    if name == "ctf_task_result":
        return backend.task_result(_mapping(arguments.get("payload"), "task result payload"))
    if name == "ctf_task_show":
        task_id = arguments.get("task_id")
        return backend.task_show(str(task_id) if task_id is not None else None)
    if name == "ctf_knowledge_hint_record":
        return backend.knowledge_hint_record(_mapping(arguments.get("payload"), "knowledge hint payload"))
    return backend.knowledge_show()


class StdioMCPServer:
    def __init__(
        self, backend: RescueBackend,
        command_executor: Callable[[Sequence[str], int | None, str], dict[str, Any]],
    ) -> None:
        self.backend = backend
        self.command_executor = command_executor

    def serve(self) -> int:
        for raw in sys.stdin.buffer:
            if len(raw) > 1024 * 1024:
                self._write(_error(None, -32600, "request exceeds 1 MiB"))
                continue
            try:
                request = json.loads(raw)
                response = self.handle(request)
            except Exception as exc:
                response = _error(None, -32603, str(exc)[:2000])
            if response is not None:
                self._write(response)
        return 0

    def handle(self, request: Mapping[str, Any]) -> dict[str, Any] | None:
        request_id = request.get("id")
        method = request.get("method")
        if request.get("jsonrpc") != "2.0" or not isinstance(method, str):
            return _error(request_id, -32600, "invalid JSON-RPC request")
        if method == "notifications/initialized":
            return None
        if method == "initialize":
            return _result(request_id, {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "ctf-rescue", "version": "3.0.0"},
                "instructions": "Exact-run CTF rescue tools only; no model launch or submission.",
            })
        if method == "tools/list":
            return _result(request_id, {"tools": [
                {"name": name, "description": _description(name), "inputSchema": schema}
                for name, schema in TOOL_SCHEMAS.items()
            ]})
        if method == "tools/call":
            params = request.get("params")
            if not isinstance(params, Mapping):
                return _error(request_id, -32602, "tools/call params must be an object")
            name = str(params.get("name") or "")
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, Mapping):
                return _error(request_id, -32602, "tool arguments must be an object")
            try:
                value = call_tool(
                    self.backend, name, arguments, command_executor=self.command_executor,
                )
            except Exception as exc:
                return _result(request_id, {
                    "content": [{"type": "text", "text": json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False)}],
                    "isError": True,
                })
            text = json.dumps({"ok": True, "result": value}, ensure_ascii=False, sort_keys=True)
            if len(text.encode()) > MAX_MCP_RESPONSE_BYTES:
                return _result(request_id, {
                    "content": [{"type": "text", "text": json.dumps({"ok": False, "error": "bounded MCP output exceeded; use cursor/pagination"})}],
                    "isError": True,
                })
            return _result(request_id, {"content": [{"type": "text", "text": text}]})
        return _error(request_id, -32601, "method not found")

    def _write(self, value: Mapping[str, Any]) -> None:
        encoded = (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
        if len(encoded) > MAX_MCP_RESPONSE_BYTES:
            encoded = (json.dumps(_error(value.get("id"), -32603, "response exceeds bound"), separators=(",", ":")) + "\n").encode()
        sys.stdout.buffer.write(encoded); sys.stdout.buffer.flush()


def _session_data(root: Path, arguments: Mapping[str, Any]) -> tuple[bytes, str]:
    choices = [key for key in ("text", "hex", "base64", "file") if arguments.get(key) is not None]
    if len(choices) != 1:
        raise RescueError("session send requires exactly one of text, hex, base64, or file")
    kind = choices[0]
    value = arguments[kind]
    try:
        if kind == "text":
            return (str(value) + "\n").encode(), "text"
        if kind == "hex":
            return bytes.fromhex(str(value)), "hex"
        if kind == "base64":
            return base64.b64decode(str(value), validate=True), "base64"
        relative = Path(str(value))
        if relative.is_absolute() or not relative.parts or relative.parts[0] not in {"work", "artifacts"} or any(part in {"", ".", ".."} for part in relative.parts):
            raise RescueError("session input file must stay under work/ or artifacts/")
        path = root / relative
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
            raise RescueError("session input file is missing, unsafe, or too large")
        return path.read_bytes(), "file"
    except (ValueError, TypeError) as exc:
        raise RescueError(f"session {kind} input is malformed") from exc


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RescueError(f"{label} must be an object")
    return value


def _description(name: str) -> str:
    return {
        "ctf_inventory": "Inspect the exact category sandbox toolchain and image identity.",
        "ctf_exec": "Run one bounded direct-argv command and create a canonical receipt.",
        "ctf_session_list": "List exact-rescue persistent sessions.",
        "ctf_session_open": "Open a persistent shell, GDB, REPL, or TCP session.",
        "ctf_session_send": "Send binary-safe input to a persistent session.",
        "ctf_session_read": "Read bounded output using a monotonic cursor.",
        "ctf_session_status": "Inspect a persistent session state.",
        "ctf_session_close": "Close and verify cleanup of a persistent session.",
        "ctf_progress_record": "Append a typed live rescue progress event.",
        "ctf_progress_show": "Project live rescue state from its append-only ledger.",
        "ctf_progress_checkpoint": "Write a bounded compaction checkpoint.",
        "ctf_task_create": "Create a typed subagent task.",
        "ctf_task_result": "Record a receipt/artifact-bound subagent result.",
        "ctf_task_show": "Show bounded typed subagent task history.",
        "ctf_knowledge_hint_record": "Structure researched facts as an unconfirmed attack hint.",
        "ctf_knowledge_show": "Show bounded research sources and candidate hints.",
    }[name]


def _result(request_id: object, result: object) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: object, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
