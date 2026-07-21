"""Claude Code lifecycle hook recording for an exact manual rescue."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import json
from pathlib import Path
from typing import Any

from .rescue import RescueError, canonical_json
from .rescue_backend import RescueBackend, record_telemetry
from .rescue_sessions import RescueSessionManager
from .workspace import append_jsonl_fsync, read_jsonl_strict, utc_now


SUPPORTED_HOOKS = frozenset({
    "SessionStart", "PreCompact", "PostCompact", "SessionEnd",
    "SubagentStart", "SubagentStop", "TaskCreated", "TaskCompleted",
    "PreToolUse", "PostToolUse",
})
RESEARCH_TOOLS = frozenset({"WebSearch", "WebFetch"})


def handle_hook(
    backend: RescueBackend, hook_name: str, payload: Mapping[str, Any],
) -> dict[str, Any]:
    if hook_name not in SUPPORTED_HOOKS:
        raise RescueError(f"unsupported Claude Code hook: {hook_name}")
    supplied = payload.get("hook_event_name")
    if supplied is not None and supplied != hook_name:
        raise RescueError("Claude hook name does not match its payload")
    if hook_name == "PreToolUse":
        return _pre_tool(backend, payload)
    if hook_name == "PostToolUse":
        return _post_tool(backend, payload)

    row = _append_hook(backend, hook_name, payload)
    if hook_name == "SessionStart":
        record_telemetry(backend.rescue_root, "claude_session_start", details={
            "claude_session_id": payload.get("session_id"),
            "observed_model": payload.get("model"), "source": payload.get("source"),
        })
        return {
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": _resume_context(backend, payload),
            }
        }
    if hook_name == "PreCompact":
        progress = backend._read("RESCUE_PROGRESS.jsonl", "rescue progress ledger")
        has_checkpoint = any(item.get("event") == "COMPACTION_CHECKPOINT" for item in progress[-20:])
        instruction = None if has_checkpoint else (
            "Before compaction, call ctf_progress_checkpoint with a short blocker, active hypotheses, "
            "last decisive experiment, latest artifact, and next action. Do not restate the full packet."
        )
        return {
            "checkpoint_present": has_checkpoint,
            "systemMessage": instruction,
        }
    if hook_name == "PostCompact":
        record_telemetry(backend.rescue_root, "compaction", details={
            "session_id": payload.get("session_id"), "trigger": payload.get("trigger"),
            "hook_receipt_id": row["hook_receipt_id"],
        })
        return {"recorded": True, "hook_receipt_id": row["hook_receipt_id"]}
    if hook_name == "SessionEnd":
        starts = [
            item for item in _hook_rows(backend)
            if item.get("event") == "SessionStart" and item.get("session_id") == payload.get("session_id")
        ]
        record_telemetry(backend.rescue_root, "claude_session_end", details={
            "claude_session_id": payload.get("session_id"), "reason": payload.get("reason"),
            "session_start_receipt_id": starts[-1].get("hook_receipt_id") if starts else None,
        })
    if hook_name in {"SubagentStart", "SubagentStop"}:
        record_telemetry(backend.rescue_root, hook_name.casefold(), details={
            "session_id": payload.get("session_id"), "subagent_id": payload.get("agent_id"),
            "agent_type": payload.get("agent_type"),
        })
    if hook_name in {"TaskCreated", "TaskCompleted"}:
        task_id = str(payload.get("task_id") or "")
        if task_id and backend._task_rows(task_id):
            backend._append(
                "RESCUE_TASKS.jsonl",
                "TASK_STARTED" if hook_name == "TaskCreated" else "TASK_CLOSED",
                {"task_id": task_id, "claude_hook_receipt_id": row["hook_receipt_id"]},
                "task_hook",
            )
    return {"recorded": True, "hook_receipt_id": row["hook_receipt_id"]}


def latest_session(backend: RescueBackend) -> dict[str, Any] | None:
    rows = [row for row in _hook_rows(backend) if row.get("event") == "SessionStart"]
    return rows[-1] if rows else None


def _append_hook(
    backend: RescueBackend, event: str, payload: Mapping[str, Any],
) -> dict[str, Any]:
    progress = backend.progress_show(write_projection=False)
    sessions = RescueSessionManager(
        backend.run, backend.rescue_root, backend.metadata, backend.packet, docker=backend.docker,
    ).list()["sessions"]
    summary = str(
        payload.get("compact_summary") or payload.get("summary")
        or payload.get("last_assistant_message") or ""
    )
    fields = {
        "schema_version": 1, "event": event, **backend.identity,
        "session_id": _bounded(payload.get("session_id"), 256),
        "model": _bounded(payload.get("model"), 256) if event == "SessionStart" else None,
        "source": _bounded(payload.get("source"), 64),
        "trigger": _bounded(payload.get("trigger"), 64),
        "reason": _bounded(payload.get("reason"), 256),
        "transcript_path": _bounded(payload.get("transcript_path"), 2000),
        "cwd": _bounded(payload.get("cwd"), 2000),
        "agent_id": _bounded(payload.get("agent_id"), 256),
        "agent_type": _bounded(payload.get("agent_type"), 256),
        "compact_summary_digest": hashlib.sha256(summary.encode()).hexdigest() if summary else None,
        "compact_summary_excerpt": _bounded(summary, 4000),
        "current_progress_receipt_id": progress.get("last_progress_receipt_id"),
        "open_persistent_sessions": [
            row.get("session_id") for row in sessions if row.get("status") == "RUNNING"
        ][:32],
        "recorded_at": utc_now(),
    }
    if event == "SessionEnd":
        starts = [
            row for row in _hook_rows(backend)
            if row.get("event") == "SessionStart" and row.get("session_id") == fields["session_id"]
        ]
        try:
            fields["duration_seconds"] = (
                datetime.fromisoformat(str(fields["recorded_at"]))
                - datetime.fromisoformat(str(starts[-1]["recorded_at"]))
            ).total_seconds() if starts else None
        except (ValueError, TypeError):
            fields["duration_seconds"] = None
    fields["hook_receipt_id"] = hashlib.sha256(canonical_json(fields)).hexdigest()[:24]
    append_jsonl_fsync(
        backend.rescue_root / "CLAUDE_SESSION_EVENTS.jsonl", fields,
        label="Claude session event ledger",
    )
    return fields


def _resume_context(backend: RescueBackend, payload: Mapping[str, Any]) -> str:
    state = backend.progress_show(write_projection=False)
    sessions = RescueSessionManager(
        backend.run, backend.rescue_root, backend.metadata, backend.packet, docker=backend.docker,
    ).list()["sessions"]
    packet_state = backend.packet.get("state") if isinstance(backend.packet.get("state"), Mapping) else {}
    request = backend.packet.get("request") if isinstance(backend.packet.get("request"), Mapping) else {}
    context = {
        "exact_identity": {
            "run_id": backend.run.name, "rescue_id": backend.rescue_root.name,
            "packet_digest": backend.packet.get("packet_digest"),
        },
        "current_blocker": state.get("current_blocker") or request.get("current_blocker"),
        "active_hypotheses": state.get("active_hypotheses", [])[:2],
        "last_decisive_experiment": state.get("last_decisive_experiment"),
        "active_persistent_sessions": [
            {"session_id": row.get("session_id"), "name": row.get("name"), "kind": row.get("session_kind")}
            for row in sessions if row.get("status") == "RUNNING"
        ][:16],
        "latest_working_artifact": state.get("latest_working_artifact") or packet_state.get("working_poc"),
        "next_action": state.get("next_action"),
        "observed_runtime_model": payload.get("model"),
    }
    return "CTF-OS bounded resume context:\n" + json.dumps(
        context, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    )


def _pre_tool(backend: RescueBackend, payload: Mapping[str, Any]) -> dict[str, Any]:
    tool = str(payload.get("tool_name") or "")
    telemetry_path = backend.rescue_root / "RESCUE_TELEMETRY.jsonl"
    telemetry = read_jsonl_strict(telemetry_path, "rescue telemetry ledger") if telemetry_path.exists() else []
    if not any(row.get("event") == "first_tool_call" for row in telemetry):
        record_telemetry(backend.rescue_root, "first_tool_call", details={"tool": tool})
    record_telemetry(backend.rescue_root, "tool_call", details={
        "tool": tool, "session_id": payload.get("session_id"),
        "subagent_id": payload.get("agent_id"),
    })
    policy = str(backend.packet.get("research_policy") or "offline")
    external_mcp = tool.startswith("mcp__") and not tool.startswith("mcp__ctf-rescue__")
    blocked = policy == "offline" and (tool in RESEARCH_TOOLS or external_mcp)
    if policy == "public-web" and external_mcp:
        blocked = True
    if blocked:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse", "permissionDecision": "deny",
                "permissionDecisionReason": f"research policy {policy} blocks {tool}",
            }
        }
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}


def _post_tool(backend: RescueBackend, payload: Mapping[str, Any]) -> dict[str, Any]:
    tool = str(payload.get("tool_name") or "")
    external_mcp = tool.startswith("mcp__") and not tool.startswith("mcp__ctf-rescue__")
    if tool not in RESEARCH_TOOLS and not external_mcp:
        return {"recorded": False}
    tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), Mapping) else {}
    output = payload.get("tool_response") or payload.get("tool_output") or ""
    candidates: list[object]
    if isinstance(output, Mapping) and isinstance(output.get("results"), list):
        candidates = list(output["results"][:20])
    elif isinstance(output, list):
        candidates = list(output[:20])
    else:
        candidates = [output]
    receipt_ids: list[str] = []
    for candidate in candidates:
        candidate_mapping = candidate if isinstance(candidate, Mapping) else {}
        output_text = (
            candidate if isinstance(candidate, str)
            else json.dumps(candidate, ensure_ascii=False, sort_keys=True)
        )
        source = (
            candidate_mapping.get("url") or candidate_mapping.get("resource")
            or tool_input.get("url") or tool_input.get("resource")
            or tool_input.get("query") or ""
        )
        row = backend.knowledge_source_record({
            "query": tool_input.get("query") or tool_input.get("url") or "",
            "tool": tool,
            "source_title": candidate_mapping.get("title") or tool_input.get("title") or "",
            "source_url_or_resource_id": source, "retrieved_at": utc_now(),
            "bounded_excerpt": output_text[:8000],
            "content_digest": hashlib.sha256(output_text.encode()).hexdigest(),
            "session_id": payload.get("session_id") or "",
            "subagent_id": payload.get("agent_id") or "",
        })
        receipt_ids.append(str(row["receipt_id"]))
    return {
        "recorded": True,
        "knowledge_source_receipt_id": receipt_ids[0] if receipt_ids else None,
        "knowledge_source_receipt_ids": receipt_ids,
    }


def _hook_rows(backend: RescueBackend) -> list[dict[str, Any]]:
    path = backend.rescue_root / "CLAUDE_SESSION_EVENTS.jsonl"
    return read_jsonl_strict(path, "Claude session event ledger") if path.exists() else []


def _bounded(value: object, maximum: int) -> str | None:
    if value is None:
        return None
    text = str(value).replace("\x00", "\\0")
    data = text.encode("utf-8")
    return text if len(data) <= maximum else data[: maximum - 3].decode("utf-8", errors="ignore") + "..."
