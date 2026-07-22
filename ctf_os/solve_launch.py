"""Bounded launch context for the single first-to-flag Solve engine."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .contest import ChallengeSpec
from .preflight import prepared_input_bytes
from .sandbox.network import parse_remotes
from .workspace import atomic_json


SOLVE_LAUNCH_SCHEMA_VERSION = 3
MAX_SOLVE_LAUNCH_BYTES = 64 * 1024
MAX_PRIORITY_FILES = 20
MAX_OBSERVATION_HINTS = 8


def build_solve_launch_context(
    challenge: ChallengeSpec, record: dict[str, object],
) -> dict[str, object]:
    """Project only the selected challenge into immediate attack context."""

    files = _priority_files(record)
    metadata = _mapping(record.get("important_metadata"))
    targets = [target.to_dict() for target in parse_remotes(challenge.remotes)]
    context: dict[str, object] = {
        "schema_version": SOLVE_LAUNCH_SCHEMA_VERSION,
        "challenge_id": challenge.id,
        "challenge_key": _text(challenge.key, 320),
        "category": _text(challenge.category, 80),
        "name": _text(challenge.name, 240),
        "problem_information": {
            "description": _optional_text(challenge.description, 4_000),
            "hint": _optional_text(challenge.hint, 2_000),
            "flag_format": _optional_text(challenge.flag_format, 320),
            "flag_pattern": _optional_text(challenge.flag_pattern, 1_000),
            "input_profile": _text(challenge.input_profile, 80),
        },
        "input_fingerprint": str(record.get("source_fingerprint") or ""),
        "objective": "FIRST_VALID_FLAG",
        "solve_engine": "first-to-flag",
        "root_lane": {
            "status": "RUNNING", "session_id": "sol-main",
            "lead_attacker": True, "coordinator_only": False,
            "model_request": "gpt-5.6-sol", "reasoning_effort": "xhigh",
        },
        "maximum_model_concurrency": 4,
        "budget_seconds": 90 * 60,
        "authorized_targets": [_target(item) for item in targets],
        "priority_files": files,
        "important_metadata": {
            "file_count": _integer(metadata.get("file_count"), len(_dict_list(record.get("files")))),
            "total_bytes": prepared_input_bytes(record),
            "subtype": _optional_text(record.get("subtype"), 240),
            "runtime": _strings(record.get("runtime"), maximum=8, length=80),
        },
        "observation_hints": _strings(
            record.get("observation_hints") or record.get("initial_attack_surface"),
            maximum=MAX_OBSERVATION_HINTS, length=240,
        ),
        "recommended_environment": {
            "image": _text(record.get("recommended_image") or "ctf-os-sandbox:base", 240),
            "resource_profile": _text(record.get("recommended_resource_profile") or "standard", 80),
            "service_plan": _service_plan(record.get("service_plan")),
        },
        "execution_policy": {
            "same_session_required": True,
            "root_attacks_immediately": True,
            "optional_native_children": True,
            "native_thread_id_required_for_running": True,
            "root_continues_attacking_without_waiting": True,
            "event_write_blocks_execution": False,
            "automatic_flag_submission": False,
            "automatic_extension": False,
        },
    }
    if solve_launch_size(context) > MAX_SOLVE_LAUNCH_BYTES:
        raise ValueError("bounded Solve Launch Context exceeds 64 KiB")
    return context


def save_solve_launch_context(solve_root: Path, context: dict[str, object]) -> Path:
    if solve_launch_size(context) > MAX_SOLVE_LAUNCH_BYTES:
        raise ValueError("bounded Solve Launch Context exceeds 64 KiB")
    path = solve_root / "SOLVE-LAUNCH.json"
    if path.is_symlink():
        raise ValueError("Solve Launch Context path must not be a symlink")
    if path.exists() and not path.is_file():
        raise ValueError(f"Solve Launch Context path is unsafe: {path}")
    atomic_json(path, context)
    return path


def solve_launch_size(context: dict[str, object]) -> int:
    return len((json.dumps(context, ensure_ascii=False, sort_keys=True) + "\n").encode())


def _priority_files(record: dict[str, object]) -> list[dict[str, object]]:
    files = _dict_list(record.get("files"))
    by_path = {str(item.get("path")): item for item in files if item.get("path") is not None}
    selected = [by_path[name] for name in map(str, _list(record.get("priority_files"))) if name in by_path]
    if not selected:
        selected = files
    return [_priority_file(item) for item in selected[:MAX_PRIORITY_FILES]]


def _priority_file(item: dict[str, Any]) -> dict[str, object]:
    result: dict[str, object] = {"path": _text(item.get("path"), 240), "size": _integer(item.get("size"))}
    for key, length in (("sha256", 64), ("mime", 120), ("kind", 320)):
        if item.get(key) is not None:
            result[key] = _text(item[key], length)
    if isinstance(item.get("elf"), dict):
        result["elf"] = dict(item["elf"])
    return result


def _target(item: dict[str, Any]) -> dict[str, object]:
    return {
        "declared": _text(item.get("declared"), 320), "host": _text(item.get("host"), 260),
        "port": _integer(item.get("port")), "scheme": _text(item.get("scheme"), 40),
        "protocol": _text(item.get("protocol"), 40), "transport": _text(item.get("transport"), 20),
        "organizer_declared": bool(item.get("organizer_declared")), "callback": bool(item.get("callback")),
    }


def _service_plan(value: object) -> dict[str, object]:
    plan = _mapping(value)
    return {
        key: plan[key]
        for key in ("kind", "status", "safe_to_start", "build_context", "dockerfile", "compose_file")
        if key in plan
    }


def _strings(value: object, *, maximum: int, length: int) -> list[str]:
    return [_text(item, length) for item in _list(value)[:maximum]]


def _text(value: object, limit: int) -> str:
    raw = str("" if value is None else value).encode()
    return raw[:limit].decode(errors="ignore")


def _optional_text(value: object, limit: int) -> str | None:
    return None if value is None else _text(value, limit)


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _dict_list(value: object) -> list[dict[str, Any]]:
    return [item for item in _list(value) if isinstance(item, dict)]


def _list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _integer(value: object, default: int = 0) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else default
