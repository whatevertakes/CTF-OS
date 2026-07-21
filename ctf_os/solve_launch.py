"""Bounded, deterministic launch context for one prepared CTF challenge."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .contest import ChallengeSpec
from .modes import SolveMode, resolve_solve_mode
from .model_routing import VERIFIED_RUNTIME_MODELS, validate_ultra_guard
from .preflight import prepared_input_bytes
from .sandbox.network import parse_remotes
from .workspace import atomic_json


SOLVE_LAUNCH_SCHEMA_VERSION = 1
MAX_SOLVE_LAUNCH_BYTES = 64 * 1024
MAX_PRIORITY_FILES = 20
MAX_OBSERVATION_HINTS = 8
OBSERVATION_HINT_SEMANTICS = (
    "Preflight observation hints only order direct inspection of this selected challenge. "
    "They are not confirmed vulnerabilities or exploit primitives. "
    "Discard a hint immediately when the first decisive experiment refutes it."
)


def build_solve_launch_context(
    challenge: ChallengeSpec,
    record: dict[str, object],
    *, mode: SolveMode | str | None = None, legacy_tier: int | None = None,
) -> dict[str, object]:
    """Project current selected-challenge evidence into bounded solve context."""

    files = _priority_files(record)
    metadata = _mapping(record.get("important_metadata"))
    all_files = _dict_list(record.get("files"))
    targets = [target.to_dict() for target in parse_remotes(challenge.remotes)]
    target_count = len(targets)
    hints = _strings(
        record.get("observation_hints") or record.get("initial_attack_surface") or record.get("attack_surface"),
        maximum=MAX_OBSERVATION_HINTS,
        length=240,
    )
    selected_mode = resolve_solve_mode(mode, tier=legacy_tier)
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
        "solve_mode": selected_mode.value,
        "legacy_tier": legacy_tier,
        "sol_lane": {"status": "RUNNING", "session_id": "sol-main"},
        "lead_runtime_contract": {
            "requested_model_class": "sol-equivalent",
            "requested_model": VERIFIED_RUNTIME_MODELS["sol-equivalent"],
            "requested_reasoning": "xhigh",
            "observed_model": None, "observed_reasoning": None,
            "runtime_observation_status": "NOT_YET_OBSERVED",
            "lead_attacker": True,
        },
        "ultra_guard": {
            **validate_ultra_guard(selected_mode.value, observed_reasoning=None),
            "adaptive_race_with_ultra_allowed": False,
            "fixed_race_with_ultra_allowed": False,
            "sol_only_with_ultra_requires_separate_experiment": True,
        },
        "planned_child_width": 0,
        "active_child_width": 0,
        "bounded_observation": {
            "status": "PENDING" if selected_mode is SolveMode.ADAPTIVE_RACE else "NOT_REQUIRED",
            "minimum_seconds": 60, "maximum_seconds": 90,
        },
        "authorized_targets": [_target(item) for item in targets],
        "authorized_target_count": target_count,
        "priority_files": files,
        "important_metadata": {
            "file_count": _integer(metadata.get("file_count"), len(all_files)),
            "total_bytes": prepared_input_bytes(record),
            "subtype": _text(record.get("subtype"), 240) if record.get("subtype") is not None else None,
            "runtime": _strings(record.get("runtime"), maximum=8, length=80),
        },
        "observation_hints": hints,
        "recommended_environment": {
            "image": _text(record.get("recommended_image") or "ctf-os-sandbox:base", 240),
            "resource_profile": _text(record.get("recommended_resource_profile") or "standard", 80),
            "service_plan": _service_plan(record.get("service_plan")),
        },
        "execution_policy": {
            "same_session_required": True,
            "observation_budget_seconds": 90,
            "maximum_active_hypotheses": 3,
            "preflight_hints_are_not_confirmed_vulnerabilities": True,
            "discard_refuted_hints_immediately": True,
            "python_must_not_choose_tier_or_spawn_children": True,
            "python_must_not_create_native_model_sessions": True,
            "mode_is_authoritative": True,
            "tier_is_legacy_resource_hint_only": True,
            "fixed_race_requires_exactly_three_frozen_intents": True,
            "adaptive_replacement_limit": 1,
            "maximum_model_concurrency": (
                1 if selected_mode is SolveMode.SOL_ONLY else 4
            ),
            "maximum_active_max_lanes": 1,
            "ultra_must_not_nest_with_ctf_os_race": True,
            "observation_hint_semantics": OBSERVATION_HINT_SEMANTICS,
        },
    }
    size = solve_launch_size(context)
    if size > MAX_SOLVE_LAUNCH_BYTES:
        raise ValueError(
            f"bounded Solve Launch Context exceeds {MAX_SOLVE_LAUNCH_BYTES} bytes: {size}"
        )
    return context


def save_solve_launch_context(solve_root: Path, context: dict[str, object]) -> Path:
    """Atomically replace the current launch file without following symlinks."""

    path = solve_root / "SOLVE-LAUNCH.json"
    if path.is_symlink():
        raise ValueError(f"Solve Launch Context path must not be a symlink: {path}")
    if path.exists() and not path.is_file():
        raise ValueError(f"Solve Launch Context path must be a regular file: {path}")
    atomic_json(path, context)
    return path


def solve_launch_size(context: dict[str, object]) -> int:
    rendered = json.dumps(context, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    return len(rendered.encode("utf-8"))


def _priority_files(record: dict[str, object]) -> list[dict[str, object]]:
    files = _dict_list(record.get("files"))
    by_path = {str(item.get("path")): item for item in files if item.get("path") is not None}
    priority_names = [str(value) for value in _list(record.get("priority_files"))]
    selected = [by_path[name] for name in priority_names if name in by_path]
    if not selected:
        selected = files
    return [_priority_file(item) for item in selected[:MAX_PRIORITY_FILES]]


def _priority_file(item: dict[str, Any]) -> dict[str, object]:
    result: dict[str, object] = {
        "path": _text(item.get("path"), 240),
        "size": _integer(item.get("size")),
    }
    for key, length in (("sha256", 64), ("mime", 120), ("kind", 320)):
        if item.get(key) is not None:
            result[key] = _text(item[key], length)
    elf = _mapping(item.get("elf"))
    if elf:
        result["elf"] = {
            "architecture": _text(elf.get("architecture"), 120),
            "type": _text(elf.get("type"), 80),
            "nx": bool(elf.get("nx")),
            "pie": bool(elf.get("pie")),
            "relro": _text(elf.get("relro"), 40),
            "stripped": bool(elf.get("stripped")),
        }
    return result


def _target(item: dict[str, Any]) -> dict[str, object]:
    return {
        "declared": _text(item.get("declared"), 320),
        "host": _text(item.get("host"), 260),
        "port": _integer(item.get("port")),
        "scheme": _text(item.get("scheme"), 40),
        "protocol": _text(item.get("protocol"), 40),
        "transport": _text(item.get("transport"), 20),
        "organizer_declared": bool(item.get("organizer_declared")),
        "callback": bool(item.get("callback")),
    }


def _service_plan(value: object) -> dict[str, object]:
    plan = _mapping(value)
    if not plan:
        return {}
    result = _selected_mapping(
        plan,
        (
            ("kind", 80), ("status", 80), ("safe_to_start", None),
            ("build_context", 240), ("dockerfile", 240), ("compose_file", 240),
        ),
    )
    result["review_reasons"] = _strings(plan.get("review_reasons"), maximum=3, length=320)
    result["compose_files"] = _strings(plan.get("compose_files"), maximum=5, length=240)
    services: list[dict[str, object]] = []
    for service in _dict_list(plan.get("services"))[:8]:
        compact = _selected_mapping(
            service,
            (
                ("name", 120), ("image", 240), ("build_context", 240),
                ("dockerfile", 240), ("internal_target", 240),
            ),
        )
        compact["internal_targets"] = _strings(
            service.get("internal_targets"), maximum=4, length=240,
        )
        compact["exposed_ports"] = [
            _integer(port) for port in _list(service.get("exposed_ports"))[:16]
        ]
        compact["mapped_ports"] = [
            _selected_mapping(port, (("target", None), ("published", None), ("protocol", 40)))
            for port in _dict_list(service.get("mapped_ports"))[:8]
        ]
        compact["depends_on"] = _strings(service.get("depends_on"), maximum=8, length=120)
        services.append(compact)
    result["services"] = services
    return result


def _selected_mapping(
    value: dict[str, Any],
    fields: tuple[tuple[str, int | None], ...],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, length in fields:
        if key not in value:
            continue
        item = value[key]
        if length is None:
            if isinstance(item, bool):
                result[key] = item
            elif isinstance(item, int):
                result[key] = item
            elif item is None:
                result[key] = None
            else:
                result[key] = _text(item, 120)
        else:
            result[key] = _text(item, length)
    return result


def _strings(value: object, *, maximum: int, length: int) -> list[str]:
    return [_text(item, length) for item in _list(value)[:maximum]]


def _text(value: object, limit: int) -> str:
    text = "" if value is None else str(value)
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    marker = "…"
    prefix = encoded[: max(0, limit - len(marker.encode("utf-8")))].decode("utf-8", errors="ignore")
    return prefix + marker


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
