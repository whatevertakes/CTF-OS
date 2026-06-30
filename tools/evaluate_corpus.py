#!/usr/bin/env python3
"""Evaluate the benchmark corpus without mutating challenge state."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - preflight requires PyYAML.
    yaml = None


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = ROOT / "benchmarks" / "corpus.yaml"
VALID_SPLITS = {"design", "holdout", "regression"}
VALID_STATUSES = {"planned", "attempted", "solved", "partial", "blocked"}
VALID_DIFFICULTIES = {"easy", "medium", "hard", "unknown"}
VALID_DEPENDENCY_STATUSES = {"ok", "missing", "unknown"}
VALID_AGENT_MODES = {
    "none",
    "hermes_readonly",
    "lazycodex_readonly",
    "gajae_bounded",
    "assisted",
    "autonomous",
}
OPTIONAL_STRING_FIELDS = (
    "owner",
    "reviewer",
    "failure_class",
    "proof_scope",
    "replay_kind",
    "replay_quality",
    "shareability",
)
OPTIONAL_MAPPING_FIELDS = (
    "time_metrics",
    "attempt_metrics",
    "reference_metrics",
    "tool_effectiveness",
)
TOOL_ENTRY_FIELDS = (
    "primary_tools_used",
    "required_tools",
    "missing_tools",
    "tools_considered",
    "tools_used",
    "tools_skipped",
)
MCP_TOOL_HINTS = {
    "angr",
    "angr-mcp",
    "ghidra-mcp",
    "ghidra_mcp",
    "playwright",
    "radare2",
    "r2",
    "r2mcp",
}
STATE_STATUS_MAP = {
    "new": "planned",
    "triaged": "attempted",
    "analyzing": "attempted",
    "exploiting": "attempted",
    "solved": "solved",
    "partial": "partial",
    "blocked": "blocked",
}


class CorpusError(Exception):
    pass


def fail(message: str, code: int = 1) -> None:
    print(f"evaluate_corpus: {message}", file=sys.stderr)
    raise SystemExit(code)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS), help="path to corpus YAML")
    parser.add_argument("--json", action="store_true", help="emit JSON metrics")
    return parser.parse_args()


def load_yaml(path: Path) -> dict[str, Any]:
    if yaml is None:
        fail("PyYAML is required to read benchmarks/corpus.yaml", code=2)
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except OSError as exc:
        fail(f"cannot read corpus: {exc}", code=2)
    except yaml.YAMLError as exc:
        fail(f"invalid corpus YAML: {exc}", code=2)
    if not isinstance(data, dict):
        fail("corpus root must be a mapping", code=2)
    return data


def as_list(value: object, field: str, item_id: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(entry, str) for entry in value):
        raise CorpusError(f"{item_id}: {field} must be a list of strings")
    return value


def as_tool_entries(value: object, field: str, item_id: str) -> list[object]:
    if not isinstance(value, list):
        raise CorpusError(f"{item_id}: {field} must be a list")
    for entry in value:
        if isinstance(entry, str):
            continue
        if isinstance(entry, dict):
            if not any(isinstance(entry.get(key), str) and entry.get(key, "").strip() for key in ("tool", "name", "id", "command")):
                raise CorpusError(f"{item_id}: {field} object entries need a tool, name, id, or command string")
            continue
        raise CorpusError(f"{item_id}: {field} entries must be strings or objects")
    return value


def optional_list(raw: dict[str, Any], field: str, item_id: str) -> list[object]:
    if field not in raw or raw[field] is None:
        return []
    if field in TOOL_ENTRY_FIELDS:
        return as_tool_entries(raw[field], field, item_id)
    return as_list(raw[field], field, item_id)


def optional_string(raw: dict[str, Any], field: str, item_id: str) -> str | None:
    if field not in raw or raw[field] is None:
        return None
    if not isinstance(raw[field], str):
        raise CorpusError(f"{item_id}: {field} must be a string")
    return raw[field]


def optional_mapping(raw: dict[str, Any], field: str, item_id: str) -> dict[str, Any]:
    if field not in raw or raw[field] is None:
        return {}
    if not isinstance(raw[field], dict):
        raise CorpusError(f"{item_id}: {field} must be a mapping")
    return raw[field]


def validate_item(raw: object, index: int) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise CorpusError(f"item {index}: must be a mapping")
    required = (
        "id",
        "event",
        "category",
        "challenge",
        "path",
        "split",
        "status",
        "difficulty",
        "tags",
        "expected_artifacts",
        "notes",
    )
    missing = [field for field in required if field not in raw]
    item_id = str(raw.get("id", f"item-{index}"))
    if missing:
        raise CorpusError(f"{item_id}: missing required field(s): {', '.join(missing)}")
    for field in ("id", "event", "category", "challenge", "path", "split", "status", "difficulty", "notes"):
        if not isinstance(raw[field], str):
            raise CorpusError(f"{item_id}: {field} must be a string")
    if raw["split"] not in VALID_SPLITS:
        raise CorpusError(f"{item_id}: split must be one of {', '.join(sorted(VALID_SPLITS))}")
    if raw["status"] not in VALID_STATUSES:
        raise CorpusError(f"{item_id}: status must be one of {', '.join(sorted(VALID_STATUSES))}")
    if raw["difficulty"] not in VALID_DIFFICULTIES:
        raise CorpusError(f"{item_id}: difficulty must be one of {', '.join(sorted(VALID_DIFFICULTIES))}")

    dependency_status = raw.get("dependency_status", "unknown")
    if not isinstance(dependency_status, str):
        raise CorpusError(f"{item_id}: dependency_status must be a string")
    if dependency_status not in VALID_DEPENDENCY_STATUSES:
        raise CorpusError(
            f"{item_id}: dependency_status must be one of {', '.join(sorted(VALID_DEPENDENCY_STATUSES))}"
        )
    tool_routing_gap = raw.get("tool_routing_gap", False)
    if not isinstance(tool_routing_gap, (bool, str)):
        raise CorpusError(f"{item_id}: tool_routing_gap must be a boolean or string")
    agent_mode = optional_string(raw, "agent_mode", item_id)
    if agent_mode is not None and agent_mode not in VALID_AGENT_MODES:
        raise CorpusError(f"{item_id}: agent_mode must be one of {', '.join(sorted(VALID_AGENT_MODES))}")

    optional_strings = {field: optional_string(raw, field, item_id) for field in OPTIONAL_STRING_FIELDS}
    optional_mappings = {field: optional_mapping(raw, field, item_id) for field in OPTIONAL_MAPPING_FIELDS}
    performance_fields_present = [
        field for field in OPTIONAL_MAPPING_FIELDS if field in raw and raw[field] is not None
    ]

    return {
        **raw,
        "tags": as_list(raw["tags"], "tags", item_id),
        "expected_artifacts": as_list(raw["expected_artifacts"], "expected_artifacts", item_id),
        "primary_tools_used": optional_list(raw, "primary_tools_used", item_id),
        "required_tools": optional_list(raw, "required_tools", item_id),
        "missing_tools": optional_list(raw, "missing_tools", item_id),
        "tools_considered": optional_list(raw, "tools_considered", item_id),
        "tools_used": optional_list(raw, "tools_used", item_id),
        "tools_skipped": optional_list(raw, "tools_skipped", item_id),
        "dependency_status": dependency_status,
        "tool_routing_gap": tool_routing_gap,
        "agent_mode": agent_mode,
        "_performance_fields_present": performance_fields_present,
        **optional_strings,
        **optional_mappings,
    }


def load_corpus(path: Path) -> list[dict[str, Any]]:
    data = load_yaml(path)
    items = data.get("items")
    if not isinstance(items, list):
        fail("corpus must contain an items list", code=2)
    try:
        return [validate_item(item, index) for index, item in enumerate(items, start=1)]
    except CorpusError as exc:
        fail(str(exc), code=2)


def resolve_path(value: str, *, base: Path) -> Path | None:
    if not value.strip():
        return None
    raw = Path(value).expanduser()
    if raw.is_absolute():
        return raw.resolve()
    return (base / raw).resolve()


def read_state(challenge_path: Path) -> tuple[dict[str, Any] | None, str | None]:
    state_path = challenge_path / "state.json"
    if not state_path.is_file():
        return None, "missing state.json"
    try:
        with state_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        return None, f"invalid state.json: {exc}"
    if not isinstance(data, dict):
        return None, "state.json root is not an object"
    return data, None


def normalize_state_status(value: object) -> str:
    if isinstance(value, str):
        return STATE_STATUS_MAP.get(value, "attempted")
    return "attempted"


def blocker_reason(state: dict[str, Any]) -> str:
    blocker = state.get("blocker")
    if isinstance(blocker, dict):
        candidates = [blocker.get("reason"), state.get("blocked_reason"), state.get("blocker_reason")]
    else:
        candidates = [blocker, state.get("blocked_reason"), state.get("blocker_reason")]
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return ""


def replay_logs(challenge_path: Path) -> list[Path]:
    evidence_dir = challenge_path / "evidence"
    if not evidence_dir.is_dir():
        return []
    return sorted(evidence_dir.glob("replay_*.log"))


def is_sanitized_report_path(path: Path) -> bool:
    name = path.name.upper()
    return path.is_file() and "SANITIZED" in name and "BENCHMARK_REPORT" in name


def resolve_path_candidates(value: str, *, bases: list[Path]) -> list[Path]:
    if not value.strip():
        return []
    raw = Path(value).expanduser()
    if raw.is_absolute():
        return [raw.resolve()]
    return [(base / raw).resolve() for base in bases]


def expected_artifacts_present(item: dict[str, Any], *, base: Path) -> bool:
    artifacts = item.get("expected_artifacts", [])
    if not artifacts:
        return False
    for artifact in artifacts:
        artifact_path = resolve_path(str(artifact), base=base)
        if artifact_path is None:
            return False
        if "*" in str(artifact_path):
            if not list(artifact_path.parent.glob(artifact_path.name)):
                return False
        elif not artifact_path.exists():
            return False
    return True


def sanitized_report_from_expected_artifacts(item: dict[str, Any], item_path: Path | None) -> Path | None:
    bases = [ROOT]
    if item_path is not None and item_path.is_dir():
        bases.insert(0, item_path)
    for artifact in item.get("expected_artifacts", []):
        for artifact_path in resolve_path_candidates(str(artifact), bases=bases):
            if "*" in str(artifact_path):
                matches = sorted(artifact_path.parent.glob(artifact_path.name))
                for match in matches:
                    if is_sanitized_report_path(match):
                        return match
            elif is_sanitized_report_path(artifact_path):
                return artifact_path
    return None


def sanitized_report_from_state(state: dict[str, Any] | None, challenge_path: Path | None) -> Path | None:
    if state is None or challenge_path is None:
        return None
    metadata = state.get("metadata")
    if not isinstance(metadata, dict):
        return None
    benchmark_report = metadata.get("benchmark_report")
    if not isinstance(benchmark_report, str):
        return None
    for report_path in resolve_path_candidates(benchmark_report, bases=[challenge_path, ROOT]):
        if is_sanitized_report_path(report_path):
            return report_path
    return None


def has_sanitized_report(item: dict[str, Any], item_path: Path | None, state: dict[str, Any] | None) -> bool:
    if item_path is not None and is_sanitized_report_path(item_path):
        return True
    if sanitized_report_from_expected_artifacts(item, item_path) is not None:
        return True
    return sanitized_report_from_state(state, item_path if item_path is not None and item_path.is_dir() else None) is not None


def run_proof_validate(challenge_path: Path) -> tuple[bool, str]:
    result = subprocess.run(
        ["python3", "tools/proof_validate.py", challenge_path.as_posix()],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode == 0:
        return True, result.stdout.strip()
    reason = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else f"returncode={result.returncode}"
    return False, reason


def sorted_counter(counter: Counter[str]) -> dict[str, int]:
    return {key: counter[key] for key in sorted(counter)}


def performance_availability(items: list[dict[str, Any]]) -> dict[str, dict[str, object]]:
    availability: dict[str, dict[str, object]] = {}
    for field in OPTIONAL_MAPPING_FIELDS:
        available = sorted(
            item["id"]
            for item in items
            if field in set(item.get("_performance_fields_present", []))
        )
        unavailable = sorted(
            item["id"]
            for item in items
            if field not in set(item.get("_performance_fields_present", []))
        )
        availability[field] = {
            "available_count": len(available),
            "unavailable_count": len(unavailable),
            "available_ids": available,
            "unavailable_ids": unavailable,
        }
    return availability


def build_split_health(
    outcome_by_split: dict[str, Counter[str]],
    missing_paths_by_split: Counter[str],
) -> dict[str, object]:
    splits: dict[str, dict[str, int]] = {}
    warnings: list[dict[str, str]] = []
    for split in sorted(VALID_SPLITS):
        outcomes = outcome_by_split.get(split, Counter())
        total = sum(outcomes.values())
        split_metrics = {status: outcomes.get(status, 0) for status in sorted(VALID_STATUSES)}
        split_metrics["total"] = total
        split_metrics["missing_challenge_paths"] = missing_paths_by_split.get(split, 0)
        splits[split] = split_metrics
        if total == 0:
            warnings.append({"split": split, "reason": "split has no entries"})
        elif outcomes.get("planned", 0) == total:
            warnings.append({"split": split, "reason": "split has only planned entries"})
        if missing_paths_by_split.get(split, 0):
            warnings.append(
                {
                    "split": split,
                    "reason": f"split has missing challenge paths: {missing_paths_by_split[split]}",
                }
            )
    return {"splits": splits, "warnings": warnings}


def unique_records(records: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[tuple[str, str], ...]] = set()
    unique: list[dict[str, str]] = []
    for record in records:
        key = tuple(sorted(record.items()))
        if key in seen:
            continue
        seen.add(key)
        unique.append(record)
    return unique


def tool_name(entry: object) -> str:
    if isinstance(entry, str):
        return entry.strip()
    if not isinstance(entry, dict):
        return ""
    for key in ("tool", "name", "id", "command"):
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def tool_reason(entry: object) -> str:
    if not isinstance(entry, dict):
        return ""
    for key in ("reason", "decision", "why", "note"):
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def tool_retrospective(entry: object) -> bool:
    if not isinstance(entry, dict):
        return False
    if entry.get("retrospective") is True:
        return True
    for key in ("basis", "mode", "source"):
        value = entry.get(key)
        if isinstance(value, str) and value.strip().lower() == "retrospective":
            return True
    return False


def tool_kind(entry: object) -> str:
    if not isinstance(entry, dict):
        return ""
    for key in ("kind", "type"):
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def is_mcp_tool(entry: object) -> bool:
    name = tool_name(entry).lower()
    kind = tool_kind(entry).lower()
    if kind == "mcp" or "mcp" in kind:
        return True
    if name in MCP_TOOL_HINTS:
        return True
    return any(hint in name for hint in ("mcp", "r2mcp", "ghidra-mcp"))


def state_tool_entries(state: dict[str, Any] | None, key: str) -> list[object]:
    if state is None:
        return []
    routing = state.get("tool_routing")
    if not isinstance(routing, dict):
        return []
    value = routing.get(key)
    if isinstance(value, list):
        return [entry for entry in value if isinstance(entry, (str, dict))]
    return []


def state_tool_summary(state: dict[str, Any] | None) -> str:
    if state is None:
        return ""
    routing = state.get("tool_routing")
    if not isinstance(routing, dict):
        return ""
    value = routing.get("decision_summary")
    if isinstance(value, str):
        return value.strip()
    return ""


def combined_tool_routing(item: dict[str, Any], state: dict[str, Any] | None) -> dict[str, object]:
    return {
        "primary_tools_used": [
            *item.get("primary_tools_used", []),
            *state_tool_entries(state, "primary_tools_used"),
        ],
        "tools_considered": [
            *item.get("tools_considered", []),
            *state_tool_entries(state, "considered"),
            *state_tool_entries(state, "tools_considered"),
        ],
        "tools_used": [
            *item.get("tools_used", []),
            *state_tool_entries(state, "used"),
            *state_tool_entries(state, "tools_used"),
        ],
        "tools_skipped": [
            *item.get("tools_skipped", []),
            *state_tool_entries(state, "skipped"),
            *state_tool_entries(state, "tools_skipped"),
        ],
        "missing_tools": [
            *item.get("missing_tools", []),
            *state_tool_entries(state, "missing"),
            *state_tool_entries(state, "missing_tools"),
        ],
        "decision_summary": state_tool_summary(state),
        "explicit_gap": item.get("tool_routing_gap", False),
    }


def has_tool_routing_data(routing: dict[str, object]) -> bool:
    for key in ("primary_tools_used", "tools_considered", "tools_used", "tools_skipped", "missing_tools"):
        value = routing.get(key)
        if isinstance(value, list) and value:
            return True
    summary = routing.get("decision_summary")
    return isinstance(summary, str) and bool(summary.strip())


def tool_record(item_id: str, entry: object, source: str) -> dict[str, str]:
    record = {"id": item_id, "tool": tool_name(entry), "source": source}
    reason = tool_reason(entry)
    if reason:
        record["reason"] = reason
    kind = tool_kind(entry)
    if kind:
        record["kind"] = kind
    if tool_retrospective(entry):
        record["retrospective"] = "true"
    return record


def missing_tool_names(item: dict[str, Any]) -> list[str]:
    declared_missing = {tool_name(tool) for tool in item.get("missing_tools", [])}
    declared_missing = {tool for tool in declared_missing if tool}
    detected_missing = {
        name
        for name in (tool_name(tool) for tool in item.get("required_tools", []))
        if name and not shutil.which(name)
    }
    return sorted(declared_missing | detected_missing)


def dependency_missing_entry(item: dict[str, Any]) -> dict[str, str] | None:
    missing_tools = missing_tool_names(item)
    dependency_status = item.get("dependency_status", "unknown")

    if dependency_status != "missing" and not missing_tools:
        return None
    if missing_tools:
        reason = f"missing required tool(s): {', '.join(missing_tools)}"
    else:
        reason = "dependency_status=missing"
    return {"id": item["id"], "reason": reason}


def routing_gap_entries(item_id: str, routing: dict[str, object]) -> list[dict[str, str]]:
    gaps: list[dict[str, str]] = []
    explicit_gap = routing.get("explicit_gap")
    if isinstance(explicit_gap, str) and explicit_gap.strip():
        gaps.append({"id": item_id, "reason": explicit_gap.strip()})
    elif explicit_gap is True:
        gaps.append({"id": item_id, "reason": "tool_routing_gap=true"})

    if not has_tool_routing_data(routing):
        gaps.append({"id": item_id, "reason": "missing tool routing data"})

    skipped = routing.get("tools_skipped", [])
    if isinstance(skipped, list):
        missing_reason = sorted(
            tool_name(entry)
            for entry in skipped
            if is_mcp_tool(entry) and not tool_reason(entry) and tool_name(entry)
        )
        if missing_reason:
            gaps.append(
                {
                    "id": item_id,
                    "reason": f"MCP skipped without explicit reason: {', '.join(missing_reason)}",
                }
            )
    return gaps


def routing_mcp_metrics(item_id: str, routing: dict[str, object]) -> dict[str, list[dict[str, str]]]:
    mcp_considered: list[dict[str, str]] = []
    mcp_used: list[dict[str, str]] = []
    mcp_skipped_with_reason: list[dict[str, str]] = []
    mcp_mentions = False

    for source in ("tools_considered", "tools_used", "tools_skipped", "missing_tools"):
        entries = routing.get(source, [])
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not is_mcp_tool(entry):
                continue
            mcp_mentions = True
            if source == "tools_considered":
                mcp_considered.append(tool_record(item_id, entry, source))
            if source == "tools_used":
                mcp_used.append(tool_record(item_id, entry, source))
            if source == "tools_skipped" and tool_reason(entry):
                mcp_skipped_with_reason.append(tool_record(item_id, entry, source))

    primary = routing.get("primary_tools_used", [])
    if isinstance(primary, list):
        for entry in primary:
            if is_mcp_tool(entry):
                mcp_mentions = True
                mcp_used.append(tool_record(item_id, entry, "primary_tools_used"))

    summary = routing.get("decision_summary")
    summary_mentions_mcp = isinstance(summary, str) and "mcp" in summary.lower()
    mcp_absent: list[dict[str, str]] = []
    if has_tool_routing_data(routing) and not mcp_mentions and not summary_mentions_mcp:
        mcp_absent.append({"id": item_id, "reason": "no MCP decision recorded"})

    return {
        "mcp_considered": mcp_considered,
        "mcp_used": mcp_used,
        "mcp_skipped_with_reason": mcp_skipped_with_reason,
        "mcp_absent_without_decision_recorded": mcp_absent,
    }


def evaluate(items: list[dict[str, Any]]) -> dict[str, Any]:
    by_category: Counter[str] = Counter()
    by_split: Counter[str] = Counter()
    by_agent_mode: Counter[str] = Counter()
    failure_taxonomy_counts: Counter[str] = Counter()
    replay_quality_counts: Counter[str] = Counter()
    shareability_counts: Counter[str] = Counter()
    outcome_counts: Counter[str] = Counter({status: 0 for status in sorted(VALID_STATUSES)})
    outcome_by_split: dict[str, Counter[str]] = {split: Counter() for split in VALID_SPLITS}
    missing_paths_by_split: Counter[str] = Counter()
    missing_paths: list[dict[str, str]] = []
    stale_entries: list[dict[str, str]] = []
    solved_missing_evidence: list[dict[str, str]] = []
    blocked_missing_reason: list[dict[str, str]] = []
    entries_missing_agent_mode: list[dict[str, str]] = []
    entries_missing_sanitized_report: list[dict[str, str]] = []
    historical_solved_without_current_proof_valid_replay: list[dict[str, str]] = []
    replay_quality_unavailable: list[str] = []
    shareability_unavailable: list[str] = []
    shareability_gaps: list[dict[str, str]] = []
    dependency_missing: list[dict[str, str]] = []
    entries_with_missing_tools: list[dict[str, str]] = []
    tool_routing_gap: list[dict[str, str]] = []
    mcp_considered: list[dict[str, str]] = []
    mcp_used: list[dict[str, str]] = []
    mcp_skipped_with_reason: list[dict[str, str]] = []
    mcp_absent_without_decision_recorded: list[dict[str, str]] = []
    proof_invalid_solved: list[dict[str, str]] = []
    proof_valid_solved: list[str] = []
    historical_solved: list[str] = []

    for item in items:
        item_id = item["id"]
        by_category[item["category"]] += 1
        by_split[item["split"]] += 1
        agent_mode = item.get("agent_mode")
        if isinstance(agent_mode, str) and agent_mode:
            by_agent_mode[agent_mode] += 1
        else:
            entries_missing_agent_mode.append({"id": item_id, "reason": "missing agent_mode"})
        failure_class = item.get("failure_class")
        if isinstance(failure_class, str) and failure_class:
            failure_taxonomy_counts[failure_class] += 1
        replay_quality = item.get("replay_quality")
        if isinstance(replay_quality, str) and replay_quality:
            replay_quality_counts[replay_quality] += 1
        else:
            replay_quality_unavailable.append(item_id)
        shareability = item.get("shareability")
        if isinstance(shareability, str) and shareability:
            shareability_counts[shareability] += 1
            if shareability.strip().lower() in {"gap", "missing", "none", "not_shareable", "unshareable", "unsafe"}:
                shareability_gaps.append({"id": item_id, "reason": f"shareability={shareability}"})
        else:
            shareability_unavailable.append(item_id)

        dependency_entry = dependency_missing_entry(item)
        if dependency_entry:
            dependency_missing.append(dependency_entry)
        item_missing_tools = missing_tool_names(item)
        if item_missing_tools:
            entries_with_missing_tools.append(
                {"id": item_id, "reason": f"missing tool(s): {', '.join(item_missing_tools)}"}
            )
        item_path = resolve_path(item["path"], base=ROOT)
        path_exists = item_path.exists() if item_path is not None else False
        state: dict[str, Any] | None = None
        state_error: str | None = None

        if item_path is None or not path_exists:
            missing_paths.append({"id": item_id, "path": item["path"]})
            missing_paths_by_split[item["split"]] += 1
        elif item_path.is_dir():
            state, state_error = read_state(item_path)
            if state_error:
                stale_entries.append({"id": item_id, "reason": state_error})

        effective_status = item["status"]
        if state is not None:
            effective_status = normalize_state_status(state.get("status"))
            for field in ("event", "category"):
                state_value = state.get(field)
                if isinstance(state_value, str) and state_value and state_value != item[field]:
                    stale_entries.append(
                        {"id": item_id, "reason": f"{field} corpus={item[field]} state={state_value}"}
                    )
            state_name = state.get("name")
            if isinstance(state_name, str) and state_name and state_name != item["challenge"]:
                stale_entries.append(
                    {"id": item_id, "reason": f"challenge corpus={item['challenge']} state={state_name}"}
                )
            if effective_status != item["status"]:
                stale_entries.append(
                    {"id": item_id, "reason": f"status corpus={item['status']} state={effective_status}"}
                )

        routing = combined_tool_routing(item, state)
        tool_routing_gap.extend(routing_gap_entries(item_id, routing))
        mcp_metrics = routing_mcp_metrics(item_id, routing)
        mcp_considered.extend(mcp_metrics["mcp_considered"])
        mcp_used.extend(mcp_metrics["mcp_used"])
        mcp_skipped_with_reason.extend(mcp_metrics["mcp_skipped_with_reason"])
        mcp_absent_without_decision_recorded.extend(
            mcp_metrics["mcp_absent_without_decision_recorded"]
        )

        outcome_counts[effective_status] += 1
        outcome_by_split[item["split"]][effective_status] += 1

        if effective_status in {"solved", "partial", "blocked"} and not has_sanitized_report(item, item_path, state):
            entries_missing_sanitized_report.append({"id": item_id, "reason": "missing sanitized benchmark report"})

        if effective_status == "solved":
            if state is not None and item_path is not None:
                logs = replay_logs(item_path)
                if not logs:
                    solved_missing_evidence.append({"id": item_id, "reason": "missing evidence/replay_*.log"})
                proof_ok, reason = run_proof_validate(item_path)
                if proof_ok:
                    proof_valid_solved.append(item_id)
                else:
                    proof_invalid_solved.append({"id": item_id, "reason": reason})
            elif expected_artifacts_present(item, base=ROOT):
                historical_solved.append(item_id)
                historical_solved_without_current_proof_valid_replay.append(
                    {"id": item_id, "reason": "historical solved evidence lacks current proof-valid replay"}
                )
            else:
                solved_missing_evidence.append({"id": item_id, "reason": "missing proof state or artifact"})

        if effective_status == "blocked" and state is not None and not blocker_reason(state):
            blocked_missing_reason.append({"id": item_id, "reason": "missing blocker reason"})

    split_health = build_split_health(outcome_by_split, missing_paths_by_split)
    critical = solved_missing_evidence or blocked_missing_reason or proof_invalid_solved
    if critical:
        verdict = "FAIL"
        reason = "false-solved, blocked, or proof-validation risk requires attention"
    elif dependency_missing:
        verdict = "FAIL"
        reason = "required challenge dependencies are missing"
    elif (
        tool_routing_gap
        or missing_paths
        or stale_entries
        or entries_missing_agent_mode
        or entries_missing_sanitized_report
        or historical_solved_without_current_proof_valid_replay
        or shareability_gaps
        or split_health["warnings"]
    ):
        verdict = "READY_WITH_CAVEATS"
        reason = "corpus is usable, but metadata, reporting, split, missing, stale, or routing caveats need follow-up"
    else:
        verdict = "READY"
        reason = "corpus has no current evaluation blockers"

    return {
        "total_challenges": len(items),
        "by_category": sorted_counter(by_category),
        "by_split": sorted_counter(by_split),
        "by_agent_mode": sorted_counter(by_agent_mode),
        "entries_missing_agent_mode": entries_missing_agent_mode,
        "failure_taxonomy_counts": sorted_counter(failure_taxonomy_counts),
        "split_health": split_health,
        "replay_quality_summary": {
            "counts": sorted_counter(replay_quality_counts),
            "unavailable_count": len(replay_quality_unavailable),
            "unavailable_ids": sorted(replay_quality_unavailable),
        },
        "shareability_summary": {
            "counts": sorted_counter(shareability_counts),
            "gap_count": len(shareability_gaps),
            "gap_entries": unique_records(shareability_gaps),
            "unavailable_count": len(shareability_unavailable),
            "unavailable_ids": sorted(shareability_unavailable),
        },
        "entries_missing_sanitized_report": unique_records(entries_missing_sanitized_report),
        "historical_solved_without_current_proof_valid_replay": unique_records(
            historical_solved_without_current_proof_valid_replay
        ),
        "performance_metrics_availability": performance_availability(items),
        "outcome_counts": sorted_counter(outcome_counts),
        "proof_valid_solved_count": len(proof_valid_solved),
        "proof_valid_solved_ids": proof_valid_solved,
        "historical_solved_count": len(historical_solved),
        "historical_solved_ids": historical_solved,
        "solved_entries_missing_evidence": solved_missing_evidence,
        "blocked_entries_missing_blocker_reason": blocked_missing_reason,
        "dependency_missing_count": len(dependency_missing),
        "dependency_missing": dependency_missing,
        "entries_with_missing_tools": unique_records(entries_with_missing_tools),
        "tool_routing_gap": unique_records(tool_routing_gap),
        "mcp_considered": unique_records(mcp_considered),
        "mcp_used": unique_records(mcp_used),
        "mcp_skipped_with_reason": unique_records(mcp_skipped_with_reason),
        "mcp_absent_without_decision_recorded": unique_records(mcp_absent_without_decision_recorded),
        "proof_invalid_solved": proof_invalid_solved,
        "missing_challenge_paths": missing_paths,
        "stale_corpus_entries": stale_entries,
        "readiness_verdict": verdict,
        "readiness_reason": reason,
    }


def print_mapping(title: str, mapping: dict[str, int]) -> None:
    print(f"{title}:")
    if not mapping:
        print("  none")
        return
    for key, value in mapping.items():
        print(f"  {key}: {value}")


def print_items(title: str, items: list[dict[str, str]]) -> None:
    print(f"{title}:")
    if not items:
        print("  none")
        return
    for item in items:
        if "path" in item:
            print(f"  - {item['id']}: {item['path']}")
        elif "tool" in item:
            details = [item["tool"]]
            if "source" in item:
                details.append(f"source={item['source']}")
            if "reason" in item:
                details.append(f"reason={item['reason']}")
            if "retrospective" in item:
                details.append("retrospective=true")
            print(f"  - {item['id']}: {'; '.join(details)}")
        else:
            print(f"  - {item['id']}: {item['reason']}")


def print_split_health(split_health: dict[str, object]) -> None:
    print("split_health:")
    splits = split_health.get("splits")
    if isinstance(splits, dict):
        for split in sorted(splits):
            metrics = splits[split]
            if not isinstance(metrics, dict):
                continue
            details = ", ".join(f"{key}={metrics[key]}" for key in sorted(metrics))
            print(f"  {split}: {details}")
    warnings = split_health.get("warnings")
    print("  warnings:")
    if not isinstance(warnings, list) or not warnings:
        print("    none")
        return
    for warning in warnings:
        if not isinstance(warning, dict):
            continue
        split = warning.get("split", "unknown")
        reason = warning.get("reason", "unknown")
        print(f"    - {split}: {reason}")


def print_summary(title: str, summary: dict[str, object]) -> None:
    print(f"{title}:")
    counts = summary.get("counts")
    if isinstance(counts, dict):
        print("  counts:")
        if counts:
            for key in sorted(counts):
                print(f"    {key}: {counts[key]}")
        else:
            print("    none")
    for key in sorted(summary):
        if key == "counts":
            continue
        value = summary[key]
        if isinstance(value, list):
            printable = ", ".join(str(entry) for entry in value) if value else "none"
            print(f"  {key}: {printable}")
        else:
            print(f"  {key}: {value}")


def print_performance_availability(availability: dict[str, dict[str, object]]) -> None:
    print("performance_metrics_availability:")
    if not availability:
        print("  none")
        return
    for field in sorted(availability):
        metrics = availability[field]
        available = metrics.get("available_count", 0)
        unavailable = metrics.get("unavailable_count", 0)
        print(f"  {field}: available={available}, unavailable={unavailable}")


def print_report(metrics: dict[str, Any]) -> None:
    print("# Level 6 Corpus Evaluation")
    print(f"total_challenges: {metrics['total_challenges']}")
    print_mapping("by_category", metrics["by_category"])
    print_mapping("by_split", metrics["by_split"])
    print_mapping("by_agent_mode", metrics["by_agent_mode"])
    print_items("entries_missing_agent_mode", metrics["entries_missing_agent_mode"])
    print_mapping("failure_taxonomy_counts", metrics["failure_taxonomy_counts"])
    print_split_health(metrics["split_health"])
    print_summary("replay_quality_summary", metrics["replay_quality_summary"])
    print_summary("shareability_summary", metrics["shareability_summary"])
    print_items("entries_missing_sanitized_report", metrics["entries_missing_sanitized_report"])
    print_items(
        "historical_solved_without_current_proof_valid_replay",
        metrics["historical_solved_without_current_proof_valid_replay"],
    )
    print_performance_availability(metrics["performance_metrics_availability"])
    print_mapping("outcome_counts", metrics["outcome_counts"])
    print(f"proof_valid_solved_count: {metrics['proof_valid_solved_count']}")
    print(f"historical_solved_count: {metrics['historical_solved_count']}")
    print_items("solved_entries_missing_evidence", metrics["solved_entries_missing_evidence"])
    print_items("blocked_entries_missing_blocker_reason", metrics["blocked_entries_missing_blocker_reason"])
    print(f"dependency_missing_count: {metrics['dependency_missing_count']}")
    print_items("dependency_missing", metrics["dependency_missing"])
    print_items("entries_with_missing_tools", metrics["entries_with_missing_tools"])
    print_items("tool_routing_gap", metrics["tool_routing_gap"])
    print_items("mcp_considered", metrics["mcp_considered"])
    print_items("mcp_used", metrics["mcp_used"])
    print_items("mcp_skipped_with_reason", metrics["mcp_skipped_with_reason"])
    print_items("mcp_absent_without_decision_recorded", metrics["mcp_absent_without_decision_recorded"])
    print_items("proof_invalid_solved", metrics["proof_invalid_solved"])
    print_items("missing_challenge_paths", metrics["missing_challenge_paths"])
    print_items("stale_corpus_entries", metrics["stale_corpus_entries"])
    print(f"readiness_verdict: {metrics['readiness_verdict']}")
    print(f"readiness_reason: {metrics['readiness_reason']}")


def main() -> int:
    args = parse_args()
    corpus_path = Path(args.corpus).expanduser()
    if not corpus_path.is_absolute():
        corpus_path = ROOT / corpus_path
    corpus_path = corpus_path.resolve()
    items = load_corpus(corpus_path)
    metrics = evaluate(items)
    if args.json:
        print(json.dumps(metrics, indent=2, sort_keys=True))
    else:
        print_report(metrics)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
