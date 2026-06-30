#!/usr/bin/env python3
"""Evaluate the benchmark corpus without mutating challenge state."""

from __future__ import annotations

import argparse
import json
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
    return {
        **raw,
        "tags": as_list(raw["tags"], "tags", item_id),
        "expected_artifacts": as_list(raw["expected_artifacts"], "expected_artifacts", item_id),
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


def evaluate(items: list[dict[str, Any]]) -> dict[str, Any]:
    by_category: Counter[str] = Counter()
    by_split: Counter[str] = Counter()
    outcome_counts: Counter[str] = Counter({status: 0 for status in sorted(VALID_STATUSES)})
    missing_paths: list[dict[str, str]] = []
    stale_entries: list[dict[str, str]] = []
    solved_missing_evidence: list[dict[str, str]] = []
    blocked_missing_reason: list[dict[str, str]] = []
    proof_invalid_solved: list[dict[str, str]] = []
    proof_valid_solved: list[str] = []
    historical_solved: list[str] = []

    for item in items:
        item_id = item["id"]
        by_category[item["category"]] += 1
        by_split[item["split"]] += 1
        item_path = resolve_path(item["path"], base=ROOT)
        path_exists = item_path.exists() if item_path is not None else False
        state: dict[str, Any] | None = None
        state_error: str | None = None

        if item_path is None or not path_exists:
            missing_paths.append({"id": item_id, "path": item["path"]})
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

        outcome_counts[effective_status] += 1

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
            else:
                solved_missing_evidence.append({"id": item_id, "reason": "missing proof state or artifact"})

        if effective_status == "blocked" and state is not None and not blocker_reason(state):
            blocked_missing_reason.append({"id": item_id, "reason": "missing blocker reason"})

    critical = solved_missing_evidence or blocked_missing_reason or proof_invalid_solved
    if critical:
        verdict = "FAIL"
        reason = "false-solved, blocked, or proof-validation risk requires attention"
    elif missing_paths or stale_entries:
        verdict = "READY_WITH_CAVEATS"
        reason = "corpus is usable, but planned/missing/stale entries need follow-up"
    else:
        verdict = "READY"
        reason = "corpus has no current evaluation blockers"

    return {
        "total_challenges": len(items),
        "by_category": sorted_counter(by_category),
        "by_split": sorted_counter(by_split),
        "outcome_counts": sorted_counter(outcome_counts),
        "proof_valid_solved_count": len(proof_valid_solved),
        "proof_valid_solved_ids": proof_valid_solved,
        "historical_solved_count": len(historical_solved),
        "historical_solved_ids": historical_solved,
        "solved_entries_missing_evidence": solved_missing_evidence,
        "blocked_entries_missing_blocker_reason": blocked_missing_reason,
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
        else:
            print(f"  - {item['id']}: {item['reason']}")


def print_report(metrics: dict[str, Any]) -> None:
    print("# Level 6 Corpus Evaluation")
    print(f"total_challenges: {metrics['total_challenges']}")
    print_mapping("by_category", metrics["by_category"])
    print_mapping("by_split", metrics["by_split"])
    print_mapping("outcome_counts", metrics["outcome_counts"])
    print(f"proof_valid_solved_count: {metrics['proof_valid_solved_count']}")
    print(f"historical_solved_count: {metrics['historical_solved_count']}")
    print_items("solved_entries_missing_evidence", metrics["solved_entries_missing_evidence"])
    print_items("blocked_entries_missing_blocker_reason", metrics["blocked_entries_missing_blocker_reason"])
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
