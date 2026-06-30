#!/usr/bin/env python3
"""Query local category reference indexes with challenge evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
INDEX_DIR = ROOT / "docs" / "reference-index"


def fail(message: str, code: int = 1) -> None:
    print(f"reference_query: {message}", file=sys.stderr)
    raise SystemExit(code)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--category", required=True, help="category index to query")
    parser.add_argument("--evidence", required=True, help="evidence text or workspace/challenge-relative file path")
    parser.add_argument("--limit", type=int, default=8)
    parser.add_argument("--json", action="store_true", help="emit JSON")
    return parser.parse_args()


def tokenize(text: str) -> set[str]:
    return {item.lower() for item in re.findall(r"[A-Za-z0-9][A-Za-z0-9_+.-]{1,}", text)}


def read_evidence(value: str) -> str:
    candidate = Path(value)
    paths = []
    if candidate.is_absolute():
        paths.append(candidate)
    else:
        paths.append(ROOT / candidate)
        paths.append(Path.cwd() / candidate)
    for path in paths:
        try:
            resolved = path.resolve()
            resolved.relative_to(ROOT.resolve())
        except (OSError, ValueError):
            continue
        if resolved.is_file():
            return resolved.read_text(encoding="utf-8", errors="replace")[:200_000]
    return value


def load_index(category: str) -> dict[str, Any]:
    path = INDEX_DIR / f"{category}.json"
    if not path.is_file():
        fail(f"missing reference index: {path.relative_to(ROOT)}", code=2)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid reference index: {exc}", code=2)
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        fail(f"invalid reference index shape: {path.relative_to(ROOT)}", code=2)
    return data


def entry_terms(entry: dict[str, Any]) -> set[str]:
    values: list[str] = []
    for key in ("id", "ref_id", "title", "kind", "applies_when", "file"):
        value = entry.get(key)
        if isinstance(value, str):
            values.append(value)
    for key in ("tags", "query_terms"):
        value = entry.get(key)
        if isinstance(value, list):
            values.extend(str(item) for item in value if isinstance(item, str))
    return tokenize(" ".join(values))


def score_entry(query_terms: set[str], entry: dict[str, Any]) -> int:
    terms = entry_terms(entry)
    overlap = query_terms & terms
    score = len(overlap) * 4
    for term in query_terms:
        if term in str(entry.get("ref_id", "")).lower():
            score += 5
        if term in str(entry.get("title", "")).lower():
            score += 3
        if term in str(entry.get("file", "")).lower():
            score += 2
    return score


def result_for(entry: dict[str, Any], score: int) -> dict[str, Any]:
    keys = (
        "id",
        "category",
        "ref_id",
        "license",
        "commit",
        "local_path",
        "file",
        "line_start",
        "line_end",
        "title",
        "kind",
        "tags",
        "applies_when",
        "url",
    )
    result = {key: entry.get(key) for key in keys if key in entry}
    result["score"] = score
    if result.get("local_path") and result.get("file"):
        result["workspace_path"] = f"{result['local_path']}/{result['file']}"
    return result


def query(category: str, evidence: str, limit: int) -> dict[str, Any]:
    data = load_index(category)
    evidence_text = read_evidence(evidence)
    terms = tokenize(evidence_text)
    ranked = []
    for entry in data["entries"]:
        if not isinstance(entry, dict):
            continue
        score = score_entry(terms, entry)
        if score > 0:
            ranked.append(result_for(entry, score))
    ranked.sort(key=lambda item: (-int(item["score"]), str(item.get("ref_id", "")), str(item.get("id", ""))))
    return {
        "schema_version": 1,
        "category": category,
        "query": evidence if len(evidence) < 240 else evidence[:240],
        "query_terms": sorted(terms)[:80],
        "results": ranked[: max(1, limit)],
    }


def main() -> int:
    args = parse_args()
    data = query(args.category, args.evidence, args.limit)
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True))
    else:
        for item in data["results"]:
            location = item.get("workspace_path") or item.get("url", "")
            print(f"{item['score']:>3} {item.get('id')} {location}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
