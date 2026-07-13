#!/usr/bin/env python3
"""Aggregate receipts produced by user-opened Sol sessions; never launch a model."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics
import sys


REQUIRED = {"fixture", "mode", "solved", "verified_flag", "elapsed_seconds", "child_agents", "cleanup_success"}


def load_receipts(paths: list[Path]) -> list[dict[str, object]]:
    receipts: list[dict[str, object]] = []
    for path in paths:
        values = json.loads(path.read_text(encoding="utf-8"))
        batch = values if isinstance(values, list) else [values]
        for value in batch:
            missing = REQUIRED.difference(value) if isinstance(value, dict) else REQUIRED
            if not isinstance(value, dict) or missing:
                raise ValueError(f"{path}: invalid receipt; missing {sorted(missing)}")
            if value["mode"] not in {"solo", "adaptive"}:
                raise ValueError(f"{path}: mode must be solo or adaptive")
            receipts.append(value)
    return receipts


def summarize(receipts: list[dict[str, object]]) -> dict[str, object]:
    solo_fixtures = {str(row["fixture"]) for row in receipts if row["mode"] == "solo"}
    adaptive_fixtures = {str(row["fixture"]) for row in receipts if row["mode"] == "adaptive"}
    paired_fixtures = sorted(solo_fixtures.intersection(adaptive_fixtures))
    paired = [row for row in receipts if str(row["fixture"]) in paired_fixtures]
    modes: dict[str, object] = {}
    for mode in ("solo", "adaptive"):
        rows = [row for row in paired if row["mode"] == mode]
        solved = [row for row in rows if row["solved"] and row["verified_flag"]]
        modes[mode] = {
            "runs": len(rows),
            "verified_solved": len(solved),
            "solve_rate": len(solved) / len(rows) if rows else None,
            "median_elapsed_seconds": statistics.median(float(row["elapsed_seconds"]) for row in solved) if solved else None,
            "mean_child_agents": statistics.mean(int(row["child_agents"]) for row in rows) if rows else None,
            "mean_context_bytes": statistics.mean(int(row.get("context_bytes", 0)) for row in rows) if rows else None,
        }
    solo, adaptive = modes["solo"], modes["adaptive"]
    comparable = bool(paired_fixtures and solo["runs"] and adaptive["runs"])
    improvement = False
    if comparable:
        improvement = bool(
            adaptive["solve_rate"] > solo["solve_rate"]
            or (
                adaptive["solve_rate"] == solo["solve_rate"]
                and adaptive["median_elapsed_seconds"] is not None
                and solo["median_elapsed_seconds"] is not None
                and adaptive["median_elapsed_seconds"] < solo["median_elapsed_seconds"]
            )
            or (
                adaptive["solve_rate"] == solo["solve_rate"]
                and adaptive["mean_context_bytes"] < solo["mean_context_bytes"]
            )
            or (
                adaptive["solve_rate"] == solo["solve_rate"]
                and adaptive["mean_child_agents"] < solo["mean_child_agents"]
            )
        )
    return {
        "schema_version": 1, "paired_fixtures": paired_fixtures,
        "modes": modes, "comparable": comparable,
        "adaptive_improvement_observed": improvement,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("receipts", nargs="+", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = summarize(load_receipts(args.receipts))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 2
    text = json.dumps({"ok": True, "result": result}, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
