#!/usr/bin/env python3
"""Print the Level 6 failure taxonomy without modifying files."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TAXONOMY_PATH = ROOT / "docs" / "FAILURE_TAXONOMY.md"
TAXONOMY = [
    ("env_missing", "Required local runtime, service, file, container, or emulator is missing."),
    ("dependency_missing", "A specific library, package, plugin, or challenge-specific toolchain is missing."),
    ("wrong_hypothesis", "The current theory of the challenge is contradicted by evidence."),
    ("primitive_gap", "The broad direction is right but a necessary primitive is absent."),
    ("leak_missing", "Exploitation or recovery needs a leak that has not been obtained."),
    ("exploit_unstable", "The solve path works intermittently or only under narrow timing/state."),
    ("remote_env_mismatch", "Local proof differs from remote behavior."),
    ("search_explosion", "Candidate space is too large without better pruning or batching."),
    ("replay_gap", "The final action cannot be repeated through the replay contract."),
    ("evidence_gap", "The state claim lacks supporting files, paths, or summaries."),
    ("false_success_risk", "The current result could be mistaken for solved without proof."),
    ("timeout", "Work stopped due to time budget rather than a technical conclusion."),
    ("unknown", "Failure is not yet classified."),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit built-in taxonomy as JSON")
    return parser.parse_args()


def render_builtin() -> str:
    lines = [
        "# Failure Taxonomy",
        "",
        "docs/FAILURE_TAXONOMY.md is missing; emitting the built-in read-only taxonomy.",
        "",
        "| Label | Meaning |",
        "| --- | --- |",
    ]
    for label, meaning in TAXONOMY:
        lines.append(f"| `{label}` | {meaning} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    if args.json:
        print(json.dumps([{"id": label, "meaning": meaning} for label, meaning in TAXONOMY], indent=2))
        return 0
    if TAXONOMY_PATH.is_file():
        print(TAXONOMY_PATH.read_text(encoding="utf-8"), end="")
    else:
        print(render_builtin(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
