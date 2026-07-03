#!/usr/bin/env python3
"""Check whether locked CTF references are materialized locally."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "references.lock.json"


def fail(message: str, code: int = 1) -> None:
    print(f"check_references: {message}", file=sys.stderr)
    raise SystemExit(code)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", default=str(DEFAULT_LOCK), help="reference lock path")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser.parse_args()


def load_lock(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        fail(f"cannot read lock: {exc}", code=2)
    except json.JSONDecodeError as exc:
        fail(f"invalid lock JSON: {exc}", code=2)
    if not isinstance(data, dict) or not isinstance(data.get("references"), list):
        fail("lock must contain a references list", code=2)
    return data


def main() -> int:
    args = parse_args()
    lock = Path(args.lock).expanduser()
    if not lock.is_absolute():
        lock = ROOT / lock
    data = load_lock(lock.resolve())
    refs = [item for item in data["references"] if isinstance(item, dict)]
    expected = [item for item in refs if isinstance(item.get("materialized_path"), str)]
    missing = []
    present = []
    for item in expected:
        rel_path = str(item["materialized_path"])
        path = ROOT / rel_path
        record = {
            "id": item.get("id", ""),
            "path": rel_path,
            "commit": item.get("materialized_commit") or item.get("commit") or "",
        }
        if path.exists():
            present.append(record)
        else:
            missing.append(record)

    result = {
        "schema_version": 1,
        "references": len(refs),
        "materialized_expected": len(expected),
        "present": len(present),
        "missing": len(missing),
        "missing_references": missing,
    }
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(
            "reference materialization summary "
            f"references={result['references']} "
            f"expected={result['materialized_expected']} "
            f"present={result['present']} "
            f"missing={result['missing']}"
        )
        for item in missing[:50]:
            print(f"MISSING {item['id']} {item['path']}")
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
