from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any


def append_evidence(path: Path, event: str, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {"timestamp": datetime.now(timezone.utc).isoformat(), "event": event, **payload}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def append_finding(root: Path, branch: str, summary: str, evidence: str, status: str) -> dict[str, object]:
    allowed = {"supported", "rejected", "inconclusive"}
    if status not in allowed:
        raise ValueError(f"finding status must be one of {sorted(allowed)}")
    record: dict[str, object] = {
        "timestamp": datetime.now(timezone.utc).isoformat(), "branch": branch,
        "summary": summary, "evidence": evidence, "status": status,
    }
    with (root / "findings.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    with (root / "FINDINGS.md").open("a", encoding="utf-8") as handle:
        handle.write(f"\n## {summary}\n\n- Branch: `{branch}`\n- Status: **{status}**\n- Evidence: {evidence}\n")
    return record
