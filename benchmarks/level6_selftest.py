#!/usr/bin/env python3
"""Run Level 6 evaluation acceptance checks."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    print(f"level6_selftest: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(command: list[str], *, expect_ok: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
    if expect_ok and result.returncode != 0:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        fail(f"command failed: {' '.join(command)}")
    if not expect_ok and result.returncode == 0:
        print(result.stdout, end="")
        fail(f"command unexpectedly succeeded: {' '.join(command)}")
    return result


def state(status: str, *, final_command: str = "", proof_scope: str = "none", blocker: str = "") -> dict[str, object]:
    return {
        "event": "level6-selftest",
        "category": "misc",
        "name": "fixture",
        "status": status,
        "final_command": final_command,
        "blocker": blocker,
        "evidence": [],
        "metadata": {
            "proof_scope": proof_scope,
            "remote_status": "not_attempted",
            "remote_solve": "not_attempted",
            "replay_kind": "local",
            "current_remote_liveness": "not_applicable",
            "evidence_sensitivity": "no_sensitive_markers",
        },
    }


def write_state(path: Path, data: dict[str, object], *, category: str, name: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "evidence").mkdir(exist_ok=True)
    data = {**data, "category": category, "name": name}
    (path / "state.json").write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_corpus(path: Path, items: list[dict[str, object]]) -> None:
    # JSON is valid YAML, keeps the fixture deterministic, and avoids hand-written
    # quoting for absolute tempfile paths.
    path.write_text(json.dumps({"schema_version": 1, "items": items}, indent=2) + "\n", encoding="utf-8")


def corpus_item(
    *,
    item_id: str,
    category: str,
    challenge: str,
    path: Path,
    split: str,
    status: str,
    tags: list[str] | None = None,
) -> dict[str, object]:
    return {
        "id": item_id,
        "event": "level6-selftest",
        "category": category,
        "challenge": challenge,
        "path": path.as_posix(),
        "split": split,
        "status": status,
        "difficulty": "unknown",
        "tags": tags or ["selftest"],
        "expected_artifacts": ["state.json", "replay.sh", "notes.md"],
        "notes": "temporary Level 6 selftest fixture",
    }


def assert_evaluate_corpus(temp_root: Path) -> None:
    solved_path = temp_root / "challenges" / "level6-selftest" / "pwn" / "solved-no-evidence"
    blocked_path = temp_root / "challenges" / "level6-selftest" / "web" / "blocked-no-reason"
    planned_path = temp_root / "challenges" / "level6-selftest" / "crypto" / "planned-existing"
    missing_path = temp_root / "challenges" / "level6-selftest" / "rev" / "missing"

    write_state(solved_path, state("solved", final_command="./replay.sh", proof_scope="local"), category="pwn", name="solved-no-evidence")
    write_state(blocked_path, state("blocked"), category="web", name="blocked-no-reason")
    write_state(planned_path, state("new"), category="crypto", name="planned-existing")

    corpus_path = temp_root / "corpus.yaml"
    write_corpus(
        corpus_path,
        [
            corpus_item(
                item_id="solved-no-evidence",
                category="pwn",
                challenge="solved-no-evidence",
                path=solved_path,
                split="design",
                status="solved",
            ),
            corpus_item(
                item_id="blocked-no-reason",
                category="web",
                challenge="blocked-no-reason",
                path=blocked_path,
                split="holdout",
                status="blocked",
            ),
            corpus_item(
                item_id="planned-existing",
                category="crypto",
                challenge="planned-existing",
                path=planned_path,
                split="regression",
                status="planned",
            ),
            corpus_item(
                item_id="missing-path",
                category="rev",
                challenge="missing",
                path=missing_path,
                split="holdout",
                status="planned",
            ),
        ],
    )

    result = run(["python3", "tools/evaluate_corpus.py", "--corpus", corpus_path.as_posix(), "--json"])
    if "FLAG{" in result.stdout:
        fail("evaluate_corpus emitted a raw flag marker")
    metrics = json.loads(result.stdout)

    if metrics["total_challenges"] != 4:
        fail("evaluate_corpus reported the wrong total challenge count")
    for category in ("pwn", "web", "crypto", "rev"):
        if metrics["by_category"].get(category) != 1:
            fail(f"evaluate_corpus category count missing {category}")
    for split in ("design", "holdout", "regression"):
        if split not in metrics["by_split"]:
            fail(f"evaluate_corpus split count missing {split}")
    if not any(item["id"] == "solved-no-evidence" for item in metrics["solved_entries_missing_evidence"]):
        fail("solved without proof evidence was not flagged")
    if not any(item["id"] == "blocked-no-reason" for item in metrics["blocked_entries_missing_blocker_reason"]):
        fail("blocked without blocker reason was not flagged")
    if not any(item["id"] == "missing-path" for item in metrics["missing_challenge_paths"]):
        fail("missing challenge path was not reported")
    if metrics["readiness_verdict"] != "FAIL":
        fail("invalid selftest corpus did not produce a FAIL readiness verdict")


def assert_regression_check_skips_replay(temp_root: Path) -> None:
    corpus_path = temp_root / "safe-corpus.yaml"
    planned_path = temp_root / "challenges" / "level6-selftest" / "misc" / "planned-only"
    write_corpus(
        corpus_path,
        [
            corpus_item(
                item_id="planned-only",
                category="misc",
                challenge="planned-only",
                path=planned_path,
                split="design",
                status="planned",
            )
        ],
    )
    result = run(["python3", "tools/regression_check.py", "--corpus", corpus_path.as_posix()])
    if "replay: skipped (use --run-replay)" not in result.stdout:
        fail("regression_check did not report replay as skipped by default")
    if "check replay:" in result.stdout:
        fail("regression_check ran replay by default")
    if "FLAG{" in result.stdout:
        fail("regression_check emitted a raw flag marker")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="level6-selftest-") as dirname:
        temp_root = Path(dirname)
        assert_evaluate_corpus(temp_root)
        assert_regression_check_skips_replay(temp_root)
    print("level6 selftest ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
