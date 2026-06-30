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
    primary_tools_used: list[object] | None = None,
    tools_considered: list[object] | None = None,
    tools_used: list[object] | None = None,
    tools_skipped: list[object] | None = None,
    required_tools: list[object] | None = None,
    missing_tools: list[object] | None = None,
    dependency_status: str = "unknown",
    tool_routing_gap: bool | str = False,
    agent_mode: str | None = None,
    failure_class: str | None = None,
    replay_quality: str | None = None,
    shareability: str | None = None,
    expected_artifacts: list[str] | None = None,
) -> dict[str, object]:
    item: dict[str, object] = {
        "id": item_id,
        "event": "level6-selftest",
        "category": category,
        "challenge": challenge,
        "path": path.as_posix(),
        "split": split,
        "status": status,
        "difficulty": "unknown",
        "tags": tags or ["selftest"],
        "primary_tools_used": primary_tools_used or [],
        "tools_considered": tools_considered or [],
        "tools_used": tools_used or [],
        "tools_skipped": tools_skipped or [],
        "required_tools": required_tools or [],
        "missing_tools": missing_tools or [],
        "dependency_status": dependency_status,
        "tool_routing_gap": tool_routing_gap,
        "expected_artifacts": expected_artifacts or ["state.json", "replay.sh", "notes.md"],
        "notes": "temporary Level 6 selftest fixture",
    }
    if agent_mode is not None:
        item["agent_mode"] = agent_mode
    if failure_class is not None:
        item["failure_class"] = failure_class
    if replay_quality is not None:
        item["replay_quality"] = replay_quality
    if shareability is not None:
        item["shareability"] = shareability
    return item


def assert_evaluate_corpus(temp_root: Path) -> None:
    solved_path = temp_root / "challenges" / "level6-selftest" / "pwn" / "solved-no-evidence"
    blocked_path = temp_root / "challenges" / "level6-selftest" / "web" / "blocked-no-reason"
    planned_path = temp_root / "challenges" / "level6-selftest" / "crypto" / "planned-existing"
    dependency_path = temp_root / "challenges" / "level6-selftest" / "hardware-rf" / "dependency-missing"
    missing_path = temp_root / "challenges" / "level6-selftest" / "rev" / "missing"
    mcp_used_path = temp_root / "challenges" / "level6-selftest" / "rev" / "mcp-used"
    mcp_skipped_path = temp_root / "challenges" / "level6-selftest" / "pwn" / "mcp-skipped"
    non_mcp_path = temp_root / "challenges" / "level6-selftest" / "misc" / "non-mcp-primary"
    routing_gap_path = temp_root / "challenges" / "level6-selftest" / "forensics" / "routing-gap"
    partial_path = temp_root / "challenges" / "level6-selftest" / "misc" / "partial-shareability-gap"
    report_path = temp_root / "benchmarks" / "HISTORICAL_SANITIZED_BENCHMARK_REPORT.md"

    write_state(solved_path, state("solved", final_command="./replay.sh", proof_scope="local"), category="pwn", name="solved-no-evidence")
    write_state(blocked_path, state("blocked"), category="web", name="blocked-no-reason")
    write_state(planned_path, state("new"), category="crypto", name="planned-existing")
    write_state(dependency_path, state("new"), category="hardware-rf", name="dependency-missing")
    write_state(mcp_used_path, state("new"), category="rev", name="mcp-used")
    write_state(mcp_skipped_path, state("new"), category="pwn", name="mcp-skipped")
    write_state(non_mcp_path, state("new"), category="misc", name="non-mcp-primary")
    write_state(routing_gap_path, state("new"), category="forensics", name="routing-gap")
    write_state(partial_path, state("partial"), category="misc", name="partial-shareability-gap")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("# Historical Sanitized Benchmark Report\n\nNo raw flags.\n", encoding="utf-8")

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
                agent_mode="none",
            ),
            corpus_item(
                item_id="dependency-missing",
                category="hardware-rf",
                challenge="dependency-missing",
                path=dependency_path,
                split="regression",
                status="planned",
                tags=["selftest", "avr"],
                required_tools=["ctf-definitely-missing-tool-for-level6-selftest"],
            ),
            corpus_item(
                item_id="mcp-used",
                category="rev",
                challenge="mcp-used",
                path=mcp_used_path,
                split="design",
                status="planned",
                primary_tools_used=[{"tool": "radare2", "kind": "mcp"}],
                tools_used=[{"tool": "radare2", "kind": "mcp", "reason": "control-flow triage"}],
            ),
            corpus_item(
                item_id="mcp-skipped",
                category="pwn",
                challenge="mcp-skipped",
                path=mcp_skipped_path,
                split="holdout",
                status="planned",
                primary_tools_used=["python3"],
                tools_considered=[{"tool": "angr", "kind": "mcp"}],
                tools_skipped=[
                    {
                        "tool": "angr",
                        "kind": "mcp",
                        "reason": "fixture has no symbolic execution surface",
                    }
                ],
            ),
            corpus_item(
                item_id="non-mcp-primary",
                category="misc",
                challenge="non-mcp-primary",
                path=non_mcp_path,
                split="regression",
                status="planned",
                primary_tools_used=["python3", "gdb"],
                tools_used=["python3", "gdb"],
            ),
            corpus_item(
                item_id="routing-gap",
                category="forensics",
                challenge="routing-gap",
                path=routing_gap_path,
                split="regression",
                status="planned",
            ),
            corpus_item(
                item_id="partial-shareability-gap",
                category="misc",
                challenge="partial-shareability-gap",
                path=partial_path,
                split="design",
                status="partial",
                failure_class="shareability_gap",
                shareability="gap",
            ),
            corpus_item(
                item_id="historical-solved-report",
                category="pwn",
                challenge="historical-solved-report",
                path=report_path,
                split="holdout",
                status="solved",
                expected_artifacts=[report_path.as_posix()],
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

    if metrics["total_challenges"] != 11:
        fail("evaluate_corpus reported the wrong total challenge count")
    expected_categories = {
        "pwn": 3,
        "web": 1,
        "crypto": 1,
        "hardware-rf": 1,
        "rev": 2,
        "misc": 2,
        "forensics": 1,
    }
    for category, count in expected_categories.items():
        if metrics["by_category"].get(category) != count:
            fail(f"evaluate_corpus category count wrong for {category}")
    for split in ("design", "holdout", "regression"):
        if split not in metrics["by_split"]:
            fail(f"evaluate_corpus split count missing {split}")
    if not any(item["id"] == "solved-no-evidence" for item in metrics["solved_entries_missing_evidence"]):
        fail("solved without proof evidence was not flagged")
    if not any(item["id"] == "blocked-no-reason" for item in metrics["blocked_entries_missing_blocker_reason"]):
        fail("blocked without blocker reason was not flagged")
    if not any(item["id"] == "missing-path" for item in metrics["missing_challenge_paths"]):
        fail("missing challenge path was not reported")
    if metrics["dependency_missing_count"] != 1:
        fail("missing dependency count was not reported")
    if not any(item["id"] == "dependency-missing" for item in metrics["dependency_missing"]):
        fail("missing dependency entry was not reported")
    if not any(item["id"] == "dependency-missing" for item in metrics["entries_with_missing_tools"]):
        fail("entry with a missing tool was not reported")
    if any(item["id"] == "dependency-missing" for item in metrics["mcp_skipped_with_reason"]):
        fail("missing dependency was incorrectly treated as a skipped MCP tool")
    if not any(item["id"] == "mcp-used" and item["tool"] == "radare2" for item in metrics["mcp_used"]):
        fail("MCP used fixture was not reported")
    if not any(item["id"] == "mcp-skipped" and item["tool"] == "angr" for item in metrics["mcp_skipped_with_reason"]):
        fail("MCP skipped fixture with explicit reason was not reported")
    if not any(item["id"] == "mcp-skipped" and item["tool"] == "angr" for item in metrics["mcp_considered"]):
        fail("MCP considered fixture was not reported")
    if not any(item["id"] == "non-mcp-primary" for item in metrics["mcp_absent_without_decision_recorded"]):
        fail("primary non-MCP fixture did not report absent MCP decision")
    if not any(item["id"] == "routing-gap" for item in metrics["tool_routing_gap"]):
        fail("missing routing data was not reported as tool_routing_gap")
    if metrics["by_agent_mode"].get("none") != 1:
        fail("agent_mode none baseline was not counted")
    if not any(item["id"] == "solved-no-evidence" for item in metrics["entries_missing_agent_mode"]):
        fail("missing agent_mode entries were not reported")
    if metrics["failure_taxonomy_counts"].get("shareability_gap") != 1:
        fail("failure taxonomy count was not reported")
    if metrics["shareability_summary"].get("gap_count") != 1:
        fail("shareability gap was not summarized")
    if not any(
        item["id"] == "partial-shareability-gap"
        for item in metrics["shareability_summary"].get("gap_entries", [])
    ):
        fail("shareability gap entry was not reported")
    if not any(
        item["id"] == "partial-shareability-gap"
        for item in metrics["entries_missing_sanitized_report"]
    ):
        fail("missing sanitized report was not reported")
    if not any(
        item["id"] == "historical-solved-report"
        for item in metrics["historical_solved_without_current_proof_valid_replay"]
    ):
        fail("historical solved without current proof-valid replay was not reported")
    split_warnings = metrics["split_health"].get("warnings", [])
    if not any("missing challenge paths" in item.get("reason", "") for item in split_warnings):
        fail("split health missing-path warning was not reported")
    if not any("only planned" in item.get("reason", "") for item in split_warnings):
        fail("split health planned-only warning was not reported")
    if metrics["performance_metrics_availability"]["time_metrics"]["available_count"] != 0:
        fail("missing time metrics were not reported as unavailable")
    if metrics["performance_metrics_availability"]["time_metrics"]["unavailable_count"] != metrics["total_challenges"]:
        fail("time metric unavailable count did not match the fixture corpus")
    text_result = run(["python3", "tools/evaluate_corpus.py", "--corpus", corpus_path.as_posix()])
    for expected_text in (
        "dependency_missing",
        "tool_routing_gap",
        "mcp_skipped_with_reason",
        "by_agent_mode",
        "failure_taxonomy_counts",
        "split_health",
        "shareability_summary",
        "entries_missing_sanitized_report",
        "historical_solved_without_current_proof_valid_replay",
        "performance_metrics_availability",
    ):
        if expected_text not in text_result.stdout:
            fail(f"text evaluate_corpus report did not include {expected_text}")
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
