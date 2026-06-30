#!/usr/bin/env python3
"""Run Level 3 orchestration acceptance checks across blind fixture categories."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MARKER = ".level3_selftest"
EVENT = "_level3blind"
CATEGORIES = (
    "web",
    "pwn",
    "rev",
    "crypto",
    "forensics",
    "misc",
    "programming",
    "jail",
    "stego",
    "osint",
    "mobile",
    "malware",
    "web3",
    "cloud",
    "container",
    "ai-ml",
    "hardware-rf",
    "side-channel",
    "hybrid",
)
CATEGORY_PRIMARY_WORKER = {
    "web": "auth_session",
    "pwn": "crash_triage",
    "rev": "static_extract",
    "crypto": "math_attack",
    "forensics": "artifact_inventory",
    "misc": "protocol_model",
    "programming": "problem_model",
    "jail": "constraint_model",
    "stego": "carrier_inventory",
    "osint": "source_inventory",
    "mobile": "package_inventory",
    "malware": "static_triage",
    "web3": "contract_inventory",
    "cloud": "scope_inventory",
    "container": "image_inventory",
    "ai-ml": "prompt_context",
    "hardware-rf": "capture_inventory",
    "side-channel": "trace_inventory",
    "hybrid": "boundary_artifact",
}
CATEGORY_REQUIRED_WORKERS = {
    "web": {"auth_session", "source_disclosure", "policy_oracle", "state_mutation", "render_runtime", "ssrf_internal"},
    "pwn": {"env_repro", "crash_triage", "primitive", "exploit_chain", "deadline_remote"},
    "rev": {"static_extract", "dynamic_trace", "symbolic", "patch_verify", "deadline_remote"},
    "crypto": {"parameter_extract", "math_attack", "oracle_model", "solver_verify"},
    "forensics": {"artifact_inventory", "timeline", "carving", "memory_network", "crypto_bridge"},
    "misc": {"protocol_model", "parser_state", "automation_solver", "category_router"},
    "programming": {"problem_model", "solver_build", "remote_runner", "verifier"},
    "jail": {"constraint_model", "payload_search", "environment_delta", "bypass_verify"},
    "stego": {"carrier_inventory", "metadata_streams", "signal_bits", "extraction_chain"},
    "osint": {"source_inventory", "identity_disambiguation", "archive_geo_time", "citation_proof"},
    "mobile": {"package_inventory", "static_decompile", "secret_logic", "protocol_replay"},
    "malware": {"static_triage", "unpack_config", "behavior_model", "safe_verifier"},
    "web3": {"contract_inventory", "state_model", "exploit_transaction", "replay_verify"},
    "cloud": {"scope_inventory", "identity_policy", "service_path", "proof_path"},
    "container": {"image_inventory", "namespace_runtime", "escape_surface", "proof_path"},
    "ai-ml": {"prompt_context", "model_behavior", "tool_chain", "replay_prompt"},
    "hardware-rf": {"capture_inventory", "signal_decode", "protocol_recover", "replay_verify"},
    "side-channel": {"trace_inventory", "leakage_model", "statistical_attack", "verifier"},
    "hybrid": {"boundary_artifact", "handoff_chain", "integrated_replay", "proof_scope"},
}


def fail(message: str) -> None:
    print(f"level3_selftest: {message}", file=sys.stderr)
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


def challenge_path(category: str) -> Path:
    return ROOT / "challenges" / EVENT / category / f"fixture-{category}"


def ensure_clean(path: Path) -> None:
    if not path.exists():
        return
    if not (path / MARKER).is_file():
        fail(f"refusing to overwrite unmarked challenge directory: {path.relative_to(ROOT)}")
    shutil.rmtree(path)


def mark(path: Path) -> None:
    (path / MARKER).write_text("created by benchmarks/level3_selftest.py\n", encoding="utf-8")


def intake(category: str) -> Path:
    path = challenge_path(category)
    ensure_clean(path)
    run(
        [
            "python3",
            "tools/intake_challenge.py",
            "--event",
            EVENT,
            "--category",
            category,
            "--name",
            f"fixture-{category}",
        ]
    )
    mark(path)
    return path


def load_json(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        fail(f"JSON root is not an object: {path.relative_to(ROOT)}")
    return data


def write_json(path: Path, data: dict[str, object]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_jsonl(path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            fail(f"invalid JSONL at {path.relative_to(ROOT)}:{index}: {exc}")
        if not isinstance(record, dict):
            fail(f"JSONL record is not an object at {path.relative_to(ROOT)}:{index}")
        records.append(record)
    return records


def prepare_fixture(path: Path, category: str) -> None:
    (path / "notes.md").write_text(
        "# Blind Level 3 Fixture\n\n"
        f"- category: `{category}`\n"
        "- purpose: validate orchestration, not category-specific exploit success\n",
        encoding="utf-8",
    )
    (path / "replay.sh").write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f"echo level3_fixture_category={category}\n"
        "echo remote_liveness=not_applicable\n",
        encoding="utf-8",
    )
    (path / "replay.sh").chmod(0o755)


def assert_workers(path: Path, category: str) -> str:
    tasks = load_json(path / "work" / "LEVEL3_TASKS.json")
    raw_tasks = tasks.get("tasks")
    if not isinstance(raw_tasks, list):
        fail(f"missing tasks list for {category}")
    workers = {task.get("worker") for task in raw_tasks if isinstance(task, dict)}
    if not {"hypothesis", "evidence"}.issubset(workers):
        fail(f"common workers missing for {category}: {workers}")
    if not CATEGORY_REQUIRED_WORKERS[category].issubset(workers):
        fail(f"category workers missing for {category}: {workers}")
    for task in raw_tasks:
        if not isinstance(task, dict):
            continue
        strategy = task.get("strategy")
        if not isinstance(strategy, dict):
            fail(f"missing v3 strategy for {category}/{task.get('worker')}")
        for key in ("playbook", "tools", "evidence_required", "failure_modes"):
            values = strategy.get(key)
            if not isinstance(values, list) or not values:
                fail(f"missing strategy.{key} for {category}/{task.get('worker')}")
        multi_agent = task.get("multi_agent")
        if not isinstance(multi_agent, dict) or multi_agent.get("spawn_tool") != "multi_agent_v1.spawn_agent":
            fail(f"missing v2 spawn contract for {category}/{task.get('worker')}")
        if multi_agent.get("parallel_safe") is not True:
            fail(f"missing multi_agent.parallel_safe for {category}/{task.get('worker')}")
        if multi_agent.get("orchestrator_merge_required") is not True:
            fail(f"missing multi_agent.orchestrator_merge_required for {category}/{task.get('worker')}")
        if not isinstance(multi_agent.get("result_contract"), str) or "collect/merge" not in str(multi_agent.get("result_contract")):
            fail(f"missing multi_agent.result_contract for {category}/{task.get('worker')}")
        inputs = task.get("inputs")
        if not isinstance(inputs, dict):
            fail(f"missing task inputs for {category}/{task.get('worker')}")
        if not isinstance(inputs.get("skill"), str) or not str(inputs.get("skill")).startswith("skills/ctf-"):
            fail(f"missing category skill input for {category}/{task.get('worker')}")
        if inputs.get("solve_playbook") != "docs/CTF_SOLVE_PLAYBOOKS.md":
            fail(f"missing solve playbook input for {category}/{task.get('worker')}")
        if not isinstance(inputs.get("reference_digest"), str) or not str(inputs.get("reference_digest")).startswith("docs/reference-digests/"):
            fail(f"missing reference digest input for {category}/{task.get('worker')}")
        if not isinstance(inputs.get("reference_index"), str) or not str(inputs.get("reference_index")).startswith("docs/reference-index/"):
            fail(f"missing reference index input for {category}/{task.get('worker')}")
        if inputs.get("reference_query_tool") != "tools/reference_query.py":
            fail(f"missing reference query tool input for {category}/{task.get('worker')}")
        if not isinstance(inputs.get("reference_query_category"), str) or not str(inputs.get("reference_query_category")):
            fail(f"missing reference query category input for {category}/{task.get('worker')}")
        expected = task.get("expected_output")
        if not isinstance(expected, dict) or not isinstance(expected.get("read_receipts"), dict):
            fail(f"missing expected read_receipts for {category}/{task.get('worker')}")
        if not isinstance(expected.get("reference_queries"), list):
            fail(f"missing expected reference_queries for {category}/{task.get('worker')}")
        if not isinstance(expected.get("reference_files_consulted"), list):
            fail(f"missing expected reference_files_consulted for {category}/{task.get('worker')}")
    return CATEGORY_PRIMARY_WORKER[category]


def assert_dispatch(path: Path, category: str, worker: str) -> None:
    dispatch = load_json(path / "work" / "LEVEL3_DISPATCH.json")
    if dispatch.get("spawn_tool") != "multi_agent_v1.spawn_agent":
        fail(f"dispatch spawn tool mismatch for {category}")
    raw_tasks = dispatch.get("tasks")
    if not isinstance(raw_tasks, list) or len(raw_tasks) != 1:
        fail(f"dispatch task count mismatch for {category}")
    task = raw_tasks[0]
    if not isinstance(task, dict) or task.get("worker") != worker:
        fail(f"dispatch worker mismatch for {category}: {task}")
    packet = task.get("packet")
    if not isinstance(packet, str) or not (path / packet).is_file():
        fail(f"dispatch packet missing for {category}: {packet}")
    packet_text = (path / packet).read_text(encoding="utf-8")
    if '"status": "dispatched"' not in packet_text:
        fail(f"dispatch packet does not embed dispatched status for {category}")
    if '"dispatch": {' not in packet_text or '"spawn_tool": "multi_agent_v1.spawn_agent"' not in packet_text:
        fail(f"dispatch packet does not embed dispatch metadata for {category}")
    if "task.inputs.reference_digest" not in packet_text:
        fail(f"dispatch packet does not require reference digest read for {category}")
    if "task.inputs.reference_index" not in packet_text:
        fail(f"dispatch packet does not require reference index read for {category}")
    if "reference_query_tool" not in packet_text:
        fail(f"dispatch packet does not expose reference query tool for {category}")


def task_inputs(path: Path, worker: str) -> dict[str, object]:
    tasks = load_json(path / "work" / "LEVEL3_TASKS.json")
    raw_tasks = tasks.get("tasks")
    if not isinstance(raw_tasks, list):
        fail("missing Level 3 tasks")
    for task in raw_tasks:
        if isinstance(task, dict) and task.get("worker") == worker:
            inputs = task.get("inputs")
            if isinstance(inputs, dict):
                return inputs
    fail(f"missing task inputs for worker {worker}")


def write_worker_result(path: Path, category: str, worker: str) -> Path:
    inputs = task_inputs(path, worker)
    evidence_rel = f"evidence/{category}_seed.md"
    evidence_path = path / evidence_rel
    evidence_path.write_text(
        f"# {category} seed evidence\n\n"
        "This fixture evidence stands in for a worker-observed artifact.\n",
        encoding="utf-8",
    )
    result = {
        "worker": worker,
        "status": "INCONCLUSIVE",
        "facts": [
            {
                "claim": f"{category} fixture has a bounded Level 3 worker fact",
                "target": f"{category}-surface",
                "evidence": [evidence_rel],
            }
        ],
        "negative_results": [
            {
                "target": f"{category}-branch",
                "input_shape": "blind-fixture-negative-family",
                "result_class": "NEGATIVE",
                "evidence": [evidence_rel],
            }
        ],
        "mutations": [
            {
                "target": f"{category}-state",
                "action": "recorded no-op mutation for ledger contract",
                "before": "unchanged",
                "after": "unchanged",
                "evidence": [evidence_rel],
            }
        ],
        "artifacts": [evidence_rel],
        "next_hypotheses": [f"split {category} blind fixture into a narrower branch"],
        "reference_queries": [
            {
                "category": str(inputs.get("reference_query_category")),
                "query": f"{category} fixture seed evidence",
                "status": "no_match",
                "result_count": 0,
            }
        ],
        "reference_files_consulted": [],
        "read_receipts": {
            "skill_read": str(inputs.get("skill")),
            "solve_playbook_read": str(inputs.get("solve_playbook")),
            "reference_digest_read": str(inputs.get("reference_digest")),
            "rules_applied": [
                "read category skill before probing",
                "read solve playbook global loop",
                "read reference digest patterns",
            ],
            "evidence_contract_used": [
                "facts require existing evidence paths",
                "negative_results require existing evidence paths",
                "mutations require mutation ledger evidence",
            ],
        },
        "stop_reason": "fixture branch exhausted",
    }
    result_dir = path / "work" / "level3_results"
    result_dir.mkdir(parents=True, exist_ok=True)
    result_path = result_dir / f"{category}_worker_result.json"
    write_json(result_path, result)
    return result_path


def assert_missing_receipts_rejected(path: Path, category: str, worker: str) -> None:
    evidence_rel = f"evidence/{category}_bad_receipt.md"
    (path / evidence_rel).write_text("# bad receipt fixture\n", encoding="utf-8")
    result = {
        "worker": worker,
        "status": "INCONCLUSIVE",
        "facts": [
            {
                "claim": "this result intentionally lacks read receipts",
                "target": f"{category}-bad-receipt",
                "evidence": [evidence_rel],
            }
        ],
        "negative_results": [],
        "mutations": [],
        "artifacts": [evidence_rel],
        "next_hypotheses": [],
        "stop_reason": "fixture missing read receipts",
    }
    result_dir = path / "work" / "level3_bad_results"
    result_dir.mkdir(parents=True, exist_ok=True)
    result_path = result_dir / f"{category}_bad_receipt.json"
    write_json(result_path, result)
    rel = path.relative_to(ROOT).as_posix()
    bad_rel = result_path.relative_to(path).as_posix()
    failure = run(["python3", "tools/level3_orchestrator.py", "merge", rel, bad_rel], expect_ok=False)
    if "read_receipts" not in failure.stderr:
        fail(f"missing-read-receipts rejection used wrong error for {category}")


def assert_missing_reference_queries_rejected(path: Path, category: str, worker: str) -> None:
    inputs = task_inputs(path, worker)
    evidence_rel = f"evidence/{category}_bad_reference_query.md"
    (path / evidence_rel).write_text("# bad reference query fixture\n", encoding="utf-8")
    result = {
        "worker": worker,
        "status": "INCONCLUSIVE",
        "facts": [
            {
                "claim": "this result intentionally lacks reference queries",
                "target": f"{category}-bad-reference-query",
                "evidence": [evidence_rel],
            }
        ],
        "negative_results": [],
        "mutations": [],
        "artifacts": [evidence_rel],
        "next_hypotheses": [],
        "reference_files_consulted": [],
        "read_receipts": {
            "skill_read": str(inputs.get("skill")),
            "solve_playbook_read": str(inputs.get("solve_playbook")),
            "reference_digest_read": str(inputs.get("reference_digest")),
            "rules_applied": ["read category skill before probing"],
            "evidence_contract_used": ["facts require existing evidence paths"],
        },
        "stop_reason": "fixture missing reference queries",
    }
    result_dir = path / "work" / "level3_bad_results"
    result_dir.mkdir(parents=True, exist_ok=True)
    result_path = result_dir / f"{category}_bad_reference_query.json"
    write_json(result_path, result)
    rel = path.relative_to(ROOT).as_posix()
    bad_rel = result_path.relative_to(path).as_posix()
    failure = run(["python3", "tools/level3_orchestrator.py", "merge", rel, bad_rel], expect_ok=False)
    if "reference_queries" not in failure.stderr:
        fail(f"missing-reference-queries rejection used wrong error for {category}")


def assert_level3_contract(path: Path, category: str) -> None:
    state = load_json(path / "state.json")
    metadata = state.get("metadata")
    if not isinstance(metadata, dict):
        fail(f"missing state metadata for {category}")
    if metadata.get("level3_status") != "evaluated":
        fail(f"level3 status not evaluated for {category}: {metadata.get('level3_status')}")
    if metadata.get("level3_version") != "v3_category_strategy":
        fail(f"level3 version not recorded for {category}: {metadata.get('level3_version')}")
    if not isinstance(metadata.get("level3_dispatch"), str):
        fail(f"level3 dispatch metadata missing for {category}")
    if metadata.get("level3_run_log") != "work/LEVEL3_RUN_LOG.jsonl":
        fail(f"level3 run log metadata missing for {category}")
    if int(metadata.get("level3_score") or 0) < 75:
        fail(f"level3 score too low for {category}: {metadata.get('level3_score')}")
    for relative in (
        "work/LEVEL3_STATE.json",
        "work/LEVEL3_TASKS.json",
        "work/LEVEL3_DISPATCH.json",
        "work/LEVEL3_DISPATCH.md",
        "work/LEVEL3_RUN_LOG.jsonl",
        "work/ATTEMPT_MATRIX.md",
        "work/MUTATION_LEDGER.md",
    ):
        if not (path / relative).exists():
            fail(f"missing {relative} for {category}")
    run_log = load_jsonl(path / "work" / "LEVEL3_RUN_LOG.jsonl")
    events = [record.get("event") for record in run_log]
    for event in ("init", "plan", "dispatch", "assign", "collect", "evaluate"):
        if event not in events:
            fail(f"run log missing {event} event for {category}")
    for record in run_log:
        if not isinstance(record.get("timestamp"), str):
            fail(f"run log record missing timestamp for {category}: {record}")
        if record.get("challenge") != path.relative_to(ROOT).as_posix():
            fail(f"run log challenge mismatch for {category}: {record}")
        if not isinstance(record.get("data"), dict):
            fail(f"run log record missing data object for {category}: {record}")
    evidence = state.get("evidence")
    if not isinstance(evidence, list) or not any(str(item).startswith("evidence/level3_worker_") for item in evidence):
        fail(f"worker evidence was not recorded in state for {category}")


def assert_category_alias() -> None:
    path = ROOT / "challenges" / EVENT / "reverse" / "fixture-reverse-alias"
    ensure_clean(path)
    run(
        [
            "python3",
            "tools/intake_challenge.py",
            "--event",
            EVENT,
            "--category",
            "reverse",
            "--name",
            "fixture-reverse-alias",
        ]
    )
    mark(path)
    prepare_fixture(path, "reverse")
    rel = path.relative_to(ROOT).as_posix()
    run(["python3", "tools/level3_orchestrator.py", "init", rel])
    run(["python3", "tools/level3_orchestrator.py", "plan", rel])
    tasks = load_json(path / "work" / "LEVEL3_TASKS.json")
    if tasks.get("category") != "rev":
        fail(f"category alias reverse did not normalize to rev: {tasks.get('category')}")
    shutil.rmtree(path)
    try:
        path.parent.rmdir()
    except OSError:
        pass


def assert_collect_idempotent(path: Path, category: str, rel: str, results_dir: str) -> None:
    before = load_json(path / "work" / "LEVEL3_STATE.json")
    merged_before = before.get("merged")
    if not isinstance(merged_before, dict):
        fail(f"missing merged state before idempotent check for {category}")
    facts_before = len(merged_before.get("facts") or [])
    negatives_before = len(merged_before.get("negative_results") or [])
    mutations_before = len(merged_before.get("mutations") or [])
    run(["python3", "tools/level3_orchestrator.py", "collect", rel, results_dir])
    after = load_json(path / "work" / "LEVEL3_STATE.json")
    merged_after = after.get("merged")
    if not isinstance(merged_after, dict):
        fail(f"missing merged state after idempotent check for {category}")
    if len(merged_after.get("facts") or []) != facts_before:
        fail(f"collect is not idempotent for facts in {category}")
    if len(merged_after.get("negative_results") or []) != negatives_before:
        fail(f"collect is not idempotent for negatives in {category}")
    if len(merged_after.get("mutations") or []) != mutations_before:
        fail(f"collect is not idempotent for mutations in {category}")


def cleanup(paths: list[Path]) -> None:
    for path in sorted(paths, key=lambda item: len(item.parts), reverse=True):
        if path.exists() and (path / MARKER).is_file():
            shutil.rmtree(path)
    for category in CATEGORIES:
        try:
            (ROOT / "challenges" / EVENT / category).rmdir()
        except OSError:
            pass
    try:
        (ROOT / "challenges" / EVENT).rmdir()
    except OSError:
        pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="leave marked self-test fixtures in place")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    created: list[Path] = []
    try:
        run(["python3", "tools/preflight_check.py", "--strict-optional"])
        assert_category_alias()
        for category in CATEGORIES:
            path = intake(category)
            created.append(path)
            prepare_fixture(path, category)
            rel = path.relative_to(ROOT).as_posix()
            run(["python3", "tools/level3_orchestrator.py", "init", rel, "--category", category])
            run(["python3", "tools/level3_orchestrator.py", "plan", rel, "--category", category])
            worker = assert_workers(path, category)
            packet = run(["python3", "tools/level3_orchestrator.py", "packet", rel, "--worker", worker])
            if f"Level 3 Worker Packet: {worker}" not in packet.stdout:
                fail(f"packet output missing worker header for {category}")
            run(["python3", "tools/level3_orchestrator.py", "dispatch", rel, "--workers", worker])
            assert_dispatch(path, category, worker)
            run(
                [
                    "python3",
                    "tools/level3_orchestrator.py",
                    "assign",
                    rel,
                    "--worker",
                    worker,
                    "--agent-id",
                    f"selftest-{category}-{worker}",
                ]
            )
            result_path = write_worker_result(path, category, worker)
            results_dir = result_path.parent.relative_to(path).as_posix()
            assert_missing_receipts_rejected(path, category, worker)
            assert_missing_reference_queries_rejected(path, category, worker)
            run(["python3", "tools/level3_orchestrator.py", "collect", rel, results_dir])
            assert_collect_idempotent(path, category, rel, results_dir)
            run(["python3", "tools/level3_orchestrator.py", "evaluate", rel, "--run-replay"])
            run(["python3", "tools/proof_validate.py", rel])
            assert_level3_contract(path, category)
    finally:
        if not args.keep:
            cleanup(created)

    print("level3 selftest ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
