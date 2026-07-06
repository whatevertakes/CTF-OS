#!/usr/bin/env python3
"""Run safe local regression checks for the CTF workspace."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - preflight requires PyYAML.
    yaml = None


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = ROOT / "benchmarks" / "corpus.yaml"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS), help="path to corpus YAML")
    parser.add_argument("--run-replay", action="store_true", help="explicitly run local replay for existing corpus paths")
    parser.add_argument(
        "--proof-validate-existing",
        action="store_true",
        help="also run proof_validate.py on every existing corpus challenge path with state.json",
    )
    return parser.parse_args()


def rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def run_check(name: str, command: list[str]) -> subprocess.CompletedProcess[str]:
    print(f"check {name}: {' '.join(command)}")
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
    if result.stdout.strip():
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
    if result.stderr.strip():
        print(result.stderr, end="" if result.stderr.endswith("\n") else "\n", file=sys.stderr)
    if result.returncode == 0:
        print(f"PASS {name}")
    else:
        print(f"FAIL {name} returncode={result.returncode}")
    return result


def python_files() -> list[str]:
    paths = sorted(ROOT.glob("tools/*.py")) + sorted(ROOT.glob("benchmarks/*.py"))
    return [rel(path) for path in paths]


def load_corpus_paths(corpus_path: Path) -> list[Path]:
    if yaml is None:
        return []
    try:
        with corpus_path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except OSError:
        return []
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        return []
    paths: list[Path] = []
    for item in data["items"]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            continue
        raw = Path(item["path"]).expanduser()
        path = raw if raw.is_absolute() else ROOT / raw
        if path.is_dir() and (path / "state.json").is_file():
            paths.append(path.resolve())
    return sorted(set(paths))


def load_all_challenge_state_paths() -> list[Path]:
    return sorted(path.parent.resolve() for path in (ROOT / "challenges").glob("**/state.json"))


def critical_evaluation_findings(metrics: dict[str, object]) -> list[str]:
    failures: list[str] = []
    for key in (
        "solved_entries_missing_evidence",
        "blocked_entries_missing_blocker_reason",
        "dependency_missing",
        "proof_invalid_solved",
    ):
        value = metrics.get(key)
        if isinstance(value, list) and value:
            failures.append(key)
    return failures


def main() -> int:
    args = parse_args()
    corpus_path = Path(args.corpus).expanduser()
    if not corpus_path.is_absolute():
        corpus_path = ROOT / corpus_path
    corpus_path = corpus_path.resolve()

    failures = 0
    compile_result = run_check("py_compile", ["python3", "-m", "py_compile", *python_files()])
    failures += compile_result.returncode != 0

    preflight_result = run_check("preflight_check", ["python3", "tools/preflight_check.py"])
    failures += preflight_result.returncode != 0

    level5_result = run_check("level5_selftest", ["python3", "benchmarks/level5_selftest.py"])
    failures += level5_result.returncode != 0

    evaluate_result = run_check(
        "evaluate_corpus",
        ["python3", "tools/evaluate_corpus.py", "--corpus", corpus_path.as_posix(), "--json"],
    )
    failures += evaluate_result.returncode != 0
    if evaluate_result.returncode == 0:
        try:
            metrics = json.loads(evaluate_result.stdout)
        except json.JSONDecodeError:
            print("FAIL evaluate_corpus_json invalid JSON")
            failures += 1
        else:
            critical = critical_evaluation_findings(metrics)
            if critical:
                print(f"FAIL evaluate_corpus critical_findings={', '.join(critical)}")
                failures += 1
            else:
                print("PASS evaluate_corpus critical findings clear")

    proof_paths = load_all_challenge_state_paths()
    if args.proof_validate_existing:
        proof_paths = sorted(set(proof_paths) | set(load_corpus_paths(corpus_path)))
    for path in proof_paths:
        result = run_check("proof_validate_existing", ["python3", "tools/proof_validate.py", path.as_posix()])
        failures += result.returncode != 0

    if args.run_replay:
        for path in load_corpus_paths(corpus_path):
            result = run_check("replay", ["python3", "tools/replay_runner.py", path.as_posix()])
            failures += result.returncode != 0
    else:
        print("replay: skipped (use --run-replay)")

    if failures:
        print(f"regression_check: FAIL failures={failures}")
        return 1
    print("regression_check: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
