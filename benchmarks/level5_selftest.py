#!/usr/bin/env python3
"""Run Level 5 bounded automation acceptance checks."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MARKER = ".level5_selftest"


def fail(message: str) -> None:
    print(f"level5_selftest: {message}", file=sys.stderr)
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


def load_json(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        fail(f"JSON root is not an object: {path.relative_to(ROOT)}")
    return data


def write_json(path: Path, data: dict[str, object]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def ensure_clean(path: Path) -> None:
    if not path.exists():
        return
    if not (path / MARKER).is_file():
        fail(f"refusing to overwrite unmarked self-test path: {path.relative_to(ROOT)}")
    shutil.rmtree(path)


def mark(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / MARKER).write_text("created by benchmarks/level5_selftest.py\n", encoding="utf-8")
    (path / ".selftest-artifact").write_text("temporary selftest fixture\n", encoding="utf-8")


def assert_replay_file_contract(path: Path) -> None:
    replay = path / "replay.sh"
    if not replay.is_file():
        fail(f"{path.relative_to(ROOT)} missing replay.sh")
    if not os.access(replay, os.X_OK):
        fail(f"{path.relative_to(ROOT)}/replay.sh is not executable")
    first_line = replay.read_text(encoding="utf-8", errors="replace").splitlines()[:1]
    if not first_line or not first_line[0].startswith("#!"):
        fail(f"{path.relative_to(ROOT)}/replay.sh lacks a shebang")


def intake(event: str, category: str, name: str) -> Path:
    path = ROOT / "challenges" / event / category / name
    ensure_clean(path)
    run(
        [
            "python3",
            "tools/intake_challenge.py",
            "--event",
            event,
            "--category",
            category,
            "--name",
            name,
        ]
    )
    mark(path)
    assert_replay_file_contract(path)
    return path


def latest_replay_log(path: Path) -> Path:
    logs = sorted((path / "evidence").glob("replay_*.log"))
    if not logs:
        fail(f"{path.relative_to(ROOT)} has no replay logs")
    return logs[-1]


def assert_dummy_runner() -> Path:
    result = run(["python3", "tools/benchmark_runner.py", "dummy"])
    for required in (
        "RUN python3 tools/intake_challenge.py",
        "RUN python3 tools/preflight_check.py",
        "RUN python3 tools/replay_runner.py",
        "RUN python3 tools/proof_validate.py",
    ):
        if required not in result.stdout:
            fail(f"benchmark runner did not print command: {required}")
    path = ROOT / "challenges" / "_level5benchmark" / "misc" / "dummy-local"
    report = path / "work" / "BENCHMARK_RUNNER_REPORT.md"
    if not report.is_file():
        fail("benchmark runner did not write report")
    text = report.read_text(encoding="utf-8")
    if "# Benchmark Runner Report" not in text or "This runner does not write `status=solved`" not in text:
        fail("benchmark runner report missing safety text")
    state = load_json(path / "state.json")
    if state.get("status") != "new":
        fail(f"dummy benchmark status changed unexpectedly: {state.get('status')}")
    log_text = latest_replay_log(path).read_text(encoding="utf-8", errors="replace")
    if "command: ./replay.sh" not in log_text:
        fail("replay_runner did not record ./replay.sh as the executed command")
    if "command: bash replay.sh" in log_text:
        fail("replay_runner used bash replay.sh instead of the executable contract")
    return path


def assert_replay_runner_negative_contracts() -> list[Path]:
    created: list[Path] = []

    missing = intake("_level5replay", "misc", "missing-replay")
    created.append(missing)
    (missing / "replay.sh").unlink()
    result = run(["python3", "tools/replay_runner.py", missing.relative_to(ROOT).as_posix()], expect_ok=False)
    if "missing replay script" not in result.stderr:
        fail("missing replay.sh failed for the wrong reason")
    if list((missing / "evidence").glob("replay_*.log")):
        fail("missing replay.sh produced replay evidence")

    non_executable = intake("_level5replay", "misc", "non-executable")
    created.append(non_executable)
    (non_executable / "replay.sh").chmod(0o644)
    result = run(
        ["python3", "tools/replay_runner.py", non_executable.relative_to(ROOT).as_posix()],
        expect_ok=False,
    )
    if "not executable" not in result.stderr:
        fail("non-executable replay.sh failed for the wrong reason")
    if list((non_executable / "evidence").glob("replay_*.log")):
        fail("non-executable replay.sh produced replay evidence")

    no_shebang = intake("_level5replay", "misc", "no-shebang")
    created.append(no_shebang)
    (no_shebang / "replay.sh").write_text("echo no shebang\n", encoding="utf-8")
    (no_shebang / "replay.sh").chmod(0o755)
    result = run(
        ["python3", "tools/replay_runner.py", no_shebang.relative_to(ROOT).as_posix()],
        expect_ok=False,
    )
    if "lacks a shebang" not in result.stderr:
        fail("replay.sh without shebang failed for the wrong reason")
    if list((no_shebang / "evidence").glob("replay_*.log")):
        fail("replay.sh without shebang produced replay evidence")

    return created


def assert_solved_without_replay_evidence_fails() -> Path:
    path = intake("_level5badproof", "misc", "solved-no-replay-evidence")
    state = load_json(path / "state.json")
    state["status"] = "solved"
    state["final_command"] = "./replay.sh"
    metadata = state.get("metadata")
    if not isinstance(metadata, dict):
        fail("metadata is not an object")
    metadata["proof_scope"] = "local"
    write_json(path / "state.json", state)
    result = run(["python3", "tools/proof_validate.py", path.relative_to(ROOT).as_posix()], expect_ok=False)
    if "solved status requires replay proof evidence" not in result.stderr:
        fail("solved without replay evidence failed for the wrong reason")
    return path


def assert_blocked_without_reason_fails() -> Path:
    path = intake("_level5badproof", "misc", "blocked-no-reason")
    state = load_json(path / "state.json")
    state["status"] = "blocked"
    state["blocker"] = ""
    state["blocked_reason"] = ""
    state["blocker_reason"] = ""
    write_json(path / "state.json", state)
    result = run(["python3", "tools/proof_validate.py", path.relative_to(ROOT).as_posix()], expect_ok=False)
    if "blocked status requires non-empty blocker" not in result.stderr:
        fail("blocked without blocker reason failed for the wrong reason")
    return path


def assert_invalid_solved_fails() -> Path:
    path = intake("_level5badproof", "misc", "solved-no-proof")
    state = load_json(path / "state.json")
    state["status"] = "solved"
    state["final_command"] = "./replay.sh"
    metadata = state.get("metadata")
    if not isinstance(metadata, dict):
        fail("metadata is not an object")
    metadata["proof_scope"] = "none"
    write_json(path / "state.json", state)
    rel = path.relative_to(ROOT).as_posix()
    result = run(["python3", "tools/benchmark_runner.py", "run", rel, "--skip-preflight"], expect_ok=False)
    if "RUN python3 tools/proof_validate.py" not in result.stdout:
        fail("benchmark runner did not reach proof validation")
    after = load_json(path / "state.json")
    if after.get("status") != "solved":
        fail("benchmark runner changed solved status instead of failing closed")
    report = path / "work" / "BENCHMARK_RUNNER_REPORT.md"
    if not report.is_file():
        fail("failed benchmark did not write report")
    report_text = report.read_text(encoding="utf-8")
    if "proof_validate.py" not in report_text or "returncode: `0`" in report_text.split("proof_validate.py", 1)[-1]:
        fail("failed proof validation was not recorded in report")
    return path


def assert_sanitize() -> Path:
    path = ROOT / "challenges" / "_level5sanitize" / "misc" / "redaction"
    ensure_clean(path)
    mark(path)
    raw = path / "evidence" / "raw.log"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text(
        "flag is FLAG{LEVEL5_SANITIZE_TEST}\n"
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz\n",
        encoding="utf-8",
    )
    out = path / "evidence" / "raw.summary.md"
    run(["python3", "tools/report_sanitize.py", raw.relative_to(ROOT).as_posix(), "--output", out.relative_to(ROOT).as_posix()])
    text = out.read_text(encoding="utf-8")
    if "FLAG{LEVEL5_SANITIZE_TEST}" in text or "abcdefghijklmnopqrstuvwxyz" in text:
        fail("report_sanitize leaked sensitive marker")
    if "<REDACTED_FLAG>" not in text or "<REDACTED_TOKEN>" not in text:
        fail("report_sanitize did not include expected redaction markers")
    return path


def assert_cleanup() -> tuple[Path, Path]:
    gitkeep = ROOT / "challenges" / ".gitkeep"
    if not gitkeep.is_file():
        fail("missing challenges/.gitkeep before cleanup test")
    result = run(["python3", "tools/cleanup_artifacts.py", "--yes", gitkeep.relative_to(ROOT).as_posix()], expect_ok=False)
    if "refusing to clean non-temporary path" not in result.stderr:
        fail("cleanup_artifacts failed for the wrong reason on challenges/.gitkeep")
    if not gitkeep.is_file():
        fail("cleanup_artifacts removed challenges/.gitkeep")

    selftest_path = ROOT / "challenges" / "_selftest" / "level5-cleanup" / "probe"
    mark(selftest_path)
    (selftest_path / "tmp.txt").write_text("temporary selftest artifact\n", encoding="utf-8")
    run(["python3", "tools/cleanup_artifacts.py", "--yes", selftest_path.relative_to(ROOT).as_posix()])
    if selftest_path.exists():
        fail("cleanup_artifacts did not remove targeted _selftest artifact")

    empty_selftest = ROOT / "challenges" / "_selftest" / "level5-empty" / "probe"
    mark(empty_selftest)
    run(["python3", "tools/cleanup_artifacts.py", "--yes", empty_selftest.relative_to(ROOT).as_posix()])
    if (ROOT / "challenges" / "_selftest" / "level5-empty").exists():
        fail("cleanup_artifacts did not prune empty _selftest parent dirs")

    empty_level5 = ROOT / "challenges" / "_level5selftest" / "misc" / "empty-probe"
    mark(empty_level5)
    run(["python3", "tools/cleanup_artifacts.py", "--yes", empty_level5.relative_to(ROOT).as_posix()])
    if (ROOT / "challenges" / "_level5selftest").exists():
        fail("cleanup_artifacts did not remove empty _level5 temp dirs completely")

    real_path = intake("practice-level5", "misc", "real-keep")
    result = run(["python3", "tools/cleanup_artifacts.py", "--yes", real_path.relative_to(ROOT).as_posix()], expect_ok=False)
    if "refusing to clean non-temporary path" not in result.stderr:
        fail("cleanup_artifacts failed for the wrong reason on real challenge path")
    if not real_path.exists():
        fail("cleanup_artifacts removed real challenge work")
    return selftest_path, real_path


def cleanup(paths: list[Path]) -> None:
    for path in sorted(paths, key=lambda item: len(item.parts), reverse=True):
        if path.exists() and ((path / MARKER).is_file() or (path / ".level5_benchmark").is_file()):
            shutil.rmtree(path)
    for dirname in (
        ROOT / "challenges" / "_level5benchmark",
        ROOT / "challenges" / "_level5badproof",
        ROOT / "challenges" / "_level5replay",
        ROOT / "challenges" / "_level5selftest",
        ROOT / "challenges" / "_level5sanitize",
        ROOT / "challenges" / "practice-level5" / "misc",
        ROOT / "challenges" / "practice-level5",
        ROOT / "challenges" / "_selftest" / "level5-cleanup",
        ROOT / "challenges" / "_selftest" / "level5-empty",
        ROOT / "challenges" / "_selftest",
    ):
        try:
            dirname.rmdir()
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
        run(["python3", "tools/preflight_check.py"])
        created.append(assert_dummy_runner())
        created.extend(assert_replay_runner_negative_contracts())
        created.append(assert_solved_without_replay_evidence_fails())
        created.append(assert_blocked_without_reason_fails())
        created.append(assert_invalid_solved_fails())
        created.append(assert_sanitize())
        _, real_path = assert_cleanup()
        created.append(real_path)
    finally:
        if not args.keep:
            cleanup(created)
    print("level5 selftest ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
