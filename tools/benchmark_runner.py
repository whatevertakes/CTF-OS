#!/usr/bin/env python3
"""Bounded automation wrapper for Level 2 replay and proof workflows."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from report_sanitize import sanitize_text


ROOT = Path(__file__).resolve().parents[1]
DUMMY_EVENT = "_level5benchmark"
DUMMY_CATEGORY = "misc"
DUMMY_NAME = "dummy-local"
DUMMY_MARKER = ".level5_benchmark"
REPORT_NAME = "BENCHMARK_RUNNER_REPORT.md"


def fail(message: str, code: int = 1) -> None:
    print(f"benchmark_runner: {message}", file=sys.stderr)
    raise SystemExit(code)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def relative_to_root(path: Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def resolve_challenge_dir(value: str) -> Path:
    raw = Path(value).expanduser()
    path = raw if raw.is_absolute() else ROOT / raw
    try:
        resolved = path.resolve()
        rel = resolved.relative_to(ROOT)
    except ValueError:
        fail(f"challenge directory must stay under {ROOT}: {value}", code=2)
    if not resolved.is_dir():
        fail(f"challenge directory does not exist: {value}", code=2)
    if len(rel.parts) >= 2 and rel.parts[0] == "challenges" and rel.parts[1] == "_selftest":
        fail("refusing to use challenges/_selftest as a benchmark input", code=2)
    return resolved


def load_state(path: Path) -> dict[str, Any]:
    state_path = path / "state.json"
    if not state_path.is_file():
        fail(f"missing state.json in {relative_to_root(path)}", code=2)
    try:
        with state_path.open("r", encoding="utf-8") as handle:
            state = json.load(handle)
    except json.JSONDecodeError as exc:
        fail(f"invalid state.json: {exc}", code=2)
    if not isinstance(state, dict):
        fail("state.json root must be an object", code=2)
    metadata = state.get("metadata")
    if not isinstance(metadata, dict):
        fail("state.json metadata must be an object", code=2)
    return state


def write_dummy_replay(path: Path) -> None:
    (path / "notes.md").write_text(
        "# Level 5 Dummy Benchmark\n\n"
        "This local fixture validates bounded automation only.\n",
        encoding="utf-8",
    )
    (path / "replay.sh").write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "echo level5_dummy=ok\n"
        "echo remote_liveness=not_applicable\n",
        encoding="utf-8",
    )
    (path / "replay.sh").chmod(0o755)


def dummy_path() -> Path:
    return ROOT / "challenges" / DUMMY_EVENT / DUMMY_CATEGORY / DUMMY_NAME


def ensure_clean_dummy(path: Path) -> None:
    if not path.exists():
        return
    if not (path / DUMMY_MARKER).is_file():
        fail(f"refusing to overwrite unmarked dummy benchmark: {relative_to_root(path)}", code=2)
    shutil.rmtree(path)


def create_dummy() -> Path:
    path = dummy_path()
    ensure_clean_dummy(path)
    run_command(
        [
            "python3",
            "tools/intake_challenge.py",
            "--event",
            DUMMY_EVENT,
            "--category",
            DUMMY_CATEGORY,
            "--name",
            DUMMY_NAME,
        ]
    )
    (path / DUMMY_MARKER).write_text("created by tools/benchmark_runner.py\n", encoding="utf-8")
    write_dummy_replay(path)
    return path


def run_command(command: list[str]) -> dict[str, Any]:
    print(f"RUN {shlex.join(command)}")
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
    return {
        "command": command,
        "returncode": result.returncode,
        "stdout_tail": sanitize_text("\n".join(result.stdout.splitlines()[-20:])),
        "stderr_tail": sanitize_text("\n".join(result.stderr.splitlines()[-20:])),
    }


def render_report(path: Path, state_before: dict[str, Any], state_after: dict[str, Any], results: list[dict[str, Any]]) -> str:
    lines = [
        "# Benchmark Runner Report",
        "",
        f"- generated_at: `{utc_now()}`",
        f"- challenge: `{relative_to_root(path)}`",
        f"- status_before: `{state_before.get('status')}`",
        f"- status_after: `{state_after.get('status')}`",
        "",
        "## Commands",
        "",
    ]
    for item in results:
        lines.append(f"### `{shlex.join(item['command'])}`")
        lines.append("")
        lines.append(f"- returncode: `{item['returncode']}`")
        if item.get("stdout_tail"):
            lines.append("")
            lines.append("stdout tail:")
            lines.append("")
            lines.append("```text")
            lines.append(str(item["stdout_tail"]))
            lines.append("```")
        if item.get("stderr_tail"):
            lines.append("")
            lines.append("stderr tail:")
            lines.append("")
            lines.append("```text")
            lines.append(str(item["stderr_tail"]))
            lines.append("```")
        lines.append("")
    lines.extend(
        [
            "## Safety",
            "",
            "- This runner does not write `status=solved`.",
            "- `proof_validate.py` is the only solved-claim validator.",
            "- Output tails in this report are sanitized.",
            "",
        ]
    )
    return "\n".join(lines)


def write_report(path: Path, state_before: dict[str, Any], results: list[dict[str, Any]]) -> Path:
    state_after = load_state(path)
    report_path = path / "work" / REPORT_NAME
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(render_report(path, state_before, state_after, results), encoding="utf-8")
    print(f"benchmark_runner report {report_path.relative_to(ROOT).as_posix()}")
    return report_path


def run_level2_workflow(path: Path, *, skip_preflight: bool) -> int:
    state_before = load_state(path)
    status_before = state_before.get("status")
    rel = relative_to_root(path)
    commands: list[list[str]] = []
    if not skip_preflight:
        commands.append(["python3", "tools/preflight_check.py"])
    commands.extend(
        [
            ["python3", "tools/replay_runner.py", rel],
            ["python3", "tools/proof_validate.py", rel],
        ]
    )
    results: list[dict[str, Any]] = []
    for command in commands:
        result = run_command(command)
        results.append(result)
        if result["returncode"] != 0:
            write_report(path, state_before, results)
            return int(result["returncode"])
    report_path = write_report(path, state_before, results)
    state_after = load_state(path)
    if state_after.get("status") != status_before:
        fail(
            f"state status changed unexpectedly from {status_before!r} to {state_after.get('status')!r}; "
            f"report={report_path.relative_to(ROOT).as_posix()}",
            code=1,
        )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    dummy_parser = subparsers.add_parser("dummy", help="run the local dummy Level 5 benchmark fixture")
    dummy_parser.add_argument("--skip-preflight", action="store_true", help="skip preflight check")

    run_parser = subparsers.add_parser("run", help="run bounded replay/proof workflow for an existing challenge")
    run_parser.add_argument("challenge_dir")
    run_parser.add_argument("--skip-preflight", action="store_true", help="skip preflight check")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "dummy":
        path = create_dummy()
        return run_level2_workflow(path, skip_preflight=args.skip_preflight)
    if args.command == "run":
        path = resolve_challenge_dir(args.challenge_dir)
        return run_level2_workflow(path, skip_preflight=args.skip_preflight)
    fail(f"unknown command: {args.command}", code=2)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
