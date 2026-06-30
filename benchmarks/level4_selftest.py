#!/usr/bin/env python3
"""Run Level 4 interface acceptance checks."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVENT = "_level4selftest"
CATEGORY = "web"
NAME = "fixture-interface"
MARKER = ".level4_selftest"


def fail(message: str) -> None:
    print(f"level4_selftest: {message}", file=sys.stderr)
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


def challenge_path() -> Path:
    return ROOT / "challenges" / EVENT / CATEGORY / NAME


def ensure_clean(path: Path) -> None:
    if not path.exists():
        return
    if not (path / MARKER).is_file():
        fail(f"refusing to overwrite unmarked challenge directory: {path.relative_to(ROOT)}")
    shutil.rmtree(path)


def mark(path: Path) -> None:
    (path / MARKER).write_text("created by benchmarks/level4_selftest.py\n", encoding="utf-8")


def load_json(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        fail(f"JSON root is not an object: {path.relative_to(ROOT)}")
    return data


def prepare_fixture(path: Path) -> None:
    (path / "notes.md").write_text(
        "# Level 4 Interface Fixture\n\n"
        "## Endpoint\n\n"
        "- local target: not started; this fixture tests interface wiring only\n\n"
        "## Evidence\n\n"
        "- Level 4 should list this notes file and the Level 3 board files.\n",
        encoding="utf-8",
    )
    (path / "replay.sh").write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "echo level4_fixture=ok\n"
        "echo remote_liveness=not_applicable\n",
        encoding="utf-8",
    )
    (path / "replay.sh").chmod(0o755)


def intake() -> Path:
    path = challenge_path()
    ensure_clean(path)
    run(
        [
            "python3",
            "tools/intake_challenge.py",
            "--event",
            EVENT,
            "--category",
            CATEGORY,
            "--name",
            NAME,
        ]
    )
    mark(path)
    prepare_fixture(path)
    return path


def assert_manifest(path: Path) -> None:
    manifest_path = path / "work" / "LEVEL4_INTERFACE.json"
    report_path = path / "work" / "LEVEL4_STATUS.md"
    if not manifest_path.is_file():
        fail("missing work/LEVEL4_INTERFACE.json")
    if not report_path.is_file():
        fail("missing work/LEVEL4_STATUS.md")
    manifest = load_json(manifest_path)
    if manifest.get("version") != "v1_interface_bridge":
        fail(f"unexpected Level 4 version: {manifest.get('version')}")
    challenge = manifest.get("challenge")
    if not isinstance(challenge, dict) or challenge.get("category") != CATEGORY:
        fail("manifest challenge category mismatch")
    inputs = manifest.get("inputs")
    if not isinstance(inputs, dict):
        fail("manifest missing inputs")
    expected_inputs = {
        "level1_config": ".codex/config.toml",
        "level2_state": "state.json",
        "level2_notes": "notes.md",
        "level2_replay": "replay.sh",
        "level3_state": "work/LEVEL3_STATE.json",
    }
    for key, expected in expected_inputs.items():
        if inputs.get(key) != expected:
            fail(f"manifest input {key} expected {expected!r}, got {inputs.get(key)!r}")
    level1 = manifest.get("level1")
    if not isinstance(level1, dict) or level1.get("playwright_configured") is not True:
        fail("manifest did not detect Playwright MCP config")
    level2 = manifest.get("level2")
    if not isinstance(level2, dict) or level2.get("missing_contract_entries") != []:
        fail("manifest reports missing Level 2 challenge contract entries")
    proof = level2.get("proof")
    if not isinstance(proof, dict) or proof.get("returncode") != 0:
        fail("manifest proof validation did not pass")
    level3 = manifest.get("level3")
    if not isinstance(level3, dict) or level3.get("initialized") is not True:
        fail("manifest did not connect to Level 3 state")
    if int(level3.get("task_count") or 0) <= 0:
        fail("manifest did not include Level 3 task count")
    interfaces = manifest.get("interfaces")
    if not isinstance(interfaces, dict):
        fail("manifest missing interfaces")
    cli = interfaces.get("cli")
    if not isinstance(cli, dict):
        fail("manifest missing CLI commands")
    flattened_commands = "\n".join(command for commands in cli.values() for command in commands)
    for required in (
        "tools/preflight_check.py",
        "tools/replay_runner.py",
        "tools/proof_validate.py",
        "tools/level3_orchestrator.py status",
        "tools/level4_interface.py doctor",
    ):
        if required not in flattened_commands:
            fail(f"manifest CLI commands missing {required}")
    browser = interfaces.get("browser_playwright")
    if not isinstance(browser, dict) or browser.get("eligible") is not True or browser.get("configured") is not True:
        fail("manifest browser surface is not ready for web category")
    report = report_path.read_text(encoding="utf-8")
    for required in ("# Level 4 Interface Status", "## Level 3 Board", "## Organic Connection"):
        if required not in report:
            fail(f"status report missing {required}")


def assert_state_metadata(path: Path) -> None:
    state = load_json(path / "state.json")
    metadata = state.get("metadata")
    if not isinstance(metadata, dict):
        fail("state metadata missing")
    expected = {
        "level4_status": "ready",
        "level4_version": "v1_interface_bridge",
        "level4_manifest": "work/LEVEL4_INTERFACE.json",
        "level4_report": "work/LEVEL4_STATUS.md",
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            fail(f"state metadata {key} expected {value!r}, got {metadata.get(key)!r}")


def cleanup(path: Path) -> None:
    if path.exists() and (path / MARKER).is_file():
        shutil.rmtree(path)
    for directory in (
        ROOT / "challenges" / EVENT / CATEGORY,
        ROOT / "challenges" / EVENT,
    ):
        try:
            directory.rmdir()
        except OSError:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="leave marked self-test fixture in place")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    path = intake()
    rel = path.relative_to(ROOT).as_posix()
    try:
        run(["python3", "tools/preflight_check.py"])
        run(["python3", "tools/level3_orchestrator.py", "init", rel, "--category", CATEGORY])
        run(["python3", "tools/level3_orchestrator.py", "plan", rel, "--category", CATEGORY])
        build = run(["python3", "tools/level4_interface.py", "build", rel])
        if "level4 interface ready" not in build.stdout:
            fail("build did not report readiness")
        assert_manifest(path)
        assert_state_metadata(path)
        doctor = run(["python3", "tools/level4_interface.py", "doctor", rel])
        if "level4 doctor ok" not in doctor.stdout:
            fail("doctor did not report ok")
        status = run(["python3", "tools/level4_interface.py", "status", rel])
        if "# Level 4 Interface Status" not in status.stdout or rel not in status.stdout:
            fail("status output missing report header or challenge path")
    finally:
        if not args.keep:
            cleanup(path)
    print("level4 selftest ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
