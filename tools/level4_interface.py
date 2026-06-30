#!/usr/bin/env python3
"""Build the Level 4 interface view for one challenge workspace."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
VERSION = "v1_interface_bridge"
INTERFACE_JSON = Path("work/LEVEL4_INTERFACE.json")
INTERFACE_REPORT = Path("work/LEVEL4_STATUS.md")
BROWSER_CATEGORIES = {"web", "osint", "ai-ml", "cloud"}
REQUIRED_CHALLENGE_FILES = ("state.json", "notes.md", "replay.sh", "evidence", "dist", "work")
COMMAND_GROUP_ORDER = ("preflight", "proof", "replay", "level3", "level4")


def fail(message: str, code: int = 1) -> None:
    print(f"level4_interface: {message}", file=sys.stderr)
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
        resolved.relative_to(ROOT)
    except ValueError:
        fail(f"challenge directory must stay under {ROOT}: {value}", code=2)
    if not resolved.is_dir():
        fail(f"challenge directory does not exist: {value}", code=2)
    return resolved


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as exc:
        fail(f"cannot read {path}: {exc}", code=2)
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON {path}: {exc}", code=2)
    if not isinstance(data, dict):
        fail(f"JSON root must be an object: {path}", code=2)
    return data


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def command_result(command: list[str]) -> dict[str, Any]:
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
    return {
        "command": " ".join(command),
        "returncode": result.returncode,
        "stdout_tail": "\n".join(result.stdout.splitlines()[-20:]),
        "stderr_tail": "\n".join(result.stderr.splitlines()[-20:]),
    }


def codex_config_summary() -> dict[str, Any]:
    config_path = ROOT / ".codex" / "config.toml"
    summary: dict[str, Any] = {
        "path": ".codex/config.toml",
        "exists": config_path.is_file(),
        "mcp_servers": [],
        "playwright_configured": False,
        "radare2_wrapper": False,
    }
    if not config_path.is_file():
        return summary
    try:
        config = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        summary["error"] = str(exc)
        return summary
    mcp = config.get("mcp_servers", {})
    if isinstance(mcp, dict):
        summary["mcp_servers"] = sorted(mcp.keys())
        summary["playwright_configured"] = "playwright" in mcp
        radare2 = mcp.get("radare2", {})
        if isinstance(radare2, dict):
            summary["radare2_wrapper"] = (
                radare2.get("command") == str(ROOT / ".codex" / "bin" / "r2mcp-codex.sh")
            )
    summary["approval_policy"] = config.get("approval_policy")
    summary["sandbox_mode"] = config.get("sandbox_mode")
    summary["model_reasoning_effort"] = config.get("model_reasoning_effort")
    return summary


def notes_headings(path: Path) -> list[str]:
    notes = path / "notes.md"
    if not notes.is_file():
        return []
    headings: list[str] = []
    for line in notes.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("#"):
            headings.append(line.strip())
        if len(headings) >= 20:
            break
    return headings


def evidence_inventory(path: Path) -> list[dict[str, Any]]:
    evidence_dir = path / "evidence"
    if not evidence_dir.is_dir():
        return []
    entries: list[dict[str, Any]] = []
    for item in sorted(evidence_dir.rglob("*")):
        if not item.is_file():
            continue
        entries.append(
            {
                "path": item.relative_to(path).as_posix(),
                "bytes": item.stat().st_size,
            }
        )
        if len(entries) >= 80:
            entries.append({"path": "<truncated>", "bytes": 0})
            break
    return entries


def level3_summary(path: Path) -> dict[str, Any]:
    work = path / "work"
    files = {
        "state": work / "LEVEL3_STATE.json",
        "tasks": work / "LEVEL3_TASKS.json",
        "dispatch": work / "LEVEL3_DISPATCH.json",
        "dispatch_report": work / "LEVEL3_DISPATCH.md",
        "run_log": work / "LEVEL3_RUN_LOG.jsonl",
    }
    present = {name: file.relative_to(path).as_posix() for name, file in files.items() if file.exists()}
    summary: dict[str, Any] = {
        "initialized": "state" in present,
        "present": present,
        "missing": sorted(set(files) - set(present)),
    }
    if files["tasks"].is_file():
        tasks = load_json(files["tasks"])
        raw_tasks = tasks.get("tasks")
        if isinstance(raw_tasks, list):
            summary["task_count"] = len(raw_tasks)
            summary["workers"] = [task.get("worker") for task in raw_tasks if isinstance(task, dict)]
    if files["run_log"].is_file():
        summary["run_log_lines"] = len(files["run_log"].read_text(encoding="utf-8", errors="replace").splitlines())
    return summary


def interface_commands(challenge_rel: str, has_level3: bool) -> dict[str, list[str]]:
    commands = {
        "preflight": ["python3 tools/preflight_check.py"],
        "proof": [f"python3 tools/proof_validate.py {challenge_rel}"],
        "replay": [f"python3 tools/replay_runner.py {challenge_rel}"],
        "level3": [
            f"python3 tools/level3_orchestrator.py status {challenge_rel}"
            if has_level3
            else f"python3 tools/level3_orchestrator.py init {challenge_rel}",
            f"python3 tools/level3_orchestrator.py evaluate {challenge_rel} --run-replay"
            if has_level3
            else f"python3 tools/level3_orchestrator.py plan {challenge_rel}",
        ],
        "level4": [
            f"python3 tools/level4_interface.py build {challenge_rel}",
            f"python3 tools/level4_interface.py doctor {challenge_rel}",
            f"python3 tools/level4_interface.py status {challenge_rel}",
        ],
    }
    return commands


def editor_files(path: Path) -> list[dict[str, str]]:
    candidates = (
        ("state", "state.json"),
        ("notes", "notes.md"),
        ("replay", "replay.sh"),
        ("level3 tasks", "work/LEVEL3_TASKS.json"),
        ("level3 dispatch", "work/LEVEL3_DISPATCH.md"),
        ("level3 run log", "work/LEVEL3_RUN_LOG.jsonl"),
        ("level4 status", INTERFACE_REPORT.as_posix()),
        ("level4 manifest", INTERFACE_JSON.as_posix()),
    )
    files: list[dict[str, str]] = []
    for label, relative in candidates:
        if (path / relative).exists() or relative in {INTERFACE_REPORT.as_posix(), INTERFACE_JSON.as_posix()}:
            files.append({"label": label, "path": relative})
    return files


def terminal_profiles(challenge_rel: str, has_level3: bool) -> list[dict[str, Any]]:
    profiles = [
        {
            "name": "proof-loop",
            "commands": [
                f"python3 tools/replay_runner.py {challenge_rel}",
                f"python3 tools/proof_validate.py {challenge_rel}",
            ],
        },
        {
            "name": "evidence-watch",
            "commands": [f"find {challenge_rel}/evidence -maxdepth 2 -type f | sort"],
        },
    ]
    if has_level3:
        profiles.append(
            {
                "name": "level3-board",
                "commands": [
                    f"python3 tools/level3_orchestrator.py status {challenge_rel}",
                    f"tail -n 40 {challenge_rel}/work/LEVEL3_RUN_LOG.jsonl",
                ],
            }
        )
    return profiles


def browser_surface(category: str, config: dict[str, Any]) -> dict[str, Any]:
    eligible = category in BROWSER_CATEGORIES
    configured = bool(config.get("playwright_configured"))
    return {
        "eligible": eligible,
        "configured": configured,
        "mcp": "mcp://playwright" if configured else "",
        "policy": "Use only after a concrete local or owned target is identified; save screenshots and traces under evidence/.",
        "screenshot_path_pattern": "evidence/playwright_<timestamp>.png",
    }


def interface_manifest(path: Path, *, run_proof: bool) -> dict[str, Any]:
    state_path = path / "state.json"
    if not state_path.is_file():
        fail(f"missing state.json in {relative_to_root(path)}", code=2)
    state = load_json(state_path)
    metadata = state.get("metadata") if isinstance(state.get("metadata"), dict) else {}
    category = str(state.get("category") or path.parent.name)
    challenge_rel = relative_to_root(path)
    missing = [relative for relative in REQUIRED_CHALLENGE_FILES if not (path / relative).exists()]
    config = codex_config_summary()
    level3 = level3_summary(path)
    proof = command_result(["python3", "tools/proof_validate.py", challenge_rel]) if run_proof else {}
    manifest: dict[str, Any] = {
        "version": VERSION,
        "generated_at": utc_now(),
        "challenge": {
            "path": challenge_rel,
            "event": state.get("event"),
            "category": category,
            "name": state.get("name"),
            "status": state.get("status"),
            "proof_scope": metadata.get("proof_scope"),
            "remote_status": metadata.get("remote_status"),
            "remote_solve": metadata.get("remote_solve"),
            "replay_kind": metadata.get("replay_kind"),
            "current_remote_liveness": metadata.get("current_remote_liveness"),
        },
        "inputs": {
            "level1_config": ".codex/config.toml",
            "level2_state": "state.json",
            "level2_notes": "notes.md",
            "level2_replay": "replay.sh",
            "level2_evidence_dir": "evidence/",
            "level3_state": "work/LEVEL3_STATE.json" if level3["initialized"] else "",
        },
        "level1": config,
        "level2": {
            "missing_contract_entries": missing,
            "notes_headings": notes_headings(path),
            "evidence": evidence_inventory(path),
            "proof": proof,
        },
        "level3": level3,
        "interfaces": {
            "cli": interface_commands(challenge_rel, bool(level3["initialized"])),
            "editor": editor_files(path),
            "terminal": terminal_profiles(challenge_rel, bool(level3["initialized"])),
            "browser_playwright": browser_surface(category, config),
            "report_surfaces": [
                INTERFACE_REPORT.as_posix(),
                "notes.md",
                "work/LEVEL3_DISPATCH.md" if (path / "work/LEVEL3_DISPATCH.md").exists() else "",
            ],
        },
        "organic_connection": {
            "level1": "Reads Codex config and MCP availability; does not redefine routing.",
            "level2": "Reads state, notes, replay, and evidence as the source of truth.",
            "level3": "Reads orchestration artifacts as a board view when present.",
            "level4": "Writes only interface manifest/status views plus state metadata pointers.",
        },
    }
    manifest["interfaces"]["report_surfaces"] = [
        item for item in manifest["interfaces"]["report_surfaces"] if item
    ]
    return manifest


def markdown_table(rows: list[tuple[str, Any]]) -> str:
    lines = ["| Field | Value |", "|---|---|"]
    for key, value in rows:
        rendered = str(value).replace("\n", " ").strip()
        lines.append(f"| {key} | {rendered} |")
    return "\n".join(lines)


def render_status(manifest: dict[str, Any]) -> str:
    challenge = manifest["challenge"]
    level3 = manifest["level3"]
    browser = manifest["interfaces"]["browser_playwright"]
    commands = manifest["interfaces"]["cli"]
    lines = [
        "# Level 4 Interface Status",
        "",
        "This report is a view over Level 1 config, Level 2 challenge state, and Level 3 orchestration artifacts.",
        "",
        "## Challenge",
        "",
        markdown_table(
            [
                ("path", challenge.get("path")),
                ("category", challenge.get("category")),
                ("status", challenge.get("status")),
                ("proof_scope", challenge.get("proof_scope")),
                ("remote_status", challenge.get("remote_status")),
                ("replay_kind", challenge.get("replay_kind")),
            ]
        ),
        "",
        "## Interface Commands",
        "",
    ]
    ordered_groups = [group for group in COMMAND_GROUP_ORDER if group in commands]
    ordered_groups.extend(group for group in commands if group not in COMMAND_GROUP_ORDER)
    for group in ordered_groups:
        group_commands = commands[group]
        lines.append(f"### {group}")
        lines.append("")
        for command in group_commands:
            lines.append(f"- `{command}`")
        lines.append("")
    lines.extend(
        [
            "## Level 3 Board",
            "",
            markdown_table(
                [
                    ("initialized", level3.get("initialized")),
                    ("task_count", level3.get("task_count", 0)),
                    ("run_log_lines", level3.get("run_log_lines", 0)),
                    ("present", ", ".join(sorted(level3.get("present", {}).values()))),
                ]
            ),
            "",
            "## Browser / Playwright",
            "",
            markdown_table(
                [
                    ("eligible", browser.get("eligible")),
                    ("configured", browser.get("configured")),
                    ("mcp", browser.get("mcp")),
                    ("evidence", browser.get("screenshot_path_pattern")),
                ]
            ),
            "",
            "## Editor Files",
            "",
        ]
    )
    for item in manifest["interfaces"]["editor"]:
        lines.append(f"- `{item['path']}` ({item['label']})")
    lines.extend(["", "## Organic Connection", ""])
    for level, rule in manifest["organic_connection"].items():
        lines.append(f"- `{level}`: {rule}")
    lines.append("")
    return "\n".join(lines)


def update_state_metadata(path: Path) -> None:
    state_path = path / "state.json"
    state = load_json(state_path)
    metadata = state.setdefault("metadata", {})
    if not isinstance(metadata, dict):
        fail("state.json metadata must be an object before Level 4 metadata can be written", code=2)
    metadata["level4_status"] = "ready"
    metadata["level4_version"] = VERSION
    metadata["level4_manifest"] = INTERFACE_JSON.as_posix()
    metadata["level4_report"] = INTERFACE_REPORT.as_posix()
    state["updated_at"] = utc_now()
    write_json(state_path, state)


def build(path: Path, *, run_proof: bool, update_state: bool) -> dict[str, Any]:
    manifest = interface_manifest(path, run_proof=run_proof)
    write_json(path / INTERFACE_JSON, manifest)
    (path / INTERFACE_REPORT).parent.mkdir(parents=True, exist_ok=True)
    (path / INTERFACE_REPORT).write_text(render_status(manifest), encoding="utf-8")
    if update_state:
        update_state_metadata(path)
        manifest = interface_manifest(path, run_proof=run_proof)
        write_json(path / INTERFACE_JSON, manifest)
        (path / INTERFACE_REPORT).write_text(render_status(manifest), encoding="utf-8")
    return manifest


def doctor(path: Path) -> int:
    manifest = interface_manifest(path, run_proof=True)
    issues: list[str] = []
    if manifest["level2"]["missing_contract_entries"]:
        issues.append("missing challenge contract entries")
    if not manifest["level1"].get("exists"):
        issues.append("missing .codex/config.toml")
    proof = manifest["level2"].get("proof", {})
    if proof and proof.get("returncode") != 0:
        issues.append("proof validation failed")
    browser = manifest["interfaces"]["browser_playwright"]
    if browser.get("eligible") and not browser.get("configured"):
        issues.append("browser category but Playwright MCP is not configured")
    if issues:
        for issue in issues:
            print(f"WARN {issue}")
        return 1
    print(f"level4 doctor ok {manifest['challenge']['path']}")
    return 0


def status(path: Path) -> int:
    manifest_path = path / INTERFACE_JSON
    if manifest_path.is_file():
        manifest = load_json(manifest_path)
    else:
        manifest = interface_manifest(path, run_proof=False)
    print(render_status(manifest))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build", help="write Level 4 manifest and status report")
    build_parser.add_argument("challenge_dir")
    build_parser.add_argument("--skip-proof", action="store_true", help="do not run proof_validate while building")
    build_parser.add_argument("--no-state-update", action="store_true", help="do not write Level 4 metadata pointers")

    doctor_parser = subparsers.add_parser("doctor", help="check Level 4 interface readiness")
    doctor_parser.add_argument("challenge_dir")

    status_parser = subparsers.add_parser("status", help="print the Level 4 status report")
    status_parser.add_argument("challenge_dir")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    path = resolve_challenge_dir(args.challenge_dir)
    if args.command == "build":
        manifest = build(path, run_proof=not args.skip_proof, update_state=not args.no_state_update)
        print(f"level4 interface ready {manifest['challenge']['path']}")
        print((path / INTERFACE_JSON).relative_to(ROOT).as_posix())
        print((path / INTERFACE_REPORT).relative_to(ROOT).as_posix())
        return 0
    if args.command == "doctor":
        return doctor(path)
    if args.command == "status":
        return status(path)
    fail(f"unknown command: {args.command}", code=2)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
