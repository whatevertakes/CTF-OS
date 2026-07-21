"""Thin handoff bridge from CTF-OS main to the separate Claude runtime.

The main repository owns the exact Sol run and protected flag state.  Claude
workspace rendering, sandbox operation, return validation, and runtime tooling
live in ``CTF-OS-claude`` and are invoked as a separate package.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
from typing import Any


MODES = frozenset({
    "BLOCKER_BREAK", "PRIMITIVE_TO_POC", "REMOTE_ENDGAME",
    "FRESH_REINTERPRETATION", "FLAG_VERIFICATION",
})
PROFILES = frozenset({"standard", "assisted", "deep", "fable-strategy"})
CLAUDE_HOME_ENV = "CTF_OS_CLAUDE_HOME"


class ClaudeBridgeError(RuntimeError):
    pass


def claude_home() -> Path:
    configured = os.environ.get(CLAUDE_HOME_ENV)
    raw_root = (
        Path(configured).expanduser() if configured
        else Path.home() / "CTF-OS-claude"
    )
    if raw_root.is_symlink():
        raise ClaudeBridgeError(f"Claude runtime root must not be a symlink: {raw_root}")
    root = raw_root.resolve(strict=False)
    required = root / "ctf_os" / "rescue.py"
    project = root / "pyproject.toml"
    if not root.is_dir() or not required.is_file() or not project.is_file():
        raise ClaudeBridgeError(
            f"Claude runtime is missing or unsafe: {root}. "
            f"Set {CLAUDE_HOME_ENV} to the migrated CTF-OS-claude directory."
        )
    return root


def dispatch_claude_rescue(repo_root: Path, args: argparse.Namespace) -> Any:
    runtime = claude_home()
    command = [
        "uv", "run", "--project", str(runtime), "python", "-m",
        "ctf_os.agent_tools", "--repo", str(repo_root.resolve(strict=False)),
        args.command, str(args.selector),
    ]
    _option(command, "--contest", getattr(args, "contest", None))
    _option(command, "--run-id", getattr(args, "run_id", None))

    if args.command == "rescue-prepare":
        _option(command, "--mode", args.mode)
        _option(command, "--profile", args.profile)
        _option(command, "--objective", args.objective)
        _option(command, "--current-blocker", args.current_blocker)
        _option(command, "--leading-exploit-path", args.leading_exploit_path)
        for value in args.path_not_to_repeat:
            _option(command, "--path-not-to-repeat", value)
        _option(command, "--operation-id", args.operation_id)
        _option(command, "--lead-model", args.lead_model)
        _option(command, "--research-policy", args.research_policy)
    elif args.command == "rescue-runtime-record":
        _option(command, "--rescue-id", args.rescue_id)
        _option(command, "--observed-model", args.observed_model)
        _option(command, "--evidence", args.evidence)
        if args.fallback_observed is True:
            command.append("--fallback-observed")
        elif args.fallback_observed is False:
            command.append("--no-fallback-observed")
    elif args.command in {"rescue-show", "rescue-return-validate"}:
        _option(command, "--rescue-id", args.rescue_id)
    elif args.command == "rescue-flag-promote":
        _option(command, "--rescue-id", args.rescue_id)
        _option(command, "--execution-receipt-id", args.execution_receipt_id)
        _option(command, "--candidate", args.candidate)
        _option(command, "--exploit-artifact", args.exploit_artifact)
    elif args.command == "rescue-close":
        _option(command, "--rescue-id", args.rescue_id)
        _option(command, "--outcome", args.outcome)
        _option(command, "--evidence-receipt-id", args.evidence_receipt_id)
    else:
        raise ClaudeBridgeError(f"unsupported Claude bridge command: {args.command}")

    _option(command, "--session-id", getattr(args, "session_id", None))
    _option(command, "--session-role", getattr(args, "session_role", None))
    _option(command, "--parent-session-id", getattr(args, "parent_session_id", None))
    if getattr(args, "recover_stale", False):
        command.append("--recover-stale")

    environment = dict(os.environ)
    environment[CLAUDE_HOME_ENV] = str(runtime)
    completed = subprocess.run(
        command, cwd=runtime, env=environment, capture_output=True, text=True,
        timeout=900, check=False,
    )
    try:
        payload = json.loads(completed.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        detail = (completed.stderr or completed.stdout or "no output").strip()[-4000:]
        raise ClaudeBridgeError(f"Claude runtime returned malformed output: {detail}") from exc
    if completed.returncode != 0 or payload.get("ok") is not True:
        detail = payload.get("error") or completed.stderr.strip() or "unknown runtime error"
        raise ClaudeBridgeError(f"Claude runtime handoff failed: {detail}")
    return payload.get("result")


def _option(argv: list[str], name: str, value: object) -> None:
    if value is not None:
        argv.extend((name, str(value)))
