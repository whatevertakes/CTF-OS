#!/usr/bin/env python3
"""Check the team-parity CTF tool surface, including MCP launch dependencies."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VENV_PYTHON = ROOT / ".venv" / "bin" / "python"
COMMANDS = (
    "docker",
    "node",
    "npm",
    "npx",
    "gcc",
    "gdb",
    "r2",
    "angr-mcp",
    "checksec",
    "ROPgadget",
    "one_gadget",
    "ropper",
    "seccomp-tools",
    "jadx",
    "apktool",
    "sage",
    "tshark",
)
PYTHON_MODULES = (
    ("angr", "angr"),
    ("capstone", "capstone"),
    ("pwntools", "pwn"),
    ("ropper", "ropper"),
    ("unicorn", "unicorn"),
)


def r2mcp_candidates() -> list[Path]:
    candidates: list[Path] = []
    env_bin = os.environ.get("R2MCP_BIN")
    if env_bin:
        candidates.append(Path(env_bin).expanduser())
    path_bin = shutil.which("r2mcp")
    if path_bin:
        candidates.append(Path(path_bin))
    candidates.extend(
        [
            Path.home() / ".local" / "bin" / "r2mcp",
            Path.home() / ".local" / "share" / "radare2" / "prefix" / "bin" / "r2mcp",
            Path("/usr/local/bin/r2mcp"),
            Path("/usr/bin/r2mcp"),
        ]
    )
    return candidates


def check_command(command: str) -> int:
    path = shutil.which(command)
    if path:
        print(f"PASS command {command}: {path}")
        return 0
    print(f"FAIL command {command}: missing")
    return 1


def check_docker_runtime() -> int:
    failures = 0
    info = subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}}"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=20,
    )
    if info.returncode == 0:
        print(f"PASS docker daemon: server {info.stdout.strip()}")
    else:
        reason = info.stderr.strip().splitlines()[-1] if info.stderr.strip() else "docker info failed"
        print(f"FAIL docker daemon: {reason}")
        return 1

    mounted_file = "tools/version_report.sh"
    run = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{ROOT}:/workspace:ro",
            "-w",
            "/workspace",
            "busybox:latest",
            "sh",
            "-c",
            f"test -f {mounted_file}",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if run.returncode == 0:
        print("PASS docker run workspace mount")
    else:
        reason = run.stderr.strip().splitlines()[-1] if run.stderr.strip() else "container run failed"
        print(f"FAIL docker run workspace mount: {reason}")
        failures += 1
    return failures


def check_r2mcp() -> int:
    for candidate in r2mcp_candidates():
        if candidate.is_file() and os.access(candidate, os.X_OK):
            print(f"PASS command r2mcp: {candidate}")
            return 0
    print("FAIL command r2mcp: missing")
    return 1


def check_python_module(package: str, module: str) -> int:
    if not VENV_PYTHON.is_file():
        print(f"FAIL python module {package}: missing .venv/bin/python")
        return 1
    result = subprocess.run(
        [str(VENV_PYTHON), "-c", f"import {module}"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode == 0:
        print(f"PASS python module {package}")
        return 0
    reason = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "import failed"
    print(f"FAIL python module {package}: {reason}")
    return 1


def main() -> int:
    failures = 0
    for command in COMMANDS:
        failures += check_command(command)
    if shutil.which("docker"):
        failures += check_docker_runtime()
    failures += check_r2mcp()
    for package, module in PYTHON_MODULES:
        failures += check_python_module(package, module)
    print(f"team parity summary failures={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
