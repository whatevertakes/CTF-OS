#!/usr/bin/env python3
"""Check the Level 0-4 workspace contract before benchmark or replay work."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VENV_PYTHON = ROOT / ".venv" / "bin" / "python"
CTF_SKILL_DIR = ROOT / "skills"

REQUIRED_PATHS = (
    "AGENTS.md",
    ".codex/env.sh",
    ".codex/config.toml",
    ".codex/bin/r2mcp-codex.sh",
    ".codex/bin/searchsploit",
    ".codex/bin/tplmap",
    "capabilities/registry.yaml",
    "docs/CTF_SOLVE_PLAYBOOKS.md",
    "tools/intake_challenge.py",
    "tools/replay_runner.py",
    "tools/proof_validate.py",
    "tools/level3_orchestrator.py",
    "tools/level4_interface.py",
    "templates/challenge/state.json",
    "benchmarks/level2_selftest.py",
    "benchmarks/level3_selftest.py",
    "benchmarks/level4_selftest.py",
    "docs/LEVEL0_INFRASTRUCTURE.md",
    "docs/LEVEL1_CORE_ENGINE.md",
    "docs/LEVEL2_CAPABILITY_MAP.md",
    "docs/LEVEL3_DESIGN_NOTES.md",
    "docs/LEVEL4_INTERFACES.md",
)

REQUIRED_COMMANDS = ("bash", "git", "python3")
OPTIONAL_COMMANDS = (
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
    ("requests", "requests"),
    ("httpx", "httpx"),
    ("aiohttp", "aiohttp"),
    ("beautifulsoup4", "bs4"),
    ("lxml", "lxml"),
    ("flask", "flask"),
    ("jinja2", "jinja2"),
    ("pwntools", "pwn"),
    ("sqlmap", "sqlmap"),
    ("defusedxml", "defusedxml"),
    ("PyYAML", "yaml"),
    ("capstone", "capstone"),
    ("pefile", "pefile"),
    ("unicorn", "unicorn"),
)

REQUIRED_SKILL_SECTIONS = ("workflow:", "first_commands:", "docs/CTF_SOLVE_PLAYBOOKS.md")


class Reporter:
    def __init__(self) -> None:
        self.failures = 0
        self.warnings = 0

    def pass_(self, label: str) -> None:
        print(f"PASS {label}")

    def warn(self, label: str) -> None:
        self.warnings += 1
        print(f"WARN {label}")

    def fail(self, label: str) -> None:
        self.failures += 1
        print(f"FAIL {label}")


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)


def check_paths(reporter: Reporter) -> None:
    for relative in REQUIRED_PATHS:
        path = ROOT / relative
        if path.exists():
            reporter.pass_(f"path {relative}")
        else:
            reporter.fail(f"missing path {relative}")

    for dirname in (".cache", ".venv", "challenges", "docs", "skills"):
        path = ROOT / dirname
        if path.is_dir():
            reporter.pass_(f"directory {dirname}")
        else:
            reporter.fail(f"missing directory {dirname}")


def check_ctf_skills(reporter: Reporter) -> None:
    skill_paths = sorted(CTF_SKILL_DIR.glob("ctf-*/SKILL.md"))
    if skill_paths:
        reporter.pass_(f"ctf skill files count={len(skill_paths)}")
    else:
        reporter.fail("missing ctf skill files under skills/ctf-*/SKILL.md")
        return

    for path in skill_paths:
        relative = path.relative_to(ROOT).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            reporter.fail(f"cannot read {relative}: {exc}")
            continue
        missing = [section for section in REQUIRED_SKILL_SECTIONS if section not in text]
        if missing:
            reporter.fail(f"skill contract incomplete {relative}: missing {', '.join(missing)}")
        else:
            reporter.pass_(f"skill contract {relative}")


def check_commands(reporter: Reporter, *, strict_optional: bool) -> None:
    for command in REQUIRED_COMMANDS:
        if shutil.which(command):
            reporter.pass_(f"command {command}")
        else:
            reporter.fail(f"missing command {command}")

    for command in OPTIONAL_COMMANDS:
        if shutil.which(command):
            reporter.pass_(f"optional command {command}")
        elif strict_optional:
            reporter.fail(f"missing optional command {command}")
        else:
            reporter.warn(f"optional command unavailable {command}")

    if shutil.which("docker"):
        result = run(["docker", "info", "--format", "{{.ServerVersion}}"])
        if result.returncode == 0 and result.stdout.strip():
            reporter.pass_(f"docker daemon reachable version={result.stdout.strip()}")
        elif strict_optional:
            reason = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "docker info failed"
            reporter.fail(f"docker daemon unreachable: {reason}")
        else:
            reporter.warn("docker daemon unreachable")


def check_python_modules(reporter: Reporter) -> None:
    if not VENV_PYTHON.is_file():
        reporter.fail(f"missing virtualenv python {VENV_PYTHON.relative_to(ROOT)}")
        return

    for package, module in PYTHON_MODULES:
        result = run([str(VENV_PYTHON), "-c", f"import {module}"])
        if result.returncode == 0:
            reporter.pass_(f"python module {package}")
        else:
            reason = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "import failed"
            reporter.fail(f"python module {package}: {reason}")


def check_config(reporter: Reporter) -> None:
    config_path = ROOT / ".codex" / "config.toml"
    try:
        config = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        reporter.fail(f"cannot read .codex/config.toml: {exc}")
        return
    except tomllib.TOMLDecodeError as exc:
        reporter.fail(f"invalid .codex/config.toml: {exc}")
        return

    expected_scalars = {
        "approval_policy": "never",
        "sandbox_mode": "danger-full-access",
        "model_reasoning_effort": "xhigh",
        "plan_mode_reasoning_effort": "xhigh",
    }
    for key, expected in expected_scalars.items():
        actual = config.get(key)
        if actual == expected:
            reporter.pass_(f"config {key}={expected}")
        else:
            reporter.fail(f"config {key} expected {expected!r}, got {actual!r}")

    shell_env = config.get("shell_environment_policy", {}).get("set", {})
    expected_env = {
        "BASH_ENV": str(ROOT / ".codex" / "env.sh"),
        "CTF_WORKSPACE_ROOT": str(ROOT),
    }
    for key, expected in expected_env.items():
        actual = shell_env.get(key)
        if actual == expected:
            reporter.pass_(f"config shell env {key}")
        else:
            reporter.fail(f"config shell env {key} expected {expected!r}, got {actual!r}")

    projects = config.get("projects", {})
    trust = projects.get(str(ROOT), {}).get("trust_level")
    if trust == "trusted":
        reporter.pass_("config project trust")
    else:
        reporter.fail(f"config project trust expected 'trusted', got {trust!r}")

    mcp = config.get("mcp_servers", {})
    radare2 = mcp.get("radare2", {}).get("command")
    if radare2 == str(ROOT / ".codex" / "bin" / "r2mcp-codex.sh"):
        reporter.pass_("config mcp radare2 wrapper")
    else:
        reporter.fail(f"config mcp radare2 wrapper mismatch: {radare2!r}")

    if "angr" in mcp and "playwright" in mcp:
        reporter.pass_("config mcp angr/playwright present")
    else:
        reporter.fail("config mcp angr/playwright missing")


def check_runtime_environment(reporter: Reporter) -> None:
    if os.environ.get("CTF_WORKSPACE_ROOT") == str(ROOT):
        reporter.pass_("environment CTF_WORKSPACE_ROOT")
    else:
        reporter.warn("environment CTF_WORKSPACE_ROOT is not set to workspace root")

    path = os.environ.get("PATH", "")
    if str(ROOT / ".codex" / "bin") in path.split(os.pathsep):
        reporter.pass_("environment PATH includes .codex/bin")
    else:
        reporter.warn("environment PATH does not include .codex/bin")

    if str(ROOT / ".venv" / "bin") in path.split(os.pathsep):
        reporter.pass_("environment PATH includes .venv/bin")
    else:
        reporter.warn("environment PATH does not include .venv/bin")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--strict-optional",
        action="store_true",
        help="treat optional command-line tooling as required",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    reporter = Reporter()
    check_paths(reporter)
    check_ctf_skills(reporter)
    check_commands(reporter, strict_optional=args.strict_optional)
    check_python_modules(reporter)
    check_config(reporter)
    check_runtime_environment(reporter)

    print(f"summary failures={reporter.failures} warnings={reporter.warnings}")
    return 1 if reporter.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
