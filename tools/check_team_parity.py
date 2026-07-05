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
    "rg",
    "binwalk",
    "exiftool",
    "nmap",
    "socat",
    "docker",
    "node",
    "npm",
    "npx",
    "gcc",
    "gdb",
    "mcp",
    "fastmcp",
    "mcp-proxy",
    "mcp-reverse-proxy",
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
    "RsaCtfTool",
    "arjun",
    "flask-unsign",
    "floss",
    "frida",
    "frida-ps",
    "shodan",
    "stegolsb",
    "zsteg",
    "wafw00f",
    "pwninit",
)
COMMAND_CHECKS = {
    "rg": ("rg", "--version"),
    "binwalk": ("binwalk", "--help"),
    "exiftool": ("exiftool", "-ver"),
    "nmap": ("nmap", "--version"),
    "socat": ("socat", "-V"),
    "mcp": ("mcp", "--help"),
    "fastmcp": ("fastmcp", "--version"),
    "mcp-proxy": ("mcp-proxy", "--version"),
    "mcp-reverse-proxy": ("mcp-reverse-proxy", "--version"),
    "RsaCtfTool": ("RsaCtfTool", "--help"),
    "arjun": ("arjun", "-h"),
    "flask-unsign": ("flask-unsign", "--version"),
    "floss": ("floss", "--version"),
    "frida": ("frida", "--version"),
    "frida-ps": ("frida-ps", "--version"),
    "shodan": ("shodan", "version"),
    "stegolsb": ("stegolsb", "--version"),
    "zsteg": ("zsteg", "--help"),
    "wafw00f": ("wafw00f", "--version"),
    "pwninit": ("pwninit", "--version"),
}
EXTERNAL_OPTIONAL_COMMANDS = (
    "burpsuite",
    "caido",
    "caido-cli",
)
PROXY_HELPERS = (
    ".codex/bin/ctf-proxy-start",
    ".codex/bin/ctf-proxy-check",
    ".codex/proxy.env.example",
)
PLAYWRIGHT_HELPER = ".codex/bin/playwright-mcp-codex.sh"
PYTHON_MODULES = (
    ("angr", "angr"),
    ("angr-mcp", "angr.mcp.__main__"),
    ("capstone", "capstone"),
    ("mcp", "mcp"),
    ("fastmcp", "fastmcp"),
    ("mcp-proxy", "mcp_proxy"),
    ("pwntools", "pwn"),
    ("ropper", "ropper"),
    ("unicorn", "unicorn"),
    ("arjun", "arjun"),
    ("flask-unsign", "flask_unsign"),
    ("flare-floss", "floss"),
    ("frida-tools", "frida"),
    ("shodan", "shodan"),
    ("stego-lsb", "stego_lsb"),
    ("wafw00f", "wafw00f"),
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


def output_line(result: subprocess.CompletedProcess[str]) -> str:
    lines = (result.stdout or result.stderr).strip().splitlines()
    return lines[0].strip() if lines else "check passed"


def check_command(command: str, *, required: bool = True) -> int:
    path = shutil.which(command)
    if not path:
        prefix = "FAIL" if required else "WARN"
        print(f"{prefix} command {command}: missing")
        return 1 if required else 0

    print(f"PASS command {command}: {path}")
    check = COMMAND_CHECKS.get(command)
    if not check:
        return 0

    try:
        result = subprocess.run(
            list(check),
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        prefix = "FAIL" if required else "WARN"
        print(f"{prefix} command check {command}: timed out")
        return 1 if required else 0
    if result.returncode == 0:
        print(f"PASS command check {command}: {output_line(result)}")
        return 0
    reason = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "command check failed"
    prefix = "FAIL" if required else "WARN"
    print(f"{prefix} command check {command}: {reason}")
    return 1 if required else 0


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

    compose = subprocess.run(
        ["docker", "compose", "version"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=20,
    )
    if compose.returncode == 0:
        print(f"PASS docker compose v2: {compose.stdout.strip()}")
    else:
        reason = compose.stderr.strip().splitlines()[-1] if compose.stderr.strip() else "docker compose failed"
        print(f"FAIL docker compose v2: {reason}")
        failures += 1

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


def check_proxy_helpers() -> int:
    failures = 0
    for relative in PROXY_HELPERS:
        path = ROOT / relative
        if path.is_file():
            print(f"PASS web proxy helper {relative}")
        else:
            print(f"FAIL web proxy helper {relative}: missing")
            failures += 1

    for relative in (".codex/bin/ctf-proxy-start", ".codex/bin/ctf-proxy-check"):
        path = ROOT / relative
        if path.is_file() and os.access(path, os.X_OK):
            print(f"PASS web proxy helper executable {relative}")
        else:
            print(f"FAIL web proxy helper executable {relative}")
            failures += 1

    caido_paths = (
        Path("/mnt/c/Program Files/Caido/resources/bin/caido-cli.exe"),
        Path("/mnt/c/Program Files (x86)/Caido/resources/bin/caido-cli.exe"),
    )
    local_caido = subprocess.run(
        [
            "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
            "-NoProfile",
            "-Command",
            'Test-Path "$env:LOCALAPPDATA\\ctf-workspace\\caido-cli\\caido-cli.exe"',
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    has_local_caido = local_caido.returncode == 0 and "True" in local_caido.stdout
    if shutil.which("caido-cli") or any(path.is_file() for path in caido_paths) or has_local_caido:
        print("PASS web proxy bridge backend caido-cli")
    else:
        print("WARN web proxy bridge backend caido-cli: missing; ctf-proxy-start will install it")
    return failures


def check_playwright_helper() -> int:
    path = ROOT / PLAYWRIGHT_HELPER
    if not path.is_file() or not os.access(path, os.X_OK):
        print(f"FAIL playwright helper executable {PLAYWRIGHT_HELPER}")
        return 1
    print(f"PASS playwright helper executable {PLAYWRIGHT_HELPER}")

    result = subprocess.run(
        [str(path), "--print-browser"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    browser = result.stdout.strip()
    if result.returncode == 0 and browser:
        print(f"PASS playwright browser executable {browser}")
        return 0
    reason = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "browser not found"
    print(f"FAIL playwright browser executable: {reason}")
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


def check_level3_tool_routing() -> int:
    result = subprocess.run(
        [sys.executable, "tools/check_level3_tool_routing.py"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    output = "\n".join(part for part in (result.stdout, result.stderr) if part.strip())
    for line in output.splitlines():
        print(line)
    return 0 if result.returncode == 0 else 1


def main() -> int:
    failures = 0
    for command in COMMANDS:
        failures += check_command(command)
    for command in EXTERNAL_OPTIONAL_COMMANDS:
        check_command(command, required=False)
    if shutil.which("docker"):
        failures += check_docker_runtime()
    failures += check_r2mcp()
    failures += check_proxy_helpers()
    failures += check_playwright_helper()
    for package, module in PYTHON_MODULES:
        failures += check_python_module(package, module)
    failures += check_level3_tool_routing()
    print(f"team parity summary failures={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
