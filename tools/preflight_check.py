#!/usr/bin/env python3
"""Check the Level 0-6 workspace contract before benchmark or replay work."""

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
    ".codex/config.toml.template",
    ".codex/proxy.env.example",
    ".codex/bin/ctf-proxy-check",
    ".codex/bin/ctf-proxy-start",
    ".codex/bin/r2mcp-codex.sh",
    ".codex/bin/searchsploit",
    ".codex/bin/tplmap",
    "capabilities/registry.yaml",
    "references.yaml",
    "references.lock.json",
    "docs/CATEGORY_REFERENCE_MAP.md",
    "docs/CTF_SOLVE_PLAYBOOKS.md",
    "docs/TOOLCHAIN_MATRIX.md",
    "docs/reference-digests/common.md",
    "docs/reference-digests/pwn.md",
    "docs/reference-digests/web.md",
    "docs/reference-digests/rev.md",
    "docs/reference-digests/crypto.md",
    "docs/reference-digests/forensics.md",
    "docs/reference-digests/stego.md",
    "docs/reference-digests/mobile.md",
    "docs/reference-digests/malware.md",
    "docs/reference-digests/web3.md",
    "docs/reference-digests/cloud-container.md",
    "docs/reference-digests/ai-ml.md",
    "docs/reference-digests/hardware-rf-side-channel.md",
    "docs/reference-digests/osint.md",
    "docs/reference-digests/jail.md",
    "docs/reference-digests/programming.md",
    "docs/reference-digests/misc.md",
    "docs/reference-digests/hybrid.md",
    "docs/reference-index/common.json",
    "docs/reference-index/pwn.json",
    "docs/reference-index/web.json",
    "docs/reference-index/rev.json",
    "docs/reference-index/crypto.json",
    "docs/reference-index/forensics.json",
    "docs/reference-index/stego.json",
    "docs/reference-index/mobile.json",
    "docs/reference-index/malware.json",
    "docs/reference-index/web3.json",
    "docs/reference-index/cloud-container.json",
    "docs/reference-index/ai-ml.json",
    "docs/reference-index/hardware-rf-side-channel.json",
    "docs/reference-index/osint.json",
    "docs/reference-index/jail.json",
    "docs/reference-index/programming.json",
    "docs/reference-index/misc.json",
    "docs/reference-index/hybrid.json",
    "tools/intake_challenge.py",
    "tools/replay_runner.py",
    "tools/proof_validate.py",
    "tools/reference_refresh.py",
    "tools/reference_index.py",
    "tools/reference_query.py",
    "tools/reference_digest_check.py",
    "tools/benchmark_runner.py",
    "tools/report_sanitize.py",
    "tools/cleanup_artifacts.py",
    "tools/evaluate_corpus.py",
    "tools/failure_taxonomy.py",
    "tools/regression_check.py",
    "tools/level3_orchestrator.py",
    "tools/level4_interface.py",
    "tools/team_member_setup.sh",
    "tools/validate_data_submission.py",
    "templates/challenge/state.json",
    "benchmarks/corpus.yaml",
    "benchmarks/level2_selftest.py",
    "benchmarks/level3_selftest.py",
    "benchmarks/level4_selftest.py",
    "benchmarks/level5_selftest.py",
    "benchmarks/level6_selftest.py",
    "docs/LEVEL0_INFRASTRUCTURE.md",
    "docs/LEVEL1_CORE_ENGINE.md",
    "docs/LEVEL2_CAPABILITY_MAP.md",
    "docs/LEVEL3_DESIGN_NOTES.md",
    "docs/LEVEL4_INTERFACES.md",
    "docs/LEVEL5_AUTOMATION_POLICY.md",
    "docs/LEVEL6_EVALUATION_POLICY.md",
    "docs/LEVEL6_AGENT_DESIGN_INPUTS.md",
    "docs/FAILURE_TAXONOMY.md",
)

REQUIRED_COMMANDS = ("bash", "git", "python3")
AVR_REQUIRED_COMMANDS = ("avr-gcc", "avr-objdump", "avr-objcopy", "avr-size")
AVR_TRIGGER_CATEGORIES = {"hardware-rf"}
AVR_TRIGGER_TAGS = {"avr", "firmware", "arduino"}
OPTIONAL_COMMANDS = (
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

OPTIONAL_COMMAND_CHECKS = {
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

DEEP_CATEGORY_COMMANDS = {
    "crypto": (
        ("RsaCtfTool", ("RsaCtfTool", "--help")),
        ("z3", ("z3", "--version")),
        ("fplll", ("fplll", "--version")),
        ("pari-gp", ("gp", "--version")),
    ),
    "forensics": (
        ("floss", ("floss", "--version")),
        ("stegolsb", ("stegolsb", "--version")),
        ("zsteg", ("zsteg", "--help")),
        ("yara", ("yara", "--version")),
        ("upx", ("upx", "--version")),
        ("sleuthkit-fls", ("fls", "-V")),
        ("volatility3", ("vol", "--help")),
    ),
    "malware": (
        ("yara", ("yara", "--version")),
        ("upx", ("upx", "--version")),
        ("volatility3", ("vol", "--help")),
    ),
    "mobile": (
        ("jadx", ("jadx", "--version")),
        ("apktool", ("apktool", "--version")),
        ("frida", ("frida", "--version")),
        ("frida-ps", ("frida-ps", "--version")),
    ),
    "pwn": (
        ("pwninit", ("pwninit", "--version")),
        ("qemu-user-x86_64", ("qemu-x86_64", "--version")),
        ("qemu-user-aarch64", ("qemu-aarch64", "--version")),
        ("qemu-system-x86_64", ("qemu-system-x86_64", "--version")),
        ("qemu-system-arm", ("qemu-system-arm", "--version")),
        ("qemu-system-aarch64", ("qemu-system-aarch64", "--version")),
    ),
    "rev": (
        ("floss", ("floss", "--version")),
        ("yara", ("yara", "--version")),
        ("upx", ("upx", "--version")),
        ("qemu-user-x86_64", ("qemu-x86_64", "--version")),
        ("qemu-user-aarch64", ("qemu-aarch64", "--version")),
        ("qemu-system-x86_64", ("qemu-system-x86_64", "--version")),
        ("qemu-system-arm", ("qemu-system-arm", "--version")),
        ("qemu-system-aarch64", ("qemu-system-aarch64", "--version")),
    ),
    "misc": (
        ("qemu-user-x86_64", ("qemu-x86_64", "--version")),
        ("qemu-user-aarch64", ("qemu-aarch64", "--version")),
        ("qemu-system-x86_64", ("qemu-system-x86_64", "--version")),
        ("qemu-system-arm", ("qemu-system-arm", "--version")),
        ("qemu-system-aarch64", ("qemu-system-aarch64", "--version")),
    ),
    "programming": (
        ("z3", ("z3", "--version")),
    ),
    "stego": (
        ("stegolsb", ("stegolsb", "--version")),
        ("zsteg", ("zsteg", "--help")),
    ),
    "web": (
        ("arjun", ("arjun", "-h")),
        ("flask-unsign", ("flask-unsign", "--version")),
        ("shodan", ("shodan", "version")),
        ("wafw00f", ("wafw00f", "--version")),
    ),
    "web3": (
        ("forge", ("forge", "--version")),
        ("cast", ("cast", "--version")),
        ("anvil", ("anvil", "--version")),
        ("slither", ("slither", "--version")),
    ),
    "cloud": (
        ("trivy", ("trivy", "--version")),
        ("syft", ("syft", "version")),
        ("grype", ("grype", "version")),
        ("crane", ("crane", "version")),
        ("skopeo", ("skopeo", "--version")),
    ),
    "container": (
        ("trivy", ("trivy", "--version")),
        ("syft", ("syft", "version")),
        ("grype", ("grype", "version")),
        ("crane", ("crane", "version")),
        ("skopeo", ("skopeo", "--version")),
    ),
}

DEEP_CATEGORY_MODULES = {
    "crypto": (
        ("z3-solver", "z3"),
        ("fpylll", "fpylll"),
    ),
    "forensics": (
        ("yara-python", "yara"),
        ("volatility3", "volatility3"),
    ),
    "malware": (
        ("yara-python", "yara"),
        ("volatility3", "volatility3"),
    ),
    "programming": (
        ("z3-solver", "z3"),
    ),
    "web3": (
        ("slither-analyzer", "slither"),
    ),
}

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
    ("mcp", "mcp"),
    ("fastmcp", "fastmcp"),
    ("mcp-proxy", "mcp_proxy"),
    ("angr-mcp", "angr.mcp.__main__"),
    ("arjun", "arjun"),
    ("flask-unsign", "flask_unsign"),
    ("flare-floss", "floss"),
    ("frida-tools", "frida"),
    ("shodan", "shodan"),
    ("stego-lsb", "stego_lsb"),
    ("wafw00f", "wafw00f"),
)

REQUIRED_SKILL_SECTIONS = (
    "workflow:",
    "first_commands:",
    "reference_digest:",
    "docs/CTF_SOLVE_PLAYBOOKS.md",
)


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


def check_reference_layer(reporter: Reporter) -> None:
    for name, command in (
        ("reference manifest", ["python3", "tools/reference_refresh.py"]),
        ("reference index", ["python3", "tools/reference_index.py", "--check"]),
        ("reference digest wiring", ["python3", "tools/reference_digest_check.py"]),
    ):
        result = run(command)
        if result.returncode == 0:
            reporter.pass_(name)
        else:
            reason = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "check failed"
            reporter.fail(f"{name}: {reason}")


def check_commands(reporter: Reporter, *, strict_optional: bool) -> None:
    for command in REQUIRED_COMMANDS:
        if shutil.which(command):
            reporter.pass_(f"command {command}")
        else:
            reporter.fail(f"missing command {command}")

    for command in OPTIONAL_COMMANDS:
        if shutil.which(command):
            reporter.pass_(f"optional command {command}")
            check = OPTIONAL_COMMAND_CHECKS.get(command)
            if check:
                ok, detail = command_version_line(check)
                if ok:
                    reporter.pass_(f"optional command check {command}: {detail}")
                elif strict_optional:
                    reporter.fail(f"optional command check failed {command}: {detail}")
                else:
                    reporter.warn(f"optional command check failed {command}: {detail}")
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

        compose = run(["docker", "compose", "version"])
        if compose.returncode == 0 and compose.stdout.strip():
            reporter.pass_(f"docker compose v2 available {compose.stdout.strip()}")
        elif strict_optional:
            reason = compose.stderr.strip().splitlines()[-1] if compose.stderr.strip() else "docker compose failed"
            reporter.fail(f"docker compose v2 unavailable: {reason}")
        else:
            reporter.warn("docker compose v2 unavailable")


def requires_avr_toolchain(category: str | None, tags: list[str]) -> bool:
    normalized_category = (category or "").strip().lower()
    normalized_tags = {tag.strip().lower() for tag in tags if tag.strip()}
    return normalized_category in AVR_TRIGGER_CATEGORIES or bool(normalized_tags & AVR_TRIGGER_TAGS)


def check_avr_toolchain(reporter: Reporter) -> None:
    missing = []
    for command in AVR_REQUIRED_COMMANDS:
        if shutil.which(command):
            reporter.pass_(f"command {command}")
        else:
            missing.append(command)
    if missing:
        reporter.fail(f"dependency_missing: avr toolchain missing {', '.join(missing)}")
    else:
        reporter.pass_("dependency avr toolchain")


def normalize_category(value: str | None) -> str:
    return (value or "").strip().lower()


def command_version_line(command: tuple[str, ...]) -> tuple[bool, str]:
    result = run(list(command))
    if result.returncode != 0:
        reason = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "version check failed"
        return False, reason
    lines = (result.stdout or result.stderr).strip().splitlines()
    return True, lines[0].strip() if lines else "version check passed"


def check_deep_category_tools(reporter: Reporter, category: str | None) -> None:
    normalized = normalize_category(category)
    if not normalized:
        reporter.warn("deep category checks skipped: --category is required with --deep")
        return

    commands = DEEP_CATEGORY_COMMANDS.get(normalized, ())
    modules = DEEP_CATEGORY_MODULES.get(normalized, ())
    if not commands and not modules:
        reporter.warn(f"deep category checks have no configured tool profile for {normalized}")
        return

    for label, command in commands:
        executable = command[0]
        if shutil.which(executable):
            ok, detail = command_version_line(command)
            if ok:
                reporter.pass_(f"deep optional command {label}: {detail}")
            else:
                reporter.warn(f"deep optional command check failed {label}: {detail}")
        else:
            reporter.warn(f"deep optional command unavailable {label}")

    if not VENV_PYTHON.is_file():
        if modules:
            reporter.warn(f"deep python modules skipped for {normalized}: missing virtualenv python")
        return

    for package, module in modules:
        result = run([str(VENV_PYTHON), "-c", f"import {module}"])
        if result.returncode == 0:
            reporter.pass_(f"deep python module {package}")
        else:
            reason = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "import failed"
            reporter.warn(f"deep optional python module unavailable {package}: {reason}")


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
    parser.add_argument("--category", help="optional challenge category for category-specific dependency checks")
    parser.add_argument(
        "--tag",
        action="append",
        default=[],
        help="optional challenge tag for tag-specific dependency checks; may be repeated",
    )
    parser.add_argument(
        "--strict-optional",
        action="store_true",
        help="treat optional command-line tooling as required",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="run opt-in category-specific advanced tool availability checks",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    reporter = Reporter()
    check_paths(reporter)
    check_ctf_skills(reporter)
    check_reference_layer(reporter)
    check_commands(reporter, strict_optional=args.strict_optional)
    if requires_avr_toolchain(args.category, args.tag):
        check_avr_toolchain(reporter)
    if args.deep:
        check_deep_category_tools(reporter, args.category)
    check_python_modules(reporter)
    check_config(reporter)
    check_runtime_environment(reporter)

    print(f"summary failures={reporter.failures} warnings={reporter.warnings}")
    return 1 if reporter.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
