#!/usr/bin/env python3
"""Validate Level 3 category tool routing coverage.

This check is intentionally structural. It verifies that installed CTF helper
CLIs are surfaced in the Level 3 strategy packets and the matching category
skill files, without requiring those CLIs to be MCP servers.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
LEVEL3_PATH = ROOT / "tools" / "level3_orchestrator.py"

EXPECTED_CATEGORY_TOOLS: dict[str, dict[str, list[str]]] = {
    "web": {
        "level3": ["arjun", "flask-unsign", "wafw00f", "shodan", "sqlmap", "ffuf", "gobuster", "Burp/Caido"],
        "skill": ["arjun", "flask-unsign", "wafw00f", "shodan", "sqlmap", "ffuf", "gobuster", "Burp Suite or Caido"],
    },
    "pwn": {
        "level3": ["pwninit", "ROPgadget", "ropper", "one_gadget", "seccomp-tools", "patchelf", "qemu-user"],
        "skill": ["pwninit", "ROPgadget", "ropper", "one_gadget", "seccomp-tools", "patchelf", "qemu-user"],
    },
    "rev": {
        "level3": ["floss", ".codex/bin/r2", ".codex/bin/angr-mcp", "yara/upx"],
        "skill": ["floss", "radare2/angr MCP", "yara", "upx"],
    },
    "crypto": {
        "level3": ["RsaCtfTool", "sage", "z3", "fplll", "pari-gp/gp"],
        "skill": ["RsaCtfTool", "Sage", "z3", "fplll", "pari-gp/gp"],
    },
    "forensics": {
        "level3": ["tshark", "vol/Volatility3", "floss", "zsteg/stegolsb"],
        "skill": ["tshark", "Volatility3", "floss", "stegolsb", "zsteg"],
    },
    "stego": {
        "level3": ["steghide", "zsteg", "stegolsb"],
        "skill": ["steghide", "zsteg", "stegolsb"],
    },
    "mobile": {
        "level3": ["jadx", "apktool", "frida/frida-ps"],
        "skill": ["jadx", "apktool", "frida"],
    },
    "malware": {
        "level3": ["floss", "yara", "upx", ".codex/bin/r2", ".codex/bin/angr-mcp", "vol/Volatility3", "tshark"],
        "skill": ["floss", "yara", "upx", "radare2/angr MCP", "Volatility3", "tshark"],
    },
    "web3": {
        "level3": ["forge", "cast", "anvil", "chisel", "solc", "slither"],
        "skill": ["forge", "cast", "anvil", "chisel", "solc", "slither"],
    },
    "cloud": {
        "level3": ["kubectl", "trivy", "syft", "grype", "crane", "skopeo"],
        "skill": ["kubectl", "trivy", "syft", "grype", "crane", "skopeo"],
    },
    "container": {
        "level3": ["docker", "kubectl", "trivy", "syft", "grype", "crane", "skopeo"],
        "skill": ["docker", "kubectl", "trivy", "syft", "grype", "crane", "skopeo"],
    },
}


def load_level3() -> Any:
    spec = importlib.util.spec_from_file_location("level3_orchestrator", LEVEL3_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {LEVEL3_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def flatten_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        items: list[str] = []
        for nested in value.values():
            items.extend(flatten_strings(nested))
        return items
    if isinstance(value, (list, tuple, set)):
        items = []
        for nested in value:
            items.extend(flatten_strings(nested))
        return items
    return []


def token_present(blob: str, token: str) -> bool:
    lowered = blob.lower()
    alternatives = [part.strip() for part in token.split("/") if part.strip()]
    if len(alternatives) > 1:
        return all(part.lower() in lowered for part in alternatives)
    return token.lower() in lowered


def check_expected(name: str, blob: str, expected: list[str]) -> int:
    failures = 0
    for token in expected:
        if token_present(blob, token):
            print(f"PASS {name}: {token}")
        else:
            print(f"FAIL {name}: missing {token}")
            failures += 1
    return failures


def category_strategy_blob(level3: Any, category: str) -> str:
    values: list[str] = []
    values.extend(flatten_strings(level3.CATEGORY_DEFAULT_STRATEGIES.get(category, {})))
    values.extend(flatten_strings(level3.WORKER_STRATEGY_OVERRIDES.get(category, {})))
    return "\n".join(values)


def skill_blob(level3: Any, category: str) -> str:
    skill_path = level3.SKILL_FOR_CATEGORY.get(category)
    if not skill_path:
        return ""
    path = ROOT / skill_path
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def main() -> int:
    level3 = load_level3()
    failures = 0
    for category, expected in EXPECTED_CATEGORY_TOOLS.items():
        strategy_text = category_strategy_blob(level3, category)
        skill_text = skill_blob(level3, category)
        failures += check_expected(f"level3 {category}", strategy_text, expected["level3"])
        failures += check_expected(f"skill {category}", skill_text, expected["skill"])
    print(f"level3 tool routing summary failures={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
