#!/usr/bin/env python3
"""Regression contract for the repaired non-SQL CTF tool surface."""

from __future__ import annotations

import ast
import json
import pathlib
import re


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
agents = (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")
catalog_source = (REPO_ROOT / "scripts" / "gen-manifest.sh").read_text(
    encoding="utf-8"
)
browser_source = (REPO_ROOT / "templates" / "web" / "browser.py").read_text(
    encoding="utf-8"
)
managed_manifest = json.loads(
    (REPO_ROOT / "capabilities.v2.json").read_text(encoding="utf-8")
)
managed_probe_source = (
    REPO_ROOT / "scripts" / "ctf-capabilities"
).read_text(encoding="utf-8")
sqlite_wrapper_source = (
    REPO_ROOT / "scripts" / "ctf-sqlite-readonly"
).read_text(encoding="utf-8")

assert "sqlmap" not in dockerfile.casefold()
assert not re.search(r"\b25\s*gb\b", dockerfile, flags=re.IGNORECASE)
assert not re.search(r"\b25\s*gb\b", agents, flags=re.IGNORECASE)
assert "/opt/playwright/chromium-" not in dockerfile
assert "SKIP:" not in dockerfile
assert dockerfile.count("/tools/failed.txt") == 2
assert ": > /tools/failed.txt" in dockerfile
assert "rm -f /tools/failed.txt" in dockerfile

required_dockerfile_tokens = {
    "cysignals",
    "pycryptodome==3.23.0",
    "h2spacex==1.2.2",
    "--only-shell chromium",
    "qemu-system-arm",
    "qemu-system-mips",
    "wine32:i386",
    "libregf-utils",
    "libevtx-utils",
    "qemu-utils",
    "squashfs-tools",
    "poppler-utils",
    "wabt",
    "binaryen",
    "hash_extender",
    "bkcrack",
    "qemu-system-mips.real",
    "qemu-system-x86_64.real",
    "/usr/local/lib/ctf-cuda",
    "libnvrtc.so.13",
}
missing_tokens = sorted(
    token for token in required_dockerfile_tokens if token not in dockerfile
)
assert not missing_tokens, missing_tokens

catalog_match = re.search(
    r"<<'CATALOG'\n(?P<catalog>.*?)\nCATALOG\n",
    catalog_source,
    flags=re.DOTALL,
)
assert catalog_match is not None
catalog_rows = [
    line.split("|") for line in catalog_match.group("catalog").splitlines()
]
assert all(len(row) == 6 for row in catalog_rows)
identities = [(row[0].casefold(), row[1].casefold()) for row in catalog_rows]
assert len(identities) == len(set(identities))

catalog_names = {row[1] for row in catalog_rows}
required_catalog_names = {
    "bkcrack",
    "crypto-python",
    "ctf-browser",
    "evtxexport",
    "fls",
    "frida-trace",
    "hash_extender",
    "msoffcrypto-tool",
    "pahole",
    "pdfimages",
    "playwright",
    "pw-python",
    "qemu-img",
    "qemu-system-aarch64",
    "rabin2",
    "ropr",
    "sage-python",
    "uncompyle6",
    "unsquashfs",
    "wasm2wat",
    "web-python",
    "wine",
}
assert required_catalog_names <= catalog_names
assert "sqlmap" not in {name.casefold() for name in catalog_names}

ast.parse(browser_source, filename="templates/web/browser.py")
assert browser_source.startswith("#!/opt/venvs/pw/bin/python\n")
ast.parse(managed_probe_source, filename="scripts/ctf-capabilities")
ast.parse(sqlite_wrapper_source, filename="scripts/ctf-sqlite-readonly")
assert managed_manifest["schema_version"] == 2
assert {
    item["name"] for item in managed_manifest["capabilities"]
} == {"convert", "sqlite_readonly", "z3", "ortools", "angr_python"}
assert "COPY capabilities.v2.json /tools/capabilities.json" in dockerfile
assert "--network" not in managed_probe_source
assert "mode=ro&immutable=1" in sqlite_wrapper_source
assert "PRAGMA query_only=ON" in sqlite_wrapper_source

print("capability contract: ok")
