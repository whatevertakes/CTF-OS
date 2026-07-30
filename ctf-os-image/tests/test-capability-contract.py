#!/usr/bin/env python3
"""Regression contract for the repaired non-SQL CTF tool surface."""

from __future__ import annotations

import ast
import hashlib
import json
import pathlib
import re
import runpy
import tempfile


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
agents = (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")
catalog_source = (REPO_ROOT / "scripts" / "gen-manifest.sh").read_text(
    encoding="utf-8"
)
browser_source = (REPO_ROOT / "templates" / "web" / "browser.py").read_text(
    encoding="utf-8"
)
active_probe_source = (
    REPO_ROOT / "templates" / "web" / "active_probe.py"
).read_text(encoding="utf-8")
forensic_index_source = (
    REPO_ROOT / "templates" / "forensic" / "evidence_index.py"
).read_text(encoding="utf-8")
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
    "ctf-web-probe",
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
ast.parse(
    active_probe_source,
    filename="templates/web/active_probe.py",
)
assert active_probe_source.startswith("#!/usr/bin/env python3\n")
ast.parse(
    forensic_index_source,
    filename="templates/forensic/evidence_index.py",
)
assert forensic_index_source.startswith("#!/usr/bin/env python3\n")
assert (
    "/opt/ctf-templates/forensic/evidence_index.py"
    in dockerfile
)
ast.parse(managed_probe_source, filename="scripts/ctf-capabilities")
ast.parse(sqlite_wrapper_source, filename="scripts/ctf-sqlite-readonly")
assert managed_manifest["schema_version"] == 2
assert len(managed_manifest["capabilities"]) == 12
assert {
    item["name"] for item in managed_manifest["capabilities"]
} == {
    "convert",
    "sqlite_readonly",
    "z3",
    "ortools",
    "angr_python",
    "pwn_crash_v1",
    "pwn_runtime_snapshot_v1",
    "pwn_exploit_effect_v1",
    "pwn_interaction_v1",
    "rev_inventory_v2",
    "rev_safe_output",
    "rev_stdin_exec",
}
managed_attestations = {
    item["name"]: item
    for item in managed_manifest["capabilities"]
    if item["name"]
    in {
        "pwn_crash_v1",
        "pwn_runtime_snapshot_v1",
        "pwn_exploit_effect_v1",
        "pwn_interaction_v1",
        "rev_inventory_v2",
        "rev_safe_output",
        "rev_stdin_exec",
    }
}
expected_managed_attestations = {
    "pwn_crash_v1": {
        "path": "/opt/ctf-templates/pwn/crash_oracle.py",
        "source": REPO_ROOT / "templates" / "pwn" / "crash_oracle.py",
        "contract_id": "ctfos.pwn.crash",
        "contract_version": 1,
    },
    "pwn_runtime_snapshot_v1": {
        "path": "/opt/ctf-templates/pwn/runtime_snapshot.py",
        "source": (
            REPO_ROOT / "templates" / "pwn" / "runtime_snapshot.py"
        ),
        "contract_id": "ctfos.pwn.runtime_snapshot",
        "contract_version": 1,
    },
    "pwn_exploit_effect_v1": {
        "path": "/opt/ctf-templates/pwn/exploit_effect.py",
        "source": REPO_ROOT / "templates" / "pwn" / "exploit_effect.py",
        "contract_id": "ctfos.pwn.exploit_effect",
        "contract_version": 1,
    },
    "pwn_interaction_v1": {
        "path": "/opt/ctf-templates/pwn/interaction.py",
        "source": REPO_ROOT / "templates" / "pwn" / "interaction.py",
        "contract_id": "ctfos.pwn.interaction",
        "contract_version": 1,
    },
    "rev_inventory_v2": {
        "path": "/opt/ctf-templates/rev/inventory_v2.py",
        "source": REPO_ROOT / "templates" / "rev" / "inventory_v2.py",
        "contract_id": "ctfos.rev.inventory",
        "contract_version": 2,
    },
    "rev_stdin_exec": {
        "path": "/opt/ctf-templates/rev/stdin_exec.py",
        "source": REPO_ROOT / "templates" / "rev" / "stdin_exec.py",
        "contract_id": "ctfos.rev.stdin_exec",
        "contract_version": 1,
    },
    "rev_safe_output": {
        "path": "/opt/ctf-templates/rev/safe_output.py",
        "source": REPO_ROOT / "templates" / "rev" / "safe_output.py",
        "contract_id": "ctfos.rev.safe_output",
        "contract_version": 1,
    },
}
probe_namespace = runpy.run_path(
    str(REPO_ROOT / "scripts" / "ctf-capabilities"),
    run_name="ctf_capabilities_under_test",
)
probe_file = probe_namespace["_probe"]
for name, expected in expected_managed_attestations.items():
    record = managed_attestations[name]
    assert record["kind"] == "file_sha256"
    assert record["path"] == expected["path"]
    assert record["attestation_schema_version"] == 1
    assert record["contract_id"] == expected["contract_id"]
    assert record["contract_version"] == expected["contract_version"]
    source = expected["source"]
    source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    assert record["sha256"] == source_sha256
    local_record = dict(record)
    local_record["path"] = str(source)
    observation = probe_file(local_record)
    assert observation["available"] is True
    assert observation["attestation"] == {
        "schema_version": 1,
        "contract_id": expected["contract_id"],
        "contract_version": expected["contract_version"],
        "path": str(source),
        "sha256": source_sha256,
    }

with tempfile.TemporaryDirectory() as temporary:
    changed = pathlib.Path(temporary) / "crash_oracle.py"
    crash_oracle = expected_managed_attestations["pwn_crash_v1"]["source"]
    changed.write_bytes(crash_oracle.read_bytes() + b"\n")
    changed_record = dict(managed_attestations["pwn_crash_v1"])
    changed_record["path"] = str(changed)
    changed_observation = probe_file(changed_record)
    assert changed_observation["available"] is False
    assert (
        changed_observation["attestation"]["sha256"]
        != changed_record["sha256"]
    )
assert "COPY capabilities.v2.json /tools/capabilities.json" in dockerfile
assert "(.capabilities | length == 12)" in dockerfile
assert 'or .name == "pwn_runtime_snapshot_v1"' in dockerfile
assert 'or .name == "pwn_exploit_effect_v1"' in dockerfile
assert 'or .name == "pwn_interaction_v1"' in dockerfile
assert "--network" not in managed_probe_source
assert "mode=ro&immutable=1" in sqlite_wrapper_source
assert "PRAGMA query_only=ON" in sqlite_wrapper_source

print("capability contract: ok")
