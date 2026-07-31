#!/usr/bin/env python3
"""Regression contract for the repaired non-SQL CTF tool surface."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import pathlib
import re
import runpy
import signal
import subprocess
import sys
import tempfile
import time


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
functional_probe_source = (
    REPO_ROOT / "scripts" / "ctf-capability-smoke"
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
    "python-sat==${PYTHON_SAT_VER}",
    "cadical300",
    "kissat404",
    "CRYPTOMINISAT_VER=5.14.7",
    "536d4cb03bbd2b4cbcca6230ed30e2aa844f170b5bbcfb0a0d7adb4852cf3ab7",
    "ewf-tools",
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
    "cryptominisat5",
    "ctf-browser",
    "ctf-egress-proxy",
    "ctf-network-smoke",
    "ctf-web-probe",
    "evtxexport",
    "ewfinfo",
    "ewfverify",
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
ast.parse(
    functional_probe_source,
    filename="scripts/ctf-capability-smoke",
)
ast.parse(sqlite_wrapper_source, filename="scripts/ctf-sqlite-readonly")
assert managed_manifest["schema_version"] == 2
assert len(managed_manifest["capabilities"]) == 34
assert {
    item["name"] for item in managed_manifest["capabilities"]
} == {
    "convert",
    "sqlite_readonly",
    "z3",
    "ortools",
    "pysat_cadical300",
    "pysat_kissat404",
    "cryptominisat5",
    "angr_python",
    "pwn_crash_v1",
    "pwn_runtime_snapshot_v1",
    "pwn_exploit_effect_v1",
    "pwn_interaction_v1",
    "rev_inventory_v2",
    "rev_safe_output",
    "rev_stdin_exec",
    "rev_runtime_exec_v1",
    "data_transcript_v1",
    "forensic_evidence_index_v1",
    "forensic_assertion_python3",
    "forensic_assertion_perl",
    "forensic_volatility3",
    "forensic_volatility_symbols",
    "forensic_sleuthkit",
    "forensic_ewf",
    "forensic_tshark",
    "forensic_zeek",
    "forensic_tesseract",
    "forensic_ocr_korean",
    "forensic_hwp",
    "misc_stegseek",
    "misc_zsteg",
    "misc_ffmpeg",
    "misc_sox",
    "misc_zbar",
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
        "rev_runtime_exec_v1",
        "data_transcript_v1",
        "forensic_evidence_index_v1",
    }
}
functional_capabilities = {
    "forensic_volatility3": "volatility3",
    "forensic_volatility_symbols": "volatility-symbols",
    "forensic_sleuthkit": "sleuthkit",
    "forensic_ewf": "ewf",
    "forensic_tshark": "tshark",
    "forensic_zeek": "zeek",
    "forensic_tesseract": "tesseract",
    "forensic_ocr_korean": "tesseract-korean",
    "forensic_hwp": "hwp",
    "misc_stegseek": "stegseek",
    "misc_zsteg": "zsteg",
    "misc_ffmpeg": "ffmpeg",
    "misc_sox": "sox",
    "misc_zbar": "zbar",
}
managed_by_name = {
    item["name"]: item for item in managed_manifest["capabilities"]
}
for capability, probe in functional_capabilities.items():
    assert managed_by_name[capability] == {
        "name": capability,
        "kind": "command",
        "command": "/usr/local/bin/ctf-capability-smoke",
        "arguments": [probe],
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
    "rev_runtime_exec_v1": {
        "path": "/opt/ctf-templates/rev/runtime_exec.py",
        "source": REPO_ROOT / "templates" / "rev" / "runtime_exec.py",
        "contract_id": "ctfos.rev.runtime_exec",
        "contract_version": 1,
    },
    "data_transcript_v1": {
        "path": "/opt/ctf-templates/common/data_transcript.py",
        "source": (
            REPO_ROOT / "templates" / "common" / "data_transcript.py"
        ),
        "contract_id": "ctfos.data_transcript.producer",
        "contract_version": 1,
    },
    "forensic_evidence_index_v1": {
        "path": "/opt/ctf-templates/forensic/evidence_index.py",
        "source": (
            REPO_ROOT / "templates" / "forensic" / "evidence_index.py"
        ),
        "contract_id": "ctfos.forensic.evidence_index",
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
assert "(.capabilities | length == 34)" in dockerfile
assert 'or .name == "pwn_runtime_snapshot_v1"' in dockerfile
assert 'or .name == "pwn_exploit_effect_v1"' in dockerfile
assert 'or .name == "pwn_interaction_v1"' in dockerfile
assert 'or .name == "rev_runtime_exec_v1"' in dockerfile
assert 'or .name == "data_transcript_v1"' in dockerfile
assert 'or .name == "forensic_evidence_index_v1"' in dockerfile
assert "--network" not in managed_probe_source
assert "subprocess.DEVNULL" in functional_probe_source
assert "start_new_session=True" in functional_probe_source
assert "resource.RLIMIT_FSIZE" in functional_probe_source
assert "COMMAND_TIMEOUT_SECONDS = 4" in functional_probe_source
assert "shell=True" not in functional_probe_source
assert "VOLATILITY3_VER=2.28.0" in dockerfile
assert "PYHWP_VER=0.1b15" in dockerfile
assert "ZEEK_VER=8.2.1" in dockerfile
assert (
    "ZEEK_SHA256=a8067c75cc89bef4b58019230434a90073671a7cabfcf7ac616ac872a40a2edd"
    in dockerfile
)
assert "https://download.zeek.org/zeek-${ZEEK_VER}.tar.gz" in dockerfile
assert "security:/zeek" not in dockerfile
assert "TESSERACT_VER=5.3.4-1build5" in dockerfile
assert "TESSERACT_LANG_VER=1:4.1.0-2" in dockerfile
assert "sharing=locked" in dockerfile
assert (
    "STEGSEEK_REF=0e10a674b326298c5d51af8f2f7219ccac45e123"
    in dockerfile
)
assert "stegseek --version 2>&1 | grep -F 'StegSeek 0.6'" in dockerfile
assert "zsteg --version 0.2.14" in dockerfile
assert (
    "PYHWP_FIXTURE_REF=83239f0d3bdf438b2c9f7dcff455a6e841154a39"
    in dockerfile
)
assert (
    "8eb333ab110db6f91d7e426d507d41ca09cacd4d40d945188b5ec40663d7576b"
    in dockerfile
)
for digest in (
    "231d69735b9a5482b16bdbf1ec356e0a95574c44079e68dfb02ebddb34d55f3e",
    "58bb7da2ed1e491ce922d04a59881d201e233b5605c9fd5a7f0c08ee528253c6",
    "fd12c8338724b175b0c5765af3313328b700ad53de4a00b4aa50e9a8bcef9129",
):
    assert digest in dockerfile
    assert digest in functional_probe_source
assert "SHA256SUMS" in dockerfile
assert "SHA256SUMS" in functional_probe_source
assert "_sha256_file(archive)" not in functional_probe_source
for size in ("839_727_133", "2_980_184", "84_808_562"):
    assert size in functional_probe_source
for digest in (
    "7d4322bd2a7749724879683fc3912cb542f19906c83bcc1a52132556427170b2",
    "6b85e11d9bbf07863b97b3523b1b112844c43e713df8b66418a081fd1060b3b2",
    "c28f19dee36927baba5215fb793a3c00fff3ef2cfbcaa100122401d8f4374869",
):
    assert digest in functional_probe_source
assert "output_frames != source_frames" in functional_probe_source
assert "0.69 <= gain_ratio <= 0.725" in functional_probe_source
for pin in (
    "SECLISTS_REF=aeb36e9df937d1b77042e5667780e8156cd419f7",
    "LIBC_DATABASE_REF=291b0ebf126de9961cd2f8dd1cea2654c57a594a",
    "VMLINUX_TO_ELF_REF=19683fb95b29cd31362d49e6f48ab8368f96cbdf",
    "EXTRACT_VMLINUX_REF=8ba098e6b6ff0db8edf28528d1552be261af30d4",
    "PYCDC_REF=b4289760970dbc399684f1e155ec6d1ea1cc787e",
    "PYINSTXTRACTOR_REF=815d31cf26bc71e62f851b2e549452e7b7c9dd98",
    "RSACTFTOOL_REF=7c98848f1945de3e67a420871e8672f5ad9aa5d5",
    "CADO_NFS_REF=d67f463a8e5d2f4ab79cd114441b2cf982dc0da7",
    "JOHN_REF=94caf43756b1f13c7e3829ff848df344ea755cac",
    "JWT_TOOL_REF=3bc7407cf2222d6a821dcc19c776e5a1b1cb9a9b",
    "PHPGGC_REF=f8aebde3a1abb88b02042fd12a71b4c61d6cfe2c",
    "DWARF2JSON_VER=0.9.0",
    "DWARF2JSON_SHA256=e2e75ba5bc9c22bc38a48edffbb050456d089d54998d54f46cb580223d9fbc6b",
):
    assert pin in dockerfile
assert "/torvalds/linux/master/" not in dockerfile
assert "DWARF2JSON_VER=latest" not in dockerfile
assert (
    dockerfile.count(
        'echo "${expected}  ${partial}" | sha256sum -c -'
    )
    == 2
)
assert 'rm -f -- "${archive}"' in dockerfile
assert dockerfile.count('rm -f -- "${partial}"') >= 2
assert "mode=ro&immutable=1" in sqlite_wrapper_source
assert "PRAGMA query_only=ON" in sqlite_wrapper_source

probe_regular_file_set = probe_namespace["_probe_regular_file_set"]
with tempfile.TemporaryDirectory() as temporary:
    asset = pathlib.Path(temporary) / "asset.zip"
    asset.write_bytes(b"PK\x03\x04" + (b"A" * 4096))
    observation = probe_regular_file_set(
        "fixture_assets",
        {
            "files": [
                {
                    "path": str(asset),
                    "minimum_bytes": 4096,
                    "magic_hex": "504b0304",
                }
            ]
        },
    )
    assert observation == {"name": "fixture_assets", "available": True}
    asset.write_bytes(b"BAD!" + (b"A" * 4096))
    observation = probe_regular_file_set(
        "fixture_assets",
        {
            "files": [
                {
                    "path": str(asset),
                    "minimum_bytes": 4096,
                    "magic_hex": "504b0304",
                }
            ]
        },
    )
    assert observation == {"name": "fixture_assets", "available": False}

functional_namespace = runpy.run_path(
    str(REPO_ROOT / "scripts" / "ctf-capability-smoke"),
    run_name="ctf_capability_smoke_under_test",
)
probe_sox = functional_namespace["_probe_sox"]
smoke_error = functional_namespace["SmokeError"]
original_run = probe_sox.__globals__["_run"]
for mutation, expected_error in (
    ("copy", "gain was not applied"),
    ("near-copy", "RMS gain mismatch"),
):
    def fake_sox(_root, argv, **_kwargs):
        source = pathlib.Path(argv[1]).read_bytes()
        if mutation == "near-copy":
            changed = bytearray(source)
            changed[-1] ^= 1
            source = bytes(changed)
        pathlib.Path(argv[2]).write_bytes(source)
        return b""

    probe_sox.__globals__["_run"] = fake_sox
    with tempfile.TemporaryDirectory() as temporary:
        try:
            probe_sox(pathlib.Path(temporary))
        except smoke_error as error:
            assert expected_error in str(error)
        else:
            raise AssertionError(f"SoX {mutation} passthrough was accepted")
probe_sox.__globals__["_run"] = original_run

with tempfile.TemporaryDirectory() as temporary:
    temporary_root = pathlib.Path(temporary)
    child_pid_path = temporary_root / "child.pid"
    hanging_child = temporary_root / "hanging-child"
    hanging_child.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$$" > "$1"\n'
        "exec /bin/sleep 30\n",
        encoding="utf-8",
    )
    hanging_child.chmod(0o755)
    parent_source = (
        "import runpy,sys\n"
        "from pathlib import Path\n"
        "namespace=runpy.run_path(sys.argv[1],run_name='signal_test')\n"
        "namespace['_run']("
        "Path(sys.argv[2]),[sys.argv[3],sys.argv[4]])\n"
    )
    parent = subprocess.Popen(
        [
            sys.executable,
            "-c",
            parent_source,
            str(REPO_ROOT / "scripts" / "ctf-capability-smoke"),
            str(temporary_root),
            str(hanging_child),
            str(child_pid_path),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    child_pid = None
    try:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if child_pid_path.is_file():
                child_pid = int(
                    child_pid_path.read_text(encoding="ascii").strip()
                )
                break
            if parent.poll() is not None:
                break
            time.sleep(0.02)
        assert child_pid is not None, parent.communicate(timeout=1)
        os.kill(parent.pid, signal.SIGTERM)
        assert parent.wait(timeout=3) == 128 + signal.SIGTERM
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError("external SIGTERM leaked the probe child")
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait()
        if child_pid is not None:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

print("capability contract: ok")
