#!/usr/bin/env python3
"""Schema and duplicate-key regressions for ctf-tools manifests."""

from __future__ import annotations

import copy
import json
import os
import pathlib
import subprocess
import sys
import tempfile


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CTF_TOOLS = REPO_ROOT / "scripts" / "ctf-tools"
GEN_MANIFEST = REPO_ROOT / "scripts" / "gen-manifest.sh"


def tool(category: str, name: str) -> dict[str, object]:
    return {
        "category": category,
        "name": name,
        "path": "/bin/true",
        "available": True,
        "description": "test tool",
        "aliases": [],
        "tags": ["test"],
    }


def invoke(manifest: dict[str, object]) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        path = pathlib.Path(directory) / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return subprocess.run(
            [
                sys.executable,
                str(CTF_TOOLS),
                "--manifest",
                str(path),
                "--json",
                "--list",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
        )


base = {
    "schema_version": 1,
    "failed": [],
    "tools": [tool("crypto", "shared"), tool("misc", "shared")],
}

# A global name may intentionally appear in multiple categories. The
# category/name pair is the manifest identity and must remain unique.
result = invoke(base)
assert result.returncode == 0, result.stderr
payload = json.loads(result.stdout)
assert payload["schema_version"] == 1, payload
assert payload["count"] == 2, payload
assert payload["failed"] == [], payload

invalid_manifests: list[tuple[str, dict[str, object]]] = []

duplicate = copy.deepcopy(base)
duplicate["tools"].append(tool("CRYPTO", "SHARED"))  # type: ignore[union-attr]
invalid_manifests.append(("duplicates category/name", duplicate))

invalid_failed = copy.deepcopy(base)
invalid_failed["failed"] = "tool failed"
invalid_manifests.append(("failed must be an array of strings", invalid_failed))

relative_path = copy.deepcopy(base)
relative_path["tools"][0]["path"] = "bin/true"  # type: ignore[index]
invalid_manifests.append(("requires an absolute path", relative_path))

unavailable_path = copy.deepcopy(base)
unavailable_path["tools"][0]["available"] = False  # type: ignore[index]
invalid_manifests.append(("unavailable tool path must be empty", unavailable_path))

invalid_aliases = copy.deepcopy(base)
invalid_aliases["tools"][0]["aliases"] = ["ok", 7]  # type: ignore[index]
invalid_manifests.append(("aliases must be an array of strings", invalid_aliases))

invalid_description = copy.deepcopy(base)
invalid_description["tools"][0]["description"] = 7  # type: ignore[index]
invalid_manifests.append(("description must be a string", invalid_description))

for expected_error, manifest in invalid_manifests:
    result = invoke(manifest)
    assert result.returncode == 1, (expected_error, result)
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1, payload
    assert payload["status"] == "error", payload
    assert expected_error in payload["error"], (expected_error, payload)

no_args = subprocess.run(
    [sys.executable, str(CTF_TOOLS)],
    stdin=subprocess.DEVNULL,
    capture_output=True,
    text=True,
    check=False,
    timeout=3,
)
assert no_args.returncode == 2, no_args
assert "usage:" in no_args.stderr.lower(), no_args.stderr

# Special files must be rejected from metadata before a potentially blocking
# open, and oversized regular files must be rejected before JSON allocation.
with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    fifo = root / "manifest.fifo"
    os.mkfifo(fifo)
    fifo_result = subprocess.run(
        [
            sys.executable,
            str(CTF_TOOLS),
            "--manifest",
            str(fifo),
            "--json",
            "--list",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=3,
    )
    assert fifo_result.returncode == 1, fifo_result
    assert "regular file" in json.loads(fifo_result.stdout)["error"], fifo_result

    oversized = root / "oversized.json"
    with oversized.open("wb") as handle:
        handle.truncate(8 * 1024 * 1024 + 1)
    oversized_result = subprocess.run(
        [
            sys.executable,
            str(CTF_TOOLS),
            "--manifest",
            str(oversized),
            "--json",
            "--list",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=3,
    )
    assert oversized_result.returncode == 1, oversized_result
    assert "byte limit" in json.loads(oversized_result.stdout)["error"], oversized_result

    failed_fifo = root / "failed.fifo"
    os.mkfifo(failed_fifo)
    failed_fifo_result = subprocess.run(
        ["bash", str(GEN_MANIFEST)],
        env={
            **os.environ,
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "CTF_FAILED_TOOLS_FILE": str(failed_fifo),
        },
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=3,
    )
    assert failed_fifo_result.returncode != 0, failed_fifo_result
    assert "regular file" in failed_fifo_result.stderr, failed_fifo_result

    oversized_failed = root / "oversized-failed.txt"
    with oversized_failed.open("wb") as handle:
        handle.truncate(1024 * 1024 + 1)
    oversized_failed_result = subprocess.run(
        ["bash", str(GEN_MANIFEST)],
        env={
            **os.environ,
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "CTF_FAILED_TOOLS_FILE": str(oversized_failed),
        },
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=3,
    )
    assert oversized_failed_result.returncode != 0, oversized_failed_result
    assert "byte limit" in oversized_failed_result.stderr, oversized_failed_result

print("ctf-tools manifest schema and duplicate regressions: ok")
