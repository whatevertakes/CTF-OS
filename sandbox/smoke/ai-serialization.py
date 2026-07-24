#!/usr/bin/env python3
from __future__ import annotations

import os
import pickle
import subprocess
import tempfile
from pathlib import Path


class UnsafeReduce:
    def __reduce__(self):
        return (os.system, ("touch /work/CTF_OS_PICKLE_EXECUTED",))


def run(argv: list[str], expected: int) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=60)
    assert result.returncode == expected, (argv, result.returncode, result.stdout, result.stderr)
    return result


marker = Path("/work/CTF_OS_PICKLE_EXECUTED")
if marker.exists():
    marker.unlink()
with tempfile.TemporaryDirectory(prefix="ai-serialization-", dir="/work") as directory:
    root = Path(directory)
    benign = root / "benign.pkl"
    unsafe = root / "unsafe.pkl"
    benign.write_bytes(pickle.dumps({"value": [1, 2, 3]}, protocol=4))
    unsafe.write_bytes(pickle.dumps(UnsafeReduce(), protocol=4))

    run(["modelscan", "--path", str(benign)], 0)
    modelscan_unsafe = run(["modelscan", "--path", str(unsafe)], 1)
    run([
        "fickling", "--check-safety", "--print-results",
        "--json-output", str(root / "benign-fickling.json"), str(benign),
    ], 0)
    fickling_unsafe = run([
        "fickling", "--check-safety", "--print-results",
        "--json-output", str(root / "unsafe-fickling.json"), str(unsafe),
    ], 1)

    combined = (modelscan_unsafe.stdout + modelscan_unsafe.stderr + fickling_unsafe.stdout + fickling_unsafe.stderr).lower()
    assert any(word in combined for word in ("unsafe", "malicious", "critical")), combined
    assert not marker.exists(), "unsafe reduce payload executed during static scanning"

print("CTF_OS_AI_SERIALIZATION_SMOKE_OK")
