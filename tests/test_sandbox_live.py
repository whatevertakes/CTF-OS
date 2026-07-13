from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest

from ctf_os.sandbox.runtime import SandboxSpec, cleanup, create, execute, export_artifacts


pytestmark = pytest.mark.skipif(os.environ.get("CTF_OS_LIVE_DOCKER") != "1", reason="live Docker opt-in")


def test_live_ro_writes_network_timeout_and_cleanup(tmp_path: Path) -> None:
    source = tmp_path / "challenge" / "input"
    source.mkdir(parents=True)
    (source / "original.txt").write_text("immutable")
    branch = tmp_path / "challenge" / "workers" / "live"
    spec = SandboxSpec("demo", "live123", "live", source, branch, image="ctf-os-sandbox:base", resource_profile="light")
    metadata = create(spec)
    try:
        result = execute(metadata, ["bash", "-c", "if echo bad >/challenge/original.txt; then exit 9; fi; echo artifact >/artifacts/proof.txt; echo work >/work/proof.txt"], 20)
        assert result["exit_code"] == 0
        assert result["artifacts_exported"] is False
        export_artifacts(metadata)
        assert (branch / "artifacts" / "proof.txt").read_text().strip() == "artifact"
        removed = execute(metadata, ["rm", "/artifacts/proof.txt"], 10)
        assert removed["exit_code"] == 0
        export_artifacts(metadata)
        assert not (branch / "artifacts" / "proof.txt").exists()
        network = execute(metadata, ["python3", "-c", "import socket; socket.create_connection(('8.8.8.8', 53), 1)"], 10)
        assert network["exit_code"] != 0
    finally:
        cleanup(metadata)
    assert (branch / "work" / "proof.txt").read_text().strip() == "work"
    assert (branch / "context" / "session.json").is_file()
    assert subprocess.run(["docker", "inspect", metadata["name"]], capture_output=True).returncode != 0

    timeout_branch = tmp_path / "challenge" / "workers" / "timeout"
    timeout_meta = create(SandboxSpec("demo", "live123", "timeout", source, timeout_branch, image="ctf-os-sandbox:base", resource_profile="light"))
    timed = execute(timeout_meta, ["sleep", "30"], 1)
    assert timed["timed_out"]
    assert subprocess.run(["docker", "inspect", timeout_meta["name"]], capture_output=True).returncode != 0
