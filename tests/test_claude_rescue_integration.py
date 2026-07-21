"""Docker-argv integration checks for the opt-in external rescue sandbox.

These tests do not require a Docker daemon; they inspect the exact argv that the
runtime passes to Docker. Live lifecycle coverage remains under the existing
CTF_OS_LIVE_SANDBOX_TESTS gate.
"""

from pathlib import Path
import json
import subprocess

import pytest

from ctf_os.sandbox.network import ResolvedTarget, Target
from ctf_os.sandbox.runtime import SandboxSpec, _cleanup_locked, build_run_argv


def _spec(tmp_path: Path) -> SandboxSpec:
    source = tmp_path / "output" / "demo" / "pwn" / "challenge" / "input"
    source.mkdir(parents=True)
    branch = (
        tmp_path / "output" / "demo" / "pwn" / "challenge" / "runs" /
        "run-1" / "rescue" / "rescue-1"
    )
    for name in ("work", "evidence", "artifacts", "context"):
        (branch / name).mkdir(parents=True, exist_ok=True)
    target = Target(
        "tcp://ctf.example:31337", "ctf.example", 31337, "tcp",
        organizer_declared=True,
    )
    return SandboxSpec(
        contest_slug="demo", challenge_id="challenge", branch="rescue-1",
        source=source, branch_root=branch, input_fingerprint="a" * 64,
        target_revision=1, input_bytes=1,
        targets=(ResolvedTarget(target, "93.184.216.34"),),
        session_id="rescue-1", parent_session_id="sol-main",
        session_role="external-rescue", workspace_mode="bind", run_id="run-1",
        rescue_attempt_id="rescue-1", external_solver=True,
        solver_family="claude", session_kind="external-rescue",
        requested_lead_model="sonnet",
    )


def test_rescue_docker_argv_has_exact_mounts_labels_and_network(tmp_path: Path) -> None:
    spec = _spec(tmp_path)
    argv = build_run_argv(spec)
    values = set(argv)
    assert f"type=bind,src={spec.source},dst=/challenge,readonly" in values
    assert f"type=bind,src={(spec.branch_root / 'context').resolve()},dst=/context,readonly" in values
    for directory in ("work", "evidence", "artifacts"):
        assert f"type=bind,src={(spec.branch_root / directory).resolve()},dst=/{directory}" in values
    assert "ctf-os.run_id=run-1" in "\n".join(argv)
    assert "ctf-os.rescue_attempt_id=rescue-1" in "\n".join(argv)
    assert "ctf-os.session_kind=external-rescue" in "\n".join(argv)
    assert "--network" in argv and argv[argv.index("--network") + 1] == "bridge"
    assert "ctf.example:93.184.216.34" in argv


def test_rescue_docker_argv_has_no_host_or_credential_mount(tmp_path: Path) -> None:
    argv = "\n".join(build_run_argv(_spec(tmp_path)))
    forbidden = (
        "/var/run/docker.sock", "/run/docker.sock", "/.git", "/.ssh",
        "kubeconfig", "credentials", "browser", "dst=/home", "dst=/root",
    )
    assert all(value not in argv.casefold() for value in forbidden)


def test_bind_cleanup_skips_export_and_absent_resource_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ctf_os.sandbox.runtime as runtime

    spec = _spec(tmp_path)
    metadata = {
        "name": spec.name,
        "branch": spec.branch,
        "branch_root": str(spec.branch_root),
        "labels": spec.labels,
        "workspace_mode": "bind",
        "session_id": spec.session_id,
    }
    calls: list[list[str]] = []

    def fake_run(argv: list[str], timeout: int, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if argv[1] == "inspect":
            return subprocess.CompletedProcess(argv, 0, json.dumps(spec.labels), "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    class FakeLedger:
        def __init__(self, _root: Path) -> None:
            self.state_path = tmp_path / "resource-state.json"
            self.state_path.write_text("{}")

        def load(self) -> dict[str, object]:
            return {"requests": {}, "observations": {}}

        def release(self, *_args: object) -> None:
            raise AssertionError("cleanup released a nonexistent resource request")

    monkeypatch.setattr(runtime, "_run", fake_run)
    monkeypatch.setattr(runtime, "ResourceLedger", FakeLedger)
    result = _cleanup_locked(metadata, docker="docker")
    assert result["artifact_export"] is None
    assert not any("tar" in call for call in calls)
    assert any(call[1:3] == ["rm", "--force"] for call in calls)
