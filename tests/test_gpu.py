from __future__ import annotations

import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from ctf_os.doctor import PROFILES, _gpu_doctor_checks, _gpu_image_probe
from ctf_os.resources.scheduler import GIB, default_request, detect_gpus
from ctf_os.sandbox.preparation import prepare_sandbox_spec
from ctf_os.sandbox.runtime import SandboxSpec, build_run_argv
import ctf_os.sandbox.runtime as runtime


def _completed(argv, returncode: int = 0, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


def _gpu_runner(*, passthrough_ok: bool = True, host_ok: bool = True):
    calls: list[list[str]] = []

    def run(argv, **_kwargs):
        argv = list(argv)
        calls.append(argv)
        if argv[0] == "nvidia-smi":
            if not host_ok:
                return _completed(argv, 127, stderr="nvidia-smi not found")
            return _completed(argv, stdout="0, NVIDIA GeForce RTX 4060 Ti, 16384, 12288, 3\n")
        if argv[1:3] == ["info", "--format"]:
            # A successful device request is sufficient even when the daemon
            # does not expose a named nvidia runtime (for example CDI setups).
            return _completed(argv, stdout='{"runc":{"path":"runc"}}')
        if argv[1:3] == ["run", "--help"]:
            return _completed(argv, stdout="      --gpus gpu-request")
        if argv[1:3] == ["image", "inspect"]:
            return _completed(argv, stdout="[]")
        if "--gpus" in argv:
            return _completed(
                argv, 0 if passthrough_ok else 1,
                stdout="0, NVIDIA GeForce RTX 4060 Ti\n" if passthrough_ok else "",
                stderr="could not select device driver" if not passthrough_ok else "",
            )
        raise AssertionError(f"unexpected command: {argv}")

    return run, calls


def test_gpu_detection_requires_host_cli_docker_option_and_real_passthrough() -> None:
    runner, calls = _gpu_runner()
    gpu = detect_gpus(run=runner)

    assert gpu["status"] == "AVAILABLE"
    assert gpu["available"] is True and gpu["backend"] == "nvidia"
    assert gpu["device_count"] == 1
    assert gpu["devices"][0]["name"] == "NVIDIA GeForce RTX 4060 Ti"
    assert gpu["devices"][0]["vram_total_bytes"] == 16384 * 1024**2
    assert gpu["docker_gpus"] is True and gpu["docker_passthrough"] is True
    assert any("--gpus" in argv and "nvidia-smi" in argv for argv in calls)


def test_gpu_detection_unavailable_and_degraded_are_cpu_safe() -> None:
    missing_runner, _ = _gpu_runner(host_ok=False)
    missing = detect_gpus(run=missing_runner)
    assert missing["status"] == "UNAVAILABLE" and missing["available"] is False

    broken_runner, _ = _gpu_runner(passthrough_ok=False)
    broken = detect_gpus(run=broken_runner)
    assert broken["status"] == "DEGRADED" and broken["available"] is False
    assert "could not select device driver" in broken["reason"]


@pytest.mark.parametrize("profile", PROFILES)
def test_gpu_enabled_adds_same_device_request_to_every_existing_profile(
    tmp_path: Path, profile: str,
) -> None:
    source = tmp_path / "input"
    source.mkdir()
    spec = SandboxSpec(
        "contest", "challenge", profile, source, tmp_path / profile,
        image=f"ctf-os-sandbox:{profile}", category=profile, gpu_enabled=True,
    )
    argv = build_run_argv(spec)

    assert argv[argv.index("--gpus") + 1] == "all"
    assert "CTF_OS_GPU_AVAILABLE=1" in argv
    assert "NVIDIA_DRIVER_CAPABILITIES=compute,utility" in argv
    assert "--read-only" in argv and "no-new-privileges" in argv


def test_gpu_support_does_not_add_image_profiles_or_tags() -> None:
    assert PROFILES == (
        "base", "pwn", "web", "rev", "crypto",
        "forensic", "misc", "osint", "ai", "cloud",
    )
    dockerfile = (
        Path(__file__).resolve().parents[1] / "sandbox" / "Dockerfile.sandbox"
    ).read_text(encoding="utf-8")
    assert "crypto-gpu" not in dockerfile
    assert "rev-gpu" not in dockerfile
    assert "ai-gpu" not in dockerfile


def test_gpu_disabled_omits_device_request_and_scheduler_device_is_selected(tmp_path: Path) -> None:
    source = tmp_path / "input"
    source.mkdir()
    cpu = build_run_argv(SandboxSpec("contest", "challenge", "cpu", source, tmp_path / "cpu"))
    gpu = build_run_argv(SandboxSpec(
        "contest", "challenge", "gpu", source, tmp_path / "gpu",
        category="crypto", gpu_enabled=True, gpu_device=2,
    ))

    assert "--gpus" not in cpu
    assert gpu[gpu.index("--gpus") + 1] == "device=2"


def _preparation_case(tmp_path: Path, *, category: str = "pwn"):
    repo = tmp_path / "repo"
    solve = repo / "output" / "contest" / "challenge" / "runs" / "run-1"
    workspace = solve
    source = workspace / "input"
    source.mkdir(parents=True)
    (source / "challenge.bin").write_bytes(b"x")
    (solve / "STATE.json").write_text(json.dumps({"target_revision": 1}))
    record = {
        "status": "READY",
        "prepared_input": str(source.resolve()),
        "prepared_fingerprint": "prepared",
        "source_fingerprint": "source",
        "important_metadata": {"total_bytes": 1},
        "files": [{"path": "challenge.bin", "size": 1}],
        "service_plan": None,
    }
    manifest = SimpleNamespace(slug="contest")
    challenge = SimpleNamespace(id="challenge", category=category, remotes=())
    kwargs = {
        "repo_root": repo,
        "manifest": manifest,
        "challenge": challenge,
        "record": record,
        "workspace": workspace,
        "solve_root": solve,
        "branch": "worker",
        "branch_root": solve / "workers" / "worker",
        "session_id": "worker",
        "parent_session_id": "sol-main",
        "session_role": "child",
        "allow_scheduler_rebalance": False,
        "prepared_fingerprint_reader": lambda _path: "prepared",
    }
    return solve, kwargs


def _write_resources(solve: Path, request: dict[str, object], allocation=None) -> None:
    (solve / "RESOURCE_STATE.json").write_text(json.dumps({
        "schema_version": 2,
        "requests": {"worker": request},
        "allocations": {"worker": allocation} if allocation is not None else {},
        "observations": {}, "released": {}, "rebalance_required": False,
    }))


def test_preparation_auto_enables_gpu_without_ai_category(tmp_path: Path) -> None:
    _solve, kwargs = _preparation_case(tmp_path, category="web")
    prepared = prepare_sandbox_spec(
        **kwargs,
        gpu_detector=lambda: {"status": "AVAILABLE", "available": True, "backend": "nvidia"},
    )

    assert prepared.spec.gpu_enabled is True
    assert prepared.spec.gpu_device is None
    assert prepared.spec.gpu_requested is True
    assert prepared.spec.gpu_fallback is None


def test_preparation_prefers_scheduler_device_and_preserves_preferred_cpu_fallback(
    tmp_path: Path,
) -> None:
    solve, kwargs = _preparation_case(tmp_path, category="crypto")
    preferred = default_request(
        contest="contest", challenge_id="challenge", session_id="worker",
        workload_class="password-cracking",
    ).to_dict()
    allocation = {
        "cpus": 2, "memory_bytes": 4 * GIB, "storage_bytes": 4 * GIB,
        "gpu_device": 0, "gpu_memory_bytes": 4 * GIB,
    }
    _write_resources(solve, preferred, allocation)
    prepared = prepare_sandbox_spec(
        **kwargs, gpu_detector=lambda: (_ for _ in ()).throw(AssertionError("must not probe")),
    )
    assert prepared.spec.gpu_enabled is True and prepared.spec.gpu_device == 0

    allocation.update({"gpu_device": None, "gpu_memory_bytes": 0, "gpu_fallback": "CPU"})
    _write_resources(solve, preferred, allocation)
    fallback = prepare_sandbox_spec(
        **kwargs, gpu_detector=lambda: (_ for _ in ()).throw(AssertionError("must not probe")),
    )
    assert fallback.spec.gpu_requested is True
    assert fallback.spec.gpu_enabled is False and fallback.spec.gpu_fallback == "CPU"


def test_gpu_required_without_an_allocation_or_usable_gpu_is_refused(tmp_path: Path) -> None:
    solve, kwargs = _preparation_case(tmp_path, category="rev")
    required = default_request(
        contest="contest", challenge_id="challenge", session_id="worker",
        workload_class="custom-cpu-bound",
        gpu_required=True,
        overrides={"gpu_memory_bytes": 4 * GIB},
    ).to_dict()
    _write_resources(solve, required)

    with pytest.raises(ValueError, match="required GPU"):
        prepare_sandbox_spec(
            **kwargs,
            gpu_detector=lambda: {
                "status": "UNAVAILABLE", "available": False,
                "reason": "nvidia-smi is unavailable",
            },
        )

    _write_resources(solve, required, {
        "cpus": 2, "memory_bytes": 4 * GIB, "storage_bytes": 4 * GIB,
        "gpu_device": None, "gpu_memory_bytes": 0, "gpu_fallback": "CPU",
    })
    with pytest.raises(ValueError, match="required GPU"):
        prepare_sandbox_spec(
            **kwargs,
            gpu_detector=lambda: (_ for _ in ()).throw(AssertionError("must not probe")),
        )


def test_sandbox_metadata_and_evidence_distinguish_request_assignment_and_fallback(
    monkeypatch, tmp_path: Path,
) -> None:
    source = tmp_path / "input"
    source.mkdir()
    monkeypatch.setattr(runtime, "admit", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        runtime, "_run", lambda *args, **kwargs: _completed([], stdout="container-id"),
    )
    gpu_root = tmp_path / "output" / "workers" / "gpu"
    gpu = runtime.create(SandboxSpec(
        "contest", "challenge", "gpu", source, gpu_root,
        category="pwn", gpu_enabled=True, gpu_device=0, gpu_requested=True,
    ))
    cpu_root = tmp_path / "output" / "workers" / "cpu"
    cpu = runtime.create(SandboxSpec(
        "contest", "challenge", "cpu", source, cpu_root,
        category="ai", gpu_enabled=False, gpu_requested=True, gpu_fallback="CPU",
    ))

    assert {key: gpu[key] for key in (
        "gpu_requested", "gpu_assigned", "gpu_enabled", "gpu_device",
        "gpu_backend", "gpu_fallback",
    )} == {
        "gpu_requested": True, "gpu_assigned": True, "gpu_enabled": True,
        "gpu_device": 0, "gpu_backend": "nvidia", "gpu_fallback": None,
    }
    assert cpu["gpu_requested"] is True and cpu["gpu_assigned"] is False
    assert cpu["gpu_backend"] is None and cpu["gpu_fallback"] == "CPU"
    events = [json.loads(line) for line in (tmp_path / "output" / "evidence.log").read_text().splitlines()]
    assert events[-1]["gpu_requested"] is True
    assert events[-1]["gpu_assigned"] is False and events[-1]["gpu_fallback"] == "CPU"


def test_doctor_gpu_checks_skip_cleanly_without_gpu_and_fail_broken_passthrough() -> None:
    skipped = _gpu_doctor_checks(
        {"status": "UNAVAILABLE", "host_driver": False, "reason": "no GPU"},
        {profile: True for profile in PROFILES},
        probe=lambda *_args: (_ for _ in ()).throw(AssertionError("must not probe")),
    )
    assert len(skipped) == 6
    assert all(item["ok"] is True and item["status"] == "SKIPPED" for item in skipped)

    degraded = _gpu_doctor_checks(
        {
            "status": "DEGRADED", "host_driver": True, "device_count": 1,
            "available": False, "docker_passthrough": False,
            "reason": "could not select device driver",
        },
        {profile: True for profile in PROFILES},
        probe=lambda *_args: (_ for _ in ()).throw(AssertionError("must not probe")),
    )
    checks = {item["name"]: item for item in degraded}
    assert checks["gpu-host-driver"]["ok"] is True
    assert checks["gpu-docker-passthrough"]["ok"] is False
    assert checks["gpu-ai-torch"]["status"] == "SKIPPED"


def test_doctor_gpu_probe_uses_writable_hashcat_state_and_keeps_security_policy() -> None:
    calls: list[list[str]] = []

    def run(argv, **_kwargs):
        calls.append(list(argv))
        return _completed(argv)

    _gpu_image_probe("crypto", ("hashcat", "-I"), run=run)
    argv = calls[0]
    assert "XDG_DATA_HOME=/work/.local/share" in argv
    assert "--read-only" in argv and "no-new-privileges" in argv
    assert argv[argv.index("--gpus") + 1] == "all"
