from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from ctf_os.agent_tools.__main__ import build_parser
from ctf_os.events import publish_event
from ctf_os.resources.scheduler import (
    GIB, HostCapacity, ResourceLedger, ResourceRequest, allocation_environment,
    classify_utilization, default_request, detect_capacity, infer_workload,
    normalize_resource_request, plan_allocations, recommended_workers,
)
from ctf_os.sandbox.runtime import SandboxError, SandboxSpec, build_run_argv, resize
import ctf_os.resources.scheduler as scheduler
import ctf_os.sandbox.resources as sandbox_resources
import ctf_os.sandbox.runtime as runtime


def _capacity(cpus: float = 10, memory: int = 28 * GIB, storage: int = 100 * GIB, devices=()) -> HostCapacity:
    return HostCapacity(
        observation_mode="FULL", degraded_metrics=(),
        cpu={"usable": cpus}, memory={"usable_bytes": memory},
        storage={"usable_bytes": storage},
        gpu={"docker_runtime": bool(devices), "devices": list(devices)},
        load_average=(0.1, 0.2, 0.3),
    )


def _request(session: str, workload: str, **overrides) -> ResourceRequest:
    return default_request(
        contest="contest", challenge_id="challenge", session_id=session,
        workload_class=workload, overrides=overrides,
    )


def _samples(*, cpu: float = 0, allocated: float = 4, memory: int = GIB,
             limit: int = 8 * GIB, net: tuple[int, int, int] = (0, 0, 0),
             io: tuple[int, int, int] = (0, 0, 0), gpu: float = 0,
             progress: bool = False):
    return [
        {
            "cpu_usage_cpus": cpu, "allocated_cpus": allocated,
            "memory_usage_bytes": memory, "memory_limit_bytes": limit,
            "network_read_bytes": net[index], "network_write_bytes": 0,
            "block_read_bytes": io[index], "block_write_bytes": 0,
            "gpu_utilization_percent": gpu, "progress": progress,
        }
        for index in range(3)
    ]


def test_request_schema_defaults_inference_and_legacy_normalization() -> None:
    symbolic = _request("symbolic-1", "symbolic-execution")
    assert (symbolic.min_cpus, symbolic.preferred_cpus, symbolic.max_cpus) == (2, 6, 10)
    assert symbolic.preferred_memory_bytes >= 12 * GIB
    assert infer_workload(command=["python", "-m", "angr"], category="rev")["workload_class"] == "symbolic-execution"
    assert infer_workload(files=["capture.pcap"], category="forensic")["workload_class"] == "forensic-scan"
    legacy = normalize_resource_request({
        "contest_slug": "contest", "challenge_id": "challenge", "branch": "old",
        "resource_profile": "large-forensic",
        "resources": {"cpus": 5, "memory": "16g", "storage": "20g"},
    })
    assert legacy["workload_class"] == "forensic-extraction"
    assert legacy["preferred_cpus"] == 5 and legacy["storage_bytes"] == 20 * GIB


def test_capacity_uses_smallest_limit_and_reserves_host(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(scheduler.os, "cpu_count", lambda: 32)
    monkeypatch.setattr(scheduler, "_physical_cores", lambda: 16)
    monkeypatch.setattr(scheduler, "_cgroup_cpu_limit", lambda: 12.0)
    monkeypatch.setattr(scheduler, "_cgroup_memory_limit", lambda: 40 * GIB)
    monkeypatch.setattr(scheduler, "_meminfo", lambda: {
        "MemTotal": 64 * GIB, "MemAvailable": 50 * GIB, "SwapTotal": 8 * GIB, "SwapFree": 6 * GIB,
    })
    monkeypatch.setattr(scheduler, "sample_docker_stats", lambda **kwargs: {"observation_mode": "FULL", "samples": [], "degraded_metrics": []})
    monkeypatch.setattr(scheduler, "detect_gpus", lambda **kwargs: {"observation_mode": "FULL", "degraded_metrics": [], "available": False, "devices": []})
    monkeypatch.setattr(sandbox_resources, "_list_managed_sandboxes", lambda **kwargs: [])
    monkeypatch.setattr(scheduler.shutil, "disk_usage", lambda path: subprocess.CompletedProcess([], 0, "", "") or None)

    class Usage:
        free = 200 * GIB

    monkeypatch.setattr(scheduler.shutil, "disk_usage", lambda path: Usage())

    def fake_run(argv, **kwargs):
        if ".NCPU" in argv[-1]:
            return subprocess.CompletedProcess(argv, 0, "16\n", "")
        if ".MemTotal" in argv[-1]:
            return subprocess.CompletedProcess(argv, 0, str(48 * GIB), "")
        if ".DockerRootDir" in argv[-1]:
            return subprocess.CompletedProcess(argv, 0, json.dumps(str(tmp_path)), "")
        return subprocess.CompletedProcess(argv, 1, "", "missing")

    capacity = detect_capacity(
        workspace=tmp_path, run=fake_run,
        environ={"CTF_OS_CPU_CAP": "14", "CTF_OS_MEMORY_CAP": "32g"},
    )
    assert capacity.cpu["effective_total"] == 12
    assert capacity.cpu["usable"] == 10
    assert capacity.memory["effective_total_bytes"] == 32 * GIB
    assert 26 * GIB <= capacity.memory["usable_bytes"] <= 28 * GIB
    assert capacity.storage["reserve_bytes"] == 20 * GIB


def test_capacity_degrades_without_docker_but_keeps_host_budget(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(scheduler, "sample_docker_stats", lambda **kwargs: {"observation_mode": "DEGRADED", "samples": [], "degraded_metrics": ["docker_stats"]})
    monkeypatch.setattr(scheduler, "detect_gpus", lambda **kwargs: {"observation_mode": "FULL", "degraded_metrics": [], "available": False, "devices": []})
    monkeypatch.setattr(sandbox_resources, "_list_managed_sandboxes", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("down")))
    failed = lambda argv, **kwargs: subprocess.CompletedProcess(argv, 1, "", "down")
    capacity = detect_capacity(workspace=tmp_path, run=failed)
    assert capacity.observation_mode == "DEGRADED"
    assert capacity.cpu["usable"] >= 0 and "docker_cpu" in capacity.degraded_metrics


def test_progressing_lead_takes_idle_static_cpu() -> None:
    requests = [
        _request("sol-main", "exploit-development", min_cpus=4, preferred_cpus=6, max_cpus=10),
        _request("static-1", "static-analysis", min_cpus=1, preferred_cpus=2, max_cpus=2),
        _request("dynamic-1", "dynamic-debugging", min_cpus=2, preferred_cpus=2, max_cpus=2),
    ]
    observations = {
        "sol-main": {"classification": "CPU_STARVED", "progress": {"step": 4}},
        "static-1": {"classification": "UNDERUTILIZED", "progress": {}},
        "dynamic-1": {"classification": "SATURATED", "progress": {"checkpoint": 1}},
    }
    plan = plan_allocations(requests, _capacity(), observations=observations)
    assert plan["allocations"]["sol-main"]["cpus"] == 7
    assert plan["allocations"]["static-1"]["cpus"] == 1
    assert plan["allocations"]["dynamic-1"]["cpus"] == 2


def test_completed_recon_releases_and_expands_symbolic() -> None:
    requests = [_request("symbolic-1", "symbolic-execution"), _request("recon-1", "quick-recon")]
    plan = plan_allocations(
        requests, _capacity(), observations={
            "symbolic-1": {"classification": "CPU_STARVED", "progress": {"coverage": 10}},
            "recon-1": {"state": "COMPLETED"},
        },
    )
    assert plan["allocations"]["symbolic-1"]["cpus"] >= 6
    assert plan["released"] == [{"session_id": "recon-1", "reason": "terminal state COMPLETED"}]


def test_multiple_heavy_fit_by_totals_and_storage_shortage_waits() -> None:
    heavy = [
        _request("heavy-1", "custom-cpu-bound", min_cpus=4, preferred_cpus=5, max_cpus=5, min_memory_bytes=4 * GIB, preferred_memory_bytes=4 * GIB, max_memory_bytes=4 * GIB),
        _request("heavy-2", "custom-cpu-bound", min_cpus=4, preferred_cpus=5, max_cpus=5, min_memory_bytes=4 * GIB, preferred_memory_bytes=4 * GIB, max_memory_bytes=4 * GIB),
    ]
    assert set(plan_allocations(heavy, _capacity())["allocations"]) == {"heavy-1", "heavy-2"}
    too_large = _request("extract", "forensic-extraction", storage_bytes=200 * GIB)
    assert plan_allocations([too_large], _capacity(storage=20 * GIB))["waiting"][0]["missing"]["storage_bytes"] > 0


@pytest.mark.parametrize(
    ("resource_req", "samples", "progress", "expected"),
    [
        (_request("cpu", "custom-cpu-bound"), _samples(cpu=3.8, progress=True), {"step": 2}, "CPU_STARVED"),
        (_request("mem", "custom-memory-bound"), _samples(cpu=1, memory=7.5 * GIB), {"step": 2}, "MEMORY_STARVED"),
        (_request("io", "custom-io-bound"), _samples(cpu=.5, io=(0, 100, 200), progress=True), {"artifact_hash": "x"}, "IO_BOUND"),
        (_request("net", "custom-network-bound"), _samples(cpu=.5, net=(0, 100, 200), progress=True), {"remote_interactions": 2}, "NETWORK_BOUND"),
        (_request("gpu", "ai-inference"), _samples(cpu=1, gpu=95, progress=True), {"generation": 2}, "GPU_STARVED"),
        (_request("under", "static-analysis"), _samples(cpu=.5), None, "UNDERUTILIZED"),
        (_request("idle", "static-analysis"), _samples(cpu=.01), None, "IDLE"),
        (_request("stalled", "custom-cpu-bound"), _samples(cpu=3.8), {"output_stalled": True}, "STALLED_COMPUTE"),
    ],
)
def test_utilization_window_classifications(resource_req, samples, progress, expected) -> None:
    assert classify_utilization(samples, request=resource_req, progress=progress) == expected


def test_single_sample_is_unknown_and_busy_loop_never_scales() -> None:
    request = _request("broken", "custom-cpu-bound", min_cpus=1, preferred_cpus=6, max_cpus=10)
    assert classify_utilization(_samples(cpu=4)[:1], request=request) == "UNKNOWN"
    plan = plan_allocations([request], _capacity(), observations={
        "broken": {"classification": "STALLED_COMPUTE", "progress": {"busy_loop": True}},
    })
    assert plan["allocations"]["broken"]["cpus"] == 1
    assert plan["preemption_recommendations"][0]["recommendation"] == "BUMP_AND_RETRY"


def test_network_progress_is_not_shrunk_as_underutilized() -> None:
    request = _request("web-1", "web-probing")
    plan = plan_allocations([request], _capacity(), observations={
        "web-1": {"classification": "NETWORK_BOUND", "progress": {"remote_interactions": 3}},
    })
    assert plan["allocations"]["web-1"]["cpus"] == request.preferred_cpus


def test_remote_flag_keeps_flag_path_and_at_most_one_verifier() -> None:
    requests = [
        _request("flagger", "exploit-development"),
        _request("verify-1", "clean-room-verification"),
        _request("verify-2", "clean-room-verification"),
        _request("recon", "quick-recon"),
    ]
    plan = plan_allocations(requests, _capacity(), remote_flag_session="flagger")
    assert set(plan["allocations"]) == {"flagger", "verify-1"}
    assert {row["session_id"] for row in plan["released"]} == {"verify-2", "recon"}


def test_gpu_assignment_vram_shortage_fallback_and_required_wait() -> None:
    device = {"index": 0, "vram_free_bytes": 8 * GIB, "vram_total_bytes": 8 * GIB}
    preferred = _request("inference", "ai-inference", gpu_memory_bytes=6 * GIB)
    fallback = _request("crack", "password-cracking", gpu_memory_bytes=4 * GIB)
    plan = plan_allocations([preferred, fallback], _capacity(devices=[device]))
    assert plan["allocations"]["inference"]["gpu_device"] == 0
    assert plan["allocations"]["crack"]["gpu_fallback"] == "CPU"
    required = _request("train", "ai-training", gpu_required=True, gpu_preferred=True, gpu_memory_bytes=12 * GIB)
    assert plan_allocations([required], _capacity(devices=[device]))["waiting"][0]["reason"].startswith("required GPU")


def test_capacity_based_tier_width_full_and_reduced() -> None:
    requests = [_request(f"child-{index}", "independent-full-solve") for index in range(3)]
    assert plan_allocations(requests, _capacity(cpus=8, memory=20 * GIB), tier=2)["capacity_based_race_width"] == 3
    assert plan_allocations(requests, _capacity(cpus=4, memory=8 * GIB), tier=2)["capacity_based_race_width"] == 2


def test_recommended_workers_and_sandbox_environment(tmp_path: Path) -> None:
    request = _request("solver", "symbolic-execution")
    assert recommended_workers("symbolic-execution", 8, 16 * GIB) == 8
    assert recommended_workers("custom-network-bound", 4, 4 * GIB) == 6
    env = allocation_environment({"cpus": 8, "memory_bytes": 16 * GIB}, request)
    assert env["CTF_OS_RECOMMENDED_WORKERS"] == "8" and env["OMP_NUM_THREADS"] == "8"
    source = tmp_path / "input"; source.mkdir()
    argv = build_run_argv(SandboxSpec(
        "contest", "challenge", "solver", source, tmp_path / "workers" / "solver",
        cpus=8, memory="16g", workload_class="symbolic-execution", resource_priority="HIGH",
    ))
    joined = " ".join(argv)
    assert "CTF_OS_ALLOCATED_CPUS=8" in joined
    assert "CTF_OS_RECOMMENDED_WORKERS=8" in joined
    assert "CTF_OS_WORKLOAD_CLASS=symbolic-execution" in joined


def test_ledger_child_ownership_event_priority_sampling_and_release(tmp_path: Path) -> None:
    ledger = ResourceLedger(tmp_path)
    request = _request("worker-1", "symbolic-execution")
    with pytest.raises(Exception, match="only for its own"):
        ledger.request(request, actor_session_id="worker-2", actor_role="child")
    ledger.request(request, actor_session_id="worker-1", actor_role="child")
    publish_event(
        tmp_path, challenge_id="challenge", input_fingerprint="fp", session_id="worker-1",
        event_type="FLAG_CANDIDATE", summary="candidate path",
    )
    state = ledger.load()
    assert state["requests"]["worker-1"]["priority"] == "CRITICAL"
    for sample in _samples(cpu=5.8, allocated=6, progress=True):
        observation = ledger.sample("worker-1", sample)
    assert observation["classification"] == "CPU_STARVED"
    release = ledger.release("worker-1", "complete")
    assert release["last_allocation"] is None
    assert {row["event"] for row in ledger.history()} >= {"REQUEST", "SAMPLE", "RELEASE", "EVENT_REBALANCE_REQUIRED"}


def test_information_only_event_does_not_claim_progress_or_request_rebalance(tmp_path: Path) -> None:
    ledger = ResourceLedger(tmp_path)
    request = _request("worker-1", "static-analysis")
    ledger.request(request, actor_session_id="sol-main", actor_role="sol")
    ledger.rebalance(_capacity())
    publish_event(
        tmp_path, challenge_id="challenge", input_fingerprint="fp", session_id="worker-1",
        event_type="SUPPORTED_FACT", summary="new architecture note without exploit relevance",
    )
    state = ledger.load()
    assert state["rebalance_required"] is False
    assert state["observations"].get("worker-1", {}).get("progress", {}).get("progressing") is not True


def test_dry_plan_preserves_baseline_and_failed_apply_restores_it(tmp_path: Path) -> None:
    ledger = ResourceLedger(tmp_path)
    request = _request("worker", "symbolic-execution")
    ledger.request(request, actor_session_id="sol-main", actor_role="sol")
    first = ledger.rebalance(_capacity(cpus=2, memory=8 * GIB))
    assert first["allocations"]["worker"]["cpus"] == 2
    for sample in _samples(cpu=2, allocated=2, progress=True):
        ledger.sample("worker", sample)
    dry = ledger.plan(_capacity(cpus=8, memory=20 * GIB))
    assert dry["allocations"]["worker"]["cpus"] > 2
    assert ledger.load()["allocations"]["worker"]["cpus"] == 2
    committed = ledger.rebalance(_capacity(cpus=8, memory=20 * GIB))
    ledger.reconcile_apply(committed, [{"session_id": "worker", "applied": False, "reason": "Docker update failed"}])
    assert ledger.load()["allocations"]["worker"]["cpus"] == 2
    assert ledger.history()[-1]["event"] == "RESIZE_FAILURE"


def _resize_fixture(tmp_path: Path):
    branch = tmp_path / "challenge" / "workers" / "worker"
    (branch / "context").mkdir(parents=True)
    metadata = {
        "schema_version": 2, "name": "ctf-os-contest-challenge-worker-1234567890",
        "contest_slug": "contest", "challenge_id": "challenge", "branch": "worker",
        "branch_root": str(branch), "metadata_path": str(branch / "sandbox.json"),
        "labels": {"ctf-os": "true", "ctf-os.contest": "contest", "ctf-os.challenge_id": "challenge", "ctf-os.branch": "worker"},
        "session_id": "worker", "parent_session_id": "sol-main",
        "resources": {"cpus": 2, "memory": str(4 * GIB), "storage": "4g"},
        "resource_request": _request("worker", "custom-cpu-bound").to_dict(),
    }
    (branch / "sandbox.json").write_text(json.dumps(metadata))
    return branch, metadata


def test_running_resize_cpu_memory_and_latest_exec_environment(monkeypatch, tmp_path: Path) -> None:
    branch, metadata = _resize_fixture(tmp_path)
    host = {"NanoCpus": 2_000_000_000, "Memory": 4 * GIB}
    updates = []

    def fake_run(argv, timeout):
        if argv[1] == "inspect":
            return subprocess.CompletedProcess(argv, 0, json.dumps([{"Config": {"Labels": metadata["labels"]}, "HostConfig": host}]), "")
        if argv[1] == "stats":
            return subprocess.CompletedProcess(argv, 0, json.dumps({"MemUsage": "2GiB / 4GiB"}), "")
        if argv[1] == "update":
            updates.append(list(argv))
            if "--cpus" in argv:
                host["NanoCpus"] = int(float(argv[argv.index("--cpus") + 1]) * 1_000_000_000)
            if "--memory" in argv:
                host["Memory"] = int(argv[argv.index("--memory") + 1])
            return subprocess.CompletedProcess(argv, 0, "ok", "")
        if argv[1] == "exec":
            return subprocess.CompletedProcess(argv, 0, "ok", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(runtime, "_run", fake_run)
    receipt = resize(metadata, cpus=6, memory="8g", session_id="sol-main", session_role="sol")
    assert receipt["verified"] and receipt["after"] == {"cpus": 6.0, "memory_bytes": 8 * GIB}
    assert json.loads((branch / "sandbox.json").read_text())["allocation_env"]["CTF_OS_ALLOCATED_CPUS"] == "6"
    runtime.execute(metadata, ["true"], 10, session_id="worker", session_role="child")
    exec_call = next(call for call in updates + [] if False) if False else None
    assert metadata["allocation_env"]["CTF_OS_RECOMMENDED_WORKERS"] == "5"


def test_resize_refuses_memory_below_usage_and_preserves_on_update_failure(monkeypatch, tmp_path: Path) -> None:
    _branch, metadata = _resize_fixture(tmp_path)
    host = {"NanoCpus": 2_000_000_000, "Memory": 4 * GIB}

    def fake_run(argv, timeout):
        if argv[1] == "inspect":
            return subprocess.CompletedProcess(argv, 0, json.dumps([{"Config": {"Labels": metadata["labels"]}, "HostConfig": host}]), "")
        if argv[1] == "stats":
            return subprocess.CompletedProcess(argv, 0, json.dumps({"MemUsage": "3GiB / 4GiB"}), "")
        return subprocess.CompletedProcess(argv, 1, "", "update failed")

    monkeypatch.setattr(runtime, "_run", fake_run)
    with pytest.raises(SandboxError, match="below current usage"):
        resize(metadata, memory="2g", session_id="sol-main", session_role="sol")
    with pytest.raises(SandboxError, match="previous allocation retained"):
        resize(metadata, cpus=4, session_id="sol-main", session_role="sol")
    assert metadata["resources"]["cpus"] == 2


def test_new_resource_cli_surface_and_sol_only_resize_hidden_from_child(monkeypatch) -> None:
    choices = build_parser()._subparsers._group_actions[0].choices
    required = {
        "resource-status", "resource-plan", "resource-request", "resource-update",
        "resource-release", "resource-history", "resource-sample", "scheduler-rebalance",
        "sandbox-resize",
    }
    assert required <= set(choices)
    monkeypatch.setenv("CTF_OS_SESSION_ROLE", "child")
    child_choices = build_parser()._subparsers._group_actions[0].choices
    assert {"resource-request", "resource-update", "resource-release", "resource-sample"} <= set(child_choices)
    assert "sandbox-resize" not in child_choices and "scheduler-rebalance" not in child_choices
