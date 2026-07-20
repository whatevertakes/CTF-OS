"""Progress-aware elastic compute scheduling for competition-first solves.

This module deliberately owns resources, not model sessions.  It detects effective
host/Docker/cgroup capacity, persists branch requests and observations, and emits
allocations plus lifecycle recommendations for the parent Sol session.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
import json
import hashlib
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any

from ..workspace import atomic_json, state_lock


GIB = 1024**3
MIB = 1024**2
RESOURCE_SCHEMA_VERSION = 1
STATE_SCHEMA_VERSION = 2
PRIORITIES = ("CRITICAL", "HIGH", "NORMAL", "LOW")
WORKLOAD_CLASSES = (
    "quick-recon", "static-analysis", "dynamic-debugging", "exploit-development",
    "web-probing", "service-runtime", "symbolic-execution", "fuzzing", "crypto-light",
    "crypto-heavy", "password-cracking", "forensic-scan", "forensic-extraction",
    "ai-inference", "ai-training", "independent-full-solve", "clean-room-verification",
    "custom-cpu-bound", "custom-memory-bound", "custom-io-bound", "custom-network-bound",
)
TERMINAL_STATES = frozenset({
    "COMPLETED", "COMPLETE", "ERROR", "DEAD", "DEAD_BRANCH", "REPLACED", "RELEASED",
    "CLEANED", "TERMINATED", "STALE", "VERIFIED", "STOPPED",
})
COMPUTE_WORKLOADS = frozenset({
    "symbolic-execution", "fuzzing", "crypto-heavy", "password-cracking",
    "forensic-scan", "forensic-extraction", "ai-inference", "ai-training",
    "custom-cpu-bound",
})
NETWORK_WORKLOADS = frozenset({"web-probing", "custom-network-bound"})
IO_WORKLOADS = frozenset({"forensic-scan", "forensic-extraction", "custom-io-bound"})
MEMORY_WORKLOADS = frozenset({
    "symbolic-execution", "crypto-heavy", "forensic-scan", "forensic-extraction",
    "ai-inference", "ai-training", "custom-memory-bound",
})


class SchedulerError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class WorkloadDefaults:
    min_cpus: float
    preferred_cpus: float
    max_cpus: float
    min_memory_bytes: int
    preferred_memory_bytes: int
    max_memory_bytes: int
    storage_bytes: int
    priority: str = "NORMAL"
    parallelizable: bool = False
    elastic: bool = True
    preemptible: bool = True
    gpu_preferred: bool = False
    memory_per_worker_bytes: int = 0


def _d(cpus: tuple[float, float, float], memory_gib: tuple[int, int, int], storage_gib: int,
       **kwargs: Any) -> WorkloadDefaults:
    return WorkloadDefaults(
        *cpus, *(value * GIB for value in memory_gib), storage_gib * GIB, **kwargs,
    )


WORKLOAD_DEFAULTS: dict[str, WorkloadDefaults] = {
    "quick-recon": _d((1, 1.5, 2), (1, 2, 3), 2, priority="LOW"),
    "static-analysis": _d((2, 3, 4), (4, 6, 8), 4, parallelizable=True),
    "dynamic-debugging": _d((2, 3, 4), (4, 6, 8), 4, priority="HIGH"),
    "exploit-development": _d((2, 4, 8), (4, 8, 12), 4, priority="HIGH", parallelizable=True),
    "web-probing": _d((1, 2, 3), (2, 4, 6), 3, parallelizable=True),
    "service-runtime": _d((1, 2, 4), (2, 4, 8), 4, preemptible=False),
    "symbolic-execution": _d((2, 6, 10), (4, 14, 16), 8, priority="HIGH", parallelizable=True, memory_per_worker_bytes=2 * GIB),
    "fuzzing": _d((2, 8, 10), (4, 8, 12), 8, priority="HIGH", parallelizable=True, memory_per_worker_bytes=GIB),
    "crypto-light": _d((1, 3, 4), (2, 4, 8), 4, parallelizable=True),
    "crypto-heavy": _d((2, 8, 10), (6, 16, 20), 8, priority="HIGH", parallelizable=True, memory_per_worker_bytes=2 * GIB),
    "password-cracking": _d((1, 8, 64), (2, 6, 12), 4, priority="HIGH", parallelizable=True, gpu_preferred=True),
    "forensic-scan": _d((2, 6, 8), (6, 14, 18), 16, parallelizable=True, memory_per_worker_bytes=2 * GIB),
    "forensic-extraction": _d((2, 6, 8), (8, 14, 18), 24, parallelizable=True, memory_per_worker_bytes=2 * GIB),
    "ai-inference": _d((2, 6, 8), (6, 12, 16), 12, priority="HIGH", parallelizable=True, gpu_preferred=True, memory_per_worker_bytes=2 * GIB),
    "ai-training": _d((4, 6, 8), (8, 16, 20), 16, priority="HIGH", parallelizable=True, gpu_preferred=True, memory_per_worker_bytes=2 * GIB),
    "independent-full-solve": _d((2, 4, 6), (4, 8, 12), 6, parallelizable=True),
    "clean-room-verification": _d((1, 2, 4), (2, 4, 8), 4, priority="LOW"),
    "custom-cpu-bound": _d((1, 4, 16), (2, 6, 16), 6, parallelizable=True),
    "custom-memory-bound": _d((1, 3, 8), (4, 12, 32), 8, memory_per_worker_bytes=2 * GIB),
    "custom-io-bound": _d((1, 3, 8), (2, 8, 16), 16, parallelizable=True),
    "custom-network-bound": _d((1, 2, 6), (2, 4, 8), 4, parallelizable=True),
}


@dataclass(frozen=True, slots=True)
class ResourceRequest:
    contest: str
    challenge_id: str
    session_id: str
    workload_class: str
    priority: str
    min_cpus: float
    preferred_cpus: float
    max_cpus: float
    min_memory_bytes: int
    preferred_memory_bytes: int
    max_memory_bytes: int
    storage_bytes: int
    gpu_required: bool = False
    gpu_preferred: bool = False
    gpu_memory_bytes: int = 0
    parallelizable: bool = False
    elastic: bool = True
    preemptible: bool = True
    created_at: str = field(default_factory=lambda: utc_now())
    updated_at: str = field(default_factory=lambda: utc_now())
    schema_version: int = RESOURCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != RESOURCE_SCHEMA_VERSION:
            raise SchedulerError(f"unsupported resource request schema {self.schema_version}")
        if self.workload_class not in WORKLOAD_DEFAULTS:
            raise SchedulerError(f"unknown workload class {self.workload_class!r}")
        if self.priority not in PRIORITIES:
            raise SchedulerError(f"priority must be one of {PRIORITIES}")
        if not all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,255}", value) for value in (self.contest, self.challenge_id, self.session_id)):
            raise SchedulerError("contest, challenge_id, and session_id must be safe identifiers")
        if not 0 < self.min_cpus <= self.preferred_cpus <= self.max_cpus:
            raise SchedulerError("CPU request must satisfy 0 < min <= preferred <= max")
        if not 0 < self.min_memory_bytes <= self.preferred_memory_bytes <= self.max_memory_bytes:
            raise SchedulerError("memory request must satisfy 0 < min <= preferred <= max")
        if self.storage_bytes <= 0 or self.gpu_memory_bytes < 0:
            raise SchedulerError("storage must be positive and GPU memory non-negative")
        if self.gpu_required and not self.gpu_memory_bytes:
            raise SchedulerError("GPU-required requests must declare a VRAM budget")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "ResourceRequest":
        normalized = normalize_resource_request(raw)
        fields = cls.__dataclass_fields__
        return cls(**{key: normalized[key] for key in fields})


def default_request(
    *, contest: str, challenge_id: str, session_id: str, workload_class: str,
    priority: str | None = None, input_bytes: int = 0, expansion_factor: float | None = None,
    gpu_required: bool = False, gpu_preferred: bool | None = None,
    overrides: Mapping[str, Any] | None = None,
) -> ResourceRequest:
    if workload_class not in WORKLOAD_DEFAULTS:
        raise SchedulerError(f"unknown workload class {workload_class!r}")
    defaults = WORKLOAD_DEFAULTS[workload_class]
    storage = max(defaults.storage_bytes, estimate_storage(input_bytes, workload_class, expansion_factor))
    payload: dict[str, Any] = {
        "contest": contest, "challenge_id": challenge_id, "session_id": session_id,
        "workload_class": workload_class, "priority": (priority or defaults.priority).upper(),
        "min_cpus": defaults.min_cpus, "preferred_cpus": defaults.preferred_cpus,
        "max_cpus": defaults.max_cpus, "min_memory_bytes": defaults.min_memory_bytes,
        "preferred_memory_bytes": defaults.preferred_memory_bytes,
        "max_memory_bytes": defaults.max_memory_bytes, "storage_bytes": storage,
        "gpu_required": gpu_required,
        "gpu_preferred": defaults.gpu_preferred if gpu_preferred is None else gpu_preferred,
        "gpu_memory_bytes": 4 * GIB if gpu_required or (defaults.gpu_preferred if gpu_preferred is None else gpu_preferred) else 0,
        "parallelizable": defaults.parallelizable, "elastic": defaults.elastic,
        "preemptible": defaults.preemptible,
    }
    payload.update(dict(overrides or {}))
    return ResourceRequest.from_mapping(payload)


def normalize_resource_request(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize v1 requests and legacy profile-shaped metadata without migration."""
    if "workload_class" not in raw:
        profile = str(raw.get("resource_profile", "standard"))
        workload = {
            "light": "quick-recon", "standard": "independent-full-solve",
            "heavy": "custom-cpu-bound", "large-forensic": "forensic-extraction",
        }.get(profile, "independent-full-solve")
        defaults = WORKLOAD_DEFAULTS[workload]
        resources = raw.get("resources") if isinstance(raw.get("resources"), Mapping) else {}
        cpus = float(resources.get("cpus", defaults.preferred_cpus))
        memory = parse_bytes(resources.get("memory", defaults.preferred_memory_bytes))
        storage = parse_bytes(resources.get("storage", defaults.storage_bytes))
        return {
            "schema_version": RESOURCE_SCHEMA_VERSION,
            "contest": str(raw.get("contest") or raw.get("contest_slug") or "legacy"),
            "challenge_id": str(raw.get("challenge_id") or "legacy"),
            "session_id": str(raw.get("session_id") or raw.get("branch") or "legacy"),
            "workload_class": workload, "priority": defaults.priority,
            "min_cpus": min(defaults.min_cpus, cpus), "preferred_cpus": cpus,
            "max_cpus": max(defaults.max_cpus, cpus),
            "min_memory_bytes": min(defaults.min_memory_bytes, memory),
            "preferred_memory_bytes": memory, "max_memory_bytes": max(defaults.max_memory_bytes, memory),
            "storage_bytes": storage, "gpu_required": False,
            "gpu_preferred": bool(raw.get("gpu_enabled", defaults.gpu_preferred)),
            "gpu_memory_bytes": 4 * GIB if raw.get("gpu_enabled") else 0,
            "parallelizable": defaults.parallelizable, "elastic": True, "preemptible": True,
            "created_at": str(raw.get("created_at") or utc_now()),
            "updated_at": str(raw.get("updated_at") or utc_now()),
        }
    result = dict(raw)
    result.setdefault("schema_version", RESOURCE_SCHEMA_VERSION)
    result.setdefault("created_at", utc_now())
    result.setdefault("updated_at", result["created_at"])
    for key in ("min_cpus", "preferred_cpus", "max_cpus"):
        result[key] = float(result[key])
    for key in ("min_memory_bytes", "preferred_memory_bytes", "max_memory_bytes", "storage_bytes", "gpu_memory_bytes"):
        result[key] = parse_bytes(result.get(key, 0))
    for key in ("gpu_required", "gpu_preferred", "parallelizable", "elastic", "preemptible"):
        result[key] = bool(result.get(key, False))
    result["priority"] = str(result.get("priority", "NORMAL")).upper()
    return result


def estimate_storage(input_bytes: int, workload_class: str, expansion_factor: float | None = None) -> int:
    factors = {
        "forensic-extraction": 6.0, "forensic-scan": 3.0, "fuzzing": 2.0,
        "ai-training": 2.5, "ai-inference": 1.5,
    }
    factor = expansion_factor if expansion_factor is not None else factors.get(workload_class, 1.25)
    return max(GIB, int(max(0, input_bytes) * max(1.0, factor)))


def infer_workload(
    *, command: Sequence[str] = (), files: Sequence[str] = (), role: str = "",
    category: str = "", override: str | None = None,
) -> dict[str, Any]:
    if override:
        if override not in WORKLOAD_DEFAULTS:
            raise SchedulerError(f"unknown workload override {override!r}")
        return {"workload_class": override, "confidence": "OVERRIDE", "evidence": ["Sol override"]}
    text = " ".join([*command, *files, role, category]).casefold()
    rules = (
        ("ai-training", ("training", "adversarial", "torchrun")),
        ("ai-inference", ("torch", "cuda", ".pt", ".safetensors", "model weights")),
        ("password-cracking", ("hashcat", "john", "password cracking")),
        ("fuzzing", ("afl++", "afl-fuzz", "honggfuzz", "fuzzer")),
        ("symbolic-execution", ("angr", "z3", "symbolic", "constraint")),
        ("crypto-heavy", ("sage", "fpylll", "cado-nfs", "lattice", "factoring")),
        ("dynamic-debugging", ("gdb", "lldb", "ptrace", "dynamic")),
        ("forensic-extraction", ("disk image", ".raw", ".e01", "memory dump", "volatility", "binwalk")),
        ("forensic-scan", ("pcap", ".pcap", "tshark", "forensic")),
        ("web-probing", ("web", "http", "burp", "curl", "network")),
        ("exploit-development", ("exploit", "pwntools", "rop", "shellcode")),
        ("clean-room-verification", ("verifier", "verification", "clean-room")),
        ("independent-full-solve", ("independent-full-solve", "full solve")),
        ("static-analysis", ("static", "ghidra", "objdump", "decompile", "elf")),
    )
    for workload, needles in rules:
        matches = [needle for needle in needles if needle in text]
        if matches:
            return {"workload_class": workload, "confidence": "INFERRED", "evidence": matches}
    fallback = "web-probing" if category.casefold() == "web" else "independent-full-solve"
    return {"workload_class": fallback, "confidence": "DEFAULT", "evidence": [f"category={category or 'unknown'}", f"role={role or 'unknown'}"]}


@dataclass(frozen=True, slots=True)
class HostCapacity:
    observation_mode: str
    degraded_metrics: tuple[str, ...]
    cpu: Mapping[str, Any]
    memory: Mapping[str, Any]
    storage: Mapping[str, Any]
    gpu: Mapping[str, Any]
    load_average: tuple[float, float, float] | None
    active: tuple[Mapping[str, Any], ...] = ()
    measured: Mapping[str, Any] = field(default_factory=dict)
    schema_version: int = RESOURCE_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def detect_capacity(
    *, docker: str = "docker", workspace: Path | str = ".",
    run: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    environ: Mapping[str, str] | None = None,
) -> HostCapacity:
    runner = run or _run
    env = dict(os.environ if environ is None else environ)
    degraded: list[str] = []
    host_logical = float(os.cpu_count() or 1)
    physical = _physical_cores()
    docker_cpus = _docker_scalar(runner, [docker, "info", "--format", "{{json .NCPU}}"], float, "docker_cpu", degraded)
    cgroup_cpu = _cgroup_cpu_limit()
    user_cpu = _optional_float(env.get("CTF_OS_CPU_CAP"))
    cpu_limits = [host_logical, *[x for x in (docker_cpus, cgroup_cpu, user_cpu) if x and x > 0]]
    cpu_total = min(cpu_limits)
    cpu_reserve = _cpu_reserve(cpu_total)
    cpu_budget = max(0.0, cpu_total - cpu_reserve)

    memory_info = _meminfo()
    host_memory = memory_info.get("MemTotal", 0)
    available_memory = memory_info.get("MemAvailable", 0)
    swap_total = memory_info.get("SwapTotal", 0)
    swap_free = memory_info.get("SwapFree", 0)
    docker_memory = _docker_scalar(runner, [docker, "info", "--format", "{{json .MemTotal}}"], int, "docker_memory", degraded)
    cgroup_memory = _cgroup_memory_limit()
    user_memory = parse_bytes(env["CTF_OS_MEMORY_CAP"]) if env.get("CTF_OS_MEMORY_CAP") else None
    memory_limits = [value for value in (host_memory, docker_memory, cgroup_memory, user_memory) if value and value > 0]
    if not memory_limits:
        memory_total = 8 * GIB
        degraded.append("host_memory")
    else:
        memory_total = min(memory_limits)
    memory_reserve = max(4 * GIB, int(memory_total * .15))
    memory_budget = max(0, memory_total - memory_reserve)

    workspace_path = Path(workspace).resolve()
    try:
        workspace_free = shutil.disk_usage(workspace_path).free
    except OSError:
        workspace_free = 0
        degraded.append("workspace_storage")
    docker_root = _docker_text(runner, [docker, "info", "--format", "{{json .DockerRootDir}}"])
    docker_free = None
    if docker_root:
        try:
            docker_free = shutil.disk_usage(Path(json.loads(docker_root))).free
        except (OSError, json.JSONDecodeError, TypeError):
            degraded.append("docker_storage")
    else:
        degraded.append("docker_storage")
    storage_free = min(value for value in (workspace_free, docker_free) if value is not None) if workspace_free else (docker_free or 0)
    storage_reserve = max(10 * GIB, int(storage_free * .10))

    active: list[Mapping[str, Any]] = []
    measured: dict[str, Any] = {"cpu_usage_cpus": 0.0, "memory_usage_bytes": 0}
    try:
        from ..sandbox.resources import _list_managed_sandboxes
        active = [item for item in _list_managed_sandboxes(docker=docker, include_stopped=False) if item.get("running")]
    except Exception:
        degraded.append("sandbox_reservations")
    stats = sample_docker_stats(docker=docker, run=runner)
    if stats.get("observation_mode") == "DEGRADED":
        degraded.extend(str(item) for item in stats.get("degraded_metrics", []))
    else:
        measured = {
            "cpu_usage_cpus": round(sum(float(item.get("cpu_usage_cpus", 0)) for item in stats["samples"]), 4),
            "memory_usage_bytes": sum(int(item.get("memory_usage_bytes", 0)) for item in stats["samples"]),
        }
    reserved_cpu = sum(float(item.get("cpus", 0)) for item in active)
    reserved_memory = sum(int(item.get("memory_bytes", 0)) for item in active)
    reserved_storage = sum(int(item.get("storage_bytes", 0)) for item in active)
    if available_memory:
        # Existing CTF usage is already part of MemAvailable pressure and remains
        # schedulable; new growth may consume only availability above host reserve.
        memory_budget = min(
            memory_budget,
            max(reserved_memory, int(measured["memory_usage_bytes"]) + max(0, available_memory - memory_reserve)),
        )
    gpu = detect_gpus(docker=docker, run=runner)
    if gpu.get("observation_mode") == "DEGRADED":
        degraded.extend(str(item) for item in gpu.get("degraded_metrics", []))
    try:
        load = tuple(float(value) for value in os.getloadavg())
    except OSError:
        load = None
        degraded.append("load_average")
    return HostCapacity(
        observation_mode="DEGRADED" if degraded else "FULL",
        degraded_metrics=tuple(sorted(set(degraded))),
        cpu={
            "host_logical": host_logical, "host_physical": physical,
            "docker_limit": docker_cpus, "cgroup_limit": cgroup_cpu, "user_cap": user_cpu,
            "effective_total": cpu_total, "reserve": cpu_reserve, "usable": cpu_budget,
            "reserved": reserved_cpu, "measured_usage": measured["cpu_usage_cpus"],
            "remaining": max(0.0, cpu_budget - reserved_cpu),
        },
        memory={
            "host_total_bytes": host_memory, "docker_limit_bytes": docker_memory,
            "cgroup_limit_bytes": cgroup_memory, "user_cap_bytes": user_memory,
            "effective_total_bytes": memory_total, "available_bytes": available_memory,
            "reserve_bytes": memory_reserve, "usable_bytes": memory_budget,
            "reserved_bytes": reserved_memory, "measured_usage_bytes": measured["memory_usage_bytes"],
            "remaining_bytes": max(0, memory_budget - reserved_memory),
            "swap_total_bytes": swap_total, "swap_used_bytes": max(0, swap_total - swap_free),
        },
        storage={
            "workspace_free_bytes": workspace_free, "docker_root": _decoded_json_string(docker_root),
            "docker_free_bytes": docker_free, "effective_free_bytes": storage_free,
            "reserve_bytes": storage_reserve, "usable_bytes": max(0, storage_free - storage_reserve),
            "reserved_bytes": reserved_storage,
            "remaining_bytes": max(0, storage_free - storage_reserve - reserved_storage),
        },
        gpu=gpu, load_average=load, active=tuple(active), measured=measured,
    )


def detect_gpus(*, docker: str = "docker", run: Callable[..., subprocess.CompletedProcess[str]] | None = None) -> dict[str, Any]:
    runner = run or _run
    degraded: list[str] = []
    runtime_text = _docker_text(runner, [docker, "info", "--format", "{{json .Runtimes}}"])
    runtime = bool(runtime_text and "nvidia" in runtime_text.casefold())
    query = runner([
        "nvidia-smi", "--query-gpu=index,name,memory.total,memory.free,utilization.gpu",
        "--format=csv,noheader,nounits",
    ], capture_output=True, text=True, timeout=10, check=False)
    devices: list[dict[str, Any]] = []
    if query.returncode == 0:
        for line in query.stdout.splitlines():
            parts = [item.strip() for item in line.split(",")]
            if len(parts) != 5:
                degraded.append("gpu_metrics")
                continue
            try:
                devices.append({
                    "index": int(parts[0]), "model": parts[1],
                    "vram_total_bytes": int(float(parts[2]) * MIB),
                    "vram_free_bytes": int(float(parts[3]) * MIB),
                    "utilization_percent": float(parts[4]), "assigned_vram_bytes": 0,
                })
            except ValueError:
                degraded.append("gpu_metrics")
    elif Path("/dev/nvidia0").exists():
        degraded.append("gpu_metrics")
    return {
        "observation_mode": "DEGRADED" if degraded else "FULL",
        "degraded_metrics": sorted(set(degraded)), "docker_runtime": runtime,
        "available": bool(devices and runtime), "device_count": len(devices), "devices": devices,
    }


def sample_docker_stats(*, docker: str = "docker", run: Callable[..., subprocess.CompletedProcess[str]] | None = None) -> dict[str, Any]:
    runner = run or _run
    listed = runner(
        [docker, "ps", "--filter", "label=ctf-os=true", "--format", "{{.Names}}"],
        capture_output=True, text=True, timeout=20, check=False,
    )
    if listed.returncode:
        return {"observation_mode": "DEGRADED", "degraded_metrics": ["docker_stats"], "samples": []}
    names = [name.strip() for name in listed.stdout.splitlines() if name.strip()]
    if not names:
        return {"observation_mode": "FULL", "degraded_metrics": [], "samples": []}
    result = runner(
        [docker, "stats", "--no-stream", "--format", "{{json .}}", *names],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if result.returncode:
        return {"observation_mode": "DEGRADED", "degraded_metrics": ["docker_stats"], "samples": []}
    samples = []
    for line in result.stdout.splitlines():
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(raw, Mapping):
            continue
        cpu_percent = _percent(raw.get("CPUPerc") or raw.get("CPU %"))
        memory_usage, memory_limit = _usage_pair(raw.get("MemUsage") or raw.get("Mem Usage"))
        block_read, block_write = _usage_pair(raw.get("BlockIO") or raw.get("Block I/O"))
        net_read, net_write = _usage_pair(raw.get("NetIO") or raw.get("Net I/O"))
        samples.append({
            "container": str(raw.get("Name") or raw.get("Container") or raw.get("ID") or ""),
            "sampled_at": utc_now(), "cpu_percent": cpu_percent,
            "cpu_usage_cpus": cpu_percent / 100.0,
            "memory_usage_bytes": memory_usage, "memory_limit_bytes": memory_limit,
            "pid_count": _int(raw.get("PIDs")), "block_read_bytes": block_read,
            "block_write_bytes": block_write, "network_read_bytes": net_read,
            "network_write_bytes": net_write,
        })
    return {"observation_mode": "FULL", "degraded_metrics": [], "samples": samples}


def recommended_workers(workload_class: str, allocated_cpus: float, allocated_memory_bytes: int) -> int:
    cpus = max(1, int(math.floor(allocated_cpus)))
    if workload_class in NETWORK_WORKLOADS or workload_class in IO_WORKLOADS:
        workers = max(1, int(math.ceil(allocated_cpus * 1.5)))
    elif workload_class in MEMORY_WORKLOADS:
        per_worker = WORKLOAD_DEFAULTS[workload_class].memory_per_worker_bytes or 2 * GIB
        workers = min(cpus, max(1, allocated_memory_bytes // per_worker))
    elif workload_class in COMPUTE_WORKLOADS or workload_class in {"static-analysis", "exploit-development"}:
        workers = cpus if cpus <= 2 else cpus - 1
    else:
        workers = cpus
    return max(1, workers)


def allocation_environment(allocation: Mapping[str, Any], request: ResourceRequest | Mapping[str, Any]) -> dict[str, str]:
    req = request if isinstance(request, ResourceRequest) else ResourceRequest.from_mapping(request)
    cpus = float(allocation.get("cpus", req.min_cpus))
    memory = int(allocation.get("memory_bytes", req.min_memory_bytes))
    workers = recommended_workers(req.workload_class, cpus, memory)
    threads = str(max(1, int(math.floor(cpus))))
    return {
        "CTF_OS_ALLOCATED_CPUS": f"{cpus:g}",
        "CTF_OS_ALLOCATED_MEMORY_BYTES": str(memory),
        "CTF_OS_RECOMMENDED_WORKERS": str(workers),
        "CTF_OS_WORKLOAD_CLASS": req.workload_class,
        "CTF_OS_RESOURCE_PRIORITY": req.priority,
        "OMP_NUM_THREADS": threads, "OPENBLAS_NUM_THREADS": threads,
        "MKL_NUM_THREADS": threads, "NUMEXPR_NUM_THREADS": threads,
        "RAYON_NUM_THREADS": threads,
    }


def progress_present(progress: Mapping[str, Any] | None, samples: Sequence[Mapping[str, Any]] = ()) -> bool:
    if progress:
        if progress.get("repeated_error") or progress.get("busy_loop") or progress.get("deadlock"):
            return False
        # Compute liveness and flag-path movement are useful.  Fact, evidence,
        # checkpoint, or generic artifact counts alone are deliberately not
        # progress: scaling those signals rewards research drift.
        indicators = (
            "step", "generation", "candidate_score", "coverage",
            "subprocess_completed", "solver_output_timestamp", "constraint_reduction",
            "exploit_proximity", "flag_proximity", "decisive_experiment_count",
            "working_poc_present", "remote_ready", "remote_interactions",
            "deterministic_extraction_progress",
        )
        if any(progress.get(key) not in (None, 0, 0.0, "", False) for key in indicators):
            return True
    return any(bool(sample.get("progress")) for sample in samples)


def classify_utilization(
    samples: Sequence[Mapping[str, Any]], *, request: ResourceRequest | Mapping[str, Any],
    progress: Mapping[str, Any] | None = None, minimum_samples: int = 3,
) -> str:
    if len(samples) < minimum_samples:
        return "UNKNOWN"
    req = request if isinstance(request, ResourceRequest) else ResourceRequest.from_mapping(request)
    window = samples[-max(minimum_samples, 5):]
    progressing = progress_present(progress, window)
    cpu_ratios = []
    for row in window:
        allocated = float(row.get("allocated_cpus") or row.get("cpu_quota") or req.min_cpus)
        usage = float(row.get("cpu_usage_cpus", float(row.get("cpu_percent", 0)) / 100.0))
        cpu_ratios.append(usage / allocated if allocated else 0.0)
    cpu = sum(cpu_ratios) / len(cpu_ratios)
    memory_ratios = [
        int(row.get("memory_usage_bytes", 0)) / int(row.get("memory_limit_bytes") or req.min_memory_bytes)
        for row in window if int(row.get("memory_limit_bytes") or req.min_memory_bytes) > 0
    ]
    memory = sum(memory_ratios) / len(memory_ratios) if memory_ratios else 0.0
    network_delta = _counter_delta(window, ("network_read_bytes", "network_write_bytes"))
    io_delta = _counter_delta(window, ("block_read_bytes", "block_write_bytes"))
    gpu = sum(float(row.get("gpu_utilization_percent", 0)) for row in window) / len(window)
    gpu_memory = max(float(row.get("gpu_memory_ratio", 0)) for row in window)
    broken = bool(progress and (progress.get("busy_loop") or progress.get("deadlock") or progress.get("repeated_error") or progress.get("output_stalled")))
    if (cpu >= .75 and (broken or not progressing)):
        return "STALLED_COMPUTE"
    if memory >= .90 and progressing:
        return "MEMORY_STARVED"
    if req.gpu_preferred and (gpu >= 90 or gpu_memory >= .92) and progressing:
        return "GPU_STARVED"
    if cpu >= .90 and progressing and req.parallelizable:
        return "CPU_STARVED"
    if network_delta > 0 and progressing and cpu < .65:
        return "NETWORK_BOUND"
    if io_delta > 0 and progressing and cpu < .65:
        return "IO_BOUND"
    if cpu >= .75:
        return "SATURATED"
    if cpu < .10 and not progressing and network_delta == 0 and io_delta == 0:
        return "IDLE"
    if cpu < .40:
        return "UNDERUTILIZED"
    return "SATURATED" if progressing else "UNKNOWN"


def plan_allocations(
    requests: Sequence[ResourceRequest | Mapping[str, Any]], capacity: HostCapacity | Mapping[str, Any],
    *, current: Mapping[str, Mapping[str, Any]] | None = None,
    observations: Mapping[str, Mapping[str, Any]] | None = None,
    remote_flag_session: str | None = None, tier: int | None = None,
) -> dict[str, Any]:
    cap = capacity.to_dict() if isinstance(capacity, HostCapacity) else dict(capacity)
    current = current or {}
    current_cpu = sum(float(row.get("cpus", 0)) for row in current.values())
    current_memory = sum(int(row.get("memory_bytes", 0)) for row in current.values())
    current_storage = sum(int(row.get("storage_bytes", 0)) for row in current.values())
    external_cpu = max(0.0, float(cap["cpu"].get("reserved", 0)) - current_cpu)
    external_memory = max(0, int(cap["memory"].get("reserved_bytes", 0)) - current_memory)
    external_storage = max(0, int(cap["storage"].get("reserved_bytes", 0)) - current_storage)
    cpu_budget = max(0.0, float(cap["cpu"]["usable"]) - external_cpu)
    memory_budget = max(0, int(cap["memory"]["usable_bytes"]) - external_memory)
    storage_budget = max(0, int(cap["storage"]["usable_bytes"]) - external_storage)
    devices = [dict(item) for item in cap.get("gpu", {}).get("devices", [])]
    normalized = [item if isinstance(item, ResourceRequest) else ResourceRequest.from_mapping(item) for item in requests]
    observations = observations or {}
    active = []
    released = []
    verifier_kept = False
    for req in normalized:
        obs = observations.get(req.session_id, {})
        state = str(obs.get("state", "ACTIVE")).upper()
        if state in TERMINAL_STATES:
            released.append({"session_id": req.session_id, "reason": f"terminal state {state}"})
            continue
        if remote_flag_session and req.session_id != remote_flag_session:
            if req.workload_class == "clean-room-verification" and not verifier_kept:
                verifier_kept = True
            else:
                released.append({"session_id": req.session_id, "reason": "remote flag fast path reclaims low-value branch"})
                continue
        active.append(req)
    active.sort(key=lambda req: _allocation_rank(req, observations.get(req.session_id, {}), remote_flag_session))
    allocations: dict[str, dict[str, Any]] = {}
    cpu_left, memory_left, storage_left = cpu_budget, memory_budget, storage_budget
    waiting = []
    for req in active:
        if req.min_cpus <= cpu_left + 1e-9 and req.min_memory_bytes <= memory_left and req.storage_bytes <= storage_left:
            allocations[req.session_id] = {
                "cpus": req.min_cpus, "memory_bytes": req.min_memory_bytes,
                "storage_bytes": req.storage_bytes, "gpu_device": None,
                "gpu_memory_bytes": 0, "state": "ADMITTED",
            }
            cpu_left -= req.min_cpus
            memory_left -= req.min_memory_bytes
            storage_left -= req.storage_bytes
        else:
            waiting.append({
                "session_id": req.session_id, "reason": "minimum CPU/memory/storage does not fit after host reserve",
                "missing": {"cpus": max(0.0, req.min_cpus - cpu_left), "memory_bytes": max(0, req.min_memory_bytes - memory_left), "storage_bytes": max(0, req.storage_bytes - storage_left)},
            })
    # GPU assignment is exclusive by declared VRAM reservation. Preferred workloads
    # fall back to CPU; required workloads wait when no safe assignment exists.
    for req in active:
        if req.session_id not in allocations or not (req.gpu_required or req.gpu_preferred):
            continue
        match = next((device for device in devices if int(device.get("vram_free_bytes", 0)) - int(device.get("assigned_vram_bytes", 0)) >= req.gpu_memory_bytes), None)
        if match and cap.get("gpu", {}).get("docker_runtime"):
            match["assigned_vram_bytes"] = int(match.get("assigned_vram_bytes", 0)) + req.gpu_memory_bytes
            allocations[req.session_id]["gpu_device"] = int(match["index"])
            allocations[req.session_id]["gpu_memory_bytes"] = req.gpu_memory_bytes
        elif req.gpu_required:
            allocation = allocations.pop(req.session_id)
            cpu_left += float(allocation["cpus"]); memory_left += int(allocation["memory_bytes"]); storage_left += int(allocation["storage_bytes"])
            waiting.append({"session_id": req.session_id, "reason": "required GPU runtime/device/VRAM unavailable"})
        else:
            allocations[req.session_id]["gpu_fallback"] = "CPU"
    # Preferred/max pass follows the already-ranked preservation order.  Minimums
    # were guaranteed first; now flag/exploit/Sol and proven progressing compute
    # receive their full useful target before lower-value preferred allocations.
    for resource in ("memory", "cpu"):
        for req in active:
            if req.session_id not in allocations:
                continue
            allocation = allocations[req.session_id]
            obs = observations.get(req.session_id, {})
            classification = str(obs.get("classification", "UNKNOWN"))
            progressing = progress_present(obs.get("progress") if isinstance(obs.get("progress"), Mapping) else obs)
            broken = classification == "STALLED_COMPUTE" or bool(obs.get("repeated_error") or obs.get("busy_loop"))
            underutilized = classification in {"UNDERUTILIZED", "IDLE"}
            if broken or underutilized or not req.elastic:
                continue
            progress = obs.get("progress") if isinstance(obs.get("progress"), Mapping) else {}
            verified = (
                progress.get("verified_long_compute")
                if isinstance(progress.get("verified_long_compute"), Mapping) else {}
            )
            long_compute = (
                req.workload_class in COMPUTE_WORKLOADS
                and verified.get("active") is True
                and verified.get("process_valid") is True
                and verified.get("fresh_artifact_evidence") is True
                and _fresh_long_compute_evidence(verified)
            )
            scale_signal = classification in {"CPU_STARVED", "MEMORY_STARVED", "GPU_STARVED"}
            if not long_compute or not scale_signal:
                continue
            flag_or_compute = bool(obs.get("flag_path")) or progressing
            if resource == "memory":
                target = req.max_memory_bytes if progressing and classification == "MEMORY_STARVED" else req.preferred_memory_bytes
                if flag_or_compute and progressing and req.workload_class in MEMORY_WORKLOADS:
                    target = req.max_memory_bytes
                step = min(target - int(allocation["memory_bytes"]), memory_left)
                if step > 0:
                    allocation["memory_bytes"] = int(allocation["memory_bytes"]) + int(step); memory_left -= int(step)
            else:
                target = req.max_cpus if progressing and (classification == "CPU_STARVED" or flag_or_compute) else req.preferred_cpus
                step = min(target - float(allocation["cpus"]), cpu_left)
                if step > 1e-9:
                    allocation["cpus"] = round(float(allocation["cpus"]) + step, 3); cpu_left -= step
    actions = []
    for req in active:
        if req.session_id not in allocations:
            continue
        allocation = allocations[req.session_id]
        old = current.get(req.session_id, {})
        allocation["recommended_workers"] = recommended_workers(req.workload_class, float(allocation["cpus"]), int(allocation["memory_bytes"]))
        allocation["workload_class"] = req.workload_class
        allocation["priority"] = req.priority
        allocation["requested"] = {
            "cpus": [req.min_cpus, req.preferred_cpus, req.max_cpus],
            "memory_bytes": [req.min_memory_bytes, req.preferred_memory_bytes, req.max_memory_bytes],
        }
        if old and (float(old.get("cpus", 0)) != float(allocation["cpus"]) or int(old.get("memory_bytes", 0)) != int(allocation["memory_bytes"])):
            actions.append({
                "action": "RESIZE", "session_id": req.session_id,
                "from": {"cpus": old.get("cpus"), "memory_bytes": old.get("memory_bytes")},
                "to": {"cpus": allocation["cpus"], "memory_bytes": allocation["memory_bytes"]},
                "reason": _resize_reason(req, observations.get(req.session_id, {}), old, allocation),
            })
    for item in released:
        actions.append({"action": "RELEASE", **item})
    requested_width = {0: 0, 1: 2, 2: 3, 3: 4, 4: 4}.get(tier or 0, len(active))
    child_allocations = [key for key in allocations if key != "sol-main"]
    race_width = min(requested_width, len(child_allocations)) if tier is not None else len(child_allocations)
    launch = None
    additional_capacity = int(min(
        cpu_left // 2, memory_left // (4 * GIB), storage_left // (4 * GIB),
    )) if cpu_left >= 0 and memory_left >= 0 and storage_left >= 0 else 0
    if additional_capacity > 0:
        launch = "Add an alternate attack family or independent full solve; Sol owns native delegation."
    preemption = [item for item in actions if item["action"] == "RELEASE"]
    for req in active:
        obs = observations.get(req.session_id, {})
        if str(obs.get("classification")) == "STALLED_COMPUTE" or str(obs.get("utility_classification")) in {"BUMP_AND_RETRY", "REPLACE_ATTACK_FAMILY", "SOL_TAKEOVER", "DEAD_BRANCH"}:
            preemption.append({
                "action": "PREEMPT_RECOMMENDATION", "session_id": req.session_id,
                "sequence": ["shrink CPU", "stop new long commands", "request checkpoint", "export artifacts", "Sol decides native lifecycle"],
                "recommendation": str(obs.get("utility_classification") or _stalled_recommendation(obs)),
            })
    return {
        "schema_version": RESOURCE_SCHEMA_VERSION, "generated_at": utc_now(),
        "capacity_based_race_width": race_width, "template_race_width": requested_width,
        "additional_branch_capacity": max(0, additional_capacity),
        "recommended_race_width": race_width + max(0, additional_capacity),
        "allocations": allocations, "waiting": waiting, "released": released,
        "resize_actions": actions, "launch_recommendation": launch,
        "preemption_recommendations": preemption,
        "remaining": {"cpus": round(cpu_left, 3), "memory_bytes": memory_left, "storage_bytes": storage_left},
        "reason": "workload evidence, priority, measured utilization, progress, and aggregate host reserve",
    }


def _fresh_long_compute_evidence(evidence: Mapping[str, Any]) -> bool:
    value = evidence.get("valid_until_at")
    if not isinstance(value, str):
        return False
    try:
        expires = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return expires.tzinfo is not None and datetime.now(timezone.utc) <= expires.astimezone(timezone.utc)


class ResourceLedger:
    """Challenge-local append-preserving request/sample/allocation store."""

    def __init__(self, solve_root: Path):
        self.root = solve_root.resolve()
        self.state_path = self.root / "RESOURCE_STATE.json"
        self.history_path = self.root / "RESOURCE_HISTORY.jsonl"

    def load(self) -> dict[str, Any]:
        identity: dict[str, Any] = {}
        run_state = self.root / "STATE.json"
        if run_state.is_file() and not run_state.is_symlink():
            try:
                state_identity = json.loads(run_state.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise SchedulerError("run state is malformed while loading resources") from exc
            if isinstance(state_identity, dict):
                identity = {
                    "run_id": state_identity.get("run_id"),
                    "challenge_id": state_identity.get("challenge_id"),
                    "input_fingerprint": state_identity.get("input_fingerprint"),
                    "target_revision": state_identity.get("target_revision"),
                }
        if not self.state_path.exists():
            return {"schema_version": STATE_SCHEMA_VERSION, **identity, "requests": {}, "allocations": {}, "observations": {}, "released": {}, "rebalance_required": False}
        if self.state_path.is_symlink() or not self.state_path.is_file():
            raise SchedulerError("resource state is missing or unsafe")
        raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise SchedulerError("resource state must be an object")
        if identity.get("run_id") and raw.get("run_id") not in {None, identity["run_id"]}:
            raise SchedulerError("resource state belongs to a different run")
        for key, value in identity.items():
            raw.setdefault(key, value)
        raw.setdefault("requests", {}); raw.setdefault("allocations", {}); raw.setdefault("observations", {}); raw.setdefault("released", {})
        return raw

    def request(self, request: ResourceRequest, *, actor_session_id: str, actor_role: str, inference: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if actor_role not in {"sol", "child"}:
            raise SchedulerError("resource request actor role must be sol or child")
        if actor_role == "child" and actor_session_id != request.session_id:
            raise SchedulerError("child may create a resource request only for its own session")
        with state_lock(self.root):
            state = self.load()
            previous = state["requests"].get(request.session_id)
            if previous:
                request = replace(request, created_at=str(previous.get("created_at") or request.created_at), updated_at=utc_now())
            state["requests"][request.session_id] = {**request.to_dict(), "inference": dict(inference or {})}
            state["released"].pop(request.session_id, None)
            state["observations"].setdefault(request.session_id, {})["state"] = "ACTIVE"
            state["rebalance_required"] = True
            state["updated_at"] = utc_now()
            atomic_json(self.state_path, state)
        self.append_history("REQUEST", request.session_id, {"request": request.to_dict(), "inference": dict(inference or {})})
        return state["requests"][request.session_id]

    def begin_race(self, active_session_ids: Sequence[str]) -> None:
        active = set(active_session_ids)
        with state_lock(self.root):
            state = self.load()
            for session_id in set(state["requests"]) - active:
                allocation = state["allocations"].pop(session_id, None)
                state["released"][session_id] = {
                    "session_id": session_id, "released_at": utc_now(),
                    "reason": "superseded race plan", "last_allocation": allocation,
                }
                state["observations"].setdefault(session_id, {})["state"] = "RELEASED"
            state.pop("remote_flag_session", None)
            state["rebalance_required"] = True
            state["updated_at"] = utc_now()
            atomic_json(self.state_path, state)
        self.append_history("RACE_RESOURCE_RESET", "sol-main", {"active_session_ids": sorted(active)})

    def update(
        self, session_id: str, *, actor_session_id: str, actor_role: str,
        changes: Mapping[str, Any], verified_long_compute: bool = False,
    ) -> dict[str, Any]:
        if actor_role not in {"sol", "child"}:
            raise SchedulerError("resource update actor role must be sol or child")
        if actor_role == "child" and actor_session_id != session_id:
            raise SchedulerError("child may update only its own resource request")
        progress_value = changes.get("progress")
        if (
            isinstance(progress_value, Mapping)
            and "verified_long_compute" in progress_value
            and not verified_long_compute
        ):
            raise SchedulerError(
                "verified_long_compute may be published only by direct process/artifact observation"
            )
        with state_lock(self.root):
            state = self.load()
            if session_id not in state["requests"]:
                raise SchedulerError("resource request does not exist")
            raw = dict(state["requests"][session_id])
            progress = changes.get("progress")
            for key in ("priority", "workload_class", "parallelizable", "elastic", "preemptible", "gpu_required", "gpu_preferred", "gpu_memory_bytes", "min_cpus", "preferred_cpus", "max_cpus", "min_memory_bytes", "preferred_memory_bytes", "max_memory_bytes", "storage_bytes"):
                if key in changes and changes[key] is not None:
                    raw[key] = changes[key]
            if isinstance(progress, Mapping) and float(progress.get("flag_proximity", 0) or 0) >= .7:
                raw["priority"] = "CRITICAL"
            raw["updated_at"] = utc_now()
            req = ResourceRequest.from_mapping(raw)
            state["requests"][session_id] = {**raw, **req.to_dict()}
            obs = state["observations"].setdefault(session_id, {})
            if isinstance(progress, Mapping):
                obs["progress"] = dict(progress)
            if changes.get("state"):
                obs["state"] = str(changes["state"]).upper()
            if changes.get("utility_classification"):
                obs["utility_classification"] = str(changes["utility_classification"]).upper()
            if changes.get("scheduler_recommendation"):
                obs["scheduler_recommendation"] = str(changes["scheduler_recommendation"])
            state["rebalance_required"] = True
            state["updated_at"] = utc_now()
            atomic_json(self.state_path, state)
        self.append_history("UPDATE", session_id, dict(changes))
        return {"request": state["requests"][session_id], "observation": state["observations"].get(session_id, {})}

    def sample(self, session_id: str, sample: Mapping[str, Any]) -> dict[str, Any]:
        with state_lock(self.root):
            state = self.load()
            if session_id not in state["requests"]:
                raise SchedulerError("resource request does not exist")
            obs = state["observations"].setdefault(session_id, {})
            samples = list(obs.get("samples", []))[-19:]
            row = {**dict(sample), "sampled_at": str(sample.get("sampled_at") or utc_now())}
            samples.append(row)
            obs["samples"] = samples
            req = ResourceRequest.from_mapping(state["requests"][session_id])
            obs["classification"] = classify_utilization(samples, request=req, progress=obs.get("progress"))
            obs["last_sample_at"] = row["sampled_at"]
            state["rebalance_required"] = obs["classification"] in {"CPU_STARVED", "MEMORY_STARVED", "GPU_STARVED", "STALLED_COMPUTE", "IDLE"}
            state["updated_at"] = utc_now()
            atomic_json(self.state_path, state)
        self.append_history("SAMPLE", session_id, {"sample": row, "classification": obs["classification"]})
        return obs

    def release(self, session_id: str, reason: str, *, actor_session_id: str | None = None, actor_role: str | None = None) -> dict[str, Any]:
        if actor_role is not None and actor_role not in {"sol", "child"}:
            raise SchedulerError("resource release actor role must be sol or child")
        if actor_role == "child" and actor_session_id != session_id:
            raise SchedulerError("child may release only its own resource request")
        with state_lock(self.root):
            state = self.load()
            allocation = state["allocations"].pop(session_id, None)
            record = {"session_id": session_id, "released_at": utc_now(), "reason": reason, "last_allocation": allocation}
            state["released"][session_id] = record
            state["observations"].setdefault(session_id, {})["state"] = "RELEASED"
            state["rebalance_required"] = True
            state["updated_at"] = utc_now()
            atomic_json(self.state_path, state)
        self.append_history("RELEASE", session_id, record)
        return record

    def record_resize(self, session_id: str, record: Mapping[str, Any]) -> None:
        with state_lock(self.root):
            state = self.load()
            after = record.get("after") if isinstance(record.get("after"), Mapping) else {}
            allocation = dict(state["allocations"].get(session_id, {}))
            if after.get("cpus") is not None:
                allocation["cpus"] = float(after["cpus"])
            if after.get("memory_bytes") is not None:
                allocation["memory_bytes"] = int(after["memory_bytes"])
            if allocation:
                state["allocations"][session_id] = allocation
            state["observations"].setdefault(session_id, {})["last_resize"] = dict(record)
            state["updated_at"] = utc_now()
            atomic_json(self.state_path, state)
        self.append_history("RESIZE", session_id, dict(record))

    def rebalance(self, capacity: HostCapacity | Mapping[str, Any], *, tier: int | None = None, remote_flag_session: str | None = None) -> dict[str, Any]:
        with state_lock(self.root):
            state = self.load()
            plan = self._plan_from_state(state, capacity, tier=tier, remote_flag_session=remote_flag_session)
            state["allocations"] = plan["allocations"]
            for item in plan["released"]:
                state["released"][item["session_id"]] = {**item, "released_at": utc_now()}
                state["observations"].setdefault(item["session_id"], {})["state"] = "RELEASED"
            state["last_plan"] = plan
            state["rebalance_required"] = False
            state["updated_at"] = utc_now()
            atomic_json(self.state_path, state)
        self.append_history("REBALANCE", "sol-main", {"plan": plan})
        return plan

    def plan(self, capacity: HostCapacity | Mapping[str, Any], *, tier: int | None = None, remote_flag_session: str | None = None) -> dict[str, Any]:
        """Return a dry plan without changing the current allocation baseline."""
        state = self.load()
        plan = self._plan_from_state(state, capacity, tier=tier, remote_flag_session=remote_flag_session)
        self.append_history("PLAN", "sol-main", {"plan": plan})
        return plan

    def reconcile_apply(self, plan: Mapping[str, Any], results: Sequence[Mapping[str, Any]]) -> None:
        """Restore the ledger baseline for resize operations that did not apply."""
        actions = {
            str(item.get("session_id")): item for item in plan.get("resize_actions", [])
            if isinstance(item, Mapping) and item.get("action") == "RESIZE"
        }
        with state_lock(self.root):
            state = self.load()
            for result in results:
                session_id = str(result.get("session_id", ""))
                action = actions.get(session_id)
                if not action or result.get("applied"):
                    if result.get("applied"):
                        state["observations"].setdefault(session_id, {}).pop("resize_circuit", None)
                    continue
                previous = action.get("from") if isinstance(action.get("from"), Mapping) else {}
                if previous and previous.get("cpus") is not None and previous.get("memory_bytes") is not None:
                    allocation = dict(state["allocations"].get(session_id, {}))
                    allocation["cpus"] = float(previous["cpus"])
                    allocation["memory_bytes"] = int(previous["memory_bytes"])
                    state["allocations"][session_id] = allocation
                else:
                    state["allocations"].pop(session_id, None)
                reason = str(result.get("reason") or "unknown resize failure")
                signature = hashlib.sha256(reason.encode()).hexdigest()[:16]
                obs = state["observations"].setdefault(session_id, {})
                circuit = dict(obs.get("resize_circuit") or {})
                count = int(circuit.get("count", 0)) + 1 if circuit.get("signature") == signature else 1
                obs["resize_circuit"] = {
                    "signature": signature, "reason": reason if count == 1 else circuit.get("reason", reason),
                    "count": count, "state": "RESIZE_CIRCUIT_OPEN" if count >= 2 else "CLOSED",
                    "opened_at": utc_now() if count >= 2 else None,
                }
            state["last_apply_results"] = [dict(item) for item in results]
            state["updated_at"] = utc_now()
            atomic_json(self.state_path, state)
        for result in results:
            if not result.get("applied"):
                session_id = str(result.get("session_id", ""))
                circuit = self.load().get("observations", {}).get(session_id, {}).get("resize_circuit", {})
                event = "RESIZE_CIRCUIT_OPEN" if circuit.get("state") == "RESIZE_CIRCUIT_OPEN" else "RESIZE_FAILURE"
                self.append_history(event, session_id, dict(result) if event == "RESIZE_FAILURE" else {"failure_signature": circuit.get("signature"), "count": circuit.get("count")})

    @staticmethod
    def _plan_from_state(state: Mapping[str, Any], capacity: HostCapacity | Mapping[str, Any], *, tier: int | None, remote_flag_session: str | None) -> dict[str, Any]:
        requests = [ResourceRequest.from_mapping(raw) for raw in state["requests"].values()]
        plan = plan_allocations(
            requests, capacity, current=state["allocations"], observations=state["observations"],
            remote_flag_session=remote_flag_session or state.get("remote_flag_session"), tier=tier,
        )
        open_sessions = {
            sid for sid, obs in state.get("observations", {}).items()
            if isinstance(obs, Mapping) and isinstance(obs.get("resize_circuit"), Mapping)
            and obs["resize_circuit"].get("state") == "RESIZE_CIRCUIT_OPEN"
        }
        plan["resize_actions"] = [row for row in plan["resize_actions"] if row.get("session_id") not in open_sessions]
        for sid in sorted(open_sessions):
            plan["preemption_recommendations"].append({"action": "RESIZE_CIRCUIT_OPEN", "session_id": sid, "retry_requires": "config/permission change or Sol override"})
        return plan

    def flag_event(self, event: Mapping[str, Any]) -> None:
        event_type = str(event.get("type", ""))
        session_id = str(event.get("session_id", ""))
        management_events = {
            "BLOCKER", "EXPLOIT_PRIMITIVE_CANDIDATE", "EXPLOIT_PRIMITIVE_CONFIRMED",
            "EXPLOIT_PRIMITIVE_REFUTED", "WORKING_POC", "FLAG_CANDIDATE",
            "REMOTE_FLAG_OBTAINED", "SERVICE_CRASHED",
        }
        if event_type not in management_events:
            return
        with state_lock(self.root):
            state = self.load()
            if session_id in state["requests"] and event_type in {"EXPLOIT_PRIMITIVE_CONFIRMED", "WORKING_POC", "FLAG_CANDIDATE", "REMOTE_FLAG_OBTAINED"}:
                state["requests"][session_id]["priority"] = "CRITICAL" if event_type in {"FLAG_CANDIDATE", "REMOTE_FLAG_OBTAINED"} else "HIGH"
                state["requests"][session_id]["updated_at"] = utc_now()
                obs = state["observations"].setdefault(session_id, {})
                if event_type in {"WORKING_POC", "FLAG_CANDIDATE", "REMOTE_FLAG_OBTAINED"}:
                    obs["flag_path"] = True
                if event_type == "REMOTE_FLAG_OBTAINED":
                    state["remote_flag_session"] = session_id
            if session_id in state["requests"] and event_type in {"EXPLOIT_PRIMITIVE_CONFIRMED", "WORKING_POC", "FLAG_CANDIDATE", "REMOTE_FLAG_OBTAINED"}:
                obs = state["observations"].setdefault(session_id, {})
                progress = dict(obs.get("progress") or {})
                progress["progressing"] = True
                progress["last_event_type"] = event_type
                progress["last_event_at"] = utc_now()
                if event_type == "EXPLOIT_PRIMITIVE_CONFIRMED":
                    progress["exploit_primitives"] = int(progress.get("exploit_primitives", 0)) + 1
                    progress["exploit_proximity"] = max(float(progress.get("exploit_proximity", 0) or 0), .5)
                if event_type == "WORKING_POC":
                    progress["working_poc_present"] = True
                    progress["exploit_proximity"] = max(float(progress.get("exploit_proximity", 0) or 0), .82)
                if event_type in {"FLAG_CANDIDATE", "REMOTE_FLAG_OBTAINED"}:
                    progress["exploit_proximity"] = 1.0
                    progress["flag_proximity"] = 1.0
                obs["progress"] = progress
            if session_id in state["requests"] and event_type == "EXPLOIT_PRIMITIVE_REFUTED":
                state["requests"][session_id]["priority"] = "LOW"
                obs = state["observations"].setdefault(session_id, {})
                obs["progress"] = {"progressing": False, "exploit_proximity": 0.0, "primitive_refuted": True}
            state["rebalance_required"] = True
            state["rebalance_reason"] = f"race event {event_type}"
            state["updated_at"] = utc_now()
            atomic_json(self.state_path, state)
        self.append_history("EVENT_REBALANCE_REQUIRED", session_id, {"event_type": event_type, "event_id": event.get("event_id")})

    def history(self, limit: int = 200) -> list[dict[str, Any]]:
        if not self.history_path.exists():
            return []
        if self.history_path.is_symlink() or not self.history_path.is_file():
            raise SchedulerError("resource history is missing or unsafe")
        rows = []
        for line in self.history_path.read_text(encoding="utf-8").splitlines()[-limit:]:
            row = json.loads(line)
            if isinstance(row, dict):
                rows.append(row)
        return rows

    def append_history(self, event: str, session_id: str, payload: Mapping[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        if self.history_path.is_symlink():
            raise SchedulerError("resource history must not be a symlink")
        row = {"schema_version": RESOURCE_SCHEMA_VERSION, "event": event, "session_id": session_id, "at": utc_now(), **dict(payload)}
        descriptor = os.open(self.history_path, os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush(); os.fsync(handle.fileno())


def note_race_event(solve_root: Path, event: Mapping[str, Any]) -> None:
    """Best-effort event integration; an absent resource ledger is valid early in solve."""
    ledger = ResourceLedger(solve_root)
    if ledger.state_path.exists():
        ledger.flag_event(event)


def _allocation_rank(req: ResourceRequest, obs: Mapping[str, Any], remote_flag_session: str | None) -> tuple[Any, ...]:
    priority = {"CRITICAL": 0, "HIGH": 1, "NORMAL": 2, "LOW": 3}[req.priority]
    flag = 0 if req.session_id == remote_flag_session or obs.get("flag_path") or float(obs.get("progress", {}).get("flag_proximity", 0) if isinstance(obs.get("progress"), Mapping) else 0) > .7 else 1
    workload = req.workload_class
    lane = 0 if workload == "exploit-development" else 1 if req.session_id == "sol-main" else 2 if workload == "dynamic-debugging" else 3 if workload in COMPUTE_WORKLOADS and progress_present(obs.get("progress") if isinstance(obs.get("progress"), Mapping) else obs) else 4 if workload == "independent-full-solve" else 5 if workload == "static-analysis" else 7 if workload == "clean-room-verification" else 6
    return priority, flag, lane, req.created_at, req.session_id


def _resize_reason(req: ResourceRequest, obs: Mapping[str, Any], old: Mapping[str, Any], new: Mapping[str, Any]) -> str:
    if str(obs.get("classification")) in {"CPU_STARVED", "MEMORY_STARVED", "GPU_STARVED"} and progress_present(obs.get("progress") if isinstance(obs.get("progress"), Mapping) else obs):
        return f"{obs.get('classification')} with progress"
    if str(obs.get("classification")) in {"UNDERUTILIZED", "IDLE"}:
        return f"{obs.get('classification')} shrinks toward minimum"
    return f"priority {req.priority} preferred allocation"


def _stalled_recommendation(obs: Mapping[str, Any]) -> str:
    if obs.get("repeated_error") or (isinstance(obs.get("progress"), Mapping) and obs["progress"].get("repeated_error")):
        return "REPLACE_ATTACK_FAMILY"
    if obs.get("flag_path"):
        return "SOL_TAKEOVER"
    return "BUMP_AND_RETRY"


def _cpu_reserve(total: float) -> float:
    if total >= 8:
        return 2.0
    if total >= 4:
        return 1.0
    return min(max(.25, total * .15), max(.25, total - .25))


def _physical_cores() -> int | None:
    try:
        pairs = set()
        physical = core = None
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines() + [""]:
            if line.startswith("physical id"):
                physical = line.split(":", 1)[1].strip()
            elif line.startswith("core id"):
                core = line.split(":", 1)[1].strip()
            elif not line and physical is not None and core is not None:
                pairs.add((physical, core)); physical = core = None
        return len(pairs) or None
    except OSError:
        return None


def _cgroup_cpu_limit() -> float | None:
    paths = (Path("/sys/fs/cgroup/cpu.max"),)
    for path in paths:
        try:
            quota, period = path.read_text().split()[:2]
            if quota != "max":
                return float(quota) / float(period)
        except (OSError, ValueError, IndexError):
            pass
    try:
        quota = int(Path("/sys/fs/cgroup/cpu/cpu.cfs_quota_us").read_text())
        period = int(Path("/sys/fs/cgroup/cpu/cpu.cfs_period_us").read_text())
        return quota / period if quota > 0 and period > 0 else None
    except (OSError, ValueError):
        return None


def _cgroup_memory_limit() -> int | None:
    for path in (Path("/sys/fs/cgroup/memory.max"), Path("/sys/fs/cgroup/memory/memory.limit_in_bytes")):
        try:
            text = path.read_text().strip()
            if text != "max":
                value = int(text)
                if 0 < value < 1 << 60:
                    return value
        except (OSError, ValueError):
            continue
    return None


def _meminfo() -> dict[str, int]:
    values = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, value = line.split(":", 1)
            match = re.search(r"\d+", value)
            if match:
                values[key] = int(match.group()) * 1024
    except OSError:
        pass
    return values


def _docker_scalar(runner: Callable[..., subprocess.CompletedProcess[str]], argv: list[str], cast: Callable[[Any], Any], metric: str, degraded: list[str]) -> Any:
    text = _docker_text(runner, argv)
    if text is None:
        degraded.append(metric); return None
    try:
        return cast(json.loads(text))
    except (TypeError, ValueError, json.JSONDecodeError):
        degraded.append(metric); return None


def _docker_text(runner: Callable[..., subprocess.CompletedProcess[str]], argv: list[str]) -> str | None:
    try:
        result = runner(argv, capture_output=True, text=True, timeout=20, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else None


def _run(argv: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(list(argv), **kwargs)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(list(argv), 127 if isinstance(exc, FileNotFoundError) else 124, "", str(exc))


def parse_bytes(value: Any) -> int:
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip().casefold()
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([kmgt]?)(?:i?b)?", text)
    if not match:
        raise SchedulerError(f"invalid byte size {value!r}")
    return int(float(match.group(1)) * {"": 1, "k": 1024, "m": MIB, "g": GIB, "t": 1024**4}[match.group(2)])


def _optional_float(value: str | None) -> float | None:
    try:
        parsed = float(value) if value else None
        return parsed if parsed and parsed > 0 else None
    except ValueError:
        return None


def _decoded_json_string(value: str | None) -> str | None:
    try:
        return str(json.loads(value)) if value else None
    except json.JSONDecodeError:
        return value


def _percent(value: Any) -> float:
    try:
        return float(str(value or "0").strip().removesuffix("%"))
    except ValueError:
        return 0.0


def _usage_pair(value: Any) -> tuple[int, int]:
    parts = str(value or "0 / 0").split("/", 1)
    if len(parts) == 1:
        parts.append("0")
    return _human_bytes(parts[0]), _human_bytes(parts[1])


def _human_bytes(value: str) -> int:
    match = re.search(r"([0-9.]+)\s*([kmgt]?i?b|b)?", value.strip(), re.I)
    if not match:
        return 0
    unit = (match.group(2) or "b").casefold().replace("ib", "").replace("b", "")
    return int(float(match.group(1)) * {"": 1, "k": 1024, "m": MIB, "g": GIB, "t": 1024**4}.get(unit, 1))


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _counter_delta(rows: Sequence[Mapping[str, Any]], keys: Sequence[str]) -> int:
    if len(rows) < 2:
        return 0
    return max(0, sum(int(rows[-1].get(key, 0)) - int(rows[0].get(key, 0)) for key in keys))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
