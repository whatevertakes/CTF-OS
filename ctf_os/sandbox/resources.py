from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Iterator, Sequence


GIB = 1024**3


class ResourceError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ResourceProfile:
    name: str
    memory: str
    cpus: float
    storage: str
    pids: int
    max_concurrent: int | None = None

    @property
    def memory_bytes(self) -> int:
        return parse_size_bytes(self.memory)

    @property
    def storage_bytes(self) -> int:
        return parse_size_bytes(self.storage)

    def to_dict(self) -> dict[str, object]:
        return {**asdict(self), "memory_bytes": self.memory_bytes, "storage_bytes": self.storage_bytes}


RESOURCE_PROFILES: dict[str, ResourceProfile] = {
    "light": ResourceProfile("light", "2g", 1.0, "1g", 128),
    "standard": ResourceProfile("standard", "4g", 2.0, "2g", 256),
    "heavy": ResourceProfile("heavy", "12g", 5.0, "8g", 512),
    "large-forensic": ResourceProfile("large-forensic", "16g", 5.0, "16g", 768),
}


def resource_profile(name: str) -> ResourceProfile:
    try:
        return RESOURCE_PROFILES[name]
    except KeyError as exc:
        raise ResourceError(
            f"unknown sandbox resource profile {name!r}; choose one of {', '.join(RESOURCE_PROFILES)}"
        ) from exc


def parse_size_bytes(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)([kmgt]?)(?:i?b)?", value.strip().casefold())
    if not match:
        raise ResourceError(f"invalid positive resource size: {value!r}")
    units = {"": 1, "k": 1024, "m": 1024**2, "g": GIB, "t": 1024**4}
    return int(match.group(1)) * units[match.group(2)]


def sandbox_status(*, docker: str = "docker") -> dict[str, object]:
    containers = _list_managed_sandboxes(docker=docker, include_stopped=True)
    active = [item for item in containers if item["running"]]
    stale = [item for item in containers if not item["running"]]
    host_memory = _docker_memory_total(docker)
    budget = _memory_budget(host_memory)
    reserved = sum(int(item["memory_bytes"]) for item in active)
    host_cpus = _docker_cpu_total(docker)
    if host_cpus >= 8:
        cpu_reserve = 2.0
    elif host_cpus >= 4:
        cpu_reserve = 1.0
    else:
        cpu_reserve = min(max(.25, host_cpus * .15), max(.25, host_cpus - .25))
    cpu_budget = max(0.0, host_cpus - cpu_reserve)
    reserved_cpus = sum(float(item.get("cpus", 0.0)) for item in active)
    host_storage_free = shutil.disk_usage("/").free
    storage_budget = max(0, host_storage_free - max(10 * GIB, host_storage_free // 10))
    reserved_storage = sum(int(item.get("storage_bytes", 0)) for item in active)
    counts = {name: sum(item["resource_profile"] == name for item in active) for name in RESOURCE_PROFILES}
    availability: dict[str, dict[str, object]] = {}
    for name, profile in RESOURCE_PROFILES.items():
        memory_ok = reserved + profile.memory_bytes <= budget
        cpu_ok = reserved_cpus + profile.cpus <= cpu_budget
        storage_ok = reserved_storage + profile.storage_bytes <= storage_budget
        availability[name] = {
            "can_admit": memory_ok and cpu_ok and storage_ok,
            "active": counts[name],
            "max_concurrent": None,
            "memory_available": memory_ok,
            "cpu_available": cpu_ok,
            "storage_available": storage_ok,
        }
    return {
        "schema_version": 1,
        "profiles": {name: profile.to_dict() for name, profile in RESOURCE_PROFILES.items()},
        "active": active,
        "stale": stale,
        "active_count": len(active),
        "reserved_memory_bytes": reserved,
        "host_memory_bytes": host_memory,
        "admission_memory_budget_bytes": budget,
        "reserved_cpus": reserved_cpus,
        "host_cpus": host_cpus,
        "admission_cpu_budget": cpu_budget,
        "reserved_storage_bytes": reserved_storage,
        "host_storage_free_bytes": host_storage_free,
        "admission_storage_budget_bytes": storage_budget,
        "gpu_available": gpu_available(docker=docker),
        "availability": availability,
    }


def admit(
    profile_name: str, *, requested_memory_bytes: int | None = None,
    requested_cpus: float | None = None, requested_storage_bytes: int | None = None,
    docker: str = "docker"
) -> dict[str, object]:
    requested = resource_profile(profile_name)
    memory_request = requested.memory_bytes if requested_memory_bytes is None else requested_memory_bytes
    if memory_request <= 0:
        raise ResourceError("sandbox admission memory request must be positive")
    status = sandbox_status(docker=docker)
    active = list(status["active"])
    reserved = int(status["reserved_memory_bytes"])
    budget = int(status["admission_memory_budget_bytes"])
    if reserved + memory_request > budget:
        available = max(0, budget - reserved)
        raise ResourceError(
            f"sandbox admission refused: {memory_request} bytes requested but only {available} "
            "bytes remain in the Docker host memory budget; choose a lighter profile or clean a sandbox"
        )
    reserved_cpus = float(status.get("reserved_cpus", 0.0))
    cpu_budget = float(status.get("admission_cpu_budget", float("inf")))
    cpu_request = requested.cpus if requested_cpus is None else requested_cpus
    if cpu_request <= 0:
        raise ResourceError("sandbox admission CPU request must be positive")
    if reserved_cpus + cpu_request > cpu_budget:
        raise ResourceError(
            f"sandbox admission refused: {cpu_request} CPUs requested but only "
            f"{max(0.0, cpu_budget - reserved_cpus):.2f} remain in the Docker host CPU budget"
        )
    reserved_storage = int(status.get("reserved_storage_bytes", 0))
    storage_budget = int(status.get("admission_storage_budget_bytes", 2**63 - 1))
    storage_request = requested.storage_bytes if requested_storage_bytes is None else requested_storage_bytes
    if storage_request <= 0:
        raise ResourceError("sandbox admission storage request must be positive")
    if reserved_storage + storage_request > storage_budget:
        raise ResourceError("sandbox admission refused: insufficient aggregate Docker storage budget")
    return status


def race_width(
    desired: int, *, profile_names: Sequence[str], docker: str = "docker",
) -> dict[str, object]:
    """Fit the highest-value prefix of a race to the live aggregate budget."""
    if desired < 0 or desired > len(profile_names):
        raise ResourceError("desired race width is outside the supplied profile list")
    status = sandbox_status(docker=docker)
    memory_left = int(status["admission_memory_budget_bytes"]) - int(status["reserved_memory_bytes"])
    cpu_left = float(status["admission_cpu_budget"]) - float(status["reserved_cpus"])
    storage_left = int(status.get("admission_storage_budget_bytes", 2**63 - 1)) - int(status.get("reserved_storage_bytes", 0))
    admitted: list[str] = []
    for name in profile_names[:desired]:
        profile = resource_profile(name)
        if profile.memory_bytes <= memory_left and profile.cpus <= cpu_left and profile.storage_bytes <= storage_left:
            admitted.append(name)
            memory_left -= profile.memory_bytes
            cpu_left -= profile.cpus
            storage_left -= profile.storage_bytes
    return {
        "desired_width": desired, "admitted_width": len(admitted),
        "profiles": admitted, "memory_remaining_bytes": memory_left,
        "cpus_remaining": round(cpu_left, 3),
        "storage_remaining_bytes": storage_left,
        "shrink_required": len(admitted) < desired,
    }


def sandbox_gc(*, docker: str = "docker") -> dict[str, object]:
    removed: list[str] = []
    failures: list[dict[str, str]] = []
    with admission_lock():
        stale = [item for item in _list_managed_sandboxes(docker=docker, include_stopped=True) if not item["running"]]
        for item in stale:
            identifier = str(item["id"])
            result = _run([docker, "rm", "--force", identifier], timeout=30)
            if result.returncode:
                failures.append({"container": str(item["name"]), "error": result.stderr.strip() or "docker rm failed"})
            else:
                removed.append(str(item["name"]))
    return {"removed": removed, "failures": failures, "remaining_stale": len(failures)}


@contextmanager
def admission_lock() -> Iterator[None]:
    runtime = Path(os.environ.get("XDG_RUNTIME_DIR", "/tmp"))
    if not runtime.is_dir() or runtime.is_symlink():
        raise ResourceError(f"unsafe or missing runtime directory for admission lock: {runtime}")
    lock_path = runtime / f"ctf-os-sandbox-admission-{os.getuid()}.lock"
    if lock_path.is_symlink():
        raise ResourceError("sandbox admission lock must not be a symlink")
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _list_managed_sandboxes(*, docker: str, include_stopped: bool) -> list[dict[str, object]]:
    argv = [docker, "ps"]
    if include_stopped:
        argv.append("--all")
    argv.extend(["--filter", "label=ctf-os=true", "--format", "{{.ID}}"])
    listed = _run(argv, timeout=20)
    if listed.returncode:
        raise ResourceError(
            f"cannot inspect active sandbox reservations: {listed.stderr.strip() or 'Docker daemon unavailable'}"
        )
    containers: list[dict[str, object]] = []
    for identifier in listed.stdout.splitlines():
        identifier = identifier.strip()
        if not identifier:
            continue
        inspected = _run([docker, "inspect", identifier], timeout=20)
        if inspected.returncode:
            if "no such object" in inspected.stderr.casefold():
                continue
            raise ResourceError(f"cannot inspect managed container {identifier}: {inspected.stderr.strip()}")
        try:
            raw = json.loads(inspected.stdout)[0]
            labels = raw.get("Config", {}).get("Labels", {}) or {}
            # The branch label includes pre-v2.1 sandboxes. Explicit service containers are excluded.
            if labels.get("ctf-os") != "true" or not (
                labels.get("ctf-os.kind") == "sandbox"
                or (labels.get("ctf-os.kind") is None and labels.get("ctf-os.branch"))
            ):
                continue
            state = raw.get("State", {}) or {}
            # Running resize changes HostConfig but Docker labels are immutable;
            # prefer the live limit and retain the label as a legacy fallback.
            memory = _positive_int(raw.get("HostConfig", {}).get("Memory"))
            if memory == 0:
                memory = _positive_int(labels.get("ctf-os.memory_bytes"))
            profile = labels.get("ctf-os.resource_profile")
            if profile not in RESOURCE_PROFILES:
                if memory <= RESOURCE_PROFILES["light"].memory_bytes:
                    profile = "light"
                elif memory <= RESOURCE_PROFILES["standard"].memory_bytes:
                    profile = "standard"
                else:
                    profile = "heavy"
            containers.append({
                "id": str(raw.get("Id", identifier)),
                "name": str(raw.get("Name", "")).removeprefix("/"),
                "status": str(state.get("Status", "unknown")),
                "running": bool(state.get("Running", False)),
                "resource_profile": str(profile),
                "memory_bytes": memory,
                "cpus": _container_cpus(raw),
                "storage_bytes": _positive_int(labels.get("ctf-os.storage_bytes")),
                "contest": str(labels.get("ctf-os.contest", "")),
                "challenge_id": str(labels.get("ctf-os.challenge_id", "")),
                "branch": str(labels.get("ctf-os.branch", "")),
                "session_id": str(labels.get("ctf-os.session_id", labels.get("ctf-os.branch", ""))),
                "workload_class": str(labels.get("ctf-os.workload_class", "")),
                "priority": str(labels.get("ctf-os.resource_priority", "")),
            })
        except (IndexError, TypeError, json.JSONDecodeError) as exc:
            raise ResourceError(f"Docker returned malformed inspect data for {identifier}") from exc
    return sorted(containers, key=lambda item: (str(item["contest"]), str(item["name"])))


def _docker_memory_total(docker: str) -> int:
    result = _run([docker, "info", "--format", "{{json .MemTotal}}"], timeout=20)
    if result.returncode:
        raise ResourceError(
            f"cannot determine Docker host memory for sandbox admission: {result.stderr.strip() or 'Docker daemon unavailable'}"
        )
    try:
        total = int(json.loads(result.stdout.strip()))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ResourceError("Docker returned an invalid host memory total") from exc
    if total <= 0:
        raise ResourceError("Docker reported no usable host memory")
    return total


def _memory_budget(total: int) -> int:
    # Leave 15% and at least 4 GiB to the host/daemon. This is reservation admission,
    # while Docker still enforces the per-container hard memory limit.
    return max(0, total - max(4 * GIB, int(total * .15)))


def _docker_cpu_total(docker: str) -> float:
    try:
        result = _run([docker, "info", "--format", "{{json .NCPU}}"], timeout=20)
    except ResourceError:
        return float(os.cpu_count() or 1)
    if result.returncode:
        return float(os.cpu_count() or 1)
    try:
        value = float(json.loads(result.stdout.strip()))
    except (TypeError, ValueError, json.JSONDecodeError):
        value = float(os.cpu_count() or 1)
    return max(1.0, value)


def _container_cpus(raw: dict[str, object]) -> float:
    host = raw.get("HostConfig", {})
    if not isinstance(host, dict):
        return 0.0
    nano = _positive_int(host.get("NanoCpus"))
    if nano:
        return nano / 1_000_000_000
    quota = _positive_int(host.get("CpuQuota"))
    period = _positive_int(host.get("CpuPeriod"))
    return quota / period if quota and period else 0.0


def gpu_available(*, docker: str = "docker") -> bool:
    # Import locally because the scheduler's capacity detector imports this
    # module for managed-container accounting.
    from ..resources.scheduler import detect_gpus

    return bool(detect_gpus(docker=docker).get("available"))


def _positive_int(value: object) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0
    return max(0, parsed)


def _run(argv: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return subprocess.CompletedProcess(list(argv), 124, stdout, stderr + "\ncommand timed out")
    except FileNotFoundError as exc:
        raise ResourceError(f"required executable not found: {argv[0]}") from exc
