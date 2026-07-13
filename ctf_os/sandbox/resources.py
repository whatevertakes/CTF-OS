from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import fcntl
import json
import os
from pathlib import Path
import re
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
    max_concurrent: int

    @property
    def memory_bytes(self) -> int:
        return parse_size_bytes(self.memory)

    @property
    def storage_bytes(self) -> int:
        return parse_size_bytes(self.storage)

    def to_dict(self) -> dict[str, object]:
        return {**asdict(self), "memory_bytes": self.memory_bytes, "storage_bytes": self.storage_bytes}


RESOURCE_PROFILES: dict[str, ResourceProfile] = {
    "light": ResourceProfile("light", "2g", 1.0, "1g", 128, 3),
    "standard": ResourceProfile("standard", "4g", 2.0, "2g", 256, 2),
    "heavy": ResourceProfile("heavy", "10g", 2.0, "8g", 512, 1),
    "large-forensic": ResourceProfile("large-forensic", "12g", 2.0, "12g", 512, 1),
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
    counts = {name: sum(item["resource_profile"] == name for item in active) for name in RESOURCE_PROFILES}
    intensive = counts["heavy"] + counts["large-forensic"]
    availability: dict[str, dict[str, object]] = {}
    for name, profile in RESOURCE_PROFILES.items():
        count_ok = counts[name] < profile.max_concurrent
        if name in {"heavy", "large-forensic"}:
            count_ok = count_ok and intensive < 1
        memory_ok = reserved + profile.memory_bytes <= budget
        availability[name] = {
            "can_admit": count_ok and memory_ok,
            "active": counts[name],
            "max_concurrent": profile.max_concurrent,
            "memory_available": memory_ok,
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
        "availability": availability,
    }


def admit(
    profile_name: str, *, requested_memory_bytes: int | None = None, docker: str = "docker"
) -> dict[str, object]:
    requested = resource_profile(profile_name)
    memory_request = requested.memory_bytes if requested_memory_bytes is None else requested_memory_bytes
    if memory_request <= 0:
        raise ResourceError("sandbox admission memory request must be positive")
    status = sandbox_status(docker=docker)
    active = list(status["active"])
    same_profile = sum(item["resource_profile"] == profile_name for item in active)
    if same_profile >= requested.max_concurrent:
        raise ResourceError(
            f"sandbox admission refused: {profile_name} already has {same_profile} active "
            f"container(s), limit {requested.max_concurrent}; inspect with sandbox-status or clean stale sandboxes"
        )
    if profile_name in {"heavy", "large-forensic"}:
        intensive = sum(item["resource_profile"] in {"heavy", "large-forensic"} for item in active)
        if intensive:
            raise ResourceError(
                "sandbox admission refused: a heavy/large-forensic sandbox is already active; "
                "finish or clean it before starting another intensive sandbox"
            )
    reserved = int(status["reserved_memory_bytes"])
    budget = int(status["admission_memory_budget_bytes"])
    if reserved + memory_request > budget:
        available = max(0, budget - reserved)
        raise ResourceError(
            f"sandbox admission refused: {memory_request} bytes requested but only {available} "
            "bytes remain in the Docker host memory budget; choose a lighter profile or clean a sandbox"
        )
    return status


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
            memory = _positive_int(labels.get("ctf-os.memory_bytes"))
            if memory == 0:
                memory = _positive_int(raw.get("HostConfig", {}).get("Memory"))
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
                "contest": str(labels.get("ctf-os.contest", "")),
                "challenge_id": str(labels.get("ctf-os.challenge_id", "")),
                "branch": str(labels.get("ctf-os.branch", "")),
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
    # Leave both 20% and at least 1 GiB to the host/daemon. This is reservation admission,
    # while Docker still enforces the per-container hard memory limit.
    return max(0, total - max(GIB, total // 5))


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
