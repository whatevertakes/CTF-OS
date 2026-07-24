"""Aggregate managed-container capacity admission for one race."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re
import subprocess
from typing import Any, Callable


GIB = 1024**3
MAX_RACE_CONCURRENCY = 4


class ResourceError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ResourceProfile:
    name: str
    memory: str
    cpus: float
    storage: str
    pids: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {
            "memory_bytes": parse_size_bytes(self.memory),
            "storage_bytes": parse_size_bytes(self.storage),
        }


RESOURCE_PROFILES = {
    "light": ResourceProfile("light", "2g", 1.0, "1g", 128),
    "standard": ResourceProfile("standard", "4g", 2.0, "2g", 256),
    "heavy": ResourceProfile("heavy", "8g", 4.0, "6g", 512),
    "large-forensic": ResourceProfile("large-forensic", "12g", 4.0, "12g", 768),
}


def resource_profile(name: str) -> ResourceProfile:
    try:
        return RESOURCE_PROFILES[name]
    except KeyError as exc:
        raise ResourceError(f"unknown resource profile: {name}") from exc


def parse_size_bytes(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)([kmgt]?)(?:i?b)?", value.strip().casefold())
    if not match:
        raise ResourceError(f"invalid positive resource size: {value!r}")
    return int(match.group(1)) * {"": 1, "k": 1024, "m": 1024**2, "g": GIB, "t": 1024**4}[match.group(2)]


def admission_status(
    *, docker: str = "docker", runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run
) -> dict[str, Any]:
    try:
        info = runner(
            [docker, "info", "--format", "{{json .}}"], capture_output=True, text=True,
            timeout=20, check=False,
        )
        listed = runner(
            [
                docker, "ps", "--filter", "label=org.ctf-os.managed=true",
                "--format", "{{.ID}}",
            ],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        raise ResourceError(f"Docker capacity inspection failed: {exc}") from exc
    if info.returncode or listed.returncode:
        raise ResourceError((info.stderr or listed.stderr).strip() or "Docker capacity inspection failed")
    try:
        host = json.loads(info.stdout)
    except json.JSONDecodeError as exc:
        raise ResourceError("Docker returned malformed capacity data") from exc
    if not isinstance(host, dict):
        raise ResourceError("Docker returned malformed capacity data")
    active = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
    usage = _managed_usage(active, docker=docker, runner=runner)
    return {
        "active_sandboxes": usage["active_sandboxes"],
        "active_services": usage["active_services"],
        "active_managed_containers": usage["active_managed_containers"],
        "reserved_memory_bytes": usage["memory_bytes"],
        "reserved_cpus": usage["cpus"],
        "host_memory_bytes": int(host.get("MemTotal") or 0),
        "host_cpus": float(host.get("NCPU") or 0),
        "profiles": {name: profile.to_dict() for name, profile in RESOURCE_PROFILES.items()},
    }


def admit(
    profile_name: str,
    *,
    race_lane_count: int,
    docker: str = "docker",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    if race_lane_count < 0 or race_lane_count >= MAX_RACE_CONCURRENCY:
        raise ResourceError("Root plus native children may not exceed concurrency four")
    profile = resource_profile(profile_name)
    status = admission_status(docker=docker, runner=runner)
    if int(status["active_sandboxes"]) >= MAX_RACE_CONCURRENCY:
        raise ResourceError(
            "managed sandbox concurrency is already at the hard limit of four"
        )
    request_memory = parse_size_bytes(profile.memory)
    projected_memory = int(status["reserved_memory_bytes"]) + request_memory
    projected_cpus = float(status["reserved_cpus"]) + profile.cpus
    memory_budget = max(0, int(status["host_memory_bytes"]) - 2 * GIB)
    cpu_budget = max(0.5, float(status["host_cpus"]) - 1.0)
    if status["host_memory_bytes"] and projected_memory > memory_budget:
        raise ResourceError(
            "aggregate managed-container memory request exceeds the reserved host budget "
            f"({projected_memory} > {memory_budget} bytes)"
        )
    if status["host_cpus"] and projected_cpus > cpu_budget:
        raise ResourceError(
            "aggregate managed-container CPU request exceeds the reserved host budget "
            f"({projected_cpus:g} > {cpu_budget:g} CPUs)"
        )
    return status | {
        "admitted_profile": profile.to_dict(),
        "projected_memory_bytes": projected_memory,
        "projected_cpus": projected_cpus,
        "memory_budget_bytes": memory_budget,
        "cpu_budget": cpu_budget,
    }


def admit_fixed(
    *,
    memory: str,
    cpus: float,
    purpose: str,
    docker: str = "docker",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Reserve capacity for a managed non-sandbox container such as a service."""

    if cpus <= 0:
        raise ResourceError("fixed CPU request must be positive")
    request_memory = parse_size_bytes(memory)
    status = admission_status(docker=docker, runner=runner)
    memory_budget = max(0, int(status["host_memory_bytes"]) - 2 * GIB)
    cpu_budget = max(0.5, float(status["host_cpus"]) - 1.0)
    projected_memory = int(status["reserved_memory_bytes"]) + request_memory
    projected_cpus = float(status["reserved_cpus"]) + cpus
    if status["host_memory_bytes"] and projected_memory > memory_budget:
        raise ResourceError(
            f"aggregate {purpose} memory request exceeds the reserved host budget "
            f"({projected_memory} > {memory_budget} bytes)"
        )
    if status["host_cpus"] and projected_cpus > cpu_budget:
        raise ResourceError(
            f"aggregate {purpose} CPU request exceeds the reserved host budget "
            f"({projected_cpus:g} > {cpu_budget:g} CPUs)"
        )
    return status | {
        "admitted_request": {
            "purpose": purpose,
            "memory": memory,
            "memory_bytes": request_memory,
            "cpus": cpus,
        },
        "projected_memory_bytes": projected_memory,
        "projected_cpus": projected_cpus,
        "memory_budget_bytes": memory_budget,
        "cpu_budget": cpu_budget,
    }


def _managed_usage(
    identifiers: list[str],
    *,
    docker: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> dict[str, Any]:
    if not identifiers:
        return {
            "active_sandboxes": 0,
            "active_services": 0,
            "active_managed_containers": 0,
            "memory_bytes": 0,
            "cpus": 0.0,
        }
    try:
        inspected = runner(
            [docker, "inspect", *identifiers],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        raise ResourceError(f"Docker managed-resource inspection failed: {exc}") from exc
    if inspected.returncode:
        raise ResourceError(
            inspected.stderr.strip() or "Docker managed-resource inspection failed"
        )
    try:
        rows = json.loads(inspected.stdout)
    except json.JSONDecodeError as exc:
        raise ResourceError("Docker returned malformed managed-resource data") from exc
    if not isinstance(rows, list):
        raise ResourceError("Docker returned malformed managed-resource data")
    sandboxes = 0
    services = 0
    memory = 0
    nano_cpus = 0
    counted = 0
    for row in rows:
        if not isinstance(row, dict):
            raise ResourceError("Docker returned malformed managed-container data")
        labels = row.get("Config", {}).get("Labels", {}) or {}
        state = row.get("State", {}) or {}
        if (
            labels.get("org.ctf-os.managed") != "true"
            or not bool(state.get("Running", True))
        ):
            continue
        kind = labels.get("org.ctf-os.kind")
        if kind not in {"sandbox", "service"}:
            continue
        host = row.get("HostConfig", {}) or {}
        try:
            memory += max(0, int(host.get("Memory") or 0))
            nano_cpus += max(0, int(host.get("NanoCpus") or 0))
        except (TypeError, ValueError) as exc:
            raise ResourceError("Docker returned invalid managed resource limits") from exc
        counted += 1
        sandboxes += kind == "sandbox"
        services += kind == "service"
    return {
        "active_sandboxes": sandboxes,
        "active_services": services,
        "active_managed_containers": counted,
        "memory_bytes": memory,
        "cpus": nano_cpus / 1_000_000_000,
    }


def sandbox_gc(
    *,
    docker: str = "docker",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Remove only stopped containers carrying a validated CTF-OS sandbox label set."""
    identifiers: set[str] = set()
    for label in ("org.ctf-os.managed=true", "ctf-os=true"):
        try:
            listed = runner(
                [
                    docker, "ps", "--all", "--filter", f"label={label}",
                    "--format", "{{.ID}}",
                ],
                capture_output=True, text=True, timeout=20, check=False,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
            raise ResourceError(f"cannot list managed sandboxes: {exc}") from exc
        if listed.returncode:
            raise ResourceError(listed.stderr.strip() or "cannot list managed sandboxes")
        identifiers.update(row.strip() for row in listed.stdout.splitlines() if row.strip())

    removed: list[str] = []
    skipped: list[dict[str, str]] = []
    failures: list[dict[str, str]] = []
    for identifier in sorted(identifiers):
        inspected = runner(
            [docker, "inspect", identifier],
            capture_output=True, text=True, timeout=20, check=False,
        )
        if inspected.returncode:
            skipped.append({"container": identifier, "reason": "inspect failed or container disappeared"})
            continue
        try:
            raw = json.loads(inspected.stdout)[0]
            labels = raw.get("Config", {}).get("Labels", {}) or {}
            state = raw.get("State", {}) or {}
            name = str(raw.get("Name", identifier)).removeprefix("/")
        except (IndexError, TypeError, json.JSONDecodeError) as exc:
            raise ResourceError(f"Docker returned malformed inspect data for {identifier}") from exc
        current = (
            labels.get("org.ctf-os.managed") == "true"
            and labels.get("org.ctf-os.kind") == "sandbox"
        )
        legacy = labels.get("ctf-os") == "true" and labels.get("ctf-os.kind") == "sandbox"
        if not (current or legacy):
            skipped.append({"container": name, "reason": "managed sandbox labels did not validate"})
            continue
        if bool(state.get("Running")) or str(state.get("Status", "")).casefold() == "running":
            skipped.append({"container": name, "reason": "sandbox is running"})
            continue
        removed_result = runner(
            [docker, "rm", identifier],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if removed_result.returncode:
            failures.append({
                "container": name,
                "error": removed_result.stderr.strip() or "docker rm failed",
            })
        else:
            removed.append(name)
    return {"removed": removed, "skipped": skipped, "failures": failures}
