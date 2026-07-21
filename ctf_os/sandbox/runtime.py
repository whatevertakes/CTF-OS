from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
from typing import Mapping, Sequence
from urllib.parse import urlparse

from ..evidence import append_evidence
from ..resources.scheduler import (
    ResourceLedger, ResourceRequest, allocation_environment, default_request, parse_bytes,
)
from .network import ResolvedTarget
from .resources import ResourceError, admit, admission_lock, parse_size_bytes, resource_profile


class SandboxError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SandboxSpec:
    contest_slug: str
    challenge_id: str
    branch: str
    source: Path
    branch_root: Path
    input_fingerprint: str = "unbound"
    target_revision: int = 1
    input_bytes: int = 0
    targets: tuple[ResolvedTarget, ...] = ()
    image: str = "ctf-os-sandbox:base"
    resource_profile: str = "standard"
    memory: str | None = None
    cpus: float | None = None
    pids: int | None = None
    storage: str | None = None
    service_network: str | None = None
    local_endpoints: tuple[str, ...] = ()
    session_id: str = "sol-main"
    parent_session_id: str = "sol-main"
    session_role: str = "sol"
    service_context: Mapping[str, object] | None = None
    category: str | None = None
    gpu_enabled: bool = False
    gpu_device: int | None = None
    workload_class: str | None = None
    resource_priority: str | None = None
    resource_request_override: Mapping[str, object] | None = None
    workspace_mode: str = "tmpfs"
    run_id: str | None = None
    rescue_attempt_id: str | None = None
    external_solver: bool = False
    solver_family: str | None = None
    session_kind: str = "native-worker"
    requested_lead_model: str | None = None

    def __post_init__(self) -> None:
        try:
            profile = resource_profile(self.resource_profile)
        except ResourceError as exc:
            raise SandboxError(str(exc)) from exc
        if self.memory is None:
            object.__setattr__(self, "memory", profile.memory)
        if self.cpus is None:
            object.__setattr__(self, "cpus", profile.cpus)
        if self.pids is None:
            object.__setattr__(self, "pids", profile.pids)
        if self.storage is None:
            object.__setattr__(self, "storage", profile.storage)
        if self.workload_class is None:
            object.__setattr__(self, "workload_class", {
                "light": "quick-recon", "standard": "independent-full-solve",
                "heavy": "custom-cpu-bound", "large-forensic": "forensic-extraction",
            }.get(self.resource_profile, "independent-full-solve"))
        if self.resource_priority is None:
            object.__setattr__(self, "resource_priority", "NORMAL")

    @property
    def name(self) -> str:
        raw = f"ctf-os-{self.contest_slug}-{self.challenge_id}-{self.branch}"
        safe = re.sub(r"[^a-zA-Z0-9_.-]+", "-", raw).strip("-.").lower()
        return safe[:100] + "-" + hashlib.sha256(raw.encode()).hexdigest()[:10]

    @property
    def labels(self) -> dict[str, str]:
        labels = {
            "ctf-os": "true", "ctf-os.contest": self.contest_slug,
            "ctf-os.challenge_id": self.challenge_id, "ctf-os.branch": self.branch,
        }
        if self.run_id:
            labels["ctf-os.run_id"] = self.run_id
        if self.rescue_attempt_id:
            labels["ctf-os.rescue_attempt_id"] = self.rescue_attempt_id
        return labels

    @property
    def runtime_labels(self) -> dict[str, str]:
        labels = {
            **self.labels,
            "ctf-os.kind": "sandbox",
            "ctf-os.resource_profile": self.resource_profile,
            "ctf-os.memory_bytes": str(parse_size_bytes(str(self.memory))),
            "ctf-os.storage_bytes": str(parse_size_bytes(str(self.storage))),
            "ctf-os.session_id": self.session_id,
            "ctf-os.parent_session_id": self.parent_session_id,
            "ctf-os.session_role": self.session_role,
            "ctf-os.workload_class": str(self.workload_class),
            "ctf-os.resource_priority": str(self.resource_priority),
        }
        if self.external_solver or self.workspace_mode != "tmpfs" or self.session_kind != "native-worker":
            labels["ctf-os.session_kind"] = self.session_kind
            labels["ctf-os.external_solver"] = str(self.external_solver).lower()
            labels["ctf-os.workspace_mode"] = self.workspace_mode
        if self.solver_family:
            labels["ctf-os.solver_family"] = str(self.solver_family)
        return labels

    @property
    def resource_request(self) -> ResourceRequest:
        if self.resource_request_override is not None:
            return ResourceRequest.from_mapping(self.resource_request_override)
        return default_request(
            contest=self.contest_slug, challenge_id=self.challenge_id,
            session_id=self.session_id, workload_class=str(self.workload_class),
            priority=str(self.resource_priority),
            input_bytes=self.input_bytes,
            overrides={
                "min_cpus": min(float(self.cpus), float(self.cpus)),
                "preferred_cpus": float(self.cpus), "max_cpus": max(float(self.cpus), float(self.cpus)),
                "min_memory_bytes": parse_size_bytes(str(self.memory)),
                "preferred_memory_bytes": parse_size_bytes(str(self.memory)),
                "max_memory_bytes": parse_size_bytes(str(self.memory)),
                "storage_bytes": parse_size_bytes(str(self.storage)),
                "gpu_preferred": self.gpu_enabled, "gpu_memory_bytes": 4 * 1024**3 if self.gpu_enabled else 0,
            },
        )


def build_run_argv(spec: SandboxSpec, docker: str = "docker") -> list[str]:
    _validate_spec(spec)
    context = (spec.branch_root / "context").resolve()
    policy = json.dumps([target.to_dict() for target in spec.targets], separators=(",", ":"))
    local_policy = json.dumps(list(spec.local_endpoints), separators=(",", ":"))
    allocation = {"cpus": spec.cpus, "memory_bytes": parse_size_bytes(str(spec.memory))}
    resource_env = allocation_environment(allocation, spec.resource_request)
    mutable_mounts = (
        [
            "--mount", f"type=bind,src={(spec.branch_root / 'work').resolve()},dst=/work",
            "--mount", f"type=bind,src={(spec.branch_root / 'evidence').resolve()},dst=/evidence",
            "--mount", f"type=bind,src={(spec.branch_root / 'artifacts').resolve()},dst=/artifacts",
        ]
        if spec.workspace_mode == "bind" else
        [
            "--tmpfs", f"/work:rw,exec,nosuid,nodev,size={spec.storage},mode=1777",
            "--tmpfs", f"/evidence:rw,exec,nosuid,nodev,size={spec.storage},mode=1777",
            "--tmpfs", f"/artifacts:rw,exec,nosuid,nodev,size={spec.storage},mode=1777",
        ]
    )
    argv = [
        docker, "run", "--detach", "--name", spec.name, "--read-only",
        "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
        "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "SETPCAP",
        "--memory", spec.memory, "--cpus", str(spec.cpus), "--pids-limit", str(spec.pids),
        "--ulimit", "nofile=1024:1024", "--ulimit", "nproc=256:256",
        "--mount", f"type=bind,src={spec.source},dst=/challenge,readonly",
        *mutable_mounts,
        "--mount", f"type=bind,src={context},dst=/context,readonly",
        "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=256m,mode=1777",
        "--env", f"CTF_OS_ALLOWED_ENDPOINTS_JSON={policy}",
        "--env", f"CTF_OS_LOCAL_ENDPOINTS_JSON={local_policy}",
        "--env", f"CTF_OS_SESSION_ID={spec.session_id}",
        "--env", f"CTF_OS_PARENT_SESSION_ID={spec.parent_session_id}",
        "--env", f"CTF_OS_SESSION_ROLE={spec.session_role}",
        "--env", f"CTF_OS_CONTEST_SLUG={spec.contest_slug}",
        "--env", f"CTF_OS_CHALLENGE_ID={spec.challenge_id}",
    ]
    for key, value in resource_env.items():
        argv.extend(["--env", f"{key}={value}"])
    category = (spec.category or spec.image.rsplit(":", 1)[-1]).casefold()
    if category in {"pwn", "rev", "misc"}:
        argv.extend([
            "--cap-add", "SYS_PTRACE", "--security-opt", "seccomp=unconfined",
            "--ulimit", "core=-1:-1",
        ])
    if category == "forensic":
        argv.extend(["--cap-add", "SYS_ADMIN", "--security-opt", "seccomp=unconfined"])
        for device in ("/dev/loop-control", "/dev/loop0", "/dev/loop1", "/dev/loop2", "/dev/loop3"):
            if Path(device).exists():
                argv.extend(["--device", f"{device}:{device}:rwm"])
    if category == "ai" and spec.gpu_enabled:
        selector = f"device={spec.gpu_device}" if spec.gpu_device is not None else "all"
        argv.extend(["--gpus", selector, "--env", "CTF_OS_GPU_ENABLED=1"])
    # Rootless Podman needs only namespace-management syscalls for local OCI
    # inspection. Keep Docker's default deny list otherwise; mount and other
    # CAP_SYS_ADMIN-gated syscalls remain blocked and every capability is still dropped.
    if spec.image == "ctf-os-sandbox:cloud":
        seccomp = Path(__file__).resolve().parents[2] / "sandbox" / "seccomp-rootless.json"
        if not seccomp.is_file() or seccomp.is_symlink():
            raise SandboxError("rootless Podman seccomp profile is missing or unsafe")
        argv.extend(["--security-opt", f"seccomp={seccomp}"])
    for key, value in spec.runtime_labels.items():
        argv.extend(["--label", f"{key}={value}"])
    if spec.service_network:
        # NET_ADMIN exists only while entrypoint installs the exact service-only
        # egress policy; setpriv drops it before any worker command executes.
        argv.extend(["--network", spec.service_network, "--cap-add", "NET_ADMIN"])
    elif spec.targets:
        argv.extend(["--network", "bridge", "--cap-add", "NET_ADMIN"])
        for target in spec.targets:
            argv.extend(["--add-host", f"{target.target.host}:{target.address}"])
    else:
        argv.extend(["--network", "none"])
    argv.extend([spec.image, "sleep", "infinity"])
    return argv


def create(spec: SandboxSpec, *, docker: str = "docker") -> dict[str, object]:
    _prepare_branch_root(spec)
    metadata: dict[str, object] = {
        "schema_version": 2, "name": spec.name, "contest_slug": spec.contest_slug,
        "challenge_id": spec.challenge_id, "branch": spec.branch,
        "source": str(spec.source), "branch_root": str(spec.branch_root),
        "labels": spec.labels, "image": spec.image,
        "runtime_labels": spec.runtime_labels,
        "resource_profile": spec.resource_profile,
        "resources": {"memory": spec.memory, "cpus": spec.cpus, "pids": spec.pids, "storage": spec.storage},
        "service_network": spec.service_network,
        "local_endpoints": list(spec.local_endpoints),
        "session_id": spec.session_id,
        "parent_session_id": spec.parent_session_id,
        "session_role": spec.session_role,
        "service_context": dict(spec.service_context or {}),
        "category": spec.category,
        "gpu_enabled": spec.gpu_enabled,
        "gpu_device": spec.gpu_device,
        "resource_request": spec.resource_request.to_dict(),
        "allocation_env": allocation_environment(
            {"cpus": spec.cpus, "memory_bytes": parse_size_bytes(str(spec.memory))}, spec.resource_request,
        ),
        "work_path": str((spec.branch_root / "work").resolve()),
        "evidence_path": str((spec.branch_root / "evidence").resolve()),
        "logs_path": str((spec.branch_root / "logs").resolve()),
        "context_path": str((spec.branch_root / "context").resolve()),
        "metadata_path": str(spec.branch_root / "sandbox.json"),
        "input_fingerprint": spec.input_fingerprint,
        "target_revision": spec.target_revision,
        "authorized_targets": [target.to_dict() for target in spec.targets],
    }
    if spec.external_solver or spec.workspace_mode != "tmpfs" or spec.session_kind != "native-worker":
        metadata.update({
            "session_kind": spec.session_kind,
            "run_id": spec.run_id,
            "rescue_attempt_id": spec.rescue_attempt_id,
            "external_solver": spec.external_solver,
            "solver_family": spec.solver_family,
            "requested_lead_model": spec.requested_lead_model,
            "workspace_mode": spec.workspace_mode,
        })
    try:
        with admission_lock():
            admit(
                spec.resource_profile, requested_memory_bytes=parse_size_bytes(str(spec.memory)),
                requested_cpus=float(spec.cpus), requested_storage_bytes=parse_size_bytes(str(spec.storage)),
                docker=docker,
            )
            result = _run(build_run_argv(spec, docker), timeout=120)
    except ResourceError as exc:
        raise SandboxError(str(exc)) from exc
    if result.returncode:
        if "already in use" not in result.stderr.casefold() and "conflict" not in result.stderr.casefold():
            _rollback_failed_create(spec, docker=docker)
        raise SandboxError(f"sandbox create failed: {result.stderr.strip()}")
    try:
        _write_json(spec.branch_root / "sandbox.json", metadata)
        append_evidence(spec.branch_root.parents[1] / "evidence.log", "sandbox_create", {"branch": spec.branch, "container": spec.name})
    except Exception:
        removed = _run([docker, "rm", "--force", spec.name], timeout=30)
        if removed.returncode:
            raise SandboxError(f"sandbox started but rollback cleanup failed: {removed.stderr.strip()}")
        raise
    return metadata


def execute(
    metadata: dict[str, object], command: Sequence[str], timeout: int, *, docker: str = "docker",
    session_id: str | None = None, session_role: str | None = None,
    timeout_profile: str | None = None, retain_on_timeout: bool | None = None,
) -> dict[str, object]:
    _authorize_sandbox(metadata, session_id, session_role, "execute")
    branch_root = Path(str(metadata["branch_root"])).resolve()
    with _sandbox_lock(branch_root):
        return _execute_locked(
            metadata, command, timeout, docker=docker,
            timeout_profile=timeout_profile, retain_on_timeout=retain_on_timeout,
        )


def probe_service_connectivity(metadata: dict[str, object], *, docker: str = "docker") -> dict[str, object]:
    """Prove that an attached worker can resolve and reach its managed service."""
    endpoints = metadata.get("local_endpoints")
    if not isinstance(endpoints, list) or not endpoints:
        raise SandboxError("managed service attachment has no declared endpoint")
    endpoint = str(endpoints[0])
    host, port = _endpoint_host_port(endpoint)
    code = (
        "import socket,sys; "
        "s=socket.create_connection((sys.argv[1],int(sys.argv[2])),5); "
        "print('CTF_OS_SERVICE_CONNECTED',sys.argv[1],sys.argv[2]); s.close()"
    )
    result = execute(metadata, ["python3", "-c", code, host, str(port)], 10, docker=docker)
    if result.get("exit_code") != 0 or "CTF_OS_SERVICE_CONNECTED" not in str(result.get("stdout", "")):
        raise SandboxError(
            f"managed service connectivity probe failed for {endpoint}: "
            f"{str(result.get('stderr', '')).strip() or 'connection was not established'}"
        )
    return {"endpoint": endpoint, "host": host, "port": port, "connected": True}


def _endpoint_host_port(endpoint: str) -> tuple[str, int]:
    text = endpoint.strip()
    if text.casefold().startswith("nc "):
        parts = text.split()
        if len(parts) == 3 and parts[2].isdigit():
            return parts[1], int(parts[2])
    parsed = urlparse(text if "://" in text else f"tcp://{text}")
    if parsed.hostname and parsed.port:
        return parsed.hostname, parsed.port
    raise SandboxError(f"managed service endpoint has no host and port: {endpoint}")


def _execute_locked(
    metadata: dict[str, object], command: Sequence[str], timeout: int, *, docker: str,
    timeout_profile: str | None = None, retain_on_timeout: bool | None = None,
) -> dict[str, object]:
    if not command or timeout < 1 or timeout > 1800:
        raise SandboxError("command is required and timeout must be between 1 and 1800 seconds")
    name = _metadata_name(metadata)
    branch_root = Path(str(metadata["branch_root"])).resolve()
    prior_timeout = branch_root / "timeout-receipt.json"
    if prior_timeout.is_file() and not prior_timeout.is_symlink():
        try:
            prior = json.loads(prior_timeout.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SandboxError("retained timeout receipt is malformed") from exc
        if prior.get("status") == "TIMED_OUT_RETAINED":
            prior_pgid = str(prior.get("exec_process_group_id") or "")
            if prior_pgid.isdigit():
                remaining = _run([docker, "exec", "--user", "1001:1001", name, "sh", "-c", "ps -o pid=,stat= --sid \"$1\" 2>/dev/null | awk '$2 !~ /^Z/'", "sh", prior_pgid], timeout=15)
            else:
                raise SandboxError("retained timeout lacks a process-group receipt; Sol cleanup is required")
            if remaining.stdout.split():
                _run([docker, "exec", "--user", "1001:1001", name, "sh", "-c", "kill -KILL -\"$1\" 2>/dev/null || true", "sh", prior_pgid], timeout=15)
                checked = _run([docker, "exec", "--user", "1001:1001", name, "sh", "-c", "ps -o pid=,stat= --sid \"$1\" 2>/dev/null | awk '$2 !~ /^Z/'", "sh", prior_pgid], timeout=15)
                if checked.stdout.split():
                    raise SandboxError("retained sandbox still has orphan worker processes; Sol cleanup is required")
    execution_id = hashlib.sha256(f"{_utc_now()}:{os.getpid()}:{list(command)}".encode()).hexdigest()[:16]
    pid_file = f"/tmp/ctf-os-exec-{execution_id}.pid"
    argv = [docker, "exec", "--user", "1001:1001", "--workdir", "/work"]
    for key, value in _metadata_allocation_env(metadata).items():
        argv.extend(["--env", f"{key}={value}"])
    # Docker exec commonly starts its process as a process-group leader.  A bare
    # `setsid` then forks and lets that parent exit successfully, which loses the
    # real command's exit status.  Force the fork, wait for the session child,
    # and have that child record its own PID (also its PGID) before exec.
    argv.extend([
        name, "setsid", "--fork", "--wait", "sh", "-c",
        "umask 077; echo $$ >\"$1\"; shift; exec \"$@\"",
        "ctf-os-exec", pid_file, *command,
    ])
    before = _firewall_counters(name, docker, list(metadata.get("authorized_targets", []))) if metadata.get("authorized_targets") else None
    result = _run(argv, timeout=timeout)
    after = _firewall_counters(name, docker, list(metadata.get("authorized_targets", []))) if metadata.get("authorized_targets") and result.returncode != 124 else None
    from ..timeouts import retain_sandbox_on_timeout
    retained = result.returncode == 124 and retain_sandbox_on_timeout(timeout_profile, retain_on_timeout)
    orphan_check = None
    process_group_id = None
    if retained:
        pid_result = _run([docker, "exec", "--user", "1001:1001", name, "cat", pid_file], timeout=15)
        process_group_id = pid_result.stdout.strip() if pid_result.returncode == 0 and pid_result.stdout.strip().isdigit() else None
        if process_group_id:
            terminated = _run([docker, "exec", "--user", "1001:1001", name, "sh", "-c", "kill -TERM -\"$1\" 2>/dev/null || true; sleep 1; kill -KILL -\"$1\" 2>/dev/null || true", "sh", process_group_id], timeout=15)
            orphan_check = _run([docker, "exec", "--user", "1001:1001", name, "sh", "-c", "ps -o pid=,stat= --sid \"$1\" 2>/dev/null | awk '$2 !~ /^Z/'", "sh", process_group_id], timeout=15)
        else:
            terminated = subprocess.CompletedProcess([], 1, "", "missing process group receipt")
            orphan_check = subprocess.CompletedProcess([], 1, "", "missing process group receipt")
        orphan_check = {"termination_exit_code": terminated.returncode, "remaining_pids": orphan_check.stdout.split()}
    cleanup_record = _cleanup_locked(metadata, docker=docker) if result.returncode == 124 and not retained else None
    timeout_status = "TIMED_OUT_RETAINED" if retained else "TIMED_OUT_CLEANED" if result.returncode == 124 else None
    record = {
        "command": list(command), "exit_code": result.returncode,
        "timed_out": result.returncode == 124, "stdout": result.stdout[-64_000:],
        "stderr": result.stderr[-64_000:],
        "input_fingerprint": metadata.get("input_fingerprint"),
        "authorized_targets": metadata.get("authorized_targets", []),
        "authorized_network_observed": (
            before is not None and after is not None
            and after["target_packets"] > before["target_packets"]
            and after["established_packets"] > before["established_packets"]
        ),
        "artifacts_exported": bool(cleanup_record and cleanup_record.get("artifact_export")),
        "timeout_profile": timeout_profile, "timeout_status": timeout_status,
        "container_retained": retained,
        "exec_process_group_id": process_group_id,
    }
    if orphan_check is not None:
        record["orphan_process_check"] = orphan_check
    if cleanup_record is not None:
        record["cleanup"] = cleanup_record
    challenge_root = branch_root.parents[1]
    append_evidence(branch_root / "logs" / "commands.jsonl", "sandbox_exec", record)
    append_evidence(challenge_root / "evidence.log", "sandbox_exec", {"branch": metadata["branch"], **record})
    if timeout_status:
        receipt = branch_root / "timeout-receipt.json"
        _write_json(receipt, {
            "schema_version": 1, "status": timeout_status, "profile": timeout_profile,
            "command": list(command), "container": name, "recorded_at": _utc_now(),
            "retention_ttl_seconds": int(metadata.get("timeout_retention_ttl_seconds", 21600)),
            "orphan_process_check": orphan_check,
            "exec_process_group_id": process_group_id,
        })
        progress_dir = branch_root / "progress"
        progress_dir.mkdir(parents=True, exist_ok=True)
        _write_json(progress_dir / "timeout-checkpoint.json", {
            "schema_version": 1, "type": "TIMEOUT_CHECKPOINT", "status": timeout_status,
            "profile": timeout_profile, "command": list(command), "recorded_at": _utc_now(),
            "next_action": "continue a bounded slice in this sandbox" if retained else "recreate the sandbox before retry",
        })
    return record


def resize(
    metadata: dict[str, object], *, cpus: float | None = None, memory: str | int | None = None,
    docker: str = "docker", session_id: str | None = None, session_role: str | None = None,
) -> dict[str, object]:
    """Safely update a running sandbox and preserve the prior allocation on failure."""
    _authorize_sandbox(metadata, session_id, session_role, "resize")
    if cpus is None and memory is None:
        raise SandboxError("sandbox resize requires --cpus and/or --memory")
    if cpus is not None and cpus <= 0:
        raise SandboxError("sandbox CPU allocation must be positive")
    requested_memory = parse_bytes(memory) if memory is not None else None
    if requested_memory is not None and requested_memory <= 0:
        raise SandboxError("sandbox memory allocation must be positive")
    branch_root = Path(str(metadata["branch_root"])).resolve()
    with _sandbox_lock(branch_root):
        name = _metadata_name(metadata)
        before = _inspect_runtime(name, docker=docker)
        labels = before.get("Config", {}).get("Labels", {}) or {}
        if any(labels.get(key) != value for key, value in dict(metadata["labels"]).items()):
            raise SandboxError("refusing resize: container labels do not match sandbox metadata")
        host = before.get("HostConfig", {}) or {}
        old_cpus = _host_cpus(host)
        old_memory = int(host.get("Memory") or parse_size_bytes(str(metadata.get("resources", {}).get("memory", "1g"))))
        usage = _container_memory_usage(name, docker=docker)
        if requested_memory is not None and requested_memory < usage:
            raise SandboxError(
                f"refusing memory shrink below current usage: requested {requested_memory}, usage {usage}"
            )
        argv = [docker, "update"]
        if cpus is not None:
            argv.extend(["--cpus", str(cpus)])
        if requested_memory is not None:
            argv.extend(["--memory", str(requested_memory)])
        argv.append(name)
        result = _run(argv, timeout=60)
        if result.returncode:
            raise SandboxError(f"sandbox resize failed; previous allocation retained: {result.stderr.strip()}")
        after = _inspect_runtime(name, docker=docker)
        updated_host = after.get("HostConfig", {}) or {}
        actual_cpus = _host_cpus(updated_host)
        actual_memory = int(updated_host.get("Memory") or old_memory)
        expected_cpus = cpus if cpus is not None else old_cpus
        expected_memory = requested_memory if requested_memory is not None else old_memory
        if abs(actual_cpus - expected_cpus) > .01 or actual_memory != expected_memory:
            # Best-effort rollback to keep metadata and live state coherent.
            _run([docker, "update", "--cpus", str(old_cpus), "--memory", str(old_memory), name], timeout=60)
            raise SandboxError("sandbox resize verification failed; rolled back to previous allocation")
        resources = dict(metadata.get("resources") or {})
        resources["cpus"] = actual_cpus
        resources["memory"] = str(actual_memory)
        metadata["resources"] = resources
        request_raw = metadata.get("resource_request")
        request = ResourceRequest.from_mapping(request_raw if isinstance(request_raw, Mapping) else metadata)
        allocation = {"cpus": actual_cpus, "memory_bytes": actual_memory}
        metadata["allocation_env"] = allocation_environment(allocation, request)
        metadata["schema_version"] = max(2, int(metadata.get("schema_version", 1)))
        metadata_path = Path(str(metadata.get("metadata_path") or branch_root / "sandbox.json"))
        if metadata_path.parent == branch_root:
            _write_json(metadata_path, metadata)
        context = branch_root / "context" / "allocation.json"
        _write_json(context, {"schema_version": 1, "allocation": allocation, "environment": metadata["allocation_env"], "updated_at": _utc_now()})
        context.chmod(0o444)
        record = {
            "container": name, "session_id": metadata.get("session_id"),
            "before": {"cpus": old_cpus, "memory_bytes": old_memory},
            "after": {"cpus": actual_cpus, "memory_bytes": actual_memory},
            "memory_usage_bytes": usage, "verified": True, "at": _utc_now(),
        }
        append_evidence(branch_root.parents[1] / "evidence.log", "sandbox_resize", record)
        ledger = ResourceLedger(branch_root.parents[1])
        if ledger.state_path.exists():
            ledger.record_resize(str(metadata.get("session_id") or metadata.get("branch")), record)
        return record


def cleanup(
    metadata: dict[str, object], *, docker: str = "docker",
    session_id: str | None = None, session_role: str | None = None,
) -> dict[str, object]:
    _authorize_sandbox(metadata, session_id, session_role, "cleanup")
    branch_root = Path(str(metadata["branch_root"])).resolve()
    with _sandbox_lock(branch_root):
        return _cleanup_locked(metadata, docker=docker)


def _cleanup_locked(metadata: dict[str, object], *, docker: str) -> dict[str, object]:
    name = _metadata_name(metadata)
    inspect = _run([docker, "inspect", name, "--format", "{{json .Config.Labels}}"], timeout=20)
    export_record: dict[str, object] | None = None
    retained_exports: dict[str, object] = {}
    export_errors: dict[str, str] = {}
    if inspect.returncode == 0:
        try:
            labels = json.loads(inspect.stdout)
        except json.JSONDecodeError as exc:
            raise SandboxError("cannot verify sandbox labels before cleanup") from exc
        if any(labels.get(key) != value for key, value in dict(metadata["labels"]).items()):
            raise SandboxError("refusing cleanup: container labels do not match sandbox metadata")
        branch_root = Path(str(metadata["branch_root"])).resolve()
        exports = () if metadata.get("workspace_mode", "tmpfs") == "bind" else (
            ("artifacts", branch_root / "artifacts", "/artifacts", "artifact"),
            ("work", branch_root / "work", "/work", "work"),
            ("evidence", branch_root / "evidence", "/evidence", "evidence"),
        )
        for key, destination, container_root, label in exports:
            try:
                exported = _export_artifacts(
                    name, destination, docker=docker,
                    container_root=container_root, label=label,
                )
                if key == "artifacts":
                    export_record = exported
                else:
                    retained_exports[key] = exported
            except Exception as exc:
                # Try every independent tree before removing the expensive
                # container; one malformed tree must not discard the others.
                export_errors[key] = str(exc)
        removed = _run([docker, "rm", "--force", name], timeout=30)
        if removed.returncode:
            raise SandboxError(f"sandbox cleanup failed: {removed.stderr.strip()}")
    elif "no such object" not in inspect.stderr.casefold():
        raise SandboxError(f"cannot inspect sandbox before cleanup: {inspect.stderr.strip() or 'unknown Docker error'}")
    branch_root = Path(str(metadata["branch_root"])).resolve()
    record: dict[str, object] = {
        "removed": inspect.returncode == 0, "container": name,
        "artifact_export": export_record, "retained_exports": retained_exports,
    }
    if "artifacts" in export_errors:
        record["artifact_export_error"] = export_errors["artifacts"]
    if export_errors:
        record["export_errors"] = export_errors
    append_evidence(branch_root.parents[1] / "evidence.log", "sandbox_cleanup", {"branch": metadata["branch"], **record})
    ledger = ResourceLedger(branch_root.parents[1])
    if ledger.state_path.exists():
        session_id = str(metadata.get("session_id") or metadata.get("branch"))
        resource_state = ledger.load()
        observation = resource_state.get("observations", {}).get(session_id, {})
        if (
            session_id in resource_state.get("requests", {})
            and (
                not isinstance(observation, Mapping)
                or observation.get("state") != "RELEASED"
            )
        ):
            ledger.release(session_id, "sandbox cleanup")
    return record


def export_artifacts(
    metadata: dict[str, object], *, docker: str = "docker",
    session_id: str | None = None, session_role: str | None = None,
) -> dict[str, object]:
    _authorize_sandbox(metadata, session_id, session_role, "export")
    branch_root = Path(str(metadata["branch_root"])).resolve()
    with _sandbox_lock(branch_root):
        name = _metadata_name(metadata)
        record = _export_artifacts(name, branch_root / "artifacts", docker=docker)
        record["retained_exports"] = {
            "work": _export_artifacts(
                name, branch_root / "work", docker=docker, container_root="/work", label="work",
            ),
            "evidence": _export_artifacts(
                name, branch_root / "evidence", docker=docker, container_root="/evidence", label="evidence",
            ),
        }
        append_evidence(
            branch_root.parents[1] / "evidence.log",
            "sandbox_export",
            {"branch": metadata["branch"], "container": name, **record},
        )
        return record


def stage_artifacts(
    metadata: dict[str, object], source: Path, destination: str = "", *, docker: str = "docker"
) -> dict[str, object]:
    branch_root = Path(str(metadata["branch_root"])).resolve()
    with _sandbox_lock(branch_root):
        if source.is_symlink():
            raise SandboxError("artifact staging source must not be a symlink")
        source = source.resolve()
        solve_root = branch_root.parents[1]
        try:
            source.relative_to(solve_root)
        except ValueError as exc:
            raise SandboxError("artifact staging source must stay inside the selected challenge workspace") from exc
        files, total = _validate_staging_source(source)
        relative = Path(destination)
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            if destination:
                raise SandboxError("artifact staging destination must be a safe relative path")
        target = "/artifacts" + (f"/{relative.as_posix()}" if destination else "")
        name = _metadata_name(metadata)
        created = _run([docker, "exec", "--user", "1001:1001", name, "mkdir", "-p", "--", target], timeout=30)
        if created.returncode:
            raise SandboxError(f"artifact staging cannot create destination: {created.stderr.strip()}")
        _stream_tree_to_container(source, name, target, docker=docker)
        record = {"source": str(source), "destination": target, "files": files, "bytes": total}
        append_evidence(
            branch_root.parents[1] / "evidence.log", "sandbox_stage_artifacts",
            {"branch": metadata["branch"], "container": name, **record},
        )
        return record


def _sandbox_lock(branch_root: Path):
    lock_path = branch_root / ".sandbox.lock"
    if lock_path.is_symlink():
        raise SandboxError("sandbox lock must not be a symlink")
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    lock = os.fdopen(descriptor, "a+")
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX)

    class _LockContext:
        def __enter__(self):
            return lock

        def __exit__(self, exc_type, exc, traceback):
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()

    return _LockContext()


def _rollback_failed_create(spec: SandboxSpec, *, docker: str) -> None:
    inspected = _run([docker, "inspect", spec.name, "--format", "{{json .Config.Labels}}"], timeout=20)
    if inspected.returncode:
        return
    try:
        labels = json.loads(inspected.stdout)
    except json.JSONDecodeError:
        return
    if any(labels.get(key) != value for key, value in spec.runtime_labels.items()):
        return
    _run([docker, "rm", "--force", spec.name], timeout=30)


def _validate_spec(spec: SandboxSpec) -> None:
    if not spec.source.is_dir() or spec.source.is_symlink():
        raise SandboxError(f"prepared challenge input is missing or unsafe: {spec.source}")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", spec.branch):
        raise SandboxError("branch id must contain only letters, numbers, dot, underscore or dash")
    for label, value in (("session id", spec.session_id), ("parent session id", spec.parent_session_id)):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
            raise SandboxError(f"{label} is invalid")
    if spec.session_role not in {"sol", "child", "external"}:
        raise SandboxError("session role must be sol, child, or external")
    if spec.session_role == "child" and spec.session_id == spec.parent_session_id:
        raise SandboxError("child session id must differ from its parent session id")
    if spec.session_role == "external" and not (
        spec.external_solver and spec.session_kind == "external-rescue"
        and spec.rescue_attempt_id == spec.session_id
    ):
        raise SandboxError("external sandbox role requires an exact external-rescue identity")
    if spec.workspace_mode not in {"tmpfs", "bind"}:
        raise SandboxError("workspace mode must be tmpfs or bind")
    if spec.workspace_mode == "bind" and not spec.external_solver:
        raise SandboxError("bind workspace mode is reserved for an external solver")
    if spec.cpus is None or spec.pids is None or spec.cpus <= 0 or spec.pids < 1:
        raise SandboxError("sandbox CPU and PID limits must be positive")
    try:
        parse_size_bytes(str(spec.memory))
        parse_size_bytes(str(spec.storage))
    except ResourceError as exc:
        raise SandboxError(str(exc)) from exc
    if spec.targets and (spec.service_network or spec.local_endpoints):
        raise SandboxError("organizer remote targets and local challenge service endpoints must use separate sandboxes")
    if spec.service_network:
        if not re.fullmatch(r"ctf-os-net-[a-z0-9][a-z0-9_.-]{0,100}", spec.service_network):
            raise SandboxError("local challenge network must use a ctf-os-net-* scoped name")
        if not spec.local_endpoints:
            raise SandboxError("local challenge network requires at least one declared local endpoint")
    elif spec.local_endpoints:
        raise SandboxError("local challenge endpoints require a scoped service network")
    for endpoint in spec.local_endpoints:
        if not endpoint or len(endpoint) > 512 or any(character in endpoint for character in "\r\n\0"):
            raise SandboxError("local challenge endpoint is invalid")


def _prepare_branch_root(spec: SandboxSpec) -> None:
    """Create durable, worker-private host directories before Docker mounts them."""
    if spec.branch_root.is_symlink():
        raise SandboxError("worker root must not be a symlink")
    spec.branch_root.mkdir(parents=True, exist_ok=True)
    context_payload = {
        "schema_version": 1,
        "session_id": spec.session_id,
        "parent_session_id": spec.parent_session_id,
        "challenge_id": spec.challenge_id,
        "role": spec.session_role,
        "input": {"path": "/challenge", "read_only": True, "fingerprint": spec.input_fingerprint},
        "work": {"path": "/work", "private": True},
        "evidence": {"path": "/evidence", "private": True},
        "managed_service": dict(spec.service_context or {}),
    }
    for name in ("work", "evidence", "artifacts", "logs", "context"):
        path = spec.branch_root / name
        if path.is_symlink():
            raise SandboxError(f"worker {name} path must not be a symlink")
        path.mkdir(exist_ok=True)
        # These paths are mounted only into this worker container. World write is
        # needed because the unprivileged container uid need not match the host uid.
        path.chmod(0o777 if name in {"work", "evidence", "artifacts"} else (0o755 if name == "context" else 0o700))
    context_file = spec.branch_root / "context" / "session.json"
    _write_json(context_file, context_payload)
    context_file.chmod(0o444)


def _metadata_name(metadata: dict[str, object]) -> str:
    name = str(metadata.get("name", ""))
    if not re.fullmatch(r"ctf-os-[a-zA-Z0-9_.-]+", name):
        raise SandboxError("invalid sandbox metadata/container name")
    return name


def _authorize_sandbox(
    metadata: Mapping[str, object], session_id: str | None, session_role: str | None, action: str,
) -> None:
    """Enforce worker ownership when a model-facing caller identity is supplied."""
    if session_id is None and session_role is None:
        return  # Backwards-compatible trusted in-process controller path.
    if session_role not in {"sol", "child", "external"} or not session_id:
        raise SandboxError("sandbox caller must provide a valid session id and role")
    owner = str(metadata.get("session_id", ""))
    parent = str(metadata.get("parent_session_id", ""))
    if session_role == "sol":
        if session_id != parent:
            raise SandboxError(
                f"DENIED_SANDBOX_ACCESS: Sol session {session_id} does not own worker parent scope {parent}"
            )
        return
    if session_role == "external":
        if (
            metadata.get("external_solver") is not True
            or metadata.get("session_kind") != "external-rescue"
            or session_id != owner
        ):
            raise SandboxError(
                f"DENIED_SANDBOX_ACCESS: external session {session_id} does not own this rescue sandbox"
            )
        return
    if session_id != owner:
        raise SandboxError(
            f"DENIED_SANDBOX_ACCESS: child session {session_id} may not {action} worker sandbox owned by {owner}"
        )


def _run(argv: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return subprocess.CompletedProcess(list(argv), 124, stdout, stderr + "\ncommand timed out")
    except FileNotFoundError as exc:
        raise SandboxError(f"required executable not found: {argv[0]}") from exc


def _inspect_runtime(name: str, *, docker: str) -> dict[str, object]:
    result = _run([docker, "inspect", name], timeout=30)
    if result.returncode:
        raise SandboxError(f"cannot inspect sandbox runtime: {result.stderr.strip()}")
    try:
        payload = json.loads(result.stdout)
        raw = payload[0]
    except (json.JSONDecodeError, IndexError, TypeError) as exc:
        raise SandboxError("Docker returned malformed sandbox inspect data") from exc
    if not isinstance(raw, dict):
        raise SandboxError("Docker returned malformed sandbox inspect data")
    return raw


def _host_cpus(host: Mapping[str, object]) -> float:
    nano = int(host.get("NanoCpus") or 0)
    if nano:
        return nano / 1_000_000_000
    quota = int(host.get("CpuQuota") or 0)
    period = int(host.get("CpuPeriod") or 0)
    return quota / period if quota and period else 0.0


def _container_memory_usage(name: str, *, docker: str) -> int:
    result = _run([docker, "stats", "--no-stream", "--format", "{{json .}}", name], timeout=30)
    if result.returncode or not result.stdout.strip():
        raise SandboxError("cannot measure current memory usage before resize")
    try:
        raw = json.loads(result.stdout.splitlines()[0])
    except json.JSONDecodeError as exc:
        raise SandboxError("Docker returned malformed memory usage before resize") from exc
    text = str(raw.get("MemUsage") or raw.get("Mem Usage") or "")
    usage = text.split("/", 1)[0].strip()
    match = re.fullmatch(r"([0-9.]+)\s*([kmgt]?i?b|b)", usage, re.I)
    if not match:
        raise SandboxError("Docker did not report current memory usage before resize")
    unit = match.group(2).casefold().replace("ib", "").replace("b", "")
    return int(float(match.group(1)) * {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}[unit])


def _metadata_allocation_env(metadata: Mapping[str, object]) -> dict[str, str]:
    stored = metadata.get("allocation_env")
    if isinstance(stored, Mapping) and stored:
        return {str(key): str(value) for key, value in stored.items()}
    resources = metadata.get("resources") if isinstance(metadata.get("resources"), Mapping) else {}
    request_raw = metadata.get("resource_request")
    request = ResourceRequest.from_mapping(request_raw if isinstance(request_raw, Mapping) else metadata)
    return allocation_environment({
        "cpus": float(resources.get("cpus") or request.preferred_cpus),
        "memory_bytes": parse_bytes(resources.get("memory") or request.preferred_memory_bytes),
    }, request)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _firewall_counters(container: str, docker: str, targets: list[object]) -> dict[str, int]:
    ipv4 = _run([docker, "exec", "--user", "0:0", container, "iptables-save", "-c"], timeout=10)
    ipv6 = _run([docker, "exec", "--user", "0:0", container, "ip6tables-save", "-c"], timeout=10)
    if ipv4.returncode or ipv6.returncode:
        raise SandboxError("cannot read authorized firewall counters for remote verification")
    target_packets = 0
    established_packets = 0
    rules = ipv4.stdout.splitlines() + ipv6.stdout.splitlines()
    for line in rules:
        counter = re.match(r"^\[([0-9]+):[0-9]+\]\s+", line)
        if not counter:
            continue
        packets = int(counter.group(1))
        if "--ctstate RELATED,ESTABLISHED" in line or "--ctstate ESTABLISHED,RELATED" in line:
            established_packets += packets
        for target in targets:
            if not isinstance(target, dict):
                continue
            address = str(target.get("ip", ""))
            port = str(target.get("port", ""))
            if address and f"--dport {port}" in line and (f"-d {address}/32" in line or f"-d {address}/128" in line):
                target_packets += packets
                break
    return {"target_packets": target_packets, "established_packets": established_packets}


def _export_artifacts(
    container: str, destination: Path, *, docker: str,
    container_root: str = "/artifacts", label: str = "artifact",
) -> dict[str, object]:
    if destination.is_symlink():
        raise SandboxError("artifact destination must not be a symlink")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        for existing in destination.rglob("*"):
            if existing.is_symlink() or (not existing.is_dir() and not existing.is_file()):
                raise SandboxError(f"artifact destination contains a link/special file: {existing}")
    staging = Path(tempfile.mkdtemp(prefix=f".{label}-", dir=destination.parent))
    try:
        try:
            result = subprocess.run(
                [docker, "exec", "--user", "1001:1001", container, "tar", "-C", container_root, "-cf", "-", "."],
                capture_output=True, timeout=60, check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise SandboxError(f"{label} export failed: {exc}") from exc
        if result.returncode:
            raise SandboxError(f"{label} export failed: {result.stderr.decode(errors='replace').strip()}")
        files = 0
        total = 0
        members = 0
        with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r|") as archive:
            for member in archive:
                members += 1
                if members > 2_000:
                    raise SandboxError(f"{label} export exceeds member limit")
                relative_text = member.name.removeprefix("./")
                if relative_text in {"", "."}:
                    continue
                relative = Path(relative_text)
                if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
                    raise SandboxError(f"{label} export rejected unsafe path: {member.name!r}")
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    raise SandboxError(f"{label} export rejected link/special file: {member.name!r}")
                target = staging / relative
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise SandboxError(f"{label} export rejected unsupported member: {member.name!r}")
                files += 1
                total += member.size
                if files > 2_000 or total > 512 * 1024 * 1024:
                    raise SandboxError(f"{label} export exceeds file or byte limit")
                source = archive.extractfile(member)
                if source is None:
                    raise SandboxError(f"{label} export cannot read member: {member.name!r}")
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
        if files > 2_000 or total > 512 * 1024 * 1024:
            raise SandboxError(f"{label} export exceeds file or byte limit")
        old = destination.parent / f".{label}-old"
        if old.exists():
            if old.is_symlink():
                raise SandboxError("stale artifact backup is a symlink")
            shutil.rmtree(old)
        if destination.exists():
            os.replace(destination, old)
        try:
            os.replace(staging, destination)
        except Exception:
            if old.exists() and not destination.exists():
                os.replace(old, destination)
            raise
        if old.exists():
            shutil.rmtree(old)
        return {"destination": str(destination), "files": files, "bytes": total}
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def _validate_staging_source(source: Path) -> tuple[int, int]:
    if not source.is_dir():
        raise SandboxError(f"artifact staging source is not a directory: {source}")
    files = 0
    total = 0
    for path in source.rglob("*"):
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise SandboxError(f"artifact staging rejected link/special file: {path}")
        if path.is_file():
            files += 1
            total += path.stat().st_size
            if files > 2_000 or total > 512 * 1024 * 1024:
                raise SandboxError("artifact staging exceeds file or byte limit")
    return files, total


def _stream_tree_to_container(source: Path, container: str, target: str, *, docker: str) -> None:
    """Stream a checked tree into the tmpfs; `docker cp` rejects read-only rootfs."""
    argv = [
        docker, "exec", "--interactive", "--user", "1001:1001", container,
        "tar", "--no-same-owner", "--no-same-permissions", "-C", target, "-xf", "-",
    ]
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except FileNotFoundError as exc:
        raise SandboxError(f"required executable not found: {docker}") from exc
    assert process.stdin is not None
    try:
        with tarfile.open(fileobj=process.stdin, mode="w|") as archive:
            for path in sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix()):
                archive.add(path, arcname=path.relative_to(source).as_posix(), recursive=False)
        process.stdin.close()
        stderr = process.stderr.read() if process.stderr is not None else b""
        code = process.wait(timeout=120)
    except (BrokenPipeError, subprocess.TimeoutExpired, OSError) as exc:
        process.kill()
        process.wait()
        raise SandboxError(f"artifact staging stream failed: {exc}") from exc
    if code:
        raise SandboxError(f"artifact staging copy failed: {stderr.decode(errors='replace').strip()}")


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
