"""Host-sibling Docker runtime for local CTF challenge services.

The runtime deliberately owns only resources carrying the exact labels for one
contest/challenge.  It never enumerates or removes unlabelled Docker objects.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Callable, Iterator, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

from .workspace import atomic_json, atomic_text


Runner = Callable[[Sequence[str], int], subprocess.CompletedProcess[str]]


class ServiceError(RuntimeError):
    """An actionable, deterministic challenge-service failure."""


class ServiceBusy(ServiceError):
    """A lifecycle mutation could not acquire or take ownership of a service."""


@dataclass(frozen=True, slots=True)
class ServiceActor:
    """Identity presented to the host-side lifecycle controller.

    Callers which predate service ownership are treated as the active parent Sol
    session.  Native child sessions must explicitly use ``role="child"``; that
    role is rejected in this module before Docker is invoked.
    """

    session_id: str = "sol-main"
    role: str = "sol"
    parent_session_id: str | None = None
    process_id: int = 0
    lease_seconds: int = 300
    recover_stale: bool = False

    @property
    def pid(self) -> int:
        return self.process_id or os.getpid()


@dataclass(frozen=True, slots=True)
class ServiceSpec:
    contest_slug: str
    challenge_id: str
    source: Path
    workspace: Path
    service_plan: Mapping[str, object]
    memory: str = "2g"
    cpus: float = 1.0
    pids: int = 256
    build_timeout: int = 900
    start_timeout: int = 180
    branch_id: str | None = None

    @property
    def scope(self) -> str:
        raw = f"{self.contest_slug}-{self.challenge_id}" + (f"-branch-{self.branch_id}" if self.branch_id else "")
        safe = re.sub(r"[^a-zA-Z0-9_.-]+", "-", raw).strip("-.").lower()
        return (safe[:60] + "-" + hashlib.sha256(raw.encode()).hexdigest()[:10])

    @property
    def project(self) -> str:
        return f"ctf-os-svc-{self.scope}"

    @property
    def network(self) -> str:
        return f"ctf-os-net-{self.scope}"

    @property
    def runtime_root(self) -> Path:
        return (
            self.workspace / "workers" / self.branch_id / "private-service"
            if self.branch_id else self.workspace / "service"
        )

    @property
    def metadata_path(self) -> Path:
        return self.runtime_root / "service.json"

    @property
    def ownership_path(self) -> Path:
        return self.runtime_root / "SERVICE_OWNER.json"

    @property
    def lifecycle_lock_path(self) -> Path:
        return self.runtime_root / ".lifecycle.lock"

    @property
    def stable_alias(self) -> str:
        return "branch-service" if self.branch_id else "challenge-service"

    @property
    def labels(self) -> dict[str, str]:
        labels = {
            "ctf-os": "true",
            "ctf-os.kind": "branch-private-service" if self.branch_id else "challenge-service",
            "ctf-os.contest": self.contest_slug,
            "ctf-os.challenge_id": self.challenge_id,
            "ctf-os.service_scope": self.scope,
        }
        if self.branch_id:
            labels["ctf-os.branch"] = self.branch_id
        return labels


def service_plan(spec: ServiceSpec, *, runner: Runner | None = None, docker: str = "docker") -> dict[str, object]:
    """Resolve and safety-check a prepared intake service plan without mutation."""
    _validate_spec(spec)
    active_runner = runner or _run
    requested = dict(spec.service_plan)
    kind = str(requested.get("kind", "")).casefold()
    reasons = [str(item) for item in requested.get("review_reasons", []) if str(item)]
    if requested.get("safe_to_start") is False:
        reasons.append("intake marked this service plan unsafe to start")

    resolved: dict[str, object] | None = None
    if kind == "compose":
        compose_file = _compose_file(spec)
        result = active_runner([docker, "compose", "-f", str(compose_file), "config", "--format", "json"], 60)
        if result.returncode:
            raise ServiceError(f"cannot resolve Compose configuration: {_detail(result)}")
        try:
            resolved = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ServiceError("docker compose returned invalid JSON configuration") from exc
        reasons.extend(_compose_review_reasons(resolved, spec.source, compose_file.parent))
    elif kind == "dockerfile":
        request = _runtime_request(spec)
        context = _scoped_path(spec.source, request.get("build_context", "."), "build context", must_dir=True)
        dockerfile = _scoped_path(spec.source, request.get("dockerfile", "Dockerfile"), "Dockerfile", must_file=True)
        _ensure_below(dockerfile, spec.source, "Dockerfile")
    else:
        reasons.append("service plan kind must be 'dockerfile' or 'compose'")

    return {
        "schema_version": 1,
        "kind": kind,
        "safe_to_start": not reasons,
        "review_reasons": sorted(set(reasons)),
        "project": spec.project,
        "network": spec.network,
        "network_internal": True,
        "labels": spec.labels,
        "source": str(spec.source.resolve()),
        "resolved_compose": resolved,
        "services": requested.get("services", []),
    }


def service_build(
    spec: ServiceSpec, *, actor: ServiceActor | None = None,
    runner: Runner = None, docker: str = "docker",
) -> dict[str, object]:
    runner = runner or _run
    active = actor or ServiceActor()
    with _lifecycle(spec, active, "build", runner, docker):
        checked = service_plan(spec, runner=runner, docker=docker)
        _require_safe(checked)
        kind = str(checked["kind"])
        if kind == "dockerfile":
            request = _runtime_request(spec)
            context = _scoped_path(spec.source, request.get("build_context", "."), "build context", must_dir=True)
            dockerfile = _scoped_path(spec.source, request.get("dockerfile", "Dockerfile"), "Dockerfile", must_file=True)
            image = f"{spec.project}:local"
            argv = [docker, "build", "--file", str(dockerfile), "--tag", image]
            for key, value in sorted(_build_args(request.get("build_args")).items()):
                argv.extend(["--build-arg", f"{key}={value}"])
            for key, value in spec.labels.items():
                argv.extend(["--label", f"{key}={value}"])
            argv.append(str(context))
        else:
            compose = _compose_file(spec)
            override = _write_compose_override(spec, dict(checked.get("resolved_compose") or {}))
            argv = _compose_argv(spec, compose, override, docker) + ["build"]
        result = runner(argv, spec.build_timeout)
        _log(spec, "build", argv, result)
        if result.returncode:
            raise ServiceError(f"challenge service build failed: {_detail(result)}")
        metadata = _metadata(spec, checked, image=(image if kind == "dockerfile" else None), status="BUILT")
        atomic_json(spec.metadata_path, metadata)
        _update_ownership(spec, active, "BUILT")
        return metadata


def service_start(
    spec: ServiceSpec, *, actor: ServiceActor | None = None,
    runner: Runner = None, docker: str = "docker",
) -> dict[str, object]:
    runner = runner or _run
    active = actor or ServiceActor()
    with _lifecycle(spec, active, "start", runner, docker):
        checked = service_plan(spec, runner=runner, docker=docker)
        _require_safe(checked)
        existing = service_status(spec, actor=active, runner=runner, docker=docker)
        if existing.get("running"):
            metadata = _metadata(
                spec, checked,
                image=(f"{spec.project}:local" if checked["kind"] == "dockerfile" else None),
                status="RUNNING",
            )
            metadata["containers"] = existing["containers"]
            metadata["already_running"] = True
            atomic_json(spec.metadata_path, metadata)
            _update_ownership(spec, active, "RUNNING")
            return metadata
        _ensure_network(spec, runner, docker)
        kind = str(checked["kind"])
        if kind == "dockerfile":
            image = f"{spec.project}:local"
            name = f"{spec.project}-main"
            request = _runtime_request(spec)
            argv = [
                docker, "run", "--detach", "--name", name,
                "--network", spec.network,
                "--network-alias", _dockerfile_alias(request),
                "--network-alias", spec.stable_alias,
                "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
                "--memory", spec.memory, "--cpus", str(spec.cpus),
                "--pids-limit", str(spec.pids), "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m",
            ]
            for key, value in spec.labels.items():
                argv.extend(["--label", f"{key}={value}"])
            for key, value in sorted(_runtime_environment(request.get("environment")).items()):
                argv.extend(["--env", f"{key}={value}"])
            argv.append(image)
            command = request.get("command")
            if isinstance(command, list) and all(isinstance(item, str) for item in command):
                argv.extend(command)
        else:
            compose = _compose_file(spec)
            override = _write_compose_override(spec, dict(checked.get("resolved_compose") or {}))
            argv = _compose_argv(spec, compose, override, docker) + ["up", "--detach", "--no-build", "--wait", "--wait-timeout", str(spec.start_timeout)]
        result = runner(argv, spec.start_timeout + 30)
        _log(spec, "start", argv, result)
        if result.returncode:
            # The lifecycle lock is already held. Use the internal cleanup path
            # instead of recursively acquiring the same nonblocking lock.
            try:
                _service_cleanup_unlocked(spec, runner, docker)
            except ServiceError as cleanup_error:
                raise ServiceError(f"challenge service start failed: {_detail(result)}; rollback failed: {cleanup_error}")
            raise ServiceError(f"challenge service start failed: {_detail(result)}")
        current = service_status(spec, actor=active, runner=runner, docker=docker)
        metadata = _metadata(spec, checked, image=(f"{spec.project}:local" if kind == "dockerfile" else None), status="RUNNING")
        metadata["containers"] = current["containers"]
        atomic_json(spec.metadata_path, metadata)
        _update_ownership(spec, active, "RUNNING")
        return metadata


def service_status(
    spec: ServiceSpec, *, actor: ServiceActor | None = None,
    runner: Runner = None, docker: str = "docker",
) -> dict[str, object]:
    runner = runner or _run
    _validate_spec(spec)
    containers = _labelled_objects(spec, runner, docker, "container")
    network = _inspect_network(spec, runner, docker)
    logs = service_logs(spec, actor=actor, runner=runner, docker=docker)
    owner = _read_ownership(spec)
    return {
        "project": spec.project,
        "service_alias": spec.stable_alias,
        "network": network,
        "containers": containers,
        "running": bool(containers) and all(item.get("state") == "running" for item in containers),
        "healthy": bool(containers) and all(item.get("health") in {"healthy", "none"} for item in containers),
        "logs": logs,
        "ownership": owner,
    }


def service_logs(
    spec: ServiceSpec, *, actor: ServiceActor | None = None,
    runner: Runner = None, docker: str = "docker",
) -> dict[str, dict[str, object]]:
    """Return scoped service logs. Child actors may call this read-only API."""
    runner = runner or _run
    _validate_spec(spec)
    containers = _labelled_objects(spec, runner, docker, "container")
    logs: dict[str, dict[str, object]] = {}
    for container in containers:
        name = str(container["name"])
        argv = [docker, "logs", "--timestamps", "--tail", "2000", name]
        result = runner(argv, 30)
        _log(spec, "container-logs", argv, result)
        logs[name] = {
            "exit_code": result.returncode,
            "stdout": (result.stdout or "")[-64_000:],
            "stderr": (result.stderr or "")[-64_000:],
        }
    return logs


def service_inspect(
    spec: ServiceSpec, *, actor: ServiceActor | None = None,
    runner: Runner = None, docker: str = "docker",
) -> dict[str, object]:
    """Return exact-label runtime and ownership metadata without mutation."""
    runner = runner or _run
    _validate_spec(spec)
    return {
        "project": spec.project,
        "network": _inspect_network(spec, runner, docker),
        "containers": _labelled_objects(spec, runner, docker, "container", include_stopped=True),
        "ownership": _read_ownership(spec),
        "service_alias": spec.stable_alias,
        "metadata": _read_json(spec.metadata_path),
    }


def service_stop(
    spec: ServiceSpec, *, actor: ServiceActor | None = None,
    runner: Runner = None, docker: str = "docker",
) -> dict[str, object]:
    runner = runner or _run
    active = actor or ServiceActor()
    with _lifecycle(spec, active, "stop", runner, docker):
        containers = _labelled_objects(spec, runner, docker, "container")
        stopped: list[str] = []
        for item in containers:
            name = str(item["name"])
            _verify_container_scope(spec, name, runner, docker)
            result = runner([docker, "stop", "--time", "10", name], 30)
            _log(spec, "stop", [docker, "stop", "--time", "10", name], result)
            if result.returncode:
                raise ServiceError(f"cannot stop scoped service container {name}: {_detail(result)}")
            stopped.append(name)
        _update_ownership(spec, active, "STOPPED")
        return {"stopped": stopped}


def service_restart(
    spec: ServiceSpec, *, actor: ServiceActor | None = None,
    runner: Runner = None, docker: str = "docker",
) -> dict[str, object]:
    """Restart exact-scope containers as one owner-locked lifecycle action."""
    runner = runner or _run
    active = actor or ServiceActor()
    with _lifecycle(spec, active, "restart", runner, docker):
        containers = _labelled_objects(spec, runner, docker, "container", include_stopped=True)
        restarted: list[str] = []
        for item in containers:
            name = str(item["name"])
            _verify_container_scope(spec, name, runner, docker)
            argv = [docker, "restart", "--time", "10", name]
            result = runner(argv, spec.start_timeout + 30)
            _log(spec, "restart", argv, result)
            if result.returncode:
                raise ServiceError(f"cannot restart scoped service container {name}: {_detail(result)}")
            restarted.append(name)
        if not restarted:
            raise ServiceError("challenge service is not present; build and start it before restart")
        _update_ownership(spec, active, "RUNNING")
        return {"restarted": restarted}


def service_reset(
    spec: ServiceSpec, *, actor: ServiceActor | None = None,
    runner: Runner = None, docker: str = "docker",
) -> dict[str, object]:
    """Recreate an exact-scope service from its immutable challenge source."""
    active_runner = runner or _run
    active = actor or ServiceActor()
    cleaned = service_cleanup(spec, actor=active, runner=active_runner, docker=docker)
    built = service_build(spec, actor=active, runner=active_runner, docker=docker)
    started = service_start(spec, actor=active, runner=active_runner, docker=docker)
    return {"reset": True, "cleanup": cleaned, "build": built, "start": started}


def service_cleanup(
    spec: ServiceSpec, *, actor: ServiceActor | None = None,
    runner: Runner = None, docker: str = "docker",
) -> dict[str, object]:
    """Remove only exact-label containers, volumes, images, and the scoped network."""
    runner = runner or _run
    active = actor or ServiceActor()
    with _lifecycle(spec, active, "cleanup", runner, docker):
        result = _service_cleanup_unlocked(spec, runner, docker)
        _update_ownership(spec, active, "CLEANED")
        return result


def _service_cleanup_unlocked(spec: ServiceSpec, runner: Runner, docker: str) -> dict[str, object]:
    _validate_spec(spec)
    removed: dict[str, list[str] | bool] = {"containers": [], "volumes": [], "images": [], "network": False}
    for item in _labelled_objects(spec, runner, docker, "container", include_stopped=True):
        name = str(item["name"])
        _verify_container_scope(spec, name, runner, docker)
        argv = [docker, "rm", "--force", "--volumes", name]
        result = runner(argv, 30)
        _log(spec, "cleanup-container", argv, result)
        if result.returncode:
            raise ServiceError(f"cannot remove scoped service container {name}: {_detail(result)}")
        removed["containers"].append(name)  # type: ignore[union-attr]
    for kind, command in (("volumes", "volume"), ("images", "image")):
        for identifier in _labelled_ids(spec, runner, docker, command):
            argv = [docker, command, "rm", identifier]
            result = runner(argv, 60)
            _log(spec, f"cleanup-{command}", argv, result)
            if result.returncode:
                raise ServiceError(f"cannot remove scoped {command} {identifier}: {_detail(result)}")
            removed[kind].append(identifier)  # type: ignore[union-attr]
    network = _inspect_network(spec, runner, docker)
    if network.get("exists"):
        if not network.get("owned"):
            raise ServiceError(f"refusing cleanup: network {spec.network} does not have exact service labels")
        result = runner([docker, "network", "rm", spec.network], 30)
        _log(spec, "cleanup-network", [docker, "network", "rm", spec.network], result)
        if result.returncode:
            raise ServiceError(f"cannot remove scoped service network: {_detail(result)}")
        removed["network"] = True
    return {"removed": removed}


def attach_analysis_sandbox(
    spec: ServiceSpec, sandbox: Mapping[str, object], *, actor: ServiceActor | None = None,
    runner: Runner = None, docker: str = "docker",
) -> dict[str, object]:
    """Attach an exact-scope analysis sandbox to the private service network."""
    runner = runner or _run
    name = str(sandbox.get("name", ""))
    labels = sandbox.get("labels")
    if not re.fullmatch(r"ctf-os-[A-Za-z0-9_.-]+", name) or not isinstance(labels, Mapping):
        raise ServiceError("invalid analysis sandbox metadata")
    if labels.get("ctf-os") != "true" or labels.get("ctf-os.contest") != spec.contest_slug or labels.get("ctf-os.challenge_id") != spec.challenge_id:
        raise ServiceError("analysis sandbox labels do not match the challenge service scope")
    _verify_labels(name, labels, runner, docker)
    with service_attachment(spec, actor=actor, runner=runner, docker=docker):
        argv = [docker, "network", "connect", spec.network, name]
        result = runner(argv, 30)
        _log(spec, "attach-sandbox", argv, result)
        if result.returncode and "already exists" not in result.stderr.casefold():
            raise ServiceError(f"cannot attach analysis sandbox to service network: {_detail(result)}")
        return {"container": name, "network": spec.network, "attached": result.returncode == 0}


@contextmanager
def service_attachment(
    spec: ServiceSpec, *, actor: ServiceActor | None = None,
    runner: Runner = None, docker: str = "docker",
) -> Iterator[None]:
    """Hold the lifecycle lock while Sol creates and probes an attached worker."""
    active_runner = runner or _run
    active = actor or ServiceActor()
    _validate_spec(spec)
    _validate_actor(active)
    if active.role != "sol" or (
        active.parent_session_id is not None and active.session_id != active.parent_session_id
    ):
        raise ServiceError("DENIED_SERVICE_ATTACHMENT: only the parent Sol session may attach a worker")
    _prepare_runtime_root(spec)
    descriptor = os.open(
        spec.lifecycle_lock_path,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    lock = os.fdopen(descriptor, "a+")
    try:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ServiceBusy(_busy_message(spec, "attach-worker", _read_ownership(spec))) from exc
        owner = _read_ownership(spec) or {}
        if owner.get("owner_session_id") != active.session_id or owner.get("state") != "RUNNING":
            raise ServiceBusy(_busy_message(spec, "attach-worker", owner))
        network = _inspect_network(spec, active_runner, docker)
        containers = _labelled_objects(spec, active_runner, docker, "container")
        if not network.get("owned") or not network.get("internal"):
            raise ServiceError("managed service attachment failed: network missing, unowned, or not internal")
        if not containers or not all(item.get("state") == "running" for item in containers):
            raise ServiceError("managed service attachment failed: service container is not running")
        _update_ownership(spec, active, "RUNNING")
        yield
    finally:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        finally:
            lock.close()


def _metadata(spec: ServiceSpec, checked: Mapping[str, object], *, image: str | None, status: str) -> dict[str, object]:
    endpoints = _stable_endpoints(spec, checked.get("services", []))
    return {
        "schema_version": 1, "status": status, "kind": checked["kind"],
        "contest_slug": spec.contest_slug, "challenge_id": spec.challenge_id,
        "project": spec.project, "network": spec.network, "labels": spec.labels,
        "source": str(spec.source.resolve()), "workspace": str(spec.workspace.resolve()),
        "metadata_path": str(spec.metadata_path), "image": image,
        "service_alias": spec.stable_alias, "service_endpoints": endpoints,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "services": checked.get("services", []),
    }


def _validate_spec(spec: ServiceSpec) -> None:
    if not spec.source.is_dir() or spec.source.is_symlink():
        raise ServiceError(f"prepared challenge input is missing or unsafe: {spec.source}")
    if spec.workspace.is_symlink():
        raise ServiceError("challenge workspace must not be a symlink")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}", spec.contest_slug):
        raise ServiceError("invalid contest slug")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}", spec.challenge_id):
        raise ServiceError("invalid challenge id")
    if spec.branch_id is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", spec.branch_id):
        raise ServiceError("invalid branch-private service id")
    if spec.cpus <= 0 or spec.pids < 1 or not re.fullmatch(r"[1-9][0-9]*(?:[kKmMgG])?", spec.memory):
        raise ServiceError("service resource limits are invalid")
    if not (30 <= spec.build_timeout <= 3600 and 5 <= spec.start_timeout <= 600):
        raise ServiceError("service timeouts are outside supported bounds")


def _compose_file(spec: ServiceSpec) -> Path:
    value = spec.service_plan.get("compose_file")
    if value is None:
        values = spec.service_plan.get("compose_files")
        if isinstance(values, list) and values:
            value = values[0]
    return _scoped_path(spec.source, value, "Compose file", must_file=True)


def _runtime_request(spec: ServiceSpec) -> dict[str, object]:
    """Merge the first intake service record over legacy top-level fields."""
    request = dict(spec.service_plan)
    services = request.get("services")
    if isinstance(services, list) and services and isinstance(services[0], Mapping):
        request.update(services[0])
    return request


def _scoped_path(root: Path, value: object, label: str, *, must_file: bool = False, must_dir: bool = False) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ServiceError(f"{label} is missing from the service plan")
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = candidate.resolve()
    _ensure_below(candidate, root, label)
    if candidate.is_symlink() or (must_file and not candidate.is_file()) or (must_dir and not candidate.is_dir()):
        expected = "file" if must_file else "directory"
        raise ServiceError(f"{label} is not a safe existing {expected}: {candidate}")
    return candidate


def _ensure_below(candidate: Path, root: Path, label: str) -> None:
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise ServiceError(f"{label} escapes the prepared challenge input: {candidate}") from exc


def _compose_review_reasons(config: Mapping[str, object], source: Path, compose_dir: Path) -> list[str]:
    reasons: list[str] = []
    services = config.get("services")
    if not isinstance(services, Mapping) or not services:
        return ["Compose configuration has no services"]
    broad_caps = {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_MODULE", "SYS_RAWIO", "SYS_PTRACE", "DAC_READ_SEARCH", "BPF", "PERFMON"}
    for raw_name, raw in services.items():
        name = str(raw_name)
        if not isinstance(raw, Mapping):
            reasons.append(f"service {name}: configuration is not an object")
            continue
        if raw.get("privileged") is True:
            reasons.append(f"service {name}: privileged=true")
        for namespace in ("network_mode", "pid", "ipc", "uts", "userns_mode"):
            if str(raw.get(namespace, "")).casefold() == "host":
                reasons.append(f"service {name}: {namespace}=host")
        devices = raw.get("devices") or []
        if devices:
            reasons.append(f"service {name}: host devices are not allowed")
        caps = {str(item).upper() for item in (raw.get("cap_add") or [])}
        if caps & broad_caps or len(caps) > 4:
            reasons.append(f"service {name}: broad cap_add is not allowed ({', '.join(sorted(caps))})")
        if raw.get("external_links") or raw.get("links"):
            reasons.append(f"service {name}: links to other Docker containers are not allowed")
        if raw.get("volumes_from"):
            reasons.append(f"service {name}: volumes_from can access another container and is not allowed")
        if raw.get("provider"):
            reasons.append(f"service {name}: external service providers may run host commands and are not allowed")
        if raw.get("use_api_socket"):
            reasons.append(f"service {name}: Docker API socket access is not allowed")
        if raw.get("cgroup_parent") or str(raw.get("cgroup", "")).casefold() == "host":
            reasons.append(f"service {name}: host cgroup access is not allowed")
        for host in raw.get("extra_hosts") or []:
            if "host-gateway" in str(host).casefold() or "host.docker.internal" in str(host).casefold():
                reasons.append(f"service {name}: host gateway mapping is not allowed")
        networks = raw.get("networks") or {}
        network_names = set(networks if isinstance(networks, list) else networks.keys() if isinstance(networks, Mapping) else [])
        if network_names - {"default"}:
            reasons.append(f"service {name}: custom networks cannot guarantee challenge isolation")
        for volume in raw.get("volumes") or []:
            reasons.extend(_volume_review_reasons(name, volume, source, compose_dir))
        build = raw.get("build")
        if build:
            details = build if isinstance(build, Mapping) else {"context": build}
            context_value = details.get("context", ".")
            try:
                context = _resolve_compose_path(compose_dir, context_value)
                _ensure_below(context, source, f"service {name} build context")
                dockerfile = details.get("dockerfile")
                if dockerfile:
                    _ensure_below((context / str(dockerfile)).resolve(), source, f"service {name} Dockerfile")
                for context_name, context_path in (details.get("additional_contexts") or {}).items():
                    if "://" not in str(context_path):
                        _ensure_below(_resolve_compose_path(compose_dir, context_path), source, f"service {name} additional build context {context_name}")
            except ServiceError as exc:
                reasons.append(str(exc))
            if details.get("privileged") or str(details.get("network", "")).casefold() == "host":
                reasons.append(f"service {name}: privileged/host-network build is not allowed")
            if details.get("entitlements") or details.get("ssh"):
                reasons.append(f"service {name}: build entitlements or SSH forwarding require review")
        for key in ("configs", "secrets"):
            for item in raw.get(key) or []:
                if isinstance(item, Mapping) and item.get("source") and str(item.get("source")).startswith(("/", ".")):
                    try:
                        _ensure_below(_resolve_compose_path(compose_dir, item["source"]), source, f"service {name} {key} source")
                    except ServiceError as exc:
                        reasons.append(str(exc))
    for top_level in ("volumes", "configs", "secrets"):
        entries = config.get(top_level) or {}
        if not isinstance(entries, Mapping):
            continue
        for name, raw in entries.items():
            if isinstance(raw, Mapping) and raw.get("external"):
                reasons.append(f"external {top_level[:-1]} {name} can access an unrelated Docker resource")
            if top_level in {"configs", "secrets"} and isinstance(raw, Mapping) and raw.get("file"):
                try:
                    _ensure_below(_resolve_compose_path(compose_dir, raw["file"]), source, f"Compose {top_level[:-1]} {name}")
                except ServiceError as exc:
                    reasons.append(str(exc))
    return reasons


def _volume_review_reasons(service: str, volume: object, source: Path, compose_dir: Path) -> list[str]:
    if isinstance(volume, Mapping):
        kind = str(volume.get("type", "volume"))
        raw_source = volume.get("source")
        target = str(volume.get("target", ""))
        if kind != "bind":
            return [f"service {service}: Docker socket mount is not allowed"] if "docker.sock" in target else []
    else:
        text = str(volume)
        parts = text.split(":")
        raw_source = parts[0] if len(parts) > 1 else None
        target = parts[1] if len(parts) > 1 else parts[0]
        kind = "bind" if raw_source and (str(raw_source).startswith(("/", ".", "~")) or re.match(r"^[A-Za-z]:[\\/]", str(raw_source))) else "volume"
    if "docker.sock" in str(raw_source) or "docker.sock" in target:
        return [f"service {service}: Docker socket mount is not allowed"]
    if kind != "bind" or not raw_source:
        return []
    try:
        host = _resolve_compose_path(compose_dir, raw_source)
        _ensure_below(host, source, f"service {service} bind mount")
    except ServiceError as exc:
        return [str(exc)]
    return []


def _resolve_compose_path(base: Path, value: object) -> Path:
    path = Path(str(value)).expanduser()
    return (path if path.is_absolute() else base / path).resolve()


def _write_compose_override(spec: ServiceSpec, config: Mapping[str, object]) -> Path:
    services = config.get("services")
    if not isinstance(services, Mapping) or not services:
        raise ServiceError("cannot generate private-network override without Compose services")
    labels = "\n".join(f"      {json.dumps(key)}: {json.dumps(value)}" for key, value in spec.labels.items())
    blocks: list[str] = ["services:"]
    service_names = sorted(str(item) for item in services)
    for ordinal, name in enumerate(service_names):
        network_block = (
            ["      default:", "        aliases:", f"          - {json.dumps(spec.stable_alias)}"]
            if ordinal == 0 else ["      default: {}"]
        )
        block = [
            f"  {json.dumps(name)}:",
            "    ports: !reset []",
            "    networks: !override",
            *network_block,
            "    labels:", labels,
            f"    mem_limit: {json.dumps(spec.memory)}",
            f"    cpus: {spec.cpus}",
            f"    pids_limit: {spec.pids}",
            "    security_opt:",
            "      - no-new-privileges:true",
        ]
        raw_service = services.get(name)
        if isinstance(raw_service, Mapping) and raw_service.get("build"):
            block.extend(["    build:", "      labels:"])
            block.extend(f"        {json.dumps(key)}: {json.dumps(value)}" for key, value in spec.labels.items())
        blocks.extend(block)
    blocks.extend([
        "networks:", "  default:", "    external: true", f"    name: {json.dumps(spec.network)}",
    ])
    volumes = config.get("volumes")
    if isinstance(volumes, Mapping) and volumes:
        blocks.append("volumes:")
        for name in sorted(str(item) for item in volumes):
            blocks.extend([f"  {json.dumps(name)}:", "    labels:", labels])
    path = spec.runtime_root / "compose.ctf-os.override.yml"
    atomic_text(path, "\n".join(blocks) + "\n")
    return path


def _compose_argv(spec: ServiceSpec, compose: Path, override: Path, docker: str) -> list[str]:
    return [docker, "compose", "--project-name", spec.project, "-f", str(compose), "-f", str(override)]


def _prepare_runtime_root(spec: ServiceSpec) -> None:
    if spec.runtime_root.is_symlink():
        raise ServiceError("service runtime path must not be a symlink")
    spec.runtime_root.mkdir(parents=True, exist_ok=True)


@contextmanager
def _lifecycle(
    spec: ServiceSpec, actor: ServiceActor, action: str, runner: Runner, docker: str,
) -> Iterator[None]:
    """Serialize and authorize one service mutation without waiting indefinitely."""
    _validate_spec(spec)
    _validate_actor(actor)
    shared_denied = spec.branch_id is None and (
        actor.role != "sol" or (
            actor.parent_session_id is not None and actor.session_id != actor.parent_session_id
        )
    )
    private_denied = spec.branch_id is not None and (
        actor.session_id != spec.branch_id or actor.role not in {"child", "sol"}
    )
    if shared_denied or private_denied:
        raise ServiceError(
            "DENIED_SERVICE_LIFECYCLE\n\n"
            "Shared challenge services are parent-Sol owned. A child may mutate only a "
            "branch-private service whose branch id exactly matches its native session id."
        )
    _prepare_runtime_root(spec)
    path = spec.lifecycle_lock_path
    if path.is_symlink():
        raise ServiceError("service lifecycle lock must not be a symlink")
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    lock = os.fdopen(descriptor, "a+")
    try:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ServiceBusy(_busy_message(spec, action, _read_ownership(spec))) from exc
        _claim_ownership(spec, actor, action, runner, docker)
        try:
            yield
        except Exception:
            _update_ownership(spec, actor, "ERROR")
            raise
    finally:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        finally:
            lock.close()


def _claim_ownership(
    spec: ServiceSpec, actor: ServiceActor, action: str, runner: Runner, docker: str,
) -> None:
    current = _read_ownership(spec)
    if current and current.get("owner_session_id") != actor.session_id:
        recoverable = False
        if current.get("state") == "CLEANED":
            containers = _labelled_objects(spec, runner, docker, "container", include_stopped=True)
            recoverable = not containers
        elif actor.recover_stale:
            lease_expired = _lease_expired(current)
            owner_alive = _pid_alive(current.get("owner_process_id"))
            containers = _labelled_objects(spec, runner, docker, "container", include_stopped=True)
            # Exact-label orphan containers may be taken over only for cleanup;
            # build/start under a different configuration still fail closed.
            recoverable = lease_expired and not owner_alive and (not containers or action == "cleanup")
        if not recoverable:
            raise ServiceBusy(_busy_message(spec, action, current))
    _update_ownership(spec, actor, f"{action.upper()}ING")


def _update_ownership(spec: ServiceSpec, actor: ServiceActor, state: str) -> dict[str, object]:
    now = datetime.now(timezone.utc)
    existing = _read_ownership(spec) or {}
    started = existing.get("started_at") if existing.get("owner_session_id") == actor.session_id else None
    record: dict[str, object] = {
        "schema_version": 1,
        "challenge_id": spec.challenge_id,
        "owner_session_id": actor.session_id,
        "owner_role": actor.role,
        "parent_session_id": actor.parent_session_id,
        "owner_process_id": actor.pid,
        "service_id": spec.project,
        "network_id": spec.network,
        "service_alias": spec.stable_alias,
        "state": state,
        "started_at": started or now.isoformat(),
        "heartbeat_at": now.isoformat(),
        "lease_expires_at": (now + timedelta(seconds=actor.lease_seconds)).isoformat(),
        "recovery": {
            "requires_expired_lease": True,
            "requires_dead_owner_process": True,
            "container_policy": "no containers, or exact-scope cleanup only",
            "explicit_opt_in": "ServiceActor.recover_stale",
        },
    }
    atomic_json(spec.ownership_path, record)
    return record


def _read_ownership(spec: ServiceSpec) -> dict[str, object] | None:
    value = _read_json(spec.ownership_path)
    return value if value else None


def _read_json(path: Path) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ServiceError(f"invalid service runtime metadata: {path.name}") from exc
    if not isinstance(value, dict):
        raise ServiceError(f"invalid service runtime metadata: {path.name}")
    return value


def _validate_actor(actor: ServiceActor) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", actor.session_id):
        raise ServiceError("invalid service actor session id")
    if actor.lease_seconds < 30 or actor.lease_seconds > 86_400:
        raise ServiceError("service owner lease must be between 30 and 86400 seconds")
    if actor.role not in {"sol", "child"}:
        raise ServiceError("service actor role must be sol or child")


def _lease_expired(owner: Mapping[str, object]) -> bool:
    try:
        expires = datetime.fromisoformat(str(owner.get("lease_expires_at", "")))
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return expires <= datetime.now(timezone.utc)
    except ValueError:
        return False


def _pid_alive(raw_pid: object) -> bool:
    try:
        pid = int(raw_pid)
    except (TypeError, ValueError):
        return False
    if pid < 1:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _busy_message(spec: ServiceSpec, action: str, owner: Mapping[str, object] | None) -> str:
    owner = owner or {}
    return (
        "SERVICE_BUSY\n\n"
        f"Owner: {owner.get('owner_session_id', 'unknown')}\n"
        f"State: {owner.get('state', 'UNKNOWN')}\n"
        f"Requested action: {action}\n\n"
        "The current session is not permitted to mutate this service."
    )


def _stable_endpoints(spec: ServiceSpec, raw_services: object) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    if not isinstance(raw_services, list):
        return result
    for item in raw_services:
        if not isinstance(item, Mapping):
            continue
        port = item.get("port")
        original = str(item.get("internal_target", ""))
        protocol = str(item.get("protocol") or ("http" if original.startswith("http") else "tcp"))
        if isinstance(port, int) or (isinstance(port, str) and port.isdigit()):
            port_number = int(port)
            path = ""
            if "://" in original:
                parsed = urlsplit(original)
                protocol = parsed.scheme or protocol
                path = urlunsplit(("", "", parsed.path, parsed.query, parsed.fragment))
            target = (
                f"{protocol}://{spec.stable_alias}:{port_number}{path}"
                if protocol in {"http", "https"} else f"{spec.stable_alias}:{port_number}"
            )
            result.append({
                "alias": spec.stable_alias, "protocol": protocol, "port": port_number,
                "path": path or None, "target": target,
            })
            break  # The stable alias is assigned only to the primary service.
    return result


def _ensure_network(spec: ServiceSpec, runner: Runner, docker: str) -> None:
    network = _inspect_network(spec, runner, docker)
    if network.get("exists"):
        if not network.get("owned") or not network.get("internal"):
            raise ServiceError(f"network name collision: {spec.network} is not an owned internal network")
        return
    argv = [docker, "network", "create", "--internal", "--driver", "bridge"]
    for key, value in spec.labels.items():
        argv.extend(["--label", f"{key}={value}"])
    argv.append(spec.network)
    result = runner(argv, 30)
    _log(spec, "network-create", argv, result)
    if result.returncode:
        raise ServiceError(f"cannot create private challenge network: {_detail(result)}")


def _inspect_network(spec: ServiceSpec, runner: Runner, docker: str) -> dict[str, object]:
    result = runner([docker, "network", "inspect", spec.network, "--format", "{{json .}}"], 20)
    if result.returncode:
        if "no such network" in result.stderr.casefold() or "not found" in result.stderr.casefold():
            return {"exists": False, "owned": False, "internal": False, "name": spec.network}
        raise ServiceError(f"cannot inspect challenge network: {_detail(result)}")
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ServiceError("Docker returned invalid network inspection JSON") from exc
    labels = data.get("Labels") or {}
    return {
        "exists": True, "owned": all(labels.get(k) == v for k, v in spec.labels.items()),
        "internal": data.get("Internal") is True, "name": spec.network,
        "containers": sorted((data.get("Containers") or {}).keys()),
    }


def _label_filters(spec: ServiceSpec) -> list[str]:
    filters: list[str] = []
    for key, value in spec.labels.items():
        filters.extend(["--filter", f"label={key}={value}"])
    return filters


def _labelled_objects(spec: ServiceSpec, runner: Runner, docker: str, kind: str, *, include_stopped: bool = False) -> list[dict[str, str]]:
    argv = [docker, "ps"]
    if include_stopped:
        argv.append("--all")
    argv.extend(_label_filters(spec))
    argv.extend(["--format", "{{json .}}"])
    result = runner(argv, 30)
    if result.returncode:
        raise ServiceError(f"cannot list scoped service containers: {_detail(result)}")
    items: list[dict[str, str]] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ServiceError("Docker returned invalid container listing JSON") from exc
        status = str(raw.get("Status", ""))
        health_match = re.search(r"\((healthy|unhealthy|health: starting)\)", status.casefold())
        health = health_match.group(1).replace("health: ", "") if health_match else "none"
        items.append({"id": str(raw.get("ID", "")), "name": str(raw.get("Names", "")), "state": str(raw.get("State", "")).casefold(), "status": status, "health": health})
    return sorted(items, key=lambda item: item["name"])


def _labelled_ids(spec: ServiceSpec, runner: Runner, docker: str, kind: str) -> list[str]:
    argv = [docker, kind, "ls", "--quiet"] + _label_filters(spec)
    result = runner(argv, 30)
    if result.returncode:
        raise ServiceError(f"cannot list scoped service {kind}s: {_detail(result)}")
    return sorted(set(line.strip() for line in result.stdout.splitlines() if line.strip()))


def _verify_container_scope(spec: ServiceSpec, name: str, runner: Runner, docker: str) -> None:
    _verify_labels(name, spec.labels, runner, docker)


def _verify_labels(name: str, expected: Mapping[str, object], runner: Runner, docker: str) -> None:
    result = runner([docker, "inspect", name, "--format", "{{json .Config.Labels}}"], 20)
    if result.returncode:
        raise ServiceError(f"cannot verify labels for {name}: {_detail(result)}")
    try:
        labels = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ServiceError(f"Docker returned invalid labels for {name}") from exc
    if any(labels.get(key) != value for key, value in expected.items()):
        raise ServiceError(f"refusing operation: {name} does not have exact expected labels")


def _string_map(value: object, label: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ServiceError(f"{label} must be a string mapping")
    result = {str(key): str(item) for key, item in value.items()}
    if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) for key in result):
        raise ServiceError(f"{label} contains an invalid key")
    return result


def _build_args(value: object) -> dict[str, str]:
    if isinstance(value, Mapping) or value is None:
        return _string_map(value, "build_args")
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        # Intake records Dockerfile ARG declarations. Only explicit non-secret
        # defaults are forwarded; bare ARG names continue using Docker defaults.
        pairs = [item.split("=", 1) for item in value if "=" in item]
        return _string_map({key: item for key, item in pairs}, "build_args")
    raise ServiceError("build_args must be a mapping or Dockerfile ARG list")


def _runtime_environment(value: object) -> dict[str, str]:
    if isinstance(value, Mapping) or value is None:
        return _string_map(value, "environment")
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        # Dockerfile ENV declarations are already part of the built image.
        return {}
    raise ServiceError("environment must be a mapping or Dockerfile ENV list")


def _dockerfile_alias(plan: Mapping[str, object]) -> str:
    services = plan.get("services")
    alias = "chall"
    if isinstance(services, list) and services and isinstance(services[0], Mapping):
        alias = str(services[0].get("name", alias))
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", alias):
        raise ServiceError("Dockerfile service name is not a valid private-network alias")
    return alias


def _require_safe(plan: Mapping[str, object]) -> None:
    if not plan.get("safe_to_start"):
        reasons = "; ".join(str(item) for item in plan.get("review_reasons", []))
        raise ServiceError(f"NEEDS_REVIEW: challenge service was not started: {reasons}")


def _log(spec: ServiceSpec, event: str, argv: Sequence[str], result: subprocess.CompletedProcess[str]) -> None:
    _prepare_runtime_root(spec)
    path = spec.runtime_root / "service.log"
    record = {
        "at": datetime.now(timezone.utc).isoformat(), "event": event,
        "argv": list(argv), "exit_code": result.returncode,
        "stdout": (result.stdout or "")[-64_000:], "stderr": (result.stderr or "")[-64_000:],
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def _detail(result: subprocess.CompletedProcess[str]) -> str:
    return (result.stderr or result.stdout or f"exit code {result.returncode}").strip()[-4_000:]


def _run(argv: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return subprocess.CompletedProcess(list(argv), 124, stdout, stderr + "\ncommand timed out")
    except FileNotFoundError as exc:
        raise ServiceError(f"required executable not found: {argv[0]}") from exc
