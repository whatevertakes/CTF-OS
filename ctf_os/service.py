"""Root-owned, race-scoped challenge service lifecycle."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .sandbox.resources import ResourceError, admit_fixed
from .workspace import atomic_json, atomic_text, state_lock


class ServiceError(RuntimeError):
    pass


class ServiceCleanupError(ServiceError):
    def __init__(
        self,
        message: str,
        *,
        service: Mapping[str, Any],
        failures: Sequence[str],
    ) -> None:
        super().__init__(message)
        self.service = dict(service)
        self.failures = tuple(str(value) for value in failures)


class _ResetList(list):
    pass


class _ComposeDumper(yaml.SafeDumper):
    pass


def _represent_reset_list(dumper: yaml.SafeDumper, value: _ResetList):
    node = dumper.represent_list(value)
    node.tag = "!reset"
    return node


_ComposeDumper.add_representer(_ResetList, _represent_reset_list)


@dataclass(frozen=True, slots=True)
class ServiceActor:
    lane_id: str
    role: str

    def require_root(self) -> None:
        if self.lane_id != "root" or self.role != "root":
            raise ServiceError("only Root may mutate challenge service lifecycle")


@dataclass(frozen=True, slots=True)
class ServiceSpec:
    run_id: str
    challenge_id: str
    source: Path
    run_root: Path
    plan: Mapping[str, Any]
    instance_id: str = "root"

    @property
    def suffix(self) -> str:
        return hashlib.sha256(
            f"{self.run_id}\0{self.instance_id}".encode()
        ).hexdigest()[:12]

    @property
    def image_suffix(self) -> str:
        return hashlib.sha256(self.run_id.encode()).hexdigest()[:12]

    @property
    def network(self) -> str:
        return f"ctf-os-net-{self.suffix}"

    @property
    def image(self) -> str:
        return f"ctf-os-challenge:{self.image_suffix}"

    @property
    def container(self) -> str:
        return f"ctf-os-service-{self.suffix}"

    @property
    def project(self) -> str:
        return f"ctf-os-{self.suffix}"

    @property
    def metadata_path(self) -> Path:
        if self.instance_id == "root":
            return self.run_root / "service" / "service.json"
        return (
            self.run_root / "service" / "instances" / self.instance_id / "service.json"
        )

    @property
    def labels(self) -> dict[str, str]:
        return {
            "org.ctf-os.managed": "true",
            "org.ctf-os.kind": "service",
            "org.ctf-os.run-id": self.run_id,
            "org.ctf-os.challenge-id": self.challenge_id,
            "org.ctf-os.service-instance": self.instance_id,
        }

    @property
    def image_labels(self) -> dict[str, str]:
        return {
            "org.ctf-os.managed": "true",
            "org.ctf-os.kind": "service-image",
            "org.ctf-os.run-id": self.run_id,
            "org.ctf-os.challenge-id": self.challenge_id,
        }


def prepare_service(
    spec: ServiceSpec,
    *,
    actor: ServiceActor,
    docker: str = "docker",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    actor.require_root()
    kind = str(spec.plan.get("kind", "none"))
    if kind == "none":
        return {
            "status": "NOT_REQUIRED", "network": None, "endpoints": [],
            "lifecycle_owner": "root",
        }
    if spec.plan.get("safe") is not True:
        raise ServiceError(
            "challenge service is unsafe to start: "
            + "; ".join(str(value) for value in spec.plan.get("review_reasons", []))
        )
    _validate_spec(spec)
    with state_lock(spec.run_root / "resources"):
        return _prepare_service_locked(
            spec,
            kind=kind,
            docker=docker,
            runner=runner,
        )


def _prepare_service_locked(
    spec: ServiceSpec,
    *,
    kind: str,
    docker: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> dict[str, Any]:
    if spec.metadata_path.is_file() and not spec.metadata_path.is_symlink():
        existing = load_service(spec.metadata_path)
        if existing.get("run_id") == spec.run_id and _service_running(existing, docker=docker, runner=runner):
            return existing | {"attached": True}
    _require_local_images(spec, docker=docker, runner=runner)
    service_count = max(
        1,
        len([
            row for row in spec.plan.get("services", [])
            if isinstance(row, Mapping)
        ]),
    )
    try:
        capacity = admit_fixed(
            memory=f"{2 * service_count}g",
            cpus=float(2 * service_count),
            purpose=f"challenge-service:{spec.instance_id}",
            docker=docker,
            runner=runner,
        )
    except ResourceError as exc:
        raise ServiceError(str(exc)) from exc
    service_root = spec.metadata_path.parent
    cursor = spec.run_root
    for part in service_root.relative_to(spec.run_root).parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ServiceError("service runtime path must not contain a symlink")
    service_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    _ensure_network(spec, docker=docker, runner=runner)
    try:
        if kind == "dockerfile":
            runtime = _start_dockerfile(spec, docker=docker, runner=runner)
        elif kind == "compose":
            runtime = _start_compose(spec, docker=docker, runner=runner)
        else:
            raise ServiceError(f"unsupported service plan kind: {kind}")
    except Exception as exc:
        rollback_failures = _cleanup_failed_start(spec, kind=kind, docker=docker, runner=runner)
        if rollback_failures:
            # The start failed AND its rollback left resources behind: surface a
            # structured recovery so the controller keeps the lane CLEANUP_FAILED
            # and race-cleanup / race-lane-cleanup can reclaim it later.
            recovery = _recovery_metadata(spec, kind=kind, failures=rollback_failures)
            raise ServiceCleanupError(
                f"service start failed and cleanup was incomplete: {exc}; "
                + "; ".join(rollback_failures),
                service=recovery,
                failures=rollback_failures,
            ) from exc
        raise
    endpoints = [
        str(endpoint)
        for service in spec.plan.get("services", [])
        if isinstance(service, Mapping)
        for endpoint in service.get("endpoints", [])
    ]
    metadata = {
        "schema_version": 1,
        "status": "READY",
        "run_id": spec.run_id,
        "challenge_id": spec.challenge_id,
        "kind": kind,
        "instance_id": spec.instance_id,
        "isolation": "private-instance",
        "network": spec.network,
        "endpoints": endpoints,
        "lifecycle_owner": "root",
        "labels": spec.labels,
        "runtime": runtime,
        "capacity_at_create": capacity,
        "metadata_path": str(spec.metadata_path.resolve()),
    }
    try:
        atomic_json(spec.metadata_path, metadata)
    except Exception as exc:
        cleanup_result = cleanup_service(
            metadata,
            actor=ServiceActor("root", "root"),
            docker=docker,
            runner=runner,
        )
        if cleanup_result["failures"]:
            failures = [str(value) for value in cleanup_result["failures"]]
            recovery = metadata | {
                "status": "CLEANUP_FAILED",
                "cleanup_failures": failures,
            }
            raise ServiceCleanupError(
                "service metadata write failed and cleanup was incomplete: "
                + "; ".join(failures),
                service=recovery,
                failures=failures,
            ) from exc
        raise
    return metadata | {"attached": False}


def load_service(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ServiceError("service metadata is missing or unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ServiceError("service metadata is unreadable") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ServiceError("service metadata schema is unsupported")
    if Path(str(value.get("metadata_path"))).resolve() != path.resolve():
        raise ServiceError("service metadata path identity mismatch")
    return value


def service_status(
    metadata: Mapping[str, Any],
    *,
    docker: str = "docker",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    return {
        "run_id": metadata.get("run_id"),
        "status": "READY" if _service_running(metadata, docker=docker, runner=runner) else "STOPPED",
        "network": metadata.get("network"),
        "endpoints": list(metadata.get("endpoints", [])),
    }


def cleanup_service(
    metadata: Mapping[str, Any],
    *,
    actor: ServiceActor,
    docker: str = "docker",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    actor.require_root()
    run_id = str(metadata.get("run_id", ""))
    runtime = metadata.get("runtime") if isinstance(metadata.get("runtime"), Mapping) else {}
    failures: list[str] = []
    if runtime.get("compose_files"):
        service_root = _compose_service_root(runtime)
        env_file, controller_env = _prepare_compose_controller(service_root)
        # Verify every container in the project carries this exact run's labels
        # before tearing it down, so a project-name collision can never delete a
        # differently-owned stack.
        ownership_error = _compose_project_owned(
            runtime, metadata.get("labels", {}),
            docker=docker, runner=runner, env_file=env_file, controller_env=controller_env,
        )
        if ownership_error:
            failures.append(ownership_error)
        else:
            argv = [docker, "compose", "--env-file", str(env_file)]
            for path in runtime["compose_files"]:
                argv.extend(["--file", str(path)])
            argv.extend([
                "--project-name", str(runtime["project"]), "down", "--volumes",
                "--remove-orphans", "--rmi", "local",
            ])
            result = _run(runner, argv, timeout=120, env=controller_env)
            if result.returncode:
                failures.append(result.stderr.strip() or "compose down failed")
    elif runtime.get("container"):
        name = str(runtime["container"])
        if _container_has_labels(name, metadata.get("labels", {}), docker=docker, runner=runner):
            result = _run(runner, [docker, "rm", "--force", name], timeout=60)
            if result.returncode and "No such" not in result.stderr:
                failures.append(result.stderr.strip() or "service container removal failed")
        image = str(runtime.get("image", ""))
        image_labels = runtime.get("image_labels", {})
        if (
            runtime.get("owns_image") is True
            and re.fullmatch(r"ctf-os-challenge:[a-f0-9]{12}", image)
        ):
            if _image_has_labels(image, image_labels, docker=docker, runner=runner):
                result = _run(runner, [docker, "image", "rm", image], timeout=60)
                if result.returncode and "No such" not in result.stderr:
                    failures.append(result.stderr.strip() or "service image removal failed")
            else:
                inspected = _run(runner, [docker, "image", "inspect", image], timeout=30)
                if inspected.returncode == 0:
                    failures.append("refusing to remove service image with mismatched labels")
    network = str(metadata.get("network", ""))
    if re.fullmatch(r"ctf-os-net-[a-z0-9_.-]+", network):
        if _network_has_labels(network, metadata.get("labels", {}), docker=docker, runner=runner):
            result = _run(runner, [docker, "network", "rm", network], timeout=30)
            if result.returncode and "not found" not in result.stderr.casefold():
                failures.append(result.stderr.strip() or "service network removal failed")
        else:
            inspected = _run(runner, [docker, "network", "inspect", network], timeout=30)
            if inspected.returncode == 0:
                failures.append("refusing to remove service network with mismatched labels")
    return {"run_id": run_id, "cleaned": not failures, "failures": failures}


def _start_dockerfile(
    spec: ServiceSpec,
    *,
    docker: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> dict[str, Any]:
    context = _scoped(spec.source, str(spec.plan.get("context", ".")), directory=True)
    dockerfile = _scoped(spec.source, str(spec.plan["source"]), directory=False)
    build_argv = [
        docker, "build", "--pull=false", "--network", "none", "--file", str(dockerfile)
    ]
    for key, value in spec.image_labels.items():
        build_argv.extend(["--label", f"{key}={value}"])
    image_exists = _image_has_labels(
        spec.image, spec.image_labels, docker=docker, runner=runner
    )
    owns_image = image_exists and spec.instance_id == "root"
    if not image_exists:
        build_argv.extend(["--tag", spec.image, str(context)])
        built = _run(runner, build_argv, timeout=900)
        if built.returncode:
            raise ServiceError(f"challenge service build failed: {built.stderr.strip()}")
        owns_image = True
    argv = [
        docker, "run", "--detach", "--name", spec.container,
        "--network", spec.network, "--network-alias", "challenge",
        "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
        "--tmpfs", "/work:rw,exec,nosuid,nodev,size=256m,mode=1777",
        "--tmpfs", "/evidence:rw,nosuid,nodev,size=64m,mode=1777",
        "--tmpfs", "/artifacts:rw,nosuid,nodev,size=64m,mode=1777",
        "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
        "--pids-limit", "512", "--memory", "2g", "--cpus", "2",
    ]
    for key, value in spec.labels.items():
        argv.extend(["--label", f"{key}={value}"])
    argv.append(spec.image)
    started = _run(runner, argv, timeout=120)
    if started.returncode:
        if owns_image:
            _remove_owned_image(
                spec.image, spec.image_labels, docker=docker, runner=runner
            )
        raise ServiceError(f"challenge service start failed: {started.stderr.strip()}")
    running = _run(
        runner, [docker, "inspect", spec.container, "--format", "{{.State.Running}}"], timeout=30
    )
    if running.returncode or running.stdout.strip() != "true":
        logs = _run(runner, [docker, "logs", "--tail", "40", spec.container], timeout=30)
        _run(runner, [docker, "rm", "--force", spec.container], timeout=30)
        if owns_image:
            _remove_owned_image(
                spec.image, spec.image_labels, docker=docker, runner=runner
            )
        raise ServiceError(
            "challenge service exited during startup: "
            + (logs.stderr or logs.stdout or running.stderr).strip()[-4096:]
        )
    return {
        "container": spec.container,
        "image": spec.image,
        "owns_image": owns_image,
        "image_labels": spec.image_labels,
        "compose_files": [],
    }


def _start_compose(
    spec: ServiceSpec,
    *,
    docker: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> dict[str, Any]:
    source = _scoped(spec.source, str(spec.plan["source"]), directory=False)
    service_root = spec.metadata_path.parent
    override = service_root / "compose.race.yml"
    env_file, controller_env = _prepare_compose_controller(service_root)
    services: dict[str, Any] = {}
    for row in spec.plan.get("services", []):
        if not isinstance(row, Mapping):
            continue
        service = {
            "ports": _ResetList(),
            "networks": _ResetList(["ctf_os_race"]),
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "labels": spec.labels,
            "read_only": True,
            "tmpfs": ["/tmp:rw,nosuid,nodev,size=256m", "/work:rw,nosuid,nodev,size=256m"],
            "mem_limit": "2g",
            "cpus": 2,
            "pids_limit": 512,
        }
        if row.get("build") is True:
            service["build"] = {"network": "none"}
        services[str(row["name"])] = service
    document = {
        "services": services,
        "networks": {"ctf_os_race": {"external": True, "name": spec.network}},
    }
    atomic_text(override, yaml.dump(document, Dumper=_ComposeDumper, sort_keys=True))
    project_argv = [
        docker, "compose", "--env-file", str(env_file),
        "--file", str(source), "--file", str(override),
        "--project-name", spec.project,
    ]
    # Defense in depth: resolve source+override to the final config and fail
    # closed if anything crosses a host/daemon boundary before starting it.
    _verify_resolved_compose_config(project_argv, runner=runner, controller_env=controller_env)
    argv = project_argv + ["up", "--detach", "--build", "--pull", "never"]
    started = _run(runner, argv, timeout=900, env=controller_env)
    if started.returncode:
        raise ServiceError(f"challenge compose start failed: {started.stderr.strip()}")
    running = _run(
        runner,
        [
            docker, "compose", "--env-file", str(env_file),
            "--file", str(source), "--file", str(override),
            "--project-name", spec.project, "ps", "--status", "running", "--quiet",
        ],
        timeout=30,
        env=controller_env,
    )
    expected = len(services)
    if running.returncode or len([line for line in running.stdout.splitlines() if line]) != expected:
        raise ServiceError(
            "challenge compose service did not become fully running: "
            + (running.stderr or running.stdout).strip()[-4096:]
        )
    return {
        "compose_files": [str(source), str(override)],
        "project": spec.project,
        "service_count": expected,
        "compose_env_file": str(env_file),
    }


def _verify_resolved_compose_config(
    project_argv: Sequence[str],
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]],
    controller_env: Mapping[str, str],
) -> None:
    """Fail closed if the fully-resolved compose config crosses a host boundary."""

    result = _run(
        runner, list(project_argv) + ["config", "--format", "json"],
        timeout=60, env=controller_env,
    )
    if result.returncode:
        raise ServiceError(
            "challenge compose config could not be resolved for verification: "
            + (result.stderr or result.stdout).strip()[-2048:]
        )
    try:
        config = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise ServiceError("resolved compose config is not valid JSON") from exc
    if not isinstance(config, Mapping):
        raise ServiceError("resolved compose config has an unexpected shape")
    reasons = _scan_resolved_config(config)
    if reasons:
        raise ServiceError(
            "resolved compose config crosses a host/daemon boundary: "
            + "; ".join(sorted(set(reasons)))
        )


def _scan_resolved_config(config: Mapping[str, Any]) -> list[str]:
    reasons: list[str] = []
    services = config.get("services")
    if isinstance(services, Mapping):
        for name, service in services.items():
            if not isinstance(service, Mapping):
                continue
            if service.get("privileged") is True:
                reasons.append(f"service {name} resolves to privileged")
            for key in ("network_mode", "pid", "ipc", "uts"):
                value = str(service.get(key) or "")
                if value.startswith(("host", "container:")) or ":host" in value:
                    reasons.append(f"service {name} resolves to host/shared {key}")
            if service.get("userns_mode"):
                reasons.append(f"service {name} sets userns_mode")
            if service.get("cap_add"):
                reasons.append(f"service {name} adds capabilities")
            if service.get("devices"):
                reasons.append(f"service {name} maps host devices")
            if service.get("device_requests") or service.get("gpus"):
                reasons.append(f"service {name} requests device passthrough")
            for opt in service.get("security_opt") or []:
                collapsed = str(opt).replace(" ", "").casefold()
                if any(token in collapsed for token in (
                    "seccomp=unconfined", "apparmor=unconfined",
                    "no-new-privileges:false", "systempaths=unconfined",
                )):
                    reasons.append(f"service {name} relaxes security_opt")
            hosts = service.get("extra_hosts")
            host_entries = (
                list(hosts.items()) if isinstance(hosts, Mapping)
                else list(hosts) if isinstance(hosts, (list, tuple)) else []
            )
            if any("host-gateway" in str(entry) for entry in host_entries):
                reasons.append(f"service {name} maps a host-gateway alias")
            for volume in service.get("volumes") or []:
                if isinstance(volume, Mapping):
                    source = str(volume.get("source") or "")
                    if volume.get("type") == "bind":
                        reasons.append(f"service {name} bind-mounts host path {source}")
                    if "docker.sock" in source:
                        reasons.append(f"service {name} mounts the Docker socket")
                else:
                    text = str(volume)
                    source = text.split(":", 1)[0]
                    if source.startswith(("/", "~", ".")):
                        reasons.append(f"service {name} bind-mounts a host path")
                    if "docker.sock" in text:
                        reasons.append(f"service {name} mounts the Docker socket")
    networks = config.get("networks")
    if isinstance(networks, Mapping):
        for network_name, settings in networks.items():
            # ctf_os_race is the controller-created internal race network.
            if network_name == "ctf_os_race":
                continue
            if isinstance(settings, Mapping) and settings.get("external"):
                reasons.append(f"network {network_name} is external")
    volumes = config.get("volumes")
    if isinstance(volumes, Mapping):
        for volume_name, settings in volumes.items():
            if isinstance(settings, Mapping) and (settings.get("external") or settings.get("driver_opts")):
                reasons.append(f"volume {volume_name} is external or host-bound")
    return reasons


def _ensure_network(
    spec: ServiceSpec,
    *,
    docker: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    inspected = _run(runner, [docker, "network", "inspect", spec.network], timeout=30)
    if inspected.returncode == 0:
        try:
            labels = json.loads(inspected.stdout)[0].get("Labels", {}) or {}
            internal = json.loads(inspected.stdout)[0].get("Internal") is True
        except (json.JSONDecodeError, IndexError, TypeError) as exc:
            raise ServiceError("Docker returned malformed service network data") from exc
        if not internal or any(labels.get(key) != value for key, value in spec.labels.items()):
            raise ServiceError("existing service network does not belong to this exact run")
        return
    argv = [docker, "network", "create", "--internal"]
    for key, value in spec.labels.items():
        argv.extend(["--label", f"{key}={value}"])
    argv.append(spec.network)
    created = _run(runner, argv, timeout=30)
    if created.returncode:
        raise ServiceError(f"service network creation failed: {created.stderr.strip()}")


def _service_running(
    metadata: Mapping[str, Any],
    *,
    docker: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> bool:
    runtime = metadata.get("runtime") if isinstance(metadata.get("runtime"), Mapping) else {}
    if runtime.get("container"):
        labels = metadata.get("labels", {})
        if not _container_has_labels(
            str(runtime["container"]), labels, docker=docker, runner=runner
        ):
            return False
        result = _run(
            runner,
            [docker, "inspect", str(runtime["container"]), "--format", "{{.State.Running}}"],
            timeout=20,
        )
        return result.returncode == 0 and result.stdout.strip() == "true"
    if runtime.get("compose_files"):
        service_root = _compose_service_root(runtime)
        env_file, controller_env = _prepare_compose_controller(service_root)
        argv = [docker, "compose", "--env-file", str(env_file)]
        for path in runtime["compose_files"]:
            argv.extend(["--file", str(path)])
        argv.extend(["--project-name", str(runtime["project"]), "ps", "--status", "running", "--quiet"])
        result = _run(runner, argv, timeout=30, env=controller_env)
        running = len([line for line in result.stdout.splitlines() if line])
        return (
            result.returncode == 0
            and running == int(runtime.get("service_count", 0))
            and running > 0
        )
    return False


def _compose_project_owned(
    runtime: Mapping[str, Any],
    expected_labels: object,
    *,
    docker: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
    env_file: Path,
    controller_env: Mapping[str, str],
) -> str | None:
    """Return an error string if the compose project is not exactly this run's.

    Enumerates every container the project owns and requires each to carry the
    full CTF-OS label set before any teardown runs. Returns None when cleanup is
    safe (verified-owned or already gone).
    """

    expected = expected_labels if isinstance(expected_labels, Mapping) else {}
    if not expected:
        return "compose cleanup has no ownership labels to verify"
    argv = [docker, "compose", "--env-file", str(env_file)]
    for path in runtime["compose_files"]:
        argv.extend(["--file", str(path)])
    argv.extend(["--project-name", str(runtime["project"]), "ps", "--all", "--quiet"])
    result = _run(runner, argv, timeout=30, env=controller_env)
    if result.returncode:
        return "cannot enumerate compose project containers before cleanup"
    ids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not ids:
        return None
    for container_id in ids:
        if not _container_has_labels(container_id, expected, docker=docker, runner=runner):
            return "refusing to remove compose project with unowned or mismatched containers"
    return None


def _container_has_labels(
    name: str,
    labels: object,
    *,
    docker: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> bool:
    result = _run(runner, [docker, "inspect", name], timeout=30)
    if result.returncode:
        return False
    try:
        actual = json.loads(result.stdout)[0].get("Config", {}).get("Labels", {}) or {}
    except (json.JSONDecodeError, IndexError, TypeError):
        return False
    expected = labels if isinstance(labels, Mapping) else {}
    return bool(expected) and all(actual.get(key) == value for key, value in expected.items())


def _image_has_labels(
    image: str,
    labels: object,
    *,
    docker: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> bool:
    result = _run(runner, [docker, "image", "inspect", image], timeout=30)
    if result.returncode:
        return False
    try:
        actual = json.loads(result.stdout)[0].get("Config", {}).get("Labels", {}) or {}
    except (json.JSONDecodeError, IndexError, TypeError):
        return False
    expected = labels if isinstance(labels, Mapping) else {}
    return bool(expected) and all(actual.get(key) == value for key, value in expected.items())


def _network_has_labels(
    network: str,
    labels: object,
    *,
    docker: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> bool:
    result = _run(runner, [docker, "network", "inspect", network], timeout=30)
    if result.returncode:
        return False
    try:
        actual = json.loads(result.stdout)[0].get("Labels", {}) or {}
    except (json.JSONDecodeError, IndexError, TypeError):
        return False
    expected = labels if isinstance(labels, Mapping) else {}
    return bool(expected) and all(actual.get(key) == value for key, value in expected.items())


def _remove_owned_image(
    image: str,
    labels: Mapping[str, str],
    *,
    docker: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    if _image_has_labels(image, labels, docker=docker, runner=runner):
        _run(runner, [docker, "image", "rm", image], timeout=60)


def _cleanup_failed_start(
    spec: ServiceSpec,
    *,
    kind: str,
    docker: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> list[str]:
    """Roll back a partial service start, returning every unrecovered failure."""

    failures: list[str] = []
    if kind == "compose":
        source = spec.source / str(spec.plan.get("source", ""))
        override = spec.metadata_path.parent / "compose.race.yml"
        if source.is_file() and override.is_file():
            env_file, controller_env = _prepare_compose_controller(
                spec.metadata_path.parent
            )
            result = _run(
                runner,
                [
                    docker, "compose", "--env-file", str(env_file),
                    "--file", str(source), "--file", str(override),
                    "--project-name", spec.project, "down", "--volumes", "--remove-orphans",
                    "--rmi", "local",
                ],
                timeout=120,
                env=controller_env,
            )
            if result.returncode:
                failures.append(result.stderr.strip() or "rollback compose down failed")
    elif kind == "dockerfile":
        if _container_has_labels(spec.container, spec.labels, docker=docker, runner=runner):
            # Reclaim anonymous volumes (e.g. from a Dockerfile VOLUME) so a failed
            # start never leaks storage.
            result = _run(runner, [docker, "rm", "--force", "--volumes", spec.container], timeout=60)
            if result.returncode and "No such" not in result.stderr:
                failures.append(result.stderr.strip() or "rollback service container removal failed")
        # _start_dockerfile removes a newly built image on its own failure
        # paths.  An existing image is race-shared and must survive a private
        # lane instance failing to start.
    if _network_has_labels(spec.network, spec.labels, docker=docker, runner=runner):
        result = _run(runner, [docker, "network", "rm", spec.network], timeout=30)
        if result.returncode and "not found" not in result.stderr.casefold():
            failures.append(result.stderr.strip() or "rollback service network removal failed")
    return failures


def _recovery_metadata(
    spec: ServiceSpec, *, kind: str, failures: Sequence[str]
) -> dict[str, Any]:
    """Structured CLEANUP_FAILED record that cleanup_service can later reclaim."""

    if kind == "compose":
        runtime: dict[str, Any] = {
            "compose_files": [
                str(spec.source / str(spec.plan.get("source", ""))),
                str(spec.metadata_path.parent / "compose.race.yml"),
            ],
            "project": spec.project,
            "service_count": max(
                1,
                len([row for row in spec.plan.get("services", []) if isinstance(row, Mapping)]),
            ),
            "compose_env_file": str(spec.metadata_path.parent / "compose.empty.env"),
        }
    else:
        runtime = {
            "container": spec.container,
            "image": spec.image,
            # An existing race-shared image is never owned by a failed private
            # instance, so recovery must not try to remove it.
            "owns_image": False,
            "image_labels": spec.image_labels,
            "compose_files": [],
        }
    return {
        "schema_version": 1,
        "status": "CLEANUP_FAILED",
        "run_id": spec.run_id,
        "challenge_id": spec.challenge_id,
        "kind": kind,
        "instance_id": spec.instance_id,
        "isolation": "private-instance",
        "network": spec.network,
        "endpoints": [],
        "lifecycle_owner": "root",
        "labels": spec.labels,
        "runtime": runtime,
        "metadata_path": str(spec.metadata_path.resolve()),
        "cleanup_failures": [str(value) for value in failures],
    }


def _validate_spec(spec: ServiceSpec) -> None:
    if spec.source.is_symlink() or not spec.source.is_dir():
        raise ServiceError("service source is missing or unsafe")
    if spec.source.stat().st_mode & 0o222:
        raise ServiceError("service source must be the read-only prepared input")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{1,127}", spec.run_id):
        raise ServiceError("service run id is invalid")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", spec.instance_id):
        raise ServiceError("service instance id is invalid")
    if spec.run_root.is_symlink():
        raise ServiceError("service run root must not be a symlink")


def _require_local_images(
    spec: ServiceSpec,
    *,
    docker: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    images = {
        str(value)
        for key in ("base_images", "runtime_images")
        for value in spec.plan.get(key, [])
    }
    missing: list[str] = []
    for image in sorted(images):
        result = _run(runner, [docker, "image", "inspect", image], timeout=30)
        if result.returncode:
            missing.append(image)
    if missing:
        raise ServiceError(
            "challenge service requires missing local images; live Solve will not pull: "
            + ", ".join(missing)
        )


def _scoped(root: Path, relative: str, *, directory: bool) -> Path:
    path = Path(relative)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts if part != "."):
        raise ServiceError("service path is not a safe input-relative path")
    target = (root / path).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError as exc:
        raise ServiceError("service path escapes prepared input") from exc
    if target.is_symlink() or (not target.is_dir() if directory else not target.is_file()):
        raise ServiceError("service path is missing or unsafe")
    return target


def _run(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    argv: Sequence[str],
    *,
    timeout: int,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        kwargs: dict[str, Any] = {
            "capture_output": True,
            "text": True,
            "timeout": timeout,
            "check": False,
        }
        if env is not None:
            kwargs["env"] = dict(env)
        return runner(list(argv), **kwargs)
    except FileNotFoundError as exc:
        raise ServiceError(f"required executable not found: {argv[0]}") from exc
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ServiceError(f"service controller command failed: {exc}") from exc


def _compose_service_root(runtime: Mapping[str, Any]) -> Path:
    configured = runtime.get("compose_env_file")
    if configured:
        return Path(str(configured)).parent
    files = runtime.get("compose_files")
    if isinstance(files, Sequence) and not isinstance(files, (str, bytes)) and files:
        return Path(str(files[-1])).parent
    raise ServiceError("compose runtime has no controller state path")


def _prepare_compose_controller(
    service_root: Path,
) -> tuple[Path, dict[str, str]]:
    if service_root.is_symlink():
        raise ServiceError("compose controller state path must not be a symlink")
    service_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    controller_home = service_root / "controller-home"
    docker_config = service_root / "docker-config"
    for path in (controller_home, docker_config):
        if path.is_symlink():
            raise ServiceError("compose controller directory must not be a symlink")
        path.mkdir(mode=0o700, exist_ok=True)
    env_file = service_root / "compose.empty.env"
    atomic_text(env_file, "")
    atomic_text(docker_config / "config.json", '{"auths":{}}\n')
    controller_env = {
        key: value
        for key in ("PATH", "LANG", "LC_ALL")
        if (value := os.environ.get(key))
    }
    controller_env.setdefault("PATH", os.defpath)
    controller_env["HOME"] = str(controller_home)
    controller_env["DOCKER_CONFIG"] = str(docker_config)
    return env_file, controller_env
