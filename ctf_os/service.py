"""Root-owned, race-scoped challenge service lifecycle."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Callable, Mapping, Sequence

import yaml

from .workspace import atomic_json, atomic_text


class ServiceError(RuntimeError):
    pass


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
            raise ServiceError("only Root may mutate shared challenge service lifecycle")


@dataclass(frozen=True, slots=True)
class ServiceSpec:
    run_id: str
    challenge_id: str
    source: Path
    run_root: Path
    plan: Mapping[str, Any]

    @property
    def suffix(self) -> str:
        return hashlib.sha256(self.run_id.encode()).hexdigest()[:12]

    @property
    def network(self) -> str:
        return f"ctf-os-net-{self.suffix}"

    @property
    def image(self) -> str:
        return f"ctf-os-challenge:{self.suffix}"

    @property
    def container(self) -> str:
        return f"ctf-os-service-{self.suffix}"

    @property
    def project(self) -> str:
        return f"ctf-os-{self.suffix}"

    @property
    def metadata_path(self) -> Path:
        return self.run_root / "service" / "service.json"

    @property
    def labels(self) -> dict[str, str]:
        return {
            "org.ctf-os.managed": "true",
            "org.ctf-os.kind": "service",
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
    if spec.metadata_path.is_file() and not spec.metadata_path.is_symlink():
        existing = load_service(spec.metadata_path)
        if existing.get("run_id") == spec.run_id and _service_running(existing, docker=docker, runner=runner):
            return existing | {"attached": True}
    _require_local_images(spec, docker=docker, runner=runner)
    service_root = spec.metadata_path.parent
    if service_root.is_symlink():
        raise ServiceError("service runtime root must not be a symlink")
    service_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    _ensure_network(spec, docker=docker, runner=runner)
    try:
        if kind == "dockerfile":
            runtime = _start_dockerfile(spec, docker=docker, runner=runner)
        elif kind == "compose":
            runtime = _start_compose(spec, docker=docker, runner=runner)
        else:
            raise ServiceError(f"unsupported service plan kind: {kind}")
    except Exception:
        _cleanup_failed_start(spec, kind=kind, docker=docker, runner=runner)
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
        "network": spec.network,
        "endpoints": endpoints,
        "lifecycle_owner": "root",
        "labels": spec.labels,
        "runtime": runtime,
        "metadata_path": str(spec.metadata_path.resolve()),
    }
    atomic_json(spec.metadata_path, metadata)
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
        argv = [docker, "compose"]
        for path in runtime["compose_files"]:
            argv.extend(["--file", str(path)])
        argv.extend([
            "--project-name", str(runtime["project"]), "down", "--volumes",
            "--remove-orphans", "--rmi", "local",
        ])
        result = _run(runner, argv, timeout=120)
        if result.returncode:
            failures.append(result.stderr.strip() or "compose down failed")
    elif runtime.get("container"):
        name = str(runtime["container"])
        if _container_has_labels(name, metadata.get("labels", {}), docker=docker, runner=runner):
            result = _run(runner, [docker, "rm", "--force", name], timeout=60)
            if result.returncode and "No such" not in result.stderr:
                failures.append(result.stderr.strip() or "service container removal failed")
        image = str(runtime.get("image", ""))
        if re.fullmatch(r"ctf-os-challenge:[a-f0-9]{12}", image):
            if _image_has_labels(image, metadata.get("labels", {}), docker=docker, runner=runner):
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
    for key, value in spec.labels.items():
        build_argv.extend(["--label", f"{key}={value}"])
    build_argv.extend(["--tag", spec.image, str(context)])
    built = _run(runner, build_argv, timeout=900)
    if built.returncode:
        raise ServiceError(f"challenge service build failed: {built.stderr.strip()}")
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
        _remove_owned_image(spec.image, spec.labels, docker=docker, runner=runner)
        raise ServiceError(f"challenge service start failed: {started.stderr.strip()}")
    running = _run(
        runner, [docker, "inspect", spec.container, "--format", "{{.State.Running}}"], timeout=30
    )
    if running.returncode or running.stdout.strip() != "true":
        logs = _run(runner, [docker, "logs", "--tail", "40", spec.container], timeout=30)
        _run(runner, [docker, "rm", "--force", spec.container], timeout=30)
        _remove_owned_image(spec.image, spec.labels, docker=docker, runner=runner)
        raise ServiceError(
            "challenge service exited during startup: "
            + (logs.stderr or logs.stdout or running.stderr).strip()[-4096:]
        )
    return {"container": spec.container, "image": spec.image, "compose_files": []}


def _start_compose(
    spec: ServiceSpec,
    *,
    docker: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> dict[str, Any]:
    source = _scoped(spec.source, str(spec.plan["source"]), directory=False)
    override = spec.metadata_path.parent / "compose.race.yml"
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
    argv = [
        docker, "compose", "--file", str(source), "--file", str(override),
        "--project-name", spec.project, "up", "--detach", "--build", "--pull", "never",
    ]
    started = _run(runner, argv, timeout=900)
    if started.returncode:
        raise ServiceError(f"challenge compose start failed: {started.stderr.strip()}")
    running = _run(
        runner,
        [
            docker, "compose", "--file", str(source), "--file", str(override),
            "--project-name", spec.project, "ps", "--status", "running", "--quiet",
        ],
        timeout=30,
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
    }


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
        argv = [docker, "compose"]
        for path in runtime["compose_files"]:
            argv.extend(["--file", str(path)])
        argv.extend(["--project-name", str(runtime["project"]), "ps", "--status", "running", "--quiet"])
        result = _run(runner, argv, timeout=30)
        running = len([line for line in result.stdout.splitlines() if line])
        return (
            result.returncode == 0
            and running == int(runtime.get("service_count", 0))
            and running > 0
        )
    return False


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
) -> None:
    if kind == "compose":
        source = spec.source / str(spec.plan.get("source", ""))
        override = spec.metadata_path.parent / "compose.race.yml"
        if source.is_file() and override.is_file():
            _run(
                runner,
                [
                    docker, "compose", "--file", str(source), "--file", str(override),
                    "--project-name", spec.project, "down", "--volumes", "--remove-orphans",
                    "--rmi", "local",
                ],
                timeout=120,
            )
    elif kind == "dockerfile":
        if _container_has_labels(spec.container, spec.labels, docker=docker, runner=runner):
            _run(runner, [docker, "rm", "--force", spec.container], timeout=60)
        _remove_owned_image(spec.image, spec.labels, docker=docker, runner=runner)
    if _network_has_labels(spec.network, spec.labels, docker=docker, runner=runner):
        _run(runner, [docker, "network", "rm", spec.network], timeout=30)


def _validate_spec(spec: ServiceSpec) -> None:
    if spec.source.is_symlink() or not spec.source.is_dir():
        raise ServiceError("service source is missing or unsafe")
    if spec.source.stat().st_mode & 0o222:
        raise ServiceError("service source must be the read-only prepared input")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{1,127}", spec.run_id):
        raise ServiceError("service run id is invalid")


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
    runner: Callable[..., subprocess.CompletedProcess[str]], argv: Sequence[str], *, timeout: int
) -> subprocess.CompletedProcess[str]:
    try:
        return runner(list(argv), capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise ServiceError(f"required executable not found: {argv[0]}") from exc
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ServiceError(f"service controller command failed: {exc}") from exc
