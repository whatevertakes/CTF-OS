"""Challenge-local, non-executing input preparation."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any, Mapping

import yaml

from .archive import (
    ArchiveError,
    ArchiveLimits,
    bounded_source_files,
    copy_tree_without_links,
    extract_archive,
)
from .contest import ChallengeSpec, ContestManifest
from .sandbox.network import parse_remotes
from .workspace import atomic_json


ARCHIVE_SUFFIXES = (
    ".zip", ".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2",
)
LIMITS = {
    "standard": ArchiveLimits(),
    "large": ArchiveLimits(max_files=20_000, max_file_bytes=2 * 1024**3, max_total_bytes=8 * 1024**3),
    "large-forensic": ArchiveLimits(max_files=100_000, max_file_bytes=16 * 1024**3, max_total_bytes=64 * 1024**3),
}
PRIORITY_LIMIT = 20
MAX_SERVICE_DESCRIPTOR_BYTES = 1024 * 1024


class PreflightError(ValueError):
    pass


def challenge_sources(manifest: ContestManifest, challenge: ChallengeSpec) -> tuple[Path, ...]:
    category = manifest.path.parent / challenge.category
    if category.is_symlink() or not category.is_dir():
        return ()
    wanted = {challenge.name.casefold(), challenge.workspace_name.casefold()}
    matches: list[Path] = []
    for entry in category.iterdir():
        if entry.is_symlink():
            continue
        if entry.is_dir() and entry.name.casefold() in wanted:
            matches.append(entry)
            continue
        if entry.is_file():
            lower = entry.name.casefold()
            if any(lower.endswith(suffix) and lower[: -len(suffix)] in wanted for suffix in ARCHIVE_SUFFIXES):
                matches.append(entry)
    return tuple(sorted(matches, key=lambda value: value.name.casefold()))


def input_fingerprint(manifest: ContestManifest, challenge: ChallengeSpec) -> str:
    sources = challenge_sources(manifest, challenge)
    if not sources and not challenge.remotes:
        raise PreflightError("challenge has neither a matching input nor a declared target")
    digest = hashlib.sha256()
    identity = {
        "contest": manifest.slug,
        "challenge_id": challenge.id,
        "category": challenge.category,
        "name": challenge.name,
        "description": challenge.description,
        "hint": challenge.hint,
        "remotes": list(challenge.remotes),
        "flag_pattern": challenge.flag_pattern,
        "input_profile": challenge.input_profile,
    }
    digest.update(json.dumps(identity, ensure_ascii=False, sort_keys=True).encode())
    limits = LIMITS[challenge.input_profile]
    for source in sources:
        digest.update(("D\0" if source.is_dir() else "F\0").encode())
        digest.update(source.name.encode())
        if source.is_file():
            digest.update(bytes.fromhex(file_hash(source)))
            continue
        total = 0
        for path in bounded_source_files(source, limits):
            total += path.stat().st_size
            if total > limits.max_total_bytes:
                raise PreflightError("challenge input exceeds its bounded profile")
            digest.update(path.relative_to(source).as_posix().encode())
            digest.update(bytes.fromhex(file_hash(path)))
    return digest.hexdigest()


def prepare_input(
    manifest: ContestManifest,
    challenge: ChallengeSpec,
    run_root: Path,
    *,
    expected_fingerprint: str,
) -> dict[str, Any]:
    """Materialize only the selected challenge into this fresh run."""

    if input_fingerprint(manifest, challenge) != expected_fingerprint:
        raise PreflightError("challenge input changed between selection and materialization")
    destination = run_root / "input"
    if destination.exists() or destination.is_symlink():
        raise PreflightError("fresh run input path already exists")
    staging = Path(tempfile.mkdtemp(prefix=".input-", dir=run_root))
    archives: list[dict[str, Any]] = []
    limits = LIMITS[challenge.input_profile]
    try:
        for source in challenge_sources(manifest, challenge):
            if source.is_dir():
                copy_tree_without_links(source, staging, limits)
            else:
                members = extract_archive(source, staging, limits)
                archives.append({
                    "name": source.name,
                    "sha256": file_hash(source),
                    "bytes": source.stat().st_size,
                    "members": len(members),
                })
        _validate_tree(staging, limits)
        _make_read_only(staging)
        os.replace(staging, destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    inventory = inventory_tree(destination)
    prepared_fingerprint = tree_hash(destination)
    targets = [target.to_dict() for target in parse_remotes(challenge.remotes)]
    service_plan = detect_service(destination, challenge.category)
    record: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_fingerprint": expected_fingerprint,
        "prepared_fingerprint": prepared_fingerprint,
        "prepared_input": str(destination),
        "read_only": True,
        "files": inventory,
        "file_count": len(inventory),
        "total_bytes": sum(int(row["size"]) for row in inventory),
        "archives": archives,
        "priority_files": _priority_files(inventory),
        "declared_targets": targets,
        "service_plan": service_plan,
    }
    atomic_json(run_root / "INPUT.json", record)
    return record


def validate_prepared_input(run_root: Path) -> tuple[Path, dict[str, Any]]:
    path = run_root / "input"
    record_path = run_root / "INPUT.json"
    if path.is_symlink() or not path.is_dir() or record_path.is_symlink() or not record_path.is_file():
        raise PreflightError("prepared input is missing or unsafe")
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PreflightError("prepared input record is unreadable") from exc
    if not isinstance(record, dict) or record.get("schema_version") != 1:
        raise PreflightError("prepared input record schema is unsupported")
    if Path(str(record.get("prepared_input"))).resolve() != path.resolve():
        raise PreflightError("prepared input record escapes this run")
    if record.get("prepared_fingerprint") != tree_hash(path):
        raise PreflightError("prepared input was modified after materialization")
    for item in path.rglob("*"):
        if item.is_symlink():
            raise PreflightError("prepared input contains a symlink")
        if item.stat().st_mode & 0o222:
            raise PreflightError("prepared input is not read-only")
    return path, record


def inventory_tree(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in bounded_source_files(root, LIMITS["large-forensic"]):
        relative = path.relative_to(root).as_posix()
        rows.append({
            "path": relative,
            "size": path.stat().st_size,
            "sha256": file_hash(path),
            "mime": mimetypes.guess_type(relative)[0] or "application/octet-stream",
        })
    return rows


def tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for row in inventory_tree(root):
        digest.update(str(row["path"]).encode())
        digest.update(int(row["size"]).to_bytes(8, "big"))
        digest.update(bytes.fromhex(str(row["sha256"])))
    return digest.hexdigest()


def file_hash(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise PreflightError(f"input file is unsafe: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def detect_service(input_root: Path, category: str) -> dict[str, Any]:
    dockerfiles = sorted(
        (path for path in input_root.rglob("Dockerfile") if path.is_file() and not path.is_symlink()),
        key=lambda value: value.relative_to(input_root).as_posix(),
    )
    compose = [
        path for name in ("compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml")
        for path in input_root.rglob(name) if path.is_file() and not path.is_symlink()
    ]
    compose.sort(key=lambda value: value.relative_to(input_root).as_posix())
    if compose:
        return _compose_plan(input_root, compose[0], category)
    if dockerfiles:
        relative = dockerfiles[0].relative_to(input_root)
        try:
            text = _read_service_descriptor(dockerfiles[0], errors="replace")
        except PreflightError as exc:
            return {
                "kind": "dockerfile", "safe": False, "source": relative.as_posix(),
                "services": [], "review_reasons": [str(exc)],
            }
        ports = _dockerfile_ports(text)
        if not ports:
            return {
                "kind": "none", "safe": True, "services": [],
                "review_reasons": ["Dockerfile has no declared service port and remains input-only"],
            }
        bases, base_reasons = _dockerfile_bases(text)
        return {
            "kind": "dockerfile",
            "safe": not base_reasons,
            "source": relative.as_posix(),
            "context": relative.parent.as_posix() or ".",
            "base_images": bases,
            "services": [{
                "name": "challenge",
                "ports": ports,
                "endpoints": _endpoints("challenge", ports, category),
            }],
            "review_reasons": base_reasons,
        }
    return {"kind": "none", "safe": True, "services": [], "review_reasons": []}


def _compose_plan(input_root: Path, path: Path, category: str) -> dict[str, Any]:
    relative = path.relative_to(input_root).as_posix()
    try:
        document = yaml.safe_load(_read_service_descriptor(path)) or {}
    except (OSError, UnicodeDecodeError, yaml.YAMLError, PreflightError) as exc:
        return {"kind": "compose", "safe": False, "source": relative, "services": [], "review_reasons": [str(exc)]}
    raw_services = document.get("services") if isinstance(document, Mapping) else None
    if not isinstance(raw_services, Mapping) or not raw_services:
        return {"kind": "compose", "safe": False, "source": relative, "services": [], "review_reasons": ["compose has no services"]}
    reasons: list[str] = []
    if isinstance(document, Mapping) and document.get("include"):
        reasons.append("compose requests external include files")
    services: list[dict[str, Any]] = []
    base_images: set[str] = set()
    runtime_images: set[str] = set()
    for section in ("networks", "volumes", "configs", "secrets"):
        entries = document.get(section) if isinstance(document, Mapping) else None
        if not isinstance(entries, Mapping):
            continue
        for name, settings in entries.items():
            if isinstance(settings, Mapping) and (settings.get("external") or settings.get("name")):
                reasons.append(f"top-level {section} {name} references a non-project-scoped resource")
            if section == "volumes" and isinstance(settings, Mapping) and (
                settings.get("driver") or settings.get("driver_opts")
            ):
                reasons.append(f"top-level volume {name} requests a custom driver or host path")
    for name, raw in raw_services.items():
        if not isinstance(raw, Mapping):
            reasons.append(f"service {name} is not a mapping")
            continue
        if raw.get("privileged") is True:
            reasons.append(f"service {name} requests privileged mode")
        for key in ("network_mode", "pid", "ipc", "userns_mode", "uts", "cgroup", "runtime"):
            if raw.get(key):
                reasons.append(f"service {name} requests explicit {key}")
        for key in (
            "use_api_socket", "volumes_from", "logging", "security_opt",
            "credential_spec", "device_cgroup_rules", "extends", "label_file",
            "gpus", "group_add", "cgroup_parent", "sysctls", "ulimits",
            "oom_score_adj", "isolation", "volume_driver",
        ):
            if raw.get(key):
                reasons.append(f"service {name} requests unsafe {key}")
        if raw.get("devices"):
            reasons.append(f"service {name} requests host devices")
        if raw.get("cap_add"):
            reasons.append(f"service {name} requests added capabilities")
        for key in ("extra_hosts", "external_links", "secrets", "configs"):
            if raw.get(key):
                reasons.append(f"service {name} requests unsafe {key}")
        if raw.get("build"):
            build_bases, build_reasons = _compose_build(input_root, path.parent, raw["build"])
            base_images.update(build_bases)
            reasons.extend(f"service {name} {reason}" for reason in build_reasons)
        elif raw.get("image"):
            image = str(raw["image"])
            if "$" in image:
                reasons.append(f"service {name} uses a dynamic image reference")
            else:
                runtime_images.add(image)
        env_files = raw.get("env_file") or []
        if isinstance(env_files, (str, Mapping)):
            env_files = [env_files]
        for env_file in env_files:
            value = env_file.get("path") if isinstance(env_file, Mapping) else env_file
            if not _compose_reference_is_scoped(input_root, path.parent, str(value or ""), file=True):
                reasons.append(f"service {name} env_file escapes prepared input")
        for volume in raw.get("volumes") or []:
            if isinstance(volume, Mapping):
                text = str(volume.get("source") or "")
                if volume.get("type") == "bind":
                    reasons.append(f"service {name} requests a host bind mount")
            else:
                text = str(volume)
            if "$" in text:
                reasons.append(f"service {name} uses a dynamic volume reference")
            if "/var/run/docker.sock" in text:
                reasons.append(f"service {name} requests the Docker socket")
            source = text.split(":", 1)[0]
            if source.startswith(("/", "~", ".")) or "/" in source or "\\" in source:
                reasons.append(f"service {name} requests a host bind mount")
        ports = _compose_ports(raw)
        services.append({
            "name": str(name),
            "ports": ports,
            "endpoints": _endpoints(str(name), ports, category),
            "build": bool(raw.get("build")),
        })
    if services and not any(service["ports"] for service in services):
        reasons.append("compose declares no challenge service port")
    return {
        "kind": "compose",
        "safe": not reasons,
        "source": relative,
        "base_images": sorted(base_images),
        "runtime_images": sorted(runtime_images),
        "services": services,
        "review_reasons": sorted(set(reasons)),
    }


def _compose_ports(raw: Mapping[str, Any]) -> list[int]:
    result: set[int] = set()
    for value in list(raw.get("expose") or []) + list(raw.get("ports") or []):
        if isinstance(value, Mapping):
            candidate = value.get("target")
        else:
            candidate = str(value).split("/", 1)[0].rsplit(":", 1)[-1].split("-", 1)[0]
        try:
            number = int(candidate)
        except (TypeError, ValueError):
            continue
        if 0 < number < 65536:
            result.add(number)
    return sorted(result)


def _dockerfile_ports(text: str) -> list[int]:
    result: set[int] = set()
    for line in text.splitlines():
        if not line.strip().casefold().startswith("expose "):
            continue
        for value in line.strip().split()[1:]:
            try:
                port = int(value.split("/", 1)[0])
            except ValueError:
                continue
            if 0 < port < 65536:
                result.add(port)
    return sorted(result)


def _dockerfile_bases(text: str) -> tuple[list[str], list[str]]:
    images: list[str] = []
    stages: set[str] = set()
    reasons: list[str] = []
    for raw in text.splitlines():
        match = re.match(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$", raw, re.I)
        if not match:
            continue
        image, stage = match.group(1), match.group(2)
        if "$" in image:
            reasons.append("Dockerfile uses a dynamic FROM image")
        elif image.casefold() != "scratch" and image.casefold() not in stages:
            images.append(image)
        if stage:
            stages.add(stage.casefold())
    if not images and not any(line.lstrip().upper().startswith("FROM ") for line in text.splitlines()):
        reasons.append("Dockerfile has no bounded FROM instruction")
    return sorted(set(images)), reasons


def _compose_build(
    input_root: Path, compose_root: Path, value: object
) -> tuple[list[str], list[str]]:
    reasons: list[str] = []
    if isinstance(value, str):
        context_value = value
        dockerfile_value = "Dockerfile"
    elif isinstance(value, Mapping):
        context_value = str(value.get("context", "."))
        dockerfile_value = str(value.get("dockerfile", "Dockerfile"))
        for key in (
            "ssh", "secrets", "additional_contexts", "entitlements",
            "dockerfile_inline",
        ):
            if value.get(key):
                reasons.append(f"build requests {key}")
    else:
        return [], ["build must be a local string or mapping"]
    if not _compose_reference_is_scoped(input_root, compose_root, context_value, file=False):
        return [], reasons + ["build context escapes prepared input"]
    context = (compose_root / context_value).resolve()
    dockerfile = (context / dockerfile_value).resolve()
    try:
        dockerfile.relative_to(input_root.resolve())
    except ValueError:
        return [], reasons + ["build Dockerfile escapes prepared input"]
    if dockerfile.is_symlink() or not dockerfile.is_file():
        return [], reasons + ["build Dockerfile is missing or unsafe"]
    try:
        text = _read_service_descriptor(dockerfile, errors="replace")
    except PreflightError as exc:
        return [], reasons + [str(exc)]
    bases, base_reasons = _dockerfile_bases(text)
    return bases, reasons + base_reasons


def _read_service_descriptor(path: Path, *, errors: str = "strict") -> str:
    if path.is_symlink() or not path.is_file():
        raise PreflightError("service descriptor is missing or unsafe")
    if path.stat().st_size > MAX_SERVICE_DESCRIPTOR_BYTES:
        raise PreflightError(
            f"service descriptor exceeds {MAX_SERVICE_DESCRIPTOR_BYTES} bytes"
        )
    return path.read_text(encoding="utf-8", errors=errors)


def _compose_reference_is_scoped(
    input_root: Path, relative_root: Path, value: str, *, file: bool
) -> bool:
    if not value or "://" in value or value.startswith(("~", "/")):
        return False
    target = (relative_root / value).resolve()
    try:
        target.relative_to(input_root.resolve())
    except ValueError:
        return False
    return not target.is_symlink() and (target.is_file() if file else target.is_dir())


def _endpoints(host: str, ports: list[int], category: str) -> list[str]:
    scheme = "http" if category == "web" else "tcp"
    return [f"{scheme}://{host}:{port}" for port in ports]


def _priority_files(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def rank(row: Mapping[str, Any]) -> tuple[int, int, str]:
        name = str(row["path"]).casefold()
        score = 0
        if name.endswith(("dockerfile", "compose.yml", "compose.yaml")):
            score += 100
        if name.endswith((".py", ".c", ".cc", ".cpp", ".js", ".ts", ".php", ".go", ".rs")):
            score += 70
        if any(token in name for token in ("chall", "main", "server", "app", "flag", "readme")):
            score += 30
        return (-score, int(row["size"]), name)
    return [dict(row) for row in sorted(files, key=rank)[:PRIORITY_LIMIT]]


def _validate_tree(root: Path, limits: ArchiveLimits) -> None:
    files = bounded_source_files(root, limits)
    total = sum(path.stat().st_size for path in files)
    if total > limits.max_total_bytes:
        raise ArchiveError("materialized challenge exceeds its total size limit")


def _make_read_only(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)
    root.chmod(0o555)
