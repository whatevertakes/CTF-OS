"""Deep-ready, deterministic intake for every challenge in one contest."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any

import yaml

from .archive import ArchiveError, ArchiveLimits, bounded_source_files, copy_tree_without_links, extract_archive
from .contest import ChallengeSpec, ContestManifest, discover_contests, select_contest
from .sandbox.network import parse_remotes
from .workspace import atomic_json, atomic_text, bind_input_fingerprint, challenge_root


ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2", ".7z", ".rar")
CONTEXT_FILE_LIMIT = 20
_ARCHIVE_LIMITS = {
    "standard": ArchiveLimits(),
    "large": ArchiveLimits(max_files=20_000, max_file_bytes=2 * 1024**3, max_total_bytes=8 * 1024**3),
    "large-forensic": ArchiveLimits(max_files=100_000, max_file_bytes=16 * 1024**3, max_total_bytes=64 * 1024**3),
}


def run_intake(repo: str | Path, contest_selector: str | None = None) -> dict[str, object]:
    root = Path(repo).resolve()
    manifest = select_contest(discover_contests(root / "incoming"), contest_selector)
    records = [_inspect_challenge(root, manifest, challenge) for challenge in manifest.challenges]
    payload: dict[str, object] = {
        "schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
        "contest": manifest.to_dict(), "challenges": records,
        "summary": {
            "total": len(records), "ready": sum(r["status"] == "READY" for r in records),
            "blocked": sum(r["status"] == "BLOCKED" for r in records),
        },
    }
    contest_output = root / "output" / manifest.slug
    atomic_json(contest_output / "intake.json", payload)
    atomic_text(contest_output / "INTAKE.md", render_intake_markdown(payload))
    return payload


def _inspect_challenge(root: Path, manifest: ContestManifest, challenge: ChallengeSpec) -> dict[str, object]:
    destination = challenge_root(root, manifest, challenge)
    base: dict[str, object] = challenge.to_dict() | {
        "status": "BLOCKED", "blockers": [], "authorized_targets": [],
        "source_paths": [], "files": [], "archives": [], "docker": {},
        "runtime": [], "subtype": None, "attack_surface": [], "hypotheses": [],
        "recommended_tools": [], "read_paths": [], "read_on_demand": [],
        "state_summary": {"status": "PREPARED", "branches": 0, "flag_candidate": False},
        "context_path": str(destination / "CONTEXT.md"),
        "inventory_path": str(destination / "inventory.json"),
        "priority_files": [], "priority_file_metadata": [], "important_metadata": {},
        "recommended_image": "ctf-os-sandbox:base", "recommended_resource_profile": "light",
        "containerized_challenge": False, "service_plan": {"kind": "none", "status": "UNAVAILABLE", "safe_to_start": False, "services": []},
        "workspace_path": str(destination), "prepared_input": str(destination / "input"),
        "source_fingerprint": None, "prepared_fingerprint": None,
    }
    try:
        base["authorized_targets"] = [target.to_dict() for target in parse_remotes(challenge.remotes)]
        sources = _match_sources(manifest, challenge)
        base["source_paths"] = [str(path) for path in sources]
        if not sources and not challenge.remotes:
            raise ValueError("contest.md entry has no matching directory/archive and no authorized remote")
        input_dir, archive_records, fingerprint, prepared_fingerprint = _materialize(destination, challenge, sources)
        base["archives"] = archive_records
        base["source_fingerprint"] = fingerprint
        base["prepared_fingerprint"] = prepared_fingerprint
        files = [_inspect_file(input_dir, path) for path in _regular_files(input_dir)] if input_dir.exists() else []
        base["files"] = files
        atomic_json(destination / "inventory.json", {"schema_version": 1, "files": files})
        preflight = _preflight(challenge, input_dir, files)
        base.update(preflight)
        base["read_paths"] = [
            str(manifest.path), str(destination / "CONTEXT.md"),
            str(destination / "STATE.json"), str(destination / "FINDINGS.md"),
        ]
        base["read_on_demand"] = [
            str(input_dir), str(destination / "inventory.json"),
            str(destination / "evidence.log"), str(destination / "workers"),
        ]
        base["status"] = "READY"
        destination.mkdir(parents=True, exist_ok=True)
        bind_input_fingerprint(destination, challenge, fingerprint)
        atomic_text(destination / "CONTEXT.md", render_context(manifest, base))
    except Exception as exc:
        base["blockers"] = [str(exc)]
        destination.mkdir(parents=True, exist_ok=True)
        atomic_text(destination / "CONTEXT.md", render_context(manifest, base))
    return base


def _match_sources(manifest: ContestManifest, challenge: ChallengeSpec) -> list[Path]:
    category_root = manifest.path.parent / challenge.category
    if not category_root.exists() and challenge.category == "forensic":
        alias = manifest.path.parent / "forensics"
        category_root = alias if alias.exists() else category_root
    if not category_root.is_dir() or category_root.is_symlink():
        return []
    wanted = {challenge.name.casefold(), challenge.workspace_name.casefold()}
    matches: list[Path] = []
    for entry in category_root.iterdir():
        if entry.is_symlink():
            continue
        if entry.is_dir() and entry.name.casefold() in wanted:
            matches.append(entry)
            continue
        if entry.is_file():
            lower = entry.name.casefold()
            for suffix in ARCHIVE_SUFFIXES:
                if lower.endswith(suffix) and lower[:-len(suffix)] in wanted:
                    matches.append(entry)
                    break
    return sorted(matches, key=lambda path: path.name.casefold())


def _materialize(destination: Path, challenge: ChallengeSpec, sources: list[Path]) -> tuple[Path, list[dict[str, object]], str, str]:
    limits = _ARCHIVE_LIMITS[challenge.input_profile]
    fingerprint = _source_fingerprint(challenge, sources)
    input_dir = destination / "input"
    marker = destination / ".input-fingerprint"
    if input_dir.is_symlink() or marker.is_symlink():
        raise ArchiveError("prepared input or fingerprint marker must not be a symlink")
    if input_dir.is_dir() and marker.is_file() and marker.read_text() == fingerprint:
        metadata_path = destination / ".archive-metadata.json"
        cached = json.loads(metadata_path.read_text(encoding="utf-8")) if metadata_path.is_file() else _archive_metadata(sources)
        return input_dir, cached, fingerprint, prepared_tree_fingerprint(input_dir)
    destination.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".input-", dir=destination))
    archives: list[dict[str, object]] = []
    try:
        for source in sources:
            if source.is_dir():
                copy_tree_without_links(source, staging, limits)
            else:
                lower = source.name.casefold()
                if lower.endswith((".7z", ".rar")):
                    raise ArchiveError(f"{source.name}: safe built-in extraction is unavailable; unpack it into a named directory")
                members = extract_archive(source, staging, limits)
                archives.append({"path": str(source), "sha256": _sha256(source), "members": members, "extracted": True})
            prepared_tree_fingerprint(staging)
        _make_read_only(staging)
        old = destination / ".old-input"
        if old.exists():
            _remove_generated_tree(old)
        if input_dir.exists():
            os.replace(input_dir, old)
        os.replace(staging, input_dir)
        if old.exists():
            _remove_generated_tree(old)
        atomic_text(marker, fingerprint)
        atomic_json(destination / ".archive-metadata.json", archives)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return input_dir, archives, fingerprint, prepared_tree_fingerprint(input_dir)


def _source_fingerprint(challenge: ChallengeSpec, sources: list[Path]) -> str:
    digest = hashlib.sha256(json.dumps(challenge.to_dict(), ensure_ascii=False, sort_keys=True).encode())
    for source in sources:
        digest.update(source.name.encode())
        if source.is_file():
            digest.update(bytes.fromhex(_sha256(source)))
        else:
            total = 0
            limits = _ARCHIVE_LIMITS[challenge.input_profile]
            for path in bounded_source_files(source, limits):
                size = path.stat().st_size
                if size > limits.max_file_bytes:
                    raise ArchiveError(f"source file exceeds size limit: {path.relative_to(source)}")
                total += size
                if total > limits.max_total_bytes:
                    raise ArchiveError("source directory exceeds total size limit")
                digest.update(path.relative_to(source).as_posix().encode())
                digest.update(bytes.fromhex(_sha256(path)))
    return digest.hexdigest()


def current_source_fingerprint(manifest: ContestManifest, challenge: ChallengeSpec) -> str:
    return _source_fingerprint(challenge, _match_sources(manifest, challenge))


def prepared_tree_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    # Profile-specific limits are enforced while materializing source input.  Use
    # the largest accepted profile here so later integrity checks can hash a
    # legitimate large-forensic workspace without weakening intake extraction.
    limits = _ARCHIVE_LIMITS["large-forensic"]
    for path in bounded_source_files(root, limits):
        size = path.stat().st_size
        if size > limits.max_file_bytes:
            raise ArchiveError(f"prepared file exceeds size limit: {path.relative_to(root)}")
        total += size
        if total > limits.max_total_bytes:
            raise ArchiveError("prepared input exceeds total size limit")
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(bytes.fromhex(_sha256(path)))
    return digest.hexdigest()


def _archive_metadata(sources: list[Path]) -> list[dict[str, object]]:
    return [{"path": str(path), "sha256": _sha256(path), "extracted": True} for path in sources if path.is_file()]


def _regular_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    result: list[Path] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ArchiveError(f"symlink found in prepared input: {path}")
        if path.is_file():
            result.append(path)
    return sorted(result, key=lambda path: path.relative_to(root).as_posix())


def _inspect_file(root: Path, path: Path) -> dict[str, object]:
    kind = _command_output(["file", "-b", str(path)]) or "unknown"
    mime = _command_output(["file", "-b", "--mime-type", str(path)]) or mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    record: dict[str, object] = {
        "path": path.relative_to(root).as_posix(), "size": path.stat().st_size,
        "sha256": _sha256(path), "mime": mime, "kind": kind,
    }
    with path.open("rb") as handle:
        magic = handle.read(4)
    if magic == b"\x7fELF":
        header = _command_output(["readelf", "-h", str(path)], limit=64_000)
        program = _command_output(["readelf", "-W", "-l", str(path)], limit=64_000)
        dynamic = _command_output(["readelf", "-W", "-d", str(path)], limit=64_000)
        record["elf"] = {
            "architecture": _readelf_value(header, "Machine"),
            "type": _readelf_value(header, "Type"),
            "nx": "GNU_STACK" in program and "RWE" not in program,
            "pie": "DYN" in (_readelf_value(header, "Type") or ""),
            "relro": "full" if "BIND_NOW" in dynamic else ("partial" if "GNU_RELRO" in program else "none"),
            "stripped": "stripped" in kind.casefold(),
        }
    return record


def _preflight(challenge: ChallengeSpec, input_dir: Path, files: list[dict[str, object]]) -> dict[str, object]:
    names = [str(item["path"]).casefold() for item in files]
    category = challenge.category
    dockerfiles = [str(item["path"]) for item in files if str(item["path"]).casefold().endswith("dockerfile") or "/dockerfile" in str(item["path"]).casefold()]
    compose = [str(item["path"]) for item in files if str(item["path"]).casefold().endswith(("compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"))]
    dependency_files = [name for name in names if name.endswith(("requirements.txt", "pyproject.toml", "package.json", "go.mod", "cargo.toml", "gemfile"))]
    text_sample = "\n".join(_small_text(path) for path in _regular_files(input_dir)[:100]) if input_dir.exists() else ""
    runtime: list[str] = []
    subtype = None
    if any(name.endswith(".py") for name in names): runtime.append("python")
    if "package.json" in names or any(name.endswith((".js", ".ts")) for name in names): runtime.append("node")
    if any("flask" in line.casefold() for line in text_sample.splitlines()): subtype = "Flask web application"
    elif "django" in text_sample.casefold(): subtype = "Django web application"
    elif "express" in text_sample.casefold(): subtype = "Express web application"
    elif category == "pwn" and any("elf" in str(item["kind"]).casefold() for item in files): subtype = "native ELF binary"
    elif category == "rev": subtype = "binary/static reverse engineering"
    elif category == "crypto": subtype = "cryptographic solver"
    surfaces = {
        "pwn": ["I/O protocol", "memory-corruption primitives", "mitigations and libc coupling"],
        "web": ["routes and authentication", "source-to-sink data flow", "container/dependency trust boundaries"],
        "rev": ["entry point and imports", "validation routine", "packing or anti-analysis"],
        "crypto": ["parameters and entropy", "input/output equations", "known weak construction families"],
        "forensic": ["file signatures and metadata", "embedded/recovered objects", "timeline and provenance"],
        "misc": ["file/protocol classification", "encoding layers", "runtime restrictions"],
        "cloud": ["identity and policy boundaries", "metadata/service endpoints", "deployment manifests"],
    }.get(category, ["file/protocol classification", "runtime and trust boundaries", "category-specific attack surface"])
    hypotheses = [f"Inspect {surface} first" for surface in surfaces[:2]]
    tools = {
        "pwn": ["file", "readelf", "checksec", "gdb", "pwntools"],
        "web": ["rg", "curl", "python", "docker compose (only if required)"],
        "rev": ["strings", "objdump", "gdb", "radare2/ghidra on demand"],
        "crypto": ["python", "sympy", "pycryptodome", "z3 on demand"],
        "forensic": ["file", "exiftool", "binwalk", "tshark on demand"],
        "misc": ["file", "xxd", "python", "category-specific tools on demand"],
        "cloud": ["jq", "curl", "manifest-specific client on demand"],
    }.get(category, ["file", "rg", "xxd", "python", "specialized tools on demand"])
    service_plan = _service_plan(challenge, input_dir, dockerfiles, compose)
    priority_metadata = _priority_files(files)
    total_size = sum(int(item["size"]) for item in files)
    elf_count = sum(bool(item.get("elf")) for item in files)
    recommended_resource = _recommended_resource_profile(challenge, names, total_size, len(files), elf_count, bool(dockerfiles or compose))
    recommended_image = _recommended_image(category)
    return {
        "docker": {"dockerfiles": dockerfiles, "compose_files": compose, "dependency_files": dependency_files},
        "runtime": sorted(set(runtime)), "subtype": subtype,
        "attack_surface": surfaces, "hypotheses": hypotheses, "recommended_tools": tools,
        "initial_attack_surface": surfaces,
        "priority_files": [str(item["path"]) for item in priority_metadata],
        "priority_file_metadata": priority_metadata,
        "important_metadata": {
            "file_count": len(files), "total_bytes": total_size, "elf_count": elf_count,
            "dependency_files": dependency_files, "input_profile": challenge.input_profile,
        },
        "recommended_image": recommended_image,
        "recommended_resource_profile": recommended_resource,
        "containerized_challenge": bool(dockerfiles or compose),
        "service_plan": service_plan,
    }


def _recommended_image(category: str) -> str:
    profile = {
        "pwn": "pwn", "jail": "pwn", "web": "web", "blockchain": "web",
        "rev": "rev", "mobile": "rev", "hardware": "rev", "windows": "rev",
        "crypto": "crypto", "forensic": "forensic", "osint": "forensic",
    }.get(category, "base")
    return f"ctf-os-sandbox:{profile}"


def _recommended_resource_profile(
    challenge: ChallengeSpec, names: list[str], total_size: int, file_count: int,
    elf_count: int, containerized: bool,
) -> str:
    if challenge.input_profile == "large-forensic":
        return "large-forensic"
    forensic_markers = (".pcap", ".pcapng", ".raw", ".mem", ".vmem", ".vmdk", ".e01", ".dd", ".img")
    heavy_tools = ("volatility", "ghidra", "angr", "sage", "firmware")
    if challenge.category == "forensic" and total_size >= 1024**3:
        return "large-forensic"
    if (
        total_size >= 512 * 1024**2 or file_count >= 5_000
        or any(name.endswith(forensic_markers) for name in names)
        or any(marker in name for name in names for marker in heavy_tools)
        or (challenge.category in {"rev", "crypto", "forensic"} and total_size >= 128 * 1024**2)
    ):
        return "heavy"
    if containerized or challenge.category in {"pwn", "web", "rev", "crypto", "forensic", "mobile", "windows"} or elf_count:
        return "standard"
    return "light"


def _priority_files(files: list[dict[str, object]]) -> list[dict[str, object]]:
    def rank(item: dict[str, object]) -> tuple[int, int, str]:
        name = str(item["path"]).casefold()
        score = 0
        if item.get("elf"): score += 100
        if name.endswith(("dockerfile", "compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml")): score += 90
        if name.endswith(("requirements.txt", "pyproject.toml", "package.json", "go.mod", "cargo.toml", "gemfile")): score += 70
        if name.endswith((".py", ".c", ".cc", ".cpp", ".h", ".js", ".ts", ".php", ".java", ".go", ".rs")): score += 50
        if any(token in name for token in ("main", "server", "app", "chall", "flag", "readme")): score += 30
        return (-score, int(item["size"]), name)

    selected = sorted(files, key=rank)[:CONTEXT_FILE_LIMIT]
    return [{key: item[key] for key in ("path", "size", "sha256", "mime", "kind") if key in item} | ({"elf": item["elf"]} if item.get("elf") else {}) for item in selected]


def _service_plan(challenge: ChallengeSpec, input_dir: Path, dockerfiles: list[str], compose_files: list[str]) -> dict[str, object]:
    if compose_files:
        return _compose_service_plan(challenge, input_dir, compose_files)
    if dockerfiles:
        dockerfile = dockerfiles[0]
        text = _small_text(input_dir / dockerfile)
        ports = _dockerfile_ports(text)
        build_context = str(Path(dockerfile).parent) or "."
        build_args = _dockerfile_variables(text, "ARG")
        environment = _dockerfile_variables(text, "ENV")
        service = {
            "name": "chall", "image": None, "build_context": build_context,
            "dockerfile": dockerfile, "build_args": build_args,
            "exposed_ports": ports, "mapped_ports": [],
            "environment": environment,
            "healthcheck": _dockerfile_instruction(text, "HEALTHCHECK"),
            "depends_on": [], "command": _dockerfile_instruction(text, "CMD"),
            "entrypoint": _dockerfile_instruction(text, "ENTRYPOINT"),
            "volumes": [], "devices": [], "cap_add": [], "privileged": False,
            "network_mode": None, "pid": None, "ipc": None,
            "docker_socket_mount": False, "host_path_mounts": [], "external_image_pull": True,
        }
        _add_internal_targets(service, challenge.category)
        return {
            "kind": "dockerfile", "status": "READY", "safe_to_start": True, "review_reasons": [],
            "compose_files": [], "build_context": build_context, "dockerfile": Path(dockerfile).name,
            "build_args": build_args, "environment": environment, "services": [service],
        }
    return {"kind": "none", "status": "UNAVAILABLE", "safe_to_start": False, "review_reasons": ["no Dockerfile or Compose file"], "services": []}


def _compose_service_plan(challenge: ChallengeSpec, input_dir: Path, compose_files: list[str]) -> dict[str, object]:
    compose_path = input_dir / compose_files[0]
    try:
        document = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        return {
            "kind": "compose", "status": "NEEDS_REVIEW", "safe_to_start": False,
            "review_reasons": [f"cannot parse {compose_files[0]}: {exc}"],
            "compose_file": compose_files[0], "compose_files": compose_files, "services": [],
        }
    raw_services = document.get("services") if isinstance(document, dict) else None
    if not isinstance(raw_services, dict) or not raw_services:
        return {
            "kind": "compose", "status": "NEEDS_REVIEW", "safe_to_start": False,
            "review_reasons": ["Compose document has no services mapping"],
            "compose_file": compose_files[0], "compose_files": compose_files, "services": [],
        }
    services: list[dict[str, object]] = []
    review: list[str] = []
    for name in sorted(raw_services):
        raw = raw_services[name]
        if not isinstance(raw, dict):
            review.append(f"service {name}: configuration is not a mapping")
            continue
        build = raw.get("build")
        build_context: str | None = None
        dockerfile: str | None = None
        build_args: object = {}
        if isinstance(build, str):
            build_context = build
            dockerfile = "Dockerfile"
        elif isinstance(build, dict):
            build_context = str(build.get("context", "."))
            dockerfile = str(build.get("dockerfile", "Dockerfile"))
            build_args = build.get("args") or {}
        if build_context is not None:
            if "$" in build_context:
                review.append(f"service {name}: interpolated build context requires review: {build_context}")
            resolved_context = (compose_path.parent / build_context).resolve()
            try:
                resolved_context.relative_to(input_dir.resolve())
            except ValueError:
                review.append(f"service {name}: build context escapes challenge input: {build_context}")
        ports = [_compose_port(value) for value in _as_list(raw.get("ports"))]
        expose = [_port_number(value) for value in _as_list(raw.get("expose"))]
        exposed = sorted({port for port in expose + [item["target"] for item in ports] if port is not None})
        volumes = _as_list(raw.get("volumes"))
        host_mounts: list[str] = []
        docker_socket = False
        for volume in volumes:
            source, target, bind = _volume_parts(volume)
            if target == "/var/run/docker.sock" or source == "/var/run/docker.sock":
                docker_socket = True
                review.append(f"service {name}: Docker socket mount is forbidden")
            if bind and source:
                host_mounts.append(source)
                if "$" in source or source.startswith("~"):
                    review.append(f"service {name}: interpolated or home-relative bind mount requires review: {source}")
                resolved_source = (compose_path.parent / source).resolve() if not Path(source).is_absolute() else Path(source).resolve()
                try:
                    resolved_source.relative_to(input_dir.resolve())
                except ValueError:
                    review.append(f"service {name}: bind mount escapes challenge input: {source}")
                if resolved_source == Path("/"):
                    review.append(f"service {name}: host root mount is forbidden")
        privileged = bool(raw.get("privileged", False))
        network_mode, pid, ipc = raw.get("network_mode"), raw.get("pid"), raw.get("ipc")
        devices = _as_list(raw.get("devices"))
        cap_add = [str(value) for value in _as_list(raw.get("cap_add"))]
        if privileged: review.append(f"service {name}: privileged mode is forbidden")
        if str(network_mode).casefold() == "host": review.append(f"service {name}: host network mode is forbidden")
        if str(pid).casefold() == "host": review.append(f"service {name}: host PID namespace is forbidden")
        if str(ipc).casefold() == "host": review.append(f"service {name}: host IPC namespace is forbidden")
        if devices: review.append(f"service {name}: host device mappings require review")
        broad_caps = [cap for cap in cap_add if cap.upper() not in {"NET_BIND_SERVICE"}]
        if broad_caps: review.append(f"service {name}: broad capabilities require review: {', '.join(broad_caps)}")
        service: dict[str, object] = {
            "name": str(name), "image": raw.get("image"), "build_context": build_context,
            "dockerfile": dockerfile, "build_args": build_args, "exposed_ports": exposed,
            "mapped_ports": ports, "environment": _environment(raw.get("environment")),
            "healthcheck": raw.get("healthcheck"), "depends_on": _depends_on(raw.get("depends_on")),
            "command": raw.get("command"), "entrypoint": raw.get("entrypoint"),
            "volumes": volumes, "devices": devices, "cap_add": cap_add,
            "privileged": privileged, "network_mode": network_mode, "pid": pid, "ipc": ipc,
            "docker_socket_mount": docker_socket, "host_path_mounts": host_mounts,
            "external_image_pull": bool(raw.get("image")) and build is None,
        }
        _add_internal_targets(service, challenge.category)
        services.append(service)
    return {
        "kind": "compose", "status": "NEEDS_REVIEW" if review else "READY",
        "safe_to_start": not review, "review_reasons": sorted(set(review)),
        "compose_file": compose_files[0], "compose_files": compose_files, "services": services,
    }


def _as_list(value: object) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _compose_port(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return {
            "target": _port_number(value.get("target")), "published": _port_number(value.get("published")),
            "host_ip": value.get("host_ip"), "protocol": str(value.get("protocol", "tcp")),
        }
    text = str(value)
    protocol = text.rsplit("/", 1)[1] if "/" in text else "tcp"
    text = text.rsplit("/", 1)[0]
    parts = text.rsplit(":", 2)
    return {
        "target": _port_number(parts[-1]),
        "published": _port_number(parts[-2]) if len(parts) >= 2 else None,
        "host_ip": parts[0] if len(parts) == 3 else None, "protocol": protocol,
    }


def _port_number(value: object) -> int | None:
    try:
        text = str(value).split("-", 1)[0]
        number = int(text)
    except (TypeError, ValueError):
        return None
    return number if 0 < number <= 65535 else None


def _volume_parts(value: object) -> tuple[str | None, str | None, bool]:
    if isinstance(value, dict):
        source = value.get("source")
        target = value.get("target")
        return (str(source) if source is not None else None, str(target) if target is not None else None, value.get("type") == "bind")
    parts = str(value).split(":")
    if len(parts) < 2:
        return None, parts[0] or None, False
    source, target = parts[0], parts[1]
    bind = source.startswith((".", "/", "~"))
    return source, target, bind


def _environment(value: object) -> object:
    if isinstance(value, dict):
        return {str(key): item for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    return _as_list(value)


def _depends_on(value: object) -> list[str]:
    if isinstance(value, dict):
        return sorted(str(key) for key in value)
    return sorted(str(item) for item in _as_list(value))


def _add_internal_targets(service: dict[str, object], category: str) -> None:
    ports = [int(port) for port in service.get("exposed_ports", []) if isinstance(port, int)]
    host = str(service["name"])
    scheme = "http" if category in {"web", "blockchain"} else "tcp"
    targets = [f"{scheme}://{host}:{port}" if scheme == "http" else f"{host}:{port}" for port in ports]
    service["internal_targets"] = targets
    service["internal_target"] = targets[0] if targets else None
    service["port"] = ports[0] if ports else None
    service["expected_local_service_url"] = targets[0] if targets else None


def _dockerfile_ports(text: str) -> list[int]:
    result: set[int] = set()
    for value in _dockerfile_instructions(text, "EXPOSE"):
        for item in value.split():
            port = _port_number(item.split("/", 1)[0])
            if port:
                result.add(port)
    return sorted(result)


def _dockerfile_instructions(text: str, instruction: str) -> list[str]:
    prefix = instruction.casefold() + " "
    return [line.strip()[len(prefix):].strip() for line in text.splitlines() if line.strip().casefold().startswith(prefix)]


def _dockerfile_instruction(text: str, instruction: str) -> str | None:
    values = _dockerfile_instructions(text, instruction)
    return values[-1] if values else None


def _dockerfile_variables(text: str, instruction: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in _dockerfile_instructions(text, instruction):
        # This deliberately handles the common KEY=value form. Shell-style
        # multi-key ENV is recorded only when unambiguous; Docker remains the
        # source of truth for the actual image configuration.
        if instruction == "ENV" and "=" not in value and len(value.split(None, 1)) == 2:
            key, item = value.split(None, 1)
            result[key] = item
            continue
        for token in value.split():
            key, separator, item = token.partition("=")
            if key and separator:
                result[key] = item
            elif instruction == "ARG" and key:
                result[key] = ""
    return result


def _small_text(path: Path) -> str:
    if path.stat().st_size > 512_000:
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:64_000]
    except OSError:
        return ""


def _readelf_value(output: str, key: str) -> str | None:
    for line in output.splitlines():
        if line.strip().startswith(f"{key}:"):
            return line.split(":", 1)[1].strip()
    return None


def _command_output(argv: list[str], *, limit: int = 16_000) -> str:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""
    return result.stdout[:limit].strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _make_read_only(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)
    root.chmod(0o555)


def _remove_generated_tree(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_dir():
            path.chmod(0o755)
        else:
            path.chmod(0o644)
    root.chmod(0o755)
    shutil.rmtree(root)


def render_context(manifest: ContestManifest, record: dict[str, object]) -> str:
    challenge = f"{record['category']}/{record['name']}"
    lines = [f"# Context — {challenge}", "", f"- Number: {int(record['number']):02d}", f"- Stable ID: `{record['id']}`", f"- Status: **{record['status']}**", f"- Contest: {manifest.name}"]
    for label, key in (("Score", "score"), ("Description", "description"), ("Hint", "hint"), ("Flag format", "flag_format")):
        if record.get(key) is not None:
            lines.append(f"- {label}: {record[key]}")
    lines.extend(["", "## Authorized targets", ""])
    targets = record.get("authorized_targets") or []
    lines.extend(f"- `{target['declared']}`" for target in targets) if targets else lines.append("- None")
    metadata = record.get("important_metadata") or {}
    lines.extend([
        "", "## Prepared evidence", "", f"- Input: `{record['prepared_input']}`",
        f"- Fingerprint: `{record.get('source_fingerprint')}`",
        f"- Files: {metadata.get('file_count', 0)} ({metadata.get('total_bytes', 0)} bytes total)",
        f"- Full inventory: `{record['inventory_path']}`",
        f"- Recommended image: `{record.get('recommended_image')}`",
        f"- Recommended resource profile: `{record.get('recommended_resource_profile')}`",
        "", f"## Priority files (top {CONTEXT_FILE_LIMIT})", "",
    ])
    for item in record.get("priority_file_metadata", []):
        details = item.get("elf")
        lines.append(f"- `{item['path']}` — {item['size']} bytes — `{item['sha256']}` — {item['kind']}" + (f" — ELF {details}" if details else ""))
    if not record.get("priority_file_metadata"):
        lines.append("- None")
    service_plan = record.get("service_plan") or {}
    lines.extend([
        "", "## Local challenge service", "",
        f"- Kind: `{service_plan.get('kind', 'none')}`",
        f"- Safe to start automatically: `{bool(service_plan.get('safe_to_start'))}`",
    ])
    for service in service_plan.get("services", []):
        lines.append(f"- `{service.get('name')}` → {', '.join(service.get('internal_targets') or []) or 'no detected port'}")
    for reason in service_plan.get("review_reasons", []):
        lines.append(f"- NEEDS_REVIEW: {reason}")
    warning_values = list(record.get("warnings") or [])
    lines.extend(["", "## Manifest warnings", ""])
    lines.extend(
        f"- **{warning['severity']}** line {warning['line']}: {warning['message']}"
        for warning in warning_values
    ) if warning_values else lines.append("- None")
    for heading, key in (("Initial attack surface", "attack_surface"), ("Initial hypotheses", "hypotheses"), ("Recommended tools", "recommended_tools"), ("Blockers", "blockers"), ("Solve session read paths", "read_paths")):
        lines.extend(["", f"## {heading}", ""])
        values = record.get(key) or []
        lines.extend(f"- {value}" for value in values) if values else lines.append("- None")
    return "\n".join(lines) + "\n"


def render_intake_markdown(payload: dict[str, object]) -> str:
    contest = payload["contest"]
    lines = [f"# {contest['name']} — Intake", ""]
    warnings = contest.get("warnings") or []
    if warnings:
        lines.extend(["## Manifest warnings", ""])
        lines.extend(f"- **{warning['severity']}** line {warning['line']}: {warning['message']}" for warning in warnings)
        lines.append("")
    for record in payload["challenges"]:
        lines.extend([f"## [{int(record['number']):02d}] {record['status']} — {record['category']}/{record['name']}", ""])
        files = record.get("source_paths") or []
        targets = record.get("authorized_targets") or []
        lines.append(f"- Input: {', '.join(Path(path).name for path in files) if files else 'none'}")
        lines.append(f"- Remote: {', '.join(target['declared'] for target in targets) if targets else 'none'}")
        lines.append(f"- Estimated: {record.get('subtype') or record['category']}")
        lines.append(f"- Runtime defaults: `{record.get('recommended_image')}` / `{record.get('recommended_resource_profile')}`")
        if record.get("containerized_challenge"):
            plan = record.get("service_plan") or {}
            lines.append(f"- Local service: `{plan.get('kind')}` / {'READY' if plan.get('safe_to_start') else 'NEEDS_REVIEW'}")
        direction = (record.get("hypotheses") or record.get("blockers") or ["none"])[0]
        lines.append(f"- Initial direction: {direction}")
        for warning in record.get("warnings") or []:
            lines.append(f"- Manifest warning: **{warning['severity']}** line {warning['line']}: {warning['message']}")
        lines.append(f"- Solve selector: {int(record['number']):02d} or {record['category']}/{record['name']}")
        lines.append("")
    return "\n".join(lines)
