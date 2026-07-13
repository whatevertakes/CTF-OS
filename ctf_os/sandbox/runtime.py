from __future__ import annotations

from dataclasses import dataclass
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
from typing import Sequence

from ..evidence import append_evidence
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
    targets: tuple[ResolvedTarget, ...] = ()
    image: str = "ctf-os-sandbox:base"
    resource_profile: str = "standard"
    memory: str | None = None
    cpus: float | None = None
    pids: int | None = None
    storage: str | None = None
    service_network: str | None = None
    local_endpoints: tuple[str, ...] = ()

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

    @property
    def name(self) -> str:
        raw = f"ctf-os-{self.contest_slug}-{self.challenge_id}-{self.branch}"
        safe = re.sub(r"[^a-zA-Z0-9_.-]+", "-", raw).strip("-.").lower()
        return safe[:100] + "-" + hashlib.sha256(raw.encode()).hexdigest()[:10]

    @property
    def labels(self) -> dict[str, str]:
        return {
            "ctf-os": "true", "ctf-os.contest": self.contest_slug,
            "ctf-os.challenge_id": self.challenge_id, "ctf-os.branch": self.branch,
        }

    @property
    def runtime_labels(self) -> dict[str, str]:
        return {
            **self.labels,
            "ctf-os.kind": "sandbox",
            "ctf-os.resource_profile": self.resource_profile,
            "ctf-os.memory_bytes": str(parse_size_bytes(str(self.memory))),
            "ctf-os.storage_bytes": str(parse_size_bytes(str(self.storage))),
        }


def build_run_argv(spec: SandboxSpec, docker: str = "docker") -> list[str]:
    _validate_spec(spec)
    policy = json.dumps([target.to_dict() for target in spec.targets], separators=(",", ":"))
    local_policy = json.dumps(list(spec.local_endpoints), separators=(",", ":"))
    argv = [
        docker, "run", "--detach", "--name", spec.name, "--read-only",
        "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
        "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "SETPCAP",
        "--memory", spec.memory, "--cpus", str(spec.cpus), "--pids-limit", str(spec.pids),
        "--ulimit", "nofile=1024:1024", "--ulimit", "nproc=256:256",
        "--mount", f"type=bind,src={spec.source},dst=/challenge,readonly",
        "--tmpfs", f"/work:rw,exec,nosuid,nodev,size={spec.storage},mode=1777",
        "--tmpfs", f"/artifacts:rw,exec,nosuid,nodev,size={spec.storage},mode=1777",
        "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=256m,mode=1777",
        "--env", f"CTF_OS_ALLOWED_ENDPOINTS_JSON={policy}",
        "--env", f"CTF_OS_LOCAL_ENDPOINTS_JSON={local_policy}",
    ]
    for key, value in spec.runtime_labels.items():
        argv.extend(["--label", f"{key}={value}"])
    if spec.service_network:
        argv.extend(["--network", spec.service_network])
    elif spec.targets:
        argv.extend(["--network", "bridge", "--cap-add", "NET_ADMIN"])
        for target in spec.targets:
            argv.extend(["--add-host", f"{target.target.host}:{target.address}"])
    else:
        argv.extend(["--network", "none"])
    argv.extend([spec.image, "sleep", "infinity"])
    return argv


def create(spec: SandboxSpec, *, docker: str = "docker") -> dict[str, object]:
    spec.branch_root.mkdir(parents=True, exist_ok=True)
    metadata: dict[str, object] = {
        "schema_version": 1, "name": spec.name, "contest_slug": spec.contest_slug,
        "challenge_id": spec.challenge_id, "branch": spec.branch,
        "source": str(spec.source), "branch_root": str(spec.branch_root),
        "labels": spec.labels, "image": spec.image,
        "runtime_labels": spec.runtime_labels,
        "resource_profile": spec.resource_profile,
        "resources": {"memory": spec.memory, "cpus": spec.cpus, "pids": spec.pids, "storage": spec.storage},
        "service_network": spec.service_network,
        "local_endpoints": list(spec.local_endpoints),
        "metadata_path": str(spec.branch_root / "sandbox.json"),
        "input_fingerprint": spec.input_fingerprint,
        "authorized_targets": [target.to_dict() for target in spec.targets],
    }
    try:
        with admission_lock():
            admit(spec.resource_profile, requested_memory_bytes=parse_size_bytes(str(spec.memory)), docker=docker)
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


def execute(metadata: dict[str, object], command: Sequence[str], timeout: int, *, docker: str = "docker") -> dict[str, object]:
    branch_root = Path(str(metadata["branch_root"])).resolve()
    with _sandbox_lock(branch_root):
        return _execute_locked(metadata, command, timeout, docker=docker)


def _execute_locked(metadata: dict[str, object], command: Sequence[str], timeout: int, *, docker: str) -> dict[str, object]:
    if not command or timeout < 1 or timeout > 1800:
        raise SandboxError("command is required and timeout must be between 1 and 1800 seconds")
    name = _metadata_name(metadata)
    branch_root = Path(str(metadata["branch_root"])).resolve()
    argv = [docker, "exec", "--user", "1001:1001", "--workdir", "/work", name, *command]
    before = _firewall_counters(name, docker, list(metadata.get("authorized_targets", []))) if metadata.get("authorized_targets") else None
    result = _run(argv, timeout=timeout)
    after = _firewall_counters(name, docker, list(metadata.get("authorized_targets", []))) if metadata.get("authorized_targets") and result.returncode != 124 else None
    cleanup_record = _cleanup_locked(metadata, docker=docker) if result.returncode == 124 else None
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
    }
    if cleanup_record is not None:
        record["cleanup"] = cleanup_record
    challenge_root = branch_root.parents[1]
    append_evidence(challenge_root / "evidence.log", "sandbox_exec", {"branch": metadata["branch"], **record})
    return record


def cleanup(metadata: dict[str, object], *, docker: str = "docker") -> dict[str, object]:
    branch_root = Path(str(metadata["branch_root"])).resolve()
    with _sandbox_lock(branch_root):
        return _cleanup_locked(metadata, docker=docker)


def _cleanup_locked(metadata: dict[str, object], *, docker: str) -> dict[str, object]:
    name = _metadata_name(metadata)
    inspect = _run([docker, "inspect", name, "--format", "{{json .Config.Labels}}"], timeout=20)
    export_record: dict[str, object] | None = None
    export_error: str | None = None
    if inspect.returncode == 0:
        try:
            labels = json.loads(inspect.stdout)
        except json.JSONDecodeError as exc:
            raise SandboxError("cannot verify sandbox labels before cleanup") from exc
        if any(labels.get(key) != value for key, value in dict(metadata["labels"]).items()):
            raise SandboxError("refusing cleanup: container labels do not match sandbox metadata")
        try:
            export_record = _export_artifacts(name, Path(str(metadata["branch_root"])).resolve() / "artifacts", docker=docker)
        except Exception as exc:
            # Cleanup must still remove a resource-expensive sandbox. Preserve an actionable
            # export failure in the receipt/evidence instead of leaking the container.
            export_error = str(exc)
        removed = _run([docker, "rm", "--force", name], timeout=30)
        if removed.returncode:
            raise SandboxError(f"sandbox cleanup failed: {removed.stderr.strip()}")
    elif "no such object" not in inspect.stderr.casefold():
        raise SandboxError(f"cannot inspect sandbox before cleanup: {inspect.stderr.strip() or 'unknown Docker error'}")
    branch_root = Path(str(metadata["branch_root"])).resolve()
    record: dict[str, object] = {"removed": inspect.returncode == 0, "container": name, "artifact_export": export_record}
    if export_error is not None:
        record["artifact_export_error"] = export_error
    append_evidence(branch_root.parents[1] / "evidence.log", "sandbox_cleanup", {"branch": metadata["branch"], **record})
    return record


def export_artifacts(metadata: dict[str, object], *, docker: str = "docker") -> dict[str, object]:
    branch_root = Path(str(metadata["branch_root"])).resolve()
    with _sandbox_lock(branch_root):
        name = _metadata_name(metadata)
        record = _export_artifacts(name, branch_root / "artifacts", docker=docker)
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


def _metadata_name(metadata: dict[str, object]) -> str:
    name = str(metadata.get("name", ""))
    if not re.fullmatch(r"ctf-os-[a-zA-Z0-9_.-]+", name):
        raise SandboxError("invalid sandbox metadata/container name")
    return name


def _run(argv: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return subprocess.CompletedProcess(list(argv), 124, stdout, stderr + "\ncommand timed out")
    except FileNotFoundError as exc:
        raise SandboxError(f"required executable not found: {argv[0]}") from exc


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


def _export_artifacts(container: str, destination: Path, *, docker: str) -> dict[str, object]:
    if destination.is_symlink():
        raise SandboxError("artifact destination must not be a symlink")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        for existing in destination.rglob("*"):
            if existing.is_symlink() or (not existing.is_dir() and not existing.is_file()):
                raise SandboxError(f"artifact destination contains a link/special file: {existing}")
    staging = Path(tempfile.mkdtemp(prefix=".artifacts-", dir=destination.parent))
    try:
        try:
            result = subprocess.run(
                [docker, "exec", "--user", "1001:1001", container, "tar", "-C", "/artifacts", "-cf", "-", "."],
                capture_output=True, timeout=60, check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise SandboxError(f"artifact export failed: {exc}") from exc
        if result.returncode:
            raise SandboxError(f"artifact export failed: {result.stderr.decode(errors='replace').strip()}")
        files = 0
        total = 0
        members = 0
        with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r|") as archive:
            for member in archive:
                members += 1
                if members > 2_000:
                    raise SandboxError("artifact export exceeds member limit")
                relative_text = member.name.removeprefix("./")
                if relative_text in {"", "."}:
                    continue
                relative = Path(relative_text)
                if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
                    raise SandboxError(f"artifact export rejected unsafe path: {member.name!r}")
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    raise SandboxError(f"artifact export rejected link/special file: {member.name!r}")
                target = staging / relative
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise SandboxError(f"artifact export rejected unsupported member: {member.name!r}")
                files += 1
                total += member.size
                if files > 2_000 or total > 512 * 1024 * 1024:
                    raise SandboxError("artifact export exceeds file or byte limit")
                source = archive.extractfile(member)
                if source is None:
                    raise SandboxError(f"artifact export cannot read member: {member.name!r}")
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
        if files > 2_000 or total > 512 * 1024 * 1024:
            raise SandboxError("artifact export exceeds file or byte limit")
        old = destination.parent / ".artifacts-old"
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
