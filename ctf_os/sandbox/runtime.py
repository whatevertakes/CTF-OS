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
    image: str = "ctf-os-sandbox:latest"
    memory: str = "4g"
    cpus: float = 2.0
    pids: int = 256
    storage: str = "512m"

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


def build_run_argv(spec: SandboxSpec, docker: str = "docker") -> list[str]:
    _validate_spec(spec)
    policy = json.dumps([target.to_dict() for target in spec.targets], separators=(",", ":"))
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
    ]
    for key, value in spec.labels.items():
        argv.extend(["--label", f"{key}={value}"])
    if spec.targets:
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
        "metadata_path": str(spec.branch_root / "sandbox.json"),
        "input_fingerprint": spec.input_fingerprint,
        "authorized_targets": [target.to_dict() for target in spec.targets],
    }
    _write_json(spec.branch_root / "sandbox.json", metadata)
    result = _run(build_run_argv(spec, docker), timeout=120)
    if result.returncode:
        raise SandboxError(f"sandbox create failed: {result.stderr.strip()}")
    try:
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
    try:
        _export_artifacts(name, branch_root / "artifacts", docker=docker)
    finally:
        if result.returncode == 124:
            _cleanup_locked(metadata, docker=docker)
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
    }
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
    if inspect.returncode == 0:
        try:
            labels = json.loads(inspect.stdout)
        except json.JSONDecodeError as exc:
            raise SandboxError("cannot verify sandbox labels before cleanup") from exc
        if any(labels.get(key) != value for key, value in dict(metadata["labels"]).items()):
            raise SandboxError("refusing cleanup: container labels do not match sandbox metadata")
        removed = _run([docker, "rm", "--force", name], timeout=30)
        if removed.returncode:
            raise SandboxError(f"sandbox cleanup failed: {removed.stderr.strip()}")
    elif "no such object" not in inspect.stderr.casefold():
        raise SandboxError(f"cannot inspect sandbox before cleanup: {inspect.stderr.strip() or 'unknown Docker error'}")
    branch_root = Path(str(metadata["branch_root"])).resolve()
    append_evidence(branch_root.parents[1] / "evidence.log", "sandbox_cleanup", {"branch": metadata["branch"], "container": name})
    return {"removed": inspect.returncode == 0, "container": name}


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


def _validate_spec(spec: SandboxSpec) -> None:
    if not spec.source.is_dir() or spec.source.is_symlink():
        raise SandboxError(f"prepared challenge input is missing or unsafe: {spec.source}")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", spec.branch):
        raise SandboxError("branch id must contain only letters, numbers, dot, underscore or dash")
    if spec.cpus <= 0 or spec.pids < 1:
        raise SandboxError("sandbox CPU and PID limits must be positive")


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


def _export_artifacts(container: str, destination: Path, *, docker: str) -> None:
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
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
