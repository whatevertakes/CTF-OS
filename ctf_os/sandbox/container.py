"""Docker container specifications and command construction for one attempt."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import re
import shlex
from collections.abc import Sequence

from .docker_cli import CommandResult, DockerCli
from .network_policy import AllowedEndpoint


_DOCKER_NAME_LIMIT = 128
_DOCKER_COMPONENT = re.compile(r"[^a-z0-9_.-]+")
DEFAULT_STORAGE_LIMIT_BYTES = 512 * 1024 * 1024
DEFAULT_STORAGE_INODE_LIMIT = 65_536
_MIN_STORAGE_LIMIT_BYTES = 8 * 1024
_MIN_STORAGE_INODE_LIMIT = 8

# This is intentionally a self-contained program passed as a fixed Docker
# argv.  The cleanup container mounts only /work and /artifacts, so importing a
# host module or mounting the project workspace would enlarge the cleanup
# boundary.  It operates through dirfds with lstat semantics and only changes
# entries owned by its fixed `ctf` identity.
STAGING_SCRUB_PROGRAM = r'''import os
import stat
import sys

ROOTS = ("/work", "/artifacts")
ME = os.geteuid()
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW
failed = False

def fail(message):
    global failed
    failed = True
    print("ctf-os staging scrub: " + message, file=sys.stderr)

def scrub(directory_fd):
    global failed
    try:
        with os.scandir(directory_fd) as entries:
            names = [entry.name for entry in entries]
    except OSError as exc:
        fail(str(exc))
        return
    for name in names:
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as exc:
            fail(str(exc))
            continue
        if info.st_uid != ME:
            continue
        if stat.S_ISDIR(info.st_mode):
            try:
                os.chmod(name, 0o700, dir_fd=directory_fd, follow_symlinks=False)
                child_fd = os.open(name, DIRECTORY, dir_fd=directory_fd)
            except OSError as exc:
                fail(str(exc))
                continue
            try:
                child_info = os.fstat(child_fd)
                if not stat.S_ISDIR(child_info.st_mode) or child_info.st_uid != ME:
                    fail("directory changed during scrub")
                    continue
                scrub(child_fd)
            finally:
                os.close(child_fd)
            try:
                os.rmdir(name, dir_fd=directory_fd)
            except OSError as exc:
                fail(str(exc))
        else:
            try:
                # unlinkat removes a symlink itself; targets are never opened.
                os.unlink(name, dir_fd=directory_fd)
            except FileNotFoundError:
                continue
            except OSError as exc:
                fail(str(exc))

for root in ROOTS:
    try:
        root_fd = os.open(root, DIRECTORY)
    except OSError as exc:
        fail(str(exc))
        continue
    try:
        root_info = os.fstat(root_fd)
        if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid == ME
                or stat.S_IMODE(root_info.st_mode) != 0o1777):
            fail("unexpected staging mount root")
            continue
        scrub(root_fd)
    finally:
        os.close(root_fd)

raise SystemExit(1 if failed else 0)
'''


def _require_text(name: str, value: str, *, label_value: bool = False, allow_leading_dash: bool = False) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if value.startswith("-") and not allow_leading_dash:
        raise ValueError(f"{name} must not start with '-'")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{name} contains an unsupported control character")
    if label_value and "=" in value:
        raise ValueError(f"{name} cannot contain '=' when used as a Docker label value")
    return value


def _slug(value: str) -> str:
    normalized = _DOCKER_COMPONENT.sub("-", _require_text("container name component", value).lower())
    normalized = normalized.strip("-.")
    return normalized or "x"


@dataclass(frozen=True)
class SandboxScope:
    team_id: str
    member: str
    contest: str
    challenge: str
    challenge_id: str = "unknown"
    challenge_key: str = "unknown"

    def __post_init__(self) -> None:
        for name in ("team_id", "member", "contest", "challenge", "challenge_id", "challenge_key"):
            _require_text(name, getattr(self, name), label_value=True)


@dataclass(frozen=True)
class SandboxSpec:
    """Everything Docker needs to create one isolated attempt container."""

    scope: SandboxScope
    attempt_id: str
    workspace: Path
    workdir: Path
    artifacts: Path
    image: str = "ctf-os-sandbox:latest"
    memory: str = "16g"
    cpus: float | str = 2.0
    pids_limit: int = 128
    nofile_limit: int = 1024
    nproc_limit: int = 128
    # The ctf-visible tmpfs is half of this total.  The broker holds the other
    # half in its host-side mirror while it transfers results.
    storage_limit_bytes: int = DEFAULT_STORAGE_LIMIT_BYTES
    storage_inode_limit: int = DEFAULT_STORAGE_INODE_LIMIT
    endpoints: tuple[AllowedEndpoint, ...] = ()

    def __post_init__(self) -> None:
        _require_text("attempt_id", self.attempt_id, label_value=True)
        _require_text("image", self.image)
        _validate_oci_image(self.image)
        _require_text("memory", self.memory)
        try:
            cpu_count = float(self.cpus)
        except (TypeError, ValueError) as exc:
            raise ValueError("cpus must be greater than zero") from exc
        if not str(self.cpus).strip() or not math.isfinite(cpu_count) or cpu_count <= 0:
            raise ValueError("cpus must be greater than zero")
        if any(not isinstance(value, int) or value < 1 for value in (self.pids_limit, self.nofile_limit, self.nproc_limit)):
            raise ValueError("sandbox pids, nofile, and nproc limits must be positive integers")
        storage_mount_limits(self.storage_limit_bytes, self.storage_inode_limit)
        if not isinstance(self.endpoints, tuple) or any(not isinstance(endpoint, AllowedEndpoint) for endpoint in self.endpoints):
            raise ValueError("sandbox endpoints must be resolved AllowedEndpoint values")

    @property
    def container_name(self) -> str:
        return build_container_name(
            self.scope.team_id,
            self.scope.contest,
            self.scope.challenge,
            self.attempt_id,
        )


def storage_mount_limits(total_bytes: int, total_inodes: int) -> tuple[int, int, int, int]:
    """Return ``work``/``artifacts`` tmpfs limits within one attempt budget.

    The broker preserves the existing host artifact contract by mirroring
    command results after every ctf execution.  Reserve half for the host
    mirror and divide the ctf-visible half 3:1 between ``/work`` and
    ``/artifacts``.  Thus the two copies together stay within one configured
    attempt total.
    """
    if not isinstance(total_bytes, int) or total_bytes < _MIN_STORAGE_LIMIT_BYTES:
        raise ValueError(f"sandbox storage_limit_bytes must be an integer of at least {_MIN_STORAGE_LIMIT_BYTES}")
    if not isinstance(total_inodes, int) or total_inodes < _MIN_STORAGE_INODE_LIMIT:
        raise ValueError(f"sandbox storage_inode_limit must be an integer of at least {_MIN_STORAGE_INODE_LIMIT}")
    mirrored_bytes, mirrored_inodes = total_bytes // 2, total_inodes // 2
    artifact_bytes, artifact_inodes = mirrored_bytes // 4, mirrored_inodes // 4
    return (
        mirrored_bytes - artifact_bytes,
        artifact_bytes,
        mirrored_inodes - artifact_inodes,
        artifact_inodes,
    )


def _tmpfs_argument(target: str, *, size: int, inodes: int) -> str:
    # CTF workloads legitimately build and execute files from /work, so retain
    # exec while still preventing device nodes and set-id behavior.  Docker
    # passes both size and nr_inodes directly to the tmpfs mount.
    return f"{target}:rw,exec,nosuid,nodev,size={size},nr_inodes={inodes},mode=1777"


def build_container_name(
    team_id: str,
    contest: str,
    challenge: str,
    attempt_id: str,
) -> str:
    """Return a Docker-valid deterministic name, even for long user identifiers."""

    parts = [_slug(value) for value in (team_id, contest, challenge, attempt_id)]
    name = "ctf-os-" + "-".join(parts)
    if len(name) <= _DOCKER_NAME_LIMIT:
        return name
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]
    return f"{name[: _DOCKER_NAME_LIMIT - len(digest) - 1].rstrip('-')}-{digest}"


def build_labels(scope: SandboxScope, attempt_id: str) -> dict[str, str]:
    """Build the complete mandatory label set; no caller-selected labels exist."""

    return {
        "ctf-os": "true",
        "ctf-os.team_id": _require_text("team_id", scope.team_id, label_value=True),
        "ctf-os.member": _require_text("member", scope.member, label_value=True),
        "ctf-os.contest": _require_text("contest", scope.contest, label_value=True),
        "ctf-os.challenge": _require_text("challenge", scope.challenge, label_value=True),
        "ctf-os.challenge_id": _require_text("challenge_id", scope.challenge_id, label_value=True),
        "ctf-os.challenge_key": _require_text("challenge_key", scope.challenge_key, label_value=True),
        "ctf-os.attempt_id": _require_text("attempt_id", attempt_id, label_value=True),
    }


def _mount_argument(source: Path, target: str, mode: str) -> str:
    source_text = str(source)
    if not source_text or source_text.startswith("-") or any(ord(character) < 32 or ord(character) == 127 for character in source_text) or ":" in source_text:
        raise ValueError("sandbox mount paths must be non-empty and cannot contain ':'")
    return f"{source_text}:{target}:{mode}"


def build_docker_run_argv(spec: SandboxSpec, *, docker_command: str = "docker") -> list[str]:
    """Build the exact one-container-per-attempt ``docker run`` argv."""

    _require_text("docker command", docker_command)
    labels = build_labels(spec.scope, spec.attempt_id)
    endpoints = tuple(sorted(spec.endpoints, key=lambda endpoint: (endpoint.address, endpoint.port, endpoint.protocol)))
    policy = json.dumps([endpoint.to_policy_dict() for endpoint in endpoints], separators=(",", ":"), sort_keys=True)
    network = "bridge" if endpoints else "none"
    work_bytes, artifact_bytes, work_inodes, artifact_inodes = storage_mount_limits(
        spec.storage_limit_bytes, spec.storage_inode_limit,
    )
    argv = [
        docker_command,
        "run",
        "-d",
        "--name",
        spec.container_name,
        "--memory",
        spec.memory,
        "--cpus",
        str(spec.cpus),
        "--pids-limit",
        str(spec.pids_limit),
        "--ulimit",
        f"nofile={spec.nofile_limit}:{spec.nofile_limit}",
        "--ulimit",
        f"nproc={spec.nproc_limit}:{spec.nproc_limit}",
        "--network",
        network,
        "--read-only",
        "--user",
        "root",
        "--cap-drop=ALL",
        "--cap-add=NET_ADMIN",
        "--cap-add=SETUID",
        "--cap-add=SETGID",
        "--cap-add=SETPCAP",
        # Only the parent-owned fixed seed normalizer runs as root after
        # startup.  The entrypoint drops these before ctf starts, so worker
        # commands still have no capabilities.
        "--cap-add=CHOWN",
        "--cap-add=DAC_OVERRIDE",
        "--cap-add=FOWNER",
        "--security-opt=no-new-privileges:true",
        "--entrypoint",
        "/usr/local/bin/ctf-os-entrypoint",
        "--env",
        f"CTF_OS_ALLOWED_ENDPOINTS_JSON={policy}",
        "--env",
        "HOME=/work/.home",
        "--env",
        "TMPDIR=/work/.tmp",
        "--env",
        "XDG_CACHE_HOME=/work/.cache",
    ]
    for key, value in labels.items():
        argv.extend(["--label", f"{key}={value}"])
    for endpoint in endpoints:
        # Freeze hostname resolution as well as the firewall destination rule.
        argv.extend(["--add-host", f"{endpoint.host}:{endpoint.address}"])
    argv.extend(
        [
            "-v",
            _mount_argument(spec.workspace, "/workspace", "ro"),
            # The complete staging root is mode 0700 and parent-owned.  It is
            # mounted only for fixed broker import/export programs; the ctf
            # UID cannot traverse it, unlike the old writable child mounts.
            "-v",
            _mount_argument(spec.workdir.parent, "/ctf-os-host", "rw"),
            "--tmpfs",
            _tmpfs_argument("/work", size=work_bytes, inodes=work_inodes),
            "--tmpfs",
            _tmpfs_argument("/artifacts", size=artifact_bytes, inodes=artifact_inodes),
            spec.image,
            "sleep",
            "infinity",
        ]
    )
    return argv


def build_docker_exec_argv(
    container_name: str,
    command: Sequence[str] | str,
    *,
    docker_command: str = "docker",
) -> list[str]:
    """Build an unprivileged Docker exec argv without an intermediary shell."""

    _require_text("docker command", docker_command)
    _require_text("container_name", container_name)
    command_argv = _command_argv(command)
    return [docker_command, "exec", "--user", "ctf", "-w", "/work", container_name, *command_argv]


def build_docker_staging_scrub_argv(
    image: str,
    workdir: str | Path,
    artifacts: str | Path,
    *,
    docker_command: str = "docker",
) -> list[str]:
    """Build a minimal, unprivileged one-shot cleanup container.

    This is safer than using the attempt container for fallback cleanup: it
    has no workspace mount, no network, no capabilities, and can only see the
    two already descriptor-validated staging mount roots.  Its program and
    identity are fixed; caller data appears only in the validated image and
    bind sources.
    """
    _require_text("docker command", docker_command)
    _require_text("image", image)
    _validate_oci_image(image)
    work, artifact_dir = Path(workdir), Path(artifacts)
    if not work.is_absolute() or not artifact_dir.is_absolute():
        raise ValueError("staging scrub mount roots must be absolute")
    return [
        docker_command,
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--user",
        "ctf",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--pids-limit",
        "32",
        "--memory",
        "256m",
        "--cpus",
        "0.25",
        "--ulimit",
        "nofile=128:128",
        "--ulimit",
        "nproc=32:32",
        "--entrypoint",
        "/usr/bin/python3",
        "-v",
        _mount_argument(work, "/work", "rw"),
        "-v",
        _mount_argument(artifact_dir, "/artifacts", "rw"),
        image,
        "-I",
        "-c",
        STAGING_SCRUB_PROGRAM,
    ]


def build_ctf_exec_argv(
    attempt_id: str,
    command: Sequence[str] | str,
    *,
    ctf_os_command: str = "ctf-os",
) -> list[str]:
    """Build the future CLI wrapper argv without involving a host shell."""

    _require_text("attempt_id", attempt_id)
    return [ctf_os_command, "sandbox", "exec", attempt_id, "--", *_command_argv(command)]


def create_ctf_exec_helper(
    path: str | Path,
    *,
    container_name: str | None = None,
    attempt_id: str | None = None,
    docker_command: str = "docker",
    ctf_os_command: str = "ctf-os",
) -> Path:
    """Legacy diagnostic helper only; production helpers use :mod:`broker`.

    Exactly one target is required.  A Docker target works before the CLI is wired;
    an attempt target delegates to the eventual ``ctf-os sandbox exec`` command.
    """

    if (container_name is None) == (attempt_id is None):
        raise ValueError("provide exactly one of container_name or attempt_id")
    target = container_name if container_name is not None else attempt_id
    assert target is not None
    _require_text("helper target", target)

    if container_name is not None:
        fixed = shlex.join([docker_command, "exec", "--user", "ctf", "-w", "/work", container_name])
    else:
        fixed = shlex.join([ctf_os_command, "sandbox", "exec", attempt_id, "--"])
    helper_path = Path(path)
    helper_path.parent.mkdir(parents=True, exist_ok=True)
    helper_path.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        'if [ "$#" -lt 1 ]; then\n'
        '  echo "usage: ctf-exec PROGRAM [ARG ...]" >&2\n'
        "  exit 64\n"
        "fi\n"
        f'exec {fixed} "$@"\n',
        encoding="utf-8",
    )
    helper_path.chmod(helper_path.stat().st_mode | 0o111)
    return helper_path


class SandboxContainer:
    """Lifecycle facade for a single attempt container."""

    def __init__(self, spec: SandboxSpec, docker: DockerCli) -> None:
        self.spec = spec
        self.docker = docker

    @property
    def name(self) -> str:
        return self.spec.container_name

    def start(self) -> CommandResult:
        return self.docker.run(build_docker_run_argv(self.spec, docker_command=self.docker.command))

    def exec(self, command: Sequence[str] | str) -> CommandResult:
        return self.docker.exec(
            build_docker_exec_argv(self.name, command, docker_command=self.docker.command)
        )

    def stop(self) -> CommandResult:
        return self.docker.stop(self.name)

    def remove(self) -> CommandResult:
        return self.docker.remove(self.name)


def _command_argv(command: Sequence[str] | str) -> list[str]:
    if isinstance(command, str):
        try:
            values = shlex.split(command, posix=True)
        except ValueError as exc:
            raise ValueError("command must be shell-lexically well formed") from exc
    else:
        values = list(command)
    if not values:
        raise ValueError("command must be a non-empty argv")
    validated: list[str] = []
    for index, value in enumerate(values):
        _require_text("command argument", value, allow_leading_dash=index > 0)
        if index == 0 and value.startswith("-"):
            raise ValueError("command program must not start with '-'")
        validated.append(value)
    return validated


def _validate_oci_image(image: str) -> None:
    # Keep this local so ``SandboxSpec`` rejects unsafe input before Docker is
    # even queried. DockerCli repeats the guard for direct image inspection.
    from .docker_cli import _validate_image

    _validate_image(image)
