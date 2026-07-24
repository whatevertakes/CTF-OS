"""Docker lifecycle for automatically prepared race lanes."""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import subprocess
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..workspace import atomic_json, state_lock, validate_identifier
from .network import ResolvedTarget
from .resources import ResourceError, admit, parse_size_bytes, resource_profile

MAX_CAPTURE = 64 * 1024
MAX_COMMAND_SECONDS = 1800
MAX_COMMAND_LOG_BYTES = 64 * 1024 * 1024
COMMAND_HEARTBEAT_SECONDS = 5.0
FLAG_TERMINATION_GRACE_SECONDS = 0.5
USER_EXEC_ENV = (
    "HOME=/work/home",
    "XDG_CONFIG_HOME=/work/home/.config",
    "XDG_CACHE_HOME=/work/home/.cache",
    "XDG_DATA_HOME=/work/home/.local/share",
    "XDG_RUNTIME_DIR=/work/runtime",
    "TMPDIR=/work/tmp",
    "JAVA_TOOL_OPTIONS=-Duser.home=/work/home",
    "AWS_SHARED_CREDENTIALS_FILE=/work/credentials/aws",
    "AWS_CONFIG_FILE=/work/credentials/aws-config",
    "AZURE_CONFIG_DIR=/work/credentials/azure",
    "CLOUDSDK_CONFIG=/work/credentials/gcloud",
    "KUBECONFIG=/work/credentials/kubeconfig",
)


class SandboxError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SandboxSpec:
    run_id: str
    contest_slug: str
    challenge_id: str
    category: str
    lane_id: str
    source: Path
    lane_root: Path
    input_fingerprint: str
    image: str
    targets: tuple[ResolvedTarget, ...] = ()
    service_network: str | None = None
    service_endpoints: tuple[str, ...] = ()
    artifact_inbox: Path | None = None
    resource_profile: str = "standard"
    race_lane_count: int = 0

    @property
    def name(self) -> str:
        raw = f"ctf-os-{self.run_id}-{self.lane_id}"
        prefix = re.sub(r"[^a-z0-9_.-]+", "-", raw.casefold()).strip("-.")[:80]
        return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:10]}"

    @property
    def labels(self) -> dict[str, str]:
        return {
            "org.ctf-os.managed": "true",
            "org.ctf-os.kind": "sandbox",
            "org.ctf-os.run-id": self.run_id,
            "org.ctf-os.challenge-id": self.challenge_id,
            "org.ctf-os.lane-id": self.lane_id,
            "org.ctf-os.category": self.category,
        }


def build_run_argv(spec: SandboxSpec, *, docker: str = "docker") -> list[str]:
    _validate_spec(spec)
    profile = resource_profile(spec.resource_profile)
    targets = json.dumps([row.to_dict() for row in spec.targets], separators=(",", ":"))
    endpoints = json.dumps(list(spec.service_endpoints), separators=(",", ":"))
    argv = [
        docker, "run", "--detach", "--name", spec.name,
        "--read-only", "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
        # The entrypoint uses these only to change uid/gid and permanently drops
        # them before the lane command starts. CHOWN and DAC_READ_SEARCH are
        # retained only in the container configuration so the Root-owned
        # cleanup exec can traverse 0700 output directories and return their
        # contents to the controller uid/gid.
        "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "SETPCAP",
        "--cap-add", "CHOWN", "--cap-add", "DAC_READ_SEARCH",
        "--memory", profile.memory, "--cpus", str(profile.cpus),
        "--pids-limit", str(profile.pids),
        "--ulimit", "nofile=2048:2048", "--ulimit", "nproc=512:512",
        "--mount", f"type=bind,src={spec.source.resolve()},dst=/challenge,readonly",
        "--mount", f"type=bind,src={(spec.lane_root / 'work').resolve()},dst=/work",
        "--mount", f"type=bind,src={(spec.lane_root / 'evidence').resolve()},dst=/evidence",
        "--mount", f"type=bind,src={(spec.lane_root / 'artifacts').resolve()},dst=/artifacts",
        "--mount", f"type=bind,src={(spec.lane_root / 'context').resolve()},dst=/context,readonly",
        "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=256m,mode=1777",
        # Hashcat resolves its kernel cache through the passwd home even when
        # HOME/XDG_CACHE_HOME point at the lane-private /work mount.
        "--tmpfs", "/home/ctf/.cache:rw,nosuid,nodev,size=256m,mode=0700,uid=1001,gid=1001",
        "--env", f"CTF_OS_ALLOWED_ENDPOINTS_JSON={targets}",
        "--env", f"CTF_OS_LOCAL_ENDPOINTS_JSON={endpoints}",
        "--env", f"CTF_OS_RUN_ID={spec.run_id}",
        "--env", f"CTF_OS_CHALLENGE_ID={spec.challenge_id}",
        "--env", f"CTF_OS_LANE_ID={spec.lane_id}",
        "--env", "HF_HUB_OFFLINE=1",
        "--env", "TRANSFORMERS_OFFLINE=1",
    ]
    if spec.artifact_inbox is not None:
        argv.extend([
            "--mount",
            f"type=bind,src={spec.artifact_inbox.resolve()},dst=/shared-artifacts,readonly",
            "--env",
            "CTF_OS_SHARED_ARTIFACTS=/shared-artifacts",
        ])
    for key, value in spec.labels.items():
        argv.extend(["--label", f"{key}={value}"])
    if spec.category in {"pwn", "rev"}:
        argv.extend(["--cap-add", "SYS_PTRACE", "--security-opt", "seccomp=unconfined"])
    if spec.category in {"cloud", "misc"}:
        seccomp = Path(__file__).resolve().parents[2] / "sandbox" / "seccomp-rootless.json"
        if seccomp.is_symlink() or not seccomp.is_file():
            raise SandboxError(
                f"{spec.category} sandbox rootless seccomp profile is missing or unsafe"
            )
        argv.extend(["--security-opt", f"seccomp={seccomp}"])
    if spec.service_network:
        argv.extend(["--network", spec.service_network, "--cap-add", "NET_ADMIN"])
    elif spec.targets:
        argv.extend(["--network", "bridge", "--cap-add", "NET_ADMIN"])
        for target in spec.targets:
            argv.extend(["--add-host", f"{target.target.host}:{target.address}"])
    else:
        argv.extend(["--network", "none"])
    argv.extend([spec.image, "sleep", "infinity"])
    return argv


def create(
    spec: SandboxSpec,
    *,
    docker: str = "docker",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    _validate_spec(spec)
    resource_scope = spec.lane_root.resolve().parents[1] / "resources"
    with state_lock(resource_scope):
        try:
            capacity = admit(
                spec.resource_profile,
                race_lane_count=spec.race_lane_count,
                docker=docker,
                runner=runner,
            )
        except ResourceError as exc:
            raise SandboxError(str(exc)) from exc
        _prepare_lane_root(spec)
        result = _run(runner, build_run_argv(spec, docker=docker), timeout=120)
        if result.returncode:
            raise SandboxError(f"sandbox create failed: {result.stderr.strip()}")
        inspected = _run(
            runner,
            [docker, "inspect", spec.name, "--format", "{{.State.Running}}"],
            timeout=30,
        )
        if inspected.returncode or inspected.stdout.strip() != "true":
            state = _run(
                runner, [docker, "inspect", spec.name, "--format", "{{json .State}}"], timeout=30
            )
            logs = _run(runner, [docker, "logs", "--tail", "40", spec.name], timeout=30)
            _run(runner, [docker, "rm", "--force", spec.name], timeout=30)
            detail = (logs.stderr or logs.stdout or state.stdout or inspected.stderr).strip()
            raise SandboxError(
                "sandbox was created but did not become running"
                + (f": {detail[-4096:]}" if detail else "")
            )
    metadata_path = spec.lane_root / "sandbox.json"
    target_identities = [row.target.declared for row in spec.targets]
    target_identities.extend(spec.service_endpoints)
    metadata: dict[str, Any] = {
        "schema_version": 1,
        "status": "READY",
        "name": spec.name,
        "run_id": spec.run_id,
        "challenge_id": spec.challenge_id,
        "category": spec.category,
        "lane_id": spec.lane_id,
        "image": spec.image,
        "source": str(spec.source.resolve()),
        "lane_root": str(spec.lane_root.resolve()),
        "metadata_path": str(metadata_path.resolve()),
        "input_fingerprint": spec.input_fingerprint,
        "labels": spec.labels,
        "authorized_targets": [row.to_dict() for row in spec.targets],
        "target_identities": target_identities,
        "service_network": spec.service_network,
        "service_endpoints": list(spec.service_endpoints),
        "artifact_inbox": (
            str(spec.artifact_inbox.resolve()) if spec.artifact_inbox is not None else None
        ),
        "paths": {
            "input": "/challenge",
            "work": "/work",
            "evidence": "/evidence",
            "artifacts": "/artifacts",
            "shared_artifacts": "/shared-artifacts" if spec.artifact_inbox is not None else None,
            "host_work": str((spec.lane_root / "work").resolve()),
            "host_evidence": str((spec.lane_root / "evidence").resolve()),
            "host_artifacts": str((spec.lane_root / "artifacts").resolve()),
        },
        "resource_profile": spec.resource_profile,
        "capacity_at_create": capacity,
        "created_at": _now(),
        "exec_command_prefix": [
            "uv", "run", "python", "-m", "ctf_os.agent_tools", "sandbox-exec",
            "--metadata", str(metadata_path.resolve()), "--",
        ],
    }
    try:
        atomic_json(metadata_path, metadata)
    except Exception:
        _run(runner, [docker, "rm", "--force", spec.name], timeout=30)
        raise
    return metadata


def load_metadata(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise SandboxError("sandbox metadata is missing or unsafe")
    try:
        metadata = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SandboxError("sandbox metadata is unreadable") from exc
    if not isinstance(metadata, dict) or metadata.get("schema_version") != 1:
        raise SandboxError("sandbox metadata schema is unsupported")
    if Path(str(metadata.get("metadata_path"))).resolve() != path.resolve():
        raise SandboxError("sandbox metadata path identity mismatch")
    lane_root = Path(str(metadata.get("lane_root", ""))).resolve()
    if path.parent.resolve() != lane_root:
        raise SandboxError("sandbox metadata escapes its lane")
    return metadata


def execute(
    metadata: Mapping[str, Any],
    command: Sequence[str],
    *,
    timeout: int = 300,
    target_identity: str | None = None,
    candidate_probe: Callable[[str], str | None] | None = None,
    docker: str = "docker",
) -> dict[str, Any]:
    if not command or any("\x00" in value for value in command):
        raise SandboxError("a non-empty NUL-free argv is required")
    if timeout < 1 or timeout > MAX_COMMAND_SECONDS:
        raise SandboxError(f"timeout must be between 1 and {MAX_COMMAND_SECONDS} seconds")
    name = _metadata_name(metadata)
    lane_root = Path(str(metadata["lane_root"])).resolve()
    receipt_id = uuid.uuid4().hex
    pid_file = f"/tmp/ctf-os-exec-{receipt_id}.pid"
    argv = [
        *user_exec_prefix(metadata, docker=docker, workdir="/work"),
        "setsid", "--fork", "--wait", "sh", "-c",
        "umask 077; echo $$ >\"$1\"; shift; exec \"$@\"",
        "ctf-os-exec", pid_file, *command,
    ]
    started_at = _now()
    started = time.monotonic()
    resolved_target = _target_identity(metadata, target_identity)
    before_packets = firewall_packets(metadata, resolved_target, docker=docker)
    logs = lane_root / "logs"
    logs.mkdir(exist_ok=True)
    stdout_path = logs / f"{receipt_id}.stdout"
    stderr_path = logs / f"{receipt_id}.stderr"
    combined_path = logs / f"{receipt_id}.combined"
    candidate: str | None = None
    candidate_detected_at: float | None = None
    candidate_forced = False
    timed_out = False
    output_limited = False
    logged_bytes = 0
    capture = bytearray()
    digest = _NormalizedDigest()
    last_output_at: str | None = None
    running_root = logs / "running"
    if running_root.is_symlink():
        raise SandboxError("running command state directory is a symlink")
    running_root.mkdir(mode=0o700, exist_ok=True)
    running_path = running_root / f"{receipt_id}.json"
    last_heartbeat = 0.0
    heartbeat_error: str | None = None

    def heartbeat(*, force: bool = False) -> None:
        nonlocal heartbeat_error, last_heartbeat
        current = time.monotonic()
        if not force and current - last_heartbeat < COMMAND_HEARTBEAT_SECONDS:
            return
        try:
            atomic_json(running_path, {
                "schema_version": 1,
                "receipt_id": receipt_id,
                "run_id": metadata["run_id"],
                "lane_id": metadata["lane_id"],
                "argv": list(command),
                "argv_family": argv_family(command),
                "target_identity": resolved_target,
                "pid_file": pid_file,
                "started_at": started_at,
                "heartbeat_at": _now(),
                "last_output_at": last_output_at,
                "observed_bytes": logged_bytes,
                "status": "RUNNING",
            })
        except Exception as exc:  # noqa: BLE001
            heartbeat_error = str(exc)[:2048]
        last_heartbeat = current

    heartbeat(force=True)
    try:
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError as exc:
        try:
            if running_path.exists():
                running_path.unlink()
        except OSError:
            pass
        raise SandboxError(f"required executable not found: {docker}") from exc
    selector = selectors.DefaultSelector()
    assert process.stdout is not None and process.stderr is not None
    selector.register(process.stdout, selectors.EVENT_READ, ("stdout", stdout_path))
    selector.register(process.stderr, selectors.EVENT_READ, ("stderr", stderr_path))
    handles = {
        "stdout": _secure_binary_file(stdout_path),
        "stderr": _secure_binary_file(stderr_path),
        "combined": _secure_binary_file(combined_path),
    }
    try:
        while selector.get_map():
            heartbeat()
            if time.monotonic() - started >= timeout:
                timed_out = True
                _kill_exec(name, pid_file, docker=docker)
                process.terminate()
            events = selector.select(timeout=0.1)
            if not events and process.poll() is not None:
                events = [(key, None) for key in list(selector.get_map().values())]
            for key, _mask in events:
                stream, _path = key.data
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                logged_bytes += len(chunk)
                last_output_at = _now()
                if logged_bytes > MAX_COMMAND_LOG_BYTES:
                    output_limited = True
                    _kill_exec(name, pid_file, docker=docker)
                    process.terminate()
                    continue
                handles[stream].write(chunk)
                handles["combined"].write(chunk)
                digest.update(chunk)
                capture.extend(chunk)
                if len(capture) > MAX_CAPTURE:
                    del capture[:-MAX_CAPTURE]
                if candidate is None and candidate_probe is not None:
                    candidate = candidate_probe(chunk.decode("utf-8", errors="replace"))
                    if candidate is not None:
                        candidate_detected_at = time.monotonic()
                        _kill_exec(
                            name,
                            pid_file,
                            docker=docker,
                            timeout_seconds=FLAG_TERMINATION_GRACE_SECONDS,
                        )
            if (
                candidate_detected_at is not None
                and not candidate_forced
                and process.poll() is None
                and time.monotonic() - candidate_detected_at
                >= FLAG_TERMINATION_GRACE_SECONDS
            ):
                candidate_forced = True
                _kill_exec(
                    name,
                    pid_file,
                    docker=docker,
                    signal="KILL",
                    timeout_seconds=FLAG_TERMINATION_GRACE_SECONDS,
                )
                process.kill()
            if timed_out and process.poll() is None and time.monotonic() - started > timeout + 2:
                process.kill()
            if output_limited and process.poll() is None:
                process.kill()
        return_code = process.wait(timeout=5)
    finally:
        selector.close()
        for handle in handles.values():
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()
    observed = capture.decode("utf-8", errors="replace")
    after_packets = firewall_packets(metadata, resolved_target, docker=docker)
    target_observed = (
        resolved_target == f"challenge:{metadata['challenge_id']}"
        or (
            before_packets is not None and after_packets is not None
            and after_packets > before_packets
        )
    )
    receipt = {
        "schema_version": 1,
        "receipt_id": receipt_id,
        "run_id": metadata["run_id"],
        "lane_id": metadata["lane_id"],
        "argv": list(command),
        "argv_family": argv_family(command),
        "exit_code": 124 if timed_out else 125 if output_limited else return_code,
        "timed_out": timed_out,
        "output_limited": output_limited,
        "observed_output": observed,
        "output_truncated": combined_path.stat().st_size > MAX_CAPTURE,
        "output_hash": digest.hexdigest(),
        "target_identity": resolved_target,
        "target_observed": target_observed,
        "target_packets_before": before_packets,
        "target_packets_after": after_packets,
        "started_at": started_at,
        "finished_at": _now(),
        "duration_seconds": round(time.monotonic() - started, 6),
        "stdout_artifact": str(stdout_path.relative_to(lane_root)),
        "stderr_artifact": str(stderr_path.relative_to(lane_root)),
        "combined_artifact": str(combined_path.relative_to(lane_root)),
        "flag_candidate": candidate,
        "heartbeat_error": heartbeat_error,
    }
    atomic_json(lane_root / "logs" / f"{receipt_id}.json", receipt)
    try:
        if running_path.exists():
            running_path.unlink()
    except OSError:
        pass
    return receipt


def cleanup(
    metadata: Mapping[str, Any],
    *,
    docker: str = "docker",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    name = _metadata_name(metadata)
    inspected = _run(runner, [docker, "inspect", name], timeout=30)
    if inspected.returncode:
        detail = (inspected.stderr or inspected.stdout).strip()
        if re.search(r"(?i)no such (?:object|container)", detail):
            return {"container": name, "removed": False, "already_absent": True}
        raise SandboxError(
            "sandbox ownership inspection failed"
            + (f": {detail[-4096:]}" if detail else "")
        )
    try:
        row = json.loads(inspected.stdout)[0]
        labels = row.get("Config", {}).get("Labels", {}) or {}
    except (json.JSONDecodeError, IndexError, TypeError) as exc:
        raise SandboxError("Docker returned malformed sandbox inspect data") from exc
    expected = metadata.get("labels")
    if not isinstance(expected, Mapping) or not expected:
        raise SandboxError("sandbox metadata has no ownership labels")
    if any(labels.get(key) != value for key, value in expected.items()):
        raise SandboxError("refusing to remove container whose labels do not match metadata")
    normalized = _run(
        runner,
        [
            docker, "exec", "--user", "0:0", name, "sh", "-c",
            "chown -R \"$1:$2\" /work /evidence /artifacts",
            "ctf-os-finalize", str(os.getuid()), str(os.getgid()),
        ],
        timeout=60,
    )
    if normalized.returncode:
        detail = (normalized.stderr or normalized.stdout).strip()
        raise SandboxError(
            "sandbox ownership normalization failed before removal"
            + (f": {detail[-4096:]}" if detail else "")
        )
    result = _run(runner, [docker, "rm", "--force", name], timeout=30)
    if result.returncode:
        raise SandboxError(f"sandbox cleanup failed: {result.stderr.strip()}")
    return {
        "container": name,
        "removed": True,
        "already_absent": False,
        "host_ownership_normalized": True,
        "normalization_warning": None,
    }


def probe_service_connectivity(
    metadata: Mapping[str, Any], *, docker: str = "docker"
) -> dict[str, Any]:
    endpoints = [str(value) for value in metadata.get("service_endpoints", [])]
    if not endpoints:
        raise SandboxError("service-attached sandbox has no declared endpoint")
    results: list[dict[str, Any]] = []
    for endpoint in endpoints:
        parsed = urlsplit(endpoint if "://" in endpoint else f"tcp://{endpoint}")
        if not parsed.hostname or not parsed.port:
            raise SandboxError(f"service endpoint is invalid: {endpoint}")
        code = (
            "import socket,sys; s=socket.create_connection((sys.argv[1],int(sys.argv[2])),5); "
            "s.close(); print('CONNECTED')"
        )
        result = subprocess.run(
            [
                *user_exec_prefix(metadata, docker=docker),
                "python3", "-c", code, parsed.hostname, str(parsed.port),
            ],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if result.returncode or "CONNECTED" not in result.stdout:
            raise SandboxError(
                f"Root sandbox cannot reach prepared challenge service {endpoint}: "
                f"{(result.stderr or result.stdout).strip()[-2048:]}"
            )
        results.append({"endpoint": endpoint, "connected": True})
    return {"connected": True, "endpoints": results}


def argv_family(command: Sequence[str]) -> str:
    executable = Path(command[0]).name.casefold()
    stable: list[str] = [executable]
    for value in command[1:4]:
        if value.startswith("-"):
            stable.append(value.split("=", 1)[0])
        elif "/" in value or "." in Path(value).name:
            stable.append(Path(value).suffix.casefold() or "path")
        else:
            stable.append("arg")
    return ":".join(stable)


def firewall_packets(
    metadata: Mapping[str, Any], target_identity: str, *, docker: str = "docker"
) -> int | None:
    """Return packets accepted by the exact target rule, or None for local challenge output."""

    if target_identity == f"challenge:{metadata.get('challenge_id')}":
        return None
    address: str | None = None
    port: int | None = None
    for row in metadata.get("authorized_targets", []):
        if isinstance(row, Mapping) and row.get("declared") == target_identity:
            address = str(row.get("ip") or "")
            try:
                port = int(row.get("port"))
            except (TypeError, ValueError):
                return 0
            break
    if port is None and target_identity in metadata.get("service_endpoints", []):
        parsed = urlsplit(target_identity if "://" in target_identity else f"tcp://{target_identity}")
        try:
            port = parsed.port
        except ValueError:
            return 0
    if port is None:
        return 0
    name = _metadata_name(metadata)
    total = 0
    for tool in ("iptables-save", "ip6tables-save"):
        try:
            result = subprocess.run(
                [docker, "exec", "--user", "0:0", name, tool, "-c"],
                capture_output=True, text=True, timeout=10, check=False,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return 0
        if result.returncode:
            return 0
        for line in result.stdout.splitlines():
            counter = re.match(r"^\[([0-9]+):[0-9]+\]\s+", line)
            if not counter or f"--dport {port}" not in line:
                continue
            if address and f"-d {address}/" not in line:
                continue
            total += int(counter.group(1))
    return total


def _prepare_lane_root(spec: SandboxSpec) -> None:
    validate_identifier(spec.lane_id, "lane id")
    if spec.lane_root.is_symlink():
        raise SandboxError("lane root must not be a symlink")
    spec.lane_root.mkdir(parents=True, mode=0o700, exist_ok=False)
    for name in ("work", "evidence", "artifacts"):
        path = spec.lane_root / name
        path.mkdir(mode=0o777)
        # mkdir honors the controller umask; the container uid is deliberately
        # unrelated to the host user, while the 0700 lane parent keeps these
        # mounts private from other host users.
        path.chmod(0o777)
    (spec.lane_root / "logs").mkdir(mode=0o700)
    (spec.lane_root / "context").mkdir(mode=0o755)
    context = {
        "schema_version": 1,
        "run_id": spec.run_id,
        "challenge_id": spec.challenge_id,
        "lane_id": spec.lane_id,
        "input": {"path": "/challenge", "read_only": True, "fingerprint": spec.input_fingerprint},
        "paths": {"work": "/work", "evidence": "/evidence", "artifacts": "/artifacts"},
        "declared_targets": [row.to_dict() for row in spec.targets],
        "service_endpoints": list(spec.service_endpoints),
    }
    atomic_json(spec.lane_root / "context" / "lane.json", context)
    (spec.lane_root / "context" / "lane.json").chmod(0o444)


def _validate_spec(spec: SandboxSpec) -> None:
    for value, label in ((spec.run_id, "run id"), (spec.challenge_id, "challenge id"), (spec.lane_id, "lane id")):
        validate_identifier(value, label)
    if spec.source.is_symlink() or not spec.source.is_dir():
        raise SandboxError("prepared challenge input is missing or unsafe")
    if spec.source.stat().st_mode & 0o222:
        raise SandboxError("prepared challenge input must be read-only")
    if spec.targets and spec.service_network:
        raise SandboxError("a sandbox cannot join both a remote and challenge-service network")
    if bool(spec.service_network) != bool(spec.service_endpoints):
        raise SandboxError("service network and endpoints must be supplied together")
    if spec.service_network and not re.fullmatch(r"ctf-os-net-[a-z0-9_.-]{1,100}", spec.service_network):
        raise SandboxError("service network is not race-scoped")
    if spec.artifact_inbox is not None:
        inbox = spec.artifact_inbox
        if inbox.is_symlink() or not inbox.is_dir():
            raise SandboxError("lane artifact inbox is missing or unsafe")
        expected = (spec.lane_root.resolve().parents[1] / "exchange" / "inbox" / spec.lane_id)
        if inbox.resolve() != expected.resolve():
            raise SandboxError("lane artifact inbox identity mismatch")
    parse_size_bytes(resource_profile(spec.resource_profile).storage)


def _target_identity(metadata: Mapping[str, Any], requested: str | None) -> str:
    identities = [str(value) for value in metadata.get("target_identities", [])]
    if requested is not None:
        if requested not in identities:
            raise SandboxError("target identity was not declared for this sandbox")
        return requested
    if len(identities) == 1:
        return identities[0]
    if identities:
        return "UNSPECIFIED_DECLARED_TARGET"
    return f"challenge:{metadata['challenge_id']}"


def _metadata_name(metadata: Mapping[str, Any]) -> str:
    name = str(metadata.get("name", ""))
    if not re.fullmatch(r"ctf-os-[a-z0-9_.-]{1,110}", name):
        raise SandboxError("invalid sandbox container identity")
    return name


def user_exec_prefix(
    metadata: Mapping[str, Any],
    *,
    docker: str = "docker",
    interactive: bool = False,
    detach: bool = False,
    workdir: str | None = None,
) -> list[str]:
    """Build a credential-isolated docker exec prefix for the sandbox user."""

    argv = [docker, "exec"]
    if interactive:
        argv.append("--interactive")
    if detach:
        argv.append("--detach")
    argv.extend(["--user", "1001:1001"])
    if workdir is not None:
        argv.extend(["--workdir", workdir])
    for value in USER_EXEC_ENV:
        argv.extend(["--env", value])
    argv.append(_metadata_name(metadata))
    return argv


def _kill_exec(
    name: str,
    pid_file: str,
    *,
    docker: str,
    signal: str = "TERM",
    timeout_seconds: float = 10,
) -> bool:
    if signal not in {"TERM", "KILL"}:
        raise SandboxError("unsupported sandbox exec termination signal")
    try:
        result = subprocess.run(
            [
                docker, "exec", "--user", "1001:1001", name, "sh", "-c",
                (
                    "p=$(cat \"$1\" 2>/dev/null || true); "
                    "[ -n \"$p\" ] && kill -\"$2\" -\"$p\" 2>/dev/null || true"
                ),
                "ctf-os-kill", pid_file, signal,
            ],
            capture_output=True, timeout=timeout_seconds, check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _secure_binary_file(path: Path):
    if path.is_symlink() or path.exists():
        raise SandboxError(f"command log path is unsafe: {path}")
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    return os.fdopen(descriptor, "wb")


class _NormalizedDigest:
    def __init__(self) -> None:
        self._digest = hashlib.sha256()
        self._pending_cr = False

    def update(self, chunk: bytes) -> None:
        data = chunk
        if self._pending_cr:
            data = b"\r" + data
            self._pending_cr = False
        if data.endswith(b"\r"):
            data = data[:-1]
            self._pending_cr = True
        self._digest.update(data.replace(b"\r\n", b"\n").replace(b"\r", b"\n"))

    def hexdigest(self) -> str:
        if self._pending_cr:
            self._digest.update(b"\n")
            self._pending_cr = False
        return self._digest.hexdigest()


def _run(
    runner: Callable[..., subprocess.CompletedProcess[str]], argv: Sequence[str], *, timeout: int
) -> subprocess.CompletedProcess[str]:
    try:
        return runner(list(argv), capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise SandboxError(f"required executable not found: {argv[0]}") from exc
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SandboxError(f"controller command failed: {exc}") from exc


def _now() -> str:
    return datetime.now(UTC).isoformat()
