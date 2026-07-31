"""Durable host supervision for challenge-scoped background sandbox jobs.

The image-level ``ctf-bg`` process owns and contains the untrusted command.
This module adds the missing host side: a trusted, detached monitor acquires
the complete :class:`LeaseBroker` vector before creating the dedicated Docker
runtime and releases it only after the recorded job is terminal and that exact
runtime has been removed.

Operational receipts live below an engine-owned mode-0700 runtime directory.
They are not canonical challenge state and never authorize a different scope;
the engine records the returned exact :class:`JobRef` in ``state.json``.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ctf_os.director.leases import LeaseBroker
from ctf_os.director.resources import ResourceVector
from ctf_os.store.atomic import (
    atomic_write_json,
    canonical_json_bytes,
    strict_json_loads,
)

from .docker import DockerLimits, DockerSandboxBackend
from .files import ensure_private_directory
from .types import (
    JOB_SUPERVISOR_ID,
    ChallengeScope,
    CommandSpec,
    JobLog,
    JobRef,
    JobState,
    JobStatus,
    NetworkPolicy,
    NetworkTarget,
    SandboxError,
    ScopeError,
)

_RECEIPT_NAME = "receipt.json"
_REQUEST_NAME = "request.json"
_MAX_CONTROL_DOCUMENT_BYTES = 256 * 1024
_TERMINAL_STATES = frozenset(
    {
        JobState.COMPLETED,
        JobState.FAILED,
        JobState.TIMED_OUT,
        JobState.CANCELLED,
        JobState.LOST,
    }
)


class _SupervisorStop(BaseException):
    """Internal signal-safe unwind used only by the trusted worker."""


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _pid_start_ticks(pid: int) -> int | None:
    if not isinstance(pid, int) or pid <= 1:
        return None
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        fields = text[text.rfind(")") + 2 :].split()
        if fields[0] in {"Z", "X", "x"}:
            return None
        return int(fields[19])
    except (OSError, UnicodeError, ValueError, IndexError):
        return None


def _pid_matches(pid: object, start_ticks: object) -> bool:
    return (
        type(pid) is int
        and type(start_ticks) is int
        and _pid_start_ticks(pid) == start_ticks
    )


def _status_dict(status: JobStatus) -> dict[str, object]:
    return {
        "status": status.status.value,
        "exit_code": status.exit_code,
        "timed_out": status.timed_out,
        "cancelled": status.cancelled,
        "started_at": status.started_at,
        "finished_at": status.finished_at,
    }


def _ref_dict(ref: JobRef) -> dict[str, str]:
    value = {
        "job_id": ref.job_id,
        "scope_fingerprint": ref.scope_fingerprint,
        "runtime_id": ref.runtime_id,
    }
    if ref.supervisor_id is not None:
        value["supervisor_id"] = ref.supervisor_id
    return value


def _ref_from_value(value: object) -> JobRef:
    if not isinstance(value, Mapping):
        raise SandboxError("background receipt has no exact job reference")
    return JobRef(
        job_id=value.get("job_id"),  # type: ignore[arg-type]
        scope_fingerprint=value.get("scope_fingerprint"),  # type: ignore[arg-type]
        runtime_id=value.get("runtime_id", "none"),  # type: ignore[arg-type]
        supervisor_id=value.get("supervisor_id"),  # type: ignore[arg-type]
    )


def _command_dict(spec: CommandSpec) -> dict[str, object]:
    return {
        "argv": list(spec.argv),
        "timeout_seconds": spec.timeout_seconds,
        "deadline_monotonic_seconds": spec.deadline_monotonic_seconds,
        "summary_bytes": spec.summary_bytes,
        "environment": dict(spec.environment),
        "network_target": (
            {
                "host": spec.network_target.host,
                "port": spec.network_target.port,
                "scheme": spec.network_target.scheme,
            }
            if spec.network_target is not None
            else None
        ),
        "resource_request": spec.resource_request.as_dict(),
    }


def _command_from_value(value: object) -> CommandSpec:
    if not isinstance(value, Mapping):
        raise SandboxError("background command contract is invalid")
    argv = value.get("argv")
    environment = value.get("environment", {})
    resource = value.get("resource_request")
    target_value = value.get("network_target")
    if (
        not isinstance(argv, list)
        or not all(isinstance(item, str) for item in argv)
        or not isinstance(environment, Mapping)
        or not all(
            isinstance(name, str) and isinstance(item, str)
            for name, item in environment.items()
        )
        or not isinstance(resource, Mapping)
    ):
        raise SandboxError("background command contract is invalid")
    target = None
    if target_value is not None:
        if not isinstance(target_value, Mapping):
            raise SandboxError("background network target is invalid")
        target = NetworkTarget(
            host=target_value.get("host"),  # type: ignore[arg-type]
            port=target_value.get("port"),  # type: ignore[arg-type]
            scheme=target_value.get("scheme"),  # type: ignore[arg-type]
        )
    return CommandSpec(
        argv=tuple(argv),
        timeout_seconds=value.get("timeout_seconds", 300),  # type: ignore[arg-type]
        deadline_monotonic_seconds=value.get(  # type: ignore[arg-type]
            "deadline_monotonic_seconds"
        ),
        summary_bytes=value.get("summary_bytes", 4096),  # type: ignore[arg-type]
        environment=dict(environment),
        network_target=target,
        resource_request=ResourceVector.from_mapping(resource),
    )


def _network_policy_dict(policy: NetworkPolicy) -> dict[str, object]:
    return {
        "docker_network": policy.docker_network,
        "enforcement": policy.enforcement,
        "http_requests_per_second": policy.http_requests_per_second,
        "http_burst": policy.http_burst,
        "allow_targets": [
            {
                "host": target.host,
                "port": target.port,
                "scheme": target.scheme,
            }
            for target in policy.allow_targets
        ],
    }


def _network_policy_from_value(value: object) -> NetworkPolicy:
    if not isinstance(value, Mapping):
        raise SandboxError("background network policy is invalid")
    targets = value.get("allow_targets", [])
    if not isinstance(targets, list):
        raise SandboxError("background network policy is invalid")
    parsed: list[NetworkTarget] = []
    for target in targets:
        if not isinstance(target, Mapping):
            raise SandboxError("background network target is invalid")
        parsed.append(
            NetworkTarget(
                host=target.get("host"),  # type: ignore[arg-type]
                port=target.get("port"),  # type: ignore[arg-type]
                scheme=target.get("scheme"),  # type: ignore[arg-type]
            )
        )
    if not parsed:
        return NetworkPolicy.deny_all()
    return NetworkPolicy.allow(
        parsed,
        docker_network=value.get("docker_network"),  # type: ignore[arg-type]
        enforcement=value.get("enforcement", "deny"),  # type: ignore[arg-type]
        http_requests_per_second=value.get(  # type: ignore[arg-type]
            "http_requests_per_second",
            2.0,
        ),
        http_burst=value.get("http_burst", 4),  # type: ignore[arg-type]
    )


def _read_private_json(path: Path) -> dict[str, object]:
    """Read one stable private regular JSON document without symlink follow."""

    try:
        before = path.stat(follow_symlinks=False)
    except OSError as error:
        raise SandboxError(f"background receipt is unavailable: {path.name}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_size > _MAX_CONTROL_DOCUMENT_BYTES
    ):
        raise SandboxError("background receipt is not a bounded regular file")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_size > _MAX_CONTROL_DOCUMENT_BYTES
                or (opened.st_dev, opened.st_ino)
                != (before.st_dev, before.st_ino)
            ):
                raise SandboxError("background receipt changed while opening")
            payload = os.read(descriptor, _MAX_CONTROL_DOCUMENT_BYTES + 1)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise SandboxError("background receipt could not be read safely") from error
    if (
        len(payload) > _MAX_CONTROL_DOCUMENT_BYTES
        or (after.st_size, after.st_mtime_ns)
        != (opened.st_size, opened.st_mtime_ns)
    ):
        raise SandboxError("background receipt changed while reading")
    try:
        value = strict_json_loads(payload, max_bytes=_MAX_CONTROL_DOCUMENT_BYTES)
    except (UnicodeError, ValueError) as error:
        raise SandboxError("background receipt contains invalid JSON") from error
    if not isinstance(value, dict):
        raise SandboxError("background receipt must be a JSON object")
    return value


def _backend_document(backend: DockerSandboxBackend) -> dict[str, object]:
    return {
        "scope": {
            "contest_id": backend.scope.contest_id,
            "category": backend.scope.category,
            "challenge_id": backend.scope.challenge_id,
            "challenge_dir": str(backend.scope.challenge_dir),
            "work_dir": str(backend.scope.work_dir),
            "fingerprint": backend.scope.fingerprint,
        },
        "image": backend.image,
        "image_digest": backend.image_digest,
        "network_policy": _network_policy_dict(backend.network_policy),
        "limits": asdict(backend.limits),
        "docker": backend.docker,
    }


def _backend_from_value(value: object) -> DockerSandboxBackend:
    if not isinstance(value, Mapping):
        raise SandboxError("background backend contract is invalid")
    scope_value = value.get("scope")
    limits_value = value.get("limits")
    if not isinstance(scope_value, Mapping) or not isinstance(
        limits_value, Mapping
    ):
        raise SandboxError("background backend contract is invalid")
    scope = ChallengeScope.create(
        contest_id=scope_value.get("contest_id"),  # type: ignore[arg-type]
        category=scope_value.get("category"),  # type: ignore[arg-type]
        challenge_id=scope_value.get("challenge_id"),  # type: ignore[arg-type]
        challenge_dir=Path(scope_value.get("challenge_dir")),  # type: ignore[arg-type]
        work_dir=Path(scope_value.get("work_dir")),  # type: ignore[arg-type]
    )
    if scope.fingerprint != scope_value.get("fingerprint"):
        raise ScopeError("background backend scope binding changed")
    allowed_limit_names = {
        "cpus",
        "memory_mib",
        "pids",
        "shm_size",
        "ptrace",
        "kvm",
        "gpu_flags",
        "read_only_root",
        "run_as_host_user",
        "work_tree_max_bytes",
    }
    if set(limits_value) != allowed_limit_names:
        raise SandboxError("background Docker limit contract is invalid")
    limits_args = dict(limits_value)
    gpu_flags = limits_args.get("gpu_flags")
    if not isinstance(gpu_flags, list):
        raise SandboxError("background GPU flag contract is invalid")
    limits_args["gpu_flags"] = tuple(gpu_flags)
    return DockerSandboxBackend(
        scope,
        image=value.get("image"),  # type: ignore[arg-type]
        image_digest=value.get("image_digest"),  # type: ignore[arg-type]
        network_policy=_network_policy_from_value(value.get("network_policy")),
        limits=DockerLimits(**limits_args),  # type: ignore[arg-type]
        docker=value.get("docker", "docker"),  # type: ignore[arg-type]
    )


class BackgroundJobSupervisor:
    """Launch and reconcile trusted host monitors for one lease broker."""

    def __init__(
        self,
        root: Path,
        lease_broker: LeaseBroker,
        *,
        lease_wait_timeout: float = 300.0,
    ) -> None:
        if (
            isinstance(lease_wait_timeout, bool)
            or not isinstance(lease_wait_timeout, (int, float))
            or not math.isfinite(float(lease_wait_timeout))
            or not 0 <= float(lease_wait_timeout) <= 604800
        ):
            raise ValueError(
                "background lease wait timeout must be finite and bounded"
            )
        self.root = ensure_private_directory(root.expanduser().resolve())
        self.lease_broker = lease_broker
        self.lease_wait_timeout = float(lease_wait_timeout)

    def _scope_root(self, fingerprint: str) -> Path:
        if re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
            raise ScopeError("invalid background scope fingerprint")
        return ensure_private_directory(self.root / fingerprint)

    def _job_root(self, fingerprint: str, supervisor_id: str) -> Path:
        if not JOB_SUPERVISOR_ID.fullmatch(supervisor_id):
            raise ScopeError("invalid background supervisor identity")
        return self._scope_root(fingerprint) / supervisor_id

    def _write_request(
        self,
        backend: DockerSandboxBackend,
        spec: CommandSpec,
        *,
        supervisor_id: str,
        name: str | None,
        owner: str,
    ) -> Path:
        job_root = self._job_root(
            backend.scope.fingerprint,
            supervisor_id,
        )
        try:
            job_root.mkdir(mode=0o700)
        except FileExistsError as error:
            raise SandboxError(
                "background supervisor identity already exists"
            ) from error
        request = {
            "schema_version": 1,
            "supervisor_id": supervisor_id,
            "created_at": _utc_now(),
            "backend": _backend_document(backend),
            "command": _command_dict(spec),
            "name": name,
            "lease": {
                "root": str(self.lease_broker.root),
                "capacity": self.lease_broker.capacity.as_dict(),
                "poll_interval": self.lease_broker.poll_interval,
                "wait_timeout": self.lease_wait_timeout,
                "owner": owner[:256],
            },
        }
        atomic_write_json(job_root / _REQUEST_NAME, request, mode=0o400)
        return job_root

    @staticmethod
    def _terminate_worker(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            # Never SIGKILL a trusted monitor that may be holding a durable
            # lease while retrying exact Docker cleanup. Its receipt/recovery
            # gate remains authoritative and the monitor is safe to outlive
            # the interrupted caller.
            return

    def start(
        self,
        backend: DockerSandboxBackend,
        spec: CommandSpec,
        *,
        name: str | None = None,
        owner: str | None = None,
    ) -> JobRef:
        """Return only after the worker publishes a lease-bound launch receipt."""

        # Reconcile any monitor that died since the last engine boundary before
        # admitting another resource request.
        self.recover(backend)
        if name is not None and (
            not isinstance(name, str)
            or not name
            or len(name) > 200
            or len(name.encode("utf-8")) > 1024
            or any(ord(character) < 0x20 for character in name)
        ):
            raise ValueError(
                "background job name must be a bounded printable string"
            )
        owner_value = owner or (
            f"{backend.scope.qualified_id}:background"
        )
        if (
            not owner_value
            or len(owner_value) > 256
            or any(ord(character) < 0x20 for character in owner_value)
        ):
            raise ValueError("background lease owner is invalid")
        supervisor_id = f"bg-{secrets.token_hex(16)}"
        # The persisted owner is an exact recovery binding, not merely a
        # human-readable challenge label.  This closes the crash window after
        # durable acquire but before the worker can publish its lease id.
        owner_value = f"{owner_value[:220]}:{supervisor_id}"
        job_root = self._write_request(
            backend,
            spec,
            supervisor_id=supervisor_id,
            name=name,
            owner=owner_value,
        )
        try:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "ctf_os.sandbox.supervisor",
                    "--worker",
                    str(job_root),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
            )
        except (OSError, ValueError) as error:
            atomic_write_json(
                job_root / _RECEIPT_NAME,
                {
                    "schema_version": 1,
                    "supervisor_id": supervisor_id,
                    "state": "launch_failed",
                    "finished_at": _utc_now(),
                    "error": (
                        "trusted background supervisor could not start: "
                        f"{type(error).__name__}"
                    ),
                },
            )
            raise SandboxError(
                "trusted background supervisor could not start"
            ) from error

        wait_deadline = time.monotonic() + self.lease_wait_timeout + 180
        if spec.deadline_monotonic_seconds is not None:
            wait_deadline = min(
                wait_deadline,
                spec.deadline_monotonic_seconds + 60,
            )
        try:
            while time.monotonic() < wait_deadline:
                receipt_path = job_root / _RECEIPT_NAME
                if receipt_path.exists():
                    receipt = _read_private_json(receipt_path)
                    if (
                        receipt.get("schema_version") != 1
                        or receipt.get("supervisor_id") != supervisor_id
                    ):
                        raise SandboxError(
                            "background launch receipt identity changed"
                        )
                    state = receipt.get("state")
                    if state in {"running", "terminal"}:
                        ref = _ref_from_value(receipt.get("ref"))
                        self._require_exact_receipt(
                            backend,
                            ref,
                            receipt=receipt,
                        )
                        if receipt.get("supervisor_pid") != process.pid:
                            raise SandboxError(
                                "background launch receipt PID changed"
                            )
                        return ref
                    if state in {"failed", "launch_failed", "cancelled"}:
                        raise SandboxError(
                            str(
                                receipt.get(
                                    "error",
                                    "background job launch failed",
                                )
                            )[:4096]
                        )
                returncode = process.poll()
                if returncode is not None:
                    raise SandboxError(
                        "background supervisor exited before launch receipt "
                        f"(status {returncode})"
                    )
                time.sleep(0.02)
            raise SandboxError(
                "timed out waiting for background launch receipt"
            )
        except BaseException:
            self._terminate_worker(process)
            raise

    def _require_exact_receipt(
        self,
        backend: DockerSandboxBackend,
        ref: JobRef,
        *,
        receipt: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        if ref.scope_fingerprint != backend.scope.fingerprint:
            raise ScopeError("job reference belongs to another challenge")
        if ref.supervisor_id is None:
            raise ScopeError("job reference has no supervisor receipt")
        value = (
            dict(receipt)
            if receipt is not None
            else _read_private_json(
                self._job_root(
                    ref.scope_fingerprint,
                    ref.supervisor_id,
                )
                / _RECEIPT_NAME
            )
        )
        if (
            value.get("schema_version") != 1
            or value.get("supervisor_id") != ref.supervisor_id
            or _ref_from_value(value.get("ref")) != ref
        ):
            raise ScopeError("job reference does not match its launch receipt")
        return value

    def recover(
        self,
        backend: DockerSandboxBackend,
        ref: JobRef | None = None,
    ) -> tuple[JobStatus, ...]:
        """Cancel orphan runtimes before reclaiming their stale host leases."""

        refs: list[JobRef] = []
        unbound: list[tuple[Path, dict[str, object]]] = []
        if ref is not None:
            refs.append(ref)
        else:
            scope_root = self._scope_root(backend.scope.fingerprint)
            for index, directory in enumerate(
                sorted(scope_root.iterdir()),
                start=1,
            ):
                if index > 1000:
                    raise SandboxError(
                        "background receipt count exceeds the recovery bound"
                    )
                if (
                    not directory.is_dir()
                    or directory.is_symlink()
                    or not JOB_SUPERVISOR_ID.fullmatch(directory.name)
                ):
                    continue
                receipt_path = directory / _RECEIPT_NAME
                if not receipt_path.exists():
                    continue
                receipt = _read_private_json(receipt_path)
                if receipt.get("ref") is not None:
                    refs.append(_ref_from_value(receipt["ref"]))
                elif receipt.get("state") != "recovered":
                    unbound.append((directory, receipt))

        # A SIGKILL can land after durable acquire or Docker create but before
        # the worker publishes a JobRef.  The immutable request binds a unique
        # supervisor owner and the container binds the same supervisor label,
        # so both resources can still be recovered without guessing.
        for directory, receipt in unbound:
            supervisor_id = directory.name
            if (
                receipt.get("schema_version") != 1
                or receipt.get("supervisor_id") != supervisor_id
            ):
                raise ScopeError(
                    "unbound background receipt identity changed"
                )
            if _pid_matches(
                receipt.get("supervisor_pid"),
                receipt.get("supervisor_start_ticks"),
            ):
                continue
            request = _read_private_json(directory / _REQUEST_NAME)
            if (
                request.get("schema_version") != 1
                or request.get("supervisor_id") != supervisor_id
            ):
                raise ScopeError(
                    "unbound background request identity changed"
                )
            expected_request_sha256 = receipt.get("request_sha256")
            if (
                expected_request_sha256 is not None
                and expected_request_sha256
                != hashlib.sha256(
                    canonical_json_bytes(request)
                ).hexdigest()
            ):
                raise ScopeError(
                    "unbound background request digest changed"
                )
            lease_value = request.get("lease")
            owner = (
                lease_value.get("owner")
                if isinstance(lease_value, Mapping)
                else None
            )
            if not isinstance(owner, str):
                raise SandboxError(
                    "unbound durable lease recovery owner is unavailable"
                )
            cleanup_error = backend._remove_supervised_runtime(
                supervisor_id,
                runtime_id=None,
                missing_ok=True,
            )
            if cleanup_error is not None:
                raise SandboxError(
                    "unbound background runtime cleanup failed: "
                    f"{cleanup_error}"
                )
            matching_leases = tuple(
                record
                for record in self.lease_broker.status().leases
                if record.durable and record.owner == owner
            )
            if len(matching_leases) > 1:
                raise SandboxError(
                    "unbound durable lease recovery is ambiguous"
                )
            for record in matching_leases:
                self.lease_broker.release_orphaned_durable(
                    record.lease_id,
                    owner=owner,
                    missing_ok=True,
                )
            atomic_write_json(
                directory / _RECEIPT_NAME,
                {
                    **receipt,
                    "state": "recovered",
                    "recovered_at": _utc_now(),
                    "recovery_action": (
                        "unbound_runtime_removed_and_lease_reclaimed"
                    ),
                    "lease_owner": owner,
                    **(
                        {"lease_id": matching_leases[0].lease_id}
                        if matching_leases
                        else {}
                    ),
                },
            )

        statuses: list[JobStatus] = []
        for current_ref in refs:
            receipt = self._require_exact_receipt(backend, current_ref)
            worker_alive = _pid_matches(
                receipt.get("supervisor_pid"),
                receipt.get("supervisor_start_ticks"),
            )
            try:
                status = backend.job_status(current_ref)
            except SandboxError:
                status = JobStatus(current_ref, JobState.LOST)
            if worker_alive:
                statuses.append(status)
                continue
            if status.status in {JobState.STARTING, JobState.RUNNING}:
                try:
                    status = backend.cancel_job(
                        current_ref,
                        grace_seconds=0,
                    )
                except SandboxError:
                    status = JobStatus(current_ref, JobState.LOST)
            assert current_ref.supervisor_id is not None
            cleanup_error = backend._remove_supervised_runtime(
                current_ref.supervisor_id,
                runtime_id=current_ref.runtime_id,
                missing_ok=True,
            )
            if cleanup_error is not None:
                raise SandboxError(
                    "orphaned background runtime cleanup failed: "
                    f"{cleanup_error}"
                )
            lease_id = receipt.get("lease_id")
            if isinstance(lease_id, str):
                request = _read_private_json(
                    self._job_root(
                        current_ref.scope_fingerprint,
                        current_ref.supervisor_id,
                    )
                    / _REQUEST_NAME
                )
                lease_value = request.get("lease")
                owner = (
                    lease_value.get("owner")
                    if isinstance(lease_value, Mapping)
                    else None
                )
                if not isinstance(owner, str):
                    raise SandboxError(
                        "durable lease recovery owner is unavailable"
                    )
                self.lease_broker.release_orphaned_durable(
                    lease_id,
                    owner=owner,
                    missing_ok=True,
                )
            recovered = {
                **receipt,
                "state": "recovered",
                "recovered_at": _utc_now(),
                "recovery_action": (
                    "orphaned_command_cancelled"
                    if status.status is JobState.CANCELLED
                    else "terminal_runtime_removed"
                    if status.status in _TERMINAL_STATES
                    else "orphaned_runtime_lost"
                ),
                "job_status": _status_dict(status),
            }
            atomic_write_json(
                self._job_root(
                    current_ref.scope_fingerprint,
                    current_ref.supervisor_id,
                )
                / _RECEIPT_NAME,
                recovered,
            )
            statuses.append(status)
        # A dead worker's flock is already closed.  One broker transaction
        # removes the exact stale metadata before this method returns.
        self.lease_broker.status()
        return tuple(statuses)

    def status(
        self,
        backend: DockerSandboxBackend,
        ref: JobRef,
    ) -> JobStatus:
        self._require_exact_receipt(backend, ref)
        try:
            return backend.job_status(ref)
        except SandboxError:
            # Status is observational. Explicit recover/cancel owns any
            # container removal and durable-lease retirement.
            return JobStatus(ref, JobState.LOST)

    def log(
        self,
        backend: DockerSandboxBackend,
        ref: JobRef,
        *,
        tail_bytes: int = 8192,
    ) -> JobLog:
        self._require_exact_receipt(backend, ref)
        return backend.job_log(ref, tail_bytes=tail_bytes)

    def cancel(
        self,
        backend: DockerSandboxBackend,
        ref: JobRef,
        *,
        grace_seconds: int = 3,
    ) -> JobStatus:
        receipt = self._require_exact_receipt(backend, ref)
        if not _pid_matches(
            receipt.get("supervisor_pid"),
            receipt.get("supervisor_start_ticks"),
        ):
            recovered = self.recover(backend, ref)
            return recovered[0]
        return backend.cancel_job(ref, grace_seconds=grace_seconds)

    def list(
        self,
        backend: DockerSandboxBackend,
    ) -> tuple[JobStatus, ...]:
        statuses: list[JobStatus] = []
        scope_root = self._scope_root(backend.scope.fingerprint)
        for index, directory in enumerate(
            sorted(scope_root.iterdir()),
            start=1,
        ):
            if index > 1000:
                raise SandboxError(
                    "background receipt count exceeds the listing bound"
                )
            if (
                not directory.is_dir()
                or directory.is_symlink()
                or not JOB_SUPERVISOR_ID.fullmatch(directory.name)
            ):
                continue
            receipt_path = directory / _RECEIPT_NAME
            if not receipt_path.exists():
                continue
            receipt = _read_private_json(receipt_path)
            if receipt.get("ref") is None:
                continue
            current_ref = _ref_from_value(receipt["ref"])
            self._require_exact_receipt(
                backend,
                current_ref,
                receipt=receipt,
            )
            try:
                statuses.append(backend.job_status(current_ref))
            except SandboxError:
                statuses.append(JobStatus(current_ref, JobState.LOST))
        return tuple(statuses)


def _worker_receipt(
    *,
    supervisor_id: str,
    request_sha256: str,
    state: str,
    worker_pid: int,
    worker_start_ticks: int,
    ref: JobRef | None = None,
    lease_id: str | None = None,
    lease_owner: str | None = None,
    status: JobStatus | None = None,
    error: str | None = None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": 1,
        "supervisor_id": supervisor_id,
        "request_sha256": request_sha256,
        "state": state,
        "supervisor_pid": worker_pid,
        "supervisor_start_ticks": worker_start_ticks,
        "updated_at": _utc_now(),
    }
    if ref is not None:
        value["ref"] = _ref_dict(ref)
    if lease_id is not None:
        value["lease_id"] = lease_id
    if lease_owner is not None:
        value["lease_owner"] = lease_owner
    if status is not None:
        value["job_status"] = _status_dict(status)
    if error is not None:
        value["error"] = error[:4096]
    return value


def _worker(job_root: Path) -> int:
    if (
        not job_root.is_absolute()
        or not JOB_SUPERVISOR_ID.fullmatch(job_root.name)
        or job_root.is_symlink()
    ):
        raise SandboxError("invalid background worker directory")
    request_path = job_root / _REQUEST_NAME
    request = _read_private_json(request_path)
    request_sha256 = hashlib.sha256(
        canonical_json_bytes(request)
    ).hexdigest()
    supervisor_id = request.get("supervisor_id")
    if (
        request.get("schema_version") != 1
        or supervisor_id != job_root.name
        or not isinstance(supervisor_id, str)
    ):
        raise SandboxError("background worker request identity changed")
    backend = _backend_from_value(request.get("backend"))
    spec = _command_from_value(request.get("command"))
    name = request.get("name")
    if name is not None and not isinstance(name, str):
        raise SandboxError("background job name is invalid")
    lease_value = request.get("lease")
    if not isinstance(lease_value, Mapping):
        raise SandboxError("background lease contract is invalid")
    capacity_value = lease_value.get("capacity")
    if not isinstance(capacity_value, Mapping):
        raise SandboxError("background lease capacity is invalid")
    wait_timeout = lease_value.get("wait_timeout")
    poll_interval = lease_value.get("poll_interval")
    owner = lease_value.get("owner")
    lease_root = lease_value.get("root")
    if (
        isinstance(wait_timeout, bool)
        or not isinstance(wait_timeout, (int, float))
        or not math.isfinite(float(wait_timeout))
        or not 0 <= float(wait_timeout) <= 604800
        or isinstance(poll_interval, bool)
        or not isinstance(poll_interval, (int, float))
        or not math.isfinite(float(poll_interval))
        or float(poll_interval) <= 0
        or not isinstance(owner, str)
        or not isinstance(lease_root, str)
        or not Path(lease_root).is_absolute()
    ):
        raise SandboxError("background lease contract is invalid")
    broker = LeaseBroker(
        Path(lease_root),
        ResourceVector.from_mapping(capacity_value),
        poll_interval=float(poll_interval),
    )
    worker_pid = os.getpid()
    worker_start_ticks = _pid_start_ticks(worker_pid)
    if worker_start_ticks is None:
        raise SandboxError("background worker PID identity is unavailable")
    receipt_path = job_root / _RECEIPT_NAME
    atomic_write_json(
        receipt_path,
        _worker_receipt(
            supervisor_id=supervisor_id,
            request_sha256=request_sha256,
            state="starting",
            worker_pid=worker_pid,
            worker_start_ticks=worker_start_ticks,
            lease_owner=owner,
        ),
    )

    def stop_handler(_signum: int, _frame: object) -> None:
        raise _SupervisorStop()

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    lease = None
    ref: JobRef | None = None
    status: JobStatus | None = None

    def publish_cleanup_pending(detail: str) -> None:
        try:
            atomic_write_json(
                receipt_path,
                _worker_receipt(
                    supervisor_id=supervisor_id,
                    request_sha256=request_sha256,
                    state="cleanup_pending",
                    worker_pid=worker_pid,
                    worker_start_ticks=worker_start_ticks,
                    ref=ref,
                    lease_id=(
                        lease.lease_id if lease is not None else None
                    ),
                    lease_owner=owner,
                    status=status,
                    error=detail,
                ),
            )
        except BaseException:
            # The durable broker record remains the authoritative capacity
            # gate even if a signal interrupts this advisory receipt update.
            pass

    def wait_for_exact_runtime_removal() -> None:
        """Hold the durable lease until exact labelled cleanup succeeds."""

        delay = 0.05
        while True:
            try:
                cleanup_error = backend._remove_supervised_runtime(
                    supervisor_id,
                    runtime_id=(
                        ref.runtime_id if ref is not None else None
                    ),
                    missing_ok=True,
                )
                if cleanup_error is None:
                    return
                detail = (
                    "background runtime cleanup pending: "
                    f"{str(cleanup_error)[:2048]}"
                )
            except BaseException as cleanup_error:
                detail = (
                    "background runtime cleanup pending: "
                    f"{type(cleanup_error).__name__}: "
                    f"{str(cleanup_error)[:2048]}"
                )
            publish_cleanup_pending(detail)
            try:
                time.sleep(delay)
            except BaseException:
                # SIGTERM requests cancellation, but it can never authorize
                # releasing capacity while the runtime may still exist.
                pass
            delay = min(delay * 2, 5.0)

    def wait_for_lease_release() -> None:
        """Retry an interrupted exact release without weakening containment."""

        assert lease is not None
        delay = 0.05
        while not lease.released:
            try:
                lease.release()
            except BaseException as release_error:
                publish_cleanup_pending(
                    "background lease release pending: "
                    f"{type(release_error).__name__}: "
                    f"{str(release_error)[:2048]}"
                )
                if lease.released:
                    return
                try:
                    time.sleep(delay)
                except BaseException:
                    pass
                delay = min(delay * 2, 5.0)

    try:
        effective_wait = float(wait_timeout)
        if spec.deadline_monotonic_seconds is not None:
            effective_wait = min(
                effective_wait,
                max(
                    0.0,
                    spec.deadline_monotonic_seconds - time.monotonic(),
                ),
            )
        lease = broker.acquire(
            spec.resource_request,
            timeout=effective_wait,
            owner=owner,
            durable=True,
        )
        if lease is None:
            raise SandboxError(
                "timed out waiting for background host resources"
            )
        # Publish the exact durable reservation before starting Docker.  If
        # the worker is SIGKILLed before this write, the unique owner in the
        # immutable request still permits unambiguous orphan recovery.
        atomic_write_json(
            receipt_path,
            _worker_receipt(
                supervisor_id=supervisor_id,
                request_sha256=request_sha256,
                state="leased",
                worker_pid=worker_pid,
                worker_start_ticks=worker_start_ticks,
                lease_id=lease.lease_id,
                lease_owner=owner,
            ),
        )
        ref = backend._start_supervised_job(
            spec,
            supervisor_id=supervisor_id,
            name=name,
        )
        atomic_write_json(
            receipt_path,
            _worker_receipt(
                supervisor_id=supervisor_id,
                request_sha256=request_sha256,
                state="running",
                worker_pid=worker_pid,
                worker_start_ticks=worker_start_ticks,
                ref=ref,
                lease_id=lease.lease_id,
                lease_owner=owner,
                status=backend.job_status(ref),
            ),
        )
        while True:
            status = backend.job_status(ref)
            if status.status in _TERMINAL_STATES:
                break
            time.sleep(0.25)
        wait_for_exact_runtime_removal()
        wait_for_lease_release()
        atomic_write_json(
            receipt_path,
            _worker_receipt(
                supervisor_id=supervisor_id,
                request_sha256=request_sha256,
                state="terminal",
                worker_pid=worker_pid,
                worker_start_ticks=worker_start_ticks,
                ref=ref,
                lease_id=lease.lease_id,
                lease_owner=owner,
                status=status,
            ),
        )
        return 0
    except BaseException as error:
        if ref is not None:
            try:
                current = backend.job_status(ref)
                if current.status not in _TERMINAL_STATES:
                    status = backend.cancel_job(ref, grace_seconds=3)
                else:
                    status = current
            except BaseException as cancellation_error:
                publish_cleanup_pending(
                    "background job cancellation pending; exact runtime "
                    "removal will enforce containment: "
                    f"{type(cancellation_error).__name__}"
                )
        if lease is not None and not lease.released:
            # This also covers launch failures after Docker create but before
            # a JobRef receipt: runtime_id=None derives and verifies the exact
            # network identity from trusted labels.
            wait_for_exact_runtime_removal()
            wait_for_lease_release()
        state = (
            "cancelled"
            if isinstance(error, _SupervisorStop)
            else "failed"
        )
        message = (
            "trusted background supervisor was stopped"
            if isinstance(error, _SupervisorStop)
            else (
                "trusted background supervisor failed: "
                f"{type(error).__name__}: {str(error)[:2048]}"
            )
        )
        atomic_write_json(
            receipt_path,
            _worker_receipt(
                supervisor_id=supervisor_id,
                request_sha256=request_sha256,
                state=state,
                worker_pid=worker_pid,
                worker_start_ticks=worker_start_ticks,
                ref=ref,
                lease_id=lease.lease_id if lease is not None else None,
                lease_owner=owner,
                status=status,
                error=message,
            ),
        )
        return 130 if isinstance(error, _SupervisorStop) else 1


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 2 or arguments[0] != "--worker":
        print(
            "ctf_os.sandbox.supervisor is an internal worker",
            file=sys.stderr,
        )
        return 2
    try:
        return _worker(Path(arguments[1]))
    except Exception as error:
        print(
            "background supervisor bootstrap failed: "
            f"{type(error).__name__}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["BackgroundJobSupervisor"]
