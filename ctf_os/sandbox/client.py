"""Typed local and Unix-socket clients for the sandbox boundary."""

from __future__ import annotations

import hashlib
import json
import math
import os
import socket
import stat
import time
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from ctf_os.director.resources import ResourceVector

from .docker import DockerLimits, DockerSandboxBackend
from .files import (
    DEFAULT_SNAPSHOT_MAX_BYTES,
    DEFAULT_WORK_TREE_MAX_BYTES,
    SafeFileError,
    measure_work_tree,
)
from .types import (
    JOB_SUPERVISOR_ID,
    AnalysisLeaseRef,
    AnalysisRuntimeCleanupPending,
    ArtifactRef,
    BackgroundLaunchState,
    BackgroundLaunchStatus,
    BackgroundJobUnsupported,
    ChallengeScope,
    CommandSpec,
    JobLog,
    JobRef,
    JobState,
    JobStatus,
    NetworkPolicy,
    NetworkTarget,
    ProofInput,
    ProofOutput,
    SandboxError,
    SandboxResult,
    ScopeError,
    sandbox_result_from_mapping,
    validate_deadline_monotonic_seconds,
)

if TYPE_CHECKING:
    from .supervisor import BackgroundJobSupervisor

MAX_RPC_BYTES = 1024 * 1024


def _validate_supervisor_id(value: object) -> str:
    if (
        type(value) is not str
        or not JOB_SUPERVISOR_ID.fullmatch(value)
    ):
        raise ValueError("invalid background supervisor identity")
    return value


def _validate_cancel_grace_seconds(grace_seconds: int) -> int:
    if (
        isinstance(grace_seconds, bool)
        or not isinstance(grace_seconds, int)
        or not 0 <= grace_seconds <= 30
    ):
        raise ValueError("grace_seconds must be between 0 and 30")
    return grace_seconds


@runtime_checkable
class ChallengeSandboxClient(Protocol):
    """The complete challenge-scoped sandbox surface used by the engine."""

    @property
    def scope_fingerprint(self) -> str: ...

    def initialize_workspace(
        self,
        *,
        deadline_monotonic_seconds: float | None = None,
    ) -> None: ...

    def run(self, spec: CommandSpec) -> SandboxResult: ...

    def isolated_analysis_runtime_id(
        self,
        lease: AnalysisLeaseRef,
    ) -> str: ...

    def run_isolated_analysis(
        self,
        lease: AnalysisLeaseRef,
        spec: CommandSpec,
        *,
        input_locators: Sequence[str] = (),
    ) -> SandboxResult: ...

    def cleanup_isolated_analysis(
        self,
        lease: AnalysisLeaseRef,
    ) -> None: ...

    def start_job(
        self,
        spec: CommandSpec,
        *,
        name: str | None = None,
        supervisor_id: str | None = None,
    ) -> JobRef: ...

    def job_status(self, ref: JobRef) -> JobStatus: ...

    def job_log(self, ref: JobRef, *, tail_bytes: int = 8192) -> JobLog: ...

    def cancel_job(self, ref: JobRef, *, grace_seconds: int = 3) -> JobStatus: ...

    def list_jobs(self) -> tuple[JobStatus, ...]: ...

    def recover_jobs(self) -> tuple[JobStatus, ...]: ...

    def recover_job_launch(
        self,
        supervisor_id: str,
    ) -> BackgroundLaunchStatus: ...

    def register_artifact(
        self,
        locator: str,
        *,
        maximum_bytes: int = DEFAULT_SNAPSHOT_MAX_BYTES,
    ) -> ArtifactRef: ...

    def run_clean_proof(
        self,
        spec: CommandSpec,
        *,
        input_locators: Sequence[str] = (),
        proof_inputs: Sequence[ProofInput] = (),
        proof_outputs: Sequence[ProofOutput] = (),
    ) -> SandboxResult: ...


def _hash_artifact(
    work_dir: Path,
    locator: str,
    scope_fingerprint: str,
    *,
    maximum_bytes: int,
) -> ArtifactRef:
    if (
        isinstance(maximum_bytes, bool)
        or not isinstance(maximum_bytes, int)
        or maximum_bytes <= 0
    ):
        raise ValueError("maximum_bytes must be positive")
    if (
        not locator
        or "\x00" in locator
        or Path(locator).is_absolute()
        or len(locator.encode("utf-8")) > 4096
    ):
        raise ScopeError("artifact locator must be a bounded relative path")
    unresolved = work_dir / locator
    current = work_dir
    for component in Path(locator).parts:
        current = current / component
        try:
            if current.is_symlink():
                raise ScopeError("artifact path must not contain symlinks")
        except OSError as error:
            raise ScopeError(f"artifact cannot be inspected: {locator}") from error
    try:
        candidate = unresolved.resolve(strict=True)
    except FileNotFoundError as error:
        raise ScopeError(f"artifact does not exist: {locator}") from error
    if candidate == work_dir or work_dir not in candidate.parents:
        raise ScopeError("artifact locator escapes the challenge workspace")
    try:
        before = unresolved.stat(follow_symlinks=False)
    except OSError as error:
        raise ScopeError(f"artifact cannot be inspected: {locator}") from error
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum_bytes:
        raise ScopeError("artifact must be a bounded regular file")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(unresolved, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_size > maximum_bytes
                or (opened.st_dev, opened.st_ino)
                != (before.st_dev, before.st_ino)
            ):
                raise ScopeError("artifact changed while opening")
            digest = hashlib.sha256()
            total = 0
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > maximum_bytes:
                    raise ScopeError("artifact grew beyond its size limit")
                digest.update(block)
            after = os.fstat(descriptor)
            if (
                after.st_size != opened.st_size
                or after.st_mtime_ns != opened.st_mtime_ns
            ):
                raise ScopeError("artifact changed while hashing")
        finally:
            os.close(descriptor)
    except OSError as error:
        raise ScopeError(f"artifact cannot be read safely: {locator}") from error
    normalized = candidate.relative_to(work_dir).as_posix()
    return ArtifactRef(
        locator=normalized,
        sha256=digest.hexdigest(),
        size_bytes=total,
        scope_fingerprint=scope_fingerprint,
    )


class LocalChallengeSandboxClient:
    """In-process client using the same fixed-scope backend as the daemon."""

    def __init__(
        self,
        scope: ChallengeScope,
        *,
        backend: DockerSandboxBackend | None = None,
        analysis_root: Path | None = None,
        image: str = "ctf-os:core",
        image_digest: str | None = None,
        network_policy: NetworkPolicy | None = None,
        limits: DockerLimits | None = None,
        job_supervisor: BackgroundJobSupervisor | None = None,
    ) -> None:
        if backend is not None and backend.scope != scope:
            raise ScopeError("sandbox backend belongs to another challenge scope")
        if backend is not None and analysis_root is not None:
            configured = getattr(backend, "analysis_root", None)
            try:
                requested = Path(analysis_root).expanduser().resolve(strict=True)
            except OSError as error:
                raise ScopeError("analysis root is unavailable") from error
            if configured != requested:
                raise ScopeError(
                    "sandbox backend has another trusted analysis root"
                )
        self.scope = scope
        self.backend = backend or DockerSandboxBackend(
            scope,
            analysis_root=analysis_root,
            image=image,
            image_digest=image_digest,
            network_policy=network_policy,
            limits=limits,
        )
        self.job_supervisor = job_supervisor

    @property
    def scope_fingerprint(self) -> str:
        return self.scope.fingerprint

    def _check_ref(self, ref: JobRef) -> None:
        if ref.scope_fingerprint != self.scope.fingerprint:
            raise ScopeError("job reference belongs to another challenge")

    def initialize_workspace(
        self,
        *,
        deadline_monotonic_seconds: float | None = None,
    ) -> None:
        self.backend.initialize_workspace(
            deadline_monotonic_seconds=deadline_monotonic_seconds
        )

    def run(self, spec: CommandSpec) -> SandboxResult:
        return self.backend.run(spec)

    def _check_analysis_ref(self, lease: AnalysisLeaseRef) -> None:
        if type(lease) is not AnalysisLeaseRef:
            raise TypeError("lease must be an AnalysisLeaseRef")
        if lease.scope_fingerprint != self.scope.fingerprint:
            raise ScopeError("analysis lease belongs to another challenge")

    def isolated_analysis_runtime_id(
        self,
        lease: AnalysisLeaseRef,
    ) -> str:
        self._check_analysis_ref(lease)
        return self.backend.isolated_analysis_runtime_id(lease)

    def run_isolated_analysis(
        self,
        lease: AnalysisLeaseRef,
        spec: CommandSpec,
        *,
        input_locators: Sequence[str] = (),
    ) -> SandboxResult:
        self._check_analysis_ref(lease)
        return self.backend.run_isolated_analysis(
            lease,
            spec,
            input_locators=input_locators,
        )

    def cleanup_isolated_analysis(
        self,
        lease: AnalysisLeaseRef,
    ) -> None:
        self._check_analysis_ref(lease)
        self.backend.cleanup_isolated_analysis(lease)

    def start_job(
        self,
        spec: CommandSpec,
        *,
        name: str | None = None,
        supervisor_id: str | None = None,
    ) -> JobRef:
        if self.job_supervisor is None:
            raise BackgroundJobUnsupported(
                "background job start requires a configured lease supervisor"
            )
        if supervisor_id is not None:
            supervisor_id = _validate_supervisor_id(supervisor_id)
        if supervisor_id is None:
            return self.job_supervisor.start(
                self.backend,
                spec,
                name=name,
                owner=f"{self.scope.qualified_id}:background",
            )
        return self.job_supervisor.start(
            self.backend,
            spec,
            name=name,
            owner=f"{self.scope.qualified_id}:background",
            supervisor_id=supervisor_id,
        )

    def job_status(self, ref: JobRef) -> JobStatus:
        self._check_ref(ref)
        if ref.supervisor_id is not None:
            if self.job_supervisor is None:
                raise BackgroundJobUnsupported(
                    "supervised job status requires its lease supervisor"
                )
            return self.job_supervisor.status(self.backend, ref)
        return self.backend.job_status(ref)

    def job_log(self, ref: JobRef, *, tail_bytes: int = 8192) -> JobLog:
        self._check_ref(ref)
        if ref.supervisor_id is not None:
            if self.job_supervisor is None:
                raise BackgroundJobUnsupported(
                    "supervised job logs require its lease supervisor"
                )
            return self.job_supervisor.log(
                self.backend,
                ref,
                tail_bytes=tail_bytes,
            )
        return self.backend.job_log(ref, tail_bytes=tail_bytes)

    def cancel_job(self, ref: JobRef, *, grace_seconds: int = 3) -> JobStatus:
        self._check_ref(ref)
        if ref.supervisor_id is not None:
            if self.job_supervisor is None:
                raise BackgroundJobUnsupported(
                    "supervised job cancellation requires its lease supervisor"
                )
            return self.job_supervisor.cancel(
                self.backend,
                ref,
                grace_seconds=_validate_cancel_grace_seconds(grace_seconds),
            )
        return self.backend.cancel_job(
            ref,
            grace_seconds=_validate_cancel_grace_seconds(grace_seconds),
        )

    def list_jobs(self) -> tuple[JobStatus, ...]:
        if self.job_supervisor is None:
            return ()
        return self.job_supervisor.list(self.backend)

    def recover_jobs(self) -> tuple[JobStatus, ...]:
        if self.job_supervisor is None:
            return ()
        return self.job_supervisor.recover(self.backend)

    def recover_job_launch(
        self,
        supervisor_id: str,
    ) -> BackgroundLaunchStatus:
        if self.job_supervisor is None:
            raise BackgroundJobUnsupported(
                "background launch recovery requires its lease supervisor"
            )
        supervisor_id = _validate_supervisor_id(supervisor_id)
        return self.job_supervisor.recover_launch(
            self.backend,
            supervisor_id,
        )

    def register_artifact(
        self,
        locator: str,
        *,
        maximum_bytes: int = DEFAULT_SNAPSHOT_MAX_BYTES,
    ) -> ArtifactRef:
        if (
            isinstance(maximum_bytes, bool)
            or not isinstance(maximum_bytes, int)
            or maximum_bytes <= 0
        ):
            raise ValueError("maximum_bytes must be positive")
        limits = getattr(self.backend, "limits", None)
        work_tree_max_bytes = getattr(
            limits,
            "work_tree_max_bytes",
            DEFAULT_WORK_TREE_MAX_BYTES,
        )
        if (
            isinstance(work_tree_max_bytes, bool)
            or not isinstance(work_tree_max_bytes, int)
            or work_tree_max_bytes <= 0
        ):
            raise ScopeError("sandbox backend has an invalid work-tree bound")

        try:
            measure_work_tree(
                self.scope.work_dir,
                maximum_bytes=work_tree_max_bytes,
            )
        except SafeFileError as error:
            raise ScopeError(
                f"artifact workspace pre-check failed: {error}"
            ) from error
        try:
            reference = _hash_artifact(
                self.scope.work_dir,
                locator,
                self.scope.fingerprint,
                maximum_bytes=min(maximum_bytes, work_tree_max_bytes),
            )
        except Exception as primary_error:
            try:
                measure_work_tree(
                    self.scope.work_dir,
                    maximum_bytes=work_tree_max_bytes,
                )
            except SafeFileError as post_error:
                raise ScopeError(
                    f"{primary_error}; artifact workspace post-check failed: "
                    f"{post_error}"
                ) from primary_error
            raise
        try:
            measure_work_tree(
                self.scope.work_dir,
                maximum_bytes=work_tree_max_bytes,
            )
        except SafeFileError as error:
            raise ScopeError(
                f"artifact workspace post-check failed: {error}"
            ) from error
        return reference

    def run_clean_proof(
        self,
        spec: CommandSpec,
        *,
        input_locators: Sequence[str] = (),
        proof_inputs: Sequence[ProofInput] = (),
        proof_outputs: Sequence[ProofOutput] = (),
    ) -> SandboxResult:
        if not proof_outputs:
            return self.backend.run_clean_proof(
                spec,
                input_locators=input_locators,
                proof_inputs=proof_inputs,
            )
        return self.backend.run_clean_proof(
            spec,
            input_locators=input_locators,
            proof_inputs=proof_inputs,
            proof_outputs=proof_outputs,
        )


def command_to_dict(spec: CommandSpec) -> dict[str, Any]:
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


def command_from_dict(value: object) -> CommandSpec:
    if not isinstance(value, dict):
        raise ValueError("command must be an object")
    target_value = value.get("network_target")
    target = None
    if target_value is not None:
        if not isinstance(target_value, dict):
            raise ValueError("network_target must be an object")
        target = NetworkTarget(
            host=target_value.get("host"),
            port=target_value.get("port"),
            scheme=target_value.get("scheme"),
        )
    environment = value.get("environment", {})
    if not isinstance(environment, dict):
        raise ValueError("environment must be an object")
    argv = value.get("argv")
    if not isinstance(argv, list):
        raise ValueError("argv must be an array")
    resource_value = value.get(
        "resource_request",
        {
            "cpu": 1,
            "memory_mib": 2 * 1024,
            "network": 1 if target is not None else 0,
        },
    )
    if not isinstance(resource_value, dict):
        raise ValueError("resource_request must be an object")
    return CommandSpec(
        argv=tuple(argv),
        timeout_seconds=value.get("timeout_seconds", 300),
        deadline_monotonic_seconds=value.get("deadline_monotonic_seconds"),
        summary_bytes=value.get("summary_bytes", 4096),
        environment=environment,
        network_target=target,
        resource_request=ResourceVector.from_mapping(resource_value),
    )


def ref_to_dict(ref: JobRef) -> dict[str, str]:
    value = {
        "job_id": ref.job_id,
        "scope_fingerprint": ref.scope_fingerprint,
        "runtime_id": ref.runtime_id,
    }
    if ref.supervisor_id is not None:
        value["supervisor_id"] = ref.supervisor_id
    return value


def ref_from_dict(value: object) -> JobRef:
    if not isinstance(value, dict):
        raise ValueError("job reference must be an object")
    return JobRef(
        job_id=value.get("job_id"),
        scope_fingerprint=value.get("scope_fingerprint"),
        runtime_id=value.get("runtime_id", "none"),
        supervisor_id=value.get("supervisor_id"),
    )


def background_launch_to_dict(
    launch: BackgroundLaunchStatus,
) -> dict[str, object]:
    status = launch.job_status
    return {
        "schema_version": 1,
        "supervisor_id": launch.supervisor_id,
        "state": launch.state.value,
        "ref": ref_to_dict(launch.ref) if launch.ref is not None else None,
        "job_status": (
            {
                "status": status.status.value,
                "exit_code": status.exit_code,
                "timed_out": status.timed_out,
                "cancelled": status.cancelled,
                "started_at": status.started_at,
                "finished_at": status.finished_at,
                "reason_code": status.reason_code,
            }
            if status is not None
            else None
        ),
    }


def background_launch_from_dict(
    value: object,
) -> BackgroundLaunchStatus:
    if (
        type(value) is not dict
        or set(value)
        != {
            "schema_version",
            "supervisor_id",
            "state",
            "ref",
            "job_status",
        }
        or value.get("schema_version") != 1
    ):
        raise SandboxError("invalid background launch recovery response")
    try:
        state = BackgroundLaunchState(value.get("state"))
        supervisor_id = value.get("supervisor_id")
        ref_value = value.get("ref")
        ref = None if ref_value is None else ref_from_dict(ref_value)
        status_value = value.get("job_status")
        status = None
        if status_value is not None:
            if (
                type(status_value) is not dict
                or frozenset(status_value)
                not in {
                    frozenset(
                        {
                            "status",
                            "exit_code",
                            "timed_out",
                            "cancelled",
                            "started_at",
                            "finished_at",
                        }
                    ),
                    frozenset(
                        {
                            "status",
                            "exit_code",
                            "timed_out",
                            "cancelled",
                            "started_at",
                            "finished_at",
                            "reason_code",
                        }
                    ),
                }
                or not {
                    "status",
                    "exit_code",
                    "timed_out",
                    "cancelled",
                    "started_at",
                    "finished_at",
                }.issubset(status_value)
                or ref is None
                or type(status_value["timed_out"]) is not bool
                or type(status_value["cancelled"]) is not bool
                or (
                    status_value["exit_code"] is not None
                    and (
                        type(status_value["exit_code"]) is not int
                        or not -(2**31)
                        <= status_value["exit_code"]
                        <= 2**31 - 1
                    )
                )
                or (
                    status_value["started_at"] is not None
                    and type(status_value["started_at"]) is not str
                )
                or (
                    status_value["finished_at"] is not None
                    and type(status_value["finished_at"]) is not str
                )
            ):
                raise ValueError("invalid background job status")
            status = JobStatus(
                ref=ref,
                status=JobState(status_value["status"]),
                exit_code=status_value["exit_code"],
                timed_out=status_value["timed_out"],
                cancelled=status_value["cancelled"],
                started_at=status_value["started_at"],
                finished_at=status_value["finished_at"],
                reason_code=status_value.get("reason_code"),
            )
        return BackgroundLaunchStatus(
            supervisor_id=supervisor_id,  # type: ignore[arg-type]
            state=state,
            ref=ref,
            job_status=status,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise SandboxError(
            "invalid background launch recovery response"
        ) from error


def result_from_dict(value: object) -> SandboxResult:
    if not isinstance(value, dict):
        raise SandboxError("sandbox result must be an object")
    try:
        return sandbox_result_from_mapping(value)
    except (KeyError, TypeError, ValueError) as error:
        raise SandboxError("invalid sandbox result") from error


class UnixChallengeSandboxClient:
    """Capability-authenticated newline-JSON client for ``ctfosd``."""

    def __init__(
        self,
        socket_path: Path,
        token: str,
        scope_fingerprint: str,
        *,
        rpc_timeout: float = 30.0,
    ) -> None:
        self.socket_path = socket_path.expanduser().resolve()
        if (
            not token
            or not token.isascii()
            or len(token.encode("ascii")) > 8192
            or "\n" in token
        ):
            raise ValueError("invalid sandbox capability token")
        if not isinstance(scope_fingerprint, str) or len(scope_fingerprint) != 64:
            raise ValueError("invalid scope fingerprint")
        if (
            isinstance(rpc_timeout, bool)
            or not isinstance(rpc_timeout, (int, float))
            or not math.isfinite(float(rpc_timeout))
            or rpc_timeout <= 0
        ):
            raise ValueError("rpc_timeout must be positive and finite")
        self.token = token
        self._scope_fingerprint = scope_fingerprint
        self.rpc_timeout = rpc_timeout

    @property
    def scope_fingerprint(self) -> str:
        return self._scope_fingerprint

    def _call(
        self,
        operation: str,
        params: dict[str, Any],
        *,
        timeout: float | None = None,
        rpc_deadline_monotonic: float | None = None,
    ) -> Any:
        request = {
            "schema_version": 1,
            "token": self.token,
            "operation": operation,
            "params": params,
        }
        payload = (
            json.dumps(request, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        if len(payload) > MAX_RPC_BYTES:
            raise SandboxError("sandbox request exceeds 1 MiB")
        if timeout is None:
            configured_timeout = self.rpc_timeout
        elif (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(float(timeout))
            or timeout <= 0
        ):
            raise SandboxError(
                "sandbox RPC timeout must be positive and finite"
            )
        else:
            configured_timeout = float(timeout)
        if rpc_deadline_monotonic is None:
            rpc_deadline = time.monotonic() + configured_timeout
        else:
            rpc_deadline = validate_deadline_monotonic_seconds(
                rpc_deadline_monotonic
            )
            assert rpc_deadline is not None
            if rpc_deadline <= time.monotonic():
                raise SandboxError(
                    "sandbox RPC deadline expired before request"
                )

        def apply_remaining_timeout(connection: socket.socket) -> None:
            remaining = rpc_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("sandbox RPC deadline expired")
            connection.settimeout(remaining)

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                apply_remaining_timeout(connection)
                connection.connect(str(self.socket_path))
                apply_remaining_timeout(connection)
                connection.sendall(payload)
                apply_remaining_timeout(connection)
                connection.shutdown(socket.SHUT_WR)
                chunks = bytearray()
                while len(chunks) <= MAX_RPC_BYTES:
                    apply_remaining_timeout(connection)
                    block = connection.recv(min(65536, MAX_RPC_BYTES + 1 - len(chunks)))
                    if not block:
                        break
                    chunks.extend(block)
                    if b"\n" in block:
                        break
        except (OSError, TimeoutError) as error:
            raise SandboxError(f"sandbox daemon request failed: {error}") from error
        if time.monotonic() >= rpc_deadline:
            raise SandboxError(
                "sandbox daemon request failed: RPC deadline expired"
            )
        if len(chunks) > MAX_RPC_BYTES:
            raise SandboxError("sandbox daemon response exceeds 1 MiB")
        try:
            response = json.loads(bytes(chunks).decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise SandboxError("sandbox daemon returned invalid JSON") from error
        if not isinstance(response, dict) or response.get("schema_version") != 1:
            raise SandboxError("sandbox daemon returned an unsupported response")
        if not response.get("ok"):
            error = response.get("error", {})
            code = error.get("code") if isinstance(error, dict) else None
            message = (
                str(error.get("message", "sandbox operation failed"))
                if isinstance(error, dict)
                else "sandbox operation failed"
            )
            if code == "AnalysisRuntimeCleanupPending":
                raise AnalysisRuntimeCleanupPending(message)
            raise SandboxError(message)
        return response.get("result")

    def _check_ref(self, ref: JobRef) -> None:
        if ref.scope_fingerprint != self.scope_fingerprint:
            raise ScopeError("job reference belongs to another challenge")

    def _check_analysis_ref(self, lease: AnalysisLeaseRef) -> None:
        if type(lease) is not AnalysisLeaseRef:
            raise TypeError("lease must be an AnalysisLeaseRef")
        if lease.scope_fingerprint != self.scope_fingerprint:
            raise ScopeError("analysis lease belongs to another challenge")

    @staticmethod
    def _rpc_deadline(
        deadline_monotonic_seconds: float | None,
        fallback: float,
        cleanup_response_grace: float,
    ) -> float:
        deadline = validate_deadline_monotonic_seconds(
            deadline_monotonic_seconds
        )
        if deadline is None:
            return time.monotonic() + fallback
        if deadline <= time.monotonic():
            raise SandboxError(
                "challenge hard deadline expired before sandbox RPC"
            )
        return deadline + cleanup_response_grace

    def initialize_workspace(
        self,
        *,
        deadline_monotonic_seconds: float | None = None,
    ) -> None:
        rpc_deadline = self._rpc_deadline(
            deadline_monotonic_seconds,
            150,
            65,
        )
        self._call(
            "initialize_workspace",
            {"deadline_monotonic_seconds": deadline_monotonic_seconds},
            rpc_deadline_monotonic=rpc_deadline,
        )

    def run(self, spec: CommandSpec) -> SandboxResult:
        fallback = (
            spec.timeout_seconds + 30 if spec.timeout_seconds else 604800 + 30
        )
        rpc_deadline = self._rpc_deadline(
            spec.deadline_monotonic_seconds,
            fallback,
            65,
        )
        return result_from_dict(
            self._call(
                "run",
                {"command": command_to_dict(spec)},
                rpc_deadline_monotonic=rpc_deadline,
            )
        )

    def isolated_analysis_runtime_id(
        self,
        lease: AnalysisLeaseRef,
    ) -> str:
        self._check_analysis_ref(lease)
        value = self._call(
            "isolated_analysis_runtime_id",
            {"lease": lease.as_dict()},
        )
        expected = (
            f"ctfos-analysis-{self.scope_fingerprint[:12]}-"
            f"{lease.analysis_id.removeprefix('analysis-')[:20]}-run"
        )
        if type(value) is not str or value != expected:
            raise SandboxError(
                "sandbox returned another isolated-analysis runtime identity"
            )
        return value

    def run_isolated_analysis(
        self,
        lease: AnalysisLeaseRef,
        spec: CommandSpec,
        *,
        input_locators: Sequence[str] = (),
    ) -> SandboxResult:
        self._check_analysis_ref(lease)
        if (
            isinstance(input_locators, (str, bytes, bytearray))
            or not isinstance(input_locators, Sequence)
            or len(input_locators) > 256
        ):
            raise ValueError("input_locators must be an array of strings")
        input_values = tuple(input_locators)
        if any(type(locator) is not str for locator in input_values):
            raise ValueError("input_locators must be an array of strings")
        fallback = (
            spec.timeout_seconds + 150 if spec.timeout_seconds else 604800 + 150
        )
        rpc_deadline = self._rpc_deadline(
            spec.deadline_monotonic_seconds,
            fallback,
            150,
        )
        return result_from_dict(
            self._call(
                "run_isolated_analysis",
                {
                    "lease": lease.as_dict(),
                    "command": command_to_dict(spec),
                    "input_locators": list(input_values),
                },
                rpc_deadline_monotonic=rpc_deadline,
            )
        )

    def cleanup_isolated_analysis(
        self,
        lease: AnalysisLeaseRef,
    ) -> None:
        self._check_analysis_ref(lease)
        value = self._call(
            "cleanup_isolated_analysis",
            {"lease": lease.as_dict()},
            timeout=90,
        )
        if value != {"runtime_absent": True}:
            raise AnalysisRuntimeCleanupPending(
                "sandbox returned an invalid analysis cleanup receipt"
            )

    def start_job(
        self,
        spec: CommandSpec,
        *,
        name: str | None = None,
        supervisor_id: str | None = None,
    ) -> JobRef:
        if supervisor_id is not None:
            supervisor_id = _validate_supervisor_id(supervisor_id)
        fallback = max(self.rpc_timeout, 330.0)
        rpc_deadline = self._rpc_deadline(
            spec.deadline_monotonic_seconds,
            fallback,
            65,
        )
        value = self._call(
            "start_job",
            {
                "command": command_to_dict(spec),
                "name": name,
                "supervisor_id": supervisor_id,
            },
            rpc_deadline_monotonic=rpc_deadline,
        )
        ref = ref_from_dict(value)
        if (
            supervisor_id is not None
            and ref.supervisor_id != supervisor_id
        ):
            raise SandboxError(
                "background launch returned another supervisor identity"
            )
        return ref

    def job_status(self, ref: JobRef) -> JobStatus:
        self._check_ref(ref)
        value = self._call("job_status", {"ref": ref_to_dict(ref)})
        if not isinstance(value, dict):
            raise SandboxError("invalid job status response")
        return JobStatus(
            ref=ref,
            status=JobState(value["status"]),
            exit_code=value.get("exit_code"),
            timed_out=bool(value.get("timed_out", False)),
            cancelled=bool(value.get("cancelled", False)),
            started_at=value.get("started_at"),
            finished_at=value.get("finished_at"),
            reason_code=value.get("reason_code"),
        )

    def job_log(self, ref: JobRef, *, tail_bytes: int = 8192) -> JobLog:
        self._check_ref(ref)
        value = self._call(
            "job_log",
            {"ref": ref_to_dict(ref), "tail_bytes": tail_bytes},
        )
        if not isinstance(value, dict):
            raise SandboxError("invalid job log response")
        return JobLog(
            ref=ref,
            stdout=str(value.get("stdout", "")),
            stderr=str(value.get("stderr", "")),
            stdout_bytes=int(value.get("stdout_bytes", 0)),
            stderr_bytes=int(value.get("stderr_bytes", 0)),
            stdout_truncated=bool(value.get("stdout_truncated", False)),
            stderr_truncated=bool(value.get("stderr_truncated", False)),
        )

    def cancel_job(self, ref: JobRef, *, grace_seconds: int = 3) -> JobStatus:
        self._check_ref(ref)
        grace_seconds = _validate_cancel_grace_seconds(grace_seconds)
        value = self._call(
            "cancel_job",
            {"ref": ref_to_dict(ref), "grace_seconds": grace_seconds},
            timeout=grace_seconds + 30,
        )
        if not isinstance(value, dict):
            raise SandboxError("invalid job cancellation response")
        return JobStatus(
            ref=ref,
            status=JobState(value["status"]),
            exit_code=value.get("exit_code"),
            timed_out=bool(value.get("timed_out", False)),
            cancelled=bool(value.get("cancelled", False)),
            started_at=value.get("started_at"),
            finished_at=value.get("finished_at"),
            reason_code=value.get("reason_code"),
        )

    def list_jobs(self) -> tuple[JobStatus, ...]:
        value = self._call("list_jobs", {})
        if not isinstance(value, list):
            raise SandboxError("invalid sandbox job list response")
        statuses: list[JobStatus] = []
        for item in value:
            if not isinstance(item, dict):
                raise SandboxError("invalid sandbox job list response")
            ref = ref_from_dict(item.get("ref"))
            if ref.scope_fingerprint != self.scope_fingerprint:
                raise ScopeError("job list returned another challenge scope")
            statuses.append(
                JobStatus(
                    ref=ref,
                    status=JobState(item["status"]),
                    exit_code=item.get("exit_code"),
                    timed_out=bool(item.get("timed_out", False)),
                    cancelled=bool(item.get("cancelled", False)),
                    started_at=item.get("started_at"),
                    finished_at=item.get("finished_at"),
                    reason_code=item.get("reason_code"),
                )
            )
        return tuple(statuses)

    def recover_jobs(self) -> tuple[JobStatus, ...]:
        value = self._call("recover_jobs", {})
        if not isinstance(value, list):
            raise SandboxError("invalid sandbox recovery response")
        statuses: list[JobStatus] = []
        for item in value:
            if not isinstance(item, dict):
                raise SandboxError("invalid sandbox recovery response")
            ref = ref_from_dict(item.get("ref"))
            if ref.scope_fingerprint != self.scope_fingerprint:
                raise ScopeError("job recovery returned another challenge scope")
            statuses.append(
                JobStatus(
                    ref=ref,
                    status=JobState(item["status"]),
                    exit_code=item.get("exit_code"),
                    timed_out=bool(item.get("timed_out", False)),
                    cancelled=bool(item.get("cancelled", False)),
                    started_at=item.get("started_at"),
                    finished_at=item.get("finished_at"),
                    reason_code=item.get("reason_code"),
                )
            )
        return tuple(statuses)

    def recover_job_launch(
        self,
        supervisor_id: str,
    ) -> BackgroundLaunchStatus:
        supervisor_id = _validate_supervisor_id(supervisor_id)
        launch = background_launch_from_dict(
            self._call(
                "recover_job_launch",
                {"supervisor_id": supervisor_id},
            )
        )
        if launch.supervisor_id != supervisor_id:
            raise SandboxError(
                "background recovery returned another supervisor identity"
            )
        if (
            launch.ref is not None
            and launch.ref.scope_fingerprint != self.scope_fingerprint
        ):
            raise ScopeError(
                "background recovery returned another challenge scope"
            )
        return launch

    def register_artifact(
        self,
        locator: str,
        *,
        maximum_bytes: int = DEFAULT_SNAPSHOT_MAX_BYTES,
    ) -> ArtifactRef:
        value = self._call(
            "register_artifact",
            {"locator": locator, "maximum_bytes": maximum_bytes},
        )
        if not isinstance(value, dict):
            raise SandboxError("invalid artifact response")
        return ArtifactRef(
            locator=str(value["locator"]),
            sha256=str(value["sha256"]),
            size_bytes=int(value["size_bytes"]),
            scope_fingerprint=str(value["scope_fingerprint"]),
        )

    def run_clean_proof(
        self,
        spec: CommandSpec,
        *,
        input_locators: Sequence[str] = (),
        proof_inputs: Sequence[ProofInput] = (),
        proof_outputs: Sequence[ProofOutput] = (),
    ) -> SandboxResult:
        fallback = (
            spec.timeout_seconds + 150 if spec.timeout_seconds else 604800 + 150
        )
        rpc_deadline = self._rpc_deadline(
            spec.deadline_monotonic_seconds,
            fallback,
            150,
        )
        return result_from_dict(
            self._call(
                "run_clean_proof",
                {
                    "command": command_to_dict(spec),
                    "input_locators": list(input_locators),
                    "proof_inputs": [
                        item.as_dict() for item in proof_inputs
                    ],
                    "proof_outputs": [
                        item.as_dict() for item in proof_outputs
                    ],
                },
                rpc_deadline_monotonic=rpc_deadline,
            )
        )
