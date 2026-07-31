"""Docker implementation of the challenge sandbox data plane.

The backend only creates containers from a pre-bound :class:`ChallengeScope`.
It never accepts host mount paths from individual operations.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from ctf_os.container_tools import (
    CLIError as ContainerCapabilityError,
)
from ctf_os.container_tools import (
    GPUPlan,
    detect_gpu_plan,
    detect_kvm,
)
from ctf_os.director.resources import ResourceVector
from ctf_os.docker_mount import bind_mount_spec
from ctf_os.engine.flags import (
    DEFAULT_SIDECAR_MAX_BYTES,
    FLAG_CANDIDATE_SIDECAR,
    PROOF_LIVE_DIRECTORY,
)
from ctf_os.images import (
    effective_image_reference,
    validate_image_digest,
    validate_image_name,
)

from .files import (
    DEFAULT_STREAM_CAPTURE_MAX_BYTES,
    DEFAULT_WORK_TREE_MAX_BYTES,
    SafeFileError,
    WorkTreeUsage,
    copy_bounded_regular,
    ensure_private_directory,
    ensure_relative_directory,
    measure_work_tree,
    normalize_locator,
)
from .egress import RestrictedEgressBoundary
from .types import (
    BackgroundJobUnsupported,
    ChallengeScope,
    CommandSpec,
    JOB_SUPERVISOR_ID,
    JobLog,
    JobRef,
    JobState,
    JobStatus,
    NetworkPolicy,
    ProofInput,
    ProofOutput,
    ArtifactRef,
    SandboxError,
    SandboxResult,
    ScopeError,
    ensure_foreground_command,
    sandbox_result_from_mapping,
    validate_deadline_monotonic_seconds,
)
from .web_private import (
    PRIVATE_WEB_SESSION_CONTAINER_ROOT,
    PRIVATE_WEB_SESSION_ROOT_ENV,
    PRIVATE_WEB_TIMELINE_CONTAINER_ROOT,
    PRIVATE_WEB_TIMELINE_ROOT_ENV,
    WebPrivateStateError,
    discard_public_artifacts,
    prepare_web_session_command,
    redact_private_timeline,
    redact_public_artifacts,
    redact_value,
    resolve_private_web_mounts,
    resolve_private_web_root,
    snapshot_all_cookie_values,
    snapshot_run_ids,
)

Runner = Callable[..., subprocess.CompletedProcess[str]]
MAX_CONTROL_OUTPUT = 1024 * 1024
MAX_PROOF_INPUTS = 256
_JOB_CONTROL_COMMANDS = frozenset({"ctf-jobs", "ctf-log", "ctf-kill"})


@dataclass(frozen=True, slots=True)
class DockerLimits:
    cpus: float = 1.0
    memory_mib: int = 2 * 1024
    pids: int = 2048
    shm_size: str = "1g"
    ptrace: bool = True
    kvm: bool = False
    gpu_flags: tuple[str, ...] = ()
    read_only_root: bool = True
    run_as_host_user: bool = True
    work_tree_max_bytes: int = DEFAULT_WORK_TREE_MAX_BYTES

    def __post_init__(self) -> None:
        if self.cpus <= 0:
            raise ValueError("cpus must be positive")
        if self.memory_mib < 256:
            raise ValueError("memory_mib must be at least 256")
        if self.pids < 16:
            raise ValueError("pids must be at least 16")
        if not re.fullmatch(r"[1-9][0-9]*[bkmgBKMG]?", self.shm_size):
            raise ValueError("invalid shm_size")
        if any(not value or "\x00" in value for value in self.gpu_flags):
            raise ValueError("invalid GPU Docker flag")
        if (
            isinstance(self.work_tree_max_bytes, bool)
            or not isinstance(self.work_tree_max_bytes, int)
            or self.work_tree_max_bytes <= 0
        ):
            raise ValueError("work_tree_max_bytes must be positive")

    @property
    def stream_capture_max_bytes(self) -> int:
        """Leave at least half of the work bound for non-stream artifacts."""

        return min(
            DEFAULT_STREAM_CAPTURE_MAX_BYTES,
            self.work_tree_max_bytes // 4,
        )


class _WorkTreeGuard:
    """Install cleanup before acquiring one backend's work-tree lock."""

    def __init__(
        self,
        backend: DockerSandboxBackend,
        work_dir: Path,
        operation: str,
    ) -> None:
        self._backend = backend
        self._work_dir = work_dir
        self._operation = operation
        self._entered = False
        self._acquire_started = False
        self._release_maybe_needed = False
        self._acquired = False
        self._started = False
        self._closed = False

    def __enter__(self) -> Self:
        if self._entered or self._closed:
            raise RuntimeError("work-tree guard is already used")
        self._entered = True
        return self

    def start(self) -> None:
        if not self._entered:
            raise RuntimeError(
                "work-tree guard start requires an active with guard"
            )
        if self._acquire_started or self._closed:
            raise RuntimeError("work-tree guard already started")
        self._acquire_started = True
        lock = self._backend._work_tree_lock
        if not lock._is_owned():
            try:
                # Record release intent before the C-level acquire. An
                # interrupt may arrive after ownership transfers but before
                # acquire() returns to this frame.
                self._release_maybe_needed = True
                lock.acquire()
                self._acquired = True
            except BaseException as error:
                self._release(error)
                raise
        try:
            self._backend.check_work_tree(
                self._work_dir,
                phase=f"before {self._operation}",
            )
        except BaseException as error:
            self._release(error)
            raise
        self._started = True

    def _release(self, active_error: BaseException | None) -> None:
        if not self._release_maybe_needed:
            return
        lock = self._backend._work_tree_lock
        cleanup_error: BaseException | None = None
        still_owned = True
        try:
            lock.release()
        except BaseException as error:  # noqa: BLE001 - includes interrupts
            cleanup_error = error
            try:
                still_owned = lock._is_owned()
            except BaseException as ownership_error:  # noqa: BLE001
                error.add_note(
                    "work-tree lock ownership check failed: "
                    f"{ownership_error}"
                )
            if still_owned:
                try:
                    lock.release()
                except BaseException as retry_error:  # noqa: BLE001
                    error.add_note(
                        "work-tree lock release retry failed: "
                        f"{retry_error}"
                    )
                    try:
                        still_owned = lock._is_owned()
                    except BaseException as ownership_error:  # noqa: BLE001
                        error.add_note(
                            "work-tree lock ownership recheck failed: "
                            f"{ownership_error}"
                        )
                else:
                    still_owned = False
            elif isinstance(error, RuntimeError):
                # acquire() was interrupted before ownership transferred.
                cleanup_error = None
        else:
            still_owned = False

        if not still_owned:
            self._release_maybe_needed = False
            self._acquired = False
        if cleanup_error is None:
            return
        if active_error is not None:
            active_error.add_note(
                f"work-tree lock cleanup failed: {cleanup_error}"
            )
            return
        if not isinstance(cleanup_error, Exception) or still_owned:
            raise cleanup_error

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        primary_error: BaseException | None,
        _traceback: TracebackType | None,
    ) -> bool:
        try:
            if not self._started:
                return False
            if primary_error is None:
                self._backend.check_work_tree(
                    self._work_dir,
                    phase=f"after {self._operation}",
                )
            elif isinstance(primary_error, Exception):
                try:
                    self._backend.check_work_tree(
                        self._work_dir,
                        phase=f"after {self._operation}",
                    )
                except SandboxError as post_error:
                    raise SandboxError(
                        f"{primary_error}; additionally, {post_error}"
                    ) from primary_error
            return False
        finally:
            try:
                self._release(sys.exception())
            finally:
                self._closed = not self._release_maybe_needed


class DockerSandboxBackend:
    """Run the image utilities in one persistent container per network mode."""

    def __init__(
        self,
        scope: ChallengeScope,
        *,
        image: str = "ctf-os:core",
        image_digest: str | None = None,
        network_policy: NetworkPolicy | None = None,
        limits: DockerLimits | None = None,
        runner: Runner = subprocess.run,
        docker: str = "docker",
        gpu_detector: Callable[[], GPUPlan | None] | None = None,
        kvm_detector: Callable[[], bool] | None = None,
    ) -> None:
        self.scope = scope
        self.image = validate_image_name(image)
        self.image_digest = (
            validate_image_digest(image_digest)
            if image_digest is not None
            else None
        )
        self.image_reference = effective_image_reference(
            self.image, self.image_digest
        )
        self.network_policy = network_policy or NetworkPolicy.deny_all()
        self.limits = limits or DockerLimits()
        self.runner = runner
        self.docker = docker
        self._gpu_detector = gpu_detector or (
            lambda: detect_gpu_plan(policy="required", runner=self.runner)
        )
        self._kvm_detector = kvm_detector or (
            lambda: detect_kvm(policy="required")
        )
        self._start_lock = threading.Lock()
        self._work_tree_lock = threading.RLock()

    @staticmethod
    def _anchor_hard_deadline(
        deadline_monotonic_seconds: float | None,
    ) -> float | None:
        deadline = validate_deadline_monotonic_seconds(
            deadline_monotonic_seconds
        )
        if deadline is None:
            return None
        if deadline <= time.monotonic():
            raise SandboxError(
                "challenge hard deadline expired before sandbox operation"
            )
        return deadline

    @staticmethod
    def _remaining_hard_deadline(
        deadline_monotonic: float | None,
        *,
        operation: str,
    ) -> float | None:
        if deadline_monotonic is None:
            return None
        remaining = deadline_monotonic - time.monotonic()
        if remaining <= 0:
            raise SandboxError(
                f"challenge hard deadline expired before {operation}"
            )
        return remaining

    @classmethod
    def _clamp_hard_deadline_timeout(
        cls,
        deadline_monotonic: float | None,
        configured_seconds: float,
        *,
        operation: str,
    ) -> float:
        remaining = cls._remaining_hard_deadline(
            deadline_monotonic,
            operation=operation,
        )
        return (
            configured_seconds
            if remaining is None
            else min(configured_seconds, remaining)
        )

    @classmethod
    def _effective_command_timeout(
        cls,
        spec: CommandSpec,
        deadline_monotonic: float | None,
        *,
        operation: str,
    ) -> int:
        if deadline_monotonic is None:
            return spec.timeout_seconds
        remaining = cls._remaining_hard_deadline(
            deadline_monotonic,
            operation=operation,
        )
        assert remaining is not None
        configured = (
            spec.timeout_seconds
            if spec.timeout_seconds
            else 604800
        )
        bounded = int(min(float(configured), remaining))
        if bounded < 1:
            raise SandboxError(
                "challenge hard deadline has less than one second left "
                f"before {operation}"
            )
        return bounded

    def _execution_limits(self, request: ResourceVector) -> DockerLimits:
        """Bind one leased resource vector to one Docker invocation."""

        if request.cpu <= 0 or request.memory_mib < 256:
            raise SandboxError(
                "sandbox execution requires leased CPU and memory resources"
            )
        if request.gpu > 1 or request.kvm > 1 or request.network > 1:
            raise SandboxError(
                "GPU, KVM, and network are single-slot sandbox resources"
            )

        gpu_flags: tuple[str, ...] = ()
        if request.gpu:
            try:
                gpu_plan = self._gpu_detector()
            except ContainerCapabilityError as error:
                raise SandboxError(str(error)) from error
            if gpu_plan is None:
                raise SandboxError(
                    "GPU was leased but no host GPU passthrough plan is available"
                )
            gpu_flags = tuple(gpu_plan.docker_flags)

        kvm = False
        if request.kvm:
            try:
                kvm = self._kvm_detector()
            except ContainerCapabilityError as error:
                raise SandboxError(str(error)) from error
            if not kvm:
                raise SandboxError(
                    "KVM was leased but host /dev/kvm is unavailable"
                )

        return DockerLimits(
            cpus=float(request.cpu),
            memory_mib=request.memory_mib,
            pids=self.limits.pids,
            shm_size=self.limits.shm_size,
            ptrace=self.limits.ptrace,
            kvm=kvm,
            gpu_flags=gpu_flags,
            read_only_root=self.limits.read_only_root,
            run_as_host_user=self.limits.run_as_host_user,
            work_tree_max_bytes=self.limits.work_tree_max_bytes,
        )

    def check_work_tree(
        self,
        work_dir: Path | None = None,
        *,
        phase: str,
    ) -> WorkTreeUsage:
        """Fail closed when one stable pre/post work-tree check is unsafe."""

        actual_work = work_dir or self.scope.work_dir
        try:
            return measure_work_tree(
                actual_work,
                maximum_bytes=self.limits.work_tree_max_bytes,
            )
        except SafeFileError as error:
            raise SandboxError(f"{phase} work-tree check failed: {error}") from error

    def _work_tree_guard(
        self,
        work_dir: Path,
        *,
        operation: str,
    ) -> _WorkTreeGuard:
        """Serialize this backend's checks and always perform the post-check.

        Foreground containers are exact-name one-shot ``--rm`` executions (and
        timeout cleanup force-removes that exact generated name).  A failed
        post-check does not delete arbitrary files from the persistent work
        tree: safely attributing concurrent human/tool writes would require a
        filesystem quota or snapshot boundary that this guard does not claim.
        """

        return _WorkTreeGuard(self, work_dir, operation)

    def _runtime_id(self, network: str) -> str:
        return network

    def _authorized_runtime(
        self,
        spec: CommandSpec,
    ) -> tuple[str, Mapping[str, str]]:
        """Resolve one command to a directly enforced Docker network.

        External ``proxy`` policies already name an operator-restricted
        network.  A ``builtin`` policy instead provisions a scope-specific
        internal network and injects only the proxy coordinates; the
        challenge container is never attached to the upstream network.
        """

        network = self.network_policy.authorize(spec.network_target)
        if (
            spec.network_target is None
            or self.network_policy.enforcement != "builtin"
        ):
            return network, {}
        boundary = RestrictedEgressBoundary(
            self.scope,
            self.network_policy,
            image=self.image,
            image_digest=self.image_digest,
            runner=self.runner,
            docker=self.docker,
        )
        with self._start_lock:
            runtime = boundary.ensure()
        return runtime.network, runtime.environment

    def _container_name(self, runtime_id: str) -> str:
        import hashlib

        runtime_digest = hashlib.sha256(runtime_id.encode("utf-8")).hexdigest()[:10]
        return f"ctfos-{self.scope.fingerprint[:16]}-{runtime_digest}"

    def build_container_argv(
        self,
        *,
        network: str,
        work_dir: Path | None = None,
        private_web_session_root: Path | None = None,
        private_web_timeline_root: Path | None = None,
        detach: bool = True,
        name: str | None = None,
        command: Sequence[str] = ("ctf-idle", "--serve"),
        remove: bool = False,
        limits: DockerLimits | None = None,
        labels: Mapping[str, str] | None = None,
    ) -> list[str]:
        """Build the only Docker ``run`` shape exposed by this backend."""

        actual_work = (work_dir or self.scope.work_dir).resolve()
        actual_limits = limits or self.limits
        container_name = name or self._container_name(self._runtime_id(network))
        extra_labels = dict(labels or {})
        for label_name, label_value in extra_labels.items():
            if (
                not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,127}", label_name)
                or not isinstance(label_value, str)
                or not label_value
                or len(label_value.encode("utf-8")) > 256
                or any(ord(character) < 0x20 for character in label_value)
            ):
                raise SandboxError("invalid trusted Docker job label")
        argv = [
            self.docker,
            "run",
            "--init",
            "--name",
            container_name,
            "--label",
            "ctfos.managed=true",
            "--label",
            f"ctfos.scope={self.scope.fingerprint}",
            "--label",
            f"ctfos.challenge={self.scope.qualified_id}",
            "--label",
            f"ctfos.network={network}",
            "--label",
            f"ctfos.image={self.image}",
            "--label",
            f"ctfos.image_digest={self.image_digest or ''}",
            "--network",
            network,
            "--cpus",
            str(actual_limits.cpus),
            "--memory",
            f"{actual_limits.memory_mib}m",
            "--pids-limit",
            str(actual_limits.pids),
            "--shm-size",
            actual_limits.shm_size,
            "--security-opt",
            "no-new-privileges",
            "--cap-drop",
            "ALL",
        ]
        for label_name, label_value in sorted(extra_labels.items()):
            argv.extend(["--label", f"{label_name}={label_value}"])
        if actual_limits.run_as_host_user:
            argv.extend(["--user", f"{os.getuid()}:{os.getgid()}"])
        argv.extend(
            [
            "--env",
            "HOME=/work",
            "--mount",
            bind_mount_spec(
                self.scope.challenge_dir,
                "/challenge",
                readonly=True,
            ),
            "--mount",
            bind_mount_spec(actual_work, "/work"),
            ]
        )
        if detach:
            argv.append("--detach")
        if (private_web_session_root is None) != (
            private_web_timeline_root is None
        ):
            raise SandboxError(
                "private Web session and timeline mounts must be paired"
            )
        if (
            private_web_session_root is not None
            and private_web_timeline_root is not None
        ):
            argv.extend(
                [
                    "--env",
                    (
                        f"{PRIVATE_WEB_SESSION_ROOT_ENV}="
                        f"{PRIVATE_WEB_SESSION_CONTAINER_ROOT}"
                    ),
                    "--env",
                    (
                        f"{PRIVATE_WEB_TIMELINE_ROOT_ENV}="
                        f"{PRIVATE_WEB_TIMELINE_CONTAINER_ROOT}"
                    ),
                    "--mount",
                    bind_mount_spec(
                        private_web_session_root,
                        PRIVATE_WEB_SESSION_CONTAINER_ROOT,
                    ),
                    "--mount",
                    bind_mount_spec(
                        private_web_timeline_root,
                        PRIVATE_WEB_TIMELINE_CONTAINER_ROOT,
                    ),
                ]
            )
        if remove:
            argv.append("--rm")
        if actual_limits.read_only_root:
            argv.extend(
                [
                    "--read-only",
                    "--tmpfs",
                    "/tmp:rw,nosuid,nodev,noexec,size=1g",
                    "--tmpfs",
                    "/run:rw,nosuid,nodev,noexec,size=64m",
                ]
            )
        if actual_limits.ptrace:
            argv.extend(
                [
                    "--cap-add",
                    "SYS_PTRACE",
                    "--security-opt",
                    "seccomp=unconfined",
                ]
            )
        if actual_limits.kvm:
            argv.extend(["--device", "/dev/kvm"])
            if actual_limits.run_as_host_user:
                try:
                    argv.extend(["--group-add", str(Path("/dev/kvm").stat().st_gid)])
                except OSError as error:
                    raise SandboxError(
                        "KVM was requested but /dev/kvm is unavailable"
                    ) from error
        argv.extend(actual_limits.gpu_flags)
        argv.append(self.image_reference)
        argv.extend(command)
        return argv

    def _capture(
        self,
        command: Sequence[str],
        *,
        timeout: float,
        timeout_cleanup_container: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        try:
            return self.runner(
                list(command),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as error:
            raise SandboxError("docker executable was not found") from error
        except subprocess.TimeoutExpired as error:
            cleanup_error = None
            if timeout_cleanup_container is not None:
                cleanup_error = self._remove_timed_out_ephemeral_container(
                    timeout_cleanup_container
                )
            message = "Docker control operation timed out"
            if cleanup_error is not None:
                message += f"; exact container cleanup failed: {cleanup_error}"
            raise SandboxError(message) from error
        except OSError as error:
            message = f"Docker control operation failed: {error}"
            if timeout_cleanup_container is not None:
                cleanup_error = self._remove_timed_out_ephemeral_container(
                    timeout_cleanup_container
                )
                if cleanup_error is None:
                    message += "; exact container cleanup recovered"
                else:
                    message += (
                        "; exact container cleanup failed: "
                        f"{cleanup_error}"
                    )
            raise SandboxError(message) from error
        except BaseException as error:
            if timeout_cleanup_container is not None:
                try:
                    cleanup_error = (
                        self._remove_timed_out_ephemeral_container(
                            timeout_cleanup_container
                        )
                    )
                except BaseException as cleanup_exception:
                    cleanup_error = (
                        f"{type(cleanup_exception).__name__}: "
                        f"{cleanup_exception}"
                    )
                if cleanup_error is not None:
                    error.add_note(
                        "exact container cleanup failed: "
                        f"{cleanup_error}"
                    )
            raise

    def _remove_timed_out_ephemeral_container(self, name: str) -> str | None:
        """Remove one exact generated name with bounded control-signal recovery."""

        expected = re.fullmatch(
            (
                r"ctfos-(?:run|init|proof-init|proof)-"
                + re.escape(self.scope.fingerprint[:12])
                + r"-[0-9a-f]{12}"
            ),
            name,
        )
        if expected is None:
            return "refused non-ephemeral container name"
        command = [self.docker, "container", "rm", "--force", name]
        failure: str | None = None
        cleanup_interruption: KeyboardInterrupt | SystemExit | None = None
        ordinary_attempts = 0
        while ordinary_attempts < 2:
            try:
                result = self.runner(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
            except subprocess.TimeoutExpired as error:
                failure = f"{type(error).__name__}: {error}"
                break
            except (KeyboardInterrupt, SystemExit) as error:
                if cleanup_interruption is not None:
                    cleanup_interruption.add_note(
                        "exact container cleanup failed: retry was "
                        f"interrupted by {type(error).__name__}: {error}"
                    )
                    raise cleanup_interruption
                # A control signal leaves the Docker client's completion
                # ambiguous.  Retry the same validated name without consuming
                # either of the two ordinary cleanup outcomes, then propagate
                # this exact exception identity with the observed result.
                cleanup_interruption = error
                continue
            except OSError as error:
                failure = f"{type(error).__name__}: {error}"
                ordinary_attempts += 1
            else:
                if result.returncode == 0:
                    if cleanup_interruption is not None:
                        cleanup_interruption.add_note(
                            "exact container cleanup succeeded after "
                            f"{type(cleanup_interruption).__name__}"
                        )
                        raise cleanup_interruption
                    return None
                detail = self._bounded(
                    result.stderr or result.stdout or "",
                    4096,
                ).strip()
                failure = (
                    detail
                    or f"docker rm exited with status {result.returncode}"
                )
                ordinary_attempts += 1
        if cleanup_interruption is not None:
            cleanup_interruption.add_note(
                "exact container cleanup failed after "
                f"{type(cleanup_interruption).__name__}: "
                f"{failure or 'no cleanup result'}"
            )
            raise cleanup_interruption
        return failure

    @staticmethod
    def _bounded(value: str, maximum: int = MAX_CONTROL_OUTPUT) -> str:
        encoded = value.encode("utf-8", errors="replace")
        if len(encoded) <= maximum:
            return value
        return encoded[-maximum:].decode("utf-8", errors="replace")

    @staticmethod
    def _parse_json(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        if (
            len(stdout.encode("utf-8", errors="replace")) > MAX_CONTROL_OUTPUT
            or len(stderr.encode("utf-8", errors="replace")) > MAX_CONTROL_OUTPUT
        ):
            raise SandboxError("sandbox control output exceeded 1 MiB")
        try:
            value = json.loads(stdout)
        except json.JSONDecodeError as error:
            detail = DockerSandboxBackend._bounded(stderr, 4096).strip()
            raise SandboxError(
                "sandbox utility returned invalid JSON"
                + (f": {detail}" if detail else "")
            ) from error
        if not isinstance(value, dict) or value.get("schema_version") != 1:
            raise SandboxError("sandbox utility returned an unsupported result")
        return value

    def _inspect(
        self,
        name: str,
        *,
        timeout: float = 30,
    ) -> dict[str, Any] | None:
        result = self._capture(
            [self.docker, "container", "inspect", name],
            timeout=timeout,
        )
        if result.returncode != 0:
            return None
        try:
            values = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise SandboxError("Docker inspect returned invalid JSON") from error
        if not isinstance(values, list) or len(values) != 1 or not isinstance(
            values[0], dict
        ):
            raise SandboxError("Docker inspect returned an unexpected result")
        return values[0]

    def _verify_container(self, details: Mapping[str, Any], network: str) -> bool:
        labels = details.get("Config", {}).get("Labels", {})
        if not isinstance(labels, dict):
            raise ScopeError("sandbox container has no trusted labels")
        if (
            labels.get("ctfos.managed") != "true"
            or labels.get("ctfos.scope") != self.scope.fingerprint
            or labels.get("ctfos.network") != network
            or labels.get("ctfos.image") != self.image
            or labels.get("ctfos.image_digest", "") != (
                self.image_digest or ""
            )
            or details.get("Config", {}).get("Image")
            != self.image_reference
            or (
                self.image_digest is not None
                and details.get("Image") != self.image_digest
            )
        ):
            raise ScopeError("sandbox container belongs to another scope")
        mounts = details.get("Mounts", [])
        challenge_match = False
        work_match = False
        for mount in mounts if isinstance(mounts, list) else []:
            if not isinstance(mount, dict):
                continue
            source = str(mount.get("Source", ""))
            destination = mount.get("Destination")
            rw = mount.get("RW")
            if (
                destination == "/challenge"
                and Path(source).resolve() == self.scope.challenge_dir
                and rw is False
            ):
                challenge_match = True
            if (
                destination == "/work"
                and Path(source).resolve() == self.scope.work_dir
                and rw is True
            ):
                work_match = True
        if not challenge_match or not work_match:
            raise ScopeError("sandbox container mount scope does not match")
        return bool(details.get("State", {}).get("Running"))

    def _ensure_container(self, network: str) -> tuple[str, str]:
        runtime_id = self._runtime_id(network)
        name = self._container_name(runtime_id)
        with self._start_lock:
            details = self._inspect(name)
            if details is not None:
                if self._verify_container(details, network):
                    return name, runtime_id
                result = self._capture([self.docker, "start", name], timeout=60)
                if result.returncode != 0:
                    raise SandboxError(
                        f"could not start sandbox container: "
                        f"{self._bounded(result.stderr, 4096).strip()}"
                    )
                return name, runtime_id

            command = self.build_container_argv(network=network, name=name)
            result = self._capture(command, timeout=120)
            if result.returncode != 0:
                # Another process may have won the deterministic-name race.
                details = self._inspect(name)
                if details is not None and self._verify_container(details, network):
                    return name, runtime_id
                raise SandboxError(
                    f"could not create sandbox container: "
                    f"{self._bounded(result.stderr, 4096).strip()}"
                )
            details = self._inspect(name)
            if details is None or not self._verify_container(details, network):
                raise SandboxError("created sandbox container failed scope verification")
            return name, runtime_id

    @staticmethod
    def _exec_argv(
        docker: str,
        container: str,
        command: Sequence[str],
        environment: Mapping[str, str],
    ) -> list[str]:
        argv = [docker, "exec", "--workdir", "/work"]
        for name, value in sorted(environment.items()):
            argv.extend(["--env", f"{name}={value}"])
        argv.append(container)
        argv.extend(command)
        return argv

    def _exec_json(
        self,
        container: str,
        command: Sequence[str],
        *,
        environment: Mapping[str, str] | None = None,
        timeout: float,
    ) -> dict[str, Any]:
        result = self._capture(
            self._exec_argv(
                self.docker,
                container,
                command,
                environment or {},
            ),
            timeout=timeout,
        )
        # ctfwrap and ctf-kill intentionally return the wrapped command status.
        # Their JSON result is authoritative even when Docker's exit is nonzero.
        return self._parse_json(result)

    def _run_one_shot_json(
        self,
        *,
        network: str,
        command: Sequence[str],
        environment: Mapping[str, str],
        timeout: float,
        limits: DockerLimits,
        private_web_session_root: Path | None = None,
        private_web_timeline_root: Path | None = None,
    ) -> dict[str, Any]:
        """Run one bounded command with container lifetime as its supervisor."""

        import secrets

        container_name = (
            f"ctfos-run-{self.scope.fingerprint[:12]}-"
            f"{secrets.token_hex(6)}"
        )
        argv = self.build_container_argv(
            network=network,
            detach=False,
            name=container_name,
            command=command,
            remove=True,
            limits=limits,
            private_web_session_root=private_web_session_root,
            private_web_timeline_root=private_web_timeline_root,
        )
        image_index = len(argv) - len(command) - 1
        environment_args: list[str] = []
        for name, environment_value in sorted(environment.items()):
            environment_args.extend(["--env", f"{name}={environment_value}"])
        argv[image_index:image_index] = environment_args
        result = self._capture(
            argv,
            timeout=timeout,
            timeout_cleanup_container=container_name,
        )
        return self._parse_json(result)

    def initialize_workspace(
        self,
        *,
        deadline_monotonic_seconds: float | None = None,
    ) -> None:
        """Initialize and verify the exact challenge copy before Live writes.

        This is a short, foreground, network-denied lifecycle operation.  The
        engine holds the matching light resource lease around this call.
        """

        import secrets

        deadline_monotonic = self._anchor_hard_deadline(
            deadline_monotonic_seconds
        )
        request = ResourceVector(cpu=1, memory_mib=2 * 1024)
        limits = self._execution_limits(request)
        name = (
            f"ctfos-init-{self.scope.fingerprint[:12]}-"
            f"{secrets.token_hex(6)}"
        )
        argv = self.build_container_argv(
            network="none",
            detach=False,
            name=name,
            command=("true",),
            remove=True,
            limits=limits,
        )
        with self._work_tree_guard(
            self.scope.work_dir,
            operation="workspace initialization",
        ) as work_tree_guard:
            work_tree_guard.start()
            result = self._capture(
                argv,
                timeout=self._clamp_hard_deadline_timeout(
                    deadline_monotonic,
                    120,
                    operation="workspace initialization container",
                ),
                timeout_cleanup_container=name,
            )
            self._remaining_hard_deadline(
                deadline_monotonic,
                operation="workspace initialization completion",
            )
            if result.returncode != 0:
                raise SandboxError(
                    "could not initialize challenge workspace: "
                    + self._bounded(result.stderr, 4096).strip()
                )
        self._remaining_hard_deadline(
            deadline_monotonic,
            operation="workspace initialization result promotion",
        )

    def run(self, spec: CommandSpec) -> SandboxResult:
        deadline_monotonic = self._anchor_hard_deadline(
            spec.deadline_monotonic_seconds
        )
        ensure_foreground_command(spec.argv)
        network, boundary_environment = self._authorized_runtime(spec)
        if bool(spec.resource_request.network) != (network != "none"):
            raise SandboxError(
                "leased network resource does not match authorized network mode"
            )
        execution_limits = self._execution_limits(spec.resource_request)
        try:
            web_session = prepare_web_session_command(
                category=self.scope.category,
                argv=spec.argv,
                environment=spec.environment,
            )
            private_web_root = (
                resolve_private_web_root(self.scope)
                if web_session is not None
                else None
            )
            private_web_mounts = (
                resolve_private_web_mounts(
                    self.scope,
                    web_session.session_name,
                )
                if web_session is not None
                else None
            )
            private_web_session_root = (
                private_web_mounts[0]
                if private_web_mounts is not None
                else None
            )
            private_web_timeline_root = (
                private_web_mounts[1]
                if private_web_mounts is not None
                else None
            )
            previous_web_run_ids = (
                snapshot_run_ids(self.scope.work_dir)
                if web_session is not None
                else frozenset()
            )
            cookie_values_before = (
                snapshot_all_cookie_values(private_web_root)
                if private_web_root is not None
                else ()
            )
            if private_web_timeline_root is not None:
                redact_private_timeline(
                    private_web_timeline_root,
                    cookie_values_before,
                )
        except WebPrivateStateError as error:
            raise SandboxError(str(error)) from error
        effective_argv = (
            web_session.argv
            if web_session is not None
            else spec.argv
        )
        execution_environment = dict(spec.environment)
        execution_environment.update(boundary_environment)
        with self._work_tree_guard(
            self.scope.work_dir,
            operation="sandbox command",
        ) as work_tree_guard:
            work_tree_guard.start()
            command_timeout = self._effective_command_timeout(
                spec,
                deadline_monotonic,
                operation="sandbox command",
            )
            command = [
                "ctfwrap",
                "--json",
                "--timeout",
                str(command_timeout),
                "--summary-bytes",
                str(spec.summary_bytes),
                "--stdout-limit-bytes",
                str(execution_limits.stream_capture_max_bytes),
                "--stderr-limit-bytes",
                str(execution_limits.stream_capture_max_bytes),
                "--",
                *effective_argv,
            ]
            if Path(effective_argv[0]).name in _JOB_CONTROL_COMMANDS:
                # Existing scoped jobs live in the persistent runtime. Starting new
                # jobs is disabled, but bounded query/log/cancel remains available.
                # A status query must not create an idle container after its host
                # lease is released.
                container = self._container_name(self._runtime_id(network))
                details = self._inspect(
                    container,
                    timeout=self._clamp_hard_deadline_timeout(
                        deadline_monotonic,
                        30,
                        operation="sandbox container inspection",
                    ),
                )
                control_timeout = self._clamp_hard_deadline_timeout(
                    deadline_monotonic,
                    (
                        command_timeout + 15
                        if command_timeout
                        else 604800 + 15
                    ),
                    operation="sandbox command",
                )
                if details is not None and self._verify_container(details, network):
                    value = self._exec_json(
                        container,
                        command,
                        environment=execution_environment,
                        timeout=control_timeout,
                    )
                else:
                    value = self._run_one_shot_json(
                        network=network,
                        command=command,
                        environment=execution_environment,
                        timeout=control_timeout,
                        limits=execution_limits,
                        private_web_session_root=private_web_session_root,
                        private_web_timeline_root=private_web_timeline_root,
                    )
            else:
                # A one-shot container is the foreground process supervisor. Even a
                # command that clears CTF_WRAP_RUN_TOKEN and starts a new SID cannot
                # outlive container PID 1 or the host ResourceBroker lease.
                control_timeout = self._clamp_hard_deadline_timeout(
                    deadline_monotonic,
                    (
                        command_timeout + 15
                        if command_timeout
                        else 604800 + 15
                    ),
                    operation="sandbox command",
                )
                operation_error: BaseException | None = None
                try:
                    value = self._run_one_shot_json(
                        network=network,
                        command=command,
                        environment=execution_environment,
                        timeout=control_timeout,
                        limits=execution_limits,
                        private_web_session_root=private_web_session_root,
                        private_web_timeline_root=private_web_timeline_root,
                    )
                except BaseException as error:
                    operation_error = error
                    value = {}
                if web_session is not None:
                    try:
                        assert private_web_session_root is not None
                        assert private_web_root is not None
                        cookie_values_after = snapshot_all_cookie_values(
                            private_web_root
                        )
                        cookie_values = tuple(
                            dict.fromkeys(
                                (
                                    *cookie_values_before,
                                    *cookie_values_after,
                                )
                            )
                        )
                        assert private_web_timeline_root is not None
                        redact_private_timeline(
                            private_web_timeline_root,
                            cookie_values,
                        )
                        redact_public_artifacts(
                            self.scope.work_dir,
                            previous_run_ids=previous_web_run_ids,
                            secrets=cookie_values,
                        )
                        value = redact_value(value, cookie_values)
                    except BaseException as audit_error:
                        try:
                            discard_public_artifacts(
                                self.scope.work_dir,
                                previous_run_ids=previous_web_run_ids,
                            )
                        except BaseException as discard_error:
                            audit_error.add_note(
                                "unaudited Web output discard also failed: "
                                f"{type(discard_error).__name__}: "
                                f"{discard_error}"
                            )
                        if operation_error is not None:
                            audit_error.add_note(
                                "Web helper execution also failed: "
                                f"{type(operation_error).__name__}: "
                                f"{operation_error}"
                            )
                        if isinstance(audit_error, Exception):
                            raise SandboxError(
                                "private Web post-run audit failed: "
                                f"{audit_error}"
                            ) from audit_error
                        raise
                if operation_error is not None:
                    raise operation_error
            if value.get("kind") != "run_result":
                raise SandboxError("ctfwrap returned the wrong result kind")
            try:
                sandbox_result = sandbox_result_from_mapping(value)
            except (KeyError, TypeError, ValueError) as error:
                raise SandboxError("ctfwrap returned an invalid result") from error
        self._remaining_hard_deadline(
            deadline_monotonic,
            operation="sandbox result promotion",
        )
        return sandbox_result

    def start_job(self, spec: CommandSpec, *, name: str | None = None) -> JobRef:
        del spec, name
        raise BackgroundJobUnsupported(
            "background job start is disabled until a supervisor can hold "
            "the resource lease for the complete job lifetime"
        )

    def _supervised_container_name(self, supervisor_id: str) -> str:
        """Return the one exact Docker runtime owned by a host supervisor."""

        if not JOB_SUPERVISOR_ID.fullmatch(supervisor_id):
            raise ScopeError("invalid background supervisor identity")
        return (
            f"ctfos-job-{self.scope.fingerprint[:12]}-"
            f"{supervisor_id.removeprefix('bg-')[:20]}"
        )

    def _verify_supervised_container(
        self,
        details: Mapping[str, Any],
        *,
        runtime_id: str,
        supervisor_id: str,
    ) -> bool:
        running = self._verify_container(details, runtime_id)
        labels = details.get("Config", {}).get("Labels", {})
        if (
            not isinstance(labels, dict)
            or labels.get("ctfos.supervisor") != supervisor_id
        ):
            raise ScopeError(
                "sandbox job container belongs to another supervisor"
            )
        return running

    def _start_supervised_job(
        self,
        spec: CommandSpec,
        *,
        supervisor_id: str,
        name: str | None = None,
    ) -> JobRef:
        """Trusted host-supervisor entrypoint for one durable background job.

        This method is intentionally private.  Untrusted callers use
        ``ChallengeSandboxClient.start_job``; that client first transfers
        ownership to the host supervisor which holds the matching resource
        lease until the job is terminal.
        """

        if not JOB_SUPERVISOR_ID.fullmatch(supervisor_id):
            raise ScopeError("invalid background supervisor identity")
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
        ensure_foreground_command(spec.argv)
        deadline_monotonic = self._anchor_hard_deadline(
            spec.deadline_monotonic_seconds
        )
        network, boundary_environment = self._authorized_runtime(spec)
        if bool(spec.resource_request.network) != (network != "none"):
            raise SandboxError(
                "leased network resource does not match authorized network mode"
            )
        try:
            web_session = prepare_web_session_command(
                category=self.scope.category,
                argv=spec.argv,
                environment=spec.environment,
            )
        except WebPrivateStateError as error:
            raise SandboxError(str(error)) from error
        if web_session is not None:
            raise SandboxError(
                "persistent Web identity helpers are unavailable to "
                "background jobs"
            )
        execution_limits = self._execution_limits(spec.resource_request)
        self.check_work_tree(phase="background job preflight")
        timeout_seconds = self._effective_command_timeout(
            spec,
            deadline_monotonic,
            operation="background job launch",
        )
        container_name = self._supervised_container_name(supervisor_id)
        if self._inspect(container_name) is not None:
            raise SandboxError(
                "background supervisor runtime already exists"
            )
        create_argv = self.build_container_argv(
            network=network,
            name=container_name,
            limits=execution_limits,
            labels={"ctfos.supervisor": supervisor_id},
        )
        created = self._capture(
            create_argv,
            timeout=self._clamp_hard_deadline_timeout(
                deadline_monotonic,
                120,
                operation="background job container creation",
            ),
            timeout_cleanup_container=None,
        )
        if created.returncode != 0:
            raise SandboxError(
                "could not create background job container: "
                + self._bounded(created.stderr, 4096).strip()
            )
        launched = False
        try:
            details = self._inspect(
                container_name,
                timeout=self._clamp_hard_deadline_timeout(
                    deadline_monotonic,
                    30,
                    operation="background job container inspection",
                ),
            )
            if details is None or not self._verify_supervised_container(
                details,
                runtime_id=network,
                supervisor_id=supervisor_id,
            ):
                raise SandboxError(
                    "created background job container failed scope verification"
                )
            command = [
                "ctf-bg",
                "--json",
                "--timeout",
                str(timeout_seconds),
            ]
            if name is not None:
                command.extend(["--name", name])
            command.extend(("--", *spec.argv))
            execution_environment = dict(spec.environment)
            execution_environment.update(boundary_environment)
            value = self._exec_json(
                container_name,
                command,
                environment=execution_environment,
                timeout=self._clamp_hard_deadline_timeout(
                    deadline_monotonic,
                    45,
                    operation="background job start receipt",
                ),
            )
            if value.get("kind") != "job_launch":
                raise SandboxError("ctf-bg returned the wrong result kind")
            ref = JobRef(
                job_id=str(value["job_id"]),
                scope_fingerprint=self.scope.fingerprint,
                runtime_id=network,
                supervisor_id=supervisor_id,
            )
            launched = True
            return ref
        except (KeyError, TypeError, ValueError) as error:
            raise SandboxError("ctf-bg returned an invalid launch receipt") from error
        finally:
            if not launched:
                cleanup_error = self._remove_supervised_runtime(
                    supervisor_id,
                    runtime_id=network,
                    missing_ok=True,
                )
                if cleanup_error is not None and sys.exception() is not None:
                    sys.exception().add_note(
                        "background runtime cleanup failed: "
                        f"{cleanup_error}"
                    )

    def _remove_supervised_runtime(
        self,
        supervisor_id: str,
        *,
        runtime_id: str | None,
        missing_ok: bool = False,
    ) -> str | None:
        """Force-remove only the exact labelled runtime for one supervisor."""

        name = self._supervised_container_name(supervisor_id)
        details = self._inspect(name)
        if details is None:
            # ``docker inspect`` deliberately has a simple optional return
            # contract used elsewhere, so a nonzero status alone cannot prove
            # absence here: daemon/API failures are also nonzero.  Independently
            # attest that no container carries this exact trusted supervisor
            # label before allowing a durable lease to be released.
            attestation = self._capture(
                [
                    self.docker,
                    "container",
                    "ls",
                    "--all",
                    "--filter",
                    f"label=ctfos.supervisor={supervisor_id}",
                    "--format",
                    "{{.Names}}\t{{.ID}}",
                ],
                timeout=30,
            )
            if attestation.returncode != 0:
                detail = self._bounded(
                    attestation.stderr or attestation.stdout,
                    4096,
                ).strip()
                return (
                    "background runtime absence attestation failed"
                    + (f": {detail}" if detail else "")
                )
            output = attestation.stdout or ""
            if len(output.encode("utf-8", errors="replace")) > 64 * 1024:
                return (
                    "background runtime absence attestation exceeded "
                    "the control-output bound"
                )
            if output.strip():
                return (
                    "background runtime still has an exact supervisor label "
                    "but could not be inspected"
                )
            return None if missing_ok else "background runtime is missing"
        if runtime_id is None:
            labels = details.get("Config", {}).get("Labels", {})
            if not isinstance(labels, Mapping):
                raise ScopeError(
                    "background runtime has no trusted labels"
                )
            observed_runtime = labels.get("ctfos.network")
            if not isinstance(observed_runtime, str):
                raise ScopeError(
                    "background runtime has no network identity"
                )
            runtime_id = observed_runtime
        self._verify_supervised_container(
            details,
            runtime_id=runtime_id,
            supervisor_id=supervisor_id,
        )
        result = self._capture(
            [self.docker, "container", "rm", "--force", name],
            timeout=60,
        )
        if result.returncode != 0:
            return (
                self._bounded(result.stderr or result.stdout, 4096).strip()
                or f"docker rm exited with status {result.returncode}"
            )
        return None

    def _supervised_container_for_ref(
        self,
        ref: JobRef,
    ) -> str | None:
        self._validate_supervised_ref(ref)
        assert ref.supervisor_id is not None
        name = self._supervised_container_name(ref.supervisor_id)
        details = self._inspect(name)
        if details is None:
            return None
        if not self._verify_supervised_container(
            details,
            runtime_id=ref.runtime_id,
            supervisor_id=ref.supervisor_id,
        ):
            return None
        return name

    def _validate_supervised_ref(self, ref: JobRef) -> None:
        if ref.scope_fingerprint != self.scope.fingerprint:
            raise ScopeError("job reference belongs to another challenge")
        if ref.supervisor_id is None:
            raise ScopeError("job reference has no supervisor receipt")
        allowed_runtime = ref.runtime_id in {
            "none",
            self.network_policy.docker_network,
        }
        if (
            self.network_policy.enforcement == "builtin"
            and re.fullmatch(
                r"ctfos-bnd-[0-9a-f]{12}-[0-9a-f]{10}",
                ref.runtime_id,
            )
        ):
            allowed_runtime = True
        if not allowed_runtime:
            raise ScopeError("job reference uses an unauthorized runtime")

    @staticmethod
    def _job_status_from_value(
        ref: JobRef,
        value: Mapping[str, object],
    ) -> JobStatus:
        try:
            state = JobState(str(value["status"]))
            return JobStatus(
                ref=ref,
                status=state,
                exit_code=(
                    int(value["exit_code"])
                    if value.get("exit_code") is not None
                    else None
                ),
                timed_out=(
                    state is JobState.TIMED_OUT
                    or bool(value.get("timed_out", False))
                ),
                cancelled=(
                    state is JobState.CANCELLED
                    or bool(value.get("cancelled", False))
                ),
                started_at=(
                    str(value["started_at"])
                    if value.get("started_at") is not None
                    else None
                ),
                finished_at=(
                    str(value["finished_at"])
                    if value.get("finished_at") is not None
                    else None
                ),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise SandboxError("ctf-jobs returned an invalid status") from error

    def _read_supervised_status(self, ref: JobRef) -> JobStatus:
        """Read a terminal status after its dedicated container is removed."""

        self._validate_supervised_ref(ref)
        locator = f".ctf/jobs/{ref.job_id}/status.json"
        payload = self._read_scoped_job_file(locator, maximum_bytes=1024 * 1024)
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise SandboxError("sandbox job status is invalid") from error
        if (
            not isinstance(value, dict)
            or value.get("schema_version") != 1
            or value.get("job_id") != ref.job_id
        ):
            raise SandboxError("sandbox job status has the wrong identity")
        status = self._job_status_from_value(ref, value)
        if status.status in {JobState.STARTING, JobState.RUNNING}:
            return JobStatus(
                ref=ref,
                status=JobState.LOST,
                exit_code=status.exit_code,
                started_at=status.started_at,
                finished_at=status.finished_at,
            )
        return status

    def _read_scoped_job_file(
        self,
        locator: str,
        *,
        maximum_bytes: int,
        tail_bytes: int | None = None,
    ) -> bytes:
        """Descriptor-walk one bounded job file without following symlinks."""

        components = Path(locator).parts
        if (
            not components
            or components[:2] != (".ctf", "jobs")
            or any(part in {"", ".", ".."} for part in components)
        ):
            raise ScopeError("invalid sandbox job file locator")
        owned: list[int] = []
        try:
            current = os.open(
                self.scope.work_dir,
                os.O_RDONLY
                | os.O_CLOEXEC
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            owned.append(current)
            for component in components[:-1]:
                current = os.open(
                    component,
                    os.O_RDONLY
                    | os.O_CLOEXEC
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=current,
                )
                owned.append(current)
            descriptor = os.open(
                components[-1],
                os.O_RDONLY
                | os.O_CLOEXEC
                | os.O_NONBLOCK
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=current,
            )
            owned.append(descriptor)
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_size > maximum_bytes
            ):
                raise SandboxError("sandbox job file exceeds its bound")
            if tail_bytes is not None:
                os.lseek(
                    descriptor,
                    max(0, opened.st_size - tail_bytes),
                    os.SEEK_SET,
                )
                remaining = tail_bytes
            else:
                remaining = maximum_bytes
            payload = bytearray()
            while remaining > 0:
                block = os.read(descriptor, min(64 * 1024, remaining))
                if not block:
                    break
                payload.extend(block)
                remaining -= len(block)
            after = os.fstat(descriptor)
            if (after.st_dev, after.st_ino) != (
                opened.st_dev,
                opened.st_ino,
            ):
                raise SandboxError("sandbox job file changed while reading")
            if (
                tail_bytes is None
                and (after.st_size, after.st_mtime_ns)
                != (opened.st_size, opened.st_mtime_ns)
            ):
                raise SandboxError("sandbox job file changed while reading")
            return bytes(payload)
        except FileNotFoundError as error:
            raise SandboxError(f"unknown sandbox job: {locator}") from error
        except OSError as error:
            raise SandboxError("sandbox job file could not be read safely") from error
        finally:
            for descriptor in reversed(owned):
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def _supervised_job_status(self, ref: JobRef) -> JobStatus:
        container = self._supervised_container_for_ref(ref)
        if container is None:
            return self._read_supervised_status(ref)
        value = self._exec_json(
            container,
            ["ctf-jobs", "--json", ref.job_id],
            timeout=30,
        )
        if value.get("kind") != "job_list":
            raise SandboxError("ctf-jobs returned the wrong result kind")
        jobs = value.get("jobs")
        if not isinstance(jobs, list) or len(jobs) != 1:
            raise SandboxError(f"unknown sandbox job: {ref.job_id}")
        if not isinstance(jobs[0], dict):
            raise SandboxError("ctf-jobs returned an invalid status")
        return self._job_status_from_value(ref, jobs[0])

    def _container_for_ref(self, ref: JobRef) -> str:
        if ref.scope_fingerprint != self.scope.fingerprint:
            raise ScopeError("job reference belongs to another challenge")
        if ref.runtime_id not in {"none", self.network_policy.docker_network}:
            raise ScopeError("job reference uses an unauthorized runtime")
        name = self._container_name(ref.runtime_id)
        details = self._inspect(name)
        if details is None or not self._verify_container(details, ref.runtime_id):
            raise SandboxError("sandbox runtime for job is not running")
        return name

    def destroy_runtime(self, runtime_id: str = "none") -> bool:
        """Remove this scope's tool container while preserving ``/work``.

        This lifecycle action is intentionally backend-only; untrusted Codex
        clients cannot name or remove containers.
        """

        if runtime_id not in {"none", self.network_policy.docker_network}:
            raise ScopeError("cannot destroy an unauthorized sandbox runtime")
        name = self._container_name(runtime_id)
        details = self._inspect(name)
        if details is None:
            return False
        self._verify_container(details, runtime_id)
        result = self._capture(
            [self.docker, "container", "rm", "--force", name],
            timeout=60,
        )
        if result.returncode != 0:
            raise SandboxError(
                "could not remove sandbox runtime: "
                + self._bounded(result.stderr, 4096).strip()
            )
        return True

    def job_status(self, ref: JobRef) -> JobStatus:
        if ref.supervisor_id is not None:
            return self._supervised_job_status(ref)
        container = self._container_for_ref(ref)
        value = self._exec_json(
            container,
            ["ctf-jobs", "--json", ref.job_id],
            timeout=30,
        )
        if value.get("kind") != "job_list":
            raise SandboxError("ctf-jobs returned the wrong result kind")
        jobs = value.get("jobs")
        if not isinstance(jobs, list) or len(jobs) != 1:
            raise SandboxError(f"unknown sandbox job: {ref.job_id}")
        job = jobs[0]
        try:
            return JobStatus(
                ref=ref,
                status=JobState(str(job["status"])),
                exit_code=(
                    int(job["exit_code"])
                    if job.get("exit_code") is not None
                    else None
                ),
                timed_out=(
                    str(job["status"]) == JobState.TIMED_OUT.value
                    or bool(job.get("timed_out", False))
                ),
                cancelled=(
                    str(job["status"]) == JobState.CANCELLED.value
                    or bool(job.get("cancelled", False))
                ),
                started_at=(
                    str(job["started_at"])
                    if job.get("started_at") is not None
                    else None
                ),
                finished_at=(
                    str(job["finished_at"])
                    if job.get("finished_at") is not None
                    else None
                ),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise SandboxError("ctf-jobs returned an invalid status") from error

    def job_log(self, ref: JobRef, *, tail_bytes: int = 8192) -> JobLog:
        if (
            isinstance(tail_bytes, bool)
            or not isinstance(tail_bytes, int)
            or not 0 <= tail_bytes <= 1024 * 1024
        ):
            raise ValueError("tail_bytes must be between 0 and 1048576")
        if ref.supervisor_id is not None:
            self._validate_supervised_ref(ref)
            stdout_locator = f".ctf/jobs/{ref.job_id}/stdout.log"
            stderr_locator = f".ctf/jobs/{ref.job_id}/stderr.log"
            stdout_payload = self._read_scoped_job_file(
                stdout_locator,
                maximum_bytes=self.limits.work_tree_max_bytes,
                tail_bytes=tail_bytes,
            )
            stderr_payload = self._read_scoped_job_file(
                stderr_locator,
                maximum_bytes=self.limits.work_tree_max_bytes,
                tail_bytes=tail_bytes,
            )
            stdout_size = self._scoped_job_file_size(stdout_locator)
            stderr_size = self._scoped_job_file_size(stderr_locator)
            return JobLog(
                ref=ref,
                stdout=stdout_payload.decode("utf-8", errors="replace"),
                stderr=stderr_payload.decode("utf-8", errors="replace"),
                stdout_bytes=stdout_size,
                stderr_bytes=stderr_size,
                stdout_truncated=stdout_size > len(stdout_payload),
                stderr_truncated=stderr_size > len(stderr_payload),
            )
        container = self._container_for_ref(ref)
        value = self._exec_json(
            container,
            [
                "ctf-log",
                "--json",
                "--stream",
                "both",
                "--tail-bytes",
                str(tail_bytes),
                ref.job_id,
            ],
            timeout=30,
        )
        if value.get("kind") != "job_log":
            raise SandboxError("ctf-log returned the wrong result kind")
        streams = value.get("streams", {})
        stdout = streams.get("stdout", {})
        stderr = streams.get("stderr", {})
        try:
            return JobLog(
                ref=ref,
                stdout=str(stdout.get("tail", "")),
                stderr=str(stderr.get("tail", "")),
                stdout_bytes=int(stdout.get("bytes", 0)),
                stderr_bytes=int(stderr.get("bytes", 0)),
                stdout_truncated=bool(stdout.get("tail_truncated", False)),
                stderr_truncated=bool(stderr.get("tail_truncated", False)),
            )
        except (TypeError, ValueError) as error:
            raise SandboxError("ctf-log returned an invalid result") from error

    def cancel_job(self, ref: JobRef, *, grace_seconds: int = 3) -> JobStatus:
        if (
            isinstance(grace_seconds, bool)
            or not isinstance(grace_seconds, int)
            or not 0 <= grace_seconds <= 30
        ):
            raise ValueError("grace_seconds must be between 0 and 30")
        if ref.supervisor_id is not None:
            status = self._supervised_job_status(ref)
            if status.status not in {JobState.STARTING, JobState.RUNNING}:
                return status
            container = self._supervised_container_for_ref(ref)
            if container is None:
                return self._read_supervised_status(ref)
        else:
            container = self._container_for_ref(ref)
        self._exec_json(
            container,
            [
                "ctf-kill",
                "--json",
                "--grace",
                str(grace_seconds),
                ref.job_id,
            ],
            timeout=grace_seconds + 15,
        )
        return self.job_status(ref)

    def _scoped_job_file_size(self, locator: str) -> int:
        """Safely obtain one regular job-file size for bounded tail reads."""

        components = Path(locator).parts
        if (
            not components
            or components[:2] != (".ctf", "jobs")
            or any(part in {"", ".", ".."} for part in components)
        ):
            raise ScopeError("invalid sandbox job file locator")
        owned: list[int] = []
        try:
            current = os.open(
                self.scope.work_dir,
                os.O_RDONLY
                | os.O_CLOEXEC
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            owned.append(current)
            for component in components[:-1]:
                current = os.open(
                    component,
                    os.O_RDONLY
                    | os.O_CLOEXEC
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=current,
                )
                owned.append(current)
            descriptor = os.open(
                components[-1],
                os.O_RDONLY
                | os.O_CLOEXEC
                | os.O_NONBLOCK
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=current,
            )
            owned.append(descriptor)
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_size > self.limits.work_tree_max_bytes
            ):
                raise SandboxError("sandbox job log exceeds the work-tree bound")
            return opened.st_size
        except (FileNotFoundError, OSError) as error:
            raise SandboxError("sandbox job log is unavailable") from error
        finally:
            for descriptor in reversed(owned):
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    @staticmethod
    def _remove_exact_directory(
        path: Path,
        expected: os.stat_result,
    ) -> str | None:
        """Remove only the engine-created directory whose identity was recorded."""

        try:
            current = path.stat(follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError as error:
            return f"cannot inspect exact cleanup target: {error}"
        if (
            not stat.S_ISDIR(current.st_mode)
            or (current.st_dev, current.st_ino)
            != (expected.st_dev, expected.st_ino)
        ):
            return "refused cleanup because the exact directory identity changed"
        try:
            shutil.rmtree(path)
        except OSError as error:
            return f"could not remove exact generated directory: {error}"
        return None

    def run_clean_proof(
        self,
        spec: CommandSpec,
        *,
        input_locators: Sequence[str] = (),
        proof_inputs: Sequence[ProofInput] = (),
        proof_outputs: Sequence[ProofOutput] = (),
    ) -> SandboxResult:
        """Run a proof with stable checks on source and durable work trees."""

        deadline_monotonic = self._anchor_hard_deadline(
            spec.deadline_monotonic_seconds
        )
        with self._work_tree_guard(
            self.scope.work_dir,
            operation="clean proof",
        ) as work_tree_guard:
            work_tree_guard.start()
            return self._run_clean_proof(
                spec,
                input_locators=input_locators,
                proof_inputs=proof_inputs,
                proof_outputs=proof_outputs,
                deadline_monotonic=deadline_monotonic,
            )

    def _run_clean_proof(
        self,
        spec: CommandSpec,
        *,
        input_locators: Sequence[str] = (),
        proof_inputs: Sequence[ProofInput] = (),
        proof_outputs: Sequence[ProofOutput] = (),
        deadline_monotonic: float | None,
    ) -> SandboxResult:
        """Run a proof in a new work directory with validated copied inputs."""

        ensure_foreground_command(spec.argv)
        try:
            web_session = prepare_web_session_command(
                category=self.scope.category,
                argv=spec.argv,
                environment=spec.environment,
            )
        except WebPrivateStateError as error:
            raise SandboxError(str(error)) from error
        if web_session is not None:
            raise SandboxError(
                "persistent Web identities are unavailable in a clean proof "
                "workspace; use explicit independent proof inputs instead"
            )
        if input_locators and proof_inputs:
            raise ValueError(
                "input_locators and proof_inputs cannot be used together"
            )
        if (
            len(input_locators) > MAX_PROOF_INPUTS
            or len(proof_inputs) > MAX_PROOF_INPUTS
            or len(proof_outputs) > MAX_PROOF_INPUTS
        ):
            raise ValueError(
                "clean proof cannot contain more than 256 inputs or outputs"
            )
        if (
            sum(item.size_bytes for item in proof_inputs)
            > self.limits.work_tree_max_bytes
        ):
            raise ValueError("clean proof inputs exceed the total size bound")
        destinations = [
            item.destination_locator for item in proof_inputs
        ]
        if len(set(destinations)) != len(destinations):
            raise ValueError("clean proof input destinations must be unique")
        if (
            any(type(item) is not ProofOutput for item in proof_outputs)
            or sum(item.maximum_bytes for item in proof_outputs)
            > self.limits.work_tree_max_bytes
        ):
            raise ValueError("clean proof outputs exceed the total size bound")
        output_sources = [item.source_locator for item in proof_outputs]
        output_names = [item.name for item in proof_outputs]
        if (
            len(set(output_sources)) != len(output_sources)
            or len(set(output_names)) != len(output_names)
            or bool(set(output_sources) & set(destinations))
        ):
            raise ValueError(
                "clean proof output sources and names must be unique and "
                "must not alias proof inputs"
            )
        network, boundary_environment = self._authorized_runtime(spec)
        if bool(spec.resource_request.network) != (network != "none"):
            raise SandboxError(
                "leased network resource does not match authorized network mode"
            )
        execution_limits = self._execution_limits(spec.resource_request)
        import secrets

        proof_nonce = secrets.token_hex(6)
        try:
            proof_live_root = ensure_private_directory(
                self.scope.work_dir.parent / PROOF_LIVE_DIRECTORY
            )
            live_parent_metadata = self.scope.work_dir.parent.stat(
                follow_symlinks=False
            )
            live_root_metadata = proof_live_root.stat(
                follow_symlinks=False
            )
        except (OSError, SafeFileError) as error:
            raise ScopeError(
                "clean proof live directory is unsafe"
            ) from error
        if (
            not stat.S_ISDIR(live_parent_metadata.st_mode)
            or live_parent_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(live_parent_metadata.st_mode) & 0o022
            or not stat.S_ISDIR(live_root_metadata.st_mode)
            or live_root_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(live_root_metadata.st_mode) & 0o077
        ):
            raise ScopeError(
                "clean proof live root must be a private owned sibling"
            )
        with tempfile.TemporaryDirectory(
            prefix=f"clean-{proof_nonce}-",
            dir=proof_live_root,
        ) as temporary:
            proof_work = Path(temporary).resolve()
            init_name = (
                f"ctfos-proof-init-{self.scope.fingerprint[:12]}-{proof_nonce}"
            )
            # The first one-shot run initializes the exact challenge copy.
            init_argv = self.build_container_argv(
                network="none",
                work_dir=proof_work,
                detach=False,
                name=init_name,
                command=("true",),
                remove=True,
                limits=execution_limits,
            )
            with self._work_tree_guard(
                proof_work,
                operation="clean proof initialization",
            ) as work_tree_guard:
                work_tree_guard.start()
                initialized = self._capture(
                    init_argv,
                    timeout=self._clamp_hard_deadline_timeout(
                        deadline_monotonic,
                        120,
                        operation="clean proof initialization container",
                    ),
                    timeout_cleanup_container=init_name,
                )
                self._remaining_hard_deadline(
                    deadline_monotonic,
                    operation="clean proof initialization completion",
                )
                if initialized.returncode != 0:
                    raise SandboxError(
                        "could not initialize clean proof workspace: "
                        + self._bounded(initialized.stderr, 4096).strip()
                    )
            for locator in input_locators:
                self._remaining_hard_deadline(
                    deadline_monotonic,
                    operation="clean proof input preparation",
                )
                try:
                    normalized = normalize_locator(locator)
                    parts = normalized.split("/")
                    parent_locator = "/".join(parts[:-1])
                    destination_parent = ensure_relative_directory(
                        proof_work,
                        parent_locator,
                    )
                except SafeFileError as error:
                    raise ScopeError(
                        f"invalid proof input locator: {locator}"
                    ) from error
                destination = destination_parent / parts[-1]
                if destination.exists() or destination.is_symlink():
                    raise ScopeError(
                        "proof input would overwrite an original challenge file: "
                        f"{normalized}"
                    )
                try:
                    copy_bounded_regular(
                        self.scope.work_dir,
                        normalized,
                        destination,
                        maximum_bytes=self.limits.work_tree_max_bytes,
                        mode=0o500,
                    )
                except SafeFileError as error:
                    raise ScopeError(
                        f"proof input could not be copied safely: {normalized}"
                    ) from error
            for item in proof_inputs:
                self._remaining_hard_deadline(
                    deadline_monotonic,
                    operation="clean proof input preparation",
                )
                parts = item.destination_locator.split("/")
                try:
                    destination_parent = ensure_relative_directory(
                        proof_work,
                        "/".join(parts[:-1]),
                    )
                except SafeFileError as error:
                    raise ScopeError(
                        "proof input destination contains an unsafe directory: "
                        f"{item.destination_locator}"
                    ) from error
                destination = destination_parent / parts[-1]
                if destination.exists() or destination.is_symlink():
                    raise ScopeError(
                        "proof input would overwrite an original challenge file: "
                        f"{item.destination_locator}"
                    )
                try:
                    copy_bounded_regular(
                        self.scope.work_dir,
                        item.source_locator,
                        destination,
                        maximum_bytes=self.limits.work_tree_max_bytes,
                        expected_sha256=item.sha256,
                        expected_size=item.size_bytes,
                        mode=0o500,
                    )
                except SafeFileError as error:
                    raise ScopeError(
                        "proof input no longer matches its immutable manifest: "
                        f"{item.destination_locator}"
                    ) from error

            # A declared proof output must be created by this invocation.  Do
            # not permit an input or pre-existing workspace file to be
            # relabelled as command output.  Missing parent directories are
            # expected; any existing symlink component fails closed.
            for item in proof_outputs:
                current = proof_work
                parts = item.source_locator.split("/")
                for index, component in enumerate(parts):
                    current = current / component
                    try:
                        metadata = current.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        break
                    except OSError as error:
                        raise ScopeError(
                            "clean proof output path cannot be inspected: "
                            f"{item.source_locator}"
                        ) from error
                    if stat.S_ISLNK(metadata.st_mode):
                        raise ScopeError(
                            "clean proof output path contains a symlink: "
                            f"{item.source_locator}"
                        )
                    if index == len(parts) - 1:
                        raise ScopeError(
                            "clean proof output already exists before command: "
                            f"{item.source_locator}"
                        )
                    if not stat.S_ISDIR(metadata.st_mode):
                        raise ScopeError(
                            "clean proof output parent is not a directory: "
                            f"{item.source_locator}"
                        )

            self.check_work_tree(
                proof_work,
                phase="after clean proof input preparation",
            )
            self._remaining_hard_deadline(
                deadline_monotonic,
                operation="clean proof command",
            )
            proof_name = (
                f"ctfos-proof-{self.scope.fingerprint[:12]}-"
                f"{proof_nonce}"
            )
            with self._work_tree_guard(
                proof_work,
                operation="clean proof command",
            ) as work_tree_guard:
                work_tree_guard.start()
                command_timeout = self._effective_command_timeout(
                    spec,
                    deadline_monotonic,
                    operation="clean proof command",
                )
                command = (
                    "ctfwrap",
                    "--json",
                    "--timeout",
                    str(command_timeout),
                    "--summary-bytes",
                    str(spec.summary_bytes),
                    "--stdout-limit-bytes",
                    str(execution_limits.stream_capture_max_bytes),
                    "--stderr-limit-bytes",
                    str(execution_limits.stream_capture_max_bytes),
                    "--",
                    *spec.argv,
                )
                argv = self.build_container_argv(
                    network=network,
                    work_dir=proof_work,
                    detach=False,
                    name=proof_name,
                    command=command,
                    remove=True,
                    limits=execution_limits,
                )
                # Environment belongs before the image for docker run. Build a
                # fresh argv insertion immediately before the image.
                image_index = argv.index(self.image_reference)
                environment_args: list[str] = []
                proof_environment = dict(spec.environment)
                proof_environment.update(boundary_environment)
                for name, environment_value in sorted(
                    proof_environment.items()
                ):
                    environment_args.extend(
                        ["--env", f"{name}={environment_value}"]
                    )
                argv[image_index:image_index] = environment_args
                control_timeout = self._clamp_hard_deadline_timeout(
                    deadline_monotonic,
                    (
                        command_timeout + 15
                        if command_timeout
                        else 604800 + 15
                    ),
                    operation="clean proof command",
                )
                result = self._capture(
                    argv,
                    timeout=control_timeout,
                    timeout_cleanup_container=proof_name,
                )
                self._remaining_hard_deadline(
                    deadline_monotonic,
                    operation="clean proof command completion",
                )
                value = self._parse_json(result)
                if value.get("kind") != "run_result":
                    raise SandboxError(
                        "clean proof returned the wrong result kind"
                    )
            try:
                run_id = str(value["run_id"])
                if not re.fullmatch(r"run-[0-9]{8,}", run_id):
                    raise ValueError("invalid run id")
                proof_source = proof_work / ".ctf" / "runs" / run_id
                proof_root = self.scope.work_dir / "proof"
                if proof_root.is_symlink():
                    raise ScopeError("proof artifact directory must not be a symlink")
                proof_root.mkdir(mode=0o700, exist_ok=True)
                proof_root_metadata = proof_root.stat(
                    follow_symlinks=False
                )
                if (
                    not stat.S_ISDIR(proof_root_metadata.st_mode)
                    or proof_root_metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(proof_root_metadata.st_mode) & 0o077
                ):
                    raise ScopeError(
                        "proof artifact path must be a private owned directory"
                    )
                proof_destination = proof_root / f"clean-{proof_nonce}"
                proof_destination_identity: os.stat_result | None = None
                try:
                    proof_destination.mkdir(mode=0o700)
                    proof_destination_identity = proof_destination.stat(
                        follow_symlinks=False
                    )
                    file_limits = {
                        "result.json": min(
                            MAX_CONTROL_OUTPUT,
                            self.limits.work_tree_max_bytes,
                        ),
                        "stdout.log": max(
                            1,
                            execution_limits.stream_capture_max_bytes,
                        ),
                        "stderr.log": max(
                            1,
                            execution_limits.stream_capture_max_bytes,
                        ),
                    }
                    for filename, maximum_bytes in file_limits.items():
                        try:
                            copy_bounded_regular(
                                proof_source,
                                filename,
                                proof_destination / filename,
                                maximum_bytes=maximum_bytes,
                                mode=0o400,
                            )
                        except SafeFileError as error:
                            raise SandboxError(
                                "clean proof produced unsafe or oversized "
                                f"{filename}: {error}"
                            ) from error
                    durable_outputs: list[ArtifactRef] = []
                    if proof_outputs:
                        try:
                            output_directory = ensure_relative_directory(
                                proof_destination,
                                "outputs",
                            )
                        except SafeFileError as error:
                            raise SandboxError(
                                "clean proof output directory is unsafe"
                            ) from error
                        for item in proof_outputs:
                            try:
                                copied = copy_bounded_regular(
                                    proof_work,
                                    item.source_locator,
                                    output_directory / item.name,
                                    maximum_bytes=item.maximum_bytes,
                                    mode=0o400,
                                )
                            except SafeFileError as error:
                                raise SandboxError(
                                    "clean proof produced an unsafe, missing, "
                                    "or oversized declared output "
                                    f"{item.name}: {error}"
                                ) from error
                            durable_outputs.append(
                                ArtifactRef(
                                    locator=(
                                        f"proof/{proof_destination.name}/"
                                        f"outputs/{item.name}"
                                    ),
                                    sha256=copied.sha256,
                                    size_bytes=copied.size_bytes,
                                    scope_fingerprint=self.scope.fingerprint,
                                )
                            )
                    sidecar_source = proof_source / FLAG_CANDIDATE_SIDECAR
                    try:
                        sidecar_source.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    except OSError as error:
                        raise SandboxError(
                            "clean proof candidate sidecar cannot be inspected"
                        ) from error
                    else:
                        try:
                            copy_bounded_regular(
                                proof_source,
                                FLAG_CANDIDATE_SIDECAR,
                                (
                                    proof_destination
                                    / FLAG_CANDIDATE_SIDECAR
                                ),
                                maximum_bytes=min(
                                    DEFAULT_SIDECAR_MAX_BYTES,
                                    self.limits.work_tree_max_bytes,
                                ),
                                mode=0o400,
                            )
                        except SafeFileError as error:
                            raise SandboxError(
                                "clean proof produced an unsafe or oversized "
                                "flag candidate sidecar"
                            ) from error
                    self.check_work_tree(
                        self.scope.work_dir,
                        phase="after clean proof evidence persistence",
                    )
                    self._remaining_hard_deadline(
                        deadline_monotonic,
                        operation="clean proof result promotion",
                    )
                    proof_locator = (
                        f"/work/proof/{proof_destination.name}"
                    )
                    return sandbox_result_from_mapping(
                        value,
                        stdout_path=f"{proof_locator}/stdout.log",
                        stderr_path=f"{proof_locator}/stderr.log",
                        proof_outputs=tuple(durable_outputs),
                    )
                except BaseException as persistence_error:
                    cleanup_error: str | None = None
                    if (
                        proof_destination_identity is None
                        and not isinstance(
                            persistence_error,
                            FileExistsError,
                        )
                    ):
                        try:
                            current = proof_destination.stat(
                                follow_symlinks=False
                            )
                        except FileNotFoundError:
                            current = None
                        except BaseException as inspection_error:
                            current = None
                            cleanup_error = (
                                "cannot inspect exact generated proof "
                                f"directory: {type(inspection_error).__name__}: "
                                f"{inspection_error}"
                            )
                        else:
                            if stat.S_ISDIR(current.st_mode):
                                proof_destination_identity = current
                            else:
                                cleanup_error = (
                                    "refused cleanup because the exact "
                                    "generated proof path is not a directory"
                                )
                    try:
                        if proof_destination_identity is not None:
                            cleanup_error = self._remove_exact_directory(
                                proof_destination,
                                proof_destination_identity,
                            )
                    except BaseException as cleanup_exception:
                        cleanup_error = (
                            f"{type(cleanup_exception).__name__}: "
                            f"{cleanup_exception}"
                        )
                    if cleanup_error is not None:
                        cleanup_failure = SandboxError(
                            f"{persistence_error}; exact proof cleanup failed: "
                            f"{cleanup_error}"
                        )
                        if isinstance(persistence_error, Exception):
                            raise cleanup_failure from persistence_error
                        persistence_error.add_note(str(cleanup_failure))
                    raise
            except (KeyError, OSError, TypeError, ValueError) as error:
                raise SandboxError("clean proof returned an invalid result") from error

    def resolve_artifact(self, locator: str) -> Path:
        if (
            not locator
            or "\x00" in locator
            or Path(locator).is_absolute()
            or len(locator.encode("utf-8")) > 4096
        ):
            raise ScopeError("artifact locator must be a bounded relative path")
        unresolved = self.scope.work_dir / locator
        current = self.scope.work_dir
        for component in Path(locator).parts:
            current = current / component
            if current.is_symlink():
                raise ScopeError("artifact path must not contain symlinks")
        candidate = unresolved.resolve(strict=True)
        if candidate == self.scope.work_dir or self.scope.work_dir not in candidate.parents:
            raise ScopeError("artifact locator escapes the challenge workspace")
        if not candidate.is_file():
            raise ScopeError("artifact must be a non-symlink regular file")
        return candidate
