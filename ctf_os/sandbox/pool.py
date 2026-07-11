"""Local, scope-limited lifecycle tracking for per-attempt sandboxes."""

from __future__ import annotations

from pathlib import Path

from ..artifact_writer import ArtifactWriter
from .broker import AttemptCommandBroker, create_ctf_exec_helper
from .container import SandboxContainer, SandboxScope, SandboxSpec, build_docker_staging_scrub_argv
from .docker_cli import CommandResult, DockerCli


class PoolCapacityError(RuntimeError):
    """Raised when a local node would exceed its configured sandbox capacity."""


class SandboxPathError(ValueError):
    """Raised when an attempt tries to mount outside its supplied roots."""


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except ValueError:
        return False
    return True


def build_cleanup_filters(scope: SandboxScope, *, all_containers: bool = False) -> list[str]:
    """Return Docker label filters that can never include unlabeled containers."""

    filters = ["label=ctf-os=true"]
    if all_containers:
        # --all is scoped across this member's contests, never across a team
        # and never across another member on the same Docker daemon.
        return filters + [f"label=ctf-os.team_id={scope.team_id}", f"label=ctf-os.member={scope.member}"]
    filters.extend(
        [
            f"label=ctf-os.team_id={scope.team_id}",
            f"label=ctf-os.member={scope.member}",
            f"label=ctf-os.contest={scope.contest}",
            f"label=ctf-os.challenge={scope.challenge}",
        ]
    )
    return filters


class DockerSandboxPool:
    """Tracks and manages only this local member's current challenge attempts."""

    def __init__(
        self,
        *,
        scope: SandboxScope,
        workspace_root: str | Path,
        output_root: str | Path,
        docker: DockerCli | None = None,
        max_containers: int = 2,
    ) -> None:
        if max_containers < 1:
            raise ValueError("max_containers must be at least one")
        self.scope = scope
        self.workspace_root = Path(workspace_root).resolve(strict=False)
        self.output_root = Path(output_root).resolve(strict=False)
        self.docker = docker or DockerCli()
        self.max_containers = max_containers
        self._containers: dict[str, SandboxContainer] = {}
        self._brokers: dict[str, AttemptCommandBroker] = {}
        self.cleanup_results: dict[str, CommandResult] = {}
        # Broker transport teardown is independently diagnosable from Docker
        # lifecycle completion.  In particular, an unsafe spool entry may be
        # retained or unlinked exactly without authorizing a container leak.
        self.broker_cleanup_errors: dict[str, str] = {}

    @property
    def active_attempt_ids(self) -> tuple[str, ...]:
        return tuple(self._containers)

    @property
    def active_count(self) -> int:
        return len(self._containers)

    def daemon_available(self) -> bool:
        return self.docker.daemon_available()

    def image_available(self, image: str) -> bool:
        return self.docker.image_exists(image)

    def _validate_spec(self, spec: SandboxSpec) -> None:
        if spec.scope != self.scope:
            raise PermissionError("sandbox spec scope does not match this local pool")
        if not _inside(spec.workspace, self.workspace_root):
            raise SandboxPathError("workspace must be inside the supplied workspace_root")
        try:
            staging = ArtifactWriter.staging_for_workdir(spec.workdir)
        except ValueError as exc:
            raise SandboxPathError(f"attempt workdir must be private sterile staging: {exc}") from exc
        if spec.artifacts != staging.artifacts:
            raise SandboxPathError("attempt artifacts must be that attempt's private staging directory")

    def precreate(self, spec: SandboxSpec, *, create_helper: bool = True) -> SandboxContainer:
        """Create one container now and track it only after Docker succeeds."""

        self._validate_spec(spec)
        if spec.attempt_id in self._containers:
            raise ValueError(f"attempt already has a sandbox: {spec.attempt_id}")
        if self.active_count >= self.max_containers:
            raise PoolCapacityError(f"sandbox capacity reached ({self.max_containers})")
        # `_validate_spec` opened and checked these exact mount roots.  Do not
        # recreate or chmod them here: `ctf-exec` will be host-owned 0700 in
        # the sticky work root and no broad construction step may touch it.
        container = SandboxContainer(spec, self.docker)
        result = container.start()
        if not result.ok:
            raise RuntimeError(f"docker run failed for {container.name}: {result.stderr}")
        broker = AttemptCommandBroker(
            attempt_id=spec.attempt_id,
            container_name=container.name,
            workdir=spec.workdir,
            artifacts=spec.artifacts,
            storage_limit_bytes=spec.storage_limit_bytes,
            storage_inode_limit=spec.storage_inode_limit,
            docker=self.docker,
        )
        try:
            broker.start()
            if create_helper:
                create_ctf_exec_helper(spec.workdir / "ctf-exec", broker=broker)
        except Exception:
            self._stop_broker(spec.attempt_id, broker)
            try:
                cleanup_result = container.remove()
            except Exception as exc:
                cleanup_result = _lifecycle_error(self.docker, "remove", container.name, exc)
            self.cleanup_results[spec.attempt_id] = cleanup_result
            raise
        self._containers[spec.attempt_id] = container
        self._brokers[spec.attempt_id] = broker
        return container

    def get(self, attempt_id: str) -> SandboxContainer | None:
        return self._containers.get(attempt_id)

    def broker(self, attempt_id: str) -> AttemptCommandBroker | None:
        return self._brokers.get(attempt_id)

    def release(self, attempt_id: str, *, remove: bool = True) -> CommandResult | None:
        container = self._containers.get(attempt_id)
        if container is None:
            return None
        broker = self._brokers.get(attempt_id)
        if broker is not None:
            self._stop_broker(attempt_id, broker)
        if not remove:
            # A preserved failed attempt retains both its stopped container
            # and its staging evidence exactly as-is.
            try:
                result = container.stop()
            except Exception as exc:
                result = _lifecycle_error(self.docker, "stop", container.name, exc)
            self.cleanup_results[attempt_id] = result
            if result.ok:
                self._containers.pop(attempt_id, None)
                self._brokers.pop(attempt_id, None)
            return result

        stop_result: CommandResult
        scrub_result: CommandResult | None = None
        # Exact Docker stop/remove is a lifecycle guarantee even when the
        # broker's hostile-spool cleanup failed above.  Keep remove in finally
        # so a scrub/build anomaly cannot strand the labeled attempt either.
        try:
            try:
                stop_result = container.stop()
            except Exception as exc:
                stop_result = _lifecycle_error(self.docker, "stop", container.name, exc)
            if stop_result.ok:
                # Primary path: no worker process remains while the one-shot
                # ctf scrubber descends the two validated bind mounts.
                try:
                    scrub_result = self._scrub_staging(container)
                except Exception as exc:
                    scrub_result = _lifecycle_error(self.docker, "staging scrub", container.name, exc)
        finally:
            try:
                remove_result = container.remove()
            except Exception as exc:
                remove_result = _lifecycle_error(self.docker, "remove", container.name, exc)
        if not stop_result.ok and remove_result.ok:
            # A broker timeout may already have removed the exact attempt
            # container.  Only after forcing that exact name is it safe to run
            # the same minimal fallback scrubber.
            try:
                scrub_result = self._scrub_staging(container)
            except Exception as exc:
                scrub_result = _lifecycle_error(self.docker, "staging scrub", container.name, exc)

        if not remove_result.ok:
            result = remove_result
        elif scrub_result is None or not scrub_result.ok:
            result = scrub_result or CommandResult(
                (self.docker.command,), returncode=1,
                stderr="attempt container stopped but staging scrub was not run",
            )
        else:
            try:
                ArtifactWriter.cleanup_attempt_staging(container.spec.workdir)
            except ValueError as exc:
                result = CommandResult(
                    scrub_result.argv, returncode=1,
                    stderr=f"staging scrub completed but host teardown was incomplete: {exc}",
                )
            else:
                result = remove_result
        self.cleanup_results[attempt_id] = result
        # Docker has already confirmed removal even when the scrub/host
        # teardown reports failure; do not retain a stale active entry.
        if remove_result.ok:
            self._containers.pop(attempt_id, None)
            self._brokers.pop(attempt_id, None)
        return result

    def _stop_broker(self, attempt_id: str, broker: AttemptCommandBroker) -> None:
        """Record transport teardown failures without weakening Docker cleanup."""
        try:
            broker.stop()
        except Exception as exc:
            self.broker_cleanup_errors[attempt_id] = f"{type(exc).__name__}: {exc}"

    def _scrub_staging(self, container: SandboxContainer) -> CommandResult:
        """Run the fixed-argv, ctf-only scrubber for one exact staging tree."""
        try:
            staging = ArtifactWriter.staging_for_workdir(container.spec.workdir)
            if staging.artifacts != container.spec.artifacts:
                raise ValueError("attempt artifacts no longer match exact staging")
            argv = build_docker_staging_scrub_argv(
                container.spec.image, staging.workdir, staging.artifacts,
                docker_command=self.docker.command,
            )
        except ValueError as exc:
            return CommandResult((self.docker.command,), returncode=1, stderr=f"unsafe staging scrub scope: {exc}")
        return self.docker.run(argv)

    def cleanup(self, *, all_containers: bool = False) -> list[str]:
        """Remove label-matched containers; ``all`` still requires ``ctf-os=true``."""

        container_ids = self.docker.list_container_ids(
            build_cleanup_filters(self.scope, all_containers=all_containers)
        )
        removed: list[str] = []
        for container_id in container_ids:
            result = self.docker.remove(container_id)
            self.cleanup_results[container_id] = result
            if result.ok:
                removed.append(container_id)
        for attempt_id, container in tuple(self._containers.items()):
            if container.name in removed:
                broker = self._brokers.pop(attempt_id, None)
                if broker is not None:
                    self._stop_broker(attempt_id, broker)
                self._containers.pop(attempt_id, None)
        return removed


def _lifecycle_error(docker: DockerCli, action: str, container_name: str, exc: Exception) -> CommandResult:
    """Turn an unexpected local lifecycle exception into recorded state."""
    return CommandResult(
        (docker.command, action, container_name),
        returncode=1,
        stderr=f"attempt container {action} raised {type(exc).__name__}: {exc}",
    )
