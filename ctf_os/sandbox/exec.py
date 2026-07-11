"""Safe lookup and Docker-only execution for a locally recorded attempt."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shlex
from collections.abc import Sequence
from typing import Any

from ..artifact_writer import ArtifactWriter
from ..config import AppConfig
from ..local_state import LocalState
from ..models import AttemptStatus
from .container import build_container_name, build_docker_exec_argv, build_docker_staging_scrub_argv
from .docker_cli import CommandResult, DockerCli


class SandboxExecError(ValueError):
    pass


@dataclass(frozen=True)
class ResolvedAttempt:
    attempt_id: str
    container_name: str
    workdir: Path
    challenge_id: str


def resolve_local_attempt(config: AppConfig, attempt_id: str) -> ResolvedAttempt:
    """Resolve one live, marker-backed local attempt by exact identity."""
    state = LocalState.for_config(config)
    attempt = state.get_active_attempt(attempt_id)
    if attempt is None:
        raise SandboxExecError(f"attempt is unknown, expired, or no longer locally leased: {attempt_id}")
    if not attempt.container_name:
        raise SandboxExecError(f"local attempt {attempt_id} has no sandbox container")
    if attempt.synthetic or attempt.backend != "codex_cli" or attempt.status is not AttemptStatus.RUNNING:
        raise SandboxExecError("sandbox exec is available only for a live production Codex attempt")
    try:
        staging = ArtifactWriter.staging_for_workdir(attempt.workdir)
    except ValueError as exc:
        raise SandboxExecError(f"attempt workdir is not exact sterile staging: {exc}") from exc
    challenge = state.get_challenge(attempt.challenge_id)
    if challenge is None or challenge.contest != config.contest_name:
        raise SandboxExecError("attempt challenge is not part of this configured local contest")
    expected = build_container_name(
        config.team_id, challenge.contest, challenge.name, attempt.id,
    )
    if attempt.container_name != expected:
        raise SandboxExecError("attempt container identity does not match this local scope")
    return ResolvedAttempt(attempt.id, attempt.container_name, staging.workdir, challenge.id)


def execute_attempt_command(
    config: AppConfig,
    attempt_id: str,
    command: Sequence[str] | str,
    *,
    docker: DockerCli | None = None,
    cancel_event: Any | None = None,
) -> CommandResult:
    try:
        command_argv = _command_argv(command)
    except ValueError as exc:
        raise SandboxExecError(str(exc)) from exc
    attempt = resolve_local_attempt(config, attempt_id)
    adapter = docker or DockerCli()
    result = adapter.exec(
        build_docker_exec_argv(attempt.container_name, command_argv, docker_command=adapter.command),
        cancel_event=cancel_event,
    )
    if result.timed_out:
        # Killing the docker-cli process alone does not guarantee that a
        # command inside the container died.  This exact name was derived from
        # the live local lease and deterministic scope above, so removing it
        # is safe and cannot target another attempt/container.
        cleanup = adapter.remove(attempt.container_name)
        scrub_error = ""
        scrub_ok = False
        if cleanup.ok:
            # The exact live container is gone, so this is the one-shot ctf
            # fallback for mode-000 worker trees.  It has no workspace mount
            # and its fixed argv can only see this validated attempt staging.
            try:
                staging = ArtifactWriter.staging_for_workdir(attempt.workdir)
                scrub = adapter.run(build_docker_staging_scrub_argv(
                    config.sandbox_image, staging.workdir, staging.artifacts,
                    docker_command=adapter.command,
                ))
                if scrub.ok:
                    ArtifactWriter.cleanup_attempt_staging(staging.workdir)
                    scrub_ok = True
                else:
                    scrub_error = scrub.stderr or "unprivileged staging scrub failed"
            except ValueError as exc:
                scrub_error = str(exc)
        if not cleanup.ok:
            detail = cleanup.stderr or "direct sandbox exec timed out/cancelled; exact container removal failed and staging was retained"
        elif not scrub_ok:
            detail = scrub_error or "direct sandbox exec timed out/cancelled; staging scrub failed and staging was retained"
        else:
            detail = "direct sandbox exec timed out/cancelled; exact container and staging removed"
        LocalState.for_config(config).record_cleanup(
            attempt.attempt_id, ok=cleanup.ok and scrub_ok, detail=detail,
        )
    return result


def _command_argv(command: Sequence[str] | str) -> list[str]:
    if isinstance(command, str):
        values = shlex.split(command, posix=True)
    else:
        values = list(command)
    if not values or any(not isinstance(value, str) or not value or any(ord(character) < 32 or ord(character) == 127 for character in value) for value in values):
        raise ValueError("sandbox command must be a non-empty argv without control characters")
    if values[0].startswith("-"):
        raise ValueError("sandbox command program must not start with '-'")
    return values
