"""Bounded, argv-only Docker adapter used by attempt brokers.

Docker's CLI is still the narrow host privilege boundary.  Its output is
streamed into a combined fixed budget rather than ``capture_output=True`` so a
container cannot make the coordinator allocate unbounded memory.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from subprocess import CompletedProcess
import subprocess
import threading
import time
from typing import Any, Callable, Protocol, Sequence


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandRunner(Protocol):
    def __call__(self, argv: Sequence[str]) -> CommandResult | CompletedProcess[str]:
        """Run an argv command without using a shell."""


class RecordingCommandRunner:
    def __init__(self, *, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str]) -> CommandResult:
        captured = list(argv)
        self.calls.append(captured)
        return CommandResult(tuple(captured), self.returncode, self.stdout, self.stderr)


def _subprocess_runner(
    argv: Sequence[str], *, timeout_sec: float, max_output_bytes: int, cancel_event: Any | None = None,
) -> CommandResult:
    """Stream stdout/stderr while retaining at most one combined byte budget."""
    proc = subprocess.Popen(
        list(argv), shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=False, start_new_session=True,
    )
    stdout, stderr = bytearray(), bytearray()
    lock = threading.Lock()
    truncated = [False]

    def pump(stream, target: bytearray) -> None:
        if stream is None:
            return
        try:
            while chunk := stream.read(16 * 1024):
                with lock:
                    remaining = max_output_bytes - len(stdout) - len(stderr)
                    if remaining > 0:
                        target.extend(chunk[:remaining])
                    if len(chunk) > max(remaining, 0):
                        truncated[0] = True
        finally:
            stream.close()

    readers = [threading.Thread(target=pump, args=(proc.stdout, stdout), daemon=True),
               threading.Thread(target=pump, args=(proc.stderr, stderr), daemon=True)]
    for reader in readers:
        reader.start()
    started, stopped = time.monotonic(), False
    try:
        while proc.poll() is None:
            if (cancel_event is not None and cancel_event.is_set()) or time.monotonic() - started >= timeout_sec:
                stopped = True
                try:
                    os.killpg(proc.pid, 15)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(proc.pid, 9)
                    except ProcessLookupError:
                        pass
                break
            time.sleep(0.02)
        returncode = proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        stopped = True
        try:
            os.killpg(proc.pid, 9)
        except ProcessLookupError:
            pass
        returncode = proc.wait()
    finally:
        for reader in readers:
            reader.join(timeout=2)
    out_text = stdout.decode("utf-8", errors="replace")
    err_text = stderr.decode("utf-8", errors="replace")
    if truncated[0]:
        err_text += "\n[ctf-os docker output truncated]\n"
    if stopped:
        err_text += f"\ndocker command exceeded/cancelled at {timeout_sec:g}s\n"
    return CommandResult(tuple(str(item) for item in argv), 124 if stopped else returncode, out_text, err_text, stopped, truncated[0])


class DockerCli:
    """Run only scoped Docker argv operations with a hard output/time budget."""

    def __init__(
        self,
        *,
        command: str = "docker",
        runner: CommandRunner | Callable[[Sequence[str]], object] | None = None,
        dry_run: bool = False,
        command_timeout_sec: float = 30.0,
        max_output_bytes: int = 64 * 1024,
    ) -> None:
        if not _safe_atom(command):
            raise ValueError("docker command must be a non-empty executable name")
        if command_timeout_sec <= 0 or command_timeout_sec > 60:
            raise ValueError("docker command timeout must be in 0..60 seconds")
        if not isinstance(max_output_bytes, int) or not 1024 <= max_output_bytes <= 4 * 1024 * 1024:
            raise ValueError("docker output budget must be between 1KiB and 4MiB")
        self.command = command
        self.runner = runner
        self.dry_run = dry_run
        self.command_timeout_sec = float(command_timeout_sec)
        self.max_output_bytes = max_output_bytes
        self.calls: list[list[str]] = []

    def invoke(
        self, argv: Sequence[str], *, timeout_sec: float | None = None, cancel_event: Any | None = None,
    ) -> CommandResult:
        command = [str(item) for item in argv]
        if not command:
            raise ValueError("cannot invoke an empty command")
        budget_time = self.command_timeout_sec if timeout_sec is None else float(timeout_sec)
        if budget_time <= 0 or budget_time > 60:
            raise ValueError("Docker invocation timeout must be in 0..60 seconds")
        self.calls.append(command)
        if self.dry_run:
            return CommandResult(tuple(command))
        raw_result = self.runner(command) if self.runner else _subprocess_runner(
            command, timeout_sec=budget_time, max_output_bytes=self.max_output_bytes, cancel_event=cancel_event,
        )
        if isinstance(raw_result, CommandResult):
            return _bound_result(raw_result, command, self.max_output_bytes)
        if isinstance(raw_result, CompletedProcess):
            return _bound_result(CommandResult(tuple(command), raw_result.returncode, raw_result.stdout or "", raw_result.stderr or ""), command, self.max_output_bytes)
        if isinstance(raw_result, int):
            return CommandResult(tuple(command), raw_result)
        raise TypeError("command runner must return CommandResult, CompletedProcess, or int")

    def daemon_available(self) -> bool:
        return self.invoke([self.command, "info", "--format", "{{.ServerVersion}}"]).ok

    def image_exists(self, image: str) -> bool:
        _validate_image(image)
        return self.invoke([self.command, "image", "inspect", image]).ok

    def image_id(self, image: str) -> str | None:
        _validate_image(image)
        result = self.invoke([self.command, "image", "inspect", "--format", "{{.Id}}", image])
        return result.stdout.strip() if result.ok and result.stdout.strip() else None

    def run(self, argv: Sequence[str], *, timeout_sec: float | None = None, cancel_event: Any | None = None) -> CommandResult:
        return self.invoke(argv, timeout_sec=timeout_sec, cancel_event=cancel_event)

    def exec(self, argv: Sequence[str], *, timeout_sec: float | None = None, cancel_event: Any | None = None) -> CommandResult:
        return self.invoke(argv, timeout_sec=timeout_sec, cancel_event=cancel_event)

    def stop(self, container_name: str) -> CommandResult:
        _validate_container_reference(container_name)
        return self.invoke([self.command, "stop", container_name])

    def remove(self, container_name: str) -> CommandResult:
        _validate_container_reference(container_name)
        return self.invoke([self.command, "rm", "-f", container_name])

    def list_container_ids(self, filters: Sequence[str]) -> list[str]:
        argv = [self.command, "ps", "-aq"]
        for item in filters:
            argv.extend(["--filter", item])
        result = self.invoke(argv)
        if not result.ok or result.truncated:
            return []
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _bound_result(value: CommandResult, argv: Sequence[str], limit: int) -> CommandResult:
    stdout, stderr = value.stdout.encode("utf-8", errors="replace"), value.stderr.encode("utf-8", errors="replace")
    remaining = limit
    clipped_out, clipped_err = stdout[:remaining], b""
    remaining -= len(clipped_out)
    if remaining > 0:
        clipped_err = stderr[:remaining]
    truncated = value.truncated or len(stdout) + len(stderr) > limit
    text_err = clipped_err.decode("utf-8", errors="replace")
    if truncated:
        text_err += "\n[ctf-os docker output truncated]\n"
    return CommandResult(tuple(str(item) for item in argv), value.returncode,
                         clipped_out.decode("utf-8", errors="replace"), text_err,
                         value.timed_out, truncated)


def _safe_atom(value: object) -> bool:
    return isinstance(value, str) and bool(value) and not value.startswith("-") and not any(ord(character) < 32 or ord(character) == 127 for character in value)


def _validate_container_reference(value: str) -> None:
    if not _safe_atom(value):
        raise ValueError("container name or ID must be a non-empty non-option atom")


def _validate_image(value: str) -> None:
    import re
    if not _safe_atom(value) or len(value) > 255:
        raise ValueError("image must be a non-empty OCI image reference")
    expression = re.compile(
        r"(?:[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?/)*"
        r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
        r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[A-Fa-f0-9]{64})?\Z"
    )
    if not expression.fullmatch(value):
        raise ValueError("image must be a valid OCI image reference")
