#!/usr/bin/env python3
"""Run the exact local Docker release gates for every CTF category.

This is a developer release validator, not a product scheduler.  Its command
set is closed in source, every child receives the same exact image ID, and no
challenge name, model configuration, remote target, or submission authority
can be supplied on the command line.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import BinaryIO, Sequence


REPOSITORY = Path(__file__).resolve().parent.parent
PROTOCOL = "ctfos.all_category_release_matrix.v1"
SCHEMA_VERSION = 1
IMAGE_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
CAPTURE_LIMIT_BYTES = 1_048_576
SUMMARY_LINE_LIMIT_BYTES = 65_536
REPORT_LIMIT_BYTES = 131_072
DEFAULT_TIMEOUT_SECONDS = 1_800
MIN_TIMEOUT_SECONDS = 60
MAX_TIMEOUT_SECONDS = 3_600
DEFAULT_JOBS = 2
MAX_JOBS = 3
TRUNCATION_MARKER = (
    b"\n... [ctfos release matrix omitted bounded middle bytes] ...\n"
)
SENSITIVE_ENVIRONMENT_PATTERN = re.compile(
    r"(?:API[_-]?KEY|AUTH|BEARER|CREDENTIAL|PASSWORD|SECRET|SESSION|TOKEN)",
    re.IGNORECASE,
)


@dataclasses.dataclass(frozen=True)
class ReleaseTask:
    id: str
    categories: tuple[str, ...]
    script: str
    network_contract: str


# Closed command inventory.  Adding a gate is a reviewed source change; users
# cannot inject commands or select challenges through this runner.
RELEASE_TASKS = (
    ReleaseTask(
        id="pwn_dependency_effect",
        categories=("pwn",),
        script="scripts/check-pwn-dependency-hotpath-docker.py",
        network_contract="none",
    ),
    ReleaseTask(
        id="web_state_impact",
        categories=("web",),
        script="scripts/check-web-impact-docker-hotpath.py",
        network_contract="docker_internal_local_targets",
    ),
    ReleaseTask(
        id="web_active_probe",
        categories=("web",),
        script="scripts/check-web-active-probe-docker-hotpath.py",
        network_contract="docker_internal_local_targets",
    ),
    ReleaseTask(
        id="rev_original_binary_acceptance",
        categories=("rev",),
        script=(
            "scripts/"
            "check-managed-rev-accepted-input-hotpath-docker.py"
        ),
        network_contract="none",
    ),
    ReleaseTask(
        id="crypto_metamorphic_and_misc_transform",
        categories=("crypto", "misc"),
        script="scripts/check-crypto-misc-docker-hotpaths.py",
        network_contract="none",
    ),
    ReleaseTask(
        id="forensic_assertion_graph",
        categories=("forensics",),
        script="scripts/check-forensic-assertion-hotpath-docker.py",
        network_contract="none",
    ),
)


class ReleaseMatrixError(RuntimeError):
    """A fail-closed release validation error."""


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _command_contract() -> dict[str, object]:
    return {
        "protocol": PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "tasks": [
            {
                "categories": list(task.categories),
                "id": task.id,
                "network_contract": task.network_contract,
                "script": task.script,
            }
            for task in RELEASE_TASKS
        ],
    }


def _git(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ("git", *arguments),
        cwd=REPOSITORY,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    if check and completed.returncode != 0:
        raise ReleaseMatrixError(
            "git preflight failed: "
            + completed.stderr.strip()[:2_048]
        )
    return completed


def _tracked_script_sha256(relative: str) -> str:
    path = REPOSITORY / relative
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ReleaseMatrixError(
            f"release script is missing: {relative}"
        ) from error
    if REPOSITORY not in resolved.parents:
        raise ReleaseMatrixError(
            f"release script escapes the repository: {relative}"
        )
    if path.is_symlink() or not path.is_file():
        raise ReleaseMatrixError(
            f"release script must be a regular non-symlink file: {relative}"
        )
    _git("ls-files", "--error-unmatch", "--", relative)
    head_blob = _git("show", f"HEAD:{relative}").stdout.encode("utf-8")
    working = path.read_bytes()
    if working != head_blob:
        raise ReleaseMatrixError(
            f"release script differs from HEAD: {relative}"
        )
    return _sha256(working)


def _source_snapshot() -> dict[str, object]:
    top = Path(
        _git("rev-parse", "--show-toplevel").stdout.strip()
    ).resolve()
    if top != REPOSITORY:
        raise ReleaseMatrixError("release runner is not at its repository root")
    commit = _git("rev-parse", "HEAD").stdout.strip()
    if COMMIT_PATTERN.fullmatch(commit) is None:
        raise ReleaseMatrixError("HEAD is not an exact Git commit")
    status = _git(
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    ).stdout
    if status:
        lines = status.splitlines()
        raise ReleaseMatrixError(
            "release matrix requires a clean source tree; first entry: "
            + lines[0][:512]
        )
    runner_relative = str(Path(__file__).resolve().relative_to(REPOSITORY))
    script_hashes = {
        relative: _tracked_script_sha256(relative)
        for relative in (
            runner_relative,
            *(task.script for task in RELEASE_TASKS),
        )
    }
    return {
        "clean": True,
        "commit": commit,
        "scripts": script_hashes,
    }


def _inspect_image(image_digest: str) -> dict[str, str]:
    if IMAGE_DIGEST_PATTERN.fullmatch(image_digest) is None:
        raise ReleaseMatrixError(
            "image digest must be sha256 plus 64 lowercase hexadecimal digits"
        )
    completed = subprocess.run(
        (
            "docker",
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            image_digest,
        ),
        cwd=REPOSITORY,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        raise ReleaseMatrixError(
            "exact release image is unavailable: "
            + completed.stderr.strip()[:2_048]
        )
    inspected = completed.stdout.strip()
    if inspected != image_digest:
        raise ReleaseMatrixError(
            "Docker inspection did not resolve to the requested exact image ID"
        )
    return {"digest": image_digest, "inspected_id": inspected}


class _BoundedCapture:
    def __init__(self, *, limit_bytes: int = CAPTURE_LIMIT_BYTES) -> None:
        if limit_bytes <= len(TRUNCATION_MARKER) + 2:
            raise ValueError("capture limit is too small")
        usable = limit_bytes - len(TRUNCATION_MARKER)
        self.prefix_limit = usable // 2
        self.tail_limit = usable - self.prefix_limit
        self.limit_bytes = limit_bytes
        self.prefix = bytearray()
        self.tail = bytearray()
        self.total_bytes = 0
        self.digest = hashlib.sha256()
        self.error: BaseException | None = None

    def consume(self, stream: BinaryIO) -> None:
        try:
            while True:
                chunk = stream.read(65_536)
                if not chunk:
                    break
                self.total_bytes += len(chunk)
                self.digest.update(chunk)
                needed = self.prefix_limit - len(self.prefix)
                if needed > 0:
                    self.prefix.extend(chunk[:needed])
                    chunk = chunk[needed:]
                if chunk:
                    self.tail.extend(chunk)
                    if len(self.tail) > self.tail_limit:
                        del self.tail[: len(self.tail) - self.tail_limit]
        except BaseException as error:
            self.error = error
        finally:
            stream.close()

    @property
    def truncated(self) -> bool:
        return self.total_bytes > len(self.prefix) + len(self.tail)

    def payload(self) -> bytes:
        if self.truncated:
            value = bytes(self.prefix) + TRUNCATION_MARKER + bytes(self.tail)
        else:
            value = bytes(self.prefix) + bytes(self.tail)
        if len(value) > self.limit_bytes:
            raise ReleaseMatrixError("bounded stream capture exceeded its limit")
        return value

    def metadata(self, locator: str) -> dict[str, object]:
        return {
            "captured_bytes": len(self.payload()),
            "locator": locator,
            "sha256": "sha256:" + self.digest.hexdigest(),
            "stream_bytes": self.total_bytes,
            "truncated": self.truncated,
        }


def _child_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if SENSITIVE_ENVIRONMENT_PATTERN.search(key) is None
    }
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        str(REPOSITORY)
        if not existing
        else str(REPOSITORY) + os.pathsep + existing
    )
    environment["CTFOS_RELEASE_MATRIX"] = "1"
    return environment


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGINT)
        process.wait(timeout=10)
        return
    except (ProcessLookupError, subprocess.TimeoutExpired):
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    process.wait(timeout=10)


def _last_nonempty_line(payload: bytes) -> bytes:
    for line in reversed(payload.splitlines()):
        if line.strip():
            return line
    return b""


def _validate_child_summary(
    task: ReleaseTask,
    capture: _BoundedCapture,
    image_digest: str,
) -> str:
    last_line = _last_nonempty_line(
        bytes(capture.tail) if capture.truncated else capture.payload()
    )
    if not last_line:
        raise ReleaseMatrixError(f"{task.id} emitted no JSON summary")
    if len(last_line) > SUMMARY_LINE_LIMIT_BYTES:
        raise ReleaseMatrixError(f"{task.id} JSON summary is oversized")
    try:
        value = json.loads(last_line)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseMatrixError(
            f"{task.id} final nonempty stdout line is not JSON"
        ) from error
    if type(value) is not dict:
        raise ReleaseMatrixError(f"{task.id} JSON summary is not an object")
    if value.get("image_digest") != image_digest:
        raise ReleaseMatrixError(
            f"{task.id} did not bind the exact release image digest"
        )
    if task.id == "web_active_probe":
        race = value.get("race")
        oob = value.get("oob")
        if (
            value.get("protocol")
            != "ctfos.web.active_probe.docker_release.v1"
            or value.get("schema_version") != 1
            or value.get("external_network") is not False
            or value.get("automatic_submission_count") != 0
            or type(race) is not dict
            or type(oob) is not dict
            or race.get("mode") != "race"
            or oob.get("mode") != "oob"
            or race.get("replay_count") != 6
            or oob.get("replay_count") != 6
            or race.get("candidate_count") != 0
            or oob.get("candidate_count") != 0
            or race.get("submission_count") != 0
            or oob.get("submission_count") != 0
        ):
            raise ReleaseMatrixError(
                "web_active_probe did not meet its exact race/OOB oracle"
            )
    elif value.get("ok") is not True:
        raise ReleaseMatrixError(f"{task.id} did not report ok=true")
    return _sha256(_canonical_json(value))


def _write_capture(path: Path, capture: _BoundedCapture) -> None:
    path.write_bytes(capture.payload())
    path.chmod(0o600)


def _run_task(
    task: ReleaseTask,
    *,
    image_digest: str,
    artifact_root: Path,
    timeout_seconds: int,
) -> dict[str, object]:
    command = (
        sys.executable,
        str(REPOSITORY / task.script),
        "--image-digest",
        image_digest,
    )
    stdout_capture = _BoundedCapture()
    stderr_capture = _BoundedCapture()
    started = time.monotonic_ns()
    timed_out = False
    process = subprocess.Popen(
        command,
        cwd=REPOSITORY,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_child_environment(),
        start_new_session=True,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    readers = (
        threading.Thread(
            target=stdout_capture.consume,
            args=(process.stdout,),
            daemon=True,
            name=f"{task.id}-stdout",
        ),
        threading.Thread(
            target=stderr_capture.consume,
            args=(process.stderr,),
            daemon=True,
            name=f"{task.id}-stderr",
        ),
    )
    for reader in readers:
        reader.start()
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process_group(process)
    for reader in readers:
        reader.join(timeout=30)
    duration_ms = (time.monotonic_ns() - started) // 1_000_000
    if any(reader.is_alive() for reader in readers):
        raise ReleaseMatrixError(f"{task.id} output reader did not terminate")
    for capture in (stdout_capture, stderr_capture):
        if capture.error is not None:
            raise ReleaseMatrixError(
                f"{task.id} output capture failed"
            ) from capture.error

    stdout_name = f"{task.id}.stdout.log"
    stderr_name = f"{task.id}.stderr.log"
    _write_capture(artifact_root / stdout_name, stdout_capture)
    _write_capture(artifact_root / stderr_name, stderr_capture)
    status = "passed"
    failure_reason: str | None = None
    summary_sha256: str | None = None
    if timed_out:
        status = "failed"
        failure_reason = "timeout"
    elif process.returncode != 0:
        status = "failed"
        failure_reason = f"exit_{process.returncode}"
    else:
        try:
            summary_sha256 = _validate_child_summary(
                task,
                stdout_capture,
                image_digest,
            )
        except ReleaseMatrixError as error:
            status = "failed"
            failure_reason = str(error)
    return {
        "categories": list(task.categories),
        "command": list(command),
        "duration_ms": duration_ms,
        "exit_code": process.returncode,
        "failure_reason": failure_reason,
        "id": task.id,
        "network_contract": task.network_contract,
        "status": status,
        "stderr": stderr_capture.metadata(stderr_name),
        "stdout": stdout_capture.metadata(stdout_name),
        "summary_sha256": summary_sha256,
        "timed_out": timed_out,
    }


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the closed, developer-only exact-Docker release matrix for "
            "Pwn, Web, Rev, Crypto, Forensic, and Misc."
        )
    )
    parser.add_argument(
        "--image-digest",
        required=True,
        help="exact local sha256:<64 lowercase hex> Docker image ID",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=DEFAULT_JOBS,
        choices=range(1, MAX_JOBS + 1),
        metavar=f"1..{MAX_JOBS}",
        help="bounded local gate parallelism (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=(
            f"per-gate timeout in {MIN_TIMEOUT_SECONDS}.."
            f"{MAX_TIMEOUT_SECONDS} seconds"
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help=(
            "new artifact directory; default creates one below "
            ".ctfos/release-matrix/"
        ),
    )
    arguments = parser.parse_args(argv)
    if not (
        MIN_TIMEOUT_SECONDS
        <= arguments.timeout_seconds
        <= MAX_TIMEOUT_SECONDS
    ):
        parser.error(
            f"--timeout-seconds must be in {MIN_TIMEOUT_SECONDS}.."
            f"{MAX_TIMEOUT_SECONDS}"
        )
    return arguments


def _new_artifact_root(requested: Path | None) -> Path:
    if requested is None:
        parent = REPOSITORY / ".ctfos" / "release-matrix"
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        return Path(
            tempfile.mkdtemp(
                prefix="run-",
                dir=parent,
            )
        ).resolve()
    path = requested.expanduser().resolve()
    if path.exists():
        raise ReleaseMatrixError(
            "--output-dir must name a new path; existing artifacts are not "
            "overwritten"
        )
    path.mkdir(parents=True, mode=0o700)
    return path


def run_matrix(arguments: argparse.Namespace) -> tuple[Path, dict[str, object]]:
    source_before = _source_snapshot()
    image_before = _inspect_image(arguments.image_digest)
    artifact_root = _new_artifact_root(arguments.output_dir)
    results_by_id: dict[str, dict[str, object]] = {}
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=arguments.jobs,
        thread_name_prefix="ctfos-release-matrix",
    ) as executor:
        futures = {
            executor.submit(
                _run_task,
                task,
                image_digest=arguments.image_digest,
                artifact_root=artifact_root,
                timeout_seconds=arguments.timeout_seconds,
            ): task
            for task in RELEASE_TASKS
        }
        for future in concurrent.futures.as_completed(futures):
            task = futures[future]
            try:
                results_by_id[task.id] = future.result()
            except BaseException as error:
                results_by_id[task.id] = {
                    "categories": list(task.categories),
                    "command": [
                        sys.executable,
                        str(REPOSITORY / task.script),
                        "--image-digest",
                        arguments.image_digest,
                    ],
                    "duration_ms": 0,
                    "exit_code": None,
                    "failure_reason": (
                        f"runner_error:{type(error).__name__}:{error}"
                    )[:1_024],
                    "id": task.id,
                    "network_contract": task.network_contract,
                    "status": "failed",
                    "stderr": None,
                    "stdout": None,
                    "summary_sha256": None,
                    "timed_out": False,
                }
    stability_error: str | None = None
    try:
        source_after = _source_snapshot()
        image_after = _inspect_image(arguments.image_digest)
        stable = (
            source_after == source_before
            and image_after == image_before
        )
        if not stable:
            stability_error = "source_or_image_changed"
    except ReleaseMatrixError as error:
        stable = False
        stability_error = str(error)[:1_024]
    ordered_results = [
        results_by_id[task.id]
        for task in RELEASE_TASKS
    ]
    covered = sorted(
        {
            category
            for result in ordered_results
            if result["status"] == "passed"
            for category in result["categories"]
        }
    )
    expected = ["crypto", "forensics", "misc", "pwn", "rev", "web"]
    ok = (
        stable
        and covered == expected
        and all(result["status"] == "passed" for result in ordered_results)
    )
    report = {
        "artifact_root": str(artifact_root),
        "categories_passed": covered,
        "command_contract_sha256": _sha256(
            _canonical_json(_command_contract())
        ),
        "image": image_before,
        "ok": ok,
        "policy": {
            "automatic_challenge_selection": False,
            "automatic_challenge_switch": False,
            "automatic_submission": False,
            "capture_limit_bytes_per_stream": CAPTURE_LIMIT_BYTES,
            "jobs": arguments.jobs,
            "model_requests": False,
            "remote_ctf_requests": False,
            "source_and_image_stable": stable,
            "stability_error": stability_error,
            "timeout_seconds_per_task": arguments.timeout_seconds,
        },
        "protocol": PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "source": source_before,
        "tasks": ordered_results,
    }
    payload = _canonical_json(report)
    if len(payload) > REPORT_LIMIT_BYTES:
        raise ReleaseMatrixError("release matrix report exceeded its bound")
    report_path = artifact_root / "report.json"
    report_path.write_bytes(payload)
    report_path.chmod(0o600)
    return report_path, report


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parse_args(argv)
    try:
        report_path, report = run_matrix(arguments)
    except ReleaseMatrixError as error:
        print(f"release matrix refused: {error}", file=sys.stderr)
        return 2
    envelope = {
        "ok": report["ok"],
        "report": str(report_path),
        "report_sha256": _sha256(report_path.read_bytes()),
    }
    print(_canonical_json(envelope).decode("ascii"), end="")
    return 0 if report["ok"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
