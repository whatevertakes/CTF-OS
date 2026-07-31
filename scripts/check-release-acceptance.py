#!/usr/bin/env python3
"""Issue one fail-closed local CTF-OS release-acceptance receipt.

This developer-only command binds the network-free source suite, read-only
``doctor`` diagnostics, and the closed all-category Docker matrix to one clean
Git commit and one configured exact local image ID.  It is not a challenge
solver, benchmark runner, model caller, remote CTF client, or submission path.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, Sequence

from ctf_os.config import ConfigError, load_config
from ctf_os.terminal import terminal_safe


REPOSITORY = Path(__file__).resolve().parent.parent
ARTIFACT_PARENT = REPOSITORY / ".ctfos" / "release-acceptance"
MATRIX_ARTIFACT_PARENT = REPOSITORY / ".ctfos" / "release-matrix"
PROTOCOL = "ctfos.release_acceptance.v1"
SCHEMA_VERSION = 1
IMAGE_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
CAPTURE_LIMIT_BYTES = 1_048_576
RECEIPT_LIMIT_BYTES = 131_072
MATRIX_REPORT_LIMIT_BYTES = 131_072
DEFAULT_TIMEOUT_SECONDS = 1_800
MIN_TIMEOUT_SECONDS = 60
MAX_TIMEOUT_SECONDS = 3_600
TRUNCATION_MARKER = (
    b"\n... [ctfos release acceptance omitted bounded middle bytes] ...\n"
)
SAFE_CHILD_ENVIRONMENT_KEYS = frozenset(
    {
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "NO_COLOR",
        "PATH",
        "TZ",
    }
)
EXPECTED_CATEGORIES = ["crypto", "forensics", "misc", "pwn", "rev", "web"]
EXPECTED_TASKS = {
    "pwn_dependency_effect": (
        ("pwn",),
        "none",
        "scripts/check-pwn-dependency-hotpath-docker.py",
    ),
    "pwn_interaction_effect": (
        ("pwn",),
        "none",
        "scripts/check-pwn-interaction-hotpath-docker.py",
    ),
    "web_state_impact": (
        ("web",),
        "docker_internal_local_targets",
        "scripts/check-web-impact-docker-hotpath.py",
    ),
    "web_active_probe": (
        ("web",),
        "docker_internal_local_targets",
        "scripts/check-web-active-probe-docker-hotpath.py",
    ),
    "rev_original_binary_acceptance": (
        ("rev",),
        "none",
        "scripts/check-managed-rev-accepted-input-hotpath-docker.py",
    ),
    "crypto_metamorphic_and_misc_transform": (
        ("crypto", "misc"),
        "none",
        "scripts/check-crypto-misc-docker-hotpaths.py",
    ),
    "forensic_assertion_graph": (
        ("forensics",),
        "none",
        "scripts/check-forensic-assertion-hotpath-docker.py",
    ),
}
MATRIX_POLICY_FALSE_KEYS = (
    "automatic_challenge_selection",
    "automatic_challenge_switch",
    "automatic_submission",
    "model_requests",
    "remote_ctf_requests",
)


class ReleaseAcceptanceError(RuntimeError):
    """Raised for a fail-closed release-acceptance condition."""


@dataclasses.dataclass(slots=True)
class CommandOutcome:
    """Bounded retained command record plus in-memory stdout for validation."""

    record: dict[str, object]
    stdout: bytes


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


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _bounded_error(value: object) -> str:
    return terminal_safe(value)[:1_024]


def _strict_json(payload: bytes, *, label: str) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate key: {key}")
            value[key] = item
        return value

    def reject_constant(value: str) -> object:
        raise ValueError(f"non-finite JSON constant: {value}")

    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ReleaseAcceptanceError(f"{label} is not strict JSON") from error


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
        raise ReleaseAcceptanceError(
            "git preflight failed: " + _bounded_error(completed.stderr)
        )
    return completed


def _source_snapshot() -> dict[str, object]:
    top = Path(
        _git("rev-parse", "--show-toplevel").stdout.strip()
    ).resolve()
    if top != REPOSITORY:
        raise ReleaseAcceptanceError(
            "release acceptance runner is not at its repository root"
        )
    commit = _git("rev-parse", "HEAD").stdout.strip()
    if COMMIT_PATTERN.fullmatch(commit) is None:
        raise ReleaseAcceptanceError("HEAD is not an exact Git commit")
    status = _git(
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    ).stdout
    if status:
        raise ReleaseAcceptanceError(
            "release acceptance requires a clean source tree; first entry: "
            + _bounded_error(status.splitlines()[0])
        )
    return {"clean": True, "commit": commit}


def _configured_image_binding(image_digest: str) -> dict[str, str]:
    try:
        runtime = load_config(REPOSITORY).runtime
    except ConfigError as error:
        raise ReleaseAcceptanceError(
            "could not load the configured release image pin"
        ) from error
    configured = runtime.image_digest
    if configured is None:
        raise ReleaseAcceptanceError(
            "release acceptance requires runtime.image_digest; run ctfos "
            "pin-image first"
        )
    if configured != image_digest:
        raise ReleaseAcceptanceError(
            "release acceptance image digest does not match the configured pin"
        )
    return {"image": runtime.image, "image_digest": configured}


def _inspect_local_image(reference: str) -> str:
    completed = subprocess.run(
        ("docker", "image", "inspect", "--format", "{{.Id}}", reference),
        cwd=REPOSITORY,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
        env=_child_environment(),
    )
    if completed.returncode != 0:
        raise ReleaseAcceptanceError(
            "exact local release image is unavailable: "
            + _bounded_error(completed.stderr or completed.stdout)
        )
    inspected = completed.stdout.strip()
    if IMAGE_DIGEST_PATTERN.fullmatch(inspected) is None:
        raise ReleaseAcceptanceError("docker returned an invalid local image ID")
    return inspected


def _inspect_image_binding(
    image_digest: str,
    binding: dict[str, str],
) -> dict[str, str]:
    inspected = _inspect_local_image(image_digest)
    tag_inspected = _inspect_local_image(binding["image"])
    if inspected != image_digest or tag_inspected != image_digest:
        raise ReleaseAcceptanceError(
            "configured release image pin does not match the exact local image"
        )
    return {
        "digest": image_digest,
        "inspected_id": inspected,
        "tag": binding["image"],
        "tag_inspected_id": tag_inspected,
    }


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
            raise ReleaseAcceptanceError("bounded stream capture exceeded its limit")
        return value

    def metadata(self, locator: str) -> dict[str, object]:
        payload = self.payload()
        return {
            "captured_bytes": len(payload),
            "captured_sha256": _sha256(payload),
            "locator": locator,
            "sha256": "sha256:" + self.digest.hexdigest(),
            "stream_bytes": self.total_bytes,
            "truncated": self.truncated,
        }


def _child_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in SAFE_CHILD_ENVIRONMENT_KEYS
    }
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        str(REPOSITORY)
        if not existing
        else str(REPOSITORY) + os.pathsep + existing
    )
    environment["CTFOS_RELEASE_ACCEPTANCE"] = "1"
    environment["CTFOS_PYTHON"] = sys.executable
    return environment


def _write_capture(path: Path, capture: _BoundedCapture) -> None:
    path.write_bytes(capture.payload())
    path.chmod(0o600)


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


def _run_command(
    identifier: str,
    command: Sequence[str],
    *,
    artifact_root: Path,
    timeout_seconds: int,
) -> CommandOutcome:
    """Run one fixed local command with bounded retained stream evidence."""

    stdout_capture = _BoundedCapture()
    stderr_capture = _BoundedCapture()
    started = time.monotonic_ns()
    timed_out = False
    process: subprocess.Popen[bytes] | None = None
    failure_reason: str | None = None
    try:
        process = subprocess.Popen(
            list(command),
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
                name=f"release-acceptance-{identifier}-stdout",
            ),
            threading.Thread(
                target=stderr_capture.consume,
                args=(process.stderr,),
                daemon=True,
                name=f"release-acceptance-{identifier}-stderr",
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
        if any(reader.is_alive() for reader in readers):
            failure_reason = "output_reader_did_not_terminate"
        elif stdout_capture.error is not None or stderr_capture.error is not None:
            failure_reason = "output_capture_failed"
    except (OSError, subprocess.SubprocessError) as error:
        failure_reason = f"spawn_error:{type(error).__name__}:{_bounded_error(error)}"

    duration_ms = (time.monotonic_ns() - started) // 1_000_000
    stdout_name = f"{identifier}.stdout.log"
    stderr_name = f"{identifier}.stderr.log"
    _write_capture(artifact_root / stdout_name, stdout_capture)
    _write_capture(artifact_root / stderr_name, stderr_capture)
    exit_code = process.returncode if process is not None else None
    if failure_reason is None and timed_out:
        failure_reason = "timeout"
    if failure_reason is None and exit_code != 0:
        failure_reason = f"exit_{exit_code}"
    return CommandOutcome(
        record={
            "command": list(command),
            "duration_ms": duration_ms,
            "exit_code": exit_code,
            "failure_reason": failure_reason,
            "id": identifier,
            "status": "passed" if failure_reason is None else "failed",
            "stderr": stderr_capture.metadata(stderr_name),
            "stdout": stdout_capture.metadata(stdout_name),
            "timed_out": timed_out,
        },
        stdout=stdout_capture.payload(),
    )


def _skipped_command(
    identifier: str,
    command: Sequence[str],
    *,
    artifact_root: Path,
    reason: str,
) -> CommandOutcome:
    stdout_capture = _BoundedCapture()
    stderr_capture = _BoundedCapture()
    stdout_name = f"{identifier}.stdout.log"
    stderr_name = f"{identifier}.stderr.log"
    _write_capture(artifact_root / stdout_name, stdout_capture)
    _write_capture(artifact_root / stderr_name, stderr_capture)
    return CommandOutcome(
        record={
            "command": list(command),
            "duration_ms": 0,
            "exit_code": None,
            "failure_reason": reason,
            "id": identifier,
            "status": "skipped",
            "stderr": stderr_capture.metadata(stderr_name),
            "stdout": stdout_capture.metadata(stdout_name),
            "timed_out": False,
        },
        stdout=b"",
    )


def _fail_outcome(outcome: CommandOutcome, reason: str) -> None:
    outcome.record["failure_reason"] = reason[:1_024]
    outcome.record["status"] = "failed"


def _outcome_passed(outcome: CommandOutcome) -> bool:
    return outcome.record.get("status") == "passed"


def _validate_doctor(outcome: CommandOutcome, image_digest: str) -> None:
    stdout = outcome.record.get("stdout")
    if not isinstance(stdout, dict) or stdout.get("truncated") is not False:
        raise ReleaseAcceptanceError("doctor stdout is truncated or malformed")
    report = _strict_json(outcome.stdout, label="doctor stdout")
    if type(report) is not dict:
        raise ReleaseAcceptanceError("doctor stdout is not an object")
    warnings = report.get("warnings")
    image = report.get("image")
    managed = report.get("managed_capabilities")
    if (
        report.get("ok") is not True
        or warnings != []
        or type(image) is not dict
        or image.get("configured_digest") != image_digest
        or image.get("id") != image_digest
        or image.get("pin_status") != "matched"
        or image.get("execution_available") is not True
        or type(managed) is not dict
        or managed.get("ok") is not True
        or managed.get("status") != "ready"
        or managed.get("image_digest") != image_digest
    ):
        raise ReleaseAcceptanceError(
            "doctor did not report ok=true, warnings=[], and the exact pinned image"
        )
    pinned = image.get("pinned_image")
    if type(pinned) is not dict or pinned.get("id") != image_digest:
        raise ReleaseAcceptanceError("doctor did not re-attest the exact pinned image")


def _read_bounded_regular(path: Path, *, maximum: int, label: str) -> bytes:
    try:
        before = path.stat(follow_symlinks=False)
    except OSError as error:
        raise ReleaseAcceptanceError(f"{label} is unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 0
        or before.st_size > maximum
    ):
        raise ReleaseAcceptanceError(f"{label} is not a bounded regular file")
    try:
        payload = path.read_bytes()
        after = path.stat(follow_symlinks=False)
    except OSError as error:
        raise ReleaseAcceptanceError(f"{label} could not be read") from error
    if (
        len(payload) != before.st_size
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        raise ReleaseAcceptanceError(f"{label} changed while reading")
    return payload


def _runtime_binding() -> dict[str, object]:
    """Attest the exact Python process and tracked dependency manifests."""

    try:
        interpreter = Path(sys.executable).resolve(strict=True)
    except OSError as error:
        raise ReleaseAcceptanceError(
            "release acceptance Python interpreter is unavailable"
        ) from error
    interpreter_payload = _read_bounded_regular(
        interpreter,
        maximum=64 * 1024 * 1024,
        label="release acceptance Python interpreter",
    )
    manifests: dict[str, str] = {}
    for relative in ("pyproject.toml", "uv.lock"):
        _git("ls-files", "--error-unmatch", "--", relative)
        payload = _read_bounded_regular(
            REPOSITORY / relative,
            maximum=4 * 1024 * 1024,
            label=relative,
        )
        manifests[relative] = _sha256(payload)
    return {
        "implementation": sys.implementation.name,
        "interpreter": str(interpreter),
        "interpreter_sha256": _sha256(interpreter_payload),
        "manifests": manifests,
        "version": list(sys.version_info[:5]),
    }


def _expected_matrix_contract_sha256() -> str:
    contract = {
        "protocol": "ctfos.all_category_release_matrix.v1",
        "schema_version": 1,
        "tasks": [
            {
                "categories": list(categories),
                "id": identifier,
                "network_contract": network_contract,
                "script": script,
            }
            for identifier, (categories, network_contract, script) in (
                EXPECTED_TASKS.items()
            )
        ],
    }
    return _sha256(_canonical_json(contract))


def _validate_matrix(
    outcome: CommandOutcome,
    *,
    image_digest: str,
    source: dict[str, object],
) -> dict[str, str]:
    stdout = outcome.record.get("stdout")
    if not isinstance(stdout, dict) or stdout.get("truncated") is not False:
        raise ReleaseAcceptanceError("matrix stdout is truncated or malformed")
    envelope = _strict_json(outcome.stdout, label="matrix stdout")
    if type(envelope) is not dict or set(envelope) != {
        "ok",
        "report",
        "report_sha256",
    }:
        raise ReleaseAcceptanceError("matrix stdout envelope is invalid")
    report_value = envelope.get("report")
    expected_hash = envelope.get("report_sha256")
    if (
        envelope.get("ok") is not True
        or not isinstance(report_value, str)
        or not isinstance(expected_hash, str)
        or SHA256_PATTERN.fullmatch(expected_hash) is None
    ):
        raise ReleaseAcceptanceError("matrix did not issue a positive exact report")
    report_path = Path(report_value)
    if not report_path.is_absolute():
        raise ReleaseAcceptanceError("matrix report pointer is not absolute")
    try:
        resolved = report_path.resolve(strict=True)
        resolved.relative_to(MATRIX_ARTIFACT_PARENT.resolve())
    except (OSError, ValueError) as error:
        raise ReleaseAcceptanceError(
            "matrix report pointer escapes the managed artifact directory"
        ) from error
    payload = _read_bounded_regular(
        resolved,
        maximum=MATRIX_REPORT_LIMIT_BYTES,
        label="matrix report",
    )
    actual_hash = _sha256(payload)
    if actual_hash != expected_hash:
        raise ReleaseAcceptanceError(
            "matrix report SHA-256 does not match its envelope"
        )
    report = _strict_json(payload, label="matrix report")
    if type(report) is not dict:
        raise ReleaseAcceptanceError("matrix report is not an object")
    matrix_source = report.get("source")
    matrix_image = report.get("image")
    policy = report.get("policy")
    tasks = report.get("tasks")
    task_contract_valid = False
    if isinstance(tasks, list) and len(tasks) == len(EXPECTED_TASKS):
        seen: set[str] = set()
        task_contract_valid = True
        for item in tasks:
            if type(item) is not dict:
                task_contract_valid = False
                break
            identifier = item.get("id")
            expected = EXPECTED_TASKS.get(identifier) if isinstance(identifier, str) else None
            if expected is None or identifier in seen:
                task_contract_valid = False
                break
            categories, network_contract, script = expected
            command = item.get("command")
            if (
                item.get("status") != "passed"
                or item.get("categories") != list(categories)
                or item.get("network_contract") != network_contract
                or not isinstance(command, list)
                or len(command) != 4
                or command[0] != sys.executable
                or command[1] != str(REPOSITORY / script)
                or command[2:] != ["--image-digest", image_digest]
                or SHA256_PATTERN.fullmatch(str(item.get("summary_sha256"))) is None
            ):
                task_contract_valid = False
                break
            seen.add(identifier)
        task_contract_valid = task_contract_valid and seen == set(EXPECTED_TASKS)
    if (
        report.get("ok") is not True
        or report.get("protocol") != "ctfos.all_category_release_matrix.v1"
        or report.get("schema_version") != 1
        or report.get("categories_passed") != EXPECTED_CATEGORIES
        or report.get("command_contract_sha256")
        != _expected_matrix_contract_sha256()
        or type(matrix_source) is not dict
        or matrix_source.get("clean") is not True
        or matrix_source.get("commit") != source.get("commit")
        or type(matrix_image) is not dict
        or matrix_image.get("digest") != image_digest
        or matrix_image.get("inspected_id") != image_digest
        or type(policy) is not dict
        or policy.get("source_and_image_stable") is not True
        or not task_contract_valid
        or any(policy.get(key) is not False for key in MATRIX_POLICY_FALSE_KEYS)
    ):
        raise ReleaseAcceptanceError(
            "matrix report is not a complete stable all-category acceptance"
        )
    return {"path": str(resolved), "sha256": actual_hash}


def _new_artifact_root(requested: Path | None) -> Path:
    ARTIFACT_PARENT.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent = ARTIFACT_PARENT.resolve()
    if requested is None:
        return Path(tempfile.mkdtemp(prefix="run-", dir=parent)).resolve()
    path = requested.expanduser().resolve()
    try:
        path.relative_to(parent)
    except ValueError as error:
        raise ReleaseAcceptanceError(
            "--output-dir must be a new path below .ctfos/release-acceptance"
        ) from error
    if path.exists():
        raise ReleaseAcceptanceError("--output-dir must name a new path")
    path.mkdir(parents=True, mode=0o700)
    return path


def _write_receipt(path: Path, report: dict[str, object]) -> None:
    payload = _canonical_json(report)
    if len(payload) > RECEIPT_LIMIT_BYTES:
        raise ReleaseAcceptanceError("release acceptance receipt exceeded its bound")
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    path.chmod(0o600)


def _initial_report(artifact_root: Path, image_digest: str) -> dict[str, object]:
    return {
        "artifact_root": str(artifact_root),
        "completed_at": None,
        "commands": {},
        "configured_pin": None,
        "image": None,
        "matrix_report": None,
        "ok": False,
        "policy": {
            "automatic_challenge_selection": False,
            "automatic_challenge_switch": False,
            "automatic_submission": False,
            "model_requests": False,
            "remote_ctf_requests": False,
            "source_image_pin_runtime_stable": False,
            "stability_error": None,
        },
        "preflight": {"failure_reason": None, "ok": False},
        "protocol": PROTOCOL,
        "requested_image_digest": image_digest,
        "runtime": None,
        "schema_version": SCHEMA_VERSION,
        "source": None,
        "started_at": _utc_now(),
    }


def run_acceptance(arguments: argparse.Namespace) -> tuple[Path, dict[str, object]]:
    image_digest = arguments.image_digest
    if IMAGE_DIGEST_PATTERN.fullmatch(image_digest) is None:
        raise ReleaseAcceptanceError(
            "image digest must be sha256 plus 64 lowercase hexadecimal digits"
        )
    artifact_root = _new_artifact_root(arguments.output_dir)
    report = _initial_report(artifact_root, image_digest)
    receipt_path = artifact_root / "receipt.json"
    fresh_command = (str(REPOSITORY / "scripts" / "check-fresh-clone.sh"),)
    doctor_command = (sys.executable, "-m", "ctf_os", "doctor")
    matrix_command = (
        sys.executable,
        str(REPOSITORY / "scripts" / "check-all-category-release-matrix.py"),
        "--image-digest",
        image_digest,
        "--timeout-seconds",
        str(arguments.timeout_seconds),
    )

    source_before: dict[str, object] | None = None
    image_before: dict[str, str] | None = None
    binding_before: dict[str, str] | None = None
    runtime_before: dict[str, object] | None = None
    try:
        binding_before = _configured_image_binding(image_digest)
        source_before = _source_snapshot()
        runtime_before = _runtime_binding()
        image_before = _inspect_image_binding(image_digest, binding_before)
    except ReleaseAcceptanceError as error:
        report["preflight"] = {"failure_reason": str(error), "ok": False}
        report["commands"] = {
            "fresh_clone": _skipped_command(
                "fresh-clone",
                fresh_command,
                artifact_root=artifact_root,
                reason="preflight_failed",
            ).record,
            "doctor": _skipped_command(
                "doctor",
                doctor_command,
                artifact_root=artifact_root,
                reason="preflight_failed",
            ).record,
            "matrix": _skipped_command(
                "matrix",
                matrix_command,
                artifact_root=artifact_root,
                reason="preflight_failed",
            ).record,
        }
        report["completed_at"] = _utc_now()
        _write_receipt(receipt_path, report)
        return receipt_path, report

    report["configured_pin"] = binding_before["image_digest"]
    report["image"] = image_before
    report["preflight"] = {"failure_reason": None, "ok": True}
    report["runtime"] = runtime_before
    report["source"] = source_before
    commands: dict[str, dict[str, object]] = {}
    report["commands"] = commands

    fresh = _run_command(
        "fresh-clone",
        fresh_command,
        artifact_root=artifact_root,
        timeout_seconds=arguments.timeout_seconds,
    )
    commands["fresh_clone"] = fresh.record
    previous_failure = not _outcome_passed(fresh)

    if previous_failure:
        doctor = _skipped_command(
            "doctor",
            doctor_command,
            artifact_root=artifact_root,
            reason="fresh_clone_failed",
        )
    else:
        doctor = _run_command(
            "doctor",
            doctor_command,
            artifact_root=artifact_root,
            timeout_seconds=arguments.timeout_seconds,
        )
        if _outcome_passed(doctor):
            try:
                _validate_doctor(doctor, image_digest)
                doctor.record["validation"] = {"ok": True, "reason": None}
            except ReleaseAcceptanceError as error:
                _fail_outcome(doctor, str(error))
                doctor.record["validation"] = {"ok": False, "reason": str(error)}
    commands["doctor"] = doctor.record
    previous_failure = previous_failure or not _outcome_passed(doctor)

    if previous_failure:
        matrix = _skipped_command(
            "matrix",
            matrix_command,
            artifact_root=artifact_root,
            reason="prior_gate_failed",
        )
    else:
        matrix = _run_command(
            "matrix",
            matrix_command,
            artifact_root=artifact_root,
            timeout_seconds=arguments.timeout_seconds,
        )
        if _outcome_passed(matrix):
            try:
                matrix_report = _validate_matrix(
                    matrix,
                    image_digest=image_digest,
                    source=source_before,
                )
                report["matrix_report"] = matrix_report
                matrix.record["validation"] = {"ok": True, "reason": None}
            except ReleaseAcceptanceError as error:
                _fail_outcome(matrix, str(error))
                matrix.record["validation"] = {"ok": False, "reason": str(error)}
    commands["matrix"] = matrix.record

    postflight_reason: str | None = None
    source_after: dict[str, object] | None = None
    image_after: dict[str, str] | None = None
    binding_after: dict[str, str] | None = None
    runtime_after: dict[str, object] | None = None
    try:
        binding_after = _configured_image_binding(image_digest)
        source_after = _source_snapshot()
        runtime_after = _runtime_binding()
        image_after = _inspect_image_binding(image_digest, binding_after)
        stable = (
            source_after == source_before
            and image_after == image_before
            and binding_after == binding_before
            and runtime_after == runtime_before
        )
        if not stable:
            postflight_reason = "source_or_image_or_pin_or_runtime_changed"
    except ReleaseAcceptanceError as error:
        stable = False
        postflight_reason = str(error)
    report["postflight"] = {
        "configured_pin": (
            binding_after["image_digest"] if binding_after is not None else None
        ),
        "failure_reason": postflight_reason,
        "image": image_after,
        "runtime": runtime_after,
        "source": source_after,
    }
    policy = report["policy"]
    assert isinstance(policy, dict)
    policy["source_image_pin_runtime_stable"] = stable
    policy["stability_error"] = postflight_reason
    report["ok"] = (
        _outcome_passed(fresh)
        and _outcome_passed(doctor)
        and _outcome_passed(matrix)
        and stable
        and report.get("matrix_report") is not None
    )
    report["completed_at"] = _utc_now()
    _write_receipt(receipt_path, report)
    return receipt_path, report


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the complete local, exact-image CTF-OS release acceptance "
            "sequence without model or remote CTF requests."
        )
    )
    parser.add_argument(
        "--image-digest",
        required=True,
        help="exact local sha256:<64 lowercase hex> Docker image ID",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help=(
            "new artifact directory below .ctfos/release-acceptance/; "
            "default creates run-* there"
        ),
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=(
            "per-command timeout and per-matrix-child timeout in "
            f"{MIN_TIMEOUT_SECONDS}..{MAX_TIMEOUT_SECONDS} seconds "
            "(default: %(default)s)"
        ),
    )
    arguments = parser.parse_args(argv)
    if not MIN_TIMEOUT_SECONDS <= arguments.timeout_seconds <= MAX_TIMEOUT_SECONDS:
        parser.error(
            f"--timeout-seconds must be in {MIN_TIMEOUT_SECONDS}..{MAX_TIMEOUT_SECONDS}"
        )
    return arguments


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _parse_args(argv)
        receipt_path, report = run_acceptance(arguments)
    except ReleaseAcceptanceError as error:
        print(f"release acceptance refused: {error}", file=sys.stderr)
        return 2
    envelope = {
        "ok": report["ok"],
        "receipt": str(receipt_path),
        "receipt_sha256": _sha256(receipt_path.read_bytes()),
    }
    print(_canonical_json(envelope).decode("ascii"), end="")
    return 0 if report["ok"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
