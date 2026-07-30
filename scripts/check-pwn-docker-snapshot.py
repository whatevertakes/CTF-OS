#!/usr/bin/env python3
"""Run the bounded Pwn runtime snapshot in real clean containers."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

from ctf_os.capabilities import inspect_pinned_capabilities
from ctf_os.contracts.pwn_runtime_snapshot_v1 import (
    PwnRuntimeSnapshotV1Result,
    PwnRuntimeSnapshotV1Status,
    parse_pwn_runtime_snapshot_v1_result,
)
from ctf_os.director.resources import ResourceVector
from ctf_os.images import validate_image_digest
from ctf_os.sandbox import (
    ChallengeScope,
    CommandSpec,
    DockerLimits,
    DockerSandboxBackend,
    NetworkPolicy,
    ProofInput,
)


REPOSITORY = Path(__file__).resolve().parent.parent
FIXTURE_SOURCE = (
    REPOSITORY
    / "ctf-os-image"
    / "tests"
    / "fixtures"
    / "pwn-runtime-snapshot.c"
)
PRODUCER = "/opt/ctf-templates/pwn/runtime_snapshot.py"
PAYLOAD_DESTINATION = "pwn-runtime-snapshot-v1/input.bin"
PAYLOAD_ARGUMENT = f"/work/{PAYLOAD_DESTINATION}"
EXPECTED_SIGNAL_NUMBER = 11
CAPTURE_PAYLOAD = b"S"
SOURCE_MANIFEST_SHA256 = hashlib.sha256(
    b"ctfos-pwn-docker-snapshot-release-smoke-v1"
).hexdigest()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compile the tracked Pwn snapshot fixture and execute three "
            "captures plus fail-closed probes through Docker clean proof."
        )
    )
    parser.add_argument(
        "--image-digest",
        required=True,
        help="exact local sha256:<64 lowercase hex> Docker image ID",
    )
    return parser.parse_args()


def _compile_fixture(destination: Path) -> None:
    compiler = shutil.which("cc")
    if compiler is None:
        raise RuntimeError("a host C compiler named cc is required")
    completed = subprocess.run(
        (
            compiler,
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(FIXTURE_SOURCE),
            "-o",
            str(destination),
        ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        detail = completed.stderr[:4096].decode(
            "utf-8",
            errors="replace",
        )
        raise RuntimeError(
            f"could not compile Pwn snapshot fixture: {detail}"
        )
    destination.chmod(0o500)


def _canonical_sha256(value: object) -> str:
    payload = (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _binding(
    *,
    label: str,
    image_digest: str,
    source_sha256: str,
    source_size_bytes: int,
    payload: bytes,
) -> dict[str, object]:
    payload_sha256 = hashlib.sha256(payload).hexdigest()
    common = {
        "expected_signal_number": EXPECTED_SIGNAL_NUMBER,
        "label": label,
        "payload_sha256": payload_sha256,
        "payload_size_bytes": len(payload),
        "source_manifest_sha256": SOURCE_MANIFEST_SHA256,
        "source_sha256": source_sha256,
        "source_size_bytes": source_size_bytes,
    }
    parent_crash_recipe_sha256 = _canonical_sha256(
        {
            **common,
            "kind": "release-smoke-parent-crash-recipe-v1",
        }
    )
    parent_crash_evaluation_sha256 = _canonical_sha256(
        {
            **common,
            "kind": "release-smoke-parent-crash-evaluation-v1",
            "parent_crash_recipe_sha256": (
                parent_crash_recipe_sha256
            ),
        }
    )
    snapshot_recipe_sha256 = _canonical_sha256(
        {
            **common,
            "image_digest": image_digest,
            "kind": "release-smoke-runtime-snapshot-recipe-v1",
            "parent_crash_evaluation_sha256": (
                parent_crash_evaluation_sha256
            ),
            "parent_crash_recipe_sha256": (
                parent_crash_recipe_sha256
            ),
            "producer": PRODUCER,
        }
    )
    return {
        "expected_signal_number": EXPECTED_SIGNAL_NUMBER,
        "parent_crash_evaluation_sha256": (
            parent_crash_evaluation_sha256
        ),
        "parent_crash_recipe_sha256": parent_crash_recipe_sha256,
        "payload_sha256": payload_sha256,
        "payload_size_bytes": len(payload),
        "snapshot_recipe_sha256": snapshot_recipe_sha256,
        "source_manifest_sha256": SOURCE_MANIFEST_SHA256,
        "source_sha256": source_sha256,
        "source_size_bytes": source_size_bytes,
    }


def _argv(binding: dict[str, object]) -> tuple[str, ...]:
    return (
        "/usr/bin/python3",
        PRODUCER,
        "--binary",
        "/challenge/challenge.bin",
        "--payload",
        PAYLOAD_ARGUMENT,
        "--source-manifest-sha256",
        str(binding["source_manifest_sha256"]),
        "--source-sha256",
        str(binding["source_sha256"]),
        "--source-size-bytes",
        str(binding["source_size_bytes"]),
        "--payload-sha256",
        str(binding["payload_sha256"]),
        "--payload-size-bytes",
        str(binding["payload_size_bytes"]),
        "--parent-crash-recipe-sha256",
        str(binding["parent_crash_recipe_sha256"]),
        "--parent-crash-evaluation-sha256",
        str(binding["parent_crash_evaluation_sha256"]),
        "--expected-signal-number",
        str(binding["expected_signal_number"]),
        "--snapshot-recipe-sha256",
        str(binding["snapshot_recipe_sha256"]),
    )


def _read_durable_stream(work: Path, locator: str) -> bytes:
    prefix = "/work/"
    if not locator.startswith(prefix):
        raise AssertionError(f"unexpected proof stream locator: {locator}")
    path = work / locator.removeprefix(prefix)
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode):
        raise AssertionError(f"proof stream is not regular: {locator}")
    return path.read_bytes()


def _require_complete_transport(
    result: object,
    *,
    stdout: bytes,
    stderr: bytes,
    label: str,
) -> None:
    if (
        getattr(result, "status", None) != "completed"
        or getattr(result, "exit_code", None) != 0
        or getattr(result, "timed_out", None)
        or getattr(result, "stdout_bytes", None) != len(stdout)
        or getattr(result, "stderr_bytes", None) != len(stderr)
        or getattr(result, "stdout_stored_bytes", None) != len(stdout)
        or getattr(result, "stderr_stored_bytes", None) != len(stderr)
        or getattr(result, "stdout_capture_complete", None) is not True
        or getattr(result, "stderr_capture_complete", None) is not True
        or getattr(result, "stdout_truncation_known", None) is not True
        or getattr(result, "stderr_truncation_known", None) is not True
        or getattr(result, "stdout_truncated", None) is not False
        or getattr(result, "stderr_truncated", None) is not False
        or getattr(result, "stdout_error", None) is not None
        or getattr(result, "stderr_error", None) is not None
        or getattr(result, "orchestration_error", None) is not None
        or getattr(result, "stream_capture_error", None) is not None
    ):
        raise AssertionError(
            f"Pwn snapshot run {label} has incomplete transport"
        )


def _parse_result(
    payload: bytes,
    binding: dict[str, object],
) -> PwnRuntimeSnapshotV1Result:
    return parse_pwn_runtime_snapshot_v1_result(
        payload,
        expected_source_manifest_sha256=str(
            binding["source_manifest_sha256"]
        ),
        expected_source_sha256=str(binding["source_sha256"]),
        expected_source_size_bytes=int(binding["source_size_bytes"]),
        expected_payload_sha256=str(binding["payload_sha256"]),
        expected_payload_size_bytes=int(binding["payload_size_bytes"]),
        expected_parent_crash_recipe_sha256=str(
            binding["parent_crash_recipe_sha256"]
        ),
        expected_parent_crash_evaluation_sha256=str(
            binding["parent_crash_evaluation_sha256"]
        ),
        expected_signal_number=int(
            binding["expected_signal_number"]
        ),
        expected_snapshot_recipe_sha256=str(
            binding["snapshot_recipe_sha256"]
        ),
    )


def _mapping_ranges(
    maps_payload: bytes,
) -> tuple[list[tuple[int, int, bytes]], list[tuple[int, int]]]:
    mappings: list[tuple[int, int, bytes]] = []
    stacks: list[tuple[int, int]] = []
    for line in maps_payload.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 2:
            raise AssertionError("proc maps line is structurally invalid")
        start_raw, separator, end_raw = fields[0].partition(b"-")
        if separator != b"-":
            raise AssertionError("proc maps range is structurally invalid")
        try:
            start = int(start_raw, 16)
            end = int(end_raw, 16)
        except ValueError as error:
            raise AssertionError("proc maps range is not hexadecimal") from error
        if start >= end:
            raise AssertionError("proc maps range is empty")
        permissions = fields[1]
        mappings.append((start, end, permissions))
        if b"[stack]" in line:
            stacks.append((start, end))
    if not mappings or not stacks:
        raise AssertionError("proc maps omitted mappings or root stack")
    return mappings, stacks


def _verify_capture(
    stdout: bytes,
    parsed: PwnRuntimeSnapshotV1Result,
) -> dict[str, object]:
    if (
        parsed.status is not PwnRuntimeSnapshotV1Status.CAPTURED
        or parsed.registers is None
        or parsed.maps is None
    ):
        raise AssertionError("runtime snapshot was not captured")
    document = json.loads(stdout)
    snapshot = document["snapshot"]
    maps_record = snapshot["maps"]
    maps_payload = parsed.maps.data
    if (
        not maps_payload.endswith(b"\n")
        or maps_record["size_bytes"] != len(maps_payload)
        or maps_record["line_count"] != maps_payload.count(b"\n")
        or maps_record["sha256"]
        != hashlib.sha256(maps_payload).hexdigest()
    ):
        raise AssertionError("runtime maps metadata is inconsistent")
    registers = dict(parsed.registers.values)
    rip = int(registers["rip"], 16)
    rsp = int(registers["rsp"], 16)
    mappings, stacks = _mapping_ranges(maps_payload)
    rip_covered = any(
        start <= rip < end and b"x" in permissions
        for start, end, permissions in mappings
    )
    rsp_covered = any(start <= rsp < end for start, end in stacks)
    if not rip_covered or not rsp_covered:
        raise AssertionError("RIP or RSP is not covered by proc maps")
    return {
        "maps_lines": maps_record["line_count"],
        "maps_sha256": maps_record["sha256"],
        "maps_size_bytes": maps_record["size_bytes"],
        "rip_mapped_executable": rip_covered,
        "rsp_mapped_stack": rsp_covered,
    }


def main() -> int:
    arguments = _parse_args()
    image_digest = validate_image_digest(arguments.image_digest)
    capability = inspect_pinned_capabilities(image_digest)
    if capability.get("ok") is not True:
        raise AssertionError(
            "pinned image failed managed capability readiness: "
            + json.dumps(capability, sort_keys=True)
        )

    with tempfile.TemporaryDirectory(
        prefix="ctfos-pwn-docker-snapshot-"
    ) as temporary:
        root = Path(temporary)
        challenge = root / "challenge"
        work = root / "work"
        inputs = work / "inputs"
        challenge.mkdir(mode=0o700)
        inputs.mkdir(parents=True, mode=0o700)
        target = challenge / "challenge.bin"
        _compile_fixture(target)
        source = target.read_bytes()
        source_sha256 = hashlib.sha256(source).hexdigest()

        scope = ChallengeScope.create(
            contest_id="release-smoke",
            category="pwn",
            challenge_id="runtime-snapshot-v1",
            challenge_dir=challenge,
            work_dir=work,
        )
        backend = DockerSandboxBackend(
            scope,
            image="ctf-os:core",
            image_digest=image_digest,
            network_policy=NetworkPolicy.deny_all(),
            limits=DockerLimits(
                cpus=1,
                memory_mib=512,
                pids=128,
                ptrace=True,
                read_only_root=True,
                run_as_host_user=True,
                work_tree_max_bytes=64 * 1024 * 1024,
            ),
        )

        durable_directories: set[str] = set()
        captures: list[dict[str, object]] = []
        for ordinal in range(1, 4):
            label = f"capture-{ordinal}"
            binding = _binding(
                label="capture",
                image_digest=image_digest,
                source_sha256=source_sha256,
                source_size_bytes=len(source),
                payload=CAPTURE_PAYLOAD,
            )
            source_locator = f"inputs/{label}.bin"
            input_path = work / source_locator
            input_path.write_bytes(CAPTURE_PAYLOAD)
            input_path.chmod(0o400)
            result = backend.run_clean_proof(
                CommandSpec.create(
                    _argv(binding),
                    timeout_seconds=15,
                    summary_bytes=4096,
                    resource_request=ResourceVector(
                        cpu=1,
                        memory_mib=512,
                    ),
                ),
                proof_inputs=(
                    ProofInput(
                        source_locator=source_locator,
                        destination_locator=PAYLOAD_DESTINATION,
                        sha256=str(binding["payload_sha256"]),
                        size_bytes=len(CAPTURE_PAYLOAD),
                    ),
                ),
            )
            stdout = _read_durable_stream(work, result.stdout_path)
            stderr = _read_durable_stream(work, result.stderr_path)
            _require_complete_transport(
                result,
                stdout=stdout,
                stderr=stderr,
                label=label,
            )
            parsed = _parse_result(stdout, binding)
            capture = _verify_capture(stdout, parsed)
            capture.update(
                {
                    "ordinal": ordinal,
                    "run_id": result.run_id,
                    "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                    "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                }
            )
            captures.append(capture)
            durable_directories.add(
                str(Path(result.stdout_path).parent)
            )

        probes: list[dict[str, object]] = []
        probe_expectations = (
            (
                "descendant",
                b"D",
                "additional_tracee_snapshot_unsupported",
            ),
            (
                "shared-mm",
                b"V",
                "additional_tracee_snapshot_unsupported",
            ),
            (
                "reexec",
                b"X",
                "target_reexec_unsupported",
            ),
        )
        for label, payload, expected_reason in probe_expectations:
            binding = _binding(
                label=label,
                image_digest=image_digest,
                source_sha256=source_sha256,
                source_size_bytes=len(source),
                payload=payload,
            )
            source_locator = f"inputs/probe-{label}.bin"
            input_path = work / source_locator
            input_path.write_bytes(payload)
            input_path.chmod(0o400)
            result = backend.run_clean_proof(
                CommandSpec.create(
                    _argv(binding),
                    timeout_seconds=15,
                    summary_bytes=4096,
                    resource_request=ResourceVector(
                        cpu=1,
                        memory_mib=512,
                    ),
                ),
                proof_inputs=(
                    ProofInput(
                        source_locator=source_locator,
                        destination_locator=PAYLOAD_DESTINATION,
                        sha256=str(binding["payload_sha256"]),
                        size_bytes=len(payload),
                    ),
                ),
            )
            stdout = _read_durable_stream(work, result.stdout_path)
            stderr = _read_durable_stream(work, result.stderr_path)
            _require_complete_transport(
                result,
                stdout=stdout,
                stderr=stderr,
                label=label,
            )
            parsed = _parse_result(stdout, binding)
            if (
                parsed.status is not PwnRuntimeSnapshotV1Status.ERROR
                or parsed.reason_code != expected_reason
                or parsed.registers is not None
                or parsed.maps is not None
            ):
                raise AssertionError(
                    f"Pwn snapshot probe {label} did not fail closed"
                )
            probes.append(
                {
                    "label": label,
                    "reason_code": parsed.reason_code,
                    "run_id": result.run_id,
                    "status": parsed.status.value,
                    "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                    "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                }
            )
            durable_directories.add(
                str(Path(result.stdout_path).parent)
            )

        if len(durable_directories) != 6:
            raise AssertionError(
                "Pwn snapshot runs reused a durable directory"
            )
        live_root = root / ".proof-live"
        if live_root.exists() and any(live_root.iterdir()):
            raise AssertionError(
                "clean proof left a live workspace behind"
            )
        print(
            json.dumps(
                {
                    "captures": captures,
                    "clean_workspaces": len(durable_directories),
                    "image_digest": image_digest,
                    "network": "none",
                    "ok": True,
                    "probes": probes,
                    "protocol": "pwn_local_stdin_runtime_snapshot_v1",
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
