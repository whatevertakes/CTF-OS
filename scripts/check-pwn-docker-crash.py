#!/usr/bin/env python3
"""Run the Pwn crash plan and safety probes in real clean containers."""

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
from ctf_os.contracts.pwn_crash_v1 import (
    PwnCrashV1Verdict,
    evaluate_pwn_crash_v1,
    parse_pwn_crash_v1_observation,
)
from ctf_os.director.resources import ResourceVector
from ctf_os.engine.pwn_crash import (
    PWN_CRASH_INPUT_DESTINATION_LOCATOR,
    PWN_CRASH_PRODUCER_FILE_SHA256,
    PwnCrashRecipe,
)
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
    / "pwn-crash-oracle.c"
)
PAYLOAD = b"X"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compile the tracked Pwn fixture and execute the deterministic "
            "three-positive/three-control crash plan through Docker clean "
            "proof."
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
            "-pthread",
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
        raise RuntimeError(f"could not compile Pwn fixture: {detail}")
    destination.chmod(0o500)


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
    ordinal: int,
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
            f"Pwn attempt {ordinal} has incomplete transport"
        )


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
        prefix="ctfos-pwn-docker-crash-"
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
        payload_sha256 = hashlib.sha256(PAYLOAD).hexdigest()
        manifest_sha256 = hashlib.sha256(
            b"ctfos-pwn-docker-crash-release-smoke-v1"
        ).hexdigest()

        recipe = PwnCrashRecipe(
            configuration_epoch=1,
            experiment_id="E-release-pwn-crash",
            hypothesis_id="H-release-pwn-crash",
            primary_elf_locator="challenge.bin",
            source_manifest_sha256=manifest_sha256,
            source_sha256=source_sha256,
            source_size_bytes=len(source),
            payload_artifact_id="A-release-pwn-crash-input",
            payload_source_run_id="MR-release-pwn-crash-builder",
            payload_artifact_locator="artifacts/release/input.bin",
            payload_sha256=payload_sha256,
            payload_size_bytes=len(PAYLOAD),
            image_reference=image_digest,
            image_digest=image_digest,
            producer_file_sha256=PWN_CRASH_PRODUCER_FILE_SHA256,
        )
        positive_source = inputs / "positive.bin"
        control_source = inputs / "control.bin"
        positive_source.write_bytes(PAYLOAD)
        control_source.write_bytes(b"")
        positive_source.chmod(0o400)
        control_source.chmod(0o400)

        scope = ChallengeScope.create(
            contest_id="release-smoke",
            category="pwn",
            challenge_id="crash-oracle-v1",
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

        stdout_documents: list[bytes] = []
        attempts: list[dict[str, object]] = []
        durable_directories: set[str] = set()
        for ordinal in range(1, 7):
            binding = recipe.attempt_input_binding(ordinal)
            positive = binding["phase"] == "positive"
            source_locator = (
                "inputs/positive.bin"
                if positive
                else "inputs/control.bin"
            )
            expected_sha256 = (
                payload_sha256 if positive else EMPTY_SHA256
            )
            expected_size = len(PAYLOAD) if positive else 0
            result = backend.run_clean_proof(
                CommandSpec.create(
                    recipe.argv_for_attempt(ordinal),
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
                        destination_locator=(
                            PWN_CRASH_INPUT_DESTINATION_LOCATOR
                        ),
                        sha256=expected_sha256,
                        size_bytes=expected_size,
                    ),
                ),
            )
            stdout = _read_durable_stream(work, result.stdout_path)
            stderr = _read_durable_stream(work, result.stderr_path)
            _require_complete_transport(
                result,
                stdout=stdout,
                stderr=stderr,
                ordinal=ordinal,
            )
            stdout_documents.append(stdout)
            durable_directories.add(str(Path(result.stdout_path).parent))
            attempts.append(
                {
                    "ordinal": ordinal,
                    "phase": binding["phase"],
                    "run_id": result.run_id,
                    "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                    "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                }
            )

        evaluation = evaluate_pwn_crash_v1(
            tuple(stdout_documents),
            poc_input=PAYLOAD,
            expected_source_manifest_sha256=manifest_sha256,
            expected_source_sha256=source_sha256,
            expected_source_size_bytes=len(source),
            expected_recipe_sha256=recipe.recipe_sha256,
        )
        if (
            evaluation.verdict is not PwnCrashV1Verdict.CONFIRMED
            or evaluation.reason_code
            != "reproducible_input_triggered_fault_signal"
            or evaluation.positive_signal_counts != ((11, 3),)
        ):
            raise AssertionError(
                "real Pwn crash gate did not confirm: "
                + json.dumps(evaluation.to_dict(), sort_keys=True)
            )

        safety_probes: list[dict[str, object]] = []
        probe_expectations = (
            (
                "clone-untraced",
                b"U",
                "ok",
                "observation_recorded",
                0,
            ),
            (
                "pthread-control",
                b"P",
                "ok",
                "observation_recorded",
                0,
            ),
            (
                "caught-core",
                b"C",
                "error",
                "caught_or_ignored_core_signal_unsupported",
                None,
            ),
            (
                "multithread-core",
                b"H",
                "error",
                "multithreaded_core_signal_unsupported",
                None,
            ),
            (
                "child-core",
                b"K",
                "error",
                "non_root_core_signal_unsupported",
                None,
            ),
        )
        for label, probe_payload, status, reason, exit_code in (
            probe_expectations
        ):
            probe_sha256 = hashlib.sha256(probe_payload).hexdigest()
            probe_source = inputs / f"probe-{label}.bin"
            probe_source.write_bytes(probe_payload)
            probe_source.chmod(0o400)
            probe_recipe = PwnCrashRecipe(
                configuration_epoch=1,
                experiment_id=f"E-release-{label}",
                hypothesis_id=f"H-release-{label}",
                primary_elf_locator="challenge.bin",
                source_manifest_sha256=manifest_sha256,
                source_sha256=source_sha256,
                source_size_bytes=len(source),
                payload_artifact_id=f"A-release-{label}",
                payload_source_run_id=f"MR-release-{label}",
                payload_artifact_locator=(
                    f"artifacts/release/{label}.bin"
                ),
                payload_sha256=probe_sha256,
                payload_size_bytes=len(probe_payload),
                image_reference=image_digest,
                image_digest=image_digest,
                producer_file_sha256=PWN_CRASH_PRODUCER_FILE_SHA256,
            )
            probe_result = backend.run_clean_proof(
                CommandSpec.create(
                    probe_recipe.argv_for_attempt(1),
                    timeout_seconds=15,
                    summary_bytes=4096,
                    resource_request=ResourceVector(
                        cpu=1,
                        memory_mib=512,
                    ),
                ),
                proof_inputs=(
                    ProofInput(
                        source_locator=f"inputs/probe-{label}.bin",
                        destination_locator=(
                            PWN_CRASH_INPUT_DESTINATION_LOCATOR
                        ),
                        sha256=probe_sha256,
                        size_bytes=len(probe_payload),
                    ),
                ),
            )
            probe_stdout = _read_durable_stream(
                work,
                probe_result.stdout_path,
            )
            probe_stderr = _read_durable_stream(
                work,
                probe_result.stderr_path,
            )
            _require_complete_transport(
                probe_result,
                stdout=probe_stdout,
                stderr=probe_stderr,
                ordinal=1,
            )
            observation = parse_pwn_crash_v1_observation(
                probe_stdout
            )
            if (
                observation.ordinal != 1
                or observation.phase != "positive"
                or observation.recipe_sha256
                != probe_recipe.recipe_sha256
                or observation.source_manifest_sha256
                != manifest_sha256
                or observation.source_sha256 != source_sha256
                or observation.source_size_bytes != len(source)
                or observation.input_sha256 != probe_sha256
                or observation.input_size_bytes != len(probe_payload)
                or observation.status != status
                or observation.reason_code != reason
                or (
                    exit_code is None
                    and observation.target is not None
                )
                or (
                    exit_code is not None
                    and (
                        observation.target is None
                        or observation.target.termination != "exited"
                        or observation.target.exit_code != exit_code
                        or observation.target.signal_number is not None
                    )
                )
            ):
                raise AssertionError(
                    f"Pwn safety probe {label} did not fail closed"
                )
            durable_directories.add(
                str(Path(probe_result.stdout_path).parent)
            )
            safety_probes.append(
                {
                    "label": label,
                    "reason_code": observation.reason_code,
                    "run_id": probe_result.run_id,
                    "status": observation.status,
                }
            )

        if len(durable_directories) != 11:
            raise AssertionError("Pwn crash attempts reused a durable directory")
        live_root = root / ".proof-live"
        if live_root.exists() and any(live_root.iterdir()):
            raise AssertionError("clean proof left a live workspace behind")

        print(
            json.dumps(
                {
                    "attempts": attempts,
                    "clean_workspaces": len(durable_directories),
                    "image_digest": image_digest,
                    "network": "none",
                    "ok": True,
                    "protocol": "pwn_local_stdin_crash_v1",
                    "safety_probes": safety_probes,
                    "verdict": evaluation.verdict.value,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
