#!/usr/bin/env python3
"""Run the exact six-attempt Rev stdin plan through real clean containers."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

from ctf_os.director.resources import ResourceVector
from ctf_os.engine.rev_proof import build_rev_stdin_proof_plan
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
    / "rev-stdin-oracle.c"
)
CANDIDATE = "KCTF{docker_rev_proof}"
ACCEPTED_INPUT = b"OPEN-SESAME\n"
RUNNER_ARGV = (
    "/usr/bin/python3",
    "/opt/ctf-templates/rev/stdin_exec.py",
    "--binary",
    "/challenge/challenge.bin",
    "--input",
    "/work/oracle/accepted-input.bin",
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compile the tracked Rev fixture and execute the deterministic "
            "three-positive/three-negative plan through Docker clean proof."
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
        raise RuntimeError(f"could not compile Rev fixture: {detail}")
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


def main() -> int:
    arguments = _parse_args()
    image_digest = validate_image_digest(arguments.image_digest)
    plan = build_rev_stdin_proof_plan(CANDIDATE, ACCEPTED_INPUT)

    with tempfile.TemporaryDirectory(
        prefix="ctfos-rev-docker-proof-"
    ) as temporary:
        root = Path(temporary)
        challenge = root / "challenge"
        work = root / "work"
        inputs = work / "inputs"
        challenge.mkdir(mode=0o700)
        inputs.mkdir(parents=True, mode=0o700)
        _compile_fixture(challenge / "challenge.bin")

        scope = ChallengeScope.create(
            contest_id="release-smoke",
            category="rev",
            challenge_id="stdin-oracle-v1",
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
                ptrace=False,
                read_only_root=True,
                run_as_host_user=True,
                work_tree_max_bytes=64 * 1024 * 1024,
            ),
        )
        command = CommandSpec.create(
            RUNNER_ARGV,
            timeout_seconds=30,
            summary_bytes=4096,
            resource_request=ResourceVector(
                cpu=1,
                memory_mib=512,
            ),
        )

        results: list[dict[str, object]] = []
        durable_directories: set[str] = set()
        for attempt in plan:
            source_locator = f"inputs/attempt-{attempt.ordinal}.bin"
            source = work / source_locator
            source.write_bytes(attempt.payload)
            source.chmod(0o400)
            result = backend.run_clean_proof(
                command,
                proof_inputs=(
                    ProofInput(
                        source_locator=source_locator,
                        destination_locator="oracle/accepted-input.bin",
                        sha256=hashlib.sha256(
                            attempt.payload
                        ).hexdigest(),
                        size_bytes=len(attempt.payload),
                    ),
                ),
            )
            stdout = _read_durable_stream(work, result.stdout_path)
            stderr = _read_durable_stream(work, result.stderr_path)
            durable_directories.add(
                str(Path(result.stdout_path).parent)
            )
            expected_positive = attempt.phase == "positive"
            if expected_positive:
                if (
                    result.status != "completed"
                    or result.exit_code != 0
                    or CANDIDATE.encode() not in stdout
                ):
                    raise AssertionError(
                        f"positive attempt {attempt.ordinal} was not accepted"
                    )
            elif (
                result.status != "failed"
                or result.exit_code != 7
                or CANDIDATE.encode() in stdout
                or stdout != b"rejected\n"
            ):
                raise AssertionError(
                    f"negative attempt {attempt.ordinal} was not rejected"
                )
            if (
                result.timed_out
                or stderr
                or result.stdout_bytes != len(stdout)
                or result.stderr_bytes != len(stderr)
                or result.stdout_stored_bytes != len(stdout)
                or result.stderr_stored_bytes != len(stderr)
                or result.stdout_capture_complete is not True
                or result.stderr_capture_complete is not True
                or result.stdout_truncation_known is not True
                or result.stderr_truncation_known is not True
                or result.stdout_truncated is not False
                or result.stderr_truncated is not False
                or result.stdout_error is not None
                or result.stderr_error is not None
                or result.orchestration_error is not None
                or result.stream_capture_error is not None
            ):
                raise AssertionError(
                    f"attempt {attempt.ordinal} has incomplete transport"
                )
            results.append(
                {
                    "exit_code": result.exit_code,
                    "mutation_id": attempt.mutation_id,
                    "ordinal": attempt.ordinal,
                    "phase": attempt.phase,
                    "run_id": result.run_id,
                    "status": result.status,
                    "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                }
            )

        if len(durable_directories) != 6:
            raise AssertionError("proof attempts reused a durable directory")
        live_root = root / ".proof-live"
        if live_root.exists() and any(live_root.iterdir()):
            raise AssertionError("clean proof left a live workspace behind")
        print(
            json.dumps(
                {
                    "attempts": results,
                    "clean_workspaces": len(durable_directories),
                    "image_digest": image_digest,
                    "network": "none",
                    "ok": True,
                    "protocol": "rev_original_binary_stdin_candidate_v1",
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
