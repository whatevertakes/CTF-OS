from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

from ctf_os.sandbox import (
    ChallengeScope,
    CommandSpec,
    DockerLimits,
    DockerSandboxBackend,
    ProofInput,
    ProofOutput,
    SandboxError,
    ScopeError,
)
from ctf_os.sandbox.client import result_from_dict


IMAGE_DIGEST = "sha256:" + "a" * 64


class CleanProofOutputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.challenge = self.root / "challenge"
        self.work = self.root / "work"
        self.challenge.mkdir()
        self.scope = ChallengeScope.create(
            contest_id="sandbox-tests",
            category="pwn",
            challenge_id="proof-output",
            challenge_dir=self.challenge,
            work_dir=self.work,
        )
        self.live_roots: list[Path] = []

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _runner(
        self,
        *,
        output: bytes | None = b"target bytes\n",
        output_symlink: bool = False,
    ):
        def run(command, **_kwargs):
            work_mount = next(
                command[index + 1]
                for index, value in enumerate(command[:-1])
                if value == "--mount" and "dst=/work" in command[index + 1]
            )
            proof_work = Path(
                next(
                    part.removeprefix("src=")
                    for part in work_mount.split(",")
                    if part.startswith("src=")
                )
            )
            self.live_roots.append(proof_work)
            if "ctfwrap" not in command:
                return subprocess.CompletedProcess(command, 0, "", "")

            if output is not None:
                generated = proof_work / "generated"
                generated.mkdir()
                destination = generated / "target.stdout"
                if output_symlink:
                    destination.symlink_to("/etc/passwd")
                else:
                    destination.write_bytes(output)

            run_id = "run-00000001"
            run_root = proof_work / ".ctf" / "runs" / run_id
            run_root.mkdir(parents=True)
            stdout = b"producer document\n"
            stderr = b""
            (run_root / "stdout.log").write_bytes(stdout)
            (run_root / "stderr.log").write_bytes(stderr)
            value = {
                "duration_ms": 1,
                "exit_code": 0,
                "kind": "run_result",
                "run_id": run_id,
                "schema_version": 1,
                "status": "completed",
                "stderr_bytes": 0,
                "stderr_path": f"/work/.ctf/runs/{run_id}/stderr.log",
                "stderr_summary": "",
                "stdout_bytes": len(stdout),
                "stdout_path": f"/work/.ctf/runs/{run_id}/stdout.log",
                "stdout_summary": stdout.decode("ascii"),
                "timed_out": False,
            }
            (run_root / "result.json").write_text(
                json.dumps(value),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(value),
                "",
            )

        return run

    def _backend(self, *, runner, maximum_bytes: int = 1024 * 1024):
        return DockerSandboxBackend(
            self.scope,
            image_digest=IMAGE_DIGEST,
            limits=DockerLimits(work_tree_max_bytes=maximum_bytes),
            runner=runner,
        )

    def test_promotes_exact_bounded_output_and_round_trips_wire_value(
        self,
    ) -> None:
        payload = b"target bytes\n"
        backend = self._backend(runner=self._runner(output=payload))
        result = backend.run_clean_proof(
            CommandSpec(("true",)),
            proof_outputs=(
                ProofOutput(
                    source_locator="generated/target.stdout",
                    name="target.stdout",
                    maximum_bytes=1024,
                ),
            ),
        )

        self.assertEqual(len(result.proof_outputs), 1)
        reference = result.proof_outputs[0]
        self.assertEqual(reference.sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(reference.size_bytes, len(payload))
        self.assertEqual(reference.scope_fingerprint, self.scope.fingerprint)
        self.assertRegex(
            reference.locator,
            r"^proof/clean-[0-9a-f]{12}/outputs/target\.stdout$",
        )
        self.assertEqual((self.work / reference.locator).read_bytes(), payload)
        self.assertTrue(all(not root.exists() for root in self.live_roots))

        wire_value = json.loads(json.dumps(asdict(result)))
        decoded = result_from_dict(wire_value)
        self.assertEqual(decoded.proof_outputs, result.proof_outputs)

    def test_missing_symlink_and_oversized_outputs_fail_closed(self) -> None:
        cases = (
            ("missing", self._runner(output=None), 1024),
            ("symlink", self._runner(output_symlink=True), 1024),
            ("oversized", self._runner(output=b"x" * 9), 8),
        )
        for label, runner, maximum_bytes in cases:
            with self.subTest(label=label):
                backend = self._backend(runner=runner)
                with self.assertRaisesRegex(
                    SandboxError,
                    "unsafe, missing, or oversized declared output",
                ):
                    backend.run_clean_proof(
                        CommandSpec(("true",)),
                        proof_outputs=(
                            ProofOutput(
                                source_locator="generated/target.stdout",
                                name="target.stdout",
                                maximum_bytes=maximum_bytes,
                            ),
                        ),
                    )
                self.assertEqual(
                    list((self.work / "proof").glob("clean-*")),
                    [],
                )

    def test_output_cannot_relabel_preexisting_proof_input(self) -> None:
        staging = self.work / "staging"
        staging.mkdir(parents=True)
        value = b"input"
        source = staging / "input.bin"
        source.write_bytes(value)
        proof_input = ProofInput(
            source_locator="staging/input.bin",
            destination_locator="generated/target.stdout",
            sha256=hashlib.sha256(value).hexdigest(),
            size_bytes=len(value),
        )
        backend = self._backend(runner=self._runner())
        with self.assertRaisesRegex(ValueError, "must not alias proof inputs"):
            backend.run_clean_proof(
                CommandSpec(("true",)),
                proof_inputs=(proof_input,),
                proof_outputs=(
                    ProofOutput(
                        source_locator="generated/target.stdout",
                        name="target.stdout",
                        maximum_bytes=1024,
                    ),
                ),
            )

    def test_preexisting_declared_output_is_rejected_before_command(
        self,
    ) -> None:
        def runner(command, **_kwargs):
            work_mount = next(
                command[index + 1]
                for index, value in enumerate(command[:-1])
                if value == "--mount" and "dst=/work" in command[index + 1]
            )
            proof_work = Path(
                next(
                    part.removeprefix("src=")
                    for part in work_mount.split(",")
                    if part.startswith("src=")
                )
            )
            (proof_work / "generated").mkdir()
            (proof_work / "generated" / "target.stdout").write_bytes(b"old")
            return subprocess.CompletedProcess(command, 0, "", "")

        backend = self._backend(runner=runner)
        with self.assertRaisesRegex(ScopeError, "already exists before command"):
            backend.run_clean_proof(
                CommandSpec(("true",)),
                proof_outputs=(
                    ProofOutput(
                        source_locator="generated/target.stdout",
                        name="target.stdout",
                        maximum_bytes=1024,
                    ),
                ),
            )

    def test_output_contract_rejects_bool_limits_and_duplicate_names(
        self,
    ) -> None:
        with self.assertRaises(ValueError):
            ProofOutput(
                source_locator="generated/a",
                name="a",
                maximum_bytes=True,
            )
        backend = self._backend(runner=self._runner())
        with self.assertRaisesRegex(ValueError, "sources and names"):
            backend.run_clean_proof(
                CommandSpec(("true",)),
                proof_outputs=(
                    ProofOutput("generated/a", "same", 1024),
                    ProofOutput("generated/b", "same", 1024),
                ),
            )


if __name__ == "__main__":
    unittest.main()
