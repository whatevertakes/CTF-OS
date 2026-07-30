from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from ctf_os import cli
from ctf_os.config import EngineConfig, RuntimeConfig
from ctf_os.engine.challenge import ChallengeEngine, EngineError
from ctf_os.engine.crypto_metamorphic import (
    CRYPTO_METAMORPHIC_PROOF_PROTOCOL,
)
from ctf_os.engine.proof import ProofResult
from ctf_os.models import (
    CandidateStatus,
    ChallengeIdentity,
    ChallengeStatus,
    FlagCandidate,
    ModelValidationError,
)
from ctf_os.sandbox import ArtifactRef, SandboxResult
from ctf_os.schema import STATE_SCHEMA_VERSION


CANDIDATE = "KCTF{crypto-engine-proof}"
ORIGINAL = b'{"N":3233,"ciphertext":2790,"e":17,"rounds":1}\n'
VARIANT = b'{"N":4757,"ciphertext":2281,"e":17,"rounds":2}\n'
VARIANT_OUTPUT = b"metamorphic-answer-42\n"


class CryptoProofSandbox:
    scope_fingerprint = "b" * 64

    def __init__(
        self,
        work: Path,
        *,
        wrong_variant: bool = False,
        fail_on_call: int | None = None,
    ) -> None:
        self.work = work
        self.wrong_variant = wrong_variant
        self.fail_on_call = fail_on_call
        self.proof_calls: list[tuple[object, tuple]] = []
        self.initializations = 0

    def initialize_workspace(self, *, deadline_monotonic_seconds=None):
        del deadline_monotonic_seconds
        self.initializations += 1

    def register_artifact(self, locator, *, maximum_bytes=1 << 34):
        path = self.work / locator
        payload = path.read_bytes()
        if len(payload) > maximum_bytes:
            raise ValueError("artifact exceeds test bound")
        return ArtifactRef(
            locator=locator,
            sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
            scope_fingerprint=self.scope_fingerprint,
        )

    def run_clean_proof(
        self,
        spec,
        *,
        input_locators=(),
        proof_inputs=(),
    ):
        self.assert_no_unexpected_locators(input_locators)
        copied: dict[str, bytes] = {}
        for item in proof_inputs:
            payload = (self.work / item.source_locator).read_bytes()
            if hashlib.sha256(payload).hexdigest() != item.sha256:
                raise AssertionError("proof input hash mismatch")
            if len(payload) != item.size_bytes:
                raise AssertionError("proof input size mismatch")
            copied[item.destination_locator] = payload
        self.proof_calls.append((spec, tuple(copied.items())))
        if len(self.proof_calls) == self.fail_on_call:
            raise RuntimeError("synthetic Crypto sandbox interruption")
        parameters = copied["oracle/parameters.json"]
        if parameters == ORIGINAL:
            output = CANDIDATE.encode()
        elif parameters == VARIANT:
            output = (
                b"wrong-variant-answer"
                if self.wrong_variant
                else VARIANT_OUTPUT
            )
        else:
            raise AssertionError("unexpected parameter document")
        number = len(self.proof_calls)
        relative = Path("proof") / f"crypto-clean-{number}"
        directory = self.work / relative
        directory.mkdir(parents=True)
        stdout = directory / "stdout.log"
        stderr = directory / "stderr.log"
        stdout.write_bytes(output)
        stderr.write_bytes(b"")
        return SandboxResult(
            run_id=f"crypto-sandbox-{number}",
            status="completed",
            exit_code=0,
            timed_out=False,
            duration_ms=3,
            stdout_summary="bounded",
            stderr_summary="",
            stdout_bytes=len(output),
            stderr_bytes=0,
            stdout_path=f"/work/{relative.as_posix()}/stdout.log",
            stderr_path=f"/work/{relative.as_posix()}/stderr.log",
            stdout_stored_bytes=len(output),
            stderr_stored_bytes=0,
            stdout_limit_bytes=1024 * 1024,
            stderr_limit_bytes=1024 * 1024,
            stdout_truncated=False,
            stderr_truncated=False,
            stdout_truncation_known=True,
            stderr_truncation_known=True,
            stdout_capture_complete=True,
            stderr_capture_complete=True,
            stdout_error=None,
            stderr_error=None,
            stream_capture_error=None,
            orchestration_error=None,
        )

    @staticmethod
    def assert_no_unexpected_locators(input_locators):
        if input_locators:
            raise AssertionError("typed proof inputs are required")

    def run(self, spec):
        raise AssertionError(f"normal sandbox run is unexpected: {spec}")

    def start_job(self, *args, **kwargs):
        raise AssertionError("not used")

    def job_status(self, *args, **kwargs):
        raise AssertionError("not used")

    def job_log(self, *args, **kwargs):
        raise AssertionError("not used")

    def cancel_job(self, *args, **kwargs):
        raise AssertionError("not used")


class CryptoEngineProofTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.identity = ChallengeIdentity(
            "Crypto CTF",
            "crypto",
            "Metamorphic",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_generic_proof_gate_is_fail_closed_for_crypto(self) -> None:
        engine, sandbox = self._engine()
        state = engine.store.load(self.identity)
        candidate_id = "C-crypto-candidate"

        with self.assertRaisesRegex(
            EngineError,
            "cannot use the generic proof gate",
        ):
            engine.prove_candidate(
                self.identity,
                candidate_id,
                ("python3", "/work/solver.py"),
            )

        current = engine.store.load(self.identity)
        candidate = next(
            item
            for item in current.candidates
            if item.id == candidate_id
        )
        self.assertEqual(current.status, state.status)
        self.assertEqual(
            candidate.status,
            CandidateStatus.OBSERVED_CANDIDATE,
        )
        self.assertEqual(sandbox.proof_calls, [])

    def _engine(
        self,
        *,
        wrong_variant: bool = False,
        pinned_image: bool = True,
        fail_on_call: int | None = None,
    ) -> tuple[ChallengeEngine, CryptoProofSandbox]:
        holder: dict[str, CryptoProofSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            sandbox = holder.get("sandbox")
            if sandbox is None:
                sandbox = CryptoProofSandbox(
                    work,
                    wrong_variant=wrong_variant,
                    fail_on_call=fail_on_call,
                )
                holder["sandbox"] = sandbox
            else:
                # Managed oracle proofs deliberately switch from the Builder
                # workspace to an engine-private proof source root.
                sandbox.work = work
            return sandbox

        engine = ChallengeEngine(
            self.root,
            config=EngineConfig(
                workspace_root=self.root,
                runtime=RuntimeConfig(
                    image_digest=(
                        "sha256:" + "1" * 64
                        if pinned_image
                        else None
                    )
                ),
            ),
            sandbox_factory=sandbox_factory,
        )
        incoming = engine.challenge_input(self.identity)
        incoming.mkdir(parents=True)
        (incoming / "task.py").write_text(
            "N = 3233\n",
            encoding="utf-8",
        )
        state = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        workspace = engine._workspace(state)
        holder["sandbox"] = CryptoProofSandbox(
            workspace,
            wrong_variant=wrong_variant,
            fail_on_call=fail_on_call,
        )
        (workspace / "solver.py").write_text(
            "import json,sys\n",
            encoding="utf-8",
        )
        (workspace / "original.json").write_bytes(ORIGINAL)
        (workspace / "variant.json").write_bytes(VARIANT)
        (workspace / "variant.out").write_bytes(VARIANT_OUTPUT)

        def add_candidate(current):
            current.candidates.append(
                FlagCandidate(
                    id="C-crypto-candidate",
                    value=CANDIDATE,
                )
            )

        engine.store.update(self.identity, add_candidate)
        return engine, holder["sandbox"]

    def _prove(self, engine: ChallengeEngine):
        return engine.prove_crypto_metamorphic_candidate(
            self.identity,
            "C-crypto-candidate",
            solver_locator="solver.py",
            original_parameters_locator="original.json",
            variant_parameters_locator="variant.json",
            variant_expected_output_locator="variant.out",
            mutation_id="rsa-size-seed-variant",
            runtime="python",
        )

    def test_six_clean_bound_runs_are_required_before_promotion(self) -> None:
        engine, sandbox = self._engine()

        state, result = self._prove(engine)

        self.assertTrue(result.passed)
        self.assertEqual(result.required_attempts, 6)
        self.assertEqual(result.successful_attempts, 6)
        self.assertEqual(state.status, ChallengeStatus.READY_TO_SUBMIT)
        candidate = next(
            item
            for item in state.candidates
            if item.id == "C-crypto-candidate"
        )
        self.assertEqual(
            candidate.status,
            CandidateStatus.READY_TO_SUBMIT,
        )
        self.assertEqual(len(candidate.proof_run_ids), 6)
        proof_runs = [
            run for run in state.runs if run.id in candidate.proof_run_ids
        ]
        self.assertEqual(len(proof_runs), 6)
        self.assertTrue(
            all(run.role == "crypto_metamorphic_proof" for run in proof_runs)
        )
        self.assertTrue(
            all(
                run.extra["crypto_metamorphic_protocol"]
                == CRYPTO_METAMORPHIC_PROOF_PROTOCOL
                for run in proof_runs
            )
        )
        self.assertEqual(len(sandbox.proof_calls), 6)
        parameter_payloads = []
        for spec, captured_inputs in sandbox.proof_calls:
            self.assertIsNone(spec.network_target)
            self.assertFalse(spec.resource_request.network)
            self.assertEqual(
                spec.argv,
                (
                    "python3",
                    "/work/oracle/solver.py",
                    "/work/oracle/parameters.json",
                ),
            )
            destinations = dict(captured_inputs)
            self.assertEqual(
                set(destinations),
                {"oracle/solver.py", "oracle/parameters.json"},
            )
            self.assertNotIn(VARIANT_OUTPUT, destinations.values())
            parameter_payloads.append(
                destinations["oracle/parameters.json"]
            )
        self.assertEqual(
            parameter_payloads,
            [ORIGINAL] * 3 + [VARIANT] * 3,
        )
        evaluation_artifact = next(
            item
            for item in state.artifacts
            if item.extra.get("kind")
            == "crypto_metamorphic_evaluation"
        )
        evaluation = json.loads(
            (
                engine.store.challenge_paths(self.identity).root
                / evaluation_artifact.path
            ).read_text(encoding="utf-8")
        )
        self.assertTrue(evaluation["passed"])
        self.assertNotIn(
            CANDIDATE,
            json.dumps(evaluation, sort_keys=True),
        )
        self.assertEqual(
            state.progress_markers[-1].extra["adapter_marker"],
            "metamorphic_variant_verified",
        )

    def test_wrong_variant_output_persists_evidence_without_promotion(
        self,
    ) -> None:
        engine, sandbox = self._engine(wrong_variant=True)

        state, result = self._prove(engine)

        self.assertFalse(result.passed)
        self.assertEqual(len(sandbox.proof_calls), 6)
        self.assertNotEqual(
            state.status,
            ChallengeStatus.READY_TO_SUBMIT,
        )
        candidate = next(
            item
            for item in state.candidates
            if item.id == "C-crypto-candidate"
        )
        self.assertEqual(
            candidate.status,
            CandidateStatus.OBSERVED_CANDIDATE,
        )
        self.assertEqual(len(candidate.proof_run_ids), 6)
        binding = candidate.extra["crypto_metamorphic_proof"]
        self.assertFalse(binding["passed"])
        self.assertTrue(
            any(
                failure.endswith(":result_mismatch")
                for failure in result.failures
            )
        )
        self.assertFalse(
            any(
                marker.extra.get("adapter_marker")
                == "metamorphic_variant_verified"
                for marker in state.progress_markers
            )
        )

    def test_interrupted_matrix_preserves_frozen_inputs_and_prior_run(
        self,
    ) -> None:
        engine, _sandbox = self._engine(fail_on_call=2)

        with self.assertRaisesRegex(
            RuntimeError,
            "synthetic Crypto sandbox interruption",
        ):
            self._prove(engine)

        state = engine.store.load(self.identity)
        inputs = [
            artifact
            for artifact in state.artifacts
            if artifact.extra.get("kind")
            in {
                "crypto_metamorphic_input",
                "crypto_metamorphic_input_manifest",
            }
        ]
        self.assertEqual(len(inputs), 5)
        self.assertTrue(
            all(
                (
                    engine.store.challenge_paths(self.identity).root
                    / artifact.path
                ).is_file()
                for artifact in inputs
            )
        )
        self.assertEqual(len(state.candidates[0].proof_run_ids), 2)
        failed_run = next(
            run
            for run in state.runs
            if run.id == state.candidates[0].proof_run_ids[-1]
        )
        self.assertEqual(failed_run.status.value, "failed")
        self.assertEqual(
            failed_run.extra["execution_error"],
            "crypto_proof_sandbox_execution_failed",
        )
        self.assertEqual(
            state.candidates[0].status,
            CandidateStatus.OBSERVED_CANDIDATE,
        )
        self.assertFalse(
            any(
                artifact.extra.get("kind")
                == "crypto_metamorphic_evaluation"
                for artifact in state.artifacts
            )
        )

    def test_ready_crypto_proof_graph_cannot_be_stripped_or_rebound(
        self,
    ) -> None:
        engine, _sandbox = self._engine()
        state, result = self._prove(engine)
        self.assertTrue(result.passed)
        revision = state.revision

        def strip_binding(current):
            current.candidates[0].extra.pop(
                "crypto_metamorphic_proof",
                None,
            )

        with self.assertRaisesRegex(
            ModelValidationError,
            "lacks its typed metamorphic proof binding",
        ):
            engine.store.update(self.identity, strip_binding)

        def strip_marker(current):
            current.progress_markers.clear()

        with self.assertRaisesRegex(
            ModelValidationError,
            "lacks one exact progress marker",
        ):
            engine.store.update(self.identity, strip_marker)

        def rebind_run(current):
            proof = current.candidates[0].extra[
                "crypto_metamorphic_proof"
            ]
            run_id = proof["run_ids"][0]
            run = next(item for item in current.runs if item.id == run_id)
            run.extra["attempt_ordinal"] = 2

        with self.assertRaisesRegex(
            ModelValidationError,
            "run 1 evidence graph is invalid",
        ):
            engine.store.update(self.identity, rebind_run)

        unchanged = engine.store.load(self.identity)
        self.assertEqual(unchanged.revision, revision)
        self.assertEqual(
            unchanged.status,
            ChallengeStatus.READY_TO_SUBMIT,
        )

    def test_manual_acceptance_preserves_typed_crypto_proof(self) -> None:
        engine, _sandbox = self._engine()
        self._prove(engine)

        solved = engine.record_manual_submission(
            self.identity,
            "C-crypto-candidate",
            outcome="accepted",
        )

        self.assertEqual(solved.status, ChallengeStatus.SOLVED)
        self.assertEqual(
            solved.candidates[0].status,
            CandidateStatus.ACCEPTED,
        )
        self.assertTrue(
            solved.candidates[0]
            .extra["crypto_metamorphic_proof"]["passed"]
        )
        self.assertTrue(solved.submissions[-1].proof_passed)

    def test_solver_with_candidate_is_rejected_before_execution(self) -> None:
        engine, sandbox = self._engine()
        workspace = engine._workspace(engine.store.load(self.identity))
        (workspace / "solver.py").write_text(
            f"ANSWER = {CANDIDATE!r}\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            EngineError,
            "embeds the exact candidate",
        ):
            self._prove(engine)

        self.assertEqual(sandbox.proof_calls, [])
        state = engine.store.load(self.identity)
        self.assertFalse(
            any(
                artifact.extra.get("kind", "").startswith(
                    "crypto_metamorphic"
                )
                for artifact in state.artifacts
            )
        )

    def test_unpinned_runtime_is_rejected_before_input_snapshot(self) -> None:
        engine, sandbox = self._engine(pinned_image=False)

        with self.assertRaisesRegex(
            EngineError,
            "digest-pinned image",
        ):
            self._prove(engine)

        self.assertEqual(sandbox.proof_calls, [])
        state = engine.store.load(self.identity)
        self.assertEqual(state.candidates[0].proof_run_ids, [])

    def test_ctfos_crypto_prove_routes_exact_operator_arguments(self) -> None:
        result = ProofResult(
            passed=True,
            candidate=CANDIDATE,
            policy_mode=CRYPTO_METAMORPHIC_PROOF_PROTOCOL,
            successful_attempts=6,
            required_attempts=6,
            total_attempts=6,
            source_manifest_sha256="a" * 64,
            failures=(),
            run_ids=tuple(f"run-{index}" for index in range(6)),
        )
        arguments = [
            "crypto-prove",
            self.identity.contest_id,
            self.identity.category,
            self.identity.challenge_id,
            "--candidate",
            "C-crypto-candidate",
            "--solver",
            "solver.py",
            "--original-parameters",
            "original.json",
            "--variant-parameters",
            "variant.json",
            "--variant-expected-output",
            "variant.out",
            "--mutation-id",
            "rsa-size-seed-variant",
            "--runtime",
            "sage",
        ]
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            ChallengeEngine,
            "prove_crypto_metamorphic_candidate",
            return_value=(mock.sentinel.state, result),
        ) as prove, redirect_stdout(stdout), redirect_stderr(stderr):
            status = cli.main(arguments, root=self.root)

        self.assertEqual(status, 0, stderr.getvalue())
        prove.assert_called_once_with(
            self.identity,
            "C-crypto-candidate",
            solver_locator="solver.py",
            original_parameters_locator="original.json",
            variant_parameters_locator="variant.json",
            variant_expected_output_locator="variant.out",
            mutation_id="rsa-size-seed-variant",
            runtime="sage",
        )
        self.assertEqual(
            json.loads(stdout.getvalue())["policy_mode"],
            CRYPTO_METAMORPHIC_PROOF_PROTOCOL,
        )


if __name__ == "__main__":
    unittest.main()
