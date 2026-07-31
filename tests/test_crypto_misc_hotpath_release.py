from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ctf_os.models import ArtifactReference, RunOrigin, RunStatus


REPOSITORY = Path(__file__).resolve().parent.parent
SCRIPT = (
    REPOSITORY
    / "scripts"
    / "check-crypto-misc-docker-hotpaths.py"
)
SPEC = importlib.util.spec_from_file_location(
    "ctfos_crypto_misc_hotpath_release",
    SCRIPT,
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load Crypto/Misc release proof")
release = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release
SPEC.loader.exec_module(release)


class CryptoMiscHotPathReleaseTests(unittest.TestCase):
    def test_release_proof_is_public_hard_pinned_and_networkless(
        self,
    ) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(
            release.RELEASE_IMAGE_DIGEST,
            "sha256:"
            "514ab5c51489f9bb66dccb4b5f2c4c86eac64711b89083e3a4ff50eb19910be9",
        )
        self.assertIn(
            "engine.preissue_managed_crypto_oracle(",
            source,
        )
        self.assertIn(
            "engine.preissue_managed_misc_oracle(",
            source,
        )
        self.assertIn("ManagedOrchestrator(", source)
        self.assertIn("_execute_managed_builder_action(", source)
        self.assertIn('"kind": "prove_crypto_metamorphic"', source)
        self.assertIn('"kind": "evaluate_misc_transform"', source)
        self.assertIn('runtime="python"', source)
        self.assertIn('runtime="sage"', source)
        self.assertIn('network_default="none"', source)
        self.assertNotIn("variant_parameters_locator=", source)
        self.assertNotIn("variant_expected_output_locator=", source)
        self.assertNotIn("spec_locator=", source)
        self.assertNotIn("FakeSandbox", source)
        self.assertNotIn("record_manual_submission", source)
        self.assertNotIn("submit_candidate", source)

    def test_crypto_summary_is_derived_from_completed_physical_runs(
        self,
    ) -> None:
        source_manifest = "a" * 64
        solver_sha256 = "b" * 64
        runtime_fingerprint_sha256 = "c" * 64
        image_digest = release.RELEASE_IMAGE_DIGEST
        configuration_epoch = 4
        run_ids = [f"crypto-run-{ordinal}" for ordinal in range(1, 7)]
        candidate = SimpleNamespace(
            id="C-crypto",
            value="KCTF{candidate}",
            proof_run_ids=list(run_ids),
        )
        original_output = candidate.value.encode("utf-8")
        variant_output = b"metamorphic-variant-output"
        oracle_sha256 = hashlib.sha256(variant_output).hexdigest()
        cases = [
            {
                "case_id": "original",
                "changed_parameter_pointers": [],
                "expected_output_sha256": hashlib.sha256(
                    original_output
                ).hexdigest(),
                "expected_output_size_bytes": len(original_output),
                "mutation_id": "original-baseline",
                "parameters_sha256": "d" * 64,
                "parameters_size_bytes": 23,
            },
            {
                "case_id": "metamorphic-variant",
                "changed_parameter_pointers": ["/N"],
                "expected_output_sha256": oracle_sha256,
                "expected_output_size_bytes": len(variant_output),
                "mutation_id": "changed-modulus",
                "parameters_sha256": "e" * 64,
                "parameters_size_bytes": 29,
            },
        ]
        attempts = []
        for ordinal in range(1, 7):
            case = cases[0] if ordinal <= 3 else cases[1]
            attempts.append(
                {
                    "case_id": case["case_id"],
                    "expected_output_sha256": (
                        case["expected_output_sha256"]
                    ),
                    "expected_output_size_bytes": (
                        case["expected_output_size_bytes"]
                    ),
                    "mutation_id": case["mutation_id"],
                    "ordinal": ordinal,
                    "parameters_sha256": case["parameters_sha256"],
                    "parameters_size_bytes": (
                        case["parameters_size_bytes"]
                    ),
                }
            )
        plan = {
            "attempts": attempts,
            "cases": cases,
            "protocol": release.CRYPTO_METAMORPHIC_PROOF_PROTOCOL,
        }
        plan_sha256 = hashlib.sha256(
            (
                json.dumps(
                    plan,
                    allow_nan=False,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode("ascii")
        ).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            challenge_root = Path(temporary)
            runs = []
            artifacts = []
            observations = []
            for ordinal, run_id in enumerate(run_ids, start=1):
                run_root = challenge_root / "runs" / run_id
                run_root.mkdir(parents=True)
                output = (
                    original_output if ordinal <= 3 else variant_output
                )
                evidence_root = (
                    challenge_root / "artifacts" / "evidence" / run_id
                )
                evidence_root.mkdir(parents=True)
                stream_artifacts = []
                for stream, payload in (
                    ("stdout", output),
                    ("stderr", b""),
                ):
                    path = evidence_root / f"{stream}.log"
                    path.write_bytes(payload)
                    stream_artifacts.append(
                        ArtifactReference(
                            id=f"A-{run_id}-{stream}",
                            path=path.relative_to(
                                challenge_root
                            ).as_posix(),
                            sha256=hashlib.sha256(payload).hexdigest(),
                            source_run_id=run_id,
                            created_at="2026-07-31T00:00:00Z",
                            size=len(payload),
                            extra={
                                "attempt_ordinal": ordinal,
                                "context_visibility": "engine_private",
                                "kind": "crypto_metamorphic_stream",
                                "plan_sha256": plan_sha256,
                                "protocol": (
                                    release
                                    .CRYPTO_METAMORPHIC_PROOF_PROTOCOL
                                ),
                                "stream": stream,
                            },
                        )
                    )
                artifacts.extend(stream_artifacts)
                expected_attempt = attempts[ordinal - 1]
                observation = {
                    "capture_complete": True,
                    "capture_error_present": False,
                    "case_id": expected_attempt["case_id"],
                    "clean_workspace": True,
                    "ctfwrap_exit_code": 0,
                    "mutation_id": expected_attempt["mutation_id"],
                    "oracle_artifact_sha256": oracle_sha256,
                    "orchestration_status": "completed",
                    "ordinal": ordinal,
                    "parameters_sha256": (
                        expected_attempt["parameters_sha256"]
                    ),
                    "parameters_size_bytes": (
                        expected_attempt["parameters_size_bytes"]
                    ),
                    "result_artifact_id": stream_artifacts[0].id,
                    "result_artifact_sha256": (
                        stream_artifacts[0].sha256
                    ),
                    "result_artifact_size_bytes": (
                        stream_artifacts[0].size
                    ),
                    "run_id": run_id,
                    "runner_exit_code": 0,
                    "runtime_fingerprint_sha256": (
                        runtime_fingerprint_sha256
                    ),
                    "solver_artifact_sha256": solver_sha256,
                    "source_manifest_sha256": source_manifest,
                    "target_exit_code": 0,
                    "timed_out": False,
                    "truncated": False,
                    "truncation_known": True,
                }
                observations.append(observation)
                documents = {
                    "request.json": {
                        "attempt": expected_attempt,
                        "base_revision": ordinal,
                        "candidate_id": "C-crypto",
                        "category": "crypto",
                        "challenge_id": "release-unit",
                        "command": [
                            "python3",
                            "/work/oracle/solver.py",
                            "/work/oracle/parameters.json",
                        ],
                        "configuration_epoch": configuration_epoch,
                        "contest_id": "release-smoke",
                        "created_at": "2026-07-31T00:00:00Z",
                        "image_reference": image_digest,
                        "kind": "crypto_metamorphic_proof",
                        "network_target": None,
                        "oracle_artifact_sha256": oracle_sha256,
                        "plan_sha256": plan_sha256,
                        "protocol": (
                            release.CRYPTO_METAMORPHIC_PROOF_PROTOCOL
                        ),
                        "runtime_fingerprint_sha256": (
                            runtime_fingerprint_sha256
                        ),
                        "run_id": run_id,
                        "schema_version": 1,
                        "solver_sha256": solver_sha256,
                        "source_manifest_sha256": source_manifest,
                    },
                    "result.json": {
                        "artifacts": [
                            item.to_dict() for item in stream_artifacts
                        ],
                        "category": "crypto",
                        "challenge_id": "release-unit",
                        "contest_id": "release-smoke",
                        "duration_ms": ordinal,
                        "exit_code": 0,
                        "observation": observation,
                        "run_id": run_id,
                        "schema_version": 1,
                        "status": "completed",
                        "timed_out": False,
                    },
                    "validation.json": {
                        "attempt_ordinal": ordinal,
                        "ok": True,
                        "plan_sha256": plan_sha256,
                        "protocol": (
                            release.CRYPTO_METAMORPHIC_PROOF_PROTOCOL
                        ),
                        "run_id": run_id,
                        "validated_at": "2026-07-31T00:00:01Z",
                    },
                }
                for name, document in documents.items():
                    (run_root / name).write_text(
                        json.dumps(document, sort_keys=True),
                        encoding="utf-8",
                    )
                runs.append(
                    SimpleNamespace(
                        id=run_id,
                        base_revision=ordinal,
                        status=RunStatus.COMPLETED,
                        origin=RunOrigin.PROOF,
                        configuration_epoch=configuration_epoch,
                        role="crypto_metamorphic_proof",
                        request_path=f"runs/{run_id}/request.json",
                        result_path=f"runs/{run_id}/result.json",
                        validation_path=f"runs/{run_id}/validation.json",
                        extra={
                            "attempt_ordinal": ordinal,
                            "crypto_metamorphic_protocol": (
                                release.CRYPTO_METAMORPHIC_PROOF_PROTOCOL
                            ),
                            "observation": observation,
                            "plan_sha256": plan_sha256,
                        },
                    )
                )
            evaluation = {
                "candidate_sha256": hashlib.sha256(
                    candidate.value.encode("utf-8")
                ).hexdigest(),
                "failure_codes": [],
                "observations": observations,
                "oracle_artifact_sha256": oracle_sha256,
                "passed": True,
                "plan": plan,
                "protocol": (
                    release.CRYPTO_METAMORPHIC_PROOF_PROTOCOL
                ),
                "runtime_fingerprint_sha256": (
                    runtime_fingerprint_sha256
                ),
                "schema_version": 1,
                "solver_artifact_sha256": solver_sha256,
                "source_manifest_sha256": source_manifest,
            }
            proof_result = {
                "candidate": candidate.value,
                "failures": [],
                "passed": True,
                "policy_mode": (
                    release.CRYPTO_METAMORPHIC_PROOF_PROTOCOL
                ),
                "required_attempts": 6,
                "run_ids": list(run_ids),
                "source_manifest_sha256": source_manifest,
                "successful_attempts": 6,
                "total_attempts": 6,
            }
            binding = {
                "artifact_id": "A-crypto-evaluation",
                "evaluation": evaluation,
                "evaluation_sha256": hashlib.sha256(
                    (
                        json.dumps(
                            evaluation,
                            allow_nan=False,
                            ensure_ascii=True,
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                        + "\n"
                    ).encode("ascii")
                ).hexdigest(),
                "oracle_authority": "managed_oracle_preissue_v1",
                "oracle_preissue_id": "O-crypto-release",
                "passed": True,
                "plan_sha256": plan_sha256,
                "proof_result": proof_result,
                "protocol": (
                    release.CRYPTO_METAMORPHIC_PROOF_PROTOCOL
                ),
                "run_ids": list(run_ids),
            }
            final = SimpleNamespace(
                artifacts=artifacts,
                category="crypto",
                challenge_id="release-unit",
                configuration_epoch=configuration_epoch,
                contest_id="release-smoke",
                metadata={"source_manifest_sha256": source_manifest},
                runs=runs,
            )

            physical, successful = release._validated_crypto_execution(
                final,
                candidate,
                binding,
                challenge_root=challenge_root,
                image_digest=image_digest,
                runtime="python",
            )

            self.assertEqual(len(physical), 6)
            self.assertEqual(successful, 6)
            runs[2].status = RunStatus.FAILED
            with self.assertRaisesRegex(
                AssertionError,
                "physical run 3",
            ):
                release._validated_crypto_execution(
                    final,
                    candidate,
                    binding,
                    challenge_root=challenge_root,
                    image_digest=image_digest,
                    runtime="python",
                )
            runs[2].status = RunStatus.COMPLETED
            proof_result["successful_attempts"] = 5
            with self.assertRaisesRegex(
                AssertionError,
                "six successful attempts",
            ):
                release._validated_crypto_execution(
                    final,
                    candidate,
                    binding,
                    challenge_root=challenge_root,
                    image_digest=image_digest,
                    runtime="python",
                )
            proof_result["successful_attempts"] = 6
            stdout_path = (
                challenge_root
                / artifacts[0].path
            )
            stdout_path.write_bytes(b"hostile physical replacement")
            with self.assertRaisesRegex(
                AssertionError,
                "stdout artifact",
            ):
                release._validated_crypto_execution(
                    final,
                    candidate,
                    binding,
                    challenge_root=challenge_root,
                    image_digest=image_digest,
                    runtime="python",
                )
            stdout_path.write_bytes(original_output)
            request_path = (
                challenge_root / "runs" / run_ids[0] / "request.json"
            )
            result_path = (
                challenge_root / "runs" / run_ids[0] / "result.json"
            )
            request = json.loads(request_path.read_text(encoding="utf-8"))
            request["attempt"].update(
                {
                    "case_id": "forged-case",
                    "mutation_id": "forged-mutation",
                    "parameters_sha256": "0" * 64,
                }
            )
            request_path.write_text(
                json.dumps(request, sort_keys=True),
                encoding="utf-8",
            )
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["observation"].update(
                {
                    "capture_error_present": True,
                    "clean_workspace": False,
                    "result_artifact_id": "missing-artifact",
                    "result_artifact_sha256": "0" * 64,
                    "result_artifact_size_bytes": 999999,
                    "target_exit_code": 99,
                }
            )
            result["artifacts"] = []
            result_path.write_text(
                json.dumps(result, sort_keys=True),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                AssertionError,
                "physical run 1",
            ):
                release._validated_crypto_execution(
                    final,
                    candidate,
                    binding,
                    challenge_root=challenge_root,
                    image_digest=image_digest,
                    runtime="python",
                )

    @unittest.skipUnless(
        os.environ.get("CTFOS_RUN_CRYPTO_MISC_DOCKER") == "1",
        "set CTFOS_RUN_CRYPTO_MISC_DOCKER=1 for the real Docker gate",
    )
    def test_misc_gate_rejects_postcommit_sidecar_rewrite(self) -> None:
        original = release._execute_managed_builder_action

        def hostile(engine, identity, **kwargs):
            final, experiment = original(engine, identity, **kwargs)
            challenge_root = engine.store.challenge_paths(identity).root
            for run in final.runs:
                if run.extra.get("misc_evaluation_id") is None:
                    continue
                result_path = challenge_root / run.result_path
                result_path.chmod(0o600)
                result = json.loads(
                    result_path.read_text(encoding="utf-8")
                )
                result.update(
                    {
                        "exit_code": 99,
                        "status": "failed",
                        "timed_out": True,
                    }
                )
                result_path.write_text(
                    json.dumps(result, sort_keys=True),
                    encoding="utf-8",
                )
                result_path.chmod(0o400)
            return final, experiment

        release._execute_managed_builder_action = hostile
        try:
            with tempfile.TemporaryDirectory() as temporary:
                with self.assertRaisesRegex(
                    AssertionError,
                    "Misc physical",
                ):
                    release._misc(
                        Path(temporary),
                        release.RELEASE_IMAGE_DIGEST,
                    )
        finally:
            release._execute_managed_builder_action = original

    @unittest.skipUnless(
        os.environ.get("CTFOS_RUN_CRYPTO_MISC_DOCKER") == "1",
        "set CTFOS_RUN_CRYPTO_MISC_DOCKER=1 for the real Docker gate",
    )
    def test_misc_gate_rejects_postcommit_artifact_deletion(self) -> None:
        original = release._execute_managed_builder_action

        def hostile(engine, identity, **kwargs):
            final, experiment = original(engine, identity, **kwargs)
            candidate = next(
                item
                for item in final.candidates
                if item.id == "C-misc-docker"
            )
            binding = candidate.extra["misc_transform_evidence"]
            artifact = next(
                item
                for item in final.artifacts
                if item.id == binding["artifact_id"]
            )
            (engine.store.challenge_paths(identity).root / artifact.path).unlink()
            return final, experiment

        release._execute_managed_builder_action = hostile
        try:
            with tempfile.TemporaryDirectory() as temporary:
                with self.assertRaises((OSError, ValueError)):
                    release._misc(
                        Path(temporary),
                        release.RELEASE_IMAGE_DIGEST,
                    )
        finally:
            release._execute_managed_builder_action = original

    @unittest.skipUnless(
        os.environ.get("CTFOS_RUN_CRYPTO_MISC_DOCKER") == "1",
        "set CTFOS_RUN_CRYPTO_MISC_DOCKER=1 for the real Docker gate",
    )
    def test_real_docker_release_gate(self) -> None:
        completed = subprocess.run(
            (
                sys.executable,
                str(SCRIPT),
                "--image-digest",
                release.RELEASE_IMAGE_DIGEST,
            ),
            cwd=REPOSITORY,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            text=True,
            timeout=1200,
        )
        if completed.returncode != 0:
            self.fail(
                "real Docker release gate failed:\n"
                + completed.stdout[-4096:]
                + completed.stderr[-4096:]
            )
        summary = json.loads(completed.stdout.splitlines()[-1])
        self.assertTrue(summary["ok"])
        self.assertEqual(
            set(summary["crypto"]),
            {"python", "sage"},
        )
        for runtime in ("python", "sage"):
            result = summary["crypto"][runtime]
            self.assertEqual(
                set(result),
                {
                    "candidate_status",
                    "network",
                    "one_shot_consumed",
                    "oracle_authority",
                    "oracle_preissue_status",
                    "runtime",
                    "runs",
                    "successful_attempts",
                    "submissions",
                },
            )
            self.assertEqual(result["runtime"], runtime)
            self.assertEqual(result["runs"], 6)
            self.assertEqual(result["successful_attempts"], 6)
            self.assertEqual(result["candidate_status"], "READY_TO_SUBMIT")
            self.assertEqual(result["submissions"], 0)
            self.assertEqual(result["network"], "none")
            self.assertEqual(
                result["oracle_authority"],
                "managed_oracle_preissue_v1",
            )
            self.assertEqual(result["oracle_preissue_status"], "consumed")
            self.assertTrue(result["one_shot_consumed"])
        self.assertEqual(
            set(summary["misc"]),
            {
                "candidate_only",
                "candidate_status",
                "network",
                "one_shot_consumed",
                "oracle_authority",
                "oracle_control_runs",
                "oracle_preissue_status",
                "runs",
                "submissions",
                "transform_evidence_passed",
                "transform_runs",
                "verification_runs",
            },
        )
        self.assertEqual(summary["misc"]["runs"], 5)
        self.assertEqual(summary["misc"]["transform_runs"], 1)
        self.assertEqual(summary["misc"]["oracle_control_runs"], 1)
        self.assertEqual(summary["misc"]["verification_runs"], 3)
        self.assertTrue(summary["misc"]["candidate_only"])
        self.assertEqual(
            summary["misc"]["oracle_authority"],
            "managed_oracle_preissue_v1",
        )
        self.assertEqual(
            summary["misc"]["oracle_preissue_status"],
            "consumed",
        )
        self.assertTrue(summary["misc"]["one_shot_consumed"])
        self.assertTrue(
            summary["misc"]["transform_evidence_passed"]
        )
        self.assertEqual(summary["misc"]["submissions"], 0)
        self.assertEqual(summary["misc"]["network"], "none")


if __name__ == "__main__":
    unittest.main()
