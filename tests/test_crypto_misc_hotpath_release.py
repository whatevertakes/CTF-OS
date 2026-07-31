from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ctf_os.models import RunStatus


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
            "f39d2216ddaa93fae3134014b25be0609096bacd8648b1621121787db6196338",
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
        plan_sha256 = "b" * 64
        image_digest = release.RELEASE_IMAGE_DIGEST
        run_ids = [f"crypto-run-{ordinal}" for ordinal in range(1, 7)]
        with tempfile.TemporaryDirectory() as temporary:
            challenge_root = Path(temporary)
            runs = []
            for ordinal, run_id in enumerate(run_ids, start=1):
                run_root = challenge_root / "runs" / run_id
                run_root.mkdir(parents=True)
                documents = {
                    "request.json": {
                        "attempt": {"ordinal": ordinal},
                        "candidate_id": "C-crypto",
                        "image_reference": image_digest,
                        "kind": "crypto_metamorphic_proof",
                        "network_target": None,
                        "plan_sha256": plan_sha256,
                        "protocol": (
                            release.CRYPTO_METAMORPHIC_PROOF_PROTOCOL
                        ),
                        "source_manifest_sha256": source_manifest,
                    },
                    "result.json": {
                        "exit_code": 0,
                        "observation": {
                            "capture_complete": True,
                            "ctfwrap_exit_code": 0,
                            "orchestration_status": "completed",
                            "ordinal": ordinal,
                            "run_id": run_id,
                            "runner_exit_code": 0,
                            "timed_out": False,
                            "truncated": False,
                            "truncation_known": True,
                        },
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
                        status=RunStatus.COMPLETED,
                        role="crypto_metamorphic_proof",
                        request_path=f"runs/{run_id}/request.json",
                        result_path=f"runs/{run_id}/result.json",
                        validation_path=f"runs/{run_id}/validation.json",
                        extra={
                            "attempt_ordinal": ordinal,
                            "crypto_metamorphic_protocol": (
                                release.CRYPTO_METAMORPHIC_PROOF_PROTOCOL
                            ),
                            "plan_sha256": plan_sha256,
                        },
                    )
                )
            candidate = SimpleNamespace(
                id="C-crypto",
                value="KCTF{candidate}",
                proof_run_ids=list(run_ids),
            )
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
                "plan_sha256": plan_sha256,
                "proof_result": proof_result,
                "run_ids": list(run_ids),
            }
            final = SimpleNamespace(
                metadata={"source_manifest_sha256": source_manifest},
                runs=runs,
            )

            physical, successful = release._validated_crypto_execution(
                final,
                candidate,
                binding,
                challenge_root=challenge_root,
                image_digest=image_digest,
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
                )

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
