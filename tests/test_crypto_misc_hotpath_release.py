from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


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
