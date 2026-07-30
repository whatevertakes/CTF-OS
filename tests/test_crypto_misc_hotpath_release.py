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
            "62bc44f2b84ccaa86cb5321ff700b73c42edd8b901c21cd61cfb3036bd985886",
        )
        self.assertIn(
            "engine.prove_crypto_metamorphic_candidate(",
            source,
        )
        self.assertIn(
            "engine.evaluate_misc_transform_candidate(",
            source,
        )
        self.assertIn('runtime="python"', source)
        self.assertIn('runtime="sage"', source)
        self.assertIn('network_default="none"', source)
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
            self.assertEqual(result["runtime"], runtime)
            self.assertEqual(result["runs"], 6)
            self.assertEqual(result["successful_attempts"], 6)
            self.assertEqual(result["candidate_status"], "READY_TO_SUBMIT")
            self.assertEqual(result["submissions"], 0)
            self.assertEqual(result["network"], "none")
        self.assertEqual(summary["misc"]["runs"], 4)
        self.assertTrue(
            summary["misc"]["transform_evidence_passed"]
        )
        self.assertEqual(summary["misc"]["submissions"], 0)
        self.assertEqual(summary["misc"]["network"], "none")


if __name__ == "__main__":
    unittest.main()
