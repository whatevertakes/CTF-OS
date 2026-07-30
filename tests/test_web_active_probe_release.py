from __future__ import annotations

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
    / "check-web-active-probe-docker-hotpath.py"
)


class WebActiveProbeReleaseTests(unittest.TestCase):
    def test_release_smoke_is_public_internal_and_not_faked(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("engine.prove_web_active_probe(", source)
        self.assertIn("engine.validate_web_active_probe(", source)
        self.assertIn('docker_network=network', source)
        self.assertIn('"--internal"', source)
        self.assertIn('mode="race"', source)
        self.assertIn('mode="oob"', source)
        self.assertIn("validate_web_active_probe_state_graph(final)", source)
        self.assertIn('"ctfos.web.active_probe.docker_release.v1"', source)
        self.assertNotIn("FakeSandbox", source)
        self.assertNotIn("mock.patch", source)
        self.assertNotIn("record_candidate(", source)
        self.assertNotIn("submit_candidate", source)
        self.assertNotIn("select_next_challenge", source)

    @unittest.skipUnless(
        os.environ.get("CTFOS_RUN_WEB_ACTIVE_DOCKER") == "1"
        and bool(os.environ.get("CTFOS_WEB_ACTIVE_IMAGE_DIGEST")),
        "set CTFOS_RUN_WEB_ACTIVE_DOCKER=1 and image digest for Docker",
    )
    def test_real_race_and_oob_docker_gate(self) -> None:
        image_digest = os.environ["CTFOS_WEB_ACTIVE_IMAGE_DIGEST"]
        completed = subprocess.run(
            (
                sys.executable,
                str(SCRIPT),
                "--image-digest",
                image_digest,
            ),
            cwd=REPOSITORY,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            text=True,
            timeout=900,
        )
        if completed.returncode != 0:
            self.fail(
                "real Web active-probe Docker gate failed:\n"
                + completed.stdout[-4096:]
                + completed.stderr[-4096:]
            )
        summary = json.loads(completed.stdout.splitlines()[-1])
        self.assertEqual(
            summary["protocol"],
            "ctfos.web.active_probe.docker_release.v1",
        )
        self.assertFalse(summary["external_network"])
        self.assertEqual(summary["automatic_submission_count"], 0)
        for mode in ("race", "oob"):
            self.assertEqual(summary[mode]["mode"], mode)
            self.assertEqual(summary[mode]["replay_count"], 6)
            self.assertEqual(summary[mode]["executed_fact_count"], 1)
            self.assertEqual(summary[mode]["candidate_count"], 0)
            self.assertEqual(summary[mode]["submission_count"], 0)
        self.assertGreaterEqual(
            summary["target_audit"][
                "maximum_parallel_race_requests"
            ],
            2,
        )
        self.assertEqual(
            summary["target_audit"]["vulnerable_oob_callbacks"],
            3,
        )
        self.assertEqual(
            summary["target_audit"]["control_oob_callbacks"],
            0,
        )


if __name__ == "__main__":
    unittest.main()
