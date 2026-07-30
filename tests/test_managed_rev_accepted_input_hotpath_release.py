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
    / "check-managed-rev-accepted-input-hotpath-docker.py"
)
SPEC = importlib.util.spec_from_file_location(
    "ctfos_managed_rev_accepted_input_release",
    SCRIPT,
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load managed Rev release proof")
release = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release
SPEC.loader.exec_module(release)


class ManagedRevAcceptedInputReleaseTests(unittest.TestCase):
    def test_release_path_is_pinned_candidate_free_and_not_faked(
        self,
    ) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(
            release.RELEASE_IMAGE_DIGEST,
            "sha256:"
            "82ef8c155a8bbe9cfe33ce1a475425c77097b6fcefc32b678da1b14bf9c8339a",
        )
        self.assertIn("ManagedOrchestrator(engine).run_cycle(", source)
        self.assertIn('"kind": "rev_accepted_input"', source)
        self.assertIn('network_default="none"', source)
        self.assertIn("validate_rev_acceptance_state_graph(state)", source)
        self.assertIn("state.candidates", source)
        self.assertIn("state.submissions", source)
        self.assertNotIn("FakeSandbox", source)
        self.assertNotIn("mock.patch", source)
        self.assertNotIn("record_candidate(", source)
        self.assertNotIn("submit_candidate", source)

    @unittest.skipUnless(
        os.environ.get("CTFOS_RUN_MANAGED_REV_ACCEPTANCE_DOCKER") == "1",
        "set CTFOS_RUN_MANAGED_REV_ACCEPTANCE_DOCKER=1 for real Docker",
    )
    def test_real_managed_docker_gate(self) -> None:
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
            timeout=900,
        )
        if completed.returncode != 0:
            self.fail(
                "real managed Rev Docker gate failed:\n"
                + completed.stdout[-4096:]
                + completed.stderr[-4096:]
            )
        summary = json.loads(completed.stdout.splitlines()[-1])
        self.assertTrue(summary["ok"])
        self.assertEqual(
            summary["managed_action"],
            "rev_accepted_input",
        )
        self.assertEqual(summary["runs"], 6)
        self.assertEqual(summary["receipts"], 6)
        self.assertEqual(summary["fact_count"], 1)
        self.assertEqual(summary["progress_count"], 1)
        self.assertEqual(summary["candidates"], 0)
        self.assertEqual(summary["submissions"], 0)
        self.assertEqual(summary["network"], "none")
        self.assertEqual(
            summary["image_digest"],
            release.RELEASE_IMAGE_DIGEST,
        )


if __name__ == "__main__":
    unittest.main()
