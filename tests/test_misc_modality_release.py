from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parent.parent
SCRIPT = REPOSITORY / "scripts" / "check-misc-modality-intake-docker.py"
SPEC = importlib.util.spec_from_file_location(
    "ctfos_misc_modality_release",
    SCRIPT,
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load Misc modality release proof")
release = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release
SPEC.loader.exec_module(release)


class MiscModalityReleaseTests(unittest.TestCase):
    def test_release_proof_is_three_way_pinned_and_networkless(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(
            release.RELEASE_IMAGE_DIGEST,
            "sha256:"
            "82ef8c155a8bbe9cfe33ce1a475425c77097b6fcefc32b678da1b14bf9c8339a",
        )
        self.assertEqual(
            release.PROBE_IDS,
            ("typed_inventory", "primary_magic", "primary_strings"),
        )
        self.assertIn("engine._sandbox_factory = None", source)
        self.assertIn("network_default=\"none\"", source)
        self.assertIn("orchestrator._execute_selected_actions(", source)
        self.assertIn("stego=0.35", source)
        self.assertIn("custom_protocol=0.25", source)
        self.assertNotIn("FakeSandbox", source)
        self.assertNotIn("submit_candidate", source)
        self.assertNotIn("record_manual_submission", source)

    @unittest.skipUnless(
        os.environ.get("CTFOS_RUN_MISC_MODALITY_DOCKER") == "1",
        "set CTFOS_RUN_MISC_MODALITY_DOCKER=1 for the real Docker gate",
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
        self.assertEqual(summary["probe_runs"], 3)
        self.assertEqual(summary["probe_ids"], list(release.PROBE_IDS))
        self.assertEqual(summary["network"], "none")
        self.assertEqual(summary["candidates"], 0)
        self.assertEqual(summary["submissions"], 0)


if __name__ == "__main__":
    unittest.main()
