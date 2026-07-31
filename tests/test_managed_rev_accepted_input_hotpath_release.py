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
            "514ab5c51489f9bb66dccb4b5f2c4c86eac64711b89083e3a4ff50eb19910be9",
        )
        self.assertIn("ManagedOrchestrator(engine).run_cycle(", source)
        self.assertIn('"kind": "rev_accepted_input"', source)
        self.assertIn('network_default="none"', source)
        self.assertIn("validate_rev_acceptance_state_graph(state)", source)
        self.assertIn("engine.store.load(identity, recover=False)", source)
        self.assertIn("engine.store.verify_artifacts(identity)", source)
        self.assertIn("_validated_physical_rev_execution(", source)
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
    def test_gate_rejects_postcommit_result_rewrite(self) -> None:
        original = release.ManagedOrchestrator.run_cycle

        def hostile(orchestrator, identity):
            state = original(orchestrator, identity)
            proof = next(
                item
                for item in state.experiments
                if "rev_acceptance_evidence" in item.result
            )
            root = orchestrator.engine.store.challenge_paths(identity).root
            for record in proof.result["rev_acceptance_evidence"]["records"]:
                path = root / record["result_path"]
                path.chmod(0o600)
                document = json.loads(path.read_text(encoding="utf-8"))
                document["status"] = "failed"
                path.write_text(
                    json.dumps(document, sort_keys=True),
                    encoding="utf-8",
                )
                path.chmod(0o400)
            return state

        saved_argv = sys.argv
        release.ManagedOrchestrator.run_cycle = hostile
        sys.argv = [
            str(SCRIPT),
            "--image-digest",
            release.RELEASE_IMAGE_DIGEST,
        ]
        try:
            with self.assertRaisesRegex(
                AssertionError,
                "Rev physical record 1 result changed",
            ):
                release.main()
        finally:
            sys.argv = saved_argv
            release.ManagedOrchestrator.run_cycle = original

    @unittest.skipUnless(
        os.environ.get("CTFOS_RUN_MANAGED_REV_ACCEPTANCE_DOCKER") == "1",
        "set CTFOS_RUN_MANAGED_REV_ACCEPTANCE_DOCKER=1 for real Docker",
    )
    def test_gate_rejects_postcommit_artifact_deletion(self) -> None:
        original = release.ManagedOrchestrator.run_cycle

        def hostile(orchestrator, identity):
            state = original(orchestrator, identity)
            proof = next(
                item
                for item in state.experiments
                if "rev_acceptance_evidence" in item.result
            )
            evidence = proof.result["rev_acceptance_evidence"]
            artifact = next(
                item
                for item in state.artifacts
                if item.id == evidence["evaluation_artifact_id"]
            )
            root = orchestrator.engine.store.challenge_paths(identity).root
            (root / artifact.path).unlink()
            return state

        saved_argv = sys.argv
        release.ManagedOrchestrator.run_cycle = hostile
        sys.argv = [
            str(SCRIPT),
            "--image-digest",
            release.RELEASE_IMAGE_DIGEST,
        ]
        try:
            with self.assertRaises((OSError, ValueError)):
                release.main()
        finally:
            sys.argv = saved_argv
            release.ManagedOrchestrator.run_cycle = original

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
