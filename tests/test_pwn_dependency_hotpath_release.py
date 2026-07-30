from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parent.parent
SCRIPT = (
    REPOSITORY
    / "scripts"
    / "check-pwn-dependency-hotpath-docker.py"
)
SINGLE = (
    REPOSITORY
    / "scripts"
    / "check-pwn-exploit-effect-hotpath-docker.py"
)
SPEC = importlib.util.spec_from_file_location(
    "ctfos_pwn_dependency_release",
    SCRIPT,
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load Pwn dependency release proof")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class PwnDependencyHotPathReleaseTests(unittest.TestCase):
    def test_release_gate_is_pinned_three_way_and_parallel(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(release.REPETITIONS, 3)
        self.assertEqual(
            release.RELEASE_IMAGE_DIGEST,
            "sha256:"
            "f39d2216ddaa93fae3134014b25be0609096bacd8648b1621121787db6196338",
        )
        self.assertIn("ThreadPoolExecutor", source)
        self.assertIn("DEPENDENCY_SCOPED_NOT_APPLICABLE", source)
        self.assertIn("tamper_control_rejected", source)
        self.assertIn('"network": "none"', source)

    def test_single_proof_binds_physical_query_and_rehashed_control(
        self,
    ) -> None:
        source = SINGLE.read_text(encoding="utf-8")
        self.assertIn("engine.validate_pwn_dependency_graph", source)
        self.assertIn(
            "validate_pwn_dependency_state_graph(tampered)",
            source,
        )
        self.assertIn('"candidates": 0', source)
        self.assertIn('"submissions": 0', source)
        self.assertNotIn("submit_candidate", source)


if __name__ == "__main__":
    unittest.main()
