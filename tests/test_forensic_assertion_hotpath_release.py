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


REPOSITORY = Path(__file__).resolve().parent.parent
SCRIPT = (
    REPOSITORY
    / "scripts"
    / "check-forensic-assertion-hotpath-docker.py"
)
SPEC = importlib.util.spec_from_file_location(
    "ctfos_forensic_assertion_hotpath_release",
    SCRIPT,
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load Forensic assertion release proof")
release = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release
SPEC.loader.exec_module(release)


class ForensicAssertionHotPathReleaseTests(unittest.TestCase):
    def test_fixture_has_two_exact_independent_range_readers(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ctfos-forensic-assertion-fixture-"
        ) as temporary:
            source = Path(temporary) / "evidence.bin"
            selected = b"private-release-range"
            payload = b"prefix|" + selected + b"|suffix"
            source.write_bytes(payload)
            expected_sha256 = hashlib.sha256(payload).hexdigest()
            observed = {
                algorithm: release.fixture.read_exact_range(
                    source,
                    algorithm=algorithm,
                    offset=len(b"prefix|"),
                    length=len(selected),
                    expected_sha256=expected_sha256,
                )
                for algorithm in ("descriptor", "mmap")
            }
            self.assertEqual(
                observed,
                {
                    "descriptor": selected,
                    "mmap": selected,
                },
            )
            source.write_bytes(b"changed" + payload[7:])
            for algorithm in ("descriptor", "mmap"):
                with self.assertRaises(release.fixture.FixtureError):
                    release.fixture.read_exact_range(
                        source,
                        algorithm=algorithm,
                        offset=len(b"prefix|"),
                        length=len(selected),
                        expected_sha256=expected_sha256,
                    )

    def test_tool_versions_bind_algorithm_and_negative_control(self) -> None:
        source = release.FIXTURE_SOURCE.read_bytes()
        descriptor = release.fixture.tool_version_sha256(
            source,
            algorithm="descriptor",
            corrupt_binding=False,
        )
        mapped = release.fixture.tool_version_sha256(
            source,
            algorithm="mmap",
            corrupt_binding=False,
        )
        control = release.fixture.tool_version_sha256(
            source,
            algorithm="mmap",
            corrupt_binding=True,
        )
        self.assertEqual(len({descriptor, mapped, control}), 3)
        self.assertTrue(
            all(
                len(value) == 64
                and set(value) <= set("0123456789abcdef")
                for value in (descriptor, mapped, control)
            )
        )

    def test_release_proof_is_public_hard_pinned_and_networkless(
        self,
    ) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(
            release.RELEASE_IMAGE_DIGEST,
            "sha256:"
            "f39d2216ddaa93fae3134014b25be0609096bacd8648b1621121787db6196338",
        )
        self.assertEqual(release.POSITIVE_REPETITIONS, 3)
        self.assertIn("engine._sandbox_factory = None", source)
        self.assertIn("engine.prove_forensic_assertion(", source)
        self.assertIn("NetworkPolicy.deny_all()", source)
        self.assertIn('"network": "none"', source)
        self.assertIn("_challenge_containers", source)
        self.assertNotIn("FakeSandbox", source)
        self.assertNotIn("submit_candidate", source)
        self.assertNotIn("network_target=", source.replace(
            "network_target=None", ""
        ))

    @unittest.skipUnless(
        os.environ.get("CTFOS_RUN_FORENSIC_ASSERTION_DOCKER") == "1",
        "set CTFOS_RUN_FORENSIC_ASSERTION_DOCKER=1 for the real Docker gate",
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
        self.assertEqual(summary["sandbox"], "production_real_docker")
        self.assertEqual(summary["network"], "none")
        self.assertEqual(summary["cleanup"], "verified")
        self.assertEqual(len(summary["confirmed"]), 3)
        self.assertFalse(summary["control"]["confirmed"])
        self.assertEqual(summary["assertion_facts"], 3)
        self.assertEqual(summary["assertion_progress"], 3)
        self.assertEqual(summary["candidates"], 0)
        self.assertEqual(summary["submissions"], 0)


if __name__ == "__main__":
    unittest.main()
