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
    def test_python_fixture_has_two_exact_range_reader_modes(self) -> None:
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

    def test_tool_versions_bind_physical_executables_not_mode_labels(
        self,
    ) -> None:
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
        self.assertEqual(
            {descriptor, mapped, control},
            {release.PYTHON_EXECUTABLE_SHA256},
        )
        self.assertNotEqual(
            release.PYTHON_EXECUTABLE_SHA256,
            release.PERL_EXECUTABLE_SHA256,
        )
        self.assertTrue(
            all(
                len(value) == 64
                and set(value) <= set("0123456789abcdef")
                for value in (
                    descriptor,
                    mapped,
                    control,
                    release.PERL_EXECUTABLE_SHA256,
                )
            )
        )
        self.assertNotEqual(
            hashlib.sha256(release.FIXTURE_SOURCE.read_bytes()).hexdigest(),
            hashlib.sha256(
                release.PERL_FIXTURE_SOURCE.read_bytes()
            ).hexdigest(),
        )

    def test_release_proof_is_public_hard_pinned_and_networkless(
        self,
    ) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(
            release.RELEASE_IMAGE_DIGEST,
            "sha256:"
            "514ab5c51489f9bb66dccb4b5f2c4c86eac64711b89083e3a4ff50eb19910be9",
        )
        self.assertEqual(release.POSITIVE_REPETITIONS, 3)
        self.assertIn("engine._sandbox_factory = None", source)
        self.assertIn("engine.prove_forensic_assertion(", source)
        self.assertIn("engine.store.load(identity, recover=False)", source)
        self.assertIn("engine.store.verify_artifacts(identity)", source)
        self.assertIn("_physical_assertion_execution(", source)
        self.assertIn("PERL_FIXTURE_SOURCE", source)
        self.assertIn("PYTHON_EXECUTABLE_SHA256", source)
        self.assertIn("PERL_EXECUTABLE_SHA256", source)
        self.assertIn("NetworkPolicy.deny_all()", source)
        self.assertIn('"network": "none"', source)
        self.assertIn("_challenge_containers", source)
        self.assertNotIn("FakeSandbox", source)
        self.assertNotIn("submit_candidate", source)
        self.assertNotIn("network_target=", source.replace(
            "network_target=None", ""
        ))

    def test_unreferenced_sidecar_reader_is_bounded_and_nofollow(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ctfos-forensic-bounded-sidecar-"
        ) as temporary:
            root = Path(temporary)
            (root / "runs").mkdir()
            payload = b'{"ok":true}\n'
            (root / "runs" / "validation.json").write_bytes(payload)
            self.assertEqual(
                release._read_unreferenced(
                    root,
                    "runs/validation.json",
                    maximum_bytes=len(payload),
                ),
                payload,
            )
            with self.assertRaisesRegex(
                AssertionError,
                "exceeded its bound",
            ):
                release._read_unreferenced(
                    root,
                    "runs/validation.json",
                    maximum_bytes=len(payload) - 1,
                )
            (root / "runs" / "link.json").symlink_to(
                root / "runs" / "validation.json"
            )
            with self.assertRaisesRegex(
                AssertionError,
                "could not be read safely",
            ):
                release._read_unreferenced(
                    root,
                    "runs/link.json",
                    maximum_bytes=len(payload),
                )

    @unittest.skipUnless(
        os.environ.get("CTFOS_RUN_FORENSIC_ASSERTION_DOCKER") == "1",
        "set CTFOS_RUN_FORENSIC_ASSERTION_DOCKER=1 for the real Docker gate",
    )
    def test_gate_rejects_postcommit_sidecar_rewrite(self) -> None:
        original = release.ChallengeEngine.prove_forensic_assertion

        def hostile(engine, identity, **kwargs):
            state, evaluation = original(engine, identity, **kwargs)
            attempts = state.extra["forensic_assertion_preissues"]
            attempt = next(
                item
                for item in attempts.values()
                if item.get("terminal", {}).get("evaluation_sha256")
                == evaluation.sha256
            )
            root = engine.store.challenge_paths(identity).root
            for request in attempt["requests"]:
                path = (
                    root
                    / "runs"
                    / request["run_id"]
                    / "forensic-assertion"
                    / "result.json"
                )
                path.chmod(0o600)
                document = json.loads(path.read_text(encoding="utf-8"))
                document["sandbox"]["status"] = "failed"
                path.write_bytes(release._canonical(document))
                path.chmod(0o400)
            return state, evaluation

        release.ChallengeEngine.prove_forensic_assertion = hostile
        try:
            with tempfile.TemporaryDirectory(
                prefix="ctfos-forensic-hostile-sidecar-"
            ) as temporary:
                with self.assertRaisesRegex(
                    AssertionError,
                    "Forensic physical sidecar 1 is not successful",
                ):
                    release._run_release(
                        Path(temporary),
                        release.ChallengeIdentity(
                            "release-smoke",
                            "forensics",
                            "hostile-sidecar",
                        ),
                        release.RELEASE_IMAGE_DIGEST,
                        b"CTFOS_PRIVATE_RANGE_hostile_sidecar",
                    )
        finally:
            release.ChallengeEngine.prove_forensic_assertion = original

    @unittest.skipUnless(
        os.environ.get("CTFOS_RUN_FORENSIC_ASSERTION_DOCKER") == "1",
        "set CTFOS_RUN_FORENSIC_ASSERTION_DOCKER=1 for the real Docker gate",
    )
    def test_gate_rejects_postcommit_artifact_deletion(self) -> None:
        original = release.ChallengeEngine.prove_forensic_assertion

        def hostile(engine, identity, **kwargs):
            state, evaluation = original(engine, identity, **kwargs)
            attempts = state.extra["forensic_assertion_preissues"]
            attempt = next(
                item
                for item in attempts.values()
                if item.get("terminal", {}).get("evaluation_sha256")
                == evaluation.sha256
            )
            artifact_id = attempt["expected_state_ids"][
                "evaluation_artifact_id"
            ]
            artifact = next(
                item for item in state.artifacts if item.id == artifact_id
            )
            root = engine.store.challenge_paths(identity).root
            (root / artifact.path).unlink()
            return state, evaluation

        release.ChallengeEngine.prove_forensic_assertion = hostile
        try:
            with tempfile.TemporaryDirectory(
                prefix="ctfos-forensic-hostile-artifact-"
            ) as temporary:
                with self.assertRaises((OSError, ValueError)):
                    release._run_release(
                        Path(temporary),
                        release.ChallengeIdentity(
                            "release-smoke",
                            "forensics",
                            "hostile-artifact",
                        ),
                        release.RELEASE_IMAGE_DIGEST,
                        b"CTFOS_PRIVATE_RANGE_hostile_artifact",
                    )
        finally:
            release.ChallengeEngine.prove_forensic_assertion = original

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
        self.assertEqual(
            {
                item["sha256"]
                for item in summary["tool_executables"].values()
            },
            {
                release.PYTHON_EXECUTABLE_SHA256,
                release.PERL_EXECUTABLE_SHA256,
            },
        )
        for item in summary["confirmed"]:
            self.assertEqual(
                item["tool_version_sha256s"],
                sorted(
                    (
                        release.PYTHON_EXECUTABLE_SHA256,
                        release.PERL_EXECUTABLE_SHA256,
                    )
                ),
            )


if __name__ == "__main__":
    unittest.main()
