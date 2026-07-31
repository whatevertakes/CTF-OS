from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path

from tests import test_web_impact_hotpath as hotpath


REPOSITORY = Path(__file__).resolve().parent.parent
SCRIPT = REPOSITORY / "scripts" / "check-web-impact-docker-hotpath.py"
SPEC = importlib.util.spec_from_file_location(
    "ctfos_web_impact_docker_hotpath",
    SCRIPT,
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load Web impact Docker hotpath")
release = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release
SPEC.loader.exec_module(release)


class WebImpactReleaseTests(unittest.TestCase):
    def test_target_stream_is_bounded_and_exact(self) -> None:
        adjacent = "".join(
            json.dumps(
                {
                    "accepted": True,
                    "mode": "vulnerable",
                    "path": f"/route-{index}",
                    "status": 200,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
            for index in range(3)
        )
        self.assertEqual(
            len(
                release._parse_target_event_stream(
                    adjacent,
                    mode="vulnerable",
                )
            ),
            3,
        )
        valid = json.dumps(
            {
                "accepted": True,
                "mode": "vulnerable",
                "path": "/extract",
                "status": 200,
            },
            separators=(",", ":"),
        )
        for suffix in (
            "trailing-garbage",
            "[]",
            '{"path":"one","path":"two"}',
            '{"status":NaN}',
        ):
            with self.subTest(suffix=suffix):
                with self.assertRaisesRegex(
                    AssertionError,
                    "target audit",
                ):
                    release._parse_target_event_stream(
                        valid + suffix,
                        mode="vulnerable",
                    )
        with self.assertRaisesRegex(AssertionError, "byte limit"):
            release._parse_target_event_stream(
                " " * (release.TARGET_AUDIT_LOG_MAX_BYTES + 1),
                mode="vulnerable",
            )
        with self.assertRaisesRegex(AssertionError, "event limit"):
            release._parse_target_event_stream(
                valid * (release.TARGET_AUDIT_LOG_MAX_EVENTS + 1),
                mode="vulnerable",
            )

    def test_physical_revalidation_rejects_all_sidecar_rewrites(
        self,
    ) -> None:
        case = hotpath.WebImpactHotPathTests()
        case.setUp()
        try:
            state, evaluation = case._prove()
            canonical, counts = release._revalidate_physical_web_impact(
                case.engine,
                case.identity,
                evaluation_sha256=evaluation.sha256,
                expected_replay_count=3,
            )
            self.assertEqual(canonical.revision, state.revision)
            self.assertEqual(
                counts,
                {
                    "physical_artifacts": 28,
                    "physical_run_sidecars": 9,
                    "physical_transport_receipts": 3,
                },
            )
            challenge_root = case.engine.store.challenge_paths(
                case.identity
            ).root
            run = state.runs[-1]
            hostile = {
                "exit_code": 99,
                "ok": False,
                "reused_run_id": state.runs[0].id,
                "status": "failed",
                "timed_out": True,
            }
            for attribute in (
                "request_path",
                "result_path",
                "validation_path",
            ):
                relative = getattr(run, attribute)
                self.assertIsNotNone(relative)
                path = challenge_root / relative
                original = path.read_bytes()
                os.chmod(path, 0o600)
                path.write_text(
                    json.dumps(hostile, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                os.chmod(path, 0o400)
                with self.subTest(attribute=attribute):
                    with self.assertRaisesRegex(
                        AssertionError,
                        "physical|canonical",
                    ):
                        release._revalidate_physical_web_impact(
                            case.engine,
                            case.identity,
                            evaluation_sha256=evaluation.sha256,
                            expected_replay_count=3,
                        )
                os.chmod(path, 0o600)
                path.write_bytes(original)
                os.chmod(path, 0o400)
        finally:
            case.tearDown()

    def test_physical_revalidation_rejects_deleted_committed_artifact(
        self,
    ) -> None:
        case = hotpath.WebImpactHotPathTests()
        case.setUp()
        try:
            state, evaluation = case._prove()
            challenge_root = case.engine.store.challenge_paths(
                case.identity
            ).root
            artifact = next(
                item
                for item in state.artifacts
                if item.extra.get("kind")
                == "web_impact_execution_evaluation"
            )
            path = challenge_root / artifact.path
            os.chmod(path, 0o600)
            path.unlink()
            with self.assertRaisesRegex(
                AssertionError,
                "artifact revalidation",
            ):
                release._revalidate_physical_web_impact(
                    case.engine,
                    case.identity,
                    evaluation_sha256=evaluation.sha256,
                    expected_replay_count=3,
                )
        finally:
            case.tearDown()


if __name__ == "__main__":
    unittest.main()
