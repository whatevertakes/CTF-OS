from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY = Path(__file__).resolve().parent.parent
SCRIPT = (
    REPOSITORY
    / "scripts"
    / "check-web-active-probe-docker-hotpath.py"
)
SPEC = importlib.util.spec_from_file_location(
    "ctfos_web_active_probe_docker_hotpath",
    SCRIPT,
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load Web active-probe Docker hotpath")
release = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release
SPEC.loader.exec_module(release)


class WebActiveProbeReleaseTests(unittest.TestCase):
    @staticmethod
    def _target_log(mode: str) -> str:
        race = [
            {
                "active_at_entry": 2 if ordinal == 1 else 1,
                "kind": "race",
                "max_active": 2,
                "mode": mode,
                "status": (
                    200
                    if mode == "vulnerable" and ordinal % 2
                    else 409
                ),
            }
            for ordinal in range(1, 7)
        ]
        oob = [
            {
                "called_back": mode == "vulnerable",
                "kind": "oob",
                "mode": mode,
                "status": 202 if mode == "vulnerable" else 403,
            }
            for _ordinal in range(1, 4)
        ]
        return "".join(
            json.dumps(item, separators=(",", ":"), sort_keys=True)
            for item in (*race, *oob)
        )

    def test_release_smoke_is_public_internal_and_not_faked(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("engine.prove_web_active_probe(", source)
        self.assertIn("engine.validate_web_active_probe(", source)
        self.assertIn('docker_network=network', source)
        self.assertIn('"--internal"', source)
        self.assertIn('("network", "inspect", network)', source)
        self.assertIn('mode="race"', source)
        self.assertIn('mode="oob"', source)
        self.assertIn("validate_web_active_probe_state_graph(final)", source)
        self.assertIn('"ctfos.web.active_probe.docker_release.v1"', source)
        self.assertNotIn("FakeSandbox", source)
        self.assertNotIn("mock.patch", source)
        self.assertNotIn("record_candidate(", source)
        self.assertNotIn("submit_candidate", source)
        self.assertNotIn("select_next_challenge", source)

    def test_network_audit_rejects_non_internal_network(self) -> None:
        inspected = subprocess.CompletedProcess(
            args=("docker", "network", "inspect"),
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "Internal": False,
                        "Name": "ctfos-web-active-test",
                    }
                ]
            ),
            stderr="",
        )
        with mock.patch.object(release, "_docker", return_value=inspected):
            with self.assertRaisesRegex(
                AssertionError,
                "not the requested internal network",
            ):
                release._inspect_internal_network(
                    "ctfos-web-active-test"
                )

    def test_network_audit_fails_closed_when_inspection_is_refused(
        self,
    ) -> None:
        with mock.patch.object(
            release,
            "_docker",
            side_effect=RuntimeError("docker inspect refused"),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "inspect refused",
            ):
                release._inspect_internal_network(
                    "ctfos-web-active-test"
                )

    def test_target_audit_accepts_adjacent_complete_json_objects(
        self,
    ) -> None:
        logs = {
            "vulnerable-target": self._target_log("vulnerable"),
            "control-target": self._target_log("control"),
        }

        def docker(
            argv: tuple[str, ...],
            *,
            timeout: int,
        ) -> subprocess.CompletedProcess[str]:
            self.assertEqual(argv[0], "logs")
            self.assertEqual(timeout, 30)
            return subprocess.CompletedProcess(
                args=("docker", *argv),
                returncode=0,
                stdout=logs[argv[1]],
                stderr="",
            )

        with mock.patch.object(release, "_docker", side_effect=docker):
            self.assertEqual(
                release._audit_targets(
                    "vulnerable-target",
                    "control-target",
                ),
                {
                    "control_oob_callbacks": 0,
                    "control_race_requests": 6,
                    "maximum_parallel_race_requests": 2,
                    "vulnerable_oob_callbacks": 3,
                    "vulnerable_race_requests": 6,
                },
            )

    def test_target_event_stream_rejects_hostile_extra_data(
        self,
    ) -> None:
        valid = json.dumps(
            {
                "kind": "race",
                "max_active": 2,
                "status": 200,
            },
            separators=(",", ":"),
        )
        for suffix in (
            "trailing-garbage",
            "[]",
            '{"kind":"race","kind":"oob"}',
            '{"kind":NaN}',
        ):
            with self.subTest(suffix=suffix):
                with self.assertRaisesRegex(
                    AssertionError,
                    "target audit log",
                ):
                    release._parse_target_event_stream(
                        valid + suffix,
                        container_name="hostile-target",
                    )

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
        self.assertEqual(
            summary["network"],
            {
                "external_internet": False,
                "internal": True,
                "name": summary["network"]["name"],
            },
        )
        self.assertTrue(
            summary["network"]["name"].startswith(
                "ctfos-web-active-"
            )
        )
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
