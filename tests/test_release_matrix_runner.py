from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY = Path(__file__).resolve().parent.parent
SCRIPT = REPOSITORY / "scripts" / "check-all-category-release-matrix.py"
SPEC = importlib.util.spec_from_file_location(
    "ctfos_all_category_release_matrix",
    SCRIPT,
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load all-category release matrix")
release = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release
SPEC.loader.exec_module(release)


IMAGE_DIGEST = "sha256:" + "a" * 64


class ReleaseMatrixRunnerTests(unittest.TestCase):
    def test_closed_inventory_covers_every_category_without_selection(self) -> None:
        covered = {
            category
            for task in release.RELEASE_TASKS
            for category in task.categories
        }
        self.assertEqual(
            covered,
            {"pwn", "web", "rev", "crypto", "forensics", "misc"},
        )
        self.assertEqual(len(release.RELEASE_TASKS), 6)
        self.assertEqual(
            sum(task.categories == ("web",) for task in release.RELEASE_TASKS),
            2,
        )
        self.assertEqual(
            {
                task.id
                for task in release.RELEASE_TASKS
                if task.categories == ("web",)
            },
            {"web_state_impact", "web_active_probe"},
        )
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("challenge-name", source)
        self.assertNotIn("challenge_name", source)
        self.assertNotIn("submit_candidate", source)
        self.assertNotIn("record_manual_submission", source)
        self.assertNotIn("codex exec", source)
        self.assertNotIn("openai", source.lower())

    def test_command_contract_is_stable_and_declares_local_networks(self) -> None:
        contract = release._command_contract()
        self.assertEqual(
            set(contract),
            {"protocol", "schema_version", "tasks"},
        )
        self.assertEqual(contract["protocol"], release.PROTOCOL)
        self.assertEqual(contract["schema_version"], 1)
        tasks = contract["tasks"]
        self.assertEqual(
            [item["id"] for item in tasks],
            [task.id for task in release.RELEASE_TASKS],
        )
        self.assertTrue(
            all(
                item["network_contract"]
                in {"none", "docker_internal_local_targets"}
                for item in tasks
            )
        )
        self.assertTrue(
            all(item["script"].startswith("scripts/check-") for item in tasks)
        )

    def test_capture_is_bounded_but_hashes_the_complete_stream(self) -> None:
        payload = b"prefix\n" + (b"x" * 1_000) + b"\nsummary\n"
        capture = release._BoundedCapture(limit_bytes=128)
        capture.consume(io.BytesIO(payload))
        stored = capture.payload()
        self.assertTrue(capture.truncated)
        self.assertLessEqual(len(stored), 128)
        self.assertIn(release.TRUNCATION_MARKER, stored)
        self.assertTrue(stored.startswith(b"prefix\n"))
        self.assertTrue(stored.endswith(b"\nsummary\n"))
        self.assertEqual(capture.total_bytes, len(payload))
        self.assertEqual(
            capture.metadata("stdout.log")["sha256"],
            "sha256:" + hashlib.sha256(payload).hexdigest(),
        )

    def test_small_capture_preserves_exact_bytes(self) -> None:
        payload = b'{"ok":true}\n'
        capture = release._BoundedCapture(limit_bytes=256)
        capture.consume(io.BytesIO(payload))
        self.assertFalse(capture.truncated)
        self.assertEqual(capture.payload(), payload)

    def test_summary_requires_exact_image_and_positive_gate(self) -> None:
        task = release.RELEASE_TASKS[0]
        valid = release._BoundedCapture(limit_bytes=512)
        valid.consume(
            io.BytesIO(
                json.dumps(
                    {"image_digest": IMAGE_DIGEST, "ok": True}
                ).encode("ascii")
                + b"\n"
            )
        )
        self.assertRegex(
            release._validate_child_summary(task, valid, IMAGE_DIGEST),
            r"^sha256:[0-9a-f]{64}$",
        )

        wrong = release._BoundedCapture(limit_bytes=512)
        wrong.consume(
            io.BytesIO(
                json.dumps(
                    {"image_digest": "sha256:" + "b" * 64, "ok": True}
                ).encode("ascii")
                + b"\n"
            )
        )
        with self.assertRaisesRegex(
            release.ReleaseMatrixError,
            "exact release image",
        ):
            release._validate_child_summary(task, wrong, IMAGE_DIGEST)

    def test_web_active_summary_has_a_stricter_race_and_oob_oracle(self) -> None:
        task = next(
            item
            for item in release.RELEASE_TASKS
            if item.id == "web_active_probe"
        )
        summary = {
            "automatic_submission_count": 0,
            "external_network": False,
            "image_digest": IMAGE_DIGEST,
            "oob": {
                "candidate_count": 0,
                "mode": "oob",
                "replay_count": 6,
                "submission_count": 0,
            },
            "protocol": "ctfos.web.active_probe.docker_release.v1",
            "race": {
                "candidate_count": 0,
                "mode": "race",
                "replay_count": 6,
                "submission_count": 0,
            },
            "schema_version": 1,
        }
        capture = release._BoundedCapture(limit_bytes=2_048)
        capture.consume(
            io.BytesIO(
                json.dumps(summary, sort_keys=True).encode("ascii") + b"\n"
            )
        )
        release._validate_child_summary(task, capture, IMAGE_DIGEST)
        summary["race"]["replay_count"] = 5
        rejected = release._BoundedCapture(limit_bytes=2_048)
        rejected.consume(
            io.BytesIO(
                json.dumps(summary, sort_keys=True).encode("ascii") + b"\n"
            )
        )
        with self.assertRaisesRegex(
            release.ReleaseMatrixError,
            "race/OOB oracle",
        ):
            release._validate_child_summary(task, rejected, IMAGE_DIGEST)

    def test_child_environment_drops_secret_and_model_credentials(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "OPENAI_API_KEY": "must-not-propagate",
                "CTF_PASSWORD": "must-not-propagate",
                "PATH": "/usr/bin",
                "PYTHONPATH": "/existing",
                "SAFE_SETTING": "yes",
            },
            clear=True,
        ):
            environment = release._child_environment()
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertNotIn("CTF_PASSWORD", environment)
        self.assertEqual(environment["PATH"], "/usr/bin")
        self.assertEqual(environment["SAFE_SETTING"], "yes")
        self.assertEqual(environment["CTFOS_RELEASE_MATRIX"], "1")
        self.assertEqual(
            environment["PYTHONPATH"],
            str(REPOSITORY) + os.pathsep + "/existing",
        )

    def test_real_local_child_records_exact_command_hashes_and_pointers(
        self,
    ) -> None:
        ignored_root = REPOSITORY / ".ctfos"
        ignored_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="release-matrix-unit-",
            dir=ignored_root,
        ) as temporary:
            root = Path(temporary)
            helper = root / "helper.py"
            helper.write_text(
                "import json, sys\n"
                "print('diagnostic', file=sys.stderr)\n"
                "print(json.dumps({'image_digest': sys.argv[2], "
                "'ok': True}, sort_keys=True))\n",
                encoding="utf-8",
            )
            task = release.ReleaseTask(
                id="unit_gate",
                categories=("misc",),
                script=str(helper.relative_to(REPOSITORY)),
                network_contract="none",
            )
            artifacts = root / "artifacts"
            artifacts.mkdir()
            result = release._run_task(
                task,
                image_digest=IMAGE_DIGEST,
                artifact_root=artifacts,
                timeout_seconds=60,
            )
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(
                result["command"],
                [
                    sys.executable,
                    str(helper),
                    "--image-digest",
                    IMAGE_DIGEST,
                ],
            )
            self.assertRegex(
                result["stdout"]["sha256"],
                r"^sha256:[0-9a-f]{64}$",
            )
            self.assertTrue(
                (artifacts / result["stdout"]["locator"]).is_file()
            )
            self.assertTrue(
                (artifacts / result["stderr"]["locator"]).is_file()
            )

    def test_cli_has_bounded_parallelism_and_timeout(self) -> None:
        parsed = release._parse_args(
            ["--image-digest", IMAGE_DIGEST]
        )
        self.assertEqual(parsed.jobs, release.DEFAULT_JOBS)
        self.assertEqual(
            parsed.timeout_seconds,
            release.DEFAULT_TIMEOUT_SECONDS,
        )
        with self.assertRaises(SystemExit):
            release._parse_args(
                [
                    "--image-digest",
                    IMAGE_DIGEST,
                    "--jobs",
                    str(release.MAX_JOBS + 1),
                ]
            )
        with self.assertRaises(SystemExit):
            release._parse_args(
                [
                    "--image-digest",
                    IMAGE_DIGEST,
                    "--timeout-seconds",
                    str(release.MIN_TIMEOUT_SECONDS - 1),
                ]
            )


if __name__ == "__main__":
    unittest.main()
