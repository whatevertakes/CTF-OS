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
SHA256 = "b" * 64


def _valid_summary(task_id: str) -> dict[str, object]:
    if task_id == "pwn_dependency_effect":
        return {
            "candidate_count": 0,
            "graph_ids": ["graph-1", "graph-2", "graph-3"],
            "image_digest": IMAGE_DIGEST,
            "network": "none",
            "no_leak_required_chains": 3,
            "ok": True,
            "real_clean_proofs": 48,
            "repetitions": 3,
            "submission_count": 0,
            "tamper_controls_rejected": 3,
        }
    if task_id == "web_state_impact":
        endpoint_counts = {
            "/admin": 3,
            "/extract": 3,
            "/login": 3,
            "/profile": 3,
            "/session": 3,
            "/warmup": 3,
        }
        return {
            "control_target": {
                "accepted_requests": 18,
                "endpoint_counts": endpoint_counts,
                "extract_status": 403,
            },
            "engine": {
                "automatic_submissions": 0,
                "canonical_requests_preissued": 6,
                "executed_facts": 1,
                "network_enforcement": "proxy",
                "progress_markers": 1,
                "replays": 6,
                "runtime_request_response_differential_confirmed": True,
                "source_sink_observed": False,
                "state_revision": 12,
                "verdict": "CONFIRMED",
            },
            "image_digest": IMAGE_DIGEST,
            "network": {
                "external_internet": False,
                "internal": True,
                "name": "isolated-network",
            },
            "ok": True,
            "vulnerable_target": {
                "accepted_requests": 18,
                "endpoint_counts": endpoint_counts,
                "extract_status": 200,
            },
        }
    if task_id == "web_active_probe":
        common = {
            "candidate_count": 0,
            "evaluation_sha256": SHA256,
            "executed_fact_count": 1,
            "graph_sha256": SHA256,
            "replay_count": 6,
            "submission_count": 0,
        }
        return {
            "automatic_submission_count": 0,
            "external_network": False,
            "image_digest": IMAGE_DIGEST,
            "oob": {
                **common,
                "mode": "oob",
                "physical_artifact_count": 26,
            },
            "protocol": "ctfos.web.active_probe.docker_release.v1",
            "race": {
                **common,
                "mode": "race",
                "physical_artifact_count": 29,
            },
            "schema_version": 1,
            "target_audit": {
                "control_oob_callbacks": 0,
                "control_race_requests": 6,
                "maximum_parallel_race_requests": 2,
                "vulnerable_oob_callbacks": 3,
                "vulnerable_race_requests": 6,
            },
        }
    if task_id == "rev_original_binary_acceptance":
        return {
            "candidates": 0,
            "cleaned_containers": 0,
            "fact_count": 1,
            "image_digest": IMAGE_DIGEST,
            "managed_action": "rev_accepted_input",
            "network": "none",
            "ok": True,
            "progress_count": 1,
            "receipts": 6,
            "runs": 6,
            "submissions": 0,
        }
    if task_id == "crypto_metamorphic_and_misc_transform":
        return {
            "crypto": {
                runtime: {
                    "candidate_status": "ready_to_submit",
                    "network": "none",
                    "runs": 6,
                    "runtime": runtime,
                    "submissions": 0,
                    "successful_attempts": 6,
                }
                for runtime in ("python", "sage")
            },
            "image_digest": IMAGE_DIGEST,
            "misc": {
                "candidate_status": "observed_candidate",
                "network": "none",
                "runs": 4,
                "submissions": 0,
                "transform_evidence_passed": True,
            },
            "ok": True,
        }
    if task_id == "forensic_assertion_graph":
        return {
            "assertion_facts": 3,
            "assertion_progress": 3,
            "candidates": 0,
            "cleanup": "verified",
            "confirmed": [
                {
                    "algorithms": ["descriptor", "mmap"],
                    "evaluation_sha256": SHA256,
                    "ordinal": ordinal,
                    "record_count": 2,
                }
                for ordinal in range(1, 4)
            ],
            "control": {
                "algorithms": ["descriptor", "mmap"],
                "confirmed": False,
                "reason_codes": [
                    "observation_request_binding_mismatch:control"
                ],
            },
            "image_digest": IMAGE_DIGEST,
            "index_execution_sha256": SHA256,
            "network": "none",
            "ok": True,
            "operator_plans": {
                "control": SHA256,
                "positive": SHA256,
            },
            "pointer": {
                "kind": "file_range",
                "length_bytes": 64,
                "offset_bytes": 32,
                "pointer_id": "pointer-1",
                "sha256": SHA256,
                "source_path": "evidence.bin",
                "source_sha256": SHA256,
            },
            "readiness_probes": 4,
            "sandbox": "production_real_docker",
            "state_status": "TRIAGING",
            "submissions": 0,
        }
    raise AssertionError(f"no valid fixture for {task_id}")


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
                json.dumps(_valid_summary(task.id)).encode("ascii")
                + b"\n"
            )
        )
        self.assertRegex(
            release._validate_child_summary(task, valid, IMAGE_DIGEST),
            r"^sha256:[0-9a-f]{64}$",
        )

        wrong_summary = _valid_summary(task.id)
        wrong_summary["image_digest"] = "sha256:" + "c" * 64
        wrong = release._BoundedCapture(limit_bytes=512)
        wrong.consume(
            io.BytesIO(
                json.dumps(wrong_summary).encode("ascii")
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
        summary = _valid_summary(task.id)
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

    def test_every_category_summary_has_a_field_level_oracle(self) -> None:
        for task in release.RELEASE_TASKS:
            with self.subTest(task=task.id):
                summary = _valid_summary(task.id)
                capture = release._BoundedCapture(limit_bytes=32_768)
                capture.consume(
                    io.BytesIO(
                        json.dumps(summary, sort_keys=True).encode("ascii")
                        + b"\n"
                    )
                )
                release._validate_child_summary(
                    task,
                    capture,
                    IMAGE_DIGEST,
                )

    def test_literal_ok_cannot_credit_any_category(self) -> None:
        for task in release.RELEASE_TASKS:
            with self.subTest(task=task.id):
                summary = _valid_summary(task.id)
                if task.id == "pwn_dependency_effect":
                    summary["real_clean_proofs"] = 0
                elif task.id == "web_state_impact":
                    summary["control_target"]["extract_status"] = 200
                elif task.id == "web_active_probe":
                    summary["target_audit"]["vulnerable_oob_callbacks"] = 0
                elif task.id == "rev_original_binary_acceptance":
                    summary["runs"] = 0
                elif (
                    task.id
                    == "crypto_metamorphic_and_misc_transform"
                ):
                    summary["crypto"]["sage"]["successful_attempts"] = 0
                elif task.id == "forensic_assertion_graph":
                    summary["control"]["confirmed"] = True
                capture = release._BoundedCapture(limit_bytes=32_768)
                capture.consume(
                    io.BytesIO(
                        json.dumps(summary, sort_keys=True).encode("ascii")
                        + b"\n"
                    )
                )
                with self.assertRaises(release.ReleaseMatrixError):
                    release._validate_child_summary(
                        task,
                        capture,
                        IMAGE_DIGEST,
                    )

    def test_web_impact_summary_keeps_dataflow_authority_false(self) -> None:
        endpoint_counts = {
            "/one": 3,
            "/two": 3,
            "/three": 3,
            "/four": 3,
            "/five": 3,
            "/six": 3,
        }
        summary = {
            "control_target": {
                "accepted_requests": 18,
                "endpoint_counts": endpoint_counts,
                "extract_status": 403,
            },
            "engine": {
                "automatic_submissions": 0,
                "canonical_requests_preissued": 6,
                "executed_facts": 1,
                "network_enforcement": "proxy",
                "progress_markers": 1,
                "replays": 6,
                "runtime_request_response_differential_confirmed": True,
                "source_sink_observed": False,
                "state_revision": 2,
                "verdict": "CONFIRMED",
            },
            "image_digest": IMAGE_DIGEST,
            "network": {
                "external_internet": False,
                "internal": True,
                "name": "release-web-local",
            },
            "ok": True,
            "vulnerable_target": {
                "accepted_requests": 18,
                "endpoint_counts": endpoint_counts,
                "extract_status": 200,
            },
        }

        release._validate_web_impact_summary(summary)

        summary["engine"]["source_sink_observed"] = True
        with self.assertRaisesRegex(
            release.ReleaseMatrixError,
            "differential oracle",
        ):
            release._validate_web_impact_summary(summary)

    def test_child_environment_drops_secret_and_model_credentials(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "OPENAI_API_KEY": "must-not-propagate",
                "AWS_ACCESS_KEY_ID": "must-not-propagate",
                "GH_PAT": "must-not-propagate",
                "CTF_PASSWORD": "must-not-propagate",
                "PATH": "/usr/bin",
                "PYTHONPATH": "/existing",
                "SAFE_SETTING": "yes",
            },
            clear=True,
        ):
            environment = release._child_environment()
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertNotIn("AWS_ACCESS_KEY_ID", environment)
        self.assertNotIn("GH_PAT", environment)
        self.assertNotIn("CTF_PASSWORD", environment)
        self.assertEqual(environment["PATH"], "/usr/bin")
        self.assertNotIn("SAFE_SETTING", environment)
        self.assertEqual(environment["CTFOS_RELEASE_MATRIX"], "1")
        self.assertEqual(
            environment["PYTHONPATH"],
            str(REPOSITORY),
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
                "print(json.dumps({"
                "'candidate_count': 0, "
                "'graph_ids': ['g1', 'g2', 'g3'], "
                "'image_digest': sys.argv[2], "
                "'network': 'none', "
                "'no_leak_required_chains': 3, "
                "'ok': True, "
                "'real_clean_proofs': 48, "
                "'repetitions': 3, "
                "'submission_count': 0, "
                "'tamper_controls_rejected': 3"
                "}, sort_keys=True))\n",
                encoding="utf-8",
            )
            task = release.ReleaseTask(
                id="pwn_dependency_effect",
                categories=("pwn",),
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
