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
    if task_id == "pwn_interaction_effect":
        return {
            "authority": {
                "auto_submit_authorized": False,
                "candidates_added": 0,
                "executed_fact_added": 1,
                "progress_added": 1,
                "status_changed": False,
                "submissions_added": 0,
            },
            "bindings": {
                "image_digest": IMAGE_DIGEST,
                "preissue_sha256": SHA256,
                "producer_sha256": (
                    "d2a5a4370242adb0fae75ac4ddc68ffd"
                    "43952e671ba0abc0ad68f1924423b5b9"
                ),
                "recipe_sha256": SHA256,
                "source_sha256": SHA256,
            },
            "evaluation": {
                "attack_replays": 3,
                "control_replays": 3,
                "matched_terminal": True,
                "passed": True,
                "reason_code": (
                    "validated_three_positive_three_control_replays"
                ),
                "sha256": SHA256,
                "unique_sentinels": 6,
            },
            "failure_control": {
                "candidates_added": 0,
                "facts_added": 0,
                "failure_mode": "preissue_sha256_tamper",
                "progress_added": 0,
                "receipts": 6,
                "runs_terminal": 6,
                "state_store_reopen_ok": True,
                "status": "failed",
                "terminal": True,
                "tested": True,
                "submissions_added": 0,
            },
            "image_digest": IMAGE_DIGEST,
            "network": "none",
            "ok": True,
            "parent": {
                "authority": "canonical_executed_parent_v1",
                "experiment_id": "E-executed-parent",
                "fact_id": "F-executed-parent",
                "run_id": "R-executed-parent",
            },
            "preissue": {
                "preissued_before_first_run": True,
                "replay_count": 6,
                "sha256": SHA256,
                "status": "passed",
                "terminal": True,
            },
            "protocol": "ctfos.pwn.interaction.hotpath.v1",
            "sandbox": "production_real_docker",
            "source_challenge": {
                "category": "pwn",
                "challenge_id": "interaction",
                "contest_id": "release",
                "source_sha256": SHA256,
            },
            "transport": {
                "canonical_scope_fingerprint": SHA256,
                "fresh_clean_workspaces": 6,
                "network_none": 6,
                "one_shot": 6,
                "physical_identities": [
                    {
                        "clean_prefix": f"clean-{ordinal:012x}",
                        "sandbox_run_id": "producer-run",
                        "scope_fingerprint": SHA256,
                    }
                    for ordinal in range(1, 7)
                ],
                "physical_records": [
                    {
                        "artifact_count": 6,
                        "artifact_manifest_sha256": SHA256,
                        "clean_prefix": f"clean-{ordinal:012x}",
                        "clean_workspace": True,
                        "network": "none",
                        "one_shot": True,
                        "proof_output_count": 4,
                        "request_sha256": SHA256,
                        "result_sha256": SHA256,
                        "run_id": f"engine-run-{ordinal}",
                        "sandbox_method": "run_clean_proof",
                        "sandbox_run_id": "producer-run",
                        "scope_fingerprint": SHA256,
                        "validation_sha256": SHA256,
                    }
                    for ordinal in range(1, 7)
                ],
                "proof_outputs_per_run": 4,
                "unique_clean_prefix_count": 6,
                "unique_proof_identity_count": 6,
            },
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
                "physical_artifacts_revalidated": 88,
                "physical_run_sidecars_revalidated": 18,
                "physical_transport_receipts_revalidated": 6,
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
            "image_digest": IMAGE_DIGEST,
            "network": {
                "external_internet": False,
                "internal": True,
                "name": "ctfos-web-active-release-test",
            },
            "oob": {
                **common,
                "attempt_id": "web-active-" + "c" * 32,
                "mode": "oob",
                "physical_artifact_count": 26,
            },
            "protocol": "ctfos.web.active_probe.docker_release.v1",
            "race": {
                **common,
                "attempt_id": "web-active-" + "d" * 32,
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
                    "candidate_status": "READY_TO_SUBMIT",
                    "network": "none",
                    "one_shot_consumed": True,
                    "oracle_authority": "managed_oracle_preissue_v1",
                    "oracle_preissue_status": "consumed",
                    "runs": 6,
                    "runtime": runtime,
                    "submissions": 0,
                    "successful_attempts": 6,
                }
                for runtime in ("python", "sage")
            },
            "image_digest": IMAGE_DIGEST,
            "misc": {
                "candidate_only": True,
                "candidate_status": "OBSERVED_CANDIDATE",
                "network": "none",
                "one_shot_consumed": True,
                "oracle_authority": "managed_oracle_preissue_v1",
                "oracle_control_runs": 1,
                "oracle_preissue_status": "consumed",
                "runs": 5,
                "submissions": 0,
                "transform_evidence_passed": True,
                "transform_runs": 1,
                "verification_runs": 3,
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
                    "algorithms": ["descriptor", "perl-sysread"],
                    "evaluation_sha256": SHA256,
                    "ordinal": ordinal,
                    "record_count": 2,
                    "tool_version_sha256s": sorted(
                        (
                            "1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118",
                            "56e5ea41974eb1eff0f7ea64677578b1938053d29818c2810bcb21e2ca68cafa",
                        )
                    ),
                }
                for ordinal in range(1, 4)
            ],
            "control": {
                "algorithms": ["descriptor", "perl-sysread"],
                "confirmed": False,
                "reason_codes": [
                    "observation_request_binding_mismatch:control"
                ],
                "tool_version_sha256s": sorted(
                    (
                        "1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118",
                        "56e5ea41974eb1eff0f7ea64677578b1938053d29818c2810bcb21e2ca68cafa",
                    )
                ),
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
            "tool_executables": {
                "family-perl-sysread": {
                    "path": "/usr/bin/perl",
                    "sha256": (
                        "56e5ea41974eb1eff0f7ea64677578b193"
                        "8053d29818c2810bcb21e2ca68cafa"
                    ),
                },
                "family-python-pread": {
                    "path": "/usr/bin/python3",
                    "sha256": (
                        "1643dacd9feaedc58f3cc581e4d22577d"
                        "fe25c09b10282936186ccf0f2e61118"
                    ),
                },
            },
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
        self.assertEqual(len(release.RELEASE_TASKS), 7)
        self.assertEqual(
            sum(task.categories == ("pwn",) for task in release.RELEASE_TASKS),
            2,
        )
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

    def test_web_active_summary_rejects_extra_root_and_nested_keys(
        self,
    ) -> None:
        for mutate in (
            lambda value: value.__setitem__("unexpected_root", True),
            lambda value: value["race"].__setitem__(
                "unexpected_nested",
                True,
            ),
            lambda value: value["network"].__setitem__(
                "unexpected_nested",
                True,
            ),
            lambda value: value["target_audit"].__setitem__(
                "unexpected_nested",
                True,
            ),
        ):
            with self.subTest(mutate=mutate):
                summary = _valid_summary("web_active_probe")
                mutate(summary)
                with self.assertRaisesRegex(
                    release.ReleaseMatrixError,
                    "schema is invalid",
                ):
                    release._validate_web_active_summary(summary)

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

    def test_crypto_misc_summary_requires_exact_managed_preissue_authority(
        self,
    ) -> None:
        task = next(
            item
            for item in release.RELEASE_TASKS
            if item.id == "crypto_metamorphic_and_misc_transform"
        )
        for mutate in (
            lambda value: value["crypto"]["python"].__setitem__(
                "oracle_authority",
                "explicit_operator_input",
            ),
            lambda value: value["misc"].__setitem__(
                "oracle_preissue_status",
                "unused",
            ),
            lambda value: value["misc"].__setitem__("runs", 4),
            lambda value: value["misc"].__setitem__("unexpected", True),
        ):
            with self.subTest(mutate=mutate):
                summary = _valid_summary(task.id)
                mutate(summary)
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

    def test_literal_ok_cannot_credit_any_category(self) -> None:
        for task in release.RELEASE_TASKS:
            with self.subTest(task=task.id):
                summary = _valid_summary(task.id)
                if task.id == "pwn_dependency_effect":
                    summary["real_clean_proofs"] = 0
                elif task.id == "pwn_interaction_effect":
                    summary["failure_control"]["tested"] = False
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

    def test_pwn_summary_rejects_bool_or_float_counters(self) -> None:
        task = next(
            item
            for item in release.RELEASE_TASKS
            if item.id == "pwn_dependency_effect"
        )
        for field, invalid in (
            ("candidate_count", False),
            ("submission_count", 0.0),
            ("repetitions", 3.0),
            ("no_leak_required_chains", 3.0),
            ("real_clean_proofs", 48.0),
            ("tamper_controls_rejected", True),
        ):
            with self.subTest(field=field, invalid=invalid):
                summary = _valid_summary(task.id)
                summary[field] = invalid
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

    def test_forensic_rejects_duplicate_tool_executable_version(
        self,
    ) -> None:
        task = next(
            item
            for item in release.RELEASE_TASKS
            if item.id == "forensic_assertion_graph"
        )
        summary = _valid_summary(task.id)
        duplicate = summary["tool_executables"][
            "family-python-pread"
        ]["sha256"]
        summary["tool_executables"]["family-perl-sysread"][
            "sha256"
        ] = duplicate
        summary["control"]["tool_version_sha256s"] = [
            duplicate,
            duplicate,
        ]
        for item in summary["confirmed"]:
            item["tool_version_sha256s"] = [
                duplicate,
                duplicate,
            ]
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

    def test_pwn_interaction_summary_is_exact_and_requires_physical_controls(
        self,
    ) -> None:
        task = next(
            item
            for item in release.RELEASE_TASKS
            if item.id == "pwn_interaction_effect"
        )
        valid = _valid_summary(task.id)
        release._validate_pwn_interaction_summary(valid)
        mutations = (
            lambda value: value["evaluation"].__setitem__(
                "attack_replays",
                2,
            ),
            lambda value: value["transport"]["physical_identities"].__setitem__(
                5,
                dict(value["transport"]["physical_identities"][0]),
            ),
            lambda value: value["transport"].__setitem__(
                "unique_clean_prefix_count",
                5,
            ),
            lambda value: value["transport"]["physical_identities"][5].update(
                {
                    "clean_prefix": value["transport"][
                        "physical_identities"
                    ][0]["clean_prefix"],
                    "sandbox_run_id": "different-run",
                }
            ),
            lambda value: value["transport"]["physical_identities"][5].update(
                {"scope_fingerprint": "c" * 64}
            ),
            lambda value: value["transport"]["physical_records"][0].update(
                {"network": "bridge"}
            ),
            lambda value: value["transport"]["physical_records"][0].update(
                {"proof_output_count": 3}
            ),
            lambda value: value["authority"].__setitem__(
                "candidates_added",
                1,
            ),
            lambda value: value["failure_control"].__setitem__(
                "facts_added",
                1,
            ),
            lambda value: value["failure_control"].__setitem__(
                "state_store_reopen_ok",
                False,
            ),
            lambda value: value["parent"].__setitem__(
                "authority",
                "model_claimed",
            ),
            lambda value: value["evaluation"].__setitem__(
                "unexpected",
                True,
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                summary = _valid_summary(task.id)
                mutate(summary)
                with self.assertRaises(release.ReleaseMatrixError):
                    release._validate_pwn_interaction_summary(summary)

        typed = _valid_summary(task.id)
        typed["parent"] = {
            "authority": "typed_pwn_ip_control_v1",
            "experiment_id": "E-typed-parent",
            "fact_id": None,
            "run_id": None,
        }
        release._validate_pwn_interaction_summary(typed)

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
                "physical_artifacts_revalidated": 88,
                "physical_run_sidecars_revalidated": 18,
                "physical_transport_receipts_revalidated": 6,
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

    def test_web_impact_summary_requires_physical_revalidation(self) -> None:
        for field, value in (
            ("physical_artifacts_revalidated", 87),
            ("physical_run_sidecars_revalidated", 17),
            ("physical_transport_receipts_revalidated", 5),
        ):
            with self.subTest(field=field):
                summary = _valid_summary("web_state_impact")
                summary["engine"][field] = value
                with self.assertRaises(release.ReleaseMatrixError):
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
