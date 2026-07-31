from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


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


_SHA = "a" * 64
IMAGE_DIGEST = "sha256:" + "b" * 64


def _valid_child_summary(seed: int = 1) -> dict[str, object]:
    records: list[dict[str, object]] = []
    role_counts = (
        ("crash", 6),
        ("runtime_snapshot", 1),
        ("ip_control", 3),
        ("effect", 6),
    )
    role_run_ids: dict[str, list[str]] = {}
    counter = 0
    for role, count in role_counts:
        role_run_ids[role] = []
        for ordinal in range(1, count + 1):
            counter += 1
            run_id = f"run-{seed}-{role}-{ordinal}"
            role_run_ids[role].append(run_id)
            records.append(
                {
                    "artifact_count": 3 if role == "effect" else 2,
                    "artifact_manifest_sha256": f"{counter:064x}",
                    "clean_prefix": (
                        f"clean-{ordinal:012x}"
                        if role == "effect"
                        else None
                    ),
                    "clean_workspace": True,
                    "network": "none",
                    "one_shot": True,
                    "request_sha256": f"{counter + 20:064x}",
                    "result_sha256": f"{counter + 40:064x}",
                    "role": role,
                    "run_id": run_id,
                    "sandbox_method": "run_clean_proof",
                    "sandbox_run_id": (
                        "sandbox-effect" if role == "effect" else None
                    ),
                    "scope_fingerprint": (
                        f"{seed + 500:064x}"
                        if role == "effect"
                        else None
                    ),
                    "transport_receipt_sha256": (
                        f"{counter + 60:064x}"
                        if role == "effect"
                        else None
                    ),
                    "validation_sha256": f"{counter + 80:064x}",
                }
            )
    effect_records = []
    for index, run_id in enumerate(role_run_ids["effect"]):
        phase = "positive" if index < 3 else "control"
        effect_records.append(
            {
                "ordinal": index + 1 if index < 3 else index - 2,
                "phase": phase,
                "run_id": run_id,
                "sentinel_sha256": (
                    f"{seed * 1000 + index + 100:064x}"
                ),
                "status": (
                    "effect_observed"
                    if phase == "positive"
                    else "effect_absent"
                ),
            }
        )
    return {
        "candidates": 0,
        "dependency": {
            "artifact_validation": {
                "aggregate_commitment_sha256": _SHA,
                "artifact_count": 73,
                "descriptor_reread": True,
                "nofollow_required": True,
                "raw_output_returned": False,
                "total_bytes": 87005,
            },
            "branch": "DEPENDENCY_SCOPED_NOT_APPLICABLE",
            "gate_route": ["D", "V", "N/A", "P", "E"],
            "graph_id": f"pwn-dependency-graph-test-{seed}",
            "graph_sha256": _SHA,
            "primitive_recomputed": True,
            "static_target_validation": {
                "manifest_sha256": _SHA,
                "raw_output_returned": False,
                "source_locator": "challenge",
                "source_sha256": _SHA,
                "source_size_bytes": 16384,
            },
            "tamper_control_rejected": True,
        },
        "effect": {
            "authorities": {
                "auto_submit_authorized": False,
                "exploit_effect_proven": True,
                "exploit_proven": True,
                "flag_proven": False,
                "primitive_proven": True,
                "proof_satisfied": False,
                "stage_advance_authorized": False,
            },
            "child_experiment_id": f"E-pwn-effect-test-{seed}",
            "records": effect_records,
        },
        "evidence_execution": {
            "crash_clean_proofs": 6,
            "effect_clean_proofs": 6,
            "ip_control_clean_proofs": 3,
            "network_none": 16,
            "physical_manifest_sha256": release._canonical_sha256(
                records
            ),
            "physical_records": records,
            "runtime_snapshot_clean_proofs": 1,
            "sandbox": "production_real_docker",
            "total_real_clean_proofs": 16,
        },
        "fixture": {
            "baseline_target": "0x0000500012345678",
            "controlled_offset": 17,
            "controlled_width_bytes": 8,
            "emit_sentinel_address": "0x0000000000401234",
            "source_sha256": _SHA,
        },
        "image_digest": IMAGE_DIGEST,
        "network": "none",
        "ok": True,
        "setup_boundary": "test fixture boundary",
        "submissions": 0,
    }


def _subprocess_writer(payload: bytes):
    def fake_run(*args, **kwargs):
        del args
        kwargs["stdout"].write(payload)
        kwargs["stderr"].write(b"")
        return subprocess.CompletedProcess(kwargs.get("args", ()), 0)

    return fake_run


class PwnDependencyHotPathReleaseTests(unittest.TestCase):
    def test_release_gate_is_exact_image_three_way_parallel_and_bounded(
        self,
    ) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(release.REPETITIONS, 3)
        self.assertIn("validate_image_digest", source)
        self.assertNotIn("RELEASE_IMAGE_DIGEST", source)
        self.assertIn("ThreadPoolExecutor", source)
        self.assertIn("TemporaryFile", source)
        self.assertIn("strict_json_loads", source)
        self.assertIn("_validate_child_summary", source)
        self.assertIn("DEPENDENCY_SCOPED_NOT_APPLICABLE", source)
        self.assertIn("tamper_control_rejected", source)
        self.assertNotIn("capture_output=True", source)
        self.assertNotIn("splitlines()", source)
        self.assertNotIn("json.loads(lines[-1])", source)

    def test_single_proof_reloads_canonical_physical_evidence(self) -> None:
        source = SINGLE.read_text(encoding="utf-8")
        self.assertIn("engine.validate_pwn_dependency_graph", source)
        self.assertIn(
            "validate_pwn_dependency_state_graph(tampered)",
            source,
        )
        self.assertIn("engine.store.load(", source)
        self.assertIn("_pwn_physical_evidence_summary(", source)
        self.assertIn("PwnExploitEffectResult.from_dict(", source)
        self.assertNotIn("submit_candidate", source)

    def test_valid_child_summary_and_full_stream_are_accepted(self) -> None:
        value = _valid_child_summary()
        self.assertIs(
            release._validate_child_summary(
                value,
                digest=IMAGE_DIGEST,
                index=1,
            ),
            value,
        )
        payload = json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        with mock.patch.object(
            release.subprocess,
            "run",
            side_effect=_subprocess_writer(payload),
        ):
            parsed = release._one(1, IMAGE_DIGEST)
        self.assertEqual(parsed, value)

    def test_false_effect_authority_is_rejected(self) -> None:
        value = _valid_child_summary()
        value["effect"]["authorities"]["exploit_effect_proven"] = False
        with self.assertRaises(RuntimeError):
            release._validate_child_summary(
                value,
                digest=IMAGE_DIGEST,
                index=1,
            )

    def test_boolean_integer_impersonation_is_rejected(self) -> None:
        mutations = (
            lambda value: value.update({"candidates": False}),
            lambda value: value.update({"submissions": False}),
            lambda value: value["effect"]["records"][0].update(
                {"ordinal": True}
            ),
            lambda value: value["evidence_execution"].update(
                {"runtime_snapshot_clean_proofs": True}
            ),
            lambda value: value["fixture"].update(
                {"controlled_offset": 17.0}
            ),
        )
        for ordinal, mutation in enumerate(mutations, start=1):
            value = _valid_child_summary()
            mutation(value)
            with self.subTest(ordinal=ordinal):
                with self.assertRaises(RuntimeError):
                    release._validate_child_summary(
                        value,
                        digest=IMAGE_DIGEST,
                        index=1,
                    )

    def test_effect_records_must_bind_exact_effect_run_cohort(self) -> None:
        value = _valid_child_summary()
        crash_run_id = next(
            item["run_id"]
            for item in value["evidence_execution"]["physical_records"]
            if item["role"] == "crash"
        )
        value["effect"]["records"][0]["run_id"] = crash_run_id
        with self.assertRaises(RuntimeError):
            release._validate_child_summary(
                value,
                digest=IMAGE_DIGEST,
                index=1,
            )

    def test_physical_record_or_manifest_tamper_is_rejected(self) -> None:
        for mutation in ("record", "manifest"):
            value = _valid_child_summary()
            if mutation == "record":
                value["evidence_execution"]["physical_records"][0][
                    "network"
                ] = "bridge"
            else:
                value["evidence_execution"][
                    "physical_manifest_sha256"
                ] = "f" * 64
            with self.subTest(mutation=mutation):
                with self.assertRaises(RuntimeError):
                    release._validate_child_summary(
                        value,
                        digest=IMAGE_DIGEST,
                        index=1,
                    )

    def test_duplicate_or_appended_root_document_is_rejected(self) -> None:
        value = _valid_child_summary()
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        payloads = (
            b'{"network":"bridge",' + encoded[1:],
            encoded + b"\n{}",
        )
        for payload in payloads:
            with self.subTest(payload=payload[:32]):
                with mock.patch.object(
                    release.subprocess,
                    "run",
                    side_effect=_subprocess_writer(payload),
                ):
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "summary is invalid",
                    ):
                        release._one(
                            1,
                            IMAGE_DIGEST,
                        )

    def test_capture_byte_limit_is_enforced(self) -> None:
        with tempfile.TemporaryFile(mode="w+b") as stream:
            stream.write(
                b"x" * (release.MAX_CHILD_STDERR_BYTES + 1)
            )
            with self.assertRaisesRegex(
                RuntimeError,
                "exceeded its byte limit",
            ):
                release._read_capture(
                    stream,
                    maximum_bytes=release.MAX_CHILD_STDERR_BYTES,
                    label="test stderr",
                )

    def test_repetition_freshness_requires_disjoint_physical_cohorts(
        self,
    ) -> None:
        fresh = [
            _valid_child_summary(seed)
            for seed in range(1, release.REPETITIONS + 1)
        ]
        release._validate_repetition_freshness(fresh)

        reused = [copy.deepcopy(fresh[0]) for _ in fresh]
        for seed, value in enumerate(reused, start=1):
            value["dependency"]["graph_id"] = (
                f"changed-graph-id-{seed}"
            )
        with self.assertRaisesRegex(
            AssertionError,
            "reused physical evidence",
        ):
            release._validate_repetition_freshness(reused)


if __name__ == "__main__":
    unittest.main()
