from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path
from unittest import mock

from ctf_os.adapters import get_adapter
from ctf_os.capabilities import REQUIRED_MANAGED_ATTESTATIONS
from ctf_os.engine import resume_capsule as resume_capsule_module
from ctf_os.engine.pwn_runtime_snapshot import (
    pwn_runtime_snapshot_child_experiment_id,
)
from ctf_os.engine.context_pack import (
    _pwn_runtime_snapshot_context_records,
    build_context_pack,
)
from ctf_os.engine.resume_capsule import (
    MIN_RESUME_CAPSULE_BYTES,
    ResumeCapsulePolicy,
    render_resume_capsule,
)
from ctf_os.models import (
    ExperimentStatus,
    ModelValidationError,
    PwnDisclosurePhase,
    PwnRuntimeSnapshotDisclosureEnvelope,
    utc_now,
)
from tests import test_pwn_crash_execution as crash_execution
from tests.test_pwn_runtime_snapshot_lifecycle import (
    _SnapshotCoordinator,
)


def _canonical_sha256(value: object) -> str:
    payload = (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


class PwnRuntimeSnapshotStateValidationTests(unittest.TestCase):
    """Tamper tests for the isolated one-run diagnostic child graph."""

    @classmethod
    def setUpClass(cls) -> None:
        fixture = crash_execution.PwnCrashExecutionTests(
            methodName=(
                "test_confirmed_gate_uses_six_clean_networkless_fixed_calls"
            )
        )
        fixture.setUp()
        try:
            coordinator = _SnapshotCoordinator(
                fixture._confirming_statuses()
            )
            engine, parent_id, _artifact_path, _payload = (
                fixture._fixture(coordinator)
            )
            registered = fixture._execute(engine, parent_id)
            child_id = pwn_runtime_snapshot_child_experiment_id(
                parent_id
            )

            def capability(digest):
                return {
                    "ok": True,
                    "image_digest": digest,
                    "available": ["pwn_runtime_snapshot_v1"],
                    "attestations": {
                        "pwn_runtime_snapshot_v1": dict(
                            REQUIRED_MANAGED_ATTESTATIONS[
                                "pwn_runtime_snapshot_v1"
                            ]
                        )
                    },
                    "attestation_errors": {},
                }

            engine._capability_probe = capability
            completed = engine.execute_registered_experiments(
                fixture.identity,
                maximum=1,
                _session_owned=True,
                experiment_ids=(child_id,),
            )
            cls.registered_state = copy.deepcopy(registered)
            cls.completed_state = copy.deepcopy(completed)
            cls.parent_id = parent_id
            cls.child_id = child_id
        finally:
            fixture.tearDown()

    def registered(self):
        return copy.deepcopy(self.registered_state)

    def completed(self):
        return copy.deepcopy(self.completed_state)

    def child(self, state):
        return next(
            item
            for item in state.experiments
            if item.id == self.child_id
        )

    def snapshot_run(self, state):
        child = self.child(state)
        return next(
            item
            for item in state.runs
            if item.id == child.evidence_run_ids[0]
        )

    def receipt(self, state):
        child = self.child(state)
        return next(
            item
            for item in state.receipts
            if item.id == child.evidence_receipt_ids[0]
        )

    def evidence(self, state):
        return self.child(state).result[
            "pwn_runtime_snapshot_evidence"
        ]

    def assert_invalid(
        self,
        state,
        pattern: str = "Pwn runtime snapshot",
    ) -> None:
        with self.assertRaisesRegex(ModelValidationError, pattern):
            state.validate()

    def test_canonical_active_terminal_round_trip_and_legacy_parent(self):
        for state in (self.registered(), self.completed()):
            state.validate()
            type(state).from_dict(state.to_dict()).validate()

        legacy = self.registered()
        legacy.experiments = [
            item
            for item in legacy.experiments
            if item.id != self.child_id
        ]
        legacy.validate()

    def test_active_child_rejects_result_or_execution_evidence(self):
        state = self.registered()
        self.child(state).result = {"error": "injected"}
        self.assert_invalid(state, "active lifecycle")

        state = self.registered()
        self.child(state).evidence_run_ids = ["R-injected"]
        self.assert_invalid(state)

    def test_duplicate_or_substituted_child_is_rejected(self):
        state = self.registered()
        duplicate = copy.deepcopy(self.child(state))
        duplicate.id = "E-pwn-runtime-snapshot-v1-" + ("f" * 64)
        state.experiments.append(duplicate)
        self.assert_invalid(state)

    def test_parent_and_recipe_binding_tamper_is_rejected(self):
        state = self.registered()
        parent = next(
            item
            for item in state.experiments
            if item.id == self.parent_id
        )
        parent.status = ExperimentStatus.INCONCLUSIVE
        self.assert_invalid(state)

        state = self.registered()
        recipe = self.child(state).extra[
            "pwn_runtime_snapshot_recipe"
        ]
        recipe["parent"]["expected_signal_number"] = 6
        self.assert_invalid(state, "recipe is invalid")

    def test_execution_policy_tamper_with_rehashed_record_is_rejected(self):
        state = self.completed()
        run = self.snapshot_run(state)
        receipt = self.receipt(state)
        record = copy.deepcopy(run.extra["pwn_runtime_snapshot"])
        contract = record["execution_contract"]
        contract["sandbox"]["network"] = "bridge"
        changed_hash = _canonical_sha256(contract)
        record["execution_contract_sha256"] = changed_hash
        record["receipt"]["execution_contract_sha256"] = changed_hash
        run.extra["pwn_runtime_snapshot"] = copy.deepcopy(record)
        receipt.extra["pwn_runtime_snapshot"] = copy.deepcopy(record)
        self.assert_invalid(state, "execution policy binding")

    def test_gate_and_artifact_tamper_are_rejected(self):
        state = self.completed()
        self.evidence(state)["evaluation_sha256"] = "0" * 64
        self.assert_invalid(state, "result/evidence")

        state = self.completed()
        stdout_id = self.evidence(state)["stdout_artifact_id"]
        stdout = next(
            item for item in state.artifacts if item.id == stdout_id
        )
        stdout.extra["stream"] = "stderr"
        self.assert_invalid(state, "stdout artifact binding")

    def test_duplicate_receipt_and_orphan_capability_are_rejected(self):
        state = self.completed()
        duplicate = copy.deepcopy(self.receipt(state))
        duplicate.id = "RCPT-pwn-runtime-snapshot-duplicate"
        state.receipts.append(duplicate)
        self.assert_invalid(state)

        state = self.completed()
        capability_id = self.evidence(state)[
            "capability_attestation_artifact_id"
        ]
        capability = copy.deepcopy(
            next(
                item
                for item in state.artifacts
                if item.id == capability_id
            )
        )
        capability.id = "A-pwn-runtime-snapshot-orphan"
        state.artifacts.append(capability)
        self.assert_invalid(state, "stdout/stderr/capability")

    def test_snapshot_evidence_cannot_promote_a_hypothesis(self):
        state = self.completed()
        hypothesis = next(
            item for item in state.hypotheses if item.evidence_run_ids
        )
        hypothesis.evidence_run_ids.append(
            self.snapshot_run(state).id
        )
        self.assert_invalid(state, "cannot promote Hypothesis")

    def test_failed_closed_child_has_no_execution_graph(self):
        state = self.registered()
        child = self.child(state)
        child.status = ExperimentStatus.FAILED
        child.result = {
            "error": (
                "Pwn runtime snapshot failed closed: capability probe "
                "unavailable"
            )
        }
        state.validate()

        child.result = {
            "error": (
                "Pwn runtime snapshot failed closed: orphaned execution "
                "recovered after the previous session owner exited"
            )
        }
        child.extra["orphan_recovered_at"] = utc_now()
        child.extra["orphan_recovery"] = (
            "failed_closed_without_canonical_evidence"
        )
        state.validate()

    def test_recovery_metadata_is_rejected_outside_canonical_orphan(
        self,
    ):
        for status in (
            ExperimentStatus.REGISTERED,
            ExperimentStatus.RUNNING,
            ExperimentStatus.COMPLETED,
        ):
            with self.subTest(status=status.value):
                state = (
                    self.completed()
                    if status is ExperimentStatus.COMPLETED
                    else self.registered()
                )
                child = self.child(state)
                child.status = status
                child.extra["orphan_recovered_at"] = utc_now()
                child.extra["orphan_recovery"] = (
                    "failed_closed_without_canonical_evidence"
                )
                self.assert_invalid(
                    state,
                    "missing or unknown engine-owned fields",
                )

        state = self.registered()
        child = self.child(state)
        child.status = ExperimentStatus.FAILED
        child.result = {
            "error": (
                "Pwn runtime snapshot failed closed: capability probe "
                "unavailable"
            )
        }
        child.extra["orphan_recovered_at"] = utc_now()
        child.extra["orphan_recovery"] = (
            "failed_closed_without_canonical_evidence"
        )
        self.assert_invalid(
            state,
            "missing or unknown engine-owned fields",
        )

    def test_stderr_receipt_metadata_tamper_is_rejected(self):
        mutations = {
            "stderr_artifact_id": "A-substituted-stderr",
            "stderr_artifact_sha256": "0" * 64,
            "stderr_artifact_size_bytes": 1,
            "stderr_capture_placeholder": True,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                state = self.completed()
                run = self.snapshot_run(state)
                receipt = self.receipt(state)
                record = copy.deepcopy(
                    run.extra["pwn_runtime_snapshot"]
                )
                record["receipt"][field] = value
                run.extra["pwn_runtime_snapshot"] = copy.deepcopy(
                    record
                )
                receipt.extra["pwn_runtime_snapshot"] = copy.deepcopy(
                    record
                )
                self.assert_invalid(state, "receipt binding")

    def test_v2_context_projects_only_raw_free_disclosure_commitments(
        self,
    ):
        state = self.completed()
        records = _pwn_runtime_snapshot_context_records(
            state
        )

        self.assertEqual(len(records), 1)
        record = json.loads(records[0])
        self.assertEqual(
            record["kind"],
            "pwn_runtime_snapshot_disclosure",
        )
        self.assertEqual(record["snapshot_status"], "CAPTURED")
        self.assertEqual(record["disclosure_phase"], "complete")
        self.assertEqual(record["result_status"], "UNRESOLVED")
        self.assertEqual(record["candidate_count"], 0)
        self.assertEqual(len(record["artifact_pointers"]), 3)
        evidence = self.evidence(state)
        artifacts = {item.id: item for item in state.artifacts}
        for pointer, (label, key) in zip(
            record["artifact_pointers"],
            (
                ("stdout", "stdout_artifact_id"),
                ("stderr", "stderr_artifact_id"),
                (
                    "capability",
                    "capability_attestation_artifact_id",
                ),
            ),
            strict=True,
        ):
            artifact = artifacts[evidence[key]]
            self.assertEqual(
                pointer,
                {
                    "artifact_id": artifact.id,
                    "label": label,
                    "path": artifact.path,
                    "sha256": artifact.sha256,
                    "size": artifact.size,
                },
            )
        self.assertNotIn("rip", record)
        self.assertNotIn("rsp", record)
        self.assertNotIn("maps", record)
        self.assertNotIn("0000000000400010", records[0])
        self.assertNotIn("00007fffffffe000", records[0])
        self.assertNotIn(
            "trusted_receipt_expectation",
            record,
        )
        self.assertNotIn("content_base64", records[0])

    def test_legacy_v1_context_keeps_compatible_register_projection(
        self,
    ):
        legacy = self.completed()
        child = self.child(legacy)
        child.extra["managed_contract_version"] = 1
        child.extra.pop("pwn_disclosure")
        legacy.validate()

        records = _pwn_runtime_snapshot_context_records(legacy)

        self.assertEqual(len(records), 1)
        record = json.loads(records[0])
        self.assertEqual(record["kind"], "pwn_runtime_snapshot")
        self.assertEqual(record["status"], "CAPTURED")
        self.assertEqual(record["rip"], "0000000000400010")
        self.assertEqual(record["rsp"], "00007fffffffe000")
        self.assertEqual(len(record["artifact_pointers"]), 3)

    def test_v2_context_projection_is_bounded_to_newest_three(
        self,
    ):
        state = self.completed()
        child = self.child(state)
        state.experiments = [
            item
            for item in state.experiments
            if item.id != child.id
        ]
        for index in range(5):
            duplicate = copy.deepcopy(child)
            duplicate.id = f"{child.id}-projection-{index}"
            state.experiments.append(duplicate)

        records = _pwn_runtime_snapshot_context_records(state)

        self.assertEqual(len(records), 3)
        ids = [
            json.loads(record)["experiment_id"]
            for record in records
        ]
        self.assertEqual(
            ids,
            [
                f"{child.id}-projection-4",
                f"{child.id}-projection-3",
                f"{child.id}-projection-2",
            ],
        )

    def test_v2_context_bounds_maximum_candidate_commitments(
        self,
    ):
        from ctf_os.engine.pwn_disclosure import (
            PWN_DISCLOSURE_MAX_CANDIDATES,
            PwnDisclosureCandidate,
            PwnDisclosureMapCommitment,
            PwnDisclosureResult,
            PwnDisclosureStatus,
        )

        state = self.completed()
        child = self.child(state)
        envelope = PwnRuntimeSnapshotDisclosureEnvelope.from_dict(
            child.extra["pwn_disclosure"]
        )
        original_result = envelope.result
        candidates = []
        for index in range(PWN_DISCLOSURE_MAX_CANDIDATES):
            replay_hashes = tuple(
                hashlib.sha256(
                    f"{index}:{replay}".encode("ascii")
                ).hexdigest()
                for replay in range(4)
            )
            candidates.append(
                PwnDisclosureCandidate(
                    byte_offset=index * 17,
                    hex_width=6,
                    replay_value_sha256=replay_hashes,
                    distinct_value_count=4,
                    final_value_sha256=replay_hashes[-1],
                    mapped_range=PwnDisclosureMapCommitment(
                        line_index=1,
                        line_sha256="a" * 64,
                    ),
                    payload_derived=False,
                )
            )
        result = PwnDisclosureResult(
            status=PwnDisclosureStatus.DYNAMIC_POINTER_OBSERVED,
            reason_code="dynamic_pointer_observed",
            binding=original_result.binding,
            candidates=tuple(candidates),
        )
        child.extra["pwn_disclosure"] = (
            PwnRuntimeSnapshotDisclosureEnvelope(
                schema_version=envelope.schema_version,
                phase=envelope.phase,
                expectation_source_state_revision=(
                    envelope.expectation_source_state_revision
                ),
                trusted_receipt_expectation=(
                    envelope.trusted_receipt_expectation
                ),
                trusted_receipt_expectation_sha256=(
                    envelope.trusted_receipt_expectation_sha256
                ),
                evaluation_source_state_revision=(
                    envelope.evaluation_source_state_revision
                ),
                result=result,
                result_sha256=result.evidence_sha256,
            ).to_dict()
        )
        state.validate()

        record = json.loads(
            _pwn_runtime_snapshot_context_records(state)[0]
        )

        commitments = record["candidate_commitments"]
        self.assertEqual(
            len(commitments),
            PWN_DISCLOSURE_MAX_CANDIDATES,
        )
        self.assertEqual(record["candidate_count"], len(candidates))
        self.assertEqual(
            [item["byte_offset"] for item in commitments],
            [item.byte_offset for item in candidates],
        )
        self.assertEqual(
            commitments[-1]["replay_value_sha256"],
            list(candidates[-1].replay_value_sha256),
        )
        self.assertNotIn("mapped_range", commitments[-1])
        self.assertNotIn("payload_derived", commitments[-1])

    def test_v2_context_redacts_both_incomplete_disclosure_phases(
        self,
    ):
        complete = self.completed()
        complete_child = self.child(complete)
        envelope = PwnRuntimeSnapshotDisclosureEnvelope.from_dict(
            complete_child.extra["pwn_disclosure"]
        )
        cases = (
            (
                PwnDisclosurePhase.AWAITING_EXPECTATION,
                PwnRuntimeSnapshotDisclosureEnvelope(
                    schema_version=envelope.schema_version,
                    phase=PwnDisclosurePhase.AWAITING_EXPECTATION,
                    expectation_source_state_revision=None,
                    trusted_receipt_expectation=None,
                    trusted_receipt_expectation_sha256=None,
                    evaluation_source_state_revision=None,
                    result=None,
                    result_sha256=None,
                ),
                complete.revision,
            ),
            (
                PwnDisclosurePhase.EXPECTATION_COMMITTED,
                PwnRuntimeSnapshotDisclosureEnvelope(
                    schema_version=envelope.schema_version,
                    phase=PwnDisclosurePhase.EXPECTATION_COMMITTED,
                    expectation_source_state_revision=(
                        envelope.expectation_source_state_revision
                    ),
                    trusted_receipt_expectation=(
                        envelope.trusted_receipt_expectation
                    ),
                    trusted_receipt_expectation_sha256=(
                        envelope
                        .trusted_receipt_expectation_sha256
                    ),
                    evaluation_source_state_revision=None,
                    result=None,
                    result_sha256=None,
                ),
                envelope.expectation_source_state_revision + 1,
            ),
        )
        for phase, replacement, revision in cases:
            with self.subTest(phase=phase.value):
                state = self.completed()
                state.revision = revision
                self.child(state).extra["pwn_disclosure"] = (
                    replacement.to_dict()
                )
                state.validate()

                record = json.loads(
                    _pwn_runtime_snapshot_context_records(state)[0]
                )

                self.assertEqual(
                    record["disclosure_phase"],
                    phase.value,
                )
                self.assertIsNone(record["result_status"])
                self.assertIsNone(record["result_sha256"])
                self.assertEqual(record["candidate_count"], 0)
                self.assertNotIn("rip", record)
                self.assertNotIn("maps", record)
                self.assertNotIn(
                    "trusted_receipt_expectation",
                    record,
                )

    def test_resume_capsule_keeps_mandatory_raw_free_v2_pointer(
        self,
    ):
        capsule = render_resume_capsule(
            self.completed(),
            state_path=Path(
                "/canonical/challenge/state.json"
            ),
        )

        record = json.loads(capsule.text)
        disclosure = record["pwn_disclosure"]
        self.assertEqual(disclosure["phase"], "complete")
        self.assertEqual(disclosure["snapshot_status"], "CAPTURED")
        self.assertEqual(disclosure["result_status"], "UNRESOLVED")
        self.assertEqual(len(disclosure["artifact_pointers"]), 3)
        self.assertNotIn("rip", disclosure)
        self.assertNotIn("rsp", disclosure)
        self.assertNotIn("maps", disclosure)
        self.assertNotIn("0000000000400010", capsule.text)
        self.assertNotIn("00007fffffffe000", capsule.text)
        self.assertNotIn(
            '"trusted_receipt_expectation":',
            capsule.text,
        )

    def test_resume_capsule_omits_disclosure_for_legacy_v1_snapshot(
        self,
    ):
        legacy = self.completed()
        child = self.child(legacy)
        child.extra["managed_contract_version"] = 1
        child.extra.pop("pwn_disclosure")
        legacy.validate()

        capsule = render_resume_capsule(
            legacy,
            state_path=Path(
                "/canonical/challenge/state.json"
            ),
        )

        self.assertNotIn("pwn_disclosure", json.loads(capsule.text))

    def test_resume_capsule_fails_closed_on_tampered_disclosure_pointer(
        self,
    ):
        state = self.completed()
        stderr_id = self.evidence(state)["stderr_artifact_id"]
        stderr = next(
            item
            for item in state.artifacts
            if item.id == stderr_id
        )
        stderr.sha256 = "0" * 64

        with self.assertRaises(ModelValidationError):
            render_resume_capsule(
                state,
                state_path=Path(
                    "/canonical/challenge/state.json"
                ),
            )

    def test_full_model_context_never_replays_v2_raw_addresses(
        self,
    ):
        context = build_context_pack(
            self.completed(),
            get_adapter("pwn"),
            state_path=Path(
                "/canonical/challenge/state.json"
            ),
        )

        self.assertIn(
            '"kind":"pwn_runtime_snapshot_disclosure"',
            context.text,
        )
        self.assertIn('"disclosure_phase":"complete"', context.text)
        self.assertNotIn("0000000000400010", context.text)
        self.assertNotIn("00007fffffffe000", context.text)
        self.assertNotIn(
            "00400000-00401000 r-xp",
            context.text,
        )
        self.assertNotIn(
            "7fffffffd000-7ffffffff000 rw-p",
            context.text,
        )
        self.assertNotIn("/challenge/bin", context.text)
        self.assertNotIn("[stack]", context.text)
        self.assertNotIn('"positive_receipts":', context.text)
        self.assertNotIn('"trusted_receipt_expectation":', context.text)

    def test_minimum_resume_budget_retains_compact_disclosure_pointer(
        self,
    ):
        state = self.completed()
        capsule = render_resume_capsule(
            state,
            state_path=Path(
                "/home/linux/CTF-OS/workspaces/"
                "대한민국최고권위보안대회/pwn/"
                "아주긴도전문제이름/state.json"
            ),
            policy=ResumeCapsulePolicy(
                max_bytes=MIN_RESUME_CAPSULE_BYTES
            ),
        )

        self.assertLessEqual(
            len(capsule.text.encode("ascii")),
            MIN_RESUME_CAPSULE_BYTES,
        )
        disclosure = json.loads(capsule.text)["pwn_disclosure"]
        self.assertTrue(disclosure["diagnostic_only"])
        stdout_id = self.evidence(state)["stdout_artifact_id"]
        stdout = next(
            item
            for item in state.artifacts
            if item.id == stdout_id
        )
        self.assertEqual(
            disclosure["artifact_pointer"],
            {
                "artifact_id": stdout.id,
                "label": "stdout",
                "path": stdout.path,
                "sha256": stdout.sha256,
                "size": stdout.size,
            },
        )
        self.assertTrue(
            disclosure["parent_crash_omitted"]
        )
        self.assertNotIn("phase", disclosure)
        self.assertNotIn("result_reason_code", disclosure)
        self.assertNotIn("result_sha256", disclosure)
        self.assertNotIn("pwn_crash", json.loads(capsule.text))
        self.assertNotIn("0000000000400010", capsule.text)

    def test_minimum_resume_keeps_newer_or_checkpoint_crash_over_disclosure(
        self,
    ):
        state_path = Path("/" + ("x" * 243) + "/state.json")
        original = resume_capsule_module._pwn_disclosure_projection

        def mismatched(*args, **kwargs):
            projection = original(*args, **kwargs)
            if projection is not None and not kwargs["compact"]:
                projection = {
                    **projection,
                    "parent_experiment_id": "E-different-crash",
                }
            return projection

        with mock.patch.object(
            resume_capsule_module,
            "_pwn_disclosure_projection",
            side_effect=mismatched,
        ):
            capsule = render_resume_capsule(
                self.completed(),
                state_path=state_path,
                policy=ResumeCapsulePolicy(
                    max_bytes=MIN_RESUME_CAPSULE_BYTES
                ),
            )
        record = json.loads(capsule.text)
        self.assertIn("pwn_crash", record)
        self.assertTrue(record["pwn_crash"]["disclosure_omitted"])
        self.assertNotIn("pwn_disclosure", record)

        state = self.completed()
        parent = next(
            item
            for item in state.experiments
            if item.id == self.parent_id
        )
        with mock.patch.object(
            resume_capsule_module,
            "_checkpoint_pwn_pointer_experiment",
            return_value=parent,
        ):
            capsule = render_resume_capsule(
                state,
                state_path=state_path,
                policy=ResumeCapsulePolicy(
                    max_bytes=MIN_RESUME_CAPSULE_BYTES
                ),
            )
        record = json.loads(capsule.text)
        self.assertEqual(
            record["pwn_crash"]["experiment_id"],
            self.parent_id,
        )
        self.assertTrue(record["pwn_crash"]["disclosure_omitted"])
        self.assertNotIn("pwn_disclosure", record)


if __name__ == "__main__":
    unittest.main()
