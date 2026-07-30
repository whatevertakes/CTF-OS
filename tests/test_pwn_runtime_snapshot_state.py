from __future__ import annotations

import copy
import hashlib
import json
import unittest

from ctf_os.capabilities import REQUIRED_MANAGED_ATTESTATIONS
from ctf_os.engine.pwn_runtime_snapshot import (
    pwn_runtime_snapshot_child_experiment_id,
)
from ctf_os.engine.context_pack import (
    _pwn_runtime_snapshot_context_records,
)
from ctf_os.models import (
    ExperimentStatus,
    ModelValidationError,
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

    def test_context_projects_registers_and_pointers_not_raw_maps(self):
        records = _pwn_runtime_snapshot_context_records(
            self.completed()
        )

        self.assertEqual(len(records), 1)
        record = json.loads(records[0])
        self.assertEqual(record["kind"], "pwn_runtime_snapshot")
        self.assertEqual(record["status"], "CAPTURED")
        self.assertEqual(record["rip"], "0000000000400010")
        self.assertEqual(record["rsp"], "00007fffffffe000")
        self.assertEqual(len(record["artifact_pointers"]), 3)
        self.assertNotIn("content_base64", records[0])


if __name__ == "__main__":
    unittest.main()
