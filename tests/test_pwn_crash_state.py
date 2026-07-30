from __future__ import annotations

import copy
import unittest

from ctf_os.models import (
    ExecutionReceipt,
    Experiment,
    ExperimentStatus,
    ModelValidationError,
    ReceiptOutcome,
    RunOrigin,
    RunReference,
    RunStatus,
)
import tests.test_pwn_crash_execution as execution_tests


class PwnCrashStateValidationTests(unittest.TestCase):
    """Tamper tests for the canonical six-attempt state graph."""

    @classmethod
    def setUpClass(cls) -> None:
        case = execution_tests.PwnCrashExecutionTests(
            methodName=(
                "test_confirmed_gate_uses_six_clean_networkless_fixed_calls"
            )
        )
        case.setUp()
        try:
            coordinator = execution_tests._SandboxCoordinator(
                case._confirming_statuses()
            )
            engine, experiment_id, _artifact_path, _payload = (
                case._fixture(coordinator)
            )
            cls.registered_state = copy.deepcopy(
                engine.store.load(case.identity)
            )
            cls.canonical_state = copy.deepcopy(
                case._execute(engine, experiment_id)
            )
            cls.experiment_id = experiment_id
        finally:
            case.tearDown()

    def state(self):
        return copy.deepcopy(self.canonical_state)

    def experiment(self, state):
        return next(
            item
            for item in state.experiments
            if item.id == self.experiment_id
        )

    def evidence(self, state):
        return self.experiment(state).result["pwn_crash_evidence"]

    def assert_invalid(self, state, pattern: str = "Pwn crash") -> None:
        with self.assertRaisesRegex(ModelValidationError, pattern):
            state.validate()

    def test_canonical_and_round_tripped_states_validate(self):
        state = self.state()
        state.validate()
        type(state).from_dict(state.to_dict()).validate()

    def test_reordered_or_copied_attempt_links_are_rejected(self):
        reordered = self.state()
        attempts = self.evidence(reordered)["attempts"]
        attempts[0], attempts[1] = attempts[1], attempts[0]
        self.assert_invalid(reordered)

        copied = self.state()
        attempts = self.evidence(copied)["attempts"]
        attempts[1] = copy.deepcopy(attempts[0])
        self.assert_invalid(copied)

    def test_request_hash_copy_mismatch_is_rejected(self):
        state = self.state()
        attempt = self.evidence(state)["attempts"][0]
        run = next(item for item in state.runs if item.id == attempt["run_id"])
        run.extra["pwn_crash"]["request_sha256"] = "0" * 64
        self.assert_invalid(state, "run/receipt binding")

    def test_execution_contract_hash_tamper_is_rejected(self):
        state = self.state()
        attempt = self.evidence(state)["attempts"][0]
        run = next(item for item in state.runs if item.id == attempt["run_id"])
        receipt = next(
            item
            for item in state.receipts
            if item.id == attempt["receipt_id"]
        )
        record = copy.deepcopy(run.extra["pwn_crash"])
        record["execution_contract_sha256"] = "0" * 64
        record["receipt"]["execution_contract_sha256"] = "0" * 64
        run.extra["pwn_crash"] = copy.deepcopy(record)
        receipt.extra["pwn_crash"] = copy.deepcopy(record)
        self.assert_invalid(state, "execution contract hash")

    def test_capability_hash_tamper_is_rejected(self):
        state = self.state()
        attempt = self.evidence(state)["attempts"][0]
        run = next(item for item in state.runs if item.id == attempt["run_id"])
        receipt = next(
            item
            for item in state.receipts
            if item.id == attempt["receipt_id"]
        )
        record = copy.deepcopy(run.extra["pwn_crash"])
        record["receipt"]["capability_attestation_sha256"] = "0" * 64
        record["execution_contract"]["producer"][
            "capability_attestation_sha256"
        ] = "0" * 64
        record["execution_contract_sha256"] = "0" * 64
        record["receipt"]["execution_contract_sha256"] = "0" * 64
        run.extra["pwn_crash"] = copy.deepcopy(record)
        receipt.extra["pwn_crash"] = copy.deepcopy(record)
        self.assert_invalid(state)

    def test_stdout_artifact_source_run_tamper_is_rejected(self):
        state = self.state()
        attempts = self.evidence(state)["attempts"]
        stdout = next(
            item
            for item in state.artifacts
            if item.id == attempts[0]["stdout_artifact_id"]
        )
        stdout.source_run_id = attempts[1]["run_id"]
        self.assert_invalid(state)

    def test_extra_receipt_is_rejected_despite_typed_exception(self):
        state = self.state()
        run_id = "R-pwn-extra-receipt"
        state.runs.append(
            RunReference(
                id=run_id,
                base_revision=state.revision,
                status=RunStatus.FAILED,
                request_path="runs/R-pwn-extra-receipt/request.json",
                result_path="runs/R-pwn-extra-receipt/result.json",
                validation_path="runs/R-pwn-extra-receipt/validation.json",
                origin=RunOrigin.MANAGED_TOOL,
                extra={"experiment_id": self.experiment_id},
            )
        )
        state.receipts.append(
            ExecutionReceipt(
                id="RCPT-pwn-extra-receipt",
                experiment_id=self.experiment_id,
                run_id=run_id,
                outcome=ReceiptOutcome.FAILED,
            )
        )
        self.assert_invalid(state, "evidence lists")

    def test_verdict_status_mismatch_is_rejected(self):
        state = self.state()
        self.experiment(state).status = ExperimentStatus.INCONCLUSIVE
        self.assert_invalid(state, "verdict/status")

    def test_generic_experiment_cannot_spoof_typed_marker(self):
        state = self.state()
        state.experiments.append(
            Experiment(
                id="E-pwn-marker-spoof",
                hypothesis_ids=[],
                command="true",
                expected_observation="exit",
                keep_if="exit zero",
                drop_if="otherwise",
                timeout_seconds=1,
                extra={
                    "engine_executor": "pwn_crash_differential_v1",
                },
            )
        )
        self.assert_invalid(state, "request has missing or unknown fields")

    def test_setup_failure_requires_a_zero_chain(self):
        state = copy.deepcopy(self.registered_state)
        experiment = self.experiment(state)
        experiment.status = ExperimentStatus.FAILED
        experiment.result = {
            "error": "Pwn crash gate failed closed: capability probe failed"
        }
        state.validate()

        state.runs.append(
            RunReference(
                id="R-orphan-setup-failure",
                base_revision=state.revision,
                status=RunStatus.FAILED,
                origin=RunOrigin.COMPATIBILITY,
            )
        )
        state.receipts.append(
            ExecutionReceipt(
                id="RCPT-orphan-setup-failure",
                experiment_id=experiment.id,
                run_id="R-orphan-setup-failure",
                outcome=ReceiptOutcome.FAILED,
            )
        )
        self.assert_invalid(state, "pre-commit failure retained")


if __name__ == "__main__":
    unittest.main()
