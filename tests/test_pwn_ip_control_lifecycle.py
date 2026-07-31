from __future__ import annotations

import hashlib
import unittest

from ctf_os.contracts.pwn_runtime_snapshot_v1 import (
    PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES,
    PwnRuntimeSnapshotV1Maps,
    PwnRuntimeSnapshotV1Registers,
    build_pwn_runtime_snapshot_v1_result,
)
from ctf_os.engine.pwn_ip_control import (
    PWN_IP_CONTROL_LEGACY_MANAGED_CONTRACT_VERSION,
    PWN_IP_CONTROL_LEGACY_TIMEOUT_SECONDS,
    PWN_IP_CONTROL_MANAGED_CONTRACT_VERSION,
    PWN_IP_CONTROL_REPLAY_COUNT,
    PWN_IP_CONTROL_TIMEOUT_SECONDS,
    PWN_IP_CONTROL_WIDTH_BYTES,
    PwnIpControlResult,
    PwnIpControlStatus,
    pwn_ip_control_child_experiment_id,
)
from ctf_os.engine.pwn_runtime_snapshot import (
    pwn_runtime_snapshot_child_experiment_id,
)
from ctf_os.models import ExperimentStatus
from tests import test_pwn_crash_execution as crash_execution
from tests import test_pwn_runtime_snapshot_lifecycle as snapshot_lifecycle


_CONTROL_OFFSET = 17
_BASELINE_RIP = 0x0000000000400010
_BASELINE_RIP_BYTES = _BASELINE_RIP.to_bytes(
    PWN_IP_CONTROL_WIDTH_BYTES,
    "little",
)


class _IpControlSandbox(snapshot_lifecycle._SnapshotSandbox):
    def run_clean_proof(
        self,
        spec,
        *,
        input_locators=(),
        proof_inputs=(),
    ):
        if "--snapshot-recipe-sha256" not in spec.argv:
            return super().run_clean_proof(
                spec,
                input_locators=input_locators,
                proof_inputs=proof_inputs,
            )
        directory = self.work / "proof" / "clean-snapshot"
        for name in ("stdout.log", "stderr.log"):
            path = directory / name
            if path.exists():
                path.chmod(0o600)
        result = super().run_clean_proof(
            spec,
            input_locators=input_locators,
            proof_inputs=proof_inputs,
        )
        proof_input = proof_inputs[0]
        payload = (self.work / proof_input.source_locator).read_bytes()
        self.owner.snapshot_payloads.append(payload)
        rip = int.from_bytes(
            payload[
                _CONTROL_OFFSET : _CONTROL_OFFSET
                + PWN_IP_CONTROL_WIDTH_BYTES
            ],
            "little",
        )
        if (
            self.owner.wrong_replay_ordinal is not None
            and self.owner.snapshot_calls - 1
            == self.owner.wrong_replay_ordinal
        ):
            rip = _BASELINE_RIP
        registers = PwnRuntimeSnapshotV1Registers(
            tuple(
                (
                    name,
                    f"{rip:016x}"
                    if name == "rip"
                    else "00007fffffffe000"
                    if name == "rsp"
                    else f"{index:016x}",
                )
                for index, name in enumerate(
                    PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES
                )
            )
        )
        maps = PwnRuntimeSnapshotV1Maps(
            b"00400000-00401000 r-xp 00000000 00:00 0 /challenge/bin\n"
            b"7fffffffd000-7ffffffff000 rw-p 00000000 00:00 0 [stack]\n"
        )
        argv = spec.argv
        document = build_pwn_runtime_snapshot_v1_result(
            registers=registers,
            maps=maps,
            expected_source_manifest_sha256=crash_execution._argument(
                argv,
                "--source-manifest-sha256",
            ),
            expected_source_sha256=crash_execution._argument(
                argv,
                "--source-sha256",
            ),
            expected_source_size_bytes=int(
                crash_execution._argument(
                    argv,
                    "--source-size-bytes",
                )
            ),
            expected_payload_sha256=crash_execution._argument(
                argv,
                "--payload-sha256",
            ),
            expected_payload_size_bytes=int(
                crash_execution._argument(
                    argv,
                    "--payload-size-bytes",
                )
            ),
            expected_parent_crash_recipe_sha256=(
                crash_execution._argument(
                    argv,
                    "--parent-crash-recipe-sha256",
                )
            ),
            expected_parent_crash_evaluation_sha256=(
                crash_execution._argument(
                    argv,
                    "--parent-crash-evaluation-sha256",
                )
            ),
            expected_signal_number=int(
                crash_execution._argument(
                    argv,
                    "--expected-signal-number",
                )
            ),
            expected_snapshot_recipe_sha256=(
                crash_execution._argument(
                    argv,
                    "--snapshot-recipe-sha256",
                )
            ),
        ).canonical_bytes()
        self.assertEqualLength(document, result.stdout_bytes)
        stdout = directory / "stdout.log"
        stdout.chmod(0o600)
        stdout.write_bytes(document)
        stdout.chmod(0o400)
        return result

    @staticmethod
    def assertEqualLength(document: bytes, expected: int) -> None:
        if len(document) != expected:
            raise AssertionError("dynamic snapshot document size changed")


class _IpControlCoordinator(snapshot_lifecycle._SnapshotCoordinator):
    def __init__(self, statuses) -> None:
        super().__init__(statuses)
        self.snapshot_payloads: list[bytes] = []
        self.wrong_replay_ordinal: int | None = None

    def factory(self, _state, work, policy):
        return _IpControlSandbox(self, work, policy)


class PwnIpControlLifecycleTests(unittest.TestCase):
    def _fixture(self):
        fixture = crash_execution.PwnCrashExecutionTests(
            methodName=(
                "test_confirmed_gate_uses_six_clean_networkless_fixed_calls"
            )
        )
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        coordinator = _IpControlCoordinator(
            fixture._confirming_statuses()
        )
        engine, parent_id, artifact_path, _payload = fixture._fixture(
            coordinator
        )
        payload = (
            b"engine-prefix-000"
            + _BASELINE_RIP_BYTES
            + b"-engine-suffix"
        )
        self.assertEqual(
            payload.find(_BASELINE_RIP_BYTES),
            _CONTROL_OFFSET,
        )
        self.assertEqual(
            payload.find(_BASELINE_RIP_BYTES, _CONTROL_OFFSET + 1),
            -1,
        )
        digest = hashlib.sha256(payload).hexdigest()
        artifact_path.chmod(0o600)
        artifact_path.write_bytes(payload)
        artifact_path.chmod(0o400)

        def bind_payload(state) -> None:
            experiment = next(
                item
                for item in state.experiments
                if item.id == parent_id
            )
            artifact = next(
                item
                for item in state.artifacts
                if item.id == experiment.artifact_ids[0]
            )
            artifact.sha256 = digest
            artifact.size = len(payload)
            request = experiment.extra["pwn_crash_request"]
            request["payload_sha256"] = digest
            request["payload_size_bytes"] = len(payload)

        engine.store.update(fixture.identity, bind_payload)
        return fixture, coordinator, engine, parent_id, payload

    @staticmethod
    def _snapshot_capability(digest):
        return {
            "ok": True,
            "image_digest": digest,
            "available": ["pwn_runtime_snapshot_v1"],
            "attestations": {
                "pwn_runtime_snapshot_v1": dict(
                    snapshot_lifecycle.REQUIRED_MANAGED_ATTESTATIONS[
                        "pwn_runtime_snapshot_v1"
                    ]
                )
            },
            "attestation_errors": {},
        }

    def test_confirmed_snapshot_proves_only_ip_control_in_three_replays(
        self,
    ) -> None:
        fixture, coordinator, engine, parent_id, payload = self._fixture()
        fixture._execute(engine, parent_id)
        snapshot_id = pwn_runtime_snapshot_child_experiment_id(parent_id)
        engine._capability_probe = self._snapshot_capability
        snapshot_state = engine.execute_registered_experiments(
            fixture.identity,
            maximum=1,
            _session_owned=True,
            experiment_ids=(snapshot_id,),
        )
        capability_calls: list[str] = []

        def capability(digest: str):
            capability_calls.append(digest)
            return self._snapshot_capability(digest)

        engine._capability_probe = capability
        before = {
            "status": snapshot_state.status,
            "candidates": len(snapshot_state.candidates),
            "submissions": len(snapshot_state.submissions),
            "facts": len(snapshot_state.facts),
            "progress": len(snapshot_state.progress_markers),
        }
        ip_control_id = pwn_ip_control_child_experiment_id(snapshot_id)
        completed = engine.execute_registered_experiments(
            fixture.identity,
            maximum=1,
            _session_owned=True,
            experiment_ids=(ip_control_id,),
        )

        child = next(
            item
            for item in completed.experiments
            if item.id == ip_control_id
        )
        envelope = child.result["pwn_ip_control_evidence"]
        result = PwnIpControlResult.from_dict(envelope["result"])
        self.assertIs(child.status, ExperimentStatus.COMPLETED)
        self.assertEqual(
            child.extra["managed_contract_version"],
            PWN_IP_CONTROL_MANAGED_CONTRACT_VERSION,
        )
        self.assertEqual(
            child.timeout_seconds,
            PWN_IP_CONTROL_TIMEOUT_SECONDS,
        )
        self.assertIs(result.status, PwnIpControlStatus.PROVEN)
        self.assertTrue(result.instruction_pointer_control_proven)
        self.assertFalse(result.to_dict()["authorities"]["exploit_proven"])
        self.assertFalse(result.to_dict()["authorities"]["flag_proven"])
        self.assertFalse(result.to_dict()["authorities"]["proof_satisfied"])
        self.assertFalse(
            result.to_dict()["authorities"]["stage_advance_authorized"]
        )
        self.assertEqual(result.controlled_offset, _CONTROL_OFFSET)
        self.assertEqual(
            len(child.evidence_run_ids),
            PWN_IP_CONTROL_REPLAY_COUNT,
        )
        self.assertEqual(
            len(child.evidence_receipt_ids),
            PWN_IP_CONTROL_REPLAY_COUNT,
        )
        self.assertEqual(len(child.artifact_ids), 13)
        self.assertEqual(len(capability_calls), 1)
        capability_artifacts = [
            item
            for item in completed.artifacts
            if item.extra.get("kind")
            == "pwn_ip_control_capability_attestation"
        ]
        self.assertEqual(
            len(capability_artifacts),
            PWN_IP_CONTROL_REPLAY_COUNT,
        )
        self.assertEqual(
            len({item.sha256 for item in capability_artifacts}),
            PWN_IP_CONTROL_REPLAY_COUNT,
        )
        self.assertEqual(
            len(
                {
                    item.extra["transport_recipe_sha256"]
                    for item in capability_artifacts
                }
            ),
            PWN_IP_CONTROL_REPLAY_COUNT,
        )
        self.assertEqual(coordinator.snapshot_calls, 4)
        self.assertEqual(coordinator.generic_calls, 0)
        self.assertEqual(coordinator.snapshot_payloads[0], payload)
        variants = coordinator.snapshot_payloads[1:]
        self.assertEqual(len(variants), PWN_IP_CONTROL_REPLAY_COUNT)
        self.assertEqual(len(set(variants)), PWN_IP_CONTROL_REPLAY_COUNT)
        for variant in variants:
            changed = [
                index
                for index, (original, current) in enumerate(
                    zip(payload, variant, strict=True)
                )
                if original != current
            ]
            self.assertTrue(changed)
            self.assertTrue(
                all(
                    _CONTROL_OFFSET
                    <= index
                    < _CONTROL_OFFSET + PWN_IP_CONTROL_WIDTH_BYTES
                    for index in changed
                )
            )
        self.assertEqual(completed.status, before["status"])
        self.assertEqual(len(completed.candidates), before["candidates"])
        self.assertEqual(len(completed.submissions), before["submissions"])
        self.assertEqual(len(completed.facts), before["facts"] + 1)
        self.assertEqual(
            len(completed.progress_markers),
            before["progress"] + 1,
        )
        self.assertEqual(child.evidence_fact_ids, [completed.facts[-1].id])
        self.assertEqual(
            completed.facts[-1].extra["pwn_ip_control"][
                "controlled_width_bytes"
            ],
            PWN_IP_CONTROL_WIDTH_BYTES,
        )
        for spec, policy in zip(
            coordinator.specs[-PWN_IP_CONTROL_REPLAY_COUNT:],
            coordinator.policies[-PWN_IP_CONTROL_REPLAY_COUNT:],
            strict=True,
        ):
            self.assertEqual(dict(spec.environment), {})
            self.assertIsNone(spec.network_target)
            self.assertEqual(spec.resource_request.network, 0)
            self.assertEqual(policy.authorize(None), "none")
        replay_deadlines = {
            spec.deadline_monotonic_seconds
            for spec in coordinator.specs[-PWN_IP_CONTROL_REPLAY_COUNT:]
        }
        self.assertNotIn(None, replay_deadlines)
        self.assertEqual(len(replay_deadlines), 1)

    def test_legacy_v1_child_remains_readable_and_executable(self) -> None:
        fixture, _coordinator, engine, parent_id, _payload = self._fixture()
        fixture._execute(engine, parent_id)
        snapshot_id = pwn_runtime_snapshot_child_experiment_id(parent_id)
        engine._capability_probe = self._snapshot_capability
        engine.execute_registered_experiments(
            fixture.identity,
            maximum=1,
            _session_owned=True,
            experiment_ids=(snapshot_id,),
        )
        disclosed = engine._advance_pwn_runtime_snapshot_disclosures(
            fixture.identity
        )
        engine._register_pwn_ip_control_child_if_applicable(
            fixture.identity,
            disclosed,
        )
        child_id = pwn_ip_control_child_experiment_id(snapshot_id)

        def restore_legacy_identity(state) -> None:
            child = next(
                item for item in state.experiments if item.id == child_id
            )
            child.extra["managed_contract_version"] = (
                PWN_IP_CONTROL_LEGACY_MANAGED_CONTRACT_VERSION
            )
            child.timeout_seconds = PWN_IP_CONTROL_LEGACY_TIMEOUT_SECONDS

        engine.store.update(fixture.identity, restore_legacy_identity)
        loaded = engine.store.load(fixture.identity)
        legacy = next(
            item for item in loaded.experiments if item.id == child_id
        )
        self.assertIs(legacy.status, ExperimentStatus.REGISTERED)
        self.assertEqual(
            legacy.extra["managed_contract_version"],
            PWN_IP_CONTROL_LEGACY_MANAGED_CONTRACT_VERSION,
        )
        self.assertEqual(
            legacy.timeout_seconds,
            PWN_IP_CONTROL_LEGACY_TIMEOUT_SECONDS,
        )

        completed = engine.execute_registered_experiments(
            fixture.identity,
            maximum=1,
            _session_owned=True,
            experiment_ids=(child_id,),
        )
        terminal = next(
            item for item in completed.experiments if item.id == child_id
        )
        self.assertIs(terminal.status, ExperimentStatus.COMPLETED)
        self.assertEqual(
            terminal.extra["managed_contract_version"],
            PWN_IP_CONTROL_LEGACY_MANAGED_CONTRACT_VERSION,
        )
        self.assertEqual(
            terminal.timeout_seconds,
            PWN_IP_CONTROL_LEGACY_TIMEOUT_SECONDS,
        )
        completed.validate()

    def test_running_child_recovery_fails_closed_without_evidence(
        self,
    ) -> None:
        fixture, _coordinator, engine, parent_id, _payload = self._fixture()
        fixture._execute(engine, parent_id)
        snapshot_id = pwn_runtime_snapshot_child_experiment_id(parent_id)
        engine._capability_probe = self._snapshot_capability
        engine.execute_registered_experiments(
            fixture.identity,
            maximum=1,
            _session_owned=True,
            experiment_ids=(snapshot_id,),
        )
        disclosed = engine._advance_pwn_runtime_snapshot_disclosures(
            fixture.identity
        )
        engine._register_pwn_ip_control_child_if_applicable(
            fixture.identity,
            disclosed,
        )
        child_id = pwn_ip_control_child_experiment_id(snapshot_id)

        def leave_running(state) -> None:
            child = next(
                item
                for item in state.experiments
                if item.id == child_id
            )
            self.assertIs(child.status, ExperimentStatus.REGISTERED)
            child.status = ExperimentStatus.RUNNING

        engine.store.update(fixture.identity, leave_running)
        recovered = engine._recover_session_boundary(fixture.identity)
        child = next(
            item
            for item in recovered.experiments
            if item.id == child_id
        )
        self.assertIs(child.status, ExperimentStatus.FAILED)
        self.assertEqual(set(child.result), {"error"})
        self.assertTrue(
            child.result["error"].startswith(
                "Pwn IP control failed closed: "
            )
        )
        self.assertEqual(
            set(child.extra),
            {
                "managed_contract_version",
                "engine_executor",
                "baseline_experiment_id",
                "pwn_ip_control_plan",
            },
        )
        self.assertEqual(len(child.artifact_ids), PWN_IP_CONTROL_REPLAY_COUNT)
        self.assertEqual(child.evidence_fact_ids, [])
        self.assertEqual(child.evidence_run_ids, [])
        self.assertEqual(child.evidence_receipt_ids, [])
        self.assertFalse(
            any(
                run.extra.get("experiment_id") == child_id
                for run in recovered.runs
            )
        )
        self.assertFalse(
            any(
                receipt.experiment_id == child_id
                for receipt in recovered.receipts
            )
        )

    def test_one_wrong_replay_cannot_promote_primitive_authority(
        self,
    ) -> None:
        fixture, coordinator, engine, parent_id, _payload = self._fixture()
        fixture._execute(engine, parent_id)
        snapshot_id = pwn_runtime_snapshot_child_experiment_id(parent_id)
        engine._capability_probe = self._snapshot_capability
        baseline = engine.execute_registered_experiments(
            fixture.identity,
            maximum=1,
            _session_owned=True,
            experiment_ids=(snapshot_id,),
        )
        before_facts = len(baseline.facts)
        before_progress = len(baseline.progress_markers)
        before_status = baseline.status
        coordinator.wrong_replay_ordinal = 2
        child_id = pwn_ip_control_child_experiment_id(snapshot_id)
        completed = engine.execute_registered_experiments(
            fixture.identity,
            maximum=1,
            _session_owned=True,
            experiment_ids=(child_id,),
        )

        child = next(
            item
            for item in completed.experiments
            if item.id == child_id
        )
        result = PwnIpControlResult.from_dict(
            child.result["pwn_ip_control_evidence"]["result"]
        )
        self.assertIs(child.status, ExperimentStatus.COMPLETED)
        self.assertIs(result.status, PwnIpControlStatus.UNVERIFIABLE)
        self.assertEqual(result.reason_code, "instruction_pointer_mismatch")
        self.assertFalse(result.instruction_pointer_control_proven)
        self.assertFalse(
            result.to_dict()["authorities"]["primitive_proven"]
        )
        self.assertEqual(child.evidence_fact_ids, [])
        self.assertEqual(len(completed.facts), before_facts)
        self.assertEqual(len(completed.progress_markers), before_progress)
        self.assertEqual(completed.status, before_status)

    def test_capability_mismatch_fails_once_before_any_replay(self) -> None:
        fixture, coordinator, engine, parent_id, _payload = self._fixture()
        fixture._execute(engine, parent_id)
        snapshot_id = pwn_runtime_snapshot_child_experiment_id(parent_id)
        engine._capability_probe = self._snapshot_capability
        baseline = engine.execute_registered_experiments(
            fixture.identity,
            maximum=1,
            _session_owned=True,
            experiment_ids=(snapshot_id,),
        )
        before = (
            len(baseline.facts),
            len(baseline.progress_markers),
            coordinator.snapshot_calls,
        )
        capability_calls: list[str] = []

        def mismatched(digest: str):
            capability_calls.append(digest)
            report = self._snapshot_capability(digest)
            report["image_digest"] = "sha256:" + ("0" * 64)
            return report

        engine._capability_probe = mismatched
        child_id = pwn_ip_control_child_experiment_id(snapshot_id)
        failed = engine.execute_registered_experiments(
            fixture.identity,
            maximum=1,
            _session_owned=True,
            experiment_ids=(child_id,),
        )
        child = next(
            item for item in failed.experiments if item.id == child_id
        )
        self.assertIs(child.status, ExperimentStatus.FAILED)
        self.assertIn("invalid_capability_report", child.result["error"])
        self.assertEqual(len(capability_calls), 1)
        self.assertEqual(coordinator.snapshot_calls, before[2])
        self.assertEqual(len(failed.facts), before[0])
        self.assertEqual(len(failed.progress_markers), before[1])
        self.assertEqual(child.evidence_fact_ids, [])
        self.assertEqual(child.evidence_run_ids, [])
        self.assertEqual(child.evidence_receipt_ids, [])

    def test_deadline_failure_preserves_cause_without_authority(self) -> None:
        fixture, coordinator, engine, parent_id, _payload = self._fixture()
        fixture._execute(engine, parent_id)
        snapshot_id = pwn_runtime_snapshot_child_experiment_id(parent_id)
        engine._capability_probe = self._snapshot_capability
        baseline = engine.execute_registered_experiments(
            fixture.identity,
            maximum=1,
            _session_owned=True,
            experiment_ids=(snapshot_id,),
        )
        before = (
            len(baseline.facts),
            len(baseline.progress_markers),
            coordinator.snapshot_calls,
        )
        original_deadline_gate = engine._require_before_hard_deadline

        def expire_before_replay(deadline: float, operation: str) -> None:
            if operation == "Pwn IP-control replay 1":
                raise RuntimeError("sentinel aggregate deadline exhausted")
            original_deadline_gate(deadline, operation)

        engine._require_before_hard_deadline = expire_before_replay
        child_id = pwn_ip_control_child_experiment_id(snapshot_id)
        failed = engine.execute_registered_experiments(
            fixture.identity,
            maximum=1,
            _session_owned=True,
            experiment_ids=(child_id,),
        )
        child = next(
            item for item in failed.experiments if item.id == child_id
        )
        self.assertIs(child.status, ExperimentStatus.FAILED)
        self.assertIn(
            "sentinel aggregate deadline exhausted",
            child.result["error"],
        )
        self.assertEqual(coordinator.snapshot_calls, before[2])
        self.assertEqual(len(failed.facts), before[0])
        self.assertEqual(len(failed.progress_markers), before[1])
        self.assertEqual(child.evidence_fact_ids, [])
        self.assertEqual(child.evidence_run_ids, [])
        self.assertEqual(child.evidence_receipt_ids, [])


if __name__ == "__main__":
    unittest.main()
