from __future__ import annotations

import copy
import hashlib
import unittest

from ctf_os.capabilities import REQUIRED_MANAGED_ATTESTATIONS
from ctf_os.contracts.pwn_runtime_snapshot_v1 import (
    PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES,
    PwnRuntimeSnapshotV1Maps,
    PwnRuntimeSnapshotV1Registers,
    build_pwn_runtime_snapshot_v1_result,
)
from ctf_os.engine.challenge import EngineError
from ctf_os.engine.pwn_runtime_snapshot import (
    PwnRuntimeSnapshotReceiptMetadata,
    PwnRuntimeSnapshotRecipe,
    pwn_runtime_snapshot_child_experiment_id,
)
from ctf_os.models import ExperimentKind, ExperimentStatus
from ctf_os.sandbox import SandboxResult
from tests import test_pwn_crash_execution as crash_execution


class _SnapshotSandbox(crash_execution._PwnCrashSandbox):
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
        self.owner.clean_calls += 1
        self.owner.snapshot_calls += 1
        self.owner.specs.append(spec)
        self.owner.policies.append(self.policy)
        self.owner.proof_inputs.append(tuple(proof_inputs))
        if input_locators or len(proof_inputs) != 1:
            raise AssertionError("one typed snapshot input is required")
        proof_input = proof_inputs[0]
        payload = (self.work / proof_input.source_locator).read_bytes()
        if (
            proof_input.destination_locator
            != "pwn-runtime-snapshot-v1/payload.bin"
            or hashlib.sha256(payload).hexdigest()
            != proof_input.sha256
            or len(payload) != proof_input.size_bytes
        ):
            raise AssertionError("snapshot proof input binding changed")
        argv = spec.argv
        registers = PwnRuntimeSnapshotV1Registers(
            tuple(
                (
                    name,
                    (
                        "0000000000400010"
                        if name == "rip"
                        else "00007fffffffe000"
                        if name == "rsp"
                        else f"{index:016x}"
                    ),
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
        document = build_pwn_runtime_snapshot_v1_result(
            registers=registers,
            maps=maps,
            expected_source_manifest_sha256=(
                crash_execution._argument(
                    argv,
                    "--source-manifest-sha256",
                )
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
        directory = self.work / "proof" / "clean-snapshot"
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        stdout = directory / "stdout.log"
        stderr = directory / "stderr.log"
        stdout.write_bytes(document)
        stderr.write_bytes(b"")
        stdout.chmod(0o400)
        stderr.chmod(0o400)
        return SandboxResult(
            run_id="sandbox-snapshot",
            status="completed",
            exit_code=0,
            timed_out=False,
            duration_ms=5,
            stdout_summary="snapshot captured",
            stderr_summary="",
            stdout_bytes=len(document),
            stderr_bytes=0,
            stdout_path="/work/proof/clean-snapshot/stdout.log",
            stderr_path="/work/proof/clean-snapshot/stderr.log",
            stdout_stored_bytes=len(document),
            stderr_stored_bytes=0,
            stdout_limit_bytes=256 * 1024,
            stderr_limit_bytes=64 * 1024,
            stdout_truncated=False,
            stderr_truncated=False,
            stdout_truncation_known=True,
            stderr_truncation_known=True,
            stdout_capture_complete=True,
            stderr_capture_complete=True,
        )


class _SnapshotCoordinator(crash_execution._SandboxCoordinator):
    def __init__(self, statuses) -> None:
        super().__init__(statuses)
        self.snapshot_calls = 0

    def factory(self, _state, work, policy):
        return _SnapshotSandbox(self, work, policy)


class PwnRuntimeSnapshotLifecycleTests(unittest.TestCase):
    def test_confirmed_crash_registers_one_later_snapshot_child(
        self,
    ) -> None:
        fixture = crash_execution.PwnCrashExecutionTests(
            methodName=(
                "test_confirmed_gate_uses_six_clean_networkless_fixed_calls"
            )
        )
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        coordinator = crash_execution._SandboxCoordinator(
            fixture._confirming_statuses()
        )
        engine, parent_id, _artifact_path, _payload = fixture._fixture(
            coordinator
        )

        state = fixture._execute(engine, parent_id)

        parent = next(
            item for item in state.experiments if item.id == parent_id
        )
        child_id = pwn_runtime_snapshot_child_experiment_id(parent_id)
        child = next(
            item for item in state.experiments if item.id == child_id
        )
        recipe = PwnRuntimeSnapshotRecipe.from_dict(
            child.extra["pwn_runtime_snapshot_recipe"]
        )
        evidence = parent.result["pwn_crash_evidence"]

        self.assertIs(parent.status, ExperimentStatus.KEPT)
        self.assertEqual(len(parent.evidence_run_ids), 6)
        self.assertEqual(len(parent.evidence_receipt_ids), 6)
        self.assertEqual(len(evidence["attempts"]), 6)
        self.assertIs(child.kind, ExperimentKind.PROBE)
        self.assertIs(child.status, ExperimentStatus.REGISTERED)
        self.assertEqual(child.hypothesis_ids, [])
        self.assertEqual(
            child.command,
            "ctfos-engine:pwn-runtime-snapshot-v1",
        )
        self.assertEqual(
            child.extra["engine_executor"],
            "pwn_runtime_snapshot_v1",
        )
        self.assertEqual(recipe.child_experiment_id, child.id)
        self.assertEqual(recipe.parent_experiment_id, parent.id)
        self.assertEqual(
            recipe.parent_crash_evaluation_sha256,
            evidence["evaluation_sha256"],
        )
        self.assertEqual(recipe.expected_signal_number, 11)
        self.assertEqual(coordinator.clean_calls, 6)
        self.assertEqual(coordinator.generic_calls, 0)

    def test_snapshot_executes_once_only_on_a_later_pass(self) -> None:
        fixture = crash_execution.PwnCrashExecutionTests(
            methodName=(
                "test_confirmed_gate_uses_six_clean_networkless_fixed_calls"
            )
        )
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        coordinator = _SnapshotCoordinator(
            fixture._confirming_statuses()
        )
        engine, parent_id, _artifact_path, _payload = fixture._fixture(
            coordinator
        )
        registered = fixture._execute(engine, parent_id)
        child_id = pwn_runtime_snapshot_child_experiment_id(parent_id)
        self.assertEqual(coordinator.clean_calls, 6)
        self.assertIs(
            next(
                item
                for item in registered.experiments
                if item.id == child_id
            ).status,
            ExperimentStatus.REGISTERED,
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

        child = next(
            item for item in completed.experiments if item.id == child_id
        )
        self.assertIs(child.status, ExperimentStatus.COMPLETED)
        self.assertEqual(
            child.result["pwn_runtime_snapshot_evidence"][
                "evaluation"
            ]["status"],
            "CAPTURED",
        )
        self.assertEqual(coordinator.clean_calls, 7)
        self.assertEqual(coordinator.snapshot_calls, 1)
        self.assertEqual(coordinator.generic_calls, 0)
        self.assertEqual(len(child.evidence_run_ids), 1)
        self.assertEqual(len(child.evidence_receipt_ids), 1)
        self.assertEqual(len(child.artifact_ids), 3)
        receipt = next(
            item
            for item in completed.receipts
            if item.id == child.evidence_receipt_ids[0]
        )
        metadata = PwnRuntimeSnapshotReceiptMetadata.from_dict(
            receipt.extra["pwn_runtime_snapshot"]["receipt"]
        )
        stderr = next(
            item
            for item in completed.artifacts
            if item.id == receipt.stderr_artifact_id
        )
        self.assertEqual(
            PwnRuntimeSnapshotReceiptMetadata.from_dict(
                metadata.to_dict()
            ),
            metadata,
        )
        self.assertEqual(metadata.stderr_artifact_id, stderr.id)
        self.assertEqual(metadata.stderr_artifact_sha256, stderr.sha256)
        self.assertEqual(
            metadata.stderr_artifact_size_bytes,
            stderr.size,
        )
        self.assertIs(
            metadata.stderr_capture_placeholder,
            stderr.extra["capture_placeholder"],
        )
        snapshot_spec = coordinator.specs[-1]
        self.assertEqual(dict(snapshot_spec.environment), {})
        self.assertIsNone(snapshot_spec.network_target)
        self.assertEqual(snapshot_spec.resource_request.network, 0)
        self.assertEqual(
            coordinator.policies[-1].authorize(None),
            "none",
        )

    def test_capability_failure_is_precommit_and_fails_closed(
        self,
    ) -> None:
        fixture = crash_execution.PwnCrashExecutionTests(
            methodName=(
                "test_confirmed_gate_uses_six_clean_networkless_fixed_calls"
            )
        )
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        coordinator = _SnapshotCoordinator(
            fixture._confirming_statuses()
        )
        engine, parent_id, _artifact_path, _payload = fixture._fixture(
            coordinator
        )
        registered = fixture._execute(engine, parent_id)
        child_id = pwn_runtime_snapshot_child_experiment_id(parent_id)
        parent_before = next(
            item for item in registered.experiments if item.id == parent_id
        )
        parent_run_ids = list(parent_before.evidence_run_ids)
        parent_artifact_ids = list(parent_before.artifact_ids)
        engine._capability_probe = lambda _digest: {
            "ok": False,
            "image_digest": _digest,
            "available": [],
            "attestations": {},
            "attestation_errors": {},
        }

        failed = engine.execute_registered_experiments(
            fixture.identity,
            maximum=1,
            _session_owned=True,
            experiment_ids=(child_id,),
        )

        child = next(
            item for item in failed.experiments if item.id == child_id
        )
        parent = next(
            item for item in failed.experiments if item.id == parent_id
        )
        self.assertIs(child.status, ExperimentStatus.FAILED)
        self.assertTrue(
            child.result["error"].startswith(
                "Pwn runtime snapshot failed closed: "
            )
        )
        self.assertEqual(child.evidence_run_ids, [])
        self.assertEqual(child.evidence_receipt_ids, [])
        self.assertEqual(len(child.artifact_ids), 1)
        self.assertEqual(parent.evidence_run_ids, parent_run_ids)
        self.assertEqual(parent.artifact_ids, parent_artifact_ids)
        self.assertEqual(coordinator.clean_calls, 6)
        self.assertEqual(coordinator.snapshot_calls, 0)

    def test_source_payload_and_recipe_tamper_are_rejected(
        self,
    ) -> None:
        fixture = crash_execution.PwnCrashExecutionTests(
            methodName=(
                "test_confirmed_gate_uses_six_clean_networkless_fixed_calls"
            )
        )
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        coordinator = _SnapshotCoordinator(
            fixture._confirming_statuses()
        )
        engine, parent_id, _artifact_path, _payload = fixture._fixture(
            coordinator
        )
        registered = fixture._execute(engine, parent_id)
        child_id = pwn_runtime_snapshot_child_experiment_id(parent_id)

        for label in ("source", "payload", "recipe"):
            with self.subTest(label=label):
                altered = copy.deepcopy(registered)
                child = next(
                    item
                    for item in altered.experiments
                    if item.id == child_id
                )
                if label == "source":
                    altered.metadata["source_manifest_sha256"] = "0" * 64
                elif label == "payload":
                    payload = next(
                        item
                        for item in altered.artifacts
                        if item.id == child.artifact_ids[0]
                    )
                    payload.sha256 = "0" * 64
                else:
                    child.extra["pwn_runtime_snapshot_recipe"][
                        "source"
                    ]["sha256"] = "0" * 64
                with self.assertRaises(EngineError):
                    engine._pwn_runtime_snapshot_recipe_for_child(
                        altered,
                        child,
                        required_status=ExperimentStatus.REGISTERED,
                    )


if __name__ == "__main__":
    unittest.main()
