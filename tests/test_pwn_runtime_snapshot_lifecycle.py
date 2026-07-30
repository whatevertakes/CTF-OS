from __future__ import annotations

import copy
import hashlib
import io
import unittest
from contextlib import redirect_stderr
from unittest import mock

from ctf_os.capabilities import REQUIRED_MANAGED_ATTESTATIONS
from ctf_os.contracts.pwn_runtime_snapshot_v1 import (
    PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES,
    PwnRuntimeSnapshotV1Maps,
    PwnRuntimeSnapshotV1Registers,
    build_pwn_runtime_snapshot_v1_result,
)
from ctf_os.engine.challenge import ChallengeEngine, EngineError
from ctf_os.engine.pwn_runtime_snapshot import (
    PwnRuntimeSnapshotReceiptMetadata,
    PwnRuntimeSnapshotRecipe,
    pwn_runtime_snapshot_child_experiment_id,
)
from ctf_os.models import (
    ExperimentKind,
    ExperimentStatus,
    ModelValidationError,
    PwnDisclosurePhase,
    PwnRuntimeSnapshotDisclosureEnvelope,
)
from ctf_os.sandbox import SandboxResult
from ctf_os.sandbox.files import read_bounded_regular
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
        stderr.write_bytes(self.owner.snapshot_stderr_payload)
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
            stderr_bytes=len(self.owner.snapshot_stderr_payload),
            stdout_path="/work/proof/clean-snapshot/stdout.log",
            stderr_path="/work/proof/clean-snapshot/stderr.log",
            stdout_stored_bytes=len(document),
            stderr_stored_bytes=len(
                self.owner.snapshot_stderr_payload
            ),
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
    def __init__(
        self,
        statuses,
        *,
        snapshot_stderr_payload: bytes = b"",
    ) -> None:
        super().__init__(statuses)
        self.snapshot_calls = 0
        self.snapshot_stderr_payload = snapshot_stderr_payload

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
        disclosure = PwnRuntimeSnapshotDisclosureEnvelope.from_dict(
            child.extra["pwn_disclosure"]
        )
        self.assertIs(disclosure.phase, PwnDisclosurePhase.COMPLETE)
        self.assertTrue(
            all(
                value is False
                for value in disclosure.result.to_dict()[
                    "authorities"
                ].values()
            )
        )
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

    def test_disclosure_resumes_across_both_state_only_boundaries(
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
        fixture._execute(engine, parent_id)
        child_id = pwn_runtime_snapshot_child_experiment_id(parent_id)

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
        with mock.patch.object(
            engine,
            "_advance_pwn_runtime_snapshot_disclosures",
            side_effect=lambda identity: engine.store.load(
                identity,
                recover=False,
            ),
        ):
            awaiting = engine.execute_registered_experiments(
                fixture.identity,
                maximum=1,
                _session_owned=True,
                experiment_ids=(child_id,),
            )
        awaiting_child = next(
            item
            for item in awaiting.experiments
            if item.id == child_id
        )
        awaiting_envelope = (
            PwnRuntimeSnapshotDisclosureEnvelope.from_dict(
                awaiting_child.extra["pwn_disclosure"]
            )
        )
        self.assertIs(
            awaiting_envelope.phase,
            PwnDisclosurePhase.AWAITING_EXPECTATION,
        )
        baseline_counts = tuple(
            len(getattr(awaiting, field))
            for field in (
                "experiments",
                "runs",
                "receipts",
                "artifacts",
                "facts",
                "hypotheses",
                "candidates",
                "submissions",
            )
        )

        def forbidden_sandbox(*_args, **_kwargs):
            raise AssertionError(
                "state-only disclosure resume invoked the sandbox"
            )

        resumed = ChallengeEngine(
            fixture.root,
            config=engine.config,
            sandbox_factory=forbidden_sandbox,
            capability_probe=lambda *_args, **_kwargs: (
                forbidden_sandbox()
            ),
        )
        with mock.patch.object(
            resumed,
            "_commit_pwn_disclosure_result",
            side_effect=RuntimeError(
                "synthetic interruption after expectation commit"
            ),
        ), mock.patch(
            "ctf_os.engine.challenge.read_bounded_regular",
            side_effect=AssertionError(
                "expectation phase reread raw artifact bytes"
            ),
        ), self.assertRaisesRegex(
            RuntimeError,
            "synthetic interruption",
        ):
            resumed._advance_pwn_runtime_snapshot_disclosures(
                fixture.identity
            )
        expected = resumed.store.load(
            fixture.identity,
            recover=False,
        )
        expected_child = next(
            item
            for item in expected.experiments
            if item.id == child_id
        )
        expected_envelope = (
            PwnRuntimeSnapshotDisclosureEnvelope.from_dict(
                expected_child.extra["pwn_disclosure"]
            )
        )
        self.assertIs(
            expected_envelope.phase,
            PwnDisclosurePhase.EXPECTATION_COMMITTED,
        )
        self.assertEqual(expected.revision, awaiting.revision + 1)
        self.assertEqual(
            expected_envelope.expectation_source_state_revision,
            awaiting.revision,
        )
        self.assertEqual(
            tuple(
                len(getattr(expected, field))
                for field in (
                    "experiments",
                    "runs",
                    "receipts",
                    "artifacts",
                    "facts",
                    "hypotheses",
                    "candidates",
                    "submissions",
                )
            ),
            baseline_counts,
        )
        expected_paths = resumed.store.challenge_paths(fixture.identity)
        expectation_state_bytes = expected_paths.state.read_bytes()
        with self.assertRaisesRegex(
            ModelValidationError,
            "consecutive canonical state replacements",
        ):
            resumed.store.update(
                fixture.identity,
                lambda state: state.metadata.__setitem__(
                    "unrelated_commit",
                    True,
                ),
            )
        self.assertEqual(
            expected_paths.state.read_bytes(),
            expectation_state_bytes,
        )

        completed_engine = ChallengeEngine(
            fixture.root,
            config=engine.config,
            sandbox_factory=forbidden_sandbox,
            capability_probe=lambda *_args, **_kwargs: (
                forbidden_sandbox()
            ),
        )
        snapshot_stderr_id = (
            expected_envelope.trusted_receipt_expectation
            .runtime_snapshot_receipt.stderr.artifact_id
        )
        snapshot_stderr = next(
            artifact
            for artifact in expected.artifacts
            if artifact.id == snapshot_stderr_id
        )
        challenge_paths = completed_engine.store.challenge_paths(
            fixture.identity
        )
        snapshot_stderr_path = (
            challenge_paths.root / snapshot_stderr.path
        )
        original_stderr = snapshot_stderr_path.read_bytes()
        canonical_before_tamper = challenge_paths.state.read_bytes()
        snapshot_stderr_path.chmod(0o600)
        snapshot_stderr_path.write_bytes(b"tampered")
        snapshot_stderr_path.chmod(0o400)
        try:
            with self.assertRaisesRegex(
                EngineError,
                "artifact reread failed closed",
            ):
                completed_engine._advance_pwn_runtime_snapshot_disclosures(
                    fixture.identity
                )
            self.assertEqual(
                challenge_paths.state.read_bytes(),
                canonical_before_tamper,
            )
        finally:
            snapshot_stderr_path.chmod(0o600)
            snapshot_stderr_path.write_bytes(original_stderr)
            snapshot_stderr_path.chmod(0o400)

        expected_child = next(
            item
            for item in expected.experiments
            if item.id == child_id
        )
        disclosure_inputs = (
            completed_engine._pwn_disclosure_inputs_from_state(
                expected,
                expected_child,
            )
        )
        payload_path = (
            challenge_paths.root
            / disclosure_inputs.payload_artifact.path
        )
        original_payload = payload_path.read_bytes()
        mutated_payload = bytes(
            [original_payload[0] ^ 1]
        ) + original_payload[1:]
        for mutation_call in (13, 25):
            with self.subTest(mutation_call=mutation_call):
                call_count = 0

                def mutate_during_guard(*args, **kwargs):
                    nonlocal call_count
                    call_count += 1
                    if call_count == mutation_call:
                        payload_path.chmod(0o600)
                        payload_path.write_bytes(mutated_payload)
                        payload_path.chmod(0o400)
                    return read_bounded_regular(*args, **kwargs)

                try:
                    with mock.patch(
                        "ctf_os.engine.challenge.read_bounded_regular",
                        side_effect=mutate_during_guard,
                    ), self.assertRaisesRegex(
                        EngineError,
                        "artifact reread failed closed",
                    ):
                        (
                            completed_engine
                            ._advance_pwn_runtime_snapshot_disclosures(
                                fixture.identity
                            )
                        )
                    self.assertEqual(call_count, mutation_call)
                    self.assertEqual(
                        challenge_paths.state.read_bytes(),
                        canonical_before_tamper,
                    )
                finally:
                    payload_path.chmod(0o600)
                    payload_path.write_bytes(original_payload)
                    payload_path.chmod(0o400)
        with mock.patch(
            "ctf_os.engine.challenge.read_bounded_regular",
            wraps=read_bounded_regular,
        ) as reread:
            complete = (
                completed_engine
                ._advance_pwn_runtime_snapshot_disclosures(
                    fixture.identity
                )
            )
        complete_child = next(
            item
            for item in complete.experiments
            if item.id == child_id
        )
        complete_envelope = (
            PwnRuntimeSnapshotDisclosureEnvelope.from_dict(
                complete_child.extra["pwn_disclosure"]
            )
        )
        self.assertIs(
            complete_envelope.phase,
            PwnDisclosurePhase.COMPLETE,
        )
        self.assertEqual(complete.revision, expected.revision + 1)
        self.assertEqual(
            complete_envelope.expectation_source_state_revision,
            awaiting.revision,
        )
        self.assertEqual(
            complete_envelope.evaluation_source_state_revision,
            expected.revision,
        )
        self.assertEqual(
            tuple(
                len(getattr(complete, field))
                for field in (
                    "experiments",
                    "runs",
                    "receipts",
                    "artifacts",
                    "facts",
                    "hypotheses",
                    "candidates",
                    "submissions",
                )
            ),
            baseline_counts,
        )
        self.assertEqual(reread.call_count, 36)
        reread_locators = [call.args[1] for call in reread.call_args_list]
        self.assertEqual(len(set(reread_locators)), 12)
        self.assertTrue(
            all(
                reread_locators.count(locator) == 3
                for locator in set(reread_locators)
            )
        )
        for call in reread.call_args_list:
            self.assertIn("maximum_bytes", call.kwargs)
            self.assertIn("expected_sha256", call.kwargs)
            self.assertIn("expected_size", call.kwargs)
        result = complete_envelope.result.to_dict()
        self.assertTrue(
            all(
                value is False
                for value in result["authorities"].values()
            )
        )
        complete.validate()

    def test_completed_legacy_v1_snapshot_is_never_backfilled(
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
        fixture._execute(engine, parent_id)
        child_id = pwn_runtime_snapshot_child_experiment_id(parent_id)

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
        engine.execute_registered_experiments(
            fixture.identity,
            maximum=1,
            _session_owned=True,
            experiment_ids=(child_id,),
        )

        def restore_legacy(state):
            child = next(
                item
                for item in state.experiments
                if item.id == child_id
            )
            child.extra["managed_contract_version"] = 1
            child.extra.pop("pwn_disclosure", None)

        legacy = engine.store.update(
            fixture.identity,
            restore_legacy,
        )
        paths = engine.store.challenge_paths(fixture.identity)
        state_bytes = paths.state.read_bytes()

        def forbidden_sandbox(*_args, **_kwargs):
            raise AssertionError("legacy v1 resume invoked the sandbox")

        restarted = ChallengeEngine(
            fixture.root,
            config=engine.config,
            sandbox_factory=forbidden_sandbox,
            capability_probe=lambda *_args, **_kwargs: (
                forbidden_sandbox()
            ),
        )
        observed = restarted.execute_registered_experiments(
            fixture.identity,
            maximum=1,
            _session_owned=True,
            experiment_ids=(child_id,),
        )
        child = next(
            item
            for item in observed.experiments
            if item.id == child_id
        )
        self.assertEqual(observed.revision, legacy.revision)
        self.assertEqual(paths.state.read_bytes(), state_bytes)
        self.assertEqual(child.extra["managed_contract_version"], 1)
        self.assertNotIn("pwn_disclosure", child.extra)

    def test_hard_death_after_terminal_replace_preserves_evidence(
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
        fixture._execute(engine, parent_id)
        child_id = pwn_runtime_snapshot_child_experiment_id(parent_id)

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
        real_append = engine.store._append_event_best_effort
        state_updates = 0

        def interrupt_after_replace(paths, event):
            nonlocal state_updates
            if event.get("event") == "state_updated":
                state_updates += 1
                if state_updates == 2:
                    raise SystemExit(
                        "synthetic death after terminal replacement"
                    )
            return real_append(paths, event)

        with mock.patch.object(
            engine.store,
            "_append_event_best_effort",
            side_effect=interrupt_after_replace,
        ), self.assertRaisesRegex(
            SystemExit,
            "synthetic death",
        ):
            engine.execute_registered_experiments(
                fixture.identity,
                maximum=1,
                _session_owned=True,
                experiment_ids=(child_id,),
            )

        awaiting = engine.store.load(
            fixture.identity,
            recover=False,
        )
        awaiting_child = next(
            item
            for item in awaiting.experiments
            if item.id == child_id
        )
        awaiting_envelope = (
            PwnRuntimeSnapshotDisclosureEnvelope.from_dict(
                awaiting_child.extra["pwn_disclosure"]
            )
        )
        self.assertIs(
            awaiting_envelope.phase,
            PwnDisclosurePhase.AWAITING_EXPECTATION,
        )
        challenge_paths = engine.store.challenge_paths(fixture.identity)
        for artifact_id in awaiting_child.artifact_ids[1:]:
            artifact = next(
                item
                for item in awaiting.artifacts
                if item.id == artifact_id
            )
            self.assertTrue(
                (challenge_paths.root / artifact.path).is_file()
            )
        for run_id in awaiting_child.evidence_run_ids:
            self.assertTrue(
                engine.store.run_paths(
                    fixture.identity,
                    run_id=run_id,
                ).root.is_dir()
            )

        def forbidden_sandbox(*_args, **_kwargs):
            raise AssertionError("hard-death recovery invoked the sandbox")

        restarted = ChallengeEngine(
            fixture.root,
            config=engine.config,
            sandbox_factory=forbidden_sandbox,
            capability_probe=lambda *_args, **_kwargs: (
                forbidden_sandbox()
            ),
        )
        recovered = restarted._recover_session_boundary(
            fixture.identity
        )
        recovered_child = next(
            item
            for item in recovered.experiments
            if item.id == child_id
        )
        recovered_envelope = (
            PwnRuntimeSnapshotDisclosureEnvelope.from_dict(
                recovered_child.extra["pwn_disclosure"]
            )
        )
        self.assertIs(
            recovered_envelope.phase,
            PwnDisclosurePhase.COMPLETE,
        )
        self.assertEqual(
            recovered_child.evidence_run_ids,
            awaiting_child.evidence_run_ids,
        )
        self.assertEqual(
            recovered_child.artifact_ids,
            awaiting_child.artifact_ids,
        )

    def test_snapshot_flag_notifies_without_candidate_authority(
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
            fixture._confirming_statuses(),
            snapshot_stderr_payload=b"KCTF{snapshot_diagnostic}\n",
        )
        engine, parent_id, _artifact_path, _payload = fixture._fixture(
            coordinator
        )
        fixture._execute(engine, parent_id)
        child_id = pwn_runtime_snapshot_child_experiment_id(parent_id)

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
        notification = io.StringIO()
        with mock.patch.object(
            engine.store,
            "record_candidate_intent",
            side_effect=AssertionError(
                "diagnostic snapshot attempted candidate promotion"
            ),
        ), redirect_stderr(notification):
            completed = engine.execute_registered_experiments(
                fixture.identity,
                maximum=1,
                _session_owned=True,
                experiment_ids=(child_id,),
            )
        self.assertIn(
            "KCTF{snapshot_diagnostic}",
            notification.getvalue(),
        )
        self.assertIn("미제출", notification.getvalue())
        self.assertEqual(completed.candidates, [])
        self.assertEqual(completed.submissions, [])
        self.assertEqual(
            engine.store.load_candidate_intents(fixture.identity),
            (),
        )
        child = next(
            item
            for item in completed.experiments
            if item.id == child_id
        )
        envelope = PwnRuntimeSnapshotDisclosureEnvelope.from_dict(
            child.extra["pwn_disclosure"]
        )
        self.assertIs(envelope.phase, PwnDisclosurePhase.COMPLETE)
        self.assertTrue(
            all(
                value is False
                for value in envelope.result.to_dict()[
                    "authorities"
                ].values()
            )
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
