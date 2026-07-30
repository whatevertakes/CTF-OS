from __future__ import annotations

import copy
import hashlib
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from ctf_os.capabilities import REQUIRED_MANAGED_ATTESTATIONS
from ctf_os.contracts.pwn_runtime_snapshot_v1 import (
    PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES,
    PwnRuntimeSnapshotV1Maps,
    PwnRuntimeSnapshotV1Registers,
    build_pwn_runtime_snapshot_v1_result,
)
from ctf_os.engine.pwn_leak import (
    PWN_LEAK_REPLAY_COUNT,
    PwnLeakResult,
    PwnLeakStatus,
    PwnLeakTrustedReplayExpectation,
    pwn_leak_child_experiment_id,
)
from ctf_os.engine.pwn_runtime_snapshot import (
    PwnRuntimeSnapshotReceiptMetadata,
    pwn_runtime_snapshot_child_experiment_id,
)
from ctf_os.models import (
    ExperimentStatus,
    RunStatus,
)
from tests import test_pwn_crash_execution as crash_execution
from tests import test_pwn_runtime_snapshot_lifecycle as snapshot_lifecycle


_BASES = (
    0x7F4100000000,
    0x7F5100000000,
    0x7F5200000000,
    0x7F5300000000,
)
_OFFSET = 0x1234


class _LeakSandbox(snapshot_lifecycle._SnapshotSandbox):
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
        next_snapshot = self.owner.snapshot_calls + 1
        if (
            self.owner.interrupt_leak_ordinal is not None
            and next_snapshot - 1
            == self.owner.interrupt_leak_ordinal
        ):
            raise KeyboardInterrupt("synthetic leak interruption")
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
        snapshot_index = self.owner.snapshot_calls - 1
        base = self.owner.bases[snapshot_index]
        argv = spec.argv
        registers = PwnRuntimeSnapshotV1Registers(
            tuple(
                (
                    name,
                    "0000000000400010"
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
            (
                f"{base:016x}-{base + 0x100000:016x} rw-p "
                "0000000000000000 00:00 0 [heap]\n"
            ).encode("ascii")
        )
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
            expected_snapshot_recipe_sha256=crash_execution._argument(
                argv,
                "--snapshot-recipe-sha256",
            ),
        ).canonical_bytes()
        stderr_payload = (
            f"leak=0x{base + _OFFSET:012x}\n".encode("ascii")
        )
        stdout = directory / "stdout.log"
        stderr = directory / "stderr.log"
        stdout.chmod(0o600)
        stderr.chmod(0o600)
        stdout.write_bytes(document)
        stderr.write_bytes(stderr_payload)
        stdout.chmod(0o400)
        stderr.chmod(0o400)
        if snapshot_index >= 1 and self.owner.on_leak_replay is not None:
            self.owner.on_leak_replay(snapshot_index)
        return replace(
            result,
            stdout_bytes=len(document),
            stderr_bytes=len(stderr_payload),
            stdout_stored_bytes=len(document),
            stderr_stored_bytes=len(stderr_payload),
        )


class _LeakCoordinator(snapshot_lifecycle._SnapshotCoordinator):
    def __init__(self, statuses) -> None:
        baseline = f"leak=0x{_BASES[0] + _OFFSET:012x}\n".encode(
            "ascii"
        )
        super().__init__(
            statuses,
            snapshot_stderr_payload=baseline,
        )
        self.stderr_payload = baseline
        self.on_leak_replay = None
        self.interrupt_leak_ordinal: int | None = None
        self.bases = list(_BASES)

    def factory(self, _state, work: Path, policy):
        return _LeakSandbox(self, work, policy)


class PwnLeakHotPathTests(unittest.TestCase):
    @staticmethod
    def _snapshot_capability(digest):
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

    def _fixture(self):
        fixture = crash_execution.PwnCrashExecutionTests(
            methodName=(
                "test_confirmed_gate_uses_six_clean_networkless_fixed_calls"
            )
        )
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        coordinator = _LeakCoordinator(fixture._confirming_statuses())
        engine, parent_id, artifact_path, _payload = fixture._fixture(
            coordinator
        )
        payload = b"engine-owned-leak-control-" + (b"A" * 48)
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
        fixture._execute(engine, parent_id)
        snapshot_id = pwn_runtime_snapshot_child_experiment_id(parent_id)
        engine._capability_probe = self._snapshot_capability
        snapshot_state = engine.execute_registered_experiments(
            fixture.identity,
            maximum=1,
            _session_owned=True,
            experiment_ids=(snapshot_id,),
        )
        leak_id = pwn_leak_child_experiment_id(snapshot_id)
        return (
            fixture,
            coordinator,
            engine,
            snapshot_state,
            snapshot_id,
            leak_id,
            payload,
        )

    def _preissue(self, engine, fixture, leak_id):
        state = engine.store.load(fixture.identity, recover=False)
        state = engine._advance_pwn_runtime_snapshot_disclosures(
            fixture.identity
        )
        state = engine._register_pwn_leak_child_if_applicable(
            fixture.identity,
            state,
        )
        child = next(
            item for item in state.experiments if item.id == leak_id
        )
        return state, child

    def test_temporal_preissue_and_three_replays_prove_only_leak(
        self,
    ) -> None:
        (
            fixture,
            coordinator,
            engine,
            before,
            _snapshot_id,
            leak_id,
            baseline_payload,
        ) = self._fixture()
        before_summary = (
            before.status,
            len(before.candidates),
            len(before.submissions),
        )
        first_replay_checked = False

        def inspect_prior_state(ordinal: int) -> None:
            nonlocal first_replay_checked
            if ordinal != 1 or first_replay_checked:
                return
            canonical = engine.store.load(
                fixture.identity,
                recover=False,
            )
            child = next(
                item
                for item in canonical.experiments
                if item.id == leak_id
            )
            expectation = PwnLeakTrustedReplayExpectation.from_dict(
                child.extra["trusted_replay_expectation"]
            )
            self.assertIs(child.status, ExperimentStatus.RUNNING)
            self.assertEqual(
                child.extra["trusted_replay_expectation_sha256"],
                expectation.evidence_sha256,
            )
            self.assertEqual(len(child.extra["preissued_requests"]), 3)
            self.assertEqual(len(child.extra["run_ids"]), 3)
            self.assertEqual(
                [
                    run.status
                    for run in canonical.runs
                    if run.id in child.extra["run_ids"]
                ],
                [RunStatus.CREATED] * 3,
            )
            self.assertTrue(
                set(expectation.preexisting_artifact_ids).issubset(
                    {item.id for item in canonical.artifacts}
                )
            )
            self.assertTrue(
                all(
                    (engine.store.challenge_paths(fixture.identity).root / path)
                    .is_file()
                    for path in child.extra["request_paths"]
                )
            )
            self.assertFalse(
                set(child.extra["stdout_artifact_ids"]).intersection(
                    {item.id for item in canonical.artifacts}
                )
            )
            first_replay_checked = True

        coordinator.on_leak_replay = inspect_prior_state
        completed = engine.execute_registered_experiments(
            fixture.identity,
            maximum=1,
            _session_owned=True,
            experiment_ids=(leak_id,),
        )
        child = next(
            item for item in completed.experiments if item.id == leak_id
        )
        envelope = child.result["pwn_leak_evidence"]
        audit = copy.deepcopy(completed)
        audit_child = next(
            item for item in audit.experiments if item.id == leak_id
        )
        audit_child.status = ExperimentStatus.RUNNING
        stdout_index = {
            item.id: item for item in audit.artifacts
        }
        stdout_artifacts = tuple(
            stdout_index[item]
            for item in child.extra["stdout_artifact_ids"]
        )
        stderr_artifacts = tuple(
            stdout_index[item]
            for item in child.extra["stderr_artifact_ids"]
        )
        replay_runs = {
            item.id: item for item in audit.runs
        }
        metadata = tuple(
            PwnRuntimeSnapshotReceiptMetadata.from_dict(
                replay_runs[run_id].extra["pwn_leak_replay"][
                    "receipt"
                ]
            )
            for run_id in child.extra["run_ids"]
        )
        _audit_inputs, expected_result = (
            engine._recompute_pwn_leak_result(
                audit,
                audit_child,
                stdout_artifacts=stdout_artifacts,
                stderr_artifacts=stderr_artifacts,
                receipt_metadata=metadata,
            )
        )
        result = PwnLeakResult.from_dict(
            envelope["result"],
            expected_result=expected_result,
        )
        self.assertTrue(first_replay_checked)
        self.assertIs(child.status, ExperimentStatus.COMPLETED)
        self.assertIs(result.status, PwnLeakStatus.PROVEN)
        self.assertEqual(
            {
                key
                for key, value in result.to_dict()["authorities"].items()
                if value
            },
            {"leak_proven"},
        )
        self.assertEqual(
            len(child.evidence_run_ids),
            PWN_LEAK_REPLAY_COUNT,
        )
        self.assertEqual(
            len(child.evidence_receipt_ids),
            1,
        )
        self.assertEqual(len(child.artifact_ids), 13)
        self.assertEqual(coordinator.snapshot_calls, 4)
        self.assertEqual(coordinator.generic_calls, 0)
        variants = tuple(
            stdout_index[item].path
            for item in child.artifact_ids[:PWN_LEAK_REPLAY_COUNT]
        )
        self.assertEqual(len(set(variants)), 3)
        for artifact_id in child.artifact_ids[:6]:
            self.assertEqual(
                stdout_index[artifact_id].extra["context_visibility"],
                "engine_private",
            )
        for artifact_id in (
            *child.extra["stdout_artifact_ids"],
            *child.extra["stderr_artifact_ids"],
        ):
            self.assertEqual(
                stdout_index[artifact_id].extra["context_visibility"],
                "engine_private",
            )
        persisted = (
            engine.store.challenge_paths(fixture.identity).state.read_bytes()
        )
        self.assertNotIn(b"0x7f", persisted.lower())
        self.assertNotIn(b"[heap]", persisted)
        self.assertNotIn(baseline_payload, persisted)
        self.assertEqual(
            (
                completed.status,
                len(completed.candidates),
                len(completed.submissions),
            ),
            before_summary,
        )
        self.assertEqual(child.evidence_fact_ids, [completed.facts[-1].id])
        self.assertEqual(
            completed.facts[-1].extra["pwn_leak"]["authority"],
            "leak_proven",
        )
        self.assertFalse(
            result.to_dict()["authorities"]["primitive_proven"]
        )
        self.assertFalse(result.to_dict()["authorities"]["exploit_proven"])
        self.assertFalse(result.to_dict()["authorities"]["proof_satisfied"])
        self.assertFalse(
            result.to_dict()["authorities"]["stage_advance_authorized"]
        )
        for spec, policy in zip(
            coordinator.specs[-PWN_LEAK_REPLAY_COUNT:],
            coordinator.policies[-PWN_LEAK_REPLAY_COUNT:],
            strict=True,
        ):
            self.assertEqual(dict(spec.environment), {})
            self.assertIsNone(spec.network_target)
            self.assertEqual(spec.resource_request.network, 0)
            self.assertEqual(policy.authorize(None), "none")

    def test_request_input_source_and_bool_mutations_fail_before_replay(
        self,
    ) -> None:
        mutators = (
            "request",
            "request-hash",
            "input",
            "artifact-id",
            "source",
            "image",
            "bool-schema",
        )
        for mutation in mutators:
            with self.subTest(mutation=mutation):
                (
                    fixture,
                    coordinator,
                    engine,
                    _before,
                    _snapshot_id,
                    leak_id,
                    _payload,
                ) = self._fixture()
                state, child = self._preissue(engine, fixture, leak_id)
                paths = engine.store.challenge_paths(fixture.identity)
                if mutation == "request":
                    request = paths.root / child.extra["request_paths"][0]
                    request.chmod(0o600)
                    request.write_bytes(request.read_bytes() + b" ")
                    request.chmod(0o400)
                elif mutation == "request-hash":
                    def corrupt_request_hash(current) -> None:
                        item = next(
                            value
                            for value in current.experiments
                            if value.id == leak_id
                        )
                        item.extra["request_sha256s"][0] = "0" * 64

                    engine.store.update(
                        fixture.identity,
                        corrupt_request_hash,
                    )
                elif mutation == "input":
                    artifact = next(
                        item
                        for item in state.artifacts
                        if item.id == child.artifact_ids[0]
                    )
                    path = paths.root / artifact.path
                    payload = path.read_bytes()
                    path.chmod(0o600)
                    path.write_bytes(b"Z" + payload[1:])
                    path.chmod(0o400)
                elif mutation == "artifact-id":
                    def corrupt_artifact_id(current) -> None:
                        item = next(
                            value
                            for value in current.experiments
                            if value.id == leak_id
                        )
                        item.artifact_ids[0] = next(
                            artifact.id
                            for artifact in current.artifacts
                            if artifact.id not in item.artifact_ids
                        )

                    engine.store.update(
                        fixture.identity,
                        corrupt_artifact_id,
                    )
                elif mutation == "source":
                    source = (
                        engine.challenge_input(fixture.identity)
                        / "challenge"
                    )
                    source.chmod(0o700)
                    source.write_bytes(source.read_bytes() + b"\x00")
                    source.chmod(0o500)
                elif mutation == "image":
                    engine.config = replace(
                        engine.config,
                        runtime=replace(
                            engine.config.runtime,
                            image_digest="sha256:" + ("2" * 64),
                        ),
                    )
                else:
                    def corrupt(current) -> None:
                        item = next(
                            value
                            for value in current.experiments
                            if value.id == leak_id
                        )
                        item.extra["pwn_leak_plan"][
                            "schema_version"
                        ] = True

                    engine.store.update(fixture.identity, corrupt)
                completed = engine.execute_registered_experiments(
                    fixture.identity,
                    maximum=1,
                    _session_owned=True,
                    experiment_ids=(leak_id,),
                )
                failed = next(
                    item
                    for item in completed.experiments
                    if item.id == leak_id
                )
                self.assertIs(failed.status, ExperimentStatus.FAILED)
                self.assertEqual(failed.evidence_fact_ids, [])
                self.assertEqual(coordinator.snapshot_calls, 1)
                self.assertEqual(len(completed.candidates), 0)
                self.assertEqual(len(completed.submissions), 0)

    def test_cherry_picked_identity_and_expectation_hash_fail_closed(
        self,
    ) -> None:
        (
            fixture,
            coordinator,
            engine,
            _before,
            _snapshot_id,
            leak_id,
            _payload,
        ) = self._fixture()
        self._preissue(engine, fixture, leak_id)

        def cherry_pick(state) -> None:
            child = next(
                item for item in state.experiments if item.id == leak_id
            )
            child.extra["run_ids"][0], child.extra["run_ids"][1] = (
                child.extra["run_ids"][1],
                child.extra["run_ids"][0],
            )
            child.extra["trusted_replay_expectation_sha256"] = "0" * 64

        engine.store.update(fixture.identity, cherry_pick)
        completed = engine.execute_registered_experiments(
            fixture.identity,
            maximum=1,
            _session_owned=True,
            experiment_ids=(leak_id,),
        )
        child = next(
            item for item in completed.experiments if item.id == leak_id
        )
        self.assertIs(child.status, ExperimentStatus.FAILED)
        self.assertEqual(coordinator.snapshot_calls, 1)
        self.assertEqual(child.evidence_run_ids, [])
        self.assertEqual(child.evidence_receipt_ids, [])

    def test_same_runtime_control_pair_cannot_create_leak_fact(
        self,
    ) -> None:
        (
            fixture,
            coordinator,
            engine,
            before,
            _snapshot_id,
            leak_id,
            _payload,
        ) = self._fixture()
        coordinator.bases[2] = coordinator.bases[1]
        completed = engine.execute_registered_experiments(
            fixture.identity,
            maximum=1,
            _session_owned=True,
            experiment_ids=(leak_id,),
        )
        child = next(
            item for item in completed.experiments if item.id == leak_id
        )
        result = child.result["pwn_leak_evidence"]["result"]
        self.assertIs(child.status, ExperimentStatus.COMPLETED)
        self.assertEqual(result["status"], "UNVERIFIABLE")
        self.assertEqual(
            result["reason_code"],
            "paired_control_runtime_state_not_varied",
        )
        self.assertTrue(
            all(value is False for value in result["authorities"].values())
        )
        self.assertEqual(child.evidence_fact_ids, [])
        self.assertEqual(len(completed.facts), len(before.facts))
        self.assertEqual(
            len(completed.progress_markers),
            len(before.progress_markers),
        )
        self.assertEqual(len(completed.candidates), len(before.candidates))
        self.assertEqual(
            len(completed.submissions),
            len(before.submissions),
        )

    def test_keyboard_interrupt_terminalizes_all_preissued_runs(
        self,
    ) -> None:
        (
            fixture,
            coordinator,
            engine,
            _before,
            _snapshot_id,
            leak_id,
            _payload,
        ) = self._fixture()
        state, child = self._preissue(engine, fixture, leak_id)
        run_ids = tuple(child.extra["run_ids"])
        coordinator.interrupt_leak_ordinal = 2
        with self.assertRaisesRegex(
            KeyboardInterrupt,
            "synthetic leak interruption",
        ):
            engine.execute_registered_experiments(
                fixture.identity,
                maximum=1,
                _session_owned=True,
                experiment_ids=(leak_id,),
            )
        recovered = engine.store.load(fixture.identity, recover=False)
        child = next(
            item for item in recovered.experiments if item.id == leak_id
        )
        self.assertIs(child.status, ExperimentStatus.FAILED)
        self.assertEqual(child.evidence_fact_ids, [])
        self.assertEqual(child.evidence_run_ids, [])
        self.assertEqual(child.evidence_receipt_ids, [])
        self.assertEqual(
            [
                run.status
                for run in recovered.runs
                if run.id in run_ids
            ],
            [RunStatus.FAILED] * 3,
        )
        self.assertEqual(len(recovered.candidates), 0)
        self.assertEqual(len(recovered.submissions), 0)

    def test_pre_replace_result_mutation_is_recomputed_and_rejected(
        self,
    ) -> None:
        (
            fixture,
            _coordinator,
            engine,
            _before,
            _snapshot_id,
            leak_id,
            _payload,
        ) = self._fixture()
        state, child = self._preissue(engine, fixture, leak_id)
        plan_sha256 = child.extra["pwn_leak_plan"]["recipe_sha256"]
        result_path = (
            engine.store.challenge_paths(fixture.identity).artifacts
            / "snapshots"
            / f"pwn-leak-{plan_sha256}"
            / "result.json"
        )
        original_update = engine.store.update
        attacked = False

        def update_with_pre_replace_attack(*args, **kwargs):
            nonlocal attacked
            mutator = args[1] if len(args) > 1 else kwargs.get("mutator")
            guard = kwargs.get("pre_replace_guard")
            if (
                not attacked
                and getattr(mutator, "__name__", "") == "finish"
                and guard is not None
            ):
                def hostile_guard() -> None:
                    nonlocal attacked
                    payload = result_path.read_bytes()
                    result_path.chmod(0o600)
                    result_path.write_bytes(b"[" + payload[1:])
                    result_path.chmod(0o400)
                    attacked = True
                    guard()

                kwargs["pre_replace_guard"] = hostile_guard
            return original_update(*args, **kwargs)

        with mock.patch.object(
            engine.store,
            "update",
            side_effect=update_with_pre_replace_attack,
        ):
            completed = engine.execute_registered_experiments(
                fixture.identity,
                maximum=1,
                _session_owned=True,
                experiment_ids=(leak_id,),
            )
        self.assertTrue(attacked)
        child = next(
            item for item in completed.experiments if item.id == leak_id
        )
        self.assertIs(child.status, ExperimentStatus.FAILED)
        self.assertEqual(child.evidence_fact_ids, [])
        self.assertEqual(child.evidence_run_ids, [])
        self.assertEqual(child.evidence_receipt_ids, [])
        self.assertEqual(len(completed.candidates), 0)
        self.assertEqual(len(completed.submissions), 0)
