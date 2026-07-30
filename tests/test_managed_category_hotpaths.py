from __future__ import annotations

import hashlib
import json
import unittest
from types import SimpleNamespace
from unittest import mock

from ctf_os.codex import BatchRunner, ProcessOutcome, Role
from ctf_os.managed import ManagedOrchestrator
from ctf_os.models import (
    ArtifactReference,
    CandidateStatus,
    ChallengeStatus,
    ExperimentStatus,
    RunStatus,
)
from tests import test_crypto_engine as crypto_support
from tests import test_forensic_assertion_hotpath as forensic_support
from tests import test_misc_engine as misc_support
from tests.test_engine import _output_path, _payload, _role_for


def _capability(_digest: str) -> dict[str, object]:
    return {
        "ok": True,
        "schema_version": 2,
        "capabilities": {},
    }


class _TypedActionExecutor:
    """Contract-valid model stand-in; deterministic gates remain real."""

    def __init__(
        self,
        *,
        action: dict[str, object],
        payloads: dict[str, bytes],
        extra_write_locators: tuple[str, ...] = (),
    ) -> None:
        self.action = action
        self.payloads = payloads
        self.extra_write_locators = extra_write_locators
        self.roles: list[Role] = []

    @staticmethod
    def _none_action() -> dict[str, object]:
        return {
            "kind": "none",
            "description": "no engine action",
            "command": None,
            "artifact_path": None,
            "hypothesis_ids": [],
            "expected_observation": "",
            "keep_if": "",
            "drop_if": "",
            "timeout_seconds": 1,
            "resource_class": "light",
            "network_target_id": None,
            "network_target_generation": None,
        }

    def run(
        self,
        command,
        *,
        cwd,
        timeout,
        on_stdout_line,
    ):
        del timeout, on_stdout_line
        role = _role_for(command)
        self.roles.append(role)
        payload = _payload(role)
        payload["schema_version"] = 2
        payload["hypotheses"] = []
        payload["actions"] = [self._none_action()]
        if role is Role.CAPTAIN:
            payload["decision"] = {
                "next_stage": "attack",
                "reason": "route the typed deterministic category gate",
            }
            payload["hypotheses"] = [
                {
                    "id": f"hyp-{ordinal}",
                    "claim": f"independent category claim {ordinal}",
                    "evidence": ["obs-1"],
                    "unknowns": [f"discriminator {ordinal}"],
                    "experiment": f"run discriminator {ordinal}",
                    "success_oracle": f"oracle accepts {ordinal}",
                    "falsifier": f"oracle rejects {ordinal}",
                }
                for ordinal in range(1, 4)
            ]
        elif role is Role.BUILDER:
            for locator, artifact_payload in self.payloads.items():
                destination = cwd / locator
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(artifact_payload)
            payload["artifacts"] = [
                {
                    "path": locator,
                    "sha256": hashlib.sha256(
                        artifact_payload
                    ).hexdigest(),
                    "purpose": "managed deterministic gate input",
                }
                for locator, artifact_payload in sorted(
                    self.payloads.items()
                )
            ]
            payload["actions"] = [
                *(
                    {
                        "kind": "write_artifact",
                        "description": (
                            "publish referenced deterministic tool"
                        ),
                        "command": None,
                        "artifact_path": locator,
                        "hypothesis_ids": [],
                        "expected_observation": "",
                        "keep_if": "",
                        "drop_if": "",
                        "timeout_seconds": 1,
                        "resource_class": "light",
                        "network_target_id": None,
                        "network_target_generation": None,
                    }
                    for locator in self.extra_write_locators
                ),
                self.action,
            ]
        _output_path(command).write_text(
            json.dumps(payload),
            encoding="utf-8",
        )
        return ProcessOutcome(0, "", 0.01)


def _execute_full_managed_cycle(
    engine,
    identity,
    *,
    action: dict[str, object],
    payloads: dict[str, bytes],
    extra_write_locators: tuple[str, ...] = (),
):
    executor = _TypedActionExecutor(
        action=action,
        payloads=payloads,
        extra_write_locators=extra_write_locators,
    )
    engine.batch_runner = BatchRunner(
        process_executor=executor,
        max_schema_retries=0,
        flag_patterns=engine.config.runtime.flag_patterns,
    )
    orchestrator = ManagedOrchestrator(
        engine,
        capability_probe=_capability,
    )
    if engine.store.load(identity).active_managed_session_id is not None:
        orchestrator.cancel_session(
            identity,
            reason="close completed deterministic fixture setup",
            target=ChallengeStatus.PAUSED,
        )
        orchestrator.reconcile(identity)
    if engine.store.load(identity).status is ChallengeStatus.PAUSED:
        engine.resume(identity)
    with mock.patch.object(
        engine,
        "synchronize_managed_adapter_seed_plan",
        side_effect=lambda selected, _session: engine.store.load(
            selected
        ),
    ):
        final = orchestrator.run_cycle(identity)
    typed = [
        item
        for item in final.experiments
        if (
            item.extra.get("engine_executor")
            == "managed_typed_gate_v1"
            and item.extra.get("managed_action_kind")
            == action["kind"]
        )
    ]
    if len(typed) != 1:
        raise AssertionError("full managed cycle did not execute one typed gate")
    return final, typed[0], executor


def _assert_exact_typed_binding(
    case: unittest.TestCase,
    experiment,
    *,
    action: dict[str, object],
    payloads: dict[str, bytes],
) -> None:
    request = experiment.extra["managed_typed_gate_request"]
    case.assertEqual(request["action_kind"], action["kind"])
    case.assertEqual(
        experiment.extra["engine_executor"],
        "managed_typed_gate_v1",
    )
    expected_fields = {
        key for key in action if key.endswith("_artifact_path")
    }
    case.assertEqual(
        set(request["artifact_bindings"]),
        expected_fields,
    )
    for field in expected_fields:
        locator = action[field]
        binding = request["artifact_bindings"][field]
        expected = payloads[locator]
        case.assertEqual(binding["locator"], locator)
        case.assertEqual(
            binding["sha256"],
            hashlib.sha256(expected).hexdigest(),
        )
        case.assertEqual(binding["size_bytes"], len(expected))
        case.assertEqual(
            set(binding),
            {
                "artifact_id",
                "locator",
                "sha256",
                "size_bytes",
                "workspace_publish_id",
            },
        )


def _execute_managed_typed_action(
    engine,
    identity,
    *,
    action: dict[str, object],
    payloads: dict[str, bytes],
    extra_write_locators: tuple[str, ...] = (),
    before_execute=None,
):
    """Drive the real Builder publish/register/dispatch path without a model."""

    orchestrator = ManagedOrchestrator(
        engine,
        capability_probe=_capability,
    )
    _state, session_id = orchestrator._reserve_session(identity, None)
    _state, cycle = orchestrator._reserve_cycle(identity, session_id)
    _state, wave, role_runs = orchestrator._reserve_wave(
        identity,
        session_id,
        cycle.id,
        "attack",
    )
    builder_run_id = role_runs[Role.BUILDER]
    paths = engine.store.challenge_paths(identity)
    run_workspace = (
        engine.store.run_paths(identity, run_id=builder_run_id).root
        / "workspace"
    )
    run_workspace.mkdir(parents=True)
    snapshots = paths.artifacts / "snapshots"
    snapshots.mkdir(parents=True, exist_ok=True)

    records: list[tuple[str, str, bytes, str]] = []
    for ordinal, (locator, payload) in enumerate(
        sorted(payloads.items()),
        start=1,
    ):
        staged = run_workspace / locator
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_bytes(payload)
        artifact_id = f"A-{builder_run_id}-managed-hotpath-{ordinal}"
        relative = f"artifacts/snapshots/{artifact_id}.bin"
        snapshot = paths.root / relative
        snapshot.write_bytes(payload)
        snapshot.chmod(0o400)
        records.append((artifact_id, relative, payload, locator))

    def seed(state) -> None:
        run = next(
            item for item in state.runs if item.id == builder_run_id
        )
        run.status = RunStatus.COMPLETED
        run.result_path = f"runs/{builder_run_id}/result.json"
        run.validation_path = f"runs/{builder_run_id}/validation.json"
        run.extra["semantic_merge"] = True
        for artifact_id, relative, payload, locator in records:
            state.artifacts.append(
                ArtifactReference(
                    id=artifact_id,
                    path=relative,
                    sha256=hashlib.sha256(payload).hexdigest(),
                    source_run_id=builder_run_id,
                    size=len(payload),
                    extra={
                        "reported_locator": locator,
                        "purpose": "managed deterministic gate input",
                    },
                )
            )

    engine.store.update(identity, seed)
    output_actions: list[dict[str, object]] = [
        {
            "kind": "write_artifact",
            "description": "publish referenced deterministic tool",
            "artifact_path": locator,
        }
        for locator in extra_write_locators
    ]
    output_actions.append(action)
    result = SimpleNamespace(
        invocation=SimpleNamespace(
            role=Role.BUILDER,
            run_id=builder_run_id,
            contract_version=2,
        ),
        output={
            "hypotheses": [],
            "actions": output_actions,
        },
        attempts=(SimpleNamespace(),),
    )
    publication = orchestrator._apply_builder_publishes(
        identity,
        wave,
        (result,),
    )
    if publication.rejection is not None:
        raise AssertionError(publication.rejection)
    registration = orchestrator._register_typed_gate_actions(
        identity,
        wave,
        (result,),
    )
    if (
        registration.rejection_code is not None
        or len(registration.experiment_ids) != 1
    ):
        raise AssertionError(
            registration.rejection_code or "typed gate was not registered"
        )
    experiment_id = registration.experiment_ids[0]
    orchestrator._mark_action_selection(
        identity,
        session_id,
        cycle.id,
        (experiment_id,),
    )
    if before_execute is not None:
        before_execute(orchestrator, experiment_id)
    final = orchestrator._execute_selected_actions(
        identity,
        (experiment_id,),
        record_stall=False,
    )
    experiment = next(
        item for item in final.experiments if item.id == experiment_id
    )
    return final, experiment, publication


class ManagedCategoryHotPathTests(unittest.TestCase):
    def test_post_registration_crypto_solver_mutation_is_rejected(
        self,
    ) -> None:
        case = crypto_support.CryptoEngineProofTests(
            "test_six_clean_bound_runs_are_required_before_promotion"
        )
        case.setUp()
        try:
            engine, sandbox = case._engine()
            workspace = engine._workspace(
                engine.store.load(case.identity)
            )
            locators = (
                "solver.py",
                "original.json",
            )
            payloads = {
                locator: (workspace / locator).read_bytes()
                for locator in locators
            }
            _state, preissue = engine.preissue_managed_crypto_oracle(
                case.identity,
                variant_parameters_locator="variant.json",
                variant_expected_output_locator="variant.out",
                mutation_id="managed-rsa-variant",
            )
            for locator in (*locators, "variant.json", "variant.out"):
                (workspace / locator).unlink()
            action = {
                "kind": "prove_crypto_metamorphic",
                "description": "prove the solver on original and variant",
                "candidate_id": "C-crypto-candidate",
                "solver_artifact_path": "solver.py",
                "original_parameters_artifact_path": "original.json",
                "oracle_preissue_id": preissue["preissue_id"],
                "runtime": "python",
            }

            def mutate_after_registration(_orchestrator, _experiment_id):
                canonical = (
                    engine.store.challenge_paths(case.identity).artifacts
                    / "workspace"
                    / "solver.py"
                )
                canonical.chmod(0o600)
                canonical.write_bytes(b"hostile replacement\n")
                canonical.chmod(0o400)

            before = engine.store.load(case.identity)
            final, experiment, _publication = (
                _execute_managed_typed_action(
                    engine,
                    case.identity,
                    action=action,
                    payloads=payloads,
                    before_execute=mutate_after_registration,
                )
            )
            candidate = next(
                item
                for item in final.candidates
                if item.id == "C-crypto-candidate"
            )
            _assert_exact_typed_binding(
                self,
                experiment,
                action=action,
                payloads=payloads,
            )
            prior_candidate = next(
                item
                for item in before.candidates
                if item.id == "C-crypto-candidate"
            )
            self.assertEqual(sandbox.proof_calls, [])
            self.assertIs(experiment.status, ExperimentStatus.FAILED)
            self.assertEqual(
                experiment.result["reason_codes"],
                ["typed_gate_dispatch_rejected"],
            )
            self.assertIs(candidate.status, prior_candidate.status)
            self.assertEqual(
                candidate.proof_run_ids,
                prior_candidate.proof_run_ids,
            )
            self.assertEqual(final.submissions, [])
            final.validate()
        finally:
            case.tearDown()

    def test_crypto_builder_action_reaches_six_run_metamorphic_proof(
        self,
    ) -> None:
        case = crypto_support.CryptoEngineProofTests(
            "test_six_clean_bound_runs_are_required_before_promotion"
        )
        case.setUp()
        try:
            engine, sandbox = case._engine()
            workspace = engine._workspace(
                engine.store.load(case.identity)
            )
            locators = (
                "solver.py",
                "original.json",
            )
            payloads = {
                locator: (workspace / locator).read_bytes()
                for locator in locators
            }
            _state, preissue = engine.preissue_managed_crypto_oracle(
                case.identity,
                variant_parameters_locator="variant.json",
                variant_expected_output_locator="variant.out",
                mutation_id="managed-rsa-variant",
            )
            for locator in (*locators, "variant.json", "variant.out"):
                (workspace / locator).unlink()
            action = {
                "kind": "prove_crypto_metamorphic",
                "description": "prove the solver on original and variant",
                "candidate_id": "C-crypto-candidate",
                "solver_artifact_path": "solver.py",
                "original_parameters_artifact_path": "original.json",
                "oracle_preissue_id": preissue["preissue_id"],
                "runtime": "python",
            }
            before = engine.store.load(case.identity)
            final, experiment, executor = (
                _execute_full_managed_cycle(
                    engine,
                    case.identity,
                    action=action,
                    payloads=payloads,
                )
            )
            candidate = next(
                item
                for item in final.candidates
                if item.id == "C-crypto-candidate"
            )
            self.assertEqual(
                len(final.workspace_publishes)
                - len(before.workspace_publishes),
                2,
            )
            self.assertIn(Role.CAPTAIN, executor.roles)
            self.assertIn(Role.BUILDER, executor.roles)
            self.assertEqual(
                {
                    item.role
                    for item in final.runs
                    if item.wave_id is not None
                },
                {
                    Role.BUILDER.value,
                    Role.FALSIFIER.value,
                    Role.REPRODUCER.value,
                },
            )
            self.assertEqual(len(sandbox.proof_calls), 6)
            self.assertIs(
                candidate.status,
                CandidateStatus.READY_TO_SUBMIT,
            )
            self.assertEqual(len(candidate.proof_run_ids), 6)
            self.assertIs(final.status, ChallengeStatus.READY_TO_SUBMIT)
            self.assertTrue(experiment.result["passed"])
            self.assertEqual(
                experiment.result["authority"],
                "engine_deterministic_gate",
            )
            self.assertNotIn(
                candidate.value,
                json.dumps(experiment.result, sort_keys=True),
            )
            self.assertGreater(
                len(final.progress_markers),
                len(before.progress_markers),
            )
            self.assertEqual(final.submissions, [])
            final.validate()
        finally:
            case.tearDown()

    def test_misc_builder_action_reaches_dag_and_original_oracle(
        self,
    ) -> None:
        case = misc_support.MiscEngineTests(
            "test_clean_dag_and_three_verifier_replays_remain_candidate_only"
        )
        case.setUp()
        try:
            engine, sandbox = case._engine()
            workspace = engine._workspace(
                engine.store.load(case.identity)
            )
            raw_spec = json.loads(
                (workspace / "misc-spec.json").read_text(
                    encoding="utf-8"
                )
            )
            raw_spec.pop("verifier")
            payloads = {
                "misc-spec.json": json.dumps(
                    raw_spec,
                    sort_keys=True,
                ).encode("utf-8"),
                "transform.py": (workspace / "transform.py").read_bytes(),
            }
            _state, preissue = engine.preissue_managed_misc_oracle(
                case.identity,
                verifier_locator="verify.py",
                verifier_id="original-condition",
                oracle_id="operator-oracle-v1",
            )
            for locator in (
                "misc-spec.json",
                "transform.py",
                "verify.py",
            ):
                (workspace / locator).unlink()
            action = {
                "kind": "evaluate_misc_transform",
                "description": "verify the transform DAG in the original oracle",
                "candidate_id": "C-misc",
                "spec_artifact_path": "misc-spec.json",
                "oracle_preissue_id": preissue["preissue_id"],
            }
            before = engine.store.load(case.identity)
            final, experiment, executor = (
                _execute_full_managed_cycle(
                    engine,
                    case.identity,
                    action=action,
                    payloads=payloads,
                    extra_write_locators=("transform.py",),
                )
            )
            candidate = next(
                item for item in final.candidates if item.id == "C-misc"
            )
            _assert_exact_typed_binding(
                self,
                experiment,
                action=action,
                payloads=payloads,
            )
            binding = candidate.extra["misc_transform_evidence"]
            self.assertEqual(
                len(final.workspace_publishes)
                - len(before.workspace_publishes),
                2,
            )
            self.assertIn(Role.CAPTAIN, executor.roles)
            self.assertIn(Role.BUILDER, executor.roles)
            self.assertEqual(len(sandbox.proof_calls), 5)
            self.assertTrue(binding["passed"])
            self.assertFalse(binding["automatic_submission_authorized"])
            self.assertIs(
                candidate.status,
                CandidateStatus.OBSERVED_CANDIDATE,
            )
            self.assertEqual(candidate.proof_run_ids, [])
            self.assertTrue(experiment.result["passed"])
            self.assertGreater(len(final.facts), len(before.facts))
            self.assertGreater(
                len(final.progress_markers),
                len(before.progress_markers),
            )
            self.assertEqual(final.submissions, [])
            final.validate()
        finally:
            case.tearDown()

    def test_forensic_builder_action_reaches_two_tool_fact_progress_gate(
        self,
    ) -> None:
        case = forensic_support.ForensicAssertionHotPathTests(
            "test_success_preissues_full_wave_and_authorizes_only_fact_progress"
        )
        case.setUp()
        try:
            engine = case.engine
            workspace = engine._workspace(
                engine.store.load(case.identity)
            )
            payloads = {
                case.spec_locator: (
                    workspace / case.spec_locator
                ).read_bytes()
            }
            (workspace / case.spec_locator).unlink()
            action = {
                "kind": "prove_forensic_assertion",
                "description": "corroborate an indexed exact range",
                "operator_spec_artifact_path": case.spec_locator,
                "hypothesis_ids": [],
                "timeout_seconds": 120,
            }
            before = engine.store.load(case.identity)
            final, experiment, executor = (
                _execute_full_managed_cycle(
                    engine,
                    case.identity,
                    action=action,
                    payloads=payloads,
                )
            )
            _assert_exact_typed_binding(
                self,
                experiment,
                action=action,
                payloads=payloads,
            )
            self.assertEqual(
                len(final.workspace_publishes)
                - len(before.workspace_publishes),
                1,
            )
            self.assertIn(Role.CAPTAIN, executor.roles)
            self.assertIn(Role.BUILDER, executor.roles)
            self.assertTrue(experiment.result["passed"])
            self.assertEqual(case.coordinator.run_count, 2)
            self.assertTrue(
                all(
                    not policy.allow_targets
                    for policy in case.coordinator.policies
                )
            )
            self.assertGreater(len(final.facts), len(before.facts))
            self.assertGreater(
                len(final.progress_markers),
                len(before.progress_markers),
            )
            self.assertEqual(len(final.candidates), len(before.candidates))
            self.assertEqual(final.submissions, [])
            encoded = json.dumps(
                final.to_dict(),
                sort_keys=True,
            ).encode("utf-8")
            self.assertNotIn(b"forensic-observation:", encoded)
            final.validate()
        finally:
            case.tearDown()


if __name__ == "__main__":
    unittest.main()
