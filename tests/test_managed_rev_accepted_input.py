from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from ctf_os.codex import Role, role_output_schema, validate_role_output
from ctf_os.config import load_config
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.engine.rev_acceptance import (
    RevAcceptanceOperatorSpec,
    canonical_json_bytes,
)
from ctf_os.managed import ManagedOrchestrator
from ctf_os.models import (
    ArtifactReference,
    ChallengeIdentity,
    ExperimentStatus,
    RunOrigin,
    RunStatus,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from tests.test_engine import _elf64_image, _payload, _rev_inventory_payload
from tests.test_rev_acceptance import (
    ACCEPTED_INPUT,
    RevAcceptanceSandbox,
    _spec,
)


IMAGE_DIGEST = "sha256:" + "a" * 64


def _managed_spec() -> dict[str, object]:
    spec = _spec()
    spec["accepted_input_locator"] = "rev/accepted-input.bin"
    return spec


def _rev_action(
    *,
    spec_payload: bytes,
    accepted_input: bytes = ACCEPTED_INPUT,
) -> dict[str, object]:
    spec = RevAcceptanceOperatorSpec.from_mapping(
        json.loads(spec_payload)
    )
    return {
        "kind": "rev_accepted_input",
        "operator_spec_artifact_path": "rev/operator-spec.json",
        "operator_spec_sha256": hashlib.sha256(
            spec_payload
        ).hexdigest(),
        "accepted_input_artifact_path": "rev/accepted-input.bin",
        "accepted_input_sha256": hashlib.sha256(
            accepted_input
        ).hexdigest(),
        "declared_argv": [
            "/usr/bin/python3",
            "/opt/ctf-templates/rev/stdin_exec.py",
            "--binary",
            "/challenge/challenge.bin",
            "--input",
            "/work/oracle/accepted-input.bin",
        ],
        "expected_oracle": spec.expected_oracle,
    }


def _builder_contract_payload(
    action: dict[str, object],
) -> dict[str, object]:
    payload = _payload(Role.BUILDER)
    payload["schema_version"] = 2
    payload["hypotheses"] = []
    payload["actions"] = [action]
    return payload


class ManagedRevAcceptedInputContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spec_payload = canonical_json_bytes(_managed_spec())

    def test_builder_contract_is_value_free_and_exact(self) -> None:
        action = _rev_action(spec_payload=self.spec_payload)
        result = validate_role_output(
            _builder_contract_payload(action),
            Role.BUILDER,
            contract_version=2,
        )
        self.assertTrue(result.valid, result.errors)
        self.assertNotIn(
            ACCEPTED_INPUT.decode("ascii").strip(),
            json.dumps(action),
        )
        self.assertTrue(
            {
                "candidate_id",
                "description",
                "verdict",
                "flag",
                "command",
            }.isdisjoint(action)
        )

        schema = role_output_schema(
            Role.BUILDER,
            contract_version=2,
        )
        variants = {
            item["properties"]["kind"]["enum"][0]: item
            for item in schema["properties"]["actions"]["items"]["anyOf"]
        }
        self.assertEqual(
            set(variants["rev_accepted_input"]["required"]),
            set(action),
        )
        for role in (Role.REPRODUCER, Role.VALIDATOR):
            other = role_output_schema(role, contract_version=2)
            kinds = {
                item["properties"]["kind"]["enum"][0]
                for item in other["properties"]["actions"]["items"]["anyOf"]
            }
            self.assertNotIn("rev_accepted_input", kinds)

    def test_contract_rejects_raw_or_authority_and_oracle_mutations(self) -> None:
        cases: list[dict[str, object]] = []
        raw = _rev_action(spec_payload=self.spec_payload)
        raw["accepted_input"] = ACCEPTED_INPUT.decode("ascii")
        cases.append(raw)
        authority = _rev_action(spec_payload=self.spec_payload)
        authority["verdict"] = "accepted"
        cases.append(authority)
        argv = _rev_action(spec_payload=self.spec_payload)
        argv["declared_argv"] = ["/bin/sh\x00"]
        cases.append(argv)
        bad_hash = _rev_action(spec_payload=self.spec_payload)
        bad_hash["accepted_input_sha256"] = "A" * 64
        cases.append(bad_hash)
        reordered = _rev_action(spec_payload=self.spec_payload)
        reordered_oracle = copy.deepcopy(reordered["expected_oracle"])
        reordered_oracle["controls"].reverse()
        reordered["expected_oracle"] = reordered_oracle
        cases.append(reordered)

        for index, action in enumerate(cases):
            with self.subTest(index=index):
                result = validate_role_output(
                    _builder_contract_payload(action),
                    Role.BUILDER,
                    contract_version=2,
                )
                self.assertFalse(result.valid)


class ManagedRevAcceptedInputHotPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.identity = ChallengeIdentity(
            "Managed Rev",
            "rev",
            "accepted-input",
        )
        incoming = (
            self.root
            / "incoming"
            / self.identity.contest_id
            / self.identity.category
            / self.identity.challenge_id
        )
        incoming.mkdir(parents=True)
        source = _elf64_image(2) + b"managed-rev-acceptance"
        (incoming / "challenge.bin").write_bytes(source)
        config = load_config(self.root)
        config = replace(
            config,
            runtime=replace(
                config.runtime,
                image_digest=IMAGE_DIGEST,
                command_timeout_s=30,
            ),
        )
        inventory_payload = _rev_inventory_payload(source)
        self.sandbox = RevAcceptanceSandbox(
            self.root / "unused",
            inventory_payload,
        )
        self.engine = ChallengeEngine(
            self.root,
            config=config,
            sandbox_factory=lambda state, work, policy: (
                RevAcceptanceSandbox(work, inventory_payload)
            ),
        )
        state = self.engine.add_challenge(
            self.identity,
            prompt="prove one accepted input without a candidate",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        inventory = next(
            item
            for item in state.experiments
            if item.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )
        self.engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(inventory.id,),
        )
        self.before = self.engine.store.load(self.identity)
        self.orchestrator = ManagedOrchestrator(self.engine)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _register(
        self,
        *,
        mutate_action=None,
    ):
        _state, session_id = self.orchestrator._reserve_session(
            self.identity,
            None,
        )
        _state, cycle = self.orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        _state, wave, role_runs = self.orchestrator._reserve_wave(
            self.identity,
            session_id,
            cycle.id,
            "attack",
        )
        run_id = role_runs[Role.BUILDER]
        spec_payload = canonical_json_bytes(_managed_spec())
        payloads = {
            "rev/operator-spec.json": spec_payload,
            "rev/accepted-input.bin": ACCEPTED_INPUT,
        }
        action = _rev_action(spec_payload=spec_payload)
        if mutate_action is not None:
            mutate_action(action)
        run_workspace = (
            self.engine.store.run_paths(
                self.identity,
                run_id=run_id,
            ).root
            / "workspace"
        )
        snapshots = (
            self.engine.store.challenge_paths(self.identity).artifacts
            / "snapshots"
        )
        snapshots.mkdir(parents=True, exist_ok=True)
        records: list[tuple[str, str, bytes, str]] = []
        for ordinal, (locator, payload) in enumerate(
            payloads.items(),
            start=1,
        ):
            staged = run_workspace / locator
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes(payload)
            artifact_id = f"A-{run_id}-rev-{ordinal}"
            relative = f"artifacts/snapshots/{artifact_id}.bin"
            snapshot = (
                self.engine.store.challenge_paths(self.identity).root
                / relative
            )
            snapshot.write_bytes(payload)
            snapshot.chmod(0o400)
            records.append(
                (artifact_id, relative, payload, locator)
            )

        def seed(state):
            run = next(item for item in state.runs if item.id == run_id)
            run.status = RunStatus.COMPLETED
            run.result_path = f"runs/{run_id}/result.json"
            run.validation_path = f"runs/{run_id}/validation.json"
            run.extra["semantic_merge"] = True
            for artifact_id, relative, payload, locator in records:
                state.artifacts.append(
                    ArtifactReference(
                        id=artifact_id,
                        path=relative,
                        sha256=hashlib.sha256(payload).hexdigest(),
                        source_run_id=run_id,
                        size=len(payload),
                        extra={
                            "reported_locator": locator,
                            "purpose": "managed Rev gate input",
                        },
                    )
                )

        self.engine.store.update(self.identity, seed)
        result = mock.Mock(
            invocation=mock.Mock(
                role=Role.BUILDER,
                run_id=run_id,
                contract_version=2,
            ),
            output={
                "hypotheses": [],
                "actions": [action],
            },
            attempts=(mock.Mock(),),
        )
        publish = self.orchestrator._apply_builder_publishes(
            self.identity,
            wave,
            (result,),
        )
        registration = self.orchestrator._register_typed_gate_actions(
            self.identity,
            wave,
            (result,),
        )
        return (
            session_id,
            cycle,
            wave,
            action,
            publish,
            registration,
        )

    def test_dispatch_runs_original_binary_three_plus_three_without_authority(
        self,
    ) -> None:
        (
            session_id,
            cycle,
            wave,
            action,
            publish,
            registration,
        ) = self._register()
        self.assertEqual(publish.published_count, 2)
        self.assertIsNone(registration.rejection_code)
        experiment_id = registration.experiment_ids[0]
        self.orchestrator._mark_action_selection(
            self.identity,
            session_id,
            cycle.id,
            (experiment_id,),
        )
        state = self.orchestrator._execute_selected_actions(
            self.identity,
            (experiment_id,),
            record_stall=False,
        )
        managed = next(
            item for item in state.experiments if item.id == experiment_id
        )
        self.assertIs(managed.status, ExperimentStatus.COMPLETED)
        self.assertTrue(managed.result["passed"])
        request = managed.extra["managed_typed_gate_request"]
        self.assertEqual(
            request["action_kind"],
            "rev_accepted_input",
        )
        self.assertEqual(request["declared_argv"], action["declared_argv"])
        self.assertEqual(
            request["expected_oracle"],
            action["expected_oracle"],
        )
        self.assertTrue(
            {
                "candidate_id",
                "candidate",
                "verdict",
                "flag",
                "accepted_input",
            }.isdisjoint(request)
        )
        rev_experiment = next(
            item
            for item in state.experiments
            if isinstance(item.result, dict)
            and "rev_acceptance_evidence" in item.result
        )
        evaluation = rev_experiment.result[
            "rev_acceptance_evidence"
        ]["evaluation"]
        self.assertTrue(evaluation["passed"])
        self.assertEqual(len(evaluation["observations"]), 6)
        proof_run_ids = {
            observation["run_id"]
            for observation in evaluation["observations"]
        }
        self.assertEqual(
            {
                item.origin
                for item in state.runs
                if item.id in proof_run_ids
            },
            {RunOrigin.MANAGED_TOOL},
        )
        self.assertTrue(
            all(
                observation["network"] == "none"
                and observation["clean_workspace"] is True
                for observation in evaluation["observations"]
            )
        )
        self.assertEqual(state.candidates, [])
        self.assertEqual(state.submissions, [])
        self.assertEqual(state.status, self.before.status)
        self.assertNotIn(
            ACCEPTED_INPUT.decode("ascii").strip(),
            json.dumps(state.to_dict()),
        )
        checkpointed = self.orchestrator._checkpoint_selected_actions(
            self.identity,
            session_id,
            cycle.id,
            wave,
            (experiment_id,),
            note=None,
        )
        self.assertIsNone(
            checkpointed.checkpoints[-1].failure_capsule
        )

    def test_registration_rejects_hash_argv_and_oracle_mismatch(self) -> None:
        mutations = (
            lambda action: action.__setitem__(
                "accepted_input_sha256",
                "0" * 64,
            ),
            lambda action: action["declared_argv"].__setitem__(
                3,
                "/challenge/other.bin",
            ),
            lambda action: action["expected_oracle"]["accepted"].__setitem__(
                "stdout_sha256",
                "1" * 64,
            ),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                if index:
                    self.tearDown()
                    self.setUp()
                registration = self._register(
                    mutate_action=mutate,
                )[-1]
                self.assertEqual(registration.experiment_ids, ())
                self.assertIn(
                    registration.rejection_code,
                    {
                        "typed_gate_workspace_binding_changed",
                        "typed_gate_reference_invalid",
                    },
                )

    def test_post_registration_request_tampering_fails_before_gate(self) -> None:
        (
            _session_id,
            _cycle,
            _wave,
            _action,
            _publish,
            registration,
        ) = self._register()
        experiment_id = registration.experiment_ids[0]

        def tamper(state):
            experiment = next(
                item
                for item in state.experiments
                if item.id == experiment_id
            )
            experiment.extra["managed_typed_gate_request"][
                "declared_argv"
            ][3] = "/challenge/other.bin"

        self.engine.store.update(self.identity, tamper)
        with mock.patch.object(
            self.engine,
            "prove_rev_accepted_input",
        ) as prove, self.assertRaisesRegex(
            Exception,
            "declaration changed",
        ):
            self.orchestrator._execute_typed_gate_experiment(
                self.identity,
                experiment_id,
            )
        prove.assert_not_called()


if __name__ == "__main__":
    unittest.main()
