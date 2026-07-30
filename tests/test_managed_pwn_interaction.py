from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from ctf_os.codex import Role, role_output_schema, validate_role_output
from ctf_os.contracts.pwn_interaction_v1 import (
    PWN_INTERACTION_V1_CONTRACT_ID,
    PWN_INTERACTION_V1_CONTRACT_VERSION,
    PWN_INTERACTION_V1_PROTOCOL,
    PWN_INTERACTION_V1_SENTINEL_REF,
    parse_pwn_interaction_v1_recipe,
    pwn_interaction_v1_canonical_json_bytes,
)
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.models import (
    ChallengeIdentity,
    Experiment,
    ExperimentKind,
    ExperimentStatus,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from tests.test_engine import _payload
from tests.test_managed_category_hotpaths import (
    _execute_managed_typed_action,
)


def _recipe_bytes() -> bytes:
    return pwn_interaction_v1_canonical_json_bytes(
        {
            "contract": {
                "id": PWN_INTERACTION_V1_CONTRACT_ID,
                "protocol": PWN_INTERACTION_V1_PROTOCOL,
                "version": PWN_INTERACTION_V1_CONTRACT_VERSION,
            },
            "effect": {
                "address_ref": "effect_address",
                "control_value": 0,
                "sentinel_ref": PWN_INTERACTION_V1_SENTINEL_REF,
                "success_stream": "stdout_or_stderr",
            },
            "schema_version": 1,
            "steps": [
                {
                    "id": "effect",
                    "name": "effect_address",
                    "op": "set_u64",
                    "value": 0x4141414141414141,
                },
                {
                    "id": "effect-bytes",
                    "name": "effect_bytes",
                    "op": "pack_u64",
                    "value": {"ref": "effect_address"},
                },
                {
                    "id": "send-effect",
                    "mode": "raw",
                    "op": "send",
                    "parts": [{"ref": "effect_bytes"}],
                },
                {
                    "id": "send-sentinel",
                    "mode": "raw",
                    "op": "send",
                    "parts": [{"ref": PWN_INTERACTION_V1_SENTINEL_REF}],
                },
                {"id": "close", "op": "shutdown_stdin"},
            ],
            "timeout_milliseconds": 1_000,
        }
    )


def _action() -> dict[str, object]:
    return {
        "kind": "prove_pwn_interaction",
        "description": "prove the data-only exploit interaction",
        "parent_experiment_id": "E-executed-parent",
        "recipe_artifact_path": "pwn/interaction.json",
        "timeout_seconds": 60,
    }


def _builder_payload(action: dict[str, object]) -> dict[str, object]:
    payload = _payload(Role.BUILDER)
    payload["schema_version"] = 2
    payload["hypotheses"] = []
    payload["actions"] = [action]
    return payload


class ManagedPwnInteractionContractTests(unittest.TestCase):
    def test_v2_builder_action_is_exact_and_data_only(self) -> None:
        action = _action()
        result = validate_role_output(
            _builder_payload(action),
            Role.BUILDER,
            contract_version=2,
        )
        self.assertTrue(result.valid, result.errors)
        self.assertEqual(
            set(action),
            {
                "kind",
                "description",
                "parent_experiment_id",
                "recipe_artifact_path",
                "timeout_seconds",
            },
        )
        schema = role_output_schema(Role.BUILDER, contract_version=2)
        variants = {
            item["properties"]["kind"]["enum"][0]: item
            for item in schema["properties"]["actions"]["items"]["anyOf"]
        }
        variant = variants["prove_pwn_interaction"]
        self.assertEqual(set(variant["required"]), set(action))
        self.assertFalse(variant["additionalProperties"])
        for role in (Role.REPRODUCER, Role.VALIDATOR):
            other = role_output_schema(role, contract_version=2)
            kinds = {
                item["properties"]["kind"]["enum"][0]
                for item in other["properties"]["actions"]["items"]["anyOf"]
            }
            self.assertNotIn("prove_pwn_interaction", kinds)

    def test_action_rejects_harness_command_environment_and_network(self) -> None:
        hostile_fields = {
            "command": "python exploit.py",
            "environment": {"LD_PRELOAD": "/tmp/libc.so"},
            "harness_artifact_path": "pwn/exploit.py",
            "network_target_id": "remote-target",
            "success": True,
        }
        for field, value in hostile_fields.items():
            with self.subTest(field=field):
                action = _action()
                action[field] = value
                result = validate_role_output(
                    _builder_payload(action),
                    Role.BUILDER,
                    contract_version=2,
                )
                self.assertFalse(result.valid)


class ManagedPwnInteractionDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.identity = ChallengeIdentity(
            "Managed Pwn",
            "pwn",
            "interaction",
        )
        incoming = (
            self.root
            / "incoming"
            / self.identity.contest_id
            / self.identity.category
            / self.identity.challenge_id
        )
        incoming.mkdir(parents=True)
        (incoming / "chall").write_bytes(
            b"\x7fELF" + b"\x00" * 256
        )
        self.engine = ChallengeEngine(self.root)
        self.engine.add_challenge(
            self.identity,
            prompt="prove a local bounded interaction",
            state_schema_version=STATE_SCHEMA_VERSION,
        )

        def seed_parent(state) -> None:
            state.experiments.append(
                Experiment(
                    id="E-executed-parent",
                    hypothesis_ids=[],
                    command="operator-owned executed parent",
                    expected_observation="terminal executed evidence",
                    keep_if="execution reproduced",
                    drop_if="execution failed",
                    timeout_seconds=30,
                    kind=ExperimentKind.PROBE,
                    status=ExperimentStatus.COMPLETED,
                    result={"authority": "executed"},
                )
            )

        self.engine.store.update(self.identity, seed_parent)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_builder_publish_register_dispatch_accepts_only_three_plus_three(
        self,
    ) -> None:
        recipe = _recipe_bytes()
        parse_pwn_interaction_v1_recipe(recipe)
        evaluation = SimpleNamespace(
            passed=True,
            reason_code="effect_proven",
            attack_receipts=(object(), object(), object()),
            control_receipts=(object(), object(), object()),
            canonical_bytes=lambda: b'{"passed":true}\n',
        )
        with mock.patch.object(
            self.engine,
            "prove_pwn_interaction",
            return_value=(
                self.engine.store.load(self.identity),
                evaluation,
            ),
        ) as prove:
            final, experiment, publication = (
                _execute_managed_typed_action(
                    self.engine,
                    self.identity,
                    action=_action(),
                    payloads={"pwn/interaction.json": recipe},
                )
            )
        self.assertEqual(publication.published_count, 1)
        self.assertIs(experiment.status, ExperimentStatus.COMPLETED)
        self.assertTrue(experiment.result["passed"])
        request = experiment.extra["managed_typed_gate_request"]
        self.assertEqual(
            request["recipe_sha256"],
            parse_pwn_interaction_v1_recipe(recipe).sha256,
        )
        self.assertEqual(request["recipe_size_bytes"], len(recipe))
        self.assertEqual(
            set(request["artifact_bindings"]),
            {"recipe_artifact_path"},
        )
        prove.assert_called_once_with(
            self.identity,
            parent_experiment_id="E-executed-parent",
            recipe_locator="pwn/interaction.json",
            timeout_seconds=60,
            _session_owned=True,
        )
        self.assertEqual(final.candidates, [])
        self.assertEqual(final.submissions, [])

    def test_engine_pass_with_wrong_replay_width_is_not_authority(self) -> None:
        evaluation = SimpleNamespace(
            passed=True,
            reason_code="effect_proven",
            attack_receipts=(object(), object()),
            control_receipts=(object(), object(), object()),
            canonical_bytes=lambda: b'{"passed":true}\n',
        )
        with mock.patch.object(
            self.engine,
            "prove_pwn_interaction",
            return_value=(
                self.engine.store.load(self.identity),
                evaluation,
            ),
        ):
            final, experiment, _publication = (
                _execute_managed_typed_action(
                    self.engine,
                    self.identity,
                    action=_action(),
                    payloads={
                        "pwn/interaction.json": _recipe_bytes(),
                    },
                )
            )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertFalse(experiment.result["passed"])
        self.assertIn(
            "pwn_interaction_replay_matrix_invalid",
            experiment.result["reason_codes"],
        )
        self.assertEqual(final.candidates, [])
        self.assertEqual(final.submissions, [])

    def test_noncanonical_recipe_is_rejected_before_dispatch(self) -> None:
        noncanonical = _recipe_bytes().replace(b",", b", ", 1)
        with self.assertRaisesRegex(
            AssertionError,
            "typed_gate_recipe_invalid",
        ), mock.patch.object(
            self.engine,
            "prove_pwn_interaction",
        ) as prove:
            _execute_managed_typed_action(
                self.engine,
                self.identity,
                action=_action(),
                payloads={"pwn/interaction.json": noncanonical},
            )
        prove.assert_not_called()

    def test_post_registration_recipe_mutation_fails_closed(self) -> None:
        workspace_recipe = (
            self.engine.store.challenge_paths(self.identity).artifacts
            / "workspace"
            / "pwn"
            / "interaction.json"
        )

        def mutate(_orchestrator, _experiment_id) -> None:
            workspace_recipe.chmod(0o600)
            workspace_recipe.write_bytes(b"{}\n")

        with mock.patch.object(
            self.engine,
            "prove_pwn_interaction",
        ) as prove:
            final, experiment, _publication = (
                _execute_managed_typed_action(
                    self.engine,
                    self.identity,
                    action=_action(),
                    payloads={
                        "pwn/interaction.json": _recipe_bytes(),
                    },
                    before_execute=mutate,
                )
            )
        prove.assert_not_called()
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertFalse(experiment.result["passed"])
        self.assertEqual(final.candidates, [])
        self.assertEqual(final.submissions, [])
