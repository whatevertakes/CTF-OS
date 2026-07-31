from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ctf_os.adapters import get_adapter
from ctf_os.codex import (
    Role,
    role_output_schema,
    validate_role_output,
)
from ctf_os.engine.context_pack import build_context_pack
from ctf_os.codex.contracts import (
    MANAGED_DATA_TRANSCRIPT_ACTION_KIND,
)
from ctf_os.contracts.data_transcript_v1 import (
    DATA_TRANSCRIPT_V1_CONTRACT_FINGERPRINT,
    DATA_TRANSCRIPT_V1_CONTRACT_ID,
    DATA_TRANSCRIPT_V1_CONTRACT_VERSION,
    DATA_TRANSCRIPT_V1_PROTOCOL,
    data_transcript_v1_canonical_json_bytes,
)
from ctf_os.managed import ManagedOrchestrator
from ctf_os.engine.managed_oracle_preissue import (
    MANAGED_ORACLE_PREISSUE_CRYPTO_TRANSCRIPT,
    MANAGED_ORACLE_PREISSUE_MISC_TRANSCRIPT,
    MANAGED_ORACLE_PREISSUE_STATE_KEY,
)
from ctf_os.models import (
    ArtifactReference,
    ChallengeIdentity,
    ExperimentStatus,
    RunStatus,
    utc_now,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from tests.test_codex import valid_payload
import tests.test_managed as managed_test_helpers


RAW_PEER_SECRET = b"operator-private-peer-body"
RAW_PEER_DATA_SECRET = b"operator-private-reset-seed"
RAW_RECIPE_SECRET = "builder-private-recipe-literal"


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _recipe(
    *,
    category: str,
    preissue_id: str,
    reset_commitment_sha256: str,
) -> bytes:
    return data_transcript_v1_canonical_json_bytes(
        {
            "category": category,
            "contract": {
                "id": DATA_TRANSCRIPT_V1_CONTRACT_ID,
                "protocol": DATA_TRANSCRIPT_V1_PROTOCOL,
                "version": DATA_TRANSCRIPT_V1_CONTRACT_VERSION,
            },
            "preissue_id": preissue_id,
            "reset_commitment_sha256": reset_commitment_sha256,
            "schema_version": 1,
            "steps": [
                {
                    "data": {
                        "encoding": "utf8",
                        "value": RAW_RECIPE_SECRET,
                    },
                    "id": "send-secret",
                    "op": "send",
                },
                {
                    "data": {
                        "encoding": "utf8",
                        "value": "accepted\n",
                    },
                    "id": "expect-result",
                    "max_read_bytes": 9,
                    "op": "expect",
                    "stream": "stdout",
                },
            ],
            "timeout_milliseconds": 1000,
        }
    )


class ManagedDataTranscriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _engine(self):
        # Reuse the repository's established no-model/no-remote managed
        # fixture: it uses a fake process executor and a local fake sandbox.
        return managed_test_helpers.ManagedTypedGateTests.engine(self)

    def _fixture(
        self,
        *,
        suffix: str,
        category: str,
        builder_base: str = "after",
    ):
        identity = ChallengeIdentity(
            "Managed Data Transcript",
            category,
            suffix,
        )
        incoming = (
            self.root
            / "incoming"
            / identity.contest_id
            / identity.category
            / identity.challenge_id
        )
        incoming.mkdir(parents=True)
        (incoming / "challenge.bin").write_bytes(
            b"local transcript challenge"
        )
        engine = self._engine()
        engine.add_challenge(
            identity,
            prompt="exercise one managed data transcript",
            state_schema_version=STATE_SCHEMA_VERSION,
        )

        operator_root = (
            self.root / "operator" / category / suffix
        )
        operator_root.mkdir(parents=True)
        peer = operator_root / "peer"
        peer.write_bytes(
            b"#!/bin/sh\n# " + RAW_PEER_SECRET + b"\nexit 0\n"
        )
        peer.chmod(0o500)
        peer_data = operator_root / "peer-data.bin"
        peer_data.write_bytes(RAW_PEER_DATA_SECRET)
        if category == "crypto":
            _state, preissue = (
                engine.preissue_managed_crypto_transcript(
                    identity,
                    peer_path=peer,
                    peer_data_path=peer_data,
                )
            )
        else:
            _state, preissue = (
                engine.preissue_managed_misc_transcript(
                    identity,
                    peer_path=peer,
                    peer_data_path=peer_data,
                )
            )

        recipe = _recipe(
            category=category,
            preissue_id=str(preissue["preissue_id"]),
            reset_commitment_sha256=str(
                preissue["reset_commitment_sha256"]
            ),
        )
        locator = "transcript/recipe.json"
        action = {
            "kind": MANAGED_DATA_TRANSCRIPT_ACTION_KIND,
            "oracle_preissue_id": str(preissue["preissue_id"]),
            "recipe_artifact_path": locator,
        }
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=(
                managed_test_helpers.ManagedTypedGateTests.capability
            ),
        )
        _state, session_id = orchestrator._reserve_session(
            identity, None
        )
        _state, cycle = orchestrator._reserve_cycle(
            identity, session_id
        )
        _state, wave, role_runs = orchestrator._reserve_wave(
            identity,
            session_id,
            cycle.id,
            "attack",
        )
        builder_run_id = role_runs[Role.BUILDER]
        run_workspace = (
            engine.store.run_paths(
                identity, run_id=builder_run_id
            ).root
            / "workspace"
        )
        staged = run_workspace / locator
        staged.parent.mkdir(parents=True)
        staged.write_bytes(recipe)

        artifact_id = f"A-{builder_run_id}-transcript-recipe"
        snapshot_relative = (
            f"artifacts/snapshots/{artifact_id}.json"
        )
        snapshot = (
            engine.store.challenge_paths(identity).root
            / snapshot_relative
        )
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(recipe)
        snapshot.chmod(0o400)

        def seed(state) -> None:
            run = next(
                item
                for item in state.runs
                if item.id == builder_run_id
            )
            if builder_base == "equal":
                run.base_revision = int(
                    preissue["issue_revision"]
                )
            elif builder_base != "after":
                raise AssertionError("invalid Builder base relation")
            run.status = RunStatus.COMPLETED
            run.result_path = (
                f"runs/{builder_run_id}/result.json"
            )
            run.validation_path = (
                f"runs/{builder_run_id}/validation.json"
            )
            run.extra["semantic_merge"] = True
            state.artifacts.append(
                ArtifactReference(
                    id=artifact_id,
                    path=snapshot_relative,
                    sha256=_sha256(recipe),
                    source_run_id=builder_run_id,
                    size=len(recipe),
                    extra={
                        "reported_locator": locator,
                        "purpose": (
                            "managed data transcript recipe"
                        ),
                    },
                )
            )

        engine.store.update(identity, seed)
        result = mock.Mock(
            invocation=mock.Mock(
                role=Role.BUILDER,
                run_id=builder_run_id,
                contract_version=2,
            ),
            output={
                "actions": [copy.deepcopy(action)],
                "hypotheses": [],
            },
            attempts=(mock.Mock(),),
        )
        publish = orchestrator._apply_builder_publishes(
            identity,
            wave,
            (result,),
        )
        registration = orchestrator._register_typed_gate_actions(
            identity,
            wave,
            (result,),
        )
        return {
            "action": action,
            "builder_run_id": builder_run_id,
            "cycle": cycle,
            "engine": engine,
            "identity": identity,
            "locator": locator,
            "orchestrator": orchestrator,
            "preissue": preissue,
            "publish": publish,
            "recipe": recipe,
            "registration": registration,
            "session_id": session_id,
            "wave": wave,
        }

    def test_v2_builder_action_schema_is_exact_and_data_only(self):
        payload = valid_payload(Role.BUILDER)
        payload["schema_version"] = 2
        payload["hypotheses"] = []
        payload["actions"] = [
            {
                "kind": MANAGED_DATA_TRANSCRIPT_ACTION_KIND,
                "oracle_preissue_id": "operator-preissue-1",
                "recipe_artifact_path": "transcript/recipe.json",
            }
        ]
        valid = validate_role_output(
            payload,
            Role.BUILDER,
            contract_version=2,
        )
        self.assertTrue(valid.valid, valid.errors)

        schema = role_output_schema(
            Role.BUILDER,
            contract_version=2,
        )
        variants = {
            item["properties"]["kind"]["enum"][0]: item
            for item in schema["properties"]["actions"]["items"][
                "anyOf"
            ]
        }
        transcript = variants[
            MANAGED_DATA_TRANSCRIPT_ACTION_KIND
        ]
        self.assertFalse(transcript["additionalProperties"])
        self.assertEqual(
            set(transcript["required"]),
            {
                "kind",
                "oracle_preissue_id",
                "recipe_artifact_path",
            },
        )
        self.assertEqual(
            set(transcript["properties"]),
            set(transcript["required"]),
        )

        for hostile_field, hostile_value in (
            ("description", "model-declared verdict"),
            ("command", "/bin/sh -lc 'read hidden peer'"),
            ("raw_command", ["peer", "--dump-secret"]),
        ):
            with self.subTest(field=hostile_field):
                hostile = copy.deepcopy(payload)
                hostile["actions"][0][
                    hostile_field
                ] = hostile_value
                rejected = validate_role_output(
                    hostile,
                    Role.BUILDER,
                    contract_version=2,
                )
                self.assertFalse(rejected.valid)
                self.assertIn(
                    "unexpected keys",
                    "\n".join(rejected.errors),
                )

        v1 = copy.deepcopy(payload)
        v1["schema_version"] = 1
        rejected_v1 = validate_role_output(
            v1,
            Role.BUILDER,
            contract_version=1,
        )
        self.assertFalse(rejected_v1.valid)
        self.assertIn(
            "restricted to the v2 builder",
            "\n".join(rejected_v1.errors),
        )
        wrong_role = copy.deepcopy(payload)
        wrong_role["role"] = Role.FALSIFIER.value
        rejected_role = validate_role_output(
            wrong_role,
            Role.FALSIFIER,
            contract_version=2,
        )
        self.assertFalse(rejected_role.valid)
        self.assertIn(
            "restricted to the v2 builder",
            "\n".join(rejected_role.errors),
        )

    def test_crypto_and_misc_registration_binds_only_commitments(self):
        for category in ("crypto", "misc"):
            with self.subTest(category=category):
                fixture = self._fixture(
                    suffix=f"binding-{category}",
                    category=category,
                )
                registration = fixture["registration"]
                self.assertIsNone(registration.rejection_code)
                self.assertEqual(
                    len(registration.experiment_ids), 1
                )
                self.assertEqual(
                    fixture["publish"].published_count, 1
                )
                state = fixture["engine"].store.load(
                    fixture["identity"]
                )
                builder_run = next(
                    item
                    for item in state.runs
                    if item.id == fixture["builder_run_id"]
                )
                self.assertGreater(
                    builder_run.base_revision,
                    int(fixture["preissue"]["issue_revision"]),
                )
                experiment = next(
                    item
                    for item in state.experiments
                    if item.id
                    == registration.experiment_ids[0]
                )
                request = experiment.extra[
                    "managed_typed_gate_request"
                ]
                self.assertEqual(
                    set(request),
                    {
                        "action_kind",
                        "artifact_bindings",
                        "configuration_epoch",
                        "oracle_preissue_id",
                        "recipe_contract_fingerprint",
                        "recipe_sha256",
                        "recipe_size_bytes",
                        "reset_commitment_sha256",
                        "schema_version",
                        "source_builder_run_id",
                    },
                )
                transcript_fields = {
                    "oracle_preissue_id",
                    "recipe_contract_fingerprint",
                    "recipe_sha256",
                    "recipe_size_bytes",
                    "reset_commitment_sha256",
                }
                self.assertEqual(
                    transcript_fields,
                    transcript_fields.intersection(request),
                )
                self.assertEqual(
                    request["recipe_contract_fingerprint"],
                    DATA_TRANSCRIPT_V1_CONTRACT_FINGERPRINT,
                )
                self.assertEqual(
                    request["recipe_sha256"],
                    _sha256(fixture["recipe"]),
                )
                self.assertEqual(
                    request["recipe_size_bytes"],
                    len(fixture["recipe"]),
                )
                self.assertEqual(
                    request["reset_commitment_sha256"],
                    fixture["preissue"][
                        "reset_commitment_sha256"
                    ],
                )
                self.assertNotIn("peer", request)
                self.assertNotIn("peer_data", request)
                encoded = json.dumps(
                    request,
                    ensure_ascii=True,
                    sort_keys=True,
                )
                self.assertNotIn(
                    RAW_PEER_SECRET.decode("ascii"), encoded
                )
                self.assertNotIn(
                    RAW_PEER_DATA_SECRET.decode("ascii"), encoded
                )
                self.assertNotIn(RAW_RECIPE_SECRET, encoded)
                self.assertNotIn(
                    fixture["recipe"].decode("ascii").strip(),
                    encoded,
                )
                canonical_recipe = (
                    fixture["engine"].store.challenge_paths(
                        fixture["identity"]
                    ).artifacts
                    / "workspace"
                    / fixture["locator"]
                ).read_bytes()
                self.assertEqual(
                    canonical_recipe, fixture["recipe"]
                )
                preissue = state.extra[
                    MANAGED_ORACLE_PREISSUE_STATE_KEY
                ][fixture["preissue"]["preissue_id"]]
                self.assertEqual(preissue["status"], "unused")
                self.assertEqual(
                    preissue["kind"],
                    (
                        MANAGED_ORACLE_PREISSUE_CRYPTO_TRANSCRIPT
                        if category == "crypto"
                        else MANAGED_ORACLE_PREISSUE_MISC_TRANSCRIPT
                    ),
                )
                context = build_context_pack(
                    state,
                    get_adapter(state.category),
                    state_path=fixture[
                        "engine"
                    ].store.challenge_paths(
                        fixture["identity"]
                    ).state,
                    role=Role.BUILDER.value,
                ).text
                recipe_binding = request["artifact_bindings"][
                    "recipe_artifact_path"
                ]
                for forbidden in (
                    RAW_PEER_SECRET.decode("ascii"),
                    RAW_PEER_DATA_SECRET.decode("ascii"),
                    RAW_RECIPE_SECRET,
                    fixture["locator"],
                    request["recipe_sha256"],
                    recipe_binding["artifact_id"],
                ):
                    self.assertNotIn(forbidden, context)

    def test_preissue_revision_must_be_strictly_before_builder(self):
        fixture = self._fixture(
            suffix="equal-revision",
            category="crypto",
            builder_base="equal",
        )
        self.assertEqual(
            fixture["registration"].experiment_ids, ()
        )
        self.assertEqual(
            fixture["registration"].rejection_code,
            "typed_gate_oracle_preissue_invalid",
        )

    def test_execution_forwards_exact_scope_and_only_terminalizes_gate(self):
        fixture = self._fixture(
            suffix="execute",
            category="misc",
        )
        experiment_id = fixture[
            "registration"
        ].experiment_ids[0]
        before = fixture["engine"].store.load(
            fixture["identity"]
        )
        before_candidate_ids = [
            item.id for item in before.candidates
        ]
        before_submission_ids = [
            item.id for item in before.submissions
        ]
        before_artifact_ids = [
            item.id for item in before.artifacts
        ]
        before_run_ids = [item.id for item in before.runs]
        before_experiment_statuses = {
            item.id: item.status for item in before.experiments
        }
        request = next(
            item
            for item in before.experiments
            if item.id == experiment_id
        ).extra["managed_typed_gate_request"]
        recipe_binding = request["artifact_bindings"][
            "recipe_artifact_path"
        ]
        before_status = before.status
        evaluation = mock.Mock(
            passed=True,
            reason_code=(
                "validated_three_clean_three_negative_replays"
            ),
        )
        evaluation.canonical_bytes.return_value = (
            b'{"passed":true}\n'
        )
        with mock.patch.object(
            fixture["engine"],
            "prove_data_transcript",
            return_value=(before, evaluation),
        ) as prove:
            final = fixture[
                "orchestrator"
            ]._execute_typed_gate_experiment(
                fixture["identity"],
                experiment_id,
            )

        prove.assert_called_once_with(
            fixture["identity"],
            recipe_locator=fixture["locator"],
            recipe_artifact_id=recipe_binding["artifact_id"],
            recipe_sha256=recipe_binding["sha256"],
            recipe_size_bytes=recipe_binding["size_bytes"],
            oracle_preissue_id=str(
                fixture["preissue"]["preissue_id"]
            ),
            _session_owned=True,
            _managed_builder_run_id=fixture[
                "builder_run_id"
            ],
            _managed_experiment_id=experiment_id,
        )
        experiment = next(
            item
            for item in final.experiments
            if item.id == experiment_id
        )
        self.assertIs(
            experiment.status, ExperimentStatus.COMPLETED
        )
        self.assertTrue(experiment.result["passed"])
        self.assertEqual(
            experiment.result["action_kind"],
            MANAGED_DATA_TRANSCRIPT_ACTION_KIND,
        )
        self.assertEqual(
            [item.id for item in final.candidates],
            before_candidate_ids,
        )
        self.assertEqual(
            [item.id for item in final.submissions],
            before_submission_ids,
        )
        self.assertEqual(
            [item.id for item in final.artifacts],
            before_artifact_ids,
        )
        self.assertEqual(
            [item.id for item in final.runs],
            before_run_ids,
        )
        self.assertIs(final.status, before_status)
        self.assertEqual(
            {item.id for item in final.experiments},
            set(before_experiment_statuses),
        )
        for item in final.experiments:
            if item.id != experiment_id:
                self.assertIs(
                    item.status,
                    before_experiment_statuses[item.id],
                )

    def test_atomic_pass_wins_over_post_commit_cleanup_error(self):
        fixture = self._fixture(
            suffix="post-commit-cleanup",
            category="crypto",
        )
        experiment_id = fixture[
            "registration"
        ].experiment_ids[0]

        def commit_then_raise(*_args, **_kwargs):
            current = fixture["engine"].store.load(
                fixture["identity"]
            )

            def terminalize(state):
                target = next(
                    item
                    for item in state.experiments
                    if item.id == experiment_id
                )
                target.status = ExperimentStatus.COMPLETED
                target.result = {
                    "schema_version": 1,
                    "action_kind": (
                        MANAGED_DATA_TRANSCRIPT_ACTION_KIND
                    ),
                    "authority": "engine_deterministic_gate",
                    "passed": True,
                    "reason_codes": [
                        "validated_three_clean_three_negative_replays"
                    ],
                    "evaluation_sha256": "f" * 64,
                    "evidence_artifact_ids": [],
                    "evidence_run_ids": [],
                    "execution_error_type": None,
                }
                target.extra["completed_at"] = utc_now()

            fixture["engine"].store.update(
                fixture["identity"],
                terminalize,
                expected_revision=current.revision,
            )
            raise OSError("post-commit lease cleanup failed")

        with mock.patch.object(
            fixture["engine"],
            "prove_data_transcript",
            side_effect=commit_then_raise,
        ):
            final = fixture[
                "orchestrator"
            ]._execute_typed_gate_experiment(
                fixture["identity"],
                experiment_id,
            )

        experiment = next(
            item
            for item in final.experiments
            if item.id == experiment_id
        )
        self.assertIs(
            experiment.status,
            ExperimentStatus.COMPLETED,
        )
        self.assertTrue(experiment.result["passed"])
        self.assertIsNone(
            experiment.result["execution_error_type"]
        )


if __name__ == "__main__":
    unittest.main()
