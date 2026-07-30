from __future__ import annotations

import copy
import unittest
from dataclasses import replace

from ctf_os.engine.web_impact_state import (
    WEB_IMPACT_STATE_EXECUTOR,
    WEB_IMPACT_STATE_PROTOCOL,
    WebImpactStateContractError,
    WebImpactStateIds,
    build_web_impact_state_projection,
    validate_web_impact_state_graph,
    validate_web_impact_state_projection,
    web_impact_state_graph_errors,
)
from ctf_os.models import (
    ArtifactReference,
    CandidateStatus,
    ChallengeIdentity,
    ChallengeState,
    ChallengeStatus,
    ExperimentKind,
    ExperimentStatus,
    FlagCandidate,
    ReceiptOutcome,
    RunOrigin,
    RunStatus,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from tests.test_web_impact_execution import (
    COOKIE_VALUE,
    CONTROL_BODY,
    VULNERABLE_BODY,
    WebImpactExecutionTests,
)


class WebImpactStateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.transport_case = WebImpactExecutionTests()
        self.transport_case.setUp()
        self.evaluation = self.transport_case._evaluate()
        self.execution_plan = self.transport_case.execution_plan
        self.operator_payload = self.transport_case.operator_payload
        self.identity = ChallengeIdentity(
            contest_id="State CTF",
            category="web",
            challenge_id="impact-state",
        )
        self.ids = WebImpactStateIds(
            experiment_id="E-web-impact",
            operator_spec_artifact_id="A-web-operator-spec",
            plan_artifact_id="A-web-execution-plan",
            evaluation_artifact_id="A-web-execution-evaluation",
            fact_id="F-web-impact",
            progress_id="P-web-impact",
        )
        self.wall_seconds = {
            record.run_id: float(index)
            for index, record in enumerate(
                self.evaluation.records,
                start=1,
            )
        }
        self.projection = self._build()

    def _build(
        self,
        *,
        evaluation=None,
        execution_plan=None,
        operator_payload=None,
        identity=None,
        configuration_epoch=4,
        base_revision=11,
        ids=None,
        hypothesis_ids=(),
        evaluated_at="2026-07-31T02:03:04Z",
        timeout_seconds=900,
        run_origin=RunOrigin.OPERATOR_TOOL,
        replay_wall_seconds=None,
        existing_global_ids=(),
    ):
        selected_evaluation = (
            self.evaluation
            if evaluation is None
            else evaluation
        )
        return build_web_impact_state_projection(
            selected_evaluation,
            (
                self.execution_plan
                if execution_plan is None
                else execution_plan
            ),
            (
                self.operator_payload
                if operator_payload is None
                else operator_payload
            ),
            identity=self.identity if identity is None else identity,
            configuration_epoch=configuration_epoch,
            base_revision=base_revision,
            ids=self.ids if ids is None else ids,
            hypothesis_ids=hypothesis_ids,
            evaluated_at=evaluated_at,
            timeout_seconds=timeout_seconds,
            run_origin=run_origin,
            replay_wall_seconds=(
                self.wall_seconds
                if replay_wall_seconds is None
                else replay_wall_seconds
            ),
            existing_global_ids=existing_global_ids,
        )

    def _state(self, projection=None) -> ChallengeState:
        selected = self.projection if projection is None else projection
        state = ChallengeState(
            contest_id=self.identity.contest_id,
            category=self.identity.category,
            challenge_id=self.identity.challenge_id,
            schema_version=STATE_SCHEMA_VERSION,
            revision=12,
            status=ChallengeStatus.TRIAGING,
            configuration_epoch=4,
        )
        state.experiments.append(selected.experiment)
        state.runs.extend(selected.runs)
        state.receipts.extend(selected.receipts)
        state.artifacts.extend(selected.artifacts)
        if selected.fact is not None:
            state.facts.append(selected.fact)
        if selected.progress is not None:
            state.progress_markers.append(selected.progress)
        return state

    def _rejected_evaluation(self):
        transports = list(self.transport_case.transports)
        artifacts = list(transports[0].artifacts)
        payload = artifacts[5].payload
        artifacts[5] = replace(
            artifacts[5],
            payload=b"X" + payload[1:],
        )
        transports[0] = replace(
            transports[0],
            artifacts=tuple(artifacts),
        )
        return self.transport_case._evaluate(transports=transports)

    def test_confirmed_projection_is_exact_and_authority_narrow(self) -> None:
        projection = self.projection

        self.assertEqual(projection.experiment.status, ExperimentStatus.COMPLETED)
        self.assertIs(projection.experiment.kind, ExperimentKind.PROBE)
        self.assertEqual(len(projection.runs), 3)
        self.assertEqual(len(projection.receipts), 3)
        self.assertEqual(len(projection.artifacts), 24)
        self.assertIsNotNone(projection.fact)
        self.assertIsNotNone(projection.progress)
        self.assertEqual(
            projection.fact.provenance.value,
            "executed",
        )
        authorities = projection.binding["authorities"]
        self.assertTrue(
            authorities["executed_web_impact_fact_authorized"]
        )
        self.assertTrue(authorities["progress_marker_authorized"])
        self.assertFalse(authorities["candidate_authorized"])
        self.assertFalse(authorities["proof_authorized"])
        self.assertFalse(authorities["flag_proven"])
        self.assertFalse(authorities["status_transition_authorized"])
        self.assertFalse(
            authorities["automatic_submission_authorized"]
        )
        self.assertNotIn("candidate", projection.to_dict())
        self.assertNotIn("submission", projection.to_dict())
        validate_web_impact_state_projection(
            projection,
            evaluation=self.evaluation,
            execution_plan=self.execution_plan,
            operator_spec_payload=self.operator_payload,
        )
        validate_web_impact_state_graph(self._state())

    def test_raw_cookie_token_and_body_never_enter_state_documents(
        self,
    ) -> None:
        encoded = self.projection.canonical_bytes

        for raw in (
            COOKIE_VALUE,
            VULNERABLE_BODY,
            CONTROL_BODY,
            b"session=super-secret-token",
            b"Bearer ",
        ):
            self.assertNotIn(raw, encoded)
        for artifact in self.projection.artifacts:
            self.assertEqual(
                artifact.extra["context_visibility"],
                "engine_private",
            )
        self.assertIsNone(self.projection.fact.locator)
        self.assertEqual(
            self.projection.receipts[0].preview,
            "",
        )

        forged = copy.deepcopy(self.projection)
        forged.binding["reduction"]["executed_fact"]["extra"][
            "cookie"
        ] = "session=super-secret-token"
        with self.assertRaises(WebImpactStateContractError):
            validate_web_impact_state_projection(
                forged,
                evaluation=self.evaluation,
                execution_plan=self.execution_plan,
                operator_spec_payload=self.operator_payload,
            )

    def test_rejected_projection_retains_evaluation_without_authority(
        self,
    ) -> None:
        evaluation = self._rejected_evaluation()
        ids = WebImpactStateIds(
            experiment_id="E-web-rejected",
            operator_spec_artifact_id="A-web-rejected-spec",
            plan_artifact_id="A-web-rejected-plan",
            evaluation_artifact_id="A-web-rejected-evaluation",
            fact_id=None,
            progress_id=None,
        )
        projection = self._build(
            evaluation=evaluation,
            ids=ids,
            replay_wall_seconds={},
        )

        self.assertFalse(evaluation.confirmed)
        self.assertEqual(
            projection.experiment.status,
            ExperimentStatus.INCONCLUSIVE,
        )
        self.assertEqual(projection.runs, ())
        self.assertEqual(projection.receipts, ())
        self.assertEqual(len(projection.artifacts), 3)
        self.assertIsNone(projection.fact)
        self.assertIsNone(projection.progress)
        self.assertEqual(
            projection.experiment.evidence_fact_ids,
            [],
        )
        authorities = projection.binding["authorities"]
        self.assertFalse(
            authorities["executed_web_impact_fact_authorized"]
        )
        self.assertFalse(authorities["progress_marker_authorized"])
        validate_web_impact_state_projection(
            projection,
            evaluation=evaluation,
            execution_plan=self.execution_plan,
            operator_spec_payload=self.operator_payload,
        )
        validate_web_impact_state_graph(self._state(projection))

    def test_projection_rejects_authority_widening_and_raw_extra(
        self,
    ) -> None:
        widened = copy.deepcopy(self.projection)
        widened.binding["authorities"]["candidate_authorized"] = True
        with self.assertRaisesRegex(
            WebImpactStateContractError,
            "authority",
        ):
            validate_web_impact_state_projection(
                widened,
                evaluation=self.evaluation,
                execution_plan=self.execution_plan,
                operator_spec_payload=self.operator_payload,
            )

        raw_extra = copy.deepcopy(self.projection)
        raw_extra.experiment.extra["cookie"] = "session=secret"
        with self.assertRaisesRegex(
            WebImpactStateContractError,
            "object_graph_rebound",
        ):
            validate_web_impact_state_projection(
                raw_extra,
                evaluation=self.evaluation,
                execution_plan=self.execution_plan,
                operator_spec_payload=self.operator_payload,
            )

    def test_object_hash_path_status_and_binding_tamper_fail(self) -> None:
        mutations = []

        artifact = copy.deepcopy(self.projection)
        artifact.artifacts[0].sha256 = "0" * 64
        mutations.append(("artifact", artifact))

        run_path = copy.deepcopy(self.projection)
        run_path.runs[0].request_path = "runs/foreign/request.json"
        mutations.append(("run", run_path))

        run_status = copy.deepcopy(self.projection)
        run_status.runs[0].status = RunStatus.FAILED
        mutations.append(("run", run_status))

        receipt = copy.deepcopy(self.projection)
        receipt.receipts[0].outcome = ReceiptOutcome.FAILED
        mutations.append(("receipt", receipt))

        experiment = copy.deepcopy(self.projection)
        experiment.experiment.status = ExperimentStatus.INCONCLUSIVE
        mutations.append(("experiment", experiment))

        fact = copy.deepcopy(self.projection)
        fact.fact.artifact_id = fact.artifacts[0].id
        mutations.append(("fact", fact))

        progress = copy.deepcopy(self.projection)
        progress.progress.artifact_ids.reverse()
        mutations.append(("progress", progress))

        for kind, projection in mutations:
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(
                    WebImpactStateContractError,
                    "object_graph_rebound",
                ):
                    validate_web_impact_state_projection(
                        projection,
                        evaluation=self.evaluation,
                        execution_plan=self.execution_plan,
                        operator_spec_payload=self.operator_payload,
                    )

    def test_state_graph_detects_orphans_and_stripped_objects(self) -> None:
        stripped = self._state()
        stripped.experiments.clear()
        errors = web_impact_state_graph_errors(stripped)
        self.assertTrue(
            any("orphan Web impact run" in item for item in errors)
        )

        missing_artifact = self._state()
        missing_artifact.artifacts.pop()
        errors = web_impact_state_graph_errors(missing_artifact)
        self.assertTrue(
            any(
                "missing_artifact" in item
                or "orphan Web impact" in item
                for item in errors
            )
        )

        missing_fact = self._state()
        missing_fact.facts.clear()
        errors = web_impact_state_graph_errors(missing_fact)
        self.assertTrue(
            any("missing_fact" in item for item in errors)
        )

    def test_duplicate_and_global_identifier_collisions_fail(self) -> None:
        with self.assertRaisesRegex(
            WebImpactStateContractError,
            "global_identifier_collision",
        ):
            self._build(
                existing_global_ids=[self.ids.experiment_id],
            )

        duplicate_ids = replace(
            self.ids,
            fact_id=self.ids.evaluation_artifact_id,
        )
        with self.assertRaisesRegex(
            WebImpactStateContractError,
            "identifier",
        ):
            self._build(ids=duplicate_ids)

        state = self._state()
        state.artifacts.append(
            ArtifactReference(
                id=self.projection.fact.id,
                path="artifacts/other.bin",
                sha256="f" * 64,
            )
        )
        errors = web_impact_state_graph_errors(state)
        self.assertTrue(
            any(
                "duplicated_globally" in item
                for item in errors
            )
        )

    def test_candidate_submission_and_status_authority_markers_fail(
        self,
    ) -> None:
        state = self._state()
        marker = copy.deepcopy(
            self.projection.fact.extra["web_impact_state"]
        )
        state.candidates.append(
            FlagCandidate(
                id="C-web-forged",
                value="FLAG{forged}",
                status=CandidateStatus.OBSERVED_CANDIDATE,
                extra={"web_impact_state": marker},
            )
        )
        errors = web_impact_state_graph_errors(state)
        self.assertTrue(
            any("candidate authority widening" in item for item in errors)
        )

        proof = self._state()
        proof.experiments[0].kind = ExperimentKind.PROOF
        self.assertTrue(web_impact_state_graph_errors(proof))

        status = self._state()
        status.extra["web_impact_state"] = marker
        errors = web_impact_state_graph_errors(status)
        self.assertTrue(
            any("status/state authority widening" in item for item in errors)
        )

    def test_evaluation_plan_and_operator_hash_rebinding_fail(self) -> None:
        forged_evaluation = replace(
            self.evaluation,
            execution_plan_sha256="0" * 64,
        )
        with self.assertRaisesRegex(
            WebImpactStateContractError,
            "evaluation_plan_binding_mismatch",
        ):
            self._build(evaluation=forged_evaluation)

        with self.assertRaisesRegex(
            WebImpactStateContractError,
            "evaluation_plan_binding_mismatch",
        ):
            self._build(
                operator_payload=self.operator_payload + b" ",
            )

    def test_forged_plan_and_semantic_record_never_reach_state(
        self,
    ) -> None:
        requests = list(self.execution_plan.requests)
        requests[0] = replace(requests[0], replay_ordinal=True)
        forged_plan = replace(
            self.execution_plan,
            requests=tuple(requests),
        )
        forged_evaluation = replace(
            self.evaluation,
            execution_plan_sha256=(
                forged_plan.execution_plan_sha256
            ),
        )
        with self.assertRaisesRegex(
            WebImpactStateContractError,
            "execution_plan_not_canonical",
        ):
            self._build(
                evaluation=forged_evaluation,
                execution_plan=forged_plan,
            )

        semantic_records = list(
            self.evaluation.semantic_evaluation.replay_records
        )
        semantic_records[0] = replace(
            semantic_records[0],
            receipt_id="RECEIPT-semantic-rebound",
        )
        semantic = replace(
            self.evaluation.semantic_evaluation,
            replay_records=tuple(semantic_records),
        )
        forged_evaluation = replace(
            self.evaluation,
            semantic_evaluation=semantic,
        )
        with self.assertRaisesRegex(
            WebImpactStateContractError,
            "semantic_evaluation_rebound|semantic_record_rebound",
        ):
            self._build(evaluation=forged_evaluation)

    def test_malformed_capture_role_and_manifest_fail_closed(
        self,
    ) -> None:
        malformed = copy.deepcopy(self.projection)
        malformed.binding["artifacts"][3]["role"] = []
        with self.assertRaises(WebImpactStateContractError):
            validate_web_impact_state_projection(
                malformed,
                evaluation=self.evaluation,
                execution_plan=self.execution_plan,
                operator_spec_payload=self.operator_payload,
            )

        state = self._state()
        binding = state.experiments[0].result[
            "web_impact_state"
        ]["binding"]
        binding["artifacts"][3]["sha256"] = "0" * 64
        binding["records"][0]["capture_artifacts"][0][
            "sha256"
        ] = "0" * 64
        errors = web_impact_state_graph_errors(state)
        self.assertTrue(
            any("capture_manifest_rebound" in item for item in errors)
        )

    def test_invalid_unicode_metadata_fails_as_contract_error(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            WebImpactStateContractError,
            "challenge_identity_invalid",
        ):
            self._build(
                identity=ChallengeIdentity(
                    contest_id="\ud800",
                    category="web",
                    challenge_id="impact-state",
                )
            )

    def test_boolean_never_satisfies_state_integer_fields(self) -> None:
        builder_cases = (
            {"configuration_epoch": True},
            {"base_revision": True},
            {"timeout_seconds": True},
            {
                "replay_wall_seconds": {
                    record.run_id: True
                    for record in self.evaluation.records
                }
            },
        )
        for changes in builder_cases:
            with self.subTest(changes=changes):
                with self.assertRaises(
                    WebImpactStateContractError
                ):
                    self._build(**changes)

        def mutate(path: tuple[object, ...]) -> None:
            projection = copy.deepcopy(self.projection)
            current = projection.binding
            for key in path[:-1]:
                current = current[key]
            current[path[-1]] = True
            with self.assertRaises(WebImpactStateContractError):
                validate_web_impact_state_projection(
                    projection,
                    evaluation=self.evaluation,
                    execution_plan=self.execution_plan,
                    operator_spec_payload=self.operator_payload,
                )

        bool_paths = (
            ("schema_version",),
            ("configuration_epoch",),
            ("base_revision",),
            ("experiment", "timeout_seconds"),
            ("evaluation", "size_bytes"),
            ("plan", "operator_spec_size_bytes"),
            ("plan", "vulnerable_target", "generation"),
            ("records", 0, "execution_record", "replay_ordinal"),
            ("records", 0, "wall_seconds"),
            ("artifacts", 0, "size_bytes"),
        )
        for path in bool_paths:
            with self.subTest(path=path):
                mutate(path)

    def test_state_graph_rejects_boolean_binding_even_if_wrapper_rehashed(
        self,
    ) -> None:
        state = self._state()
        wrapper = state.experiments[0].result["web_impact_state"]
        wrapper["binding"]["configuration_epoch"] = True

        errors = web_impact_state_graph_errors(state)

        self.assertTrue(
            any("state_binding_header_invalid" in item for item in errors)
        )

    def test_ids_and_replay_wall_time_inputs_are_exact(self) -> None:
        duplicate_walls = dict(self.wall_seconds)
        duplicate_walls["RUN-unbound"] = 1.0
        with self.assertRaisesRegex(
            WebImpactStateContractError,
            "replay_wall_seconds_invalid",
        ):
            self._build(replay_wall_seconds=duplicate_walls)

        with self.assertRaisesRegex(
            WebImpactStateContractError,
            "state_identifier_invalid",
        ):
            self._build(
                ids=replace(
                    self.ids,
                    experiment_id="../escape",
                )
            )

    def test_projection_protocol_markers_are_exact_and_raw_free(
        self,
    ) -> None:
        self.assertEqual(
            self.projection.to_dict()["protocol"],
            WEB_IMPACT_STATE_PROTOCOL,
        )
        self.assertEqual(
            self.projection.experiment.extra["engine_executor"],
            WEB_IMPACT_STATE_EXECUTOR,
        )
        for collection in (
            self.projection.runs,
            self.projection.receipts,
            self.projection.artifacts,
            (self.projection.fact,),
            (self.projection.progress,),
        ):
            for record in collection:
                marker = record.extra["web_impact_state"]
                self.assertEqual(
                    marker["protocol"],
                    WEB_IMPACT_STATE_PROTOCOL,
                )
                self.assertEqual(
                    marker["binding_sha256"],
                    self.projection.binding_sha256,
                )


if __name__ == "__main__":
    unittest.main()
