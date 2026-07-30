from __future__ import annotations

import copy
import hashlib
import unittest
from dataclasses import replace

import ctf_os.engine.forensic_assertion_state as state_contract
from ctf_os.engine.forensic_assertion_execution import (
    ForensicCapturedArtifact,
    plan_forensic_assertion_execution,
)
from ctf_os.engine.forensic_assertion_state import (
    FORENSIC_ASSERTION_STATE_PROTOCOL,
    ForensicAssertionStateContractError,
    ForensicAssertionStateIds,
    build_forensic_assertion_state_projection,
    forensic_assertion_state_graph_errors,
    validate_forensic_assertion_state_graph,
    validate_forensic_assertion_state_projection,
)
from ctf_os.models import (
    ArtifactReference,
    ChallengeIdentity,
    ChallengeState,
    ExecutionReceipt,
    Fact,
    FactKind,
    FlagCandidate,
    ProgressMarker,
    Provenance,
    ReceiptOutcome,
    RunOrigin,
    RunReference,
    RunStatus,
    SourceFile,
)
from tests import test_forensic_assertion_execution as execution_support


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


class ForensicAssertionStateTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = execution_support.ForensicAssertionExecutionTests(
            "test_clean_preissued_wave_confirms_only_fact_and_progress"
        )
        fixture.setUp()
        self.fixture = fixture
        self.confirmed = fixture._evaluate()
        first = fixture.transports[0]
        corrupted = replace(
            first,
            artifact=ForensicCapturedArtifact(
                artifact_id=first.artifact.artifact_id,
                path=first.artifact.path,
                payload=first.artifact.payload + b":corrupt",
            ),
        )
        self.rejected = fixture._evaluate(
            transports=(corrupted, *fixture.transports[1:])
        )
        self.identity = ChallengeIdentity(
            contest_id="contest",
            category="forensics",
            challenge_id="challenge",
        )
        self.timestamp = "2026-07-31T00:00:00+00:00"

    def _projection(self, *, confirmed: bool = True):
        evaluation = self.confirmed if confirmed else self.rejected
        suffix = "ok" if confirmed else "bad"
        ids = ForensicAssertionStateIds(
            experiment_id=f"EXP-assert-{suffix}",
            operator_spec_artifact_id=f"ART-operator-{suffix}",
            plan_artifact_id=f"ART-plan-{suffix}",
            evaluation_artifact_id=f"ART-evaluation-{suffix}",
            fact_id=f"FACT-assert-{suffix}" if confirmed else None,
            progress_id=(
                f"PROGRESS-assert-{suffix}" if confirmed else None
            ),
        )
        return build_forensic_assertion_state_projection(
            evaluation,
            self.fixture.execution_plan,
            self.fixture.operator_payload,
            identity=self.identity,
            configuration_epoch=3,
            base_revision=0,
            ids=ids,
            hypothesis_ids=(),
            evaluated_at=self.timestamp,
            timeout_seconds=120,
            run_origin=RunOrigin.MANAGED_TOOL,
            observation_wall_seconds={
                record.run_id: position / 10
                for position, record in enumerate(
                    evaluation.records,
                    start=1,
                )
            },
        )

    def _state(self, projection) -> ChallengeState:
        root = projection.binding["plan"]["index_root"]
        operator = projection.binding["plan"]["operator_spec"]
        state = ChallengeState(
            contest_id=self.identity.contest_id,
            category=self.identity.category,
            challenge_id=self.identity.challenge_id,
            revision=1,
            configuration_epoch=3,
            source_inventory=[
                SourceFile(
                    path=source.path,
                    sha256=source.sha256,
                    size=source.size_bytes,
                )
                for source in self.fixture.sources
            ],
            metadata={
                "source_manifest_sha256": root[
                    "source_manifest_sha256"
                ]
            },
        )
        state.runs.append(
            RunReference(
                id=root["index_run_id"],
                base_revision=0,
                status=RunStatus.COMPLETED,
                role="tool",
                origin=RunOrigin.MANAGED_TOOL,
                configuration_epoch=3,
                created_at=self.timestamp,
            )
        )
        state.receipts.append(
            ExecutionReceipt(
                id=root["index_receipt_id"],
                experiment_id="EXP-index",
                run_id=root["index_run_id"],
                outcome=ReceiptOutcome.SUCCEEDED,
                exit_code=0,
                stdout_artifact_id=root["index_artifact"][
                    "artifact_id"
                ],
                stdout_bytes=root["index_artifact"]["size_bytes"],
                created_at=self.timestamp,
            )
        )
        state.artifacts.append(
            ArtifactReference(
                id=root["index_artifact"]["artifact_id"],
                path="artifacts/index.json",
                sha256=root["index_artifact"]["sha256"],
                source_run_id=root["index_run_id"],
                created_at=self.timestamp,
                media_type="application/json",
                size=root["index_artifact"]["size_bytes"],
            )
        )
        index_binding = {
            "evaluation_sha256": root[
                "index_execution_evaluation_sha256"
            ],
            "receipt_id": root["index_receipt_id"],
            "source_inventory_sha256": root[
                "source_inventory_sha256"
            ],
            "source_manifest_sha256": root[
                "source_manifest_sha256"
            ],
        }
        state.facts.append(
            Fact(
                id="FACT-index-anchor",
                statement="confirmed evidence index",
                provenance=Provenance.EXECUTED,
                kind=FactKind.OBSERVATION,
                challenge_id=state.challenge_id,
                source_run_id=root["index_run_id"],
                artifact_id=root["index_artifact"]["artifact_id"],
                created_at=self.timestamp,
                extra={"forensic_evidence_index": index_binding},
            )
        )
        state.progress_markers.append(
            ProgressMarker(
                id="PROGRESS-index-anchor",
                statement="confirmed evidence index",
                run_id=root["index_run_id"],
                artifact_ids=[root["index_artifact"]["artifact_id"]],
                created_at=self.timestamp,
                extra={"forensic_evidence_index": index_binding},
            )
        )
        for tool in operator["tools"]:
            artifact = tool["readiness_artifact"]
            state.artifacts.append(
                ArtifactReference(
                    id=artifact["artifact_id"],
                    path=(
                        "artifacts/readiness/"
                        f"{artifact['artifact_id']}.json"
                    ),
                    sha256=artifact["sha256"],
                    created_at=self.timestamp,
                    media_type="application/json",
                    size=artifact["size_bytes"],
                )
            )
        state.experiments.append(projection.experiment)
        state.runs.extend(projection.runs)
        state.receipts.extend(projection.receipts)
        state.artifacts.extend(projection.artifacts)
        if projection.fact is not None:
            state.facts.append(projection.fact)
        if projection.progress is not None:
            state.progress_markers.append(projection.progress)
        return state

    def _assert_binding_invalid(self, mutate) -> None:
        projection = self._projection()
        binding = copy.deepcopy(projection.binding)
        mutate(binding)
        with self.assertRaises(ForensicAssertionStateContractError):
            state_contract._validate_binding_document(binding)

    def test_confirmed_projection_is_complete_raw_free_and_narrow(
        self,
    ) -> None:
        projection = self._projection()
        self.assertEqual(
            len(projection.runs),
            len(self.fixture.execution_plan.requests),
        )
        self.assertEqual(len(projection.receipts), len(projection.runs))
        self.assertEqual(
            len(projection.artifacts),
            3 + len(projection.runs) * 3,
        )
        self.assertIsNotNone(projection.fact)
        self.assertIsNotNone(projection.progress)
        encoded = projection.canonical_bytes
        for transport in self.fixture.transports:
            self.assertNotIn(transport.artifact.payload, encoded)
        self.assertNotIn(b"flag{", encoded.lower())
        self.assertFalse(
            projection.binding["authorities"][
                "candidate_authorized"
            ]
        )
        self.assertIsNone(projection.binding["reduction"]["candidate"])
        validate_forensic_assertion_state_projection(
            projection,
            evaluation=self.confirmed,
            execution_plan=self.fixture.execution_plan,
            operator_spec_payload=self.fixture.operator_payload,
        )

    def test_rejected_projection_preissues_all_but_has_no_authority(
        self,
    ) -> None:
        projection = self._projection(confirmed=False)
        self.assertFalse(projection.binding["evaluation"]["confirmed"])
        self.assertEqual(projection.runs, ())
        self.assertEqual(projection.receipts, ())
        self.assertIsNone(projection.fact)
        self.assertIsNone(projection.progress)
        self.assertEqual(
            len(projection.artifacts),
            3 + len(self.fixture.execution_plan.requests),
        )
        self.assertEqual(
            [
                artifact.id
                for artifact in projection.artifacts[3:]
            ],
            [
                request.request_id
                for request in self.fixture.execution_plan.requests
            ],
        )

    def test_existing_id_collision_includes_unmaterialized_preissue(
        self,
    ) -> None:
        request = self.fixture.execution_plan.requests[0]
        with self.assertRaisesRegex(
            ForensicAssertionStateContractError,
            "projection_global_identifier_collision",
        ):
            build_forensic_assertion_state_projection(
                self.rejected,
                self.fixture.execution_plan,
                self.fixture.operator_payload,
                identity=self.identity,
                configuration_epoch=3,
                base_revision=0,
                ids=ForensicAssertionStateIds(
                    "EXP-collision",
                    "ART-op-collision",
                    "ART-plan-collision",
                    "ART-eval-collision",
                    None,
                    None,
                ),
                hypothesis_ids=(),
                evaluated_at=self.timestamp,
                timeout_seconds=120,
                run_origin=RunOrigin.MANAGED_TOOL,
                observation_wall_seconds={},
                existing_global_ids=(request.run_id,),
            )

    def test_bool_integer_and_wall_map_fail_closed(self) -> None:
        common = dict(
            evaluation=self.confirmed,
            execution_plan=self.fixture.execution_plan,
            operator_spec_payload=self.fixture.operator_payload,
            identity=self.identity,
            configuration_epoch=True,
            base_revision=0,
            ids=ForensicAssertionStateIds(
                "EXP-bool",
                "ART-op-bool",
                "ART-plan-bool",
                "ART-eval-bool",
                "FACT-bool",
                "PROGRESS-bool",
            ),
            hypothesis_ids=(),
            evaluated_at=self.timestamp,
            timeout_seconds=120,
            run_origin=RunOrigin.MANAGED_TOOL,
            observation_wall_seconds={
                record.run_id: 0.1 for record in self.confirmed.records
            },
        )
        with self.assertRaises(ForensicAssertionStateContractError):
            build_forensic_assertion_state_projection(**common)
        common["configuration_epoch"] = 3
        common["observation_wall_seconds"] = {
            **common["observation_wall_seconds"],
            "RUN-extra": 0.1,
        }
        with self.assertRaises(ForensicAssertionStateContractError):
            build_forensic_assertion_state_projection(**common)

    def test_binding_rejects_extra_keys_and_raw_value_injection(
        self,
    ) -> None:
        self._assert_binding_invalid(
            lambda binding: binding.__setitem__(
                "raw_output",
                "flag{not-allowed}",
            )
        )
        self._assert_binding_invalid(
            lambda binding: binding["records"][0][
                "execution_record"
            ].__setitem__("raw_claim", "secret")
        )

    def test_binding_rejects_reorder_hash_and_corroboration_tamper(
        self,
    ) -> None:
        self._assert_binding_invalid(
            lambda binding: binding["preissued_requests"].reverse()
        )
        self._assert_binding_invalid(
            lambda binding: binding["records"][0][
                "execution_record"
            ]["artifact"].__setitem__("sha256", "0" * 64)
        )
        self._assert_binding_invalid(
            lambda binding: binding["corroboration"][0].__setitem__(
                "covered",
                False,
            )
        )

    def test_binding_recomputes_registry_graph_and_execution_plan(
        self,
    ) -> None:
        self._assert_binding_invalid(
            lambda binding: binding["plan"].__setitem__(
                "readiness_registry_sha256",
                "1" * 64,
            )
        )
        self._assert_binding_invalid(
            lambda binding: binding["plan"].__setitem__(
                "assertion_graph_plan_sha256",
                "2" * 64,
            )
        )
        self._assert_binding_invalid(
            lambda binding: binding["plan"].__setitem__(
                "execution_plan_sha256",
                "3" * 64,
            )
        )

    def test_legitimate_unsorted_operator_pointer_input_is_normalized(
        self,
    ) -> None:
        document = copy.deepcopy(self.fixture.operator_document)
        document["pointers"].reverse()
        payload = execution_support._canonical(document)
        specification = self.fixture._parse(payload)
        plan = plan_forensic_assertion_execution(
            specification,
            self.fixture.issues,
        )
        original_plan = self.fixture.execution_plan
        original_transports = self.fixture.transports
        try:
            self.fixture.execution_plan = plan
            self.fixture.transports = self.fixture._transports()
            evaluation = self.fixture._evaluate(
                operator_spec_payload=payload,
            )
        finally:
            self.fixture.execution_plan = original_plan
            self.fixture.transports = original_transports
        self.assertTrue(evaluation.confirmed)
        projection = build_forensic_assertion_state_projection(
            evaluation,
            plan,
            payload,
            identity=self.identity,
            configuration_epoch=3,
            base_revision=0,
            ids=ForensicAssertionStateIds(
                "EXP-unsorted",
                "ART-op-unsorted",
                "ART-plan-unsorted",
                "ART-eval-unsorted",
                "FACT-unsorted",
                "PROGRESS-unsorted",
            ),
            hypothesis_ids=(),
            evaluated_at=self.timestamp,
            timeout_seconds=120,
            run_origin=RunOrigin.MANAGED_TOOL,
            observation_wall_seconds={
                record.run_id: 0.1 for record in evaluation.records
            },
        )
        self.assertTrue(projection.binding["evaluation"]["confirmed"])

    def test_binding_rejects_raw_statement_and_authority_widening(
        self,
    ) -> None:
        self._assert_binding_invalid(
            lambda binding: binding["reduction"][
                "executed_fact"
            ].__setitem__("statement", "raw evidence value")
        )
        self._assert_binding_invalid(
            lambda binding: binding["authorities"].__setitem__(
                "candidate_authorized",
                True,
            )
        )
        self._assert_binding_invalid(
            lambda binding: binding["reduction"].__setitem__(
                "status_transition",
                "solved",
            )
        )

    def test_complete_confirmed_and_rejected_state_graphs_validate(
        self,
    ) -> None:
        for projection in (
            self._projection(),
            self._projection(confirmed=False),
        ):
            state = self._state(projection)
            self.assertEqual(
                forensic_assertion_state_graph_errors(state),
                [],
            )
            validate_forensic_assertion_state_graph(state)

    def test_state_graph_requires_current_index_and_readiness_anchors(
        self,
    ) -> None:
        state = self._state(self._projection())
        state.metadata["source_manifest_sha256"] = "0" * 64
        self.assertTrue(forensic_assertion_state_graph_errors(state))

        state = self._state(self._projection())
        state.facts = [
            fact
            for fact in state.facts
            if "forensic_evidence_index" not in fact.extra
        ]
        self.assertTrue(forensic_assertion_state_graph_errors(state))

        state = self._state(self._projection())
        readiness_id = self.fixture.readiness[0].readiness_artifact_id
        state.artifacts = [
            artifact
            for artifact in state.artifacts
            if artifact.id != readiness_id
        ]
        self.assertTrue(forensic_assertion_state_graph_errors(state))

    def test_state_graph_binds_current_sources_and_exact_pointers(
        self,
    ) -> None:
        state = self._state(self._projection())
        state.source_inventory[0].sha256 = _digest("stale")
        self.assertTrue(forensic_assertion_state_graph_errors(state))

        state = self._state(self._projection())
        state.source_inventory[0].size = 1
        self.assertTrue(forensic_assertion_state_graph_errors(state))

    def test_state_graph_detects_rebound_and_global_collision(
        self,
    ) -> None:
        state = self._state(self._projection())
        assertion_run = next(
            run
            for run in state.runs
            if "forensic_assertion_state" in run.extra
        )
        assertion_run.role = "rebound"
        self.assertTrue(forensic_assertion_state_graph_errors(state))

        state = self._state(self._projection())
        state.artifacts[0].id = state.experiments[-1].id
        self.assertTrue(forensic_assertion_state_graph_errors(state))

    def test_rejected_reserved_identifier_cannot_be_claimed_later(
        self,
    ) -> None:
        projection = self._projection(confirmed=False)
        state = self._state(projection)
        reserved = self.fixture.execution_plan.requests[0].run_id
        state.runs.append(
            RunReference(
                id=reserved,
                base_revision=0,
                status=RunStatus.CREATED,
            )
        )
        self.assertTrue(forensic_assertion_state_graph_errors(state))

    def test_orphan_marker_candidate_and_status_widening_are_rejected(
        self,
    ) -> None:
        state = self._state(self._projection())
        state.artifacts.append(
            ArtifactReference(
                id="ART-orphan-marker",
                path="artifacts/orphan.json",
                sha256=_digest("orphan"),
                extra={
                    "forensic_assertion_state": {
                        "protocol": FORENSIC_ASSERTION_STATE_PROTOCOL
                    }
                },
            )
        )
        self.assertTrue(forensic_assertion_state_graph_errors(state))

        state = self._state(self._projection())
        state.candidates.append(
            FlagCandidate(
                id="CAND-forbidden",
                value="flag{candidate-only}",
                extra={"protocol": FORENSIC_ASSERTION_STATE_PROTOCOL},
            )
        )
        self.assertTrue(forensic_assertion_state_graph_errors(state))

        state = self._state(self._projection())
        state.extra["forensic_assertion_state"] = {"status": "solved"}
        self.assertTrue(forensic_assertion_state_graph_errors(state))

    def test_projection_object_mutation_is_not_accepted(self) -> None:
        projection = self._projection()
        projection.experiment.command = "rebound"
        with self.assertRaisesRegex(
            ForensicAssertionStateContractError,
            "projection_object_graph_rebound",
        ):
            validate_forensic_assertion_state_projection(
                projection,
                evaluation=self.confirmed,
                execution_plan=self.fixture.execution_plan,
                operator_spec_payload=self.fixture.operator_payload,
            )

    def test_wrong_input_types_and_duplicate_existing_ids_fail(self) -> None:
        with self.assertRaises(ForensicAssertionStateContractError):
            state_contract._validate_binding_document([])
        with self.assertRaises(ForensicAssertionStateContractError):
            state_contract._reserved_ids(("A", "A"))
        self.assertTrue(
            forensic_assertion_state_graph_errors(object())
        )


if __name__ == "__main__":
    unittest.main()
