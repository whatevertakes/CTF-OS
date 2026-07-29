from __future__ import annotations

import unittest
from unittest import mock

from ctf_os.models import (
    MAX_RECORDS_PER_COLLECTION,
    MAX_REPEATED_FIELD_ITEMS,
    ArtifactReference,
    ChallengeIdentity,
    ChallengeStatus,
    Experiment,
    ExperimentStatus,
    Fact,
    Falsifier,
    FlagCandidate,
    Goal,
    Hypothesis,
    HypothesisStatus,
    MAX_EXPERIMENT_TIMEOUT_SECONDS,
    ModelValidationError,
    Provenance,
    RunReference,
    RunStatus,
    new_challenge_state,
)
from ctf_os.store.upgrades import upgrade_state


class ModelTests(unittest.TestCase):
    def test_experiment_timeout_requires_a_positive_integer(self) -> None:
        for timeout in (
            True,
            0,
            -1,
            1.0,
            float("nan"),
            float("inf"),
            float("-inf"),
            "1",
            MAX_EXPERIMENT_TIMEOUT_SECONDS + 1,
            604_801,
        ):
            state = new_challenge_state(
                ChallengeIdentity("Demo", "rev", "Timeout")
            )
            state.experiments.append(
                Experiment(
                    id="E-timeout",
                    hypothesis_ids=[],
                    command="true",
                    expected_observation="bounded output",
                    keep_if="the output appears",
                    drop_if="the output does not appear",
                    timeout_seconds=timeout,  # type: ignore[arg-type]
                )
            )
            with (
                self.subTest(timeout=timeout),
                self.assertRaisesRegex(
                    ModelValidationError,
                    "not fully pre-registered",
                ),
            ):
                state.validate()
            serialized = state.to_dict()
            restored = type(state).from_dict(serialized)
            with (
                self.subTest(serialized_timeout=timeout),
                self.assertRaisesRegex(
                    ModelValidationError,
                    "not fully pre-registered",
                ),
            ):
                restored.validate()

        for timeout in (1, MAX_EXPERIMENT_TIMEOUT_SECONDS):
            state = new_challenge_state(
                ChallengeIdentity(
                    "Demo",
                    "rev",
                    f"Valid timeout {timeout}",
                )
            )
            state.experiments.append(
                Experiment(
                    id="E-timeout",
                    hypothesis_ids=[],
                    command="true",
                    expected_observation="bounded output",
                    keep_if="the output appears",
                    drop_if="the output does not appear",
                    timeout_seconds=timeout,
                )
            )
            with self.subTest(valid_timeout=timeout):
                state.validate()

    def test_repeated_record_and_typed_fields_are_bounded_before_copy(
        self,
    ) -> None:
        self.assertEqual(MAX_RECORDS_PER_COLLECTION, 16_384)
        self.assertEqual(MAX_REPEATED_FIELD_ITEMS, 16_384)
        identity = ChallengeIdentity("Demo", "web", "Bounded")
        payload = new_challenge_state(identity).to_dict()
        valid_facts = [
            {
                "id": f"F-{index}",
                "statement": "bounded",
                "provenance": "model_claimed",
            }
            for index in range(2)
        ]
        with mock.patch(
            "ctf_os.models.MAX_RECORDS_PER_COLLECTION",
            2,
        ):
            payload["facts"] = valid_facts
            state = new_challenge_state(identity).from_dict(payload)
            self.assertEqual(len(state.facts), 2)
            payload["facts"] = [*valid_facts, valid_facts[0]]
            with self.assertRaisesRegex(
                ModelValidationError,
                "record collection exceeds 2",
            ):
                new_challenge_state(identity).from_dict(payload)
            payload["facts"] = {
                f"F-{index}": {
                    "statement": "bounded",
                    "provenance": "model_claimed",
                }
                for index in range(3)
            }
            with self.assertRaisesRegex(
                ModelValidationError,
                "record collection exceeds 2",
            ):
                new_challenge_state(identity).from_dict(payload)

        with mock.patch(
            "ctf_os.models.MAX_REPEATED_FIELD_ITEMS",
            2,
        ):
            with self.assertRaisesRegex(
                ModelValidationError,
                "fact supports exceeds 2",
            ):
                Fact.from_dict(
                    {
                        "id": "F-over",
                        "statement": "bounded",
                        "provenance": "model_claimed",
                        "supports": ["H-1", "H-1", "H-1"],
                    }
                )
            with self.assertRaisesRegex(
                ModelValidationError,
                "fact supports must be an array",
            ):
                Fact.from_dict(
                    {
                        "id": "F-string",
                        "statement": "bounded",
                        "provenance": "model_claimed",
                        "supports": "H-1",
                    }
                )
            with self.assertRaisesRegex(
                ModelValidationError,
                "goal artifact_ids exceeds 2",
            ):
                Goal.from_dict(
                    {
                        "id": "G-over",
                        "description": "bounded",
                        "artifact_ids": ["A-1", "A-2"],
                        "artifact": "A-3",
                    }
                )
            state = new_challenge_state(identity)
            state.facts.append(
                Fact(
                    id="F-memory",
                    statement="bounded",
                    provenance=Provenance.MODEL_CLAIMED,
                    supports=["H-1", "H-1", "H-1"],
                )
            )
            with self.assertRaisesRegex(
                ModelValidationError,
                "fact F-memory supports exceeds 2",
            ):
                state.validate()

    def test_provenance_uses_canonical_09_values_and_reads_legacy_values(
        self,
    ) -> None:
        fact = Fact.from_dict(
            {
                "id": "F-1",
                "claim": "decompiler reconstructed a branch",
                "confidence": "tool-inferred",
            },
            default_challenge_id="warmup",
        )

        self.assertIs(fact.provenance, Provenance.TOOL_INFERRED)
        self.assertEqual(fact.to_dict()["provenance"], "tool_inferred")
        self.assertEqual(
            {item.value for item in Provenance},
            {
                "executed",
                "tool_inferred",
                "model_claimed",
                "external_doc",
                "operator",
            },
        )

    def test_legacy_state_is_upgraded_without_losing_unknown_fields(self) -> None:
        upgraded = upgrade_state(
            {
                "identity": {
                    "contest_id": "Demo",
                    "category": "rev",
                    "challenge_id": "Warmup",
                },
                "revision": 2,
                "facts": [
                    {
                        "id": "F-1",
                        "claim": "claim",
                        "confidence": "model-claimed",
                    }
                ],
                "vendor_extension": {"kept": True},
            }
        )

        state = new_challenge_state(
            ChallengeIdentity("unused", "unused", "unused")
        ).from_dict(upgraded)
        round_trip = state.to_dict()
        self.assertEqual(round_trip["schema_version"], 1)
        self.assertEqual(round_trip["contest_id"], "Demo")
        self.assertEqual(
            round_trip["facts"][0]["provenance"], "model_claimed"
        )
        self.assertEqual(round_trip["vendor_extension"], {"kept": True})

    def test_legacy_paused_alias_preserves_exact_resume_target(self) -> None:
        identity = ChallengeIdentity("Demo", "misc", "Paused")
        payload = new_challenge_state(identity).to_dict()
        payload.update(
            {
                "schema_version": 0,
                "status": "PAUSED",
                "paused_from_status": "NEW",
            }
        )
        payload.pop("resume_status", None)

        state = new_challenge_state(identity).from_dict(
            upgrade_state(payload)
        )

        self.assertIs(state.status, ChallengeStatus.PAUSED)
        self.assertIs(state.resume_status, ChallengeStatus.NEW)

    def test_candidate_values_use_the_canonical_printable_bounds(self) -> None:
        identity = ChallengeIdentity("Demo", "misc", "Candidate bounds")
        invalid_values = (
            "KCTF{line\nbreak}",
            "KCTF{zero\u200bwidth}",
            "K" * 1025,
        )

        for value in invalid_values:
            with self.subTest(value=ascii(value[:32])):
                state = new_challenge_state(identity)
                state.candidates.append(
                    FlagCandidate(id="C-invalid", value=value)
                )
                with self.assertRaises(ModelValidationError):
                    state.validate()

    def test_legacy_candidate_alias_cannot_bypass_canonical_validation(
        self,
    ) -> None:
        identity = ChallengeIdentity("Demo", "misc", "Legacy candidate")
        payload = new_challenge_state(identity).to_dict()
        payload["schema_version"] = 0
        payload["flag_candidates"] = [
            {
                "id": "C-legacy-invalid",
                "flag": "KCTF{legacy\ncontext-injection}",
            }
        ]
        payload.pop("candidates", None)

        state = new_challenge_state(identity).from_dict(
            upgrade_state(payload)
        )
        with self.assertRaises(ModelValidationError):
            state.validate()

    def test_model_claim_alone_cannot_confirm_hypothesis(self) -> None:
        state = new_challenge_state(
            ChallengeIdentity("Demo", "crypto", "Oracle")
        )
        state.facts.append(
            Fact(
                id="F-1",
                challenge_id="Oracle",
                statement="the model guessed AES",
                provenance=Provenance.MODEL_CLAIMED,
            )
        )
        state.hypotheses.append(
            Hypothesis(
                id="H-1",
                statement="the primitive is AES",
                falsifier=Falsifier("known-answer test differs"),
                status=HypothesisStatus.CONFIRMED,
                evidence_fact_ids=["F-1"],
            )
        )

        with self.assertRaisesRegex(
            ModelValidationError, "cannot be confirmed"
        ):
            state.validate()

        state.facts.append(
            Fact(
                id="F-2",
                challenge_id="Oracle",
                statement="known-answer test matches",
                provenance=Provenance.EXECUTED,
                source_run_id="R-1",
                artifact_id="A-1",
            )
        )
        state.runs.append(
            RunReference(
                id="R-1",
                base_revision=0,
                status=RunStatus.COMPLETED,
            )
        )
        state.artifacts.append(
            ArtifactReference(
                id="A-1",
                path="artifacts/known-answer.txt",
                sha256="a" * 64,
                source_run_id="R-1",
            )
        )
        state.hypotheses[0].evidence_fact_ids.append("F-2")
        state.hypotheses[0].evidence_artifact_ids.append("A-1")
        state.hypotheses[0].evidence_run_ids.append("R-1")
        state.validate()

    def test_evaluated_experiment_requires_its_own_result_run_chain(
        self,
    ) -> None:
        state = new_challenge_state(
            ChallengeIdentity("Demo", "rev", "OwnRun")
        )
        for run_id in ("R-old", "R-target"):
            state.runs.append(
                RunReference(
                    id=run_id,
                    base_revision=0,
                    status=RunStatus.COMPLETED,
                )
            )
        state.artifacts.append(
            ArtifactReference(
                id="A-old",
                path="artifacts/old.log",
                sha256="a" * 64,
                source_run_id="R-old",
            )
        )
        state.facts.append(
            Fact(
                id="F-old",
                statement="unrelated executed result",
                provenance=Provenance.EXECUTED,
                source_run_id="R-old",
                artifact_id="A-old",
            )
        )
        state.experiments.append(
            Experiment(
                id="E-target",
                hypothesis_ids=[],
                command="true",
                expected_observation="target output",
                keep_if="target succeeds",
                drop_if="target fails",
                timeout_seconds=10,
                status=ExperimentStatus.KEPT,
                result={"run_id": "R-target"},
                artifact_ids=["A-old"],
                evidence_fact_ids=["F-old"],
                evidence_run_ids=["R-old"],
                evaluation_reason="incorrect cross-run evidence",
                evaluated_at="2026-01-01T00:00:00Z",
            )
        )

        with self.assertRaisesRegex(
            ModelValidationError,
            "own result run",
        ):
            state.validate()

    def test_executed_fact_requires_terminal_same_run_artifact(
        self,
    ) -> None:
        identity = ChallengeIdentity("Demo", "rev", "Executed evidence")
        state = new_challenge_state(identity)
        state.runs.extend(
            (
                RunReference(
                    id="R-source",
                    base_revision=0,
                    status=RunStatus.COMPLETED,
                ),
                RunReference(
                    id="R-other",
                    base_revision=0,
                    status=RunStatus.COMPLETED,
                ),
            )
        )
        state.artifacts.append(
            ArtifactReference(
                id="A-other",
                path="artifacts/other.log",
                sha256="a" * 64,
                source_run_id="R-other",
            )
        )
        state.facts.append(
            Fact(
                id="F-executed",
                statement="claimed executed evidence",
                provenance=Provenance.EXECUTED,
                source_run_id="R-source",
            )
        )
        with self.assertRaisesRegex(
            ModelValidationError,
            "requires an artifact",
        ):
            state.validate()

        state.facts[0].artifact_id = "A-other"
        with self.assertRaisesRegex(
            ModelValidationError,
            "artifact/run mismatch",
        ):
            state.validate()

        state.artifacts[0].source_run_id = "R-source"
        state.runs[0].status = RunStatus.RUNNING
        with self.assertRaisesRegex(
            ModelValidationError,
            "requires a terminal run",
        ):
            state.validate()

    def test_identity_includes_category(self) -> None:
        web = ChallengeIdentity("Demo", "web", "Warmup")
        rev = ChallengeIdentity("Demo", "rev", "Warmup")
        self.assertNotEqual(web, rev)
        self.assertEqual(web.key, "web/Warmup")

    def test_paused_state_preserves_an_explicit_resume_target(self) -> None:
        state = new_challenge_state(
            ChallengeIdentity("Demo", "web", "Warmup")
        )
        state.resume_status = state.status
        state.status = ChallengeStatus.PAUSED
        state.validate()

        loaded = state.from_dict(state.to_dict())
        self.assertEqual(loaded.resume_status, ChallengeStatus.NEW)

        loaded.resume_status = None
        with self.assertRaisesRegex(
            ModelValidationError, "requires resume_status"
        ):
            loaded.validate()

        for terminal in (
            ChallengeStatus.SOLVED,
            ChallengeStatus.ABANDONED,
        ):
            with self.subTest(terminal=terminal.value):
                loaded.resume_status = terminal
                with self.assertRaisesRegex(
                    ModelValidationError,
                    "terminal status",
                ):
                    loaded.validate()


if __name__ == "__main__":
    unittest.main()
