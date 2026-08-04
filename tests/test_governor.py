from __future__ import annotations

import unittest

from ctf_os.governor import (
    GOVERNOR_METADATA_KEY,
    GovernorPolicy,
    RecoveryAction,
    StallSignal,
    choose_recovery_action,
    evaluate_stall,
)
from ctf_os.models import (
    ArtifactReference,
    ChallengeIdentity,
    ChallengeStatus,
    Experiment,
    ExperimentStatus,
    Fact,
    ProgressMarker,
    Provenance,
    RunReference,
    RunStatus,
    new_challenge_state,
)


class GovernorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = new_challenge_state(
            ChallengeIdentity("Korea CTF", "misc", "governor")
        )
        self.state.status = ChallengeStatus.ACTIVE

    def _experiment(
        self,
        number: int,
        command: str,
        *,
        failure_label: str | None = None,
    ) -> Experiment:
        return Experiment(
            id=f"E-{number}",
            hypothesis_ids=[],
            command=command,
            expected_observation="bounded observation",
            keep_if="new evidence",
            drop_if="no evidence",
            timeout_seconds=30,
            status=ExperimentStatus.FAILED,
            extra=(
                {"failure_label": failure_label}
                if failure_label is not None
                else {}
            ),
        )

    def _run(
        self,
        number: int,
        *,
        failure_label: str | None = None,
    ) -> RunReference:
        return RunReference(
            id=f"R-{number}",
            base_revision=number,
            status=RunStatus.FAILED,
            role="tool",
            extra=(
                {"failure_label": failure_label}
                if failure_label is not None
                else {}
            ),
        )

    def _fact_for(self, run: RunReference) -> None:
        self.state.facts.append(
            Fact(
                id=f"F-{run.id}",
                statement=f"evidence for {run.id}",
                provenance=Provenance.EXECUTED,
                challenge_id=self.state.challenge_id,
                source_run_id=run.id,
            )
        )

    def test_default_last_three_repeated_commands_stall(self) -> None:
        self.state.experiments.extend(
            self._experiment(number, "python3 solve.py")
            for number in range(1, 4)
        )

        decision = evaluate_stall(self.state)

        self.assertTrue(decision.stalled)
        self.assertEqual(
            decision.signals,
            (StallSignal.REPEATED_COMMAND,),
        )
        self.assertEqual(
            decision.recovery_action,
            RecoveryAction.CHANGE_OBSERVATION_LAYER,
        )
        self.assertEqual(decision.repeated_command, "python3 solve.py")

    def test_recent_different_command_breaks_old_repetition(self) -> None:
        self.state.experiments.extend(
            [
                self._experiment(1, "python3 solve.py"),
                self._experiment(2, "python3 solve.py"),
                self._experiment(3, "python3 solve.py"),
                self._experiment(4, "objdump -d challenge"),
            ]
        )

        decision = evaluate_stall(self.state)

        self.assertFalse(decision.stalled)
        self.assertIsNone(decision.recovery_action)

    def test_repeated_failure_labels_are_case_normalized(self) -> None:
        for number, label in enumerate(
            ("Wrong_Tool", "wrong_tool", "WRONG_TOOL"),
            start=1,
        ):
            run = self._run(number, failure_label=label)
            self.state.runs.append(run)
            self._fact_for(run)

        decision = evaluate_stall(self.state)

        self.assertEqual(
            decision.signals,
            (StallSignal.REPEATED_FAILURE_LABEL,),
        )
        self.assertEqual(decision.repeated_failure_label, "wrong_tool")

    def test_recent_unlabeled_successes_break_old_failure_repetition(
        self,
    ) -> None:
        for number in range(1, 4):
            run = self._run(
                number,
                failure_label="challenge_budget_expired",
            )
            self.state.runs.append(run)
            self._fact_for(run)
        for number in range(4, 7):
            run = self._run(number)
            run.status = RunStatus.COMPLETED
            self.state.runs.append(run)
            self._fact_for(run)

        decision = evaluate_stall(self.state)

        self.assertFalse(decision.stalled)
        self.assertNotIn(
            StallSignal.REPEATED_FAILURE_LABEL,
            decision.signals,
        )
        self.assertIsNone(decision.repeated_failure_label)
        self.assertEqual(
            decision.inspected_run_ids,
            ("R-4", "R-5", "R-6"),
        )

    def test_known_evaluation_reason_can_supply_failure_label(self) -> None:
        self.state.metadata["failure_labels"] = ["wrong_tool"]
        for number in range(1, 4):
            experiment = self._experiment(number, f"probe-{number}")
            experiment.evaluation_reason = "wrong_tool"
            self.state.experiments.append(experiment)

        decision = evaluate_stall(self.state)

        self.assertEqual(
            decision.signals,
            (StallSignal.REPEATED_FAILURE_LABEL,),
        )

    def test_repeated_free_form_reason_is_not_a_failure_label(self) -> None:
        for number in range(1, 4):
            experiment = self._experiment(number, f"probe-{number}")
            experiment.evaluation_reason = "the output was not useful"
            self.state.experiments.append(experiment)

        decision = evaluate_stall(self.state)

        self.assertFalse(decision.stalled)

    def test_three_runs_without_fact_artifact_or_progress_stall(self) -> None:
        self.state.runs.extend(self._run(number) for number in range(1, 4))

        decision = evaluate_stall(self.state)

        self.assertEqual(
            decision.signals,
            (StallSignal.NO_NEW_EVIDENCE,),
        )
        self.assertEqual(decision.inspected_run_ids, ("R-1", "R-2", "R-3"))

    def test_any_linked_progress_breaks_no_evidence_window(self) -> None:
        self.state.runs.extend(self._run(number) for number in range(1, 4))
        self.state.progress_markers.append(
            ProgressMarker(
                id="PM-3",
                statement="new primitive",
                run_id="R-3",
            )
        )

        decision = evaluate_stall(self.state)

        self.assertNotIn(StallSignal.NO_NEW_EVIDENCE, decision.signals)
        self.assertFalse(decision.stalled)

    def test_same_locator_with_changing_digest_is_artifact_churn(self) -> None:
        for number, digest_character in enumerate(("a", "b", "a"), start=1):
            run = self._run(number)
            self.state.runs.append(run)
            self.state.artifacts.append(
                ArtifactReference(
                    id=f"A-{number}",
                    path=f"artifacts/snapshots/A-{number}.bin",
                    sha256=digest_character * 64,
                    source_run_id=run.id,
                    extra={"reported_locator": "solve.py"},
                )
            )

        decision = evaluate_stall(self.state)

        self.assertEqual(
            decision.signals,
            (StallSignal.ARTIFACT_CHURN,),
        )
        self.assertEqual(decision.artifact_locator, "solve.py")

    def test_same_locator_with_same_digest_is_not_churn(self) -> None:
        for number in range(1, 4):
            run = self._run(number)
            self.state.runs.append(run)
            self.state.artifacts.append(
                ArtifactReference(
                    id=f"A-{number}",
                    path=f"artifacts/snapshots/A-{number}.bin",
                    sha256="a" * 64,
                    source_run_id=run.id,
                    extra={"reported_locator": "solve.py"},
                )
            )

        decision = evaluate_stall(self.state)

        self.assertNotIn(StallSignal.ARTIFACT_CHURN, decision.signals)
        self.assertFalse(decision.stalled)

    def test_run_local_source_locator_does_not_merge_distinct_snapshots(
        self,
    ) -> None:
        source_locator = ".ctf/runs/run-00000001/stdout.log"
        for number, (digest_character, size) in enumerate(
            (("a", 11), ("b", 22), ("c", 33)),
            start=1,
        ):
            run = self._run(number)
            self.state.runs.append(run)
            self.state.artifacts.append(
                ArtifactReference(
                    id=f"A-{run.id}-stdout",
                    path=(
                        "artifacts/snapshots/"
                        f"A-{run.id}-stdout.log"
                    ),
                    sha256=digest_character * 64,
                    source_run_id=run.id,
                    size=size,
                    extra={
                        "source_locator": source_locator,
                        "stream": "stdout",
                    },
                )
            )

        decision = evaluate_stall(self.state)

        self.assertNotIn(StallSignal.ARTIFACT_CHURN, decision.signals)
        self.assertFalse(decision.stalled)

    def test_multiple_signals_still_choose_exactly_one_action(self) -> None:
        for number in range(1, 4):
            self.state.experiments.append(
                self._experiment(
                    number,
                    "python3 solve.py",
                    failure_label="wrong_tool",
                )
            )
            self.state.runs.append(
                self._run(number, failure_label="wrong_tool")
            )

        decision = evaluate_stall(
            self.state,
            policy=GovernorPolicy(signal_threshold=2),
        )
        metadata = decision.to_metadata()

        self.assertTrue(decision.stalled)
        self.assertGreaterEqual(len(decision.signals), 2)
        self.assertIsInstance(decision.recovery_action, RecoveryAction)
        self.assertIsInstance(metadata["recovery_action"], str)

    def test_recovery_ladder_escalates_without_running_any_action(self) -> None:
        attempted = [
            RecoveryAction.CHANGE_OBSERVATION_LAYER,
            RecoveryAction.INDEPENDENT_FALSIFIER,
            RecoveryAction.RECLASSIFY,
        ]
        self.assertEqual(
            choose_recovery_action(attempted),
            RecoveryAction.PRIMARY_KNOWLEDGE,
        )
        attempted.append(RecoveryAction.PRIMARY_KNOWLEDGE)
        self.assertEqual(
            choose_recovery_action(attempted),
            RecoveryAction.NEEDS_HUMAN,
        )

    def test_state_metadata_drives_next_single_recovery_action(self) -> None:
        self.state.experiments.extend(
            self._experiment(number, "python3 solve.py")
            for number in range(1, 4)
        )
        self.state.metadata[GOVERNOR_METADATA_KEY] = {
            "attempted_recovery_actions": [
                RecoveryAction.CHANGE_OBSERVATION_LAYER.value,
                RecoveryAction.INDEPENDENT_FALSIFIER.value,
                RecoveryAction.RECLASSIFY.value,
            ]
        }

        decision = evaluate_stall(self.state)
        metadata = decision.to_metadata(
            attempted_actions=self.state.metadata[
                GOVERNOR_METADATA_KEY
            ]["attempted_recovery_actions"]
        )

        self.assertEqual(
            decision.recovery_action,
            RecoveryAction.PRIMARY_KNOWLEDGE,
        )
        self.assertEqual(
            metadata["recovery_action"],
            RecoveryAction.PRIMARY_KNOWLEDGE.value,
        )
        self.assertEqual(
            metadata["attempted_recovery_actions"],
            [
                RecoveryAction.CHANGE_OBSERVATION_LAYER.value,
                RecoveryAction.INDEPENDENT_FALSIFIER.value,
                RecoveryAction.RECLASSIFY.value,
            ],
        )

    def test_recorded_suggestion_is_not_treated_as_attempted(self) -> None:
        self.state.experiments.extend(
            self._experiment(number, "python3 solve.py")
            for number in range(1, 4)
        )
        first = evaluate_stall(self.state)
        self.state.metadata[GOVERNOR_METADATA_KEY] = first.to_metadata()

        second = evaluate_stall(self.state)

        self.assertEqual(
            second.recovery_action,
            RecoveryAction.CHANGE_OBSERVATION_LAYER,
        )
        self.assertEqual(
            self.state.metadata[GOVERNOR_METADATA_KEY][
                "attempted_recovery_actions"
            ],
            [],
        )

    def test_policy_rejects_unbounded_or_unsafe_values(self) -> None:
        for kwargs in (
            {"history_window": 1},
            {"history_window": 65},
            {"signal_threshold": 0},
            {"signal_threshold": 5},
            {"history_window": 4, "max_records": 3},
            {"max_records": 4097},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                GovernorPolicy(**kwargs)

    def test_oversized_command_is_not_compared(self) -> None:
        oversized = "x" * (64 * 1024 + 1)
        self.state.experiments.extend(
            self._experiment(number, oversized)
            for number in range(1, 4)
        )

        decision = evaluate_stall(self.state)

        self.assertFalse(decision.stalled)


if __name__ == "__main__":
    unittest.main()
