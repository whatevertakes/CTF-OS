from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ctf_os.engine.checkpoint_projection import (
    CHECKPOINT_ACTION_PROJECTION_KEY,
    checkpoint_action_reference,
)
from ctf_os.engine.challenge import EngineError
from ctf_os.lifecycle import create_checkpoint, pause_with_handoff
from ctf_os.models import (
    ArtifactReference,
    ChallengeState,
    ChallengeStatus,
    Checkpoint,
    Experiment,
    ExperimentKind,
    ExperimentStatus,
    Fact,
    Falsifier,
    Hypothesis,
    HypothesisStatus,
    Provenance,
    RunReference,
    RunStatus,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.store.atomic import canonical_json_record
from ctf_os.store.atomic import read_json


class _MemoryStore:
    def __init__(self, state: ChallengeState, root: Path | None = None) -> None:
        self.state = state
        self.root = root

    def load(self, identity):
        self.assert_identity(identity)
        return self.state

    def update(self, identity, mutator, *, expected_revision):
        self.assert_identity(identity)
        if expected_revision != self.state.revision:
            raise AssertionError("unexpected revision")
        mutator(self.state)
        self.state.revision += 1
        self.state.validate()
        return self.state

    def assert_identity(self, identity) -> None:
        if identity != self.state.identity:
            raise AssertionError("unexpected challenge identity")

    def challenge_paths(self, identity):
        self.assert_identity(identity)
        if self.root is None:
            raise AssertionError("test store has no filesystem root")
        return SimpleNamespace(state=self.root / "state.json")


class _MemoryEngine:
    def __init__(
        self,
        state: ChallengeState,
        root: Path | None = None,
    ) -> None:
        self.store = _MemoryStore(state, root)

    def pause(self, identity):
        current = self.store.load(identity)

        def apply(state: ChallengeState) -> None:
            state.resume_status = state.status
            state.status = ChallengeStatus.PAUSED

        return self.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        )


class LifecycleCheckpointTests(unittest.TestCase):
    def test_pause_rejects_overlong_handoff_before_state_mutation(self) -> None:
        state = ChallengeState(
            "contest",
            "rev",
            "challenge",
            schema_version=STATE_SCHEMA_VERSION,
        )
        engine = _MemoryEngine(state)
        before_status = state.status

        with self.assertRaisesRegex(
            EngineError,
            "handoff destination",
        ):
            pause_with_handoff(
                engine,
                state.identity,
                Path("H" * 300),
            )

        self.assertEqual(state.revision, 0)
        self.assertIs(state.status, before_status)
        self.assertIsNone(state.resume_status)
        self.assertEqual(state.checkpoints, [])

    def test_pause_preflights_atomic_temporary_filename_headroom(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = ChallengeState(
                "contest",
                "rev",
                "challenge",
                schema_version=STATE_SCHEMA_VERSION,
            )
            engine = _MemoryEngine(state)
            destination = Path(directory) / ("H" * 230)

            with self.assertRaisesRegex(
                EngineError,
                "atomic write",
            ):
                pause_with_handoff(
                    engine,
                    state.identity,
                    destination,
                )

            self.assertEqual(state.revision, 0)
            self.assertEqual(state.checkpoints, [])

    def test_pause_writes_valid_nested_handoff_with_existing_semantics(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = ChallengeState(
                "contest",
                "rev",
                "challenge",
                schema_version=STATE_SCHEMA_VERSION,
            )
            engine = _MemoryEngine(state, root)
            destination = root / "nested" / "handoff.json"

            updated = pause_with_handoff(
                engine,
                state.identity,
                destination,
            )

            self.assertIs(updated.status, ChallengeStatus.PAUSED)
            self.assertEqual(updated.revision, 2)
            self.assertEqual(len(updated.checkpoints), 1)
            payload = read_json(destination)
            self.assertEqual(payload["state_revision"], 2)
            self.assertEqual(payload["status"], "PAUSED")
            self.assertEqual(
                payload["checkpoint"]["id"],
                updated.checkpoints[0].id,
            )

    def test_legacy_checkpoint_action_text_remains_readable(self) -> None:
        payload = {
            "id": "CP-legacy",
            "session_id": None,
            "cycle_id": None,
            "active_goal_id": None,
            "next_actions": ["legacy complete command"],
            "do_not_repeat": ["legacy operator note"],
        }

        checkpoint = Checkpoint.from_dict(payload)

        self.assertEqual(
            checkpoint.next_actions,
            ["legacy complete command"],
        )
        self.assertEqual(
            checkpoint.do_not_repeat,
            ["legacy operator note"],
        )

    def test_operator_checkpoint_retains_supported_frontier(self) -> None:
        state = ChallengeState(
            "contest",
            "rev",
            "challenge",
            schema_version=STATE_SCHEMA_VERSION,
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
                path="artifacts/evidence.txt",
                sha256="a" * 64,
                source_run_id="R-1",
            )
        )
        state.facts.append(
            Fact(
                id="F-1",
                statement="the executed probe supports the frontier",
                provenance=Provenance.EXECUTED,
                challenge_id="challenge",
                source_run_id="R-1",
                artifact_id="A-1",
                locator="artifacts/evidence.txt:1",
                supports=["H-supported", "H-confirmed"],
            )
        )
        state.hypotheses.extend(
            [
                Hypothesis(
                    "H-open",
                    "an untested branch remains",
                    Falsifier("exercise the branch"),
                ),
                Hypothesis(
                    "H-supported",
                    "the observed branch is promising",
                    Falsifier("repeat without the trigger"),
                    status=HypothesisStatus.SUPPORTED,
                    evidence_fact_ids=["F-1"],
                ),
                Hypothesis(
                    "H-confirmed",
                    "a resolved control hypothesis",
                    Falsifier("run the recorded control"),
                    status=HypothesisStatus.CONFIRMED,
                    evidence_fact_ids=["F-1"],
                ),
            ]
        )
        state.validate()
        engine = _MemoryEngine(state)

        _updated, checkpoint = create_checkpoint(
            engine,
            state.identity,
            note="operator handoff",
        )

        self.assertEqual(
            checkpoint.open_hypothesis_ids,
            ["H-open", "H-supported"],
        )

    def test_checkpoint_stores_bounded_experiment_refs_not_commands(
        self,
    ) -> None:
        state = ChallengeState(
            "contest",
            "rev",
            "challenge",
            schema_version=STATE_SCHEMA_VERSION,
        )
        large_registered_command = "probe " + ("R" * 16_000)
        large_failed_command = "probe " + ("F" * 16_000)
        registered = Experiment(
            id="E-large-registered",
            hypothesis_ids=[],
            command=large_registered_command,
            expected_observation="a bounded observation",
            keep_if="the observation advances the goal",
            drop_if="the observation is absent",
            timeout_seconds=10,
            kind=ExperimentKind.PROBE,
            status=ExperimentStatus.REGISTERED,
        )
        failed = Experiment(
            id="E-large-failed",
            hypothesis_ids=[],
            command=large_failed_command,
            expected_observation="a bounded observation",
            keep_if="the observation advances the goal",
            drop_if="the observation is absent",
            timeout_seconds=10,
            kind=ExperimentKind.PROBE,
            status=ExperimentStatus.FAILED,
        )
        state.experiments.extend((registered, failed))
        state.validate()

        _updated, checkpoint = create_checkpoint(
            _MemoryEngine(state),
            state.identity,
        )

        self.assertEqual(
            checkpoint.next_actions,
            [checkpoint_action_reference(registered)],
        )
        self.assertEqual(
            checkpoint.do_not_repeat,
            [checkpoint_action_reference(failed)],
        )
        rendered = canonical_json_record(checkpoint.to_dict())
        self.assertNotIn(large_registered_command, rendered)
        self.assertNotIn(large_failed_command, rendered)
        self.assertLess(len(rendered.encode("ascii")), 2_000)
        self.assertEqual(
            checkpoint.extra[CHECKPOINT_ACTION_PROJECTION_KEY][
                "canonical_pointer"
            ],
            "state.json#/experiments",
        )

    def test_checkpoint_hashes_oversized_experiment_id(self) -> None:
        state = ChallengeState(
            "contest",
            "rev",
            "challenge",
            schema_version=STATE_SCHEMA_VERSION,
        )
        oversized_id = "E-" + ("I" * 10_000)
        experiment = Experiment(
            id=oversized_id,
            hypothesis_ids=[],
            command="probe bounded-id-reference",
            expected_observation="a bounded observation",
            keep_if="the observation advances the goal",
            drop_if="the observation is absent",
            timeout_seconds=10,
            kind=ExperimentKind.PROBE,
            status=ExperimentStatus.REGISTERED,
        )
        state.experiments.append(experiment)
        state.validate()

        _updated, checkpoint = create_checkpoint(
            _MemoryEngine(state),
            state.identity,
        )

        reference = checkpoint.next_actions[0]
        self.assertNotIn(oversized_id, reference)
        self.assertTrue(reference.startswith("experiment_id_sha256:"))
        self.assertLess(len(reference.encode("ascii")), 200)
        self.assertNotIn(
            oversized_id,
            canonical_json_record(checkpoint.to_dict()),
        )


if __name__ == "__main__":
    unittest.main()
