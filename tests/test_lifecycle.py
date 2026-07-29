from __future__ import annotations

import unittest

from ctf_os.lifecycle import create_checkpoint
from ctf_os.models import (
    ArtifactReference,
    ChallengeState,
    Fact,
    Falsifier,
    Hypothesis,
    HypothesisStatus,
    Provenance,
    RunReference,
    RunStatus,
)
from ctf_os.schema import STATE_SCHEMA_VERSION


class _MemoryStore:
    def __init__(self, state: ChallengeState) -> None:
        self.state = state

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


class _MemoryEngine:
    def __init__(self, state: ChallengeState) -> None:
        self.store = _MemoryStore(state)


class LifecycleCheckpointTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
