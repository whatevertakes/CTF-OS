from __future__ import annotations

import unittest
from pathlib import Path

from ctf_os.adapters import get_adapter
from ctf_os.engine.context_pack import build_context_pack
from ctf_os.models import (
    ArtifactReference,
    ChallengeState,
    Fact,
    Falsifier,
    Goal,
    GoalStatus,
    Hypothesis,
    Provenance,
    RunReference,
    RunStatus,
)


class ContextPackTests(unittest.TestCase):
    def state(self) -> ChallengeState:
        state = ChallengeState("contest", "rev", "challenge")
        state.goals.append(Goal("G-1", "locate validation", GoalStatus.ACTIVE))
        state.active_goal_id = "G-1"
        state.facts.extend(
            [
                Fact(
                    "F-1",
                    "runtime reached 0x401000",
                    Provenance.EXECUTED,
                    challenge_id="challenge",
                    locator="run.log:20",
                    source_run_id="R-1",
                    artifact_id="A-1",
                ),
                Fact(
                    "F-2",
                    "the answer may be 7",
                    Provenance.MODEL_CLAIMED,
                    challenge_id="challenge",
                ),
            ]
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
                path="artifacts/run.log",
                sha256="a" * 64,
                source_run_id="R-1",
            )
        )
        state.hypotheses.append(
            Hypothesis("H-1", "comparison is direct", Falsifier("change input"))
        )
        state.validate()
        return state

    def test_pack_preserves_active_goal_provenance_and_state_pointer(self) -> None:
        pack = build_context_pack(
            self.state(),
            get_adapter("rev"),
            state_path=Path("/state/state.json"),
        )
        self.assertIn("locate validation", pack.text)
        self.assertIn("[executed]", pack.text)
        self.assertIn("/state/state.json", pack.text)
        self.assertIn("Category progress and failure contract", pack.text)
        self.assertIn("failure label:", pack.text)
        self.assertIn("evidence=", pack.text)
        self.assertEqual(len(pack.sha256), 64)

    def test_pack_is_bounded_and_reports_omissions(self) -> None:
        state = self.state()
        for index in range(200):
            state.facts.append(
                Fact(
                    f"F-{index + 10}",
                    "x" * 200,
                    Provenance.MODEL_CLAIMED,
                    challenge_id="challenge",
                )
            )
        pack = build_context_pack(
            state,
            get_adapter("rev"),
            state_path=Path("/state/state.json"),
            max_chars=4096,
        )
        self.assertLessEqual(len(pack.text), 4096)
        self.assertTrue(pack.truncated)
        self.assertIn("facts", pack.omitted)

    def test_falsifier_pack_prioritizes_executed_facts(self) -> None:
        pack = build_context_pack(
            self.state(),
            get_adapter("rev"),
            state_path=Path("/state/state.json"),
            role="falsifier",
        )
        self.assertLess(
            pack.text.index("runtime reached"), pack.text.index("answer may")
        )

    def test_long_operator_prompt_has_explicit_pointer_and_truncation(self) -> None:
        state = self.state()
        state.prompt = "A" * 16_000 + "TAIL_SENTINEL"
        state_path = Path("/state/state.json")
        pack = build_context_pack(
            state,
            get_adapter("rev"),
            state_path=state_path,
        )
        self.assertNotIn("TAIL_SENTINEL", pack.text)
        self.assertIn("complete operator prompt", pack.text)
        self.assertIn(str(state_path), pack.text)
        self.assertTrue(pack.truncated)
        self.assertEqual(pack.omitted["prompt_chars"], len("TAIL_SENTINEL"))


if __name__ == "__main__":
    unittest.main()
