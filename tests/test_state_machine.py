from __future__ import annotations

import unittest

from ctf_os.engine.state_machine import (
    TRANSITIONS,
    TransitionError,
    TransitionEvidence,
    validate_transition,
)


class StateMachineTests(unittest.TestCase):
    def test_human_state_can_return_to_active(self) -> None:
        validate_transition("NEEDS_HUMAN", "ACTIVE")

    def test_ready_requires_proof(self) -> None:
        with self.assertRaisesRegex(TransitionError, "proof"):
            validate_transition("PROVING", "READY_TO_SUBMIT")
        validate_transition(
            "PROVING",
            "READY_TO_SUBMIT",
            evidence=TransitionEvidence(proof_passed=True),
        )

    def test_solved_requires_manual_accepted_outcome(self) -> None:
        with self.assertRaisesRegex(TransitionError, "operator"):
            validate_transition("READY_TO_SUBMIT", "SOLVED")
        validate_transition(
            "READY_TO_SUBMIT",
            "SOLVED",
            evidence=TransitionEvidence(operator_outcome="accepted"),
        )

    def test_accepted_outcome_can_close_every_nonterminal_state(
        self,
    ) -> None:
        for source in (
            "NEW",
            "TRIAGING",
            "ACTIVE",
            "STALLED",
            "NEEDS_RESEARCH",
            "NEEDS_HUMAN",
            "PROVING",
            "READY_TO_SUBMIT",
            "PAUSED",
        ):
            with self.subTest(source=source):
                with self.assertRaisesRegex(TransitionError, "operator"):
                    validate_transition(source, "SOLVED")
                validate_transition(
                    source,
                    "SOLVED",
                    evidence=TransitionEvidence(
                        operator_outcome="accepted"
                    ),
                )
        with self.assertRaises(TransitionError):
            validate_transition(
                "ABANDONED",
                "SOLVED",
                evidence=TransitionEvidence(operator_outcome="accepted"),
            )

    def test_rejection_returns_to_active(self) -> None:
        validate_transition(
            "READY_TO_SUBMIT",
            "ACTIVE",
            evidence=TransitionEvidence(operator_outcome="rejected"),
        )

    def test_pause_resumes_exact_prior_state_when_supplied(self) -> None:
        validate_transition(
            "PAUSED",
            "STALLED",
            evidence=TransitionEvidence(pause_resume_target="STALLED"),
        )
        with self.assertRaisesRegex(TransitionError, "resume"):
            validate_transition(
                "PAUSED",
                "ACTIVE",
                evidence=TransitionEvidence(pause_resume_target="STALLED"),
            )

    def test_every_pauseable_state_has_an_exact_resume_edge(self) -> None:
        for source, targets in TRANSITIONS.items():
            if "PAUSED" not in targets:
                continue
            with self.subTest(source=source):
                self.assertIn(source, TRANSITIONS["PAUSED"])
                validate_transition(
                    "PAUSED",
                    source,
                    evidence=TransitionEvidence(
                        pause_resume_target=source,
                        proof_passed=source == "READY_TO_SUBMIT",
                    ),
                )

    def test_terminal_states_do_not_reopen(self) -> None:
        with self.assertRaises(TransitionError):
            validate_transition("SOLVED", "ACTIVE")


if __name__ == "__main__":
    unittest.main()
