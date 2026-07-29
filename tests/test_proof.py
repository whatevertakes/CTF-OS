from __future__ import annotations

import unittest

from ctf_os.adapters.base import ProofPolicy
from ctf_os.engine.proof import ProofAttempt, evaluate_proof


class ProofTests(unittest.TestCase):
    def attempt(
        self,
        run_id: str,
        *,
        flag: str = "CTF{ok}",
        source_hash: str = "source",
        clean: bool = True,
        remote: bool = False,
        exit_code: int = 0,
    ) -> ProofAttempt:
        return ProofAttempt(
            run_id,
            exit_code,
            (flag,),
            source_hash,
            clean,
            remote,
        )

    def test_deterministic_candidate_requires_all_clean_reproductions(self) -> None:
        policy = ProofPolicy("deterministic", clean_repetitions=3)
        result = evaluate_proof(
            "CTF{ok}",
            "source",
            [self.attempt(str(index)) for index in range(3)],
            policy,
        )
        self.assertTrue(result.passed)
        failed = evaluate_proof(
            "CTF{ok}",
            "source",
            [self.attempt("1"), self.attempt("2", clean=False)],
            policy,
        )
        self.assertFalse(failed.passed)

    def test_source_hash_mismatch_never_passes(self) -> None:
        result = evaluate_proof(
            "CTF{ok}",
            "source",
            [self.attempt("1", source_hash="changed")],
            ProofPolicy("hash_chain", clean_repetitions=1),
        )
        self.assertFalse(result.passed)
        self.assertTrue(
            any("manifest mismatch" in failure for failure in result.failures)
        )

    def test_remote_and_local_requirements_are_counted_separately(self) -> None:
        policy = ProofPolicy(
            "remote_independent", clean_repetitions=1, remote_repetitions=2
        )
        result = evaluate_proof(
            "CTF{ok}",
            "source",
            [
                self.attempt("local"),
                self.attempt("remote-1", remote=True),
                self.attempt("remote-2", remote=True),
            ],
            policy,
        )
        self.assertTrue(result.passed)

    def test_race_uses_success_distribution(self) -> None:
        policy = ProofPolicy(
            "success_distribution",
            clean_repetitions=0,
            trial_count=10,
            minimum_success_rate=0.7,
        )
        attempts = [
            self.attempt(str(index), flag="CTF{ok}" if index < 7 else "no")
            for index in range(10)
        ]
        result = evaluate_proof("CTF{ok}", "source", attempts, policy)
        self.assertTrue(result.passed)
        self.assertEqual(result.required_attempts, 7)


if __name__ == "__main__":
    unittest.main()
