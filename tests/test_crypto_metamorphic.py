from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace

from ctf_os.adapters import get_adapter
from ctf_os.engine.crypto_metamorphic import (
    CRYPTO_METAMORPHIC_MAX_CHANGED_POINTERS,
    CRYPTO_METAMORPHIC_PROOF_PROTOCOL,
    CryptoMetamorphicObservation,
    CryptoMetamorphicPreflightError,
    build_crypto_metamorphic_plan,
    evaluate_crypto_metamorphic_proof,
)


CANDIDATE = "KCTF{crypto-metamorphic-candidate}"
ORIGINAL = (
    b'{"N":3233,"ciphertext":2790,"e":17,"rounds":1}\n'
)
VARIANT = (
    b'{"N":4757,"ciphertext":2281,"e":17,"rounds":2}\n'
)
VARIANT_OUTPUT = b"metamorphic-plaintext-42\n"
MANIFEST = "a" * 64
SOLVER = "b" * 64
RUNTIME = "c" * 64
ORACLE = "d" * 64


def _valid_observations() -> tuple[CryptoMetamorphicObservation, ...]:
    plan = build_crypto_metamorphic_plan(
        CANDIDATE,
        ORIGINAL,
        VARIANT,
        VARIANT_OUTPUT,
        mutation_id="rsa-size-seed-variant",
    )
    return tuple(
        CryptoMetamorphicObservation(
            run_id=f"crypto-proof-{attempt.ordinal}",
            ordinal=attempt.ordinal,
            case_id=attempt.case_id,
            mutation_id=attempt.mutation_id,
            parameters_sha256=attempt.parameters_sha256,
            parameters_size_bytes=attempt.parameters_size_bytes,
            source_manifest_sha256=MANIFEST,
            solver_artifact_sha256=SOLVER,
            runtime_fingerprint_sha256=RUNTIME,
            oracle_artifact_sha256=ORACLE,
            clean_workspace=True,
            target_exit_code=0,
            runner_exit_code=0,
            ctfwrap_exit_code=0,
            timed_out=False,
            orchestration_status="completed",
            result_artifact_id=f"artifact-result-{attempt.ordinal}",
            result_artifact_sha256=attempt.expected_output_sha256,
            result_artifact_size_bytes=(
                attempt.expected_output_size_bytes
            ),
            capture_complete=True,
            truncation_known=True,
            truncated=False,
            capture_error=None,
        )
        for attempt in plan.attempts
    )


def _evaluate(observations):
    return evaluate_crypto_metamorphic_proof(
        CANDIDATE,
        ORIGINAL,
        VARIANT,
        VARIANT_OUTPUT,
        mutation_id="rsa-size-seed-variant",
        source_manifest_sha256=MANIFEST,
        solver_artifact_sha256=SOLVER,
        runtime_fingerprint_sha256=RUNTIME,
        oracle_artifact_sha256=ORACLE,
        observations=observations,
    )


class CryptoMetamorphicPlanTests(unittest.TestCase):
    def test_crypto_adapter_exposes_mandatory_contract_to_model_context(
        self,
    ) -> None:
        adapter = get_adapter("crypto")
        marker_keys = {
            marker.key for marker in adapter.progress_markers()
        }

        self.assertIn("metamorphic_variant_verified", marker_keys)
        self.assertIn(
            CRYPTO_METAMORPHIC_PROOF_PROTOCOL,
            adapter.captain_guidance(),
        )
        self.assertIn(
            CRYPTO_METAMORPHIC_PROOF_PROTOCOL,
            adapter.proof_policy().notes,
        )

    def test_plan_is_canonical_six_run_original_then_variant(self) -> None:
        formatted_original = (
            b'{ "rounds": 1, "e": 17, "ciphertext": 2790, '
            b'"N": 3233 }\n'
        )
        first = build_crypto_metamorphic_plan(
            CANDIDATE,
            formatted_original,
            VARIANT,
            VARIANT_OUTPUT,
            mutation_id="rsa-size-seed-variant",
        )
        second = build_crypto_metamorphic_plan(
            CANDIDATE,
            ORIGINAL,
            VARIANT,
            VARIANT_OUTPUT,
            mutation_id="rsa-size-seed-variant",
        )

        self.assertEqual(first, second)
        self.assertEqual(len(first.attempts), 6)
        self.assertEqual(
            tuple(item.ordinal for item in first.attempts),
            (1, 2, 3, 4, 5, 6),
        )
        self.assertEqual(
            tuple(item.case_id for item in first.attempts),
            ("original",) * 3 + ("metamorphic-variant",) * 3,
        )
        self.assertEqual(
            first.cases[1].changed_parameter_pointers,
            ("/N", "/ciphertext", "/rounds"),
        )
        self.assertNotEqual(
            first.cases[0].parameters_sha256,
            first.cases[1].parameters_sha256,
        )
        self.assertNotEqual(
            first.cases[0].expected_output_sha256,
            first.cases[1].expected_output_sha256,
        )
        self.assertEqual(len(first.sha256), 64)

    def test_rejects_vacuous_or_schema_changing_variant(self) -> None:
        cases = (
            (ORIGINAL, "parameter_variant_absent"),
            (
                b'{"N":"4757","ciphertext":2281,"e":17,"rounds":2}',
                "parameter_schema_mismatch",
            ),
            (
                b'{"N":4757,"ciphertext":2281,"e":17}',
                "parameter_schema_mismatch",
            ),
        )
        for variant, code in cases:
            with self.subTest(code=code):
                with self.assertRaisesRegex(
                    CryptoMetamorphicPreflightError,
                    code,
                ):
                    build_crypto_metamorphic_plan(
                        CANDIDATE,
                        ORIGINAL,
                        variant,
                        VARIANT_OUTPUT,
                        mutation_id="variant-1",
                    )

    def test_rejects_candidate_contamination_and_memorized_variant(self) -> None:
        contaminated = json.dumps(
            {
                "N": 4757,
                "ciphertext": 2281,
                "e": 17,
                "rounds": 2,
                "answer": CANDIDATE,
            },
            separators=(",", ":"),
        ).encode()
        original_with_answer = json.dumps(
            {
                "N": 3233,
                "ciphertext": 2790,
                "e": 17,
                "rounds": 1,
                "answer": "",
            },
            separators=(",", ":"),
        ).encode()
        with self.assertRaisesRegex(
            CryptoMetamorphicPreflightError,
            "candidate_contaminates_parameters",
        ):
            build_crypto_metamorphic_plan(
                CANDIDATE,
                original_with_answer,
                contaminated,
                VARIANT_OUTPUT,
                mutation_id="variant-1",
            )
        with self.assertRaisesRegex(
            CryptoMetamorphicPreflightError,
            "variant_output_contains_candidate",
        ):
            build_crypto_metamorphic_plan(
                CANDIDATE,
                ORIGINAL,
                VARIANT,
                CANDIDATE.encode(),
                mutation_id="variant-1",
            )
        with self.assertRaisesRegex(
            CryptoMetamorphicPreflightError,
            "oracle_not_independent",
        ):
            build_crypto_metamorphic_plan(
                CANDIDATE,
                ORIGINAL,
                VARIANT,
                VARIANT,
                mutation_id="variant-1",
            )

    def test_rejects_duplicate_json_keys_and_overbroad_variant(self) -> None:
        with self.assertRaisesRegex(
            CryptoMetamorphicPreflightError,
            "parameter_document_invalid",
        ):
            build_crypto_metamorphic_plan(
                CANDIDATE,
                b'{"N":1,"N":2}',
                b'{"N":3}',
                VARIANT_OUTPUT,
                mutation_id="variant-1",
            )

        original = {
            f"p{index}": 0
            for index in range(
                CRYPTO_METAMORPHIC_MAX_CHANGED_POINTERS + 1
            )
        }
        variant = {key: 1 for key in original}
        with self.assertRaisesRegex(
            CryptoMetamorphicPreflightError,
            "parameter_variant_too_broad",
        ):
            build_crypto_metamorphic_plan(
                CANDIDATE,
                json.dumps(original).encode(),
                json.dumps(variant).encode(),
                VARIANT_OUTPUT,
                mutation_id="variant-1",
            )


class CryptoMetamorphicEvaluationTests(unittest.TestCase):
    def test_exact_original_and_variant_matrix_passes(self) -> None:
        result, evaluation = _evaluate(_valid_observations())

        self.assertTrue(result.passed)
        self.assertTrue(evaluation.passed)
        self.assertEqual(
            result.policy_mode,
            CRYPTO_METAMORPHIC_PROOF_PROTOCOL,
        )
        self.assertEqual(result.successful_attempts, 6)
        self.assertEqual(result.required_attempts, 6)
        self.assertEqual(result.total_attempts, 6)
        self.assertEqual(evaluation.failure_codes, ())
        self.assertEqual(len(evaluation.sha256), 64)

    def test_evidence_is_commitment_only_and_raw_free(self) -> None:
        _result, evaluation = _evaluate(_valid_observations())
        encoded = json.dumps(
            evaluation.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        )

        self.assertNotIn(CANDIDATE, encoded)
        self.assertNotIn("3233", encoded)
        self.assertNotIn("4757", encoded)
        self.assertNotIn(
            VARIANT_OUTPUT.decode().strip(),
            encoded,
        )
        self.assertIn(hashlib.sha256(CANDIDATE.encode()).hexdigest(), encoded)
        self.assertIn("/ciphertext", encoded)

    def test_result_runtime_and_transport_tamper_fail_closed(self) -> None:
        base = _valid_observations()
        mutations = (
            (
                replace(
                    base[0],
                    result_artifact_sha256="e" * 64,
                ),
                "attempt-1:result_mismatch",
            ),
            (
                replace(base[1], runtime_fingerprint_sha256="f" * 64),
                "attempt-2:solver_or_runtime_mismatch",
            ),
            (
                replace(base[2], clean_workspace=False),
                "attempt-3:workspace_not_clean",
            ),
            (
                replace(base[3], timed_out=True),
                "attempt-4:timed_out",
            ),
            (
                replace(base[4], truncated=True),
                "attempt-5:capture_truncated",
            ),
            (
                replace(base[5], target_exit_code=1),
                "attempt-6:exit_status_mismatch",
            ),
        )
        for replacement, code in mutations:
            with self.subTest(code=code):
                ordinal = replacement.ordinal - 1
                observations = (
                    *base[:ordinal],
                    replacement,
                    *base[ordinal + 1 :],
                )
                result, evaluation = _evaluate(observations)
                self.assertFalse(result.passed)
                self.assertIn(code, evaluation.failure_codes)

    def test_order_count_run_and_artifact_reuse_fail_closed(self) -> None:
        base = _valid_observations()
        cases = (
            (
                base[:-1],
                "attempt_count_mismatch",
            ),
            (
                (*base, base[-1]),
                "attempt_count_mismatch",
            ),
            (
                (
                    base[1],
                    base[0],
                    *base[2:],
                ),
                "attempt-1:attempt_order_mismatch",
            ),
            (
                (
                    base[0],
                    replace(base[1], run_id=base[0].run_id),
                    *base[2:],
                ),
                "attempt-2:duplicate_run_id",
            ),
            (
                (
                    base[0],
                    replace(
                        base[1],
                        result_artifact_id=base[0].result_artifact_id,
                    ),
                    *base[2:],
                ),
                "attempt-2:artifact_reused",
            ),
        )
        for observations, code in cases:
            with self.subTest(code=code):
                result, evaluation = _evaluate(observations)
                self.assertFalse(result.passed)
                self.assertIn(code, evaluation.failure_codes)

    def test_preflight_failure_does_not_consume_observation_iterator(
        self,
    ) -> None:
        class Exploding:
            def __iter__(self):
                raise AssertionError("must not consume observations")

        result, evaluation = evaluate_crypto_metamorphic_proof(
            CANDIDATE,
            ORIGINAL,
            ORIGINAL,
            VARIANT_OUTPUT,
            mutation_id="variant-1",
            source_manifest_sha256=MANIFEST,
            solver_artifact_sha256=SOLVER,
            runtime_fingerprint_sha256=RUNTIME,
            oracle_artifact_sha256=ORACLE,
            observations=Exploding(),
        )

        self.assertFalse(result.passed)
        self.assertEqual(
            evaluation.failure_codes,
            ("parameter_variant_absent",),
        )
        self.assertEqual(evaluation.observations, ())

    def test_invalid_hash_binding_and_non_iterable_are_bounded(self) -> None:
        result, evaluation = evaluate_crypto_metamorphic_proof(
            CANDIDATE,
            ORIGINAL,
            VARIANT,
            VARIANT_OUTPUT,
            mutation_id="variant-1",
            source_manifest_sha256="not-a-hash",
            solver_artifact_sha256=SOLVER,
            runtime_fingerprint_sha256=RUNTIME,
            oracle_artifact_sha256=ORACLE,
            observations=_valid_observations(),
        )
        self.assertFalse(result.passed)
        self.assertEqual(
            evaluation.failure_codes,
            ("hash_binding_invalid",),
        )

        result, evaluation = evaluate_crypto_metamorphic_proof(
            CANDIDATE,
            ORIGINAL,
            VARIANT,
            VARIANT_OUTPUT,
            mutation_id="variant-1",
            source_manifest_sha256=MANIFEST,
            solver_artifact_sha256=SOLVER,
            runtime_fingerprint_sha256=RUNTIME,
            oracle_artifact_sha256=SOLVER,
            observations=_valid_observations(),
        )
        self.assertFalse(result.passed)
        self.assertEqual(
            evaluation.failure_codes,
            ("oracle_not_independent",),
        )

        result, evaluation = _evaluate(None)
        self.assertFalse(result.passed)
        self.assertEqual(
            evaluation.failure_codes,
            ("observations_not_iterable",),
        )

    def test_untrusted_ids_and_capture_error_are_bounded_and_redacted(
        self,
    ) -> None:
        base = _valid_observations()
        observations = (
            replace(
                base[0],
                run_id="\ud800",
                capture_error="secret diagnostic that must not persist",
            ),
            *base[1:],
        )

        result, evaluation = _evaluate(observations)
        encoded = json.dumps(
            evaluation.to_dict(),
            ensure_ascii=True,
            sort_keys=True,
        )

        self.assertFalse(result.passed)
        self.assertIn("attempt-1:run_id_invalid", evaluation.failure_codes)
        self.assertIn("attempt-1:capture_error", evaluation.failure_codes)
        self.assertNotIn("secret diagnostic", encoded)
        self.assertIn('"capture_error_present": true', encoded)


if __name__ == "__main__":
    unittest.main()
