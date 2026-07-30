from __future__ import annotations

import copy
import hashlib
import json
import unittest

from ctf_os.contracts.pwn_crash_v1 import (
    PWN_CRASH_V1_CONTRACT_FINGERPRINT,
    PWN_CRASH_V1_CONTRACT_ID,
    PWN_CRASH_V1_CONTRACT_VERSION,
    PWN_CRASH_V1_MAX_DOCUMENT_BYTES,
    PWN_CRASH_V1_SCHEMA_VERSION,
    PwnCrashV1ContractError,
    PwnCrashV1Verdict,
    build_pwn_crash_v1_plan,
    evaluate_pwn_crash_v1,
    parse_pwn_crash_v1_observation,
    pwn_crash_v1_canonical_json_bytes,
    pwn_crash_v1_contract_descriptor,
)


POC = b"A" * 48
SOURCE = b"\x7fELF-pwn-crash-contract-fixture"
SOURCE_SHA256 = hashlib.sha256(SOURCE).hexdigest()
SOURCE_SIZE = len(SOURCE)
MANIFEST_SHA256 = hashlib.sha256(b"manifest").hexdigest()
RECIPE_SHA256 = hashlib.sha256(b"recipe").hexdigest()
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def document(
    ordinal: int,
    termination: str = "exited",
    *,
    exit_code: int | None = 0,
    signal_number: int | None = None,
) -> dict[str, object]:
    positive = ordinal <= 3
    return {
        "binding": {
            "input_sha256": (
                hashlib.sha256(POC).hexdigest()
                if positive
                else EMPTY_SHA256
            ),
            "input_size_bytes": len(POC) if positive else 0,
            "ordinal": ordinal,
            "phase": "positive" if positive else "control",
            "recipe_sha256": RECIPE_SHA256,
            "source_manifest_sha256": MANIFEST_SHA256,
            "source_sha256": SOURCE_SHA256,
            "source_size_bytes": SOURCE_SIZE,
        },
        "contract": {
            "fingerprint": PWN_CRASH_V1_CONTRACT_FINGERPRINT,
            "id": PWN_CRASH_V1_CONTRACT_ID,
            "version": PWN_CRASH_V1_CONTRACT_VERSION,
        },
        "reason_code": "observation_recorded",
        "schema_version": PWN_CRASH_V1_SCHEMA_VERSION,
        "status": "ok",
        "target": {
            "exit_code": exit_code,
            "signal_number": signal_number,
            "termination": termination,
        },
    }


def payloads(
    target_statuses: tuple[tuple[str, int | None, int | None], ...],
) -> tuple[bytes, ...]:
    return tuple(
        pwn_crash_v1_canonical_json_bytes(
            document(
                ordinal,
                termination,
                exit_code=exit_code,
                signal_number=signal_number,
            )
        )
        for ordinal, (
            termination,
            exit_code,
            signal_number,
        ) in enumerate(target_statuses, start=1)
    )


def evaluate(
    values: tuple[bytes, ...],
):
    return evaluate_pwn_crash_v1(
        values,
        poc_input=POC,
        expected_source_manifest_sha256=MANIFEST_SHA256,
        expected_source_sha256=SOURCE_SHA256,
        expected_source_size_bytes=SOURCE_SIZE,
        expected_recipe_sha256=RECIPE_SHA256,
    )


NORMAL = ("exited", 0, None)
EXIT_139 = ("exited", 139, None)
SIGSEGV = ("signaled", None, 11)


class PwnCrashV1ContractTests(unittest.TestCase):
    def test_fixed_plan_is_three_positive_then_three_empty_controls(
        self,
    ) -> None:
        plan = build_pwn_crash_v1_plan(POC)
        self.assertEqual([item.ordinal for item in plan], list(range(1, 7)))
        self.assertEqual(
            [item.phase for item in plan],
            ["positive"] * 3 + ["control"] * 3,
        )
        self.assertEqual(
            {item.input_sha256 for item in plan[:3]},
            {hashlib.sha256(POC).hexdigest()},
        )
        self.assertEqual(
            {
                (item.input_sha256, item.input_size_bytes)
                for item in plan[3:]
            },
            {(EMPTY_SHA256, 0)},
        )
        with self.assertRaisesRegex(ValueError, "non-empty"):
            build_pwn_crash_v1_plan(b"")

    def test_three_and_two_of_three_same_fault_confirm(self) -> None:
        for positive in (
            (SIGSEGV, SIGSEGV, SIGSEGV),
            (SIGSEGV, EXIT_139, SIGSEGV),
        ):
            with self.subTest(positive=positive):
                result = evaluate(
                    payloads((*positive, NORMAL, NORMAL, NORMAL))
                )
            self.assertIs(result.verdict, PwnCrashV1Verdict.CONFIRMED)
            self.assertTrue(result.passed)
            self.assertEqual(
                result.reason_code,
                "reproducible_input_triggered_fault_signal",
            )
            self.assertEqual(dict(result.positive_signal_counts)[11], 2 if EXIT_139 in positive else 3)
            self.assertEqual(
                result.evidence_sha256,
                hashlib.sha256(result.canonical_bytes()).hexdigest(),
            )

    def test_exit_139_and_output_claims_are_not_signals(self) -> None:
        result = evaluate(
            payloads(
                (
                    EXIT_139,
                    EXIT_139,
                    EXIT_139,
                    NORMAL,
                    NORMAL,
                    NORMAL,
                )
            )
        )
        self.assertIs(result.verdict, PwnCrashV1Verdict.INCONCLUSIVE)
        self.assertEqual(result.reason_code, "no_positive_fault_observed")
        self.assertFalse(result.passed)
        self.assertNotIn("Segmentation fault", result.canonical_bytes().decode())

    def test_signal_threshold_signature_and_control_are_ordered(
        self,
    ) -> None:
        cases = (
            (
                (SIGSEGV, NORMAL, NORMAL, NORMAL, NORMAL, NORMAL),
                "positive_fault_threshold_not_met",
            ),
            (
                (
                    ("signaled", None, 4),
                    ("signaled", None, 6),
                    ("signaled", None, 11),
                    NORMAL,
                    NORMAL,
                    NORMAL,
                ),
                "positive_fault_signature_not_reproduced",
            ),
            (
                (
                    SIGSEGV,
                    SIGSEGV,
                    NORMAL,
                    ("signaled", None, 11),
                    NORMAL,
                    NORMAL,
                ),
                "control_abnormal_termination_observed",
            ),
        )
        for statuses, reason in cases:
            with self.subTest(reason=reason):
                result = evaluate(payloads(statuses))
            self.assertIs(result.verdict, PwnCrashV1Verdict.INCONCLUSIVE)
            self.assertEqual(result.reason_code, reason)
            self.assertFalse(result.passed)

    def test_all_bindings_and_exact_attempt_order_fail_closed(self) -> None:
        base = [
            document(
                ordinal,
                "signaled" if ordinal <= 3 else "exited",
                exit_code=None if ordinal <= 3 else 0,
                signal_number=11 if ordinal <= 3 else None,
            )
            for ordinal in range(1, 7)
        ]
        mutations = (
            ("source_manifest_mismatch", "source_manifest_sha256"),
            ("source_binding_mismatch", "source_sha256"),
            ("recipe_binding_mismatch", "recipe_sha256"),
            ("input_binding_mismatch", "input_sha256"),
        )
        for reason, field in mutations:
            altered = copy.deepcopy(base)
            binding = altered[0]["binding"]
            assert isinstance(binding, dict)
            binding[field] = "f" * 64
            result = evaluate(
                tuple(
                    pwn_crash_v1_canonical_json_bytes(item)
                    for item in altered
                )
            )
            with self.subTest(reason=reason):
                self.assertIs(result.verdict, PwnCrashV1Verdict.ERROR)
                self.assertIn(reason, result.failure_codes)

        reordered = copy.deepcopy(base)
        first_binding = reordered[0]["binding"]
        assert isinstance(first_binding, dict)
        first_binding["ordinal"] = 2
        first_binding["phase"] = "positive"
        result = evaluate(
            tuple(
                pwn_crash_v1_canonical_json_bytes(item)
                for item in reordered
            )
        )
        self.assertIn("attempt_order_mismatch", result.failure_codes)
        self.assertIs(result.verdict, PwnCrashV1Verdict.ERROR)

    def test_producer_error_and_missing_attempt_are_errors(self) -> None:
        values = list(
            payloads(
                (
                    SIGSEGV,
                    SIGSEGV,
                    SIGSEGV,
                    NORMAL,
                    NORMAL,
                    NORMAL,
                )
            )
        )
        failed = document(1)
        failed["status"] = "error"
        failed["reason_code"] = "target_timeout"
        failed["target"] = None
        values[0] = pwn_crash_v1_canonical_json_bytes(failed)
        result = evaluate(tuple(values))
        self.assertIs(result.verdict, PwnCrashV1Verdict.ERROR)
        self.assertEqual(result.reason_code, "producer_error")
        self.assertEqual(
            result.failures[0].producer_reason,
            "target_timeout",
        )

        missing = evaluate(tuple(values[1:]))
        self.assertIs(missing.verdict, PwnCrashV1Verdict.ERROR)
        self.assertIn("attempt_count_mismatch", missing.failure_codes)

    def test_parser_rejects_noncanonical_duplicate_and_oversized_json(
        self,
    ) -> None:
        valid = pwn_crash_v1_canonical_json_bytes(document(1))
        observation = parse_pwn_crash_v1_observation(valid)
        self.assertEqual(observation.ordinal, 1)
        self.assertEqual(observation.target.signal_number, None)

        pretty = json.dumps(document(1), indent=2).encode()
        with self.assertRaisesRegex(
            PwnCrashV1ContractError,
            "noncanonical_json",
        ):
            parse_pwn_crash_v1_observation(pretty)
        duplicate = valid.replace(
            b'{"binding":',
            b'{"schema_version":1,"binding":',
            1,
        )
        with self.assertRaisesRegex(
            PwnCrashV1ContractError,
            "duplicate_json_key",
        ):
            parse_pwn_crash_v1_observation(duplicate)
        with self.assertRaisesRegex(
            PwnCrashV1ContractError,
            "artifact_too_large",
        ):
            parse_pwn_crash_v1_observation(
                b"{" + b" " * PWN_CRASH_V1_MAX_DOCUMENT_BYTES + b"}"
            )
        deeply_nested = b"[" * 1_100 + b"0" + b"]" * 1_100
        with self.assertRaisesRegex(
            PwnCrashV1ContractError,
            "invalid_json",
        ):
            parse_pwn_crash_v1_observation(deeply_nested)

    def test_iterable_setup_failure_is_a_bounded_contract_error(self) -> None:
        class BrokenIterable:
            def __iter__(self):
                raise RuntimeError("producer-controlled iterator failure")

        result = evaluate_pwn_crash_v1(
            BrokenIterable(),
            poc_input=POC,
            expected_source_manifest_sha256=MANIFEST_SHA256,
            expected_source_sha256=SOURCE_SHA256,
            expected_source_size_bytes=SOURCE_SIZE,
            expected_recipe_sha256=RECIPE_SHA256,
        )
        self.assertIs(result.verdict, PwnCrashV1Verdict.ERROR)
        self.assertEqual(
            result.failure_codes,
            ("observations_not_iterable",),
        )

    def test_descriptor_and_fingerprint_are_deterministic(self) -> None:
        descriptor = pwn_crash_v1_contract_descriptor()
        self.assertEqual(
            PWN_CRASH_V1_CONTRACT_FINGERPRINT,
            hashlib.sha256(
                pwn_crash_v1_canonical_json_bytes(descriptor)
            ).hexdigest(),
        )
        self.assertEqual(
            descriptor["target_status"],
            (
                "direct-child-wait-status-only;"
                "numeric-exit-is-never-a-signal"
            ),
        )


if __name__ == "__main__":
    unittest.main()
