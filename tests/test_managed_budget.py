from __future__ import annotations

import copy
import math
import unittest

from ctf_os.managed_budget import (
    MANAGED_WAVE_LOGICAL_ROLE_COUNT,
    ManagedWaveBudgetContractError,
    build_managed_wave_budget_guard,
    managed_wave_budget_guard_errors,
)


class ManagedWaveBudgetContractTests(unittest.TestCase):
    @staticmethod
    def build(
        *,
        provider_limit: int = 3,
        remaining_seconds: float | None = 510.0,
        budget_mode: str = "bounded",
    ) -> dict[str, object]:
        return build_managed_wave_budget_guard(
            wave_kind="attack",
            provider_max_concurrent_calls=provider_limit,
            queue_reserve_seconds=90.0,
            role_call_reserve_seconds=240.0,
            action_commit_reserve_seconds=180.0,
            remaining_seconds=remaining_seconds,
            checked_state_revision=17,
            configuration_epoch=4,
            budget_mode=budget_mode,
        )

    def test_exact_boundary_admits_and_submillisecond_deficit_pauses(self):
        admitted = self.build(remaining_seconds=510.0)
        self.assertEqual(admitted["minimum_required_ms"], 510_000)
        self.assertEqual(admitted["decision"], "allow")
        self.assertEqual(
            admitted["reason_code"],
            "sufficient_remaining_budget",
        )

        paused = self.build(remaining_seconds=509.9999)
        self.assertEqual(paused["remaining_budget_ms"], 509_999)
        self.assertEqual(paused["decision"], "pause")
        self.assertEqual(
            paused["reason_code"],
            "insufficient_budget_for_wave",
        )
        self.assertEqual(managed_wave_budget_guard_errors(paused), [])

    def test_provider_limit_changes_batches_not_logical_role_count(self):
        parallel = self.build(provider_limit=99)
        serial = self.build(
            provider_limit=1,
            remaining_seconds=990.0,
        )
        self.assertEqual(
            parallel["logical_role_count"],
            MANAGED_WAVE_LOGICAL_ROLE_COUNT,
        )
        self.assertEqual(
            serial["logical_role_count"],
            MANAGED_WAVE_LOGICAL_ROLE_COUNT,
        )
        self.assertEqual(parallel["provider_parallel_capacity"], 3)
        self.assertEqual(parallel["serial_provider_batches"], 1)
        self.assertEqual(parallel["minimum_required_ms"], 510_000)
        self.assertEqual(serial["provider_parallel_capacity"], 1)
        self.assertEqual(serial["serial_provider_batches"], 3)
        self.assertEqual(serial["minimum_required_ms"], 990_000)

    def test_operator_unbounded_is_explicit_and_finite_clock_is_required(self):
        audit = self.build(
            remaining_seconds=None,
            budget_mode="operator_unbounded",
        )
        self.assertEqual(audit["decision"], "allow")
        self.assertEqual(audit["reason_code"], "operator_unbounded")
        self.assertIsNone(audit["remaining_budget_ms"])
        self.assertEqual(managed_wave_budget_guard_errors(audit), [])

        for hostile in (math.nan, math.inf, -math.inf, -0.001, True):
            with self.subTest(hostile=hostile):
                with self.assertRaises(
                    ManagedWaveBudgetContractError
                ):
                    self.build(remaining_seconds=hostile)
        with self.assertRaises(ManagedWaveBudgetContractError):
            self.build(
                remaining_seconds=None,
                budget_mode="bounded",
            )
        with self.assertRaises(ManagedWaveBudgetContractError):
            self.build(
                remaining_seconds=510.0,
                budget_mode="operator_unbounded",
            )

    def test_mutated_math_width_and_decision_fail_exact_validation(self):
        base = self.build()
        for field, value in (
            ("logical_role_count", 2),
            ("provider_parallel_capacity", 2),
            ("serial_provider_batches", 3),
            ("minimum_required_ms", 509_999),
            ("decision", "pause"),
            ("reason_code", "insufficient_budget_for_wave"),
            ("remaining_budget_ms", 509_999),
        ):
            with self.subTest(field=field):
                mutated = copy.deepcopy(base)
                mutated[field] = value
                self.assertTrue(
                    managed_wave_budget_guard_errors(mutated)
                )

    def test_unknown_fields_and_nonfinite_reserves_fail_closed(self):
        audit = self.build()
        audit["surprise"] = True
        self.assertTrue(managed_wave_budget_guard_errors(audit))
        for hostile in (0, -1, math.nan, math.inf, True):
            with self.subTest(hostile=hostile):
                with self.assertRaises(
                    ManagedWaveBudgetContractError
                ):
                    build_managed_wave_budget_guard(
                        wave_kind="attack",
                        provider_max_concurrent_calls=3,
                        queue_reserve_seconds=hostile,
                        role_call_reserve_seconds=240.0,
                        action_commit_reserve_seconds=180.0,
                        remaining_seconds=510.0,
                        checked_state_revision=0,
                        configuration_epoch=0,
                        budget_mode="bounded",
                    )


if __name__ == "__main__":
    unittest.main()
