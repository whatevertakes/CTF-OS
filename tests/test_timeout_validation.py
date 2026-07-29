from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from ctf_os.codex.commands import BatchInvocation
from ctf_os.codex.contracts import Role
from ctf_os.codex.limiter import (
    FifoModelCallLimiter,
    FileFifoModelCallLimiter,
    UnlimitedModelCallLimiter,
)


class TimeoutValidationTests(unittest.TestCase):
    def test_model_call_capacity_requires_a_positive_integer(self) -> None:
        invalid_capacities = (
            True,
            0,
            -1,
            1.5,
            float("nan"),
            float("inf"),
            float("-inf"),
            "1",
        )
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "model-calls.json"
            for capacity in invalid_capacities:
                for constructor in (
                    lambda: FifoModelCallLimiter(capacity),
                    lambda: FileFifoModelCallLimiter(
                        state_path,
                        capacity,
                    ),
                ):
                    with (
                        self.subTest(
                            constructor=constructor,
                            capacity=capacity,
                        ),
                        self.assertRaisesRegex(
                            ValueError,
                            "capacity must be a positive integer",
                        ),
                    ):
                        constructor()

            self.assertEqual(FifoModelCallLimiter(1).snapshot().capacity, 1)
            self.assertEqual(
                FileFifoModelCallLimiter(
                    state_path,
                    1,
                ).snapshot().capacity,
                1,
            )

    def test_file_limiter_repairs_invalid_persisted_capacity(self) -> None:
        invalid_capacities = (
            True,
            0,
            -1,
            1.5,
            float("nan"),
            float("inf"),
            float("-inf"),
            "1",
        )
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "model-calls.json"
            limiter = FileFifoModelCallLimiter(state_path, 2)
            for capacity in invalid_capacities:
                with self.subTest(capacity=capacity):
                    state_path.write_text(
                        json.dumps(
                            {
                                "version": 1,
                                "capacity": capacity,
                                "queue": [{"pid": os.getpid()}],
                                "holders": [],
                            }
                        ),
                        encoding="utf-8",
                    )
                    _, state = limiter._load_state()
                    self.assertEqual(state["capacity"], 2)

    def test_batch_invocation_timeout_requires_a_finite_positive_number(
        self,
    ) -> None:
        invalid_timeouts = (
            True,
            0,
            -1,
            float("nan"),
            float("inf"),
            float("-inf"),
            "1",
        )
        for timeout in invalid_timeouts:
            with (
                self.subTest(timeout=timeout),
                self.assertRaisesRegex(
                    ValueError,
                    "timeout_seconds",
                ),
            ):
                BatchInvocation(
                    "timeout-validation",
                    Role.RECON,
                    "inspect the challenge",
                    Path("/challenge"),
                    Path("/runs/timeout-validation"),
                    timeout_seconds=timeout,  # type: ignore[arg-type]
                )

        for timeout in (None, 0.25, 1):
            with self.subTest(valid_timeout=timeout):
                invocation = BatchInvocation(
                    "timeout-validation",
                    Role.RECON,
                    "inspect the challenge",
                    Path("/challenge"),
                    Path("/runs/timeout-validation"),
                    timeout_seconds=timeout,
                )
                self.assertEqual(invocation.timeout_seconds, timeout)

    def test_batch_invocation_deadlines_require_finite_positive_numbers(
        self,
    ) -> None:
        invalid_deadlines = (
            True,
            0,
            -1,
            float("nan"),
            float("inf"),
            float("-inf"),
            "1",
        )
        for field in (
            "deadline_epoch_seconds",
            "deadline_monotonic_seconds",
        ):
            for value in invalid_deadlines:
                with (
                    self.subTest(field=field, value=value),
                    self.assertRaisesRegex(ValueError, field),
                ):
                    BatchInvocation(
                        "deadline-validation",
                        Role.RECON,
                        "inspect the challenge",
                        Path("/challenge"),
                        Path("/runs/deadline-validation"),
                        **{field: value},
                    )

            for value in (None, 0.25, 1):
                with self.subTest(field=field, valid_value=value):
                    invocation = BatchInvocation(
                        "deadline-validation",
                        Role.RECON,
                        "inspect the challenge",
                        Path("/challenge"),
                        Path("/runs/deadline-validation"),
                        **{field: value},
                    )
                    self.assertEqual(getattr(invocation, field), value)

    def test_batch_invocation_contract_version_is_explicitly_bounded(
        self,
    ) -> None:
        for version in (True, 0, 3, "2"):
            with (
                self.subTest(version=version),
                self.assertRaisesRegex(ValueError, "contract_version"),
            ):
                BatchInvocation(
                    "contract-validation",
                    Role.RECON,
                    "inspect the challenge",
                    Path("/challenge"),
                    Path("/runs/contract-validation"),
                    contract_version=version,  # type: ignore[arg-type]
                )
        for version in (1, 2):
            invocation = BatchInvocation(
                "contract-validation",
                Role.RECON,
                "inspect the challenge",
                Path("/challenge"),
                Path("/runs/contract-validation"),
                contract_version=version,
            )
            self.assertEqual(invocation.contract_version, version)

    def test_model_call_timeout_is_finite_nonnegative_or_none(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            limiters = (
                FifoModelCallLimiter(1),
                FileFifoModelCallLimiter(
                    Path(temporary) / "model-calls.json",
                    1,
                ),
                UnlimitedModelCallLimiter(),
            )
            invalid_timeouts = (
                True,
                -1,
                float("nan"),
                float("inf"),
                float("-inf"),
                "1",
            )
            for limiter in limiters:
                for timeout in invalid_timeouts:
                    with (
                        self.subTest(
                            limiter=type(limiter).__name__,
                            timeout=timeout,
                        ),
                        self.assertRaisesRegex(ValueError, "timeout"),
                    ):
                        limiter.slot(timeout=timeout)  # type: ignore[arg-type]

                for timeout in (None, 0, 0.25, 1):
                    with self.subTest(
                        limiter=type(limiter).__name__,
                        valid_timeout=timeout,
                    ):
                        owner = limiter.slot(timeout=timeout)
                        with owner as slot:
                            self.assertGreaterEqual(slot.acquire(), 0)

    def test_file_limiter_poll_interval_requires_a_finite_positive_number(
        self,
    ) -> None:
        invalid_intervals = (
            True,
            0,
            -1,
            float("nan"),
            float("inf"),
            float("-inf"),
            "0.1",
        )
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "model-calls.json"
            for interval in invalid_intervals:
                with (
                    self.subTest(poll_interval=interval),
                    self.assertRaisesRegex(ValueError, "poll_interval"),
                ):
                    FileFifoModelCallLimiter(
                        state_path,
                        1,
                        poll_interval=interval,  # type: ignore[arg-type]
                    )

            for interval in (0.01, 1):
                with self.subTest(valid_poll_interval=interval):
                    limiter = FileFifoModelCallLimiter(
                        state_path,
                        1,
                        poll_interval=interval,
                    )
                    self.assertEqual(limiter.snapshot().active, 0)


if __name__ == "__main__":
    unittest.main()
