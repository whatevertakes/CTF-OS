from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import ctf_os.codex.runner as runner_module
from ctf_os.budget import (
    BudgetExhausted,
    deadline_epoch,
    deadline_utc_after,
    remaining_seconds,
    require_remaining_seconds,
)
from ctf_os.codex import (
    BatchInvocation,
    BatchRunner,
    BatchWave,
    BatchWaveRunner,
    BuiltCommand,
    FifoModelCallLimiter,
    FileFifoModelCallLimiter,
    ModelCallLimitTimeout,
    ProcessOutcome,
    Role,
)
from ctf_os.models import Budget


def _output_path(command: BuiltCommand) -> Path:
    index = command.argv.index("--output-last-message")
    return Path(command.argv[index + 1])


def _payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "role": "recon",
        "status": "ok",
        "summary": "deadline-bound result",
        "observations": [],
        "hypotheses": [],
        "hypothesis_updates": [],
        "evaluations": [],
        "actions": [],
        "artifacts": [],
        "progress_markers": [],
        "flag_candidates": [],
        "decision": None,
        "goal_update": None,
        "refusal": None,
    }


class _RecordingExecutor:
    def __init__(self) -> None:
        self.timeouts: list[float | None] = []

    def run(self, command, *, cwd, timeout, on_stdout_line):
        del cwd, on_stdout_line
        self.timeouts.append(timeout)
        _output_path(command).write_text(
            json.dumps(_payload()),
            encoding="utf-8",
        )
        return ProcessOutcome(0, "", 0.01)


class _RecordingLimiter:
    def __init__(self, delegate) -> None:
        self.delegate = delegate
        self._lock = threading.Lock()
        self.requested_timeouts: list[float | None] = []

    def slot(self, timeout=None, *, cancel_event=None):
        with self._lock:
            self.requested_timeouts.append(timeout)
        return self.delegate.slot(
            timeout,
            cancel_event=cancel_event,
        )

    def snapshot(self):
        return self.delegate.snapshot()


class _ForbiddenExecutor:
    def __init__(self) -> None:
        self.calls = 0

    def run(self, command, *, cwd, timeout, on_stdout_line):
        del command, cwd, timeout, on_stdout_line
        self.calls += 1
        raise AssertionError("expired provider waiter executed")


class _DeadlineExecutor:
    def run(self, command, *, cwd, timeout, on_stdout_line):
        del command, cwd, on_stdout_line
        assert timeout is not None
        time.sleep(timeout + 0.02)
        return ProcessOutcome(
            124,
            "deadline elapsed",
            timeout + 0.02,
            timed_out=True,
        )


class _FakeMonotonicClock:
    def __init__(self, value: float) -> None:
        self._value = value
        self._lock = threading.Lock()

    def __call__(self) -> float:
        with self._lock:
            return self._value

    def advance(self, seconds: float) -> None:
        with self._lock:
            self._value += seconds


class BudgetTests(unittest.TestCase):
    def test_absolute_and_accounting_bounds_use_the_stricter_value(self) -> None:
        now = 1_800_000_000.0
        deadline = deadline_utc_after(120, now_epoch=now)
        budget = Budget(
            deadline_utc=deadline,
            allocated_seconds=100,
            spent_seconds=25,
        )

        self.assertAlmostEqual(deadline_epoch(deadline), now + 120, places=5)
        self.assertEqual(remaining_seconds(budget, now_epoch=now), 75)
        self.assertEqual(
            remaining_seconds(budget, now_epoch=now + 80),
            40,
        )
        with self.assertRaises(BudgetExhausted):
            require_remaining_seconds(budget, now_epoch=now + 121)

    def test_deadline_helper_rejects_unrepresentable_timestamp(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "outside the supported datetime range",
        ):
            deadline_utc_after(1e308, now_epoch=0)

    def test_provider_queue_wait_is_inside_the_absolute_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            limiter = FifoModelCallLimiter(1)
            executor = _ForbiddenExecutor()
            runner = BatchRunner(
                process_executor=executor,
                limiter=limiter,
                limiter_wait_timeout=5,
                max_schema_retries=0,
            )
            invocation = BatchInvocation(
                "deadline-wait",
                Role.RECON,
                "inspect",
                root,
                root / "output",
                timeout_seconds=30,
                deadline_epoch_seconds=time.time() + 0.12,
            )

            started = time.monotonic()
            with limiter.slot() as model_call_slot:
                model_call_slot.acquire()
                result = runner.run(invocation)
            elapsed = time.monotonic() - started

        self.assertLess(elapsed, 0.6)
        self.assertFalse(result.success)
        self.assertTrue(result.attempts[-1].timed_out)
        self.assertEqual(
            [failure.kind for failure in result.failures],
            ["challenge_budget_expired"],
        )
        self.assertFalse(result.failures[0].retryable)
        self.assertEqual(executor.calls, 0)
        self.assertEqual(limiter.snapshot().active, 0)
        self.assertEqual(limiter.snapshot().waiting, 0)

    def test_file_limited_wave_waits_until_challenge_deadline_then_gets_full_timeout(
        self,
    ) -> None:
        fake_monotonic = _FakeMonotonicClock(100.0)
        executor = _RecordingExecutor()
        completed = []
        failures: list[BaseException] = []

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            file_limiter = FileFifoModelCallLimiter(
                root / "model-calls.json",
                1,
                poll_interval=0.005,
            )
            limiter = _RecordingLimiter(file_limiter)
            runner = BatchRunner(
                process_executor=executor,
                limiter=limiter,
                # Deliberately shorter than the simulated queue wait. A hard
                # challenge deadline, not this fallback, governs admission.
                limiter_wait_timeout=1,
                max_schema_retries=0,
            )
            invocations = tuple(
                BatchInvocation(
                    f"queued-role-{number}",
                    Role.RECON,
                    "inspect",
                    root,
                    root / f"run-{number}",
                    timeout_seconds=10,
                    deadline_monotonic_seconds=200,
                )
                for number in range(3)
            )
            wave = BatchWave.create("queued-wave", invocations)

            def run_wave() -> None:
                try:
                    completed.append(BatchWaveRunner(runner).run(wave))
                except BaseException as error:
                    failures.append(error)

            with mock.patch.object(
                runner_module.time,
                "monotonic",
                side_effect=fake_monotonic,
            ):
                with file_limiter.slot() as external_holder:
                    external_holder.acquire()
                    thread = threading.Thread(target=run_wave)
                    thread.start()
                    snapshot = limiter.snapshot()
                    for _ in range(400):
                        if snapshot.waiting == 3:
                            break
                        threading.Event().wait(0.005)
                        snapshot = limiter.snapshot()
                    self.assertEqual(len(wave.invocations), 3)
                    self.assertEqual(snapshot.active, 1)
                    self.assertEqual(snapshot.waiting, 3)
                    self.assertEqual(executor.timeouts, [])
                    self.assertEqual(
                        limiter.requested_timeouts,
                        [100, 100, 100],
                    )

                    # This exceeds both the fallback admission timeout and the
                    # execution timeout, while remaining inside the challenge.
                    fake_monotonic.advance(20)
                thread.join(timeout=5)

            self.assertFalse(thread.is_alive())
            self.assertEqual(failures, [])
            self.assertEqual(len(completed), 1)
            results = completed[0]
            self.assertEqual(len(results), 3)
            self.assertTrue(all(result.success for result in results))
            self.assertEqual(executor.timeouts, [10, 10, 10])
            self.assertTrue(
                all(
                    result.timing.provider_wait_seconds >= 20
                    for result in results
                )
            )
            self.assertEqual(limiter.snapshot().active, 0)
            self.assertEqual(limiter.snapshot().waiting, 0)

    def test_file_limited_wave_still_stops_at_challenge_deadline(self) -> None:
        fake_monotonic = _FakeMonotonicClock(100.0)
        executor = _RecordingExecutor()
        completed = []
        failures: list[BaseException] = []

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            file_limiter = FileFifoModelCallLimiter(
                root / "model-calls.json",
                1,
                poll_interval=0.005,
            )
            limiter = _RecordingLimiter(file_limiter)
            runner = BatchRunner(
                process_executor=executor,
                limiter=limiter,
                limiter_wait_timeout=60,
                max_schema_retries=0,
            )
            wave = BatchWave.create(
                "expiring-queued-wave",
                tuple(
                    BatchInvocation(
                        f"expiring-role-{number}",
                        Role.RECON,
                        "inspect",
                        root,
                        root / f"run-{number}",
                        timeout_seconds=30,
                        deadline_monotonic_seconds=110,
                    )
                    for number in range(3)
                ),
            )

            def run_wave() -> None:
                try:
                    completed.append(BatchWaveRunner(runner).run(wave))
                except BaseException as error:
                    failures.append(error)

            with mock.patch.object(
                runner_module.time,
                "monotonic",
                side_effect=fake_monotonic,
            ):
                with file_limiter.slot() as external_holder:
                    external_holder.acquire()
                    thread = threading.Thread(target=run_wave)
                    thread.start()
                    snapshot = limiter.snapshot()
                    for _ in range(400):
                        if snapshot.waiting == 3:
                            break
                        threading.Event().wait(0.005)
                        snapshot = limiter.snapshot()
                    self.assertEqual(snapshot.active, 1)
                    self.assertEqual(snapshot.waiting, 3)
                    self.assertEqual(executor.timeouts, [])
                    self.assertEqual(
                        limiter.requested_timeouts,
                        [10, 10, 10],
                    )
                    fake_monotonic.advance(11)
                thread.join(timeout=5)

            self.assertFalse(thread.is_alive())
            self.assertEqual(failures, [])
            self.assertEqual(len(completed), 1)
            results = completed[0]
            self.assertEqual(executor.timeouts, [])
            self.assertTrue(all(not result.success for result in results))
            self.assertTrue(
                all(
                    [failure.kind for failure in result.failures]
                    == ["challenge_budget_expired"]
                    for result in results
                )
            )
            self.assertEqual(limiter.snapshot().active, 0)
            self.assertEqual(limiter.snapshot().waiting, 0)

    def test_process_finishing_after_deadline_has_one_budget_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            invocation = BatchInvocation(
                "deadline-process-expired",
                Role.RECON,
                "inspect",
                root,
                root / "output",
                timeout_seconds=30,
                deadline_epoch_seconds=time.time() + 0.06,
            )
            result = BatchRunner(
                process_executor=_DeadlineExecutor(),
                max_schema_retries=0,
            ).run(invocation)

        self.assertFalse(result.success)
        self.assertTrue(result.attempts[-1].timed_out)
        self.assertEqual(
            [failure.kind for failure in result.failures],
            ["challenge_budget_expired"],
        )
        self.assertFalse(result.failures[0].retryable)

    def test_host_result_processing_after_exact_deadline_is_invalidated(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            deadline = time.monotonic() + 0.2
            invocation = BatchInvocation(
                "deadline-host-postprocess",
                Role.RECON,
                "inspect",
                root,
                root / "output",
                timeout_seconds=30,
                deadline_monotonic_seconds=deadline,
            )
            real_read_output = runner_module._read_output

            def delayed_read_output(*args, **kwargs):
                output = real_read_output(*args, **kwargs)
                time.sleep(0.25)
                return output

            with mock.patch.object(
                runner_module,
                "_read_output",
                side_effect=delayed_read_output,
            ):
                result = BatchRunner(
                    process_executor=_RecordingExecutor(),
                    max_schema_retries=0,
                ).run(invocation)

        self.assertFalse(result.success)
        self.assertIsNone(result.output)
        self.assertEqual(result.deadline_monotonic_seconds, deadline)
        self.assertEqual(result.attempts[-1].returncode, 124)
        self.assertTrue(result.attempts[-1].timed_out)
        self.assertFalse(result.attempts[-1].validation.valid)
        self.assertEqual(
            [
                failure.kind
                for failure in result.failures
                if failure.kind == "challenge_budget_expired"
            ],
            ["challenge_budget_expired"],
        )

    def test_process_timeout_is_clamped_to_remaining_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executor = _RecordingExecutor()
            invocation = BatchInvocation(
                "deadline-process",
                Role.RECON,
                "inspect",
                root,
                root / "output",
                timeout_seconds=30,
                deadline_epoch_seconds=time.time() + 0.5,
            )
            result = BatchRunner(
                process_executor=executor,
                max_schema_retries=0,
            ).run(invocation)

        self.assertTrue(result.success, result.validation.errors)
        self.assertEqual(len(executor.timeouts), 1)
        self.assertIsNotNone(executor.timeouts[0])
        assert executor.timeouts[0] is not None
        self.assertGreater(executor.timeouts[0], 0)
        self.assertLessEqual(executor.timeouts[0], 0.5)

    def test_wall_clock_rollback_does_not_extend_process_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executor = _RecordingExecutor()
            invocation = BatchInvocation(
                "deadline-clock-anchor",
                Role.RECON,
                "inspect",
                root,
                root / "output",
                timeout_seconds=30,
                deadline_epoch_seconds=110,
            )
            wall_clock_calls = 0

            def wall_clock() -> float:
                nonlocal wall_clock_calls
                wall_clock_calls += 1
                return 100 if wall_clock_calls == 1 else 90

            with mock.patch(
                "ctf_os.codex.runner.time.time",
                side_effect=wall_clock,
            ):
                result = BatchRunner(
                    process_executor=executor,
                    max_schema_retries=0,
                ).run(invocation)

        self.assertTrue(result.success, result.validation.errors)
        self.assertEqual(len(executor.timeouts), 1)
        timeout = executor.timeouts[0]
        self.assertIsNotNone(timeout)
        assert timeout is not None
        self.assertGreater(timeout, 9)
        self.assertLessEqual(timeout, 10)

    def test_cancelled_provider_wait_is_distinct_and_cleans_fifo(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            limiter = FifoModelCallLimiter(1)
            executor = _ForbiddenExecutor()
            runner = BatchRunner(
                process_executor=executor,
                limiter=limiter,
                max_schema_retries=0,
            )
            invocation = BatchInvocation(
                "cancelled-wait",
                Role.RECON,
                "inspect",
                root,
                root / "output",
                timeout_seconds=30,
                deadline_monotonic_seconds=time.monotonic() + 30,
            )
            cancel_event = threading.Event()
            results = []

            def wait_for_slot() -> None:
                results.append(
                    runner.run(
                        invocation,
                        _cancel_event=cancel_event,
                    )
                )

            with limiter.slot() as model_call_slot:
                model_call_slot.acquire()
                waiter = threading.Thread(target=wait_for_slot)
                waiter.start()
                wait_deadline = time.monotonic() + 2
                while (
                    limiter.snapshot().waiting != 1
                    and time.monotonic() < wait_deadline
                ):
                    time.sleep(0.005)
                self.assertEqual(limiter.snapshot().waiting, 1)
                cancel_event.set()
                waiter.join(timeout=2)
                self.assertFalse(waiter.is_alive())

        self.assertEqual(len(results), 1)
        self.assertEqual(
            [failure.kind for failure in results[0].failures],
            ["model_call_cancelled"],
        )
        self.assertFalse(results[0].failures[0].retryable)
        self.assertEqual(executor.calls, 0)
        self.assertEqual(limiter.snapshot().active, 0)
        self.assertEqual(limiter.snapshot().waiting, 0)

    def test_fifo_checks_timeout_before_late_acquisition(self) -> None:
        limiter = FifoModelCallLimiter(1)
        with mock.patch(
            "ctf_os.codex.limiter.time.monotonic",
            side_effect=(0.0, 2.0),
        ), self.assertRaises(ModelCallLimitTimeout):
            with limiter.slot(timeout=1) as model_call_slot:
                model_call_slot.acquire()
                self.fail("expired ticket acquired a slot")

        self.assertEqual(limiter.snapshot().active, 0)
        self.assertEqual(limiter.snapshot().waiting, 0)

    def test_zero_timeout_gets_one_immediate_fifo_check(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            limiters = (
                FifoModelCallLimiter(1),
                FileFifoModelCallLimiter(
                    Path(temporary) / "limiter.json",
                    1,
                    poll_interval=0.005,
                ),
            )
            for limiter in limiters:
                with self.subTest(limiter=type(limiter).__name__):
                    with limiter.slot(timeout=0) as model_call_slot:
                        model_call_slot.acquire()
                        self.assertEqual(limiter.snapshot().active, 1)
                    with limiter.slot() as model_call_slot:
                        model_call_slot.acquire()
                        with self.assertRaises(ModelCallLimitTimeout):
                            with limiter.slot(
                                timeout=0
                            ) as unavailable_slot:
                                unavailable_slot.acquire()
                                self.fail(
                                    "unavailable zero-timeout slot acquired"
                                )
                        snapshot = limiter.snapshot()
                        self.assertEqual(snapshot.active, 1)
                        self.assertEqual(snapshot.waiting, 0)
                    snapshot = limiter.snapshot()
                    self.assertEqual(snapshot.active, 0)
                    self.assertEqual(snapshot.waiting, 0)


if __name__ == "__main__":
    unittest.main()
