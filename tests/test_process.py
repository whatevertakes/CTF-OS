from __future__ import annotations

import inspect
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import ctf_os.process as process_module
from ctf_os.process import run_bounded_interactive


@unittest.skipUnless(
    os.name == "posix" and Path("/proc").is_dir(),
    "requires Linux process groups",
)
class InteractiveProcessTests(unittest.TestCase):
    def test_already_expired_deadline_does_not_spawn(self) -> None:
        with patch.object(
            process_module,
            "_popen_with_constructor_cleanup",
        ) as popen:
            result = run_bounded_interactive(
                (sys.executable, "-c", "raise SystemExit(0)"),
                cwd=Path.cwd(),
                env=os.environ,
                timeout=30,
                deadline_monotonic_seconds=time.monotonic() - 1,
            )

        self.assertEqual(result.returncode, 124)
        popen.assert_not_called()

    def test_slow_popen_handoff_consumes_the_issued_deadline(
        self,
    ) -> None:
        spawned_pids: list[int] = []
        real_helper = process_module._popen_with_constructor_cleanup

        def delayed_helper(*args, **kwargs):
            process = real_helper(*args, **kwargs)
            spawned_pids.append(process.pid)
            time.sleep(0.15)
            return process

        deadline = time.monotonic() + 0.05
        started = time.monotonic()
        with patch.object(
            process_module,
            "_popen_with_constructor_cleanup",
            side_effect=delayed_helper,
        ):
            result = run_bounded_interactive(
                (
                    sys.executable,
                    "-c",
                    "import time;time.sleep(30)",
                ),
                cwd=Path.cwd(),
                env=os.environ,
                timeout=30,
                terminate_grace_seconds=0.1,
                deadline_monotonic_seconds=deadline,
            )
        elapsed = time.monotonic() - started

        self.assertEqual(result.returncode, 124)
        self.assertEqual(
            result.stderr,
            b"challenge wall-clock budget expired",
        )
        self.assertLess(elapsed, 0.8)
        self.assertEqual(len(spawned_pids), 1)
        self.assertFalse(
            Path(f"/proc/{spawned_pids[0]}").exists()
        )

    def test_caller_store_interrupt_reaps_pending_process_handoff(
        self,
    ) -> None:
        interruption = KeyboardInterrupt(
            "synthetic caller store interrupt"
        )
        spawned_pids: list[int] = []
        signals: list[tuple[int, int]] = []
        real_killpg = os.killpg
        real_helper = process_module._popen_with_constructor_cleanup

        def interrupt_after_helper_return(*args, **kwargs):
            process = real_helper(*args, **kwargs)
            pending = kwargs["pending_handoff"]
            self.assertIs(pending[0], process)
            spawned_pids.append(process.pid)
            raise interruption

        def record_killpg(process_group: int, sent_signal: int) -> None:
            if sent_signal in {signal.SIGTERM, signal.SIGKILL}:
                signals.append((process_group, sent_signal))
            real_killpg(process_group, sent_signal)

        script = "import time;time.sleep(30)"
        with (
            patch.object(
                process_module.os,
                "killpg",
                side_effect=record_killpg,
            ),
            patch.object(
                process_module,
                "_popen_with_constructor_cleanup",
                side_effect=interrupt_after_helper_return,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            run_bounded_interactive(
                (sys.executable, "-c", script),
                cwd=Path.cwd(),
                env=os.environ,
                timeout=30,
                terminate_grace_seconds=0.1,
            )

        self.assertIs(raised.exception, interruption)
        self.assertEqual(len(spawned_pids), 1)
        child_pid = spawned_pids[0]
        self.assertEqual(
            signals,
            [
                (child_pid, signal.SIGTERM),
                (child_pid, signal.SIGKILL),
            ],
        )
        self.assertFalse(Path(f"/proc/{child_pid}").exists())

    def test_constructor_return_interrupt_reaps_partial_process_group(
        self,
    ) -> None:
        interruption = KeyboardInterrupt(
            "synthetic constructor return interrupt"
        )
        spawned_pids: list[int] = []
        signals: list[tuple[int, int]] = []
        real_killpg = os.killpg
        helper = process_module._popen_with_constructor_cleanup
        source_lines, source_start = inspect.getsourcelines(helper)
        return_line = source_start + next(
            offset
            for offset, line in enumerate(source_lines)
            if line.strip() == "return process"
        )
        armed = True

        def interrupt_on_return(frame, event, _argument):
            nonlocal armed
            if (
                armed
                and frame.f_code is helper.__code__
                and event == "line"
                and frame.f_lineno == return_line
            ):
                armed = False
                spawned_pids.append(frame.f_locals["process"].pid)
                raise interruption
            return interrupt_on_return

        def record_killpg(process_group: int, sent_signal: int) -> None:
            if sent_signal in {signal.SIGTERM, signal.SIGKILL}:
                signals.append((process_group, sent_signal))
            real_killpg(process_group, sent_signal)

        previous_trace = sys.gettrace()
        script = "import time;time.sleep(30)"
        with (
            patch.object(
                process_module.os,
                "killpg",
                side_effect=record_killpg,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            sys.settrace(interrupt_on_return)
            try:
                run_bounded_interactive(
                    (sys.executable, "-c", script),
                    cwd=Path.cwd(),
                    env=os.environ,
                    timeout=30,
                    terminate_grace_seconds=0.1,
                )
            finally:
                sys.settrace(previous_trace)

        self.assertIs(raised.exception, interruption)
        self.assertEqual(len(spawned_pids), 1)
        child_pid = spawned_pids[0]
        self.assertEqual(
            signals,
            [
                (child_pid, signal.SIGTERM),
                (child_pid, signal.SIGKILL),
            ],
        )
        self.assertFalse(Path(f"/proc/{child_pid}").exists())

    def test_constructor_interrupt_reaps_partial_process_group(
        self,
    ) -> None:
        interruption = KeyboardInterrupt(
            "synthetic interactive constructor interrupt"
        )
        spawned_pids: list[int] = []
        signals: list[tuple[int, int]] = []
        real_execute_child = subprocess.Popen._execute_child
        real_killpg = os.killpg

        def interrupt_after_execute(process, *args, **kwargs):
            real_execute_child(process, *args, **kwargs)
            spawned_pids.append(process.pid)
            raise interruption

        def record_killpg(process_group: int, sent_signal: int) -> None:
            if sent_signal in {signal.SIGTERM, signal.SIGKILL}:
                signals.append((process_group, sent_signal))
            real_killpg(process_group, sent_signal)

        script = "import time;time.sleep(30)"
        with (
            patch.object(
                subprocess.Popen,
                "_execute_child",
                new=interrupt_after_execute,
            ),
            patch.object(
                process_module.os,
                "killpg",
                side_effect=record_killpg,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            run_bounded_interactive(
                (sys.executable, "-c", script),
                cwd=Path.cwd(),
                env=os.environ,
                timeout=30,
                terminate_grace_seconds=0.1,
            )

        self.assertIs(raised.exception, interruption)
        self.assertEqual(len(spawned_pids), 1)
        child_pid = spawned_pids[0]
        self.assertEqual(
            signals,
            [
                (child_pid, signal.SIGTERM),
                (child_pid, signal.SIGKILL),
            ],
        )
        deadline = time.monotonic() + 1
        while (
            Path(f"/proc/{child_pid}").exists()
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        self.assertFalse(Path(f"/proc/{child_pid}").exists())

    def _assert_post_fork_pre_pid_store_interrupt_reaps_exact_child(
        self,
        *,
        sent_signal: int,
        expected_exception: type[BaseException],
    ) -> None:
        """A control exception cannot orphan a pre-``self.pid`` child."""

        real_fork_exec = subprocess._fork_exec
        real_killpg = os.killpg
        fork_returned = threading.Event()
        release_pid_store = threading.Event()
        spawned_pids: list[int] = []
        signals: list[tuple[int, int]] = []

        def delay_pid_store(*args, **kwargs):
            pid = real_fork_exec(*args, **kwargs)
            spawned_pids.append(pid)
            fork_returned.set()
            if not release_pid_store.wait(2):
                raise AssertionError("pid STORE release timed out")
            return pid

        def interrupt_parent() -> None:
            if not fork_returned.wait(2):
                return
            os.kill(os.getpid(), sent_signal)
            # Keep the constructor exactly between _fork_exec return and
            # Popen's later STORE_ATTR until the parent observes the exception.
            time.sleep(0.02)
            release_pid_store.set()

        def record_killpg(process_group: int, sent_signal: int) -> None:
            if sent_signal in {signal.SIGTERM, signal.SIGKILL}:
                signals.append((process_group, sent_signal))
            real_killpg(process_group, sent_signal)

        interrupter = threading.Thread(
            target=interrupt_parent,
            name="ctfos-test-popen-pid-store-interrupt",
            daemon=True,
        )
        interrupter.start()
        survived = False
        try:
            with (
                patch.object(
                    subprocess,
                    "_fork_exec",
                    new=delay_pid_store,
                ),
                patch.object(
                    process_module.os,
                    "killpg",
                    side_effect=record_killpg,
                ),
                self.assertRaises(expected_exception),
            ):
                run_bounded_interactive(
                    (
                        sys.executable,
                        "-c",
                        "import signal,time;"
                        "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                        "time.sleep(30)",
                    ),
                    cwd=Path.cwd(),
                    env=os.environ,
                    timeout=30,
                    terminate_grace_seconds=0.1,
                )
            self.assertEqual(len(spawned_pids), 1)
            child_pid = spawned_pids[0]
            survived = Path(f"/proc/{child_pid}").exists()
        finally:
            release_pid_store.set()
            interrupter.join(timeout=1)
            for child_pid in spawned_pids:
                if Path(f"/proc/{child_pid}").exists():
                    try:
                        real_killpg(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        os.waitpid(child_pid, 0)
                    except ChildProcessError:
                        pass

        self.assertFalse(survived)
        child_pid = spawned_pids[0]
        self.assertEqual(
            signals,
            [
                (child_pid, signal.SIGTERM),
                (child_pid, signal.SIGKILL),
            ],
        )

    def test_post_fork_pre_pid_store_interrupt_reaps_exact_child(
        self,
    ) -> None:
        self._assert_post_fork_pre_pid_store_interrupt_reaps_exact_child(
            sent_signal=signal.SIGINT,
            expected_exception=KeyboardInterrupt,
        )

    def test_post_fork_pre_pid_store_system_exit_reaps_exact_child(
        self,
    ) -> None:
        previous_handler = signal.getsignal(signal.SIGUSR1)

        def raise_system_exit(
            _signal_number: int,
            _frame: object,
        ) -> None:
            raise SystemExit(42)

        signal.signal(signal.SIGUSR1, raise_system_exit)
        try:
            self._assert_post_fork_pre_pid_store_interrupt_reaps_exact_child(
                sent_signal=signal.SIGUSR1,
                expected_exception=SystemExit,
            )
        finally:
            signal.signal(signal.SIGUSR1, previous_handler)

    def test_timeout_cleanup_interrupt_retries_and_reaps_process_group(
        self,
    ) -> None:
        interruption = KeyboardInterrupt(
            "synthetic timeout cleanup interrupt"
        )
        cleanup_pids: list[int] = []
        signals: list[tuple[int, int]] = []
        real_terminate = process_module._terminate_process_group
        real_killpg = os.killpg

        def interrupt_first_cleanup(
            process,
            *,
            terminate_grace_seconds: float,
        ) -> None:
            cleanup_pids.append(process.pid)
            if len(cleanup_pids) == 1:
                raise interruption
            real_terminate(
                process,
                terminate_grace_seconds=terminate_grace_seconds,
            )

        def record_killpg(process_group: int, sent_signal: int) -> None:
            if sent_signal in {signal.SIGTERM, signal.SIGKILL}:
                signals.append((process_group, sent_signal))
            real_killpg(process_group, sent_signal)

        script = "import time;time.sleep(30)"
        with (
            patch.object(
                process_module,
                "_terminate_process_group",
                side_effect=interrupt_first_cleanup,
            ),
            patch.object(
                process_module.os,
                "killpg",
                side_effect=record_killpg,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            run_bounded_interactive(
                (sys.executable, "-c", script),
                cwd=Path.cwd(),
                env=os.environ,
                timeout=0.01,
                terminate_grace_seconds=0.1,
            )

        self.assertIs(raised.exception, interruption)
        self.assertEqual(len(cleanup_pids), 2)
        child_pid = cleanup_pids[0]
        self.assertEqual(cleanup_pids, [child_pid, child_pid])
        self.assertEqual(
            signals,
            [
                (child_pid, signal.SIGTERM),
                (child_pid, signal.SIGKILL),
            ],
        )
        self.assertFalse(Path(f"/proc/{child_pid}").exists())

    def test_immediate_post_spawn_interrupt_reaps_process_group(
        self,
    ) -> None:
        interruption = KeyboardInterrupt("synthetic post-spawn interrupt")
        spawned_pids: list[int] = []
        real_popen = process_module.subprocess.Popen

        def interrupt_on_first_wait(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            spawned_pids.append(process.pid)
            real_wait = process.wait
            interrupted = False

            def wait(*wait_args, **wait_kwargs):
                nonlocal interrupted
                if not interrupted:
                    interrupted = True
                    raise interruption
                return real_wait(*wait_args, **wait_kwargs)

            process.wait = wait
            return process

        script = (
            "import signal,time;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "time.sleep(30)"
        )
        with (
            patch.object(
                process_module.subprocess,
                "Popen",
                side_effect=interrupt_on_first_wait,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            run_bounded_interactive(
                (sys.executable, "-c", script),
                cwd=Path.cwd(),
                env=os.environ,
                timeout=30,
                terminate_grace_seconds=0.1,
            )

        self.assertIs(raised.exception, interruption)
        self.assertEqual(len(spawned_pids), 1)
        process_path = Path(f"/proc/{spawned_pids[0]}")
        deadline = time.monotonic() + 1
        while process_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertFalse(process_path.exists())

    def test_interrupt_cleanup_retries_transient_error_until_reaped(
        self,
    ) -> None:
        interruption = KeyboardInterrupt(
            "synthetic interactive cleanup retry"
        )
        spawned_pids: list[int] = []
        cleanup_pids: list[int] = []
        real_popen = process_module.subprocess.Popen
        real_terminate = process_module._terminate_process_group

        def interrupt_on_first_wait(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            spawned_pids.append(process.pid)
            real_wait = process.wait
            interrupted = False

            def wait(*wait_args, **wait_kwargs):
                nonlocal interrupted
                if not interrupted:
                    interrupted = True
                    raise interruption
                return real_wait(*wait_args, **wait_kwargs)

            process.wait = wait
            return process

        def fail_first_cleanup(
            process,
            *,
            terminate_grace_seconds: float,
        ) -> None:
            cleanup_pids.append(process.pid)
            if len(cleanup_pids) == 1:
                raise OSError("synthetic transient cleanup failure")
            real_terminate(
                process,
                terminate_grace_seconds=terminate_grace_seconds,
            )

        script = (
            "import signal,time;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "time.sleep(30)"
        )
        with (
            patch.object(
                process_module.subprocess,
                "Popen",
                side_effect=interrupt_on_first_wait,
            ),
            patch.object(
                process_module,
                "_terminate_process_group",
                side_effect=fail_first_cleanup,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            run_bounded_interactive(
                (sys.executable, "-c", script),
                cwd=Path.cwd(),
                env=os.environ,
                timeout=30,
                terminate_grace_seconds=0.1,
            )

        self.assertIs(raised.exception, interruption)
        self.assertEqual(len(spawned_pids), 1)
        self.assertEqual(
            cleanup_pids,
            [spawned_pids[0], spawned_pids[0]],
        )
        self.assertFalse(Path(f"/proc/{spawned_pids[0]}").exists())
        self.assertTrue(
            any(
                "cleanup recovered after 2 attempts" in note
                for note in interruption.__notes__
            )
        )

    def test_interrupt_cleanup_treats_one_shot_poll_error_as_live(
        self,
    ) -> None:
        interruption = KeyboardInterrupt(
            "synthetic interrupt before cleanup poll"
        )
        spawned_pids: list[int] = []
        real_popen = process_module.subprocess.Popen

        def interrupt_then_fail_first_poll(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            spawned_pids.append(process.pid)
            real_wait = process.wait
            real_poll = process.poll
            wait_interrupted = False
            poll_failed = False

            def wait(*wait_args, **wait_kwargs):
                nonlocal wait_interrupted
                if not wait_interrupted:
                    wait_interrupted = True
                    raise interruption
                return real_wait(*wait_args, **wait_kwargs)

            def poll():
                nonlocal poll_failed
                if not poll_failed:
                    poll_failed = True
                    raise OSError("synthetic one-shot poll error")
                return real_poll()

            process.wait = wait
            process.poll = poll
            return process

        script = (
            "import signal,time;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "time.sleep(30)"
        )
        with (
            patch.object(
                process_module.subprocess,
                "Popen",
                side_effect=interrupt_then_fail_first_poll,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            run_bounded_interactive(
                (sys.executable, "-c", script),
                cwd=Path.cwd(),
                env=os.environ,
                timeout=30,
                terminate_grace_seconds=0.1,
            )

        self.assertIs(raised.exception, interruption)
        self.assertEqual(len(spawned_pids), 1)
        self.assertFalse(Path(f"/proc/{spawned_pids[0]}").exists())

    def test_interrupt_cleanup_retries_one_shot_sigterm_error(
        self,
    ) -> None:
        interruption = KeyboardInterrupt(
            "synthetic interrupt before cleanup signal"
        )
        spawned_pids: list[int] = []
        sent_signals: list[int] = []
        real_popen = process_module.subprocess.Popen
        real_killpg = process_module.os.killpg
        failed_term = False

        def interrupt_on_first_wait(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            spawned_pids.append(process.pid)
            real_wait = process.wait
            wait_interrupted = False

            def wait(*wait_args, **wait_kwargs):
                nonlocal wait_interrupted
                if not wait_interrupted:
                    wait_interrupted = True
                    raise interruption
                return real_wait(*wait_args, **wait_kwargs)

            process.wait = wait
            return process

        def fail_first_term(process_group: int, sent_signal: int) -> None:
            nonlocal failed_term
            if sent_signal in {signal.SIGTERM, signal.SIGKILL}:
                sent_signals.append(sent_signal)
            if sent_signal == signal.SIGTERM and not failed_term:
                failed_term = True
                raise OSError("synthetic one-shot SIGTERM error")
            real_killpg(process_group, sent_signal)

        script = (
            "import signal,time;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "time.sleep(30)"
        )
        with (
            patch.object(
                process_module.subprocess,
                "Popen",
                side_effect=interrupt_on_first_wait,
            ),
            patch.object(
                process_module.os,
                "killpg",
                side_effect=fail_first_term,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            run_bounded_interactive(
                (sys.executable, "-c", script),
                cwd=Path.cwd(),
                env=os.environ,
                timeout=30,
                terminate_grace_seconds=0.1,
            )

        self.assertIs(raised.exception, interruption)
        self.assertEqual(sent_signals.count(signal.SIGTERM), 2)
        self.assertIn(signal.SIGKILL, sent_signals)
        self.assertEqual(len(spawned_pids), 1)
        self.assertFalse(Path(f"/proc/{spawned_pids[0]}").exists())

    def test_signal_retry_lookup_preserves_first_interrupt_identity(
        self,
    ) -> None:
        interruption = KeyboardInterrupt(
            "synthetic signal handoff interrupt"
        )
        term_attempts = 0

        class FinishedProcess:
            pid = 2_000_000_001

            @staticmethod
            def poll() -> int:
                return 0

            @staticmethod
            def wait(*, timeout: float) -> int:
                del timeout
                return 0

        def interrupt_then_disappear(
            _process_group: int,
            sent_signal: int,
        ) -> None:
            nonlocal term_attempts
            if sent_signal == signal.SIGTERM:
                term_attempts += 1
                if term_attempts == 1:
                    raise interruption
            raise ProcessLookupError

        with (
            patch.object(
                process_module.os,
                "killpg",
                side_effect=interrupt_then_disappear,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            process_module._terminate_process_group(
                FinishedProcess(),  # type: ignore[arg-type]
                terminate_grace_seconds=0.01,
            )

        self.assertIs(raised.exception, interruption)
        self.assertEqual(term_attempts, 2)

    def test_reap_refreshes_the_final_process_group_identity(self) -> None:
        class ReapedProcess:
            pid = 2_000_000_002

            def __init__(self) -> None:
                self.waited = False

            def poll(self) -> int | None:
                return 0 if self.waited else None

            def wait(self, *, timeout: float) -> int:
                del timeout
                self.waited = True
                return 0

        process = ReapedProcess()

        def group_exists_until_wait(
            _process_group: int,
            sent_signal: int,
        ) -> None:
            if sent_signal == 0 and process.waited:
                raise ProcessLookupError

        with patch.object(
            process_module.os,
            "killpg",
            side_effect=group_exists_until_wait,
        ):
            process_module._terminate_process_group(
                process,  # type: ignore[arg-type]
                terminate_grace_seconds=0.001,
            )

        self.assertTrue(process.waited)

    def test_published_cleanup_receipt_blocks_return_boundary_resignal(
        self,
    ) -> None:
        interruption = KeyboardInterrupt(
            "synthetic cleanup success return interrupt"
        )

        class ReapedProcess:
            pid = 2_000_000_003

            def __init__(self) -> None:
                self.returncode: int | None = None

            def poll(self) -> int | None:
                return self.returncode

            def wait(self, *, timeout: float) -> int:
                del timeout
                self.returncode = 0
                return 0

        process = ReapedProcess()
        owner = process_module._ProcessGroupCleanup(
            process,  # type: ignore[arg-type]
            terminate_grace_seconds=0.001,
        )
        generation = "original"
        signals: list[tuple[str, int]] = []

        def modeled_killpg(
            _process_group: int,
            sent_signal: int,
        ) -> None:
            if sent_signal == 0:
                raise ProcessLookupError
            signals.append((generation, sent_signal))

        target_code = process_module._terminate_process_group.__code__
        injected = False

        def interrupt_success_return(frame, event, _argument):
            nonlocal generation, injected
            if (
                frame.f_code is target_code
                and event == "return"
                and not injected
            ):
                injected = True
                # Model the kernel reusing the now-reaped numeric PGID before
                # the outer cleanup retry regains control.
                generation = "replacement"
                sys.settrace(None)
                raise interruption
            return interrupt_success_return

        previous_trace = sys.gettrace()
        try:
            with patch.object(
                process_module.os,
                "killpg",
                side_effect=modeled_killpg,
            ):
                sys.settrace(interrupt_success_return)
                propagated = (
                    process_module
                    ._retry_process_group_cleanup_until_confirmed(
                        owner,
                        active_error=OSError(
                            "synthetic original process error"
                        ),
                    )
                )
        finally:
            sys.settrace(previous_trace)

        self.assertTrue(injected)
        self.assertTrue(owner.confirmed)
        self.assertIs(propagated, interruption)
        self.assertEqual(
            signals,
            [
                ("original", signal.SIGTERM),
                ("original", signal.SIGKILL),
            ],
        )

    def test_parent_only_interrupt_terminates_and_reaps_process_group(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pid_path = root / "leader.pid"

            def interrupt_parent() -> None:
                deadline = time.monotonic() + 2
                while (
                    not pid_path.exists()
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.01)
                if pid_path.exists():
                    os.kill(os.getpid(), signal.SIGINT)

            interrupter = threading.Thread(
                target=interrupt_parent,
                name="ctfos-test-live-interrupt",
                daemon=True,
            )
            interrupter.start()
            script = (
                "import os,pathlib,subprocess,sys,time;"
                "child=subprocess.Popen([sys.executable,'-c',"
                "'import signal,time;"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                "time.sleep(30)']);"
                "pathlib.Path(sys.argv[1]).write_text("
                "f'{os.getpid()} {child.pid}');"
                "time.sleep(30)"
            )
            leader_pid: int | None = None
            descendant_pid: int | None = None
            survived_interrupt = False
            descendant_state: str | None = None
            try:
                with self.assertRaises(KeyboardInterrupt):
                    run_bounded_interactive(
                        (
                            sys.executable,
                            "-c",
                            script,
                            str(pid_path),
                        ),
                        cwd=root,
                        env=os.environ,
                        timeout=30,
                        terminate_grace_seconds=0.1,
                    )
                leader_pid, descendant_pid = (
                    int(value)
                    for value in pid_path.read_text(
                        encoding="utf-8"
                    ).split()
                )
            finally:
                interrupter.join(timeout=1)
                if (
                    leader_pid is None
                    and pid_path.exists()
                ):
                    leader_pid, descendant_pid = (
                        int(value)
                        for value in pid_path.read_text(
                            encoding="utf-8"
                        ).split()
                    )
                survived_interrupt = (
                    leader_pid is not None
                    and Path(f"/proc/{leader_pid}").exists()
                )
                if descendant_pid is not None:
                    try:
                        stat = Path(
                            f"/proc/{descendant_pid}/stat"
                        ).read_text(encoding="utf-8")
                    except FileNotFoundError:
                        descendant_state = None
                    else:
                        descendant_state = stat[
                            stat.rfind(")") + 2 :
                        ].split()[0]
                if (
                    leader_pid is not None
                    and (
                        survived_interrupt
                        or descendant_state
                        not in {None, "Z", "X", "x"}
                    )
                ):
                    try:
                        os.killpg(leader_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        os.waitpid(leader_pid, 0)
                    except ChildProcessError:
                        pass

            self.assertIsNotNone(leader_pid)
            assert leader_pid is not None
            self.assertIsNotNone(descendant_pid)
            self.assertFalse(survived_interrupt)
            self.assertIn(
                descendant_state,
                (None, "Z", "X", "x"),
            )
            self.assertFalse(Path(f"/proc/{leader_pid}").exists())

    def test_successful_leader_cannot_leave_a_live_process_group(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pid_path = root / "successful-leader.pids"
            script = (
                "import os,pathlib,subprocess,sys;"
                "child=subprocess.Popen([sys.executable,'-c',"
                "'import signal,time;"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                "time.sleep(30)']);"
                "pathlib.Path(sys.argv[1]).write_text("
                "f'{os.getpid()} {child.pid}');"
                "os._exit(0)"
            )
            leader_pid: int | None = None
            descendant_pid: int | None = None
            descendant_state: str | None = None
            result = None
            try:
                result = run_bounded_interactive(
                    (
                        sys.executable,
                        "-c",
                        script,
                        str(pid_path),
                    ),
                    cwd=root,
                    env=os.environ,
                    timeout=5,
                    terminate_grace_seconds=0.5,
                )
                leader_pid, descendant_pid = (
                    int(value)
                    for value in pid_path.read_text(
                        encoding="utf-8"
                    ).split()
                )
                try:
                    stat_text = Path(
                        f"/proc/{descendant_pid}/stat"
                    ).read_text(encoding="utf-8")
                except FileNotFoundError:
                    descendant_state = None
                else:
                    descendant_state = stat_text[
                        stat_text.rfind(")") + 2 :
                    ].split()[0]
            finally:
                if (
                    leader_pid is not None
                    and descendant_pid is not None
                    and descendant_state
                    not in {None, "Z", "X", "x"}
                ):
                    try:
                        os.killpg(leader_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        os.waitpid(leader_pid, 0)
                    except ChildProcessError:
                        pass

            assert result is not None
            self.assertEqual(result.returncode, 125)
            self.assertEqual(
                result.stderr,
                b"interactive process left a residual process group",
            )
            self.assertIsNotNone(leader_pid)
            assert leader_pid is not None
            self.assertFalse(Path(f"/proc/{leader_pid}").exists())
            self.assertIsNotNone(descendant_pid)
            self.assertIn(
                descendant_state,
                (None, "Z", "X", "x"),
            )

    def test_deadline_terminates_the_attached_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pid_path = root / "child.pid"
            script = (
                "import pathlib,signal,subprocess,sys,time;"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                "child=subprocess.Popen([sys.executable,'-c',"
                "'import signal,time;"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                "time.sleep(30)']);"
                "pathlib.Path(sys.argv[1]).write_text(str(child.pid));"
                "time.sleep(30)"
            )
            started = time.monotonic()
            result = run_bounded_interactive(
                (sys.executable, "-c", script, str(pid_path)),
                cwd=root,
                env=os.environ,
                timeout=0.15,
                terminate_grace_seconds=0.1,
            )
            elapsed = time.monotonic() - started
            child_pid = int(pid_path.read_text(encoding="utf-8"))

        self.assertEqual(result.returncode, 124)
        self.assertLess(elapsed, 0.8)
        deadline = time.monotonic() + 1
        while Path(f"/proc/{child_pid}").exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        if Path(f"/proc/{child_pid}/stat").exists():
            fields = Path(f"/proc/{child_pid}/stat").read_text(
                encoding="utf-8"
            ).split()
            self.assertEqual(fields[2], "Z")

    def test_normal_exit_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = run_bounded_interactive(
                (sys.executable, "-c", "raise SystemExit(7)"),
                cwd=Path(temporary),
                env=os.environ,
                timeout=1,
            )
        self.assertEqual(result.returncode, 7)


if __name__ == "__main__":
    unittest.main()
