from __future__ import annotations

import hashlib
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

import ctf_os.engine.challenge as challenge_module
import ctf_os.storage as storage_module
import ctf_os.store.files as store_files
from ctf_os.codex import Role
from ctf_os.credential_safety import CredentialSafetyError
from ctf_os.engine.challenge import ChallengeEngine, EngineError
from ctf_os.models import ChallengeIdentity, ExperimentStatus
from ctf_os.sandbox.types import (
    BackgroundLaunchState,
    BackgroundLaunchStatus,
    CommandSpec,
    JobLog,
    JobRef,
    JobState,
    JobStatus,
)
from ctf_os.store import ChallengeLock


class _BackgroundSandbox:
    def __init__(self, work: Path) -> None:
        self.work = work
        self.scope_fingerprint = hashlib.sha256(
            str(work).encode("utf-8")
        ).hexdigest()
        self.ref = JobRef(
            "job-00000001",
            self.scope_fingerprint,
            runtime_id="none",
            supervisor_id="bg-" + "1" * 32,
        )
        self.started: list[CommandSpec] = []
        self.status = JobStatus(self.ref, JobState.RUNNING)
        self.status_calls = 0
        self.log_calls = 0
        self.cancel_calls = 0
        self.fail_start = False
        self.launch_override: BackgroundLaunchStatus | None = None
        self.on_start = None

    def start_job(
        self,
        spec: CommandSpec,
        *,
        name: str | None = None,
        supervisor_id: str | None = None,
    ) -> JobRef:
        del name
        self.started.append(spec)
        if self.on_start is not None:
            self.on_start(supervisor_id)
        if self.fail_start:
            raise RuntimeError("injected launch failure")
        if supervisor_id is not None:
            self.ref = JobRef(
                "job-00000001",
                self.scope_fingerprint,
                runtime_id="none",
                supervisor_id=supervisor_id,
            )
            self.status = JobStatus(self.ref, JobState.RUNNING)
        return self.ref

    def list_jobs(self) -> tuple[JobStatus, ...]:
        return (self.status,)

    def recover_jobs(self) -> tuple[JobStatus, ...]:
        return (self.status,)

    def recover_job_launch(
        self,
        supervisor_id: str,
    ) -> BackgroundLaunchStatus:
        if self.launch_override is not None:
            return self.launch_override
        if supervisor_id != self.ref.supervisor_id:
            return BackgroundLaunchStatus(
                supervisor_id,
                BackgroundLaunchState.ABSENT,
            )
        if self.status.status in {
            JobState.STARTING,
            JobState.RUNNING,
        }:
            return BackgroundLaunchStatus(
                supervisor_id,
                BackgroundLaunchState.ACTIVE,
                ref=self.ref,
                job_status=self.status,
            )
        if self.status.status is JobState.LOST:
            return BackgroundLaunchStatus(
                supervisor_id,
                BackgroundLaunchState.PENDING,
                ref=self.ref,
                job_status=self.status,
            )
        return BackgroundLaunchStatus(
            supervisor_id,
            BackgroundLaunchState.RELEASED,
            ref=self.ref,
            job_status=self.status,
        )

    def job_status(self, ref: JobRef) -> JobStatus:
        if ref != self.ref:
            raise AssertionError("engine passed an unbound job ref")
        self.status_calls += 1
        return self.status

    def job_log(self, ref: JobRef, *, tail_bytes: int = 8192) -> JobLog:
        if ref != self.ref:
            raise AssertionError("engine passed an unbound job ref")
        self.log_calls += 1
        stdout = "bounded-output"[-tail_bytes:]
        return JobLog(
            ref,
            stdout,
            "",
            len("bounded-output"),
            0,
            tail_bytes < len("bounded-output"),
            False,
        )

    def cancel_job(
        self,
        ref: JobRef,
        *,
        grace_seconds: int = 3,
    ) -> JobStatus:
        if ref != self.ref:
            raise AssertionError("engine passed an unbound job ref")
        del grace_seconds
        self.cancel_calls += 1
        self.status = JobStatus(
            ref,
            JobState.CANCELLED,
            exit_code=130,
            cancelled=True,
        )
        return self.status


class BackgroundEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.identity = ChallengeIdentity(
            "Engine CTF",
            "forensic",
            "Memory",
        )
        self.sandboxes: dict[Path, _BackgroundSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            return self.sandboxes.setdefault(
                work,
                _BackgroundSandbox(work),
            )

        self.engine = ChallengeEngine(
            self.root,
            sandbox_factory=sandbox_factory,
        )
        self.engine.add_challenge(self.identity, prompt="analyze memory")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_launch_binds_canonical_ref_and_reads_do_not_write_state(
        self,
    ) -> None:
        before = self.engine.store.read_snapshot(self.identity)
        launched, ref = self.engine.start_background_job(
            self.identity,
            ("volatility3", "-f", "memory.raw", "windows.pslist"),
            name="memory-scan",
            timeout_seconds=600,
            resource_class="heavy",
        )
        self.assertEqual(launched.revision, before.revision + 2)
        records = launched.extra["background_jobs"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["job_id"], ref.job_id)
        self.assertEqual(records[0]["supervisor_id"], ref.supervisor_id)
        self.assertEqual(records[0]["schema_version"], 2)
        self.assertGreater(records[0]["storage_reservation_bytes"], 0)
        self.assertEqual(
            records[0]["command"],
            ["volatility3", "-f", "memory.raw", "windows.pslist"],
        )
        sandbox = next(iter(self.sandboxes.values()))
        self.assertEqual(len(sandbox.started), 1)

        state_path = self.engine.store.challenge_paths(self.identity).state
        canonical_before_reads = state_path.read_bytes()
        revision_before_reads = launched.revision

        listed_state, listed = self.engine.list_background_jobs(
            self.identity,
            recover=False,
        )
        status_state, status = self.engine.background_job_status(
            self.identity,
            ref,
        )
        log = self.engine.background_job_log(
            self.identity,
            ref,
            tail_bytes=7,
        )

        self.assertEqual(listed, (sandbox.status,))
        self.assertEqual(status.status, JobState.RUNNING)
        self.assertEqual(log.stdout, "-output")
        self.assertEqual(
            (listed_state.revision, status_state.revision),
            (revision_before_reads, revision_before_reads),
        )
        self.assertEqual(state_path.read_bytes(), canonical_before_reads)

        foreign = JobRef(
            ref.job_id,
            ref.scope_fingerprint,
            runtime_id=ref.runtime_id,
            supervisor_id="bg-" + "2" * 32,
        )
        with self.assertRaisesRegex(
            EngineError,
            "not recorded in canonical state",
        ):
            self.engine.background_job_status(self.identity, foreign)
        self.assertEqual(state_path.read_bytes(), canonical_before_reads)

        cancelled, cancel_status = self.engine.cancel_background_job(
            self.identity,
            ref,
            grace_seconds=0,
        )
        self.assertEqual(cancel_status.status, JobState.CANCELLED)
        self.assertEqual(cancelled.revision, revision_before_reads + 3)
        self.assertEqual(sandbox.cancel_calls, 1)
        self.assertEqual(
            cancelled.extra["background_jobs"][0]["status"],
            "cancelled",
        )
        self.assertEqual(
            cancelled.extra["background_jobs"][0][
                "storage_reservation_bytes"
            ],
            0,
        )

    def test_background_admission_precedes_intent_and_supplied_launch(
        self,
    ) -> None:
        sandbox = self.engine.sandbox(
            self.engine.store.load(self.identity)
        )
        events: list[str] = []

        def inspect_intent(supervisor_id) -> None:
            events.append("sandbox-start")
            current = self.engine.store.load(self.identity)
            record = current.extra["background_jobs"][0]
            self.assertEqual(record["status"], "launching")
            self.assertEqual(record["supervisor_id"], supervisor_id)
            self.assertGreater(record["storage_reservation_bytes"], 0)

        sandbox.on_start = inspect_intent
        original = self.engine._enforce_storage_admission

        def admit(*args, **kwargs):
            events.append("admission")
            return original(*args, **kwargs)

        with mock.patch.object(
            self.engine,
            "_enforce_storage_admission",
            side_effect=admit,
        ):
            _state, ref = self.engine.start_background_job(
                self.identity,
                ("sleep", "1"),
            )

        self.assertEqual(events, ["admission", "sandbox-start"])
        self.assertEqual(ref.supervisor_id, sandbox.ref.supervisor_id)

    def test_real_lock_order_is_session_then_shared_scan_then_update(
        self,
    ) -> None:
        paths = self.engine.store.challenge_paths(self.identity)
        events: list[tuple[str, Path, bool, bool]] = []
        held_session = 0
        real_lock = ChallengeLock

        class TracingLock:
            def __init__(inner_self, path, **kwargs) -> None:
                inner_self.path = Path(path)
                inner_self.shared = bool(kwargs.get("shared", False))
                inner_self.lock = real_lock(path, **kwargs)

            @property
            def acquired(inner_self):
                return inner_self.lock.acquired

            def acquire(inner_self):
                nonlocal held_session
                inner_self.lock.acquire()
                if inner_self.path == paths.runtime / "session.lock":
                    held_session += 1
                events.append(
                    (
                        "acquire",
                        inner_self.path,
                        inner_self.shared,
                        held_session > 0,
                    )
                )
                return inner_self

            def release(inner_self) -> None:
                nonlocal held_session
                was_acquired = inner_self.lock.acquired
                inner_self.lock.release()
                if was_acquired:
                    if inner_self.path == paths.runtime / "session.lock":
                        held_session -= 1
                    events.append(
                        (
                            "release",
                            inner_self.path,
                            inner_self.shared,
                            held_session > 0,
                        )
                    )

            def __enter__(inner_self):
                inner_self.lock.__enter__()
                return inner_self

            def __exit__(inner_self, *args) -> None:
                nonlocal held_session
                was_acquired = inner_self.lock.acquired
                inner_self.lock.__exit__(*args)
                if was_acquired:
                    if inner_self.path == paths.runtime / "session.lock":
                        held_session -= 1
                    events.append(
                        (
                            "release",
                            inner_self.path,
                            inner_self.shared,
                            held_session > 0,
                        )
                    )

        with (
            mock.patch.object(
                challenge_module,
                "ChallengeLock",
                TracingLock,
            ),
            mock.patch.object(
                storage_module,
                "ChallengeLock",
                TracingLock,
            ),
            mock.patch.object(
                store_files,
                "ChallengeLock",
                TracingLock,
            ),
        ):
            self.engine.start_background_job(
                self.identity,
                ("sleep", "1"),
            )

        session_index = next(
            index
            for index, event in enumerate(events)
            if event[:3]
            == (
                "acquire",
                paths.runtime / "session.lock",
                False,
            )
        )
        shared_index = next(
            index
            for index, event in enumerate(events)
            if index > session_index
            and event[:3] == ("acquire", paths.lock, True)
        )
        shared_release_index = next(
            index
            for index, event in enumerate(events)
            if index > shared_index
            and event[:3] == ("release", paths.lock, True)
        )
        update_index = next(
            index
            for index, event in enumerate(events)
            if index > shared_release_index
            and event[:3] == ("acquire", paths.lock, False)
        )
        self.assertLess(session_index, shared_index)
        self.assertLess(shared_index, shared_release_index)
        self.assertLess(shared_release_index, update_index)
        self.assertTrue(events[shared_index][3])
        self.assertTrue(events[update_index][3])
        self.assertEqual(held_session, 0)

    def test_quota_rejection_prevents_intent_and_sandbox_start(
        self,
    ) -> None:
        sandbox = self.engine.sandbox(
            self.engine.store.load(self.identity)
        )
        with (
            mock.patch.object(
                self.engine,
                "_enforce_storage_admission",
                side_effect=EngineError("synthetic quota rejection"),
            ),
            self.assertRaisesRegex(EngineError, "quota rejection"),
        ):
            self.engine.start_background_job(
                self.identity,
                ("sleep", "1"),
            )
        current = self.engine.store.load(self.identity)
        self.assertNotIn("background_jobs", current.extra)
        self.assertEqual(sandbox.started, [])

    def test_credential_bearing_name_is_rejected_before_intent(self) -> None:
        state_path = self.engine.store.challenge_paths(self.identity).state
        before = state_path.read_bytes()
        with self.assertRaisesRegex(
            CredentialSafetyError,
            "metadata contains credential-bearing text",
        ):
            self.engine.start_background_job(
                self.identity,
                ("sleep", "1"),
                name="sk-proj-ABCDEFGHIJKLMNOPQRSTUV",
            )
        self.assertEqual(state_path.read_bytes(), before)
        self.assertEqual(self.sandboxes, {})

    def test_real_quota_rejection_calls_no_sandbox_or_provider(
        self,
    ) -> None:
        self.engine.config = replace(
            self.engine.config,
            runtime=replace(
                self.engine.config.runtime,
                challenge_storage_quota_bytes=1,
                work_tree_max_bytes=2,
            ),
        )
        with mock.patch.object(
            self.engine.batch_runner,
            "run",
        ) as provider_run:
            with self.assertRaisesRegex(EngineError, "storage quota"):
                self.engine.run_role(
                    self.identity,
                    Role.CAPTAIN,
                    instruction="inspect the challenge",
                )
            with self.assertRaisesRegex(EngineError, "storage quota"):
                self.engine.run_tool_command(
                    self.identity,
                    ("true",),
                )
            with self.assertRaisesRegex(EngineError, "storage quota"):
                self.engine.start_background_job(
                    self.identity,
                    ("sleep", "1"),
                )
        provider_run.assert_not_called()
        self.assertEqual(self.sandboxes, {})

    def test_crash_after_intent_recovers_absence_and_releases_reserve(
        self,
    ) -> None:
        sandbox = self.engine.sandbox(
            self.engine.store.load(self.identity)
        )
        sandbox.fail_start = True
        with self.assertRaisesRegex(
            RuntimeError,
            "injected launch failure",
        ):
            self.engine.start_background_job(
                self.identity,
                ("sleep", "1"),
            )
        record = self.engine.store.load(
            self.identity
        ).extra["background_jobs"][0]
        self.assertEqual(record["status"], "recovered")
        self.assertEqual(record["storage_reservation_bytes"], 0)

    def test_bind_commit_failure_cancels_and_releases_exact_launch(
        self,
    ) -> None:
        original_update = self.engine.store.update
        bind_failed = False

        def fail_bind_once(*args, **kwargs):
            nonlocal bind_failed
            mutator = args[1]
            if (
                getattr(mutator, "__name__", None) == "bind"
                and not bind_failed
            ):
                bind_failed = True
                raise RuntimeError("injected bind commit failure")
            return original_update(*args, **kwargs)

        with (
            mock.patch.object(
                self.engine.store,
                "update",
                side_effect=fail_bind_once,
            ),
            self.assertRaisesRegex(
                RuntimeError,
                "bind commit failure",
            ),
        ):
            self.engine.start_background_job(
                self.identity,
                ("sleep", "1"),
            )

        sandbox = next(iter(self.sandboxes.values()))
        self.assertTrue(bind_failed)
        self.assertEqual(sandbox.cancel_calls, 1)
        record = self.engine.store.load(
            self.identity
        ).extra["background_jobs"][0]
        self.assertEqual(record["status"], "cancelled")
        self.assertEqual(record["supervisor_id"], sandbox.ref.supervisor_id)
        self.assertEqual(record["storage_reservation_bytes"], 0)

    def test_observational_lost_retains_storage_reservation(self) -> None:
        launched, ref = self.engine.start_background_job(
            self.identity,
            ("sleep", "1"),
        )
        sandbox = next(iter(self.sandboxes.values()))
        sandbox.status = JobStatus(
            ref,
            JobState.LOST,
            reason_code="runtime_missing",
        )
        recovered, _statuses = self.engine.list_background_jobs(
            self.identity,
            recover=True,
        )
        record = recovered.extra["background_jobs"][0]
        self.assertEqual(record["status"], "lost")
        self.assertEqual(record["reason_code"], "runtime_missing")
        self.assertEqual(
            record["storage_reservation_bytes"],
            record["work_tree_limit_bytes"],
        )

    def test_cleanup_pending_retains_storage_reservation(self) -> None:
        launched, ref = self.engine.start_background_job(
            self.identity,
            ("sleep", "1"),
        )
        initial_record = launched.extra["background_jobs"][0]
        sandbox = next(iter(self.sandboxes.values()))
        terminal = JobStatus(
            ref,
            JobState.CANCELLED,
            exit_code=130,
            cancelled=True,
            reason_code="work_tree_quota_exceeded",
        )
        sandbox.status = terminal
        sandbox.launch_override = BackgroundLaunchStatus(
            ref.supervisor_id,
            BackgroundLaunchState.PENDING,
            ref=ref,
            job_status=terminal,
        )

        recovered, _statuses = self.engine.list_background_jobs(
            self.identity,
            recover=True,
        )

        record = recovered.extra["background_jobs"][0]
        self.assertEqual(record["status"], "cleanup_pending")
        self.assertEqual(
            record["reason_code"],
            "work_tree_quota_exceeded",
        )
        self.assertEqual(
            record["storage_reservation_bytes"],
            initial_record["work_tree_limit_bytes"],
        )

    def test_foreground_tool_rejects_before_sandbox_execution(self) -> None:
        with (
            mock.patch.object(
                self.engine,
                "_enforce_storage_admission",
                side_effect=EngineError("synthetic quota rejection"),
            ),
            self.assertRaisesRegex(EngineError, "quota rejection"),
        ):
            self.engine.run_tool_command(
                self.identity,
                ("true",),
            )
        state = self.engine.store.load(self.identity)
        self.assertEqual(state.runs, [])
        self.assertTrue(state.experiments)
        self.assertEqual(
            {item.status for item in state.experiments},
            {ExperimentStatus.REGISTERED},
        )


if __name__ == "__main__":
    unittest.main()
