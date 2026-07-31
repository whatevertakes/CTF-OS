from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ctf_os.credential_safety import CredentialSafetyError
from ctf_os.director.leases import LeaseBroker
from ctf_os.director.resources import ResourceVector
from ctf_os.sandbox.client import LocalChallengeSandboxClient
from ctf_os.sandbox.docker import DockerSandboxBackend
from ctf_os.sandbox.supervisor import (
    BackgroundJobSupervisor,
    _pid_start_ticks,
    _read_private_json,
    _worker,
)
from ctf_os.sandbox.types import (
    BackgroundLaunchState,
    BackgroundLaunchStatus,
    ChallengeScope,
    CommandSpec,
    JobLog,
    JobRef,
    JobState,
    JobStatus,
    NetworkPolicy,
    SandboxError,
)
from ctf_os.store.atomic import atomic_write_json, canonical_json_bytes


class _FakeBackend:
    def __init__(
        self,
        scope: ChallengeScope,
        *,
        work_tree_error: bool = False,
    ) -> None:
        self.scope = scope
        self.events: list[str] = []
        self.work_tree_error = work_tree_error

    def job_status(self, ref: JobRef) -> JobStatus:
        self.events.append("status")
        return JobStatus(ref, JobState.RUNNING)

    def cancel_job(
        self,
        ref: JobRef,
        *,
        grace_seconds: int,
    ) -> JobStatus:
        self.events.append(f"cancel:{grace_seconds}")
        return JobStatus(
            ref,
            JobState.CANCELLED,
            exit_code=130,
            cancelled=True,
        )

    def _remove_supervised_runtime(
        self,
        supervisor_id: str,
        *,
        runtime_id: str,
        missing_ok: bool,
    ) -> None:
        self.events.append(
            f"remove:{supervisor_id}:{runtime_id}:{missing_ok}"
        )
        return None

    def check_work_tree(self, *, phase: str) -> None:
        self.events.append(f"work-tree:{phase}")
        if self.work_tree_error:
            raise SandboxError("synthetic work tree exceeds limit")


class _LifecycleLease:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.lease_id = "lease-" + "1" * 32
        self.released = False

    def release(self) -> None:
        self.events.append("release")
        self.released = True


class _LifecycleBroker:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def acquire(self, request, *, timeout, owner, durable=False):
        del request, timeout, owner
        if not durable:
            raise AssertionError("background lease must be durable")
        self.events.append("acquire")
        return _LifecycleLease(self.events)

    def status(self):
        self.events.append("broker-status")
        return SimpleNamespace(leases=())


class _LifecycleBackend:
    def __init__(
        self,
        scope: ChallengeScope,
        events: list[str],
        *,
        removal_failures: int = 0,
        work_tree_error: bool = False,
        work_tree_interruptions: int = 0,
        status_error_after: int | None = None,
    ) -> None:
        self.scope = scope
        self.events = events
        self.removal_failures = removal_failures
        self.work_tree_error = work_tree_error
        self.work_tree_interruptions = work_tree_interruptions
        self.status_error_after = status_error_after
        self.ref = JobRef(
            "job-00000001",
            scope.fingerprint,
            supervisor_id="bg-" + "2" * 32,
        )
        self.status_calls = 0

    def _start_supervised_job(self, spec, *, supervisor_id, name):
        del spec, name
        self.events.append("start")
        self.ref = JobRef(
            "job-00000001",
            self.scope.fingerprint,
            supervisor_id=supervisor_id,
        )
        return self.ref

    def job_status(self, ref):
        self.status_calls += 1
        self.events.append(f"status:{self.status_calls}")
        if (
            self.status_error_after is not None
            and self.status_calls >= self.status_error_after
        ):
            raise SandboxError("synthetic job status failure")
        state = (
            JobState.RUNNING
            if self.status_calls == 1
            else JobState.COMPLETED
        )
        return JobStatus(ref, state, exit_code=0 if state is JobState.COMPLETED else None)

    def cancel_job(self, ref, *, grace_seconds):
        self.events.append(f"cancel:{grace_seconds}")
        return JobStatus(ref, JobState.CANCELLED, exit_code=130, cancelled=True)

    def check_work_tree(self, *, phase):
        self.events.append(f"work-tree:{phase}")
        if self.work_tree_interruptions:
            self.work_tree_interruptions -= 1
            raise KeyboardInterrupt("synthetic postcheck interruption")
        if self.work_tree_error:
            raise SandboxError("synthetic work tree exceeds limit")

    def _remove_supervised_runtime(
        self,
        supervisor_id,
        *,
        runtime_id,
        missing_ok,
    ):
        del supervisor_id, runtime_id, missing_ok
        if self.removal_failures:
            self.removal_failures -= 1
            self.events.append("remove-failed")
            return "synthetic docker busy"
        self.events.append("remove")
        return None


class _RoutingSupervisor:
    def __init__(self, ref: JobRef) -> None:
        self.ref = ref
        self.calls: list[str] = []

    def start(
        self,
        backend,
        spec,
        *,
        name,
        owner,
        supervisor_id=None,
    ):
        del backend, spec, name, owner
        self.calls.append(f"start:{supervisor_id or 'generated'}")
        return self.ref

    def status(self, backend, ref):
        del backend
        self.calls.append("status")
        return JobStatus(ref, JobState.RUNNING)

    def log(self, backend, ref, *, tail_bytes):
        del backend
        self.calls.append(f"log:{tail_bytes}")
        return JobLog(ref, "out", "", 3, 0, False, False)

    def cancel(self, backend, ref, *, grace_seconds):
        del backend
        self.calls.append(f"cancel:{grace_seconds}")
        return JobStatus(ref, JobState.CANCELLED, cancelled=True)

    def list(self, backend):
        del backend
        self.calls.append("list")
        return (JobStatus(self.ref, JobState.RUNNING),)

    def recover(self, backend):
        del backend
        self.calls.append("recover")
        return (JobStatus(self.ref, JobState.RUNNING),)

    def recover_launch(self, backend, supervisor_id):
        del backend
        self.calls.append(f"recover-launch:{supervisor_id}")
        return BackgroundLaunchStatus(
            supervisor_id,
            BackgroundLaunchState.ACTIVE,
            ref=self.ref,
            job_status=JobStatus(self.ref, JobState.RUNNING),
        )


class BackgroundSupervisorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        challenge = self.root / "incoming" / "demo"
        work = self.root / "work"
        challenge.mkdir(parents=True)
        self.scope = ChallengeScope.create(
            contest_id="contest",
            category="forensic",
            challenge_id="memory",
            challenge_dir=challenge,
            work_dir=work,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _launch_request(self, supervisor_id: str) -> dict[str, object]:
        return {
            "schema_version": 1,
            "supervisor_id": supervisor_id,
            "backend": {
                "scope": {"fingerprint": self.scope.fingerprint},
            },
            "lease": {
                "owner": (
                    f"{self.scope.qualified_id}:background:"
                    f"{supervisor_id}"
                ),
            },
        }

    def _worker_request(
        self,
        supervisor_id: str,
        *,
        name: str,
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "supervisor_id": supervisor_id,
            "created_at": "2026-07-31T00:00:00+00:00",
            "backend": {},
            "command": {
                "argv": ["sleep", "1"],
                "timeout_seconds": 60,
                "deadline_monotonic_seconds": None,
                "summary_bytes": 4096,
                "environment": {},
                "network_target": None,
                "resource_request": {
                    "cpu": 1,
                    "memory_mib": 2048,
                    "gpu": 0,
                    "kvm": 0,
                    "network": 0,
                },
            },
            "name": name,
            "lease": {
                "root": str(self.root / "leases"),
                "capacity": {
                    "cpu": 2,
                    "memory_mib": 4096,
                    "gpu": 0,
                    "kvm": 0,
                    "network": 0,
                },
                "poll_interval": 0.01,
                "wait_timeout": 1,
                "owner": f"test:{supervisor_id}",
            },
        }

    def test_local_client_routes_only_receipt_bound_jobs_to_supervisor(self) -> None:
        backend = _FakeBackend(self.scope)
        ref = JobRef(
            "job-00000001",
            self.scope.fingerprint,
            supervisor_id="bg-" + "a" * 32,
        )
        supervisor = _RoutingSupervisor(ref)
        client = LocalChallengeSandboxClient(
            self.scope,
            backend=backend,  # type: ignore[arg-type]
            job_supervisor=supervisor,  # type: ignore[arg-type]
        )

        self.assertEqual(
            client.start_job(CommandSpec(("sleep", "1"))),
            ref,
        )
        self.assertEqual(client.job_status(ref).status, JobState.RUNNING)
        self.assertEqual(client.job_log(ref, tail_bytes=7).stdout, "out")
        self.assertEqual(
            client.cancel_job(ref, grace_seconds=0).status,
            JobState.CANCELLED,
        )
        self.assertEqual(len(client.list_jobs()), 1)
        self.assertEqual(len(client.recover_jobs()), 1)
        self.assertEqual(
            supervisor.calls,
            [
                "start:generated",
                "status",
                "log:7",
                "cancel:0",
                "list",
                "recover",
            ],
        )

    def test_local_client_forwards_preallocated_identity_and_recovery(
        self,
    ) -> None:
        backend = _FakeBackend(self.scope)
        supervisor_id = "bg-" + "a" * 32
        ref = JobRef(
            "job-00000001",
            self.scope.fingerprint,
            supervisor_id=supervisor_id,
        )
        supervisor = _RoutingSupervisor(ref)
        client = LocalChallengeSandboxClient(
            self.scope,
            backend=backend,  # type: ignore[arg-type]
            job_supervisor=supervisor,  # type: ignore[arg-type]
        )

        self.assertEqual(
            client.start_job(
                CommandSpec(("sleep", "1")),
                supervisor_id=supervisor_id,
            ),
            ref,
        )
        recovered = client.recover_job_launch(supervisor_id)
        self.assertIs(recovered.state, BackgroundLaunchState.ACTIVE)
        self.assertEqual(
            supervisor.calls,
            [
                f"start:{supervisor_id}",
                f"recover-launch:{supervisor_id}",
            ],
        )

    def test_supplied_identity_is_strict_and_collision_safe(self) -> None:
        broker = LeaseBroker(
            self.root / "strict-leases",
            ResourceVector(cpu=2, memory_mib=4096),
        )
        supervisor = BackgroundJobSupervisor(
            self.root / "strict-supervisors",
            broker,
        )
        backend = _FakeBackend(self.scope)
        with self.assertRaisesRegex(
            ValueError,
            "invalid background supervisor identity",
        ):
            supervisor.start(
                backend,  # type: ignore[arg-type]
                CommandSpec(("sleep", "1")),
                supervisor_id="../escape",
            )

        supervisor_id = "bg-" + "9" * 32
        supervisor._job_root(
            self.scope.fingerprint,
            supervisor_id,
        ).mkdir(mode=0o700)
        with self.assertRaisesRegex(
            Exception,
            "identity already exists",
        ):
            supervisor.start(
                backend,  # type: ignore[arg-type]
                CommandSpec(("sleep", "1")),
                supervisor_id=supervisor_id,
            )

    def test_credential_bearing_name_is_rejected_before_request(self) -> None:
        broker = LeaseBroker(
            self.root / "credential-name-leases",
            ResourceVector(cpu=2, memory_mib=4096),
        )
        supervisor = BackgroundJobSupervisor(
            self.root / "credential-name-supervisors",
            broker,
        )
        backend = _FakeBackend(self.scope)
        with (
            patch.object(supervisor, "recover"),
            patch.object(supervisor, "_write_request") as write_request,
            self.assertRaisesRegex(
                CredentialSafetyError,
                "metadata contains credential-bearing text",
            ),
        ):
            supervisor.start(
                backend,  # type: ignore[arg-type]
                CommandSpec(("sleep", "1")),
                name="sk-proj-ABCDEFGHIJKLMNOPQRSTUV",
            )
        write_request.assert_not_called()

    def test_recover_launch_distinguishes_absent_pending_active_and_released(
        self,
    ) -> None:
        broker = LeaseBroker(
            self.root / "launch-leases",
            ResourceVector(cpu=2, memory_mib=4096),
        )
        supervisor = BackgroundJobSupervisor(
            self.root / "launch-supervisors",
            broker,
        )
        backend = _FakeBackend(self.scope)

        absent_id = "bg-" + "1" * 32
        with (
            patch.object(
                backend,
                "_remove_supervised_runtime",
                return_value="synthetic control failure",
            ),
            self.assertRaisesRegex(
                SandboxError,
                "could not be attested",
            ),
        ):
            supervisor.recover_launch(
                backend,  # type: ignore[arg-type]
                absent_id,
            )
        self.assertIs(
            supervisor.recover_launch(
                backend,  # type: ignore[arg-type]
                absent_id,
            ).state,
            BackgroundLaunchState.ABSENT,
        )

        prelaunch_id = "bg-" + "2" * 32
        prelaunch_root = supervisor._job_root(
            self.scope.fingerprint,
            prelaunch_id,
        )
        prelaunch_root.mkdir(mode=0o700)
        atomic_write_json(
            prelaunch_root / "request.json",
            self._launch_request(prelaunch_id),
            mode=0o400,
        )
        released = supervisor.recover_launch(
            backend,  # type: ignore[arg-type]
            prelaunch_id,
        )
        self.assertIs(released.state, BackgroundLaunchState.RELEASED)
        self.assertEqual(
            supervisor.recover_launch(
                backend,  # type: ignore[arg-type]
                prelaunch_id,
            ),
            released,
        )
        self.assertEqual(
            backend.events,
            [
                f"remove:{absent_id}:None:True",
                f"remove:{prelaunch_id}:None:True",
            ],
        )

        pending_id = "bg-" + "3" * 32
        pending_root = supervisor._job_root(
            self.scope.fingerprint,
            pending_id,
        )
        pending_root.mkdir(mode=0o700)
        pending_request = self._launch_request(pending_id)
        atomic_write_json(
            pending_root / "request.json",
            pending_request,
            mode=0o400,
        )
        worker_ticks = _pid_start_ticks(os.getpid())
        self.assertIsNotNone(worker_ticks)
        atomic_write_json(
            pending_root / "receipt.json",
            {
                "schema_version": 1,
                "supervisor_id": pending_id,
                "request_sha256": hashlib.sha256(
                    canonical_json_bytes(pending_request)
                ).hexdigest(),
                "state": "starting",
                "supervisor_pid": os.getpid(),
                "supervisor_start_ticks": worker_ticks,
            },
        )
        pending = supervisor.recover_launch(
            backend,  # type: ignore[arg-type]
            pending_id,
        )
        self.assertIs(pending.state, BackgroundLaunchState.PENDING)
        self.assertIsNone(pending.ref)

        active_id = "bg-" + "4" * 32
        active_root = supervisor._job_root(
            self.scope.fingerprint,
            active_id,
        )
        active_root.mkdir(mode=0o700)
        active_request = self._launch_request(active_id)
        active_ref = JobRef(
            "job-00000001",
            self.scope.fingerprint,
            supervisor_id=active_id,
        )
        atomic_write_json(
            active_root / "request.json",
            active_request,
            mode=0o400,
        )
        atomic_write_json(
            active_root / "receipt.json",
            {
                "schema_version": 1,
                "supervisor_id": active_id,
                "request_sha256": hashlib.sha256(
                    canonical_json_bytes(active_request)
                ).hexdigest(),
                "state": "running",
                "supervisor_pid": os.getpid(),
                "supervisor_start_ticks": worker_ticks,
                "ref": {
                    "job_id": active_ref.job_id,
                    "scope_fingerprint": active_ref.scope_fingerprint,
                    "runtime_id": active_ref.runtime_id,
                    "supervisor_id": active_ref.supervisor_id,
                },
            },
        )
        active = supervisor.recover_launch(
            backend,  # type: ignore[arg-type]
            active_id,
        )
        self.assertIs(active.state, BackgroundLaunchState.ACTIVE)
        self.assertEqual(active.ref, active_ref)

        terminal_id = "bg-" + "5" * 32
        terminal_root = supervisor._job_root(
            self.scope.fingerprint,
            terminal_id,
        )
        terminal_root.mkdir(mode=0o700)
        terminal_request = self._launch_request(terminal_id)
        terminal_ref = JobRef(
            "job-00000002",
            self.scope.fingerprint,
            supervisor_id=terminal_id,
        )
        atomic_write_json(
            terminal_root / "request.json",
            terminal_request,
            mode=0o400,
        )
        atomic_write_json(
            terminal_root / "receipt.json",
            {
                "schema_version": 1,
                "supervisor_id": terminal_id,
                "request_sha256": hashlib.sha256(
                    canonical_json_bytes(terminal_request)
                ).hexdigest(),
                "state": "terminal",
                "ref": {
                    "job_id": terminal_ref.job_id,
                    "scope_fingerprint": terminal_ref.scope_fingerprint,
                    "runtime_id": terminal_ref.runtime_id,
                    "supervisor_id": terminal_ref.supervisor_id,
                },
                "job_status": {
                    "status": "completed",
                    "exit_code": 0,
                    "timed_out": False,
                    "cancelled": False,
                    "started_at": None,
                    "finished_at": None,
                },
            },
        )
        terminal = supervisor.recover_launch(
            backend,  # type: ignore[arg-type]
            terminal_id,
        )
        self.assertIs(terminal.state, BackgroundLaunchState.RELEASED)
        self.assertEqual(
            terminal.job_status,
            JobStatus(terminal_ref, JobState.COMPLETED, exit_code=0),
        )

    def test_recover_launch_fails_closed_on_request_digest_mismatch(
        self,
    ) -> None:
        broker = LeaseBroker(
            self.root / "mismatch-leases",
            ResourceVector(cpu=2, memory_mib=4096),
        )
        supervisor = BackgroundJobSupervisor(
            self.root / "mismatch-supervisors",
            broker,
        )
        backend = _FakeBackend(self.scope)
        supervisor_id = "bg-" + "6" * 32
        job_root = supervisor._job_root(
            self.scope.fingerprint,
            supervisor_id,
        )
        job_root.mkdir(mode=0o700)
        atomic_write_json(
            job_root / "request.json",
            self._launch_request(supervisor_id),
            mode=0o400,
        )
        atomic_write_json(
            job_root / "receipt.json",
            {
                "schema_version": 1,
                "supervisor_id": supervisor_id,
                "request_sha256": "0" * 64,
                "state": "starting",
                "supervisor_pid": os.getpid(),
                "supervisor_start_ticks": _pid_start_ticks(os.getpid()),
            },
        )
        with self.assertRaisesRegex(
            Exception,
            "request digest changed",
        ):
            supervisor.recover_launch(
                backend,  # type: ignore[arg-type]
                supervisor_id,
            )

    def test_recovery_cancels_orphan_before_reclaiming_stale_lease(self) -> None:
        broker = LeaseBroker(
            self.root / "leases",
            ResourceVector(cpu=2, memory_mib=4096),
        )
        supervisor = BackgroundJobSupervisor(
            self.root / "supervisors",
            broker,
        )
        backend = _FakeBackend(self.scope)
        supervisor_id = "bg-" + "b" * 32
        ref = JobRef(
            "job-00000001",
            self.scope.fingerprint,
            supervisor_id=supervisor_id,
        )
        job_root = supervisor._job_root(
            self.scope.fingerprint,
            supervisor_id,
        )
        job_root.mkdir(mode=0o700)
        atomic_write_json(
            job_root / "receipt.json",
            {
                "schema_version": 1,
                "supervisor_id": supervisor_id,
                "state": "running",
                "supervisor_pid": 99_999_999,
                "supervisor_start_ticks": 1,
                "ref": {
                    "job_id": ref.job_id,
                    "scope_fingerprint": ref.scope_fingerprint,
                    "runtime_id": ref.runtime_id,
                    "supervisor_id": ref.supervisor_id,
                },
            },
        )

        statuses = supervisor.recover(backend, ref)  # type: ignore[arg-type]

        self.assertEqual(statuses[0].status, JobState.CANCELLED)
        self.assertEqual(
            backend.events,
            [
                "status",
                "cancel:0",
                f"remove:{supervisor_id}:none:True",
                "work-tree:background orphan recovery",
            ],
        )
        receipt = _read_private_json(job_root / "receipt.json")
        self.assertEqual(receipt["state"], "recovered")
        self.assertEqual(
            receipt["recovery_action"],
            "orphaned_command_cancelled",
        )

    def test_worker_holds_lease_until_terminal_runtime_is_removed(self) -> None:
        supervisor_id = "bg-" + "c" * 32
        job_root = self.root / supervisor_id
        job_root.mkdir(mode=0o700)
        events: list[str] = []
        backend = _LifecycleBackend(self.scope, events)
        request = {
            "schema_version": 1,
            "supervisor_id": supervisor_id,
            "created_at": "2026-07-31T00:00:00+00:00",
            "backend": {},
            "command": {
                "argv": ["sleep", "1"],
                "timeout_seconds": 60,
                "deadline_monotonic_seconds": None,
                "summary_bytes": 4096,
                "environment": {},
                "network_target": None,
                "resource_request": {
                    "cpu": 1,
                    "memory_mib": 2048,
                    "gpu": 0,
                    "kvm": 0,
                    "network": 0,
                },
            },
            "name": "long-analysis",
            "lease": {
                "root": str(self.root / "leases"),
                "capacity": {
                    "cpu": 2,
                    "memory_mib": 4096,
                    "gpu": 0,
                    "kvm": 0,
                    "network": 0,
                },
                "poll_interval": 0.01,
                "wait_timeout": 1,
                "owner": "test",
            },
        }
        atomic_write_json(job_root / "request.json", request, mode=0o400)
        broker = _LifecycleBroker(events)

        with (
            patch(
                "ctf_os.sandbox.supervisor._backend_from_value",
                return_value=backend,
            ),
            patch(
                "ctf_os.sandbox.supervisor.LeaseBroker",
                return_value=broker,
            ),
            patch("ctf_os.sandbox.supervisor.signal.signal"),
            patch("ctf_os.sandbox.supervisor.time.sleep"),
        ):
            result = _worker(job_root)

        self.assertEqual(result, 0)
        self.assertLess(events.index("acquire"), events.index("start"))
        self.assertLess(events.index("start"), events.index("remove"))
        self.assertLess(events.index("remove"), events.index("release"))
        receipt = _read_private_json(job_root / "receipt.json")
        self.assertEqual(receipt["state"], "terminal")
        self.assertEqual(
            receipt["job_status"]["status"],  # type: ignore[index]
            "completed",
        )

    def test_terminal_work_tree_breach_is_failed_and_visible(self) -> None:
        supervisor_id = "bg-" + "7" * 32
        supervisor_root = self.root / "supervisor"
        job_root = (
            supervisor_root
            / self.scope.fingerprint
            / supervisor_id
        )
        job_root.mkdir(parents=True, mode=0o700)
        events: list[str] = []
        backend = _LifecycleBackend(
            self.scope,
            events,
            work_tree_error=True,
        )
        atomic_write_json(
            job_root / "request.json",
            self._worker_request(
                supervisor_id,
                name="quota-breach",
            ),
            mode=0o400,
        )
        broker = _LifecycleBroker(events)
        with (
            patch(
                "ctf_os.sandbox.supervisor._backend_from_value",
                return_value=backend,
            ),
            patch(
                "ctf_os.sandbox.supervisor.LeaseBroker",
                return_value=broker,
            ),
            patch("ctf_os.sandbox.supervisor.signal.signal"),
            patch("ctf_os.sandbox.supervisor.time.sleep"),
        ):
            result = _worker(job_root)

        self.assertEqual(result, 1)
        self.assertLess(
            events.index("remove"),
            events.index("work-tree:background job terminal"),
        )
        self.assertLess(
            events.index("work-tree:background job terminal"),
            events.index("release"),
        )
        self.assertLess(events.index("remove"), events.index("release"))
        receipt = _read_private_json(job_root / "receipt.json")
        self.assertEqual(receipt["state"], "failed")
        self.assertEqual(
            receipt["job_status"]["status"],  # type: ignore[index]
            "failed",
        )
        self.assertEqual(
            receipt["job_status"]["reason_code"],  # type: ignore[index]
            "work_tree_quota_exceeded",
        )
        self.assertIn("quota", receipt["error"])
        status_calls = backend.status_calls
        supervisor = BackgroundJobSupervisor(
            supervisor_root,
            broker,  # type: ignore[arg-type]
            lease_wait_timeout=1,
        )
        self.assertEqual(
            supervisor.status(backend, backend.ref).status,
            JobState.FAILED,
        )
        self.assertEqual(
            supervisor.status(backend, backend.ref).reason_code,
            "work_tree_quota_exceeded",
        )
        self.assertEqual(
            [item.status for item in supervisor.list(backend)],
            [JobState.FAILED],
        )
        self.assertEqual(
            [item.status for item in supervisor.recover(backend, backend.ref)],
            [JobState.FAILED],
        )
        self.assertEqual(backend.status_calls, status_calls)
        recovered_receipt = _read_private_json(job_root / "receipt.json")
        self.assertEqual(recovered_receipt["state"], "failed")
        self.assertIn("quota", recovered_receipt["error"])

    def test_status_failure_still_checks_quiesced_tree_before_release(
        self,
    ) -> None:
        supervisor_id = "bg-" + "8" * 32
        job_root = self.root / supervisor_id
        job_root.mkdir(mode=0o700)
        events: list[str] = []
        backend = _LifecycleBackend(
            self.scope,
            events,
            work_tree_error=True,
            status_error_after=2,
        )
        atomic_write_json(
            job_root / "request.json",
            self._worker_request(
                supervisor_id,
                name="status-error-quota-breach",
            ),
            mode=0o400,
        )
        broker = _LifecycleBroker(events)
        with (
            patch(
                "ctf_os.sandbox.supervisor._backend_from_value",
                return_value=backend,
            ),
            patch(
                "ctf_os.sandbox.supervisor.LeaseBroker",
                return_value=broker,
            ),
            patch("ctf_os.sandbox.supervisor.signal.signal"),
            patch("ctf_os.sandbox.supervisor.time.sleep"),
        ):
            result = _worker(job_root)

        self.assertEqual(result, 1)
        self.assertLess(
            events.index("remove"),
            events.index("work-tree:background job terminal"),
        )
        self.assertLess(
            events.index("work-tree:background job terminal"),
            events.index("release"),
        )
        receipt = _read_private_json(job_root / "receipt.json")
        self.assertEqual(receipt["state"], "failed")
        self.assertEqual(
            receipt["job_status"]["status"],  # type: ignore[index]
            "failed",
        )
        self.assertEqual(
            receipt["job_status"]["reason_code"],  # type: ignore[index]
            "work_tree_quota_exceeded",
        )

    def test_interrupted_terminal_postcheck_retries_before_release(
        self,
    ) -> None:
        supervisor_id = "bg-" + "c" * 32
        job_root = self.root / supervisor_id
        job_root.mkdir(mode=0o700)
        events: list[str] = []
        backend = _LifecycleBackend(
            self.scope,
            events,
            work_tree_interruptions=1,
        )
        atomic_write_json(
            job_root / "request.json",
            self._worker_request(
                supervisor_id,
                name="postcheck-interrupt",
            ),
            mode=0o400,
        )
        broker = _LifecycleBroker(events)
        with (
            patch(
                "ctf_os.sandbox.supervisor._backend_from_value",
                return_value=backend,
            ),
            patch(
                "ctf_os.sandbox.supervisor.LeaseBroker",
                return_value=broker,
            ),
            patch("ctf_os.sandbox.supervisor.signal.signal"),
            patch("ctf_os.sandbox.supervisor.time.sleep"),
        ):
            result = _worker(job_root)

        self.assertEqual(result, 0)
        work_tree_events = [
            index
            for index, value in enumerate(events)
            if value == "work-tree:background job terminal"
        ]
        self.assertEqual(len(work_tree_events), 2)
        self.assertLess(events.index("remove"), work_tree_events[0])
        self.assertLess(work_tree_events[-1], events.index("release"))
        receipt = _read_private_json(job_root / "receipt.json")
        self.assertEqual(receipt["state"], "terminal")

    def test_unbound_start_failure_checks_tree_before_lease_release(
        self,
    ) -> None:
        supervisor_id = "bg-" + "b" * 32
        job_root = self.root / supervisor_id
        job_root.mkdir(mode=0o700)
        events: list[str] = []
        backend = _LifecycleBackend(
            self.scope,
            events,
            work_tree_error=True,
        )
        atomic_write_json(
            job_root / "request.json",
            self._worker_request(
                supervisor_id,
                name="unbound-start-failure",
            ),
            mode=0o400,
        )
        broker = _LifecycleBroker(events)

        def fail_after_runtime_create(*_args, **_kwargs):
            events.append("start-unbound")
            raise SandboxError("synthetic post-create failure")

        with (
            patch(
                "ctf_os.sandbox.supervisor._backend_from_value",
                return_value=backend,
            ),
            patch(
                "ctf_os.sandbox.supervisor.LeaseBroker",
                return_value=broker,
            ),
            patch.object(
                backend,
                "_start_supervised_job",
                side_effect=fail_after_runtime_create,
            ),
            patch("ctf_os.sandbox.supervisor.signal.signal"),
            patch("ctf_os.sandbox.supervisor.time.sleep"),
        ):
            result = _worker(job_root)

        self.assertEqual(result, 1)
        self.assertLess(events.index("remove"), events.index(
            "work-tree:background job terminal"
        ))
        self.assertLess(events.index(
            "work-tree:background job terminal"
        ), events.index("release"))
        receipt = _read_private_json(job_root / "receipt.json")
        self.assertEqual(receipt["state"], "failed")
        self.assertNotIn("job_status", receipt)
        self.assertEqual(
            receipt["reason_code"],
            "work_tree_quota_exceeded",
        )
        self.assertIn("quota", receipt["error"])

    def test_worker_retries_removal_and_never_releases_lease_early(
        self,
    ) -> None:
        supervisor_id = "bg-" + "d" * 32
        job_root = self.root / supervisor_id
        job_root.mkdir(mode=0o700)
        events: list[str] = []
        receipt_states: list[str] = []
        backend = _LifecycleBackend(
            self.scope,
            events,
            removal_failures=2,
        )
        request = {
            "schema_version": 1,
            "supervisor_id": supervisor_id,
            "created_at": "2026-07-31T00:00:00+00:00",
            "backend": {},
            "command": {
                "argv": ["sleep", "1"],
                "timeout_seconds": 60,
                "deadline_monotonic_seconds": None,
                "summary_bytes": 4096,
                "environment": {},
                "network_target": None,
                "resource_request": {
                    "cpu": 1,
                    "memory_mib": 2048,
                    "gpu": 0,
                    "kvm": 0,
                    "network": 0,
                },
            },
            "name": "retry-cleanup",
            "lease": {
                "root": str(self.root / "leases"),
                "capacity": {
                    "cpu": 2,
                    "memory_mib": 4096,
                    "gpu": 0,
                    "kvm": 0,
                    "network": 0,
                },
                "poll_interval": 0.01,
                "wait_timeout": 1,
                "owner": f"test:{supervisor_id}",
            },
        }
        atomic_write_json(job_root / "request.json", request, mode=0o400)
        broker = _LifecycleBroker(events)
        real_atomic_write_json = atomic_write_json

        def recording_write(path, value, *args, **kwargs):
            if path.name == "receipt.json":
                receipt_states.append(str(value.get("state")))
            return real_atomic_write_json(path, value, *args, **kwargs)

        with (
            patch(
                "ctf_os.sandbox.supervisor._backend_from_value",
                return_value=backend,
            ),
            patch(
                "ctf_os.sandbox.supervisor.LeaseBroker",
                return_value=broker,
            ),
            patch(
                "ctf_os.sandbox.supervisor.atomic_write_json",
                side_effect=recording_write,
            ),
            patch("ctf_os.sandbox.supervisor.signal.signal"),
            patch("ctf_os.sandbox.supervisor.time.sleep"),
        ):
            result = _worker(job_root)

        self.assertEqual(result, 0)
        self.assertEqual(events.count("remove-failed"), 2)
        self.assertEqual(
            events[-3:],
            ["remove", "work-tree:background job terminal", "release"],
        )
        self.assertNotIn("release", events[:-1])
        self.assertIn("cleanup_pending", receipt_states)
        self.assertEqual(receipt_states[-1], "terminal")

    def test_inspect_control_failure_cannot_attest_runtime_absence(
        self,
    ) -> None:
        supervisor_id = "bg-" + "f" * 32
        calls: list[tuple[str, ...]] = []
        list_attempts = 0

        def runner(command, **_kwargs):
            nonlocal list_attempts
            calls.append(tuple(command))
            if command[1:3] == ["container", "inspect"]:
                return subprocess.CompletedProcess(
                    command,
                    1,
                    "",
                    "temporary Docker daemon failure",
                )
            if command[1:3] == ["container", "ls"]:
                list_attempts += 1
                if list_attempts == 1:
                    return subprocess.CompletedProcess(
                        command,
                        1,
                        "",
                        "temporary Docker daemon failure",
                    )
                return subprocess.CompletedProcess(command, 0, "", "")
            raise AssertionError(f"unexpected Docker command: {command}")

        backend = DockerSandboxBackend(self.scope, runner=runner)

        first = backend._remove_supervised_runtime(
            supervisor_id,
            runtime_id=None,
            missing_ok=True,
        )
        second = backend._remove_supervised_runtime(
            supervisor_id,
            runtime_id=None,
            missing_ok=True,
        )

        self.assertIn("absence attestation failed", str(first))
        self.assertIsNone(second)
        self.assertEqual(list_attempts, 2)
        self.assertFalse(
            any(command[1:4] == ("container", "rm", "--force") for command in calls)
        )

    def test_recovery_closes_unbound_post_acquire_crash_window(self) -> None:
        broker = LeaseBroker(
            self.root / "leases",
            ResourceVector(cpu=2, memory_mib=4096),
        )
        supervisor = BackgroundJobSupervisor(
            self.root / "supervisors",
            broker,
        )
        backend = _FakeBackend(self.scope)
        supervisor_id = "bg-" + "e" * 32
        owner = f"contest/forensic/memory:background:{supervisor_id}"
        lease = broker.acquire(
            ResourceVector(cpu=1, memory_mib=2048),
            timeout=0,
            owner=owner,
            durable=True,
        )
        self.assertIsNotNone(lease)
        assert lease is not None
        # Model SIGKILL: the kernel drops the worker's flock while the durable
        # metadata and an exact-labelled runtime may remain.
        os.close(lease._fd)  # type: ignore[attr-defined]
        lease._released = True  # type: ignore[attr-defined]
        job_root = supervisor._job_root(
            self.scope.fingerprint,
            supervisor_id,
        )
        job_root.mkdir(mode=0o700)
        atomic_write_json(
            job_root / "request.json",
            {
                "schema_version": 1,
                "supervisor_id": supervisor_id,
                "lease": {"owner": owner},
            },
            mode=0o400,
        )
        atomic_write_json(
            job_root / "receipt.json",
            {
                "schema_version": 1,
                "supervisor_id": supervisor_id,
                "state": "starting",
                "supervisor_pid": 99_999_999,
                "supervisor_start_ticks": 1,
            },
        )

        statuses = supervisor.recover(backend)  # type: ignore[arg-type]

        self.assertEqual(statuses, ())
        self.assertEqual(broker.status().used.cpu, 0)
        self.assertEqual(broker.status().leases, ())
        self.assertEqual(
            backend.events,
            [
                f"remove:{supervisor_id}:None:True",
                "work-tree:background orphan recovery",
            ],
        )
        receipt = _read_private_json(job_root / "receipt.json")
        self.assertEqual(receipt["state"], "recovered")
        self.assertEqual(receipt["lease_id"], lease.lease_id)

    def test_dead_monitor_quota_breach_is_failed_before_lease_reclaim(
        self,
    ) -> None:
        broker = LeaseBroker(
            self.root / "quota-recovery-leases",
            ResourceVector(cpu=2, memory_mib=4096),
        )
        supervisor = BackgroundJobSupervisor(
            self.root / "quota-recovery-supervisors",
            broker,
        )
        backend = _FakeBackend(
            self.scope,
            work_tree_error=True,
        )
        supervisor_id = "bg-" + "9" * 32
        owner = f"contest/forensic/memory:background:{supervisor_id}"
        lease = broker.acquire(
            ResourceVector(cpu=1, memory_mib=2048),
            timeout=0,
            owner=owner,
            durable=True,
        )
        self.assertIsNotNone(lease)
        assert lease is not None
        os.close(lease._fd)  # type: ignore[attr-defined]
        lease._released = True  # type: ignore[attr-defined]
        ref = JobRef(
            "job-00000001",
            self.scope.fingerprint,
            supervisor_id=supervisor_id,
        )
        job_root = supervisor._job_root(
            self.scope.fingerprint,
            supervisor_id,
        )
        job_root.mkdir(mode=0o700)
        atomic_write_json(
            job_root / "request.json",
            {
                "schema_version": 1,
                "supervisor_id": supervisor_id,
                "lease": {"owner": owner},
            },
            mode=0o400,
        )
        atomic_write_json(
            job_root / "receipt.json",
            {
                "schema_version": 1,
                "supervisor_id": supervisor_id,
                "state": "running",
                "supervisor_pid": 99_999_999,
                "supervisor_start_ticks": 1,
                "lease_id": lease.lease_id,
                "ref": {
                    "job_id": ref.job_id,
                    "scope_fingerprint": ref.scope_fingerprint,
                    "runtime_id": ref.runtime_id,
                    "supervisor_id": ref.supervisor_id,
                },
            },
        )

        statuses = supervisor.recover(backend, ref)  # type: ignore[arg-type]

        self.assertEqual(len(statuses), 1)
        self.assertEqual(statuses[0].status, JobState.FAILED)
        self.assertEqual(
            statuses[0].reason_code,
            "work_tree_quota_exceeded",
        )
        self.assertEqual(broker.status().leases, ())
        self.assertEqual(
            backend.events,
            [
                "status",
                "cancel:0",
                f"remove:{supervisor_id}:none:True",
                "work-tree:background orphan recovery",
            ],
        )
        receipt = _read_private_json(job_root / "receipt.json")
        self.assertEqual(receipt["state"], "failed")
        self.assertEqual(
            receipt["reason_code"],
            "work_tree_quota_exceeded",
        )


if __name__ == "__main__":
    unittest.main()
