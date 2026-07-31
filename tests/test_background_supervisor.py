from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ctf_os.director.leases import LeaseBroker
from ctf_os.director.resources import ResourceVector
from ctf_os.sandbox.client import LocalChallengeSandboxClient
from ctf_os.sandbox.docker import DockerSandboxBackend
from ctf_os.sandbox.supervisor import (
    BackgroundJobSupervisor,
    _read_private_json,
    _worker,
)
from ctf_os.sandbox.types import (
    ChallengeScope,
    CommandSpec,
    JobLog,
    JobRef,
    JobState,
    JobStatus,
    NetworkPolicy,
)
from ctf_os.store.atomic import atomic_write_json


class _FakeBackend:
    def __init__(self, scope: ChallengeScope) -> None:
        self.scope = scope
        self.events: list[str] = []

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


class _LifecycleBackend:
    def __init__(
        self,
        scope: ChallengeScope,
        events: list[str],
        *,
        removal_failures: int = 0,
    ) -> None:
        self.scope = scope
        self.events = events
        self.removal_failures = removal_failures
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
        state = (
            JobState.RUNNING
            if self.status_calls == 1
            else JobState.COMPLETED
        )
        return JobStatus(ref, state, exit_code=0 if state is JobState.COMPLETED else None)

    def cancel_job(self, ref, *, grace_seconds):
        self.events.append(f"cancel:{grace_seconds}")
        return JobStatus(ref, JobState.CANCELLED, exit_code=130, cancelled=True)

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

    def start(self, backend, spec, *, name, owner):
        del backend, spec, name, owner
        self.calls.append("start")
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
            ["start", "status", "log:7", "cancel:0", "list", "recover"],
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
        self.assertEqual(events[-2:], ["remove", "release"])
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
            [f"remove:{supervisor_id}:None:True"],
        )
        receipt = _read_private_json(job_root / "receipt.json")
        self.assertEqual(receipt["state"], "recovered")
        self.assertEqual(receipt["lease_id"], lease.lease_id)


if __name__ == "__main__":
    unittest.main()
