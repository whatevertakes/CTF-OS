from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from ctf_os.engine.challenge import ChallengeEngine, EngineError
from ctf_os.models import ChallengeIdentity
from ctf_os.sandbox.types import (
    CommandSpec,
    JobLog,
    JobRef,
    JobState,
    JobStatus,
)


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

    def start_job(
        self,
        spec: CommandSpec,
        *,
        name: str | None = None,
    ) -> JobRef:
        del name
        self.started.append(spec)
        return self.ref

    def list_jobs(self) -> tuple[JobStatus, ...]:
        return (self.status,)

    def recover_jobs(self) -> tuple[JobStatus, ...]:
        return (self.status,)

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
        self.assertEqual(launched.revision, before.revision + 1)
        records = launched.extra["background_jobs"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["job_id"], ref.job_id)
        self.assertEqual(records[0]["supervisor_id"], ref.supervisor_id)
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
        self.assertEqual(cancelled.revision, revision_before_reads + 1)
        self.assertEqual(sandbox.cancel_calls, 1)
        self.assertEqual(
            cancelled.extra["background_jobs"][0]["status"],
            "cancelled",
        )


if __name__ == "__main__":
    unittest.main()
