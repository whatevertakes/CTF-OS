from __future__ import annotations

import multiprocessing
import tempfile
import threading
import time
import unittest
from pathlib import Path

from ctf_os.live_broker import (
    LiveBrokerClient,
    LiveBrokerServer,
    LiveBrokerService,
)
from ctf_os.models import ChallengeIdentity
from ctf_os.store import ChallengeLock, RevisionConflict, StateStore


def _cas_writer(
    root: str,
    identity_value: tuple[str, str, str],
    writer_name: str,
    barrier,
    results,
) -> None:
    store = StateStore(Path(root))
    identity = ChallengeIdentity(*identity_value)
    base = store.read_snapshot(identity)
    barrier.wait()

    def mutate(state) -> None:
        state.extra.setdefault("parallel_writers", []).append(writer_name)

    try:
        committed = store.update(
            identity,
            mutate,
            expected_revision=base.revision,
        )
    except RevisionConflict as error:
        results.put(("conflict", error.expected, error.actual))
    else:
        results.put(("committed", committed.revision, writer_name))


class ReadConcurrencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.store = StateStore(self.root)
        self.identity = ChallengeIdentity(
            "Concurrency CTF",
            "misc",
            "Atomic reads",
        )
        self.store.create_challenge(self.identity, prompt="inspect safely")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_snapshots_ignore_session_and_writer_locks_without_writes(
        self,
    ) -> None:
        paths = self.store.challenge_paths(self.identity)
        before = {
            path: path.read_bytes()
            for path in (
                paths.state,
                paths.previous_state,
                paths.events,
                paths.current_context,
            )
        }
        readers = 8
        barrier = threading.Barrier(readers + 1)
        revisions: list[int] = []
        errors: list[BaseException] = []

        def read() -> None:
            try:
                barrier.wait()
                revisions.append(
                    self.store.read_snapshot(self.identity).revision
                )
            except BaseException as error:
                errors.append(error)

        with (
            ChallengeLock(
                paths.runtime / "session.lock",
                timeout=0,
            ) as session_lock,
            ChallengeLock(paths.lock, timeout=0) as writer_lock,
        ):
            session_lock.acquire()
            writer_lock.acquire()
            threads = [
                threading.Thread(target=read, name=f"snapshot-{index}")
                for index in range(readers)
            ]
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join(2)
                self.assertFalse(thread.is_alive())

        self.assertFalse(errors, errors)
        self.assertEqual(revisions, [0] * readers)
        self.assertEqual(
            {
                path: path.read_bytes()
                for path in before
            },
            before,
        )

    def test_atomic_snapshots_observe_only_coherent_revisions(self) -> None:
        self.store.update(
            self.identity,
            lambda state: state.extra.__setitem__("epoch", 1),
        )
        start = threading.Barrier(7)
        stop = threading.Event()
        observations: list[tuple[int, int]] = []
        errors: list[BaseException] = []

        def reader() -> None:
            try:
                start.wait()
                while not stop.is_set():
                    snapshot = self.store.read_snapshot(self.identity)
                    observations.append(
                        (
                            snapshot.revision,
                            int(snapshot.extra["epoch"]),
                        )
                    )
            except BaseException as error:
                errors.append(error)

        def writer() -> None:
            try:
                start.wait()
                for expected_epoch in range(2, 32):
                    self.store.update(
                        self.identity,
                        lambda state, value=expected_epoch: (
                            state.extra.__setitem__("epoch", value)
                        ),
                    )
            except BaseException as error:
                errors.append(error)
            finally:
                stop.set()

        threads = [
            threading.Thread(target=reader, name=f"reader-{index}")
            for index in range(6)
        ]
        writer_thread = threading.Thread(target=writer, name="writer")
        for thread in (*threads, writer_thread):
            thread.start()
        for thread in (*threads, writer_thread):
            thread.join(5)
            self.assertFalse(thread.is_alive())

        self.assertFalse(errors, errors)
        self.assertTrue(observations)
        self.assertTrue(
            all(revision == epoch for revision, epoch in observations)
        )
        final = self.store.read_snapshot(self.identity)
        self.assertEqual((final.revision, final.extra["epoch"]), (31, 31))

    def test_process_writers_are_serialized_and_stale_cas_loses(
        self,
    ) -> None:
        context = multiprocessing.get_context("fork")
        barrier = context.Barrier(2)
        results = context.Queue()
        identity_value = (
            self.identity.contest_id,
            self.identity.category,
            self.identity.challenge_id,
        )
        processes = [
            context.Process(
                target=_cas_writer,
                args=(
                    str(self.root),
                    identity_value,
                    name,
                    barrier,
                    results,
                ),
            )
            for name in ("alpha", "beta")
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(5)
            self.assertFalse(process.is_alive())
            self.assertEqual(process.exitcode, 0)

        outcomes = sorted(results.get(timeout=1) for _ in processes)
        self.assertEqual(
            [outcome[0] for outcome in outcomes],
            ["committed", "conflict"],
        )
        final = self.store.read_snapshot(self.identity)
        self.assertEqual(final.revision, 1)
        self.assertEqual(len(final.extra["parallel_writers"]), 1)

    def test_live_mailbox_reads_overlap_each_other_and_active_writer(
        self,
    ) -> None:
        writer_entered = threading.Event()
        release_writer = threading.Event()
        read_barrier = threading.Barrier(2)
        active_lock = threading.Lock()
        active_reads = 0
        maximum_reads = 0

        class FakeService:
            expected_scope = "a" * 64

            @staticmethod
            def is_read_only_request(operation, params) -> bool:
                return LiveBrokerService.is_read_only_request(
                    operation,
                    params,
                )

            @staticmethod
            def dispatch(request):
                nonlocal active_reads, maximum_reads
                operation = request["operation"]
                if operation == "tool.run":
                    writer_entered.set()
                    if not release_writer.wait(3):
                        raise AssertionError("writer was not released")
                    return {"writer": "done"}
                if operation != "inspect":
                    raise AssertionError(f"unexpected operation: {operation}")
                with active_lock:
                    active_reads += 1
                    maximum_reads = max(maximum_reads, active_reads)
                try:
                    read_barrier.wait(2)
                    return {"revision": 0}
                finally:
                    with active_lock:
                        active_reads -= 1

        mailbox = self.root / "live-mailbox"
        mailbox.mkdir(mode=0o700)
        service = FakeService()
        errors: list[BaseException] = []
        read_results: list[object] = []

        def call(operation: str) -> None:
            try:
                result = LiveBrokerClient(mailbox, "token").call(
                    operation,
                    self.identity,
                    (
                        {"section": "state"}
                        if operation == "inspect"
                        else {}
                    ),
                    timeout=4,
                )
                if operation == "inspect":
                    read_results.append(result)
            except BaseException as error:
                errors.append(error)

        with LiveBrokerServer(
            mailbox,
            service,  # type: ignore[arg-type]
        ) as server:
            server.start()
            writer = threading.Thread(
                target=call,
                args=("tool.run",),
            )
            writer.start()
            self.assertTrue(writer_entered.wait(2))
            readers = [
                threading.Thread(target=call, args=("inspect",))
                for _ in range(2)
            ]
            for reader in readers:
                reader.start()
            for reader in readers:
                reader.join(3)
                self.assertFalse(reader.is_alive())
            self.assertFalse(release_writer.is_set())
            release_writer.set()
            writer.join(3)
            self.assertFalse(writer.is_alive())

        self.assertFalse(errors, errors)
        self.assertEqual(len(read_results), 2)
        self.assertEqual(maximum_reads, 2)


if __name__ == "__main__":
    unittest.main()
