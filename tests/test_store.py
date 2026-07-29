from __future__ import annotations

import builtins
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import warnings
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

import ctf_os.store.atomic as atomic_module
from ctf_os.models import (
    ArtifactReference,
    CandidateStatus,
    ChallengeIdentity,
    ChallengeStatus,
    ClosureCompleteness,
    FlagCandidate,
    Goal,
    GoalStatus,
    ModelValidationError,
    SubmissionStatus,
)
from ctf_os.store.atomic import append_json_line, atomic_write_bytes


class AtomicWriteTests(unittest.TestCase):
    def test_temporary_is_private_at_initial_allocation_under_umask_zero(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ".state.json.private.tmp"
            pending = []
            previous_umask = os.umask(0)
            try:
                stream = atomic_module._open_exclusive_with_handoff(
                    path,
                    pending_handoff=pending,
                )
            finally:
                os.umask(previous_umask)
            try:
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            finally:
                stream.close()
                path.unlink()

    def test_open_result_store_interrupt_closes_and_removes_exact_temporary(
        self,
    ) -> None:
        for interruption in (
            KeyboardInterrupt("synthetic atomic allocation interrupt"),
            SystemExit(31),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    destination = root / "state.json"
                    before_fds = (
                        set(Path("/proc/self/fd").iterdir())
                        if Path("/proc/self/fd").is_dir()
                        else set()
                    )
                    injected = False

                    def profile(frame, event, argument):
                        nonlocal injected
                        if (
                            frame.f_code
                            is atomic_module._open_exclusive_with_handoff.__code__
                            and event == "c_return"
                            and argument is builtins.open
                            and not injected
                        ):
                            injected = True
                            raise interruption

                    previous_profile = sys.getprofile()
                    try:
                        with warnings.catch_warnings():
                            warnings.simplefilter("ignore", ResourceWarning)
                            sys.setprofile(profile)
                            with self.assertRaises(
                                type(interruption)
                            ) as raised:
                                atomic_write_bytes(destination, b"secret")
                    finally:
                        sys.setprofile(previous_profile)

                    self.assertTrue(injected)
                    self.assertIs(raised.exception, interruption)
                    self.assertFalse(destination.exists())
                    self.assertEqual(list(root.iterdir()), [])
                    if before_fds:
                        self.assertEqual(
                            set(Path("/proc/self/fd").iterdir()),
                            before_fds,
                        )
                    atomic_write_bytes(destination, b"recovered")
                    self.assertEqual(
                        destination.read_bytes(),
                        b"recovered",
                    )

    def test_random_name_collision_does_not_clobber_existing_file(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "state.json"
            collision = root / f".{destination.name}.{'a' * 32}.tmp"
            collision.write_bytes(b"belongs to someone else")

            with mock.patch.object(
                atomic_module.secrets,
                "token_hex",
                side_effect=("a" * 32, "b" * 32),
            ):
                atomic_write_bytes(destination, b"canonical", mode=0o640)

            self.assertEqual(
                collision.read_bytes(),
                b"belongs to someone else",
            )
            self.assertEqual(destination.read_bytes(), b"canonical")
            self.assertEqual(destination.stat().st_mode & 0o777, 0o640)

    def test_partial_stream_write_completes_and_zero_write_is_atomic(
        self,
    ) -> None:
        real_open = atomic_module._open_exclusive_with_handoff

        class ShortWriter:
            def __init__(self, stream, *, zero: bool = False) -> None:
                self.stream = stream
                self.zero = zero
                self.first = True

            def write(self, payload):
                if self.first:
                    self.first = False
                    if self.zero:
                        return 0
                    partial = memoryview(payload)[: max(1, len(payload) // 2)]
                    return self.stream.write(partial)
                return self.stream.write(payload)

            def __getattr__(self, name):
                return getattr(self.stream, name)

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "state.json"

            def partial_open(*args, **kwargs):
                return ShortWriter(real_open(*args, **kwargs))

            with mock.patch.object(
                atomic_module,
                "_open_exclusive_with_handoff",
                side_effect=partial_open,
            ):
                atomic_write_bytes(destination, b"complete payload")
            self.assertEqual(destination.read_bytes(), b"complete payload")

            before = destination.read_bytes()

            def zero_open(*args, **kwargs):
                return ShortWriter(
                    real_open(*args, **kwargs),
                    zero=True,
                )

            with (
                mock.patch.object(
                    atomic_module,
                    "_open_exclusive_with_handoff",
                    side_effect=zero_open,
                ),
                self.assertRaisesRegex(
                    OSError,
                    "atomic file write made no progress",
                ),
            ):
                atomic_write_bytes(destination, b"must not replace")

            self.assertEqual(destination.read_bytes(), before)
            self.assertEqual(
                list(destination.parent.glob(f".{destination.name}.*.tmp")),
                [],
            )

    def test_zero_progress_json_line_append_fails_and_next_append_works(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            before = b'{"old":true}\n'
            path.write_bytes(before)

            with (
                mock.patch.object(
                    atomic_module.os,
                    "write",
                    return_value=0,
                ),
                self.assertRaisesRegex(
                    OSError,
                    "JSON line append made no progress",
                ),
            ):
                append_json_line(path, {"new": False})

            self.assertEqual(path.read_bytes(), before)
            append_json_line(path, {"new": True})
            self.assertEqual(
                path.read_text(encoding="utf-8").splitlines(),
                ['{"old":true}', '{"new":true}'],
            )
from ctf_os.store import (
    MAX_CANONICAL_STATE_BYTES,
    ArtifactValidationError,
    CorruptStateError,
    FileLock,
    InvalidIdentity,
    RevisionConflict,
    StateNotFound,
    StateStore,
    WorkerResultValidationError,
    validate_artifact,
)


class StateStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name).resolve()
        self.store = StateStore(self.root)
        self.identity = ChallengeIdentity("Demo CTF", "web", "Warmup")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def create(self):
        return self.store.create_challenge(
            self.identity,
            description="find the flag",
            prompt="nc challenge.invalid 31337",
        )

    def test_state_root_is_private_even_under_umask_zero_and_is_tightened(
        self,
    ) -> None:
        separate = self.root / "private-store"
        separate.mkdir()
        state_root = separate / ".ctfos"
        state_root.mkdir(mode=0o777)
        state_root.chmod(0o777)

        previous_umask = os.umask(0)
        try:
            StateStore(separate)
        finally:
            os.umask(previous_umask)

        self.assertEqual(state_root.stat().st_mode & 0o777, 0o700)

    def test_create_builds_09_layout_and_namespaces_same_name_by_category(
        self,
    ) -> None:
        state = self.create()
        other = self.store.create_challenge(
            "Demo CTF", "rev", "Warmup", description="reverse it"
        )
        paths = self.store.challenge_paths(self.identity)

        self.assertEqual(state.identity, self.identity)
        self.assertNotEqual(paths.root, self.store.challenge_paths(other).root)
        self.assertTrue(paths.state.is_file())
        self.assertTrue(paths.previous_state.is_file())
        self.assertTrue(paths.events.is_file())
        self.assertTrue(paths.lock.is_file())
        self.assertTrue(paths.current_context.is_file())
        for directory in (
            paths.runtime,
            paths.context_history,
            paths.runs,
            paths.artifacts,
            paths.knowledge,
            paths.proof,
            paths.exports,
        ):
            self.assertTrue(directory.is_dir(), directory)

        payload = json.loads(paths.state.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["revision"], 0)
        self.assertEqual(payload["category"], "web")

    def test_identity_rejects_terminal_controls_and_overlong_components(
        self,
    ) -> None:
        with self.assertRaisesRegex(InvalidIdentity, "control"):
            self.store.create_challenge(
                ChallengeIdentity("contest\nspoof", "web", "challenge")
            )
        with self.assertRaisesRegex(InvalidIdentity, "255 UTF-8 bytes"):
            self.store.create_challenge(
                ChallengeIdentity("contest", "web", "가" * 86)
            )

    def test_missing_state_is_distinct_from_corrupt_state(self) -> None:
        with self.assertRaises(StateNotFound):
            self.store.load(self.identity)

    def test_save_is_compare_and_swap_and_preserves_previous_revision(
        self,
    ) -> None:
        first = self.create()
        stale = self.store.load(self.identity)
        first.description = "updated"

        committed = self.store.save(first, expected_revision=0)

        self.assertEqual(committed.revision, 1)
        self.assertEqual(self.store.load(self.identity).description, "updated")
        previous = json.loads(
            self.store.challenge_paths(self.identity).previous_state.read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(previous["revision"], 0)
        with self.assertRaises(RevisionConflict) as raised:
            self.store.save(stale, expected_revision=0)
        self.assertEqual(raised.exception.expected, 0)
        self.assertEqual(raised.exception.actual, 1)

    def test_update_releases_state_lock_when_acquire_return_is_interrupted(
        self,
    ) -> None:
        initial = self.create()
        paths = self.store.challenge_paths(self.identity)
        canonical = paths.state.read_bytes()
        previous = paths.previous_state.read_bytes()
        real_acquire = FileLock.acquire

        for interruption in (
            KeyboardInterrupt("synthetic state lock handoff interrupt"),
            SystemExit(43),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                injected = False

                def acquire_then_interrupt(lock):
                    nonlocal injected
                    acquired = real_acquire(lock)
                    if lock.path == paths.lock and not injected:
                        injected = True
                        raise interruption
                    return acquired

                with (
                    mock.patch.object(
                        FileLock,
                        "acquire",
                        new=acquire_then_interrupt,
                    ),
                    self.assertRaises(type(interruption)) as raised,
                ):
                    self.store.update(
                        self.identity,
                        lambda state: setattr(
                            state,
                            "description",
                            "must not commit",
                        ),
                    )

                self.assertTrue(injected)
                self.assertIs(raised.exception, interruption)
                self.assertEqual(paths.state.read_bytes(), canonical)
                self.assertEqual(paths.previous_state.read_bytes(), previous)

        committed = self.store.update(
            self.identity,
            lambda state: setattr(
                state,
                "description",
                "next update succeeds",
            ),
        )
        self.assertEqual(committed.revision, initial.revision + 1)
        self.assertEqual(committed.description, "next update succeeds")

    def test_state_json_byte_cap_is_inclusive_and_failed_write_is_atomic(
        self,
    ) -> None:
        state = self.create()
        paths = self.store.challenge_paths(self.identity)
        canonical = paths.state.read_bytes()
        previous = paths.previous_state.read_bytes()
        self.assertEqual(MAX_CANONICAL_STATE_BYTES, 16 * 1024 * 1024)

        with mock.patch(
            "ctf_os.store.files.MAX_CANONICAL_STATE_BYTES",
            len(canonical),
        ):
            self.assertEqual(
                self.store._serialized_state(state),
                canonical,
            )
        with mock.patch(
            "ctf_os.store.files.MAX_CANONICAL_STATE_BYTES",
            len(canonical) - 1,
        ), self.assertRaisesRegex(
            WorkerResultValidationError,
            "canonical state JSON exceeds",
        ):
            self.store._serialized_state(state)

        def enlarge(current):
            current.prompt = "x" * len(canonical)

        with mock.patch(
            "ctf_os.store.files.MAX_CANONICAL_STATE_BYTES",
            len(canonical),
        ), self.assertRaisesRegex(
            WorkerResultValidationError,
            "canonical state JSON exceeds",
        ):
            self.store.update(self.identity, enlarge)
        self.assertEqual(paths.state.read_bytes(), canonical)
        self.assertEqual(paths.previous_state.read_bytes(), previous)

    def test_invalid_candidate_update_is_rejected_atomically(self) -> None:
        initial = self.create()
        paths = self.store.challenge_paths(self.identity)
        canonical = paths.state.read_bytes()
        previous = paths.previous_state.read_bytes()

        def add_invalid_candidate(current):
            current.candidates.append(
                FlagCandidate(
                    id="C-invalid",
                    value="KCTF{canonical\tcontrol}",
                )
            )

        with self.assertRaises(ModelValidationError):
            self.store.update(self.identity, add_invalid_candidate)

        unchanged = self.store.load(self.identity)
        self.assertEqual(unchanged.revision, initial.revision)
        self.assertEqual(unchanged.candidates, [])
        self.assertEqual(paths.state.read_bytes(), canonical)
        self.assertEqual(paths.previous_state.read_bytes(), previous)

    def test_oversized_state_read_recovers_only_from_a_bounded_previous(
        self,
    ) -> None:
        original = self.create()
        paths = self.store.challenge_paths(self.identity)
        canonical = paths.state.read_bytes()
        paths.state.write_bytes(canonical + b" ")

        with mock.patch(
            "ctf_os.store.files.MAX_CANONICAL_STATE_BYTES",
            len(canonical),
        ):
            recovered = self.store.load(self.identity)
        self.assertEqual(recovered.revision, original.revision)
        self.assertEqual(paths.state.read_bytes(), canonical)

        paths.state.write_bytes(canonical + b" ")
        paths.previous_state.write_bytes(canonical + b" ")
        with mock.patch(
            "ctf_os.store.files.MAX_CANONICAL_STATE_BYTES",
            len(canonical),
        ), self.assertRaisesRegex(
            CorruptStateError,
            "state.json and state.prev.json are unusable",
        ):
            self.store.load(self.identity)

    def test_artifact_byte_cap_applies_when_digest_rehash_is_disabled(
        self,
    ) -> None:
        store = StateStore(self.root, max_artifact_bytes=5)
        store.create_challenge(self.identity)
        paths = store.challenge_paths(self.identity)
        first_path = paths.artifacts / "first.bin"
        second_path = paths.artifacts / "second.bin"
        first_path.write_bytes(b"abc")
        second_path.write_bytes(b"def")

        def add_first(current):
            current.artifacts.append(
                ArtifactReference(
                    id="A-first",
                    path="artifacts/first.bin",
                    sha256=hashlib.sha256(b"abc").hexdigest(),
                    size=None,
                )
            )

        store.update(
            self.identity,
            add_first,
            validate_artifacts=False,
        )
        before_state = paths.state.read_bytes()
        before_previous = paths.previous_state.read_bytes()

        def add_second(current):
            current.artifacts.append(
                ArtifactReference(
                    id="A-second",
                    path="artifacts/second.bin",
                    sha256=hashlib.sha256(b"def").hexdigest(),
                    size=3,
                )
            )

        with self.assertRaisesRegex(
            ArtifactValidationError,
            "canonical artifact bytes exceed",
        ):
            store.update(
                self.identity,
                add_second,
                validate_artifacts=False,
            )
        self.assertEqual(paths.state.read_bytes(), before_state)
        self.assertEqual(paths.previous_state.read_bytes(), before_previous)
        self.assertEqual(
            [item.id for item in store.load(self.identity).artifacts],
            ["A-first"],
        )

    def test_interrupted_replace_leaves_old_state_readable(self) -> None:
        original = self.create()
        original.description = "not committed"
        real_replace = __import__("os").replace
        replacements = 0

        def fail_second_replace(source, destination):
            nonlocal replacements
            replacements += 1
            if replacements == 2:
                raise OSError("simulated power loss")
            return real_replace(source, destination)

        with mock.patch(
            "ctf_os.store.atomic.os.replace", side_effect=fail_second_replace
        ), self.assertRaisesRegex(OSError, "power loss"):
            self.store.save(original)

        recovered = self.store.load(self.identity)
        self.assertEqual(recovered.revision, 0)
        self.assertEqual(recovered.description, "find the flag")

    def test_candidate_intent_reconciles_once_without_printing(self) -> None:
        state = self.create()
        intent_id = self.store.record_candidate_intent(
            self.identity,
            value="flag{journal_recovery}",
            source="batch:raw.fragment",
            source_run_id="run-that-did-not-commit",
        )
        paths = self.store.challenge_paths(self.identity)

        self.assertEqual(paths.candidate_intents.stat().st_mode & 0o777, 0o600)
        self.assertEqual(
            [item["id"] for item in self.store.load_candidate_intents(
                self.identity
            )],
            [intent_id],
        )
        self.assertEqual(self.store.load(self.identity).revision, state.revision)

        terminal = io.StringIO()
        with redirect_stderr(terminal):
            recovered = self.store.reconcile_candidate_intents(self.identity)

        self.assertEqual(terminal.getvalue(), "")
        self.assertEqual(recovered.revision, state.revision + 1)
        self.assertEqual(len(recovered.candidates), 1)
        candidate = recovered.candidates[0]
        self.assertEqual(candidate.id, intent_id)
        self.assertEqual(candidate.value, "flag{journal_recovery}")
        self.assertIsNone(candidate.source_run_id)
        self.assertEqual(
            candidate.extra["intended_source_run_id"],
            "run-that-did-not-commit",
        )
        self.assertEqual(self.store.load_candidate_intents(self.identity), ())

        again = self.store.reconcile_candidate_intents(self.identity)
        self.assertEqual(again.revision, recovered.revision)
        self.assertEqual(len(again.candidates), 1)

    def test_candidate_intent_clear_requires_canonical_candidate(self) -> None:
        self.create()
        self.store.record_candidate_intent(
            self.identity,
            value="flag{not_committed_yet}",
            source="tool:stdout-live",
        )

        with self.assertRaisesRegex(
            WorkerResultValidationError,
            "before canonical commit",
        ):
            self.store.clear_candidate_intents(
                self.identity,
                ("flag{not_committed_yet}",),
            )

        self.assertEqual(
            len(self.store.load_candidate_intents(self.identity)),
            1,
        )

    def test_candidate_intent_commit_before_clear_is_idempotent(self) -> None:
        state = self.create()
        self.store.record_candidate_intent(
            self.identity,
            value="flag{commit_won_clear_lost}",
            source="batch:raw.fragment",
        )
        real_write = self.store._write_candidate_intents_locked

        def fail_empty_journal(paths, intents):
            if not intents:
                raise OSError("simulated crash before candidate intent clear")
            return real_write(paths, intents)

        with mock.patch.object(
            self.store,
            "_write_candidate_intents_locked",
            side_effect=fail_empty_journal,
        ), self.assertRaisesRegex(OSError, "before candidate intent clear"):
            self.store.reconcile_candidate_intents(self.identity)

        committed = self.store.load(self.identity)
        self.assertEqual(committed.revision, state.revision + 1)
        self.assertEqual(
            [item.value for item in committed.candidates],
            ["flag{commit_won_clear_lost}"],
        )
        self.assertEqual(
            len(self.store.load_candidate_intents(self.identity)),
            1,
        )

        restarted = StateStore(self.root)
        recovered = restarted.reconcile_candidate_intents(self.identity)
        self.assertEqual(recovered.revision, committed.revision)
        self.assertEqual(len(recovered.candidates), 1)
        self.assertEqual(restarted.load_candidate_intents(self.identity), ())

    def test_candidate_intent_journal_rejects_symlink_and_bounds(self) -> None:
        self.create()
        paths = self.store.challenge_paths(self.identity)
        outside = self.root / "outside.json"
        outside.write_text('{"untouched":true}\n', encoding="utf-8")
        paths.candidate_intents.symlink_to(outside)
        with self.assertRaises(OSError):
            self.store.record_candidate_intent(
                self.identity,
                value="flag{nofollow}",
                source="batch:raw.fragment",
            )
        self.assertEqual(
            outside.read_text(encoding="utf-8"),
            '{"untouched":true}\n',
        )
        paths.candidate_intents.unlink()

        with mock.patch("ctf_os.store.files._CANDIDATE_INTENT_LIMIT", 1):
            self.store.record_candidate_intent(
                self.identity,
                value="flag{first}",
                source="batch:raw.fragment",
            )
            with self.assertRaisesRegex(
                WorkerResultValidationError,
                "journal is full",
            ):
                self.store.record_candidate_intent(
                    self.identity,
                    value="flag{second}",
                    source="batch:raw.fragment",
                )
        self.store.reconcile_candidate_intents(self.identity)
        with mock.patch(
            "ctf_os.store.files._CANDIDATE_INTENT_VALUE_BYTES_LIMIT",
            4,
        ), self.assertRaisesRegex(
            WorkerResultValidationError,
            "value byte limit",
        ):
            self.store.record_candidate_intent(
                self.identity,
                value="flag{too_many_bytes}",
                source="batch:raw.fragment",
            )

    def test_corrupt_current_state_recovers_previous_image(self) -> None:
        state = self.create()
        state.description = "revision one"
        self.store.save(state)
        paths = self.store.challenge_paths(self.identity)
        paths.state.write_text("{broken", encoding="utf-8")

        recovered = self.store.load(self.identity)

        self.assertEqual(recovered.revision, 0)
        self.assertEqual(recovered.description, "find the flag")
        json.loads(paths.state.read_text(encoding="utf-8"))
        self.assertIn("state_recovered", paths.events.read_text("utf-8"))

    def test_recovery_refuses_to_erase_a_newer_accepted_submission(
        self,
    ) -> None:
        state = self.create()
        state.status = ChallengeStatus.READY_TO_SUBMIT
        state.candidates.append(
            FlagCandidate(
                id="C-recovery-accepted",
                value="flag{accepted_before_corruption}",
                status=CandidateStatus.READY_TO_SUBMIT,
            )
        )
        state = self.store.save(state)
        solved = self.store.record_submission(
            self.identity,
            candidate_id="C-recovery-accepted",
            outcome=SubmissionStatus.ACCEPTED,
            submission_id="SUB-recovery-accepted",
            proof_passed=True,
            expected_revision=state.revision,
        )
        self.assertIs(solved.status, ChallengeStatus.SOLVED)
        paths = self.store.challenge_paths(self.identity)
        contest_paths = self.store.contest_paths(
            self.identity.contest_id
        )
        ledger_before = contest_paths.submissions.read_bytes()
        corrupt = b"{corrupt-current-state"
        paths.state.write_bytes(corrupt)

        with self.assertRaisesRegex(
            CorruptStateError,
            "newer than recoverable state",
        ):
            self.store.load(self.identity)

        self.assertEqual(paths.state.read_bytes(), corrupt)
        self.assertEqual(
            contest_paths.submissions.read_bytes(),
            ledger_before,
        )

    def test_artifact_path_hash_and_symlink_are_validated(self) -> None:
        self.create()
        paths = self.store.challenge_paths(self.identity)
        artifact_path = paths.artifacts / "solver.py"
        artifact_path.write_bytes(b"print('ok')\n")
        digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        reference = ArtifactReference(
            id="A-1",
            path="artifacts/solver.py",
            sha256=digest,
        )

        self.assertEqual(
            validate_artifact(paths.root, reference), artifact_path
        )
        with self.assertRaisesRegex(ArtifactValidationError, "normalized"):
            validate_artifact(
                paths.root,
                ArtifactReference(
                    id="A-2",
                    path="artifacts/../state.json",
                    sha256=digest,
                ),
            )
        with self.assertRaisesRegex(ArtifactValidationError, "hash mismatch"):
            validate_artifact(
                paths.root,
                ArtifactReference(
                    id="A-3",
                    path="artifacts/solver.py",
                    sha256="0" * 64,
                ),
            )
        link = paths.artifacts / "link"
        link.symlink_to(artifact_path)
        with self.assertRaisesRegex(ArtifactValidationError, "symlink"):
            validate_artifact(
                paths.root,
                ArtifactReference(
                    id="A-4",
                    path="artifacts/link",
                    sha256=digest,
                ),
            )

    def test_run_result_rejects_stale_revision_and_records_validation(
        self,
    ) -> None:
        state = self.create()
        run = self.store.create_run(
            self.identity,
            "run-1",
            request={"role": "observer"},
        )
        state.description = "changed while worker ran"
        self.store.save(state)
        self.store.write_run_result(
            self.identity,
            "run-1",
            {"base_revision": 0, "artifacts": []},
        )

        with self.assertRaises(RevisionConflict):
            self.store.validate_worker_result(
                self.identity, run_id="run-1"
            )

        validation = json.loads(run.validation.read_text(encoding="utf-8"))
        self.assertFalse(validation["ok"])
        self.assertEqual(validation["error_type"], "RevisionConflict")

    def test_current_and_board_views_are_derived_from_state(self) -> None:
        state = self.create()
        state.status = ChallengeStatus.ACTIVE
        committed = self.store.save(state)
        paths = self.store.challenge_paths(self.identity)

        current = paths.current_context.read_text(encoding="utf-8")
        board = self.store.contest_paths("Demo CTF").board.read_text("utf-8")
        entry = self.store.board_entry(self.identity)

        self.assertIn("find the flag", current)
        self.assertIn("`ACTIVE`", current)
        self.assertIn("Warmup", board)
        self.assertEqual(entry["revision"], committed.revision)

    def test_refresh_board_releases_lock_when_acquire_return_is_interrupted(
        self,
    ) -> None:
        self.create()
        contest_paths = self.store.contest_paths(self.identity.contest_id)
        board_json = contest_paths.root / "board.json"
        board_before = contest_paths.board.read_bytes()
        board_json_before = board_json.read_bytes()
        board_lock = contest_paths.runtime / "board.lock"
        real_acquire = FileLock.acquire

        for interruption in (
            KeyboardInterrupt("synthetic board lock handoff interrupt"),
            SystemExit(37),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                injected = False

                def acquire_then_interrupt(lock):
                    nonlocal injected
                    acquired = real_acquire(lock)
                    if lock.path == board_lock and not injected:
                        injected = True
                        raise interruption
                    return acquired

                with (
                    mock.patch.object(
                        FileLock,
                        "acquire",
                        new=acquire_then_interrupt,
                    ),
                    self.assertRaises(type(interruption)) as raised,
                ):
                    self.store.refresh_board(self.identity.contest_id)

                self.assertTrue(injected)
                self.assertIs(raised.exception, interruption)
                self.assertEqual(contest_paths.board.read_bytes(), board_before)
                self.assertEqual(board_json.read_bytes(), board_json_before)

                probe = FileLock(board_lock, timeout=0)
                probe.acquire()
                probe.release()
                refreshed = self.store.refresh_board(
                    self.identity.contest_id
                )
                self.assertEqual(
                    [entry["challenge_id"] for entry in refreshed],
                    [self.identity.challenge_id],
                )
                board_before = contest_paths.board.read_bytes()
                board_json_before = board_json.read_bytes()

    def test_manual_submission_outcome_is_challenge_and_contest_durable(
        self,
    ) -> None:
        state = self.create()
        state.status = ChallengeStatus.READY_TO_SUBMIT
        state.candidates.append(
            FlagCandidate(
                id="C-1",
                value="flag{operator_submitted_this}",
                status=CandidateStatus.READY_TO_SUBMIT,
            )
        )
        state = self.store.save(state)

        solved = self.store.record_submission(
            self.identity,
            candidate_id="C-1",
            outcome=SubmissionStatus.ACCEPTED,
            response="correct",
            submission_id="SUB-1",
            proof_passed=True,
            expected_revision=state.revision,
        )

        self.assertEqual(solved.status, ChallengeStatus.SOLVED)
        self.assertEqual(
            solved.candidates[0].status, CandidateStatus.ACCEPTED
        )
        self.assertEqual(solved.submissions[0].status, SubmissionStatus.ACCEPTED)
        history = self.store.load_contest_submissions("Demo CTF")
        self.assertEqual(history[0]["challenge_id"], "Warmup")
        self.assertEqual(history[0]["status"], "accepted")
        self.assertEqual(history[0]["flag"], "flag{operator_submitted_this}")

    def test_operator_accepted_outcome_can_close_unproved_state(
        self,
    ) -> None:
        state = self.create()
        state.candidates.append(
            FlagCandidate(
                id="C-operator-override",
                value="flag{submitted_outside_ctfos}",
                status=CandidateStatus.OBSERVED_CANDIDATE,
            )
        )
        state = self.store.save(state)

        solved = self.store.record_submission(
            self.identity,
            candidate_id="C-operator-override",
            outcome=SubmissionStatus.ACCEPTED,
            submission_id="SUB-operator-override",
            proof_passed=False,
            expected_revision=state.revision,
        )

        self.assertIs(solved.status, ChallengeStatus.SOLVED)
        self.assertIs(
            solved.candidates[0].status,
            CandidateStatus.ACCEPTED,
        )
        self.assertFalse(solved.submissions[0].proof_passed)

    def test_v2_accepted_outcome_atomically_creates_incomplete_closure(
        self,
    ) -> None:
        state = self.store.create_challenge(
            self.identity,
            schema_version=2,
        )
        state.status = ChallengeStatus.TRIAGING
        state.goals.append(
            Goal(
                id="G-active",
                description="finish the selected challenge",
                status=GoalStatus.ACTIVE,
            )
        )
        state.active_goal_id = "G-active"
        state.candidates.append(
            FlagCandidate(
                id="C-v2-accepted",
                value="flag{v2_atomic_closure}",
                status=CandidateStatus.OBSERVED_CANDIDATE,
            )
        )
        state = self.store.save(state)

        contest_paths = self.store.contest_paths(
            self.identity.contest_id
        )
        with (
            mock.patch(
                "ctf_os.store.files.append_json_line",
                side_effect=OSError("synthetic ledger boundary crash"),
            ),
            self.assertRaisesRegex(OSError, "ledger boundary"),
        ):
            self.store.record_submission(
                self.identity,
                candidate_id="C-v2-accepted",
                outcome=SubmissionStatus.ACCEPTED,
                submission_id="SUB-v2-accepted",
                proof_passed=True,
                expected_revision=state.revision,
            )

        solved = self.store.load(self.identity)
        self.assertIs(solved.status, ChallengeStatus.SOLVED)
        self.assertIsNone(solved.active_goal_id)
        self.assertIs(
            solved.goals[0].status,
            GoalStatus.CANCELLED,
        )
        self.assertIsNotNone(solved.closure)
        self.assertIs(
            solved.closure.completeness,
            ClosureCompleteness.INCOMPLETE,
        )
        self.assertEqual(
            solved.closure.submission_ids,
            ["SUB-v2-accepted"],
        )
        self.assertTrue(
            solved.closure.extra["automatic_incomplete"]
        )
        self.assertTrue(
            json.loads(
                contest_paths.submission_intents.read_text(
                    encoding="utf-8"
                )
            )["intents"]
        )
        recovered = self.store.reconcile_submissions(
            self.identity.contest_id
        )
        self.assertEqual(
            recovered["ledger_appended"],
            ["SUB-v2-accepted"],
        )
        self.assertEqual(
            self.store.load(self.identity).closure.id,
            solved.closure.id,
        )

    def test_abandoned_challenge_cannot_be_solved_at_the_store_sink(
        self,
    ) -> None:
        state = self.create()
        state.status = ChallengeStatus.ABANDONED
        state.candidates.append(
            FlagCandidate(
                id="C-abandoned",
                value="flag{must_stay_abandoned}",
                status=CandidateStatus.READY_TO_SUBMIT,
            )
        )
        state = self.store.save(state)
        contest_paths = self.store.contest_paths(
            self.identity.contest_id
        )
        ledger_before = contest_paths.submissions.read_bytes()
        intent_before = (
            contest_paths.submission_intents.read_bytes()
            if contest_paths.submission_intents.exists()
            else None
        )

        with self.assertRaisesRegex(
            WorkerResultValidationError,
            "ABANDONED",
        ):
            self.store.record_submission(
                self.identity,
                candidate_id="C-abandoned",
                outcome=SubmissionStatus.ACCEPTED,
                submission_id="SUB-abandoned",
                proof_passed=True,
                expected_revision=state.revision,
            )

        current = self.store.load(self.identity)
        self.assertIs(current.status, ChallengeStatus.ABANDONED)
        self.assertEqual(current.submissions, [])
        self.assertEqual(
            contest_paths.submissions.read_bytes(),
            ledger_before,
        )
        self.assertEqual(
            (
                contest_paths.submission_intents.read_bytes()
                if contest_paths.submission_intents.exists()
                else None
            ),
            intent_before,
        )

    def test_paused_ready_submission_outcomes_update_the_latent_state(
        self,
    ) -> None:
        state = self.create()
        state.status = ChallengeStatus.PAUSED
        state.resume_status = ChallengeStatus.READY_TO_SUBMIT
        state.candidates.extend(
            (
                FlagCandidate(
                    id="C-rejected",
                    value="flag{paused_rejected}",
                    status=CandidateStatus.READY_TO_SUBMIT,
                ),
                FlagCandidate(
                    id="C-accepted",
                    value="flag{paused_accepted}",
                    status=CandidateStatus.READY_TO_SUBMIT,
                ),
            )
        )
        state = self.store.save(state)

        rejected = self.store.record_submission(
            self.identity,
            candidate_id="C-rejected",
            outcome=SubmissionStatus.REJECTED,
            submission_id="SUB-paused-rejected",
            proof_passed=True,
            expected_revision=state.revision,
        )
        self.assertIs(rejected.status, ChallengeStatus.PAUSED)
        self.assertIs(rejected.resume_status, ChallengeStatus.ACTIVE)
        self.assertIs(
            rejected.candidates[0].status,
            CandidateStatus.REJECTED,
        )

        def restore_latent_ready(current) -> None:
            current.resume_status = ChallengeStatus.READY_TO_SUBMIT

        latent_ready = self.store.update(
            self.identity,
            restore_latent_ready,
            expected_revision=rejected.revision,
        )
        accepted = self.store.record_submission(
            self.identity,
            candidate_id="C-accepted",
            outcome=SubmissionStatus.ACCEPTED,
            submission_id="SUB-paused-accepted",
            proof_passed=True,
            expected_revision=latent_ready.revision,
        )
        self.assertIs(accepted.status, ChallengeStatus.SOLVED)
        self.assertIsNone(accepted.resume_status)
        self.assertIs(
            accepted.candidates[1].status,
            CandidateStatus.ACCEPTED,
        )

    def test_same_flag_cannot_be_accepted_for_two_challenges_concurrently(
        self,
    ) -> None:
        identities = (
            ChallengeIdentity("Demo CTF", "web", "First"),
            ChallengeIdentity("Demo CTF", "rev", "Second"),
        )
        states = []
        for index, identity in enumerate(identities, start=1):
            state = self.store.create_challenge(identity, prompt="solve")
            state.status = ChallengeStatus.READY_TO_SUBMIT
            state.candidates.append(
                FlagCandidate(
                    id=f"C-{index}",
                    value="flag{contest_transaction}",
                    status=CandidateStatus.READY_TO_SUBMIT,
                )
            )
            states.append(self.store.save(state))

        barrier = threading.Barrier(2)
        outcomes: list[str] = []
        outcome_lock = threading.Lock()

        def submit(index: int) -> None:
            state = states[index]
            barrier.wait()
            try:
                self.store.record_submission(
                    state.identity,
                    candidate_id=f"C-{index + 1}",
                    outcome=SubmissionStatus.ACCEPTED,
                    submission_id=f"SUB-{index + 1}",
                    proof_passed=True,
                    expected_revision=state.revision,
                )
            except WorkerResultValidationError:
                result = "rejected"
            else:
                result = "accepted"
            with outcome_lock:
                outcomes.append(result)

        threads = [
            threading.Thread(target=submit, args=(index,))
            for index in range(2)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())

        self.assertCountEqual(outcomes, ["accepted", "rejected"])
        history = self.store.load_contest_submissions("Demo CTF")
        accepted = [
            item
            for item in history
            if item["status"] == SubmissionStatus.ACCEPTED.value
        ]
        self.assertEqual(len(accepted), 1)

    def test_restart_reconciles_submission_before_same_flag_check(
        self,
    ) -> None:
        identities = (
            ChallengeIdentity("Demo CTF", "web", "First"),
            ChallengeIdentity("Demo CTF", "rev", "Second"),
        )
        for index, identity in enumerate(identities, start=1):
            state = self.store.create_challenge(identity, prompt="solve")
            state.status = ChallengeStatus.READY_TO_SUBMIT
            state.candidates.append(
                FlagCandidate(
                    id=f"C-{index}",
                    value="flag{recover_before_duplicate_check}",
                    status=CandidateStatus.READY_TO_SUBMIT,
                )
            )
            self.store.save(state)

        contest_paths = self.store.contest_paths("Demo CTF")
        from ctf_os.store.atomic import append_json_line as real_append

        def fail_ledger_append(path, value, **kwargs):
            if Path(path) == contest_paths.submissions:
                raise OSError("simulated crash before ledger append")
            return real_append(path, value, **kwargs)

        first = self.store.load(identities[0])
        with mock.patch(
            "ctf_os.store.files.append_json_line",
            side_effect=fail_ledger_append,
        ), self.assertRaisesRegex(OSError, "simulated crash"):
            self.store.record_submission(
                identities[0],
                candidate_id="C-1",
                outcome=SubmissionStatus.ACCEPTED,
                submission_id="SUB-first",
                proof_passed=True,
                expected_revision=first.revision,
            )

        self.assertEqual(
            self.store.load(identities[0]).status,
            ChallengeStatus.SOLVED,
        )
        intent_document = json.loads(
            contest_paths.submission_intents.read_text(encoding="utf-8")
        )
        self.assertEqual(
            [item["id"] for item in intent_document["intents"]],
            ["SUB-first"],
        )
        # Simulate a process dying after only a prefix of the JSONL append.
        contest_paths.submissions.write_bytes(b'{"id":"SUB-first"')

        restarted = StateStore(self.root)
        restarted.refresh_board("Demo CTF")
        recovered = restarted.load_contest_submissions("Demo CTF")
        self.assertEqual(
            [(item["id"], item["challenge_id"]) for item in recovered],
            [("SUB-first", "First")],
        )
        second = restarted.load(identities[1])
        with self.assertRaisesRegex(
            WorkerResultValidationError,
            "already recorded as accepted",
        ):
            restarted.record_submission(
                identities[1],
                candidate_id="C-2",
                outcome=SubmissionStatus.ACCEPTED,
                submission_id="SUB-second",
                proof_passed=True,
                expected_revision=second.revision,
            )
        self.assertNotEqual(
            restarted.load(identities[1]).status,
            ChallengeStatus.SOLVED,
        )
        intent_document = json.loads(
            contest_paths.submission_intents.read_text(encoding="utf-8")
        )
        self.assertEqual(intent_document["intents"], [])

    def test_reconcile_reports_and_removes_state_less_intent(self) -> None:
        state = self.create()
        state.candidates.append(
            FlagCandidate(
                id="C-1",
                value="flag{stale_intent}",
                status=CandidateStatus.OBSERVED_CANDIDATE,
            )
        )
        state = self.store.save(state)
        with mock.patch.object(
            self.store,
            "update",
            side_effect=RevisionConflict(state.revision, state.revision + 1),
        ), self.assertRaises(RevisionConflict):
            self.store.record_submission(
                self.identity,
                candidate_id="C-1",
                outcome=SubmissionStatus.REJECTED,
                submission_id="SUB-stale",
                expected_revision=state.revision,
            )

        restarted = StateStore(self.root)
        report = restarted.reconcile_submissions("Demo CTF")
        self.assertEqual(report["intents_seen"], 1)
        self.assertEqual(
            report["stale_intents_removed"],
            ["SUB-stale"],
        )
        self.assertEqual(report["ledger_appended"], [])
        self.assertEqual(report["remaining_intents"], 0)
        self.assertEqual(
            restarted.load(self.identity).submissions,
            [],
        )

    def test_reconcile_deduplicates_ledger_before_clearing_intent(
        self,
    ) -> None:
        state = self.create()
        state.candidates.append(
            FlagCandidate(
                id="C-1",
                value="flag{ledger_won_clear_lost}",
                status=CandidateStatus.OBSERVED_CANDIDATE,
            )
        )
        state = self.store.save(state)
        real_write = self.store._write_submission_intents

        def fail_empty_journal(paths, intents):
            if not intents:
                raise OSError("simulated crash before intent clear")
            return real_write(paths, intents)

        with mock.patch.object(
            self.store,
            "_write_submission_intents",
            side_effect=fail_empty_journal,
        ), self.assertRaisesRegex(OSError, "before intent clear"):
            self.store.record_submission(
                self.identity,
                candidate_id="C-1",
                outcome=SubmissionStatus.REJECTED,
                submission_id="SUB-ledger-first",
                expected_revision=state.revision,
            )

        restarted = StateStore(self.root)
        report = restarted.reconcile_submissions("Demo CTF")
        self.assertEqual(report["intents_seen"], 1)
        self.assertEqual(report["ledger_appended"], [])
        self.assertEqual(
            report["completed_intents_removed"],
            ["SUB-ledger-first"],
        )
        records = restarted.load_contest_submissions("Demo CTF")
        self.assertEqual(
            [item["id"] for item in records],
            ["SUB-ledger-first"],
        )

    def test_flock_is_released_when_owner_process_dies(self) -> None:
        lock_path = self.root / "crash.lock"
        script = (
            "import os, sys, time\n"
            "from pathlib import Path\n"
            "from ctf_os.store import FileLock\n"
            "lock = FileLock(Path(sys.argv[1])).acquire()\n"
            "print('locked', flush=True)\n"
            "time.sleep(60)\n"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", script, str(lock_path)],
            cwd=Path(__file__).resolve().parents[1],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertEqual(process.stdout.readline().strip(), "locked")
            process.kill()
            process.wait(timeout=5)
            with FileLock(lock_path, timeout=1) as lock:
                lock.acquire()
                self.assertTrue(lock_path.exists())
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()


if __name__ == "__main__":
    unittest.main()
