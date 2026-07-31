from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import ctf_os.engine.flags as flags_module
from ctf_os.candidates import FlagNotificationError
from ctf_os.engine.flags import (
    FLAG_CANDIDATE_SIDECAR,
    PROOF_FINAL_DIRECTORY,
    PROOF_LIVE_DIRECTORY,
    DetectedFlag,
    FlagDetector,
    FlagLogTailer,
    FlagTailerError,
    print_flag_candidate,
)


class FlagDetectorTests(unittest.TestCase):
    def test_log_tailer_poll_interval_requires_a_finite_positive_number(
        self,
    ) -> None:
        detector = FlagDetector((r"CTF\{[^}]+\}",))
        with tempfile.TemporaryDirectory() as directory:
            for interval in (
                True,
                0,
                -1,
                float("nan"),
                float("inf"),
                float("-inf"),
                "0.1",
            ):
                with (
                    self.subTest(poll_interval=interval),
                    self.assertRaisesRegex(ValueError, "poll_interval"),
                ):
                    FlagLogTailer(
                        Path(directory),
                        detector,
                        source_prefix="validation",
                        max_bytes=1024,
                        poll_interval=interval,  # type: ignore[arg-type]
                    )

    def test_detects_across_chunks_and_deduplicates(self) -> None:
        candidates: list[DetectedFlag] = []
        detector = FlagDetector(
            (r"FLAG\{[^}]+\}",), callback=candidates.append, overlap=32
        )
        self.assertEqual(detector.feed("noise FLAG{spl", source="run-1"), ())
        found = detector.feed("it} then FLAG{split}", source="run-1")
        self.assertEqual([item.value for item in found], ["FLAG{split}"])
        self.assertEqual([item.value for item in candidates], ["FLAG{split}"])

    def test_sources_have_independent_stream_tails(self) -> None:
        candidates: list[DetectedFlag] = []
        detector = FlagDetector((r"CTF\{[^}]+\}",), callback=candidates.append)
        detector.feed("CTF{wrong", source="a")
        self.assertEqual(detector.feed("tail}", source="b"), ())

    def test_candidate_collection_has_count_and_character_bounds(self) -> None:
        candidates: list[DetectedFlag] = []
        detector = FlagDetector(
            (r"CTF\{[^}]+\}",),
            callback=candidates.append,
            candidate_limit=2,
            candidate_chars_limit=32,
        )
        detector.feed(
            "CTF{one} CTF{two} CTF{three} CTF{four}",
            source="bounded",
        )
        self.assertEqual(
            [candidate.value for candidate in candidates],
            ["CTF{one}", "CTF{two}"],
        )
        self.assertEqual(len(detector.seen), 2)
        self.assertEqual(detector.suppressed_matches, 2)

    def test_generic_code_noise_filter_suppresses_field_false_positives(
        self,
    ) -> None:
        candidates: list[DetectedFlag] = []
        detector = FlagDetector(
            (r"\b[A-Za-z0-9_]{2,32}\{[^{}\r\n]{1,512}\}",),
            callback=candidates.append,
            suppress_generic_code_noise=True,
        )

        found = detector.feed(
            "body{color:#222;font:normal 13px arial;"
            "margin:0} .disabled{color:#ccc} "
            "return{file:!1,glob:!1,sortOrder:!1} "
            "u003d{docid} DH{%s} DH{real_candidate}",
            source="browser:stdout",
        )

        self.assertEqual(
            [candidate.value for candidate in found],
            ["DH{real_candidate}"],
        )
        self.assertEqual(
            [candidate.value for candidate in candidates],
            ["DH{real_candidate}"],
        )
        self.assertEqual(detector.code_noise_suppressed_matches, 5)

    def test_generic_code_noise_does_not_spend_candidate_quota(self) -> None:
        candidates: list[DetectedFlag] = []
        detector = FlagDetector(
            (r"\b[A-Za-z0-9_]{2,32}\{[^{}\r\n]{1,512}\}",),
            callback=candidates.append,
            candidate_limit=1,
            suppress_generic_code_noise=True,
        )

        detector.feed(
            ".disabled{color:#ccc} "
            "return{file:!1} "
            "function{return result=1} "
            "return{file,glob}",
            source="browser:stdout",
        )
        found = detector.feed(
            "KCTF{color:red;margin:0}",
            source="/challenge/assets/site.css",
        )

        self.assertEqual(
            [candidate.value for candidate in found],
            ["KCTF{color:red;margin:0}"],
        )
        self.assertEqual(candidates, list(found))
        self.assertEqual(
            detector.seen,
            frozenset({"KCTF{color:red;margin:0}"}),
        )
        self.assertEqual(detector.code_noise_suppressed_matches, 4)
        self.assertEqual(detector.suppressed_matches, 4)

    def test_generic_code_noise_keeps_ambiguous_and_flag_shaped_values(
        self,
    ) -> None:
        candidates: list[DetectedFlag] = []
        detector = FlagDetector(
            (r"\b[A-Za-z0-9_]{2,32}\{[^{}\r\n]{1,512}\}",),
            callback=candidates.append,
            suppress_generic_code_noise=True,
        )

        detector.feed(
            "<scripture>config{alpha:1,beta:2}</scripture> "
            "<script>TEAM{alpha:1,beta:2}</script> "
            "return{not_code} acsc{real_candidate} "
            "flag:acsc{color:red}",
            source="response.html",
        )
        detector.feed(
            "<script>NYU{alpha:1,beta:2} "
            "ACSC{file:!1,glob:!1} "
            "QZX2026{first:1,second:2} "
            "'zer0pts{alpha:1,beta:2}'</script>",
            source="response.html",
        )
        detector.feed(
            "LINECTF{color:red;margin:0}",
            source="/challenge/assets/site.css",
        )

        self.assertEqual(
            [candidate.value for candidate in candidates],
            [
                "config{alpha:1,beta:2}",
                "TEAM{alpha:1,beta:2}",
                "return{not_code}",
                "acsc{real_candidate}",
                "acsc{color:red}",
                "NYU{alpha:1,beta:2}",
                "ACSC{file:!1,glob:!1}",
                "QZX2026{first:1,second:2}",
                "zer0pts{alpha:1,beta:2}",
                "LINECTF{color:red;margin:0}",
            ],
        )
        self.assertEqual(detector.code_noise_suppressed_matches, 0)

    def test_generic_code_noise_filter_uses_markup_and_source_context(
        self,
    ) -> None:
        candidates: list[DetectedFlag] = []
        detector = FlagDetector(
            (r"\b[A-Za-z0-9_]{2,32}\{[^{}\r\n]{1,512}\}",),
            callback=candidates.append,
            suppress_generic_code_noise=True,
        )

        detector.feed(
            "<script>config{alpha:1,beta:2}</script> "
            "TEAM{alpha:1,beta:2}",
            source="response.html",
        )
        detector.feed(
            "theme{foreground:#fff;background:#000}",
            source="/challenge/site.css",
        )

        self.assertEqual(
            [candidate.value for candidate in candidates],
            ["TEAM{alpha:1,beta:2}"],
        )
        self.assertEqual(detector.code_noise_suppressed_matches, 2)

    def test_generic_code_noise_filter_is_opt_in_for_exact_formats(self) -> None:
        candidates: list[DetectedFlag] = []
        detector = FlagDetector(
            (r"TEAM\{[^{}\r\n]+\}",),
            callback=candidates.append,
        )

        detector.feed(
            "<script>TEAM{alpha:1,beta:2}</script>",
            source="response.html",
        )

        self.assertEqual(
            [candidate.value for candidate in candidates],
            ["TEAM{alpha:1,beta:2}"],
        )
        self.assertEqual(detector.code_noise_suppressed_matches, 0)

    def test_invalid_candidate_does_not_consume_seen_or_quota(self) -> None:
        candidates: list[DetectedFlag] = []
        detector = FlagDetector(
            (r"CTF\{[^}]+\}",),
            callback=candidates.append,
            candidate_limit=1,
        )

        for character in (
            "\t",
            "\u0085",
            "\u200b",
            "\u2028",
            "\u2029",
            "\u202e",
        ):
            with self.subTest(character=ascii(character)):
                self.assertEqual(
                    detector.feed(
                        f"CTF{{bad{character}flag}}",
                        source="untrusted",
                    ),
                    (),
                )
        self.assertEqual(detector.seen, frozenset())
        self.assertEqual(detector.suppressed_matches, 0)

        found = detector.feed("CTF{valid}", source="untrusted")
        self.assertEqual([candidate.value for candidate in found], ["CTF{valid}"])
        self.assertEqual(candidates, list(found))

    def test_callback_failure_releases_every_unnotified_candidate(
        self,
    ) -> None:
        attempts: list[str] = []
        fail_once = True

        def callback(candidate: DetectedFlag) -> None:
            nonlocal fail_once
            attempts.append(candidate.value)
            if fail_once:
                fail_once = False
                raise RuntimeError("durable notification failed")

        detector = FlagDetector(
            (r"CTF\{[^}]+\}",),
            callback=callback,
            candidate_limit=2,
            candidate_chars_limit=32,
        )
        payload = "CTF{one} CTF{two}"
        with self.assertRaisesRegex(RuntimeError, "notification failed"):
            detector.feed(payload, source="first observation")

        self.assertEqual(detector.seen, frozenset())
        retried = detector.feed(payload, source="later observation")
        self.assertEqual(
            [candidate.value for candidate in retried],
            ["CTF{one}", "CTF{two}"],
        )
        self.assertEqual(
            attempts,
            ["CTF{one}", "CTF{one}", "CTF{two}"],
        )
        self.assertEqual(
            detector.seen,
            frozenset({"CTF{one}", "CTF{two}"}),
        )

    def test_callback_failure_keeps_only_prior_successes_seen(
        self,
    ) -> None:
        attempts: list[str] = []
        failed_two = False

        def callback(candidate: DetectedFlag) -> None:
            nonlocal failed_two
            attempts.append(candidate.value)
            if candidate.value == "CTF{two}" and not failed_two:
                failed_two = True
                raise RuntimeError("second callback failed")

        detector = FlagDetector(
            (r"CTF\{[^}]+\}",),
            callback=callback,
            candidate_limit=3,
            candidate_chars_limit=48,
        )
        payload = "CTF{one} CTF{two} CTF{three}"
        with self.assertRaisesRegex(RuntimeError, "second callback"):
            detector.feed(payload, source="first observation")

        self.assertEqual(detector.seen, frozenset({"CTF{one}"}))
        detector.feed(payload, source="later observation")
        self.assertEqual(
            attempts,
            ["CTF{one}", "CTF{two}", "CTF{two}", "CTF{three}"],
        )
        self.assertEqual(
            detector.seen,
            frozenset({"CTF{one}", "CTF{two}", "CTF{three}"}),
        )

    def test_sidecar_callback_failure_can_be_retried(self) -> None:
        attempts = 0

        def callback(_candidate: DetectedFlag) -> None:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RuntimeError("sidecar callback failed")

        detector = FlagDetector(
            (r"CTF\{[^}]+\}",),
            callback=callback,
        )
        with self.assertRaisesRegex(RuntimeError, "sidecar callback"):
            detector.report_candidate(
                "CTF{retry_sidecar}",
                source="sidecar",
            )

        self.assertNotIn("CTF{retry_sidecar}", detector.seen)
        found = detector.report_candidate(
            "CTF{retry_sidecar}",
            source="sidecar retry",
        )
        self.assertEqual(
            [candidate.value for candidate in found],
            ["CTF{retry_sidecar}"],
        )
        self.assertEqual(attempts, 2)

    def test_sidecar_candidate_is_rechecked_against_patterns(self) -> None:
        candidates: list[DetectedFlag] = []
        detector = FlagDetector(
            (r"FLAG\{[^}]+\}",), callback=candidates.append
        )
        self.assertEqual(
            detector.report_candidate("not-a-flag", source="sidecar"),
            (),
        )
        found = detector.report_candidate("FLAG{exact}", source="sidecar")
        self.assertEqual(
            [candidate.value for candidate in found],
            ["FLAG{exact}"],
        )
        self.assertEqual(candidates, list(found))

    def test_print_is_immediate_and_marks_candidate_unsubmitted(self) -> None:
        stream = io.StringIO()
        print_flag_candidate(
            DetectedFlag(
                "CTF{x}\x1b[31m\u009bunsafe",
                "tool\x7f\u0085source",
                "now",
            ),
            stream=stream,
        )
        output = stream.getvalue()
        self.assertIn("FLAG CANDIDATE", output)
        self.assertIn("미제출", output)
        self.assertNotIn("\x1b", output)
        self.assertNotIn("\x7f", output)
        self.assertNotIn("\u0085", output)
        self.assertNotIn("\u009b", output)

    def test_scans_only_bounded_file_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raw.log"
            path.write_bytes(b"FLAG{early}" + b"x" * 32 + b"FLAG{late}")
            values: list[DetectedFlag] = []
            detector = FlagDetector(
                (r"FLAG\{[^}]+\}",), callback=values.append
            )
            detector.scan_file(path, max_bytes=20, chunk_size=4)
        self.assertEqual([candidate.value for candidate in values], ["FLAG{early}"])

    def test_scan_rejects_symlink_without_following_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "outside.log"
            target.write_text("FLAG{outside}", encoding="utf-8")
            link = root / "raw.log"
            link.symlink_to(target)
            detector = FlagDetector((r"FLAG\{[^}]+\}",))
            with self.assertRaises(OSError):
                detector.scan_file(link)

    def test_directory_close_never_recloses_same_number_peer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory) / "workspace"
            child = work / "child"
            child.mkdir(parents=True, mode=0o700)
            tailer = FlagLogTailer(
                work,
                FlagDetector((r"FLAG\{[^}]+\}",)),
                source_prefix="tool:test",
                max_bytes=64,
            )
            real_close = flags_module.os.close
            peer_descriptor: int | None = None
            target_descriptor: int | None = None
            close_calls: list[int] = []

            def close_then_reopen_anchor(descriptor: int) -> None:
                nonlocal peer_descriptor, target_descriptor
                close_calls.append(descriptor)
                if target_descriptor is None:
                    target_descriptor = descriptor
                    real_close(descriptor)
                    replacement = flags_module.os.open(
                        work,
                        flags_module.os.O_RDONLY
                        | flags_module.os.O_CLOEXEC
                        | flags_module.os.O_DIRECTORY
                        | getattr(flags_module.os, "O_NOFOLLOW", 0),
                    )
                    if replacement != descriptor:
                        flags_module.os.dup2(
                            replacement,
                            descriptor,
                            inheritable=False,
                        )
                        real_close(replacement)
                    peer_descriptor = descriptor
                    raise OSError(
                        "synthetic ambiguous directory close error"
                    )
                real_close(descriptor)

            try:
                with mock.patch.object(
                    flags_module.os,
                    "close",
                    side_effect=close_then_reopen_anchor,
                ):
                    self.assertIsNone(tailer._open_directory(child))

                assert target_descriptor is not None
                assert peer_descriptor is not None
                self.assertEqual(
                    close_calls.count(target_descriptor),
                    1,
                )
                self.assertGreaterEqual(len(close_calls), 2)
                flags_module.os.fstat(peer_descriptor)
            finally:
                if peer_descriptor is not None:
                    real_close(peer_descriptor)

    def test_regular_file_cleanup_continues_after_directory_close_error(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory) / "workspace"
            run = work / ".ctf" / "runs" / "run-00000001"
            run.mkdir(parents=True, mode=0o700)
            log = run / "stdout.log"
            log.write_bytes(b"output")
            tailer = FlagLogTailer(
                work,
                FlagDetector((r"FLAG\{[^}]+\}",)),
                source_prefix="tool:test",
                max_bytes=64,
            )
            real_open = flags_module.os.open
            real_close = flags_module.os.close
            file_descriptor: int | None = None
            directory_peer: int | None = None
            directory_identity: tuple[int, int] | None = None
            directory_close_calls = 0
            file_close_calls = 0
            directory_error = OSError(
                "synthetic ambiguous directory close error"
            )
            cleanup_interruption = KeyboardInterrupt(
                "synthetic file cleanup interruption"
            )

            def traced_open(path, flags, *args, **kwargs):
                nonlocal file_descriptor
                descriptor = real_open(path, flags, *args, **kwargs)
                if (
                    str(path) == log.name
                    and kwargs.get("dir_fd") is not None
                    and not flags & flags_module.os.O_DIRECTORY
                ):
                    file_descriptor = descriptor
                return descriptor

            def fail_directory_then_file_close(descriptor: int) -> None:
                nonlocal directory_close_calls
                nonlocal directory_identity
                nonlocal directory_peer
                nonlocal file_close_calls
                try:
                    target = Path(
                        f"/proc/self/fd/{descriptor}"
                    ).readlink()
                except OSError:
                    target = Path()
                if (
                    file_descriptor is not None
                    and target == run
                    and directory_peer is None
                ):
                    directory_close_calls += 1
                    opened = flags_module.os.fstat(descriptor)
                    directory_identity = (
                        opened.st_dev,
                        opened.st_ino,
                    )
                    real_close(descriptor)
                    replacement = real_open(
                        run,
                        flags_module.os.O_RDONLY
                        | flags_module.os.O_CLOEXEC
                        | flags_module.os.O_DIRECTORY
                        | getattr(
                            flags_module.os,
                            "O_NOFOLLOW",
                            0,
                        ),
                    )
                    if replacement != descriptor:
                        flags_module.os.dup2(
                            replacement,
                            descriptor,
                            inheritable=False,
                        )
                        real_close(replacement)
                    directory_peer = descriptor
                    raise directory_error
                if descriptor == file_descriptor:
                    file_close_calls += 1
                    real_close(descriptor)
                    raise cleanup_interruption
                real_close(descriptor)

            try:
                with (
                    mock.patch.object(
                        flags_module.os,
                        "open",
                        side_effect=traced_open,
                    ),
                    mock.patch.object(
                        flags_module.os,
                        "close",
                        side_effect=fail_directory_then_file_close,
                    ),
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    tailer._open_regular(log)

                assert file_descriptor is not None
                assert directory_peer is not None
                assert directory_identity is not None
                self.assertIs(raised.exception, cleanup_interruption)
                self.assertEqual(directory_close_calls, 1)
                self.assertEqual(file_close_calls, 1)
                with self.assertRaises(OSError):
                    flags_module.os.fstat(file_descriptor)
                peer = flags_module.os.fstat(directory_peer)
                self.assertEqual(
                    (peer.st_dev, peer.st_ino),
                    directory_identity,
                )
                self.assertTrue(
                    any(
                        str(directory_error) in note
                        for note in getattr(
                            raised.exception,
                            "__notes__",
                            (),
                        )
                    )
                )
            finally:
                if directory_peer is not None:
                    real_close(directory_peer)
                if file_descriptor is not None and file_close_calls == 0:
                    real_close(file_descriptor)

    def test_live_tailer_scans_only_new_bounded_ctfwrap_log_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            old_run = work / ".ctf" / "runs" / "run-00000001"
            old_run.mkdir(parents=True)
            (old_run / "stdout.log").write_text(
                "FLAG{old}", encoding="utf-8"
            )
            (old_run / "stderr.log").write_text("", encoding="utf-8")
            candidates: list[DetectedFlag] = []
            detector = FlagDetector(
                (r"FLAG\{[^}]+\}",), callback=candidates.append, overlap=32
            )
            tailer = FlagLogTailer(
                work,
                detector,
                source_prefix="tool:test",
                max_bytes=64,
                poll_interval=0.01,
            ).start()
            try:
                new_run = work / ".ctf" / "runs" / "run-00000002"
                new_run.mkdir()
                stdout = new_run / "stdout.log"
                stdout.write_text("noise FLAG{spl", encoding="utf-8")
                (new_run / "stderr.log").write_text("", encoding="utf-8")
                with stdout.open("a", encoding="utf-8") as handle:
                    handle.write("it}")
                    handle.flush()
                deadline = time.monotonic() + 1
                while not candidates and time.monotonic() < deadline:
                    time.sleep(0.01)
            finally:
                tailer.stop()
        self.assertEqual(
            [candidate.value for candidate in candidates],
            ["FLAG{split}"],
        )
        self.assertIn("run-00000002:stdout-live", candidates[0].source)

    def test_live_tailer_does_not_follow_log_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            runs = work / ".ctf" / "runs"
            runs.mkdir(parents=True)
            outside = work / "outside"
            outside.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "kind": "flag_candidate",
                        "stream": "stdout",
                        "value": "FLAG{outside}",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            candidates: list[DetectedFlag] = []
            detector = FlagDetector(
                (r"FLAG\{[^}]+\}",), callback=candidates.append
            )
            tailer = FlagLogTailer(
                work,
                detector,
                source_prefix="tool:test",
                max_bytes=64,
                poll_interval=0.01,
            ).start()
            try:
                run = runs / "run-00000001"
                run.mkdir()
                (run / "stdout.log").symlink_to(outside)
                (run / "stderr.log").write_text("", encoding="utf-8")
                (run / "flag-candidates.jsonl").symlink_to(outside)
                time.sleep(0.05)
            finally:
                tailer.stop()
        self.assertEqual(candidates, [])

    def test_live_tailer_reads_full_stream_candidate_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            runs = work / ".ctf" / "runs"
            runs.mkdir(parents=True)
            candidates: list[DetectedFlag] = []
            detector = FlagDetector(
                (r"FLAG\{[^}]+\}",),
                callback=candidates.append,
                overlap=32,
            )
            tailer = FlagLogTailer(
                work,
                detector,
                source_prefix="tool:test",
                # Exhausting the independent raw-log budget must not prevent
                # the full-stream sidecar from being consumed.
                max_bytes=1,
                poll_interval=0.01,
            ).start()
            try:
                run = runs / "run-00000001"
                run.mkdir()
                (run / "stdout.log").write_text("x", encoding="utf-8")
                (run / "stderr.log").write_text("", encoding="utf-8")
                record = (
                    json.dumps(
                        {
                            "schema_version": 1,
                            "kind": "flag_candidate",
                            "stream": "stdout",
                            "value": 'FLAG{quote"and\\slash}',
                        }
                    )
                    + "\n"
                )
                midpoint = len(record) // 2
                sidecar = run / "flag-candidates.jsonl"
                invalid_prefix = (
                    json.dumps(
                        {
                            "schema_version": 1,
                            "kind": "flag_candidate",
                            "stream": [],
                            "value": "FLAG{forged}",
                        }
                    )
                    + "\n"
                    + (
                        '{"schema_version":1,"kind":"flag_candidate",'
                        '"stream":"stdout","value":"\\ud800"}\n'
                    )
                )
                sidecar.write_text(
                    invalid_prefix + record[:midpoint],
                    encoding="utf-8",
                )
                time.sleep(0.03)
                with sidecar.open("a", encoding="utf-8") as handle:
                    handle.write(record[midpoint:])
                    handle.flush()
                deadline = time.monotonic() + 1
                while not candidates and time.monotonic() < deadline:
                    time.sleep(0.01)
            finally:
                tailer.stop()
        self.assertEqual(
            [candidate.value for candidate in candidates],
            ['FLAG{quote"and\\slash}'],
        )
        self.assertIn(
            "run-00000001:stdout-stream",
            candidates[0].source,
        )

    def test_proof_tailer_reads_only_private_live_and_final_sidecars(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "workspace"
            work.mkdir(mode=0o700)
            candidates: list[DetectedFlag] = []
            detector = FlagDetector(
                (r"FLAG\{[^}]+\}",),
                callback=candidates.append,
            )
            tailer = FlagLogTailer(
                work,
                detector,
                source_prefix="proof:test",
                max_bytes=1,
                proof=True,
                poll_interval=0.01,
            ).start()
            try:
                live_root = root / PROOF_LIVE_DIRECTORY
                live_attempt = (
                    live_root / "clean-012345abcdef-abcdefgh"
                )
                live_runs = live_attempt / ".ctf" / "runs"
                live_run = live_runs / "run-00000001"
                live_run.mkdir(parents=True)
                for private_directory in (
                    live_root,
                    live_attempt,
                    live_attempt / ".ctf",
                    live_runs,
                    live_run,
                ):
                    private_directory.chmod(0o700)
                live_sidecar = live_run / FLAG_CANDIDATE_SIDECAR
                live_sidecar.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "kind": "flag_candidate",
                            "stream": "stdout",
                            "value": "FLAG{proof_live}",
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                live_sidecar.chmod(0o600)

                final_root = work / PROOF_FINAL_DIRECTORY
                final_attempt = final_root / "clean-fedcba987654"
                final_attempt.mkdir(parents=True)
                final_root.chmod(0o700)
                final_attempt.chmod(0o700)
                final_sidecar = (
                    final_attempt / FLAG_CANDIDATE_SIDECAR
                )
                final_sidecar.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "kind": "flag_candidate",
                            "stream": "stderr",
                            "value": "FLAG{proof_final}",
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                final_sidecar.chmod(0o400)

                unrelated_run = (
                    work / ".ctf" / "runs" / "run-00000002"
                )
                unrelated_run.mkdir(parents=True)
                (
                    unrelated_run / FLAG_CANDIDATE_SIDECAR
                ).write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "kind": "flag_candidate",
                            "stream": "stdout",
                            "value": "FLAG{ordinary_tool}",
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                deadline = time.monotonic() + 1
                while len(candidates) < 2 and time.monotonic() < deadline:
                    time.sleep(0.01)
            finally:
                tailer.stop()

        self.assertEqual(
            {candidate.value for candidate in candidates},
            {"FLAG{proof_live}", "FLAG{proof_final}"},
        )

    def test_proof_tailer_budgets_live_prefix_and_complete_final_copy(
        self,
    ) -> None:
        def record(value: str) -> bytes:
            return (
                json.dumps(
                    {
                        "schema_version": 1,
                        "kind": "flag_candidate",
                        "stream": "stdout",
                        "value": value,
                    },
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "workspace"
            work.mkdir(mode=0o700)
            late_candidate = "FLAG{only_in_complete_final_suffix}"
            filler_records = tuple(
                record(f"not-a-candidate-{index:02d}") for index in range(12)
            )
            payload = b"".join((*filler_records, record(late_candidate)))
            live_prefix = b"".join(filler_records[:9])
            physical_file_limit = len(payload)
            old_final_budget = physical_file_limit - len(live_prefix)
            self.assertGreater(len(live_prefix), physical_file_limit // 2)
            self.assertNotIn(
                late_candidate.encode("utf-8"),
                payload[:old_final_budget],
            )

            candidates: list[DetectedFlag] = []
            tailer = FlagLogTailer(
                work,
                FlagDetector(
                    (r"FLAG\{[^}]+\}",),
                    callback=candidates.append,
                ),
                source_prefix="proof:test",
                max_bytes=1,
                proof=True,
                poll_interval=60,
                candidate_sidecar_max_bytes=physical_file_limit,
            ).start()
            try:
                live_root = root / PROOF_LIVE_DIRECTORY
                live_attempt = (
                    live_root / "clean-012345abcdef-abcdefgh"
                )
                live_runs = live_attempt / ".ctf" / "runs"
                live_run = live_runs / "run-00000001"
                live_run.mkdir(parents=True)
                for private_directory in (
                    live_root,
                    live_attempt,
                    live_attempt / ".ctf",
                    live_runs,
                    live_run,
                ):
                    private_directory.chmod(0o700)
                live_sidecar = live_run / FLAG_CANDIDATE_SIDECAR
                live_sidecar.write_bytes(live_prefix)
                live_sidecar.chmod(0o600)

                # Model the last live poll before proof persistence. With only
                # one physical-file budget, the final drain would now reread
                # only an earlier prefix and miss the candidate at the end.
                tailer._poll_candidate_sidecars_once()
                self.assertEqual(candidates, [])

                final_root = work / PROOF_FINAL_DIRECTORY
                final_attempt = final_root / "clean-fedcba987654"
                final_attempt.mkdir(parents=True)
                final_root.chmod(0o700)
                final_attempt.chmod(0o700)
                final_sidecar = (
                    final_attempt / FLAG_CANDIDATE_SIDECAR
                )
                final_sidecar.write_bytes(payload)
                final_sidecar.chmod(0o400)
                tailer._poll_candidate_sidecars_once()
            finally:
                tailer.stop()

        self.assertEqual(
            [candidate.value for candidate in candidates],
            [late_candidate],
        )

    def test_proof_tailer_rejects_symlink_and_nonprivate_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "workspace"
            work.mkdir(mode=0o700)
            outside_live = root / "outside-live"
            outside_run = (
                outside_live
                / "clean-012345abcdef-abcdefgh"
                / ".ctf"
                / "runs"
                / "run-00000001"
            )
            outside_run.mkdir(parents=True)
            (root / PROOF_LIVE_DIRECTORY).symlink_to(
                outside_live,
                target_is_directory=True,
            )

            final_root = work / PROOF_FINAL_DIRECTORY
            final_attempt = final_root / "clean-fedcba987654"
            final_attempt.mkdir(parents=True)
            final_root.chmod(0o755)
            final_attempt.chmod(0o700)
            final_sidecar = (
                final_attempt / FLAG_CANDIDATE_SIDECAR
            )
            live_sidecar = outside_run / FLAG_CANDIDATE_SIDECAR
            for sidecar in (live_sidecar, final_sidecar):
                sidecar.write_text("", encoding="utf-8")
                sidecar.chmod(0o600)

            candidates: list[DetectedFlag] = []
            tailer = FlagLogTailer(
                work,
                FlagDetector(
                    (r"FLAG\{[^}]+\}",),
                    callback=candidates.append,
                ),
                source_prefix="proof:test",
                max_bytes=1,
                proof=True,
                poll_interval=0.01,
            ).start()
            try:
                with live_sidecar.open("a", encoding="utf-8") as stream:
                    stream.write(
                        json.dumps(
                            {
                                "schema_version": 1,
                                "kind": "flag_candidate",
                                "stream": "stdout",
                                "value": "FLAG{symlink_escape}",
                            }
                        )
                        + "\n"
                    )
                    stream.flush()
                with final_sidecar.open("a", encoding="utf-8") as stream:
                    stream.write(
                        json.dumps(
                            {
                                "schema_version": 1,
                                "kind": "flag_candidate",
                                "stream": "stdout",
                                "value": "FLAG{public_root}",
                            }
                        )
                        + "\n"
                    )
                    stream.flush()
                time.sleep(0.05)
            finally:
                tailer.stop()

        self.assertEqual(candidates, [])

    def test_proof_tailer_fails_closed_when_final_directory_exceeds_bound(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "workspace"
            work.mkdir(mode=0o700)
            candidates: list[DetectedFlag] = []
            tailer = FlagLogTailer(
                work,
                FlagDetector(
                    (r"FLAG\{[^}]+\}",),
                    callback=candidates.append,
                ),
                source_prefix="proof:test",
                max_bytes=1,
                proof=True,
                poll_interval=60,
                max_run_directories=2,
            ).start()

            final_root = work / PROOF_FINAL_DIRECTORY
            final_root.mkdir(mode=0o700)
            for nonce in (
                "000000000001",
                "000000000002",
                "000000000003",
            ):
                attempt = final_root / f"clean-{nonce}"
                attempt.mkdir(mode=0o700)
                sidecar = attempt / FLAG_CANDIDATE_SIDECAR
                sidecar.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "kind": "flag_candidate",
                            "stream": "stdout",
                            "value": f"FLAG{{proof_{nonce}}}",
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                sidecar.chmod(0o400)

            with self.assertRaisesRegex(
                FlagTailerError,
                "final drain failed",
            ):
                tailer.stop()
            self.assertEqual(candidates, [])

    def test_live_tailer_fails_closed_when_run_directory_exceeds_bound(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            runs = work / ".ctf" / "runs"
            runs.mkdir(parents=True)
            candidates: list[DetectedFlag] = []
            tailer = FlagLogTailer(
                work,
                FlagDetector(
                    (r"FLAG\{[^}]+\}",),
                    callback=candidates.append,
                ),
                source_prefix="tool:test",
                max_bytes=1,
                poll_interval=60,
                max_run_directories=2,
            ).start()

            for sequence in (1, 2, 3):
                run = runs / f"run-{sequence:08d}"
                run.mkdir()
                sidecar = run / FLAG_CANDIDATE_SIDECAR
                sidecar.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "kind": "flag_candidate",
                            "stream": "stdout",
                            "value": f"FLAG{{tool_{sequence}}}",
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )

            with self.assertRaisesRegex(
                FlagTailerError,
                "final drain failed",
            ):
                tailer.stop()
            self.assertEqual(candidates, [])

    def test_live_tailer_stop_surfaces_a_stuck_poll_and_can_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / ".ctf" / "runs").mkdir(parents=True)
            tailer = FlagLogTailer(
                work,
                FlagDetector((r"FLAG\{[^}]+\}",)),
                source_prefix="tool:test",
                max_bytes=64,
                poll_interval=0.01,
            )
            original_poll = tailer._poll_once
            entered = threading.Event()
            release = threading.Event()

            def stuck_poll() -> None:
                entered.set()
                release.wait(3)

            tailer._poll_once = stuck_poll
            tailer.start()
            self.assertTrue(entered.wait(1))
            with self.assertRaisesRegex(
                FlagTailerError,
                "did not stop",
            ):
                tailer.stop()
            self.assertIsNotNone(tailer._thread)

            tailer._poll_once = original_poll
            release.set()
            tailer.stop()
            self.assertIsNone(tailer._thread)

    def test_live_tailer_start_interrupt_cleans_actual_watcher(self) -> None:
        for interruption in (
            KeyboardInterrupt("synthetic start handoff interrupt"),
            SystemExit("synthetic start handoff exit"),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                with tempfile.TemporaryDirectory() as directory:
                    work = Path(directory)
                    (work / ".ctf" / "runs").mkdir(parents=True)
                    tailer = FlagLogTailer(
                        work,
                        FlagDetector((r"FLAG\{[^}]+\}",)),
                        source_prefix="tool:test",
                        max_bytes=64,
                        poll_interval=0.01,
                    )
                    started_threads: list[threading.Thread] = []
                    real_start = threading.Thread.start

                    def start_then_interrupt(
                        thread: threading.Thread,
                    ) -> None:
                        real_start(thread)
                        started_threads.append(thread)
                        raise interruption

                    with (
                        mock.patch.object(
                            threading.Thread,
                            "start",
                            new=start_then_interrupt,
                        ),
                        self.assertRaises(
                            type(interruption)
                        ) as raised,
                    ):
                        tailer.start()

                    self.assertIs(raised.exception, interruption)
                    self.assertEqual(len(started_threads), 1)
                    self.assertFalse(started_threads[0].is_alive())
                    self.assertIsNone(tailer._thread)
                    tailer.stop()
                    tailer.start()
                    tailer.stop()
                    self.assertIsNone(tailer._thread)

    def test_live_tailer_delayed_bootstrap_start_interrupt_stays_cancelled(
        self,
    ) -> None:
        for interruption in (
            KeyboardInterrupt("synthetic delayed bootstrap interrupt"),
            SystemExit("synthetic delayed bootstrap exit"),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                with tempfile.TemporaryDirectory() as directory:
                    work = Path(directory)
                    (work / ".ctf" / "runs").mkdir(parents=True)
                    tailer = FlagLogTailer(
                        work,
                        FlagDetector((r"FLAG\{[^}]+\}",)),
                        source_prefix="tool:test",
                        max_bytes=64,
                        poll_interval=0.01,
                    )
                    gate = threading.Event()
                    captured: list[threading.Thread] = []
                    real_bootstrap = threading.Thread._bootstrap
                    real_lowlevel_start = (
                        flags_module.threading._start_joinable_thread
                    )

                    def delayed_bootstrap(
                        thread: threading.Thread,
                    ) -> None:
                        gate.wait(timeout=2)
                        real_bootstrap(thread)

                    def start_then_interrupt(
                        function,
                        *,
                        handle,
                        daemon,
                    ):
                        thread = function.__self__
                        captured.append(thread)
                        real_lowlevel_start(
                            function,
                            handle=handle,
                            daemon=daemon,
                        )
                        raise interruption

                    with (
                        mock.patch.object(
                            threading.Thread,
                            "_bootstrap",
                            new=delayed_bootstrap,
                        ),
                        mock.patch.object(
                            flags_module.threading,
                            "_start_joinable_thread",
                            new=start_then_interrupt,
                        ),
                        self.assertRaises(
                            type(interruption)
                        ) as raised,
                    ):
                        tailer.start()

                    self.assertIs(raised.exception, interruption)
                    self.assertEqual(len(captured), 1)
                    self.assertIs(tailer._thread, captured[0])
                    self.assertTrue(tailer._stop.is_set())
                    self.assertIsNone(captured[0].ident)
                    gate.set()
                    deadline = time.monotonic() + 1
                    while (
                        captured[0].ident is None
                        and time.monotonic() < deadline
                    ):
                        time.sleep(0.005)
                    tailer.stop()
                    self.assertFalse(captured[0].is_alive())
                    self.assertIsNone(tailer._thread)
                    tailer.start()
                    tailer.stop()
                    self.assertIsNone(tailer._thread)

    def test_live_tailer_start_interrupt_drains_active_callback(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            runs = work / ".ctf" / "runs"
            runs.mkdir(parents=True)
            callback_active = threading.Event()
            release_callback = threading.Event()
            callback_finished = threading.Event()
            interruption = KeyboardInterrupt(
                "synthetic active start handoff interruption"
            )

            def blocking_callback(_candidate: DetectedFlag) -> None:
                callback_active.set()
                if not release_callback.wait(timeout=2):
                    raise AssertionError(
                        "active start callback was not released"
                    )
                callback_finished.set()

            tailer = FlagLogTailer(
                work,
                FlagDetector(
                    (r"KCTF\{[^}]+\}",),
                    callback=blocking_callback,
                ),
                source_prefix="tool:test",
                max_bytes=4096,
                poll_interval=0.01,
            )
            real_start = threading.Thread.start
            captured: list[threading.Thread] = []
            real_joins: list[object] = []

            def start_then_interrupt(
                thread: threading.Thread,
            ) -> None:
                real_start(thread)
                run = runs / "run-00000001"
                run.mkdir()
                (run / "stdout.log").write_text(
                    "KCTF{tailer_active_start}\n",
                    encoding="utf-8",
                )
                if not callback_active.wait(timeout=1):
                    raise AssertionError(
                        "start callback did not become active"
                    )
                real_join = thread.join
                real_joins.append(real_join)

                def distinguish_bounded_join(
                    *,
                    timeout: float | None = None,
                ) -> None:
                    if timeout is not None:
                        return
                    real_join()

                thread.join = distinguish_bounded_join
                captured.append(thread)
                raise interruption

            def release_after_entry() -> None:
                if callback_active.wait(timeout=1):
                    time.sleep(0.1)
                    release_callback.set()

            releaser = threading.Thread(target=release_after_entry)
            releaser.start()
            started = time.monotonic()
            try:
                with (
                    mock.patch.object(
                        threading.Thread,
                        "start",
                        new=start_then_interrupt,
                    ),
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    tailer.start()
            finally:
                release_callback.set()
                releaser.join(timeout=1)
                if captured and real_joins:
                    captured[0].join = real_joins[0]
            elapsed = time.monotonic() - started

            self.assertIs(raised.exception, interruption)
            self.assertEqual(len(captured), 1)
            self.assertTrue(callback_finished.is_set())
            self.assertFalse(captured[0].is_alive())
            self.assertIsNone(tailer._thread)
            self.assertGreaterEqual(elapsed, 0.09)
            self.assertLess(elapsed, 1.0)

    def test_live_tailer_join_interrupt_finishes_cleanup(self) -> None:
        for interruption in (
            KeyboardInterrupt("synthetic join interrupt"),
            SystemExit("synthetic join exit"),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                with tempfile.TemporaryDirectory() as directory:
                    work = Path(directory)
                    (work / ".ctf" / "runs").mkdir(parents=True)
                    tailer = FlagLogTailer(
                        work,
                        FlagDetector((r"FLAG\{[^}]+\}",)),
                        source_prefix="tool:test",
                        max_bytes=64,
                        poll_interval=0.01,
                    ).start()
                    thread = tailer._thread
                    assert thread is not None
                    real_join = thread.join
                    join_calls = 0
                    final_drains = 0
                    real_poll = tailer._poll_once

                    def join_then_interrupt(
                        *,
                        timeout: float | None = None,
                    ) -> None:
                        nonlocal join_calls
                        join_calls += 1
                        real_join(timeout=timeout)
                        if join_calls == 1:
                            raise interruption

                    def record_final_drain() -> None:
                        nonlocal final_drains
                        final_drains += 1
                        real_poll()

                    tailer._poll_once = record_final_drain
                    with (
                        mock.patch.object(
                            thread,
                            "join",
                            side_effect=join_then_interrupt,
                        ),
                        self.assertRaises(
                            type(interruption)
                        ) as raised,
                    ):
                        tailer.stop()

                    self.assertIs(raised.exception, interruption)
                    self.assertEqual(join_calls, 2)
                    self.assertEqual(final_drains, 1)
                    self.assertTrue(
                        any(
                            "cleanup completed after join retry" in note
                            for note in interruption.__notes__
                        )
                    )
                    self.assertFalse(thread.is_alive())
                    self.assertIsNone(tailer._thread)
                    tailer.stop()
                    tailer.start()
                    tailer.stop()
                    self.assertIsNone(tailer._thread)

    def test_live_tailer_exit_preserves_active_base_exception(self) -> None:
        cases = (
            (
                KeyboardInterrupt("synthetic tool interrupt"),
                FlagNotificationError(
                    "synthetic final notification failure"
                ),
                "FlagNotificationError",
            ),
            (
                SystemExit("synthetic tool exit"),
                OSError("synthetic final drain failure"),
                "FlagTailerError",
            ),
        )
        for body_error, cleanup_error, expected_note in cases:
            with self.subTest(body_error=type(body_error).__name__):
                with tempfile.TemporaryDirectory() as directory:
                    work = Path(directory)
                    (work / ".ctf" / "runs").mkdir(parents=True)
                    tailer = FlagLogTailer(
                        work,
                        FlagDetector((r"FLAG\{[^}]+\}",)),
                        source_prefix="tool:test",
                        max_bytes=64,
                        poll_interval=60,
                    )
                    threads: list[threading.Thread] = []

                    def fail_final_drain() -> None:
                        raise cleanup_error

                    with self.assertRaises(
                        type(body_error)
                    ) as raised:
                        with tailer:
                            tailer.start()
                            thread = tailer._thread
                            assert thread is not None
                            threads.append(thread)
                            tailer._poll_once = fail_final_drain
                            raise body_error

                    self.assertIs(raised.exception, body_error)
                    self.assertEqual(len(threads), 1)
                    self.assertFalse(threads[0].is_alive())
                    self.assertIsNone(tailer._thread)
                    self.assertTrue(
                        any(
                            expected_note in note
                            for note in body_error.__notes__
                        )
                    )

    def test_live_tailer_exit_drains_active_callback_before_scope_unwinds(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            runs = work / ".ctf" / "runs"
            runs.mkdir(parents=True)
            callback_active = threading.Event()
            release_callback = threading.Event()
            callback_finished = threading.Event()
            body_error = KeyboardInterrupt(
                "synthetic session owner interruption"
            )
            cleanup_error = SystemExit(
                "synthetic drain liveness interruption"
            )

            def blocking_callback(_candidate: DetectedFlag) -> None:
                callback_active.set()
                if not release_callback.wait(timeout=3):
                    raise AssertionError(
                        "tailer callback was not released"
                    )
                callback_finished.set()

            tailer = FlagLogTailer(
                work,
                FlagDetector(
                    (r"KCTF\{[^}]+\}",),
                    callback=blocking_callback,
                ),
                source_prefix="tool:test",
                max_bytes=4096,
                poll_interval=0.01,
            )
            started_thread: threading.Thread | None = None
            real_is_alive = None
            alive_checks = 0

            def release_after_bounded_stop() -> None:
                if callback_active.wait(timeout=1):
                    # The ordinary stop() boundary is one second.  Releasing
                    # after it proves __exit__ does not return merely because
                    # that bounded diagnostic stop timed out.
                    time.sleep(1.1)
                    release_callback.set()

            releaser = threading.Thread(
                target=release_after_bounded_stop
            )
            releaser.start()
            started = time.monotonic()
            try:
                with self.assertRaises(KeyboardInterrupt) as raised:
                    with tailer:
                        tailer.start()
                        started_thread = tailer._thread
                        run = runs / "run-00000001"
                        run.mkdir()
                        (run / "stdout.log").write_text(
                            "KCTF{tailer_scope_drain}\n",
                            encoding="utf-8",
                        )
                        if not callback_active.wait(timeout=1):
                            raise AssertionError(
                                "tailer callback did not become active"
                            )

                        real_is_alive = started_thread.is_alive

                        def is_alive_then_interrupt() -> bool:
                            nonlocal alive_checks
                            alive_checks += 1
                            if alive_checks == 1:
                                raise cleanup_error
                            return real_is_alive()

                        started_thread.is_alive = (
                            is_alive_then_interrupt
                        )
                        raise body_error
            finally:
                release_callback.set()
                releaser.join(timeout=1)
                if (
                    started_thread is not None
                    and real_is_alive is not None
                ):
                    started_thread.is_alive = real_is_alive
            elapsed = time.monotonic() - started

            self.assertIs(raised.exception, body_error)
            self.assertIsNotNone(started_thread)
            assert started_thread is not None
            self.assertTrue(callback_finished.is_set())
            self.assertFalse(started_thread.is_alive())
            self.assertIsNone(tailer._thread)
            self.assertGreaterEqual(alive_checks, 2)
            self.assertGreaterEqual(elapsed, 1.05)
            self.assertLess(elapsed, 2.0)
            self.assertTrue(
                any(
                    "SystemExit" in note
                    and "synthetic drain liveness interruption" in note
                    for note in body_error.__notes__
                )
            )

    def test_live_tailer_exit_retries_interrupted_drain_until_callback_ends(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            runs = work / ".ctf" / "runs"
            runs.mkdir(parents=True)
            callback_active = threading.Event()
            release_callback = threading.Event()
            callback_finished = threading.Event()
            body_error = KeyboardInterrupt(
                "synthetic session owner interruption"
            )
            cleanup_error = SystemExit(
                "synthetic drain join interruption"
            )

            def blocking_callback(_candidate: DetectedFlag) -> None:
                callback_active.set()
                if not release_callback.wait(timeout=2):
                    raise AssertionError(
                        "tailer callback was not released"
                    )
                callback_finished.set()

            tailer = FlagLogTailer(
                work,
                FlagDetector(
                    (r"KCTF\{[^}]+\}",),
                    callback=blocking_callback,
                ),
                source_prefix="tool:test",
                max_bytes=4096,
                poll_interval=0.01,
            )
            started_thread: threading.Thread | None = None
            real_join = None
            join_calls = 0

            def release_after_entry() -> None:
                if callback_active.wait(timeout=1):
                    time.sleep(0.1)
                    release_callback.set()

            releaser = threading.Thread(target=release_after_entry)
            releaser.start()
            try:
                with self.assertRaises(KeyboardInterrupt) as raised:
                    with tailer:
                        tailer.start()
                        started_thread = tailer._thread
                        assert started_thread is not None
                        real_join = started_thread.join

                        def join_then_interrupt(
                            *,
                            timeout: float | None = None,
                        ) -> None:
                            nonlocal join_calls
                            join_calls += 1
                            if join_calls == 1:
                                raise cleanup_error
                            real_join(timeout=timeout)

                        started_thread.join = join_then_interrupt
                        run = runs / "run-00000001"
                        run.mkdir()
                        (run / "stdout.log").write_text(
                            "KCTF{tailer_interrupted_drain}\n",
                            encoding="utf-8",
                        )
                        if not callback_active.wait(timeout=1):
                            raise AssertionError(
                                "tailer callback did not become active"
                            )
                        raise body_error
            finally:
                release_callback.set()
                releaser.join(timeout=1)
                if started_thread is not None and real_join is not None:
                    started_thread.join = real_join

            self.assertIs(raised.exception, body_error)
            self.assertGreaterEqual(join_calls, 2)
            self.assertTrue(callback_finished.is_set())
            assert started_thread is not None
            self.assertFalse(started_thread.is_alive())
            self.assertIsNone(tailer._thread)
            self.assertTrue(
                any(
                    "SystemExit" in note
                    and "synthetic drain join interruption" in note
                    for note in body_error.__notes__
                )
            )

    def test_live_tailer_exit_retries_interrupted_stop_publication(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / ".ctf" / "runs").mkdir(parents=True)
            polled = threading.Event()
            body_error = KeyboardInterrupt(
                "synthetic session owner interruption"
            )
            cleanup_error = SystemExit(
                "synthetic stop publication interruption"
            )
            tailer = FlagLogTailer(
                work,
                FlagDetector((r"KCTF\{[^}]+\}",)),
                source_prefix="tool:test",
                max_bytes=4096,
                poll_interval=0.01,
            )
            original_poll = tailer._poll_once
            real_set = tailer._stop.set
            set_calls = 0

            def record_poll() -> None:
                polled.set()
                original_poll()

            def set_then_interrupt() -> None:
                nonlocal set_calls
                set_calls += 1
                if set_calls == 1:
                    raise cleanup_error
                real_set()

            tailer._poll_once = record_poll
            try:
                with self.assertRaises(KeyboardInterrupt) as raised:
                    with tailer:
                        tailer.start()
                        thread = tailer._thread
                        assert thread is not None
                        if not polled.wait(timeout=1):
                            raise AssertionError(
                                "tailer did not begin polling"
                            )
                        tailer._stop.set = set_then_interrupt
                        raise body_error
            finally:
                tailer._stop.set = real_set

            self.assertIs(raised.exception, body_error)
            self.assertGreaterEqual(set_calls, 2)
            self.assertFalse(thread.is_alive())
            self.assertIsNone(tailer._thread)
            self.assertTrue(
                any(
                    "SystemExit" in note
                    and "synthetic stop publication interruption" in note
                    for note in body_error.__notes__
                )
            )

    def test_live_tailer_exit_surfaces_cleanup_failure_without_body_error(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / ".ctf" / "runs").mkdir(parents=True)
            tailer = FlagLogTailer(
                work,
                FlagDetector((r"FLAG\{[^}]+\}",)),
                source_prefix="tool:test",
                max_bytes=64,
                poll_interval=60,
            )
            cleanup_error = FlagNotificationError(
                "synthetic final notification failure"
            )
            threads: list[threading.Thread] = []

            def fail_final_drain() -> None:
                raise cleanup_error

            with self.assertRaises(FlagNotificationError) as raised:
                with tailer:
                    tailer.start()
                    thread = tailer._thread
                    assert thread is not None
                    threads.append(thread)
                    tailer._poll_once = fail_final_drain

            self.assertIs(raised.exception, cleanup_error)
            self.assertEqual(len(threads), 1)
            self.assertFalse(threads[0].is_alive())
            self.assertIsNone(tailer._thread)

    def test_live_tailer_enter_return_interrupt_cleans_watcher(self) -> None:
        for interruption in (
            KeyboardInterrupt("synthetic enter return interrupt"),
            SystemExit("synthetic enter return exit"),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                with tempfile.TemporaryDirectory() as directory:
                    work = Path(directory)
                    (work / ".ctf" / "runs").mkdir(parents=True)
                    tailer = FlagLogTailer(
                        work,
                        FlagDetector((r"FLAG\{[^}]+\}",)),
                        source_prefix="tool:test",
                        max_bytes=64,
                        poll_interval=0.01,
                    )
                    returned = False
                    enter_code = FlagLogTailer.__enter__.__code__

                    def interrupt_return(frame, event, _argument):
                        if (
                            frame.f_code is enter_code
                            and event == "return"
                        ):
                            sys.settrace(None)
                            raise interruption
                        return interrupt_return

                    previous_trace = sys.gettrace()
                    try:
                        sys.settrace(interrupt_return)
                        with self.assertRaises(
                            type(interruption)
                        ) as raised:
                            with tailer:
                                returned = True
                    finally:
                        sys.settrace(previous_trace)

                    self.assertIs(raised.exception, interruption)
                    self.assertFalse(returned)
                    self.assertIsNone(tailer._thread)
                    tailer.stop()
                    with tailer:
                        tailer.start()
                    self.assertIsNone(tailer._thread)

    def test_live_tailer_start_return_interrupt_is_guarded_by_exit(
        self,
    ) -> None:
        for interruption in (
            KeyboardInterrupt("synthetic start return interrupt"),
            SystemExit("synthetic start return exit"),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                with tempfile.TemporaryDirectory() as directory:
                    work = Path(directory)
                    (work / ".ctf" / "runs").mkdir(parents=True)
                    tailer = FlagLogTailer(
                        work,
                        FlagDetector((r"FLAG\{[^}]+\}",)),
                        source_prefix="tool:test",
                        max_bytes=64,
                        poll_interval=0.01,
                    )
                    started_threads: list[threading.Thread] = []
                    start_code = FlagLogTailer.start.__code__

                    def interrupt_return(frame, event, _argument):
                        if (
                            frame.f_code is start_code
                            and event == "return"
                        ):
                            thread = tailer._thread
                            assert thread is not None
                            started_threads.append(thread)
                            sys.settrace(None)
                            raise interruption
                        return interrupt_return

                    previous_trace = sys.gettrace()
                    try:
                        sys.settrace(interrupt_return)
                        with self.assertRaises(
                            type(interruption)
                        ) as raised:
                            with tailer:
                                tailer.start()
                    finally:
                        sys.settrace(previous_trace)

                    self.assertIs(raised.exception, interruption)
                    self.assertEqual(len(started_threads), 1)
                    self.assertFalse(started_threads[0].is_alive())
                    self.assertIsNone(tailer._thread)
                    with tailer:
                        tailer.start()
                    self.assertIsNone(tailer._thread)

    def test_live_tailer_surfaces_polling_exception(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / ".ctf" / "runs").mkdir(parents=True)
            tailer = FlagLogTailer(
                work,
                FlagDetector((r"FLAG\{[^}]+\}",)),
                source_prefix="tool:test",
                max_bytes=64,
                poll_interval=0.01,
            )
            failed = threading.Event()

            def fail_poll() -> None:
                failed.set()
                raise OSError("synthetic poll failure")

            tailer._poll_once = fail_poll
            tailer.start()
            self.assertTrue(failed.wait(1))
            with self.assertRaisesRegex(
                FlagTailerError,
                "polling failed",
            ):
                tailer.stop()

    def test_live_tailer_preserves_flag_notification_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            runs = work / ".ctf" / "runs"
            runs.mkdir(parents=True)
            callback_attempted = threading.Event()

            def fail_notification(_candidate: DetectedFlag) -> None:
                callback_attempted.set()
                raise OSError("candidate journal unavailable")

            tailer = FlagLogTailer(
                work,
                FlagDetector(
                    (r"KCTF\{[^}]+\}",),
                    callback=fail_notification,
                ),
                source_prefix="tool:test",
                max_bytes=4096,
                poll_interval=0.01,
            )
            tailer.start()
            run = runs / "run-00000001"
            run.mkdir()
            (run / "stdout.log").write_text(
                "KCTF{tailer_notification_failure}\n",
                encoding="utf-8",
            )
            self.assertTrue(callback_attempted.wait(1))

            with self.assertRaisesRegex(
                FlagNotificationError,
                "candidate notification failed",
            ):
                tailer.stop()


if __name__ == "__main__":
    unittest.main()
