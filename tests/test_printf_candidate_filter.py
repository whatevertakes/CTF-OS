from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ctf_os.candidates import FlagNotificationError
from ctf_os.codex.events import (
    EventAccumulator,
    FlagCandidate as EventFlagCandidate,
    FlagDetector as EventFlagDetector,
)
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.engine.flags import FlagDetector as StreamingFlagDetector
from ctf_os.models import ArtifactReference, ChallengeIdentity


_PATTERNS = (r"[A-Za-z][A-Za-z0-9_]{1,31}\{[^{}\r\n]+\}",)


class PrintfCandidateFilterTests(unittest.TestCase):
    def test_event_notice_is_not_accumulated_or_charged_to_quota(
        self,
    ) -> None:
        notices = []
        accepted = []
        detector = EventFlagDetector(
            _PATTERNS,
            candidate_limit=1,
            suppress_generic_code_noise=True,
            notice_callback=notices.append,
        )
        accumulator = EventAccumulator(
            detector=detector,
            on_flag=accepted.append,
        )

        accumulator.feed(
            json.dumps(
                {
                    "type": "item.completed",
                    "text": "csawctf{%s}",
                }
            )
        )
        accumulator.feed(
            json.dumps(
                {
                    "type": "item.completed",
                    "text": "duplicate csawctf{%s}",
                }
            )
        )
        accumulator.feed(
            json.dumps(
                {
                    "type": "item.completed",
                    "text": "csawctf{actual_candidate}",
                }
            )
        )

        self.assertEqual(
            [candidate.value for candidate in notices],
            ["csawctf{%s}"],
        )
        self.assertEqual(
            [candidate.value for candidate in accepted],
            ["csawctf{actual_candidate}"],
        )
        self.assertEqual(accumulator.flags, accepted)
        self.assertEqual(
            detector.accepted_chars,
            len("csawctf{actual_candidate}"),
        )

    def test_notice_failure_retries_without_spending_candidate_state(
        self,
    ) -> None:
        event_notices = []

        def flaky_event_notice(candidate) -> None:
            event_notices.append(candidate)
            if len(event_notices) == 1:
                raise RuntimeError("synthetic notice failure")

        event_detector = EventFlagDetector(
            _PATTERNS,
            candidate_limit=1,
            suppress_generic_code_noise=True,
            notice_callback=flaky_event_notice,
        )
        with self.assertRaises(FlagNotificationError):
            event_detector.scan("csawctf{%s}", "tool.output")
        self.assertEqual(event_detector.notice_count, 0)
        self.assertEqual(event_detector.accepted_chars, 0)
        self.assertEqual(
            event_detector.scan("csawctf{%s}", "tool.output"),
            [],
        )
        self.assertEqual(len(event_notices), 2)
        explicit_event = event_detector.report_candidate(
            "csawctf{%s}",
            "final.output",
        )
        self.assertIsNotNone(explicit_event)

        regular_stream = []
        stream_notices = []

        def flaky_stream_notice(candidate) -> None:
            stream_notices.append(candidate)
            if len(stream_notices) == 1:
                raise RuntimeError("synthetic stream notice failure")

        stream_detector = StreamingFlagDetector(
            _PATTERNS,
            callback=regular_stream.append,
            notice_callback=flaky_stream_notice,
            candidate_limit=1,
            suppress_generic_code_noise=True,
        )
        with self.assertRaises(FlagNotificationError):
            stream_detector.feed("csawctf{%s}", source="tool:stdout")
        self.assertEqual(stream_detector.notice_count, 0)
        self.assertEqual(stream_detector.seen, frozenset())
        self.assertEqual(
            stream_detector.feed("csawctf{%s}", source="tool:stdout"),
            (),
        )
        self.assertEqual(len(stream_notices), 2)
        explicit_stream = stream_detector.report_candidate(
            "csawctf{%s}",
            source="structured:report_candidate",
        )
        self.assertEqual(
            [candidate.value for candidate in explicit_stream],
            ["csawctf{%s}"],
        )
        self.assertEqual(regular_stream, list(explicit_stream))

    def test_notice_then_explicit_report_promotes_without_second_print(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            engine = ChallengeEngine(Path(temporary))
            identity = ChallengeIdentity(
                "Scanner CTF",
                "misc",
                "notice promotion",
            )
            engine.add_challenge(identity, prompt="scan proof output")
            candidate = EventFlagCandidate(
                "KCTF{%s}",
                "tool.output",
                "event_stream",
            )
            with mock.patch(
                "ctf_os.engine.challenge.print_flag_candidate"
            ) as printer:
                engine._print_codex_flag_notice(identity, candidate)
                self.assertEqual(
                    engine.store.load_candidate_intents(identity),
                    (),
                )
                self.assertEqual(
                    engine.store.load(identity).candidates,
                    [],
                )

                engine._print_codex_flag(identity, candidate)
                self.assertEqual(
                    len(engine.store.load_candidate_intents(identity)),
                    1,
                )
                reconciled = engine._reconcile_candidate_intents_and_notify(
                    identity
                )

            self.assertEqual(printer.call_count, 1)
            self.assertEqual(
                [item.value for item in reconciled.candidates],
                ["KCTF{%s}"],
            )

    def test_event_detector_filters_directives_only_when_opted_in(
        self,
    ) -> None:
        notices = []
        detector = EventFlagDetector(
            _PATTERNS,
            candidate_limit=1,
            suppress_generic_code_noise=True,
            notice_callback=notices.append,
        )
        templates = (
            "csawctf{%s}",
            "csawctf{%02x%02x}",
            "csawctf{%2$s %1$08llx}",
            "csawctf{%2$*3$.*4$llx}",
            "csawctf{%*.*s}",
            "csawctf{%S%C}",
            "csawctf{%I64d}",
            "csawctf{%(name)08x}",
            "csawctf{%#v}",
            "csawctf{%[2]08x}",
        )

        self.assertEqual(
            detector.scan(" ".join(templates), "tool.output"),
            [],
        )
        self.assertEqual(detector.template_suppressed_matches, len(templates))
        self.assertEqual(detector.suppressed_matches, 0)
        self.assertEqual(
            detector.code_noise_suppressed_matches,
            len(templates),
        )
        self.assertEqual(
            [candidate.value for candidate in notices],
            list(templates),
        )
        self.assertEqual(detector.notice_count, len(templates))
        self.assertEqual(detector.accepted_chars, 0)

        unfiltered = EventFlagDetector(_PATTERNS)
        automatic = unfiltered.scan(
            "csawctf{%1$s}",
            "tool.output",
        )
        self.assertEqual(
            [candidate.value for candidate in automatic],
            ["csawctf{%1$s}"],
        )
        self.assertEqual(unfiltered.template_suppressed_matches, 0)

        explicit_detector = EventFlagDetector(
            _PATTERNS,
            suppress_generic_code_noise=True,
        )
        explicit = explicit_detector.report_candidate(
            "csawctf{%1$s}",
            "final.output",
        )
        self.assertIsNotNone(explicit)
        self.assertEqual(explicit.value, "csawctf{%1$s}")

        actual = detector.scan(
            "csawctf{actual_candidate}",
            "tool.output",
        )
        self.assertEqual(
            [candidate.value for candidate in actual],
            ["csawctf{actual_candidate}"],
        )

    def test_streaming_detector_filters_only_when_opted_in(
        self,
    ) -> None:
        notified = []
        notices = []
        detector = StreamingFlagDetector(
            _PATTERNS,
            callback=notified.append,
            notice_callback=notices.append,
            candidate_limit=1,
            suppress_generic_code_noise=True,
        )

        self.assertEqual(
            detector.feed(
                "csawctf{%3$#08x%1$s}",
                source="tool:stdout",
            ),
            (),
        )
        self.assertEqual(notified, [])
        self.assertEqual(
            [candidate.value for candidate in notices],
            ["csawctf{%3$#08x%1$s}"],
        )
        self.assertEqual(detector.template_suppressed_matches, 1)
        self.assertEqual(detector.suppressed_matches, 0)
        self.assertEqual(detector.code_noise_suppressed_matches, 1)
        self.assertEqual(
            detector.feed(
                "duplicate csawctf{%3$#08x%1$s}",
                source="tool:stdout",
            ),
            (),
        )
        self.assertEqual(len(notices), 1)
        explicit = detector.report_candidate(
            "csawctf{%3$#08x%1$s}",
            source="structured:report_candidate",
        )
        self.assertEqual(
            [candidate.value for candidate in explicit],
            ["csawctf{%3$#08x%1$s}"],
        )

        scan_detector = StreamingFlagDetector(
            _PATTERNS,
            callback=notified.append,
            notice_callback=notices.append,
            candidate_limit=1,
            suppress_generic_code_noise=True,
        )
        found = scan_detector.feed(
            "csawctf{%s} ",
            source="tool:stdout",
        )
        self.assertEqual(found, ())
        found = scan_detector.feed(
            "csawctf{actual_candidate}",
            source="tool:stdout",
        )

        self.assertEqual(
            [candidate.value for candidate in found],
            ["csawctf{actual_candidate}"],
        )
        self.assertEqual(notified, [*explicit, *found])
        self.assertEqual(
            [candidate.value for candidate in notices],
            ["csawctf{%3$#08x%1$s}", "csawctf{%s}"],
        )

        immediate = []
        unfiltered = StreamingFlagDetector(
            _PATTERNS,
            callback=immediate.append,
        )
        automatic = unfiltered.feed(
            "csawctf{%3$#08x%1$s}",
            source="tool:stdout",
        )
        self.assertEqual(
            [candidate.value for candidate in automatic],
            ["csawctf{%3$#08x%1$s}"],
        )
        self.assertEqual(immediate, list(automatic))
        self.assertEqual(unfiltered.template_suppressed_matches, 0)

    def test_rev_stream_scan_keeps_template_visible_without_overflow(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            engine = ChallengeEngine(Path(temporary))
            identity = ChallengeIdentity(
                "Scanner CTF",
                "rev",
                "printf overflow isolation",
            )
            state = engine.add_challenge(identity, prompt="scan proof output")
            paths = engine.store.challenge_paths(identity)
            payloads = {
                "stdout": (
                    b"source spelling csawctf{%I64d} "
                    b"csawctf{actual_candidate}\n"
                ),
                "stderr": b"",
            }
            artifacts = []
            for stream, payload in payloads.items():
                relative = f"artifacts/snapshots/{stream}.log"
                destination = paths.root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(payload)
                artifacts.append(
                    ArtifactReference(
                        id=f"A-{stream}",
                        path=relative,
                        sha256=hashlib.sha256(payload).hexdigest(),
                        size=len(payload),
                        extra={"stream": stream},
                    )
                )

            values, selected_direct, overflow, complete = (
                engine._scan_rev_proof_stream_artifacts(
                    state,
                    artifacts,
                    candidate="csawctf{actual_candidate}",
                    patterns=_PATTERNS,
                )
            )

        self.assertEqual(
            values,
            ("csawctf{%I64d}", "csawctf{actual_candidate}"),
        )
        self.assertTrue(selected_direct)
        self.assertFalse(overflow)
        self.assertTrue(complete)

    def test_percent_with_substantive_body_text_is_preserved(self) -> None:
        values = (
            "csawctf{100%real}",
            "csawctf{%s-but-substantive}",
            "csawctf{real-%02x}",
            "csawctf{%s,%02x}",
        )

        event_detector = EventFlagDetector(_PATTERNS)
        event_candidates = event_detector.scan(
            " ".join(values),
            "tool.output",
        )
        streaming_detector = StreamingFlagDetector(
            _PATTERNS,
            callback=lambda _candidate: None,
        )
        streaming_candidates = streaming_detector.feed(
            " ".join(values),
            source="tool:stdout",
        )

        self.assertEqual(
            [candidate.value for candidate in event_candidates],
            list(values),
        )
        self.assertEqual(
            [candidate.value for candidate in streaming_candidates],
            list(values),
        )


if __name__ == "__main__":
    unittest.main()
