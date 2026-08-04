from __future__ import annotations

import json
import unittest

from ctf_os.codex.events import (
    DEFAULT_FLAG_PATTERNS,
    FlagDetector as EventFlagDetector,
)
from ctf_os.engine.flags import FlagDetector as StreamingFlagDetector


_DIAGNOSTICS = (
    (r"\x9a xEZ{R:0.} \x85", 0.5, "offset-short"),
    (
        r"\xae{!0R\x85m\xb2\xd6\xd9s\xf2",
        0.5714,
        "lsb-offset-5-inverted",
    ),
    (r"\x82{C", 0.5, "lsb-offset-6-inverted"),
    (
        r"\xa3{\x05HaF\x17 \xea,\xc4\x03",
        0.5,
        "lsb-offset-4-inverted",
    ),
    (
        r"\xf5{S0\x05\xcfd\xfbcYY",
        0.5714,
        "reversed-bits-inverted",
    ),
    (r"\xe6{1\xae\xce2\x0f", 0.5714, "lsb-offset-0-inverted"),
    (r"\x1fkg{\x86", 0.5, "msb-offset-1-inverted"),
)

_FALSE_CANDIDATES = (
    "xEZ{R:0.}",
    (
        r'xae{!0R\\x85m\\xb2\\xd6\\xd9s\\xf2","printable_ratio":'
        r'0.5714,"transform":"lsb-offset-5-inverted"}'
    ),
    (
        r'x82{C","printable_ratio":0.5,"transform":'
        r'"lsb-offset-6-inverted"}'
    ),
    (
        r'xa3{\\x05HaF\\x17 \\xea,\\xc4\\x03","printable_ratio":'
        r'0.5,"transform":"lsb-offset-4-inverted"}'
    ),
    (
        r'xf5{S0\\x05\\xcfd\\xfbcYY","printable_ratio":0.5714,'
        r'"transform":"reversed-bits-inverted"}'
    ),
    (
        r'xe6{1\\xae\\xce2\\x0f","printable_ratio":0.5714,'
        r'"transform":"lsb-offset-0-inverted"}'
    ),
    (
        r'x1fkg{\\x86","printable_ratio":0.5,"transform":'
        r'"msb-offset-1-inverted"}'
    ),
)


def _diagnostic_jsonl() -> str:
    return "\n".join(
        json.dumps(
            {
                "escaped": escaped,
                "printable_ratio": printable_ratio,
                "transform": transform,
            },
            separators=(",", ":"),
        )
        for escaped, printable_ratio, transform in _DIAGNOSTICS
    )


class EscapedByteDiagnosticCandidateTests(unittest.TestCase):
    def test_reproduces_then_suppresses_seven_jsonl_false_matches(self) -> None:
        output = _diagnostic_jsonl()
        unfiltered = EventFlagDetector()
        reproduced = unfiltered.scan(
            output,
            "tool.output",
            "tool:run:stdout",
        )
        self.assertEqual(
            tuple(candidate.value for candidate in reproduced),
            _FALSE_CANDIDATES,
        )

        detector = EventFlagDetector(
            candidate_limit=1,
            suppress_generic_code_noise=True,
        )
        self.assertEqual(
            detector.scan(output, "tool.output", "tool:run:stdout"),
            [],
        )
        self.assertEqual(detector.code_noise_suppressed_matches, 7)
        self.assertEqual(detector.suppressed_matches, 7)

        actual = detector.scan(
            "flag{ordinary_candidate}",
            "tool.output",
            "tool:run:stdout",
        )
        self.assertEqual(
            [candidate.value for candidate in actual],
            ["flag{ordinary_candidate}"],
        )

    def test_streaming_tool_scanner_uses_the_same_suppression(self) -> None:
        notified = []
        detector = StreamingFlagDetector(
            DEFAULT_FLAG_PATTERNS,
            callback=notified.append,
            suppress_generic_code_noise=True,
        )

        self.assertEqual(
            detector.feed(_diagnostic_jsonl(), source="tool:run:stdout"),
            (),
        )
        self.assertEqual(detector.code_noise_suppressed_matches, 7)
        self.assertEqual(notified, [])

        explicit = detector.report_candidate(
            "xEZ{R:0.}",
            source="structured:report_candidate",
        )
        self.assertEqual(
            [candidate.value for candidate in explicit],
            ["xEZ{R:0.}"],
        )
        self.assertEqual(notified, list(explicit))

        event_detector = EventFlagDetector(
            suppress_generic_code_noise=True,
        )
        event_explicit = event_detector.report_candidate(
            _FALSE_CANDIDATES[1],
            "final.output",
            "structured:report_candidate",
        )
        self.assertIsNotNone(event_explicit)
        self.assertEqual(event_explicit.value, _FALSE_CANDIDATES[1])

    def test_nested_jsonl_string_shape_is_also_suppressed(self) -> None:
        nested = json.dumps(_diagnostic_jsonl(), separators=(",", ":"))
        unfiltered = EventFlagDetector().scan(
            nested,
            "tool.output",
            "tool:nested:stdout",
        )
        self.assertEqual(len(unfiltered), 7)
        self.assertTrue(
            any(
                r'\"printable_ratio\"' in candidate.value
                for candidate in unfiltered
            )
        )

        detector = EventFlagDetector(suppress_generic_code_noise=True)
        self.assertEqual(
            detector.scan(
                nested,
                "tool.output",
                "tool:nested:stdout",
            ),
            [],
        )
        self.assertEqual(detector.code_noise_suppressed_matches, 7)

    def test_keeps_exact_json_values_and_strong_flags_in_diagnostics(
        self,
    ) -> None:
        records = (
            {
                "escaped": r"\xff",
                "candidate": "xEZ{actual_json_field}",
                "printable_ratio": 0.5,
                "transform": "identity",
            },
            {
                "escaped": r"\x80 prefix flag{ordinary_flag}",
                "printable_ratio": 0.5,
                "transform": "identity",
            },
            {
                "escaped": r"\x81 prefix NYU{strong_acronym}",
                "printable_ratio": 0.5,
                "transform": "identity",
            },
        )
        regular = "\n".join(
            json.dumps(record, separators=(",", ":"))
            for record in records
        )
        nested = json.dumps(regular, separators=(",", ":"))
        regular_detector = EventFlagDetector(
            suppress_generic_code_noise=True
        )
        regular_candidates = regular_detector.scan(
            regular,
            "tool.output",
            "tool:regular:stdout",
        )
        nested_detector = EventFlagDetector(
            suppress_generic_code_noise=True
        )
        nested_candidates = nested_detector.scan(
            nested,
            "tool.output",
            "tool:nested:stdout",
        )

        expected = {
            "xEZ{actual_json_field}",
            "flag{ordinary_flag}",
            "NYU{strong_acronym}",
        }
        self.assertEqual(
            {candidate.value for candidate in regular_candidates},
            expected,
        )
        self.assertEqual(
            {candidate.value for candidate in nested_candidates},
            expected,
        )
        self.assertEqual(
            regular_detector.code_noise_suppressed_matches,
            0,
        )
        self.assertEqual(
            nested_detector.code_noise_suppressed_matches,
            0,
        )

    def test_metadata_or_escape_signal_alone_is_not_sufficient(self) -> None:
        detector = EventFlagDetector(suppress_generic_code_noise=True)
        values = detector.scan(
            "xEZ{outside_record}\n"
            '{"value":"prefix xEZ{metadata_only}",'
            '"printable_ratio":0.5,"transform":"identity"}\n'
            '{"value":"\\\\x80 prefix xEZ{escape_only}"}',
            "tool.output",
            "tool:run:stdout",
        )

        self.assertEqual(
            [candidate.value for candidate in values],
            [
                "xEZ{outside_record}",
                "xEZ{metadata_only}",
                "xEZ{escape_only}",
            ],
        )
        self.assertEqual(detector.code_noise_suppressed_matches, 0)


if __name__ == "__main__":
    unittest.main()
