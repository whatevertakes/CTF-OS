from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ctf_os.codex.events import EventAccumulator, FlagDetector
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.models import ChallengeIdentity


class FlagScannerCanonicalStateTests(unittest.TestCase):
    def test_python_fstring_templates_do_not_become_candidates(self) -> None:
        detector = FlagDetector(
            candidate_limit=2,
            suppress_generic_code_noise=True,
        )
        source = (
            "name = f'FF{code:02X}'\n"
            "return f'APP{code - 0xe0}'\n"
            "return f'RST{code - 0xd0}'\n"
            "return rf'SOF_{code:02X}'\n"
            "fallback = fr'M_{code:02X}'\n"
            "candidate = 'NYU{actual_candidate}'\n"
        )
        accumulator = EventAccumulator(detector=detector)

        accumulator.feed(
            json.dumps(
                {
                    "type": "item.completed",
                    "item": {
                        "type": "agent_message",
                        "text": json.dumps(
                            {
                                "actions": [{"command": source}],
                                "flag_candidates": [],
                            }
                        ),
                    },
                }
            )
        )
        explicit = detector.report_candidate(
            "FF{code:02X}",
            "final.output",
        )

        self.assertEqual(
            [candidate.value for candidate in accumulator.flags],
            ["NYU{actual_candidate}"],
        )
        self.assertIsNotNone(explicit)
        self.assertEqual(explicit.value, "FF{code:02X}")
        self.assertEqual(detector.code_noise_suppressed_matches, 5)
        self.assertEqual(detector.suppressed_matches, 5)

    def test_live_python_format_template_is_generic_noise_only(self) -> None:
        detector = FlagDetector(
            (r"\b[A-Za-z0-9_]{2,32}\{[^{}\r\n]{1,512}\}",),
            suppress_generic_code_noise=True,
        )
        source = (
            "def location(item):\n"
            "    return 'missing' if item is None else "
            "'{}@0x{:x}'.format(item['func'], item['addr'])\n"
            "candidate = 'KCTF{real_control}'\n"
        )
        accumulator = EventAccumulator(detector=detector)

        accumulator.feed(
            json.dumps(
                {
                    "type": "item.completed",
                    "item": {
                        "type": "agent_message",
                        "text": json.dumps(
                            {
                                "actions": [{"command": source}],
                                "flag_candidates": [],
                            }
                        ),
                    },
                }
            )
        )
        explicit = detector.report_candidate(
            "0x{:x}",
            "final.output",
        )

        self.assertEqual(
            [candidate.value for candidate in accumulator.flags],
            ["KCTF{real_control}"],
        )
        self.assertIsNotNone(explicit)
        self.assertEqual(explicit.value, "0x{:x}")
        self.assertEqual(detector.code_noise_suppressed_matches, 1)
        self.assertEqual(detector.suppressed_matches, 1)

    def test_python_format_template_across_json_layers_preserves_controls(
        self,
    ) -> None:
        source = (
            'rendered = "{}@0x{:x}".format(item[\'func\'], item[\'addr\'])\n'
            'ordinary = "0x{:x}"\n'
            'attribute = "HEX{:X}".format\n'
            'fstring = f"FF{code:02X}"\n'
            'printf = "DH{%s}"\n'
            'control = "KCTF{real_control}"\n'
        )

        for layers in range(4):
            with self.subTest(json_layers=layers):
                detector = FlagDetector(
                    (
                        r"\b[A-Za-z0-9_]{2,32}"
                        r"\{[^{}\r\n]{1,512}\}",
                    ),
                    suppress_generic_code_noise=True,
                )
                encoded = source
                for _ in range(layers):
                    encoded = json.dumps(encoded)

                scanned = detector.scan(encoded, "item.completed")

                self.assertEqual(
                    [candidate.value for candidate in scanned],
                    [
                        "0x{:x}",
                        "HEX{:X}",
                        "KCTF{real_control}",
                    ],
                )
                self.assertEqual(
                    detector.code_noise_suppressed_matches,
                    3,
                )
                self.assertEqual(detector.template_suppressed_matches, 1)
                self.assertEqual(detector.suppressed_matches, 2)

    def test_fstring_marker_requires_exact_python_prefix_context(self) -> None:
        detector = FlagDetector(suppress_generic_code_noise=True)

        scanned = detector.scan(
            "prefixf'NYU{bounded_literal}' "
            "f 'ACSC{ordinary_literal}' "
            '"LINECTF{ordinary_double_quoted}" '
            "f`KCTF{backtick_candidate}`",
            "item.completed",
        )

        self.assertEqual(
            [candidate.value for candidate in scanned],
            [
                "NYU{bounded_literal}",
                "ACSC{ordinary_literal}",
                "LINECTF{ordinary_double_quoted}",
                "KCTF{backtick_candidate}",
            ],
        )
        self.assertEqual(detector.code_noise_suppressed_matches, 0)

    def test_numeric_prefix_fstrings_are_suppressed_for_runtime_pattern(
        self,
    ) -> None:
        detector = FlagDetector(
            (r"\b[A-Za-z0-9_]{2,32}\{[^{}\r\n]{1,512}\}",),
            suppress_generic_code_noise=True,
        )
        accumulator = EventAccumulator(detector=detector)

        accumulator.feed(
            json.dumps(
                {
                    "type": "item.completed",
                    "item": {
                        "type": "agent_message",
                        "text": json.dumps(
                            {
                                "actions": [
                                    {
                                        "command": (
                                            'address = f"0x{instruction[\'address\']:x}"\n'
                                            "pair = f'0x{match.group(1)}:"
                                            "{match.group(2)}'\n"
                                            "date = f'0711{year}'\n"
                                            "little = f'int:{value}:le{width}'\n"
                                            "big = f'int:{value}:be{width}'\n"
                                        )
                                    }
                                ],
                                "flag_candidates": [],
                                "summary": "31337{actual_candidate}",
                            }
                        ),
                    },
                }
            )
        )

        self.assertEqual(
            [candidate.value for candidate in accumulator.flags],
            ["31337{actual_candidate}"],
        )
        self.assertEqual(detector.code_noise_suppressed_matches, 5)
        self.assertEqual(detector.suppressed_matches, 5)

    def test_triple_quoted_fstrings_are_suppressed_across_json_layers(
        self,
    ) -> None:
        source = (
            'first = f"""NYU{value}"""\n'
            "second = rf'''ACSC{code:02X}'''\n"
            'third = fr"""prefix\nLINECTF{item}\nsuffix"""\n'
            'control = """KCTF{ordinary_literal}"""\n'
        )

        for layers in range(4):
            with self.subTest(json_layers=layers):
                detector = FlagDetector(
                    (
                        r"\b[A-Za-z0-9_]{2,32}"
                        r"\{[^{}\r\n]{1,512}\}",
                    ),
                    suppress_generic_code_noise=True,
                )
                encoded = source
                for _ in range(layers):
                    encoded = json.dumps(encoded)

                scanned = detector.scan(encoded, "item.completed")

                self.assertEqual(
                    [candidate.value for candidate in scanned],
                    ["KCTF{ordinary_literal}"],
                )
                self.assertEqual(
                    detector.code_noise_suppressed_matches,
                    3,
                )

    def test_triple_quoted_literals_cannot_leak_across_their_boundary(
        self,
    ) -> None:
        detector = FlagDetector(
            (r"\b[A-Za-z0-9_]{2,32}\{[^{}\r\n]{1,512}\}",),
            suppress_generic_code_noise=True,
        )

        scanned = detector.scan(
            'probe = f"""flag{"""; close = "}" '
            'control = "flag{real_control}"',
            "item.completed",
        )

        self.assertEqual(
            [candidate.value for candidate in scanned],
            ["flag{real_control}"],
        )
        self.assertEqual(detector.code_noise_suppressed_matches, 1)

    def test_matches_cannot_cross_json_or_code_string_boundaries(
        self,
    ) -> None:
        detector = FlagDetector(
            (r"\b[A-Za-z0-9_]{2,32}\{[^{}\r\n]{1,512}\}",),
            suppress_generic_code_noise=True,
        )
        accumulator = EventAccumulator(detector=detector)
        structured = {
            "actions": [
                {
                    "command": (
                        'start = lowered.find(b"flag{", position)\n'
                        'close = buffer.find(b"}", start + 5)\n'
                        'candidate = "fl" + "ag{" + "body" + "}"\n'
                    ),
                    "keep_if": (
                        "Keep if stdout reports flag{ seed=A qua after "
                        "INPUT_OK."
                    ),
                    "kind": "command",
                }
            ],
            "hypotheses": [
                {
                    "unknowns": [
                        "Whether flag{ is the actual plaintext prefix",
                        "Continuation of the readable pad",
                    ]
                }
            ],
            "flag_candidates": [],
            "summary": "flag{real_control}",
        }

        accumulator.feed(
            json.dumps(
                {
                    "type": "item.completed",
                    "item": {
                        "type": "agent_message",
                        "text": json.dumps(structured),
                    },
                }
            )
        )

        self.assertEqual(
            [candidate.value for candidate in accumulator.flags],
            ["flag{real_control}"],
        )
        self.assertGreaterEqual(
            detector.code_noise_suppressed_matches,
            4,
        )

    def test_python_if_predicate_fragment_is_suppressed_in_event_stream(
        self,
    ) -> None:
        detector = FlagDetector(suppress_generic_code_noise=True)
        accumulator = EventAccumulator(detector=detector)
        source = (
            "flag_strings = sorted({s for s in all_strings "
            "if 'flag{' in s.lower()})\n"
            "quoted = 'flag{quoted_control}'\n"
            "# observed flag{standalone_control}\n"
            "if 'KCTF{strong_control}' in values:\n"
            "    pass\n"
        )

        accumulator.feed(
            json.dumps(
                {
                    "type": "item.completed",
                    "item": {
                        "type": "agent_message",
                        "text": json.dumps(
                            {
                                "actions": [{"command": source}],
                                "flag_candidates": [],
                            }
                        ),
                    },
                }
            )
        )

        self.assertEqual(
            [candidate.value for candidate in accumulator.flags],
            [
                "flag{quoted_control}",
                "flag{standalone_control}",
                "KCTF{strong_control}",
            ],
        )
        self.assertEqual(detector.code_noise_suppressed_matches, 1)
        self.assertEqual(detector.suppressed_matches, 1)

    def test_python_else_concatenation_template_is_suppressed_across_events(
        self,
    ) -> None:
        source = (
            'text = payload.decode("ascii")\n'
            'wrapped = text if text.startswith("csawctf{") '
            'and text.endswith("}") else "csawctf{" + text + "}"\n'
            'control = "csawctf{real_control}"\n'
        )
        structured = {
            "actions": [{"command": source}],
            "flag_candidates": [],
        }

        for layers in range(4):
            with self.subTest(json_layers=layers):
                detector = FlagDetector(suppress_generic_code_noise=True)
                encoded = source
                for _ in range(layers):
                    encoded = json.dumps(encoded)

                scanned = detector.scan(encoded, "item.completed")

                self.assertEqual(
                    [candidate.value for candidate in scanned],
                    ["csawctf{real_control}"],
                )
                self.assertEqual(
                    detector.code_noise_suppressed_matches,
                    2,
                )

        event = json.dumps(
            {
                "type": "item.completed",
                "item": {
                    "type": "agent_message",
                    "text": json.dumps(structured),
                },
            }
        )

        item_detector = FlagDetector(suppress_generic_code_noise=True)
        item_accumulator = EventAccumulator(detector=item_detector)
        item_accumulator.feed(event)
        self.assertEqual(
            [candidate.value for candidate in item_accumulator.flags],
            ["csawctf{real_control}"],
        )

        raw_detector = FlagDetector(suppress_generic_code_noise=True)
        raw_scanned = raw_detector.scan(
            event,
            "raw.fragment",
            "raw_jsonl",
        )
        self.assertEqual(
            [candidate.value for candidate in raw_scanned],
            ["csawctf{real_control}"],
        )

        final_detector = FlagDetector(suppress_generic_code_noise=True)
        final_accumulator = EventAccumulator(detector=final_detector)
        final_scanned = final_accumulator.scan_final(structured)
        self.assertEqual(
            [candidate.value for candidate in final_scanned],
            ["csawctf{real_control}"],
        )
        explicit = final_detector.report_candidate(
            'csawctf{" + text + "}',
            "final.output",
            "structured_output",
        )

        for detector in (item_detector, raw_detector, final_detector):
            self.assertGreaterEqual(
                detector.code_noise_suppressed_matches,
                2,
            )
        self.assertIsNotNone(explicit)
        self.assertEqual(explicit.value, 'csawctf{" + text + "}')
        self.assertEqual(explicit.source, "structured_output")

    def test_python_else_whitespace_templates_are_suppressed_across_json(
        self,
    ) -> None:
        cases = (
            (
                "tab",
                'wrapped = text if ok else\t"csawctf{" + text + "}"\n',
            ),
            (
                "bounded_multiline",
                "wrapped = (\n"
                "    text if ok else\n"
                '        "csawctf{" + text + "}"\n'
                ")\n",
            ),
        )

        for name, template in cases:
            source = template + 'control = "csawctf{real_control}"\n'
            for layers in range(4):
                with self.subTest(case=name, json_layers=layers):
                    detector = FlagDetector(
                        suppress_generic_code_noise=True
                    )
                    encoded = source
                    for _ in range(layers):
                        encoded = json.dumps(encoded)

                    scanned = detector.scan(encoded, "item.completed")

                    self.assertEqual(
                        [candidate.value for candidate in scanned],
                        ["csawctf{real_control}"],
                    )
                    self.assertEqual(
                        detector.code_noise_suppressed_matches,
                        1,
                    )

    def test_python_else_exact_candidate_is_preserved_across_json(
        self,
    ) -> None:
        source = 'result = prior if ok else "csawctf{legitimate}"\n'

        for layers in range(4):
            with self.subTest(json_layers=layers):
                detector = FlagDetector(suppress_generic_code_noise=True)
                encoded = source
                for _ in range(layers):
                    encoded = json.dumps(encoded)

                scanned = detector.scan(encoded, "item.completed")

                self.assertEqual(
                    [candidate.value for candidate in scanned],
                    ["csawctf{legitimate}"],
                )
                self.assertEqual(detector.code_noise_suppressed_matches, 0)

    def test_python_else_keyword_requires_exact_identifier_boundary(
        self,
    ) -> None:
        source = 'wrapped = someoneelse "csawctf{" + text + "}"\n'

        for layers in range(4):
            with self.subTest(json_layers=layers):
                detector = FlagDetector(suppress_generic_code_noise=True)
                encoded = source
                for _ in range(layers):
                    encoded = json.dumps(encoded)

                scanned = detector.scan(encoded, "item.completed")

                self.assertEqual(len(scanned), 1)
                self.assertIn("+ text +", scanned[0].value)
                self.assertEqual(detector.code_noise_suppressed_matches, 0)

    def test_python_condition_quote_boundary_preserves_controls_across_json(
        self,
    ) -> None:
        source = (
            "quoted = 'flag{quoted_layer_control}'\n"
            "# observed flag{standalone_layer_control}\n"
            "if 'LINECTF{strong_layer_control}' in values:\n"
            "    pass\n"
            "probe = sorted({s for s in values "
            "if 'flag{' in s.lower()})\n"
            "if ready:\n"
            "    pass\n"
            'elif "NYU{" in s.lower():  # enclosing diagnostic }\n'
        )

        for layers in range(4):
            with self.subTest(json_layers=layers):
                detector = FlagDetector(suppress_generic_code_noise=True)
                encoded = source
                for _ in range(layers):
                    encoded = json.dumps(encoded)

                scanned = detector.scan(encoded, "item.completed")
                explicit = detector.report_candidate(
                    "flag{' in s.lower()}",
                    "final.output",
                    "structured_output",
                )

                self.assertEqual(
                    [candidate.value for candidate in scanned],
                    [
                        "flag{quoted_layer_control}",
                        "flag{standalone_layer_control}",
                        "LINECTF{strong_layer_control}",
                    ],
                )
                self.assertEqual(
                    detector.code_noise_suppressed_matches,
                    2,
                )
                self.assertEqual(detector.suppressed_matches, 2)
                self.assertIsNotNone(explicit)
                self.assertEqual(explicit.value, "flag{' in s.lower()}")
                self.assertEqual(explicit.source, "structured_output")

    def test_prior_closed_literal_does_not_hide_later_candidate(self) -> None:
        detector = FlagDetector(
            (r"\b[A-Za-z0-9_]{2,32}\{[^{}\r\n]{1,512}\}",),
            suppress_generic_code_noise=True,
        )

        scanned = detector.scan(
            '"prior label" flag{real "quoted" value}',
            "item.completed",
        )

        self.assertEqual(
            [candidate.value for candidate in scanned],
            ['flag{real "quoted" value}'],
        )
        self.assertEqual(detector.code_noise_suppressed_matches, 0)

    def test_code_noise_cannot_spend_quota_or_pollute_canonical_state(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            identity = ChallengeIdentity(
                "Domestic CTF",
                "web",
                "scanner precision",
            )
            engine = ChallengeEngine(Path(temporary))
            engine.add_challenge(identity, prompt="solve")
            detector = FlagDetector(
                candidate_limit=4,
                suppress_generic_code_noise=True,
            )
            accumulator = EventAccumulator(
                detector=detector,
                on_flag=lambda candidate: engine.record_candidate(
                    identity,
                    candidate.value,
                    print_immediately=False,
                ),
            )

            accumulator.feed(
                json.dumps(
                    {
                        "type": "item.completed",
                        "text": (
                            ".disabled{color:#ccc} "
                            "return{file:!1} "
                            "function{return result=1} "
                            "<script>NYU{alpha:1,beta:2} "
                            "ACSC{file:!1,glob:!1} "
                            "LINECTF{color:red;margin:0} "
                            "'zer0pts{alpha:1,beta:2}'</script>"
                        ),
                    }
                )
            )

            state = engine.store.load(identity)

        self.assertEqual(
            [candidate.value for candidate in state.candidates],
            [
                "NYU{alpha:1,beta:2}",
                "ACSC{file:!1,glob:!1}",
                "LINECTF{color:red;margin:0}",
                "zer0pts{alpha:1,beta:2}",
            ],
        )
        self.assertEqual(
            [candidate.value for candidate in accumulator.flags],
            [
                "NYU{alpha:1,beta:2}",
                "ACSC{file:!1,glob:!1}",
                "LINECTF{color:red;margin:0}",
                "zer0pts{alpha:1,beta:2}",
            ],
        )
        self.assertEqual(detector.code_noise_suppressed_matches, 3)
        self.assertEqual(detector.suppressed_matches, 3)

    def test_javascript_else_block_call_is_generic_noise_only(self) -> None:
        detector = FlagDetector(suppress_generic_code_noise=True)
        false_positive = (
            "else{repositionParticle(particle,W+20,Math.random()*H,"
            "Math.floor(Math.random()*10)-20)}"
        )

        scanned = detector.scan(
            false_positive + " KCTF{real_control}",
            "tool:bounded-source-scan:stdout-stream",
        )
        explicit = detector.report_candidate(
            false_positive,
            "structured.flag_candidates",
        )

        self.assertEqual(
            [candidate.value for candidate in scanned],
            ["KCTF{real_control}"],
        )
        self.assertEqual(detector.code_noise_suppressed_matches, 1)
        self.assertIsNotNone(explicit)
        self.assertEqual(explicit.value, false_positive)

    def test_go_address_of_composite_literal_is_generic_noise_only(
        self,
    ) -> None:
        source = (
            'SOURCE class=symmetric-focus line=217 '
            'text="return &Payload{V, nonce, body}, nil" '
            'line_sha256=0123456789abcdef\n'
            'quoted = "Payload{V, nonce, body}"\n'
            'known = &NYU{alpha, beta, gamma}\n'
            'ordinary = flag{one, two, three}\n'
        )
        detector = FlagDetector(suppress_generic_code_noise=True)

        scanned = detector.scan(
            source,
            "tool.output",
            "tool:bounded-source-scan:stdout-stream",
        )
        explicit = detector.report_candidate(
            "Record{first, second}",
            "structured.flag_candidates",
        )

        self.assertEqual(
            [candidate.value for candidate in scanned],
            [
                "Payload{V, nonce, body}",
                "NYU{alpha, beta, gamma}",
                "flag{one, two, three}",
            ],
        )
        self.assertEqual(detector.code_noise_suppressed_matches, 1)
        self.assertIsNotNone(explicit)
        self.assertEqual(explicit.value, "Record{first, second}")

    def test_comma_separated_shape_without_go_address_evidence_is_kept(
        self,
    ) -> None:
        detector = FlagDetector(suppress_generic_code_noise=True)

        scanned = detector.scan(
            "Payload{V, nonce, body}",
            "agent_message",
        )

        self.assertEqual(
            [candidate.value for candidate in scanned],
            ["Payload{V, nonce, body}"],
        )
        self.assertEqual(detector.code_noise_suppressed_matches, 0)


if __name__ == "__main__":
    unittest.main()
