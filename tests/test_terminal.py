from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from ctf_os import cli
from ctf_os.terminal import terminal_safe


class TerminalSafetyTests(unittest.TestCase):
    def test_controls_and_bidi_are_visible_escapes(self) -> None:
        rendered = terminal_safe(
            "prefix\x1b]0;owned\x07\u202etxt\u2028line\u2029paragraph\nsuffix"
        )
        self.assertEqual(
            rendered,
            "prefix\\x1b]0;owned\\x07\\u202etxt"
            "\\u2028line\\u2029paragraph\\x0asuffix",
        )
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\x07", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertNotIn("\u2028", rendered)
        self.assertNotIn("\u2029", rendered)

    def test_ingest_error_cannot_write_terminal_control_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = ("KCTF", "misc", "terminal")

            def invoke(arguments: list[str]) -> tuple[int, str, str]:
                stdout = io.StringIO()
                stderr = io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    status = cli.main(arguments, root=root)
                return status, stdout.getvalue(), stderr.getvalue()

            status, _, errors = invoke(
                ["add-challenge", *identity, "--prompt", "inspect files"]
            )
            self.assertEqual(status, 0, errors)
            incoming = root / "incoming" / identity[0] / identity[1] / identity[2]
            target = root / "outside"
            target.write_text("outside", encoding="utf-8")
            hostile_name = "bad\x1b]0;CTFOS-PWN\x07"
            (incoming / hostile_name).symlink_to(target)

            status, _, errors = invoke(["add-challenge", *identity])
            self.assertEqual(status, 2)
            self.assertNotIn("\x1b", errors)
            self.assertNotIn("\x07", errors)
            self.assertIn("\\x1b", errors)
            self.assertIn("\\x07", errors)

    def test_json_output_escapes_bidi_controls(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            cli._print_json({"value": "left\u202eright"})
        rendered = output.getvalue()
        self.assertNotIn("\u202e", rendered)
        self.assertIn("\\u202e", rendered)


if __name__ == "__main__":
    unittest.main()
