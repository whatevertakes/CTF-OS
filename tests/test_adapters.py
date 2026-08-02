from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from ctf_os.adapters import get_adapter
from ctf_os.sandbox.types import CommandSpec, ensure_foreground_command


class AdapterTests(unittest.TestCase):
    def test_all_supported_categories_have_complete_contracts(self) -> None:
        for category in ("pwn", "rev", "crypto", "forensic", "web", "misc"):
            with self.subTest(category=category):
                adapter = get_adapter(category)
                self.assertTrue(adapter.initial_observations())
                self.assertTrue(adapter.progress_markers())
                self.assertTrue(adapter.failure_labels())
                self.assertTrue(adapter.captain_guidance())
                self.assertGreaterEqual(
                    adapter.proof_policy().clean_repetitions, 1
                )

    def test_competition_category_labels_resolve_without_changing_state_names(self) -> None:
        aliases = {
            "System Hacking": "pwn",
            "system-hacking": "pwn",
            "binary exploitation": "pwn",
            "Reverse Engineering": "reversing",
            "reverse-engineering": "reversing",
            "Cryptography": "crypto",
            "Digital Forensics": "forensics",
            "digital-forensics": "forensics",
            "Web Hacking": "web",
            "web security": "web",
            "Miscellaneous": "misc",
            "Steganography": "misc",
        }
        for label, expected in aliases.items():
            with self.subTest(label=label):
                self.assertEqual(get_adapter(label).name, expected)

    def test_pwn_markers_are_capabilities_not_a_required_ladder(self) -> None:
        adapter = get_adapter("pwn")
        keys = {marker.key for marker in adapter.progress_markers()}
        self.assertIn("control", keys)
        self.assertIn("flag_read", keys)
        self.assertNotIn("ordered", adapter.captain_guidance().lower())

    def test_pwn_runtime_baseline_is_bounded_and_path_safe(self) -> None:
        baseline = next(
            experiment
            for experiment in get_adapter("pwn").initial_observations()
            if experiment.id == "runtime_baseline"
        )
        primary = "/challenge/name with 'quotes' and $shell"
        argv = tuple(
            argument.replace("{primary}", primary)
            for argument in baseline.command_template
        )

        self.assertEqual(argv[:2], ("/bin/sh", "-lc"))
        self.assertEqual(argv[-1], primary)
        self.assertEqual(argv[-2], "ctfos-pwn-runtime-baseline")
        self.assertEqual(baseline.timeout_s, 15)
        self.assertEqual(baseline.resource_class, "light")
        self.assertNotIn(primary, argv[2])
        self.assertIn(
            "/usr/bin/timeout --signal=TERM --kill-after=1 3",
            argv[2],
        )
        self.assertIn("--kill-after=1", argv[2])
        self.assertNotIn("ulimit -f", argv[2])
        self.assertIn("/usr/bin/head -c 65536", argv[2])
        self.assertIn("ctfos_runtime_baseline_exit=", argv[2])
        CommandSpec.create(argv)
        ensure_foreground_command(argv)

    def test_pwn_runtime_baseline_drains_an_unbounded_menu_without_disk_capture(
        self,
    ) -> None:
        baseline = next(
            experiment
            for experiment in get_adapter("pwn").initial_observations()
            if experiment.id == "runtime_baseline"
        )
        with tempfile.TemporaryDirectory(
            prefix="ctfos-pwn-baseline-test-"
        ) as temporary:
            target = Path(temporary) / "menu"
            target.write_text(
                "#!/bin/sh\nexec /usr/bin/yes MENU\n",
                encoding="utf-8",
            )
            os.chmod(target, 0o700)
            argv = tuple(
                argument.replace("{primary}", str(target))
                for argument in baseline.command_template
            )
            result = subprocess.run(
                argv,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLessEqual(len(result.stdout), 65_700)
        self.assertTrue(result.stdout.startswith(b"MENU\n"))
        self.assertIn(b"ctfos_runtime_baseline_exit=", result.stdout)
        self.assertIn(b"pipe_exit=0", result.stdout)

    def test_web_intake_never_makes_an_implicit_remote_request(self) -> None:
        adapter = get_adapter("web")
        for experiment in adapter.initial_observations():
            self.assertFalse(experiment.requires_network)
        marker_keys = {marker.key for marker in adapter.progress_markers()}
        self.assertIn("endpoint_observed", marker_keys)
        self.assertIn("auth_state_captured", marker_keys)
        self.assertIn("impact_verified", marker_keys)
        self.assertIn("--session attacker|user|admin", adapter.captain_guidance())
        self.assertIn("ctf-sqlite-readonly", adapter.captain_guidance())
        self.assertIn("allowlisted HTTP", adapter.captain_guidance())

    def test_forensics_intake_uses_bounded_read_only_evidence_index(
        self,
    ) -> None:
        experiments = get_adapter("forensics").initial_observations()
        self.assertEqual(len(experiments), 1)
        inventory = experiments[0]
        self.assertEqual(inventory.id, "file_inventory")
        self.assertEqual(
            inventory.command_template,
            (
                "/usr/bin/python3",
                "/opt/ctf-templates/forensic/evidence_index.py",
                "--root",
                "/challenge",
                "--tree",
                "/work/.ctf/challenge.tree",
                "--metadata",
                "/work/.ctf/challenge.json",
            ),
        )
        self.assertFalse(inventory.requires_network)
        self.assertIn("coverage", inventory.expected_observation)

    def test_misc_intake_preserves_three_independent_modality_probes(
        self,
    ) -> None:
        adapter = get_adapter("misc")
        experiments = adapter.initial_observations()

        self.assertEqual(
            [item.id for item in experiments],
            ["typed_inventory", "primary_magic", "primary_strings"],
        )
        self.assertTrue(
            all(not item.requires_network for item in experiments)
        )
        self.assertEqual(
            experiments[0].command_template[1],
            "/opt/ctf-templates/forensic/evidence_index.py",
        )
        self.assertEqual(experiments[1].command_template[0], "/usr/bin/file")
        self.assertEqual(experiments[2].command_template[:2], ("/bin/sh", "-lc"))
        self.assertIn("/usr/bin/head -c 65536", experiments[2].command_template[2])

        guidance = adapter.captain_guidance()
        for prior in (
            "stego=0.35",
            "custom_protocol=0.25",
            "audio_signal=0.15",
            "jail=0.10",
            "ppc=0.10",
            "other=0.05",
        ):
            self.assertIn(prior, guidance)
        self.assertIn("three independent", guidance)
        self.assertIn("two independent observations", guidance)

    def test_misc_strings_probe_keeps_primary_out_of_shell_source(self) -> None:
        probe = next(
            item
            for item in get_adapter("misc").initial_observations()
            if item.id == "primary_strings"
        )
        primary = "/challenge/name with 'quotes' and $shell"
        argv = tuple(
            argument.replace("{primary}", primary)
            for argument in probe.command_template
        )

        self.assertEqual(argv[-1], primary)
        self.assertEqual(argv[-2], "ctfos-misc-primary-strings")
        self.assertNotIn(primary, argv[2])
        CommandSpec.create(argv)
        ensure_foreground_command(argv)

    def test_unknown_category_keeps_single_generic_inventory(self) -> None:
        adapter = get_adapter("unknown-category")
        self.assertEqual(adapter.name, "misc")
        self.assertEqual(
            [item.id for item in adapter.initial_observations()],
            ["inventory"],
        )


if __name__ == "__main__":
    unittest.main()
