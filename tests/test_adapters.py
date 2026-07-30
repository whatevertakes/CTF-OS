from __future__ import annotations

import unittest

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
        self.assertIn("/usr/bin/timeout --signal=TERM 3", argv[2])
        CommandSpec.create(argv)
        ensure_foreground_command(argv)

    def test_web_intake_never_makes_an_implicit_remote_request(self) -> None:
        adapter = get_adapter("web")
        for experiment in adapter.initial_observations():
            self.assertFalse(experiment.requires_network)
        marker_keys = {marker.key for marker in adapter.progress_markers()}
        self.assertIn("endpoint_observed", marker_keys)
        self.assertIn("auth_state_captured", marker_keys)
        self.assertIn("impact_verified", marker_keys)
        self.assertIn("--session attacker|user|admin", adapter.captain_guidance())

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


if __name__ == "__main__":
    unittest.main()
