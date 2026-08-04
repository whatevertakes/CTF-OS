from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ctf_os.config import (
    ConfigError,
    default_config_text,
    load_config,
    set_runtime_image_digest,
)
from ctf_os.models import MAX_EXPERIMENT_TIMEOUT_SECONDS

IMAGE_DIGEST = "sha256:" + "a" * 64


class ConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def write_config(self, text: str) -> None:
        directory = self.root / ".ctfos"
        directory.mkdir()
        (directory / "engine.toml").write_text(text, encoding="utf-8")

    def test_defaults_keep_logical_and_provider_limits_separate(self) -> None:
        config = load_config(self.root)
        self.assertEqual(config.resources.worker_slots_per_challenge, 3)
        self.assertEqual(config.resources.provider_max_concurrent_calls, 4)
        self.assertEqual(
            config.resources.remote_command_min_interval_s,
            1.0,
        )
        model_roles = (
            "captain",
            "recon",
            "specialist",
            "builder",
            "falsifier",
            "extractor",
            "reproducer",
            "validator",
            "evidence_auditor",
        )
        self.assertEqual(
            {getattr(config.models, role) for role in model_roles},
            {"gpt-5.6-sol"},
        )
        self.assertEqual(config.runtime.network_default, "none")
        self.assertEqual(
            config.runtime.work_tree_max_bytes,
            16 * 1024 * 1024 * 1024,
        )
        self.assertEqual(
            config.runtime.challenge_storage_quota_bytes,
            64 * 1024 * 1024 * 1024,
        )
        self.assertEqual(config.runtime.storage_scan_max_entries, 100_000)
        self.assertEqual(
            config.runtime.storage_scan_max_bytes,
            256 * 1024 * 1024 * 1024,
        )
        self.assertEqual(config.runtime.managed_wave_queue_reserve_s, 900.0)
        self.assertEqual(
            config.runtime.managed_wave_role_call_reserve_s,
            1200.0,
        )
        self.assertEqual(
            config.runtime.managed_wave_action_commit_reserve_s,
            300.0,
        )

    def test_default_text_round_trips(self) -> None:
        text = default_config_text()
        self.assertIn("# image_digest", text)
        self.write_config(text)
        config = load_config(self.root)
        self.assertEqual(config.resources.wave_width_proof, 3)
        self.assertEqual(len(config.runtime.flag_patterns), 2)
        self.assertIn("not a live filesystem quota", text)
        self.assertIn("remote_command_min_interval_s = 1.0", text)
        self.assertIn("not an HTTP request limiter", text)
        self.assertIn("command_timeout_s = 900\n", text)
        self.assertNotIn("command_timeout_s = 900.0", text)
        self.assertIn(
            "challenge_storage_quota_bytes = 68719476736",
            text,
        )
        self.assertIn("storage_scan_max_entries = 100000", text)
        self.assertIn(
            "storage_scan_max_bytes = 274877906944",
            text,
        )
        self.assertIn("managed_wave_queue_reserve_s = 900.0", text)
        self.assertIn(
            "managed_wave_role_call_reserve_s = 1200.0",
            text,
        )
        self.assertIn(
            "managed_wave_action_commit_reserve_s = 300.0",
            text,
        )
        self.assertIn("fail-closed defaults are calibrated", text)
        self.assertIn(
            "Provider concurrency changes",
            text,
        )
        self.assertEqual(text.count('= "gpt-5.6-sol"'), 9)
        self.assertNotIn("gpt-5.6-terra", text)
        self.assertNotIn("gpt-5.6-luna", text)

    def test_remote_command_interval_accepts_zero_and_is_bounded(self) -> None:
        self.write_config(
            "[resources]\n"
            "remote_command_min_interval_s = 0\n"
        )
        config_path = self.root / ".ctfos" / "engine.toml"
        self.assertEqual(
            load_config(self.root).resources.remote_command_min_interval_s,
            0,
        )

        config_path.write_text(
            "[resources]\n"
            "remote_command_min_interval_s = 3600.0\n",
            encoding="utf-8",
        )
        self.assertEqual(
            load_config(self.root).resources.remote_command_min_interval_s,
            3600.0,
        )

        for value in ("-0.1", "nan", "3600.1", "true", '"1.0"'):
            with self.subTest(value=value):
                config_path.write_text(
                    "[resources]\n"
                    f"remote_command_min_interval_s = {value}\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    ConfigError,
                    "remote_command_min_interval_s",
                ):
                    load_config(self.root)

    def test_timeout_settings_require_finite_positive_numbers(self) -> None:
        self.write_config("")
        config_path = self.root / ".ctfos" / "engine.toml"
        invalid_values = (
            "nan",
            "inf",
            "-inf",
            "true",
            '"1.0"',
            "0",
            "-1",
        )
        for section, name in (
            ("resources", "provider_wait_timeout_s"),
            ("resources", "lease_wait_timeout_s"),
            ("runtime", "wave_deadline_s"),
            ("runtime", "managed_wave_queue_reserve_s"),
            ("runtime", "managed_wave_role_call_reserve_s"),
            ("runtime", "managed_wave_action_commit_reserve_s"),
        ):
            for value in invalid_values:
                with self.subTest(
                    section=section,
                    name=name,
                    value=value,
                ):
                    config_path.write_text(
                        f"[{section}]\n{name} = {value}\n",
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(ConfigError, name):
                        load_config(self.root)

    def test_command_timeout_matches_the_live_integer_bound(self) -> None:
        self.write_config("")
        config_path = self.root / ".ctfos" / "engine.toml"
        for value in (
            "true",
            "0",
            "-1",
            "1.0",
            "nan",
            "inf",
            "-inf",
            '"1"',
            str(MAX_EXPERIMENT_TIMEOUT_SECONDS + 1),
            "604801",
        ):
            with self.subTest(value=value):
                config_path.write_text(
                    f"[runtime]\ncommand_timeout_s = {value}\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    ConfigError,
                    "command_timeout_s",
                ):
                    load_config(self.root)

        for value in (1, MAX_EXPERIMENT_TIMEOUT_SECONDS):
            with self.subTest(valid=value):
                config_path.write_text(
                    f"[runtime]\ncommand_timeout_s = {value}\n",
                    encoding="utf-8",
                )
                self.assertEqual(
                    load_config(self.root).runtime.command_timeout_s,
                    value,
                )

    def test_runtime_work_tree_bound_is_configurable_and_positive(self) -> None:
        self.write_config(
            "[runtime]\n"
            "work_tree_max_bytes = 67108864\n"
        )
        self.assertEqual(
            load_config(self.root).runtime.work_tree_max_bytes,
            64 * 1024 * 1024,
        )

        for value in ("0", "-1", "true", "1.5"):
            with self.subTest(value=value):
                (self.root / ".ctfos" / "engine.toml").write_text(
                    f"[runtime]\nwork_tree_max_bytes = {value}\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    ConfigError,
                    "work_tree_max_bytes",
                ):
                    load_config(self.root)

    def test_runtime_storage_bounds_are_configurable_positive_integers(
        self,
    ) -> None:
        self.write_config(
            "[runtime]\n"
            "challenge_storage_quota_bytes = 67108864\n"
            "storage_scan_max_entries = 1234\n"
            "storage_scan_max_bytes = 134217728\n"
        )
        runtime = load_config(self.root).runtime
        self.assertEqual(runtime.challenge_storage_quota_bytes, 67_108_864)
        self.assertEqual(runtime.storage_scan_max_entries, 1_234)
        self.assertEqual(runtime.storage_scan_max_bytes, 134_217_728)

        config_path = self.root / ".ctfos" / "engine.toml"
        for name in (
            "challenge_storage_quota_bytes",
            "storage_scan_max_entries",
            "storage_scan_max_bytes",
        ):
            for value in ("0", "-1", "true", "1.5", '"1"'):
                with self.subTest(name=name, value=value):
                    config_path.write_text(
                        f"[runtime]\n{name} = {value}\n",
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(ConfigError, name):
                        load_config(self.root)

    def test_model_efforts_accept_only_codex_supported_values(self) -> None:
        self.write_config(
            "[models]\n"
            'captain_effort = "high"\n'
            'worker_effort = "xhigh"\n'
        )
        config = load_config(self.root)
        self.assertEqual(config.models.captain_effort, "high")
        self.assertEqual(config.models.worker_effort, "xhigh")

    def test_rejects_unknown_model_effort(self) -> None:
        self.write_config('[models]\nworker_effort = "extreme"\n')
        with self.assertRaisesRegex(ConfigError, "worker_effort"):
            load_config(self.root)

    def test_provider_limit_can_be_overridden_without_narrowing_wave(self) -> None:
        with patch.dict(os.environ, {"CTFOS_MODEL_CONCURRENCY": "1"}):
            config = load_config(self.root)
        self.assertEqual(config.resources.provider_max_concurrent_calls, 1)
        self.assertEqual(config.resources.wave_width_discovery, 3)

    def test_rejects_wave_wider_than_logical_role_limit(self) -> None:
        self.write_config(
            "[resources]\n"
            "worker_slots_per_challenge = 2\n"
            "wave_width_discovery = 3\n"
        )
        with self.assertRaisesRegex(ConfigError, "must remain 3"):
            load_config(self.root)

    def test_rejects_silently_narrowing_a_logical_wave(self) -> None:
        self.write_config(
            "[resources]\n"
            "wave_width_attack = 1\n"
        )
        with self.assertRaisesRegex(ConfigError, "queue calls"):
            load_config(self.root)

    def test_rejects_permissive_network_default(self) -> None:
        self.write_config('[runtime]\nnetwork_default = "bridge"\n')
        with self.assertRaisesRegex(ConfigError, "must remain 'none'"):
            load_config(self.root)

    def test_image_digest_accepts_only_exact_lowercase_local_image_id(self) -> None:
        self.write_config(
            f'[runtime]\nimage_digest = "{IMAGE_DIGEST}"\n'
        )
        self.assertEqual(load_config(self.root).runtime.image_digest, IMAGE_DIGEST)

        invalid_values = (
            '"sha256:' + "a" * 63 + '"',
            '"sha256:' + "A" * 64 + '"',
            '"SHA256:' + "a" * 64 + '"',
            '"sha512:' + "a" * 64 + '"',
            '""',
            "123",
        )
        for value in invalid_values:
            with self.subTest(value=value):
                (self.root / ".ctfos" / "engine.toml").write_text(
                    f"[runtime]\nimage_digest = {value}\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(ConfigError, "image_digest"):
                    load_config(self.root)

    def test_image_name_rejects_non_string_and_control_characters(self) -> None:
        directory = self.root / ".ctfos"
        directory.mkdir()
        for value in (
            "123",
            '"bad\\nimage"',
            '" leading"',
            '"trailing "',
            '"inner space"',
            '"tab\\timage"',
        ):
            with self.subTest(value=value):
                (directory / "engine.toml").write_text(
                    f"[runtime]\nimage = {value}\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(ConfigError, "image"):
                    load_config(self.root)

    def test_runtime_digest_update_preserves_other_text_and_is_idempotent(
        self,
    ) -> None:
        original = (
            "# operator comment\n"
            "[runtime]\n"
            'image = "ctf-os:core"\n'
            "network_default = \"none\"\n"
            "\n"
            "[models]\n"
            'worker_effort = "max"\n'
        )
        updated = set_runtime_image_digest(original, IMAGE_DIGEST)
        self.assertIn("# operator comment", updated)
        self.assertIn(f'image_digest = "{IMAGE_DIGEST}"', updated)
        self.assertEqual(
            set_runtime_image_digest(updated, IMAGE_DIGEST),
            updated,
        )
        self.write_config(updated)
        self.assertEqual(load_config(self.root).runtime.image_digest, IMAGE_DIGEST)

    def test_runtime_digest_update_adds_missing_runtime_table(self) -> None:
        updated = set_runtime_image_digest(
            '[models]\nworker_effort = "max"\n',
            IMAGE_DIGEST,
        )
        self.assertIn("[runtime]", updated)
        self.assertIn(f'image_digest = "{IMAGE_DIGEST}"', updated)


if __name__ == "__main__":
    unittest.main()
