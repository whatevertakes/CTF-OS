from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from ctf_os.capabilities import (
    REQUIRED_MANAGED_ATTESTATIONS,
    REQUIRED_MANAGED_CAPABILITIES,
)
from ctf_os.config import load_config
from ctf_os.doctor import collect_diagnostics

IMAGE_DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64


def capability_manifest(
    *,
    missing: frozenset[str] = frozenset(),
) -> str:
    records = []
    for name in sorted(REQUIRED_MANAGED_CAPABILITIES):
        record = {
            "name": name,
            "available": name not in missing,
        }
        if name not in missing and name in REQUIRED_MANAGED_ATTESTATIONS:
            record["attestation"] = REQUIRED_MANAGED_ATTESTATIONS[name]
        records.append(record)
    return json.dumps(
        {"schema_version": 2, "capabilities": records}
    )


class DoctorTests(unittest.TestCase):
    def test_reports_missing_binaries_without_mutating_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def missing_runner(command, **kwargs):
                raise FileNotFoundError(command[0])

            report = collect_diagnostics(
                load_config(root),
                runner=missing_runner,
                which=lambda name: None,
                calibrate=True,
            )
            self.assertFalse(report["ok"])
            self.assertFalse(report["codex"]["available"])
            self.assertIn("calibration", report)
            self.assertEqual(list(root.iterdir()), [])

    def test_keeps_logical_width_visible_next_to_provider_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def fake_runner(command, **kwargs):
                if command[:2] == ["docker", "image"]:
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        f'"{IMAGE_DIGEST}"\n[]',
                        "",
                    )
                if command[:3] == ["docker", "info", "--format"]:
                    return subprocess.CompletedProcess(command, 0, "{}", "")
                return subprocess.CompletedProcess(command, 0, "ok", "")

            report = collect_diagnostics(
                load_config(root), runner=fake_runner, which=lambda name: None
            )
        self.assertEqual(
            report["policy"]["logical_workers_per_challenge"], 3
        )
        self.assertEqual(
            report["policy"]["provider_max_concurrent_calls"], 4
        )
        self.assertEqual(report["image"]["id"], IMAGE_DIGEST)
        self.assertNotIn("error", report["image"])
        self.assertEqual(report["image"]["pin_status"], "unpinned")
        self.assertFalse(report["ok"])
        self.assertEqual(
            report["managed_capabilities"]["status"],
            "blocked",
        )

    def test_image_inspect_uses_bounded_fields_instead_of_truncated_object(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def fake_runner(command, **kwargs):
                if command[:2] == ["docker", "image"]:
                    self.assertEqual(
                        command[-1],
                        "{{json .Id}}\n{{json .RepoDigests}}",
                    )
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        (
                            f'"{IMAGE_DIGEST}"\n'
                            f'["ctf-os@{IMAGE_DIGEST}"]'
                        ),
                        "",
                    )
                if command[:3] == ["docker", "info", "--format"]:
                    return subprocess.CompletedProcess(command, 0, "{}", "")
                return subprocess.CompletedProcess(command, 0, "ok", "")

            report = collect_diagnostics(
                load_config(root), runner=fake_runner, which=lambda name: None
            )

        self.assertEqual(
            report["image"]["repo_digests"],
            [f"ctf-os@{IMAGE_DIGEST}"],
        )
        self.assertNotIn("error", report["image"])

    def test_pinned_image_match_is_ready(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_root = root / ".ctfos"
            config_root.mkdir()
            (config_root / "engine.toml").write_text(
                f'[runtime]\nimage_digest = "{IMAGE_DIGEST}"\n',
                encoding="utf-8",
            )

            def fake_runner(command, **kwargs):
                if command[:2] == ["docker", "image"]:
                    return subprocess.CompletedProcess(
                        command, 0, f'"{IMAGE_DIGEST}"\n[]', ""
                    )
                if command[:2] == ["docker", "run"]:
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        capability_manifest(),
                        "",
                    )
                if command[:3] == ["docker", "info", "--format"]:
                    return subprocess.CompletedProcess(command, 0, "{}", "")
                return subprocess.CompletedProcess(command, 0, "ok", "")

            report = collect_diagnostics(
                load_config(root), runner=fake_runner, which=lambda name: None
            )

        self.assertTrue(report["ok"])
        self.assertEqual(report["image"]["pin_status"], "matched")
        self.assertEqual(report["image"]["execution_reference"], IMAGE_DIGEST)
        self.assertTrue(report["image"]["execution_available"])
        self.assertEqual(
            report["managed_capabilities"]["status"],
            "ready",
        )

    def test_missing_managed_capability_is_not_false_green(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_root = root / ".ctfos"
            config_root.mkdir()
            (config_root / "engine.toml").write_text(
                f'[runtime]\nimage_digest = "{IMAGE_DIGEST}"\n',
                encoding="utf-8",
            )

            def fake_runner(command, **kwargs):
                if command[:2] == ["docker", "image"]:
                    return subprocess.CompletedProcess(
                        command, 0, f'"{IMAGE_DIGEST}"\n[]', ""
                    )
                if command[:2] == ["docker", "run"]:
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        capability_manifest(
                            missing=frozenset({"pwn_crash_v1"})
                        ),
                        "",
                    )
                if command[:3] == ["docker", "info", "--format"]:
                    return subprocess.CompletedProcess(command, 0, "{}", "")
                return subprocess.CompletedProcess(command, 0, "ok", "")

            report = collect_diagnostics(
                load_config(root), runner=fake_runner, which=lambda name: None
            )

        self.assertFalse(report["ok"])
        self.assertEqual(
            report["managed_capabilities"]["status"],
            "missing",
        )
        self.assertEqual(
            report["managed_capabilities"]["missing"],
            ["pwn_crash_v1"],
        )
        self.assertTrue(
            any(
                "pwn_crash_v1" in item
                for item in report["warnings"]
            )
        )

    def test_pinned_tag_mismatch_is_not_false_green(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_root = root / ".ctfos"
            config_root.mkdir()
            (config_root / "engine.toml").write_text(
                f'[runtime]\nimage_digest = "{IMAGE_DIGEST}"\n',
                encoding="utf-8",
            )

            def fake_runner(command, **kwargs):
                if command[:2] == ["docker", "image"]:
                    reference = command[3]
                    digest = (
                        IMAGE_DIGEST
                        if reference == IMAGE_DIGEST
                        else OTHER_DIGEST
                    )
                    return subprocess.CompletedProcess(
                        command, 0, f'"{digest}"\n[]', ""
                    )
                if command[:3] == ["docker", "info", "--format"]:
                    return subprocess.CompletedProcess(command, 0, "{}", "")
                return subprocess.CompletedProcess(command, 0, "ok", "")

            report = collect_diagnostics(
                load_config(root), runner=fake_runner, which=lambda name: None
            )

        self.assertFalse(report["ok"])
        self.assertEqual(report["image"]["pin_status"], "mismatch")
        self.assertTrue(report["image"]["execution_available"])
        self.assertTrue(any("does not match" in item for item in report["warnings"]))

    def test_missing_pinned_image_is_not_false_green(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_root = root / ".ctfos"
            config_root.mkdir()
            (config_root / "engine.toml").write_text(
                f'[runtime]\nimage_digest = "{IMAGE_DIGEST}"\n',
                encoding="utf-8",
            )

            def fake_runner(command, **kwargs):
                if command[:2] == ["docker", "image"]:
                    if command[3] == IMAGE_DIGEST:
                        return subprocess.CompletedProcess(
                            command, 1, "", "not found"
                        )
                    return subprocess.CompletedProcess(
                        command, 0, f'"{OTHER_DIGEST}"\n[]', ""
                    )
                if command[:3] == ["docker", "info", "--format"]:
                    return subprocess.CompletedProcess(command, 0, "{}", "")
                return subprocess.CompletedProcess(command, 0, "ok", "")

            report = collect_diagnostics(
                load_config(root), runner=fake_runner, which=lambda name: None
            )

        self.assertFalse(report["ok"])
        self.assertEqual(report["image"]["pin_status"], "missing")
        self.assertFalse(report["image"]["execution_available"])
        self.assertTrue(any("pinned tool image" in item for item in report["warnings"]))


if __name__ == "__main__":
    unittest.main()
