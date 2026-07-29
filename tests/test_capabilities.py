from __future__ import annotations

import json
import subprocess
import unittest

from ctf_os.capabilities import (
    CapabilityError,
    inspect_pinned_capabilities,
    normalize_capability_manifest,
)


DIGEST = "sha256:" + "c" * 64


class CapabilityTests(unittest.TestCase):
    def test_v1_and_v2_manifests_normalize_without_silent_omission(self):
        self.assertEqual(
            normalize_capability_manifest(
                {
                    "schema_version": 1,
                    "tools": [
                        {"name": "convert", "available": True},
                    ],
                }
            ),
            {"convert": True},
        )
        self.assertEqual(
            normalize_capability_manifest(
                {
                    "schema_version": 2,
                    "capabilities": [
                        {"name": "z3", "available": False},
                    ],
                }
            ),
            {"z3": False},
        )
        with self.assertRaisesRegex(CapabilityError, "duplicate"):
            normalize_capability_manifest(
                {
                    "schema_version": 2,
                    "capabilities": [
                        {"name": "Z3", "available": True},
                        {"name": "z3", "available": True},
                    ],
                }
            )

    def test_probe_uses_exact_image_network_none_readonly_root_and_tmpfs(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            payload = {
                "schema_version": 2,
                "capabilities": [
                    {"name": name, "available": True}
                    for name in (
                        "convert",
                        "sqlite_readonly",
                        "z3",
                        "ortools",
                        "angr_python",
                    )
                ],
            }
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(payload).encode(),
                b"",
            )

        report = inspect_pinned_capabilities(DIGEST, runner=runner)
        self.assertTrue(report["ok"])
        argv, kwargs = calls[0]
        self.assertEqual(
            argv,
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,noexec,size=64m",
                "--entrypoint",
                "ctf-capabilities",
                DIGEST,
                "--json",
            ],
        )
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)

    def test_probe_rejects_duplicate_json_keys(self):
        def runner(argv, **kwargs):
            del kwargs
            return subprocess.CompletedProcess(
                argv,
                0,
                b'{"schema_version":2,"schema_version":2,'
                b'"capabilities":[]}',
                b"",
            )

        with self.assertRaisesRegex(CapabilityError, "duplicate"):
            inspect_pinned_capabilities(DIGEST, runner=runner)


if __name__ == "__main__":
    unittest.main()
