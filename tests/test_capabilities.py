from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path

from ctf_os.capabilities import (
    CapabilityError,
    REQUIRED_MANAGED_ATTESTATIONS,
    inspect_pinned_capabilities,
    normalize_capability_manifest,
)


DIGEST = "sha256:" + "c" * 64
GENERIC_CAPABILITIES = (
    "convert",
    "sqlite_readonly",
    "z3",
    "ortools",
    "angr_python",
)


def capability_payload(*, include_rev: bool = True) -> dict[str, object]:
    records: list[dict[str, object]] = [
        {"name": name, "available": True}
        for name in GENERIC_CAPABILITIES
    ]
    if include_rev:
        records.extend(
            {
                "name": name,
                "available": True,
                "attestation": dict(attestation),
            }
            for name, attestation in REQUIRED_MANAGED_ATTESTATIONS.items()
        )
    return {"schema_version": 2, "capabilities": records}


class CapabilityTests(unittest.TestCase):
    def test_host_attestations_match_vendored_v2_manifest(self):
        manifest = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "ctf-os-image"
                / "capabilities.v2.json"
            ).read_text(encoding="utf-8")
        )
        observed = {}
        for record in manifest["capabilities"]:
            name = record["name"]
            if name not in REQUIRED_MANAGED_ATTESTATIONS:
                continue
            observed[name] = {
                "schema_version": record[
                    "attestation_schema_version"
                ],
                "contract_id": record["contract_id"],
                "contract_version": record["contract_version"],
                "path": record["path"],
                "sha256": record["sha256"],
            }
        self.assertEqual(observed, REQUIRED_MANAGED_ATTESTATIONS)

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
            payload = capability_payload()
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(payload).encode(),
                b"",
            )

        report = inspect_pinned_capabilities(DIGEST, runner=runner)
        self.assertTrue(report["ok"])
        self.assertEqual(
            report["attestations"],
            REQUIRED_MANAGED_ATTESTATIONS,
        )
        self.assertEqual(report["attestation_errors"], {})
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

    def test_old_v2_image_without_rev_attestations_fails_closed(self):
        def runner(argv, **kwargs):
            del kwargs
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    capability_payload(include_rev=False)
                ).encode(),
                b"",
            )

        report = inspect_pinned_capabilities(DIGEST, runner=runner)
        self.assertFalse(report["ok"])
        self.assertEqual(
            report["missing"],
            [
                "rev_inventory_v2",
                "rev_safe_output",
                "rev_stdin_exec",
            ],
        )
        self.assertEqual(report["attestations"], {})

    def test_rev_fingerprint_or_version_mismatch_fails_closed(self):
        payload = capability_payload()
        records = payload["capabilities"]
        self.assertIsInstance(records, list)
        inventory = next(
            item
            for item in records
            if item["name"] == "rev_inventory_v2"
        )
        inventory["attestation"]["sha256"] = "0" * 64
        stdin_exec = next(
            item
            for item in records
            if item["name"] == "rev_stdin_exec"
        )
        stdin_exec["attestation"]["contract_version"] = True
        safe_output = next(
            item
            for item in records
            if item["name"] == "rev_safe_output"
        )
        safe_output["attestation"]["path"] = (
            "/opt/ctf-templates/rev/stale_output.py"
        )

        def runner(argv, **kwargs):
            del kwargs
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(payload).encode(),
                b"",
            )

        report = inspect_pinned_capabilities(DIGEST, runner=runner)
        self.assertFalse(report["ok"])
        self.assertEqual(
            report["missing"],
            [
                "rev_inventory_v2",
                "rev_safe_output",
                "rev_stdin_exec",
            ],
        )
        self.assertEqual(
            set(report["attestation_errors"]),
            {
                "rev_inventory_v2",
                "rev_safe_output",
                "rev_stdin_exec",
            },
        )
        self.assertEqual(report["attestations"], {})

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
