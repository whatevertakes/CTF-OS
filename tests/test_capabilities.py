from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path

from ctf_os.capabilities import (
    CapabilityError,
    REQUIRED_MANAGED_ATTESTATIONS,
    REQUIRED_MANAGED_CAPABILITIES,
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


def capability_payload(
    *,
    excluded_attestations: frozenset[str] = frozenset(),
) -> dict[str, object]:
    records: list[dict[str, object]] = [
        {"name": name, "available": True}
        for name in GENERIC_CAPABILITIES
    ]
    records.extend(
        {
            "name": name,
            "available": True,
            "attestation": dict(attestation),
        }
        for name, attestation in REQUIRED_MANAGED_ATTESTATIONS.items()
        if name not in excluded_attestations
    )
    return {"schema_version": 2, "capabilities": records}


class CapabilityTests(unittest.TestCase):
    def test_host_attestations_match_vendored_v2_manifest(self):
        self.assertEqual(len(REQUIRED_MANAGED_CAPABILITIES), 11)
        manifest = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "ctf-os-image"
                / "capabilities.v2.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            {
                record["name"]
                for record in manifest["capabilities"]
            },
            REQUIRED_MANAGED_CAPABILITIES,
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
        self.assertEqual(kwargs["timeout"], 30.0)

    def test_probe_timeout_is_positive_finite_and_capped(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append(kwargs["timeout"])
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(capability_payload()).encode(),
                b"",
            )

        inspect_pinned_capabilities(
            DIGEST,
            runner=runner,
            timeout_seconds=0.25,
        )
        inspect_pinned_capabilities(
            DIGEST,
            runner=runner,
            timeout_seconds=300,
        )
        self.assertEqual(calls, [0.25, 30.0])
        for invalid in (0, -1, True, float("inf"), float("nan")):
            with self.subTest(timeout=invalid):
                with self.assertRaisesRegex(
                    CapabilityError,
                    "positive and finite",
                ):
                    inspect_pinned_capabilities(
                        DIGEST,
                        runner=runner,
                        timeout_seconds=invalid,
                    )

    def test_old_v2_image_without_managed_attestations_fails_closed(self):
        def runner(argv, **kwargs):
            del kwargs
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    capability_payload(
                        excluded_attestations=frozenset(
                            REQUIRED_MANAGED_ATTESTATIONS
                        )
                    )
                ).encode(),
                b"",
            )

        report = inspect_pinned_capabilities(DIGEST, runner=runner)
        self.assertFalse(report["ok"])
        self.assertEqual(
            report["missing"],
            [
                "pwn_crash_v1",
                "pwn_exploit_effect_v1",
                "pwn_runtime_snapshot_v1",
                "rev_inventory_v2",
                "rev_safe_output",
                "rev_stdin_exec",
            ],
        )
        self.assertEqual(report["attestations"], {})

    def test_pwn_crash_capability_missing_fails_closed(self):
        def runner(argv, **kwargs):
            del kwargs
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    capability_payload(
                        excluded_attestations=frozenset({"pwn_crash_v1"})
                    )
                ).encode(),
                b"",
            )

        report = inspect_pinned_capabilities(DIGEST, runner=runner)
        self.assertFalse(report["ok"])
        self.assertEqual(report["missing"], ["pwn_crash_v1"])
        self.assertNotIn("pwn_crash_v1", report["attestations"])

    def test_pwn_runtime_snapshot_capability_missing_fails_closed(self):
        def runner(argv, **kwargs):
            del kwargs
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    capability_payload(
                        excluded_attestations=frozenset(
                            {"pwn_runtime_snapshot_v1"}
                        )
                    )
                ).encode(),
                b"",
            )

        report = inspect_pinned_capabilities(DIGEST, runner=runner)
        self.assertFalse(report["ok"])
        self.assertEqual(
            report["missing"],
            ["pwn_runtime_snapshot_v1"],
        )
        self.assertNotIn(
            "pwn_runtime_snapshot_v1",
            report["attestations"],
        )

    def test_pwn_exploit_effect_capability_missing_fails_closed(self):
        def runner(argv, **kwargs):
            del kwargs
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    capability_payload(
                        excluded_attestations=frozenset(
                            {"pwn_exploit_effect_v1"}
                        )
                    )
                ).encode(),
                b"",
            )

        report = inspect_pinned_capabilities(DIGEST, runner=runner)
        self.assertFalse(report["ok"])
        self.assertEqual(
            report["missing"],
            ["pwn_exploit_effect_v1"],
        )
        self.assertNotIn(
            "pwn_exploit_effect_v1",
            report["attestations"],
        )

    def test_managed_fingerprint_or_version_mismatch_fails_closed(self):
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
        pwn_crash = next(
            item
            for item in records
            if item["name"] == "pwn_crash_v1"
        )
        pwn_crash["attestation"]["sha256"] = "f" * 64
        runtime_snapshot = next(
            item
            for item in records
            if item["name"] == "pwn_runtime_snapshot_v1"
        )
        runtime_snapshot["attestation"]["contract_id"] = (
            "ctfos.pwn.runtime_snapshot.stale"
        )
        exploit_effect = next(
            item
            for item in records
            if item["name"] == "pwn_exploit_effect_v1"
        )
        exploit_effect["attestation"]["path"] = (
            "/opt/ctf-templates/pwn/stale-exploit-effect.py"
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
                "pwn_crash_v1",
                "pwn_exploit_effect_v1",
                "pwn_runtime_snapshot_v1",
                "rev_inventory_v2",
                "rev_safe_output",
                "rev_stdin_exec",
            ],
        )
        self.assertEqual(
            set(report["attestation_errors"]),
            {
                "pwn_crash_v1",
                "pwn_exploit_effect_v1",
                "pwn_runtime_snapshot_v1",
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
