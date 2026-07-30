from __future__ import annotations

import importlib
import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

from ctf_os.codex import Role
from ctf_os.codex.contracts import role_output_schema


REPOSITORY = Path(__file__).resolve().parent.parent
MATRIX_PATH = (
    REPOSITORY
    / "docs"
    / "managed-category-hotpath-evidence-v1.json"
)
MANAGED_SOURCE = REPOSITORY / "ctf_os" / "managed.py"


def _matrix() -> dict[str, object]:
    value = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise AssertionError("managed category evidence matrix is not an object")
    return value


class ManagedCategoryHotPathReleaseTests(unittest.TestCase):
    def test_matrix_is_closed_and_points_to_runnable_tests(self) -> None:
        matrix = _matrix()
        self.assertEqual(
            set(matrix),
            {
                "schema_version",
                "protocol",
                "release_image_digest",
                "managed_contract",
                "categories",
            },
        )
        self.assertEqual(matrix["schema_version"], 1)
        self.assertEqual(
            matrix["protocol"],
            "managed_category_hotpath_evidence_v1",
        )
        self.assertRegex(
            matrix["release_image_digest"],
            r"^sha256:[0-9a-f]{64}$",
        )
        contract = matrix["managed_contract"]
        self.assertEqual(
            contract,
            {
                "captain_route": "attack",
                "action_source_role": "builder",
                "contract_version": 2,
                "wave_kind": "attack",
                "engine_executor": "managed_typed_gate_v1",
                "artifact_binding": [
                    "artifact_id",
                    "locator",
                    "sha256",
                    "size_bytes",
                    "workspace_publish_id",
                ],
                "network_default": "none",
                "automatic_submission_authorized": False,
            },
        )
        categories = matrix["categories"]
        self.assertIs(type(categories), list)
        self.assertEqual(
            {item["category"] for item in categories},
            {"crypto", "forensics", "misc"},
        )
        expected_keys = {
            "category",
            "action_kind",
            "artifact_path_fields",
            "public_oracle",
            "expected_oracle_runs",
            "state_authority",
            "unit_test",
            "hostile_test",
            "docker_script",
        }
        for item in categories:
            self.assertEqual(set(item), expected_keys)
            self.assertGreaterEqual(item["expected_oracle_runs"], 2)
            for key in ("unit_test", "hostile_test"):
                module_name, class_name, method_name = item[key].rsplit(
                    ".",
                    2,
                )
                module = importlib.import_module(module_name)
                case = getattr(module, class_name)
                self.assertTrue(callable(getattr(case, method_name)))
            script = REPOSITORY / item["docker_script"]
            self.assertTrue(script.is_file())

    def test_builder_schema_dispatch_and_hash_binding_match_matrix(
        self,
    ) -> None:
        matrix = _matrix()
        variants = role_output_schema(
            Role.BUILDER,
            contract_version=2,
        )["properties"]["actions"]["items"]["anyOf"]
        schema_kinds = {
            variant["properties"]["kind"]["enum"][0]
            for variant in variants
        }
        source = MANAGED_SOURCE.read_text(encoding="utf-8")
        self.assertIn("canonical_workspace_hash(", source)
        for field in (
            '"artifact_id": artifact.id',
            '"locator": locator',
            '"sha256": artifact.sha256',
            '"size_bytes": artifact.size',
            '"workspace_publish_id": publish.id',
        ):
            self.assertIn(field, source)
        expected_dispatch = {
            "crypto": "self.engine.prove_crypto_metamorphic_candidate(",
            "forensics": "self.engine.prove_forensic_assertion(",
            "misc": "self.engine.evaluate_misc_transform_candidate(",
        }
        for item in matrix["categories"]:
            self.assertIn(item["action_kind"], schema_kinds)
            self.assertIn(
                expected_dispatch[item["category"]],
                source,
            )
            for field in item["artifact_path_fields"]:
                self.assertIn(f'"{field}"', source)
        self.assertNotIn("record_manual_submission(", source)

    def test_docker_evidence_is_public_pinned_networkless_and_no_submit(
        self,
    ) -> None:
        matrix = _matrix()
        digest = matrix["release_image_digest"]
        scripts = {
            REPOSITORY / item["docker_script"]
            for item in matrix["categories"]
        }
        self.assertEqual(
            scripts,
            {
                REPOSITORY
                / "scripts"
                / "check-crypto-misc-docker-hotpaths.py",
                REPOSITORY
                / "scripts"
                / "check-forensic-assertion-hotpath-docker.py",
            },
        )
        for script in scripts:
            source = script.read_text(encoding="utf-8")
            self.assertIn(digest.removeprefix("sha256:"), source)
            self.assertNotIn("FakeSandbox", source)
            self.assertNotIn("submit_candidate", source)
            self.assertNotIn("record_manual_submission", source)
            self.assertTrue(
                "network_default=\"none\"" in source
                or "NetworkPolicy.deny_all()" in source
            )
            self.assertIsNone(
                re.search(r"image_digest\s*=\s*[\"']ctfos:", source)
            )

    @unittest.skipUnless(
        os.environ.get("CTFOS_RUN_MANAGED_CATEGORY_DOCKER") == "1",
        "set CTFOS_RUN_MANAGED_CATEGORY_DOCKER=1 for real Docker gates",
    )
    def test_real_pinned_docker_evidence_matrix(self) -> None:
        matrix = _matrix()
        summaries: dict[str, dict[str, object]] = {}
        for script_name in dict.fromkeys(
            item["docker_script"] for item in matrix["categories"]
        ):
            completed = subprocess.run(
                (
                    sys.executable,
                    str(REPOSITORY / script_name),
                    "--image-digest",
                    matrix["release_image_digest"],
                ),
                cwd=REPOSITORY,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                text=True,
                timeout=1200,
            )
            if completed.returncode != 0:
                self.fail(
                    f"{script_name} failed:\n"
                    + completed.stdout[-4096:]
                    + completed.stderr[-4096:]
                )
            summaries[script_name] = json.loads(
                completed.stdout.splitlines()[-1]
            )
        crypto_misc = summaries[
            "scripts/check-crypto-misc-docker-hotpaths.py"
        ]
        self.assertTrue(crypto_misc["ok"])
        self.assertEqual(crypto_misc["crypto"]["python"]["runs"], 6)
        self.assertEqual(crypto_misc["crypto"]["sage"]["runs"], 6)
        self.assertEqual(crypto_misc["misc"]["runs"], 4)
        self.assertEqual(
            crypto_misc["crypto"]["python"]["submissions"],
            0,
        )
        self.assertEqual(
            crypto_misc["crypto"]["sage"]["submissions"],
            0,
        )
        self.assertEqual(crypto_misc["misc"]["submissions"], 0)
        forensic = summaries[
            "scripts/check-forensic-assertion-hotpath-docker.py"
        ]
        self.assertTrue(forensic["ok"])
        self.assertEqual(forensic["network"], "none")
        self.assertFalse(forensic["control"]["confirmed"])
        self.assertEqual(forensic["submissions"], 0)


if __name__ == "__main__":
    unittest.main()
