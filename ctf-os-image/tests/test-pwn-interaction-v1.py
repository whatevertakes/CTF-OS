#!/usr/bin/env python3
"""Source-level and six-replay tests for the interaction producer."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
PROJECT_ROOT = REPOSITORY.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ctf_os.contracts.pwn_interaction_v1 import (  # noqa: E402
    PWN_INTERACTION_V1_CONTRACT_FINGERPRINT,
    PWN_INTERACTION_V1_CONTRACT_ID,
    PWN_INTERACTION_V1_CONTRACT_VERSION,
    PWN_INTERACTION_V1_MAX_AGGREGATE_DELAY_MILLISECONDS,
    PWN_INTERACTION_V1_MAX_AGGREGATE_SEND_BYTES,
    PWN_INTERACTION_V1_MAX_CAPTURES,
    PWN_INTERACTION_V1_MAX_DELAY_MILLISECONDS,
    PWN_INTERACTION_V1_MAX_DOCUMENT_BYTES,
    PWN_INTERACTION_V1_MAX_SEND_BYTES,
    PWN_INTERACTION_V1_MAX_STEP_READ_BYTES,
    PWN_INTERACTION_V1_MAX_STEPS,
    PWN_INTERACTION_V1_MAX_TIMEOUT_MILLISECONDS,
    PWN_INTERACTION_V1_PROTOCOL,
    PWN_INTERACTION_V1_SCHEMA_VERSION,
    PWN_INTERACTION_V1_SENTINEL_REF,
    parse_pwn_interaction_v1_recipe,
    pwn_interaction_v1_canonical_json_bytes,
)


MODULE_PATH = REPOSITORY / "templates" / "pwn" / "interaction.py"
SPEC = importlib.util.spec_from_file_location(
    "ctfos_pwn_interaction_image_under_test",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
producer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(producer)

SOURCE_MANIFEST_SHA256 = hashlib.sha256(b"manifest").hexdigest()
IMAGE_DIGEST = "sha256:" + "a" * 64
PREISSUE_SHA256 = hashlib.sha256(b"preissue").hexdigest()
READ_OFFSET = 0x5555
SYSTEM_OFFSET = 0x1234


def _literal(value: str, encoding: str = "utf8") -> dict[str, str]:
    return {"encoding": encoding, "value": value}


def _recipe() -> dict[str, object]:
    return {
        "contract": {
            "id": PWN_INTERACTION_V1_CONTRACT_ID,
            "protocol": PWN_INTERACTION_V1_PROTOCOL,
            "version": PWN_INTERACTION_V1_CONTRACT_VERSION,
        },
        "effect": {
            "address_ref": "system_address",
            "control_value": 0,
            "sentinel_ref": PWN_INTERACTION_V1_SENTINEL_REF,
            "success_stream": "stdout_or_stderr",
        },
        "schema_version": PWN_INTERACTION_V1_SCHEMA_VERSION,
        "steps": [
            {
                "id": "capture-stack",
                "max_read_bytes": 4096,
                "name": "stack_leak",
                "op": "capture_hex",
                "prefix": _literal("Environment setup: 0x"),
            },
            {
                "data": _literal("menu> "),
                "id": "expect-menu",
                "max_read_bytes": 4096,
                "op": "expect_exact",
            },
            {
                "id": "send-menu",
                "mode": "line",
                "op": "send",
                "parts": [{"literal": _literal("5")}],
            },
            {
                "id": "scanf-raw-gap",
                "milliseconds": 100,
                "op": "delay",
            },
            {
                "id": "derive-stack-target",
                "left": {"ref": "stack_leak"},
                "name": "stack_target",
                "op": "derive_u64",
                "operator": "add",
                "right": {"value": 0x78},
            },
            {
                "id": "pack-stack-target",
                "name": "stack_target_bytes",
                "op": "pack_u64",
                "value": {"ref": "stack_target"},
            },
            {
                "id": "send-stack-target",
                "mode": "raw",
                "op": "send",
                "parts": [{"ref": "stack_target_bytes"}],
            },
            {
                "id": "capture-read-address",
                "max_read_bytes": 64,
                "name": "read_address",
                "op": "capture_u64_line",
            },
            {
                "id": "derive-libc-base",
                "left": {"ref": "read_address"},
                "name": "libc_base",
                "op": "derive_u64",
                "operator": "sub",
                "right": {"value": READ_OFFSET},
            },
            {
                "comparison": "aligned",
                "id": "assert-libc-page",
                "left": {"ref": "libc_base"},
                "op": "assert_u64",
                "right": {"value": 0x1000},
            },
            {
                "id": "derive-system",
                "left": {"ref": "libc_base"},
                "name": "system_address",
                "op": "derive_u64",
                "operator": "add",
                "right": {"value": SYSTEM_OFFSET},
            },
            {
                "id": "pack-system",
                "name": "system_bytes",
                "op": "pack_u64",
                "value": {"ref": "system_address"},
            },
            {
                "id": "send-system",
                "mode": "raw",
                "op": "send",
                "parts": [{"ref": "system_bytes"}],
            },
            {
                "id": "send-sentinel-command",
                "mode": "line",
                "op": "send",
                "parts": [{"ref": PWN_INTERACTION_V1_SENTINEL_REF}],
            },
            {"id": "close-input", "op": "shutdown_stdin"},
        ],
        "timeout_milliseconds": 10_000,
    }


class PwnInteractionProducerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="ctfos-pwn-interaction-"
        )
        self.root = Path(self.temporary.name)
        self.challenge = self.root / "challenge"
        self.challenge.mkdir()
        self.binary = self.challenge / "target"
        self._compile_fixture()
        self.original_challenge_root = producer.CHALLENGE_ROOT
        self.original_work_root = producer.WORK_ROOT
        self.original_sentinel_path = producer.SENTINEL_PATH_RELATIVE
        producer.CHALLENGE_ROOT = self.challenge

    def tearDown(self) -> None:
        producer.CHALLENGE_ROOT = self.original_challenge_root
        producer.WORK_ROOT = self.original_work_root
        producer.SENTINEL_PATH_RELATIVE = self.original_sentinel_path
        self.temporary.cleanup()

    def _compile_fixture(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler is unavailable")
        sentinel = (
            self.root / "sentinel-runtime-path"
        ).as_posix().replace("\\", "\\\\").replace('"', '\\"')
        expected_command = producer.SENTINEL_COMMAND.rstrip(b"\0").decode(
            "ascii"
        ).replace("\\", "\\\\").replace('"', '\\"')
        source = self.root / "target.c"
        source.write_text(
            f"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int read_exact(unsigned char *buffer, size_t size) {{
    size_t used = 0;
    while (used < size) {{
        ssize_t count = read(0, buffer + used, size - used);
        if (count <= 0) return 0;
        used += (size_t)count;
    }}
    return 1;
}}

int main(void) {{
    setvbuf(stdout, NULL, _IONBF, 0);
    uint64_t anchor = (uint64_t)(uintptr_t)&anchor;
    const uint64_t base = 0x00007f1234500000ULL;
    const uint64_t read_address = base + {READ_OFFSET}ULL;
    const uint64_t system_address = base + {SYSTEM_OFFSET}ULL;
    char menu[16] = {{0}};
    unsigned char raw[8];
    char command[256] = {{0}};
    printf("Environment setup: 0x%llx\\nmenu> ",
           (unsigned long long)anchor);
    if (fgets(menu, sizeof(menu), stdin) == NULL ||
        strcmp(menu, "5\\n") != 0) return 0;
    if (!read_exact(raw, sizeof(raw))) return 0;
    uint64_t stack_target = 0;
    memcpy(&stack_target, raw, sizeof(stack_target));
    if (stack_target != anchor + 0x78ULL) return 0;
    if (write(1, &read_address, 6) != 6 ||
        write(1, "\\n", 1) != 1) return 0;
    if (!read_exact(raw, sizeof(raw))) return 0;
    uint64_t effect = 0;
    memcpy(&effect, raw, sizeof(effect));
    if (fgets(command, sizeof(command), stdin) == NULL) return 0;
    command[strcspn(command, "\\n")] = 0;
    if (effect == system_address &&
        strcmp(command, "{expected_command}") == 0) {{
        FILE *sentinel = fopen("{sentinel}", "rb");
        if (sentinel == NULL) return 0;
        unsigned char buffer[256];
        size_t count = fread(buffer, 1, sizeof(buffer), sentinel);
        fclose(sentinel);
        if (count && write(1, buffer, count) != (ssize_t)count) return 0;
    }}
    return 0;
}}
""",
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                compiler,
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-o",
                str(self.binary),
                str(source),
            ],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            self.fail(result.stderr.decode(errors="replace"))
        self.sentinel_runtime_path = Path(
            self.root / "sentinel-runtime-path"
        )

    def _invoke(
        self,
        phase: str,
        ordinal: int,
        *,
        recipe_document: dict[str, object] | None = None,
        expected_recipe_sha256: str | None = None,
    ) -> tuple[dict[str, object], Path, bytes]:
        work = self.root / f"work-{phase}-{ordinal}-{secrets_token()}"
        work.mkdir()
        producer.WORK_ROOT = work
        producer.SENTINEL_PATH_RELATIVE = self.sentinel_runtime_path
        recipe_bytes = pwn_interaction_v1_canonical_json_bytes(
            recipe_document or _recipe()
        )
        parse_pwn_interaction_v1_recipe(recipe_bytes)
        recipe_path = work / "recipe.json"
        recipe_path.write_bytes(recipe_bytes)
        source = self.binary.read_bytes()
        namespace = producer._parse_args(
            [
                "--binary",
                str(self.binary),
                "--recipe",
                str(recipe_path),
                "--phase",
                phase,
                "--ordinal",
                str(ordinal),
                "--source-manifest-sha256",
                SOURCE_MANIFEST_SHA256,
                "--source-sha256",
                hashlib.sha256(source).hexdigest(),
                "--source-size-bytes",
                str(len(source)),
                "--recipe-sha256",
                expected_recipe_sha256
                or hashlib.sha256(recipe_bytes).hexdigest(),
                "--recipe-size-bytes",
                str(len(recipe_bytes)),
                "--image-digest",
                IMAGE_DIGEST,
                "--configuration-epoch",
                "7",
                "--preissue-sha256",
                PREISSUE_SHA256,
            ]
        )
        try:
            encoded = producer._run(namespace)
        except producer.ProducerError as error:
            encoded = producer._failure_document(namespace, error.reason_code)
        finally:
            self.sentinel_runtime_path.unlink(missing_ok=True)
        self.assertEqual(encoded, producer._canonical_json_bytes(json.loads(encoded)))
        return json.loads(encoded), work, recipe_bytes

    def test_three_attack_and_three_matched_controls(self) -> None:
        records = []
        for phase in ("attack", "control"):
            for ordinal in range(1, 4):
                record, work, recipe = self._invoke(phase, ordinal)
                records.append(record)
                self.assertEqual(record["binding"]["network"], "none")
                self.assertEqual(
                    record["binding"]["recipe_sha256"],
                    hashlib.sha256(recipe).hexdigest(),
                )
                self.assertEqual(
                    record["contract"]["recipe_contract_fingerprint"],
                    PWN_INTERACTION_V1_CONTRACT_FINGERPRINT,
                )
                self.assertNotIn(
                    producer.SENTINEL_PREFIX,
                    json.dumps(record).encode("ascii"),
                )
                observation = record["observation"]
                self.assertEqual(observation["target_exit_code"], 0)
                self.assertIsNone(observation["target_signal"])
                self.assertTrue(observation["process_group_cleaned"])
                for key in (
                    "stdout",
                    "stderr",
                    "transcript",
                    "derivation_dag",
                ):
                    path = work / observation[f"{key}_path"]
                    payload = path.read_bytes()
                    self.assertEqual(
                        hashlib.sha256(payload).hexdigest(),
                        observation[f"{key}_sha256"],
                    )
                    self.assertEqual(
                        stat.S_IMODE(path.stat().st_mode) & 0o222,
                        0,
                    )
                dag = json.loads(
                    (work / observation["derivation_dag_path"]).read_bytes()
                )
                effect_node = next(
                    node
                    for node in dag["nodes"]
                    if node["name"] == "system_address"
                )
                self.assertIs(
                    effect_node["control_substituted"],
                    phase == "control",
                )
        attacks = records[:3]
        controls = records[3:]
        self.assertTrue(
            all(record["status"] == "effect_observed" for record in attacks)
        )
        self.assertTrue(
            all(record["status"] == "effect_absent" for record in controls)
        )
        self.assertTrue(
            all(
                record["observation"]["sentinel_occurrences"] == 1
                for record in attacks
            )
        )
        self.assertTrue(
            all(
                record["observation"]["sentinel_occurrences"] == 0
                for record in controls
            )
        )
        self.assertEqual(
            len(
                {
                    record["observation"]["sentinel_sha256"]
                    for record in records
                }
            ),
            6,
        )
        self.assertTrue(
            all(
                not record["observation"]["control_substitution_applied"]
                for record in attacks
            )
        )
        self.assertTrue(
            all(
                record["observation"]["control_substitution_applied"]
                for record in controls
            )
        )

    def test_hash_substitution_checked_arithmetic_and_no_secret_in_summary(
        self,
    ) -> None:
        bad_hash = hashlib.sha256(b"different").hexdigest()
        record, _work, recipe = self._invoke(
            "attack",
            1,
            expected_recipe_sha256=bad_hash,
        )
        self.assertEqual(record["status"], "unverifiable")
        self.assertEqual(record["reason_code"], "artifact_hash_mismatch")

        overflow = _recipe()
        overflow["steps"][4]["right"] = {
            "value": (1 << 64) - 1
        }
        record, _work, recipe = self._invoke(
            "attack",
            2,
            recipe_document=overflow,
        )
        self.assertEqual(record["status"], "unverifiable")
        self.assertEqual(record["reason_code"], "checked_add_overflow")
        self.assertNotIn(
            producer.SENTINEL_PREFIX,
            json.dumps(record).encode("ascii"),
        )
        self.assertNotIn(
            producer.SENTINEL_PREFIX,
            recipe,
        )

    def test_contract_limits_and_closed_surface_do_not_drift(self) -> None:
        self.assertEqual(
            producer.CONTRACT_FINGERPRINT,
            PWN_INTERACTION_V1_CONTRACT_FINGERPRINT,
        )
        self.assertEqual(producer.MAX_RECIPE_BYTES, PWN_INTERACTION_V1_MAX_DOCUMENT_BYTES)
        self.assertEqual(producer.MAX_STEPS, PWN_INTERACTION_V1_MAX_STEPS)
        self.assertEqual(producer.MAX_CAPTURES, PWN_INTERACTION_V1_MAX_CAPTURES)
        self.assertEqual(producer.MAX_SEND_BYTES, PWN_INTERACTION_V1_MAX_SEND_BYTES)
        self.assertEqual(
            producer.MAX_AGGREGATE_SEND_BYTES,
            PWN_INTERACTION_V1_MAX_AGGREGATE_SEND_BYTES,
        )
        self.assertEqual(
            producer.MAX_STEP_READ_BYTES,
            PWN_INTERACTION_V1_MAX_STEP_READ_BYTES,
        )
        self.assertEqual(
            producer.MAX_TIMEOUT_MILLISECONDS,
            PWN_INTERACTION_V1_MAX_TIMEOUT_MILLISECONDS,
        )
        self.assertEqual(
            producer.MAX_DELAY_MILLISECONDS,
            PWN_INTERACTION_V1_MAX_DELAY_MILLISECONDS,
        )
        self.assertEqual(
            producer.MAX_AGGREGATE_DELAY_MILLISECONDS,
            PWN_INTERACTION_V1_MAX_AGGREGATE_DELAY_MILLISECONDS,
        )
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("shell=True", source)
        self.assertNotIn("--network", source)
        self.assertNotIn("--argv", source)
        self.assertNotIn("submit", source.casefold())


def secrets_token() -> str:
    return os.urandom(4).hex()


if __name__ == "__main__":
    unittest.main()
