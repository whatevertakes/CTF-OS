from __future__ import annotations

import copy
import json
import unittest

from ctf_os.contracts.pwn_interaction_v1 import (
    PWN_INTERACTION_V1_CONTRACT_FINGERPRINT,
    PWN_INTERACTION_V1_CONTRACT_ID,
    PWN_INTERACTION_V1_CONTRACT_VERSION,
    PWN_INTERACTION_V1_MAX_AGGREGATE_DELAY_MILLISECONDS,
    PWN_INTERACTION_V1_MAX_AGGREGATE_SEND_BYTES,
    PWN_INTERACTION_V1_MAX_CAPTURES,
    PWN_INTERACTION_V1_MAX_DELAY_MILLISECONDS,
    PWN_INTERACTION_V1_MAX_SEND_BYTES,
    PWN_INTERACTION_V1_MAX_STEPS,
    PWN_INTERACTION_V1_PROTOCOL,
    PWN_INTERACTION_V1_SCHEMA_VERSION,
    PWN_INTERACTION_V1_SENTINEL_REF,
    PwnInteractionRecipeError,
    parse_pwn_interaction_v1_recipe,
    pwn_interaction_v1_canonical_json_bytes,
    pwn_interaction_v1_contract_descriptor,
)


def _literal(value: str, *, encoding: str = "utf8") -> dict[str, str]:
    return {"encoding": encoding, "value": value}


def _zone_style_recipe() -> dict[str, object]:
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
                "id": "derive-stack-target",
                "left": {"ref": "stack_leak"},
                "name": "stack_target",
                "op": "derive_u64",
                "operator": "add",
                "right": {"value": 0x78},
            },
            {
                "id": "menu-create",
                "mode": "line",
                "op": "send",
                "parts": [{"literal": _literal("1")}],
            },
            {
                "id": "menu-prompt",
                "max_read_bytes": 4096,
                "op": "expect_exact",
                "data": _literal("> "),
            },
            {
                "id": "raw-payload",
                "data": _literal("4141414141414141", encoding="hex"),
                "name": "first_payload",
                "op": "literal",
            },
            {
                "id": "send-raw",
                "mode": "raw",
                "op": "send",
                "parts": [{"ref": "first_payload"}],
            },
            {
                "id": "scanf-gap",
                "milliseconds": 100,
                "op": "delay",
            },
            {
                "id": "capture-libc",
                "max_read_bytes": 4096,
                "name": "read_address",
                "op": "capture_u64_line",
            },
            {
                "id": "derive-base",
                "left": {"ref": "read_address"},
                "name": "libc_base",
                "op": "derive_u64",
                "operator": "sub",
                "right": {"value": 0xF7250},
            },
            {
                "comparison": "aligned",
                "id": "base-aligned",
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
                "right": {"value": 0x45390},
            },
            {
                "id": "pack-system",
                "name": "system_packed",
                "op": "pack_u64",
                "value": {"ref": "system_address"},
            },
            {
                "id": "send-system",
                "mode": "raw",
                "op": "send",
                "parts": [{"ref": "system_packed"}],
            },
            {
                "id": "send-command",
                "mode": "raw",
                "op": "send",
                "parts": [{"ref": PWN_INTERACTION_V1_SENTINEL_REF}],
            },
            {"id": "close-input", "op": "shutdown_stdin"},
        ],
        "timeout_milliseconds": 30_000,
    }


def _payload(document: object) -> bytes:
    return pwn_interaction_v1_canonical_json_bytes(document)


class PwnInteractionContractTests(unittest.TestCase):
    def test_zone_mixed_stdio_recipe_is_typed_and_bounded(self) -> None:
        parsed = parse_pwn_interaction_v1_recipe(
            _payload(_zone_style_recipe())
        )
        self.assertEqual(parsed.step_count, 15)
        self.assertEqual(parsed.capture_count, 2)
        self.assertEqual(parsed.aggregate_delay_milliseconds, 100)
        self.assertEqual(parsed.effect_address_ref, "system_address")
        self.assertIn("system_address", parsed.effect_payload_refs)
        self.assertEqual(len(parsed.sha256), 64)
        self.assertEqual(parsed.canonical_bytes, _payload(parsed.document))

    def test_contract_descriptor_pins_closed_execution_surface(self) -> None:
        descriptor = pwn_interaction_v1_contract_descriptor()
        self.assertEqual(len(PWN_INTERACTION_V1_CONTRACT_FINGERPRINT), 64)
        self.assertEqual(
            descriptor["phase_authority"],
            "image_producer",
        )
        self.assertEqual(
            descriptor["sentinel_authority"],
            "image_producer",
        )
        self.assertNotIn("shell", descriptor["operations"])
        self.assertNotIn("exec", descriptor["operations"])
        self.assertEqual(
            descriptor["limits"]["steps"],
            PWN_INTERACTION_V1_MAX_STEPS,
        )

    def test_noncanonical_duplicate_unknown_and_post_shutdown_fail(self) -> None:
        document = _zone_style_recipe()
        with self.assertRaisesRegex(
            PwnInteractionRecipeError,
            "noncanonical_json",
        ):
            parse_pwn_interaction_v1_recipe(
                json.dumps(document).encode("ascii")
            )
        duplicate = (
            b'{"contract":{},"contract":{},"effect":{},'
            b'"schema_version":1,"steps":[],"timeout_milliseconds":1}\n'
        )
        with self.assertRaisesRegex(
            PwnInteractionRecipeError,
            "duplicate_json_key",
        ):
            parse_pwn_interaction_v1_recipe(duplicate)

        unknown = copy.deepcopy(document)
        unknown["steps"][0]["command"] = "sh"
        with self.assertRaisesRegex(
            PwnInteractionRecipeError,
            "invalid_schema",
        ):
            parse_pwn_interaction_v1_recipe(_payload(unknown))

        after_close = copy.deepcopy(document)
        after_close["steps"].append(
            {
                "id": "too-late",
                "mode": "line",
                "op": "send",
                "parts": [{"literal": _literal("x")}],
            }
        )
        with self.assertRaisesRegex(
            PwnInteractionRecipeError,
            "step_after_shutdown",
        ):
            parse_pwn_interaction_v1_recipe(_payload(after_close))

    def test_effect_and_sentinel_must_reach_transmitted_bytes(self) -> None:
        no_effect = _zone_style_recipe()
        no_effect["steps"][12]["parts"] = [
            {"literal": _literal("0000000000000000", encoding="hex")}
        ]
        with self.assertRaisesRegex(
            PwnInteractionRecipeError,
            "effect_reference_unused",
        ):
            parse_pwn_interaction_v1_recipe(_payload(no_effect))

        no_sentinel = _zone_style_recipe()
        no_sentinel["steps"][13]["parts"] = [
            {"literal": _literal("id")}
        ]
        with self.assertRaisesRegex(
            PwnInteractionRecipeError,
            "sentinel_reference_unused",
        ):
            parse_pwn_interaction_v1_recipe(_payload(no_sentinel))

        forged = _zone_style_recipe()
        forged["steps"][4]["data"] = _literal(
            "CTFOS_PWN_INTERACTION_V1_" + "0" * 64
        )
        with self.assertRaisesRegex(
            PwnInteractionRecipeError,
            "sentinel_shape_forbidden",
        ):
            parse_pwn_interaction_v1_recipe(_payload(forged))

    def test_forward_mistyped_duplicate_and_reserved_refs_fail(self) -> None:
        forward = _zone_style_recipe()
        forward["steps"][2]["parts"] = [{"ref": "system_packed"}]
        with self.assertRaisesRegex(
            PwnInteractionRecipeError,
            "unknown_or_mistyped_reference",
        ):
            parse_pwn_interaction_v1_recipe(_payload(forward))

        duplicate = _zone_style_recipe()
        duplicate["steps"][8]["name"] = "stack_leak"
        with self.assertRaisesRegex(
            PwnInteractionRecipeError,
            "duplicate_name",
        ):
            parse_pwn_interaction_v1_recipe(_payload(duplicate))

        reserved = _zone_style_recipe()
        reserved["steps"][0]["name"] = PWN_INTERACTION_V1_SENTINEL_REF
        with self.assertRaisesRegex(
            PwnInteractionRecipeError,
            "reserved_name",
        ):
            parse_pwn_interaction_v1_recipe(_payload(reserved))

        mistyped = _zone_style_recipe()
        mistyped["steps"][11]["value"] = {"ref": "first_payload"}
        with self.assertRaisesRegex(
            PwnInteractionRecipeError,
            "unknown_or_mistyped_reference",
        ):
            parse_pwn_interaction_v1_recipe(_payload(mistyped))

    def test_safe_regex_is_anchored_group_free_and_bounded(self) -> None:
        document = _zone_style_recipe()
        document["steps"].insert(
            3,
            {
                "id": "safe-menu",
                "max_read_bytes": 4096,
                "op": "expect_safe_regex",
                "pattern": "^[A-Za-z0-9 :>]{1,128}$",
            },
        )
        parsed = parse_pwn_interaction_v1_recipe(_payload(document))
        self.assertEqual(parsed.step_count, 16)

        for pattern in (
            "unanchored",
            "^(A+)+$",
            "^(a|aa){1,5}$",
            "^A*$",
            "^A{1,999}$",
            "^CTFOS_PWN_INTERACTION_V1_[0-9a-f]{64}$",
        ):
            hostile = copy.deepcopy(document)
            hostile["steps"][3]["pattern"] = pattern
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(
                    PwnInteractionRecipeError,
                    "unsafe_regex",
                ):
                    parse_pwn_interaction_v1_recipe(_payload(hostile))

    def test_exact_resource_limits_fail_closed(self) -> None:
        too_many_steps = _zone_style_recipe()
        filler_count = (
            PWN_INTERACTION_V1_MAX_STEPS
            - len(too_many_steps["steps"])
            + 1
        )
        too_many_steps["steps"][-1:-1] = [
            {
                "id": f"delay-{index}",
                "milliseconds": 0,
                "op": "delay",
            }
            for index in range(filler_count)
        ]
        with self.assertRaisesRegex(
            PwnInteractionRecipeError,
            "steps must be",
        ):
            parse_pwn_interaction_v1_recipe(_payload(too_many_steps))

        too_many_captures = _zone_style_recipe()
        too_many_captures["steps"][1:1] = [
            {
                "id": f"capture-{index}",
                "max_read_bytes": 8,
                "name": f"capture_{index}",
                "op": "capture_u64_line",
            }
            for index in range(PWN_INTERACTION_V1_MAX_CAPTURES)
        ]
        with self.assertRaisesRegex(
            PwnInteractionRecipeError,
            "capture_limit_exceeded",
        ):
            parse_pwn_interaction_v1_recipe(_payload(too_many_captures))

        long_send = _zone_style_recipe()
        long_send["steps"][2]["parts"] = [
            {
                "literal": _literal(
                    "41" * PWN_INTERACTION_V1_MAX_SEND_BYTES,
                    encoding="hex",
                )
            }
        ]
        with self.assertRaisesRegex(
            PwnInteractionRecipeError,
            "send_limit_exceeded|value_too_large",
        ):
            parse_pwn_interaction_v1_recipe(_payload(long_send))

        delay = _zone_style_recipe()
        delay["steps"][-1:-1] = [
            {
                "id": f"bounded-delay-{index}",
                "milliseconds": PWN_INTERACTION_V1_MAX_DELAY_MILLISECONDS,
                "op": "delay",
            }
            for index in range(
                PWN_INTERACTION_V1_MAX_AGGREGATE_DELAY_MILLISECONDS
                // PWN_INTERACTION_V1_MAX_DELAY_MILLISECONDS
            )
        ]
        with self.assertRaisesRegex(
            PwnInteractionRecipeError,
            "delay_limit_exceeded",
        ):
            parse_pwn_interaction_v1_recipe(_payload(delay))

    def test_aggregate_send_bound_counts_references_and_line_newline(self) -> None:
        document = _zone_style_recipe()
        document["steps"][4]["data"] = _literal(
            "41" * PWN_INTERACTION_V1_MAX_SEND_BYTES,
            encoding="hex",
        )
        repeated = (
            PWN_INTERACTION_V1_MAX_AGGREGATE_SEND_BYTES
            // PWN_INTERACTION_V1_MAX_SEND_BYTES
        )
        document["steps"][5:5] = [
            {
                "id": f"bulk-send-{index}",
                "mode": "raw",
                "op": "send",
                "parts": [{"ref": "first_payload"}],
            }
            for index in range(repeated)
        ]
        with self.assertRaisesRegex(
            PwnInteractionRecipeError,
            "send_limit_exceeded",
        ):
            parse_pwn_interaction_v1_recipe(_payload(document))


if __name__ == "__main__":
    unittest.main()
