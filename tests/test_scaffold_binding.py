from __future__ import annotations

import copy
import hashlib
import unittest

from ctf_os.benchmark import CTF_OS_SYSTEM, THIN_SCAFFOLD
from ctf_os.scaffold_binding import (
    ScaffoldBindingError,
    build_scaffold_launch_binding,
    managed_command_contract_sha256,
    parse_scaffold_launch_record,
    solve_mode_arm,
    validate_scaffold_launch_record,
)


SHA_A = hashlib.sha256(b"a").hexdigest()
SHA_B = hashlib.sha256(b"b").hexdigest()
SHA_C = hashlib.sha256(b"c").hexdigest()
SHA_D = hashlib.sha256(b"d").hexdigest()
SHA_E = hashlib.sha256(b"e").hexdigest()
IMAGE = "sha256:" + hashlib.sha256(b"image").hexdigest()


def prepared_metadata(arm: str = THIN_SCAFFOLD) -> dict[str, object]:
    return {
        "evaluation_prepared": True,
        "evaluation_system": arm,
        "evaluation_benchmark_id": "blind-release",
        "evaluation_case_id": "blind-pwn",
        "evaluation_session_id": "blind-pwn-thin-1",
        "evaluation_manifest_sha256": SHA_A,
        "source_manifest_sha256": SHA_B,
        "evaluation_model": "gpt-5.6-sol",
        "evaluation_image_sha256": IMAGE.removeprefix("sha256:"),
        "evaluation_tool_manifest_sha256": SHA_C,
        "evaluation_model_config_sha256": SHA_D,
    }


class ScaffoldBindingTests(unittest.TestCase):
    def test_managed_contract_binds_policy_model_and_effort(self) -> None:
        base = managed_command_contract_sha256(
            model_id="frontier-model",
            captain_effort="ultra",
            worker_effort="max",
            thread_continuity_policy="fresh",
        )
        self.assertEqual(
            base,
            managed_command_contract_sha256(
                model_id="frontier-model",
                captain_effort="ultra",
                worker_effort="max",
                thread_continuity_policy="fresh",
            ),
        )
        for changed in (
            {
                "model_id": "other-model",
                "captain_effort": "ultra",
                "worker_effort": "max",
                "thread_continuity_policy": "fresh",
            },
            {
                "model_id": "frontier-model",
                "captain_effort": "max",
                "worker_effort": "max",
                "thread_continuity_policy": "fresh",
            },
            {
                "model_id": "frontier-model",
                "captain_effort": "ultra",
                "worker_effort": "max",
                "thread_continuity_policy": "captain_lane",
            },
        ):
            self.assertNotEqual(
                base,
                managed_command_contract_sha256(**changed),
            )
        with self.assertRaisesRegex(
            ScaffoldBindingError,
            "continuity",
        ):
            managed_command_contract_sha256(
                model_id="frontier-model",
                captain_effort="ultra",
                worker_effort="max",
                thread_continuity_policy="unbound",
            )

    def test_prepared_arm_requires_the_exact_solve_scaffold(self) -> None:
        thin = prepared_metadata()
        self.assertEqual(solve_mode_arm(thin, "thin"), THIN_SCAFFOLD)
        with self.assertRaisesRegex(
            ScaffoldBindingError,
            "does not match",
        ):
            solve_mode_arm(thin, "managed")
        with self.assertRaisesRegex(
            ScaffoldBindingError,
            "unbound assisted",
        ):
            solve_mode_arm(thin, "assisted")

        full = prepared_metadata(CTF_OS_SYSTEM)
        full["evaluation_session_id"] = "blind-pwn-full-1"
        self.assertEqual(solve_mode_arm(full, "managed"), CTF_OS_SYSTEM)
        with self.assertRaises(ScaffoldBindingError):
            solve_mode_arm(full, "thin")

    def test_non_evaluation_sessions_keep_existing_modes(self) -> None:
        self.assertIsNone(solve_mode_arm({}, "assisted"))
        self.assertEqual(solve_mode_arm({}, "managed"), CTF_OS_SYSTEM)
        self.assertEqual(solve_mode_arm({}, "thin"), THIN_SCAFFOLD)

    def test_launch_record_binds_all_frozen_execution_inputs(self) -> None:
        metadata = prepared_metadata()
        binding = build_scaffold_launch_binding(
            metadata=metadata,
            configuration_epoch=7,
            contest_id="contest-a",
            category="pwn",
            challenge_id="challenge-a",
            arm=THIN_SCAFFOLD,
            model_id="gpt-5.6-sol",
            runtime_image_digest=IMAGE,
            command_contract_sha256=SHA_E,
        )
        record = binding.to_record(
            launched_at="2026-07-31T00:00:00.000000Z"
        )

        parsed, launched_at = parse_scaffold_launch_record(record)
        self.assertEqual(parsed, binding)
        self.assertEqual(launched_at, "2026-07-31T00:00:00.000000Z")
        self.assertEqual(
            validate_scaffold_launch_record(
                metadata=metadata,
                configuration_epoch=7,
                contest_id="contest-a",
                category="pwn",
                challenge_id="challenge-a",
                value=record,
                expected_arm=THIN_SCAFFOLD,
                expected_command_contract_sha256=SHA_E,
            ),
            binding,
        )

    def test_launch_record_rejects_tamper_and_cross_session_reuse(self) -> None:
        metadata = prepared_metadata()
        record = build_scaffold_launch_binding(
            metadata=metadata,
            configuration_epoch=7,
            contest_id="contest-a",
            category="pwn",
            challenge_id="challenge-a",
            arm=THIN_SCAFFOLD,
            model_id="gpt-5.6-sol",
            runtime_image_digest=IMAGE,
            command_contract_sha256=SHA_E,
        ).to_record(launched_at="2026-07-31T00:00:00Z")
        for field, replacement in (
            ("arm", CTF_OS_SYSTEM),
            ("configuration_epoch", 8),
            ("model_id", "other-model"),
            ("runtime_image_digest", "sha256:" + SHA_A),
            ("command_contract_sha256", SHA_A),
            ("binding_sha256", SHA_A),
            ("launched_at", "2026-08-01T00:00:00Z"),
            ("record_sha256", SHA_A),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(record)
                changed[field] = replacement
                with self.assertRaises(ScaffoldBindingError):
                    parse_scaffold_launch_record(changed)

        other = dict(metadata)
        other["evaluation_session_id"] = "blind-pwn-thin-2"
        with self.assertRaisesRegex(
            ScaffoldBindingError,
            "another session",
        ):
            validate_scaffold_launch_record(
                metadata=other,
                configuration_epoch=7,
                contest_id="contest-a",
                category="pwn",
                challenge_id="challenge-a",
                value=record,
                expected_arm=THIN_SCAFFOLD,
                expected_command_contract_sha256=SHA_E,
            )
        with self.assertRaisesRegex(
            ScaffoldBindingError,
            "another session",
        ):
            validate_scaffold_launch_record(
                metadata=metadata,
                configuration_epoch=7,
                contest_id="contest-a",
                category="pwn",
                challenge_id="challenge-b",
                value=record,
                expected_arm=THIN_SCAFFOLD,
                expected_command_contract_sha256=SHA_E,
            )

    def test_launch_builder_refuses_model_image_and_arm_relabeling(self) -> None:
        metadata = prepared_metadata()
        common = {
            "metadata": metadata,
            "configuration_epoch": 3,
            "contest_id": "contest-a",
            "category": "pwn",
            "challenge_id": "challenge-a",
            "arm": THIN_SCAFFOLD,
            "model_id": "gpt-5.6-sol",
            "runtime_image_digest": IMAGE,
            "command_contract_sha256": SHA_E,
        }
        for field, replacement in (
            ("arm", CTF_OS_SYSTEM),
            ("model_id", "other-model"),
            ("runtime_image_digest", "sha256:" + SHA_A),
        ):
            with self.subTest(field=field):
                changed = dict(common)
                changed[field] = replacement
                with self.assertRaises(ScaffoldBindingError):
                    build_scaffold_launch_binding(**changed)


if __name__ == "__main__":
    unittest.main()
