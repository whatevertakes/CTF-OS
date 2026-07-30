from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError

from ctf_os.contracts.pwn_runtime_snapshot_v1 import (
    PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_FINGERPRINT,
    PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_ID,
    PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_VERSION,
    PWN_RUNTIME_SNAPSHOT_V1_FAILURE_REASONS,
    PWN_RUNTIME_SNAPSHOT_V1_INCONCLUSIVE_REASONS,
    PWN_RUNTIME_SNAPSHOT_V1_MAX_DOCUMENT_BYTES,
    PWN_RUNTIME_SNAPSHOT_V1_MAX_MAPS_BASE64_BYTES,
    PWN_RUNTIME_SNAPSHOT_V1_MAX_MAPS_BYTES,
    PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES,
    PWN_RUNTIME_SNAPSHOT_V1_REGISTER_SET_BYTES,
    PWN_RUNTIME_SNAPSHOT_V1_SCHEMA_VERSION,
    PWN_RUNTIME_SNAPSHOT_V1_PRODUCER_ERROR_REASONS,
    PWN_RUNTIME_SNAPSHOT_V1_SUCCESS_REASON,
    PwnRuntimeSnapshotV1ContractError,
    PwnRuntimeSnapshotV1Maps,
    PwnRuntimeSnapshotV1Registers,
    PwnRuntimeSnapshotV1Status,
    build_pwn_runtime_snapshot_v1_failure,
    build_pwn_runtime_snapshot_v1_result,
    parse_pwn_runtime_snapshot_v1_result,
    pwn_runtime_snapshot_v1_canonical_json_bytes,
    pwn_runtime_snapshot_v1_contract_descriptor,
    validate_pwn_runtime_snapshot_v1_result_mapping,
)


MANIFEST_SHA256 = "a" * 64
SOURCE_SHA256 = "b" * 64
SOURCE_SIZE = 8192
PAYLOAD_SHA256 = "c" * 64
PAYLOAD_SIZE = 96
PARENT_RECIPE_SHA256 = "d" * 64
PARENT_EVALUATION_SHA256 = "e" * 64
EXPECTED_SIGNAL = 11
SNAPSHOT_RECIPE_SHA256 = "f" * 64

# Updated only when the append-only v1 descriptor intentionally changes.
EXPECTED_CONTRACT_FINGERPRINT = (
    "0b008ed31cd7daf240bf2d96f76c5ce1ac3b340bb5425bfd56fe0fe55f956d4a"
)

MAPS = (
    b"00400000-00401000 r--p 00000000 00:00 0 /challenge/main\n"
    b"7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0 [stack]\n"
)


def registers(
    *,
    replacement: tuple[str, str] | None = None,
) -> PwnRuntimeSnapshotV1Registers:
    values = [
        (name, f"{index + 1:016x}")
        for index, name in enumerate(
            PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES
        )
    ]
    if replacement is not None:
        name, value = replacement
        index = PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES.index(name)
        values[index] = (name, value)
    return PwnRuntimeSnapshotV1Registers(tuple(values))


def trusted_kwargs(
    **overrides: object,
) -> dict[str, object]:
    values: dict[str, object] = {
        "expected_parent_crash_evaluation_sha256": (
            PARENT_EVALUATION_SHA256
        ),
        "expected_parent_crash_recipe_sha256": (
            PARENT_RECIPE_SHA256
        ),
        "expected_payload_sha256": PAYLOAD_SHA256,
        "expected_payload_size_bytes": PAYLOAD_SIZE,
        "expected_signal_number": EXPECTED_SIGNAL,
        "expected_snapshot_recipe_sha256": SNAPSHOT_RECIPE_SHA256,
        "expected_source_manifest_sha256": MANIFEST_SHA256,
        "expected_source_sha256": SOURCE_SHA256,
        "expected_source_size_bytes": SOURCE_SIZE,
    }
    values.update(overrides)
    return values


def result():
    return build_pwn_runtime_snapshot_v1_result(
        registers=registers(),
        maps=PwnRuntimeSnapshotV1Maps(MAPS),
        **trusted_kwargs(),
    )


class StringSubclass(str):
    pass


class PwnRuntimeSnapshotV1ContractTests(unittest.TestCase):
    def test_round_trip_is_exact_bounded_and_non_authoritative(
        self,
    ) -> None:
        built = result()
        payload = built.canonical_bytes()
        parsed = parse_pwn_runtime_snapshot_v1_result(
            payload,
            **trusted_kwargs(),
        )

        self.assertEqual(parsed, built)
        self.assertEqual(parsed.canonical_bytes(), payload)
        self.assertEqual(
            parsed.evidence_sha256,
            hashlib.sha256(payload).hexdigest(),
        )
        self.assertLessEqual(
            len(payload),
            PWN_RUNTIME_SNAPSHOT_V1_MAX_DOCUMENT_BYTES,
        )
        document = parsed.to_dict()
        self.assertEqual(
            document["contract"],
            {
                "fingerprint": (
                    PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_FINGERPRINT
                ),
                "id": PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_ID,
                "version": PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_VERSION,
            },
        )
        self.assertEqual(
            document["schema_version"],
            PWN_RUNTIME_SNAPSHOT_V1_SCHEMA_VERSION,
        )
        self.assertEqual(document["status"], "CAPTURED")
        self.assertEqual(
            document["reason_code"],
            PWN_RUNTIME_SNAPSHOT_V1_SUCCESS_REASON,
        )
        self.assertEqual(
            document["snapshot"]["register_source"],
            "ptrace_getregset_nt_prstatus",
        )
        self.assertEqual(
            document["snapshot"]["register_set_size_bytes"],
            PWN_RUNTIME_SNAPSHOT_V1_REGISTER_SET_BYTES,
        )
        self.assertTrue(document["claims"])
        self.assertTrue(
            all(value is False for value in document["claims"].values())
        )

    def test_register_and_maps_representation_is_exact(self) -> None:
        built = result()
        snapshot = built.to_dict()["snapshot"]
        register_mapping = snapshot["registers"]
        self.assertEqual(
            set(register_mapping),
            set(PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES),
        )
        self.assertEqual(len(register_mapping), 27)
        self.assertTrue(
            all(
                len(value) == 16
                and value == value.lower()
                and not value.startswith("0x")
                for value in register_mapping.values()
            )
        )

        maps = snapshot["maps"]
        self.assertEqual(maps["encoding"], "base64")
        self.assertEqual(
            base64.b64decode(
                maps["content_base64"],
                validate=True,
            ),
            MAPS,
        )
        self.assertEqual(maps["size_bytes"], len(MAPS))
        self.assertEqual(maps["line_count"], 2)
        self.assertEqual(
            maps["sha256"],
            hashlib.sha256(MAPS).hexdigest(),
        )

    def test_all_failure_reasons_have_exact_typed_statuses(self) -> None:
        self.assertEqual(
            PWN_RUNTIME_SNAPSHOT_V1_FAILURE_REASONS,
            (
                PWN_RUNTIME_SNAPSHOT_V1_INCONCLUSIVE_REASONS
                | PWN_RUNTIME_SNAPSHOT_V1_PRODUCER_ERROR_REASONS
            ),
        )
        self.assertFalse(
            PWN_RUNTIME_SNAPSHOT_V1_INCONCLUSIVE_REASONS
            & PWN_RUNTIME_SNAPSHOT_V1_PRODUCER_ERROR_REASONS
        )
        self.assertEqual(
            len(PWN_RUNTIME_SNAPSHOT_V1_INCONCLUSIVE_REASONS),
            4,
        )
        self.assertEqual(
            len(PWN_RUNTIME_SNAPSHOT_V1_PRODUCER_ERROR_REASONS),
            67,
        )
        self.assertEqual(
            len(PWN_RUNTIME_SNAPSHOT_V1_FAILURE_REASONS),
            71,
        )
        for reason_code in sorted(
            PWN_RUNTIME_SNAPSHOT_V1_FAILURE_REASONS
        ):
            with self.subTest(reason_code=reason_code):
                built = build_pwn_runtime_snapshot_v1_failure(
                    reason_code=reason_code,
                    **trusted_kwargs(),
                )
                expected_status = (
                    PwnRuntimeSnapshotV1Status.INCONCLUSIVE
                    if reason_code
                    in PWN_RUNTIME_SNAPSHOT_V1_INCONCLUSIVE_REASONS
                    else PwnRuntimeSnapshotV1Status.ERROR
                )
                self.assertIs(built.status, expected_status)
                self.assertIsNone(built.registers)
                self.assertIsNone(built.maps)
                self.assertIsNone(built.to_dict()["snapshot"])
                parsed = parse_pwn_runtime_snapshot_v1_result(
                    built.canonical_bytes(),
                    **trusted_kwargs(),
                )
                self.assertEqual(parsed, built)

        crossed = build_pwn_runtime_snapshot_v1_failure(
            reason_code=next(
                iter(PWN_RUNTIME_SNAPSHOT_V1_INCONCLUSIVE_REASONS)
            ),
            **trusted_kwargs(),
        ).to_dict()
        crossed["status"] = "ERROR"
        with self.assertRaisesRegex(
            PwnRuntimeSnapshotV1ContractError,
            "^invalid_schema$",
        ):
            validate_pwn_runtime_snapshot_v1_result_mapping(
                crossed,
                **trusted_kwargs(),
            )

    def test_contract_fingerprint_covers_fixed_semantics(self) -> None:
        descriptor = pwn_runtime_snapshot_v1_contract_descriptor()
        self.assertEqual(
            PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_FINGERPRINT,
            EXPECTED_CONTRACT_FINGERPRINT,
        )
        self.assertEqual(
            hashlib.sha256(
                pwn_runtime_snapshot_v1_canonical_json_bytes(
                    descriptor
                )
            ).hexdigest(),
            EXPECTED_CONTRACT_FINGERPRINT,
        )
        self.assertEqual(
            descriptor["registers"]["names_in_getregset_order"],
            list(PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES),
        )
        self.assertEqual(
            descriptor["registers"]["set_size_bytes"],
            216,
        )
        self.assertEqual(
            descriptor["maps"]["maximum_decoded_bytes"],
            128 * 1024,
        )

    def test_result_is_deeply_independent_and_immutable(self) -> None:
        built = result()
        document = built.to_dict()
        validated = validate_pwn_runtime_snapshot_v1_result_mapping(
            document,
            **trusted_kwargs(),
        )
        document["binding"]["source_sha256"] = "0" * 64
        document["snapshot"]["registers"]["rip"] = "0" * 16
        document["snapshot"]["maps"]["content_base64"] = ""

        self.assertEqual(validated, built)
        self.assertEqual(validated.maps.data, MAPS)
        with self.assertRaises(FrozenInstanceError):
            validated.source_sha256 = "0" * 64
        with self.assertRaises(FrozenInstanceError):
            validated.maps.data = b"x\n"
        with self.assertRaises(TypeError):
            validated.registers.values[0] = ("r15", "0" * 16)

    def test_coherent_binding_substitution_is_rejected(self) -> None:
        original = result().to_dict()
        substitutions = {
            "expected_signal_number": 4,
            "parent_crash_evaluation_sha256": "0" * 64,
            "parent_crash_recipe_sha256": "1" * 64,
            "payload_sha256": "2" * 64,
            "payload_size_bytes": PAYLOAD_SIZE + 1,
            "snapshot_recipe_sha256": "3" * 64,
            "source_manifest_sha256": "4" * 64,
            "source_sha256": "5" * 64,
            "source_size_bytes": SOURCE_SIZE + 1,
        }
        for key, substituted in substitutions.items():
            with self.subTest(key=key):
                document = copy.deepcopy(original)
                document["binding"][key] = substituted
                if key == "expected_signal_number":
                    document["snapshot"]["signal_number"] = substituted
                with self.assertRaisesRegex(
                    PwnRuntimeSnapshotV1ContractError,
                    "^result_binding_mismatch$",
                ):
                    validate_pwn_runtime_snapshot_v1_result_mapping(
                        document,
                        **trusted_kwargs(),
                    )

    def test_register_shape_and_values_fail_closed(self) -> None:
        original = result().to_dict()
        mutations = [
            lambda document: document["snapshot"][
                "registers"
            ].pop("rip"),
            lambda document: document["snapshot"][
                "registers"
            ].update({"extra": "0" * 16}),
            lambda document: document["snapshot"][
                "registers"
            ].update({"rip": "0x00000000000000"}),
            lambda document: document["snapshot"][
                "registers"
            ].update({"rip": "A" * 16}),
            lambda document: document["snapshot"][
                "registers"
            ].update({"rip": 0}),
            lambda document: document["snapshot"].update(
                {"architecture": "aarch64"}
            ),
            lambda document: document["snapshot"].update(
                {"register_source": "gdb"}
            ),
            lambda document: document["snapshot"].update(
                {"register_set_size_bytes": 215}
            ),
            lambda document: document["snapshot"].update(
                {"signal_number": 4}
            ),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                document = copy.deepcopy(original)
                mutate(document)
                with self.assertRaisesRegex(
                    PwnRuntimeSnapshotV1ContractError,
                    "^invalid_schema$",
                ):
                    validate_pwn_runtime_snapshot_v1_result_mapping(
                        document,
                        **trusted_kwargs(),
                    )

    def test_maps_metadata_and_encoding_fail_closed(self) -> None:
        original = result().to_dict()
        alternate = b"00400000-00401000 r-xp 0 00:00 0\n"
        mutations = [
            lambda maps: maps.update({"content_base64": "***"}),
            lambda maps: maps.update(
                {
                    "content_base64": "A"
                    * (
                        PWN_RUNTIME_SNAPSHOT_V1_MAX_MAPS_BASE64_BYTES
                        + 1
                    )
                }
            ),
            lambda maps: maps.update(
                {
                    "content_base64": (
                        base64.b64encode(MAPS).decode("ascii") + "\n"
                    )
                }
            ),
            lambda maps: maps.update({"encoding": "base64url"}),
            lambda maps: maps.update({"sha256": "0" * 64}),
            lambda maps: maps.update({"size_bytes": len(MAPS) + 1}),
            lambda maps: maps.update({"line_count": 1}),
            lambda maps: maps.update(
                {
                    "content_base64": base64.b64encode(
                        alternate
                    ).decode("ascii")
                }
            ),
            lambda maps: maps.update(
                {
                    "content_base64": base64.b64encode(
                        b"no-final-newline"
                    ).decode("ascii"),
                    "line_count": 0,
                    "sha256": hashlib.sha256(
                        b"no-final-newline"
                    ).hexdigest(),
                    "size_bytes": len(b"no-final-newline"),
                }
            ),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                document = copy.deepcopy(original)
                mutate(document["snapshot"]["maps"])
                with self.assertRaisesRegex(
                    PwnRuntimeSnapshotV1ContractError,
                    "^invalid_schema$",
                ):
                    validate_pwn_runtime_snapshot_v1_result_mapping(
                        document,
                        **trusted_kwargs(),
                    )

        with self.assertRaises(ValueError):
            PwnRuntimeSnapshotV1Maps(
                b"x" * PWN_RUNTIME_SNAPSHOT_V1_MAX_MAPS_BYTES
                + b"\n"
            )
        maximum_maps = PwnRuntimeSnapshotV1Maps(
            b"x" * (PWN_RUNTIME_SNAPSHOT_V1_MAX_MAPS_BYTES - 1)
            + b"\n"
        )
        maximum_result = build_pwn_runtime_snapshot_v1_result(
            registers=registers(),
            maps=maximum_maps,
            **trusted_kwargs(),
        )
        self.assertLessEqual(
            len(maximum_result.canonical_bytes()),
            PWN_RUNTIME_SNAPSHOT_V1_MAX_DOCUMENT_BYTES,
        )

    def test_canonical_duplicate_bounded_and_depth_rules(
        self,
    ) -> None:
        payload = result().canonical_bytes()
        document = result().to_dict()

        with self.assertRaisesRegex(
            PwnRuntimeSnapshotV1ContractError,
            "^noncanonical_json$",
        ):
            parse_pwn_runtime_snapshot_v1_result(
                json.dumps(document).encode("ascii"),
                **trusted_kwargs(),
            )

        duplicate = payload.replace(
            b'{"binding":',
            b'{"status":"CAPTURED","binding":',
            1,
        )
        with self.assertRaisesRegex(
            PwnRuntimeSnapshotV1ContractError,
            "^duplicate_json_key$",
        ):
            parse_pwn_runtime_snapshot_v1_result(
                duplicate,
                **trusted_kwargs(),
            )

        with self.assertRaisesRegex(
            PwnRuntimeSnapshotV1ContractError,
            "^artifact_too_large$",
        ):
            parse_pwn_runtime_snapshot_v1_result(
                b" " * (PWN_RUNTIME_SNAPSHOT_V1_MAX_DOCUMENT_BYTES + 1),
                **trusted_kwargs(),
            )

        deep = b'{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":0}}}}}}}}\n'
        with self.assertRaisesRegex(
            PwnRuntimeSnapshotV1ContractError,
            "^invalid_json$",
        ):
            parse_pwn_runtime_snapshot_v1_result(
                deep,
                **trusted_kwargs(),
            )

        wrong_contract = copy.deepcopy(document)
        wrong_contract["contract"]["fingerprint"] = "0" * 64
        with self.assertRaisesRegex(
            PwnRuntimeSnapshotV1ContractError,
            "^contract_mismatch$",
        ):
            validate_pwn_runtime_snapshot_v1_result_mapping(
                wrong_contract,
                **trusted_kwargs(),
            )

        with self.assertRaisesRegex(
            PwnRuntimeSnapshotV1ContractError,
            "^invalid_json$",
        ):
            parse_pwn_runtime_snapshot_v1_result(
                b'{"x":NaN}\n',
                **trusted_kwargs(),
            )

    def test_exact_scalar_and_container_types_are_required(
        self,
    ) -> None:
        document = result().to_dict()
        mutations = [
            lambda value: value.update({"schema_version": True}),
            lambda value: value.update({"status": StringSubclass(
                "CAPTURED"
            )}),
            lambda value: value["binding"].update(
                {"payload_size_bytes": True}
            ),
            lambda value: value["binding"].update(
                {"payload_sha256": StringSubclass(PAYLOAD_SHA256)}
            ),
            lambda value: value["claims"].update(
                {"proof_satisfied": 0}
            ),
            lambda value: value["snapshot"].update(
                {"signal_number": True}
            ),
            lambda value: value["snapshot"]["maps"].update(
                {"line_count": True}
            ),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                changed = copy.deepcopy(document)
                mutate(changed)
                with self.assertRaisesRegex(
                    PwnRuntimeSnapshotV1ContractError,
                    "^invalid_schema$",
                ):
                    validate_pwn_runtime_snapshot_v1_result_mapping(
                        changed,
                        **trusted_kwargs(),
                    )

        with self.assertRaises(TypeError):
            parse_pwn_runtime_snapshot_v1_result(
                bytearray(result().canonical_bytes()),
                **trusted_kwargs(),
            )

    def test_trusted_inputs_are_validated_before_reconstruction(
        self,
    ) -> None:
        document = result().to_dict()
        invalid_values = [
            ("expected_source_sha256", "A" * 64),
            ("expected_source_size_bytes", True),
            ("expected_payload_sha256", StringSubclass(PAYLOAD_SHA256)),
            ("expected_payload_size_bytes", 0),
            ("expected_parent_crash_recipe_sha256", "x"),
            ("expected_parent_crash_evaluation_sha256", "x"),
            ("expected_signal_number", 9),
            ("expected_snapshot_recipe_sha256", "x"),
        ]
        for key, value in invalid_values:
            with self.subTest(key=key):
                kwargs = trusted_kwargs(**{key: value})
                with self.assertRaises(ValueError):
                    validate_pwn_runtime_snapshot_v1_result_mapping(
                        document,
                        **kwargs,
                    )


if __name__ == "__main__":
    unittest.main()
