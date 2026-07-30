from __future__ import annotations

import copy
import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError

from ctf_os.contracts.pwn_leak_requirement_v1 import (
    PWN_LEAK_REQUIREMENT_V1_CONTRACT_FINGERPRINT,
    PWN_LEAK_REQUIREMENT_V1_CONTRACT_ID,
    PWN_LEAK_REQUIREMENT_V1_CONTRACT_VERSION,
    PWN_LEAK_REQUIREMENT_V1_MAX_DEPENDENCIES,
    PWN_LEAK_REQUIREMENT_V1_MAX_RESULT_BYTES,
    PWN_LEAK_REQUIREMENT_V1_MAX_SOURCE_BYTES,
    PWN_LEAK_REQUIREMENT_V1_MAX_STRATEGY_BYTES,
    PWN_LEAK_REQUIREMENT_V1_REASON_CODES,
    PWN_LEAK_REQUIREMENT_V1_SCHEMA_VERSION,
    PwnLeakRequirementV1ContractError,
    PwnLeakRequirementV1Dependency,
    PwnLeakRequirementV1ElfProfile,
    PwnLeakRequirementV1Strategy,
    PwnLeakRequirementV1Verdict,
    classify_pwn_leak_requirement_v1,
    parse_pwn_leak_requirement_v1_result,
    parse_pwn_leak_requirement_v1_strategy,
    pwn_leak_requirement_v1_canonical_json_bytes,
    pwn_leak_requirement_v1_contract_descriptor,
    validate_pwn_leak_requirement_v1_result_mapping,
)


MANIFEST_SHA256 = "a" * 64
SOURCE_SHA256 = "b" * 64
SOURCE_SIZE = 4096
PROFILE_EVIDENCE_SHA256 = "c" * 64
EXPECTED_CONTRACT_FINGERPRINT = (
    "520eacd6988bd6b2c843c72f00e51570d71f1fca5d411e0bb5dd508d41cfb0ad"
)


def dependency(
    dependency_id: str,
    object_kind: str = "primary_elf",
    address_mode: str = "absolute",
    purpose: str = "control_flow",
) -> dict[str, object]:
    return {
        "address_mode": address_mode,
        "dependency_id": dependency_id,
        "object_kind": object_kind,
        "purpose": purpose,
    }


def strategy_document(
    dependencies: list[dict[str, object]] | None = None,
    *,
    strategy_id: str = "ret2libc.v1",
) -> dict[str, object]:
    selected = (
        dependencies
        if dependencies is not None
        else [dependency("primary.pc")]
    )
    return {
        "contract": {
            "fingerprint": (
                PWN_LEAK_REQUIREMENT_V1_CONTRACT_FINGERPRINT
            ),
            "id": PWN_LEAK_REQUIREMENT_V1_CONTRACT_ID,
            "version": PWN_LEAK_REQUIREMENT_V1_CONTRACT_VERSION,
        },
        "dependencies": sorted(
            selected,
            key=lambda item: str(item["dependency_id"]),
        ),
        "schema_version": PWN_LEAK_REQUIREMENT_V1_SCHEMA_VERSION,
        "strategy_id": strategy_id,
    }


def strategy_bytes(
    dependencies: list[dict[str, object]] | None = None,
    *,
    strategy_id: str = "ret2libc.v1",
) -> bytes:
    return pwn_leak_requirement_v1_canonical_json_bytes(
        strategy_document(
            dependencies,
            strategy_id=strategy_id,
        )
    )


def profile_mapping(
    e_type: str = "ET_EXEC",
    has_interp: bool = True,
    status: str = "supported",
    *,
    source_manifest_sha256: str = MANIFEST_SHA256,
    source_sha256: str = SOURCE_SHA256,
    source_size_bytes: int = SOURCE_SIZE,
    profile_evidence_sha256: str = PROFILE_EVIDENCE_SHA256,
) -> dict[str, object]:
    return {
        "e_type": e_type,
        "has_interp": has_interp,
        "profile_evidence_sha256": profile_evidence_sha256,
        "source_manifest_sha256": source_manifest_sha256,
        "source_sha256": source_sha256,
        "source_size_bytes": source_size_bytes,
        "status": status,
    }


def profile(
    e_type: str = "ET_EXEC",
    has_interp: bool = True,
    status: str = "supported",
    *,
    source_manifest_sha256: str = MANIFEST_SHA256,
    source_sha256: str = SOURCE_SHA256,
    source_size_bytes: int = SOURCE_SIZE,
    profile_evidence_sha256: str = PROFILE_EVIDENCE_SHA256,
) -> PwnLeakRequirementV1ElfProfile:
    return PwnLeakRequirementV1ElfProfile(
        e_type=e_type,
        has_interp=has_interp,
        status=status,
        source_manifest_sha256=source_manifest_sha256,
        source_sha256=source_sha256,
        source_size_bytes=source_size_bytes,
        profile_evidence_sha256=profile_evidence_sha256,
    )


def trusted_kwargs(
    strategy: PwnLeakRequirementV1Strategy,
    dependency_id: object,
    elf_profile: PwnLeakRequirementV1ElfProfile,
) -> dict[str, object]:
    return {
        "expected_dependency_id": dependency_id,
        "expected_elf_profile": elf_profile,
        "expected_profile_evidence_sha256": (
            elf_profile.profile_evidence_sha256
        ),
        "expected_source_manifest_sha256": (
            elf_profile.source_manifest_sha256
        ),
        "expected_source_sha256": elf_profile.source_sha256,
        "expected_source_size_bytes": elf_profile.source_size_bytes,
        "expected_strategy": strategy,
    }


class StringSubclass(str):
    pass


class PwnLeakRequirementV1ContractTests(unittest.TestCase):
    def test_full_supported_verdict_and_reason_table(self) -> None:
        dependencies = [
            dependency(
                f"{object_kind}.{address_mode}",
                object_kind,
                address_mode,
            )
            for object_kind in ("primary_elf", "libc", "stack", "heap")
            for address_mode in ("absolute", "relative")
        ]
        self.assertEqual(
            len(dependencies),
            PWN_LEAK_REQUIREMENT_V1_MAX_DEPENDENCIES,
        )
        parsed = parse_pwn_leak_requirement_v1_strategy(
            strategy_bytes(dependencies)
        )

        observed_reasons: set[str] = set()
        for e_type in ("ET_EXEC", "ET_DYN"):
            for has_interp in (False, True):
                elf_profile = profile(e_type, has_interp)
                for item in dependencies:
                    dependency_id = str(item["dependency_id"])
                    result = classify_pwn_leak_requirement_v1(
                        parsed,
                        dependency_id=dependency_id,
                        elf_profile=elf_profile,
                    )
                    object_kind = item["object_kind"]
                    address_mode = item["address_mode"]
                    if address_mode == "relative":
                        expected = (
                            PwnLeakRequirementV1Verdict
                            .CONDITIONAL_NOT_APPLICABLE,
                            "relative_address_dependency",
                        )
                    elif (
                        object_kind == "primary_elf"
                        and e_type == "ET_EXEC"
                    ):
                        expected = (
                            PwnLeakRequirementV1Verdict
                            .CONDITIONAL_NOT_APPLICABLE,
                            "fixed_primary_elf_address_dependency",
                        )
                    elif (
                        object_kind == "primary_elf"
                        and e_type == "ET_DYN"
                        and not has_interp
                    ):
                        expected = (
                            PwnLeakRequirementV1Verdict.UNRESOLVED,
                            "static_et_dyn_profile_unsupported",
                        )
                    else:
                        expected = (
                            PwnLeakRequirementV1Verdict
                            .RUNTIME_ADDRESS_RESOLUTION_REQUIRED,
                            "absolute_runtime_address_dependency",
                        )
                    self.assertEqual(
                        (result.verdict, result.reason_code),
                        expected,
                    )
                    observed_reasons.add(result.reason_code)
                    self.assertEqual(
                        result.to_dict()["claims"],
                        {
                            "global_leak_not_applicable_proven": False,
                            "global_runtime_address_resolution_not_applicable_proven": (
                                False
                            ),
                            "leak_proven": False,
                            "leak_required_proven": False,
                            "primitive_proven": False,
                            "proof_satisfied": False,
                            "stage_advance_authorized": False,
                        },
                    )
                    self.assertEqual(
                        result.to_dict()["binding"][
                            "source_manifest_sha256"
                        ],
                        MANIFEST_SHA256,
                    )

        self.assertEqual(
            observed_reasons,
            {
                "absolute_runtime_address_dependency",
                "fixed_primary_elf_address_dependency",
                "relative_address_dependency",
                "static_et_dyn_profile_unsupported",
            },
        )

    def test_profile_status_and_dependency_lookup_reason_table(
        self,
    ) -> None:
        parsed = parse_pwn_leak_requirement_v1_strategy(
            strategy_bytes(
                [
                    dependency(
                        "relative.libc",
                        "libc",
                        "relative",
                    )
                ]
            )
        )
        cases = (
            (
                "relative.libc",
                profile(status="unsupported"),
                PwnLeakRequirementV1Verdict.UNRESOLVED,
                "elf_profile_unsupported",
            ),
            (
                "relative.libc",
                profile(status="ambiguous"),
                PwnLeakRequirementV1Verdict.UNRESOLVED,
                "elf_profile_ambiguous",
            ),
            (
                "unknown.address",
                profile(),
                PwnLeakRequirementV1Verdict.UNRESOLVED,
                "unknown_dependency",
            ),
            (
                None,
                profile(),
                PwnLeakRequirementV1Verdict.UNRESOLVED,
                "malformed_dependency_lookup",
            ),
        )
        observed = set()
        for dependency_id, elf_profile, verdict, reason in cases:
            result = classify_pwn_leak_requirement_v1(
                parsed,
                dependency_id=dependency_id,
                elf_profile=elf_profile,
            )
            self.assertIs(result.verdict, verdict)
            self.assertEqual(result.reason_code, reason)
            observed.add(reason)
        self.assertEqual(
            observed
            | {
                "absolute_runtime_address_dependency",
                "fixed_primary_elf_address_dependency",
                "relative_address_dependency",
                "static_et_dyn_profile_unsupported",
            },
            PWN_LEAK_REQUIREMENT_V1_REASON_CODES,
        )

    def test_exact_scalar_types_and_malformed_profiles_fail_stably(
        self,
    ) -> None:
        parsed = parse_pwn_leak_requirement_v1_strategy(
            strategy_bytes()
        )
        malformed_profiles = (
            profile_mapping(has_interp=1),
            profile_mapping(source_size_bytes=True),
            {
                key: value
                for key, value in profile_mapping().items()
                if key != "profile_evidence_sha256"
            },
            profile_mapping(e_type="ET_REL"),
        )
        for malformed in malformed_profiles:
            with self.subTest(malformed=malformed):
                with self.assertRaisesRegex(
                    ValueError,
                    "exact source-bound",
                ):
                    classify_pwn_leak_requirement_v1(
                        parsed,
                        dependency_id="primary.pc",
                        elf_profile=malformed,
                    )

        invalid_dependencies = (
            {
                "dependency_id": "d",
                "purpose": StringSubclass("read"),
                "object_kind": "libc",
                "address_mode": "absolute",
            },
            {
                "dependency_id": "d",
                "purpose": [],
                "object_kind": "libc",
                "address_mode": "absolute",
            },
        )
        for values in invalid_dependencies:
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    PwnLeakRequirementV1Dependency(**values)

        for values in (
            {"has_interp": 1},
            {"source_size_bytes": True},
            {"e_type": StringSubclass("ET_EXEC")},
            {"status": []},
            {"source_sha256": StringSubclass(SOURCE_SHA256)},
        ):
            arguments = profile_mapping()
            arguments.update(values)
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    PwnLeakRequirementV1ElfProfile(**arguments)

        for field in ("schema_version", "contract_version"):
            document = strategy_document()
            if field == "schema_version":
                document["schema_version"] = True
            else:
                document["contract"]["version"] = True
            with self.subTest(field=field):
                with self.assertRaises(PwnLeakRequirementV1ContractError):
                    parse_pwn_leak_requirement_v1_strategy(
                        pwn_leak_requirement_v1_canonical_json_bytes(
                            document
                        )
                    )

    def test_strategy_is_canonical_bounded_and_non_executable(
        self,
    ) -> None:
        payload = strategy_bytes()
        parsed = parse_pwn_leak_requirement_v1_strategy(payload)
        self.assertEqual(parsed.canonical_bytes(), payload)
        self.assertEqual(
            parsed.strategy_sha256,
            hashlib.sha256(payload).hexdigest(),
        )

        pretty = json.dumps(strategy_document(), indent=2).encode()
        with self.assertRaisesRegex(
            PwnLeakRequirementV1ContractError,
            "noncanonical_json",
        ):
            parse_pwn_leak_requirement_v1_strategy(pretty)

        duplicate_key = payload.replace(
            b'{"contract":',
            b'{"schema_version":1,"contract":',
            1,
        )
        with self.assertRaisesRegex(
            PwnLeakRequirementV1ContractError,
            "duplicate_json_key",
        ):
            parse_pwn_leak_requirement_v1_strategy(duplicate_key)

        oversized = (
            b"{" + b" " * PWN_LEAK_REQUIREMENT_V1_MAX_STRATEGY_BYTES
            + b"}"
        )
        with self.assertRaisesRegex(
            PwnLeakRequirementV1ContractError,
            "artifact_too_large",
        ):
            parse_pwn_leak_requirement_v1_strategy(oversized)

        for forbidden_key, forbidden_value in (
            ("command", "gdb ./target"),
            ("absolute_address", 0x41414141),
            ("payload", "AAAA"),
        ):
            document = strategy_document()
            document["dependencies"][0][
                forbidden_key
            ] = forbidden_value
            with self.subTest(forbidden_key=forbidden_key):
                with self.assertRaisesRegex(
                    PwnLeakRequirementV1ContractError,
                    "invalid_schema",
                ):
                    parse_pwn_leak_requirement_v1_strategy(
                        pwn_leak_requirement_v1_canonical_json_bytes(
                            document
                        )
                    )

    def test_dependency_order_count_duplicate_and_id_bounds(
        self,
    ) -> None:
        unordered = strategy_document(
            [dependency("a"), dependency("b")]
        )
        unordered["dependencies"].reverse()
        with self.assertRaisesRegex(
            PwnLeakRequirementV1ContractError,
            "dependency_order_mismatch",
        ):
            parse_pwn_leak_requirement_v1_strategy(
                pwn_leak_requirement_v1_canonical_json_bytes(unordered)
            )
        with self.assertRaises(ValueError):
            PwnLeakRequirementV1Strategy(
                strategy_id="ordered.v1",
                dependencies=(
                    PwnLeakRequirementV1Dependency(
                        dependency_id="b",
                        purpose="read",
                        object_kind="libc",
                        address_mode="absolute",
                    ),
                    PwnLeakRequirementV1Dependency(
                        dependency_id="a",
                        purpose="read",
                        object_kind="libc",
                        address_mode="absolute",
                    ),
                ),
            )

        for count in (
            0,
            PWN_LEAK_REQUIREMENT_V1_MAX_DEPENDENCIES + 1,
        ):
            with self.subTest(count=count):
                with self.assertRaisesRegex(
                    PwnLeakRequirementV1ContractError,
                    "invalid_schema",
                ):
                    parse_pwn_leak_requirement_v1_strategy(
                        strategy_bytes(
                            [
                                dependency(f"dep{index}")
                                for index in range(count)
                            ]
                        )
                    )

        with self.assertRaisesRegex(
            PwnLeakRequirementV1ContractError,
            "duplicate_dependency_id",
        ):
            parse_pwn_leak_requirement_v1_strategy(
                strategy_bytes(
                    [dependency("same"), dependency("same")]
                )
            )

        valid_id = "a" * 64
        parsed = parse_pwn_leak_requirement_v1_strategy(
            strategy_bytes(
                [dependency(valid_id)],
                strategy_id=valid_id,
            )
        )
        self.assertEqual(parsed.strategy_id, valid_id)
        with self.assertRaisesRegex(
            PwnLeakRequirementV1ContractError,
            "invalid_schema",
        ):
            parse_pwn_leak_requirement_v1_strategy(
                strategy_bytes(
                    [dependency("a" * 65)],
                    strategy_id="a" * 65,
                )
            )

    def test_expected_hash_and_contract_tamper_fail_closed(self) -> None:
        original = strategy_bytes()
        expected_sha256 = hashlib.sha256(original).hexdigest()
        parsed = parse_pwn_leak_requirement_v1_strategy(
            original,
            expected_strategy_sha256=expected_sha256,
        )
        tampered_document = strategy_document()
        tampered_document["dependencies"][0]["purpose"] = "write"
        with self.assertRaisesRegex(
            PwnLeakRequirementV1ContractError,
            "strategy_hash_mismatch",
        ):
            parse_pwn_leak_requirement_v1_strategy(
                pwn_leak_requirement_v1_canonical_json_bytes(
                    tampered_document
                ),
                expected_strategy_sha256=expected_sha256,
            )

        contract_tamper = strategy_document()
        contract_tamper["contract"]["version"] = 2
        with self.assertRaisesRegex(
            PwnLeakRequirementV1ContractError,
            "contract_mismatch",
        ):
            parse_pwn_leak_requirement_v1_strategy(
                pwn_leak_requirement_v1_canonical_json_bytes(
                    contract_tamper
                )
            )
        self.assertEqual(parsed.strategy_sha256, expected_sha256)

    def test_validator_rejects_coherent_dependency_and_profile_swap(
        self,
    ) -> None:
        parsed = parse_pwn_leak_requirement_v1_strategy(
            strategy_bytes(
                [
                    dependency("needs.base"),
                    dependency(
                        "relative.delta",
                        "libc",
                        "relative",
                    ),
                ]
            )
        )
        pie = profile("ET_DYN", True)
        expected = classify_pwn_leak_requirement_v1(
            parsed,
            dependency_id="needs.base",
            elf_profile=pie,
        )
        validated = validate_pwn_leak_requirement_v1_result_mapping(
            expected.to_dict(),
            **trusted_kwargs(parsed, "needs.base", pie),
        )
        self.assertEqual(validated, expected)
        self.assertIsNot(validated, expected)

        substitutions = (
            classify_pwn_leak_requirement_v1(
                parsed,
                dependency_id="relative.delta",
                elf_profile=pie,
            ).to_dict(),
            classify_pwn_leak_requirement_v1(
                parsed,
                dependency_id="needs.base",
                elf_profile=profile("ET_EXEC", True),
            ).to_dict(),
        )
        for substituted in substitutions:
            with self.subTest(substituted=substituted):
                with self.assertRaisesRegex(
                    PwnLeakRequirementV1ContractError,
                    "result_binding_mismatch",
                ):
                    validate_pwn_leak_requirement_v1_result_mapping(
                        substituted,
                        **trusted_kwargs(parsed, "needs.base", pie),
                    )

    def test_validator_rejects_source_and_profile_evidence_swap(
        self,
    ) -> None:
        parsed = parse_pwn_leak_requirement_v1_strategy(
            strategy_bytes()
        )
        trusted = profile("ET_DYN", True)
        expected = classify_pwn_leak_requirement_v1(
            parsed,
            dependency_id="primary.pc",
            elf_profile=trusted,
        )

        for field, replacement in (
            ("source_manifest_sha256", "d" * 64),
            ("source_sha256", "e" * 64),
            ("source_size_bytes", SOURCE_SIZE + 1),
            ("profile_evidence_sha256", "f" * 64),
        ):
            tampered_profile = profile_mapping("ET_DYN", True)
            tampered_profile[field] = replacement
            substituted = classify_pwn_leak_requirement_v1(
                parsed,
                dependency_id="primary.pc",
                elf_profile=tampered_profile,
            ).to_dict()
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    PwnLeakRequirementV1ContractError,
                    "result_binding_mismatch",
                ):
                    validate_pwn_leak_requirement_v1_result_mapping(
                        substituted,
                        **trusted_kwargs(
                            parsed,
                            "primary.pc",
                            trusted,
                        ),
                    )

            one_sided = copy.deepcopy(expected.to_dict())
            one_sided["binding"][field] = replacement
            with self.subTest(one_sided=field):
                with self.assertRaisesRegex(
                    PwnLeakRequirementV1ContractError,
                    "invalid_schema",
                ):
                    validate_pwn_leak_requirement_v1_result_mapping(
                        one_sided,
                        **trusted_kwargs(
                            parsed,
                            "primary.pc",
                            trusted,
                        ),
                    )

        bad_trusted = trusted_kwargs(
            parsed,
            "primary.pc",
            trusted,
        )
        bad_trusted["expected_source_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            ValueError,
            "does not match",
        ):
            validate_pwn_leak_requirement_v1_result_mapping(
                expected.to_dict(),
                **bad_trusted,
            )

    def test_result_parser_is_canonical_duplicate_free_and_bounded(
        self,
    ) -> None:
        parsed = parse_pwn_leak_requirement_v1_strategy(
            strategy_bytes()
        )
        elf_profile = profile("ET_DYN", True)
        result = classify_pwn_leak_requirement_v1(
            parsed,
            dependency_id="primary.pc",
            elf_profile=elf_profile,
        )
        kwargs = trusted_kwargs(
            parsed,
            "primary.pc",
            elf_profile,
        )
        reparsed = parse_pwn_leak_requirement_v1_result(
            result.canonical_bytes(),
            **kwargs,
        )
        self.assertEqual(reparsed, result)
        self.assertIsNot(reparsed, result)

        pretty = json.dumps(result.to_dict(), indent=2).encode()
        with self.assertRaisesRegex(
            PwnLeakRequirementV1ContractError,
            "noncanonical_json",
        ):
            parse_pwn_leak_requirement_v1_result(pretty, **kwargs)

        duplicate = result.canonical_bytes().replace(
            b'{"binding":',
            b'{"schema_version":1,"binding":',
            1,
        )
        with self.assertRaisesRegex(
            PwnLeakRequirementV1ContractError,
            "duplicate_json_key",
        ):
            parse_pwn_leak_requirement_v1_result(
                duplicate,
                **kwargs,
            )

        oversized = (
            b"{" + b" " * PWN_LEAK_REQUIREMENT_V1_MAX_RESULT_BYTES
            + b"}"
        )
        with self.assertRaisesRegex(
            PwnLeakRequirementV1ContractError,
            "artifact_too_large",
        ):
            parse_pwn_leak_requirement_v1_result(
                oversized,
                **kwargs,
            )

        too_deep = pwn_leak_requirement_v1_canonical_json_bytes(
            [[[[[[[]]]]]]]
        )
        with self.assertRaisesRegex(
            PwnLeakRequirementV1ContractError,
            "invalid_json",
        ):
            parse_pwn_leak_requirement_v1_result(
                too_deep,
                **kwargs,
            )

    def test_result_validation_returns_immutable_isolated_result(
        self,
    ) -> None:
        parsed = parse_pwn_leak_requirement_v1_strategy(
            strategy_bytes()
        )
        elf_profile = profile()
        result = classify_pwn_leak_requirement_v1(
            parsed,
            dependency_id="primary.pc",
            elf_profile=elf_profile,
        )
        mapping = result.to_dict()
        validated = validate_pwn_leak_requirement_v1_result_mapping(
            mapping,
            **trusted_kwargs(
                parsed,
                "primary.pc",
                elf_profile,
            ),
        )
        mapping["claims"]["stage_advance_authorized"] = True
        self.assertFalse(
            validated.to_dict()["claims"]["stage_advance_authorized"]
        )
        with self.assertRaises(FrozenInstanceError):
            validated.reason_code = "unknown_dependency"

        scalar_subclass = result.to_dict()
        scalar_subclass["contract"]["id"] = StringSubclass(
            PWN_LEAK_REQUIREMENT_V1_CONTRACT_ID
        )
        with self.assertRaisesRegex(
            PwnLeakRequirementV1ContractError,
            "invalid_schema",
        ):
            validate_pwn_leak_requirement_v1_result_mapping(
                scalar_subclass,
                **trusted_kwargs(
                    parsed,
                    "primary.pc",
                    elf_profile,
                ),
            )

    def test_relative_advisory_never_grants_global_or_stage_authority(
        self,
    ) -> None:
        parsed = parse_pwn_leak_requirement_v1_strategy(
            strategy_bytes(
                [
                    dependency(
                        "only.delta",
                        "libc",
                        "relative",
                    )
                ]
            )
        )
        result = classify_pwn_leak_requirement_v1(
            parsed,
            dependency_id="only.delta",
            elf_profile=profile("ET_DYN", True),
        )
        self.assertIs(
            result.verdict,
            PwnLeakRequirementV1Verdict
            .CONDITIONAL_NOT_APPLICABLE,
        )
        self.assertEqual(
            result.to_dict()["claims"],
            {
                "global_leak_not_applicable_proven": False,
                "global_runtime_address_resolution_not_applicable_proven": (
                    False
                ),
                "leak_proven": False,
                "leak_required_proven": False,
                "primitive_proven": False,
                "proof_satisfied": False,
                "stage_advance_authorized": False,
            },
        )
        self.assertNotIn("passed", result.to_dict())
        non_authorities = pwn_leak_requirement_v1_contract_descriptor()[
            "non_authorities"
        ]
        self.assertIn(
            "does-not-prove-dependency-set-complete",
            non_authorities,
        )
        self.assertIn(
            "does-not-prove-relative-anchor-resolved",
            non_authorities,
        )

    def test_profile_source_bounds_are_exact(self) -> None:
        for invalid_size in (
            0,
            True,
            PWN_LEAK_REQUIREMENT_V1_MAX_SOURCE_BYTES + 1,
        ):
            arguments = profile_mapping()
            arguments["source_size_bytes"] = invalid_size
            with self.subTest(invalid_size=invalid_size):
                with self.assertRaises(ValueError):
                    PwnLeakRequirementV1ElfProfile(**arguments)

    def test_descriptor_and_fingerprint_are_frozen_and_complete(
        self,
    ) -> None:
        descriptor = pwn_leak_requirement_v1_contract_descriptor()
        self.assertEqual(
            PWN_LEAK_REQUIREMENT_V1_CONTRACT_FINGERPRINT,
            EXPECTED_CONTRACT_FINGERPRINT,
        )
        self.assertEqual(
            PWN_LEAK_REQUIREMENT_V1_CONTRACT_FINGERPRINT,
            hashlib.sha256(
                pwn_leak_requirement_v1_canonical_json_bytes(
                    descriptor
                )
            ).hexdigest(),
        )
        self.assertEqual(
            descriptor["advisory_name"],
            "runtime-address-resolution-requirement",
        )
        self.assertEqual(
            descriptor["classification_authority"],
            "advisory-only",
        )
        self.assertEqual(
            descriptor["dependency_order"],
            "dependency_id-strictly-increasing",
        )
        self.assertEqual(
            set(descriptor["reason_codes"]),
            PWN_LEAK_REQUIREMENT_V1_REASON_CODES,
        )
        self.assertEqual(
            descriptor["claims"],
            {
                "global_leak_not_applicable_proven": False,
                "global_runtime_address_resolution_not_applicable_proven": (
                    False
                ),
                "leak_proven": False,
                "leak_required_proven": False,
                "primitive_proven": False,
                "proof_satisfied": False,
                "stage_advance_authorized": False,
            },
        )
        self.assertIn(
            "does-not-authorize-stage-advance",
            descriptor["non_authorities"],
        )
        self.assertIn("failure_codes", descriptor)
        self.assertIn("schemas", descriptor)
        self.assertIn("json_max_depth", descriptor)
        self.assertIn("validation", descriptor)


if __name__ == "__main__":
    unittest.main()
